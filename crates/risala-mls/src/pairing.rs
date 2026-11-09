//! Pairing a new device (4.8): the relay through `PAIR PUT/GET`, the
//! signed NewDevice, and the IdentityBundle sealed to the new device.
//!
//! The new device makes a one-time 32-byte pairing secret and shows it in
//! a QR code that never reaches the server. From it, both devices derive,
//! with PRK = HKDF-Extract("", secret) and HKDF-SHA384:
//!
//! - `new_id` = HKDF-Expand(PRK, "risala/1 pair new id", 16) and
//!   `new_key` = HKDF-Expand(PRK, "risala/1 pair new key", 32), for the
//!   new device's message, its encoded [`NewDevice`] encrypted and sent
//!   as a SealedNewDevice;
//! - `old_id` and `old_key` the same way with `old`, for the reply, a
//!   [`SealedBundle`].
//!
//! The NewDevice is encrypted with ChaCha20-Poly1305 under `new_key`, a
//! nonce of 12 zero bytes and the associated data `risala/1 pair`, and the
//! ciphertext is wrapped in a SealedNewDevice with a version byte. It is
//! signed by the new device key (RisalaSign, label `pair`) and carries a
//! new X-Wing **pairing key**. The [`IdentityBundle`] is sealed to that key
//! with HPKE \[RFC9180\] in mode_psk, with 12.2's KEM, KDF and AEAD (X-Wing
//! `0x647a`, HKDF-SHA384 `0x0002`, ChaCha20-Poly1305 `0x0003`), info and
//! psk_id `risala/1 pair`, an empty aad, and `old_key` as the psk. So
//! opening it takes both the QR code's secret and the private pairing key,
//! which never leaves the new device.
//!
//! HPKE is hpke-rs with its libcrux backend, the crates OpenMLS's libcrux
//! provider seals with; OpenMLS's own crypto trait offers base mode only.
//!
//! The PairingCode, NewDevice, its content and the SealedBundle are
//! `risala-proto`'s (its `pairing` module), which also makes the checks of
//! a NewDevice that need no crypto beyond signatures. This module derives
//! the relay's ids and keys, encrypts and seals, and holds the
//! IdentityBundle and the SealedNewDevice, whose contents are secret.
//!
//! Ids are written as boxes (3.5). A device that sends `PAIR PUT` again,
//! after a lost answer, sends the same bytes: the NewDevice's ciphertext is
//! deterministic, but sealing a bundle is not, so the device that seals
//! one keeps the bytes it sent.
//!
//! ```text
//! struct { DeviceKeys keys; opaque pairing_key<V>; } NewDeviceContent;
//! struct { uint8 version; NewDeviceContent content; opaque signature<V>; } NewDevice;
//! struct { uint8 version; opaque ciphertext<V>; } SealedNewDevice;
//! opaque Host<V>;
//! struct {
//!     uint8 version; opaque uid<V>; opaque master_key<V>;
//!     opaque signing_seed[32]; uint32 backup_generation;
//!     opaque backup_key[32]; opaque record_hash[48]; Host hosts<V>;
//!     opaque transfer<V>;
//! } IdentityBundle;
//! struct { uint8 version; opaque enc[1120]; opaque ciphertext<V>; } SealedBundle;
//! ```

use std::fmt;

use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::HpkeCrypto as _;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_libcrux::HpkeLibcrux;
use risala_proto::auth::PUBLIC_KEY_LEN;
use risala_proto::names::{Identity, ServerAddr};
use risala_proto::pairing::PairingError as CheckError;
pub use risala_proto::pairing::{
    KEYS_HASH_LEN, NewDevice, NewDeviceContent, PAIRING_SECRET_LEN, PAIRING_VERSION, PairingCode,
    SealedBundle, XWING_ENC_LEN,
};
use risala_proto::record::{RecordError, XWingPublicKey};
use zeroize::Zeroizing;

use crate::archive::{ArchiveError, Reader, TRANSFER_REF_LEN, TransferRef, Writer};
use crate::backup::{BACKUP_KEY_LEN, BackupKey, base32_lower};
use crate::crypto::x_wing_public_key_ok;
use crate::primitives::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, HASH_LEN, ct_eq, hkdf_expand, hkdf_extract, open, seal, sha384,
};

/// The length of a relay id (4.8).
pub const RELAY_ID_LEN: usize = 16;

/// The length of a device-signing key's seed (4.8).
pub const SIGNING_SEED_LEN: usize = 32;

/// The length of an ML-DSA-44 public key, the master key's (4.3).
pub const MASTER_KEY_LEN: usize = PUBLIC_KEY_LEN;

/// The length of an X-Wing private key, its seed (4.3).
pub const PAIRING_SEED_LEN: usize = 32;

/// The associated data of the NewDevice's encryption, and the HPKE info
/// and psk_id of the IdentityBundle's (4.8).
pub const PAIR_LABEL: &[u8] = b"risala/1 pair";

const NEW_ID_LABEL: &[u8] = b"risala/1 pair new id";
const NEW_KEY_LABEL: &[u8] = b"risala/1 pair new key";
const OLD_ID_LABEL: &[u8] = b"risala/1 pair old id";
const OLD_KEY_LABEL: &[u8] = b"risala/1 pair old key";

/// Why a pairing message cannot be made or read (4.8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// The message does not decrypt: another secret, another pairing key,
    /// the other message, or it was changed.
    #[error("the pairing message does not decrypt")]
    Decrypt,
    /// The NewDevice's hash is not the PairingCode's `keys_hash`.
    #[error("the new device's keys do not match the QR code")]
    Hash,
    /// The NewDevice's signature does not verify under its device key.
    #[error("the new device's signature does not verify")]
    Signature,
    /// A key is not one the device may use: an X-Wing key that fails the
    /// checks of 12.2, or the same key twice.
    #[error("the new device's {0} is not acceptable")]
    Key(&'static str),
    /// The structure names a version this device does not support (2.4).
    #[error("unsupported pairing version {0}")]
    Version(u8),
    /// The bytes are not the encoded structure.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// The operating system gave no randomness, or HPKE failed to seal.
    #[error("the bundle could not be sealed")]
    Seal,
}

impl From<ArchiveError> for PairingError {
    fn from(error: ArchiveError) -> PairingError {
        match error {
            ArchiveError::Malformed(what) => PairingError::Malformed(what),
            ArchiveError::Version(version) => PairingError::Version(version),
            _ => PairingError::Malformed("pairing structure"),
        }
    }
}

impl From<RecordError> for PairingError {
    fn from(error: RecordError) -> PairingError {
        match error {
            RecordError::Version(version) => PairingError::Version(version),
            RecordError::Malformed(what) => PairingError::Malformed(what),
            _ => PairingError::Malformed("pairing structure"),
        }
    }
}

impl From<CheckError> for PairingError {
    fn from(error: CheckError) -> PairingError {
        match error {
            CheckError::KeysHash => PairingError::Hash,
            CheckError::Signature => PairingError::Signature,
            // The pairing key is for this pairing only, so it is not the
            // attestation key (4.8).
            CheckError::RepeatedKey => PairingError::Key("pairing key"),
        }
    }
}

/// A one-time pairing secret (4.8): 32 bytes, wiped when dropped. `Debug`
/// does not show it, and equality is in constant time.
#[derive(Clone)]
pub struct PairingSecret(Zeroizing<[u8; PAIRING_SECRET_LEN]>);

impl PairingSecret {
    /// A new random secret.
    pub fn generate() -> Result<PairingSecret, getrandom::Error> {
        let mut secret = Zeroizing::new([0; PAIRING_SECRET_LEN]);
        getrandom::fill(&mut secret[..])?;
        Ok(PairingSecret(secret))
    }

    /// A secret from its bytes, as read from a PairingCode.
    pub fn from_bytes(bytes: [u8; PAIRING_SECRET_LEN]) -> PairingSecret {
        PairingSecret(Zeroizing::new(bytes))
    }

    /// The secret of a PairingCode, as the scanning device reads it.
    pub fn of_code(code: &PairingCode) -> PairingSecret {
        PairingSecret(code.secret.clone())
    }

    /// The secret's bytes.
    pub fn as_bytes(&self) -> &[u8; PAIRING_SECRET_LEN] {
        &self.0
    }

    /// The PairingCode the new device shows (4.8): pairing through `host`,
    /// with this secret, for `new_device`. A device MUST make one code per
    /// secret: the relay seals only the NewDevice its code names
    /// ([`Relay::seal_new_device`]), under a nonce of zeros, so two codes
    /// for two NewDevices would reuse it.
    pub fn code(&self, host: ServerAddr, new_device: &NewDevice) -> PairingCode {
        PairingCode {
            host,
            secret: self.0.clone(),
            keys_hash: new_device.keys_hash(),
        }
    }

    /// The ids and keys of the relay (4.8).
    pub fn relay(&self) -> Relay {
        let prk = hkdf_extract(b"", &self.0[..]);
        let id = |label: &[u8]| {
            let mut out = [0; RELAY_ID_LEN];
            hkdf_expand(&prk[..], label, &mut out);
            RelayId(out)
        };
        let key = |label: &[u8]| {
            let mut out = Zeroizing::new([0; AEAD_KEY_LEN]);
            hkdf_expand(&prk[..], label, &mut out[..]);
            out
        };
        Relay {
            new_id: id(NEW_ID_LABEL),
            new_key: key(NEW_KEY_LABEL),
            old_id: id(OLD_ID_LABEL),
            old_key: key(OLD_KEY_LABEL),
        }
    }
}

impl PartialEq for PairingSecret {
    fn eq(&self, other: &PairingSecret) -> bool {
        ct_eq(&self.0[..], &other.0[..])
    }
}

impl Eq for PairingSecret {}

impl fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingSecret(…)")
    }
}

/// A relay id (4.8): 16 bytes, written as a box (3.5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RelayId([u8; RELAY_ID_LEN]);

impl RelayId {
    /// The id's bytes.
    pub fn as_bytes(&self) -> &[u8; RELAY_ID_LEN] {
        &self.0
    }
}

/// The id as a box (3.5): 26 characters of lower-case base32. (The box
/// type of risala-proto may replace this.)
impl fmt::Display for RelayId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base32_lower(&self.0))
    }
}

/// A new device's one-time X-Wing pairing key (4.8): the 32-byte seed,
/// wiped when dropped, and its public key. The new device deletes it once
/// it has opened the bundle. `Debug` does not show the seed.
pub struct PairingKey {
    seed: Zeroizing<[u8; PAIRING_SEED_LEN]>,
    public: XWingPublicKey,
}

impl PairingKey {
    /// A new random pairing key.
    pub fn generate() -> Result<PairingKey, getrandom::Error> {
        let mut seed = Zeroizing::new([0; PAIRING_SEED_LEN]);
        getrandom::fill(&mut seed[..])?;
        Ok(PairingKey::from_seed(seed))
    }

    /// The pairing key of `seed`: X-Wing's key generation from its seed.
    pub fn from_seed(seed: Zeroizing<[u8; PAIRING_SEED_LEN]>) -> PairingKey {
        let (public, mut private) =
            HpkeLibcrux::kem_key_gen_derand(KemAlgorithm::XWingDraft06, &seed[..])
                .expect("X-Wing makes a key pair from any 32-byte seed");
        // libcrux's X-Wing private key is the seed itself.
        debug_assert_eq!(&private[..], &seed[..]);
        zeroize::Zeroize::zeroize(&mut private);
        let public = XWingPublicKey::from_bytes(&public)
            .expect("X-Wing's key generation makes keys that pass 12.2's checks");
        PairingKey { seed, public }
    }

    /// The public key, for NewDeviceContent's `pairing_key`.
    pub fn public(&self) -> &XWingPublicKey {
        &self.public
    }

    /// The public key's bytes.
    pub fn public_key(&self) -> &[u8] {
        self.public.as_bytes()
    }
}

impl fmt::Debug for PairingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingKey(…)")
    }
}

/// HPKE with 12.2's suite in mode_psk (4.8).
fn hpke() -> Hpke<HpkeLibcrux> {
    Hpke::new(
        Mode::Psk,
        KemAlgorithm::XWingDraft06,
        KdfAlgorithm::HkdfSha384,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

/// The relay's ids and keys, derived from a pairing secret (4.8).
pub struct Relay {
    new_id: RelayId,
    new_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    old_id: RelayId,
    old_key: Zeroizing<[u8; AEAD_KEY_LEN]>,
}

const ZERO_NONCE: [u8; AEAD_NONCE_LEN] = [0; AEAD_NONCE_LEN];

impl Relay {
    /// The id of the new device's message, for `PAIR PUT` and `PAIR GET`.
    pub fn new_id(&self) -> RelayId {
        self.new_id
    }

    /// The id of the reply.
    pub fn old_id(&self) -> RelayId {
        self.old_id
    }

    /// Encrypts the new device's NewDevice, and returns the encoded
    /// SealedNewDevice, for `PAIR PUT new_id`. The key encrypts this one
    /// message only, under a nonce of zeros (4.8): the same NewDevice gives
    /// the same bytes, which is what a repeated PAIR PUT sends, and to send
    /// another the device starts again with a new secret. So sealing is
    /// bound to `code`, the PairingCode of this relay's secret: it refuses
    /// any NewDevice other than the one whose hash the code carries
    /// ([`PairingError::Hash`]), since sealing two under one key would
    /// reuse the nonce. Signing is hedged, so a NewDevice signed again is
    /// another one.
    pub fn seal_new_device(
        &self,
        new_device: &NewDevice,
        code: &PairingCode,
    ) -> Result<Vec<u8>, PairingError> {
        let same_secret = PairingSecret::of_code(code).relay().new_id == self.new_id;
        if !same_secret || !ct_eq(&sha384(new_device.encoded()), &code.keys_hash) {
            return Err(PairingError::Hash);
        }
        Ok(self.seal_new_device_bytes(new_device.encoded()))
    }

    fn seal_new_device_bytes(&self, new_device: &[u8]) -> Vec<u8> {
        let ciphertext = seal(&self.new_key, &ZERO_NONCE, PAIR_LABEL, new_device);
        let mut w = Writer::default();
        w.u8(PAIRING_VERSION);
        w.vector(&ciphertext);
        w.0.to_vec()
    }

    /// Opens the data of `PAIR new_id` (4.8, step 2), for the device that
    /// scanned `code`: reads the SealedNewDevice, rejecting a `version`
    /// other than 1, decrypts it, checks in constant time that its SHA-384
    /// hash is the code's `keys_hash`, reads it (risala-proto checks its
    /// keys as 4.4 does), and checks its signature and that its pairing key
    /// is not its attestation key ([`NewDevice::check`]). The checks of 4.4
    /// that need the identity's chain (keys never seen in it, at most 64
    /// devices) are the caller's.
    pub fn open_new_device(
        &self,
        data: &[u8],
        code: &PairingCode,
    ) -> Result<NewDevice, PairingError> {
        let mut r = Reader(data);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(PairingError::Version(version));
        }
        let ciphertext = r.vector()?;
        r.end()?;
        let new_device = open(&self.new_key, &ZERO_NONCE, PAIR_LABEL, ciphertext)
            .ok_or(PairingError::Decrypt)?;
        if !ct_eq(&sha384(&new_device), &code.keys_hash) {
            return Err(PairingError::Hash);
        }
        let new_device = NewDevice::decode(&new_device)?;
        new_device.check(code)?;
        Ok(new_device)
    }

    /// Seals `bundle` to the new device's pairing key, for `PAIR PUT
    /// old_id` (4.8, step 4). Each call gives other bytes: keep the encoded
    /// SealedBundle, and send the same bytes if the PAIR PUT is repeated.
    pub fn seal_bundle(
        &self,
        bundle: &IdentityBundle,
        new_device: &NewDevice,
    ) -> Result<SealedBundle, PairingError> {
        let pairing_key = new_device.content().pairing_key.as_bytes();
        // Checked when the NewDevice was read; checked again since HPKE
        // must never encrypt to a key that fails (12.2).
        if !x_wing_public_key_ok(pairing_key) {
            return Err(PairingError::Key("pairing key"));
        }
        let (enc, ciphertext) = hpke()
            .seal(
                &HpkePublicKey::new(pairing_key.to_vec()),
                PAIR_LABEL,
                b"",
                &bundle.encode(),
                Some(&self.old_key[..]),
                Some(PAIR_LABEL),
                None,
            )
            .map_err(|_| PairingError::Seal)?;
        Ok(SealedBundle {
            enc: Box::new(enc.try_into().map_err(|_| PairingError::Seal)?),
            ciphertext,
        })
    }

    /// Opens the data of `PAIR old_id` with the new device's pairing key
    /// (4.8, step 5), and reads the IdentityBundle. Checking it against the
    /// identity's key file is the caller's.
    pub fn open_bundle(
        &self,
        data: &[u8],
        pairing_key: &PairingKey,
    ) -> Result<IdentityBundle, PairingError> {
        let sealed = SealedBundle::decode(data)?;
        let private = HpkePrivateKey::new(pairing_key.seed.to_vec());
        let plain = Zeroizing::new(
            hpke()
                .open(
                    &sealed.enc[..],
                    &private,
                    PAIR_LABEL,
                    b"",
                    &sealed.ciphertext,
                    Some(&self.old_key[..]),
                    Some(PAIR_LABEL),
                    None,
                )
                .map_err(|_| PairingError::Decrypt)?,
        );
        IdentityBundle::decode(&plain)
    }
}

impl fmt::Debug for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relay")
            .field("new_id", &self.new_id)
            .field("old_id", &self.old_id)
            .finish_non_exhaustive()
    }
}

/// An IdentityBundle (4.8): what the device that scans the QR code sends
/// the new one. Secrets are wiped when dropped, and `Debug` does not show
/// them.
#[derive(Clone)]
pub struct IdentityBundle {
    /// The identity.
    pub uid: Identity,
    /// The current master public key, ML-DSA-44 (4.3).
    pub master_key: Vec<u8>,
    /// The current device-signing key's seed.
    pub signing_seed: Zeroizing<[u8; SIGNING_SEED_LEN]>,
    /// The current backup key, with its generation, which is the chain's
    /// (4.4, 12.13): the new device checks it against the key file.
    pub backup: BackupKey,
    /// SHA-384 of the new device's `device` record (4.4).
    pub record_hash: [u8; HASH_LEN],
    /// The servers the identity uses, each a server address in its one
    /// written form (2.1), its home first (12.13). Never empty, without
    /// repeats.
    pub hosts: Vec<ServerAddr>,
    /// The history transfer, if any (12.13).
    pub transfer: Option<TransferRef>,
}

impl IdentityBundle {
    /// The encoded bundle, wiped when dropped.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        debug_assert_eq!(self.master_key.len(), MASTER_KEY_LEN);
        let mut w = Writer::default();
        w.u8(PAIRING_VERSION);
        w.vector(self.uid.as_str().as_bytes());
        w.vector(&self.master_key);
        w.bytes(&self.signing_seed[..]);
        w.u32(self.backup.generation());
        w.bytes(self.backup.as_bytes());
        w.bytes(&self.record_hash);
        w.nested(|w| {
            for host in &self.hosts {
                w.vector(host.to_string().as_bytes());
            }
        });
        match &self.transfer {
            Some(transfer) => w.vector(&transfer.to_bytes()[..]),
            None => w.vector(&[]),
        }
        w.0
    }

    /// Reads an encoded bundle: version 1, a uid in lower case, a master
    /// key of 1312 bytes, at least one host, each a server address in its
    /// one written form (2.1) and none twice, a transfer that is empty or one TransferRef of version 1,
    /// and nothing after it.
    pub fn decode(bytes: &[u8]) -> Result<IdentityBundle, PairingError> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(PairingError::Version(version));
        }
        let uid = canonical::<Identity>(r.vector()?, "uid")?;
        let master_key = r.vector()?;
        if master_key.len() != MASTER_KEY_LEN {
            return Err(PairingError::Malformed("master_key"));
        }
        let signing_seed = Zeroizing::new(r.array::<SIGNING_SEED_LEN>()?);
        let generation = r.u32()?;
        let backup = BackupKey::from_bytes(generation, r.array::<BACKUP_KEY_LEN>()?);
        let record_hash = r.array::<HASH_LEN>()?;
        let mut hosts: Vec<ServerAddr> = Vec::new();
        let mut list = Reader(r.vector()?);
        while !list.0.is_empty() {
            let host = server_addr(list.vector()?, "hosts")?;
            // The home server comes first, and the list has no repeats
            // (4.8).
            if hosts.contains(&host) {
                return Err(PairingError::Malformed("hosts"));
            }
            hosts.push(host);
        }
        if hosts.is_empty() {
            return Err(PairingError::Malformed("hosts"));
        }
        let transfer = match r.vector()? {
            [] => None,
            bytes if bytes.len() == TRANSFER_REF_LEN => Some(TransferRef::from_bytes(bytes)?),
            _ => return Err(PairingError::Malformed("transfer")),
        };
        r.end()?;
        Ok(IdentityBundle {
            uid,
            master_key: master_key.to_vec(),
            signing_seed,
            backup,
            record_hash,
            hosts,
            transfer,
        })
    }
}

/// The seed and keys are compared in constant time.
impl PartialEq for IdentityBundle {
    fn eq(&self, other: &IdentityBundle) -> bool {
        let seeds = ct_eq(&self.signing_seed[..], &other.signing_seed[..]);
        seeds
            & (self.backup == other.backup)
            & (self.transfer == other.transfer)
            & (self.uid == other.uid)
            & (self.master_key == other.master_key)
            & (self.record_hash == other.record_hash)
            & (self.hosts == other.hosts)
    }
}

impl Eq for IdentityBundle {}

impl fmt::Debug for IdentityBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityBundle")
            .field("uid", &self.uid)
            .field("backup", &self.backup)
            .field("record_hash", &self.record_hash)
            .field("hosts", &self.hosts)
            .field("transfer", &self.transfer.as_ref().map(|t| t.blob))
            .finish_non_exhaustive()
    }
}

/// A server address in its one written form (2.1): parsing it is strict,
/// so the text is already the one form.
fn server_addr(bytes: &[u8], what: &'static str) -> Result<ServerAddr, PairingError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(PairingError::Malformed(what))
}

/// A name in the exact form it is sent in: UTF-8 that parses and is
/// already in lower case.
fn canonical<T: std::str::FromStr + AsRef<str>>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, PairingError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PairingError::Malformed(what))?;
    let value: T = text.parse().map_err(|_| PairingError::Malformed(what))?;
    if value.as_ref() != text {
        return Err(PairingError::Malformed(what));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{BlobRef, FileKey};
    use crate::primitives::hmac_sha384;
    use risala_proto::auth::SecretKey;
    use risala_proto::record::DeviceKeys;

    /// The secret of Appendix B.9 and B.11.
    fn secret() -> PairingSecret {
        PairingSecret::from_bytes([0x0d; 32])
    }

    fn pairing_key(seed: u8) -> PairingKey {
        PairingKey::from_seed(Zeroizing::new([seed; 32]))
    }

    fn device_key(seed: u8) -> SecretKey {
        SecretKey::from_seed([seed; 32])
    }

    fn content(device: u8, attestation: u8, pairing: &PairingKey, label: &str) -> NewDeviceContent {
        NewDeviceContent {
            keys: DeviceKeys {
                device_key: device_key(device).public_key(),
                attestation_key: pairing_key(attestation).public().clone(),
                label: label.to_owned(),
            },
            pairing_key: pairing.public().clone(),
        }
    }

    /// A NewDevice signed by device key `device`, with pairing key
    /// `pairing`, with the deterministic variant of ML-DSA.
    fn new_device(device: u8, pairing: &PairingKey) -> NewDevice {
        NewDevice::sign_deterministic(
            content(device, 0xa7, pairing, "Alice's phone"),
            &device_key(device),
        )
    }

    /// The NewDevice of Appendix B.9: device key seed 0a, attestation key
    /// seed 0b, label "new phone", pairing key seed 0c.
    fn b9_new_device() -> NewDevice {
        NewDevice::sign_deterministic(
            content(0x0a, 0x0b, &pairing_key(0x0c), "new phone"),
            &device_key(0x0a),
        )
    }

    /// The PairingCode of `new_device` with [`secret`].
    fn code_of(new_device: &NewDevice) -> PairingCode {
        secret().code("chat.example.org".parse().unwrap(), new_device)
    }

    fn bundle(transfer: bool) -> IdentityBundle {
        IdentityBundle {
            uid: "alice@example.org".parse().unwrap(),
            master_key: (0..MASTER_KEY_LEN).map(|i| i as u8).collect(),
            signing_seed: Zeroizing::new([0x51; 32]),
            backup: BackupKey::from_bytes(2, [0x52; 32]),
            record_hash: [0x53; 48],
            hosts: vec![
                "chat.example.org".parse().unwrap(),
                "example.net".parse().unwrap(),
            ],
            transfer: transfer.then(|| TransferRef {
                blob: BlobRef::from_bytes([0x54; 48]),
                key: FileKey::from_bytes([0x55; 32]),
            }),
        }
    }

    /// The ids and keys, against HKDF written out with HMAC.
    #[test]
    fn derivation() {
        let relay = secret().relay();
        let prk = hmac_sha384(&[0; 48], secret().as_bytes());
        let expand = |label: &str| hmac_sha384(&prk, &[label.as_bytes(), &[1]].concat());
        assert_eq!(
            relay.new_id.as_bytes(),
            &expand("risala/1 pair new id")[..16]
        );
        assert_eq!(&relay.new_key[..], &expand("risala/1 pair new key")[..32]);
        assert_eq!(
            relay.old_id.as_bytes(),
            &expand("risala/1 pair old id")[..16]
        );
        assert_eq!(&relay.old_key[..], &expand("risala/1 pair old key")[..32]);
        assert_ne!(relay.new_id(), relay.old_id());
        let text = relay.new_id().to_string();
        assert_eq!(text.len(), 26);
        assert!(text.bytes().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')));
        assert_ne!(
            PairingSecret::generate().unwrap().relay().new_id(),
            relay.new_id()
        );
        assert_eq!(format!("{:?}", secret()), "PairingSecret(…)");
    }

    /// The X-Wing key check (12.2) agrees with libcrux, which refuses to
    /// encapsulate to a key that fails it.
    #[test]
    fn x_wing_keys() {
        let key = pairing_key(1);
        let good = key.public_key().to_vec();
        assert_eq!(good.len(), 1216);
        assert!(x_wing_public_key_ok(&good));
        assert_ne!(pairing_key(2).public_key(), &good[..]);
        assert_eq!(pairing_key(1).public_key(), &good[..]);
        assert!(
            PairingKey::generate()
                .map(|k| x_wing_public_key_ok(k.public_key()))
                .unwrap()
        );
        assert!(!x_wing_public_key_ok(&good[..1215]));
        assert!(!x_wing_public_key_ok(&[&good[..], &[0]].concat()));
        assert_eq!(format!("{key:?}"), "PairingKey(…)");

        let seals = |pk: &[u8]| {
            hpke()
                .seal(
                    &HpkePublicKey::new(pk.to_vec()),
                    b"",
                    b"",
                    b"x",
                    Some(&[1; 32]),
                    Some(b"id"),
                    None,
                )
                .is_ok()
        };
        assert!(seals(&good));
        // A coefficient of q or more: the first (q itself, then 4095), and
        // the last, the high half of bytes 1150 and 1151.
        let mut bad = Vec::new();
        let mut b = good.clone();
        b[0] = 0x01;
        b[1] = (b[1] & 0xf0) | 0x0d;
        bad.push(b);
        let mut b = good.clone();
        b[0] = 0xff;
        b[1] |= 0x0f;
        bad.push(b);
        let mut b = good.clone();
        b[1150] |= 0xf0;
        b[1151] = 0xff;
        bad.push(b);
        for (n, b) in bad.iter().enumerate() {
            assert!(!x_wing_public_key_ok(b), "{n}");
            assert!(!seals(b), "{n}");
        }
        // Bytes after the coefficients (rho and the X25519 key) are free.
        let mut b = good.clone();
        b[1152..].fill(0xff);
        assert!(x_wing_public_key_ok(&b));
        // q - 1 is fine: 3328 is 0x0d00.
        let mut edge = good.clone();
        edge[0] = 0x00;
        edge[1] = (edge[1] & 0xf0) | 0x0d;
        assert!(x_wing_public_key_ok(&edge));
        assert!(seals(&edge));
    }

    #[test]
    fn new_device_message() {
        let device = new_device(9, &pairing_key(3));
        let new_device_bytes = device.encoded().to_vec();
        let code = code_of(&device);
        let relay = PairingSecret::of_code(&code).relay();
        assert_eq!(PairingSecret::of_code(&code), secret());
        let data = relay.seal_new_device(&device, &code).unwrap();
        // A SealedNewDevice: the version, the ciphertext's two-byte length,
        // then the ciphertext and its tag (4.8).
        assert_eq!(data.len(), 1 + 2 + new_device_bytes.len() + 16);
        assert_eq!(data[0], PAIRING_VERSION);
        assert_eq!(relay.open_new_device(&data, &code), Ok(device.clone()));
        // A repeated PAIR PUT sends the same bytes.
        assert_eq!(relay.seal_new_device(&device, &code).unwrap(), data);
        // Only the NewDevice the code names is sealed, so the zero nonce is
        // never used twice under one key (4.8): not another device's, nor
        // the same content signed again, nor under another secret's code.
        let other_device = new_device(10, &pairing_key(4));
        assert_eq!(
            relay.seal_new_device(&other_device, &code),
            Err(PairingError::Hash)
        );
        assert_eq!(
            relay.seal_new_device(&other_device, &code_of(&other_device)),
            Ok(relay.seal_new_device_bytes(other_device.encoded()))
        );
        let elsewhere = PairingCode {
            secret: Zeroizing::new([9; 32]),
            ..code.clone()
        };
        assert_eq!(
            relay.seal_new_device(&device, &elsewhere),
            Err(PairingError::Hash)
        );
        // Swapped keys: the server swapped the NewDevice for another, even
        // a well-signed one.
        let other = relay.seal_new_device_bytes(other_device.encoded());
        assert_eq!(
            relay.open_new_device(&other, &code),
            Err(PairingError::Hash)
        );
        // Changed, under another secret, or without the associated data.
        let mut changed = data.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            relay.open_new_device(&changed, &code),
            Err(PairingError::Decrypt)
        );
        // Another version, bytes after the ciphertext, the bare ciphertext.
        let mut v2 = data.clone();
        v2[0] = 2;
        assert_eq!(
            relay.open_new_device(&v2, &code),
            Err(PairingError::Version(2))
        );
        let mut longer = data.clone();
        longer.push(0);
        assert!(matches!(
            relay.open_new_device(&longer, &code),
            Err(PairingError::Malformed(_))
        ));
        assert!(relay.open_new_device(&data[3..], &code).is_err());
        let stranger = PairingSecret::from_bytes([9; 32]).relay();
        assert_eq!(
            stranger.open_new_device(&data, &code),
            Err(PairingError::Decrypt)
        );
        let mut no_aad = Writer::default();
        no_aad.u8(PAIRING_VERSION);
        no_aad.vector(&seal(&relay.new_key, &ZERO_NONCE, b"", &new_device_bytes));
        let no_aad = no_aad.0.to_vec();
        assert_eq!(
            relay.open_new_device(&no_aad, &code),
            Err(PairingError::Decrypt)
        );
        // A hash that matches bytes that are not a NewDevice.
        let junk = relay.seal_new_device_bytes(b"\x01junk");
        let junk_code = PairingCode {
            keys_hash: sha384(b"\x01junk"),
            ..code.clone()
        };
        assert!(matches!(
            relay.open_new_device(&junk, &junk_code),
            Err(PairingError::Malformed(_))
        ));
        // risala-proto's checks of a NewDevice whose hash matches: signed by
        // another key, or with its attestation key as its pairing key.
        let forged = NewDevice::sign_deterministic(device.content().clone(), &device_key(10));
        assert_eq!(
            relay.open_new_device(
                &relay.seal_new_device_bytes(forged.encoded()),
                &code_of(&forged)
            ),
            Err(PairingError::Signature)
        );
        let mut reused = device.content().clone();
        reused.pairing_key = reused.keys.attestation_key.clone();
        let reused = NewDevice::sign_deterministic(reused, &device_key(9));
        assert_eq!(
            relay.open_new_device(
                &relay.seal_new_device_bytes(reused.encoded()),
                &code_of(&reused)
            ),
            Err(PairingError::Key("pairing key"))
        );
    }

    #[test]
    fn bundles() {
        let relay = secret().relay();
        let key = pairing_key(3);
        let device = new_device(9, &key);
        for transfer in [false, true] {
            let b = bundle(transfer);
            assert_eq!(IdentityBundle::decode(&b.encode()), Ok(b.clone()));
            let sealed = relay.seal_bundle(&b, &device).unwrap();
            let data = sealed.encode();
            assert_eq!(data.len(), 1 + 1120 + 2 + b.encode().len() + 16);
            assert_eq!(SealedBundle::decode(&data), Ok(sealed.clone()));
            assert_eq!(relay.open_bundle(&data, &key), Ok(b.clone()));
            // Sealing again gives other bytes: the sender keeps what it
            // sent, for a repeated PAIR PUT.
            assert_ne!(relay.seal_bundle(&b, &device).unwrap(), sealed);

            // Changed ciphertext or enc.
            let mut changed = data.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert_eq!(
                relay.open_bundle(&changed, &key),
                Err(PairingError::Decrypt)
            );
            let mut changed = data.clone();
            changed[5] ^= 1;
            assert_eq!(
                relay.open_bundle(&changed, &key),
                Err(PairingError::Decrypt)
            );
            // Seeing the QR code is not enough: another pairing key fails,
            // and so does another secret with the right pairing key.
            assert_eq!(
                relay.open_bundle(&data, &pairing_key(4)),
                Err(PairingError::Decrypt)
            );
            let stranger = PairingSecret::from_bytes([9; 32]).relay();
            assert_eq!(
                stranger.open_bundle(&data, &key),
                Err(PairingError::Decrypt)
            );
        }
        // Sealed in base mode, without the psk: refused.
        let mut base = Hpke::<HpkeLibcrux>::new(
            Mode::Base,
            KemAlgorithm::XWingDraft06,
            KdfAlgorithm::HkdfSha384,
            AeadAlgorithm::ChaCha20Poly1305,
        );
        let (enc, ciphertext) = base
            .seal(
                &HpkePublicKey::new(key.public_key().to_vec()),
                PAIR_LABEL,
                b"",
                &bundle(false).encode(),
                None,
                None,
                None,
            )
            .unwrap();
        let base_sealed = SealedBundle {
            enc: Box::new(enc.try_into().unwrap()),
            ciphertext,
        }
        .encode();
        assert_eq!(
            relay.open_bundle(&base_sealed, &key),
            Err(PairingError::Decrypt)
        );
        // Another psk_id or info.
        for (info, psk_id) in [
            (&b"risala/1 pair"[..], &b"other"[..]),
            (b"other", b"risala/1 pair"),
        ] {
            let (enc, ciphertext) = hpke()
                .seal(
                    &HpkePublicKey::new(key.public_key().to_vec()),
                    info,
                    b"",
                    &bundle(false).encode(),
                    Some(&relay.old_key[..]),
                    Some(psk_id),
                    None,
                )
                .unwrap();
            let sealed = SealedBundle {
                enc: Box::new(enc.try_into().unwrap()),
                ciphertext,
            };
            assert_eq!(
                relay.open_bundle(&sealed.encode(), &key),
                Err(PairingError::Decrypt)
            );
        }

        // SealedBundle framing.
        let data = relay.seal_bundle(&bundle(true), &device).unwrap().encode();
        for n in 0..1124 {
            assert!(SealedBundle::decode(&data[..n]).is_err(), "cut at {n}");
        }
        assert!(SealedBundle::decode(&[&data[..], &[0]].concat()).is_err());
        let mut b = data.clone();
        b[0] = 2;
        assert_eq!(SealedBundle::decode(&b), Err(RecordError::Version(2)));
        assert_eq!(relay.open_bundle(&b, &key), Err(PairingError::Version(2)));

        let debug = format!("{:?}", bundle(true));
        assert!(!debug.contains("81, 81"), "the seed is hidden: {debug}");
        assert!(
            !debug.contains("85, 85"),
            "the transfer key is hidden: {debug}"
        );
    }

    #[test]
    fn bundle_rejections() {
        let bytes = bundle(true).encode().to_vec();
        for n in 0..bytes.len() {
            assert!(IdentityBundle::decode(&bytes[..n]).is_err(), "cut at {n}");
        }
        assert!(IdentityBundle::decode(&[&bytes[..], &[0]].concat()).is_err());
        let mut b = bytes.clone();
        b[0] = 2;
        assert_eq!(IdentityBundle::decode(&b), Err(PairingError::Version(2)));
        // An upper-case uid.
        let mut b = bytes.clone();
        b[2] = b'A';
        assert_eq!(
            IdentityBundle::decode(&b),
            Err(PairingError::Malformed("uid"))
        );

        // Field by field.
        let build = |master_key: &[u8], hosts: &[&str], transfer: &[u8]| {
            let mut w = Writer::default();
            w.u8(1);
            w.vector(b"alice@example.org");
            w.vector(master_key);
            w.bytes(&[0x51; 32]);
            w.u32(2);
            w.bytes(&[0x52; 32]);
            w.bytes(&[0x53; 48]);
            w.nested(|w| {
                for host in hosts {
                    w.vector(host.as_bytes());
                }
            });
            w.vector(transfer);
            IdentityBundle::decode(&w.0)
        };
        let master = vec![7; MASTER_KEY_LEN];
        let hosts = ["chat.example.org", "example.net"];
        let transfer = bundle(true).transfer.unwrap().to_bytes();
        assert!(build(&master, &hosts, &[]).is_ok());
        assert!(build(&master, &hosts, &transfer[..]).is_ok());
        assert!(build(&master, &["example.org"], &[]).is_ok());
        // Servers with ports and single labels are servers (2.1).
        assert!(build(&master, &["chat.example.org:7000", "localhost"], &[]).is_ok());
        // The default port written out, or an IP address, are not in the
        // one written form.
        for host in ["chat.example.org:7472", "192.0.2.1", "chat.example.org."] {
            assert_eq!(
                build(&master, &[host], &[]),
                Err(PairingError::Malformed("hosts")),
                "{host}"
            );
        }
        assert_eq!(
            build(&master[..1311], &hosts, &[]),
            Err(PairingError::Malformed("master_key"))
        );
        // No host, a host in upper case or not a host, a host twice.
        assert_eq!(
            build(&master, &[], &[]),
            Err(PairingError::Malformed("hosts"))
        );
        assert_eq!(
            build(&master, &["Example.org"], &[]),
            Err(PairingError::Malformed("hosts"))
        );
        assert_eq!(
            build(&master, &["exa mple.org"], &[]),
            Err(PairingError::Malformed("hosts"))
        );
        assert_eq!(
            build(&master, &["example.org", "example.net", "example.org"], &[]),
            Err(PairingError::Malformed("hosts"))
        );
        // A transfer that is neither empty nor 81 bytes, or of version 2.
        assert_eq!(
            build(&master, &hosts, &transfer[..80]),
            Err(PairingError::Malformed("transfer"))
        );
        let mut t = *transfer;
        t[0] = 2;
        assert_eq!(build(&master, &hosts, &t), Err(PairingError::Version(2)));
    }

    /// The whole exchange, as two devices run it.
    #[test]
    fn exchange() {
        // The new device: its keys, a pairing key, a secret, the QR code.
        let key = PairingKey::generate().unwrap();
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).unwrap();
        let device_key = SecretKey::from_seed(seed);
        let content = NewDeviceContent {
            keys: DeviceKeys {
                device_key: device_key.public_key(),
                attestation_key: PairingKey::generate().unwrap().public().clone(),
                label: "laptop".to_owned(),
            },
            pairing_key: key.public().clone(),
        };
        let mut rnd = [0; 32];
        getrandom::fill(&mut rnd).unwrap();
        let device = NewDevice::sign(content, &device_key, rnd);
        let secret = PairingSecret::generate().unwrap();
        let code = secret.code("example.org".parse().unwrap(), &device);
        let relay = secret.relay();
        let put_new = (
            relay.new_id(),
            relay.seal_new_device(&device, &code).unwrap(),
        );
        let qr = code.to_qr_text();

        // The other device scans the code, checks the keys, and replies.
        let scanned = PairingCode::from_qr_text(&qr).unwrap();
        let theirs = PairingSecret::of_code(&scanned).relay();
        assert_eq!(theirs.new_id(), put_new.0);
        let opened = theirs.open_new_device(&put_new.1, &scanned).unwrap();
        assert_eq!(opened, device);
        let reply = theirs.seal_bundle(&bundle(true), &opened).unwrap();
        let put_old = (theirs.old_id(), reply.encode());

        // The new device polls the reply.
        assert_eq!(relay.old_id(), put_old.0);
        assert_eq!(relay.open_bundle(&put_old.1, &key), Ok(bundle(true)));
    }

    /// Appendix B.11: the keys and ids from B.9's pairing secret, the
    /// SealedNewDevice of B.9's NewDevice, and a SealedBundle sealed to
    /// B.9's pairing key. Sealing is randomized, so the SealedBundle is
    /// read from its file, and made afresh only in print mode.
    #[test]
    fn appendix_b() {
        let mut ck = crate::appendix::Checker::open("B.11 ");
        let relay = secret().relay();
        let key = pairing_key(0x0c);
        let new_device = b9_new_device();
        let b = IdentityBundle {
            master_key: vec![0x50; MASTER_KEY_LEN],
            ..bundle(true)
        };
        ck.hex("secret", secret().as_bytes());
        ck.hex("pairing key seed", &[0x0c; 32]);
        ck.eq("uid", b.uid.to_string());
        assert!(b.master_key.iter().all(|&x| x == 0x50));
        ck.eq("master_key", format!("{} bytes of 50", b.master_key.len()));
        ck.hex("signing_seed", &b.signing_seed[..]);
        ck.eq("backup_generation", b.backup.generation().to_string());
        ck.hex("backup_key", b.backup.as_bytes());
        ck.hex("record_hash", &b.record_hash);
        ck.eq(
            "hosts",
            b.hosts
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        );
        let transfer = b.transfer.as_ref().unwrap();
        ck.eq("transfer blob", transfer.blob.to_string());
        ck.hex("transfer key", transfer.key.as_bytes());
        ck.gap();
        ck.hex("new_id", relay.new_id().as_bytes());
        ck.eq("new_id as a box", relay.new_id().to_string());
        ck.hex("new_key", &relay.new_key[..]);
        ck.hex("old_id", relay.old_id().as_bytes());
        ck.eq("old_id as a box", relay.old_id().to_string());
        ck.hex("old_key", &relay.old_key[..]);
        let sealed_new = relay
            .seal_new_device(
                &new_device,
                &secret().code("chat.example.org".parse().unwrap(), &new_device),
            )
            .unwrap();
        ck.file(
            "SealedNewDevice of B.9's NewDevice",
            "sealed-newdevice.bin",
            &sealed_new,
        );
        assert_eq!(
            relay.open_new_device(&sealed_new, &code_of(&new_device)),
            Ok(new_device.clone())
        );
        ck.file("pairing key", "pairing-key.bin", key.public_key());
        let encoded = b.encode();
        ck.file("IdentityBundle", "identity-bundle.bin", &encoded);
        assert_eq!(IdentityBundle::decode(&encoded), Ok(b.clone()));
        let path = format!("{}/sealed-bundle.bin", crate::appendix::FILES);
        let sealed = if crate::appendix::printing() {
            relay.seal_bundle(&b, &new_device).unwrap().encode()
        } else {
            std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
        };
        assert_eq!(relay.open_bundle(&sealed, &key), Ok(b.clone()));
        ck.file("a SealedBundle of it", "sealed-bundle.bin", &sealed);
        ck.gap();
        let mut version = sealed_new.clone();
        version[0] = 2;
        ck.rejected(
            "the SealedNewDevice with version 2",
            relay.open_new_device(&version, &code_of(&new_device)) == Err(PairingError::Version(2)),
        );
        let other = PairingSecret::from_bytes([1; 32]).relay();
        ck.rejected(
            "the SealedNewDevice opened with the new_key of the secret 32 bytes of 01",
            other.open_new_device(&sealed_new, &code_of(&new_device)) == Err(PairingError::Decrypt),
        );
        let mut version = sealed.clone();
        version[0] = 2;
        ck.rejected(
            "the SealedBundle with version 2",
            relay.open_bundle(&version, &key).is_err(),
        );
        ck.rejected(
            "the SealedBundle opened with the old_key of the secret 32 bytes of 01",
            other.open_bundle(&sealed, &key).is_err(),
        );
        ck.rejected(
            "the SealedBundle opened with the pairing key of seed 32 bytes of 04",
            relay.open_bundle(&sealed, &pairing_key(4)).is_err(),
        );
        let no_hosts = IdentityBundle {
            hosts: vec![],
            ..b.clone()
        };
        ck.rejected(
            "the IdentityBundle with no hosts",
            IdentityBundle::decode(&no_hosts.encode()).is_err(),
        );
        let repeated = IdentityBundle {
            hosts: vec![b.hosts[0].clone(), b.hosts[1].clone(), b.hosts[0].clone()],
            ..b.clone()
        };
        ck.rejected(
            "the IdentityBundle with hosts chat.example.org example.net chat.example.org",
            IdentityBundle::decode(&repeated.encode()).is_err(),
        );
        let mut version = encoded.to_vec();
        version[0] = 2;
        ck.rejected(
            "the IdentityBundle with version 2",
            IdentityBundle::decode(&version).is_err(),
        );
        ck.finish();
    }

    /// B.11's NewDevice is B.9's.
    #[test]
    fn b9_and_b11_agree() {
        let path = format!("{}/newdevice.bin", crate::appendix::FILES);
        let b9 = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(b9_new_device().encoded(), &b9[..]);
    }
}

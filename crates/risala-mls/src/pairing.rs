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
//! with HPKE [RFC9180] in mode_psk, with 12.2's KEM, KDF and AEAD (X-Wing
//! `0x647a`, HKDF-SHA384 `0x0002`, ChaCha20-Poly1305 `0x0003`), info and
//! psk_id `risala/1 pair`, an empty aad, and `old_key` as the psk. So
//! opening it takes both the QR code's secret and the private pairing key,
//! which never leaves the new device.
//!
//! HPKE is hpke-rs with its libcrux backend, the crates OpenMLS's libcrux
//! provider seals with; OpenMLS's own crypto trait offers base mode only.
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
use risala_proto::auth::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, Signature};
use risala_proto::names::{Identity, ServerAddr};
use zeroize::Zeroizing;

use crate::archive::{ArchiveError, Reader, TRANSFER_REF_LEN, TransferRef, Writer};
use crate::backup::{BACKUP_KEY_LEN, BackupKey, base32_lower};
use crate::crypto::x_wing_public_key_ok;
use crate::mldsa::SigningKey;
use crate::primitives::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, HASH_LEN, ct_eq, hkdf_expand, hkdf_extract, open, seal, sha384,
};
use crate::risala_sign::{risala_sign, risala_verify};

/// The length of a pairing secret (4.8).
pub const PAIRING_SECRET_LEN: usize = 32;

/// The length of a relay id (4.8).
pub const RELAY_ID_LEN: usize = 16;

/// The length of a device-signing key's seed (4.8).
pub const SIGNING_SEED_LEN: usize = 32;

/// The length of an ML-DSA-44 public key, the master key's (4.3).
pub const MASTER_KEY_LEN: usize = PUBLIC_KEY_LEN;

/// The length of an X-Wing private key, its seed (4.3).
pub const PAIRING_SEED_LEN: usize = 32;

/// The length of an X-Wing encapsulated key, a SealedBundle's `enc`.
pub const ENC_LEN: usize = 1120;

/// The most bytes of a device's label (4.4).
pub const MAX_LABEL_LEN: usize = 64;

/// The version of a NewDevice, SealedNewDevice, IdentityBundle,
/// SealedBundle and PairingCode (4.8).
pub const PAIRING_VERSION: u8 = 1;

/// The associated data of the NewDevice's encryption, and the HPKE info
/// and psk_id of the IdentityBundle's (4.8).
pub const PAIR_LABEL: &[u8] = b"risala/1 pair";

/// RisalaSign's label for a NewDevice (4.3, 4.8), after `risala/1 `.
pub const PAIR_SIGN_LABEL: &str = "pair";

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

    /// The secret's bytes.
    pub fn as_bytes(&self) -> &[u8; PAIRING_SECRET_LEN] {
        &self.0
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
    public: Vec<u8>,
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
        PairingKey { seed, public }
    }

    /// The public key, for NewDeviceContent's `pairing_key`.
    pub fn public_key(&self) -> &[u8] {
        &self.public
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

    /// Encrypts the new device's encoded NewDevice, and returns the
    /// encoded SealedNewDevice, for `PAIR PUT new_id`. The key encrypts
    /// this one message only: the same NewDevice gives the same bytes,
    /// which is what a repeated PAIR PUT sends, and to send another the
    /// device starts again with a new secret.
    pub fn seal_new_device(&self, new_device: &[u8]) -> Vec<u8> {
        let ciphertext = seal(&self.new_key, &ZERO_NONCE, PAIR_LABEL, new_device);
        let mut w = Writer::default();
        w.u8(PAIRING_VERSION);
        w.vector(&ciphertext);
        w.0.to_vec()
    }

    /// Opens the data of `PAIR new_id` (4.8, step 2): reads the
    /// SealedNewDevice, rejecting a `version` other than 1, decrypts it, checks
    /// in constant time that its SHA-384 hash is the PairingCode's
    /// `keys_hash`, reads it, and checks its signature and keys
    /// ([`NewDevice::decode`]). The checks of 4.4 that need the identity's
    /// chain (keys never seen in it, at most 64 devices) are the caller's.
    pub fn open_new_device(
        &self,
        data: &[u8],
        keys_hash: &[u8; HASH_LEN],
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
        if !ct_eq(&sha384(&new_device), keys_hash) {
            return Err(PairingError::Hash);
        }
        NewDevice::decode(&new_device)
    }

    /// Seals `bundle` to the new device's pairing key, for `PAIR PUT
    /// old_id` (4.8, step 4). Each call gives other bytes: keep the encoded
    /// SealedBundle, and send the same bytes if the PAIR PUT is repeated.
    pub fn seal_bundle(
        &self,
        bundle: &IdentityBundle,
        new_device: &NewDevice,
    ) -> Result<SealedBundle, PairingError> {
        let pairing_key = &new_device.content.pairing_key;
        // Checked when the NewDevice was read; checked again since HPKE
        // must never encrypt to a key that fails (12.2).
        if !x_wing_public_key_ok(pairing_key) {
            return Err(PairingError::Key("pairing key"));
        }
        let (enc, ciphertext) = hpke()
            .seal(
                &HpkePublicKey::new(pairing_key.clone()),
                PAIR_LABEL,
                b"",
                &bundle.encode(),
                Some(&self.old_key[..]),
                Some(PAIR_LABEL),
                None,
            )
            .map_err(|_| PairingError::Seal)?;
        Ok(SealedBundle {
            enc: enc.try_into().map_err(|_| PairingError::Seal)?,
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
                    &sealed.enc,
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

/// A device record's DeviceKeys (4.4).
///
/// TO MOVE: task P2 owns the key file records in risala-proto; this local
/// copy goes once it lands.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceKeys {
    /// The device key, ML-DSA-44.
    pub device_key: PublicKey,
    /// The attestation key, X-Wing, 1216 bytes.
    pub attestation_key: Vec<u8>,
    /// A label for people, usually the device's name: UTF-8, at most 64
    /// bytes.
    pub label: String,
}

/// A NewDeviceContent (4.8): the new device's keys, and its pairing key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewDeviceContent {
    /// The keys for its `device` record.
    pub keys: DeviceKeys,
    /// Its X-Wing pairing key, 1216 bytes, for this pairing only.
    pub pairing_key: Vec<u8>,
}

impl NewDeviceContent {
    /// The encoded content, which the device key signs.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.vector(self.keys.device_key.as_bytes());
        w.vector(&self.keys.attestation_key);
        w.vector(self.keys.label.as_bytes());
        w.vector(&self.pairing_key);
        w.0.to_vec()
    }

    fn decode(r: &mut Reader<'_>) -> Result<NewDeviceContent, PairingError> {
        let device_key: &[u8; PUBLIC_KEY_LEN] = r
            .vector()?
            .try_into()
            .map_err(|_| PairingError::Malformed("device_key"))?;
        let attestation_key = r.vector()?.to_vec();
        let label = std::str::from_utf8(r.vector()?)
            .map_err(|_| PairingError::Malformed("label"))?
            .to_owned();
        if label.len() > MAX_LABEL_LEN {
            return Err(PairingError::Malformed("label"));
        }
        let pairing_key = r.vector()?.to_vec();
        if !x_wing_public_key_ok(&attestation_key) {
            return Err(PairingError::Key("attestation key"));
        }
        // The pairing key is for this pairing only, so it is not the
        // attestation key (a choice; 4.8 does not say).
        if !x_wing_public_key_ok(&pairing_key) || pairing_key == attestation_key {
            return Err(PairingError::Key("pairing key"));
        }
        Ok(NewDeviceContent {
            keys: DeviceKeys {
                device_key: PublicKey::from_bytes(device_key),
                attestation_key,
                label,
            },
            pairing_key,
        })
    }
}

/// A NewDevice (4.8): its content, signed by the new device key with
/// RisalaSign under the label `pair`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewDevice {
    /// The keys.
    pub content: NewDeviceContent,
    /// RisalaSign(the device key, "pair", content).
    pub signature: Signature,
}

impl NewDevice {
    /// Signs `content` with the new device's device key: RisalaSign(key,
    /// "pair", content), hedged (4.3, 4.8). Fails if `key` is not the
    /// content's device key.
    pub fn sign(content: NewDeviceContent, key: &SigningKey) -> Result<NewDevice, PairingError> {
        let signature = risala_sign(key, PAIR_SIGN_LABEL, &content.encode());
        NewDevice::new(content, Signature::from_bytes(&signature))
    }

    /// A NewDevice from its content and a signature RisalaSign(device key,
    /// "pair", content). Fails if the signature does not verify, so a
    /// device never sends one that would be refused.
    pub fn new(content: NewDeviceContent, signature: Signature) -> Result<NewDevice, PairingError> {
        let new_device = NewDevice { content, signature };
        new_device.verify()?;
        Ok(new_device)
    }

    /// The encoded NewDevice, whose SHA-384 hash is the PairingCode's
    /// `keys_hash`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(PAIRING_VERSION);
        w.bytes(&self.content.encode());
        w.vector(self.signature.as_bytes());
        w.0.to_vec()
    }

    /// Reads an encoded NewDevice, and checks it: version 1, nothing after
    /// the signature, a device key of 1312 bytes, X-Wing keys that pass
    /// 12.2's checks and differ, a label of at most 64 bytes of UTF-8, and
    /// a signature that verifies under the device key in it.
    pub fn decode(bytes: &[u8]) -> Result<NewDevice, PairingError> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(PairingError::Version(version));
        }
        let content = NewDeviceContent::decode(&mut r)?;
        let signature: &[u8; SIGNATURE_LEN] = r
            .vector()?
            .try_into()
            .map_err(|_| PairingError::Malformed("signature"))?;
        r.end()?;
        NewDevice::new(content, Signature::from_bytes(signature))
    }

    fn verify(&self) -> Result<(), PairingError> {
        if risala_verify(
            self.content.keys.device_key.as_bytes(),
            PAIR_SIGN_LABEL,
            &self.content.encode(),
            self.signature.as_bytes(),
        ) {
            Ok(())
        } else {
            Err(PairingError::Signature)
        }
    }

    /// The SHA-384 hash of the encoding: a PairingCode's `keys_hash`.
    pub fn hash(&self) -> [u8; HASH_LEN] {
        sha384(&self.encode())
    }
}

/// A SealedBundle (4.8): an IdentityBundle sealed with HPKE to the new
/// device's pairing key.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBundle {
    /// The X-Wing encapsulated key.
    pub enc: [u8; ENC_LEN],
    /// The sealed IdentityBundle.
    pub ciphertext: Vec<u8>,
}

impl SealedBundle {
    /// The encoded SealedBundle, the data of `PAIR PUT old_id`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(PAIRING_VERSION);
        w.bytes(&self.enc);
        w.vector(&self.ciphertext);
        w.0.to_vec()
    }

    /// Reads an encoded SealedBundle: version 1, and nothing after the
    /// ciphertext.
    pub fn decode(bytes: &[u8]) -> Result<SealedBundle, PairingError> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(PairingError::Version(version));
        }
        let enc = r.array::<ENC_LEN>()?;
        let ciphertext = r.vector()?.to_vec();
        r.end()?;
        Ok(SealedBundle { enc, ciphertext })
    }
}

impl fmt::Debug for SealedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBundle")
            .field("ciphertext_len", &self.ciphertext.len())
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

/// A PairingCode (4.8): what the QR code holds.
///
/// ```text
/// struct {
///     uint8 version; opaque host<V>; opaque secret[32]; opaque keys_hash[48];
/// } PairingCode;
/// ```
///
/// TO MOVE: the PairingCode and its `RISALA-PAIR:` text form are task P2's,
/// in risala-proto. These are its bytes only, until that lands.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PairingCode {
    /// The server used for pairing, as a server address in its one
    /// written form (2.1), which may carry a port.
    pub host: ServerAddr,
    /// The one-time pairing secret.
    pub secret: PairingSecret,
    /// SHA-384 of the encoded NewDevice.
    pub keys_hash: [u8; HASH_LEN],
}

impl PairingCode {
    /// The code for pairing through `host`, with `secret`, for
    /// `new_device`.
    pub fn new(host: ServerAddr, secret: PairingSecret, new_device: &NewDevice) -> PairingCode {
        PairingCode {
            host,
            secret,
            keys_hash: new_device.hash(),
        }
    }

    /// The encoded code, wiped when dropped.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::default();
        w.u8(PAIRING_VERSION);
        w.vector(self.host.to_string().as_bytes());
        w.bytes(self.secret.as_bytes());
        w.bytes(&self.keys_hash);
        w.0
    }

    /// Reads an encoded code: version 1, a host that is a server address
    /// in its one written form (2.1), and nothing after the hash.
    pub fn decode(bytes: &[u8]) -> Result<PairingCode, PairingError> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(PairingError::Version(version));
        }
        let host = server_addr(r.vector()?, "host")?;
        let secret = PairingSecret(Zeroizing::new(r.array()?));
        let keys_hash = r.array()?;
        r.end()?;
        Ok(PairingCode {
            host,
            secret,
            keys_hash,
        })
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
    use crate::risala_sign::sign_content;
    use libcrux_ml_dsa::ml_dsa_44 as mldsa;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn secret() -> PairingSecret {
        PairingSecret::from_bytes(std::array::from_fn(|i| i as u8))
    }

    fn pairing_key(seed: u8) -> PairingKey {
        PairingKey::from_seed(Zeroizing::new([seed; 32]))
    }

    /// ML-DSA-44 with the deterministic variant, as a test signer, so that
    /// vectors stay fixed.
    fn ml_dsa(seed: u8) -> (PublicKey, impl Fn(&[u8]) -> Signature) {
        let pair = mldsa::generate_key_pair([seed; 32]);
        let public = PublicKey::from_bytes(pair.verification_key.as_ref());
        let sign = move |message: &[u8]| {
            let signature = mldsa::sign(&pair.signing_key, message, b"", [0; 32]).unwrap();
            Signature::from_bytes(signature.as_ref())
        };
        (public, sign)
    }

    fn content(device: u8, pairing: &PairingKey, label: &str) -> NewDeviceContent {
        NewDeviceContent {
            keys: DeviceKeys {
                device_key: ml_dsa(device).0,
                attestation_key: pairing_key(0xa7).public_key().to_vec(),
                label: label.to_owned(),
            },
            pairing_key: pairing.public_key().to_vec(),
        }
    }

    /// A NewDevice signed by device key `device`, with pairing key
    /// `pairing`.
    fn new_device(device: u8, pairing: &PairingKey) -> NewDevice {
        let content = content(device, pairing, "Alice's phone");
        let signature = ml_dsa(device).1(&sign_content("pair", &content.encode()));
        NewDevice::new(content, signature).unwrap()
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
    fn new_devices() {
        let pairing = pairing_key(3);
        let device = new_device(9, &pairing);
        let bytes = device.encode();
        assert_eq!(NewDevice::decode(&bytes), Ok(device.clone()));
        assert_eq!(bytes[0], 1);
        // The signed bytes: RisalaSignContent with `risala/1 pair`.
        let signed = sign_content("pair", &device.content.encode());
        assert_eq!(&signed[..14], b"\x0drisala/1 pair");
        let len = device.content.encode().len();
        assert_eq!(len, (2 + 1312) + (2 + 1216) + (1 + 13) + (2 + 1216));
        assert_eq!(&signed[14..16], &(0x4000 | len as u16).to_be_bytes());
        assert_eq!(&signed[16..], &device.content.encode()[..]);
        assert_eq!(device.hash(), sha384(&bytes));

        // Every truncation, and a byte too many.
        for n in 0..bytes.len() {
            assert!(NewDevice::decode(&bytes[..n]).is_err(), "cut at {n}");
        }
        assert!(NewDevice::decode(&[&bytes[..], &[0]].concat()).is_err());
        let mut b = bytes.clone();
        b[0] = 2;
        assert_eq!(NewDevice::decode(&b), Err(PairingError::Version(2)));

        // A changed signature, or one by another key, or over other
        // content.
        let mut b = bytes.clone();
        *b.last_mut().unwrap() ^= 1;
        assert_eq!(NewDevice::decode(&b), Err(PairingError::Signature));
        let other = ml_dsa(10).1(&signed);
        assert_eq!(
            NewDevice::new(device.content.clone(), other),
            Err(PairingError::Signature)
        );
        let mut relabelled = device.content.clone();
        relabelled.keys.label = "Mallory's phone".to_owned();
        assert_eq!(
            NewDevice::new(relabelled, device.signature.clone()),
            Err(PairingError::Signature)
        );
        // Signed without the label, or under another label.
        let raw = ml_dsa(9).1(&device.content.encode());
        assert_eq!(
            NewDevice::new(device.content.clone(), raw),
            Err(PairingError::Signature)
        );
        let record = ml_dsa(9).1(&sign_content("record", &device.content.encode()));
        assert_eq!(
            NewDevice::new(device.content.clone(), record),
            Err(PairingError::Signature)
        );

        // Field checks, each over a well-signed NewDevice.
        let build = |device_key: &[u8], attestation: &[u8], label: &[u8], pairing: &[u8]| {
            let mut c = Writer::default();
            c.vector(device_key);
            c.vector(attestation);
            c.vector(label);
            c.vector(pairing);
            let signature = ml_dsa(9).1(&sign_content("pair", &c.0));
            let mut w = Writer::default();
            w.u8(1);
            w.bytes(&c.0);
            w.vector(signature.as_bytes());
            NewDevice::decode(&w.0)
        };
        let dk = device.content.keys.device_key.as_bytes().to_vec();
        let ak = device.content.keys.attestation_key.clone();
        let pk = device.content.pairing_key.clone();
        assert_eq!(
            build(&dk, &ak, "Alice's phone".as_bytes(), &pk),
            Ok(device.clone())
        );
        assert!(build(&dk, &ak, &[b'x'; 64], &pk).is_ok());
        assert!(build(&dk, &ak, b"", &pk).is_ok());
        assert_eq!(
            build(&dk, &ak, &[b'x'; 65], &pk),
            Err(PairingError::Malformed("label"))
        );
        assert_eq!(
            build(&dk, &ak, b"\xff", &pk),
            Err(PairingError::Malformed("label"))
        );
        assert_eq!(
            build(&dk[..1311], &ak, b"", &pk),
            Err(PairingError::Malformed("device_key"))
        );
        let mut bad_x_wing = pk.clone();
        bad_x_wing[0] = 0xff;
        bad_x_wing[1] |= 0x0f;
        assert_eq!(
            build(&dk, &bad_x_wing, b"", &pk),
            Err(PairingError::Key("attestation key"))
        );
        assert_eq!(
            build(&dk, &ak[..1215], b"", &pk),
            Err(PairingError::Key("attestation key"))
        );
        assert_eq!(
            build(&dk, &ak, b"", &bad_x_wing),
            Err(PairingError::Key("pairing key"))
        );
        assert_eq!(
            build(&dk, &ak, b"", &[]),
            Err(PairingError::Key("pairing key"))
        );
        assert_eq!(
            build(&dk, &ak, b"", &ak),
            Err(PairingError::Key("pairing key"))
        );
        // A signature of another length.
        let mut w = Writer::default();
        w.u8(1);
        w.bytes(&device.content.encode());
        w.vector(&device.signature.as_bytes()[..2419]);
        assert_eq!(
            NewDevice::decode(&w.0),
            Err(PairingError::Malformed("signature"))
        );
    }

    #[test]
    fn new_device_message() {
        let device = new_device(9, &pairing_key(3));
        let new_device_bytes = device.encode();
        let code = PairingCode::new("example.org".parse().unwrap(), secret(), &device);
        let relay = code.secret.relay();
        let data = relay.seal_new_device(&new_device_bytes);
        // A SealedNewDevice: the version, the ciphertext's two-byte length,
        // then the ciphertext and its tag (4.8).
        assert_eq!(data.len(), 1 + 2 + new_device_bytes.len() + 16);
        assert_eq!(data[0], PAIRING_VERSION);
        assert_eq!(relay.open_new_device(&data, &code.keys_hash), Ok(device));
        // A repeated PAIR PUT sends the same bytes.
        assert_eq!(relay.seal_new_device(&new_device_bytes), data);
        // Swapped keys: the server swapped the NewDevice for another, even
        // a well-signed one.
        let other = relay.seal_new_device(&new_device(10, &pairing_key(4)).encode());
        assert_eq!(
            relay.open_new_device(&other, &code.keys_hash),
            Err(PairingError::Hash)
        );
        // Changed, under another secret, or without the associated data.
        let mut changed = data.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            relay.open_new_device(&changed, &code.keys_hash),
            Err(PairingError::Decrypt)
        );
        // Another version, bytes after the ciphertext, the bare ciphertext.
        let mut v2 = data.clone();
        v2[0] = 2;
        assert_eq!(
            relay.open_new_device(&v2, &code.keys_hash),
            Err(PairingError::Version(2))
        );
        let mut longer = data.clone();
        longer.push(0);
        assert!(matches!(
            relay.open_new_device(&longer, &code.keys_hash),
            Err(PairingError::Malformed(_))
        ));
        assert!(relay.open_new_device(&data[3..], &code.keys_hash).is_err());
        let stranger = PairingSecret::from_bytes([9; 32]).relay();
        assert_eq!(
            stranger.open_new_device(&data, &code.keys_hash),
            Err(PairingError::Decrypt)
        );
        let mut no_aad = Writer::default();
        no_aad.u8(PAIRING_VERSION);
        no_aad.vector(&seal(&relay.new_key, &ZERO_NONCE, b"", &new_device_bytes));
        let no_aad = no_aad.0.to_vec();
        assert_eq!(
            relay.open_new_device(&no_aad, &code.keys_hash),
            Err(PairingError::Decrypt)
        );
        // A hash that matches bytes that are not a NewDevice.
        let junk = relay.seal_new_device(b"\x01junk");
        assert!(matches!(
            relay.open_new_device(&junk, &sha384(b"\x01junk")),
            Err(PairingError::Malformed(_))
        ));
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
            enc: enc.try_into().unwrap(),
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
                enc: enc.try_into().unwrap(),
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
        assert_eq!(SealedBundle::decode(&b), Err(PairingError::Version(2)));
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

    #[test]
    fn pairing_codes() {
        let code = PairingCode {
            host: "chat.example.org".parse().unwrap(),
            secret: secret(),
            keys_hash: sha384(b"keys"),
        };
        let bytes = code.encode();
        assert_eq!(bytes.len(), 1 + 1 + 16 + 32 + 48);
        assert_eq!(PairingCode::decode(&bytes), Ok(code.clone()));
        for n in 0..bytes.len() {
            assert!(PairingCode::decode(&bytes[..n]).is_err());
        }
        assert!(PairingCode::decode(&[&bytes[..], &[0]].concat()).is_err());
        let mut b = bytes.to_vec();
        b[0] = 0;
        assert_eq!(PairingCode::decode(&b), Err(PairingError::Version(0)));
        let mut b = bytes.to_vec();
        b[2] = b'C';
        assert_eq!(
            PairingCode::decode(&b),
            Err(PairingError::Malformed("host"))
        );
        let mut b = bytes.to_vec();
        b[6] = b' ';
        assert_eq!(
            PairingCode::decode(&b),
            Err(PairingError::Malformed("host"))
        );
        // A host with a port other than 7472 (2.1, 4.8).
        let ported = PairingCode {
            host: "chat.example.org:7000".parse().unwrap(),
            ..code.clone()
        };
        assert_eq!(PairingCode::decode(&ported.encode()), Ok(ported));
    }

    /// The whole exchange, as two devices run it.
    #[test]
    fn exchange() {
        // The new device: its keys, a pairing key, a secret, the QR code.
        let key = PairingKey::generate().unwrap();
        let device_key = SigningKey::generate().unwrap();
        let content = NewDeviceContent {
            keys: DeviceKeys {
                device_key: PublicKey::from_bytes(device_key.public_key()),
                attestation_key: PairingKey::generate().unwrap().public_key().to_vec(),
                label: "laptop".to_owned(),
            },
            pairing_key: key.public_key().to_vec(),
        };
        // Signed by another key: refused.
        assert_eq!(
            NewDevice::sign(content.clone(), &SigningKey::from_seed([1; 32])),
            Err(PairingError::Signature)
        );
        let device = NewDevice::sign(content, &device_key).unwrap();
        let code = PairingCode::new(
            "example.org".parse().unwrap(),
            PairingSecret::generate().unwrap(),
            &device,
        );
        let relay = code.secret.relay();
        let put_new = (relay.new_id(), relay.seal_new_device(&device.encode()));
        let qr = code.encode();

        // The other device scans the code, checks the keys, and replies.
        let scanned = PairingCode::decode(&qr).unwrap();
        let theirs = scanned.secret.relay();
        assert_eq!(theirs.new_id(), put_new.0);
        let opened = theirs
            .open_new_device(&put_new.1, &scanned.keys_hash)
            .unwrap();
        assert_eq!(opened, device);
        let reply = theirs.seal_bundle(&bundle(true), &opened).unwrap();
        let put_old = (theirs.old_id(), reply.encode());

        // The new device polls the reply.
        assert_eq!(relay.old_id(), put_old.0);
        assert_eq!(relay.open_bundle(&put_old.1, &key), Ok(bundle(true)));
    }

    /// Fixed-input vectors for Appendix B: the secret 00 01 ... 1f, device
    /// key seed 09 ..., attestation key seed a7 ..., pairing key seed
    /// 03 ..., and the deterministic ML-DSA signature.
    #[test]
    fn vector() {
        let relay = secret().relay();
        let key = pairing_key(3);
        let device = new_device(9, &key);
        let code = PairingCode::new("example.org".parse().unwrap(), secret(), &device);
        let b = IdentityBundle {
            master_key: vec![0x50; MASTER_KEY_LEN],
            ..bundle(true)
        };
        let sealed_new = relay.seal_new_device(&device.encode());
        println!("secret         {}", hex(secret().as_bytes()));
        println!(
            "new_id         {} ({})",
            hex(relay.new_id().as_bytes()),
            relay.new_id()
        );
        println!("new_key        {}", hex(&relay.new_key[..]));
        println!(
            "old_id         {} ({})",
            hex(relay.old_id().as_bytes()),
            relay.old_id()
        );
        println!("old_key        {}", hex(&relay.old_key[..]));
        println!("pairing_key sha384 {}", hex(&sha384(key.public_key())));
        println!("NewDevice sha384   {}", hex(&device.hash()));
        println!("PairingCode    {}", hex(&code.encode()));
        println!("PAIR new sha384    {}", hex(&sha384(&sealed_new)));
        println!("bundle         {}", hex(&b.encode()));
        let sealed = relay.seal_bundle(&b, &device).unwrap().encode();
        println!("a SealedBundle {}", hex(&sealed));

        assert_eq!(
            [
                hex(relay.new_id().as_bytes()),
                hex(&relay.new_key[..]),
                hex(relay.old_id().as_bytes()),
                hex(&relay.old_key[..]),
                hex(&sha384(key.public_key())),
                hex(&device.hash()),
                hex(&sha384(&sealed_new)),
                hex(&sha384(&b.encode())),
            ],
            PAIRING_VECTOR
        );
        assert_eq!(relay.new_id().to_string(), "ha4vagarkj4o5s3qaiyfb4qlwi");
        // A SealedBundle made once, opened with the pairing key and the
        // secret.
        let fixed: Vec<u8> = (0..SEALED_BUNDLE_VECTOR.len() / 2)
            .map(|i| u8::from_str_radix(&SEALED_BUNDLE_VECTOR[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        assert_eq!(relay.open_bundle(&fixed, &key), Ok(b));
    }

    /// Appendix B.11: the keys and ids from the pairing secret, and a
    /// SealedBundle, checked against the appendix.
    #[test]
    fn appendix_b() {
        let mut ck = crate::appendix::Checker::open("B.11 ");
        let relay = secret().relay();
        let key = pairing_key(3);
        let b = IdentityBundle {
            master_key: vec![0x50; MASTER_KEY_LEN],
            ..bundle(true)
        };
        ck.hex("secret", secret().as_bytes());
        ck.hex("pairing key seed", &[3; 32]);
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
        ck.file("pairing key", "pairing-key.bin", key.public_key());
        let encoded = b.encode();
        ck.file("IdentityBundle", "identity-bundle.bin", &encoded);
        assert_eq!(IdentityBundle::decode(&encoded), Ok(b.clone()));
        let sealed = unhex(SEALED_BUNDLE_VECTOR);
        assert_eq!(relay.open_bundle(&sealed, &key), Ok(b.clone()));
        ck.file("a SealedBundle of it", "sealed-bundle.bin", &sealed);
        ck.gap();
        let mut version = sealed.clone();
        version[0] = 2;
        ck.rejected(
            "the SealedBundle with version 2",
            relay.open_bundle(&version, &key).is_err(),
        );
        let other = PairingSecret::from_bytes([1; 32]).relay();
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

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    const PAIRING_VECTOR: [&str; 8] = [
        "38395018115278eecb70023050f20bb2",
        "f730c19cdb093a583cf927c2e8dac3c2c45c75ee3f8b89dcd7a1ed16e4ad6931",
        "02cb56f3764824ee4fd02a9b9e1fa29d",
        "d7bd4cef94c09a4513dbaacbe8b1eaee53ad8dc9283a37be93943ab16e4eeaad",
        "4ed035344675972bf76955cc5ea6325bbd706eb205c8bdce9005db1848747829\
         c5e3a062ed8f861842998228a16ba507",
        "6724886199a6839cb44935a19138c3470964797ec10151f3527a3af44766f84b\
         61c5bef0775a4f412d844c2d3fde9e04",
        "a95c35fa425d3fbc4b6a8d6a2c47affe5dd4d82f0354c2a7166066a472539a86\
         628e71623e5f1d23a7258fa58da0112d",
        "b40b00f93adf73c5a83e2107f0c2955829bb80520f016565444a6effa3f24c81\
         4efe898183acbf5db3c12fc69c2a73f1",
    ];

    const SEALED_BUNDLE_VECTOR: &str = "010b4e73a6434919d0b3840121240f399b7fca5251a03f115a1a1597db418701\
    83d6436ae1c167f3449e9ba2a418fab52203628d632c4b50ef3564b3580bc783\
    b105cebe2d780c6b1da7fc48b6d218d9c8d7e2050b1caa7dc01cb416b3619831\
    302aea98cfc31294cd47bc67d5961608588b66b29b3b24d4ec2a74dd926c9411\
    1db36b4a255a149db0e4f6774e86b7e7068ba3aa31e64729fc7de4ca2808329f\
    c95fdb93b489782755257a7a26b2ea5ab3dc9f3dd2d1e151c66d9ec5931e6939\
    52d09e6666cb4fbdf2e292e8d726c60c7cbb1f580abf5e627a1de57fb429f6ac\
    e25c53e586adc3e44017a7e8897328eaccca6be4094c961e2fc5b3a9830785c0\
    8fdfb57a71c128c55a7c8813d3839d5f9196fa88a6572a5e320545753387557f\
    db5a529bb236a90bb87c18cbc7f3d885f7ebfeec75e9dfb463be3bf9aa370519\
    0759dd50b8c2e4297519f0d63f3636c82a53473f07435e44e9f872b8ef70c69a\
    25937314a71e60d08f8a7ca769bd7aa453c9346d92c90be2d2d18598939b7bef\
    14c5205bd78a470edc1188c04b9bf66ed05f7a9261ef177413d26a69af6afedd\
    8f73046ebfa27a808e3c898013df86b61469871382e667dba86fe9d5d935e364\
    14f445042528dc29ef8c80124f480d2c3363d4d27f2c33a1f9a938354e2c4a5e\
    404a4d6da32c6581dcdbcef0fd3eb0ef5b3b5c808db859ff9d979e37c5e98c88\
    5e63a75deabd0aa4da86dec32595106353d67266e8211df7c9c15ff37c04c931\
    01c6a6feac4a6513adb8d7155cfce1b85ac5508b52bc349a507d0a42700d221b\
    c67074235c944d8c813d20558c8ee8d2bfba05b2c4719c4849bf1add12a3cdcc\
    445ec9b2a704ace20d113bfc66650803462db31d206488008d6ddf1150c101be\
    954e1dbf47df548d2a372256b05fc12278db2f6a00acd5253c782333eda7cf76\
    a08268f8f8afaa7e6cf15df33e66a499d1a6e68d97eee42cbf6ad79065b01bd0\
    ea64f31a7969d8253dd238de39502ed8a9dc16c88e67c04d2844160d1bfe2c99\
    a3fefc306d8683610690eb1e7cb09efb69ee1d80084bd205382c1fe6715af045\
    03276bb0cff1ff4885209e79f4359826401b5e94cb9a01bfb9f1b252a9b5a87f\
    2c7baf6f593ba01841e0b88e0e2f6f2d207e34d8bc9f6152f6b075a1d9f0190b\
    f2c30aeb1d5d06175243551de73a9bbf0eecd1b8851bc4c72eb0e09881201a0d\
    23ba117067645d8a9ec9cf3ed9b3c887ccc55c7c383e634b5ddc570c7c099cf5\
    4bff510eb958a253989923570c3a9172259c85aca2e0c75bea7b74cb6df6a6dc\
    e506640a23120937b7ef0c94aaec22d46b32bde257b2d2350a9bc0a4633f5e36\
    b7427de4eae070fc008bfd46aee9ed082f282280c6dc7e258ff25463ee8c8dc8\
    766298847849ce140754faac469328b264d7c983a710af4cd1713a1f21e8b139\
    052fd69e64eba3eb1e2f7a1101ebfcac30b57d866b8e9e294f24334a3f675401\
    9a4a7e096926cf03357d9b044eaf36495568f98baa38a588e8204ea2d01ac108\
    f46b742bdfbb5d50a1d6282d7c654da2f23d9dc047358aace54c56dd9ed464c0\
    1a462a107032a84c4415b76f32d564b09b9a4c5178b91f87ffdb342b4926721c\
    246eba9a7a6fdc598774b687c4ec5d0f126928399df77396dc3377c71ffa0ff1\
    4bba25ef58407086d2f3a3965b83e908c0e03c104cea6f6237ca8bd68a445222\
    acaebfc98bd5fd92b2a2c7b0592d77a7b2a83085c1f4af677fa928819ad142f1\
    dcbf2e3a4d790eced6876e1213e61405f80fcfb6c1a54680120a427693a08ff7\
    6aa67263cd27f47be881215f32e812e27b2afc0892cdd37743646f274298ea1f\
    ca22c4046a324ce631af1af49afbcb00674438a592b7e7057e933e7335fe2223\
    3e16246f69801567bbd3bf96ab9ea70029e2c864872ce24a94235c5634c52f1e\
    3e1e6f616c593e96b90ce19ef356f48fb38f511aee2a08c78cad53d88a0901f7\
    95579eed4c2a0e6bc192f51be5cffc2655d232c9c98bb36eda47d8cd59f9d303\
    418c0ae1ca29d11faec33ac65ce74c2d181dc4a399fcf9b0e4ed541caa202cb3\
    8126b7421005fee4a1c1ed3b0e2162c62b15bf4809cf4c068adca194b695adce\
    37791a14d094663e7b191306c176fe23ac45549ebf3e26a0871eec9d200c707b\
    a26af578c48a92e7544c3d7d2f7f5c7b19e2d9cd64067388eded36351ca26a42\
    53978802073d4cc59e69a4bd5184135a9964b41fcc799cfd71ee0ac642583883\
    5122078cd947ae4502c06597f974dc7dc625a3bdd22ff007b2388300de2d64d4\
    063a3928bafb4c0c01496bee4e41efccde8e521f82b13aa7806621f1118316ac\
    c2e7eeff122c1520f5e791948174020201143958dd301a727cba1d850126dc6a\
    0c5f2ba29587613a9a85df2d7494e58a724715d850144ddae75be8ecb3e4069c\
    fee83bc7c25280009efe3decc9a420b40b9d467d6ba57299eb669262a31b09dc\
    af3deb489096360ef86552d78199f972c104f5e891cfac04d9241df5a9adbc1d\
    2050fc74781a004bf21776d60cc485c5fcb7b4f710296e15b38bc595c032e49d\
    33f563a2a11f21419583ad8b4232da12dd3934430907a604442720b8962d6133\
    274be7d30315ea177a71a9df858e55db67db8363f1aa2bd7d17f05ee9d277bc7\
    628c1103ab7689429fb0c9f4dffcc5de2a3eb7946806d7696eeaccf78a7ef238\
    d3f51d7e48e937762ead04acae892406463b1b38809eab0093d11852e1c80d2d\
    51b9e1f4a041a34a82261d22bdf7cacd107e5babe7c891dc69c50b0d3876bd85\
    ad6b16fdf8ce788437c2eb13bd5d1e6033893ade16c35ce9ccfe7786add93f1c\
    cf8d6bf263eebfb799ed6ed972e74a0d3c733f1ea0f69eeebbd597257af34c57\
    5133f947850144b9601a0edd75b581b6a37f3120a940755666e4baad16ebdd65\
    5e030be5855134815c0cfd669798d147bb5390770c0c68e63c750fde34286dd3\
    c27cc72fc719fe80b5f18e8f2781cfc379d078ec29004be20ef9ce06b8e2b270\
    2b968eb0432add1af7239f28cfea5caa0a31fa15fb6d655d9441e93224eb8a36\
    f981cf70363ad88709934c047d29165f9c5ba50fa55a9551c7d7f472511874cf\
    4ac5238cf9529a58f04df854e25055bb3a29229e5cd2c42694ba3a67a975d683\
    bd512d9d43e94f67d3ae2e2aa3b2963bc1b472cc9f5c6e70172696abab306a31\
    bd2f1e2ceaefc5c888e67b571673b27274f743cb828d8c30fb55996687a1a7bb\
    1716e8876cd4d6e0288e874f6542d719d264785be2499247ee93a69883200522\
    0173d4750de644db8e9c6622cf3180b3912c86e353f9f52a7dcf1b55c613cd2d\
    f08cfdf7fb33669d209b081b96841b63bfb9e1721f531abd20704d528f6092bb\
    8eac55204bf9385e94bfdd17586ba705c63d52fa493370e9721302302144d32e\
    a7dadb2fac45156929b2b7c9f69f40c67124ebd64502d32e6b0f4dbfd8230ec1\
    ca60b61d1c1f969a37edf53e36d26120867977f1aff5bd2494d4213355e3c0a5\
    3f3fd1176dee258e5885fee6264956bb9e10a23795d25d0e48d37b6b32b7ebc5\
    17dfa88627c126feb94096524279779de3b0821f1c76bb8c366d4dc9d9629673\
    6703e58b6f194ac22920b31e77f94b43772270c2ab965a8d0325411c9c5bf6a6\
    0326786639f49bd9c7f1a18b4b99704d016b8f075ab421518b2c21c66225e3cb\
    735ebd24ffe39ebad6234af31c3506cb04ae39e04cd1717d66774c79198ad55e\
    445fc9b3d504478a889085c8603528dec34be187bc8c63c03e2e935d67f331d9\
    27e190c24b38f91274073f1fcc";
}

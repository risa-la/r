//! Pairing a new device (4.8): the relay through `PAIR PUT/GET`, and the
//! IdentityBundle.
//!
//! The new device makes a one-time 32-byte pairing secret and shows it in
//! a QR code that never reaches the server. From it, both devices derive,
//! with PRK = HKDF-Extract("", secret) and HKDF-SHA384:
//!
//! - `new_id` = HKDF-Expand(PRK, "risala/1 pair new id", 16) and
//!   `new_key` = HKDF-Expand(PRK, "risala/1 pair new key", 32), for the
//!   new device's message, its encoded NewDevice;
//! - `old_id` and `old_key` the same way with `old`, for the reply, the
//!   encoded IdentityBundle.
//!
//! Each message is encrypted once, with ChaCha20-Poly1305 under its key, a
//! nonce of 12 zero bytes, and the associated data `risala/1 pair`. Each
//! key encrypts one message only, so the fixed nonce never repeats under
//! a key. Ids are written as boxes (3.5).
//!
//! ```text
//! struct {
//!     uint8 version; opaque uid<V>; opaque master_key<V>;
//!     opaque signing_seed[32]; uint32 backup_generation;
//!     opaque backup_key[32]; opaque record_hash[48]; opaque transfer<V>;
//! } IdentityBundle;
//! ```
//!
//! NewDevice holds a device record's DeviceKeys (4.4), which belong to the
//! key file code in risala-proto: here it is bytes, checked against the
//! PairingCode's `keys_hash`.

use std::fmt;

use risala_proto::names::{Domain, Identity};
use zeroize::Zeroizing;

use crate::archive::{ArchiveError, Reader, TRANSFER_REF_LEN, TransferRef, Writer};
use crate::backup::{BACKUP_KEY_LEN, BackupKey, base32_lower};
use crate::primitives::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, HASH_LEN, ct_eq, hkdf_expand, hkdf_extract, open, seal, sha384,
};

/// The length of a pairing secret (4.8).
pub const PAIRING_SECRET_LEN: usize = 32;

/// The length of a relay id (4.8).
pub const RELAY_ID_LEN: usize = 16;

/// The length of a device-signing key's seed (4.8).
pub const SIGNING_SEED_LEN: usize = 32;

/// The length of an ML-DSA-44 public key, the master key's (4.3).
pub const MASTER_KEY_LEN: usize = 1312;

/// The version of an IdentityBundle and a PairingCode (4.8).
pub const PAIRING_VERSION: u8 = 1;

/// The associated data of both pairing messages (4.8).
pub const PAIR_AAD: &[u8] = b"risala/1 pair";

const NEW_ID_LABEL: &[u8] = b"risala/1 pair new id";
const NEW_KEY_LABEL: &[u8] = b"risala/1 pair new key";
const OLD_ID_LABEL: &[u8] = b"risala/1 pair old id";
const OLD_KEY_LABEL: &[u8] = b"risala/1 pair old key";

/// Why a pairing message cannot be read (4.8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// The message does not decrypt: another secret, the other message,
    /// or it was changed.
    #[error("the pairing message does not decrypt")]
    Decrypt,
    /// The NewDevice's hash is not the PairingCode's `keys_hash`.
    #[error("the new device's keys do not match the QR code")]
    Hash,
    /// The structure names a version this device does not support (2.4).
    #[error("unsupported pairing version {0}")]
    Version(u8),
    /// The bytes are not the encoded structure.
    #[error("malformed {0}")]
    Malformed(&'static str),
}

impl From<ArchiveError> for PairingError {
    fn from(error: ArchiveError) -> PairingError {
        match error {
            ArchiveError::Malformed(what) => PairingError::Malformed(what),
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

    /// Encrypts the new device's encoded NewDevice, for `PAIR PUT new_id`.
    /// Call it once per secret.
    pub fn seal_new_device(&self, new_device: &[u8]) -> Vec<u8> {
        seal(&self.new_key, &ZERO_NONCE, PAIR_AAD, new_device)
    }

    /// Decrypts the data of `PAIR new_id`, and checks, in constant time,
    /// that its SHA-384 hash is the PairingCode's `keys_hash`. Gives the
    /// encoded NewDevice.
    pub fn open_new_device(
        &self,
        data: &[u8],
        keys_hash: &[u8; HASH_LEN],
    ) -> Result<Zeroizing<Vec<u8>>, PairingError> {
        let new_device =
            open(&self.new_key, &ZERO_NONCE, PAIR_AAD, data).ok_or(PairingError::Decrypt)?;
        if !ct_eq(&sha384(&new_device), keys_hash) {
            return Err(PairingError::Hash);
        }
        Ok(new_device)
    }

    /// Encrypts the IdentityBundle, for `PAIR PUT old_id`. Call it once
    /// per secret.
    pub fn seal_bundle(&self, bundle: &IdentityBundle) -> Vec<u8> {
        seal(&self.old_key, &ZERO_NONCE, PAIR_AAD, &bundle.encode())
    }

    /// Decrypts and reads the data of `PAIR old_id`.
    pub fn open_bundle(&self, data: &[u8]) -> Result<IdentityBundle, PairingError> {
        let plain =
            open(&self.old_key, &ZERO_NONCE, PAIR_AAD, data).ok_or(PairingError::Decrypt)?;
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
    /// The current backup key, with its generation (12.13).
    pub backup: BackupKey,
    /// SHA-384 of the new device's `device` record (4.4).
    pub record_hash: [u8; HASH_LEN],
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
        match &self.transfer {
            Some(transfer) => w.vector(&transfer.to_bytes()[..]),
            None => w.vector(&[]),
        }
        w.0
    }

    /// Reads an encoded bundle: version 1, a uid in lower case, a master
    /// key of 1312 bytes, a transfer that is empty or one TransferRef, and
    /// nothing after it.
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
    }
}

impl Eq for IdentityBundle {}

impl fmt::Debug for IdentityBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityBundle")
            .field("uid", &self.uid)
            .field("backup", &self.backup)
            .field("record_hash", &self.record_hash)
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
    /// The server used for pairing.
    pub host: Domain,
    /// The one-time pairing secret.
    pub secret: PairingSecret,
    /// SHA-384 of the encoded NewDevice.
    pub keys_hash: [u8; HASH_LEN],
}

impl PairingCode {
    /// The code for pairing through `host`, with `secret`, for the encoded
    /// NewDevice `new_device`.
    pub fn new(host: Domain, secret: PairingSecret, new_device: &[u8]) -> PairingCode {
        PairingCode {
            host,
            secret,
            keys_hash: sha384(new_device),
        }
    }

    /// The encoded code, wiped when dropped.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::default();
        w.u8(PAIRING_VERSION);
        w.vector(self.host.as_str().as_bytes());
        w.bytes(self.secret.as_bytes());
        w.bytes(&self.keys_hash);
        w.0
    }

    /// Reads an encoded code: version 1, a host in lower case, and
    /// nothing after the hash.
    pub fn decode(bytes: &[u8]) -> Result<PairingCode, PairingError> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(PairingError::Version(version));
        }
        let host = canonical::<Domain>(r.vector()?, "host")?;
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

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn secret() -> PairingSecret {
        PairingSecret::from_bytes(std::array::from_fn(|i| i as u8))
    }

    fn bundle(transfer: bool) -> IdentityBundle {
        IdentityBundle {
            uid: "alice@example.org".parse().unwrap(),
            master_key: (0..MASTER_KEY_LEN).map(|i| i as u8).collect(),
            signing_seed: Zeroizing::new([0x51; 32]),
            backup: BackupKey::from_bytes(2, [0x52; 32]),
            record_hash: [0x53; 48],
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

    #[test]
    fn new_device_message() {
        let new_device = b"\x01 the encoded NewDevice";
        let code = PairingCode::new("example.org".parse().unwrap(), secret(), new_device);
        let relay = code.secret.relay();
        let data = relay.seal_new_device(new_device);
        assert_eq!(data.len(), new_device.len() + 16);
        assert_eq!(
            relay
                .open_new_device(&data, &code.keys_hash)
                .unwrap()
                .as_slice(),
            new_device
        );
        // Swapped keys: the server swapped the NewDevice for another.
        let other = relay.seal_new_device(b"\x01 other keys");
        assert_eq!(
            relay.open_new_device(&other, &code.keys_hash),
            Err(PairingError::Hash)
        );
        // Changed, under another secret, or the reply in its place.
        let mut changed = data.clone();
        changed[0] ^= 1;
        assert_eq!(
            relay.open_new_device(&changed, &code.keys_hash),
            Err(PairingError::Decrypt)
        );
        let stranger = PairingSecret::from_bytes([9; 32]).relay();
        assert_eq!(
            stranger.open_new_device(&data, &code.keys_hash),
            Err(PairingError::Decrypt)
        );
        let reply = relay.seal_bundle(&bundle(false));
        assert_eq!(
            relay.open_new_device(&reply, &code.keys_hash),
            Err(PairingError::Decrypt)
        );
        assert_eq!(relay.open_bundle(&data), Err(PairingError::Decrypt));
        // Without associated data the tag differs.
        assert_ne!(seal(&relay.new_key, &ZERO_NONCE, b"", new_device), data);
    }

    #[test]
    fn bundles() {
        let relay = secret().relay();
        for transfer in [false, true] {
            let b = bundle(transfer);
            assert_eq!(IdentityBundle::decode(&b.encode()), Ok(b.clone()));
            let data = relay.seal_bundle(&b);
            assert_eq!(relay.open_bundle(&data), Ok(b.clone()));
            let mut changed = data.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert_eq!(relay.open_bundle(&changed), Err(PairingError::Decrypt));
        }
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
        // A master key of another length.
        let mut short = bundle(false);
        short.master_key.pop();
        let mut w = Writer::default();
        w.u8(1);
        w.vector(b"alice@example.org");
        w.vector(&short.master_key);
        let b = [
            &w.0[..],
            &bundle(false).encode()[1 + 18 + 2 + MASTER_KEY_LEN..],
        ]
        .concat();
        assert_eq!(
            IdentityBundle::decode(&b),
            Err(PairingError::Malformed("master_key"))
        );
        // A transfer that is neither empty nor 80 bytes.
        let without = bundle(false).encode().to_vec();
        let mut b = without[..without.len() - 1].to_vec();
        b.push(63);
        b.extend([0; 63]);
        assert_eq!(
            IdentityBundle::decode(&b),
            Err(PairingError::Malformed("transfer"))
        );
    }

    #[test]
    fn pairing_codes() {
        let code = PairingCode::new("chat.example.org".parse().unwrap(), secret(), b"keys");
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
    }

    /// The whole exchange, as two devices run it.
    #[test]
    fn exchange() {
        // The new device.
        let new_device = b"\x01 device keys";
        let code = PairingCode::new(
            "example.org".parse().unwrap(),
            PairingSecret::generate().unwrap(),
            new_device,
        );
        let relay = code.secret.relay();
        let put_new = (relay.new_id(), relay.seal_new_device(new_device));
        let qr = code.encode();

        // The other device scans the code.
        let scanned = PairingCode::decode(&qr).unwrap();
        let theirs = scanned.secret.relay();
        assert_eq!(theirs.new_id(), put_new.0);
        let keys = theirs
            .open_new_device(&put_new.1, &scanned.keys_hash)
            .unwrap();
        assert_eq!(keys.as_slice(), new_device);
        let put_old = (theirs.old_id(), theirs.seal_bundle(&bundle(true)));

        // The new device polls the reply.
        assert_eq!(relay.old_id(), put_old.0);
        assert_eq!(relay.open_bundle(&put_old.1), Ok(bundle(true)));
    }

    /// Fixed-input vectors for Appendix B: the secret 00 01 ... 1f.
    #[test]
    fn vector() {
        let relay = secret().relay();
        let new_device = b"\x01 NewDevice";
        let code = PairingCode::new("example.org".parse().unwrap(), secret(), new_device);
        let b = IdentityBundle {
            master_key: vec![0x50; MASTER_KEY_LEN],
            ..bundle(true)
        };
        let sealed_new = relay.seal_new_device(new_device);
        let sealed_bundle = relay.seal_bundle(&b);
        println!("secret       {}", hex(secret().as_bytes()));
        println!(
            "new_id       {} ({})",
            hex(relay.new_id().as_bytes()),
            relay.new_id()
        );
        println!("new_key      {}", hex(&relay.new_key[..]));
        println!(
            "old_id       {} ({})",
            hex(relay.old_id().as_bytes()),
            relay.old_id()
        );
        println!("old_key      {}", hex(&relay.old_key[..]));
        println!("PairingCode  {}", hex(&code.encode()));
        println!("NewDevice    {}", hex(new_device));
        println!("PAIR new     {}", hex(&sealed_new));
        println!("bundle sha384 {}", hex(&sha384(&b.encode())));
        println!("PAIR old sha384 {}", hex(&sha384(&sealed_bundle)));
        assert_eq!(
            hex(&code.encode()),
            "010b6578616d706c652e6f7267000102030405060708090a0b0c0d0e0f101112\
             131415161718191a1b1c1d1e1ffb88d7b2d51ff747bf4c9cacf0aa727529efd7\
             c8d029c372ad9f7b9d48e6ddaf0f5bc468caff4d38850eb33565fda730"
        );
        assert_eq!(
            hex(&sha384(&b.encode())),
            "7c3fc017d5743972610088f123acc7f3ac57ee217496ca0fd972b49c99f0c439\
             dbdb6c352cf25d82d6bb59a92a186f79"
        );
        assert_eq!(relay.new_id().to_string(), "ha4vagarkj4o5s3qaiyfb4qlwi");
        assert_eq!(
            [
                hex(relay.new_id().as_bytes()),
                hex(&relay.new_key[..]),
                hex(relay.old_id().as_bytes()),
                hex(&relay.old_key[..]),
                hex(&sealed_new),
                hex(&sha384(&sealed_bundle)),
            ],
            PAIRING_VECTOR
        );
    }

    const PAIRING_VECTOR: [&str; 6] = [
        "38395018115278eecb70023050f20bb2",
        "f730c19cdb093a583cf927c2e8dac3c2c45c75ee3f8b89dcd7a1ed16e4ad6931",
        "02cb56f3764824ee4fd02a9b9e1fa29d",
        "d7bd4cef94c09a4513dbaacbe8b1eaee53ad8dc9283a37be93943ab16e4eeaad",
        "ab91e54da2f8983e3f7758888bfd3bd4a54737f1e5da32889bad78",
        "93f836ade21986d3f7dde9320fda1a2c3d9b3321ac68e62600083214a993dbaf\
         b8cc79b286663a6f052bd847abbe70f2",
    ];
}

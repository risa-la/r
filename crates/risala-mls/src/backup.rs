//! Recovery keys and backups of history keys (12.10).
//!
//! - A **recovery key** is 32 random bytes. People see it as 52 characters
//!   of lower-case base32 [RFC4648] in groups of four, and type it back
//!   ignoring case, spaces and `-`. Devices send it to each other as a
//!   RECOVERY line, in base64.
//! - The **backup key** is HKDF-Expand(HKDF-Extract("", recovery key),
//!   "risala backup " + uid, 32) with SHA-384. Its key id is the first 8
//!   bytes of its SHA-384 hash.
//! - A **blob** holds one history key: the key id, a random 12-byte nonce,
//!   then the history key encrypted with ChaCha20-Poly1305 under the
//!   backup key, with the conversation's id, a space and the epoch as the
//!   associated data. It is 84 bytes.
//! - The **recovery signing key** is the ML-DSA-44 key whose seed is
//!   HKDF-Expand(HKDF-Extract("", recovery key), "risala identity " + uid,
//!   32) with SHA-384, the same shape as the backup key (PLAN.md 43). It
//!   lets the recovery key restore the identity once every device is lost.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::auth::{SEED_LEN, SecretKey};
use risala_proto::mls::{
    BACKUP_BLOB_LEN, BACKUP_INFO_PREFIX, BackupBlob, HISTORY_KEY_LEN, RECOVERY_SIGNING_INFO_PREFIX,
};
use risala_proto::names::{Id, Identity};
use zeroize::Zeroizing;

use crate::history::HistoryKey;
use crate::primitives::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, hkdf_expand, hkdf_extract, open, random, seal, sha384,
};

/// The length of a recovery key (12.10).
pub const RECOVERY_KEY_LEN: usize = 32;

/// The length of a recovery key as people see it, without spaces: 52
/// characters of base32 (12.10).
pub const RECOVERY_KEY_BASE32_LEN: usize = 52;

/// The length of a backup key's key id (12.10).
pub const KEY_ID_LEN: usize = 8;

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Why a typed recovery key cannot be read (12.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryKeyError {
    /// It has another number of characters than 52, after leaving out
    /// spaces and `-`.
    #[error("a recovery key has 52 characters")]
    Length,
    /// It has a character that is not base32, or ends in one that cannot
    /// end a key, so it was mistyped.
    #[error("a recovery key has only the letters a to z and digits 2 to 7")]
    Character,
}

/// A recovery key (12.10): 32 bytes, wiped when dropped. `Debug` does not
/// show it.
#[derive(Clone)]
pub struct RecoveryKey(Box<Zeroizing<[u8; RECOVERY_KEY_LEN]>>);

impl RecoveryKey {
    /// A new random recovery key.
    pub fn generate() -> Result<RecoveryKey, getrandom::Error> {
        let mut bytes = Zeroizing::new([0; RECOVERY_KEY_LEN]);
        getrandom::fill(&mut bytes[..])?;
        Ok(RecoveryKey(Box::new(bytes)))
    }

    /// A recovery key from its bytes.
    pub fn from_bytes(bytes: [u8; RECOVERY_KEY_LEN]) -> RecoveryKey {
        RecoveryKey(Box::new(Zeroizing::new(bytes)))
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_LEN] {
        &self.0
    }

    /// The key as people see it (12.10): 52 characters of lower-case
    /// base32 without padding, in 13 groups of four separated by spaces.
    pub fn to_display(&self) -> Zeroizing<String> {
        let plain = base32_lower(&self.0[..]);
        let mut out = Zeroizing::new(String::with_capacity(RECOVERY_KEY_BASE32_LEN + 12));
        for (i, group) in plain.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(std::str::from_utf8(group).expect("base32 is ASCII"));
        }
        out
    }

    /// Reads a key a person typed (12.10), ignoring case, spaces and `-`.
    pub fn parse(typed: &str) -> Result<RecoveryKey, RecoveryKeyError> {
        let mut bits: u64 = 0;
        let mut count = 0;
        let mut filled = 0;
        let mut written = 0;
        let mut out = Zeroizing::new([0; RECOVERY_KEY_LEN]);
        for c in typed.bytes().filter(|&c| c != b' ' && c != b'-') {
            if count == RECOVERY_KEY_BASE32_LEN {
                return Err(RecoveryKeyError::Length);
            }
            let value = BASE32
                .iter()
                .position(|&b| b == c.to_ascii_lowercase())
                .ok_or(RecoveryKeyError::Character)?;
            bits = (bits << 5) | value as u64;
            filled += 5;
            count += 1;
            if filled >= 8 {
                filled -= 8;
                // 52 characters fill exactly 32 bytes.
                out[written] = (bits >> filled) as u8;
                written += 1;
                bits &= (1 << filled) - 1;
            }
        }
        if count != RECOVERY_KEY_BASE32_LEN {
            return Err(RecoveryKeyError::Length);
        }
        // 52 characters carry 260 bits: the last 4 are zero in a key.
        if bits != 0 {
            return Err(RecoveryKeyError::Character);
        }
        zeroize::Zeroize::zeroize(&mut bits);
        Ok(RecoveryKey(Box::new(out)))
    }

    /// The key as on a RECOVERY line, in base64 with padding (12.8, 12.10).
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(&self.0[..]))
    }

    /// Reads a key from a RECOVERY line: exactly 32 bytes in strict base64
    /// with padding.
    pub fn from_base64(text: &str) -> Option<RecoveryKey> {
        if text.len() != 44 || !risala_proto::mls::is_strict_base64(text) {
            return None;
        }
        let mut out = Zeroizing::new([0; RECOVERY_KEY_LEN]);
        match BASE64.decode_slice(text, &mut out[..]) {
            Ok(RECOVERY_KEY_LEN) => Some(RecoveryKey(Box::new(out))),
            _ => None,
        }
    }

    /// HKDF-Expand(HKDF-Extract("", recovery key), prefix + uid, N) with
    /// SHA-384.
    fn derive<const N: usize>(&self, prefix: &str, uid: &Identity) -> Zeroizing<[u8; N]> {
        let prk = hkdf_extract(b"", &self.0[..]);
        let info = [prefix.as_bytes(), uid.as_str().as_bytes()].concat();
        let mut out = Zeroizing::new([0; N]);
        hkdf_expand(&prk[..], &info, &mut out[..]);
        out
    }

    /// The backup key of `uid`'s backups (12.10).
    pub fn backup_key(&self, uid: &Identity) -> BackupKey {
        let key = self.derive::<AEAD_KEY_LEN>(BACKUP_INFO_PREFIX, uid);
        let id = sha384(&key[..])[..KEY_ID_LEN]
            .try_into()
            .expect("a hash is longer than a key id");
        BackupKey { key, id }
    }

    /// The recovery signing key of `uid` (PLAN.md 43): the ML-DSA-44 key
    /// whose seed is derived from the recovery key with the info
    /// `risala identity <uid>`.
    pub fn signing_key(&self, uid: &Identity) -> SecretKey {
        let seed = self.derive::<SEED_LEN>(RECOVERY_SIGNING_INFO_PREFIX, uid);
        // from_seed wipes the copy it is given, and `seed` is wiped on drop.
        SecretKey::from_seed(*seed)
    }
}

/// Constant-time, since the key is secret.
impl PartialEq for RecoveryKey {
    fn eq(&self, other: &RecoveryKey) -> bool {
        crate::primitives::ct_eq(&self.0[..], &other.0[..])
    }
}

impl Eq for RecoveryKey {}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(…)")
    }
}

/// Lower-case base32 [RFC4648] without padding.
fn base32_lower(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    let mut bits: u32 = 0;
    let mut filled = 0;
    for &b in bytes {
        bits = (bits << 8) | u32::from(b);
        filled += 8;
        while filled >= 5 {
            filled -= 5;
            out.push(char::from(BASE32[((bits >> filled) & 31) as usize]));
        }
        bits &= (1 << filled) - 1;
    }
    if filled > 0 {
        out.push(char::from(BASE32[((bits << (5 - filled)) & 31) as usize]));
    }
    out
}

/// Why a blob does not give a history key (12.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    /// The blob was made with another backup key: skip it. If no blob of a
    /// conversation matches, the recovery key is wrong.
    #[error("the blob is for another backup key")]
    OtherKey,
    /// The blob has this key's id but does not decrypt for this
    /// conversation and epoch.
    #[error("the blob does not decrypt")]
    Decrypt,
}

/// The key that encrypts an identity's backups (12.10). Wiped when
/// dropped.
pub struct BackupKey {
    key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    id: [u8; KEY_ID_LEN],
}

impl BackupKey {
    /// The key id, the first 8 bytes of every blob it makes.
    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.id
    }

    /// Encrypts the history key of `epoch` of conversation `conv` into a
    /// blob, for BACKUP ADD (12.10).
    pub fn seal(
        &self,
        conv: &Id,
        epoch: u64,
        history_key: &HistoryKey,
    ) -> Result<BackupBlob, getrandom::Error> {
        Ok(self.seal_with_nonce(conv, epoch, history_key, random()?))
    }

    fn seal_with_nonce(
        &self,
        conv: &Id,
        epoch: u64,
        history_key: &HistoryKey,
        nonce: [u8; AEAD_NONCE_LEN],
    ) -> BackupBlob {
        let ciphertext = seal(
            &self.key,
            &nonce,
            &associated_data(conv, epoch),
            history_key.as_bytes(),
        );
        let mut blob = [0; BACKUP_BLOB_LEN];
        blob[..KEY_ID_LEN].copy_from_slice(&self.id);
        blob[KEY_ID_LEN..KEY_ID_LEN + AEAD_NONCE_LEN].copy_from_slice(&nonce);
        blob[KEY_ID_LEN + AEAD_NONCE_LEN..].copy_from_slice(&ciphertext);
        BackupBlob::from_bytes(blob)
    }

    /// The history key of `epoch` of conversation `conv` in a blob from
    /// BACKUP GET (12.10).
    pub fn open(
        &self,
        conv: &Id,
        epoch: u64,
        blob: &BackupBlob,
    ) -> Result<HistoryKey, BackupError> {
        if blob.key_id() != &self.id {
            return Err(BackupError::OtherKey);
        }
        let bytes = blob.as_bytes();
        let nonce: [u8; AEAD_NONCE_LEN] = bytes[KEY_ID_LEN..KEY_ID_LEN + AEAD_NONCE_LEN]
            .try_into()
            .expect("a blob holds a nonce");
        let plaintext = open(
            &self.key,
            &nonce,
            &associated_data(conv, epoch),
            &bytes[KEY_ID_LEN + AEAD_NONCE_LEN..],
        )
        .ok_or(BackupError::Decrypt)?;
        let key: [u8; HISTORY_KEY_LEN] = plaintext[..]
            .try_into()
            .expect("a blob's ciphertext is one history key long");
        Ok(HistoryKey::from_bytes(key))
    }
}

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupKey")
            .field("key_id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The associated data of a blob: the conversation's id, a space and the
/// epoch, in ASCII (12.10).
fn associated_data(conv: &Id, epoch: u64) -> Vec<u8> {
    format!("{} {epoch}", conv.as_str()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hmac_sha384;

    fn identity() -> Identity {
        "alice@example.org".parse().unwrap()
    }

    /// RFC 4648, section 10, in lower case without padding.
    #[test]
    fn base32() {
        for (input, output) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(*base32_lower(input.as_bytes()), output);
        }
    }

    #[test]
    fn display_and_parse() {
        let key = RecoveryKey::from_bytes(std::array::from_fn(|i| i as u8 * 7 + 3));
        let shown = key.to_display();
        assert_eq!(shown.len(), 52 + 12);
        let groups: Vec<&str> = shown.split(' ').collect();
        assert_eq!(groups.len(), 13);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(shown.bytes().all(|c| c == b' ' || BASE32.contains(&c)));
        assert_eq!(RecoveryKey::parse(&shown), Ok(key.clone()));

        // Case, spaces and `-` are ignored.
        let typed = shown.to_uppercase().replace(' ', "-");
        assert_eq!(RecoveryKey::parse(&typed), Ok(key.clone()));
        let squashed: String = shown.split(' ').collect();
        assert_eq!(RecoveryKey::parse(&squashed), Ok(key.clone()));
        assert_eq!(
            RecoveryKey::parse(&format!(" {squashed} ")),
            Ok(key.clone())
        );

        // Too short or long, letters outside base32, and a last character
        // with bits a key cannot have.
        assert_eq!(
            RecoveryKey::parse(&squashed[..51]),
            Err(RecoveryKeyError::Length)
        );
        assert_eq!(
            RecoveryKey::parse(&format!("{squashed}a")),
            Err(RecoveryKeyError::Length)
        );
        assert_eq!(RecoveryKey::parse(""), Err(RecoveryKeyError::Length));
        let mut bad = squashed.clone();
        bad.replace_range(0..1, "1");
        assert_eq!(RecoveryKey::parse(&bad), Err(RecoveryKeyError::Character));
        let mut bad = squashed.clone();
        bad.replace_range(51..52, "b");
        assert_eq!(RecoveryKey::parse(&bad), Err(RecoveryKeyError::Character));

        // Random keys survive the round trip.
        for _ in 0..50 {
            let key = RecoveryKey::generate().unwrap();
            assert_eq!(RecoveryKey::parse(&key.to_display()), Ok(key));
        }
        assert_eq!(format!("{key:?}"), "RecoveryKey(…)");
    }

    #[test]
    fn base64_round_trip() {
        let key = RecoveryKey::from_bytes([0xab; 32]);
        let text = key.to_base64();
        assert_eq!(text.len(), 44);
        assert_eq!(RecoveryKey::from_base64(&text), Some(key));
        assert_eq!(RecoveryKey::from_base64(&text[..40]), None);
    }

    /// The backup key and the recovery signing key, checked against HKDF
    /// written out with HMAC: for one block, HKDF-Expand(prk, info, L) is
    /// the first L bytes of HMAC(prk, info || 0x01) [RFC5869].
    #[test]
    fn key_derivation() {
        let recovery = RecoveryKey::from_bytes([0x11; 32]);
        let prk = hmac_sha384(&[0; 48], recovery.as_bytes());

        let backup = recovery.backup_key(&identity());
        let expected = hmac_sha384(&prk, b"risala backup alice@example.org\x01");
        assert_eq!(&backup.key[..], &expected[..32]);
        assert_eq!(backup.key_id(), &sha384(&expected[..32])[..8]);

        let seed = hmac_sha384(&prk, b"risala identity alice@example.org\x01");
        let signing = recovery.signing_key(&identity());
        assert_eq!(
            signing.public_key(),
            SecretKey::from_seed(seed[..32].try_into().unwrap()).public_key()
        );
        // Deterministic, and different for another uid or recovery key.
        assert_eq!(
            signing.public_key(),
            recovery.signing_key(&identity()).public_key()
        );
        let bob: Identity = "bob@example.org".parse().unwrap();
        assert_ne!(
            signing.public_key(),
            recovery.signing_key(&bob).public_key()
        );
        assert_ne!(recovery.backup_key(&bob).key_id(), backup.key_id());
        let other = RecoveryKey::from_bytes([0x12; 32]);
        assert_ne!(
            signing.public_key(),
            other.signing_key(&identity()).public_key()
        );
    }

    #[test]
    fn blobs() {
        let backup = RecoveryKey::from_bytes([0x11; 32]).backup_key(&identity());
        let conv: Id = "d7hq2klm".parse().unwrap();
        let history_key = HistoryKey::from_bytes([0x42; 48]);

        let blob = backup.seal(&conv, 3, &history_key).unwrap();
        assert_eq!(blob.key_id(), backup.key_id());
        assert_eq!(blob.to_string().len(), 112);
        assert_eq!(backup.open(&conv, 3, &blob), Ok(history_key.clone()));
        // Each blob has its own nonce.
        assert_ne!(backup.seal(&conv, 3, &history_key).unwrap(), blob);

        // Fixed nonce: the layout of 12.10.
        let fixed = backup.seal_with_nonce(&conv, 3, &history_key, [7; 12]);
        let bytes = fixed.as_bytes();
        assert_eq!(&bytes[..8], backup.key_id());
        assert_eq!(&bytes[8..20], &[7; 12]);
        let expected = seal(&backup.key, &[7; 12], b"d7hq2klm 3", history_key.as_bytes());
        assert_eq!(&bytes[20..], &expected[..]);

        // Another epoch or conversation, a flipped bit, or another key.
        assert_eq!(backup.open(&conv, 4, &blob), Err(BackupError::Decrypt));
        assert_eq!(
            backup.open(&"other".parse().unwrap(), 3, &blob),
            Err(BackupError::Decrypt)
        );
        let mut bytes = *blob.as_bytes();
        bytes[30] ^= 1;
        assert_eq!(
            backup.open(&conv, 3, &BackupBlob::from_bytes(bytes)),
            Err(BackupError::Decrypt)
        );
        let other = RecoveryKey::from_bytes([0x12; 32]).backup_key(&identity());
        assert_eq!(other.open(&conv, 3, &blob), Err(BackupError::OtherKey));
    }
}

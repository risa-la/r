//! Recovery keys and the master key derived from them (SPEC 4.3, 4.8).
//!
//! A recovery key is 32 random bytes that the person writes down. The
//! identity's master key, an ML-DSA-44 key, is derived from it:
//!
//! ```text
//! seed = HKDF-Expand(HKDF-Extract("", recovery key), "risala/1 identity " || uid, 32)
//! ```
//!
//! with SHA-384 \[RFC5869\]. Clients show the recovery key as 52
//! characters of lower-case base32 in groups of four.

use std::fmt;

use zeroize::Zeroizing;

use crate::auth::{PublicKey, SEED_LEN, SecretKey};
use crate::chain::Chain;
use crate::error::ParseError;
use crate::names::Identity;

/// The length of a recovery key (4.8).
pub const RECOVERY_KEY_LEN: usize = 32;

/// The length of a recovery key in base32, without spaces (4.8).
pub const RECOVERY_KEY_CHARS: usize = 52;

/// The HKDF info prefix of the master key, followed by the uid (4.8, 15).
pub const IDENTITY_INFO_PREFIX: &str = "risala/1 identity ";

/// The length of HKDF-SHA384's PRK.
const PRK_LEN: usize = 48;

/// An identity's recovery key (4.3, 4.8). It is wiped from memory when
/// dropped, and `Debug` does not show it.
#[derive(Clone)]
pub struct RecoveryKey(Box<Zeroizing<[u8; RECOVERY_KEY_LEN]>>);

impl RecoveryKey {
    /// The key from its 32 bytes. To make a new one, pass 32 bytes from a
    /// cryptographically secure random source.
    pub fn from_bytes(bytes: [u8; RECOVERY_KEY_LEN]) -> RecoveryKey {
        let mut bytes = Zeroizing::new(bytes);
        let mut key: Box<Zeroizing<[u8; RECOVERY_KEY_LEN]>> = Box::default();
        key.copy_from_slice(&bytes[..]);
        zeroize::Zeroize::zeroize(&mut *bytes);
        RecoveryKey(key)
    }

    /// The 32 bytes.
    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_LEN] {
        &self.0
    }

    /// The key as clients show it (4.8): 52 characters of lower-case
    /// base32 without padding, in groups of four separated by spaces.
    pub fn to_text(&self) -> Zeroizing<String> {
        let plain = Zeroizing::new(crate::base32::encode(&self.0[..], false));
        let mut out = Zeroizing::new(String::with_capacity(RECOVERY_KEY_CHARS + 12));
        for (i, c) in plain.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }

    /// Reads a recovery key that a user typed (4.8), ignoring case, spaces
    /// and `-`. It must be 52 characters of base32 whose last 4 bits are
    /// zero.
    pub fn parse(text: &str) -> Result<RecoveryKey, ParseError> {
        const BAD: ParseError = ParseError::BadSyntax("a recovery key is 52 characters of base32");
        let plain: Zeroizing<String> = Zeroizing::new(
            text.chars()
                .filter(|&c| c != ' ' && c != '-')
                .map(|c| c.to_ascii_lowercase())
                .collect(),
        );
        if plain.len() != RECOVERY_KEY_CHARS {
            return Err(BAD);
        }
        let bytes = Zeroizing::new(crate::base32::decode(&plain, false).ok_or(BAD)?);
        let bytes: [u8; RECOVERY_KEY_LEN] = bytes[..].try_into().map_err(|_| BAD)?;
        Ok(RecoveryKey::from_bytes(bytes))
    }

    /// The master key of `uid` that this recovery key gives (4.8).
    pub fn master_key(&self, uid: &Identity) -> SecretKey {
        let mut prk = Zeroizing::new([0u8; PRK_LEN]);
        libcrux_hkdf::extract(
            libcrux_hkdf::Algorithm::Sha384,
            &mut prk[..],
            b"",
            &self.0[..],
        )
        .expect("the PRK is one hash long");
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        let info = format!("{IDENTITY_INFO_PREFIX}{uid}");
        libcrux_hkdf::expand(
            libcrux_hkdf::Algorithm::Sha384,
            &mut seed[..],
            &prk[..],
            info.as_bytes(),
        )
        .expect("32 bytes is within HKDF-Expand's limit");
        SecretKey::from_seed(*seed)
    }

    /// The master key this recovery key gives for the identity of
    /// `chain`, if its public key is the chain's current master key. A
    /// device checks this before it uses the key for anything, and tells
    /// the user that the recovery key is wrong if not (4.8).
    pub fn master_key_for(&self, chain: &Chain) -> Option<SecretKey> {
        let key = self.master_key(chain.uid());
        (key.public_key() == *chain.master_key()).then_some(key)
    }

    /// The master public key this recovery key gives for `uid`.
    pub fn master_public_key(&self, uid: &Identity) -> PublicKey {
        self.master_key(uid).public_key()
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

impl PartialEq for RecoveryKey {
    /// Compares in constant time.
    fn eq(&self, other: &RecoveryKey) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl Eq for RecoveryKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trip() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8 * 7 + 3;
        }
        let key = RecoveryKey::from_bytes(bytes);
        let text = key.to_text();
        assert_eq!(text.len(), 52 + 12);
        assert_eq!(text.split(' ').count(), 13);
        assert!(text.split(' ').all(|g| g.len() == 4));
        assert_eq!(RecoveryKey::parse(&text).unwrap(), key);
        // Case, spaces and hyphens are ignored.
        let typed = text.to_uppercase().replace(' ', "-");
        assert_eq!(RecoveryKey::parse(&typed).unwrap(), key);
        let squashed: String = text.chars().filter(|&c| c != ' ').collect();
        assert_eq!(RecoveryKey::parse(&squashed).unwrap(), key);
    }

    #[test]
    fn rejects_bad_text() {
        let key = RecoveryKey::from_bytes([0xff; 32]);
        let text: String = key.to_text().chars().filter(|&c| c != ' ').collect();
        // The last character carries 1 bit of the key and 4 zero bits.
        assert!(text.ends_with('q'));
        let mut bad = text.clone();
        bad.replace_range(51.., "r");
        assert!(RecoveryKey::parse(&bad).is_err());
        assert!(RecoveryKey::parse(&text[..51]).is_err());
        assert!(RecoveryKey::parse(&format!("{text}a")).is_err());
        let mut bad = text.clone();
        bad.replace_range(0..1, "1");
        assert!(RecoveryKey::parse(&bad).is_err());
        assert!(RecoveryKey::parse(&format!("{text}\t")).is_err());
    }

    #[test]
    fn master_key_depends_on_uid_and_key() {
        let key = RecoveryKey::from_bytes([1; 32]);
        let alice: Identity = "alice@example.org".parse().unwrap();
        let bob: Identity = "bob@example.org".parse().unwrap();
        let a = key.master_public_key(&alice);
        assert_eq!(a, key.master_public_key(&alice));
        assert_ne!(a, key.master_public_key(&bob));
        assert_ne!(
            a,
            RecoveryKey::from_bytes([2; 32]).master_public_key(&alice)
        );
        assert_eq!(format!("{key:?}"), "RecoveryKey(..)");
    }
}

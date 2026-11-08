//! Bearer secrets: values that work for whoever holds them, such as guest
//! tokens (4.2), send tokens (7.2), the `put`, `get` and `del` URLs of
//! uploads and blobs (5.6, 12.12) and pairing ids (4.8).
//!
//! Section 14 ("Server secrets") and PLAN.md item 58 ask that the server
//! keep only a hash of each, look it up by a part that is not secret, and
//! compare the secret part in constant time:
//!
//! - **Store** a [`SecretHash`] (SHA-384 of the secret), never the secret.
//! - **Look up** by something that is not secret: a guest's name, a
//!   mailbox and epoch, the public half of a URL. Where the whole value is
//!   secret, as with pairing ids, look up by its [`SecretHash`]: an index
//!   lookup can leak timing about the hash, which says nothing useful
//!   about the secret.
//! - **Compare** with [`SecretHash::matches`] or [`ct_eq`], which take the
//!   same time wherever two values differ.
//!
//! New secrets come from [`random_token`] and [`random_bytes`], both from
//! the operating system's secure source.

use std::fmt;

use sha2::{Digest as _, Sha384};

/// The length of a [`SecretHash`]: SHA-384.
pub const SECRET_HASH_LEN: usize = 48;

/// The SHA-384 hash of a bearer secret, which is what the server stores in
/// its place.
///
/// Equality is in constant time, and `Debug` leaves the hash out.
#[derive(Clone, Copy)]
pub struct SecretHash([u8; SECRET_HASH_LEN]);

impl SecretHash {
    /// The hash of `secret`.
    pub fn of(secret: &[u8]) -> SecretHash {
        SecretHash(Sha384::digest(secret).into())
    }

    /// A stored hash, read back. `None` if it is not 48 bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<SecretHash> {
        bytes.try_into().ok().map(SecretHash)
    }

    /// A hash from its bytes.
    pub const fn from_bytes(bytes: [u8; SECRET_HASH_LEN]) -> SecretHash {
        SecretHash(bytes)
    }

    /// The hash, to store.
    pub const fn as_bytes(&self) -> &[u8; SECRET_HASH_LEN] {
        &self.0
    }

    /// Whether `secret` hashes to this, compared in constant time.
    pub fn matches(&self, secret: &[u8]) -> bool {
        *self == SecretHash::of(secret)
    }
}

impl PartialEq for SecretHash {
    fn eq(&self, other: &SecretHash) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for SecretHash {}

impl fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretHash(..)")
    }
}

/// Whether `a` and `b` are equal, in time that depends only on their
/// lengths, not on where they differ. Lengths are not secret here: every
/// value compared this way has a fixed length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a
        .iter()
        .zip(b)
        .fold(0u8, |acc, (x, y)| acc | std::hint::black_box(x ^ y));
    std::hint::black_box(diff) == 0
}

/// The characters of a [`random_token`]: lower-case letters and digits,
/// which are valid in an id (3.5), in a URL path and in a tag value.
const TOKEN_ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// The fewest characters a [`random_token`] has: 25 characters of 36 carry
/// over 129 bits, more than the 128 the spec asks of guest tokens (4.2)
/// and capability URLs (5.6).
pub const MIN_TOKEN_LEN: usize = 25;

/// A new secret of `len` random characters of `a-z 0-9`, each chosen
/// uniformly.
///
/// # Panics
///
/// If `len` is under [`MIN_TOKEN_LEN`], which would carry too little
/// randomness for a bearer secret.
pub fn random_token(len: usize) -> Result<String, getrandom::Error> {
    assert!(
        len >= MIN_TOKEN_LEN,
        "a bearer secret needs at least {MIN_TOKEN_LEN} characters"
    );
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        getrandom::fill(&mut buf)?;
        // 252 is the largest multiple of 36 that fits a byte: bytes from
        // 252 up are skipped, so every character is equally likely.
        for &b in buf.iter().filter(|&&b| b < 252) {
            if out.len() == len {
                break;
            }
            out.push(char::from(TOKEN_ALPHABET[usize::from(b % 36)]));
        }
    }
    Ok(out)
}

/// `N` random bytes from the operating system's secure source.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_their_secret_only() {
        let hash = SecretHash::of(b"open sesame");
        assert!(hash.matches(b"open sesame"));
        assert!(!hash.matches(b"open sesame "));
        assert!(!hash.matches(b""));
        assert_eq!(hash, SecretHash::of(b"open sesame"));
        assert_ne!(hash, SecretHash::of(b"open says me"));
        // SHA-384 of "abc" (FIPS 180-2, B.1).
        assert_eq!(
            SecretHash::of(b"abc").as_bytes()[..8],
            [0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b]
        );
    }

    #[test]
    fn hashes_round_trip_and_hide_in_debug() {
        let hash = SecretHash::of(b"token");
        assert_eq!(SecretHash::from_slice(hash.as_bytes()), Some(hash));
        assert_eq!(SecretHash::from_bytes(*hash.as_bytes()), hash);
        assert_eq!(SecretHash::from_slice(&[0; 47]), None);
        assert_eq!(format!("{hash:?}"), "SecretHash(..)");
    }

    #[test]
    fn constant_time_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"xbc"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn tokens_are_random_ids() {
        let a = random_token(32).unwrap();
        let b = random_token(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        // Valid as an id (3.5), which guest tokens are (4.2).
        assert!(a.parse::<risala_proto::names::Id>().is_ok());
        assert_eq!(random_token(MIN_TOKEN_LEN).unwrap().len(), MIN_TOKEN_LEN);
        assert_ne!(random_bytes::<16>().unwrap(), random_bytes::<16>().unwrap());
    }

    #[test]
    #[should_panic(expected = "at least")]
    fn short_tokens_are_refused() {
        let _ = random_token(MIN_TOKEN_LEN - 1);
    }
}

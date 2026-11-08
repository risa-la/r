//! Values of encrypted conversations (SPEC 12, 15): the MLS data that
//! commands and server lines carry, franking tags, backup blobs and the
//! assigned numbers and labels.
//!
//! This crate does not implement MLS. KeyPackages, GroupInfo, commits,
//! Welcomes, ratchet trees and ENC payloads are opaque to it: each type
//! here only checks that its value is valid base64 within the size limit,
//! and keeps the text exactly as received so that a server can relay it
//! unchanged. Decoding and checking the MLS structures inside is up to the
//! MLS library of the server or the client.
//!
//! Base64 is the standard alphabet with padding (RFC 4648), read strictly:
//! the length is a multiple of 4, padding appears only at the end, and the
//! bits after the last byte are zero. So every value has exactly one
//! encoding, and parsing then writing gives back the same string.

use std::fmt;
use std::hash::Hash;
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::ParseError;
use crate::frame::MAX_LONG_CLIENT_LINE;

/// The MLS cipher suite of every encrypted conversation: X-Wing,
/// ChaCha20-Poly1305, SHA-384 and ML-DSA-44 (12.2, 15).
pub const CIPHER_SUITE: u16 = 0x0052;

/// The MLS extension type of the conversation extension (12.2, 15).
pub const CONVERSATION_EXTENSION_TYPE: u16 = 0xF2A1;

/// The most leaves a group may have (12.5).
pub const MAX_GROUP_LEAVES: usize = 512;

/// The fewest bytes an ENC payload must decode to (12.8). A server replies
/// `ERR invalid` to a shorter one.
pub const MIN_PAYLOAD_LEN: usize = 48;

/// The length of a franking commitment, HMAC-SHA-384 (12.8).
pub const FRANK_LEN: usize = 48;

/// The length of a franking key (12.8).
pub const FRANK_KEY_LEN: usize = 32;

/// The length of a history key (12.9).
pub const HISTORY_KEY_LEN: usize = 48;

/// The length of a backup blob: an 8-byte key id, a 12-byte nonce and a
/// 48-byte history key with its 16-byte tag (12.10).
pub const BACKUP_BLOB_LEN: usize = 84;

/// The most epochs one page of BACKUP GET returns blobs for when `limit`
/// is not given (12.10).
pub const DEFAULT_BACKUP_LIMIT: u64 = 500;

/// The MLS exporter label of history keys (12.9, 15).
pub const HISTORY_KEY_LABEL: &str = "risala history";

/// The SignWithLabel label of encrypted messages (12.8, 15).
pub const MESSAGE_SIGNATURE_LABEL: &str = "risala message";

/// The ExpandWithLabel label of message keys (12.8, 15).
pub const MESSAGE_KEY_LABEL: &str = "risala message key";

/// The HKDF info prefix of backup keys, followed by the uid (12.10, 15).
pub const BACKUP_INFO_PREFIX: &str = "risala backup ";

/// The HKDF info prefix of the recovery signing key, the ML-DSA-44 key a
/// recovery key gives, followed by the uid (12.10, PLAN.md 43).
pub const RECOVERY_SIGNING_INFO_PREFIX: &str = "risala identity ";

/// The most base64 characters any MLS value may have: the longest line a
/// client may send (2.3). Longer values are `TooLong`.
pub const MAX_BASE64_LEN: usize = MAX_LONG_CLIENT_LINE;

/// The value of one base64 character, or `None` for `=` and characters
/// outside the standard alphabet.
fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Whether `s` is strict, padded, standard base64, possibly empty (12.2).
///
/// This checks the encoding without decoding it, so it needs no memory.
pub fn is_strict_base64(s: &str) -> bool {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return false;
    }
    let pad = b.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return false;
    }
    let data = &b[..b.len() - pad];
    if !data.iter().all(|&c| base64_value(c).is_some()) {
        return false;
    }
    // The bits after the last whole byte must be zero: 4 of them with two
    // `=`, 2 with one.
    match (pad, data.last().and_then(|&c| base64_value(c))) {
        (0, _) => true,
        (1, Some(last)) => last & 0b11 == 0,
        (2, Some(last)) => last & 0b1111 == 0,
        _ => false,
    }
}

/// The number of bytes strict base64 `s` decodes to.
fn decoded_len(s: &str) -> usize {
    let pad = s.bytes().rev().take_while(|&c| c == b'=').count();
    s.len() / 4 * 3 - pad
}

/// Checks a non-empty base64 value of at most [`MAX_BASE64_LEN`]
/// characters.
fn check_blob(s: &str, what: &'static str) -> Result<(), ParseError> {
    if s.len() > MAX_BASE64_LEN {
        Err(ParseError::TooLong)
    } else if s.is_empty() || !is_strict_base64(s) {
        Err(ParseError::BadSyntax(what))
    } else {
        Ok(())
    }
}

/// Defines a newtype for opaque MLS data in base64.
macro_rules! blob_type {
    ($(#[$meta:meta])* $ty:ident, $what:literal) => {
        $(#[$meta])*
        ///
        /// It is kept as received: non-empty, strict base64 of at most
        /// [`MAX_BASE64_LEN`] characters (`TooLong` beyond that,
        /// `BadSyntax` for anything else). Cloning is cheap: the text is
        /// shared. `Debug` shows only the start and the length.
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty(Arc<str>);

        impl $ty {
            /// Encodes `bytes`, which must not be empty.
            pub fn from_bytes(bytes: &[u8]) -> Result<$ty, ParseError> {
                if bytes.len() / 3 * 4 >= MAX_BASE64_LEN {
                    return Err(ParseError::TooLong);
                }
                BASE64.encode(bytes).parse()
            }

            /// The base64 text, as on the wire.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The bytes the text encodes.
            pub fn decode(&self) -> Vec<u8> {
                BASE64
                    .decode(self.0.as_bytes())
                    .expect("checked when parsed")
            }

            /// The number of bytes the text encodes, without decoding it.
            pub fn decoded_len(&self) -> usize {
                decoded_len(&self.0)
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<$ty, ParseError> {
                check_blob(s, $what)?;
                Ok($ty(s.into()))
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let start: String = self.0.chars().take(16).collect();
                write!(f, "{}({start}…, {} bytes)", stringify!($ty), self.decoded_len())
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

blob_type!(
    /// A KeyPackage, an MLSMessage (12.2, 12.4), as in KEYPKG ADD and the
    /// KEYPKG lines of KEYPKG GET.
    KeyPackage,
    "a KeyPackage is base64"
);

blob_type!(
    /// A GroupInfo, an MLSMessage (12.2, 12.5), as in INIT, COMMIT and the
    /// GROUPINFO line.
    GroupInfo,
    "a GroupInfo is base64"
);

blob_type!(
    /// A commit, an MLSMessage holding a Commit as a PublicMessage or an
    /// external commit (12.2, 12.5), as in COMMIT and its event.
    CommitMessage,
    "a commit is base64"
);

blob_type!(
    /// A Welcome, an MLSMessage (12.2, 12.7), as in COMMIT and the WELCOME
    /// line.
    Welcome,
    "a Welcome is base64"
);

blob_type!(
    /// A ratchet tree, the data of a `ratchet_tree` extension (12.2), as in
    /// INIT and the GROUPINFO and WELCOME lines.
    RatchetTree,
    "a ratchet tree is base64"
);

blob_type!(
    /// The payload of an ENC message: a salt followed by the encrypted
    /// RisalaMessage (12.8).
    ///
    /// A payload that decodes to fewer than [`MIN_PAYLOAD_LEN`] bytes
    /// still parses: a server answers it with `ERR invalid`, not
    /// `ERR bad-syntax` (12.8). See [`Ciphertext::is_long_enough`].
    Ciphertext,
    "an ENC payload is base64"
);

impl Ciphertext {
    /// Whether the payload decodes to at least [`MIN_PAYLOAD_LEN`] bytes,
    /// as a server requires (12.8).
    pub fn is_long_enough(&self) -> bool {
        self.decoded_len() >= MIN_PAYLOAD_LEN
    }
}

blob_type!(
    /// The `<content>` of REPORTENC: the decrypted content of the
    /// reported ENC event, the bytes of `content` in its RisalaMessage
    /// (5.8, 12.8).
    Content,
    "content is base64"
);

/// Defines a newtype for a fixed number of bytes in base64.
macro_rules! fixed_type {
    ($(#[$meta:meta])* $ty:ident, $len:expr, $what:literal) => {
        $(#[$meta])*
        ///
        /// On the wire it is strict base64 with padding. A value of
        /// another length is `BadSyntax`, as for keys and signatures
        /// (3.7).
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty([u8; $len]);

        impl $ty {
            /// Makes the value from its bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> $ty {
                $ty(bytes)
            }

            /// The bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<$ty, ParseError> {
                let mut out = [0u8; $len];
                if s.len() != usize::div_ceil($len, 3) * 4 || !is_strict_base64(s) {
                    return Err(ParseError::BadSyntax($what));
                }
                match BASE64.decode_slice(s, &mut out) {
                    Ok(n) if n == $len => Ok($ty(out)),
                    _ => Err(ParseError::BadSyntax($what)),
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&BASE64.encode(self.0))
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($ty))
            }
        }
    };
}

fixed_type!(
    /// The `frank` tag of ENC: the message's franking commitment,
    /// HMAC-SHA-384 of its content under its franking key (12.8).
    Frank,
    FRANK_LEN,
    "frank is 48 bytes of base64"
);

fixed_type!(
    /// The `<frank-key>` of REPORTENC: the reported message's franking
    /// key, `frank_key` in its RisalaMessage (5.8, 12.8).
    FrankKey,
    FRANK_KEY_LEN,
    "frank-key is 32 bytes of base64"
);

fixed_type!(
    /// A backup blob, as in BACKUP ADD and the BACKUP lines of BACKUP GET:
    /// a key id, a nonce and an encrypted history key (12.10).
    BackupBlob,
    BACKUP_BLOB_LEN,
    "a backup blob is 84 bytes of base64"
);

/// What REPORTENC adds to a report of an ENC event (5.8): the message's
/// franking key and its decrypted content. The command carries them, and
/// so does the REPORTENC line that reviewers receive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Franking {
    /// The franking key.
    pub key: FrankKey,
    /// The decrypted content.
    pub content: Content,
}

impl Franking {
    /// Whether HMAC-SHA-384 of the decoded content bytes under the key
    /// equals `frank`, the ENC event's franking commitment (5.8, 12.8).
    /// The server checks this before it accepts a report, and replies
    /// `ERR invalid` if it fails.
    pub fn verifies(&self, frank: &Frank) -> bool {
        let tag = hmac_sha384(self.key.as_bytes(), &self.content.decode());
        // The commitment is public, so a plain comparison is fine.
        tag == *frank.as_bytes()
    }
}

/// HMAC-SHA-384 [RFC2104] of `message` under a key of at most 128 bytes,
/// the hash's block size.
fn hmac_sha384(key: &[u8; FRANK_KEY_LEN], message: &[u8]) -> [u8; FRANK_LEN] {
    use sha2::{Digest as _, Sha384};
    const BLOCK: usize = 128;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let inner = Sha384::new()
        .chain_update(ipad)
        .chain_update(message)
        .finalize();
    Sha384::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

impl BackupBlob {
    /// The blob's key id, the first 8 bytes (12.10).
    pub fn key_id(&self) -> &[u8; 8] {
        self.0.first_chunk().expect("a blob is longer than 8 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_base64() {
        for good in ["", "AAAA", "AA==", "AAA=", "+/+/", "YQ==", "YWI=", "YWJj"] {
            assert!(is_strict_base64(good), "{good:?}");
        }
        for bad in [
            "A", "AA", "AAA", "A===", "====", "AA=A", "YR==", "YWJ=", "YQ", "YQ=", " AAA", "AAA\n",
            "-_-_", "AA==AAAA", "…",
        ] {
            assert!(!is_strict_base64(bad), "{bad:?}");
        }
    }

    #[test]
    fn blobs() {
        let kp: KeyPackage = "AAEABQABAFI=".parse().unwrap();
        assert_eq!(kp.as_str(), "AAEABQABAFI=");
        assert_eq!(kp.to_string(), "AAEABQABAFI=");
        assert_eq!(kp.decode(), [0, 1, 0, 5, 0, 1, 0, 0x52]);
        assert_eq!(kp.decoded_len(), 8);
        assert_eq!(KeyPackage::from_bytes(&kp.decode()), Ok(kp.clone()));
        assert!(format!("{kp:?}").starts_with("KeyPackage(AAEABQABAFI=…, 8 bytes"));

        assert!("".parse::<KeyPackage>().is_err());
        assert!(KeyPackage::from_bytes(&[]).is_err());
        assert!("AAEABQABAFI".parse::<GroupInfo>().is_err());
        assert!("AAEABQABAF…".parse::<Welcome>().is_err());

        let max = "A".repeat(MAX_BASE64_LEN);
        assert!(max.parse::<CommitMessage>().is_ok());
        let over = "A".repeat(MAX_BASE64_LEN + 4);
        assert_eq!(over.parse::<RatchetTree>(), Err(ParseError::TooLong));
        assert_eq!(
            Content::from_bytes(&vec![0; MAX_BASE64_LEN]),
            Err(ParseError::TooLong)
        );
    }

    #[test]
    fn payload_length() {
        let short = Ciphertext::from_bytes(&[1; MIN_PAYLOAD_LEN - 1]).unwrap();
        assert!(!short.is_long_enough());
        let enough = Ciphertext::from_bytes(&[1; MIN_PAYLOAD_LEN]).unwrap();
        assert!(enough.is_long_enough());
        assert_eq!(enough.as_str().len(), 64);
    }

    /// The franking test vector of Appendix B.
    #[test]
    fn franking_verifies() {
        let mut key = [0u8; FRANK_KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = 0xa0 + i as u8;
        }
        let content = b"@reply=15;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n";
        assert_eq!(content.len(), 61);
        let hex = "83d717202ee3a882e770e8ceaa04ff715561ecd5574e6576839cb99ec98f8b96\
                   0277c6cc92ce07971b46e3a6935798ca";
        let mut frank = [0u8; FRANK_LEN];
        for (i, b) in frank.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        let frank = Frank::from_bytes(frank);
        let franking = Franking {
            key: FrankKey::from_bytes(key),
            content: Content::from_bytes(content).unwrap(),
        };
        assert!(franking.verifies(&frank));

        // Another content, another key, or the base64 text instead of the
        // decoded bytes, do not verify.
        let other = Franking {
            content: Content::from_bytes(b"TEXT see you at 1\n").unwrap(),
            ..franking.clone()
        };
        assert!(!other.verifies(&frank));
        let other = Franking {
            key: FrankKey::from_bytes([0; FRANK_KEY_LEN]),
            ..franking.clone()
        };
        assert!(!other.verifies(&frank));
        let other = Franking {
            content: Content::from_bytes(franking.content.as_str().as_bytes()).unwrap(),
            ..franking
        };
        assert!(!other.verifies(&frank));
    }

    #[test]
    fn fixed_lengths() {
        let frank = Frank::from_bytes([7; FRANK_LEN]);
        let text = frank.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<Frank>(), Ok(frank));
        assert!(text[..60].parse::<Frank>().is_err());
        assert!(format!("{text}AAAA").parse::<Frank>().is_err());

        let key = FrankKey::from_bytes([9; FRANK_KEY_LEN]);
        let text = key.to_string();
        assert_eq!(text.len(), 44);
        assert!(text.ends_with('='));
        assert_eq!(text.parse::<FrankKey>(), Ok(key));
        // Non-zero bits after the last byte.
        let mut bad = text.clone();
        bad.replace_range(42..43, "R");
        assert!(bad.parse::<FrankKey>().is_err());

        let mut bytes = [0; BACKUP_BLOB_LEN];
        bytes[..8].copy_from_slice(b"keyid-01");
        let blob = BackupBlob::from_bytes(bytes);
        assert_eq!(blob.to_string().len(), 112);
        assert_eq!(blob.key_id(), b"keyid-01");
        assert_eq!(blob.to_string().parse::<BackupBlob>(), Ok(blob));
        assert!(frank.to_string().parse::<BackupBlob>().is_err());
    }
}

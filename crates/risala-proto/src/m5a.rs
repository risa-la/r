//! draft-02 values that `risala-mls` still uses, kept only until task M1
//! of docs/plans/M5b.md rewrites it for draft-03. Nothing in draft-03
//! uses them, and nothing new should: delete this module, and its
//! re-exports in [`mls`](crate::mls) and [`types`](crate::types), once
//! `risala-mls` no longer needs them.

#![allow(missing_docs)]

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::ParseError;
use crate::mls::{
    MAX_BASE64_LEN, blob_type, check_blob, decoded_len, fixed_type, is_strict_base64,
};

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

/// The `history` setting of an encrypted room in draft-02.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum HistoryMode {
    /// `shared`
    #[default]
    Shared,
    /// `joined`
    Joined,
}

impl HistoryMode {
    /// Every value.
    pub const ALL: &'static [HistoryMode] = &[HistoryMode::Shared, HistoryMode::Joined];

    /// The keyword.
    pub const fn as_str(self) -> &'static str {
        match self {
            HistoryMode::Shared => "shared",
            HistoryMode::Joined => "joined",
        }
    }
}

impl fmt::Display for HistoryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HistoryMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<HistoryMode, ParseError> {
        if s.eq_ignore_ascii_case("shared") {
            Ok(HistoryMode::Shared)
        } else if s.eq_ignore_ascii_case("joined") {
            Ok(HistoryMode::Joined)
        } else {
            Err(ParseError::BadSyntax("history is shared or joined"))
        }
    }
}

blob_type!(
    /// A commit, an MLSMessage holding a Commit as a PublicMessage or an
    /// external commit (12.2, 12.5), as in COMMIT and its event.
    CommitMessage,
    "a commit is base64"
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

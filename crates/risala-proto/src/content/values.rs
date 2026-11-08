//! The values that content lines carry (SPEC 4.5, 5.3-5.8, 12.9-12.13):
//! message ids, file references, confirmation data, keys and log
//! origins.
//!
//! Binary values are strict base64 with padding, of the length the spec
//! fixes (`BadSyntax` otherwise, 3.7). Values that are secrets (file
//! keys, seeds, backup keys and TransferRefs, which hold a key) leave
//! their bytes out of `Debug` and are wiped from memory when dropped.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::error::ParseError;
use crate::line::is_tag_value;
use crate::mls::{fixed_type, is_strict_base64, secret_type};
use crate::names::Domain;
use crate::parse::bad;
use crate::types::parse_u64;

/// The length of a `message_id` (12.9).
pub const MESSAGE_ID_LEN: usize = 16;

/// The length of an X-Wing ciphertext, the `<ciphertext>` of CHALLENGE
/// (12.10).
pub const CHALLENGE_LEN: usize = 1120;

/// The length of the MAC in ANSWER: HMAC-SHA-384 (12.10).
pub const CONFIRM_MAC_LEN: usize = 48;

/// The length of an ML-DSA-44 seed: a period key's in REVEAL, the
/// device-signing key's in SIGNINGKEY (4.8, 12.10).
pub const SEED_LEN: usize = 32;

/// The length of a backup key (12.13).
pub const BACKUP_KEY_LEN: usize = 32;

/// The length of a file key (12.11).
pub const FILE_KEY_LEN: usize = 32;

/// The length of a `file-hash`: SHA-384 (12.11).
pub const FILE_HASH_LEN: usize = 48;

/// The length of an encoded TransferRef: a version byte, a 48-byte blob
/// hash and a 32-byte key (12.13).
pub const TRANSFER_REF_LEN: usize = 1 + 48 + 32;

/// The longest `file` URL (5.6).
pub const MAX_FILE_URL_LEN: usize = 512;

/// The longest name in a media type, the type or the subtype (RFC 6838,
/// 4.2).
pub const MAX_MEDIA_NAME_LEN: usize = 127;

/// The longest log origin: a signed-note key name (4.5, C2SP
/// tlog-cosignature).
pub const MAX_ORIGIN_LEN: usize = 255;

/// The path in a key log's origin, between the host and the number (4.5).
pub const ORIGIN_PATH: &str = "/risala-log/";

fixed_type!(
    /// A `message_id` (12.9): 16 random bytes that name a message within
    /// its conversation. Content lines refer to messages by it alone, as
    /// in DELETE, REPORT's `target` and TEXT's `reply`, `edit` and
    /// `react` (5.3-5.8).
    MessageId,
    MESSAGE_ID_LEN,
    "a message id is 16 bytes of base64"
);

fixed_type!(
    /// The `<mac>` of ANSWER (12.10): HMAC-SHA-384 over a ConfirmContent.
    /// Devices compare it in constant time.
    ConfirmMac,
    CONFIRM_MAC_LEN,
    "a confirmation MAC is 48 bytes of base64"
);

fixed_type!(
    /// The `<seed>` of REVEAL (12.10): the 32-byte seed of a period key,
    /// published once its period and grace hour are over. It is meant to
    /// be public by then, so it is not treated as a secret.
    PeriodSeed,
    SEED_LEN,
    "a period key's seed is 32 bytes of base64"
);

fixed_type!(
    /// The `file-hash` tag of TEXT (12.11): the SHA-384 hash of the exact
    /// bytes uploaded. Devices compare it in constant time before they
    /// decrypt anything.
    FileHash,
    FILE_HASH_LEN,
    "a file hash is 48 bytes of base64"
);

secret_type!(
    /// The `file-key` tag of TEXT (12.11): the 32-byte key the file is
    /// encrypted under.
    FileKey,
    FILE_KEY_LEN,
    "a file key is 32 bytes of base64"
);

secret_type!(
    /// The `<seed>` of SIGNINGKEY (4.8, 12.9): the 32-byte seed of the
    /// identity's new device-signing key.
    SigningSeed,
    SEED_LEN,
    "a device-signing seed is 32 bytes of base64"
);

secret_type!(
    /// The `<key>` of BACKUPKEY (12.13): the backup key of a generation.
    BackupKey,
    BACKUP_KEY_LEN,
    "a backup key is 32 bytes of base64"
);

secret_type!(
    /// The `<ref>` of TRANSFER (12.13): an encoded TransferRef, a
    /// `version` byte, the 48-byte hash of the first archive's blob and
    /// its 32-byte key. It is a secret, since it holds the key.
    ///
    /// Only the length is checked here. A device that opens the transfer
    /// rejects a `version` other than 1 (12.13, 2.4).
    TransferRef,
    TRANSFER_REF_LEN,
    "a TransferRef is 81 bytes of base64"
);

impl TransferRef {
    /// The `version` byte.
    pub fn version(&self) -> u8 {
        self.as_bytes()[0]
    }

    /// The hash of the first archive's blob (12.12).
    pub fn blob_hash(&self) -> [u8; 48] {
        let mut out = [0; 48];
        out.copy_from_slice(&self.as_bytes()[1..49]);
        out
    }

    /// The first archive's file key. The copy is wiped when dropped.
    pub fn key(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0; 32]);
        out.copy_from_slice(&self.as_bytes()[49..]);
        out
    }
}

/// The `<ciphertext>` of CHALLENGE (12.10): an X-Wing ciphertext of 1120
/// bytes, encapsulated to the challenged device's attestation key.
///
/// On the wire it is strict base64 with padding; another length is
/// `BadSyntax`. The bytes are on the heap, so that a
/// [`ContentLine`](super::ContentLine) stays small.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ChallengeCiphertext(Box<[u8; CHALLENGE_LEN]>);

impl ChallengeCiphertext {
    /// Makes the value from its bytes.
    pub fn from_bytes(bytes: &[u8; CHALLENGE_LEN]) -> ChallengeCiphertext {
        ChallengeCiphertext(Box::new(*bytes))
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; CHALLENGE_LEN] {
        &self.0
    }
}

impl FromStr for ChallengeCiphertext {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<ChallengeCiphertext, ParseError> {
        const WHAT: ParseError = bad("a challenge is 1120 bytes of base64");
        if s.len() != CHALLENGE_LEN.div_ceil(3) * 4 || !is_strict_base64(s) {
            return Err(WHAT);
        }
        let mut out = Box::new([0u8; CHALLENGE_LEN]);
        match BASE64.decode_slice(s, &mut out[..]) {
            Ok(CHALLENGE_LEN) => Ok(ChallengeCiphertext(out)),
            _ => Err(WHAT),
        }
    }
}

impl fmt::Display for ChallengeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(&self.0[..]))
    }
}

impl fmt::Debug for ChallengeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.to_string();
        write!(f, "ChallengeCiphertext({}…)", &text[..16])
    }
}

// ---------------------------------------------------------------------------
// Files (5.6, 12.11)

/// The `file` tag of TEXT (5.6, 12.11): a file's `get` URL.
///
/// It starts with `https://` (the scheme in any case), has a host, holds
/// no user information (`@` before the host), is at most 512 bytes
/// (`TooLong` beyond that), and is a valid tag value, so it has no space
/// or `;`. It is kept exactly as written.
///
/// Whether its origin is one of the server's `files` origins (8.5) is for
/// the device to check, with [`origin`](Self::origin).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FileUrl(String);

impl FileUrl {
    /// The URL as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The URL's origin, as INFO's `files` lists them (8.5):
    /// `https://<host>[:<port>]`, in lower case.
    pub fn origin(&self) -> String {
        format!("https://{}", authority(&self.0).to_ascii_lowercase())
    }
}

/// The authority of an `https://` URL: what follows the scheme, up to
/// the first `/`, `?` or `#`.
fn authority(url: &str) -> &str {
    let rest = &url["https://".len()..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    &rest[..end]
}

impl FromStr for FileUrl {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<FileUrl, ParseError> {
        let https = s
            .get(.."https://".len())
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"));
        if !https {
            return Err(bad("a file URL starts with https://"));
        }
        if !is_tag_value(s) {
            return Err(bad("a file URL has no space or ;"));
        }
        if s.len() > MAX_FILE_URL_LEN {
            return Err(ParseError::TooLong);
        }
        let authority = authority(s);
        // A host is required, and user information is refused, so that
        // the URL's origin is what it appears to be.
        if authority.is_empty() || authority.starts_with(':') || authority.contains('@') {
            return Err(bad("a file URL needs a host and no user information"));
        }
        Ok(FileUrl(s.to_owned()))
    }
}

impl fmt::Display for FileUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The `file-type` tag of TEXT (12.9): a media type as `type/subtype`
/// (RFC 6838), without parameters, folded to lower case.
///
/// Each name is 1 to 127 characters, starting with a letter or digit,
/// followed by letters, digits and `! # $ & - ^ _ . +` (RFC 6838, 4.2).
/// Devices MUST NOT trust it over what the decrypted file holds (12.11).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MediaType(String);

impl MediaType {
    /// The media type, in lower case.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Checks a `restricted-name` of RFC 6838, 4.2.
fn media_name(name: &str) -> Result<(), ParseError> {
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c));
    if !first_ok || !rest_ok {
        Err(bad("a media type is type/subtype"))
    } else if name.len() > MAX_MEDIA_NAME_LEN {
        Err(ParseError::TooLong)
    } else {
        Ok(())
    }
}

impl FromStr for MediaType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<MediaType, ParseError> {
        let (kind, subtype) = s
            .split_once('/')
            .ok_or(bad("a media type is type/subtype"))?;
        media_name(kind)?;
        media_name(subtype)?;
        Ok(MediaType(s.to_ascii_lowercase()))
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A shared file, from the file tags of a TEXT line (5.6, 12.9, 12.11).
///
/// `file`, `file-key` and `file-hash` are what a device needs to fetch
/// and check the file, so a TEXT line has a file only if all three are
/// present and valid (12.9). `file-type` and `file-size` are only for
/// showing before the download, so an invalid one is left out rather
/// than losing the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRef {
    /// `file`: the `get` URL.
    pub url: FileUrl,
    /// `file-key`: the file key.
    pub key: FileKey,
    /// `file-hash`: the SHA-384 hash of the bytes uploaded.
    pub hash: FileHash,
    /// `file-type`: the media type, if given and valid.
    pub media_type: Option<MediaType>,
    /// `file-size`: the size in bytes before encryption, if given and
    /// valid.
    pub size: Option<u64>,
}

// ---------------------------------------------------------------------------
// Key logs (4.5)

/// A key log's origin (4.5): its host in lower case, `/risala-log/` and a
/// number of at least 1, such as `chat.example.org/risala-log/1`. It is
/// the `<origin>` of PIN (12.9).
///
/// An origin is the name of the log's signing key, compared byte for
/// byte, so it is not folded: upper case is `BadSyntax`. It is at most
/// 255 bytes (`TooLong`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogOrigin {
    host: Domain,
    number: u64,
}

impl LogOrigin {
    /// The origin of log `number` of `host`. `None` for number 0, or if
    /// the origin would be longer than 255 bytes.
    pub fn new(host: Domain, number: u64) -> Option<LogOrigin> {
        let origin = LogOrigin { host, number };
        (number >= 1 && origin.to_string().len() <= MAX_ORIGIN_LEN).then_some(origin)
    }

    /// The log's host.
    pub fn host(&self) -> &Domain {
        &self.host
    }

    /// The log's number: 1 for a host's first log (4.5).
    pub fn number(&self) -> u64 {
        self.number
    }
}

impl FromStr for LogOrigin {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<LogOrigin, ParseError> {
        const WHAT: ParseError = bad("a log origin is <host>/risala-log/<n>");
        let (host, number) = s.split_once(ORIGIN_PATH).ok_or(WHAT)?;
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(WHAT);
        }
        let host: Domain = host.parse()?;
        let number = parse_u64(number)?;
        if number == 0 {
            return Err(WHAT);
        }
        if s.len() > MAX_ORIGIN_LEN {
            return Err(ParseError::TooLong);
        }
        Ok(LogOrigin { host, number })
    }
}

impl fmt::Display for LogOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{ORIGIN_PATH}{}", self.host, self.number)
    }
}

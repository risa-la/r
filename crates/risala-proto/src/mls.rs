//! MLS objects and the values derived from them that lines carry (SPEC
//! 5.2, 6.1, 7.2, 7.3, 12), the assigned numbers of Section 15, and the
//! base64 rules shared by every binary value in a line.
//!
//! This crate does not implement MLS. KeyPackages, GroupInfo, ratchet
//! trees, Welcomes and MLS messages are opaque to it: each type here only
//! checks that its value is valid base64 within the size limit, and keeps
//! the text exactly as received so that a server can relay it unchanged.
//! Decoding and checking the MLS structures inside is up to the MLS
//! library of the server or the client (`risala-mls`).
//!
//! Base64 is the standard alphabet with padding (RFC 4648), read strictly:
//! the length is a multiple of 4, padding appears only at the end, and the
//! bits after the last byte are zero. So every value has exactly one
//! encoding, and parsing then writing gives back the same string. A value
//! of a fixed size with the wrong length is `BadSyntax` (3.7).
//!
//! Objects too large for a line travel as blobs (12.12), and the line
//! carries a [`BlobRef`] in their place: [`OrBlob`] is either.

use std::fmt;
use std::hash::Hash;
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::error::ParseError;
use crate::frame::MAX_LONG_CLIENT_LINE;
use crate::names::BlobRef;

/// The MLS cipher suite of every conversation: X-Wing, HKDF-SHA384,
/// ChaCha20-Poly1305, SHA-384 and ML-DSA-44 (12.2, 15). It is the value
/// draft-ietf-mls-pq-ciphersuites-07 requests.
pub const CIPHER_SUITE: u16 = 0x0020;

/// The MLS extension type of the conversation extension, in the group
/// context (12.4, 15).
pub const CONVERSATION_EXTENSION_TYPE: u16 = 0xF2A1;

/// The MLS extension type of the device binding, in KeyPackages and leaf
/// nodes (12.3, 15).
pub const DEVICE_BINDING_EXTENSION_TYPE: u16 = 0xF2A2;

/// The MLS extension type of the profile, in leaf nodes (12.3, 15).
pub const PROFILE_EXTENSION_TYPE: u16 = 0xF2A3;

/// The MLS exporter label of send tokens (7.2, 15).
pub const SEND_TOKEN_LABEL: &str = "risala/1 send";

/// The length of a send token, from the MLS exporter (7.2).
pub const SEND_TOKEN_LEN: usize = 32;

/// The length of a put secret: 32 random bytes (12.5, 12.8).
pub const PUT_SECRET_LEN: usize = 32;

/// The length of a send token's hash, SHA-384 (5.2, 7.2).
pub const TOKEN_HASH_LEN: usize = 48;

/// The length of a group id: 32 random bytes (12.6).
pub const GROUP_ID_LEN: usize = 32;

/// The length of a pseudonym (7.3).
pub const PSEUDONYM_LEN: usize = 16;

/// The length of a KeyPackageRef, a SHA-384 hash in this cipher suite
/// (12.8).
pub const KEY_PACKAGE_REF_LEN: usize = 48;

/// The most base64 characters any binary value in a line may have: the
/// longest line a client may send (2.3). Longer values are `TooLong`.
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
pub(crate) fn decoded_len(s: &str) -> usize {
    let pad = s.bytes().rev().take_while(|&c| c == b'=').count();
    s.len() / 4 * 3 - pad
}

/// Checks a non-empty base64 value of at most [`MAX_BASE64_LEN`]
/// characters.
pub(crate) fn check_blob(s: &str, what: &'static str) -> Result<(), ParseError> {
    if s.len() > MAX_BASE64_LEN {
        Err(ParseError::TooLong)
    } else if s.is_empty() || !is_strict_base64(s) {
        Err(ParseError::BadSyntax(what))
    } else {
        Ok(())
    }
}

/// Defines a newtype for opaque binary data in base64.
macro_rules! blob_type {
    ($(#[$meta:meta])* $ty:ident, $what:literal) => {
        $(#[$meta])*
        ///
        /// It is kept as received: non-empty, strict base64 of at most
        /// [`MAX_BASE64_LEN`](crate::mls::MAX_BASE64_LEN) characters
        /// (`TooLong` beyond that, `BadSyntax` for anything else). Cloning is cheap: the text is
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
pub(crate) use blob_type;

/// Defines a newtype for a fixed number of bytes in base64.
macro_rules! fixed_type {
    ($(#[$meta:meta])* $ty:ident, $len:expr, $what:literal) => {
        $(#[$meta])*
        ///
        /// On the wire it is strict base64 with padding. A value of
        /// another length is `BadSyntax`, as for keys, tokens and hashes
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
pub(crate) use fixed_type;

/// Defines a newtype for a fixed number of secret bytes in base64: like
/// [`fixed_type`], but `Debug` leaves the value out, so that a line
/// written to a log does not give it away.
macro_rules! secret_type {
    ($(#[$meta:meta])* $ty:ident, $len:expr, $what:literal) => {
        $(#[$meta])*
        ///
        /// On the wire it is strict base64 with padding. A value of
        /// another length is `BadSyntax` (3.7). It is a secret: `Debug`
        /// shows only the type's name.
        #[derive(Clone, PartialEq, Eq)]
        pub struct $ty(Zeroizing<[u8; $len]>);

        impl $ty {
            /// Makes the value from its bytes.
            pub fn from_bytes(bytes: [u8; $len]) -> $ty {
                $ty(Zeroizing::new(bytes))
            }

            /// The bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<$ty, ParseError> {
                let mut out = Zeroizing::new([0u8; $len]);
                if s.len() != usize::div_ceil($len, 3) * 4 || !is_strict_base64(s) {
                    return Err(ParseError::BadSyntax($what));
                }
                match BASE64.decode_slice(s, &mut out[..]) {
                    Ok(n) if n == $len => Ok($ty(out)),
                    _ => Err(ParseError::BadSyntax($what)),
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&BASE64.encode(&self.0[..]))
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(..)"))
            }
        }
    };
}
pub(crate) use secret_type;

blob_type!(
    /// A KeyPackage, as an MLSMessage (12.5), as in KEYPKG ADD and the
    /// KEYPKG lines of KEYPKG GET.
    KeyPackage,
    "a KeyPackage is base64"
);

blob_type!(
    /// A GroupInfo, as an MLSMessage (12.6), as in the second form of
    /// CREATE, POST's `groupinfo=` and the GROUPINFO line.
    GroupInfo,
    "a GroupInfo is base64"
);

blob_type!(
    /// A ratchet tree, the data of a `ratchet_tree` extension (12.2,
    /// 12.6), as in the second form of CREATE and the GROUPINFO line.
    RatchetTree,
    "a ratchet tree is base64"
);

blob_type!(
    /// A Welcome, as an MLSMessage (12.8), as in WELCOME PUT and the
    /// WELCOME line, or an AnnotatedWelcome for a light client (12.6).
    Welcome,
    "a Welcome is base64"
);

blob_type!(
    /// An MLSMessage posted to a mailbox (5.2): a PrivateMessage, or in a
    /// public room a PublicMessage holding a commit or a proposal, as in
    /// POST and the POST line. For a light client's FETCH, a commit may
    /// be an AnnotatedCommit (12.6).
    MlsMessage,
    "an MLS message is base64"
);

fixed_type!(
    /// A group id (5.2, 12.6): 32 random bytes, as in CREATE.
    ///
    /// MLS allows group ids of any length, but every group risala makes
    /// has a 32-byte one (12.6), so a CREATE with another length is
    /// `BadSyntax` rather than a mailbox no valid group can post to.
    GroupId,
    GROUP_ID_LEN,
    "a group id is 32 bytes of base64"
);

fixed_type!(
    /// The SHA-384 hash of a send token (5.2, 7.2), as in CREATE.
    TokenHash,
    TOKEN_HASH_LEN,
    "a token hash is 48 bytes of base64"
);

secret_type!(
    /// A send token (7.2): `MLS-Exporter("risala/1 send", "", 32)` in the
    /// epoch a post belongs to, as in POST, UPLOAD and BLOB. A bearer
    /// secret that every member of the epoch can compute.
    SendToken,
    SEND_TOKEN_LEN,
    "a send token is 32 bytes of base64"
);

impl SendToken {
    /// Its SHA-384 hash, which the server keeps and compares (7.2).
    pub fn hash(&self) -> TokenHash {
        use sha2::{Digest as _, Sha384};
        TokenHash::from_bytes(Sha384::digest(&self.0[..]).into())
    }
}

secret_type!(
    /// A put secret (12.5): 32 random bytes the server makes for one
    /// KEYPKG GET handout, as in the KEYPKG line and WELCOME PUT. Only
    /// whoever fetched the KeyPackage can deliver its Welcome (12.8); the
    /// server keeps only its hash.
    PutSecret,
    PUT_SECRET_LEN,
    "a put secret is 32 bytes of base64"
);

/// The `<secret>` of WELCOME PUT (12.8): the put secret of a KEYPKG GET
/// handout, or `-` for a KeyPackage of an external Add proposal in a
/// public room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WelcomeSecret {
    /// The put secret of the handout (12.5).
    Put(PutSecret),
    /// `-`: an external Add proposal's KeyPackage, which the server takes
    /// only from the device that committed the proposal (12.8).
    Proposal,
}

impl fmt::Display for WelcomeSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WelcomeSecret::Put(secret) => fmt::Display::fmt(secret, f),
            WelcomeSecret::Proposal => f.write_str("-"),
        }
    }
}

impl FromStr for WelcomeSecret {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<WelcomeSecret, ParseError> {
        if s == "-" {
            Ok(WelcomeSecret::Proposal)
        } else {
            s.parse().map(WelcomeSecret::Put)
        }
    }
}

impl From<PutSecret> for WelcomeSecret {
    fn from(secret: PutSecret) -> WelcomeSecret {
        WelcomeSecret::Put(secret)
    }
}

fixed_type!(
    /// A leaf's pseudonym (7.3): 16 random bytes in the RisalaAAD of
    /// everything the leaf posts, as in MUTE and UNMUTE (6.4).
    Pseudonym,
    PSEUDONYM_LEN,
    "a pseudonym is 16 bytes of base64"
);

fixed_type!(
    /// A KeyPackageRef of RFC 9420 (12.8): 48 bytes, as in WELCOME PUT and
    /// WELCOME GET.
    KeyPackageRef,
    KEY_PACKAGE_REF_LEN,
    "a KeyPackageRef is 48 bytes of base64"
);

/// The `<token>` of POST (5.2): a send token, or `-` for an external
/// commit or external Add proposal that joins a public room (6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostToken {
    /// A send token of the message's epoch.
    Send(SendToken),
    /// `-`: a join of a public room, which has no token yet.
    Join,
}

impl fmt::Display for PostToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PostToken::Send(token) => fmt::Display::fmt(token, f),
            PostToken::Join => f.write_str("-"),
        }
    }
}

impl FromStr for PostToken {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<PostToken, ParseError> {
        if s == "-" {
            Ok(PostToken::Join)
        } else {
            s.parse().map(PostToken::Send)
        }
    }
}

impl From<SendToken> for PostToken {
    fn from(token: SendToken) -> PostToken {
        PostToken::Send(token)
    }
}

/// An MLS object in a line (5.2, 6.1, 12.8, 12.12): its bytes in base64,
/// or, if it is too large for a line, the [`BlobRef`] of a blob that
/// holds them.
///
/// The two are told apart by the `sha384:` prefix, which base64 cannot
/// contain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OrBlob<T> {
    /// The object itself, in base64.
    Inline(T),
    /// The hash of a blob that holds the object's bytes (12.12).
    Blob(BlobRef),
}

impl<T> OrBlob<T> {
    /// The object, if it is in the line.
    pub fn inline(&self) -> Option<&T> {
        match self {
            OrBlob::Inline(value) => Some(value),
            OrBlob::Blob(_) => None,
        }
    }

    /// The blob, if the object is one.
    pub fn blob(&self) -> Option<&BlobRef> {
        match self {
            OrBlob::Inline(_) => None,
            OrBlob::Blob(blob) => Some(blob),
        }
    }
}

impl<T: fmt::Display> fmt::Display for OrBlob<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrBlob::Inline(value) => fmt::Display::fmt(value, f),
            OrBlob::Blob(blob) => fmt::Display::fmt(blob, f),
        }
    }
}

impl<T: FromStr<Err = ParseError>> FromStr for OrBlob<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<OrBlob<T>, ParseError> {
        let prefix = BlobRef::PREFIX;
        if s.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        {
            s.parse().map(OrBlob::Blob)
        } else {
            s.parse().map(OrBlob::Inline)
        }
    }
}

impl<T> From<BlobRef> for OrBlob<T> {
    fn from(blob: BlobRef) -> OrBlob<T> {
        OrBlob::Blob(blob)
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

        // 1 MiB of base64 at most (2.3).
        assert_eq!(MAX_BASE64_LEN, 1 << 20);
        let max = "A".repeat(MAX_BASE64_LEN);
        assert!(max.parse::<MlsMessage>().is_ok());
        let over = "A".repeat(MAX_BASE64_LEN + 4);
        assert_eq!(over.parse::<RatchetTree>(), Err(ParseError::TooLong));
        assert_eq!(
            MlsMessage::from_bytes(&vec![0; MAX_BASE64_LEN]),
            Err(ParseError::TooLong)
        );
    }

    #[test]
    fn fixed_lengths() {
        let id = GroupId::from_bytes([7; GROUP_ID_LEN]);
        let text = id.to_string();
        assert_eq!(text.len(), 44);
        assert_eq!(text.parse::<GroupId>(), Ok(id));
        assert!(text[..40].parse::<GroupId>().is_err());
        assert!(format!("{text}AAAA").parse::<GroupId>().is_err());
        // Non-zero bits after the last byte.
        let mut bad = text.clone();
        bad.replace_range(42..43, "R");
        assert!(bad.parse::<GroupId>().is_err());

        let hash = TokenHash::from_bytes([1; TOKEN_HASH_LEN]);
        assert_eq!(hash.to_string().len(), 64);
        assert_eq!(hash.to_string().parse::<TokenHash>(), Ok(hash));
        assert!(id.to_string().parse::<TokenHash>().is_err());

        let p = Pseudonym::from_bytes([2; PSEUDONYM_LEN]);
        assert_eq!(p.to_string().len(), 24);
        assert!(p.to_string().ends_with("=="));
        assert_eq!(p.to_string().parse::<Pseudonym>(), Ok(p));

        let r = KeyPackageRef::from_bytes([3; KEY_PACKAGE_REF_LEN]);
        assert_eq!(r.to_string().parse::<KeyPackageRef>(), Ok(r));
    }

    #[test]
    fn send_tokens_are_secret() {
        // The send token of the spec's example (1.4).
        let s = "3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE=";
        let token: SendToken = s.parse().unwrap();
        assert_eq!(token.to_string(), s);
        assert_eq!(format!("{token:?}"), "SendToken(..)");
        assert!(!format!("{:?}", PostToken::Send(token.clone())).contains("3J0n"));
        // Its hash is SHA-384 of the 32 bytes.
        use sha2::{Digest as _, Sha384};
        let want: [u8; 48] = Sha384::digest(token.as_bytes()).into();
        assert_eq!(token.hash().as_bytes(), &want);
        assert!(s[..40].parse::<SendToken>().is_err());

        assert_eq!("-".parse::<PostToken>(), Ok(PostToken::Join));
        assert_eq!(PostToken::Join.to_string(), "-");
        assert_eq!(s.parse::<PostToken>(), Ok(PostToken::Send(token)));
        assert!("--".parse::<PostToken>().is_err());
    }

    #[test]
    fn inline_or_blob() {
        let inline: OrBlob<MlsMessage> = "AAEAAQ==".parse().unwrap();
        assert_eq!(inline.inline().map(MlsMessage::as_str), Some("AAEAAQ=="));
        assert_eq!(inline.blob(), None);
        assert_eq!(inline.to_string(), "AAEAAQ==");
        let hex = "ab".repeat(48);
        let blob: OrBlob<RatchetTree> = format!("SHA384:{hex}").parse().unwrap();
        assert_eq!(blob.to_string(), format!("sha384:{hex}"));
        assert!(blob.inline().is_none());
        // A blob-ref that is not valid is an error, not base64.
        assert!(
            format!("sha384:{}", &hex[2..])
                .parse::<OrBlob<GroupInfo>>()
                .is_err()
        );
        assert!("sha384".parse::<OrBlob<GroupInfo>>().is_err());
    }
}

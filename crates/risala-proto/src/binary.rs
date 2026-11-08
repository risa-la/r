//! Binary values that lines carry in base64 and that are not MLS objects
//! (SPEC 4.7, 4.8, 5.8, 9.1, 12.13). Like the MLS objects of
//! [`mls`](crate::mls), they are opaque here: each type checks only its
//! base64 and its length, and keeps the text exactly as received.
//!
//! Decoding the structures inside is for other modules: key file records
//! for the key file code (4.4), reports for the server (5.8).

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, ParseError};
use crate::mls::{
    MAX_BASE64_LEN, blob_type, check_blob, decoded_len, fixed_type, is_strict_base64, secret_type,
};
use crate::names::{BLOB_HASH_LEN, BlobRef};

/// The length of a WrappedKey (12.13): a one-byte `version`, a 12-byte
/// nonce, then a 32-byte key encrypted with its 16-byte tag.
pub const WRAPPED_KEY_LEN: usize = 61;

/// The `version` byte that starts a WrappedKey (12.13).
pub const WRAPPED_KEY_VERSION: u8 = 1;

/// The length of a push subscription's P-256 public key, uncompressed
/// (9.1).
pub const PUSH_KEY_LEN: usize = 65;

/// The length of a push subscription's authentication secret (9.1).
pub const PUSH_AUTH_LEN: usize = 16;

blob_type!(
    /// The `<keyfile>` of REGISTER and KEYS PUT (4.7): a one-byte
    /// `version` (1) followed by the vector `Record records<V>`, the
    /// identity's records in chain order (4.4).
    ///
    /// Only the base64 is checked here. Whether the records form a valid
    /// key file is checked by the key file code, and a server replies
    /// `ERR invalid` if they do not.
    EncodedRecords,
    "a key file is base64"
);

blob_type!(
    /// The `<data>` of PAIR PUT and the PAIR line (4.8): a NewDevice or an
    /// IdentityBundle, encrypted with ChaCha20-Poly1305 under a key that
    /// only the two devices know.
    PairData,
    "pairing data is base64"
);

blob_type!(
    /// The `<report>` of REPORT and the REPORT line (5.8): a RisalaReport.
    /// The server checks its franking (`ERR invalid`).
    ReportData,
    "a report is base64"
);

/// The `<report>` of REPORT and the REPORT line (5.8): a RisalaReport in
/// base64, or a blob-ref naming a blob that holds its bytes, for a report
/// too large for a line. Base64 never holds a `:`, so the two forms never
/// overlap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReportRef {
    /// The RisalaReport itself.
    Inline(ReportData),
    /// A blob that holds the RisalaReport's bytes, without base64 (12.12).
    /// The server keeps it as long as the report, and sends operators the
    /// same blob-ref.
    Blob(BlobRef),
}

impl fmt::Display for ReportRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportRef::Inline(data) => data.fmt(f),
            ReportRef::Blob(blob) => blob.fmt(f),
        }
    }
}

impl FromStr for ReportRef {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<ReportRef, ParseError> {
        if s.contains(':') {
            s.parse().map(ReportRef::Blob)
        } else {
            s.parse().map(ReportRef::Inline)
        }
    }
}

impl From<ReportData> for ReportRef {
    fn from(data: ReportData) -> ReportRef {
        ReportRef::Inline(data)
    }
}

impl From<BlobRef> for ReportRef {
    fn from(blob: BlobRef) -> ReportRef {
        ReportRef::Blob(blob)
    }
}

fixed_type!(
    /// The `<key>` of BACKUP PUT and the BACKUP line (12.13): a
    /// WrappedKey, a backup's random key wrapped under the backup key of
    /// its generation, [`WRAPPED_KEY_LEN`] bytes.
    ///
    /// 12.13: a key of another length is `ERR bad-syntax`, as any value
    /// of the wrong length is (3.7), but one whose first byte is not
    /// [`WRAPPED_KEY_VERSION`] is `ERR invalid`. [`WrappedKey::check`] is
    /// that second check.
    WrappedKey,
    WRAPPED_KEY_LEN,
    "a wrapped key is 61 bytes of base64"
);

impl WrappedKey {
    /// Encodes a WrappedKey's bytes.
    pub fn from_array(bytes: &[u8; WRAPPED_KEY_LEN]) -> WrappedKey {
        WrappedKey::from_bytes(*bytes)
    }

    /// The check of BACKUP PUT (12.13): `ERR invalid` unless the key
    /// starts with [`WRAPPED_KEY_VERSION`].
    pub fn check(&self) -> Result<(), ErrorCode> {
        match self.as_bytes() {
            [WRAPPED_KEY_VERSION, ..] => Ok(()),
            _ => Err(ErrorCode::Invalid),
        }
    }

    /// The key's bytes, if it passes [`WrappedKey::check`].
    pub fn to_array(&self) -> Option<[u8; WRAPPED_KEY_LEN]> {
        self.check().ok().map(|()| *self.as_bytes())
    }
}

fixed_type!(
    /// The `<key>` of PUSH ADD (9.1): the subscription's P-256 public key,
    /// 65 bytes. Whether it is a point on the curve is for the server to
    /// check.
    PushKey,
    PUSH_KEY_LEN,
    "a push key is 65 bytes of base64"
);

secret_type!(
    /// The `<auth>` of PUSH ADD (9.1): the subscription's 16-byte
    /// authentication secret (RFC 8291).
    PushAuth,
    PUSH_AUTH_LEN,
    "a push auth secret is 16 bytes of base64"
);

/// The `version` byte that starts the list blob of BACKUP PUT's
/// `files=` (12.13).
pub const BLOB_LIST_VERSION: u8 = 1;

/// Reads the list blob of BACKUP PUT's `files=` (12.13): a `version` byte,
/// [`BLOB_LIST_VERSION`], then the 48-byte hashes of the backup's other
/// blobs, one after another. Another first byte, or a length that is not
/// 1 plus a multiple of 48, is `ERR invalid`.
pub fn read_blob_list(bytes: &[u8]) -> Result<Vec<BlobRef>, ErrorCode> {
    let Some((&BLOB_LIST_VERSION, hashes)) = bytes.split_first() else {
        return Err(ErrorCode::Invalid);
    };
    let (hashes, rest) = hashes.as_chunks::<BLOB_HASH_LEN>();
    if !rest.is_empty() {
        return Err(ErrorCode::Invalid);
    }
    Ok(hashes.iter().copied().map(BlobRef::from_hash).collect())
}

/// Writes the list blob of BACKUP PUT's `files=` (12.13).
pub fn write_blob_list(refs: &[BlobRef]) -> Vec<u8> {
    std::iter::once(BLOB_LIST_VERSION)
        .chain(refs.iter().flat_map(|r| *r.hash()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        let key = WrappedKey::from_array(&[1; WRAPPED_KEY_LEN]);
        assert_eq!(key.to_string().len(), 84);
        assert_eq!(key.to_string().parse::<WrappedKey>(), Ok(key));
        assert_eq!(key.check(), Ok(()));
        assert_eq!(key.to_array(), Some([1; WRAPPED_KEY_LEN]));
        let push = PushKey::from_bytes([4; PUSH_KEY_LEN]);
        assert_eq!(push.to_string().len(), 88);
        assert_eq!(push.to_string().parse::<PushKey>(), Ok(push));
        assert!(key.to_string().parse::<PushKey>().is_err());
        let auth = PushAuth::from_bytes([5; PUSH_AUTH_LEN]);
        assert_eq!(auth.to_string().parse::<PushAuth>(), Ok(auth.clone()));
        assert_eq!(format!("{auth:?}"), "PushAuth(..)");
        // 12.13: a wrong length is `ERR bad-syntax` (a parse error), a
        // wrong version `ERR invalid`.
        for bad in [&[1u8; 60][..], &[1; 62]] {
            let text = BASE64.encode(bad);
            assert!(
                matches!(text.parse::<WrappedKey>(), Err(ParseError::BadSyntax(_))),
                "{bad:?}"
            );
        }
        for bad in [[2; 61], [0; 61]] {
            let key = WrappedKey::from_array(&bad);
            assert_eq!(key.check(), Err(ErrorCode::Invalid), "{bad:?}");
            assert_eq!(key.to_array(), None);
        }
        // The list starts with its version byte (12.13).
        let refs = [BlobRef::of(b"a"), BlobRef::of(b"b")];
        let list = write_blob_list(&refs);
        assert_eq!(list.len(), 97);
        assert_eq!(list[0], 1);
        assert_eq!(read_blob_list(&list), Ok(refs.to_vec()));
        assert_eq!(read_blob_list(&[1]), Ok(vec![]));
        assert_eq!(read_blob_list(&[]), Err(ErrorCode::Invalid));
        assert_eq!(read_blob_list(&list[1..]), Err(ErrorCode::Invalid));
        assert_eq!(read_blob_list(&list[..96]), Err(ErrorCode::Invalid));
        let mut v2 = list.clone();
        v2[0] = 2;
        assert_eq!(read_blob_list(&v2), Err(ErrorCode::Invalid));
        // REPORT's `<report>` is base64 or a blob-ref (5.8).
        let blob = BlobRef::of(b"r");
        assert_eq!(
            blob.to_string().parse::<ReportRef>(),
            Ok(ReportRef::Blob(blob))
        );
        assert!(matches!(
            "AQ==".parse::<ReportRef>(),
            Ok(ReportRef::Inline(_))
        ));
        assert!("sha384:00".parse::<ReportRef>().is_err());
        let records: EncodedRecords = "AQ==".parse().unwrap();
        assert_eq!(records.decode(), [1]);
        assert!("".parse::<PairData>().is_err());
        assert!("AQ".parse::<ReportData>().is_err());
    }
}

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

use crate::error::ParseError;
use crate::mls::{
    MAX_BASE64_LEN, blob_type, check_blob, decoded_len, fixed_type, is_strict_base64, secret_type,
};

/// The length of a wrapped backup key: a 12-byte nonce, then a 32-byte key
/// encrypted with its 16-byte tag (12.13).
pub const WRAPPED_KEY_LEN: usize = 60;

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

fixed_type!(
    /// The `<key>` of BACKUP PUT and the BACKUP line (12.13): a backup's
    /// random key, wrapped under the backup key of its generation.
    WrappedKey,
    WRAPPED_KEY_LEN,
    "a wrapped key is 60 bytes of base64"
);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        let key = WrappedKey::from_bytes([1; WRAPPED_KEY_LEN]);
        assert_eq!(key.to_string().len(), 80);
        assert_eq!(key.to_string().parse::<WrappedKey>(), Ok(key));
        let push = PushKey::from_bytes([4; PUSH_KEY_LEN]);
        assert_eq!(push.to_string().len(), 88);
        assert_eq!(push.to_string().parse::<PushKey>(), Ok(push));
        assert!(key.to_string().parse::<PushKey>().is_err());
        let auth = PushAuth::from_bytes([5; PUSH_AUTH_LEN]);
        assert_eq!(auth.to_string().parse::<PushAuth>(), Ok(auth.clone()));
        assert_eq!(format!("{auth:?}"), "PushAuth(..)");
        let records: EncodedRecords = "AQ==".parse().unwrap();
        assert_eq!(records.decode(), [1]);
        assert!("".parse::<PairData>().is_err());
        assert!("AQ".parse::<ReportData>().is_err());
    }
}

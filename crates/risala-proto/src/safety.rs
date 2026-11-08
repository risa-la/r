//! Safety numbers (SPEC 12.14).
//!
//! Each identity has one safety number, which covers its master key and
//! its uid:
//!
//! ```text
//! struct { opaque label<V>; opaque uid<V>; opaque master_key<V>; } SafetyNumberContent;
//! struct { uint8 version; opaque uid<V>; opaque fingerprint[48]; } SafetyNumberCode;
//! ```
//!
//! The fingerprint is SHA-384 of the encoded SafetyNumberContent, whose
//! label is `risala-fp-1`. Clients show it as 40 digits in eight groups
//! of five, and as a QR code holding `RISALA-FP:` and the encoded
//! SafetyNumberCode in upper-case base32.

use std::fmt;

use crate::auth::PublicKey;
use crate::codec::{Reader, Writer};
use crate::names::Identity;
use crate::record::{RecordError, sha384};

/// The label of SafetyNumberContent (12.14, 2.4, 15).
pub const SAFETY_NUMBER_LABEL: &str = "risala-fp-1";

/// The start of a safety number QR code's text (12.14, 15).
pub const SAFETY_QR_PREFIX: &str = "RISALA-FP:";

/// The `version` of SafetyNumberCode (12.14).
pub const SAFETY_CODE_VERSION: u8 = 1;

/// The length of a fingerprint, SHA-384 (12.14).
pub const FINGERPRINT_LEN: usize = 48;

/// An identity's safety number (12.14).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SafetyNumber {
    uid: Identity,
    fingerprint: [u8; FINGERPRINT_LEN],
}

impl SafetyNumber {
    /// The safety number of `uid` with master key `master_key`.
    pub fn new(uid: &Identity, master_key: &PublicKey) -> SafetyNumber {
        let mut w = Writer::new();
        w.vector(SAFETY_NUMBER_LABEL.as_bytes())
            .vector(uid.as_str().as_bytes())
            .vector(master_key.as_bytes());
        SafetyNumber {
            uid: uid.clone(),
            fingerprint: sha384(w.as_bytes()),
        }
    }

    /// The identity.
    pub fn uid(&self) -> &Identity {
        &self.uid
    }

    /// The fingerprint, SHA-384 of the encoded SafetyNumberContent.
    pub fn fingerprint(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.fingerprint
    }

    /// The eight groups of five digits: each is the next 5 bytes of the
    /// fingerprint as a big-endian number, modulo 100000, with leading
    /// zeros (12.14).
    pub fn groups(&self) -> [String; 8] {
        let (chunks, _) = self.fingerprint.as_chunks::<5>();
        std::array::from_fn(|i| {
            let n = chunks[i].iter().fold(0u64, |n, &b| (n << 8) | u64::from(b));
            format!("{:05}", n % 100_000)
        })
    }

    /// The 40 digits, without spaces.
    pub fn digits(&self) -> String {
        self.groups().concat()
    }

    /// The QR code's text: `RISALA-FP:` and the encoded SafetyNumberCode
    /// in upper-case base32 without padding (12.14).
    pub fn to_qr_text(&self) -> String {
        let mut w = Writer::new();
        w.u8(SAFETY_CODE_VERSION)
            .vector(self.uid.as_str().as_bytes())
            .fixed(&self.fingerprint);
        format!(
            "{SAFETY_QR_PREFIX}{}",
            crate::base32::encode(w.as_bytes(), true)
        )
    }

    /// Reads a QR code's text, as [`to_qr_text`](SafetyNumber::to_qr_text)
    /// writes it. A client compares the result with the safety number it
    /// computed itself.
    pub fn from_qr_text(text: &str) -> Result<SafetyNumber, RecordError> {
        let body = text
            .strip_prefix(SAFETY_QR_PREFIX)
            .ok_or(RecordError::Malformed(
                "a safety number code starts RISALA-FP:",
            ))?;
        let bytes = crate::base32::decode(body, true).ok_or(RecordError::Malformed(
            "a safety number code is upper-case base32",
        ))?;
        let mut r = Reader::new(&bytes);
        let version = r.u8()?;
        if version != SAFETY_CODE_VERSION {
            return Err(RecordError::Version(version));
        }
        let uid = std::str::from_utf8(r.vector()?)
            .ok()
            .and_then(|s| s.parse::<Identity>().ok().filter(|id| id.as_str() == s))
            .ok_or(RecordError::Malformed("a uid is an identity in lower case"))?;
        let fingerprint = *r.fixed::<FINGERPRINT_LEN>()?;
        r.end()?;
        Ok(SafetyNumber { uid, fingerprint })
    }
}

impl fmt::Display for SafetyNumber {
    /// The 40 digits in eight groups of five, separated by spaces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.groups().join(" "))
    }
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafetyNumber({} {self})", self.uid)
    }
}

//! RisalaSign and RisalaVerify (4.3).
//!
//! TODO(P2): RisalaSign belongs to `risala-proto` (task P2, 4.3), which
//! was being written at the same time as this crate. This module follows
//! 4.3 exactly; move it there, and use that one, once it exists.
//!
//! ```text
//! struct {
//!     opaque label<V>;      // "risala/1 " + Label
//!     opaque content<V>;
//! } RisalaSignContent;
//! ```
//!
//! RisalaSign(key, Label, Content) is ML-DSA.Sign over the encoded
//! RisalaSignContent, with an empty context and no prehash, hedged.

use crate::codec::Writer;
use crate::mldsa::{SIGNATURE_LEN, SigningKey, verify};

/// The prefix of every RisalaSign label (4.3, 15).
pub const LABEL_PREFIX: &str = "risala/1 ";

/// The label of device bindings (12.3, 15).
pub const KEYPACKAGE_LABEL: &str = "keypackage";

/// The encoded RisalaSignContent for `label` and `content` (4.3).
pub fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.vector(&[LABEL_PREFIX.as_bytes(), label.as_bytes()].concat())
        .vector(content);
    w.into_bytes()
}

/// RisalaSign(key, label, content) (4.3).
pub fn risala_sign(key: &SigningKey, label: &str, content: &[u8]) -> Box<[u8; SIGNATURE_LEN]> {
    key.sign(&sign_content(label, content))
}

/// RisalaVerify: whether `signature` is RisalaSign(key, label, content)
/// for the key whose raw public key is `public_key` (4.3).
pub fn risala_verify(public_key: &[u8], label: &str, content: &[u8], signature: &[u8]) -> bool {
    verify(public_key, &sign_content(label, content), signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_encoding() {
        assert_eq!(
            sign_content("keypackage", b"abc"),
            b"\x13risala/1 keypackage\x03abc"
        );
    }

    #[test]
    fn sign_and_verify() {
        let key = SigningKey::from_seed([5; 32]);
        let signature = risala_sign(&key, KEYPACKAGE_LABEL, b"content");
        assert!(risala_verify(
            key.public_key(),
            KEYPACKAGE_LABEL,
            b"content",
            &signature[..]
        ));
        // Another label, content or key fails.
        assert!(!risala_verify(
            key.public_key(),
            "record",
            b"content",
            &signature[..]
        ));
        assert!(!risala_verify(
            key.public_key(),
            KEYPACKAGE_LABEL,
            b"other",
            &signature[..]
        ));
        let other = SigningKey::from_seed([6; 32]);
        assert!(!risala_verify(
            other.public_key(),
            KEYPACKAGE_LABEL,
            b"content",
            &signature[..]
        ));
        // It is not an MLS signature: SignWithLabel's content differs.
        let mut mls = Writer::new();
        mls.vector(b"MLS 1.0 keypackage").vector(b"content");
        assert!(!verify(key.public_key(), &mls.into_bytes(), &signature[..]));
    }
}

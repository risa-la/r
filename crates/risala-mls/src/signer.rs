//! A device's signer and credential (12.2).
//!
//! A device signs in MLS with the same ML-DSA-44 key it signs in with
//! (4.5): a [`SecretKey`], as librisala's key store holds it. The key stays
//! with the caller. OpenMLS gets a [`DeviceSigner`] that borrows it, so the
//! private key is never written to OpenMLS storage (PLAN.md 22).
//!
//! A leaf's credential is a `basic` credential whose identity is the uid
//! in lower case, and its signature key is the raw 1312-byte public key.

use openmls::prelude::{BasicCredential, Credential, CredentialType, CredentialWithKey};
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use risala_proto::auth::{PUBLIC_KEY_LEN, PublicKey, SecretKey};

/// Signs for OpenMLS, and for encrypted messages (12.8), with a device key.
///
/// Signatures are ML-DSA-44 with an empty context and the deterministic
/// variant. The key signs only MLS SignContent through this, never
/// anything else (see [`SecretKey::sign_mls`]).
#[derive(Clone, Copy)]
pub struct DeviceSigner<'a> {
    key: &'a SecretKey,
}

impl<'a> DeviceSigner<'a> {
    /// A signer for `key`.
    pub fn new(key: &'a SecretKey) -> DeviceSigner<'a> {
        DeviceSigner { key }
    }

    /// The device key.
    pub fn key(&self) -> &'a SecretKey {
        self.key
    }

    /// The device's public key, the leaf's signature key (12.2).
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }
}

impl std::fmt::Debug for DeviceSigner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DeviceSigner").field(self.key).finish()
    }
}

impl Signer for DeviceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.key
            .sign_mls(payload)
            .map(|signature| signature.as_bytes().to_vec())
            .ok_or(SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::MLDSA44
    }
}

/// The credential and signature key of a device of `uid` (12.2): a basic
/// credential with the uid in lower case, and the raw public key.
pub fn credential_with_key(uid: &str, key: &PublicKey) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(uid.to_lowercase().into_bytes()).into(),
        signature_key: key.as_bytes().to_vec().into(),
    }
}

/// The uid in a leaf's credential, or `None` if it is not a basic
/// credential whose identity is a lower-case UTF-8 string (12.2). The
/// caller still checks that it is a uid it expects.
pub fn credential_uid(credential: &Credential) -> Option<String> {
    if credential.credential_type() != CredentialType::Basic {
        return None;
    }
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    let uid = String::from_utf8(basic.identity().to_vec()).ok()?;
    (uid.to_lowercase() == uid).then_some(uid)
}

/// A leaf's signature key as a device key, or `None` if it is not 1312
/// bytes long (12.2).
pub fn signature_key(bytes: &[u8]) -> Option<PublicKey> {
    let bytes: &[u8; PUBLIC_KEY_LEN] = bytes.try_into().ok()?;
    Some(PublicKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::sign_content;

    #[test]
    fn signs_with_the_device_key() {
        let key = SecretKey::from_seed([3; 32]);
        let signer = DeviceSigner::new(&key);
        assert_eq!(signer.signature_scheme(), SignatureScheme::MLDSA44);
        let content = sign_content("LeafNodeTBS", b"leaf");
        let signature = signer.sign(&content).unwrap();
        assert!(crate::verify_ml_dsa_44(
            &key.public_key(),
            &content,
            &signature
        ));
        // Deterministic, and only for SignContent.
        assert_eq!(signer.sign(&content).unwrap(), signature);
        assert_eq!(
            signer.sign(b"risala-auth-1\n"),
            Err(SignerError::SigningError)
        );
        assert!(!format!("{signer:?}").contains("seed"));
    }

    #[test]
    fn credentials() {
        let key = SecretKey::from_seed([4; 32]).public_key();
        let cwk = credential_with_key("Alice@Example.org", &key);
        assert_eq!(
            credential_uid(&cwk.credential).unwrap(),
            "alice@example.org"
        );
        assert_eq!(signature_key(cwk.signature_key.as_slice()), Some(key));
        assert_eq!(signature_key(&[0; 32]), None);

        let upper: Credential = BasicCredential::new(b"Alice@example.org".to_vec()).into();
        assert_eq!(credential_uid(&upper), None);
        let binary: Credential = BasicCredential::new(vec![0xff]).into();
        assert_eq!(credential_uid(&binary), None);
    }
}

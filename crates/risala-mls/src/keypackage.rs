//! Checking KeyPackages (12.4).
//!
//! The server checks each KeyPackage of KEYPKG ADD with
//! [`check_key_package`], and the server and devices check the lifetime of
//! each KeyPackage a commit adds with [`lifetime_acceptable`] (12.5, 12.6).
//! OpenMLS checks that a lifetime holds the current time, but not how long
//! it spans.

use std::time::SystemTime;

use openmls::prelude::{KeyPackage, KeyPackageVerifyError, Lifetime, ProtocolVersion};
use openmls::treesync::EncryptionKey;
use openmls_traits::crypto::OpenMlsCrypto;
use risala_proto::auth::PublicKey;
use risala_proto::mls;
use risala_proto::names::Uid;

use crate::CIPHERSUITE;
use crate::group::{MAX_LIFETIME_SPAN, has_capabilities};
use crate::signer::credential_uid;
use crate::wire::{WireError, key_package_from_wire};

/// Why a KeyPackage is not acceptable (12.4). A server answers each with
/// `ERR invalid`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyPackageError {
    /// It is not an MLSMessage holding a KeyPackage.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// It uses another cipher suite than `0x0052`.
    #[error("the KeyPackage uses another cipher suite")]
    CipherSuite,
    /// A signature does not verify, or OpenMLS finds it invalid otherwise.
    #[error("the KeyPackage is not valid MLS")]
    Invalid,
    /// Its credential is not a basic credential with the expected uid.
    #[error("the KeyPackage's credential is not the uid")]
    Credential,
    /// Its signature key is not the expected device key.
    #[error("the KeyPackage's signature key is not the device key")]
    SignatureKey,
    /// Its leaf does not list the conversation extension and
    /// `last_resort` in its capabilities, or the suite and `basic`
    /// credentials.
    #[error("the KeyPackage's leaf lacks capabilities")]
    Capabilities,
    /// Its lifetime does not hold the current time, or spans more than 12
    /// weeks and one hour.
    #[error("the KeyPackage's lifetime is not acceptable")]
    Lifetime,
    /// Its init key or its leaf's encryption key is not an X-Wing public
    /// key of the right length, which would crash whoever encrypts to it
    /// (see [`crate::crypto::X_WING_PUBLIC_KEY_LEN`]).
    #[error("the KeyPackage has an HPKE key of the wrong length")]
    HpkeKey,
}

/// Whether `key` has the length of an X-Wing public key, the HPKE keys of
/// the suite (12.2). Init keys, leaves' encryption keys, parent nodes' keys
/// and a GroupInfo's `external_pub` must all pass, since OpenMLS does not
/// check their length.
pub fn hpke_public_key_ok(key: &[u8]) -> bool {
    key.len() == crate::crypto::X_WING_PUBLIC_KEY_LEN
}

/// [`hpke_public_key_ok`] for a leaf's or parent node's encryption key,
/// whose bytes OpenMLS keeps private: they are read from its TLS encoding,
/// a variable-length vector.
pub fn encryption_key_ok(key: &EncryptionKey) -> bool {
    use tls_codec::{DeserializeBytes as _, Serialize as _};
    let Ok(encoded) = key.tls_serialize_detached() else {
        return false;
    };
    matches!(
        tls_codec::VLBytes::tls_deserialize_exact_bytes(&encoded),
        Ok(bytes) if hpke_public_key_ok(bytes.as_slice())
    )
}

/// A KeyPackage that passed [`check_key_package`].
#[derive(Debug, Clone)]
pub struct CheckedKeyPackage {
    /// The KeyPackage.
    pub key_package: KeyPackage,
    /// Whether it has the `last_resort` extension (12.4).
    pub last_resort: bool,
    /// The end of its lifetime, in seconds since the Unix epoch. A server
    /// deletes it then (12.4).
    pub not_after: u64,
}

/// Whether a KeyPackage's lifetime is acceptable at `now` (12.4): `now`
/// is within it, and it spans at most 12 weeks and one hour.
pub fn lifetime_acceptable(lifetime: &Lifetime, now: SystemTime) -> bool {
    lifetime.validate_with_time(now).is_ok()
        && lifetime.not_after().saturating_sub(lifetime.not_before()) <= MAX_LIFETIME_SPAN
}

/// Checks a KeyPackage of KEYPKG ADD from `uid`'s device with key `key`
/// (12.4): the cipher suite, the credential, the signature key, the leaf's
/// capabilities, the signatures, and the lifetime at `now`.
pub fn check_key_package(
    crypto: &impl OpenMlsCrypto,
    value: &mls::KeyPackage,
    uid: &Uid,
    key: &PublicKey,
    now: SystemTime,
) -> Result<CheckedKeyPackage, KeyPackageError> {
    let unchecked = key_package_from_wire(value)?;
    // This is checked again below, on the verified KeyPackage, but the
    // cheap check comes before the signatures.
    let claimed = unchecked.unverified_credential();
    if claimed.signature_key.as_slice() != key.as_bytes() {
        return Err(KeyPackageError::SignatureKey);
    }
    let key_package = match unchecked.validate(crypto, ProtocolVersion::Mls10) {
        Ok(key_package) => key_package,
        // OpenMLS checks the lifetime against the clock itself.
        Err(KeyPackageVerifyError::LifetimeError(_) | KeyPackageVerifyError::MissingLifetime) => {
            return Err(KeyPackageError::Lifetime);
        }
        Err(_) => return Err(KeyPackageError::Invalid),
    };
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(KeyPackageError::CipherSuite);
    }
    let leaf = key_package.leaf_node();
    if leaf.signature_key().as_slice() != key.as_bytes() {
        return Err(KeyPackageError::SignatureKey);
    }
    if !hpke_public_key_ok(key_package.hpke_init_key().as_slice())
        || !encryption_key_ok(leaf.encryption_key())
    {
        return Err(KeyPackageError::HpkeKey);
    }
    if credential_uid(leaf.credential()).as_deref() != Some(uid.as_str()) {
        return Err(KeyPackageError::Credential);
    }
    if !has_capabilities(leaf.capabilities()) {
        return Err(KeyPackageError::Capabilities);
    }
    let lifetime = *key_package.life_time();
    if !lifetime_acceptable(&lifetime, now) {
        return Err(KeyPackageError::Lifetime);
    }
    Ok(CheckedKeyPackage {
        last_resort: key_package.last_resort(),
        not_after: lifetime.not_after(),
        key_package,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::X_WING_PUBLIC_KEY_LEN;

    #[test]
    fn hpke_keys_must_be_x_wing_sized() {
        assert!(hpke_public_key_ok(&[1; X_WING_PUBLIC_KEY_LEN]));
        assert!(encryption_key_ok(&EncryptionKey::from(
            vec![1; X_WING_PUBLIC_KEY_LEN]
        )));
        for len in [
            0,
            10,
            1184,
            X_WING_PUBLIC_KEY_LEN - 1,
            X_WING_PUBLIC_KEY_LEN + 1,
        ] {
            assert!(!hpke_public_key_ok(&vec![1; len]), "{len}");
            assert!(
                !encryption_key_ok(&EncryptionKey::from(vec![1; len])),
                "{len}"
            );
        }
    }
}

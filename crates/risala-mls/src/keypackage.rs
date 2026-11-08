//! Checking KeyPackages (12.4).
//!
//! The server checks each KeyPackage of KEYPKG ADD with
//! [`check_key_package`], and the server and devices check the lifetime of
//! each KeyPackage a commit adds with [`lifetime_acceptable`] (12.5, 12.6).
//! OpenMLS checks that a lifetime holds the current time, but not how long
//! it spans.

use std::time::SystemTime;

use openmls::prelude::{KeyPackage, KeyPackageVerifyError, Lifetime, ProtocolVersion};
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

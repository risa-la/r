//! KeyPackages (12.5): making them, and the checks of KEYPKG ADD.
//!
//! A device's KeyPackage has:
//!
//! - a credential with its RisalaIdentity (12.3), and a fresh leaf key of
//!   its own, so that each group the device joins gets a different one;
//! - the leaf's capabilities (12.3) and a profile (12.3);
//! - a device binding (`0xF2A2`) among its extensions, signed by the
//!   device key over the uid, the init key and the leaf's encryption key;
//! - if it is the device's KeyPackage of last resort, the
//!   `app_data_dictionary` extension (`0x0006`) holding the
//!   `last_resort_key_package` component (`0x0004`) with empty data
//!   [MLS-EXT, draft-11] (12.5, 15).
//!
//! OpenMLS 0.9 knows only the older `last_resort` extension (`0x000A`) and,
//! without its `extensions-draft` feature, reads `0x0006` as an unknown
//! extension. This crate writes and reads the dictionary itself, so no
//! patch is needed. OpenMLS deletes a KeyPackage's private keys once a
//! Welcome uses it unless it has the old extension, so
//! [`crate::group::join_by_welcome`] stores a last-resort one again.

use std::time::SystemTime;

use openmls::prelude::{
    Extension, ExtensionType, Extensions, KeyPackage, KeyPackageBundle, KeyPackageIn,
    KeyPackageNewError, KeyPackageVerifyError, Lifetime, MlsMessageBodyIn, MlsMessageIn,
    ProtocolVersion, UnknownExtension,
};
use openmls::treesync::EncryptionKey;
use openmls_memory_storage::MemoryStorage;
use openmls::storage::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use risala_proto::names::Uid;
use tls_codec::Deserialize as _;

use crate::CIPHERSUITE;
use crate::binding::DeviceBinding;
use crate::codec::{DecodeError, Reader, Writer};
use crate::crypto::x_wing_public_key_ok;
use crate::group::{capabilities, has_capabilities};
use crate::identity::{DeviceId, RisalaIdentity};
use crate::mldsa::{KEY_PACKAGE_SCOPE, LeafKey, SigningKey};
use crate::profile::RisalaProfile;
use crate::seeded::{Parts, SeededRand};

/// How long a KeyPackage is valid after it is made: 12 weeks (12.5).
/// OpenMLS starts the lifetime an hour early, for clocks that are behind,
/// so it spans [`MAX_LIFETIME_SPAN`].
pub const KEY_PACKAGE_LIFETIME: u64 = 12 * 7 * 24 * 60 * 60;

/// The longest lifetime a KeyPackage may span, from `not_before` to
/// `not_after`: 12 weeks and one hour, 7261200 seconds (12.5).
pub const MAX_LIFETIME_SPAN: u64 = KEY_PACKAGE_LIFETIME + 60 * 60;

/// The extension type of `app_data_dictionary` [MLS-EXT] (12.5, 15).
pub const APP_DATA_DICTIONARY_EXTENSION_TYPE: u16 = 0x0006;

/// `app_data_dictionary`, as OpenMLS names it without its
/// `extensions-draft` feature.
pub const APP_DATA_DICTIONARY_EXTENSION: ExtensionType =
    ExtensionType::Unknown(APP_DATA_DICTIONARY_EXTENSION_TYPE);

/// The component id of `last_resort_key_package` [MLS-EXT] (12.5, 15).
pub const LAST_RESORT_COMPONENT: u16 = 0x0004;

/// The `app_data_dictionary` extension of a last-resort KeyPackage: one
/// ComponentData, `last_resort_key_package` with empty data.
///
/// ```text
/// struct { uint16 component_id; opaque data<V>; } ComponentData;
/// struct { ComponentData component_data<V>; } AppDataDictionary;
/// ```
pub fn last_resort_extension() -> Extension {
    let mut entry = Writer::new();
    entry
        .fixed(&LAST_RESORT_COMPONENT.to_be_bytes())
        .vector(b"");
    let mut dictionary = Writer::new();
    dictionary.vector(&entry.into_bytes());
    Extension::Unknown(
        APP_DATA_DICTIONARY_EXTENSION_TYPE,
        UnknownExtension(dictionary.into_bytes()),
    )
}

/// Reads an AppDataDictionary: its component ids and data, which must be
/// in ascending order with no id twice [MLS-EXT].
fn read_dictionary(bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, DecodeError> {
    let mut outer = Reader::new(bytes);
    let entries = outer.vector()?;
    outer.finish()?;
    let mut r = Reader::new(entries);
    let mut out: Vec<(u16, &[u8])> = Vec::new();
    while r.remaining() > 0 {
        let id = r.u16()?;
        let data = r.vector()?;
        if out.last().is_some_and(|(last, _)| *last >= id) {
            return Err(DecodeError("dictionary not in ascending order"));
        }
        out.push((id, data));
    }
    Ok(out)
}

/// Whether a KeyPackage is marked as of last resort (12.5): its
/// `app_data_dictionary` holds `last_resort_key_package` with empty data.
/// A malformed dictionary is an error.
pub fn is_last_resort(key_package: &KeyPackage) -> Result<bool, DecodeError> {
    let Some(extension) = key_package
        .extensions()
        .unknown(APP_DATA_DICTIONARY_EXTENSION_TYPE)
    else {
        return Ok(false);
    };
    let entries = read_dictionary(&extension.0)?;
    match entries.iter().find(|(id, _)| *id == LAST_RESORT_COMPONENT) {
        None => Ok(false),
        Some((_, [])) => Ok(true),
        Some(_) => Err(DecodeError("last_resort_key_package with data")),
    }
}

/// A new KeyPackage, with the leaf key it was made with.
#[derive(Debug)]
pub struct NewKeyPackage {
    /// The KeyPackage, for KEYPKG ADD. Its private keys are in the
    /// provider's storage, under its KeyPackageRef.
    pub key_package: KeyPackage,
    /// Its leaf key, also in the provider's storage, under
    /// [`KEY_PACKAGE_SCOPE`] until a Welcome uses it.
    pub leaf_key: LeafKey,
}

/// Why a KeyPackage could not be made.
#[derive(Debug, thiserror::Error)]
pub enum NewKeyPackageError<E> {
    /// No randomness for the leaf key or the seed.
    #[error("no randomness")]
    Random,
    /// OpenMLS could not build it.
    #[error(transparent)]
    Build(#[from] KeyPackageNewError),
    /// The leaf key could not be stored.
    #[error("storage: {0:?}")]
    Storage(E),
}

/// Makes a KeyPackage of the device whose key is `device_key`, for `uid`
/// (12.5), with a lifetime of [`KEY_PACKAGE_LIFETIME`] and the leaf's
/// profile `profile`. `last_resort` marks it as the device's KeyPackage of
/// last resort.
///
/// The profile is shown to the server and to whoever fetches the
/// KeyPackage with KEYPKG GET, so give it an empty display name: the
/// device sets its name in its first commit in the group. Its `updated`
/// should be the current time.
pub fn make_key_package<P: OpenMlsProvider>(
    provider: &P,
    device_key: &SigningKey,
    uid: &Uid,
    profile: &RisalaProfile,
    last_resort: bool,
) -> Result<NewKeyPackage, NewKeyPackageError<P::StorageError>> {
    let leaf_key = LeafKey::generate().map_err(|_| NewKeyPackageError::Random)?;
    let identity = RisalaIdentity::device(
        uid.clone(),
        DeviceId::of_device_key(device_key.public_key()),
    );
    let credential = identity.credential_with_key(leaf_key.public_key());
    let leaf_extensions = Extensions::single(profile.to_extension())
        .expect("a profile is valid in a leaf node");
    // First the keys, to bind them (see crate::seeded), then the real one.
    let seed = SeededRand::fresh().map_err(|_| NewKeyPackageError::Random)?;
    let scratch = MemoryStorage::default();
    let first = build_key_package(
        &Parts {
            crypto: provider.crypto(),
            rand: &SeededRand::new(&seed),
            storage: &scratch,
        },
        &leaf_key,
        credential.clone(),
        leaf_extensions.clone(),
        Vec::new(),
    )?;
    let binding = DeviceBinding::sign(
        device_key,
        uid,
        first.key_package().hpke_init_key().as_slice(),
        &encryption_key_bytes(first.key_package().leaf_node().encryption_key()),
    );
    let mut extensions = vec![binding.to_extension()];
    if last_resort {
        extensions.push(last_resort_extension());
    }
    let bundle = build_key_package(
        &Parts {
            crypto: provider.crypto(),
            rand: &SeededRand::new(&seed),
            storage: provider.storage(),
        },
        &leaf_key,
        credential,
        leaf_extensions,
        extensions,
    )?;
    leaf_key
        .store(provider.storage(), KEY_PACKAGE_SCOPE)
        .map_err(NewKeyPackageError::Storage)?;
    Ok(NewKeyPackage {
        key_package: bundle.key_package().clone(),
        leaf_key,
    })
}

fn build_key_package<P: OpenMlsProvider>(
    provider: &P,
    leaf_key: &LeafKey,
    credential: openmls::prelude::CredentialWithKey,
    leaf_extensions: Extensions<openmls::prelude::LeafNode>,
    extensions: Vec<Extension>,
) -> Result<KeyPackageBundle, KeyPackageNewError> {
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .leaf_node_extensions(leaf_extensions)
        .key_package_extensions(
            Extensions::from_vec(extensions).expect("distinct KeyPackage extensions"),
        )
        .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME))
        .build(CIPHERSUITE, provider, leaf_key, credential)
}

/// A leaf's HPKE public key, as bytes. OpenMLS keeps them private, so
/// they are read from its TLS encoding, a variable-size vector.
pub fn encryption_key_bytes(key: &EncryptionKey) -> Vec<u8> {
    use tls_codec::Serialize as _;
    let encoded = key
        .tls_serialize_detached()
        .expect("OpenMLS serialises its keys");
    let mut r = Reader::new(&encoded);
    r.vector().map(<[u8]>::to_vec).unwrap_or_default()
}

/// Why a KeyPackage is not acceptable (12.5, 12.7). A server answers each
/// with `ERR invalid`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyPackageError {
    /// It is not an MLSMessage holding one KeyPackage.
    #[error("not a KeyPackage")]
    Malformed,
    /// Its protocol version is not `mls10`, or its suite not `0x0020`.
    #[error("the KeyPackage uses another protocol version or cipher suite")]
    CipherSuite,
    /// A signature does not verify, or OpenMLS finds it invalid otherwise.
    #[error("the KeyPackage is not valid MLS")]
    Invalid,
    /// Its credential is not a RisalaIdentity of the expected uid and
    /// device, or is a guest's.
    #[error("the KeyPackage's credential is not the device's")]
    Credential,
    /// It has no device binding, or one that does not verify under the
    /// device key over its init and encryption keys.
    #[error("the KeyPackage's device binding does not verify")]
    Binding,
    /// Its leaf has no well-formed profile.
    #[error("the KeyPackage's leaf has no profile")]
    Profile,
    /// Its leaf does not list the capabilities of 12.3.
    #[error("the KeyPackage's leaf lacks capabilities")]
    Capabilities,
    /// Its init key or its leaf's encryption key fails the checks of 12.2.
    #[error("the KeyPackage has an HPKE key that fails the checks")]
    HpkeKey,
    /// Its lifetime does not hold the current time, or spans more than 12
    /// weeks and one hour.
    #[error("the KeyPackage's lifetime is not acceptable")]
    Lifetime,
    /// Its `app_data_dictionary` is malformed.
    #[error("the KeyPackage's app_data_dictionary is malformed")]
    Dictionary,
}

/// Whether a KeyPackage's lifetime is acceptable at `now` (12.5): `now` is
/// within it, and it spans at most 12 weeks and one hour.
pub fn lifetime_acceptable(lifetime: &Lifetime, now: SystemTime) -> bool {
    let Ok(now) = now.duration_since(SystemTime::UNIX_EPOCH) else {
        return false;
    };
    let now = now.as_secs();
    lifetime.not_before() <= now
        && now <= lifetime.not_after()
        && lifetime.not_after().saturating_sub(lifetime.not_before()) <= MAX_LIFETIME_SPAN
}

/// A KeyPackage that passed [`check_key_package`].
#[derive(Debug, Clone)]
pub struct CheckedKeyPackage {
    /// The KeyPackage.
    pub key_package: KeyPackage,
    /// Whether it is of last resort (12.5).
    pub last_resort: bool,
    /// The end of its lifetime, in seconds since the Unix epoch. A server
    /// deletes it then (12.5).
    pub not_after: u64,
}

/// Reads a KeyPackage from the bytes of an MLSMessage, unchecked.
pub fn read_key_package(bytes: &[u8]) -> Result<KeyPackageIn, KeyPackageError> {
    match MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| KeyPackageError::Malformed)?
        .extract()
    {
        MlsMessageBodyIn::KeyPackage(key_package) => Ok(key_package),
        _ => Err(KeyPackageError::Malformed),
    }
}

/// The checks of 12.5 and 12.7 on a KeyPackage whose signatures OpenMLS
/// has verified: the suite, the credential is a RisalaIdentity of a
/// device (not a guest), the leaf's capabilities and profile, the HPKE
/// keys, the lifetime at `now`, and the dictionary. Returns the identity.
///
/// The device binding is checked by the caller, which knows the device
/// key (see [`check_binding`]).
pub fn check_key_package_contents(
    key_package: &KeyPackage,
    now: SystemTime,
) -> Result<(RisalaIdentity, bool), KeyPackageError> {
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(KeyPackageError::CipherSuite);
    }
    let leaf = key_package.leaf_node();
    let identity =
        RisalaIdentity::from_credential(leaf.credential()).map_err(|_| KeyPackageError::Credential)?;
    if identity.is_guest() {
        // Guests have no device key to bind with, and join public rooms by
        // external commit (6.1). A guest KeyPackage for an external
        // proposal is checked by `check_guest_key_package`.
        return Err(KeyPackageError::Credential);
    }
    check_leaf_parts(key_package, now, true)?;
    let last_resort = is_last_resort(key_package).map_err(|_| KeyPackageError::Dictionary)?;
    Ok((identity, last_resort))
}

/// The checks every KeyPackage gets, a guest's too: capabilities, HPKE keys
/// and lifetime, and a profile for a device's (12.3).
fn check_leaf_parts(
    key_package: &KeyPackage,
    now: SystemTime,
    needs_profile: bool,
) -> Result<(), KeyPackageError> {
    let leaf = key_package.leaf_node();
    if !has_capabilities(leaf.capabilities()) {
        return Err(KeyPackageError::Capabilities);
    }
    if needs_profile && RisalaProfile::of_leaf(leaf).is_none() {
        return Err(KeyPackageError::Profile);
    }
    if !x_wing_public_key_ok(key_package.hpke_init_key().as_slice())
        || !x_wing_public_key_ok(&encryption_key_bytes(leaf.encryption_key()))
    {
        return Err(KeyPackageError::HpkeKey);
    }
    if !lifetime_acceptable(key_package.life_time(), now) {
        return Err(KeyPackageError::Lifetime);
    }
    Ok(())
}

/// The checks of a guest's KeyPackage in an external Add proposal (6.1):
/// a guest credential, and [`check_leaf_parts`]. Guests have no binding.
pub fn check_guest_key_package(
    key_package: &KeyPackage,
    now: SystemTime,
) -> Result<RisalaIdentity, KeyPackageError> {
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(KeyPackageError::CipherSuite);
    }
    let identity = RisalaIdentity::from_credential(key_package.leaf_node().credential())
        .map_err(|_| KeyPackageError::Credential)?;
    if !identity.is_guest() {
        return Err(KeyPackageError::Credential);
    }
    check_leaf_parts(key_package, now, false)?;
    Ok(identity)
}

/// Whether the KeyPackage's device binding verifies under `device_key`,
/// the raw key of the device its credential names, over its uid, init key
/// and leaf encryption key (12.3).
pub fn check_binding(
    key_package: &KeyPackage,
    identity: &RisalaIdentity,
    device_key: &[u8],
) -> Result<(), KeyPackageError> {
    let binding = DeviceBinding::from_extensions(key_package.extensions())
        .ok_or(KeyPackageError::Binding)?
        .map_err(|_| KeyPackageError::Binding)?;
    let ok = identity.device_id == Some(binding.device_id)
        && binding.verify(
            device_key,
            &identity.uid,
            key_package.hpke_init_key().as_slice(),
            &encryption_key_bytes(key_package.leaf_node().encryption_key()),
        );
    if ok {
        Ok(())
    } else {
        Err(KeyPackageError::Binding)
    }
}

/// Verifies a KeyPackage's signatures with OpenMLS.
pub fn verify_key_package(
    crypto: &impl OpenMlsCrypto,
    key_package: KeyPackageIn,
) -> Result<KeyPackage, KeyPackageError> {
    match key_package.validate(crypto, ProtocolVersion::Mls10) {
        Ok(key_package) => Ok(key_package),
        Err(KeyPackageVerifyError::LifetimeError(_) | KeyPackageVerifyError::MissingLifetime) => {
            Err(KeyPackageError::Lifetime)
        }
        Err(_) => Err(KeyPackageError::Invalid),
    }
}

/// The server's checks of KEYPKG ADD (12.5): `bytes` is an MLSMessage
/// holding a KeyPackage of `mls10` and the suite `0x0020`, whose
/// credential is a RisalaIdentity of `uid` and the device whose raw device
/// key is `device_key`, with a device binding by that key over its init
/// and encryption keys, the capabilities of 12.3, a profile, HPKE keys
/// that pass the checks of 12.2, valid signatures, and an acceptable
/// lifetime at `now`.
pub fn check_key_package(
    crypto: &impl OpenMlsCrypto,
    bytes: &[u8],
    uid: &Uid,
    device_key: &[u8],
    now: SystemTime,
) -> Result<CheckedKeyPackage, KeyPackageError> {
    match crate::framing::read_message(bytes) {
        Ok(crate::framing::MlsMessage::KeyPackage) => {}
        Err(
            crate::framing::FramingError::CipherSuite | crate::framing::FramingError::Version,
        ) => return Err(KeyPackageError::CipherSuite),
        _ => return Err(KeyPackageError::Malformed),
    }
    let key_package = verify_key_package(crypto, read_key_package(bytes)?)?;
    let (identity, last_resort) = check_key_package_contents(&key_package, now)?;
    let expected = RisalaIdentity::device(uid.clone(), DeviceId::of_device_key(device_key));
    if identity != expected {
        return Err(KeyPackageError::Credential);
    }
    check_binding(&key_package, &identity, device_key)?;
    let not_after = key_package.life_time().not_after();
    Ok(CheckedKeyPackage {
        key_package,
        last_resort,
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_resort_encoding() {
        let Extension::Unknown(0x0006, UnknownExtension(data)) = last_resort_extension() else {
            panic!("not an unknown extension");
        };
        assert_eq!(data, b"\x03\x00\x04\x00");
        assert_eq!(read_dictionary(&data), Ok(vec![(4, &b""[..])]));
        // Order and uniqueness.
        assert!(read_dictionary(b"\x06\x00\x04\x00\x00\x02\x00").is_err());
        assert!(read_dictionary(b"\x06\x00\x04\x00\x00\x04\x00").is_err());
        assert_eq!(
            read_dictionary(b"\x07\x00\x02\x00\x00\x04\x01x"),
            Ok(vec![(2, &b""[..]), (4, &b"x"[..])])
        );
        assert!(read_dictionary(b"\x03\x00\x04\x00\x00").is_err());
        // Without the extensions-draft feature, OpenMLS reads 0x0006 as an
        // unknown extension, so this crate's encoding is the one used.
        assert_eq!(ExtensionType::from(6), APP_DATA_DICTIONARY_EXTENSION);
    }

    #[test]
    fn lifetimes() {
        let now = SystemTime::now();
        assert!(lifetime_acceptable(&Lifetime::new(KEY_PACKAGE_LIFETIME), now));
        assert!(!lifetime_acceptable(
            &Lifetime::new(KEY_PACKAGE_LIFETIME + 1),
            now
        ));
        assert!(!lifetime_acceptable(
            &Lifetime::new(KEY_PACKAGE_LIFETIME),
            now + std::time::Duration::from_secs(KEY_PACKAGE_LIFETIME + 10)
        ));
    }
}

//! KeyPackages (12.5): making them, and the checks of KEYPKG ADD.
//!
//! A device's KeyPackage has:
//!
//! - a credential with its RisalaIdentity (12.3), and a fresh leaf key of
//!   its own, so that each group the device joins gets a different one;
//! - the leaf's capabilities (12.3) and a profile (12.3);
//! - a device binding (`0xF2A2`) among its leaf node's extensions, signed
//!   by the device key over the uid, the init key and the leaf's encryption
//!   key, except in a KeyPackage made to join a public room, which has none
//!   (12.3, 6.1);
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
use openmls::storage::OpenMlsProvider;
use openmls::treesync::EncryptionKey;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};
use risala_proto::names::Uid;
use risala_proto::time::Timestamp;
use tls_codec::Deserialize as _;

use crate::CIPHERSUITE;
use crate::binding::DeviceBinding;
use crate::checks::PERIOD_MS;
use crate::codec::{DecodeError, Reader, Writer};
use crate::crypto::x_wing_public_key_ok;
use crate::group::{GroupError, capabilities, has_capabilities};
use crate::identity::{RisalaIdentity, device_id_of};
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
    /// OpenMLS made other keys on the second build, so the binding would
    /// not cover them (see `crate::seeded`).
    #[error("OpenMLS made other keys on the second build")]
    Unbound,
}

/// Makes a KeyPackage of the device whose key is `device_key`, for `uid`,
/// to upload with KEYPKG ADD (12.5), with a lifetime of
/// [`KEY_PACKAGE_LIFETIME`], the leaf's profile `profile`, and a device
/// binding in its leaf node (12.3). `last_resort` marks it as the device's
/// KeyPackage of last resort. `now` is the device's time, from which the
/// lifetime is counted ([`key_package_lifetime`]).
///
/// The profile is shown to the server and to whoever fetches the
/// KeyPackage with KEYPKG GET, so give it an empty display name: the
/// device sets its name in its first commit in the group. Its `updated`
/// should be the current time. For a last-resort KeyPackage it is moved
/// back to the start of the period before the one it falls in (12.3), so
/// that a device added from it may change its signature key at once in an
/// epochal group.
pub fn make_key_package<P: OpenMlsProvider>(
    provider: &P,
    device_key: &SigningKey,
    uid: &Uid,
    profile: &RisalaProfile,
    last_resort: bool,
    now: Timestamp,
) -> Result<NewKeyPackage, NewKeyPackageError<P::StorageError>> {
    make_key_package_with(
        provider,
        device_key,
        uid,
        profile,
        last_resort,
        key_package_lifetime(now),
    )
}

/// The lifetime of a KeyPackage made at `now` (12.5): from an hour before
/// `now`, for clocks that run slow, to [`KEY_PACKAGE_LIFETIME`] after it.
/// As OpenMLS's `Lifetime::new`, but from the caller's clock rather than
/// the system's, so that a client with a replaced clock stamps its own
/// time.
pub fn key_package_lifetime(now: Timestamp) -> Lifetime {
    let now = now.unix_millis() / 1000;
    Lifetime::init(now.saturating_sub(60 * 60), now + KEY_PACKAGE_LIFETIME)
}

/// A last-resort KeyPackage's `updated` (12.3): the start of the period
/// (12.10) before the one that `made`, in ms, falls in.
pub fn last_resort_updated(made: u64) -> u64 {
    (made / PERIOD_MS).saturating_sub(1) * PERIOD_MS
}

/// [`make_key_package`] with a given lifetime, for tests.
pub(crate) fn make_key_package_with<P: OpenMlsProvider>(
    provider: &P,
    device_key: &SigningKey,
    uid: &Uid,
    profile: &RisalaProfile,
    last_resort: bool,
    lifetime: Lifetime,
) -> Result<NewKeyPackage, NewKeyPackageError<P::StorageError>> {
    let leaf_key = LeafKey::generate().map_err(|_| NewKeyPackageError::Random)?;
    let identity = RisalaIdentity::device(uid.clone(), device_key.device_id());
    let credential = identity.credential_with_key(leaf_key.public_key());
    let mut profile = profile.clone().with_streak(0);
    if last_resort {
        profile.updated = last_resort_updated(profile.updated);
    }
    let extensions = if last_resort {
        vec![last_resort_extension()]
    } else {
        Vec::new()
    };
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
        vec![profile.to_extension()],
        extensions.clone(),
        lifetime,
    )?;
    let binding = DeviceBinding::sign(
        device_key,
        uid,
        first.key_package().hpke_init_key().as_slice(),
        &encryption_key_bytes(first.key_package().leaf_node().encryption_key()),
    );
    let bundle = build_key_package(
        &Parts {
            crypto: provider.crypto(),
            rand: &SeededRand::new(&seed),
            storage: provider.storage(),
        },
        &leaf_key,
        credential,
        vec![profile.to_extension(), binding.to_extension()],
        extensions,
        lifetime,
    )?;
    if bundle.key_package().hpke_init_key() != first.key_package().hpke_init_key() {
        return Err(NewKeyPackageError::Unbound);
    }
    leaf_key
        .store(provider.storage(), KEY_PACKAGE_SCOPE)
        .map_err(NewKeyPackageError::Storage)?;
    Ok(NewKeyPackage {
        key_package: bundle.key_package().clone(),
        leaf_key,
    })
}

/// Makes a KeyPackage to join one public room by external proposal (6.1):
/// with no device binding, never uploaded with KEYPKG ADD, and a fresh leaf
/// key, whose credential is `identity`, a device's or a guest's. A
/// device's leaf carries `profile`; a guest's may carry none (12.3). Its
/// lifetime is counted from `now` ([`key_package_lifetime`]).
pub fn make_join_key_package<P: OpenMlsProvider>(
    provider: &P,
    identity: &RisalaIdentity,
    profile: Option<&RisalaProfile>,
    now: Timestamp,
) -> Result<NewKeyPackage, NewKeyPackageError<P::StorageError>> {
    make_join_key_package_with(provider, identity, profile, key_package_lifetime(now))
}

/// [`make_join_key_package`] with a given lifetime, for tests.
pub(crate) fn make_join_key_package_with<P: OpenMlsProvider>(
    provider: &P,
    identity: &RisalaIdentity,
    profile: Option<&RisalaProfile>,
    lifetime: Lifetime,
) -> Result<NewKeyPackage, NewKeyPackageError<P::StorageError>> {
    let leaf_key = LeafKey::generate().map_err(|_| NewKeyPackageError::Random)?;
    let credential = identity.credential_with_key(leaf_key.public_key());
    let leaf_extensions = profile
        .map(|p| p.clone().with_streak(0).to_extension())
        .into_iter()
        .collect();
    let bundle = build_key_package(
        provider,
        &leaf_key,
        credential,
        leaf_extensions,
        Vec::new(),
        lifetime,
    )?;
    leaf_key
        .store(provider.storage(), KEY_PACKAGE_SCOPE)
        .map_err(NewKeyPackageError::Storage)?;
    Ok(NewKeyPackage {
        key_package: bundle.key_package().clone(),
        leaf_key,
    })
}

/// Deletes the private keys of a join KeyPackage that will not be used,
/// as when the user leaves a public room while joining it (6.1): the
/// KeyPackage's own, kept by its KeyPackageRef `reference`, and the leaf
/// key whose public key is `signature_key`. A KeyPackage made by
/// [`make_join_key_package`] has no others.
pub fn forget_join_key_package<S: StorageProvider<CURRENT_VERSION>>(
    storage: &S,
    reference: &[u8],
    signature_key: &[u8],
) -> Result<(), GroupError<S::Error>> {
    let reference =
        crate::welcome::key_package_ref(reference).map_err(|e| GroupError::Group(e.0.into()))?;
    storage
        .delete_key_package(&reference)
        .map_err(GroupError::Storage)?;
    LeafKey::delete(storage, KEY_PACKAGE_SCOPE, signature_key).map_err(GroupError::Storage)
}

/// Deletes the private keys of a KeyPackage whose Welcome the device will
/// not join, as for an invitation the user declined or that expired
/// (6.1, 12.8): the KeyPackage's own, kept by its KeyPackageRef
/// `reference`, and its leaf key. A last-resort KeyPackage is kept, since
/// further Welcomes may use it (12.5). Returns whether the keys were
/// deleted; a KeyPackage not in storage has none.
pub fn forget_key_package<S: StorageProvider<CURRENT_VERSION>>(
    storage: &S,
    reference: &[u8],
) -> Result<bool, GroupError<S::Error>> {
    let hash_ref =
        crate::welcome::key_package_ref(reference).map_err(|e| GroupError::Group(e.0.into()))?;
    let bundle: Option<KeyPackageBundle> = storage
        .key_package(&hash_ref)
        .map_err(GroupError::Storage)?;
    let Some(bundle) = bundle else {
        return Ok(false);
    };
    if is_last_resort(bundle.key_package()).unwrap_or(false) {
        return Ok(false);
    }
    let signature_key = bundle.key_package().leaf_node().signature_key().as_slice();
    forget_join_key_package(storage, reference, signature_key)?;
    Ok(true)
}

pub(crate) fn build_key_package<P: OpenMlsProvider>(
    provider: &P,
    leaf_key: &LeafKey,
    credential: openmls::prelude::CredentialWithKey,
    leaf_extensions: Vec<Extension>,
    extensions: Vec<Extension>,
    lifetime: Lifetime,
) -> Result<KeyPackageBundle, KeyPackageNewError> {
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .leaf_node_extensions(
            Extensions::from_vec(leaf_extensions).expect("distinct leaf node extensions"),
        )
        .key_package_extensions(
            Extensions::from_vec(extensions).expect("distinct KeyPackage extensions"),
        )
        .key_package_lifetime(lifetime)
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

/// How far from a post's `t` a KeyPackage's lifetime may be and still be
/// acceptable, in ms: an hour (12.5).
pub const LIFETIME_SKEW_MS: u64 = 60 * 60 * 1000;

/// Whether a KeyPackage's lifetime is acceptable at `now`, by the server's
/// clock when it is uploaded (12.5): `now` is within it, and it spans at
/// most 12 weeks and one hour.
pub fn lifetime_acceptable(lifetime: &Lifetime, now: SystemTime) -> bool {
    let Ok(now) = now.duration_since(SystemTime::UNIX_EPOCH) else {
        return false;
    };
    let now = now.as_secs();
    lifetime.not_before() <= now
        && now <= lifetime.not_after()
        && lifetime.not_after().saturating_sub(lifetime.not_before()) <= MAX_LIFETIME_SPAN
}

/// Whether a KeyPackage's lifetime is acceptable for a commit that adds it,
/// against the `t` of the post that carries the commit, in ms, give or take
/// an hour (12.5, 12.7): some time within an hour of `t` is within it, and
/// it spans at most 12 weeks and one hour. Never against the device's own
/// clock, so that every device reaches the same answer.
pub fn lifetime_acceptable_at(lifetime: &Lifetime, t_ms: u64) -> bool {
    let not_before = lifetime.not_before().saturating_mul(1000);
    let not_after = lifetime.not_after().saturating_mul(1000);
    not_before <= t_ms.saturating_add(LIFETIME_SKEW_MS)
        && t_ms.saturating_sub(LIFETIME_SKEW_MS) <= not_after
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

/// The checks of 12.5 and 12.7 on any KeyPackage whose signatures OpenMLS
/// has verified, other than its lifetime and binding: the suite, a
/// RisalaIdentity credential, the leaf's capabilities, a profile for a
/// device's leaf (12.3), the HPKE keys (12.2) and the dictionary. Returns
/// the identity, and whether it is of last resort.
pub fn check_key_package_contents(
    key_package: &KeyPackage,
) -> Result<(RisalaIdentity, bool), KeyPackageError> {
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(KeyPackageError::CipherSuite);
    }
    let leaf = key_package.leaf_node();
    let identity = RisalaIdentity::from_credential(leaf.credential())
        .map_err(|_| KeyPackageError::Credential)?;
    if !has_capabilities(leaf.capabilities()) {
        return Err(KeyPackageError::Capabilities);
    }
    match RisalaProfile::from_extensions(leaf.extensions()) {
        None if identity.is_guest() => {}
        Some(Ok(_)) => {}
        _ => return Err(KeyPackageError::Profile),
    }
    if !x_wing_public_key_ok(key_package.hpke_init_key().as_slice())
        || !x_wing_public_key_ok(&encryption_key_bytes(leaf.encryption_key()))
    {
        return Err(KeyPackageError::HpkeKey);
    }
    let last_resort = is_last_resort(key_package).map_err(|_| KeyPackageError::Dictionary)?;
    Ok((identity, last_resort))
}

/// The device binding in a KeyPackage's leaf node, if it has one: `None`
/// if it has none, an error if it is malformed (12.3).
pub fn leaf_binding(key_package: &KeyPackage) -> Option<Result<DeviceBinding, DecodeError>> {
    DeviceBinding::from_extensions(key_package.leaf_node().extensions())
}

/// Whether a KeyPackage has a binding in the place 12.3 puts it, as far as
/// a group check can tell without the device key (12.7): one well-formed
/// binding in its leaf node, none among the KeyPackage's own extensions,
/// whose `device_id` is the credential's. Whether it verifies is a key
/// check ([`check_binding`]).
pub fn binding_fits_credential(
    key_package: &KeyPackage,
    identity: &RisalaIdentity,
) -> Result<(), KeyPackageError> {
    if DeviceBinding::from_extensions(key_package.extensions()).is_some() {
        return Err(KeyPackageError::Binding);
    }
    match leaf_binding(key_package) {
        Some(Ok(binding)) if identity.device_id == Some(binding.device_id) => Ok(()),
        _ => Err(KeyPackageError::Binding),
    }
}

/// Whether a KeyPackage carries no device binding anywhere, as one that
/// joins a public room must not (12.3, 6.1).
pub fn has_no_binding(key_package: &KeyPackage) -> bool {
    leaf_binding(key_package).is_none()
        && DeviceBinding::from_extensions(key_package.extensions()).is_none()
}

/// Whether the KeyPackage's device binding verifies under `device_key`,
/// the raw key of the device its credential names, over its uid, its init
/// key and its leaf's encryption key (12.3). This is a key check (12.7).
pub fn check_binding(
    key_package: &KeyPackage,
    identity: &RisalaIdentity,
    device_key: &[u8],
) -> Result<(), KeyPackageError> {
    binding_fits_credential(key_package, identity)?;
    let binding = leaf_binding(key_package)
        .and_then(Result::ok)
        .ok_or(KeyPackageError::Binding)?;
    let ok = binding.verify(
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

/// Verifies a KeyPackage's signatures with OpenMLS. It must have a
/// lifetime, but the lifetime is not checked against any clock here: the
/// caller checks it against its own time, a server's with
/// [`lifetime_acceptable`] and a device's against a post's `t` with
/// [`lifetime_acceptable_at`] (12.5), never against the system's clock
/// behind the caller's back.
pub fn verify_key_package(
    crypto: &impl OpenMlsCrypto,
    key_package: KeyPackageIn,
) -> Result<KeyPackage, KeyPackageError> {
    match key_package.validate_without_lifetime(crypto, ProtocolVersion::Mls10) {
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
/// key is `device_key`, with a device binding in its leaf node by that key
/// over its init and encryption keys, the capabilities of 12.3, a profile,
/// HPKE keys that pass the checks of 12.2, valid signatures, and an
/// acceptable lifetime at `now`, by the server's clock.
pub fn check_key_package(
    crypto: &impl OpenMlsCrypto,
    bytes: &[u8],
    uid: &Uid,
    device_key: &[u8],
    now: SystemTime,
) -> Result<CheckedKeyPackage, KeyPackageError> {
    match crate::framing::read_message(bytes) {
        Ok(crate::framing::MlsMessage::KeyPackage) => {}
        Err(crate::framing::FramingError::CipherSuite | crate::framing::FramingError::Version) => {
            return Err(KeyPackageError::CipherSuite);
        }
        _ => return Err(KeyPackageError::Malformed),
    }
    let key_package = verify_key_package(crypto, read_key_package(bytes)?)?;
    let (identity, last_resort) = check_key_package_contents(&key_package)?;
    if !lifetime_acceptable(key_package.life_time(), now) {
        return Err(KeyPackageError::Lifetime);
    }
    let device_id = device_id_of(device_key).ok_or(KeyPackageError::Credential)?;
    let expected = RisalaIdentity::device(uid.clone(), device_id);
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
        let made = Timestamp::from_unix_millis(1_800_000_000_123).unwrap();
        let lifetime = key_package_lifetime(made);
        assert_eq!(lifetime.not_before(), 1_800_000_000 - 3600);
        assert_eq!(lifetime.not_after(), 1_800_000_000 + KEY_PACKAGE_LIFETIME);
        let now = made.to_system_time();
        let secs = std::time::Duration::from_secs;
        assert!(lifetime_acceptable(&lifetime, now));
        assert!(lifetime_acceptable(&lifetime, now - secs(3600)));
        assert!(!lifetime_acceptable(&lifetime, now - secs(3601)));
        let long = Lifetime::init(lifetime.not_before(), lifetime.not_after() + 1);
        assert!(!lifetime_acceptable(&long, now));
        assert!(!lifetime_acceptable(
            &lifetime,
            now + secs(KEY_PACKAGE_LIFETIME + 10)
        ));
    }

    /// Against a post's `t`, give or take an hour, never the clock (12.5).
    #[test]
    fn lifetimes_at_a_post() {
        let hour = 3600;
        let lifetime = Lifetime::init(1_000_000, 1_000_000 + KEY_PACKAGE_LIFETIME);
        let ms = |s: u64| s * 1000;
        for (t, ok) in [
            (ms(1_000_000), true),
            (ms(1_000_000 - hour), true),
            (ms(1_000_000 - hour) - 1, false),
            (ms(1_000_000 + KEY_PACKAGE_LIFETIME + hour), true),
            (ms(1_000_000 + KEY_PACKAGE_LIFETIME + hour) + 1, false),
        ] {
            assert_eq!(lifetime_acceptable_at(&lifetime, t), ok, "{t}");
        }
        // Too long a span is never acceptable.
        let long = Lifetime::init(1_000_000, 1_000_001 + MAX_LIFETIME_SPAN);
        assert!(!lifetime_acceptable_at(&long, ms(1_000_100)));
        let max = Lifetime::init(1_000_000, 1_000_000 + MAX_LIFETIME_SPAN);
        assert!(lifetime_acceptable_at(&max, ms(1_000_100)));
    }
}

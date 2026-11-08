//! ML-DSA-44 keys (12.2, 12.3): a group's leaf keys, and a device key
//! when it signs a device binding.
//!
//! A private key is its 32-byte seed (4.3), kept on the heap and wiped
//! when dropped. Each signature expands the seed again and wipes the
//! expanded key afterwards. Signatures are hedged (12.2): ML-DSA.Sign with
//! fresh randomness, an empty context and no prehash.

use libcrux_ml_dsa::ml_dsa_44 as mldsa;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use openmls_traits::types::SignatureScheme;
use risala_proto::auth::{SignLabel, risala_sign_content};
use zeroize::{Zeroize as _, Zeroizing};

/// The length of an ML-DSA-44 public key.
pub const PUBLIC_KEY_LEN: usize = 1312;
/// The length of an ML-DSA-44 signature.
pub const SIGNATURE_LEN: usize = 2420;
/// The length of a private key's seed (4.3).
pub const SEED_LEN: usize = 32;

/// An ML-DSA-44 private key, held as its seed, with its public key.
#[derive(Clone)]
pub struct SigningKey {
    seed: Box<Zeroizing<[u8; SEED_LEN]>>,
    public: Box<[u8; PUBLIC_KEY_LEN]>,
}

impl SigningKey {
    /// A new key from the operating system's random source.
    pub fn generate() -> Result<SigningKey, getrandom::Error> {
        let mut seed = Zeroizing::new([0; SEED_LEN]);
        getrandom::fill(&mut seed[..])?;
        Ok(SigningKey::from_seed(*seed))
    }

    /// The key whose seed is `seed`: the ξ of FIPS 204's
    /// ML-DSA.KeyGen_internal (4.3).
    pub fn from_seed(mut seed: [u8; SEED_LEN]) -> SigningKey {
        let mut stored: Box<Zeroizing<[u8; SEED_LEN]>> = Box::default();
        stored.copy_from_slice(&seed);
        seed.zeroize();
        let expanded = Expanded::new(&stored);
        let public = Box::new(*expanded.0.verification_key.as_ref());
        SigningKey {
            seed: stored,
            public,
        }
    }

    /// The seed, which is the private key (4.3). Store it as a secret.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The raw public key.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// The device id (4.4) of the device whose device key this is.
    pub fn device_id(&self) -> risala_proto::record::DeviceId {
        risala_proto::record::DeviceId::of(&risala_proto::auth::PublicKey::from_bytes(&self.public))
    }

    /// ML-DSA.Sign over `message`, hedged, with an empty context (12.2).
    /// Falls back to the deterministic variant if the operating system has
    /// no randomness, which verifiers cannot tell apart.
    pub(crate) fn sign(&self, message: &[u8]) -> Box<[u8; SIGNATURE_LEN]> {
        let mut rnd = Zeroizing::new([0; 32]);
        if getrandom::fill(&mut rnd[..]).is_err() {
            rnd.zeroize();
        }
        let expanded = Expanded::new(&self.seed);
        // Signing fails only if rejection sampling runs out of attempts,
        // which FIPS 204 Appendix C bounds at 2^-256, or with a context
        // longer than 255 bytes, which ours is not.
        let signature = mldsa::sign(&expanded.0.signing_key, message, b"", *rnd)
            .expect("ML-DSA-44 signing with an empty context does not fail");
        Box::new(*signature.as_ref())
    }

    /// RisalaSign(key, label, content) (4.3): ML-DSA.Sign, hedged, over
    /// the RisalaSignContent that risala-proto encodes.
    pub fn risala_sign(&self, label: SignLabel, content: &[u8]) -> Box<[u8; SIGNATURE_LEN]> {
        self.sign(&risala_sign_content(label, content))
    }
}

/// RisalaVerify (4.3): whether `signature` is RisalaSign(key, label,
/// content) for the key whose raw public key is `public_key`.
pub fn risala_verify(
    public_key: &[u8],
    label: SignLabel,
    content: &[u8],
    signature: &[u8],
) -> bool {
    verify(public_key, &risala_sign_content(label, content), signature)
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = crate::primitives::sha384(&self.public[..]);
        f.debug_struct("SigningKey")
            .field("public_key_sha384_prefix", &&hash[..8])
            .finish_non_exhaustive()
    }
}

/// A key pair expanded from a seed, whose signing key is wiped on drop.
struct Expanded(mldsa::MLDSA44KeyPair);

impl Expanded {
    fn new(seed: &[u8; SEED_LEN]) -> Expanded {
        Expanded(mldsa::generate_key_pair(*seed))
    }
}

impl Drop for Expanded {
    fn drop(&mut self) {
        self.0.signing_key.as_ref_mut().zeroize();
    }
}

/// Checks an ML-DSA-44 signature with an empty context, hedged or
/// deterministic (12.2). Keys and signatures of the wrong length fail.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        <[u8; PUBLIC_KEY_LEN]>::try_from(public_key),
        <[u8; SIGNATURE_LEN]>::try_from(signature),
    ) else {
        return false;
    };
    mldsa::verify(
        &mldsa::MLDSA44VerificationKey::new(public_key),
        message,
        b"",
        &mldsa::MLDSA44Signature::new(signature),
    )
    .is_ok()
}

/// The prefix of every label MLS signs with [RFC9420, 5.1.2].
const MLS_LABEL_PREFIX: &[u8] = b"MLS 1.0 ";

/// A leaf key (12.3): a fresh ML-DSA-44 key that a device makes for one
/// group, and uses there alone. It signs only MLS content, never risala's
/// own structures, and it is never a device key.
///
/// This crate keeps it in the OpenMLS storage ([`LeafKey::store`]), in the
/// same transaction as the group, and deletes it when the leaf is gone.
#[derive(Clone, Debug)]
pub struct LeafKey(SigningKey);

impl LeafKey {
    /// A new leaf key, for one group (12.3).
    pub fn generate() -> Result<LeafKey, getrandom::Error> {
        SigningKey::generate().map(LeafKey)
    }

    /// A leaf key from its seed, as stored.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> LeafKey {
        LeafKey(SigningKey::from_seed(seed))
    }

    /// The seed.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        self.0.seed()
    }

    /// The raw public key, the leaf's signature key.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.0.public_key()
    }

    /// Stores the key in OpenMLS storage, under `scope` and its public
    /// key. The scope is the group id for a group's leaf key, or
    /// [`KEY_PACKAGE_SCOPE`] for a KeyPackage's: a last-resort KeyPackage's
    /// leaf key may be in several groups at once (12.5), so each group
    /// keeps its own copy, and deletes it on its own.
    pub fn store<S: StorageProvider<CURRENT_VERSION>>(
        &self,
        storage: &S,
        scope: &[u8],
    ) -> Result<(), S::Error> {
        storage.write_signature_key_pair(
            &StorageId::new(scope, self.public_key()),
            &StoredLeafKey::from(self),
        )
    }

    /// Loads the key whose public key is `public_key` from OpenMLS
    /// storage, under `scope`.
    pub fn load<S: StorageProvider<CURRENT_VERSION>>(
        storage: &S,
        scope: &[u8],
        public_key: &[u8],
    ) -> Result<Option<LeafKey>, S::Error> {
        let stored: Option<StoredLeafKey> =
            storage.signature_key_pair(&StorageId::new(scope, public_key))?;
        Ok(stored.and_then(|stored| {
            let seed: [u8; SEED_LEN] = stored.seed.as_slice().try_into().ok()?;
            let key = LeafKey::from_seed(seed);
            (key.public_key()[..] == *public_key).then_some(key)
        }))
    }

    /// Deletes the key whose public key is `public_key` under `scope`, once
    /// its leaf has a new one or has left the group (12.3).
    pub fn delete<S: StorageProvider<CURRENT_VERSION>>(
        storage: &S,
        scope: &[u8],
        public_key: &[u8],
    ) -> Result<(), S::Error> {
        storage.delete_signature_key_pair(&StorageId::new(scope, public_key))
    }
}

/// The scope under which KeyPackages' leaf keys are stored, before they are
/// in any group (see [`LeafKey::store`]).
pub const KEY_PACKAGE_SCOPE: &[u8] = b"";

impl Signer for LeafKey {
    /// Signs MLS SignContent only: anything whose label does not start with
    /// `MLS 1.0 ` is refused, so a leaf key never signs anything but MLS.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        if !is_mls_sign_content(payload) {
            return Err(SignerError::SigningError);
        }
        Ok(self.0.sign(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::MLDSA44
    }
}

/// Whether `bytes` is one encoded SignContent [RFC9420, 5.1.2] whose label
/// starts with `MLS 1.0 `.
fn is_mls_sign_content(bytes: &[u8]) -> bool {
    let mut reader = crate::codec::Reader::new(bytes);
    let (Ok(label), Ok(_content)) = (reader.vector(), reader.vector()) else {
        return false;
    };
    reader.finish().is_ok() && label.starts_with(MLS_LABEL_PREFIX)
}

/// The key a leaf key is stored under: its scope, then its public key.
#[derive(serde::Serialize)]
struct StorageId(Vec<u8>);

impl StorageId {
    fn new(scope: &[u8], public_key: &[u8]) -> StorageId {
        let mut w = crate::codec::Writer::new();
        w.vector(b"risala leaf key")
            .vector(scope)
            .vector(public_key);
        StorageId(w.into_bytes())
    }
}

impl traits::SignaturePublicKey<CURRENT_VERSION> for StorageId {}
impl openmls_traits::storage::Key<CURRENT_VERSION> for StorageId {}

/// A leaf key as OpenMLS storage keeps it: the seed alone.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredLeafKey {
    seed: Vec<u8>,
}

impl From<&LeafKey> for StoredLeafKey {
    fn from(key: &LeafKey) -> StoredLeafKey {
        StoredLeafKey {
            seed: key.seed().to_vec(),
        }
    }
}

impl Drop for StoredLeafKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl traits::SignatureKeyPair<CURRENT_VERSION> for StoredLeafKey {}
impl openmls_traits::storage::Entity<CURRENT_VERSION> for StoredLeafKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_memory_storage::MemoryStorage;

    fn sign_content(label: &[u8], content: &[u8]) -> Vec<u8> {
        let mut w = crate::codec::Writer::new();
        w.vector(&[MLS_LABEL_PREFIX, label].concat())
            .vector(content);
        w.into_bytes()
    }

    #[test]
    fn keys_from_seeds() {
        let a = SigningKey::from_seed([1; 32]);
        let b = SigningKey::from_seed([1; 32]);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), SigningKey::from_seed([2; 32]).public_key());
        assert_eq!(a.seed(), &[1; 32]);
        let fresh = SigningKey::generate().unwrap();
        assert_ne!(fresh.seed(), a.seed());
        assert!(!format!("{a:?}").contains("seed:"));
    }

    #[test]
    fn hedged_signatures_verify() {
        let key = SigningKey::from_seed([3; 32]);
        let one = key.sign(b"message");
        let two = key.sign(b"message");
        // Hedged: two signatures of the same message differ.
        assert_ne!(one, two);
        assert!(verify(key.public_key(), b"message", &one[..]));
        assert!(verify(key.public_key(), b"message", &two[..]));
        assert!(!verify(key.public_key(), b"other", &one[..]));
        assert!(!verify(&key.public_key()[1..], b"message", &one[..]));
        assert!(!verify(key.public_key(), b"message", &one[1..]));
    }

    /// RisalaSign (4.3), over risala-proto's RisalaSignContent.
    #[test]
    fn risala_signatures() {
        let key = SigningKey::from_seed([5; 32]);
        let label = SignLabel::KeyPackage;
        let signature = key.risala_sign(label, b"content");
        assert!(risala_verify(
            key.public_key(),
            label,
            b"content",
            &signature[..]
        ));
        // Another label, content or key fails.
        assert!(!risala_verify(
            key.public_key(),
            SignLabel::Record,
            b"content",
            &signature[..]
        ));
        assert!(!risala_verify(
            key.public_key(),
            label,
            b"other",
            &signature[..]
        ));
        let other = SigningKey::from_seed([6; 32]);
        assert!(!risala_verify(
            other.public_key(),
            label,
            b"content",
            &signature[..]
        ));
        // risala-proto's keys verify it, and sign the same bytes.
        let public = risala_proto::auth::PublicKey::from_bytes(key.public_key());
        assert!(public.risala_verify(label, b"content", &signature[..]));
        let proto = risala_proto::auth::SecretKey::from_seed([5; 32]);
        let theirs = proto.risala_sign_deterministic(label, b"content");
        assert!(risala_verify(
            key.public_key(),
            label,
            b"content",
            theirs.as_bytes()
        ));
        // It is not an MLS signature: SignWithLabel's content differs.
        let mls = sign_content(b"keypackage", b"content");
        assert!(!verify(key.public_key(), &mls, &signature[..]));
    }

    #[test]
    fn leaf_keys_sign_only_mls_content() {
        let key = LeafKey::generate().unwrap();
        assert_eq!(key.signature_scheme(), SignatureScheme::MLDSA44);
        let content = sign_content(b"LeafNodeTBS", b"leaf");
        let signature = key.sign(&content).unwrap();
        assert!(verify(key.public_key(), &content, &signature));
        // risala's own labels, and anything else, are refused.
        let mut w = crate::codec::Writer::new();
        w.vector(b"risala/1 keypackage").vector(b"x");
        assert_eq!(key.sign(&w.into_bytes()), Err(SignerError::SigningError));
        assert_eq!(key.sign(b"risala-auth-1\n"), Err(SignerError::SigningError));
        let mut trailing = content.clone();
        trailing.push(0);
        assert_eq!(key.sign(&trailing), Err(SignerError::SigningError));
    }

    #[test]
    fn leaf_keys_in_storage() {
        let storage = MemoryStorage::default();
        let key = LeafKey::generate().unwrap();
        key.store(&storage, b"group").unwrap();
        let loaded = LeafKey::load(&storage, b"group", key.public_key())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.seed(), key.seed());
        // Scopes are apart.
        assert!(
            LeafKey::load(&storage, KEY_PACKAGE_SCOPE, key.public_key())
                .unwrap()
                .is_none()
        );
        let other = LeafKey::generate().unwrap();
        assert!(
            LeafKey::load(&storage, b"group", other.public_key())
                .unwrap()
                .is_none()
        );
        LeafKey::delete(&storage, b"group", key.public_key()).unwrap();
        assert!(
            LeafKey::load(&storage, b"group", key.public_key())
                .unwrap()
                .is_none()
        );
    }
}

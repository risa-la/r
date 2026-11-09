//! The OpenMLS crypto provider for cipher suite `0x0020` (12.2).
//!
//! `openmls_libcrux_crypto` has X-Wing, ChaCha20-Poly1305 and SHA-384, but
//! signs only with Ed25519. [`RisalaCrypto`] passes every call through to
//! it and adds ML-DSA-44 verification from `libcrux-ml-dsa`, the crate
//! that signs in (4.6), so a binary carries one ML-DSA (PLAN.md 22). Drop
//! the ML-DSA part once upstream supports it.
//!
//! HPKE uses the KEM `0x647a` (X-Wing), HKDF-SHA384 and ChaCha20-Poly1305
//! (12.2). OpenMLS names its X-Wing KEM `0x004D` inside, but the libcrux
//! provider hands HPKE `0x647a`; a test pins that.
//!
//! [`Provider`] puts the crypto together with any OpenMLS storage: the
//! SQLite storage on one of librisala's transactions, or the server's.

use std::sync::Arc;

use openmls_libcrux_crypto::CryptoProvider as Libcrux;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
    HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};
use tls_codec::SecretVLBytes;

use crate::CIPHERSUITE;
use crate::mldsa::{PUBLIC_KEY_LEN, SIGNATURE_LEN, verify};

/// The crypto and randomness of the OpenMLS provider: libcrux, with
/// ML-DSA-44 added (12.2).
///
/// It holds a random generator seeded from the operating system, behind a
/// lock, so one value can serve many groups and threads. Share it with an
/// [`Arc`] rather than making one per operation.
pub struct RisalaCrypto {
    inner: Libcrux,
}

impl RisalaCrypto {
    /// Seeds the random generator from the operating system.
    pub fn new() -> Result<RisalaCrypto, CryptoError> {
        Ok(RisalaCrypto {
            inner: Libcrux::new()?,
        })
    }
}

impl std::fmt::Debug for RisalaCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RisalaCrypto")
    }
}

impl OpenMlsCrypto for RisalaCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if ciphersuite == CIPHERSUITE {
            Ok(())
        } else {
            self.inner.supports(ciphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        let mut suites = self.inner.supported_ciphersuites();
        suites.push(CIPHERSUITE);
        suites
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    /// Refused for ML-DSA-44: leaf keys are made by [`LeafKey`], and their
    /// seeds stay out of OpenMLS's crypto (12.3).
    ///
    /// [`LeafKey`]: crate::LeafKey
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if alg == SignatureScheme::MLDSA44 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        self.inner.signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if alg != SignatureScheme::MLDSA44 {
            return self.inner.verify_signature(alg, data, pk, signature);
        }
        if pk.len() != PUBLIC_KEY_LEN || signature.len() != SIGNATURE_LEN {
            return Err(CryptoError::InvalidLength);
        }
        if verify(pk, data, signature) {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }

    /// Refused for ML-DSA-44: leaves sign with [`LeafKey`], which signs only
    /// MLS content (12.3).
    ///
    /// [`LeafKey`]: crate::LeafKey
    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if alg == SignatureScheme::MLDSA44 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        self.inner.sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        check_hpke_public_key(&config, pk_r)?;
        self.inner.hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        check_hpke_public_key(&config, pk_r)?;
        self.inner.hpke_setup_sender_and_export(
            config,
            pk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.inner.hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        self.inner.derive_hpke_keypair(config, ikm)
    }
}

/// The length of an X-Wing public key: ML-KEM-768's 1184 bytes, then
/// X25519's 32 (12.2).
pub const X_WING_PUBLIC_KEY_LEN: usize = 1216;

/// The length of an ML-KEM-768 encapsulation key.
const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;

/// ML-KEM's modulus q \[FIPS203\].
const ML_KEM_Q: u16 = 3329;

/// Whether `key` is an X-Wing public key that may be encrypted to (12.2):
/// 1216 bytes, whose ML-KEM-768 part passes FIPS 203's encapsulation key
/// check (7.2): each of its 768 coefficients, 12 bits each in the first
/// 1152 bytes, is below q, so that decoding and encoding it again gives
/// the same bytes. The X25519 part needs no check.
pub fn x_wing_public_key_ok(key: &[u8]) -> bool {
    if key.len() != X_WING_PUBLIC_KEY_LEN {
        return false;
    }
    // The first 384 * k = 1152 bytes hold the coefficients of t-hat; the
    // last 32 of the ML-KEM part are rho, which is not checked.
    key[..ML_KEM_768_PUBLIC_KEY_LEN - 32]
        .as_chunks::<3>()
        .0
        .iter()
        .all(|b| {
            let first = u16::from(b[0]) | (u16::from(b[1]) & 0x0f) << 8;
            let second = u16::from(b[1]) >> 4 | u16::from(b[2]) << 4;
            first < ML_KEM_Q && second < ML_KEM_Q
        })
}

/// Refuses an X-Wing public key that fails [`x_wing_public_key_ok`] before
/// encrypting to it (12.2). libcrux-kem 0.0.9 also slices a short key and
/// panics (RUSTSEC-2026-0331); anyone can put such a key in a KeyPackage,
/// a leaf or a GroupInfo's `external_pub`.
fn check_hpke_public_key(config: &HpkeConfig, pk: &[u8]) -> Result<(), CryptoError> {
    if config.0 == HpkeKemType::XWingKemDraft6 && !x_wing_public_key_ok(pk) {
        return Err(CryptoError::InvalidLength);
    }
    Ok(())
}

impl OpenMlsRand for RisalaCrypto {
    type Error = <Libcrux as OpenMlsRand>::Error;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.inner.random_array()
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.inner.random_vec(len)
    }
}

/// The OpenMLS provider: [`RisalaCrypto`] for crypto and randomness, and a
/// storage of the caller's choice.
///
/// librisala builds one per transaction, around the SQLite storage on that
/// transaction, sharing one [`RisalaCrypto`]:
///
/// ```ignore
/// let provider = Provider::with_crypto(crypto.clone(), SqliteStorageProvider::<MsgPack, _>::new(&*tx));
/// ```
#[derive(Debug)]
pub struct Provider<S> {
    crypto: Arc<RisalaCrypto>,
    storage: S,
}

impl<S> Provider<S> {
    /// A provider with its own new [`RisalaCrypto`].
    pub fn new(storage: S) -> Result<Provider<S>, CryptoError> {
        Ok(Provider::with_crypto(
            Arc::new(RisalaCrypto::new()?),
            storage,
        ))
    }

    /// A provider that shares `crypto`.
    pub fn with_crypto(crypto: Arc<RisalaCrypto>, storage: S) -> Provider<S> {
        Provider { crypto, storage }
    }

    /// The shared crypto, to build further providers with.
    pub fn shared_crypto(&self) -> &Arc<RisalaCrypto> {
        &self.crypto
    }

    /// Gives back the storage.
    pub fn into_storage(self) -> S {
        self.storage
    }
}

impl<S: StorageProvider<CURRENT_VERSION>> OpenMlsProvider for Provider<S> {
    type CryptoProvider = RisalaCrypto;
    type RandProvider = RisalaCrypto;
    type StorageProvider = S;

    fn storage(&self) -> &S {
        &self.storage
    }

    fn crypto(&self) -> &RisalaCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RisalaCrypto {
        &self.crypto
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mldsa::SigningKey;

    /// FIPS 203's encapsulation key check (12.2): a coefficient of q or
    /// more fails, anywhere in t-hat, while rho and the X25519 key are not
    /// checked.
    #[test]
    fn x_wing_key_check() {
        let crypto = RisalaCrypto::new().unwrap();
        let pair = crypto
            .derive_hpke_keypair(CIPHERSUITE.hpke_config(), &[7; 32])
            .unwrap();
        assert!(x_wing_public_key_ok(&pair.public));
        assert!(x_wing_public_key_ok(&[0; X_WING_PUBLIC_KEY_LEN]));
        // 0xff in the last 64 bytes is rho and X25519.
        let mut tail = vec![0; X_WING_PUBLIC_KEY_LEN];
        tail[1152..].fill(0xff);
        assert!(x_wing_public_key_ok(&tail));
        // Coefficient 3329 (0xd01) as the first and as the second of a pair.
        for (at, bytes) in [(0, [0x01, 0x0d, 0x00]), (1149, [0x00, 0x10, 0xd0])] {
            let mut bad = pair.public.clone();
            bad[at..at + 3].copy_from_slice(&bytes);
            assert!(!x_wing_public_key_ok(&bad), "{at}");
            assert_eq!(
                crypto
                    .hpke_seal(CIPHERSUITE.hpke_config(), &bad, b"", b"", b"hi")
                    .err(),
                Some(CryptoError::InvalidLength)
            );
        }
        // 3328 is the largest coefficient.
        let mut max = vec![0; X_WING_PUBLIC_KEY_LEN];
        max[..3].copy_from_slice(&[0x00, 0x0d, 0xd0]);
        assert!(x_wing_public_key_ok(&max));
        assert!(!x_wing_public_key_ok(&[0xff; X_WING_PUBLIC_KEY_LEN]));
    }

    /// A short X-Wing public key, as anyone can put in a KeyPackage, leaf or
    /// GroupInfo, is an error rather than a panic (RUSTSEC-2026-0331).
    #[test]
    fn hpke_refuses_x_wing_keys_of_the_wrong_length() {
        let crypto = RisalaCrypto::new().unwrap();
        let pair = crypto
            .derive_hpke_keypair(CIPHERSUITE.hpke_config(), &[7; 32])
            .unwrap();
        assert_eq!(pair.public.len(), X_WING_PUBLIC_KEY_LEN);
        assert!(
            crypto
                .hpke_seal(CIPHERSUITE.hpke_config(), &pair.public, b"", b"", b"hi")
                .is_ok()
        );
        for len in [
            0,
            10,
            1184,
            X_WING_PUBLIC_KEY_LEN - 1,
            X_WING_PUBLIC_KEY_LEN + 1,
        ] {
            let pk = vec![1; len];
            assert_eq!(
                crypto
                    .hpke_seal(CIPHERSUITE.hpke_config(), &pk, b"", b"", b"hi")
                    .err(),
                Some(CryptoError::InvalidLength),
                "{len}"
            );
            assert_eq!(
                crypto
                    .hpke_setup_sender_and_export(CIPHERSUITE.hpke_config(), &pk, b"", b"", 32)
                    .err(),
                Some(CryptoError::InvalidLength),
                "{len}"
            );
        }
    }

    #[test]
    fn supports_the_suite() {
        let crypto = RisalaCrypto::new().unwrap();
        assert_eq!(crypto.supports(CIPHERSUITE), Ok(()));
        assert!(crypto.supported_ciphersuites().contains(&CIPHERSUITE));
        // The plain libcrux provider does not, which is why this exists.
        assert!(Libcrux::new().unwrap().supports(CIPHERSUITE).is_err());
    }

    #[test]
    fn ml_dsa_verifies_and_never_signs() {
        let crypto = RisalaCrypto::new().unwrap();
        let seed = [9; 32];
        let key = SigningKey::from_seed(seed);
        let public = key.public_key().to_vec();

        // Only leaf keys sign, outside OpenMLS's crypto (12.3).
        assert_eq!(
            crypto.signature_key_gen(SignatureScheme::MLDSA44),
            Err(CryptoError::UnsupportedSignatureScheme)
        );
        let content = crate::primitives::sign_content("test", b"data");
        assert_eq!(
            crypto.sign(SignatureScheme::MLDSA44, &content, &seed),
            Err(CryptoError::UnsupportedSignatureScheme)
        );
        let ours = key.sign(&content).to_vec();
        assert_eq!(
            crypto.verify_signature(SignatureScheme::MLDSA44, &content, &public, &ours),
            Ok(())
        );
        assert_eq!(
            crypto.verify_signature(SignatureScheme::MLDSA44, b"other", &public, &ours),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            crypto.verify_signature(SignatureScheme::MLDSA44, &content, &public[1..], &ours),
            Err(CryptoError::InvalidLength)
        );
        assert_eq!(
            crypto.verify_signature(SignatureScheme::MLDSA44, &content, &public, &ours[1..]),
            Err(CryptoError::InvalidLength)
        );
    }

    /// HPKE in the suite uses the KEM `0x647a`, X-Wing (12.2, PLAN.md 22),
    /// not the `0x004D` OpenMLS uses for it inside: an HPKE built with the
    /// KEM id spelled out opens what the provider seals, and the other way
    /// round.
    #[test]
    fn hpke_uses_x_wing_0x647a() {
        use hpke_rs::{Hpke, Mode};
        use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
        use hpke_rs_libcrux::HpkeLibcrux;

        assert_eq!(KemAlgorithm::XWingDraft06 as u16, 0x647a);
        let crypto = RisalaCrypto::new().unwrap();
        let pair = crypto
            .derive_hpke_keypair(CIPHERSUITE.hpke_config(), &[7; 32])
            .unwrap();

        let mut hpke = Hpke::<HpkeLibcrux>::new(
            Mode::Base,
            KemAlgorithm::XWingDraft06,
            KdfAlgorithm::HkdfSha384,
            AeadAlgorithm::ChaCha20Poly1305,
        );
        let sealed = crypto
            .hpke_seal(
                CIPHERSUITE.hpke_config(),
                &pair.public,
                b"info",
                b"aad",
                b"hello",
            )
            .unwrap();
        let sk = hpke_rs::HpkePrivateKey::new(pair.private.to_vec());
        let opened = hpke
            .open(
                sealed.kem_output.as_slice(),
                &sk,
                b"info",
                b"aad",
                sealed.ciphertext.as_slice(),
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(opened, b"hello");

        let pk = hpke_rs::HpkePublicKey::new(pair.public.clone());
        let (enc, ct) = hpke
            .seal(&pk, b"info", b"aad", b"back", None, None, None)
            .unwrap();
        let input = HpkeCiphertext {
            kem_output: enc.into(),
            ciphertext: ct.into(),
        };
        let opened = crypto
            .hpke_open(
                CIPHERSUITE.hpke_config(),
                &input,
                &pair.private,
                b"info",
                b"aad",
            )
            .unwrap();
        assert_eq!(opened, b"back");
    }
}

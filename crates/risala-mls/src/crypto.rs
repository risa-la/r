//! The OpenMLS crypto provider for cipher suite `0x0052` (12.2).
//!
//! `openmls_libcrux_crypto` has X-Wing, ChaCha20-Poly1305 and SHA-384, but
//! signs only with Ed25519. [`RisalaCrypto`] passes every call through to
//! it and adds ML-DSA-44 from `libcrux-ml-dsa`, the crate that signs in
//! (4.5), so a binary carries one ML-DSA (PLAN.md 22). Drop the ML-DSA
//! part once upstream supports it.
//!
//! HPKE uses the KEM `0x647a` (X-Wing), HKDF-SHA384 and ChaCha20-Poly1305
//! (12.2). OpenMLS names its X-Wing KEM `0x004D` inside, but the libcrux
//! provider hands HPKE `0x647a`; a test pins that.
//!
//! [`Provider`] puts the crypto together with any OpenMLS storage: the
//! SQLite storage on one of librisala's transactions, or the server's.

use std::sync::Arc;

use libcrux_ml_dsa::ml_dsa_44 as mldsa;
use openmls_libcrux_crypto::CryptoProvider as Libcrux;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};
use openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
    HpkeKemType, HpkeKeyPair, KemOutput, SignatureScheme,
};
use risala_proto::auth::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN};
use tls_codec::SecretVLBytes;

use crate::CIPHERSUITE;

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

/// Checks an ML-DSA-44 signature over `message`, with an empty context, as
/// every signature in risala is (4.5, 12.2). It accepts both the hedged
/// and the deterministic variant.
pub fn verify_ml_dsa_44(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    verify_raw(public_key.as_bytes(), message, signature)
}

fn verify_raw(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
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

    /// Refused for ML-DSA-44: device keys are made by librisala, and their
    /// seeds never pass through OpenMLS (12.2).
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
        if verify_raw(pk, data, signature) {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }

    /// Refused for ML-DSA-44: devices sign with [`DeviceSigner`], which
    /// signs only MLS content (12.2), and whose key stays out of OpenMLS.
    ///
    /// [`DeviceSigner`]: crate::DeviceSigner
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

/// The length of an X-Wing public key: ML-KEM-768's 1184 bytes and
/// X25519's 32.
pub const X_WING_PUBLIC_KEY_LEN: usize = 1216;

/// Refuses an X-Wing public key of the wrong length, before libcrux-kem
/// 0.0.9 slices it and panics on a short one (RUSTSEC-2026-0331). Anyone
/// can put such a key in a KeyPackage, a leaf or a GroupInfo's
/// `external_pub`, and OpenMLS does not check its length, so without this a
/// device that encrypts to it would crash.
fn check_hpke_public_key(config: &HpkeConfig, pk: &[u8]) -> Result<(), CryptoError> {
    if config.0 == HpkeKemType::XWingKemDraft6 && pk.len() != X_WING_PUBLIC_KEY_LEN {
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
    use risala_proto::auth::{SEED_LEN, SecretKey};

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
    fn ml_dsa_verifies_device_signatures_and_never_signs() {
        let crypto = RisalaCrypto::new().unwrap();
        let seed = [9; SEED_LEN];
        let key = SecretKey::from_seed(seed);
        let public = key.public_key().as_bytes().to_vec();

        // Only the device signer signs, and only MLS content (12.2).
        assert_eq!(
            crypto.signature_key_gen(SignatureScheme::MLDSA44),
            Err(CryptoError::UnsupportedSignatureScheme)
        );
        let content = crate::primitives::sign_content("test", b"data");
        assert_eq!(
            crypto.sign(SignatureScheme::MLDSA44, &content, &seed),
            Err(CryptoError::UnsupportedSignatureScheme)
        );
        let ours = key.sign_mls(&content).unwrap().as_bytes().to_vec();
        assert_eq!(
            crypto.verify_signature(SignatureScheme::MLDSA44, &content, &public, &ours),
            Ok(())
        );
        assert!(verify_ml_dsa_44(&key.public_key(), &content, &ours));
        assert_eq!(
            crypto.verify_signature(SignatureScheme::MLDSA44, b"other", &public, &ours),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            crypto.verify_signature(SignatureScheme::MLDSA44, &content, &public[1..], &ours),
            Err(CryptoError::InvalidLength)
        );
        assert!(!verify_ml_dsa_44(&key.public_key(), &content, &ours[1..]));
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

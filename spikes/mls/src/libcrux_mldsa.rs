//! openmls_libcrux_crypto 0.4 has X-Wing but no ML-DSA. This wraps it and
//! adds ML-DSA-44 from libcrux-ml-dsa, so suite 0x0052 runs on libcrux
//! alone. Checked for interop against openmls_rust_crypto devices.

use libcrux_ml_dsa::ml_dsa_44 as mldsa;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::*;
use openmls_traits::OpenMlsProvider;
use tls_codec::SecretVLBytes;

use crate::common::CS;

pub struct LibcruxMlDsa {
    inner: CryptoProvider,
}

impl Default for LibcruxMlDsa {
    fn default() -> Self {
        Self {
            inner: CryptoProvider::new().unwrap(),
        }
    }
}

/// libcrux key generation from the 32-byte seed (FIPS 204 KeyGen_internal).
pub fn keypair(seed: [u8; 32]) -> mldsa::MLDSA44KeyPair {
    mldsa::generate_key_pair(seed)
}

/// Deterministic ML-DSA-44 signing: rnd = 32 zero bytes (FIPS 204 3.4).
pub fn sign_deterministic(kp: &mldsa::MLDSA44KeyPair, msg: &[u8]) -> Vec<u8> {
    mldsa::sign(&kp.signing_key, msg, b"", [0u8; 32])
        .unwrap()
        .as_slice()
        .to_vec()
}

impl OpenMlsCrypto for LibcruxMlDsa {
    fn supports(&self, cs: Ciphersuite) -> Result<(), CryptoError> {
        if cs == CS {
            Ok(())
        } else {
            self.inner.supports(cs)
        }
    }
    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        let mut v = self.inner.supported_ciphersuites();
        v.push(CS);
        v
    }
    fn hkdf_extract(&self, h: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_extract(h, salt, ikm)
    }
    fn hmac(&self, h: HashType, key: &[u8], m: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hmac(h, key, m)
    }
    fn hkdf_expand(&self, h: HashType, prk: &[u8], info: &[u8], n: usize) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_expand(h, prk, info, n)
    }
    fn hash(&self, h: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.hash(h, data)
    }
    fn aead_encrypt(&self, a: AeadType, k: &[u8], d: &[u8], n: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_encrypt(a, k, d, n, aad)
    }
    fn aead_decrypt(&self, a: AeadType, k: &[u8], c: &[u8], n: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_decrypt(a, k, c, n, aad)
    }
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if alg != SignatureScheme::MLDSA44 {
            return self.inner.signature_key_gen(alg);
        }
        let seed: [u8; 32] = rand::random();
        let kp = keypair(seed);
        Ok((seed.to_vec(), kp.verification_key.as_slice().to_vec()))
    }
    fn verify_signature(&self, alg: SignatureScheme, data: &[u8], pk: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        if alg != SignatureScheme::MLDSA44 {
            return self.inner.verify_signature(alg, data, pk, sig);
        }
        let pk: [u8; 1312] = pk.try_into().map_err(|_| CryptoError::InvalidLength)?;
        let sig: [u8; 2420] = sig.try_into().map_err(|_| CryptoError::InvalidLength)?;
        mldsa::verify(
            &mldsa::MLDSA44VerificationKey::new(pk),
            data,
            b"",
            &mldsa::MLDSA44Signature::new(sig),
        )
        .map_err(|_| CryptoError::InvalidSignature)
    }
    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if alg != SignatureScheme::MLDSA44 {
            return self.inner.sign(alg, data, key);
        }
        let seed: [u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(sign_deterministic(&keypair(seed), data))
    }
    fn hpke_seal(&self, c: HpkeConfig, pk: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<HpkeCiphertext, CryptoError> {
        self.inner.hpke_seal(c, pk, info, aad, pt)
    }
    fn hpke_open(&self, c: HpkeConfig, ct: &HpkeCiphertext, sk: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.hpke_open(c, ct, sk, info, aad)
    }
    fn hpke_setup_sender_and_export(&self, c: HpkeConfig, pk: &[u8], info: &[u8], ctx: &[u8], n: usize) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.inner.hpke_setup_sender_and_export(c, pk, info, ctx, n)
    }
    fn hpke_setup_receiver_and_export(&self, c: HpkeConfig, enc: &[u8], sk: &[u8], info: &[u8], ctx: &[u8], n: usize) -> Result<ExporterSecret, CryptoError> {
        self.inner.hpke_setup_receiver_and_export(c, enc, sk, info, ctx, n)
    }
    fn derive_hpke_keypair(&self, c: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        self.inner.derive_hpke_keypair(c, ikm)
    }
}

pub struct LibcruxProvider {
    pub crypto: LibcruxMlDsa,
    pub rand: CryptoProvider,
    pub storage: MemoryStorage,
}

impl Default for LibcruxProvider {
    fn default() -> Self {
        Self {
            crypto: LibcruxMlDsa::default(),
            rand: CryptoProvider::new().unwrap(),
            storage: MemoryStorage::default(),
        }
    }
}

impl OpenMlsProvider for LibcruxProvider {
    type CryptoProvider = LibcruxMlDsa;
    type RandProvider = CryptoProvider;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }
    fn crypto(&self) -> &LibcruxMlDsa {
        &self.crypto
    }
    fn rand(&self) -> &CryptoProvider {
        &self.rand
    }
}

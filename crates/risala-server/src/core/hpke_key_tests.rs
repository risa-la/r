//! Tests of the HPKE public keys INIT and COMMIT take (12.2, 12.5): every
//! key a device may encrypt to must be an X-Wing key, since OpenMLS does
//! not check their length and libcrux-kem panics on a short one (PLAN.md
//! 5, item 50).
//!
//! The groups and KeyPackages with short keys come from an [`Odd`]
//! device, whose crypto shortens the HPKE keys it derives when told to,
//! and encrypts to short keys without failing, so that it can build what
//! an honest device cannot.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use openmls_memory_storage::MemoryStorage;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::KeyPackage;
use risala_mls::openmls_traits::OpenMlsProvider;
use risala_mls::openmls_traits::crypto::OpenMlsCrypto;
use risala_mls::openmls_traits::types::{
    AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
    HpkeKeyPair, KemOutput, SignatureScheme,
};
use risala_mls::{Changes, RisalaConversation, RisalaCrypto, wire};
use risala_proto::names::Uid;
use tls_codec::SecretVLBytes;

use super::group_tests::{ALICE, BOB, Device, Sent, World, uid};

/// [`RisalaCrypto`], but for what tests ask of it: the HPKE key pairs it
/// derives are cut to 32 bytes when `plan` says so, one entry per key,
/// and it encrypts to keys of the wrong length with made-up output rather
/// than fail.
struct ShortCrypto {
    inner: RisalaCrypto,
    plan: Mutex<VecDeque<bool>>,
    derived: AtomicUsize,
}

impl ShortCrypto {
    /// The next key pairs derived are shortened as `plan` says, in order;
    /// those after it are not.
    fn plan(&self, plan: &[bool]) {
        *self.plan.lock().unwrap() = plan.iter().copied().collect();
    }

    /// How many key pairs it has derived so far.
    fn derived(&self) -> usize {
        self.derived.load(Ordering::SeqCst)
    }
}

impl OpenMlsCrypto for ShortCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        self.inner.supports(ciphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.inner.supported_ciphersuites()
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

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.inner.signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner.verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
        if !risala_mls::hpke_public_key_ok(pk_r) {
            return Ok(HpkeCiphertext {
                kem_output: vec![0; 1120].into(),
                ciphertext: vec![0; ptxt.len() + 16].into(),
            });
        }
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
        let mut pair = self.inner.derive_hpke_keypair(config, ikm)?;
        self.derived.fetch_add(1, Ordering::SeqCst);
        if self.plan.lock().unwrap().pop_front() == Some(true) {
            pair.public.truncate(32);
        }
        Ok(pair)
    }
}

/// An OpenMLS provider with [`ShortCrypto`].
struct OddProvider {
    crypto: ShortCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for OddProvider {
    type CryptoProvider = ShortCrypto;
    type RandProvider = RisalaCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &ShortCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RisalaCrypto {
        &self.crypto.inner
    }
}

/// A device that builds groups and KeyPackages with [`OddProvider`]. Its
/// key is that of `device`, which connects for it.
struct Odd {
    device: Device,
    provider: OddProvider,
}

impl Odd {
    fn new(who: &str, n: u8) -> Odd {
        Odd {
            device: Device::new(who, n),
            provider: OddProvider {
                crypto: ShortCrypto {
                    inner: RisalaCrypto::new().unwrap(),
                    plan: Mutex::new(VecDeque::new()),
                    derived: AtomicUsize::new(0),
                },
                storage: MemoryStorage::default(),
            },
        }
    }

    fn uid(&self) -> &Uid {
        &self.device.uid
    }

    fn plan(&self, plan: &[bool]) {
        self.provider.crypto.plan(plan);
    }

    fn create(&self, conversation: &RisalaConversation) -> MlsGroup {
        risala_mls::create_group(
            &self.provider,
            &self.device.signer(),
            self.uid(),
            conversation,
        )
        .unwrap()
    }

    fn init_line(&self, conv: &str, group: &MlsGroup) -> String {
        let gi = group
            .export_group_info(self.provider.crypto(), &self.device.signer(), false)
            .unwrap();
        let gi = wire::group_info_to_wire(&gi).unwrap();
        let tree = wire::tree_to_wire(&group.export_ratchet_tree()).unwrap();
        format!("init {conv} {gi} {tree}")
    }

    fn kp(&self) -> KeyPackage {
        risala_mls::key_package(&self.provider, &self.device.signer(), self.uid(), false)
            .unwrap()
            .key_package()
            .clone()
    }

    fn commit(&self, group: &mut MlsGroup, changes: Changes) -> Sent {
        let bundle =
            risala_mls::commit(&self.provider, group, &self.device.signer(), changes).unwrap();
        Sent::of(bundle.into_messages())
    }
}

#[tokio::test]
async fn init_refuses_hpke_keys_of_the_wrong_length() {
    let mut w = World::new();
    let a1 = Odd::new(ALICE, 1);
    let mut c1 = w.connect(&a1.device);
    let conversation = RisalaConversation::direct(a1.uid(), &uid(BOB));

    // The leaf's encryption key is the first key a new group derives.
    a1.plan(&[true]);
    let g = a1.create(&conversation);
    a1.plan(&[]);
    assert_eq!(
        w.ask(&mut c1, &a1.init_line(BOB, &g)).await,
        ["ERR invalid a leaf's encryption key is not an X-Wing public key"]
    );

    // `external_pub` is the first key exporting a GroupInfo derives.
    let g = a1.create(&conversation);
    a1.plan(&[true]);
    let line = a1.init_line(BOB, &g);
    assert_eq!(
        w.ask(&mut c1, &line).await,
        ["ERR invalid the GroupInfo's external_pub is not an X-Wing public key"]
    );

    // With neither, it is a group.
    let g = a1.create(&conversation);
    let lines = w.ask(&mut c1, &a1.init_line(BOB, &g)).await;
    assert!(lines[0].starts_with("OK id="), "{lines:?}");
}

#[tokio::test]
async fn commits_refuse_hpke_keys_of_the_wrong_length() {
    let mut w = World::new();
    let a1 = Odd::new(ALICE, 1);
    let mut c1 = w.connect(&a1.device);
    let mut g = a1.create(&RisalaConversation::direct(a1.uid(), &uid(BOB)));
    w.ask(&mut c1, &a1.init_line(BOB, &g)).await;
    let b5 = Device::new(BOB, 5);
    let sent = a1.commit(
        &mut g,
        Changes {
            add: vec![b5.kp()],
            ..Changes::default()
        },
    );
    let lines = w.ask(&mut c1, &sent.line(BOB)).await;
    assert_eq!(lines.last().unwrap(), "OK seq=1 epoch=1");
    g.merge_pending_commit(&a1.provider).unwrap();

    // A commit with a path in a group of two derives the root's key, then
    // the committer's leaf's, then the new epoch's `external_pub`.
    let before = a1.provider.crypto.derived();
    let _probe = a1.commit(&mut g, Changes::default());
    assert_eq!(a1.provider.crypto.derived() - before, 3);
    g.clear_pending_commit(a1.provider.storage()).unwrap();
    for (plan, reply) in [
        (
            [true, false, false],
            "ERR invalid a parent node's encryption key is not an X-Wing public key",
        ),
        (
            [false, true, false],
            "ERR invalid a leaf's encryption key is not an X-Wing public key",
        ),
        (
            [false, false, true],
            "ERR invalid the GroupInfo's external_pub is not an X-Wing public key",
        ),
    ] {
        a1.plan(&plan);
        let sent = a1.commit(&mut g, Changes::default());
        g.clear_pending_commit(a1.provider.storage()).unwrap();
        assert_eq!(w.ask(&mut c1, &sent.line(BOB)).await, [reply], "{plan:?}");
    }

    // A KeyPackage with a short init key and a short encryption key, the
    // two keys a KeyPackage derives, in that order.
    for plan in [[true, false], [false, true]] {
        let b6 = Odd::new(BOB, 6);
        b6.plan(&plan);
        let sent = a1.commit(
            &mut g,
            Changes {
                add: vec![b6.kp()],
                ..Changes::default()
            },
        );
        g.clear_pending_commit(a1.provider.storage()).unwrap();
        assert_eq!(
            w.ask(&mut c1, &sent.line(BOB)).await,
            ["ERR invalid an added KeyPackage has an HPKE key of the wrong length"],
            "{plan:?}"
        );
    }

    // Nothing of the above got in: a commit with good keys still does.
    let sent = a1.commit(&mut g, Changes::default());
    let lines = w.ask(&mut c1, &sent.line(BOB)).await;
    assert_eq!(lines.last().unwrap(), "OK seq=2 epoch=2");
}

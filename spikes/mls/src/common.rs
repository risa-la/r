//! Shared pieces: the cipher suite, device keys, credentials, the
//! conversation extension (0xF2A1), and line encodings.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ml_dsa::{Keypair as _, MlDsa44, Signer as _};
use openmls::prelude::tls_codec::{
    Deserialize as _, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize, VLBytes,
};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;

/// SPEC 12.2: the one suite risala uses.
pub const CS: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44;
/// SPEC 12.2 / 15: the conversation extension type.
pub const EXT_CONV: u16 = 0xF2A1;

pub type Provider = OpenMlsRustCrypto;

// ---------------------------------------------------------------------
// Device keys: one ML-DSA-44 key that signs in (4.5) and signs in MLS.

pub struct DeviceKey {
    /// The 32-byte ML-DSA seed (the private key, as in Appendix B).
    pub seed: [u8; 32],
    sk: ml_dsa::SigningKey<MlDsa44>,
    /// Raw 1312-byte public key, as in key files (4.4).
    pub pk: Vec<u8>,
}

impl DeviceKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = ml_dsa::SigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from(seed));
        let pk = sk.verifying_key().encode().to_vec();
        Self { seed, sk, pk }
    }

    pub fn generate() -> Self {
        Self::from_seed(rand::random())
    }

    /// SPEC 4.5: plain ML-DSA.Sign, empty context, no prehash. The
    /// `ml_dsa` Signer impl is the deterministic variant.
    pub fn auth_sign(&self, host: &str, nonce: &str, uid: &str) -> Vec<u8> {
        let msg = format!("risala-auth-1\n{host}\n{nonce}\n{uid}\n");
        self.sk.sign(msg.as_bytes()).encode().to_vec()
    }

    /// Sign arbitrary bytes (used for SignWithLabel in 12.8).
    pub fn raw_sign(&self, msg: &[u8]) -> Vec<u8> {
        self.sk.sign(msg).encode().to_vec()
    }
}

/// The same key, used as the MLS signer.
impl Signer for DeviceKey {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.sk.sign(payload).encode().to_vec())
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::MLDSA44
    }
}

pub fn verify_mldsa44(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::signature::Verifier as _;
    let Ok(pk) = <&ml_dsa::EncodedVerifyingKey<MlDsa44>>::try_from(pk) else {
        return false;
    };
    let vk = ml_dsa::VerifyingKey::<MlDsa44>::decode(pk);
    let Ok(sig) = <&ml_dsa::EncodedSignature<MlDsa44>>::try_from(sig) else {
        return false;
    };
    let Some(sig) = ml_dsa::Signature::<MlDsa44>::decode(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

/// A device: its uid, key, and its own OpenMLS provider (memory storage).
pub struct Device {
    pub uid: String,
    pub key: DeviceKey,
    pub provider: Provider,
}

impl Device {
    pub fn new(uid: &str) -> Self {
        Self::with_key(uid, DeviceKey::generate())
    }
    pub fn with_key(uid: &str, key: DeviceKey) -> Self {
        Self {
            uid: uid.to_lowercase(),
            key,
            provider: Provider::default(),
        }
    }

    /// SPEC 12.2: basic credential, identity = uid in lower case, and the
    /// raw device key as signature key.
    pub fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.uid.as_bytes().to_vec()).into(),
            signature_key: self.key.pk.clone().into(),
        }
    }

    pub fn key_package(&self, last_resort: bool) -> KeyPackage {
        let mut b = KeyPackage::builder().leaf_node_capabilities(capabilities());
        if last_resort {
            b = b.mark_as_last_resort();
        }
        b.build(CS, &self.provider, &self.key, self.credential())
            .expect("key package")
            .key_package()
            .clone()
    }
}

/// Leaf capabilities: our suite, basic credentials, and the conversation
/// extension (12.2). LastResort is listed so that last-resort KeyPackages
/// (12.4) validate.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CS]),
        Some(&[ExtensionType::Unknown(EXT_CONV), ExtensionType::LastResort]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

// ---------------------------------------------------------------------
// The conversation extension (12.2).

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct RisalaConversation {
    /// ConversationKind: 1 direct, 2 room.
    pub kind: u8,
    pub name: VLBytes,
    /// HistoryMode: 1 shared, 2 joined.
    pub history: u8,
}

impl RisalaConversation {
    pub fn direct(a: &str, b: &str) -> Self {
        let mut v = [a.to_lowercase(), b.to_lowercase()];
        v.sort(); // byte order: Rust string order is byte order
        let name = if v[0] == v[1] {
            v[0].clone()
        } else {
            format!("{} {}", v[0], v[1])
        };
        Self {
            kind: 1,
            name: name.into_bytes().into(),
            history: 1,
        }
    }
    pub fn room(id: &str, history: u8) -> Self {
        Self {
            kind: 2,
            name: id.as_bytes().to_vec().into(),
            history,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        self.tls_serialize_detached().unwrap()
    }
    /// Strict decode: the whole extension data must be consumed, and the
    /// enums must be known values.
    pub fn decode(mut data: &[u8]) -> Result<Self, String> {
        let c = Self::tls_deserialize(&mut data).map_err(|e| e.to_string())?;
        if !data.is_empty() {
            return Err("trailing bytes".into());
        }
        if !matches!(c.kind, 1 | 2) || !matches!(c.history, 1 | 2) {
            return Err("unknown enum value".into());
        }
        Ok(c)
    }
    pub fn from_extensions(ext: &Extensions<GroupContext>) -> Result<Self, String> {
        let u = ext.unknown(EXT_CONV).ok_or("no 0xF2A1 extension")?;
        Self::decode(&u.0)
    }
}

pub fn group_context_extensions(conv: &RisalaConversation) -> Extensions<GroupContext> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(EXT_CONV)],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(EXT_CONV, UnknownExtension(conv.encode())),
    ])
    .expect("extensions")
}

/// INIT (12.5): a new group with a random 32-byte id, our device the only
/// member. Commits are PublicMessages; the ratchet tree is never put in
/// an extension (it travels as `<tree>`).
pub fn create_group(dev: &Device, conv: &RisalaConversation) -> MlsGroup {
    let gid: [u8; 32] = rand::random();
    MlsGroup::builder()
        .ciphersuite(CS)
        .with_group_id(GroupId::from_slice(&gid))
        .with_capabilities(capabilities())
        .with_group_context_extensions(group_context_extensions(conv))
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
        .build(&dev.provider, &dev.key, dev.credential())
        .expect("create group")
}

pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
        .build()
}

// ---------------------------------------------------------------------
// Line encodings (12.2): MLSMessage or ratchet tree, base64 with padding.

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
pub fn unb64(s: &str) -> Vec<u8> {
    B64.decode(s).expect("base64")
}

pub fn msg_b64(m: &MlsMessageOut) -> String {
    b64(&m.tls_serialize_detached().unwrap())
}

pub fn parse_msg(s: &str) -> MlsMessageBodyIn {
    let bytes = unb64(s);
    let mut r = bytes.as_slice();
    let m = MlsMessageIn::tls_deserialize(&mut r).expect("MLSMessage");
    assert!(r.is_empty(), "trailing bytes after MLSMessage");
    m.extract()
}

/// `<tree>`: the data of a `ratchet_tree` extension, base64.
pub fn tree_b64(t: &openmls::treesync::RatchetTree) -> String {
    b64(&t.tls_serialize_detached().unwrap())
}
pub fn parse_tree(s: &str) -> RatchetTreeIn {
    let bytes = unb64(s);
    let mut r = bytes.as_slice();
    let t = RatchetTreeIn::tls_deserialize(&mut r).expect("ratchet tree");
    assert!(r.is_empty());
    t
}

pub fn kp_b64(kp: &KeyPackage) -> String {
    msg_b64(&MlsMessageOut::from(kp.clone()))
}


pub fn identity_of(c: &Credential) -> String {
    let b = BasicCredential::try_from(c.clone()).expect("basic credential");
    String::from_utf8(b.identity().to_vec()).expect("utf-8 uid")
}

/// Join from a Welcome line, with the tree from the line (12.7).
pub fn join_welcome(dev: &Device, welcome_line: &str, tree_line: &str) -> MlsGroup {
    let MlsMessageBodyIn::Welcome(w) = parse_msg(welcome_line) else {
        panic!("not a welcome")
    };
    StagedWelcome::new_from_welcome(
        &dev.provider,
        &join_config(),
        w,
        Some(parse_tree(tree_line)),
    )
    .expect("stage welcome")
    .into_group(&dev.provider)
    .expect("join")
}

/// Apply a COMMIT event line on a member.
pub fn apply_commit(dev: &Device, g: &mut MlsGroup, commit_line: &str) {
    let m = match parse_msg(commit_line) {
        MlsMessageBodyIn::PublicMessage(p) => p,
        _ => panic!("commit is not a PublicMessage"),
    };
    let pm = g.process_message(&dev.provider, m).expect("process commit");
    match pm.into_content() {
        ProcessedMessageContent::StagedCommitMessage(sc) => {
            g.merge_staged_commit(&dev.provider, *sc).expect("merge")
        }
        _ => panic!("not a commit"),
    }
}

pub fn history_key(dev: &Device, g: &MlsGroup) -> Vec<u8> {
    g.export_secret(dev.provider.crypto(), "risala history", b"", 48)
        .expect("exporter")
}

pub fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

//! The Appendix B test vector for history keys and ENC (SPEC 12.8, 12.9).
//!
//! `cargo run --release -- vectors` prints it. Every input is fixed, so the
//! output is the same on every run. `vectors.txt` holds the last output.
//!
//! The vector starts at the epoch's MLS `exporter_secret`, not at a whole
//! MLS group: a group's secrets come from random HPKE and init values,
//! which no other implementation can reproduce from the spec. So the
//! MLS-Exporter step is checked here against the RFC 9420 test vectors for
//! cipher suite 7, which also uses SHA-384 and HKDF-SHA384.
//!
//! The rest is cross-checked against a second library: libcrux for
//! ML-DSA-44 signing, HKDF, ChaCha20-Poly1305 and HMAC.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{AeadType, HashType};
use sha2::{Digest, Sha256};

use crate::common::DeviceKey;
use crate::history::{self, Randomness};
use crate::libcrux_mldsa;

/// RFC 9420 test vectors, cipher suite 7, from mlswg/mls-implementations
/// `test-vectors/crypto-basics.json`: (secret, label, context, length, out).
const RFC_EXPAND_WITH_LABEL: (&str, &str, &str, u16, &str) = (
    "39bb10928726fffb2b9b61fa4b07fed7ef5e554021a83c9d3af3aac9a8abab3db0bae67df71e8b3dd7ab3cf17dc783ce",
    "ExpandWithLabel",
    "2588d6b1ca306a9fc348a8b1b4de45c7111c4fb86ee362086ecf3f8f18f0b869df492fc5d30af6dd2d53e7b1eddf7d2f",
    32,
    "a2b96cd5edc41d0d56ce7a2282ce52aa792c7990483a52cbb044ee3f1f14f159",
);

/// The same file: DeriveSecret (secret, label, out).
const RFC_DERIVE_SECRET: (&str, &str, &str) = (
    "ee9426e58f77d9e2c16a18a8758097143645c523a1e3050c7e61c54b6703c721d3747961660a163230a03515f0ca0746",
    "DeriveSecret",
    "ad64a2748a2894e725825fbb97d8e9e11b30c7df09056b825a9328d7dd95a35436c326929b964afb181c747c1e95c3da",
);

/// `test-vectors/key-schedule.json`, cipher suite 7, every epoch:
/// (exporter_secret, label, context, secret). The length is always 48.
/// The label is a text string that happens to look like hex, and is used
/// as is. The context is hex.
const RFC_EXPORTER: [(&str, &str, &str, &str); 5] = [
    (
        "15069e73a02efc7168fccd5438e046762db53c708d9bd9ca0fc4602db7811e1ff25d653c9e23c11713bfe0cfc0cab050",
        "fe3a0807822eee9bbf74b4ecdb5b81ab68f961b8641c2182cfcc98321aae211fd1c71af98857b9e9e76834a57f6f001f",
        "575673f68ec4de0b8fffd678599636ec8688e135318739723a81b9505f3546e5655031e29180a308e4cd93f07ab349c7",
        "e8b44bd61781e56a4436239124e14709d9e0f607d463f406bd5d6160bad5297d8953763db9190521d20643a6efc97537",
    ),
    (
        "2343107e2ada585eefed4bdce1ba2a1dea2f6eb1d8e139f8cd09308d1a89c2a8caf47190745f4001ebedf3311330ae27",
        "9c0e0a37acc19bc1cfa6e2d9634befca8d6646bafc2bf60852c6bec55188e239de717b9db23388bbe1c26e1ff022e6ac",
        "d23e5f05d47260d54589047263eda73084fc3da8da19b4af1a6daf33503de520b3b3e858b43d38247808110f84e6fc85",
        "4fc234ac737a741d600f62bfb3bf74e8cf90d0901c653e339482cb066ea69c86da2d11c0fd48dddfbeff7603f69e5bb4",
    ),
    (
        "37a66527cb6f0bab5dc743b46fe573db4f156c4fe9418a39c7a02e193113d873df86f8dfef5d5eff61d0fda021f1b528",
        "45a07e78e177a5377e569dd6b5270cc6c5cffec8a022c9f0bebaa979a6b5a08c8bfb89ccae93b4c937067cfc6a3f5e87",
        "1c62f380a55a6929298161501345ab88ea35be89250a8c70107e049a9368fed1ed14e0211ca7913714a63b0d7083a1b9",
        "88b54c476050cc790d9becf2138b618bb31b017c2ecf9ad6d6af3e357dcc001d8497f3e2050ee403cce3a7ed3f932c26",
    ),
    (
        "f68ecae5df797d5bf900a3d8cbaa0b9bdb5f2f272669795497f3420a3b1e4b0e9e92bf1a239c4bd5c16edf2ad9d45a79",
        "94ea659949207fc98b151266a7e93ffd374d63fae340a246097b627f2c7502b6418deb62ce85f344eb093e88da99ca02",
        "e5ab748859faafd080f2db44c55c20f61b0631bb88206b5dc5aa11d63dfb7855463425b7bab19f4d6cec1be072fd4f71",
        "55ca5cec9ea11f77997e7ce962fee628c329a984a2eef0b41847ef727e0d042fa95b78035f374e2b6b63f15d53819563",
    ),
    (
        "b7d9e24338964a571448654a00a77a4edaaf9841f8561ca6bb9daa5288b3942b5674b20a161728ad8fae37b220a04fa2",
        "3bfa901fa99aefa0c88ddd412a63932e55f32aa2ec016200fef54118d195cbf80ee8014f21d512e7a9bbbceb1118122f",
        "510a846edd7258cf8fb3e4b8206ed772465babce448fe06d8cd94e24f8e13eb4d5b6bd12ec036610c9d5b2e3182aef11",
        "79542d77a234e4d562294a74079c8b4f7bdecd500c104f3c68b6875d44bbacac257075c767675fd9c71df63fb73aac87",
    ),
];

/// Appendix B's private key.
const SEED: &str = "c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8";

/// The 12.8 example reply, as the message content.
const CONTENT: &str = "@reply=15;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n";

const EPOCH: u64 = 1;

/// `start`, `start + 1`, ... as `N` bytes, so the inputs are easy to type.
fn counting<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Hex, wrapped at 64 characters.
fn wrap(s: &str) -> String {
    s.as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn check_rfc_vectors() {
    let (secret, label, context, len, out) = RFC_EXPAND_WITH_LABEL;
    assert_eq!(
        hex::encode(history::expand_with_label(&unhex(secret), label, &unhex(context), len)),
        out
    );
    let (secret, label, out) = RFC_DERIVE_SECRET;
    assert_eq!(hex::encode(history::derive_secret(&unhex(secret), label.as_bytes())), out);
    for (exporter_secret, label, context, out) in RFC_EXPORTER {
        assert_eq!(
            hex::encode(history::mls_exporter(
                &unhex(exporter_secret),
                label.as_bytes(),
                &unhex(context),
                48
            )),
            out
        );
    }
}

pub fn run() {
    check_rfc_vectors();

    let key = DeviceKey::from_seed(unhex(SEED).try_into().unwrap());
    let exporter_secret: [u8; 48] = counting(0x00);
    let group_id: [u8; 32] = counting(0x40);
    let r = Randomness {
        message_id: counting(0x80),
        frank_key: counting(0xa0),
        salt: counting(0xc0),
    };

    // 12.9.
    let derived = history::derive_secret(&exporter_secret, b"risala history");
    let history_key = history::mls_exporter(&exporter_secret, b"risala history", b"", 48);

    // 12.8.
    let (sent, steps) =
        history::encrypt_with(&key, &history_key, &group_id, EPOCH, CONTENT, true, &r);
    assert_eq!(steps.plaintext.len() % 256, 0);

    // It decrypts and verifies.
    let m = history::decrypt(
        &history_key,
        &group_id,
        EPOCH,
        &sent.payload,
        &sent.frank,
        &[key.pk.clone()],
    )
    .unwrap();
    assert_eq!(m.content.as_slice(), CONTENT.as_bytes());

    // A second library agrees on every primitive.
    let lc = libcrux_mldsa::LibcruxMlDsa::default();
    let kp = libcrux_mldsa::keypair(key.seed);
    assert_eq!(kp.verification_key.as_slice(), key.pk.as_slice());
    assert_eq!(
        libcrux_mldsa::sign_deterministic(&kp, &steps.sign_content),
        steps.signature
    );
    let ct = lc
        .aead_encrypt(
            AeadType::ChaCha20Poly1305,
            &steps.message_key,
            &steps.plaintext,
            &[0u8; 12],
            &steps.aad,
        )
        .unwrap();
    assert_eq!(ct, sent.payload[32..]);
    let tag = lc
        .hmac(HashType::Sha2_384, &r.frank_key, CONTENT.as_bytes())
        .unwrap();
    assert_eq!(tag.as_slice(), sent.frank.as_slice());
    // ExpandWithLabel for the message key, with libcrux's HKDF-Expand.
    let mut info = 32u16.to_be_bytes().to_vec();
    let label = b"MLS 1.0 risala message key";
    info.push(label.len() as u8);
    info.extend_from_slice(label);
    info.push(32);
    info.extend_from_slice(&r.salt);
    let mk = lc
        .hkdf_expand(HashType::Sha2_384, &history_key, &info, 32)
        .unwrap();
    assert_eq!(mk.as_slice(), steps.message_key.as_slice());

    eprintln!("checked: RFC 9420 suite 7 vectors, decryption, libcrux sign/AEAD/HMAC/HKDF");

    // The vector, as it goes into SPEC.md Appendix B.
    println!("Inputs:\n");
    println!("```");
    println!("exporter_secret (48 bytes):");
    println!("{}", wrap(&hex::encode(exporter_secret)));
    println!("group_id (32 bytes):");
    println!("{}", wrap(&hex::encode(group_id)));
    println!("epoch: {EPOCH}");
    println!("message_id (16 bytes):");
    println!("{}", hex::encode(r.message_id));
    println!("frank_key (32 bytes):");
    println!("{}", hex::encode(r.frank_key));
    println!("salt (32 bytes):");
    println!("{}", hex::encode(r.salt));
    println!("```");
    println!();
    println!(
        "content ({} bytes, ending in LF):\n\n```\n{}```\n",
        CONTENT.len(),
        CONTENT
    );
    println!("Outputs:\n");
    println!("```");
    println!("DeriveSecret(exporter_secret, \"risala history\"):");
    println!("{}", wrap(&hex::encode(&derived)));
    println!("history_key:");
    println!("{}", wrap(&hex::encode(&history_key)));
    println!("sender_key_id:");
    println!("{}", wrap(&hex::encode(steps.sender_key_id)));
    println!("RisalaMessageTBS ({} bytes):", steps.tbs.len());
    println!("{}", wrap(&hex::encode(&steps.tbs)));
    println!(
        "signature: {} bytes, SHA-256 {}",
        steps.signature.len(),
        sha256_hex(&steps.signature)
    );
    println!(
        "padding: {} bytes; RisalaMessage: {} bytes, SHA-256 {}",
        steps.padding_len,
        steps.plaintext.len(),
        sha256_hex(&steps.plaintext)
    );
    println!("message key:");
    println!("{}", hex::encode(&steps.message_key));
    println!("RisalaMessageAAD ({} bytes):", steps.aad.len());
    println!("{}", wrap(&hex::encode(&steps.aad)));
    println!(
        "payload: {} bytes, SHA-256 {}",
        sent.payload.len(),
        sha256_hex(&sent.payload)
    );
    println!("frank tag:");
    println!("{}", wrap(&hex::encode(&sent.frank)));
    println!("```");
    println!();
    let b64 = B64.encode(&sent.payload);
    println!("Payload ({} characters of base64):\n", b64.len());
    println!("```");
    println!("{}", wrap(&b64));
    println!("```");
    println!();
    println!("frank tag, as on the line: `{}`", B64.encode(&sent.frank));
}

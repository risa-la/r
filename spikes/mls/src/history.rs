//! 12.8 (ENC), 12.9 (history keys) and 12.10 (backup blobs), implemented
//! as the spec words them.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use openmls::prelude::tls_codec::{
    Deserialize as _, Serialize as _, Size as _, TlsDeserialize, TlsSerialize, TlsSize, VLBytes,
};
use sha2::{Digest, Sha384};

use crate::common::{DeviceKey, verify_mldsa44};

#[derive(Debug, Clone, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct RisalaMessage {
    pub message_id: [u8; 16],
    pub sender_key_id: [u8; 48],
    pub frank_key: [u8; 32],
    pub content: VLBytes,
    pub signature: VLBytes,
    pub padding: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
struct RisalaMessageTBS {
    group_id: VLBytes,
    epoch: u64,
    message_id: [u8; 16],
    sender_key_id: [u8; 48],
    frank_key: [u8; 32],
    content: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
struct RisalaMessageAAD {
    group_id: VLBytes,
    epoch: u64,
}

/// RFC 9420 5.1.2: SignContent { opaque label<V> = "MLS 1.0 " + Label; opaque content<V>; }
pub fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    #[derive(TlsSerialize, TlsSize)]
    struct SignContent {
        label: VLBytes,
        content: VLBytes,
    }
    SignContent {
        label: format!("MLS 1.0 {label}").into_bytes().into(),
        content: content.to_vec().into(),
    }
    .tls_serialize_detached()
    .unwrap()
}

/// RFC 9420 8: ExpandWithLabel with the suite's KDF (HKDF-SHA384).
pub fn expand_with_label(secret: &[u8], label: &str, context: &[u8], len: u16) -> Vec<u8> {
    #[derive(TlsSerialize, TlsSize)]
    struct KdfLabel {
        length: u16,
        label: VLBytes,
        context: VLBytes,
    }
    let info = KdfLabel {
        length: len,
        label: format!("MLS 1.0 {label}").into_bytes().into(),
        context: context.to_vec().into(),
    }
    .tls_serialize_detached()
    .unwrap();
    let hk = hkdf::Hkdf::<Sha384>::from_prk(secret).expect("prk length");
    let mut out = vec![0u8; len as usize];
    hk.expand(&info, &mut out).unwrap();
    out
}

pub fn frank(frank_key: &[u8], content: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha384> as Mac>::new_from_slice(frank_key).unwrap();
    m.update(content);
    m.finalize().into_bytes().to_vec()
}

fn tbs(group_id: &[u8], epoch: u64, m: &RisalaMessage) -> Vec<u8> {
    RisalaMessageTBS {
        group_id: group_id.to_vec().into(),
        epoch,
        message_id: m.message_id,
        sender_key_id: m.sender_key_id,
        frank_key: m.frank_key,
        content: m.content.clone(),
    }
    .tls_serialize_detached()
    .unwrap()
}

fn aad(group_id: &[u8], epoch: u64) -> Vec<u8> {
    RisalaMessageAAD {
        group_id: group_id.to_vec().into(),
        epoch,
    }
    .tls_serialize_detached()
    .unwrap()
}

/// Pad so the serialised RisalaMessage is a multiple of `block` bytes.
/// The varint length prefix of `padding` grows with it (1 byte below 64,
/// 2 bytes below 16384), so this has to search.
fn pad_to(m: &mut RisalaMessage, block: usize) {
    for p in 0..(block + 4) {
        m.padding = vec![0u8; p].into();
        if m.tls_serialized_len() % block == 0 {
            return;
        }
    }
    unreachable!("no padding length works");
}

pub struct Sent {
    /// `<payload...>`: salt || ciphertext, base64 on the line.
    pub payload: Vec<u8>,
    /// The `frank` tag value.
    pub frank: Vec<u8>,
    pub plaintext_len: usize,
}

/// The eight steps of 12.8.
pub fn encrypt(
    key: &DeviceKey,
    history_key: &[u8],
    group_id: &[u8],
    epoch: u64,
    content: &str,
    pad: bool,
) -> Sent {
    let mut m = RisalaMessage {
        message_id: rand::random(),
        sender_key_id: Sha384::digest(&key.pk).into(),
        frank_key: rand::random(),
        content: content.as_bytes().to_vec().into(),
        signature: VLBytes::new(vec![]),
        padding: VLBytes::new(vec![]),
    };
    let to_sign = sign_content("risala message", &tbs(group_id, epoch, &m));
    m.signature = key.raw_sign(&to_sign).into();
    if pad {
        pad_to(&mut m, 256);
    }
    let pt = m.tls_serialize_detached().unwrap();
    let salt: [u8; 32] = rand::random();
    let mk = expand_with_label(history_key, "risala message key", &salt, 32);
    let ct = ChaCha20Poly1305::new_from_slice(&mk)
        .unwrap()
        .encrypt(
            &[0u8; 12].into(),
            Payload {
                msg: &pt,
                aad: &aad(group_id, epoch),
            },
        )
        .unwrap();
    let mut payload = salt.to_vec();
    payload.extend_from_slice(&ct);
    Sent {
        payload,
        frank: frank(&m.frank_key, content.as_bytes()),
        plaintext_len: pt.len(),
    }
}

/// The decryption steps of 12.8 (steps 2-5; step 1 and 6 are the
/// caller's bookkeeping). `sender_keys` are the candidate keys of `from`.
pub fn decrypt(
    history_key: &[u8],
    group_id: &[u8],
    epoch: u64,
    payload: &[u8],
    frank_tag: &[u8],
    sender_keys: &[Vec<u8>],
) -> Result<RisalaMessage, String> {
    if payload.len() < 48 {
        return Err("payload shorter than 48 bytes".into());
    }
    let (salt, ct) = payload.split_at(32);
    let mk = expand_with_label(history_key, "risala message key", salt, 32);
    let pt = ChaCha20Poly1305::new_from_slice(&mk)
        .unwrap()
        .decrypt(
            &[0u8; 12].into(),
            Payload {
                msg: ct,
                aad: &aad(group_id, epoch),
            },
        )
        .map_err(|_| "AEAD")?;
    let mut r = pt.as_slice();
    let m = RisalaMessage::tls_deserialize(&mut r).map_err(|e| e.to_string())?;
    if !r.is_empty() {
        return Err("trailing bytes after RisalaMessage".into());
    }
    let sk = sender_keys
        .iter()
        .find(|k| Sha384::digest(k).as_slice() == m.sender_key_id)
        .ok_or("no key of `from` matches sender_key_id")?;
    let to_verify = sign_content("risala message", &tbs(group_id, epoch, &m));
    if !verify_mldsa44(sk, &to_verify, m.signature.as_slice()) {
        return Err("signature".into());
    }
    if frank(&m.frank_key, m.content.as_slice()) != frank_tag {
        return Err("franking tag".into());
    }
    Ok(m)
}

/// 12.10: backup key and key id from a recovery key.
pub fn backup_key(recovery: &[u8; 32], uid: &str) -> ([u8; 32], [u8; 8]) {
    let hk = hkdf::Hkdf::<Sha384>::new(Some(b""), recovery);
    let mut k = [0u8; 32];
    hk.expand(format!("risala backup {uid}").as_bytes(), &mut k)
        .unwrap();
    let id: [u8; 8] = Sha384::digest(k)[..8].try_into().unwrap();
    (k, id)
}

/// 12.10: a blob = key id || nonce || ChaCha20-Poly1305(history key).
pub fn backup_blob(recovery: &[u8; 32], uid: &str, conv_id: &str, epoch: u64, hk: &[u8]) -> Vec<u8> {
    let (k, id) = backup_key(recovery, uid);
    let nonce: [u8; 12] = rand::random();
    let ad = format!("{conv_id} {epoch}");
    let ct = ChaCha20Poly1305::new_from_slice(&k)
        .unwrap()
        .encrypt(
            &nonce.into(),
            Payload {
                msg: hk,
                aad: ad.as_bytes(),
            },
        )
        .unwrap();
    [id.as_slice(), &nonce, &ct].concat()
}

pub fn open_blob(recovery: &[u8; 32], uid: &str, conv_id: &str, epoch: u64, blob: &[u8]) -> Option<Vec<u8>> {
    let (k, id) = backup_key(recovery, uid);
    if blob.len() != 84 || blob[..8] != id {
        return None;
    }
    let ad = format!("{conv_id} {epoch}");
    ChaCha20Poly1305::new_from_slice(&k)
        .unwrap()
        .decrypt(
            blob[8..20].into(),
            Payload {
                msg: &blob[20..],
                aad: ad.as_bytes(),
            },
        )
        .ok()
}

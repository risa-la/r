//! Encrypted messages, the payload of ENC (12.8).
//!
//! ```text
//! struct {
//!     opaque message_id[16];
//!     opaque sender_key_id[48];
//!     opaque frank_key[32];
//!     opaque content<V>;
//!     opaque signature<V>;
//!     opaque padding<V>;
//! } RisalaMessage;
//! ```
//!
//! The sender signs the message with SignWithLabel(signature key,
//! "risala message", RisalaMessageTBS), pads it to a multiple of 256
//! bytes, and encrypts it with ChaCha20-Poly1305 under a message key that
//! ExpandWithLabel derives from the epoch's history key and a random salt.
//! The payload is the salt, then the ciphertext. The `frank` tag is
//! HMAC-SHA-384(frank_key, content), which lets the content be reported
//! (5.8).
//!
//! [`encrypt`] does the eight steps of 12.8. [`decrypt`] does steps 3 and
//! 5 of decryption, and [`UnverifiedMessage::verify`] step 4. Steps 1, 2
//! and 6, which need the conversation's events, are the caller's.

use risala_proto::auth::PublicKey;
use risala_proto::error::ParseError;
use risala_proto::mls::{
    Ciphertext, Content, FRANK_KEY_LEN, Frank, FrankKey, Franking, MESSAGE_SIGNATURE_LABEL,
    MIN_PAYLOAD_LEN,
};
use tls_codec::{
    Deserialize as _, Serialize as _, Size as _, TlsDeserialize, TlsSerialize, TlsSize,
    VLByteSlice, VLBytes,
};
use zeroize::Zeroizing;

use crate::history::HistoryKey;
use crate::primitives::{
    AEAD_NONCE_LEN, HASH_LEN, hmac_sha384, open, random, seal, sha384, sign_content,
};
use crate::signer::DeviceSigner;

/// The most bytes a message's content may have, 4 MiB (12.8). Larger
/// content fails to decrypt.
pub const MAX_CONTENT_LEN: usize = 4 * 1024 * 1024;

/// The length of a message id (12.8).
pub const MESSAGE_ID_LEN: usize = 16;

/// The length of a sender key id, the SHA-384 hash of the sender's key
/// (12.8).
pub const SENDER_KEY_ID_LEN: usize = HASH_LEN;

/// The length of the salt at the start of a payload (12.8).
pub const SALT_LEN: usize = 32;

/// Encoded RisalaMessages are padded to a multiple of this (12.8).
pub const PADDING_BLOCK: usize = 256;

/// The nonce of every message: a message key is used only once (12.8).
const NONCE: [u8; AEAD_NONCE_LEN] = [0; AEAD_NONCE_LEN];

/// A message's id, `message_id` (12.8). TEXT lines refer to other messages
/// by it, as `target` (12.8).
pub type MessageId = [u8; MESSAGE_ID_LEN];

/// Why a message could not be encrypted or read (12.8). A device does not
/// show the content of a message that fails, and may show that it could
/// not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// The content is empty or longer than [`MAX_CONTENT_LEN`].
    #[error("the content is empty or too long")]
    ContentLength,
    /// The payload is shorter than the salt and the tag.
    #[error("the payload is too short")]
    TooShort,
    /// The payload does not decrypt under this history key, group and
    /// epoch.
    #[error("the payload does not decrypt")]
    Decrypt,
    /// The plaintext is not exactly one RisalaMessage.
    #[error("the plaintext is not a RisalaMessage")]
    Malformed,
    /// The `frank` tag is not the HMAC of the content.
    #[error("the franking tag does not match")]
    Frank,
    /// The key does not have the message's `sender_key_id`.
    #[error("not the sender's key")]
    WrongSender,
    /// The signature does not verify under the sender's key.
    #[error("the signature does not verify")]
    Signature,
    /// No randomness, or the payload is too long for a line.
    #[error("the message could not be encrypted")]
    Encrypt,
}

#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct RisalaMessage {
    message_id: [u8; MESSAGE_ID_LEN],
    sender_key_id: [u8; SENDER_KEY_ID_LEN],
    frank_key: [u8; FRANK_KEY_LEN],
    content: VLBytes,
    signature: VLBytes,
    padding: VLBytes,
}

#[derive(TlsSerialize, TlsSize)]
struct RisalaMessageTbs<'a> {
    group_id: VLByteSlice<'a>,
    epoch: u64,
    message_id: [u8; MESSAGE_ID_LEN],
    sender_key_id: [u8; SENDER_KEY_ID_LEN],
    frank_key: [u8; FRANK_KEY_LEN],
    content: VLByteSlice<'a>,
}

#[derive(TlsSerialize, TlsSize)]
struct RisalaMessageAad<'a> {
    group_id: VLByteSlice<'a>,
    epoch: u64,
}

/// The `sender_key_id` of a device key: its SHA-384 hash (12.8).
pub fn sender_key_id(key: &PublicKey) -> [u8; SENDER_KEY_ID_LEN] {
    sha384(key.as_bytes())
}

/// The `frank` tag of `content`: HMAC-SHA-384 under the franking key, over
/// the content's bytes alone (12.8).
pub fn frank_tag(frank_key: &[u8; FRANK_KEY_LEN], content: &[u8]) -> Frank {
    Frank::from_bytes(hmac_sha384(frank_key, content))
}

/// RisalaMessageTBS (12.8).
fn tbs(
    group_id: &[u8],
    epoch: u64,
    message_id: &MessageId,
    sender_key_id: &[u8; SENDER_KEY_ID_LEN],
    frank_key: &[u8; FRANK_KEY_LEN],
    content: &[u8],
) -> Vec<u8> {
    RisalaMessageTbs {
        group_id: VLByteSlice(group_id),
        epoch,
        message_id: *message_id,
        sender_key_id: *sender_key_id,
        frank_key: *frank_key,
        content: VLByteSlice(content),
    }
    .tls_serialize_detached()
    .expect("lengths fit variable-size vectors")
}

/// RisalaMessageAAD (12.8).
fn aad(group_id: &[u8], epoch: u64) -> Vec<u8> {
    RisalaMessageAad {
        group_id: VLByteSlice(group_id),
        epoch,
    }
    .tls_serialize_detached()
    .expect("lengths fit variable-size vectors")
}

/// The length of a variable-size vector's length prefix [RFC9420, 2.1.2].
fn prefix_len(len: usize) -> usize {
    match len {
        0..64 => 1,
        64..16384 => 2,
        _ => 4,
    }
}

/// The fewest zero bytes of padding that make a RisalaMessage, which is
/// `unpadded` bytes long with empty padding, a multiple of
/// [`PADDING_BLOCK`] (12.8, step 5). The length prefix of `padding` grows
/// from one byte to two at 64 bytes, so this may be more than 255.
fn padding_len(unpadded: usize) -> usize {
    let without_prefix = unpadded - 1;
    (0..)
        .find(|&p| (without_prefix + prefix_len(p) + p).is_multiple_of(PADDING_BLOCK))
        .expect("some length within two blocks works")
}

/// The random values of a message (12.8, steps 2 and 6).
struct Randomness {
    message_id: MessageId,
    frank_key: Zeroizing<[u8; FRANK_KEY_LEN]>,
    salt: [u8; SALT_LEN],
}

/// An encrypted message, for ENC (12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    /// `<payload...>`: the salt, then the encrypted RisalaMessage.
    pub payload: Ciphertext,
    /// The `frank` tag.
    pub frank: Frank,
    /// The message's id, for replies, edits and reactions to it, and to
    /// recognise it when it comes back (12.8).
    pub message_id: MessageId,
}

/// Encrypts `content`, one or more lines (12.8), under the history key of
/// the group's epoch, signed with the device's key.
///
/// The content must not be empty, and is at most [`MAX_CONTENT_LEN`]
/// bytes. Checking the lines themselves is the caller's job.
pub fn encrypt(
    signer: &DeviceSigner<'_>,
    key: &HistoryKey,
    group_id: &[u8],
    epoch: u64,
    content: &[u8],
) -> Result<Encrypted, MessageError> {
    let randomness = Randomness {
        message_id: random().map_err(|_| MessageError::Encrypt)?,
        frank_key: Zeroizing::new(random().map_err(|_| MessageError::Encrypt)?),
        salt: random().map_err(|_| MessageError::Encrypt)?,
    };
    encrypt_with(signer, key, group_id, epoch, content, &randomness)
}

/// [`encrypt`] with its random values given.
fn encrypt_with(
    signer: &DeviceSigner<'_>,
    key: &HistoryKey,
    group_id: &[u8],
    epoch: u64,
    content: &[u8],
    randomness: &Randomness,
) -> Result<Encrypted, MessageError> {
    if content.is_empty() || content.len() > MAX_CONTENT_LEN {
        return Err(MessageError::ContentLength);
    }
    let sender_key_id = sender_key_id(&signer.public_key());
    // Step 4: SignWithLabel(key, "risala message", RisalaMessageTBS).
    let to_sign = sign_content(
        MESSAGE_SIGNATURE_LABEL,
        &tbs(
            group_id,
            epoch,
            &randomness.message_id,
            &sender_key_id,
            &randomness.frank_key,
            content,
        ),
    );
    let signature = signer
        .key()
        .sign_mls(&to_sign)
        .expect("SignContent is what sign_mls signs");
    let mut message = RisalaMessage {
        message_id: randomness.message_id,
        sender_key_id,
        frank_key: *randomness.frank_key,
        content: content.into(),
        signature: signature.as_bytes().as_slice().into(),
        padding: VLBytes::new(Vec::new()),
    };
    // Step 5.
    message.padding = vec![0; padding_len(message.tls_serialized_len())].into();
    let plaintext = Zeroizing::new(
        message
            .tls_serialize_detached()
            .expect("lengths fit variable-size vectors"),
    );
    zeroize::Zeroize::zeroize(&mut message.frank_key);
    // Steps 6-8.
    let message_key = key.message_key(&randomness.salt);
    let ciphertext = seal(&message_key, &NONCE, &aad(group_id, epoch), &plaintext);
    let mut payload = Vec::with_capacity(SALT_LEN + ciphertext.len());
    payload.extend_from_slice(&randomness.salt);
    payload.extend_from_slice(&ciphertext);
    Ok(Encrypted {
        payload: Ciphertext::from_bytes(&payload).map_err(|_| MessageError::Encrypt)?,
        frank: frank_tag(&randomness.frank_key, content),
        message_id: randomness.message_id,
    })
}

/// Decrypts an ENC payload under the history key of the group's epoch, and
/// checks its `frank` tag (12.8, decryption steps 3 and 5).
///
/// The signature is not checked yet: see [`UnverifiedMessage`].
pub fn decrypt(
    key: &HistoryKey,
    group_id: &[u8],
    epoch: u64,
    payload: &Ciphertext,
    frank: &Frank,
) -> Result<UnverifiedMessage, MessageError> {
    if payload.decoded_len() < MIN_PAYLOAD_LEN {
        return Err(MessageError::TooShort);
    }
    let payload = payload.decode();
    let (salt, ciphertext) = payload.split_at(SALT_LEN);
    let plaintext = open(
        &key.message_key(salt),
        &NONCE,
        &aad(group_id, epoch),
        ciphertext,
    )
    .ok_or(MessageError::Decrypt)?;
    let message = RisalaMessage::tls_deserialize_exact(&plaintext[..])
        .map_err(|_| MessageError::Malformed)?;
    let content: Vec<u8> = message.content.into();
    if content.is_empty() || content.len() > MAX_CONTENT_LEN {
        return Err(MessageError::ContentLength);
    }
    if frank_tag(&message.frank_key, &content) != *frank {
        return Err(MessageError::Frank);
    }
    Ok(UnverifiedMessage {
        group_id: group_id.to_vec(),
        epoch,
        message_id: message.message_id,
        sender_key_id: message.sender_key_id,
        frank_key: FrankKey::from_bytes(message.frank_key),
        content,
        signature: message.signature.into(),
    })
}

/// A decrypted message whose signature is not checked yet (12.8, step 4).
///
/// A device that was in the group in the message's epoch knows every
/// leaf, and must [`verify`](Self::verify) with the key of the leaf of
/// `from` whose hash is [`sender_key_id`](Self::sender_key_id). Otherwise
/// it uses a key of `from` with that hash that it has seen in a key file
/// or a group, and only if it knows none may it show the content as
/// unverified, with [`into_unverified`](Self::into_unverified).
pub struct UnverifiedMessage {
    group_id: Vec<u8>,
    epoch: u64,
    message_id: MessageId,
    sender_key_id: [u8; SENDER_KEY_ID_LEN],
    frank_key: FrankKey,
    content: Vec<u8>,
    signature: Vec<u8>,
}

impl UnverifiedMessage {
    /// The SHA-384 hash of the sender's key.
    pub fn sender_key_id(&self) -> &[u8; SENDER_KEY_ID_LEN] {
        &self.sender_key_id
    }

    /// Whether `key` has the message's `sender_key_id`.
    pub fn is_from(&self, key: &PublicKey) -> bool {
        sender_key_id(key) == self.sender_key_id
    }

    /// The first of `keys` that has the message's `sender_key_id`.
    pub fn find_sender<'k>(
        &self,
        keys: impl IntoIterator<Item = &'k PublicKey>,
    ) -> Option<&'k PublicKey> {
        keys.into_iter().find(|key| self.is_from(key))
    }

    /// Checks the signature with `sender`, which must have the message's
    /// `sender_key_id` (12.8, step 4).
    pub fn verify(self, sender: &PublicKey) -> Result<Message, MessageError> {
        if !self.is_from(sender) {
            return Err(MessageError::WrongSender);
        }
        let signed = sign_content(
            MESSAGE_SIGNATURE_LABEL,
            &tbs(
                &self.group_id,
                self.epoch,
                &self.message_id,
                &self.sender_key_id,
                self.frank_key.as_bytes(),
                &self.content,
            ),
        );
        if !crate::verify_ml_dsa_44(sender, &signed, &self.signature) {
            return Err(MessageError::Signature);
        }
        Ok(self.into_message(Some(sender.clone())))
    }

    /// The message without a checked signature, for a device that was not
    /// in the group in its epoch and knows no key of the sender with its
    /// `sender_key_id` (12.8). Show it marked as unverified.
    pub fn into_unverified(self) -> Message {
        self.into_message(None)
    }

    fn into_message(self, sender: Option<PublicKey>) -> Message {
        Message {
            message_id: self.message_id,
            sender_key_id: self.sender_key_id,
            frank_key: self.frank_key,
            content: self.content,
            sender,
        }
    }
}

impl std::fmt::Debug for UnverifiedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnverifiedMessage")
            .field("epoch", &self.epoch)
            .field("content_len", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// A decrypted message (12.8).
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    /// Its id. The caller checks that it has not seen it before in the
    /// conversation (step 6).
    pub message_id: MessageId,
    /// The SHA-384 hash of the sender's key.
    pub sender_key_id: [u8; SENDER_KEY_ID_LEN],
    /// Its franking key, needed to report it (5.8).
    pub frank_key: FrankKey,
    /// The content lines (12.8), not yet checked.
    pub content: Vec<u8>,
    /// The key whose signature verified, or `None` if the message is shown
    /// as unverified.
    pub sender: Option<PublicKey>,
}

impl Message {
    /// What REPORTENC sends to report the message (5.8): its franking key
    /// and content. Fails only if the content is too long for a line.
    pub fn franking(&self) -> Result<Franking, ParseError> {
        Ok(Franking {
            key: self.frank_key,
            content: Content::from_bytes(&self.content)?,
        })
    }
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("content_len", &self.content.len())
            .field("verified", &self.sender.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::tests::{hex, unhex};
    use risala_proto::auth::SecretKey;

    /// Appendix B's private key.
    const SEED: &str = "c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8";
    /// The reply of 12.8, the content of Appendix B's vector.
    const CONTENT: &[u8] = b"@reply=15;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n";

    fn sha256_hex(bytes: &[u8]) -> String {
        hex(&<sha2::Sha256 as sha2::Digest>::digest(bytes))
    }

    fn counting<const N: usize>(start: u8) -> [u8; N] {
        std::array::from_fn(|i| start.wrapping_add(i as u8))
    }

    fn appendix_b() -> (SecretKey, HistoryKey, [u8; 32], Randomness) {
        let key = SecretKey::from_seed(unhex(SEED).try_into().unwrap());
        let history_key = HistoryKey::from_exporter_secret(&counting::<48>(0));
        let randomness = Randomness {
            message_id: counting(0x80),
            frank_key: Zeroizing::new(counting(0xa0)),
            salt: counting(0xc0),
        };
        (key, history_key, counting(0x40), randomness)
    }

    /// Appendix B: every step of encrypting the reply of 12.8.
    #[test]
    fn appendix_b_message() {
        let (key, history_key, group_id, randomness) = appendix_b();
        let signer = DeviceSigner::new(&key);
        let sender = key.public_key();

        let id = sender_key_id(&sender);
        assert_eq!(
            hex(&id),
            "9dd34a4b2e6712ac7d2c679a46caaaaf875c945aefc33a78cefe1a014b9dacfa\
             0f7c1460fbe5d395af0b70f54d51a994"
        );

        let tbs_bytes = tbs(
            &group_id,
            1,
            &randomness.message_id,
            &id,
            &randomness.frank_key,
            CONTENT,
        );
        assert_eq!(tbs_bytes.len(), 199);
        assert_eq!(
            hex(&tbs_bytes),
            "20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e\
             5f0000000000000001808182838485868788898a8b8c8d8e8f9dd34a4b2e6712\
             ac7d2c679a46caaaaf875c945aefc33a78cefe1a014b9dacfa0f7c1460fbe5d3\
             95af0b70f54d51a994a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6\
             b7b8b9babbbcbdbebf3d407265706c793d31353b7461726765743d304a783148\
             6b593378397a326235523071576d3166413d3d20544558542073656520796f75\
             2061742031320a"
        );
        let signature = key
            .sign_mls(&sign_content("risala message", &tbs_bytes))
            .unwrap();
        assert_eq!(
            sha256_hex(signature.as_bytes()),
            "64033444c9e465b935808dcb6cf257b77ada5579f5fe82a40e4d0b9340939b07"
        );

        let aad_bytes = aad(&group_id, 1);
        assert_eq!(
            hex(&aad_bytes),
            "20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e\
             5f0000000000000001"
        );

        let sent = encrypt_with(&signer, &history_key, &group_id, 1, CONTENT, &randomness).unwrap();
        let payload = sent.payload.decode();
        assert_eq!(payload.len(), 2864);
        assert_eq!(
            sha256_hex(&payload),
            "737abc1cf8642de1064a4fee45f6732d4caa7fbe8d492079fcb61ee4713d47ff"
        );
        assert!(
            sent.payload
                .as_str()
                .starts_with("wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t+ltid5Gy41XPaamODmckA4")
        );
        assert!(
            sent.payload
                .as_str()
                .ends_with("7CwSmMLfe3djuT2rfwgG6urxgOoq0d9HG+VExWE/k3s=")
        );
        assert_eq!(sent.payload.as_str().len(), 3820);
        assert_eq!(
            sent.frank.to_string(),
            "g9cXIC7jqILncOjOqgT/cVVh7NVXTmV2g5y5nsmPi5YCd8bMks4HlxtG46aTV5jK"
        );
        assert_eq!(sent.message_id, randomness.message_id);

        // Step 5: the RisalaMessage is 2581 bytes before padding, and 2816
        // after 234 bytes of it.
        let plaintext = open(
            &history_key.message_key(&randomness.salt),
            &NONCE,
            &aad_bytes,
            &payload[SALT_LEN..],
        )
        .unwrap();
        assert_eq!(plaintext.len(), 2816);
        assert_eq!(
            sha256_hex(&plaintext),
            "a070ee7fdfc54f7caf69e20be49447642f49f825d705f21882723d3700287d62"
        );
        assert_eq!(padding_len(2581), 234);

        // And it decrypts, with the franking of 5.8.
        let message = decrypt(&history_key, &group_id, 1, &sent.payload, &sent.frank)
            .unwrap()
            .verify(&sender)
            .unwrap();
        assert_eq!(message.content, CONTENT);
        assert_eq!(message.message_id, randomness.message_id);
        assert_eq!(message.sender, Some(sender));
        assert!(message.franking().unwrap().verifies(&sent.frank));
    }

    #[test]
    fn padding() {
        for unpadded in 2..3000 {
            let p = padding_len(unpadded);
            assert_eq!(
                (unpadded - 1 + prefix_len(p) + p) % PADDING_BLOCK,
                0,
                "{unpadded}"
            );
            // The fewest: no shorter padding works.
            assert!(
                (0..p).all(|q| !(unpadded - 1 + prefix_len(q) + q).is_multiple_of(PADDING_BLOCK))
            );
        }
    }

    #[test]
    fn round_trip_and_failures() {
        let key = SecretKey::from_seed([5; 32]);
        let other = SecretKey::from_seed([6; 32]).public_key();
        let signer = DeviceSigner::new(&key);
        let history_key = HistoryKey::from_bytes([1; 48]);
        let group_id = [2; 32];
        let sent = encrypt(&signer, &history_key, &group_id, 7, b"TEXT hi\n").unwrap();
        assert_eq!(sent.payload.decoded_len() % 256, SALT_LEN + 16);

        let ok = decrypt(&history_key, &group_id, 7, &sent.payload, &sent.frank).unwrap();
        assert_eq!(
            ok.find_sender([&other, &key.public_key()]),
            Some(&key.public_key())
        );
        assert_eq!(ok.verify(&other).unwrap_err(), MessageError::WrongSender);
        let ok = decrypt(&history_key, &group_id, 7, &sent.payload, &sent.frank).unwrap();
        let unverified = ok.into_unverified();
        assert_eq!(unverified.content, b"TEXT hi\n");
        assert_eq!(unverified.sender, None);

        // Another key, group or epoch does not decrypt.
        let wrong = |key: &HistoryKey, group: &[u8], epoch| {
            decrypt(key, group, epoch, &sent.payload, &sent.frank).unwrap_err()
        };
        assert_eq!(
            wrong(&HistoryKey::from_bytes([9; 48]), &group_id, 7),
            MessageError::Decrypt
        );
        assert_eq!(wrong(&history_key, &[3; 32], 7), MessageError::Decrypt);
        assert_eq!(wrong(&history_key, &group_id, 8), MessageError::Decrypt);

        // A flipped bit anywhere in the payload, or a wrong frank tag.
        let mut bytes = sent.payload.decode();
        for i in [0, SALT_LEN, bytes.len() - 1] {
            bytes[i] ^= 1;
            let tampered = Ciphertext::from_bytes(&bytes).unwrap();
            assert_eq!(
                decrypt(&history_key, &group_id, 7, &tampered, &sent.frank).unwrap_err(),
                MessageError::Decrypt
            );
            bytes[i] ^= 1;
        }
        let short = Ciphertext::from_bytes(&bytes[..47]).unwrap();
        assert_eq!(
            decrypt(&history_key, &group_id, 7, &short, &sent.frank).unwrap_err(),
            MessageError::TooShort
        );
        assert_eq!(
            decrypt(
                &history_key,
                &group_id,
                7,
                &sent.payload,
                &Frank::from_bytes([0; 48])
            )
            .unwrap_err(),
            MessageError::Frank
        );

        assert_eq!(
            encrypt(&signer, &history_key, &group_id, 7, b"").unwrap_err(),
            MessageError::ContentLength
        );
    }

    /// A message whose signature was made over another epoch, re-encrypted
    /// by someone holding the history key, does not verify.
    #[test]
    fn signature_binds_group_and_epoch() {
        let key = SecretKey::from_seed([5; 32]);
        let signer = DeviceSigner::new(&key);
        let history_key = HistoryKey::from_bytes([1; 48]);
        let randomness = Randomness {
            message_id: [1; 16],
            frank_key: Zeroizing::new([2; 32]),
            salt: [3; 32],
        };
        let sent = encrypt_with(
            &signer,
            &history_key,
            &[2; 32],
            7,
            b"TEXT hi\n",
            &randomness,
        )
        .unwrap();
        // Decrypt the RisalaMessage, then encrypt it again for epoch 8.
        let payload = sent.payload.decode();
        let plaintext = open(
            &history_key.message_key(&randomness.salt),
            &NONCE,
            &aad(&[2; 32], 7),
            &payload[SALT_LEN..],
        )
        .unwrap();
        let moved = seal(
            &history_key.message_key(&randomness.salt),
            &NONCE,
            &aad(&[2; 32], 8),
            &plaintext,
        );
        let moved = Ciphertext::from_bytes(&[&randomness.salt[..], &moved].concat()).unwrap();
        let unverified = decrypt(&history_key, &[2; 32], 8, &moved, &sent.frank).unwrap();
        assert_eq!(
            unverified.verify(&key.public_key()).unwrap_err(),
            MessageError::Signature
        );
    }
}

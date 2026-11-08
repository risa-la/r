//! History archives and transfer refs (12.13).
//!
//! A [`HistoryArchive`] carries an identity's history of some
//! conversations from one of its devices to another: at pairing, to catch
//! up a device that has a gap, or as a backup ([`crate::backup`]). It is
//! encrypted as a file (12.11) under a new random key and stored as a blob
//! (12.12). A [`TransferRef`] names the blob and holds the key: the
//! IdentityBundle carries one (4.8), and so does a `TRANSFER` line in the
//! conversation with yourself (12.9). A transfer too large for one blob is
//! split over several archives, and the first names the others in `more`.
//!
//! The structures are in the TLS presentation language, with MLS's
//! variable-size vectors [RFC9420, 2.1.2]:
//!
//! ```text
//! struct { opaque blob_hash[48]; opaque key[32]; } TransferRef;
//! struct {
//!     opaque message_id[16]; opaque sender<V>; uint8 verified;
//!     uint64 sent; uint64 received; uint64 seq; opaque content<V>;
//! } ArchivedMessage;
//! struct {
//!     opaque group_id<V>; opaque host<V>; opaque box[16];
//!     ArchivedMessage messages<V>;
//! } ArchivedConversation;
//! struct {
//!     uint8 version; opaque uid<V>; uint64 made;
//!     ArchivedConversation conversations<V>; TransferRef more<V>;
//! } HistoryArchive;
//! ```

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::names::{Domain, Identity, Uid};
use zeroize::Zeroizing;

use crate::file::{self, BlobRef, FILE_KEY_LEN, FileError, FileKey};
use crate::primitives::HASH_LEN;

/// The version of a HistoryArchive (12.13).
pub const ARCHIVE_VERSION: u8 = 1;

/// The length of an encoded TransferRef (12.13).
pub const TRANSFER_REF_LEN: usize = HASH_LEN + FILE_KEY_LEN;

/// The length of a message id (12.9).
pub const MESSAGE_ID_LEN: usize = 16;

/// The length of a box (3.5).
pub const BOX_LEN: usize = 16;

/// The largest seq (3.5): 2^63 - 1.
const MAX_SEQ: u64 = i64::MAX as u64;

/// Why an archive or transfer ref cannot be read or opened (12.13).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArchiveError {
    /// The bytes are not an encoded structure: too short, too long, a bad
    /// vector length, or a field out of range.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// The archive names a version this device does not support (2.4).
    #[error("unsupported archive version {0}")]
    Version(u8),
    /// The archive is another identity's.
    #[error("the archive is for another identity")]
    OtherIdentity,
    /// The blob does not match its hash, or does not decrypt as a file.
    #[error(transparent)]
    File(#[from] FileError),
    /// One message alone is larger than a blob may be, so the transfer
    /// cannot be split.
    #[error("a message is too large for one archive")]
    TooLarge,
    /// The operating system gave no randomness for a key.
    #[error("no randomness: {0}")]
    Random(#[from] getrandom::Error),
}

/// A TransferRef (12.13): the hash of a blob that holds an encrypted
/// HistoryArchive, and the key it is encrypted under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferRef {
    /// The blob's hash, its blob-ref (12.12).
    pub blob: BlobRef,
    /// The archive's file key (12.11).
    pub key: FileKey,
}

impl TransferRef {
    /// The encoded TransferRef: the hash, then the key. 80 bytes, wiped
    /// when dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; TRANSFER_REF_LEN]> {
        let mut out = Zeroizing::new([0; TRANSFER_REF_LEN]);
        out[..HASH_LEN].copy_from_slice(self.blob.as_bytes());
        out[HASH_LEN..].copy_from_slice(self.key.as_bytes());
        out
    }

    /// Reads an encoded TransferRef: exactly 80 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<TransferRef, ArchiveError> {
        if bytes.len() != TRANSFER_REF_LEN {
            return Err(ArchiveError::Malformed("TransferRef"));
        }
        Ok(TransferRef {
            blob: BlobRef::from_bytes(bytes[..HASH_LEN].try_into().expect("48 bytes")),
            key: FileKey::from_bytes(bytes[HASH_LEN..].try_into().expect("32 bytes")),
        })
    }

    /// The `<ref>` of a TRANSFER line (12.13): the TransferRef in base64
    /// with padding.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(&self.to_bytes()[..]))
    }

    /// Reads the `<ref>` of a TRANSFER line: exactly 80 bytes in canonical
    /// base64 with padding.
    pub fn from_base64(text: &str) -> Option<TransferRef> {
        let mut bytes = Zeroizing::new([0; TRANSFER_REF_LEN]);
        file::decode_base64_exact(text, &mut bytes[..])?;
        TransferRef::from_bytes(&bytes[..]).ok()
    }
}

/// An ArchivedMessage (12.13): one message as its recipient stored it.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchivedMessage {
    /// The message's id (12.9).
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// Who sent it.
    pub sender: Uid,
    /// Whether the sender's leaf was confirmed (12.10).
    pub verified: bool,
    /// The sender's time, in ms since the epoch.
    pub sent: u64,
    /// The server's time, in ms since the epoch.
    pub received: u64,
    /// The post's seq (5.2), from 1 to 2^63 - 1.
    pub seq: u64,
    /// The content lines, as received (12.9). Edited messages hold their
    /// newest version here, and deleted ones are left out (12.13).
    pub content: Vec<u8>,
}

/// `Debug` shows the content's length only, so logs never hold messages.
impl fmt::Debug for ArchivedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchivedMessage")
            .field("message_id", &self.message_id)
            .field("sender", &self.sender)
            .field("verified", &self.verified)
            .field("sent", &self.sent)
            .field("received", &self.received)
            .field("seq", &self.seq)
            .field("content_len", &self.content.len())
            .finish()
    }
}

/// An ArchivedConversation (12.13): a conversation's messages, oldest
/// first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedConversation {
    /// The MLS group id.
    pub group_id: Vec<u8>,
    /// The server that holds its mailbox.
    pub host: Domain,
    /// Its mailbox (5.2).
    pub mailbox: [u8; BOX_LEN],
    /// Its messages, oldest first.
    pub messages: Vec<ArchivedMessage>,
}

/// A HistoryArchive (12.13). Its encoding holds message content, so
/// [`HistoryArchive::encode`] gives it in memory that is wiped when
/// dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryArchive {
    /// The identity whose history this is.
    pub uid: Identity,
    /// When the archive was made, in ms since the epoch.
    pub made: u64,
    /// The conversations.
    pub conversations: Vec<ArchivedConversation>,
    /// Further archives of the same transfer.
    pub more: Vec<TransferRef>,
}

/// An archive encrypted as a file, ready to store as a blob (12.13).
#[derive(Debug)]
pub struct SealedArchive {
    /// The bytes to store as a blob.
    pub blob: Vec<u8>,
    /// The blob's hash and the key, to send as a TransferRef.
    pub transfer: TransferRef,
}

impl HistoryArchive {
    /// The encoded archive.
    ///
    /// # Panics
    ///
    /// If a vector would hold 2^30 bytes or more, which
    /// [`seal_transfer`] avoids by splitting.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::default();
        w.u8(ARCHIVE_VERSION);
        w.vector(self.uid.as_str().as_bytes());
        w.u64(self.made);
        w.nested(|w| {
            for conversation in &self.conversations {
                encode_conversation(w, conversation);
            }
        });
        w.nested(|w| {
            for transfer in &self.more {
                w.bytes(&transfer.to_bytes()[..]);
            }
        });
        w.0
    }

    /// Reads an encoded archive. Every field is checked: the version, the
    /// uids and hosts (in lower case, as they are sent), the verified flag
    /// and the seqs, and nothing may follow the end.
    pub fn decode(bytes: &[u8]) -> Result<HistoryArchive, ArchiveError> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != ARCHIVE_VERSION {
            return Err(ArchiveError::Version(version));
        }
        let uid = canonical::<Identity>(r.vector()?, "uid")?;
        let made = r.u64()?;
        let mut conversations = Vec::new();
        let mut list = Reader(r.vector()?);
        while !list.0.is_empty() {
            conversations.push(decode_conversation(&mut list)?);
        }
        let mut more = Vec::new();
        let mut list = Reader(r.vector()?);
        while !list.0.is_empty() {
            more.push(TransferRef::from_bytes(list.take(TRANSFER_REF_LEN)?)?);
        }
        r.end()?;
        Ok(HistoryArchive {
            uid,
            made,
            conversations,
            more,
        })
    }

    /// Encrypts the archive as a file under a new random key (12.13).
    pub fn seal(&self) -> Result<SealedArchive, getrandom::Error> {
        let encrypted = file::encrypt(&self.encode())?;
        Ok(SealedArchive {
            blob: encrypted.upload,
            transfer: TransferRef {
                blob: encrypted.hash,
                key: encrypted.key,
            },
        })
    }

    /// Opens the archive in `blob`, named by `transfer` (12.13): checks
    /// the blob's hash before anything else, decrypts it as a file, reads
    /// the archive, and checks that it is `uid`'s.
    pub fn open(
        transfer: &TransferRef,
        blob: &[u8],
        uid: &Identity,
    ) -> Result<HistoryArchive, ArchiveError> {
        let plain = file::decrypt(&transfer.key, &transfer.blob, blob)?;
        let archive = HistoryArchive::decode(&plain)?;
        if archive.uid != *uid {
            return Err(ArchiveError::OtherIdentity);
        }
        Ok(archive)
    }
}

/// Splits a transfer of `conversations` into archives whose blobs are at
/// most `max_blob` bytes, and seals them (12.13). The first archive in the
/// result is the one to name in a TransferRef: if everything fits in one,
/// it is the only one; otherwise it holds no conversations and names all
/// the others in `more`. A conversation too large for one archive is
/// spread over several, each with some of its messages in order.
pub fn seal_transfer(
    uid: &Identity,
    made: u64,
    conversations: Vec<ArchivedConversation>,
    max_blob: u64,
) -> Result<Vec<SealedArchive>, ArchiveError> {
    let archive = |conversations, more| HistoryArchive {
        uid: uid.clone(),
        made,
        conversations,
        more,
    };
    // Every vector of an archive is at most its encoding, which is at most
    // its blob, so capping blobs below 1 GiB keeps every vector encodable.
    let max_blob = max_blob.min(MAX_VECTOR_LEN as u64);
    let fits = |encoded_len: u64| file::encrypted_len(encoded_len).is_some_and(|l| l <= max_blob);

    // Sizes are measured against an upper bound of the encoded length that
    // counts every vector length as 4 bytes. Padmé only grows with the
    // length, so a bound that fits is a blob that fits.
    let header = 1 + VECTOR_BOUND + uid.as_str().len() as u64 + 8 + VECTOR_BOUND + VECTOR_BOUND;
    let whole_bound = conversations.iter().fold(header, |sum, c| {
        sum + opening_bound(c) + c.messages.iter().map(message_bound).sum::<u64>()
    });
    let whole = archive(conversations, Vec::new());
    if fits(whole_bound) {
        return Ok(vec![whole.seal()?]);
    }

    // Greedy packing, message by message.
    let mut parts: Vec<HistoryArchive> = Vec::new();
    let mut current = archive(Vec::new(), Vec::new());
    let mut bound = header;
    for conversation in whole.conversations {
        let opening = opening_bound(&conversation);
        let empty = ArchivedConversation {
            messages: Vec::new(),
            ..conversation
        };
        for message in conversation.messages {
            let size = message_bound(&message);
            let continues = current
                .conversations
                .last()
                .is_some_and(|c| c.group_id == empty.group_id && c.mailbox == empty.mailbox);
            let added = size + if continues { 0 } else { opening };
            if !fits(bound + added) {
                if current.conversations.is_empty() {
                    return Err(ArchiveError::TooLarge);
                }
                parts.push(std::mem::replace(
                    &mut current,
                    archive(Vec::new(), Vec::new()),
                ));
                bound = header + opening + size;
                if !fits(bound) {
                    return Err(ArchiveError::TooLarge);
                }
            } else {
                bound += added;
            }
            push_message(&mut current, &empty, message);
        }
    }
    if !current.conversations.is_empty() {
        parts.push(current);
    }

    let mut sealed = Vec::with_capacity(parts.len() + 1);
    for part in &parts {
        sealed.push(part.seal()?);
    }
    let head = archive(
        Vec::new(),
        sealed.iter().map(|s| s.transfer.clone()).collect(),
    );
    sealed.insert(0, head.seal()?);
    Ok(sealed)
}

/// The most bytes a vector's length takes [RFC9420, 2.1.2].
const VECTOR_BOUND: u64 = 4;

/// An upper bound of a conversation's encoding without its messages.
fn opening_bound(c: &ArchivedConversation) -> u64 {
    VECTOR_BOUND * 3 + c.group_id.len() as u64 + c.host.as_str().len() as u64 + BOX_LEN as u64
}

/// An upper bound of a message's encoding.
fn message_bound(m: &ArchivedMessage) -> u64 {
    MESSAGE_ID_LEN as u64
        + VECTOR_BOUND * 2
        + m.sender.as_str().len() as u64
        + 1
        + 24
        + m.content.len() as u64
}

/// Adds `message` to `archive`, in the conversation like `empty`: the last
/// one if it is the same, or a new one.
fn push_message(
    archive: &mut HistoryArchive,
    empty: &ArchivedConversation,
    message: ArchivedMessage,
) {
    match archive.conversations.last_mut() {
        Some(last) if last.group_id == empty.group_id && last.mailbox == empty.mailbox => {
            last.messages.push(message);
        }
        _ => {
            let mut conversation = empty.clone();
            conversation.messages.push(message);
            archive.conversations.push(conversation);
        }
    }
}

fn encode_conversation(w: &mut Writer, conversation: &ArchivedConversation) {
    w.vector(&conversation.group_id);
    w.vector(conversation.host.as_str().as_bytes());
    w.bytes(&conversation.mailbox);
    w.nested(|w| {
        for message in &conversation.messages {
            w.bytes(&message.message_id);
            w.vector(message.sender.as_str().as_bytes());
            w.u8(u8::from(message.verified));
            w.u64(message.sent);
            w.u64(message.received);
            w.u64(message.seq);
            w.vector(&message.content);
        }
    });
}

fn decode_conversation(r: &mut Reader<'_>) -> Result<ArchivedConversation, ArchiveError> {
    let group_id = r.vector()?.to_vec();
    let host = canonical::<Domain>(r.vector()?, "host")?;
    let mailbox = r.array::<BOX_LEN>()?;
    let mut messages = Vec::new();
    let mut list = Reader(r.vector()?);
    while !list.0.is_empty() {
        let message_id = list.array::<MESSAGE_ID_LEN>()?;
        let sender = canonical::<Uid>(list.vector()?, "sender")?;
        let verified = match list.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ArchiveError::Malformed("verified")),
        };
        let sent = list.u64()?;
        let received = list.u64()?;
        let seq = list.u64()?;
        if !(1..=MAX_SEQ).contains(&seq) {
            return Err(ArchiveError::Malformed("seq"));
        }
        let content = list.vector()?.to_vec();
        messages.push(ArchivedMessage {
            message_id,
            sender,
            verified,
            sent,
            received,
            seq,
            content,
        });
    }
    Ok(ArchivedConversation {
        group_id,
        host,
        mailbox,
        messages,
    })
}

/// A name in the exact form it is sent in: UTF-8 that parses, and is
/// already in lower case, so each name has one encoding.
fn canonical<T: FromStr + AsRef<str>>(bytes: &[u8], what: &'static str) -> Result<T, ArchiveError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ArchiveError::Malformed(what))?;
    let value: T = text.parse().map_err(|_| ArchiveError::Malformed(what))?;
    if value.as_ref() != text {
        return Err(ArchiveError::Malformed(what));
    }
    Ok(value)
}

/// The largest length of a variable-size vector [RFC9420, 2.1.2]: 2^30 - 1.
const MAX_VECTOR_LEN: usize = (1 << 30) - 1;

/// Writes the TLS presentation language, with MLS's variable-size
/// vectors, into memory that is wiped when dropped.
#[derive(Default)]
pub(crate) struct Writer(pub(crate) Zeroizing<Vec<u8>>);

impl Writer {
    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    /// Fixed-length bytes, with no length.
    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    /// A variable-size vector of bytes: its length, then the bytes.
    pub(crate) fn vector(&mut self, v: &[u8]) {
        self.length(v.len());
        self.0.extend_from_slice(v);
    }

    /// A variable-size vector whose contents `f` writes.
    pub(crate) fn nested(&mut self, f: impl FnOnce(&mut Writer)) {
        let mut inner = Writer::default();
        f(&mut inner);
        self.vector(&inner.0);
    }

    /// A length in the fewest bytes [RFC9420, 2.1.2].
    fn length(&mut self, len: usize) {
        assert!(len <= MAX_VECTOR_LEN, "a vector holds less than 1 GiB");
        if len < 1 << 6 {
            self.0.push(len as u8);
        } else if len < 1 << 14 {
            self.0
                .extend_from_slice(&(0x4000 | len as u16).to_be_bytes());
        } else {
            self.0
                .extend_from_slice(&(0x8000_0000 | len as u32).to_be_bytes());
        }
    }
}

/// Reads what [`Writer`] writes. Lengths must use the fewest bytes, as
/// [RFC9420, 2.1.2] requires, and the prefix `11` is rejected.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ArchiveError> {
        if self.0.len() < n {
            return Err(ArchiveError::Malformed("truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ArchiveError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ArchiveError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ArchiveError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ArchiveError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A variable-size vector's contents.
    pub(crate) fn vector(&mut self) -> Result<&'a [u8], ArchiveError> {
        let first = self.u8()?;
        let len = match first >> 6 {
            0 => usize::from(first),
            1 => {
                let len = usize::from(u16::from_be_bytes([first, self.u8()?]) & 0x3fff);
                if len < 1 << 6 {
                    return Err(ArchiveError::Malformed("vector length"));
                }
                len
            }
            2 => {
                let rest: [u8; 3] = self.array()?;
                let len = u32::from_be_bytes([first, rest[0], rest[1], rest[2]]) & 0x3fff_ffff;
                if len < 1 << 14 {
                    return Err(ArchiveError::Malformed("vector length"));
                }
                len as usize
            }
            _ => return Err(ArchiveError::Malformed("vector length")),
        };
        self.take(len)
    }

    /// Checks that nothing is left.
    pub(crate) fn end(&self) -> Result<(), ArchiveError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ArchiveError::Malformed("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Identity {
        "alice@example.org".parse().unwrap()
    }

    fn message(seq: u64, content: &str) -> ArchivedMessage {
        ArchivedMessage {
            message_id: [seq as u8; 16],
            sender: "bob@example.net".parse().unwrap(),
            verified: seq.is_multiple_of(2),
            sent: 1_762_560_000_000 + seq,
            received: 1_762_560_000_100 + seq,
            seq,
            content: content.as_bytes().to_vec(),
        }
    }

    fn conversation(group: u8, messages: Vec<ArchivedMessage>) -> ArchivedConversation {
        ArchivedConversation {
            group_id: vec![group; 32],
            host: "example.org".parse().unwrap(),
            mailbox: [group; 16],
            messages,
        }
    }

    fn sample() -> HistoryArchive {
        HistoryArchive {
            uid: alice(),
            made: 1_762_600_000_000,
            conversations: vec![
                conversation(1, vec![message(1, "TEXT hi"), message(2, "TEXT there")]),
                conversation(2, vec![]),
            ],
            more: vec![TransferRef {
                blob: BlobRef::of(b"next"),
                key: FileKey::from_bytes([5; 32]),
            }],
        }
    }

    #[test]
    fn encode_round_trip() {
        let archive = sample();
        let bytes = archive.encode();
        assert_eq!(HistoryArchive::decode(&bytes), Ok(archive.clone()));
        // A guest sender, and long vectors in each length form.
        let mut archive = archive;
        archive.conversations[0].messages[0].sender = "~sam".parse().unwrap();
        for len in [0, 63, 64, 16383, 16384, 70000] {
            archive.conversations[0].messages[1].content = vec![b'x'; len];
            let bytes = archive.encode();
            assert_eq!(HistoryArchive::decode(&bytes), Ok(archive.clone()));
        }
    }

    #[test]
    fn decode_rejections() {
        let bytes = sample().encode().to_vec();
        let malformed =
            |b: &[u8]| matches!(HistoryArchive::decode(b), Err(ArchiveError::Malformed(_)));

        // Every truncation, and a byte too many.
        for n in 0..bytes.len() {
            assert!(HistoryArchive::decode(&bytes[..n]).is_err(), "cut at {n}");
        }
        assert!(malformed(&[&bytes[..], &[0]].concat()));
        // Another version.
        let mut b = bytes.clone();
        b[0] = 2;
        assert_eq!(HistoryArchive::decode(&b), Err(ArchiveError::Version(2)));
        b[0] = 0;
        assert_eq!(HistoryArchive::decode(&b), Err(ArchiveError::Version(0)));
        // The uid in upper case, or not an identity.
        let mut b = bytes.clone();
        b[2] = b'A';
        assert!(malformed(&b));
        let at = bytes.iter().position(|&c| c == b'@').unwrap();
        let mut b = bytes.clone();
        b[at] = b'.';
        assert!(malformed(&b));

        // Field by field, from a minimal archive with one message.
        let one = HistoryArchive {
            uid: alice(),
            made: 7,
            conversations: vec![conversation(1, vec![message(1, "x")])],
            more: vec![],
        };
        let b = one.encode().to_vec();
        // version 1, uid (1 + 17), made 8, then the conversations' length.
        // (The conversation is 121 bytes, so its length takes 2.)
        let conv = 1 + 18 + 8 + 2;
        // group_id (1 + 32), host (1 + 11), box 16, messages' length 1.
        let msg = conv + 33 + 12 + 16 + 1;
        let verified = msg + 16 + 1 + 15;
        let seq = verified + 1 + 16;
        assert_eq!(b[verified], 0);
        assert_eq!(&b[seq..seq + 8], &1u64.to_be_bytes());
        let mut bad = b.clone();
        bad[verified] = 2;
        assert_eq!(
            HistoryArchive::decode(&bad),
            Err(ArchiveError::Malformed("verified"))
        );
        bad[verified] = 1;
        assert!(HistoryArchive::decode(&bad).unwrap().conversations[0].messages[0].verified);
        let mut bad = b.clone();
        bad[seq..seq + 8].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            HistoryArchive::decode(&bad),
            Err(ArchiveError::Malformed("seq"))
        );
        bad[seq..seq + 8].copy_from_slice(&(1u64 << 63).to_be_bytes());
        assert_eq!(
            HistoryArchive::decode(&bad),
            Err(ArchiveError::Malformed("seq"))
        );
        bad[seq..seq + 8].copy_from_slice(&MAX_SEQ.to_be_bytes());
        assert!(HistoryArchive::decode(&bad).is_ok());
        // An upper-case host or sender.
        let mut bad = b.clone();
        bad[conv + 34] = b'E';
        assert_eq!(
            HistoryArchive::decode(&bad),
            Err(ArchiveError::Malformed("host"))
        );
        let mut bad = b.clone();
        bad[msg + 17] = b'B';
        assert_eq!(
            HistoryArchive::decode(&bad),
            Err(ArchiveError::Malformed("sender"))
        );
        // A `more` entry that is not 80 bytes.
        let mut bad = b.clone();
        *bad.last_mut().unwrap() = 1;
        bad.push(0);
        assert!(malformed(&bad));
    }

    #[test]
    fn vector_lengths() {
        let read = |b: &[u8]| Reader(b).vector().map(<[u8]>::len);
        assert_eq!(read(&[0]), Ok(0));
        assert_eq!(read(&[0x3f; 64]), Ok(63));
        // Not the fewest bytes.
        assert!(read(&[0x40, 0x01, 0]).is_err());
        assert!(read(&[0x80, 0, 0x01, 0, 0]).is_err());
        assert!(read(&[0x80, 0, 0x3f, 0xff]).is_err());
        // The prefix 11.
        assert!(read(&[0xc0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // Longer than what follows.
        assert!(read(&[0x05, 1, 2]).is_err());
        let mut w = Writer::default();
        w.vector(&[1; 64]);
        assert_eq!(&w.0[..2], &[0x40, 64]);
        let mut w = Writer::default();
        w.vector(&[1; 16384]);
        assert_eq!(&w.0[..4], &[0x80, 0, 0x40, 0]);
    }

    #[test]
    fn transfer_refs() {
        let t = sample().more[0].clone();
        let bytes = t.to_bytes();
        assert_eq!(&bytes[..48], t.blob.as_bytes());
        assert_eq!(&bytes[48..], &[5; 32]);
        assert_eq!(TransferRef::from_bytes(&bytes[..]), Ok(t.clone()));
        assert!(TransferRef::from_bytes(&bytes[..79]).is_err());
        assert!(TransferRef::from_bytes(&[0; 81]).is_err());
        let text = t.to_base64();
        assert_eq!(text.len(), 108);
        assert_eq!(TransferRef::from_base64(&text), Some(t));
        assert_eq!(TransferRef::from_base64(&text[..104]), None);
        assert_eq!(TransferRef::from_base64(""), None);
    }

    #[test]
    fn seal_and_open() {
        let archive = sample();
        let sealed = archive.seal().unwrap();
        assert_eq!(sealed.transfer.blob, BlobRef::of(&sealed.blob));
        assert_eq!(
            HistoryArchive::open(&sealed.transfer, &sealed.blob, &alice()),
            Ok(archive)
        );
        // Another identity's archive.
        let bob: Identity = "bob@example.net".parse().unwrap();
        assert_eq!(
            HistoryArchive::open(&sealed.transfer, &sealed.blob, &bob),
            Err(ArchiveError::OtherIdentity)
        );
        // A changed blob fails the hash, and another key fails to decrypt.
        let mut blob = sealed.blob.clone();
        blob[3] ^= 1;
        assert_eq!(
            HistoryArchive::open(&sealed.transfer, &blob, &alice()),
            Err(ArchiveError::File(FileError::Hash))
        );
        let wrong = TransferRef {
            key: FileKey::from_bytes([1; 32]),
            ..sealed.transfer.clone()
        };
        assert_eq!(
            HistoryArchive::open(&wrong, &sealed.blob, &alice()),
            Err(ArchiveError::File(FileError::Chunk(0)))
        );
        // A blob that decrypts but is not an archive.
        let not = file::encrypt(b"not an archive").unwrap();
        let t = TransferRef {
            blob: not.hash,
            key: not.key,
        };
        assert!(matches!(
            HistoryArchive::open(&t, &not.upload, &alice()),
            Err(ArchiveError::Version(_) | ArchiveError::Malformed(_))
        ));
    }

    #[test]
    fn split_transfers() {
        let conversations = vec![
            conversation(1, (1..=40).map(|i| message(i, &"a".repeat(100))).collect()),
            conversation(2, (1..=40).map(|i| message(i, &"b".repeat(100))).collect()),
        ];
        // Everything fits: one archive.
        let one = seal_transfer(&alice(), 9, conversations.clone(), 1 << 20).unwrap();
        assert_eq!(one.len(), 1);
        let head = HistoryArchive::open(&one[0].transfer, &one[0].blob, &alice()).unwrap();
        assert_eq!(head.conversations, conversations);
        assert!(head.more.is_empty());

        // Split into blobs of at most 2 KiB.
        let max = 2048;
        let parts = seal_transfer(&alice(), 9, conversations.clone(), max).unwrap();
        assert!(parts.len() > 3);
        assert!(parts.iter().all(|p| p.blob.len() as u64 <= max));
        let head = HistoryArchive::open(&parts[0].transfer, &parts[0].blob, &alice()).unwrap();
        assert!(head.conversations.is_empty());
        assert_eq!(head.more.len(), parts.len() - 1);
        // Joining the parts gives back every message, in order.
        let mut joined: Vec<ArchivedConversation> = Vec::new();
        for (t, part) in head.more.iter().zip(&parts[1..]) {
            assert_eq!(t, &part.transfer);
            let archive = HistoryArchive::open(t, &part.blob, &alice()).unwrap();
            assert!(archive.more.is_empty());
            for c in archive.conversations {
                match joined.last_mut() {
                    Some(last) if last.group_id == c.group_id => last.messages.extend(c.messages),
                    _ => joined.push(c),
                }
            }
        }
        assert_eq!(joined, conversations);

        // A message larger than a blob.
        let huge = vec![conversation(1, vec![message(1, &"x".repeat(5000))])];
        assert_eq!(
            seal_transfer(&alice(), 9, huge, max).unwrap_err(),
            ArchiveError::TooLarge
        );
    }

    /// A fixed-input vector for Appendix B: [`sample`]'s encoding.
    #[test]
    fn vector() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let bytes = sample().encode();
        println!("HistoryArchive {}", hex(&bytes));
        assert_eq!(hex(&bytes), ARCHIVE_VECTOR);
    }

    const ARCHIVE_VECTOR: &str = "0111616c696365406578616d706c652e6f72670000019a63259a004102200101\
     0101010101010101010101010101010101010101010101010101010101010b65\
     78616d706c652e6f726701010101010101010101010101010101408501010101\
     0101010101010101010101010f626f62406578616d706c652e6e657400000001\
     9a60c340010000019a60c3406500000000000000010754455854206869020202\
     020202020202020202020202020f626f62406578616d706c652e6e6574010000\
     019a60c340020000019a60c3406600000000000000020a544558542074686572\
     6520020202020202020202020202020202020202020202020202020202020202\
     02020b6578616d706c652e6f7267020202020202020202020202020202020040\
     50e1c9f3884f4b23c88e2991de91e518c8d35a4a9b6d14dbc872904281bde844\
     1fe4c0518d85b7904c8b7f38449e40a166050505050505050505050505050505\
     0505050505050505050505050505050505";
}

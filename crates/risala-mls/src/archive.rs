//! History archives and transfer refs (12.13).
//!
//! A [`HistoryArchive`] carries an identity's history of some
//! conversations from one of its devices to another: at pairing, to catch
//! up a device that has a gap, or as a backup ([`crate::backup`]). It is
//! encrypted as a file (12.11) with the label `risala/1 archive` under a
//! new random key and stored as a blob (12.12). A [`TransferRef`] names the
//! blob and holds the key: the IdentityBundle carries one (4.8), and so
//! does a `TRANSFER` line in the conversation with yourself (12.13). Files
//! travel beside the archive, each encrypted again as a file of its own
//! and listed in `files` ([`ArchivedFile`]).
//!
//! History too large for one blob is split over several archives
//! ([`seal_transfer`]): the **first** names all the others in `more`, and
//! they have an empty `more` and the first's `uid` and `made`. A device
//! reads them with [`open_transfer`], which joins the pieces of each
//! conversation in order.
//!
//! The structures are in the TLS presentation language, with MLS's
//! variable-size vectors [RFC9420, 2.1.2]:
//!
//! ```text
//! struct {
//!     opaque message_id[16]; opaque sender<V>; opaque device_id<V>;
//!     uint64 counter; opaque previous<V>; uint8 verified;
//!     uint64 sent; uint64 received; uint64 seq; opaque content<V>;
//! } ArchivedMessage;
//! struct {
//!     opaque group_id<V>; opaque host<V>; opaque box[16];
//!     ArchivedMessage messages<V>;
//! } ArchivedConversation;
//! struct { opaque file_hash[48]; opaque blob_hash[48]; opaque key[32]; } ArchivedFile;
//! struct { uint8 version; opaque blob_hash[48]; opaque key[32]; } TransferRef;
//! struct {
//!     uint8 version; opaque uid<V>; uint64 made;
//!     ArchivedConversation conversations<V>; ArchivedFile files<V>;
//!     TransferRef more<V>;
//! } HistoryArchive;
//! ```
//!
//! What a device then applies (only groups it is in, only ranges it asked
//! for with WANT, never replacing a message it holds, shown as copied from
//! the sending device) is the client's to decide, not this module's.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::names::{Identity, ServerAddr, Uid};
use zeroize::Zeroizing;

use crate::file::{self, BlobRef, FILE_KEY_LEN, FileError, FileKey, Label};
use crate::identity::DeviceId;
use crate::primitives::HASH_LEN;

/// The version of a HistoryArchive and of a TransferRef (12.13).
pub const ARCHIVE_VERSION: u8 = 1;

/// The length of an encoded TransferRef (12.13): version, hash and key.
pub const TRANSFER_REF_LEN: usize = 1 + HASH_LEN + FILE_KEY_LEN;

/// The length of an encoded ArchivedFile (12.13): two hashes and a key.
pub const ARCHIVED_FILE_LEN: usize = 2 * HASH_LEN + FILE_KEY_LEN;

/// The length of a message id (12.9).
pub const MESSAGE_ID_LEN: usize = 16;

/// The length of a device id (4.4): SHA-384 of the device key.
pub const DEVICE_ID_LEN: usize = HASH_LEN;

/// The length of a RisalaMessage's `previous` when it is not empty (12.9).
pub const PREVIOUS_LEN: usize = 16;

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
    /// The archive or TransferRef names a version this device does not
    /// support (2.4).
    #[error("unsupported archive version {0}")]
    Version(u8),
    /// The archive is another identity's.
    #[error("the archive is for another identity")]
    OtherIdentity,
    /// The blob does not match its hash, or does not decrypt as an
    /// archive.
    #[error(transparent)]
    File(#[from] FileError),
    /// The first archive of a transfer could not be fetched.
    #[error("the transfer's first archive could not be fetched")]
    Missing,
    /// Another archive of a transfer has a non-empty `more`, or another
    /// `uid` or `made` than the first, so the whole transfer is rejected.
    #[error("the transfer's archives do not belong together")]
    Split,
    /// One message alone, or the list of archives, is larger than a blob
    /// may be, so the transfer cannot be split.
    #[error("a message is too large for one archive")]
    TooLarge,
    /// The operating system gave no randomness for a key.
    #[error("no randomness: {0}")]
    Random(#[from] getrandom::Error),
}

/// A TransferRef (12.13): the hash of a blob that holds an encrypted
/// HistoryArchive, and the key it is encrypted under. Its `version` is
/// always 1 here: one of another version does not decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferRef {
    /// The blob's hash, its blob-ref (12.12).
    pub blob: BlobRef,
    /// The archive's file key (12.11).
    pub key: FileKey,
}

impl TransferRef {
    /// The encoded TransferRef: the version, the hash, then the key. 81
    /// bytes, wiped when dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; TRANSFER_REF_LEN]> {
        let mut out = Zeroizing::new([0; TRANSFER_REF_LEN]);
        out[0] = ARCHIVE_VERSION;
        out[1..1 + HASH_LEN].copy_from_slice(self.blob.as_bytes());
        out[1 + HASH_LEN..].copy_from_slice(self.key.as_bytes());
        out
    }

    /// Reads an encoded TransferRef: exactly 81 bytes, of version 1.
    pub fn from_bytes(bytes: &[u8]) -> Result<TransferRef, ArchiveError> {
        if bytes.len() != TRANSFER_REF_LEN {
            return Err(ArchiveError::Malformed("TransferRef"));
        }
        if bytes[0] != ARCHIVE_VERSION {
            return Err(ArchiveError::Version(bytes[0]));
        }
        Ok(TransferRef {
            blob: BlobRef::from_bytes(bytes[1..1 + HASH_LEN].try_into().expect("48 bytes")),
            key: FileKey::from_bytes(bytes[1 + HASH_LEN..].try_into().expect("32 bytes")),
        })
    }

    /// The `<ref>` of a TRANSFER line (12.13): the TransferRef in base64
    /// with padding, 108 characters.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(&self.to_bytes()[..]))
    }

    /// Reads the `<ref>` of a TRANSFER line: exactly 81 bytes in canonical
    /// base64 with padding, of version 1.
    pub fn from_base64(text: &str) -> Option<TransferRef> {
        let mut bytes = Zeroizing::new([0; TRANSFER_REF_LEN]);
        file::decode_base64_exact(text, &mut bytes[..])?;
        TransferRef::from_bytes(&bytes[..]).ok()
    }
}

/// An ArchivedMessage (12.13): one message as the archiving device
/// received it.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchivedMessage {
    /// The message's id (12.9).
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// Who sent it.
    pub sender: Uid,
    /// The sender's device id (4.4), or `None` for a guest, which has no
    /// device ids. Decoding holds it to the sender: 48 bytes for an
    /// identity, empty for a guest.
    pub device_id: Option<DeviceId>,
    /// The RisalaMessage's counter (12.9).
    pub counter: u64,
    /// The RisalaMessage's `previous` (12.9), if it had one.
    pub previous: Option<[u8; PREVIOUS_LEN]>,
    /// Whether the archiving device had confirmed the sender's leaf
    /// (12.10).
    pub verified: bool,
    /// The sender's time, in ms since the epoch.
    pub sent: u64,
    /// The server's time, in ms since the epoch.
    pub received: u64,
    /// The post's seq (5.2), from 1 to 2^63 - 1.
    pub seq: u64,
    /// The content lines, as received (12.9). Deletes, edits and reactions
    /// are messages of their own (12.13).
    pub content: Vec<u8>,
}

/// `Debug` shows the content's length only, so logs never hold messages.
impl fmt::Debug for ArchivedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchivedMessage")
            .field("message_id", &self.message_id)
            .field("sender", &self.sender)
            .field("counter", &self.counter)
            .field("verified", &self.verified)
            .field("sent", &self.sent)
            .field("received", &self.received)
            .field("seq", &self.seq)
            .field("content_len", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// An ArchivedConversation (12.13): a conversation's messages, oldest
/// first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedConversation {
    /// The MLS group id.
    pub group_id: Vec<u8>,
    /// The server that holds its mailbox, as a server address in its one
    /// written form (3.5), which may carry a port.
    pub host: ServerAddr,
    /// Its mailbox (5.2).
    pub mailbox: [u8; BOX_LEN],
    /// Its messages, in seq order, oldest first.
    pub messages: Vec<ArchivedMessage>,
}

impl ArchivedConversation {
    /// Whether `other` is the same conversation: the same group, server
    /// and mailbox (12.13).
    fn same(&self, other: &ArchivedConversation) -> bool {
        self.group_id == other.group_id && self.host == other.host && self.mailbox == other.mailbox
    }
}

/// An ArchivedFile (12.13): a file that travels with history, encrypted
/// again as a file of its own (12.11, label `risala/1 file`) and stored as
/// a blob. A TEXT line whose `file-hash` is `file_hash` is read from this
/// blob instead of its `file` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedFile {
    /// The `file-hash` of the original upload (12.9).
    pub file_hash: BlobRef,
    /// The blob that holds the file now.
    pub blob: BlobRef,
    /// That blob's file key.
    pub key: FileKey,
}

impl ArchivedFile {
    /// Encrypts `file`, a file that was downloaded and checked under
    /// `file_hash`, again under a new key (12.13). Gives the blob to store
    /// and its entry for `files`. A device SHOULD keep the entry and reuse
    /// the blob in later backups, rather than call this again.
    pub fn encrypt(
        file_hash: BlobRef,
        file: &[u8],
    ) -> Result<(Vec<u8>, ArchivedFile), getrandom::Error> {
        let encrypted = file::encrypt(Label::File, file)?;
        Ok((
            encrypted.upload,
            ArchivedFile {
                file_hash,
                blob: encrypted.hash,
                key: encrypted.key,
            },
        ))
    }

    /// Checks the blob against `blob_hash` and decrypts it as a file
    /// (12.11, 12.13).
    pub fn decrypt(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, FileError> {
        file::decrypt(&self.key, Label::File, &self.blob, blob)
    }

    fn encode(&self, w: &mut Writer) {
        w.bytes(self.file_hash.as_bytes());
        w.bytes(self.blob.as_bytes());
        w.bytes(self.key.as_bytes());
    }

    fn decode(r: &mut Reader<'_>) -> Result<ArchivedFile, ArchiveError> {
        Ok(ArchivedFile {
            file_hash: BlobRef::from_bytes(r.array()?),
            blob: BlobRef::from_bytes(r.array()?),
            key: FileKey::from_bytes(r.array()?),
        })
    }
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
    /// The files that travel with them.
    pub files: Vec<ArchivedFile>,
    /// The other archives of the same transfer or backup: only in the
    /// first.
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
            for file in &self.files {
                file.encode(w);
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
    /// uids and hosts (in lower case, as they are sent), the device ids
    /// against their senders, `previous`, the verified flag, the seqs, the
    /// TransferRefs' versions, and nothing may follow the end. The order of
    /// seqs is checked when archives are joined ([`open_transfer`]).
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
        let mut files = Vec::new();
        let mut list = Reader(r.vector()?);
        while !list.0.is_empty() {
            files.push(ArchivedFile::decode(&mut list)?);
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
            files,
            more,
        })
    }

    /// Encrypts the archive as a file with the label `risala/1 archive`,
    /// under a new random key (12.13).
    pub fn seal(&self) -> Result<SealedArchive, getrandom::Error> {
        let encrypted = file::encrypt(Label::Archive, &self.encode())?;
        Ok(SealedArchive {
            blob: encrypted.upload,
            transfer: TransferRef {
                blob: encrypted.hash,
                key: encrypted.key,
            },
        })
    }

    /// Opens the archive in `blob`, named by `transfer` (12.13): checks
    /// the blob's hash before anything else, decrypts it as an archive,
    /// reads it, and checks that it is `uid`'s.
    pub fn open(
        transfer: &TransferRef,
        blob: &[u8],
        uid: &Identity,
    ) -> Result<HistoryArchive, ArchiveError> {
        let plain = file::decrypt(&transfer.key, Label::Archive, &transfer.blob, blob)?;
        let archive = HistoryArchive::decode(&plain)?;
        if archive.uid != *uid {
            return Err(ArchiveError::OtherIdentity);
        }
        Ok(archive)
    }
}

/// Splits a transfer of `conversations` and `files` into archives whose
/// blobs are at most `max_blob` bytes, and seals them (12.13). The first
/// archive in the result is the one to name in a TransferRef: if
/// everything fits in one, it is the only one; otherwise it holds no
/// conversations or files and names all the others in `more`, which have
/// an empty `more` and the same `uid` and `made`. A conversation too large
/// for one archive is spread over several, each with some of its messages
/// in order.
pub fn seal_transfer(
    uid: &Identity,
    made: u64,
    conversations: Vec<ArchivedConversation>,
    files: Vec<ArchivedFile>,
    max_blob: u64,
) -> Result<Vec<SealedArchive>, ArchiveError> {
    let archive = |conversations, files, more| HistoryArchive {
        uid: uid.clone(),
        made,
        conversations,
        files,
        more,
    };
    // Every vector of an archive is at most its encoding, which is at most
    // its blob, so capping blobs below 1 GiB keeps every vector encodable.
    let max_blob = max_blob.min(MAX_VECTOR_LEN as u64);
    let fits = |encoded_len: u64| file::encrypted_len(encoded_len).is_some_and(|l| l <= max_blob);

    // Sizes are measured against an upper bound of the encoded length that
    // counts every vector length as 4 bytes. Padmé only grows with the
    // length, so a bound that fits is a blob that fits.
    let header = 1 + VECTOR_BOUND + uid.as_str().len() as u64 + 8 + 3 * VECTOR_BOUND;
    let whole_bound = conversations.iter().fold(header, |sum, c| {
        sum + opening_bound(c) + c.messages.iter().map(message_bound).sum::<u64>()
    }) + files.len() as u64 * ARCHIVED_FILE_LEN as u64;
    if fits(whole_bound) {
        return Ok(vec![archive(conversations, files, Vec::new()).seal()?]);
    }

    // Greedy packing, message by message, then file by file.
    let mut parts: Vec<HistoryArchive> = Vec::new();
    let mut current = archive(Vec::new(), Vec::new(), Vec::new());
    let mut bound = header;
    let mut place = |current: &mut HistoryArchive, bound: &mut u64, added: u64, alone: u64| {
        if fits(*bound + added) {
            *bound += added;
            return Ok(());
        }
        if current.conversations.is_empty() && current.files.is_empty() {
            return Err(ArchiveError::TooLarge);
        }
        parts.push(std::mem::replace(
            current,
            archive(Vec::new(), Vec::new(), Vec::new()),
        ));
        *bound = header + alone;
        if fits(*bound) {
            Ok(())
        } else {
            Err(ArchiveError::TooLarge)
        }
    };
    for conversation in conversations {
        let opening = opening_bound(&conversation);
        let empty = ArchivedConversation {
            messages: Vec::new(),
            ..conversation
        };
        for message in conversation.messages {
            let size = message_bound(&message);
            let continues = current.conversations.last().is_some_and(|c| c.same(&empty));
            let added = size + if continues { 0 } else { opening };
            place(&mut current, &mut bound, added, opening + size)?;
            push_message(&mut current, &empty, message);
        }
    }
    for archived in files {
        let size = ARCHIVED_FILE_LEN as u64;
        place(&mut current, &mut bound, size, size)?;
        current.files.push(archived);
    }
    if !current.conversations.is_empty() || !current.files.is_empty() {
        parts.push(current);
    }

    let more_bound = header + parts.len() as u64 * TRANSFER_REF_LEN as u64;
    if !fits(more_bound) {
        return Err(ArchiveError::TooLarge);
    }
    let mut sealed = Vec::with_capacity(parts.len() + 1);
    for part in &parts {
        sealed.push(part.seal()?);
    }
    let head = archive(
        Vec::new(),
        Vec::new(),
        sealed.iter().map(|s| s.transfer.clone()).collect(),
    );
    sealed.insert(0, head.seal()?);
    Ok(sealed)
}

/// A transfer or backup, opened and joined (12.13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedTransfer {
    /// When the archives were made, from the first: a restoring device
    /// shows it (12.13).
    pub made: u64,
    /// The conversations, each joined from its pieces in archive order.
    /// Conversations whose messages were then not in strictly increasing
    /// seq order are left out, and counted in `ignored`.
    pub conversations: Vec<ArchivedConversation>,
    /// The files of every archive, in order.
    pub files: Vec<ArchivedFile>,
    /// How many archives of `more` could not be fetched or opened. If it
    /// is not 0, the device tells the user that part of the history is
    /// missing.
    pub missing: usize,
    /// How many conversations were left out for their seq order.
    pub ignored: usize,
}

/// Opens a transfer or backup whose first archive is `first` (12.13):
/// fetches and opens the first archive, then the others in the order of
/// its `more`, and joins the ArchivedConversations with the same
/// `group_id`, `host` and `box` by appending their messages in that order.
///
/// `fetch` gives a blob's bytes, or `None` if it cannot be fetched; the
/// hash is checked here. The first archive must open. An archive of `more`
/// that cannot be fetched or opened is counted in `missing` and skipped.
/// One that opens but has a non-empty `more`, or another `uid` or `made`
/// than the first, rejects the whole transfer ([`ArchiveError::Split`]):
/// only the device that made the transfer can produce one, so it is
/// broken or hostile.
pub fn open_transfer(
    first: &TransferRef,
    uid: &Identity,
    mut fetch: impl FnMut(&BlobRef) -> Option<Vec<u8>>,
) -> Result<OpenedTransfer, ArchiveError> {
    let blob = fetch(&first.blob).ok_or(ArchiveError::Missing)?;
    let head = HistoryArchive::open(first, &blob, uid)?;
    let mut conversations: Vec<ArchivedConversation> = Vec::new();
    let mut files = Vec::new();
    let mut missing = 0;
    let mut join = |archive: HistoryArchive, files: &mut Vec<ArchivedFile>| {
        for conversation in archive.conversations {
            match conversations.iter_mut().find(|c| c.same(&conversation)) {
                Some(held) => held.messages.extend(conversation.messages),
                None => conversations.push(conversation),
            }
        }
        files.extend(archive.files);
    };
    let more = head.more.clone();
    let made = head.made;
    join(
        HistoryArchive {
            more: Vec::new(),
            ..head
        },
        &mut files,
    );
    for transfer in &more {
        let opened = fetch(&transfer.blob)
            .ok_or(ArchiveError::Missing)
            .and_then(|blob| HistoryArchive::open(transfer, &blob, uid));
        let archive = match opened {
            Ok(archive) => archive,
            // Another identity's archive cannot be in this transfer.
            Err(ArchiveError::OtherIdentity) => return Err(ArchiveError::Split),
            Err(_) => {
                missing += 1;
                continue;
            }
        };
        if !archive.more.is_empty() || archive.made != made {
            return Err(ArchiveError::Split);
        }
        join(archive, &mut files);
    }
    let before = conversations.len();
    conversations.retain(|c| c.messages.windows(2).all(|w| w[0].seq < w[1].seq));
    Ok(OpenedTransfer {
        made,
        ignored: before - conversations.len(),
        conversations,
        files,
        missing,
    })
}

/// The most bytes a vector's length takes [RFC9420, 2.1.2].
const VECTOR_BOUND: u64 = 4;

/// An upper bound of a conversation's encoding without its messages.
fn opening_bound(c: &ArchivedConversation) -> u64 {
    VECTOR_BOUND * 3 + c.group_id.len() as u64 + c.host.to_string().len() as u64 + BOX_LEN as u64
}

/// An upper bound of a message's encoding.
fn message_bound(m: &ArchivedMessage) -> u64 {
    MESSAGE_ID_LEN as u64
        + VECTOR_BOUND * 4
        + m.sender.as_str().len() as u64
        + DEVICE_ID_LEN as u64
        + 8
        + PREVIOUS_LEN as u64
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
        Some(last) if last.same(empty) => last.messages.push(message),
        _ => {
            let mut conversation = empty.clone();
            conversation.messages.push(message);
            archive.conversations.push(conversation);
        }
    }
}

fn encode_conversation(w: &mut Writer, conversation: &ArchivedConversation) {
    w.vector(&conversation.group_id);
    w.vector(conversation.host.to_string().as_bytes());
    w.bytes(&conversation.mailbox);
    w.nested(|w| {
        for message in &conversation.messages {
            w.bytes(&message.message_id);
            w.vector(message.sender.as_str().as_bytes());
            w.vector(
                message
                    .device_id
                    .as_ref()
                    .map_or(&[][..], |d| &d.as_bytes()[..]),
            );
            w.u64(message.counter);
            w.vector(message.previous.as_ref().map_or(&[][..], |p| &p[..]));
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
    // Parsing a server address is strict: only its one written form
    // parses (3.5).
    let host = std::str::from_utf8(r.vector()?)
        .ok()
        .and_then(|host| host.parse::<ServerAddr>().ok())
        .ok_or(ArchiveError::Malformed("host"))?;
    let mailbox = r.array::<BOX_LEN>()?;
    let mut messages = Vec::new();
    let mut list = Reader(r.vector()?);
    while !list.0.is_empty() {
        let message_id = list.array::<MESSAGE_ID_LEN>()?;
        let sender = canonical::<Uid>(list.vector()?, "sender")?;
        // 48 bytes for an identity's device, empty for a guest (12.13).
        let device_id = match (list.vector()?, sender.is_guest()) {
            ([], true) => None,
            (id, false) if id.len() == DEVICE_ID_LEN => {
                Some(DeviceId::from_bytes(id.try_into().expect("48 bytes")))
            }
            _ => return Err(ArchiveError::Malformed("device_id")),
        };
        let counter = list.u64()?;
        let previous = match list.vector()? {
            [] => None,
            p if p.len() == PREVIOUS_LEN => Some(p.try_into().expect("16 bytes")),
            _ => return Err(ArchiveError::Malformed("previous")),
        };
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
            device_id,
            counter,
            previous,
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
    use std::collections::HashMap;

    fn alice() -> Identity {
        "alice@example.org".parse().unwrap()
    }

    fn message(seq: u64, content: &str) -> ArchivedMessage {
        ArchivedMessage {
            message_id: [seq as u8; 16],
            sender: "bob@example.net".parse().unwrap(),
            device_id: Some(DeviceId::from_bytes([0xd0u8.wrapping_add(seq as u8); 48])),
            counter: 100 + seq,
            previous: seq
                .is_multiple_of(2)
                .then_some([0xe0u8.wrapping_add(seq as u8); 16]),
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

    fn archived_file(n: u8) -> ArchivedFile {
        ArchivedFile {
            file_hash: BlobRef::from_bytes([n; 48]),
            blob: BlobRef::from_bytes([n + 1; 48]),
            key: FileKey::from_bytes([n + 2; 32]),
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
            files: vec![archived_file(0x30)],
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
        // A guest sender, with no device id, and long vectors in each
        // length form.
        let mut archive = archive;
        archive.conversations[0].messages[0].sender = "~sam".parse().unwrap();
        archive.conversations[0].messages[0].device_id = None;
        for len in [0, 63, 64, 16383, 16384, 70000] {
            archive.conversations[0].messages[1].content = vec![b'x'; len];
            let bytes = archive.encode();
            assert_eq!(HistoryArchive::decode(&bytes), Ok(archive.clone()));
        }
        // A server on a port other than 7472 (3.5, 12.13).
        archive.conversations[1].host = "example.org:7000".parse().unwrap();
        let bytes = archive.encode();
        assert!(bytes.windows(17).any(|w| w == b"\x10example.org:7000"));
        assert_eq!(HistoryArchive::decode(&bytes), Ok(archive.clone()));
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
        // A guest uid cannot own an archive.
        let mut w = Writer::default();
        w.u8(1);
        w.vector(b"~sam");
        w.u64(0);
        w.vector(&[]);
        w.vector(&[]);
        w.vector(&[]);
        assert!(malformed(&w.0));

        // Field by field, from a minimal archive with one message.
        let one = HistoryArchive {
            uid: alice(),
            made: 7,
            conversations: vec![conversation(1, vec![message(1, "x")])],
            files: vec![],
            more: vec![],
        };
        let b = one.encode().to_vec();
        // version 1, uid (1 + 17), made 8, then the conversations' length
        // (two bytes, as the conversation is longer than 63).
        let conv = 1 + 18 + 8 + 2;
        // group_id (1 + 32), host (1 + 11), box 16, messages' length 2.
        let msg = conv + 33 + 12 + 16 + 2;
        // message_id 16, sender (1 + 15).
        let device_id = msg + 16 + 16;
        let counter = device_id + 1 + 48;
        let previous = counter + 8;
        let verified = previous + 1;
        let seq = verified + 1 + 16;
        assert_eq!(b[device_id], 48);
        assert_eq!(&b[counter..counter + 8], &101u64.to_be_bytes());
        assert_eq!(b[previous], 0);
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
        // A host that is not a server address: `example:org`.
        let mut bad = b.clone();
        assert_eq!(bad[conv + 41], b'.');
        bad[conv + 41] = b':';
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

        // Device ids and `previous` of other lengths, and a device id
        // missing for an identity or given for a guest.
        let reencode = |f: &dyn Fn(&mut Writer)| {
            let mut w = Writer::default();
            w.u8(1);
            w.vector(b"alice@example.org");
            w.u64(7);
            w.nested(|w| {
                w.vector(&[1; 32]);
                w.vector(b"example.org");
                w.bytes(&[1; 16]);
                w.nested(f);
            });
            w.vector(&[]);
            w.vector(&[]);
            HistoryArchive::decode(&w.0)
        };
        let message_with = |sender: &[u8], device: &[u8], previous: &[u8]| {
            let sender = sender.to_vec();
            let device = device.to_vec();
            let previous = previous.to_vec();
            move |w: &mut Writer| {
                w.bytes(&[1; 16]);
                w.vector(&sender);
                w.vector(&device);
                w.u64(5);
                w.vector(&previous);
                w.u8(0);
                w.u64(1);
                w.u64(2);
                w.u64(3);
                w.vector(b"TEXT x");
            }
        };
        assert!(reencode(&message_with(b"bob@example.net", &[7; 48], &[])).is_ok());
        assert!(reencode(&message_with(b"bob@example.net", &[7; 48], &[8; 16])).is_ok());
        assert!(reencode(&message_with(b"~sam", &[], &[8; 16])).is_ok());
        for (sender, device, previous, what) in [
            (&b"bob@example.net"[..], &[7; 47][..], &[][..], "device_id"),
            (b"bob@example.net", &[7; 49], &[], "device_id"),
            (b"bob@example.net", &[], &[], "device_id"),
            (b"~sam", &[7; 48], &[], "device_id"),
            (b"bob@example.net", &[7; 48], &[8; 15], "previous"),
            (b"bob@example.net", &[7; 48], &[8; 17], "previous"),
        ] {
            assert_eq!(
                reencode(&message_with(sender, device, previous)),
                Err(ArchiveError::Malformed(what))
            );
        }

        // A `files` entry cut short, and a `more` entry that is not 81
        // bytes or not of version 1.
        let with_lists = |files: &[u8], more: &[u8]| {
            let mut w = Writer::default();
            w.u8(1);
            w.vector(b"alice@example.org");
            w.u64(7);
            w.vector(&[]);
            w.vector(files);
            w.vector(more);
            HistoryArchive::decode(&w.0)
        };
        assert!(with_lists(&[0; 128], &[]).is_ok());
        assert!(with_lists(&[0; 127], &[]).is_err());
        assert!(with_lists(&[0; 129], &[]).is_err());
        let mut transfer = [0; 81];
        transfer[0] = 1;
        assert!(with_lists(&[], &transfer).is_ok());
        assert!(with_lists(&[], &transfer[..80]).is_err());
        assert!(with_lists(&[], &[&transfer[..], &[1]].concat()).is_err());
        transfer[0] = 2;
        assert_eq!(with_lists(&[], &transfer), Err(ArchiveError::Version(2)));
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
        assert_eq!(bytes.len(), 81);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..49], t.blob.as_bytes());
        assert_eq!(&bytes[49..], &[5; 32]);
        assert_eq!(TransferRef::from_bytes(&bytes[..]), Ok(t.clone()));
        assert!(TransferRef::from_bytes(&bytes[..80]).is_err());
        assert!(TransferRef::from_bytes(&[1; 82]).is_err());
        for version in [0, 2] {
            let mut b = *bytes;
            b[0] = version;
            assert_eq!(
                TransferRef::from_bytes(&b),
                Err(ArchiveError::Version(version))
            );
            assert_eq!(TransferRef::from_base64(&BASE64.encode(b)), None);
        }
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
            Ok(archive.clone())
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
        // The encoded archive encrypted as a file, not as an archive: the
        // label differs, so it does not decrypt.
        let as_file = file::encrypt(Label::File, &archive.encode()).unwrap();
        let t = TransferRef {
            blob: as_file.hash,
            key: as_file.key,
        };
        assert_eq!(
            HistoryArchive::open(&t, &as_file.upload, &alice()),
            Err(ArchiveError::File(FileError::Chunk(0)))
        );
        // A blob that decrypts but is not an archive.
        let not = file::encrypt(Label::Archive, b"not an archive").unwrap();
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
    fn archived_files() {
        let original = b"a photo";
        let file_hash = BlobRef::of(b"the original upload");
        let (blob, entry) = ArchivedFile::encrypt(file_hash, original).unwrap();
        assert_eq!(entry.file_hash, file_hash);
        assert_eq!(entry.blob, BlobRef::of(&blob));
        assert_eq!(entry.decrypt(&blob).unwrap().as_slice(), original);
        // Encrypted as a file, so it is not an archive, and a changed blob
        // fails its hash.
        let as_transfer = TransferRef {
            blob: entry.blob,
            key: entry.key.clone(),
        };
        assert_eq!(
            HistoryArchive::open(&as_transfer, &blob, &alice()),
            Err(ArchiveError::File(FileError::Chunk(0)))
        );
        let mut changed = blob.clone();
        changed[1] ^= 1;
        assert_eq!(entry.decrypt(&changed), Err(FileError::Hash));
        // A new key each time.
        let (_, again) = ArchivedFile::encrypt(file_hash, original).unwrap();
        assert_ne!(again.key, entry.key);
    }

    /// A store of blobs by hash, as the server's.
    fn store(sealed: &[SealedArchive]) -> HashMap<[u8; 48], Vec<u8>> {
        sealed
            .iter()
            .map(|s| (*s.transfer.blob.as_bytes(), s.blob.clone()))
            .collect()
    }

    #[test]
    fn split_transfers() {
        let conversations = vec![
            conversation(1, (1..=40).map(|i| message(i, &"a".repeat(100))).collect()),
            conversation(2, (1..=40).map(|i| message(i, &"b".repeat(100))).collect()),
        ];
        let files: Vec<ArchivedFile> = (0..20).map(|i| archived_file(i * 3)).collect();
        // Everything fits: one archive.
        let one =
            seal_transfer(&alice(), 9, conversations.clone(), files.clone(), 1 << 20).unwrap();
        assert_eq!(one.len(), 1);
        let head = HistoryArchive::open(&one[0].transfer, &one[0].blob, &alice()).unwrap();
        assert_eq!(head.conversations, conversations);
        assert_eq!(head.files, files);
        assert!(head.more.is_empty());
        let blobs = store(&one);
        let opened = open_transfer(&one[0].transfer, &alice(), |h| {
            blobs.get(h.as_bytes()).cloned()
        })
        .unwrap();
        assert_eq!(opened.conversations, conversations);
        assert_eq!(opened.files, files);
        assert_eq!((opened.made, opened.missing, opened.ignored), (9, 0, 0));

        // Split into blobs of at most 4 KiB.
        let max = 4096;
        let parts = seal_transfer(&alice(), 9, conversations.clone(), files.clone(), max).unwrap();
        assert!(parts.len() > 3);
        assert!(parts.iter().all(|p| p.blob.len() as u64 <= max));
        let head = HistoryArchive::open(&parts[0].transfer, &parts[0].blob, &alice()).unwrap();
        assert!(head.conversations.is_empty());
        assert!(head.files.is_empty());
        assert_eq!(head.more.len(), parts.len() - 1);
        for (t, part) in head.more.iter().zip(&parts[1..]) {
            assert_eq!(t, &part.transfer);
            let archive = HistoryArchive::open(t, &part.blob, &alice()).unwrap();
            assert!(archive.more.is_empty());
            assert_eq!((archive.uid.clone(), archive.made), (alice(), 9));
        }
        // Joining the parts gives back every message and file, in order.
        let blobs = store(&parts);
        let opened = open_transfer(&parts[0].transfer, &alice(), |h| {
            blobs.get(h.as_bytes()).cloned()
        })
        .unwrap();
        assert_eq!(opened.conversations, conversations);
        assert_eq!(opened.files, files);
        assert_eq!((opened.made, opened.missing, opened.ignored), (9, 0, 0));

        // A part that cannot be fetched, or does not open: the rest is
        // used, and the count says history is missing.
        let lost = parts[2].transfer.blob;
        let opened = open_transfer(&parts[0].transfer, &alice(), |h| {
            (h != &lost)
                .then(|| blobs.get(h.as_bytes()).cloned())
                .flatten()
        })
        .unwrap();
        assert_eq!(opened.missing, 1);
        let opened = open_transfer(&parts[0].transfer, &alice(), |h| {
            let mut blob = blobs.get(h.as_bytes()).cloned()?;
            if h == &lost {
                blob[5] ^= 1;
            }
            Some(blob)
        })
        .unwrap();
        assert_eq!(opened.missing, 1);
        // The first archive must open.
        assert_eq!(
            open_transfer(&parts[0].transfer, &alice(), |_| None),
            Err(ArchiveError::Missing)
        );
        assert_eq!(
            open_transfer(
                &parts[0].transfer,
                &"bob@example.net".parse().unwrap(),
                |h| { blobs.get(h.as_bytes()).cloned() }
            ),
            Err(ArchiveError::OtherIdentity)
        );

        // A message larger than a blob.
        let huge = vec![conversation(1, vec![message(1, &"x".repeat(5000))])];
        assert_eq!(
            seal_transfer(&alice(), 9, huge, vec![], max).unwrap_err(),
            ArchiveError::TooLarge
        );
    }

    /// Builds a transfer by hand: a first archive naming `others`.
    fn hand_transfer(
        first: HistoryArchive,
        others: Vec<HistoryArchive>,
    ) -> (TransferRef, HashMap<[u8; 48], Vec<u8>>) {
        let sealed: Vec<SealedArchive> = others.iter().map(|a| a.seal().unwrap()).collect();
        let head = HistoryArchive {
            more: sealed.iter().map(|s| s.transfer.clone()).collect(),
            ..first
        }
        .seal()
        .unwrap();
        let mut blobs = store(&sealed);
        blobs.insert(*head.transfer.blob.as_bytes(), head.blob);
        (head.transfer, blobs)
    }

    fn part(made: u64, conversations: Vec<ArchivedConversation>) -> HistoryArchive {
        HistoryArchive {
            uid: alice(),
            made,
            conversations,
            files: vec![],
            more: vec![],
        }
    }

    #[test]
    fn merging() {
        let open = |(first, blobs): (TransferRef, HashMap<[u8; 48], Vec<u8>>)| {
            open_transfer(&first, &alice(), |h| blobs.get(h.as_bytes()).cloned())
        };
        // The first archive holds messages of its own; a conversation spans
        // three archives, and another server's mailbox of the same group
        // stays apart.
        let mut elsewhere = conversation(1, vec![message(1, "TEXT elsewhere")]);
        elsewhere.host = "example.net".parse().unwrap();
        let opened = open(hand_transfer(
            part(9, vec![conversation(1, vec![message(1, "a")])]),
            vec![
                part(
                    9,
                    vec![conversation(1, vec![message(2, "b")]), elsewhere.clone()],
                ),
                part(
                    9,
                    vec![
                        conversation(2, vec![message(1, "c")]),
                        conversation(1, vec![message(5, "d")]),
                    ],
                ),
            ],
        ))
        .unwrap();
        assert_eq!(
            opened.conversations,
            vec![
                conversation(1, vec![message(1, "a"), message(2, "b"), message(5, "d")]),
                elsewhere,
                conversation(2, vec![message(1, "c")]),
            ]
        );
        assert_eq!(opened.ignored, 0);

        // Seqs that do not increase strictly once joined: that one
        // conversation is ignored.
        let opened = open(hand_transfer(
            part(9, vec![conversation(1, vec![message(3, "a")])]),
            vec![part(
                9,
                vec![
                    conversation(1, vec![message(3, "again")]),
                    conversation(2, vec![message(1, "c")]),
                ],
            )],
        ))
        .unwrap();
        assert_eq!(
            opened.conversations,
            vec![conversation(2, vec![message(1, "c")])]
        );
        assert_eq!(opened.ignored, 1);
        let opened = open(hand_transfer(
            part(
                9,
                vec![conversation(1, vec![message(3, "a"), message(2, "b")])],
            ),
            vec![],
        ))
        .unwrap();
        assert_eq!((opened.conversations.len(), opened.ignored), (0, 1));

        // Another part with a `more`, another `made`, or another identity:
        // the whole transfer is rejected.
        let mut nested = part(9, vec![]);
        nested.more = vec![sample().more[0].clone()];
        assert_eq!(
            open(hand_transfer(part(9, vec![]), vec![nested])),
            Err(ArchiveError::Split)
        );
        assert_eq!(
            open(hand_transfer(part(9, vec![]), vec![part(8, vec![])])),
            Err(ArchiveError::Split)
        );
        let mut theirs = part(9, vec![]);
        theirs.uid = "bob@example.net".parse().unwrap();
        assert_eq!(
            open(hand_transfer(part(9, vec![]), vec![theirs])),
            Err(ArchiveError::Split)
        );
    }

    /// A fixed-input vector for Appendix B: [`sample`]'s encoding.
    #[test]
    fn vector() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let bytes = sample().encode();
        println!("HistoryArchive {}", hex(&bytes));
        println!("TransferRef    {}", hex(&sample().more[0].to_bytes()[..]));
        assert_eq!(hex(&bytes), ARCHIVE_VECTOR);
    }

    /// Appendix B.16: [`sample`] and its TransferRef, checked against the
    /// appendix.
    #[test]
    fn appendix_b() {
        let mut ck = crate::appendix::Checker::open("B.16 ");
        let archive = sample();
        let more = &archive.more[0];
        ck.eq("TransferRef blob", more.blob.to_string());
        ck.hex("TransferRef key", more.key.as_bytes());
        ck.gap();
        let transfer = more.to_bytes();
        ck.hex("TransferRef", &transfer[..]);
        let bytes = archive.encode();
        ck.hex("HistoryArchive", &bytes);
        assert_eq!(TransferRef::from_bytes(&transfer[..]), Ok(more.clone()));
        assert_eq!(HistoryArchive::decode(&bytes), Ok(archive.clone()));
        ck.gap();
        let mut version = bytes.to_vec();
        version[0] = 2;
        ck.rejected(
            "the HistoryArchive with version 2",
            HistoryArchive::decode(&version).is_err(),
        );
        let mut longer = bytes.to_vec();
        longer.push(0);
        ck.rejected(
            "the HistoryArchive with a byte after it",
            HistoryArchive::decode(&longer).is_err(),
        );
        let mut version = transfer.to_vec();
        version[0] = 2;
        ck.rejected(
            "the TransferRef with version 2",
            TransferRef::from_bytes(&version).is_err(),
        );
        ck.finish();
    }

    const ARCHIVE_VECTOR: &str = "0111616c696365406578616d706c652e6f72670000019a63259a004186200101\
     0101010101010101010101010101010101010101010101010101010101010b65\
     78616d706c652e6f726701010101010101010101010101010101410901010101\
     0101010101010101010101010f626f62406578616d706c652e6e657430d1d1d1\
     d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1\
     d1d1d1d1d1d1d1d1d1d1d1d1d1000000000000006500000000019a60c3400100\
     00019a60c3406500000000000000010754455854206869020202020202020202\
     020202020202020f626f62406578616d706c652e6e657430d2d2d2d2d2d2d2d2\
     d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2\
     d2d2d2d2d2d2d2d2000000000000006610e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2\
     e2010000019a60c340020000019a60c3406600000000000000020a5445585420\
     7468657265200202020202020202020202020202020202020202020202020202\
     0202020202020b6578616d706c652e6f72670202020202020202020202020202\
     0202004080303030303030303030303030303030303030303030303030303030\
     3030303030303030303030303030303030303030303131313131313131313131\
     3131313131313131313131313131313131313131313131313131313131313131\
     3131313131323232323232323232323232323232323232323232323232323232\
     3232323232405101e1c9f3884f4b23c88e2991de91e518c8d35a4a9b6d14dbc8\
     72904281bde8441fe4c0518d85b7904c8b7f38449e40a1660505050505050505\
     050505050505050505050505050505050505050505050505";
}

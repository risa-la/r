//! Messages (12.9): the RisalaMessage inside every application message,
//! franking, counters and gaps (7.4), times, the rules for late messages
//! and past epochs, deletes (5.4), and reports to operators (5.8).
//!
//! ```text
//! struct {
//!     uint8 version;               // 1
//!     opaque message_id[16];
//!     uint64 counter;
//!     opaque previous<V>;          // 16 bytes, or empty
//!     uint64 time;                 // the sender's clock, ms since 1970-01-01T00:00:00Z
//!     opaque frank_key[32];
//!     opaque content<V>;
//! } RisalaMessage;
//! ```
//!
//! **Sending.** A device keeps a [`SendCounter`] per leaf, and writes each
//! message with [`SendCounter::write`] (or [`RisalaMessage::live`] for a
//! TYPING), then encrypts it with [`encrypt`], which puts its frank in the
//! RisalaAAD. A message is fixed once written: if its post gets
//! `ERR stale`, or must go again for another reason (7.6), the device
//! encrypts the same RisalaMessage again with [`encrypt_again`] in the
//! current epoch, which re-makes only an ATTEST line's pseudonym (12.10).
//!
//! **Receiving.** [`receive`] takes an application message's post, checks
//! the past-epoch limits, decrypts it with MLS (which checks its signature
//! and deletes its key), and makes the checks of 12.9 in order: the
//! pseudonym (step 1), the frank (2), that the `message_id` is new (3),
//! the counter and `previous` (4), and the time (5). Steps 1 to 3, and a
//! sender that has left, are errors: the device MUST NOT show the content.
//! The rest come back in a [`Decrypted`], which says what the caller still
//! has to check: whether the sender's leaf is confirmed (12.10, step 6,
//! [`Decrypted::trust`]), and in a public room, a new pseudonym's ATTEST
//! ([`PseudonymCheck::NeedsAttest`]).
//!
//! What a device remembers about a group's messages (public rooms' pins,
//! counters, seen ids, the times of the commits that ended past epochs,
//! and past epochs' pseudonyms) is the caller's, behind
//! [`MessageHistory`]; [`MemoryHistory`] keeps it in memory. After
//! applying a commit, the caller calls [`MessageHistory::note_commit`] with
//! what [`group::apply_commit`] or [`group::merge_own_commit`] returned and
//! the commit's `t`; after applying any post, [`expire_past_epochs`]; and
//! each time it has caught up one of the group's mailboxes, or stops
//! following one, [`expire_past_epochs_caught_up`]. After a move (7.8), the
//! history lists the mailboxes the group moved from that the device still
//! follows ([`MessageHistory::moves`]); the caller calls
//! [`expire_past_epochs`] once it has noted the move, so that the old
//! mailbox's last epochs are judged by that mailbox's posts alone.
//!
//! **Franking makes messages key-committing.** ChaCha20-Poly1305 is not
//! key-committing, so without the frank a sender could make one ciphertext
//! that decrypts to different content for different keys, and a report
//! could reveal content nobody saw. The frank is checked on every message,
//! never skipped.
//!
//! **Reports to operators** ([`RisalaReport`], [`verify_report`]) prove what
//! a post said, but not who wrote it (5.8): the frank key is chosen by the
//! sender, and the RisalaAAD holds no signature an operator can check.
//! The `author` is the reporter's claim.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;
use std::time::Duration;

use openmls::group::{MlsGroup, PastEpochDeletionPolicy};
use openmls::prelude::{LeafNodeIndex, Proposal, Sender, StagedCommit};
use openmls::storage::OpenMlsProvider;
use risala_proto::content::{
    Content, ContentLine, Conversation, MAX_CONTENT_LEN, MAX_REASON_LEN, MESSAGE_ID_LEN, MessageId,
    Place,
};
use risala_proto::error::ParseError;
use risala_proto::names::Uid;
use risala_proto::time::Timestamp;
use risala_proto::types::{ConfirmMode as LineConfirmMode, MAX_REPORT_CONTEXT};
use zeroize::Zeroizing;

use crate::aad::{EpochPseudonyms, Pseudonym, RisalaAad};
use crate::checks::PERIOD_MS;
use crate::codec::{DecodeError, Reader, Writer};
use crate::conversation::{ConfirmMode, ConversationKind, RisalaConversation, Role};
use crate::framing::{ContentType, read_post};
use crate::group::{self, GroupError, Incoming, ProcessError};
use crate::identity::RisalaIdentity;
use crate::primitives::{HASH_LEN, ct_eq, hmac_sha384, random};

/// The `version` of a RisalaMessage and of a RisalaReport (12.9, 5.8).
pub const VERSION: u8 = 1;

/// The length of a frank key (12.9).
pub const FRANK_KEY_LEN: usize = 32;

/// The length of a frank: HMAC-SHA-384 (12.9).
pub const FRANK_LEN: usize = HASH_LEN;

/// How far a message's `time` may be from its post's `t` before devices
/// mark that the times disagree (12.9, step 5).
pub const MAX_CLOCK_DIFFERENCE: Duration = Duration::from_secs(10 * 60);

/// How many epochs past a message's epoch a device may have applied and
/// still decrypt it (12.9): at most e + 2. The group's configuration keeps
/// as many ([`group::MAX_PAST_EPOCHS`]).
pub const MAX_PAST_EPOCHS: u64 = group::MAX_PAST_EPOCHS as u64;

/// How long after the commit that ended a message's epoch its post may be,
/// by `t`, for a device to decrypt it (12.9).
pub const PAST_EPOCH_WINDOW: Duration = Duration::from_secs(60 * 60);

/// How far past the `t` of the commit that ended an epoch the server's time
/// must be, as of a catch-up of every mailbox that may carry the epoch's
/// messages, for a device to delete the epoch's secrets whatever posts
/// arrive (12.9, [`expire_past_epochs_caught_up`]).
pub const PAST_EPOCH_KEEP: Duration = Duration::from_secs(2 * 60 * 60);

/// How many generations a device keeps the keys of skipped messages
/// behind the newest it has seen from a sender, and how far ahead of it it
/// accepts a message (12.9).
pub const MAX_GENERATIONS: u32 = group::MAX_SKIPPED_GENERATIONS;

/// How many gaps a device remembers per leaf, to recognise a late message
/// that fills one (7.4). Older gaps are forgotten first.
pub const MAX_GAPS: usize = 1000;

// ---------------------------------------------------------------------------
// Franking

/// A frank key (12.9): 32 random bytes, new for each message, under which
/// the frank in the RisalaAAD is computed. It is in the encrypted message,
/// and goes to operators only in a report (5.8).
#[derive(Clone)]
pub struct FrankKey(Zeroizing<[u8; FRANK_KEY_LEN]>);

impl FrankKey {
    /// A new random frank key.
    pub fn generate() -> Result<FrankKey, getrandom::Error> {
        Ok(FrankKey(Zeroizing::new(random()?)))
    }

    /// The frank key with these bytes.
    pub fn from_bytes(bytes: [u8; FRANK_KEY_LEN]) -> FrankKey {
        FrankKey(Zeroizing::new(bytes))
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; FRANK_KEY_LEN] {
        &self.0
    }

    /// HMAC-SHA-384(frank_key, content) (RFC 2104), over the bytes of
    /// `content` alone, without their length prefix (12.9, step 4).
    pub fn frank(&self, content: &[u8]) -> [u8; FRANK_LEN] {
        hmac_sha384(&self.0[..], content)
    }

    /// Whether `frank` is the frank of `content` under this key, compared
    /// in constant time (12.9, receiving step 2; 5.8).
    pub fn matches(&self, content: &[u8], frank: &[u8; FRANK_LEN]) -> bool {
        ct_eq(&self.frank(content), frank)
    }
}

impl PartialEq for FrankKey {
    /// Constant time.
    fn eq(&self, other: &FrankKey) -> bool {
        ct_eq(&self.0[..], &other.0[..])
    }
}

impl Eq for FrankKey {}

impl fmt::Debug for FrankKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FrankKey(..)")
    }
}

// ---------------------------------------------------------------------------
// RisalaMessage

/// The content of an application message (12.9).
#[derive(Clone, PartialEq, Eq)]
pub struct RisalaMessage {
    /// The message's id, 16 random bytes, by which other messages refer to
    /// it (5.3).
    pub message_id: MessageId,
    /// How many messages the sending leaf has written in the group, this
    /// one included; 0 in a live message.
    pub counter: u64,
    /// The `message_id` of the leaf's previous message; `None` for its
    /// first, and in a live message.
    pub previous: Option<MessageId>,
    /// The sender's clock, in ms since 1970-01-01T00:00:00Z.
    pub time: u64,
    /// The key of the frank.
    pub frank_key: FrankKey,
    /// The content lines.
    pub content: Content,
}

/// Why bytes are not a RisalaMessage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// Not one RisalaMessage of version 1, or `previous` neither empty nor
    /// 16 bytes.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
    /// `content` is not content lines (12.9).
    #[error("the content is not lines: {0}")]
    Content(ParseError),
}

impl RisalaMessage {
    /// A live message (5.2, 8.1): counter 0, no `previous`, and new random
    /// `message_id` and `frank_key`. It does not count in the leaf's
    /// messages.
    pub fn live(content: Content, now: Timestamp) -> Result<RisalaMessage, getrandom::Error> {
        Ok(RisalaMessage {
            message_id: MessageId::from_bytes(random()?),
            counter: 0,
            previous: None,
            time: now.unix_millis(),
            frank_key: FrankKey::generate()?,
            content,
        })
    }

    /// Whether this is a live message: `counter` 0 (12.9, step 3).
    pub fn is_live(&self) -> bool {
        self.counter == 0
    }

    /// The frank of the content, for the RisalaAAD (12.9, step 4).
    pub fn frank(&self) -> [u8; FRANK_LEN] {
        self.frank_key.frank(self.content.as_bytes())
    }

    /// The sender's time, if it is a valid timestamp (3.5).
    pub fn timestamp(&self) -> Option<Timestamp> {
        Timestamp::from_unix_millis(self.time)
    }

    /// The encoded RisalaMessage. It holds the content and the frank key,
    /// so it is wiped when dropped.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(VERSION)
            .fixed(self.message_id.as_bytes())
            .u64(self.counter)
            .vector(
                self.previous
                    .as_ref()
                    .map_or(&[][..], |id| &id.as_bytes()[..]),
            )
            .u64(self.time)
            .fixed(&self.frank_key.as_bytes()[..])
            .vector(self.content.as_bytes());
        Zeroizing::new(w.into_bytes())
    }

    /// Reads exactly one RisalaMessage of version 1, whose content is
    /// content lines (12.9).
    pub fn decode(bytes: &[u8]) -> Result<RisalaMessage, MessageError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(DecodeError("unknown RisalaMessage version").into());
        }
        let message_id = MessageId::from_bytes(r.array()?);
        let counter = r.u64()?;
        let previous = match r.vector()? {
            [] => None,
            id => Some(MessageId::from_bytes(
                <[u8; MESSAGE_ID_LEN]>::try_from(id)
                    .map_err(|_| DecodeError("a previous id that is neither empty nor 16 bytes"))?,
            )),
        };
        let time = r.u64()?;
        let frank_key = FrankKey::from_bytes(r.array()?);
        let content = r.vector()?;
        r.finish()?;
        let content = Content::parse(content).map_err(MessageError::Content)?;
        Ok(RisalaMessage {
            message_id,
            counter,
            previous,
            time,
            frank_key,
            content,
        })
    }
}

impl fmt::Debug for RisalaMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RisalaMessage")
            .field("message_id", &self.message_id)
            .field("counter", &self.counter)
            .field("previous", &self.previous)
            .field("time", &self.time)
            .field("content", &self.content)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Sending

/// The messages a leaf has written in a group (12.9, step 3): how many,
/// and the id of the last. A device keeps one per leaf, starts it afresh
/// for a new leaf, and stores it before posting what [`SendCounter::write`]
/// returns, so that a crash never makes two messages with one counter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SendCounter {
    /// How many messages the leaf has written.
    pub written: u64,
    /// The `message_id` of the last.
    pub last: Option<MessageId>,
}

/// Why a message could not be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// No randomness.
    #[error("no randomness")]
    Random,
    /// The leaf has written 2^64 - 1 messages.
    #[error("the counter is exhausted")]
    Counter,
}

impl SendCounter {
    /// Writes the leaf's next message (12.9, steps 1-3): new random
    /// `message_id` and `frank_key`, `time` from `now`, the next counter,
    /// and `previous` the last message's id.
    pub fn write(&mut self, content: Content, now: Timestamp) -> Result<RisalaMessage, WriteError> {
        let counter = self.written.checked_add(1).ok_or(WriteError::Counter)?;
        let message = RisalaMessage {
            message_id: MessageId::from_bytes(random().map_err(|_| WriteError::Random)?),
            counter,
            previous: self.last,
            time: now.unix_millis(),
            frank_key: FrankKey::generate().map_err(|_| WriteError::Random)?,
            content,
        };
        self.written = counter;
        self.last = Some(message.message_id);
        Ok(message)
    }
}

/// Encrypts `message` as an MLS application message of `group`'s current
/// epoch (12.9, step 5), with a RisalaAAD of the leaf's pseudonym and the
/// message's frank. The pseudonym is derived from the epoch outside public
/// rooms, where `period` is `None`, and in a public room is `period`, the
/// one the device picked for the period (7.3). MLS signs it with the leaf
/// key, and pads it with zero bytes to a multiple of 256 bytes (the
/// group's padding, [`group::PADDING_SIZE`]).
///
/// To post the same message again, in a later epoch (7.6), use
/// [`encrypt_again`].
pub fn encrypt<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    period: Option<Pseudonym>,
    message: &RisalaMessage,
) -> Result<Vec<u8>, GroupError<P::StorageError>> {
    let pseudonym = group::sending_pseudonym(group, provider.crypto(), period)?;
    let aad = RisalaAad::application(pseudonym, message.frank());
    group::encrypt_application(provider, group, &aad, &message.encode())
}

/// Encrypts `message` again for a post that must go again, after
/// `ERR stale` or for another reason (7.6, 12.9), in `group`'s current
/// epoch, as [`encrypt`] does. Returns the message as sent, which the
/// device keeps in place of `message`, and the post.
///
/// 12.9 keeps a RisalaMessage's fields fixed once written, but an ATTEST
/// line carries the pseudonym of its message's RisalaAAD (12.10), which
/// outside public rooms is derived from the epoch (7.3): sent unchanged in
/// a later epoch, it would carry the old epoch's pseudonym, and receivers
/// would refuse it. 12.9 and 12.10 do not say which wins. So this re-makes
/// each ATTEST line whose pseudonym is not the one this post carries, and
/// keeps every other field and line: the `message_id`, `counter`,
/// `previous`, `time` and `frank_key` stay, so receivers that get both
/// copies still show the message once (12.9, step 3), but the content and
/// so the frank change. A message without such a line goes again
/// unchanged, frank and all.
pub fn encrypt_again<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    period: Option<Pseudonym>,
    message: &RisalaMessage,
) -> Result<(RisalaMessage, Vec<u8>), GroupError<P::StorageError>> {
    let pseudonym = group::sending_pseudonym(group, provider.crypto(), period)?;
    let message = with_attest_pseudonym(message, pseudonym);
    let post = encrypt(provider, group, period, &message)?;
    Ok((message, post))
}

/// `message` with the pseudonym of each of its ATTEST lines set to
/// `pseudonym` (12.10), or `message` itself if they all have it already.
fn with_attest_pseudonym(message: &RisalaMessage, pseudonym: Pseudonym) -> RisalaMessage {
    let wanted = risala_proto::mls::Pseudonym::from_bytes(pseudonym.0);
    let stale = |line: &ContentLine| matches!(line, ContentLine::Attest { pseudonym, .. } if *pseudonym != wanted);
    if !message.content.lines().iter().any(stale) {
        return message.clone();
    }
    let lines = message
        .content
        .lines()
        .iter()
        .map(|line| match line {
            ContentLine::Attest {
                period,
                period_key,
                certificate,
                attestation,
                ..
            } => ContentLine::Attest {
                period: *period,
                period_key: period_key.clone(),
                certificate: certificate.clone(),
                attestation: attestation.clone(),
                pseudonym: wanted,
            },
            other => other.clone(),
        })
        .collect();
    // The device wrote the content with Content::new, and an ATTEST line
    // with another pseudonym has the same length, so writing it again
    // cannot fail.
    let content = Content::new(lines).expect("content the device wrote, written again");
    RisalaMessage {
        content,
        ..message.clone()
    }
}

// ---------------------------------------------------------------------------
// What a device remembers

/// What a device remembers about one leaf index's messages in a group
/// (12.9, 7.3, 7.4). It is reset when a commit removes the leaf
/// ([`MessageHistory::note_commit`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderLog {
    /// In a public room, the pinned pseudonym (7.3). Outside public rooms
    /// pseudonyms are derived for each epoch, and never pinned.
    pub pseudonym: Option<Pseudonym>,
    /// For a guest's leaf in a public room, the period (12.10) its
    /// pseudonym was pinned in, from its first message of that period.
    pub pin_period: Option<u64>,
    /// The highest counter seen from the leaf, and its message's id.
    pub last: Option<(u64, MessageId)>,
    /// The counters not yet seen below `last`, as inclusive ranges in
    /// increasing order: the gaps (7.4). At most [`MAX_GAPS`].
    pub gaps: Vec<(u64, u64)>,
    /// Whether the leaf has posted a SelfRemove (12.9).
    pub left: bool,
    /// The epochs that commits removing a leaf at this index ended, oldest
    /// first. A message of the newest such epoch or earlier from this
    /// index is from a removed leaf (12.9, late messages). Older removals
    /// are kept while a mailbox the group moved from is followed
    /// ([`MessageHistory::moves`]): a late post there is judged by the
    /// newest removal before the move, even if the index was used again
    /// and removed again after it.
    pub removals: Vec<u64>,
}

impl SenderLog {
    /// The newest epoch that a commit removing a leaf at this index ended.
    pub fn removed_in(&self) -> Option<u64> {
        self.removals.last().copied()
    }

    /// The newest epoch that a commit removing a leaf at this index ended,
    /// among those before a move that created epoch `moved` (7.8, 12.9).
    pub fn removed_before(&self, moved: u64) -> Option<u64> {
        self.removals.iter().rev().copied().find(|r| *r < moved)
    }
}

/// A mailbox the group moved away from, which the device still follows,
/// for a day after the move (7.8). A post there that comes after the move
/// is judged as of the move (12.9), so the device keeps what that needs
/// for as long as it follows the mailbox: the secrets of the epochs before
/// the move, and the removals before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Moved {
    /// The first epoch whose posts the mailbox holds: the epoch of the move
    /// to it, or 0.
    pub from: u64,
    /// The epoch that the move away from it created.
    pub to: u64,
}

impl Moved {
    /// The past epochs whose messages a post in the mailbox may still
    /// carry, as of the move: the last two before it (12.9), and none
    /// before the mailbox's first.
    pub fn epochs(&self) -> std::ops::Range<u64> {
        self.to.saturating_sub(MAX_PAST_EPOCHS).max(self.from)..self.to
    }
}

/// The past epochs that the mailboxes in `moves` keep (12.9).
fn moved_epochs(moves: &[Moved]) -> BTreeSet<u64> {
    moves.iter().flat_map(Moved::epochs).collect()
}

/// Drops the removals of a leaf's log that no rule needs any more: the
/// newest is kept, and for each move in `moves`, the newest before it
/// (12.9).
fn prune_removals(removals: &mut Vec<u64>, moves: &[Moved]) {
    let newest = removals.last().copied();
    let needed: BTreeSet<u64> = moves
        .iter()
        .filter_map(|m| removals.iter().rev().copied().find(|r| *r < m.to))
        .chain(newest)
        .collect();
    removals.retain(|r| needed.contains(r));
    removals.dedup();
}

/// What a device remembers about a group's messages, for the checks of
/// 12.9. Implementations store it with the group, and change it only
/// through these methods.
pub trait MessageHistory {
    /// Whether a message with `id` has been accepted in the group.
    fn seen(&self, id: &MessageId) -> bool;
    /// Remembers that a message with `id` has been accepted.
    fn add_seen(&mut self, id: MessageId);
    /// The log of the leaf at `leaf`, or an empty one.
    fn sender(&self, leaf: LeafNodeIndex) -> SenderLog;
    /// Replaces the log of the leaf at `leaf`.
    fn set_sender(&mut self, leaf: LeafNodeIndex, log: SenderLog);
    /// The `t` of the commit that ended `epoch`, if the device applied it.
    fn epoch_end(&self, epoch: u64) -> Option<Timestamp>;
    /// Remembers the `t` of the commit that ended `epoch`.
    fn set_epoch_end(&mut self, epoch: u64, t: Timestamp);
    /// The pseudonym of the leaf at `leaf` in the past epoch `epoch`,
    /// outside public rooms (7.3), if the device kept that epoch's.
    fn epoch_pseudonym(&self, epoch: u64, leaf: LeafNodeIndex) -> Option<Pseudonym>;
    /// Keeps the pseudonyms of an epoch that has ended, for as long as the
    /// device keeps its secrets (12.9). Older ones may go, but not those of
    /// the epochs that [`Self::moves`] keep.
    fn set_epoch_pseudonyms(&mut self, pseudonyms: EpochPseudonyms);
    /// The mailboxes the group moved away from that the device still
    /// follows (7.8), oldest first. While it does, the device keeps the
    /// secrets of the epochs before each move ([`Moved::epochs`]), their
    /// ends and pseudonyms, and the removals before it, so that it judges
    /// a late post there as of the move however many commits it has
    /// applied since (12.9). [`MessageHistory::set_epoch_end`] keeps those
    /// epochs' ends too.
    fn moves(&self) -> Vec<Moved>;

    /// Notes a commit the device applied, whose post has `t`, from what
    /// applying it returned. The logs of the leaves it removed start again,
    /// so a new leaf at the same index has its own pin and counters, and
    /// messages of the removed leaves are ignored from now on, even of
    /// earlier epochs.
    fn note_commit(&mut self, applied: &group::Applied, t: Timestamp) {
        let ended_epoch = applied.ended_epoch;
        self.set_epoch_end(ended_epoch, t);
        self.set_epoch_pseudonyms(applied.pseudonyms.clone());
        let moves = self.moves();
        for &leaf in &applied.removed {
            let mut removals = self.sender(leaf).removals;
            removals.push(ended_epoch);
            prune_removals(&mut removals, &moves);
            self.set_sender(
                leaf,
                SenderLog {
                    removals,
                    ..SenderLog::default()
                },
            );
        }
    }

    /// Pins `pseudonym` for the leaf at `leaf`: in a public room, once the
    /// leaf's ATTEST for the current period has been checked and carries it
    /// (7.3, 12.10).
    fn pin(&mut self, leaf: LeafNodeIndex, pseudonym: Pseudonym) {
        let mut log = self.sender(leaf);
        log.pseudonym = Some(pseudonym);
        self.set_sender(leaf, log);
    }
}

/// A [`MessageHistory`] in memory, for tests and short-lived tools: the ids
/// of every message it has seen stay for as long as it lives, so a device
/// keeps its history in its store instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryHistory {
    seen: BTreeSet<MessageId>,
    senders: BTreeMap<u32, SenderLog>,
    epoch_ends: BTreeMap<u64, Timestamp>,
    pseudonyms: BTreeMap<u64, EpochPseudonyms>,
    moves: Vec<Moved>,
}

impl MemoryHistory {
    /// Sets the mailboxes the group moved away from that the device still
    /// follows ([`MessageHistory::moves`]).
    pub fn set_moves(&mut self, moves: Vec<Moved>) {
        self.moves = moves;
    }
}

impl MessageHistory for MemoryHistory {
    fn seen(&self, id: &MessageId) -> bool {
        self.seen.contains(id)
    }

    fn add_seen(&mut self, id: MessageId) {
        self.seen.insert(id);
    }

    fn sender(&self, leaf: LeafNodeIndex) -> SenderLog {
        self.senders.get(&leaf.u32()).cloned().unwrap_or_default()
    }

    fn set_sender(&mut self, leaf: LeafNodeIndex, log: SenderLog) {
        self.senders.insert(leaf.u32(), log);
    }

    fn epoch_end(&self, epoch: u64) -> Option<Timestamp> {
        self.epoch_ends.get(&epoch).copied()
    }

    fn set_epoch_end(&mut self, epoch: u64, t: Timestamp) {
        self.epoch_ends.insert(epoch, t);
        // Only the last few are ever needed (MAX_PAST_EPOCHS), and those
        // of the moves followed.
        let kept = moved_epochs(&self.moves);
        let oldest = epoch.saturating_sub(16);
        self.epoch_ends
            .retain(|e, _| *e >= oldest || kept.contains(e));
    }

    fn epoch_pseudonym(&self, epoch: u64, leaf: LeafNodeIndex) -> Option<Pseudonym> {
        self.pseudonyms.get(&epoch)?.of(leaf.u32())
    }

    fn set_epoch_pseudonyms(&mut self, pseudonyms: EpochPseudonyms) {
        // Messages of at most MAX_PAST_EPOCHS past epochs are read (12.9).
        let oldest = pseudonyms.epoch.saturating_sub(MAX_PAST_EPOCHS - 1);
        let kept = moved_epochs(&self.moves);
        self.pseudonyms.insert(pseudonyms.epoch, pseudonyms);
        self.pseudonyms
            .retain(|epoch, _| *epoch >= oldest || kept.contains(epoch));
    }

    fn moves(&self) -> Vec<Moved> {
        self.moves.clone()
    }
}

/// The leaves a commit removes: by Remove, and by SelfRemove (12.6, 12.7),
/// for [`MessageHistory::note_commit`]. For a commit of this device's own,
/// pass [`MlsGroup::pending_commit`] before merging it.
pub fn removed_leaves(staged: &StagedCommit) -> Vec<LeafNodeIndex> {
    staged
        .queued_proposals()
        .filter_map(|queued| match (queued.proposal(), queued.sender()) {
            (Proposal::Remove(remove), _) => Some(remove.removed()),
            (Proposal::SelfRemove, Sender::Member(index)) => Some(*index),
            _ => None,
        })
        .collect()
}

/// Notes the SelfRemoves pending in `group` in their senders' logs (12.9):
/// their messages are not shown from now on. [`receive`] does this itself;
/// call it also after processing a SelfRemove.
pub fn note_self_removes(group: &MlsGroup, history: &mut impl MessageHistory) {
    let leaving: Vec<LeafNodeIndex> = group
        .pending_proposals()
        .filter_map(|queued| match (queued.proposal(), queued.sender()) {
            (Proposal::SelfRemove, Sender::Member(index)) => Some(*index),
            _ => None,
        })
        .collect();
    for leaf in leaving {
        let mut log = history.sender(leaf);
        if !log.left {
            log.left = true;
            history.set_sender(leaf, log);
        }
    }
}

// ---------------------------------------------------------------------------
// Past epochs and skipped messages

fn within(a: Timestamp, b: Timestamp, limit: Duration) -> bool {
    a.saturating_duration_since(b) <= limit && b.saturating_duration_since(a) <= limit
}

/// Whether a message of `epoch` may be decrypted by a device whose newest
/// applied epoch is `current`, in a post whose `t` is `t`, where `ended` is
/// the `t` of the commit that ended `epoch` (12.9): at most two epochs
/// behind, and within an hour of that commit. A message of the current
/// epoch always may; one whose epoch's end is unknown may not.
pub fn past_epoch_readable(
    epoch: u64,
    current: u64,
    t: Timestamp,
    ended: Option<Timestamp>,
) -> bool {
    if epoch >= current {
        return true;
    }
    current - epoch <= MAX_PAST_EPOCHS && ended.is_some_and(|end| within(t, end, PAST_EPOCH_WINDOW))
}

/// Deletes the secrets of every past epoch that a post with `t` puts past
/// the limits of 12.9, with the keys kept for its skipped messages. Call it
/// after applying each post, of any kind; [`receive`] calls it itself.
/// `as_of` is [`PostInfo::as_of`]: for a post in a mailbox the group moved
/// away from, the epoch the move created.
///
/// So a device holds the secrets of at most 2 past epochs, and of none for
/// more than an hour after the commit that ended it, besides those of the
/// mailboxes the group moved away from ([`MessageHistory::moves`]). Those
/// are judged by their own mailbox's order alone, as of the move: only a
/// post there deletes them, by the same limits counted from the move, or a
/// catch-up there ([`expire_past_epochs_caught_up`]), and otherwise they go
/// once the device stops following the mailbox (12.9).
/// So every device decides alike whether it can read a late post there,
/// whatever it applied in the new mailbox first.
pub fn expire_past_epochs<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    history: &impl MessageHistory,
    t: Timestamp,
    as_of: Option<u64>,
) -> Result<(), GroupError<P::StorageError>> {
    let moves = history.moves();
    if let Some(moved) = as_of {
        let theirs: BTreeSet<u64> = moves
            .iter()
            .filter(|m| m.to == moved)
            .flat_map(Moved::epochs)
            .collect();
        return keep_past_epochs(provider, group, &moves, |epoch| {
            !theirs.contains(&epoch)
                || past_epoch_readable(epoch, moved, t, history.epoch_end(epoch))
        });
    }
    let current = group.epoch().as_u64();
    let kept = moved_epochs(&moves);
    // Past epochs end in order, so the ones to keep are the newest `keep`.
    let mut keep = 0;
    for back in 1..=MAX_PAST_EPOCHS {
        let Some(epoch) = current.checked_sub(back) else {
            break;
        };
        if !past_epoch_readable(epoch, current, t, history.epoch_end(epoch)) {
            break;
        }
        keep = back;
    }
    keep_past_epochs(provider, group, &moves, |epoch| {
        epoch + keep >= current || kept.contains(&epoch)
    })
}

/// Keeps the secrets of the past epochs of `group` for which `keep` is
/// true, with their skipped messages' keys, and deletes the rest. While
/// `moves` keep epochs, the group may hold that many more past epochs, and
/// one besides: merging a commit adds the epoch it ended before the device
/// expires past epochs again, and OpenMLS would push the oldest out, the
/// moves' own.
fn keep_past_epochs<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    moves: &[Moved],
    keep: impl FnMut(u64) -> bool,
) -> Result<(), GroupError<P::StorageError>> {
    group
        .retain_past_epoch_secrets(provider, keep)
        .map_err(|e| GroupError::Mls(e.to_string()))?;
    let kept = moved_epochs(moves).len();
    let max = if kept == 0 {
        group::MAX_PAST_EPOCHS
    } else {
        group::MAX_PAST_EPOCHS + 1 + kept
    };
    let policy = PastEpochDeletionPolicy::MaxEpochs(max);
    if *group.past_epoch_deletion_policy() != policy {
        group
            .set_past_epoch_deletion_policy(provider, policy)
            .map_err(|e| GroupError::Mls(e.to_string()))?;
    }
    Ok(())
}

/// A mailbox of the group that the device follows, for the 2-hour limit
/// on past epochs (12.9): which epochs' messages a post there may carry,
/// and as of which server time the device last caught it up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Followed {
    /// The epochs whose messages a post in the mailbox may carry: from its
    /// first epoch, the epoch of the move to it or 0, up to the epoch that
    /// the move away from it created, or on for the current mailbox (7.8).
    pub epochs: Range<u64>,
    /// The newest server time the device knew (posts' `t`, PING) when it
    /// sent a FOLLOW or FETCH of the mailbox, after whose reply it had
    /// applied every post the reply showed, up to the server's newest:
    /// every post there it has not applied was accepted later. `None` if it
    /// has not caught the mailbox up so.
    pub caught_up: Option<Timestamp>,
}

/// Deletes the secrets of every past epoch that the 2-hour limit of 12.9
/// puts past, with the keys kept for its skipped messages: an epoch goes
/// once, in every mailbox in `followed` that may carry its messages, the
/// device caught up as of a server time more than 2 hours after the `t` of
/// the commit that ended it. Any post there that the device has not
/// applied was then accepted more than an hour after that commit, so the
/// limits of [`expire_past_epochs`] make it unreadable on every device:
/// deleting the secrets changes what no device shows. An epoch that no
/// mailbox in `followed` may carry any more, such as an old mailbox's last
/// epochs once the device stops following it (7.8), goes at once, and so
/// does one whose ending commit's `t` the device does not know.
///
/// Call it each time the device has caught up one of the group's
/// mailboxes, and once it stops following one. The device's own clock
/// plays no part, so every device decides alike, however long it was
/// offline (12.9).
///
/// Returns the indices into `followed` of the mailboxes whose catch-up as
/// of `server_time`, the newest server time the device knows, would delete
/// an epoch they keep: the device fetches them again, so that the limit
/// holds while a FOLLOW stays open with nothing new.
pub fn expire_past_epochs_caught_up<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    history: &impl MessageHistory,
    followed: &[Followed],
    server_time: Option<Timestamp>,
) -> Result<BTreeSet<usize>, GroupError<P::StorageError>> {
    let moves = history.moves();
    let mut stale = BTreeSet::new();
    keep_past_epochs(provider, group, &moves, |epoch| {
        let Some(end) = history.epoch_end(epoch) else {
            return false;
        };
        let past = |at: Option<Timestamp>| {
            at.is_some_and(|at| at.saturating_duration_since(end) > PAST_EPOCH_KEEP)
        };
        let mut keep = false;
        for (i, f) in followed.iter().enumerate() {
            if !f.epochs.contains(&epoch) || past(f.caught_up) {
                continue;
            }
            keep = true;
            if past(server_time) {
                stale.insert(i);
            }
        }
        keep
    })?;
    Ok(stale)
}

// ---------------------------------------------------------------------------
// Receiving

/// What the device knows of a post besides its message (5.2): its `t`,
/// whether it came with `live=yes`, and whether it is in a mailbox the
/// group moved away from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostInfo {
    /// The post's `t`.
    pub t: Timestamp,
    /// Whether it is a live post.
    pub live: bool,
    /// For a post in a mailbox the group moved away from, the epoch the
    /// move created. Such a post and a commit in the new mailbox have no
    /// common order, so the post is judged by its own mailbox's order
    /// alone, as of the move (7.8, 12.9): a commit after the move did not
    /// remove its sender.
    pub as_of: Option<u64>,
}

/// The pseudonym check (7.3, 12.9 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudonymCheck {
    /// Outside public rooms: it is the one derived for the leaf from the
    /// message's epoch.
    Derived,
    /// In a public room: it is the leaf's pinned pseudonym.
    Pinned,
    /// In a public room, a guest's leaf had none pinned for the period, and
    /// this one is now, from its first message of the period.
    NewlyPinned,
    /// In a public room, an identity's leaf: it is not the pseudonym pinned
    /// for the leaf (or none is), and is pinned only by the leaf's ATTEST
    /// for the current period (7.3, 12.10). The caller shows nothing of the
    /// message unless its content has that ATTEST, valid and carrying this
    /// pseudonym, and then pins it with [`MessageHistory::pin`].
    NeedsAttest(Pseudonym),
}

/// Checks `pseudonym`, from a PrivateMessage of a public room's leaf whose
/// log is `log`, posted in `period` (12.10), against its pin (7.3, 12.9
/// step 1). `guest` says whether the leaf is a guest's, which never
/// attests, and so is pinned by its first message of each period. `None`
/// if the device ignores the message: a guest's, under another pseudonym
/// than the one pinned for the period.
///
/// Outside public rooms pseudonyms are derived for each epoch, and checked
/// as [`receive`] does, never pinned.
pub fn check_pseudonym(
    log: &SenderLog,
    pseudonym: Pseudonym,
    guest: bool,
    period: u64,
) -> Option<PseudonymCheck> {
    match log.pseudonym {
        Some(pinned) if pinned == pseudonym && (!guest || log.pin_period == Some(period)) => {
            Some(PseudonymCheck::Pinned)
        }
        _ if !guest => Some(PseudonymCheck::NeedsAttest(pseudonym)),
        Some(_) if log.pin_period == Some(period) => None,
        _ => Some(PseudonymCheck::NewlyPinned),
    }
}

/// Where a message falls among its sender's (12.9 step 4, 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// The first of the leaf's messages the device has seen; `earlier` of
    /// the leaf's messages came before it, sent before the device joined
    /// or not received.
    First {
        /// How many.
        earlier: u64,
    },
    /// The message after the leaf's previous one.
    Next,
    /// A gap: `missing` of the leaf's messages, between its last one and
    /// this one, have not arrived. Retention may explain it, or a transfer
    /// fill it (12.13); otherwise, the server held them back (7.4).
    Gap {
        /// How many.
        missing: u64,
    },
    /// One of the messages a gap was missing, arriving late: sent again
    /// after its first post failed (7.6), or held back.
    Late,
    /// `counter` and `previous` do not agree with the leaf's earlier
    /// messages: a counter seen before, or `previous` not the id of the
    /// message before. The sender's device is faulty or lying.
    Inconsistent,
    /// A live message, which does not count.
    Live,
}

/// The time check (12.9 step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clock {
    /// The sender's time is within 10 minutes of the post's `t`.
    Agrees,
    /// It is not: the device shows the sender's time with a mark that the
    /// times disagree.
    Disagrees,
}

/// How a message is shown (12.9 step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// The sender's leaf is confirmed (12.10).
    Verified,
    /// It is not.
    Unverified,
    /// Not at all yet: the pseudonym needs the leaf's ATTEST
    /// ([`PseudonymCheck::NeedsAttest`]).
    Withheld,
}

/// A message that passed the checks of 12.9 steps 1 to 3.
#[derive(Debug)]
pub struct Decrypted {
    /// The sending leaf.
    pub sender: LeafNodeIndex,
    /// Its credential.
    pub identity: RisalaIdentity,
    /// The epoch the message was sent in. A line that depends on a role
    /// counts only if the sender has the role in this epoch's extension
    /// and in the current one (12.9, [`may_delete`]).
    pub epoch: u64,
    /// The message.
    pub message: RisalaMessage,
    /// Step 1.
    pub pseudonym: PseudonymCheck,
    /// Step 4.
    pub order: Order,
    /// Step 5.
    pub clock: Clock,
}

impl Decrypted {
    /// How to show the message (step 6), given whether the sender's leaf is
    /// confirmed (12.10, task M3).
    pub fn trust(&self, leaf_confirmed: bool) -> Trust {
        match (self.pseudonym, leaf_confirmed) {
            (PseudonymCheck::NeedsAttest(_), _) => Trust::Withheld,
            (_, true) => Trust::Verified,
            (_, false) => Trust::Unverified,
        }
    }

    /// Where the message's lines arrive, for [`Content::allowed`]: the
    /// conversation, whether it is live, and whether the sender is a guest.
    pub fn place(&self, conversation: &RisalaConversation) -> Place {
        Place {
            conversation: line_conversation(conversation),
            live: self.message.is_live(),
            guest: self.identity.is_guest(),
        }
    }
}

/// The conversation a group is, as the content lines see it (12.9).
pub fn line_conversation(conversation: &RisalaConversation) -> Conversation {
    match conversation.kind {
        ConversationKind::Direct => match conversation.direct_participants() {
            Some(uids) if uids.len() == 1 => Conversation::WithYourself,
            _ => Conversation::Direct,
        },
        ConversationKind::PrivateRoom => Conversation::PrivateRoom(match conversation.confirm {
            ConfirmMode::Pairwise => LineConfirmMode::Pairwise,
            ConfirmMode::Epochal => LineConfirmMode::Epochal,
        }),
        ConversationKind::PublicRoom => Conversation::PublicRoom,
    }
}

/// Why a message is not shown. Devices MUST NOT show its content, and MAY
/// show that a message could not be read (12.9).
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError<E> {
    /// The post is not an application message: process it with
    /// [`group::process_message`].
    #[error("not an application message")]
    NotApplication,
    /// Its epoch is past the limits of 12.9: shown as unreadable.
    #[error("the message's epoch is too old")]
    TooOld,
    /// MLS rejected it: a future epoch, a key already used or deleted, a
    /// generation too far ahead or behind, or a bad signature.
    #[error(transparent)]
    Process(ProcessError<E>),
    /// This device's own message.
    #[error("this device's own message")]
    Own,
    /// The sending leaf was removed by a commit with a lower seq (12.9).
    #[error("the sender's leaf was removed")]
    Removed,
    /// The sender's credential is not a RisalaIdentity.
    #[error("the sender's credential is not a RisalaIdentity")]
    Identity,
    /// Not a RisalaMessage.
    #[error(transparent)]
    Malformed(MessageError),
    /// Step 1: not the leaf's pseudonym for the message's epoch, or in a
    /// public room, not the one pinned for it.
    #[error("not the leaf's pseudonym")]
    Pseudonym,
    /// Step 2: the frank does not match the content.
    #[error("the frank does not match")]
    Frank,
    /// Step 3: the `message_id` was seen before in the group. A message
    /// sent twice shows once (7.6).
    #[error("a message seen before")]
    Duplicate,
    /// `counter` and `previous` do not fit how it was posted: a live post
    /// with a counter, or a stored one without (12.9, 5.2).
    #[error("the counter does not fit a live or stored post")]
    Live,
    /// The leaf has posted a SelfRemove (12.9).
    #[error("the sender has left")]
    Left,
    /// Storage failed.
    #[error("storage: {0:?}")]
    Storage(E),
}

impl<E: fmt::Debug> From<GroupError<E>> for ReceiveError<E> {
    fn from(e: GroupError<E>) -> ReceiveError<E> {
        match e {
            GroupError::Storage(e) => ReceiveError::Storage(e),
            other => ReceiveError::Process(ProcessError::Mls(other.to_string())),
        }
    }
}

/// Receives the application message in `post` (12.9), which the caller
/// applies in seq order (7.2). See the [module documentation](self).
///
/// On success, the history has the message: its id, the leaf's counters
/// and, in a pairwise group, its pin. On an error it is unchanged, except
/// that past-epoch secrets are expired and SelfRemoves noted, which every
/// post does.
pub fn receive<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    post: &[u8],
    info: PostInfo,
    history: &mut impl MessageHistory,
) -> Result<Decrypted, ReceiveError<P::StorageError>> {
    let (framing, _) =
        read_post(post).map_err(|e| ReceiveError::Process(ProcessError::Mls(e.to_string())))?;
    if framing.content_type != ContentType::Application {
        return Err(ReceiveError::NotApplication);
    }
    let epoch = framing.epoch;
    // Live posts have no seq and reach only the devices online, so only
    // stored posts move the limits, which every device must reach alike.
    if !info.live {
        expire_past_epochs(provider, group, history, info.t, info.as_of)?;
    }
    note_self_removes(group, history);
    let current = group.epoch().as_u64();
    // 12.9: after a move, judged as of the move.
    let applied = info.as_of.map_or(current, |moved| moved.min(current));
    if !past_epoch_readable(epoch, applied, info.t, history.epoch_end(epoch)) {
        return Err(ReceiveError::TooOld);
    }
    let public = group::conversation(group)
        .ok_or(ReceiveError::Process(ProcessError::Group))?
        .kind
        == ConversationKind::PublicRoom;

    // MLS decrypts it, checks its signature, and deletes its key.
    let (sender, credential, aad, content) = match group::process_message(provider, group, post) {
        Ok(Incoming::Application {
            sender,
            credential,
            aad,
            content,
        }) => (sender, credential, aad, Zeroizing::new(content)),
        Ok(Incoming::Own) => return Err(ReceiveError::Own),
        Ok(_) => return Err(ReceiveError::NotApplication),
        Err(e) => return Err(ReceiveError::Process(e)),
    };

    // A leaf that a commit with a lower seq removed: even its messages of
    // earlier epochs are ignored (12.9, late messages). As of a move, only
    // a commit before it counts, even if the index was used again and
    // removed again since; a leaf's log that a later one started again is
    // not this message's, and is left alone (7.8).
    let mut log = history.sender(sender);
    let removed = match info.as_of {
        Some(moved) => log.removed_before(moved),
        None => log.removed_in(),
    };
    if removed.is_some_and(|removed| epoch <= removed) {
        return Err(ReceiveError::Removed);
    }
    let removed_later = info
        .as_of
        .is_some_and(|moved| log.removed_in().is_some_and(|removed| removed >= moved));
    // The sender as of the message's epoch: after a move, the leaf may
    // have gone from the tree since, or another taken its place.
    let identity = if info.as_of.is_some() {
        RisalaIdentity::from_credential(&credential)
    } else {
        let leaf = group::leaf(group, sender).ok_or(ReceiveError::Removed)?;
        RisalaIdentity::from_credential(leaf.credential())
    }
    .map_err(|_| ReceiveError::Identity)?;
    let message = RisalaMessage::decode(&content).map_err(ReceiveError::Malformed)?;

    // Step 1. An application message is a PrivateMessage, whose RisalaAAD
    // always has a pseudonym (12.9). Outside public rooms it is derived
    // from the message's epoch (7.3): the group's current one, or one the
    // device kept from an epoch that has ended.
    let aad_pseudonym = aad.pseudonym.ok_or(ReceiveError::Pseudonym)?;
    let period = info.t.unix_millis() / PERIOD_MS;
    let pseudonym = if public {
        check_pseudonym(&log, aad_pseudonym, identity.is_guest(), period)
            .ok_or(ReceiveError::Pseudonym)?
    } else {
        let expected = if epoch == current {
            Some(group::leaf_pseudonym::<P::StorageError>(
                group,
                provider.crypto(),
                sender,
            )?)
        } else {
            history.epoch_pseudonym(epoch, sender)
        };
        if expected != Some(aad_pseudonym) {
            return Err(ReceiveError::Pseudonym);
        }
        PseudonymCheck::Derived
    };
    // Step 2. Never skipped: it is what makes the message key-committing.
    let frank = aad.frank.ok_or(ReceiveError::Frank)?;
    if !message
        .frank_key
        .matches(message.content.as_bytes(), &frank)
    {
        return Err(ReceiveError::Frank);
    }
    // Step 3.
    if history.seen(&message.message_id) {
        return Err(ReceiveError::Duplicate);
    }
    if log.left {
        return Err(ReceiveError::Left);
    }
    // Step 4.
    if info.live != message.is_live() || (message.is_live() && message.previous.is_some()) {
        return Err(ReceiveError::Live);
    }
    let order = if message.is_live() {
        Order::Live
    } else if removed_later {
        Order::Late
    } else {
        log.order(message.counter, message.previous, message.message_id)
    };
    // Step 5.
    let clock = match message.timestamp() {
        Some(time) if within(time, info.t, MAX_CLOCK_DIFFERENCE) => Clock::Agrees,
        _ => Clock::Disagrees,
    };

    if pseudonym == PseudonymCheck::NewlyPinned {
        log.pseudonym = Some(aad_pseudonym);
        log.pin_period = Some(period);
    }
    if !removed_later {
        history.set_sender(sender, log);
    }
    history.add_seen(message.message_id);
    Ok(Decrypted {
        sender,
        identity,
        epoch,
        message,
        pseudonym,
        order,
        clock,
    })
}

impl SenderLog {
    /// Places a stored message with `counter` and `previous` among the
    /// leaf's earlier ones, and remembers it (12.9 step 4, 7.4).
    fn order(&mut self, counter: u64, previous: Option<MessageId>, id: MessageId) -> Order {
        // The first message has no previous one, and every later one has.
        if (counter == 1) != previous.is_none() {
            self.advance(counter, id);
            return Order::Inconsistent;
        }
        let Some((last, last_id)) = self.last else {
            self.last = Some((counter, id));
            if counter > 1 {
                self.add_gap(1, counter - 1);
            }
            return Order::First {
                earlier: counter - 1,
            };
        };
        if counter > last {
            self.last = Some((counter, id));
            if counter == last + 1 {
                if previous == Some(last_id) {
                    Order::Next
                } else {
                    Order::Inconsistent
                }
            } else {
                self.add_gap(last + 1, counter - 1);
                Order::Gap {
                    missing: counter - last - 1,
                }
            }
        } else if self.fill(counter) {
            Order::Late
        } else {
            Order::Inconsistent
        }
    }

    fn advance(&mut self, counter: u64, id: MessageId) {
        match self.last {
            Some((last, _)) if last >= counter => {
                self.fill(counter);
            }
            Some((last, _)) => {
                if counter > last + 1 {
                    self.add_gap(last + 1, counter - 1);
                }
                self.last = Some((counter, id));
            }
            None => self.last = Some((counter, id)),
        }
    }

    fn add_gap(&mut self, from: u64, to: u64) {
        self.gaps.push((from, to));
        if self.gaps.len() > MAX_GAPS {
            self.gaps.remove(0);
        }
    }

    /// Removes `counter` from the gaps, if it is in one.
    fn fill(&mut self, counter: u64) -> bool {
        let Some(i) = self
            .gaps
            .iter()
            .position(|&(from, to)| from <= counter && counter <= to)
        else {
            return false;
        };
        let (from, to) = self.gaps[i];
        let mut parts = Vec::with_capacity(2);
        if from < counter {
            parts.push((from, counter - 1));
        }
        if counter < to {
            parts.push((counter + 1, to));
        }
        self.gaps.splice(i..=i, parts);
        true
    }
}

// ---------------------------------------------------------------------------
// Deletes (5.4)

/// Whether a device acts on a DELETE from `sender` of a message by
/// `author` (5.4): the author's own devices may delete it, and in a room,
/// an owner or moderator, both in `at_epoch`, the extension of the
/// DELETE's epoch, and in `at_seq`, that of the newest epoch the device
/// has applied at its seq (12.9).
pub fn may_delete(
    sender: &Uid,
    author: &Uid,
    at_epoch: &RisalaConversation,
    at_seq: &RisalaConversation,
) -> bool {
    if sender == author {
        return true;
    }
    let moderates = |conversation: &RisalaConversation| {
        conversation.kind != ConversationKind::Direct
            && matches!(conversation.role(sender), Role::Owner | Role::Mod)
    };
    moderates(at_epoch) && moderates(at_seq)
}

// ---------------------------------------------------------------------------
// Reports to operators (5.8)

/// A post named in a report (5.8).
#[derive(Clone, PartialEq, Eq)]
pub struct ReportedPost {
    /// The post's seq in the mailbox.
    pub seq: u64,
    /// The RisalaMessage's frank key.
    pub frank_key: FrankKey,
    /// The RisalaMessage's content, exactly.
    pub content: Vec<u8>,
}

impl ReportedPost {
    /// The post at `seq` whose message is `message`.
    pub fn of(seq: u64, message: &RisalaMessage) -> ReportedPost {
        ReportedPost {
            seq,
            frank_key: message.frank_key.clone(),
            content: message.content.as_bytes().to_vec(),
        }
    }

    /// Whether `frank`, from the post's RisalaAAD, is the frank of the
    /// content under the frank key, compared in constant time (5.8).
    pub fn matches(&self, frank: &[u8; FRANK_LEN]) -> bool {
        self.frank_key.matches(&self.content, frank)
    }

    fn write(&self, w: &mut Writer) {
        w.u64(self.seq)
            .fixed(&self.frank_key.as_bytes()[..])
            .vector(&self.content);
    }

    fn read(r: &mut Reader<'_>) -> Result<ReportedPost, DecodeError> {
        let seq = r.u64()?;
        let frank_key = FrankKey::from_bytes(r.array()?);
        let content = r.vector()?;
        if content.len() > MAX_CONTENT_LEN {
            return Err(DecodeError("reported content longer than 4 MiB"));
        }
        Ok(ReportedPost {
            seq,
            frank_key,
            content: content.to_vec(),
        })
    }
}

impl fmt::Debug for ReportedPost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReportedPost")
            .field("seq", &self.seq)
            .field("content", &String::from_utf8_lossy(&self.content))
            .finish_non_exhaustive()
    }
}

/// A report to a server's operators (5.8): `REPORT <box> <report>`.
///
/// ```text
/// struct {
///     uint64 seq;              // the post's seq in the mailbox
///     opaque frank_key[32];
///     opaque content<V>;       // the RisalaMessage's content
/// } ReportedPost;
///
/// struct {
///     uint8 version;           // 1
///     ReportedPost target;
///     ReportedPost context<V>; // up to 10 earlier posts, oldest first
///     opaque author<V>;        // the uid the reporter says wrote the target
///     opaque reason<V>;        // UTF-8, at most 512 bytes
/// } RisalaReport;
/// ```
///
/// Its franks prove what the posts said. They do not prove who wrote
/// them: `author` is the reporter's claim, and nothing in it can show an
/// operator otherwise, by design (12.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RisalaReport {
    /// The reported post.
    pub target: ReportedPost,
    /// Up to 10 earlier posts, oldest first.
    pub context: Vec<ReportedPost>,
    /// The uid the reporter says wrote the target.
    pub author: Uid,
    /// Why, in at most 512 bytes.
    pub reason: String,
}

/// Why a report is refused (5.8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// Not one RisalaReport of version 1: `ERR invalid`.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
    /// Too many context posts, seqs out of order, an author that is not a
    /// uid, or a reason that is not UTF-8 of at most 512 bytes:
    /// `ERR invalid`.
    #[error("the report is invalid: {0}")]
    Invalid(&'static str),
    /// A post it names is not kept in the mailbox: `ERR not-found`.
    #[error("post {0} is not kept")]
    NotFound(u64),
    /// A post it names is not an application message, or its frank does
    /// not match the content and frank key: `ERR invalid`.
    #[error("post {0} does not match its frank")]
    Frank(u64),
}

impl RisalaReport {
    /// Checks the report's own rules (5.8): at most 10 context posts, with
    /// seqs strictly increasing and each lower than the target's, and a
    /// reason of at most 512 bytes.
    pub fn check(&self) -> Result<(), ReportError> {
        if self.context.len() > MAX_REPORT_CONTEXT {
            return Err(ReportError::Invalid("more than 10 context posts"));
        }
        let seqs: Vec<u64> = self.context.iter().map(|post| post.seq).collect();
        if seqs.windows(2).any(|pair| pair[0] >= pair[1])
            || seqs.last().is_some_and(|&last| last >= self.target.seq)
        {
            return Err(ReportError::Invalid("context seqs out of order"));
        }
        if self.reason.len() > MAX_REASON_LEN {
            return Err(ReportError::Invalid("a reason longer than 512 bytes"));
        }
        Ok(())
    }

    /// The posts the report names: the target, then the context.
    pub fn posts(&self) -> impl Iterator<Item = &ReportedPost> {
        std::iter::once(&self.target).chain(&self.context)
    }

    /// The encoded RisalaReport.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(VERSION);
        self.target.write(&mut w);
        let mut context = Writer::new();
        for post in &self.context {
            post.write(&mut context);
        }
        w.vector(&context.into_bytes())
            .vector(self.author.as_str().as_bytes())
            .vector(self.reason.as_bytes());
        w.into_bytes()
    }

    /// Reads exactly one RisalaReport of version 1, and checks it
    /// ([`RisalaReport::check`]).
    pub fn decode(bytes: &[u8]) -> Result<RisalaReport, ReportError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(DecodeError("unknown RisalaReport version").into());
        }
        let target = ReportedPost::read(&mut r)?;
        let mut context_bytes = Reader::new(r.vector()?);
        let mut context = Vec::new();
        while context_bytes.remaining() > 0 {
            if context.len() == MAX_REPORT_CONTEXT {
                return Err(ReportError::Invalid("more than 10 context posts"));
            }
            context.push(ReportedPost::read(&mut context_bytes)?);
        }
        let author = std::str::from_utf8(r.vector()?)
            .ok()
            .and_then(|s| s.parse::<Uid>().ok())
            .ok_or(ReportError::Invalid("an author that is not a uid"))?;
        let reason = String::from_utf8(r.vector()?.to_vec())
            .map_err(|_| ReportError::Invalid("a reason that is not UTF-8"))?;
        r.finish()?;
        let report = RisalaReport {
            target,
            context,
            author,
            reason,
        };
        report.check()?;
        Ok(report)
    }
}

/// What a server checks of a report (5.8), and what an operator can rely
/// on: every post it names is kept in the mailbox (`post` gives a stored
/// post's message by seq) and is an application message, and its
/// RisalaAAD's frank is the frank of the reported content under the
/// reported frank key, compared in constant time. With
/// [`RisalaReport::check`], which [`RisalaReport::decode`] has made.
///
/// So the content is what was posted. Who wrote it is not proven.
pub fn verify_report<B: AsRef<[u8]>>(
    report: &RisalaReport,
    mut post: impl FnMut(u64) -> Option<B>,
) -> Result<(), ReportError> {
    report.check()?;
    for reported in report.posts() {
        let stored = post(reported.seq).ok_or(ReportError::NotFound(reported.seq))?;
        let frank = match read_post(stored.as_ref()) {
            Ok((framing, aad)) if framing.content_type == ContentType::Application => aad.frank,
            _ => None,
        };
        if !frank.is_some_and(|frank| reported.matches(&frank)) {
            return Err(ReportError::Frank(reported.seq));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

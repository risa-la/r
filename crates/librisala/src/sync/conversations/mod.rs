//! The group engine (5-8, 12.4-12.9): FOLLOW and FETCH on anonymous
//! connections and the sync points of 7.4, posting with send tokens and
//! pseudonyms, the first valid commit of each epoch (7.2), Welcomes and
//! KeyPackages, membership, roles, profiles, typing, read markers, blocks,
//! deletes and gaps.
//!
//! Owned by task C2 in docs/plans/M5b.md.
//!
//! # Shape
//!
//! [`ConversationEngine`] is sans-I/O, like every engine ([`super`]). What
//! must last is in the cache: conversations, mailboxes and sync points,
//! posts waiting to be applied, the outbox, Welcomes waiting to be sent.
//! What it keeps in memory only lives as long as a connection: which
//! mailboxes are followed on which connection, commands in flight, jobs
//! waiting for KeyPackages, and random waits.
//!
//! - **Receiving.** Posts are kept, then applied in seq order once every
//!   earlier one is ([`group::apply_post`]); the sync point moves only
//!   forward (7.4).
//! - **Sending.** Everything to post goes through the outbox. A
//!   conversation posts only once its mailbox is followed and caught up,
//!   and while one of its commits is pending it posts nothing else: a
//!   commit is made from its intent just before it is posted, and if it
//!   loses its epoch, it is made again (7.2). Messages are kept as
//!   RisalaMessages and encrypted afresh in the current epoch each time
//!   they are posted (12.9).
//! - **Jobs.** Starting a conversation or inviting someone needs
//!   KeyPackages first (KEYPKG GET, one fresh anonymous connection per
//!   identity). [`ConversationEngine::start`] begins a [`Job`]; its end
//!   is reported as [`ConversationEvent::JobDone`].
//!
//! # Seams
//!
//! [`Hooks`] is what the engine needs from other areas: the device key and
//! key facts (task C1), whether a leaf is confirmed and the lines of leaf
//! confirmation (task C3), and the lines of transfers and reports (task
//! C4). [`content::queue_lines`] is how those areas send lines.

pub(crate) mod content;
pub(crate) mod group;
mod keycheck;
pub(crate) mod public;
mod recovery;
mod rooms;
mod upkeep;
pub(crate) mod wire;

use recovery::may_replace;

#[cfg(test)]
pub(crate) mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use risala_mls::RisalaCrypto;
use risala_mls::checks::{Fact, KeyFacts};
use risala_mls::conversation::RisalaConversation;
use risala_mls::identity::DeviceId;
use risala_mls::mldsa::SigningKey;
use risala_proto::command::{Command, CreateForm, KeyPkgCommand, WelcomeCommand};
use risala_proto::connection::ConnectionKind;
use risala_proto::content::ContentLine;
use risala_proto::error::ErrorCode;
use risala_proto::mls::{
    GroupId, KeyPackage as KeyPackageText, KeyPackageRef as RefText, MlsMessage, OrBlob, PostToken,
    PutSecret, SendToken as SendTokenText, TokenHash, Welcome as WelcomeText, WelcomeSecret,
};
use risala_proto::names::{BlobRef, BoxName, Room, Uid};
use risala_proto::server::{Post, ServerLine, ServerMessage};

use super::{Action, Context, Engine, Input, Target, Token};
use crate::client::Event;
use crate::client::conversations::ConversationEvent;
use crate::clock::{Clock, SystemClock};
use crate::conn::{End, Response, SingleUse, Slot};
use crate::store::conversations::{ConvKind, ConvRow, ConvState, ConversationId, LeafRow, PostRow};
use crate::store::messages::{OutboxKind, OutboxRow, OutboxState};
use crate::store::{AccountId, AccountKind, Change, StoreError, Tx};

use wire::Intent;

/// How long a device keeps following a mailbox its group moved away from
/// (7.8): a day.
pub(crate) const OLD_MAILBOX_MS: u64 = 24 * 60 * 60 * 1000;

/// The slot of a connection of its own ([`Target::Own`]), in the
/// [`Input::Reply`] of its command. Such connections have no slot of
/// their own.
pub const SINGLE_USE_SLOT: Slot = Slot::Anonymous(usize::MAX);

/// How many Welcomes in blobs wait for their blob at once (LR-M5).
const MAX_WELCOME_BLOBS: usize = 4;

/// How many queued messages a conversation posts at once.
const POST_BATCH: usize = 16;

/// The group engine's settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// The longest random wait before following a mailbox learned from a
    /// Welcome (7.4): 10 minutes.
    pub max_follow_wait_ms: u64,
    /// The longest random wait before sending a Welcome (12.8): 10
    /// minutes.
    pub max_welcome_wait_ms: u64,
    /// The longest random wait before committing pending proposals, or
    /// replacing a leaf that asked with RESYNC (6.1, 12.7): 10 minutes.
    pub max_commit_wait_ms: u64,
    /// The most posts a FETCH starts before the sync point (7.4): 20.
    pub fetch_jitter: u64,
    /// How many ordinary KeyPackages to keep on the server (12.5): 10.
    pub key_packages: u64,
    /// Below how many to upload more (12.5): 5.
    pub key_packages_low: u64,
    /// How long to wait before posting again after a failure.
    pub retry_ms: u64,
    /// How long a leaf may go without a commit of its own before the weekly
    /// fresh-leaf commit (12.7): a week.
    pub refresh_after_ms: u64,
    /// Whether to start the conversation with yourself if the identity has
    /// none, once the signed-in connection is up and its Welcomes are in
    /// (5.1, 12.13).
    pub self_conversation: bool,
    /// How often a join of a public room looks at the room's GroupInfo
    /// when no commit came to prompt it (6.1): 5 minutes. Each commit in
    /// the room prompts a look at once.
    pub join_poll_ms: u64,
    /// The server's retention period (7.5, 8.5), for replacing the own
    /// identity's stale leaves (12.7): 7 days unless INFO says otherwise.
    pub retention_ms: u64,
    /// How long after another member's removal any member moves the
    /// mailbox if nobody has (7.8): 10 minutes, then a random wait of up to
    /// `max_commit_wait_ms`.
    pub move_fallback_ms: u64,
    /// How long a RESYNC may go unanswered before the device asks its own
    /// devices with `RESYNC <box> <seq>` (12.7): an hour.
    pub resync_escalate_ms: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            max_follow_wait_ms: 10 * 60 * 1000,
            max_welcome_wait_ms: 10 * 60 * 1000,
            max_commit_wait_ms: 10 * 60 * 1000,
            fetch_jitter: 20,
            key_packages: 10,
            key_packages_low: 5,
            retry_ms: 5_000,
            refresh_after_ms: risala_mls::checks::REFRESH_AFTER_MS,
            self_conversation: true,
            join_poll_ms: 5 * 60 * 1000,
            retention_ms: 7 * 24 * 60 * 60 * 1000,
            move_fallback_ms: 10 * 60 * 1000,
            resync_escalate_ms: 60 * 60 * 1000,
        }
    }
}

impl Config {
    /// No random waits, for tests.
    pub fn immediate() -> Config {
        Config {
            max_follow_wait_ms: 0,
            max_welcome_wait_ms: 0,
            max_commit_wait_ms: 0,
            retry_ms: 0,
            join_poll_ms: 60_000,
            ..Config::default()
        }
    }
}

/// Facts from key files that nobody can fetch: every fact unknown, so that
/// removals stand and adds stay unconfirmed (12.7). The default until the
/// identity area (task C1) provides its own.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnknownFacts;

impl KeyFacts for UnknownFacts {
    fn current_device_key(&self, _: &Uid, _: &DeviceId) -> Fact<Option<Vec<u8>>> {
        Fact::Unknown
    }

    fn device_removed(&self, _: &Uid, _: &DeviceId) -> Fact<bool> {
        Fact::Unknown
    }

    fn identity_retired(&self, _: &Uid) -> Fact<bool> {
        Fact::Unknown
    }

    fn forked_or_missing(&self, _: &Uid) -> Fact<bool> {
        Fact::Unknown
    }
}

/// What the group engine needs from the other areas. Every method has a
/// default that knows nothing, so the engine runs before they are built.
pub(crate) trait Hooks: Send + Sync {
    /// This device's device key for `uid` (4.3), to make KeyPackages and
    /// bind them (12.3, 12.5), and to name the device in credentials.
    /// `None` for a guest, or until the identity area (C1) provides it.
    /// It is the one hook called outside a transaction of the cache, so it
    /// may read the cache; the engine keeps the key once found.
    fn device_key(&self, account: AccountId, uid: &Uid) -> Option<SigningKey> {
        let _ = (account, uid);
        None
    }

    /// The device key of `uid`'s device `device`, if the device knows:
    /// `Some(Some(key))` for a current, logged device, `Some(None)` for one
    /// that is not, `None` if it cannot tell yet (4.4, 4.5). Task C1.
    fn device_key_of(
        &self,
        tx: &Tx<'_>,
        account: AccountId,
        uid: &Uid,
        device: &DeviceId,
    ) -> Option<Option<Vec<u8>>> {
        let _ = (tx, account, uid, device);
        None
    }

    /// Whether this device starts the conversation with yourself, having
    /// found none (5.1): not while the identity has another current
    /// device, which adds this one to its own (12.7). Task C5.
    fn start_self_conversation(&self, tx: &Tx<'_>, uid: &Uid) -> bool {
        let _ = (tx, uid);
        true
    }

    /// Facts from key files and the key log, for the checks of 12.7. Task
    /// C1.
    fn key_facts<'a>(&'a self, tx: &'a Tx<'_>, account: AccountId) -> Box<dyn KeyFacts + 'a> {
        let _ = (tx, account);
        Box::new(UnknownFacts)
    }

    /// Whether the engine acts on the key checks of 12.7: holds sending
    /// while an added leaf is unchecked, and repairs failed checks (task
    /// R2). Always, except for tests that run without key files.
    fn enforce_key_checks(&self) -> bool {
        true
    }

    /// Whether this device has confirmed a leaf (12.10). Task C3: this is
    /// the seam of leaf confirmation. Until it is built, no leaf is
    /// confirmed: messages show as unverified, and the lines of the
    /// conversation with yourself are ignored, as 12.9 requires.
    fn leaf_confirmed(&self, tx: &Tx<'_>, conv: ConversationId, leaf: &LeafRow) -> bool {
        let _ = (tx, conv, leaf);
        false
    }

    /// A line for another area: CHALLENGE, ANSWER, ATTEST and REVEAL (C3);
    /// RECORD, ALERT, RECORDS, SIGNINGKEY, BACKUPKEY, PIN and SERVERS (C1);
    /// WANT, TRANSFER and REPORT (C4). `leaf` is its sender. The lines of
    /// the conversation with yourself come here only from confirmed
    /// leaves of the own identity (12.9).
    fn content_line(
        &self,
        tx: &mut Tx<'_>,
        conv: ConversationId,
        leaf: &LeafRow,
        line: &ContentLine,
    ) -> Vec<Action> {
        let _ = (tx, conv, leaf, line);
        Vec::new()
    }

    /// A group's leaves changed, after a commit or a join: leaf
    /// confirmation (C3) challenges new leaves here (12.10).
    fn leaves_changed(&self, tx: &mut Tx<'_>, conv: ConversationId) -> Vec<Action> {
        let _ = (tx, conv);
        Vec::new()
    }

    /// A message passed the checks of 12.9 steps 1 to 5, posted with `t`,
    /// from `leaf`: leaf confirmation (C3) acts on its CHALLENGE, ANSWER,
    /// ATTEST and REVEAL lines, and says whether to show it as verified
    /// (step 6).
    #[allow(clippy::too_many_arguments)]
    fn message_received(
        &self,
        tx: &mut Tx<'_>,
        cx: &Ctx<'_>,
        conv: &ConvRow,
        leaf: &LeafRow,
        group: &risala_mls::openmls::group::MlsGroup,
        message: &risala_mls::message::Decrypted,
        t: u64,
    ) -> super::confirm::Received {
        let _ = (cx, group, message, t);
        super::confirm::Received {
            confirmed: self.leaf_confirmed(tx, conv.id, leaf),
            ..Default::default()
        }
    }

    /// A commit was applied, by `by`: leaf confirmation (C3) challenges a
    /// committer that used authority (12.7, 12.10).
    fn commit_applied(
        &self,
        tx: &mut Tx<'_>,
        conv: ConversationId,
        by: super::confirm::CommitBy,
    ) -> Vec<Action> {
        let _ = (tx, conv, by);
        Vec::new()
    }

    /// A message of this device's (not a live one), from outbox row
    /// `outbox`, is about to be encrypted and posted: leaf confirmation
    /// (C3) adds its pending lines to it (12.10).
    fn outgoing(
        &self,
        tx: &mut Tx<'_>,
        conv: &ConvRow,
        outbox: i64,
        body: &[u8],
    ) -> super::confirm::Outgoing {
        let _ = (tx, conv, outbox, body);
        super::confirm::Outgoing::Keep
    }

    /// Posts of `mailbox` after `after` and before `before` expired before
    /// the device fetched them (7.4): transfers (C4) ask the identity's
    /// other devices for them with WANT (12.13).
    fn posts_expired(
        &self,
        tx: &mut Tx<'_>,
        account: AccountId,
        mailbox: &BoxName,
        after: u64,
        before: u64,
    ) -> Vec<Action> {
        let _ = (tx, account, mailbox, after, before);
        Vec::new()
    }

    /// The `quiet` tag for FOLLOW of `mailbox` (7.1, 9.2), from push (C4).
    /// `None` leaves it out, as devices SHOULD.
    fn follow_quiet(
        &self,
        store: &crate::store::Store,
        account: AccountId,
        mailbox: &BoxName,
    ) -> Option<risala_proto::types::PushTag> {
        let _ = (store, account, mailbox);
        None
    }

    /// The bytes of a blob (12.12), for a post, a GroupInfo, a tree or a
    /// Welcome that came as a blob-ref. The blob store is task C4's (and the
    /// server's SV4b): it fetches the blob from INFO's `blobs` URL prefix,
    /// and answers [`BlobFetch::Waiting`] until it has it, when the engine
    /// asks again on a later tick. The engine checks the hash itself. It is
    /// called outside a transaction of the cache. `prefix` is INFO's
    /// `blobs` URL prefix (8.5), if the server offers blobs; the blob's URL
    /// is it followed by [`BlobRef::hex`].
    fn blob(&self, account: AccountId, prefix: Option<&str>, blob: &BlobRef) -> BlobFetch {
        let _ = (account, prefix, blob);
        BlobFetch::Unavailable
    }
}

/// What [`Hooks::blob`] has of a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobFetch {
    /// Its bytes.
    Ready(Vec<u8>),
    /// Being fetched: ask again later.
    Waiting,
    /// No blob store, or the blob is gone.
    Unavailable,
}

/// The hooks of no other area.
#[derive(Debug, Default)]
pub(crate) struct NoHooks;

impl Hooks for NoHooks {}

/// Why an engine step failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EngineError {
    /// The cache failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// OpenMLS or risala-mls failed.
    #[error("MLS: {0}")]
    Mls(String),
    /// Something is not as it should be.
    #[error("{0}")]
    Invalid(String),
    /// No randomness.
    #[error("no randomness")]
    Random,
    /// A Welcome to a guest's report conversation, to hold until the user
    /// accepts it (12.7).
    #[error("a report conversation from {0}, held for the user")]
    Hold(Uid),
    /// A Welcome for the group of a conversation the device has, that does
    /// not continue it (LR-C1): refused, and the transaction rolled back so
    /// that the old group stays.
    #[error("a Welcome for a known group that does not continue it: {reason}")]
    KnownGroup {
        /// The conversation.
        conv: ConversationId,
        /// Why.
        reason: String,
    },
    /// The server changed a public room in a way no commit the device
    /// checked explains: it joins again only if the user accepts (12.7).
    #[error("the server changed the room: {fields:?}")]
    RoomChanged {
        /// The conversation.
        conv: ConversationId,
        /// What changed.
        fields: Vec<String>,
    },
}

/// What an engine step works with.
pub(crate) struct Ctx<'a> {
    pub account: AccountId,
    pub uid: &'a Uid,
    pub host: &'a risala_proto::names::ServerAddr,
    pub guest: bool,
    pub crypto: &'a Arc<RisalaCrypto>,
    pub hooks: &'a dyn Hooks,
    /// This device's device key for the account (4.3), found before the
    /// transaction: hooks may read the cache, which a transaction holds.
    pub device_key: Option<&'a SigningKey>,
    pub now: u64,
    pub config: &'a Config,
}

/// What a step tells the engine.
#[derive(Debug)]
pub(crate) enum Note {
    /// A commit at `seq` failed MLS for this device (12.7).
    Unprocessable {
        conv: ConversationId,
        epoch: u64,
        seq: u64,
    },
    /// A commit failed the group checks.
    InvalidCommit {
        conv: ConversationId,
        seq: u64,
        reason: String,
    },
    /// This device was removed from the group.
    Removed { conv: ConversationId },
    /// Proposals are pending: commit them after a random wait (6.1).
    Proposals { conv: ConversationId },
    /// A post of a later epoch that the device cannot read (12.7).
    Undecryptable { conv: ConversationId, epoch: u64 },
    /// The group moved to a new mailbox (7.8).
    Moved {
        conv: ConversationId,
        mailbox: BoxName,
    },
    /// A commit was applied.
    Committed {
        conv: ConversationId,
        own: bool,
        removed: Vec<risala_mls::identity::RisalaIdentity>,
    },
    /// This device's commit won its epoch.
    Won,
    /// Someone is typing (8.1).
    Typing { conv: ConversationId, uid: Uid },
    /// A leaf asked to be replaced (12.7).
    Resync { conv: ConversationId, leaf: u32 },
    /// Another device of this identity asked to be replaced in a group
    /// (12.7, `RESYNC <box> <seq>`).
    OwnResync {
        conv: ConversationId,
        seq: u64,
        device: Option<[u8; 48]>,
    },
    /// A read marker moved (7.7).
    Read,
    /// A READ's epoch check differs: the server may have split the group
    /// (7.7).
    Split { conv: ConversationId },
    /// Blocks changed (5.7).
    Blocks,
    /// A message to show arrived.
    NewMessage,
    /// An action from a hook.
    Hook(Box<Action>),
    /// A commit in a public room being joined: did it add the join's leaf
    /// (6.1)?
    JoinCheck { conv: ConversationId },
    /// The server took a commit in a public room that this device cannot
    /// apply: it resyncs or joins again (12.7).
    PublicStuck {
        conv: ConversationId,
        epoch: u64,
        seq: u64,
    },
    /// A resync commit undid a commit this device applied without trouble
    /// (12.7): possible abuse.
    ResyncByOther { conv: ConversationId, by: Uid },
}

/// A random number below `max`, or 0.
pub(crate) fn random_below(max: u64) -> Result<u64, EngineError> {
    if max == 0 {
        return Ok(0);
    }
    let bytes: [u8; 8] = risala_mls::primitives::random().map_err(|_| EngineError::Random)?;
    Ok(u64::from_le_bytes(bytes) % (max + 1))
}

fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = random_below(i as u64).unwrap_or(0) as usize;
        items.swap(i, j);
    }
}

/// A job's number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId(pub u64);

/// Work that needs KeyPackages first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Job {
    /// Start the direct conversation with `peer` (6.1, 12.7).
    Direct {
        /// The other identity.
        peer: Uid,
    },
    /// Create a private room, and invite `members` (6.1).
    PrivateRoom {
        /// Its name.
        name: String,
        /// Identities to invite.
        members: Vec<Uid>,
    },
    /// Start the conversation with yourself (5.1).
    WithYourself,
    /// Add the devices of `uids` that have no leaf in a conversation:
    /// an invitation in a room, or new devices of a member (6.1, 12.7).
    Invite {
        /// The conversation.
        conv: ConversationId,
        /// The identities.
        uids: Vec<Uid>,
    },
    /// Replace a leaf with one from a new KeyPackage of the same device
    /// (12.7: RESYNC, stale leaves).
    Replace {
        /// The conversation.
        conv: ConversationId,
        /// The leaf's identity.
        uid: Uid,
        /// Its device.
        device: [u8; 48],
    },
    /// Replace several stale leaves in one commit (12.7): remove each, and
    /// add the same devices again from new KeyPackages, those that KEYPKG
    /// GET returns one for.
    ReplaceAll {
        /// The conversation.
        conv: ConversationId,
        /// The leaves, by identity and device.
        leaves: Vec<(Uid, [u8; 48])>,
    },
    /// Create the public room `room` (6.1).
    PublicRoom {
        /// Its name.
        room: Room,
    },
    /// Join the public room `room` by external proposal (6.1), as an
    /// identity or a guest. Done once the Welcome is in.
    JoinPublic {
        /// Its name.
        room: Room,
        /// Join even if the name now leads to another group than the one
        /// joined before (6.1).
        new_group: bool,
    },
    /// A guest's report conversation with `peer`, an owner or moderator of
    /// a public room here (5.8, 12.7).
    Report {
        /// The identity.
        peer: Uid,
    },
}

/// Why the engine asked for a public room's GroupInfo (6.1, 12.7).
#[derive(Debug, Clone)]
enum RoomPurpose {
    /// To join it.
    Join {
        job: JobId,
        room: Room,
        new_group: bool,
    },
    /// To see whether a commit added a join's leaf.
    Check { conv: ConversationId },
    /// The device cannot follow the room from `epoch`: resync or join
    /// again.
    Stuck { conv: ConversationId, epoch: u64 },
}

#[derive(Debug)]
struct JobState {
    job: Job,
    waiting: usize,
    key_packages: Vec<(Uid, wire::Fetched)>,
    error: Option<String>,
}

/// A command in flight, by its token.
#[derive(Debug, Clone)]
enum Pending {
    Follow {
        mailbox: BoxName,
    },
    Unfollow,
    Fetch {
        mailbox: BoxName,
        after: u64,
    },
    Post {
        conv: ConversationId,
        outbox: i64,
        live: bool,
    },
    Create {
        job: Option<JobId>,
        conv: ConversationId,
    },
    CreateMove {
        conv: ConversationId,
        outbox: i64,
    },
    Token {
        outbox: i64,
    },
    KeyPkgCount,
    KeyPkgAdd,
    KeyPkgGet {
        job: JobId,
        uid: Uid,
    },
    WelcomeList,
    WelcomeDel,
    WelcomePut {
        id: i64,
        conv: ConversationId,
        device: Option<(Uid, [u8; 48])>,
    },
    RoomInfo {
        job: JobId,
        room: Room,
        new_group: bool,
    },
    GroupInfo {
        purpose: RoomPurpose,
    },
    JoinPost {
        conv: ConversationId,
    },
    WelcomeGet {
        conv: ConversationId,
    },
    ServerInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Follow {
    /// FOLLOW sent.
    Requested,
    /// Followed on `slot`; `caught_up` once the sync point reached the head
    /// and nothing kept is waiting on a missing post (7.4).
    Following {
        slot: Slot,
        caught_up: bool,
        fetching: bool,
    },
}

/// The account the engine runs for.
#[derive(Debug, Clone)]
struct Me {
    account: AccountId,
    uid: Uid,
    /// The account's server, as the conversation extension writes it
    /// (3.5, 12.4).
    host: risala_proto::names::ServerAddr,
    guest: bool,
}

/// The group engine, for one account. See the [module docs](self).
pub struct ConversationEngine {
    config: Config,
    hooks: Arc<dyn Hooks>,
    clock: Arc<dyn Clock>,
    crypto: OnceLock<Arc<RisalaCrypto>>,
    device_key: OnceLock<Arc<SigningKey>>,
    me: Option<Me>,
    ready: BTreeMap<Slot, ConnectionKind>,
    follows: HashMap<BoxName, Follow>,
    inflight: HashMap<Token, Pending>,
    next_token: u64,
    jobs: HashMap<JobId, JobState>,
    next_job: u64,
    /// When to commit pending proposals, per conversation (6.1).
    proposal_timers: HashMap<ConversationId, u64>,
    /// When to replace leaves that asked with RESYNC (12.7).
    resync_timers: HashMap<(ConversationId, u32), u64>,
    /// Commits this device could not process, per conversation: the epoch
    /// it holds and the commit's seq (12.7).
    unprocessable: HashMap<ConversationId, (u64, u64)>,
    /// Conversations for which RESYNC was posted.
    resynced: HashSet<ConversationId>,
    /// When RESYNC was posted, and the seq it named, to ask the own
    /// devices after an hour (12.7).
    resync_since: HashMap<ConversationId, (u64, u64)>,
    /// Jobs waiting for a public room's Welcome, by conversation (6.1).
    join_jobs: HashMap<ConversationId, JobId>,
    /// When to look at a joining room's GroupInfo next (6.1).
    join_checks: HashMap<ConversationId, u64>,
    /// Joining rooms whose GROUPINFO or WELCOME GET is in flight.
    join_inflight: HashSet<ConversationId>,
    /// Public rooms this device cannot follow: the epoch it holds, and
    /// when to resync or join again (12.7).
    stuck: HashMap<ConversationId, (u64, u64)>,
    /// When any member moves the mailbox after another's removal, and the
    /// box it was in then (7.8).
    move_timers: HashMap<ConversationId, (u64, BoxName)>,
    /// Leaves being replaced, so that each is replaced once (12.7).
    replacing: HashSet<(ConversationId, u32)>,
    /// Conversations whose "branch nobody follows" was told (12.8).
    branch_warned: HashSet<ConversationId>,
    /// Mailboxes whose next post waits for its blob (12.12).
    blob_waiting: HashSet<BoxName>,
    /// Mailboxes not to FOLLOW again before a time, after a refusal.
    follow_backoff: HashMap<BoxName, u64>,
    /// INFO's `blobs` URL prefix (8.5, 12.12), once INFO has answered.
    blob_prefix: Option<String>,
    /// Public rooms' Welcomes whose blobs are being fetched (12.12).
    welcome_waits:
        HashMap<ConversationId, (OrBlob<WelcomeText>, OrBlob<risala_proto::mls::RatchetTree>)>,
    /// GROUPINFO answers whose blobs are being fetched, to ask again.
    groupinfo_waits: Vec<(RoomPurpose, BoxName)>,
    /// Whether INFO was sent on a connection that is up.
    info_asked: bool,
    /// Whether INFO answered.
    info_answered: bool,
    /// Whether a blob-ref came before INFO's `blobs` prefix was known.
    need_info: std::sync::atomic::AtomicBool,
    /// Welcomes whose blob is being fetched (12.12).
    welcome_blobs: Vec<(risala_proto::names::Id, BlobRef)>,
    /// Devices added again after a refused WELCOME PUT, once each, so
    /// that a server that refuses every Welcome cannot loop the group
    /// through commits (12.8).
    readded: HashSet<(ConversationId, [u8; 48])>,
    started: bool,
    welcomes_listed: bool,
    self_requested: bool,
    last_refresh_check: u64,
    /// Upkeep's times and the timers it saved (task R2).
    upkeep: upkeep::Upkeep,
}

impl std::fmt::Debug for ConversationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationEngine")
            .field("config", &self.config)
            .field("follows", &self.follows)
            .finish_non_exhaustive()
    }
}

impl Default for ConversationEngine {
    fn default() -> Self {
        ConversationEngine::new(Config::default(), Arc::new(NoHooks), Arc::new(SystemClock))
    }
}

impl ConversationEngine {
    /// An engine with these settings, hooks and clock.
    pub(crate) fn new(config: Config, hooks: Arc<dyn Hooks>, clock: Arc<dyn Clock>) -> Self {
        ConversationEngine {
            config,
            hooks,
            clock,
            crypto: OnceLock::new(),
            device_key: OnceLock::new(),
            me: None,
            ready: BTreeMap::new(),
            follows: HashMap::new(),
            inflight: HashMap::new(),
            next_token: 1,
            jobs: HashMap::new(),
            next_job: 1,
            proposal_timers: HashMap::new(),
            resync_timers: HashMap::new(),
            unprocessable: HashMap::new(),
            resynced: HashSet::new(),
            resync_since: HashMap::new(),
            join_jobs: HashMap::new(),
            join_checks: HashMap::new(),
            join_inflight: HashSet::new(),
            stuck: HashMap::new(),
            move_timers: HashMap::new(),
            replacing: HashSet::new(),
            branch_warned: HashSet::new(),
            blob_waiting: HashSet::new(),
            follow_backoff: HashMap::new(),
            blob_prefix: None,
            welcome_waits: HashMap::new(),
            groupinfo_waits: Vec::new(),
            info_asked: false,
            info_answered: false,
            need_info: std::sync::atomic::AtomicBool::new(false),
            welcome_blobs: Vec::new(),
            readded: HashSet::new(),
            started: false,
            welcomes_listed: false,
            self_requested: false,
            last_refresh_check: 0,
            upkeep: upkeep::Upkeep::default(),
        }
    }

    fn crypto(&self) -> Result<Arc<RisalaCrypto>, EngineError> {
        if let Some(c) = self.crypto.get() {
            return Ok(c.clone());
        }
        let c = Arc::new(RisalaCrypto::new().map_err(|e| EngineError::Mls(e.to_string()))?);
        Ok(self.crypto.get_or_init(|| c).clone())
    }

    /// This device's device key for the account, from the hooks, kept once
    /// found. Called outside transactions only.
    fn device_key(&self, me: &Me) -> Option<Arc<SigningKey>> {
        if me.guest {
            return None;
        }
        if let Some(key) = self.device_key.get() {
            return Some(key.clone());
        }
        let key = Arc::new(self.hooks.device_key(me.account, &me.uid)?);
        Some(self.device_key.get_or_init(|| key).clone())
    }

    fn now(&self) -> u64 {
        self.clock.now().unix_millis()
    }

    fn me(&mut self, cx: &Context) -> Result<Me, EngineError> {
        if let Some(me) = &self.me {
            return Ok(me.clone());
        }
        let row = cx
            .store
            .accounts()?
            .into_iter()
            .find(|a| a.id == cx.account)
            .ok_or(EngineError::Invalid("no such account".into()))?;
        let me = Me {
            account: row.id,
            uid: row.uid,
            // In its one written form, with the port unless it is 7472
            // (3.5); an IP address is not a server there.
            host: row.server.to_string().parse().map_err(|_| {
                EngineError::Invalid("the account's server is not a server address (3.5)".into())
            })?,
            guest: row.kind == AccountKind::Guest,
        };
        self.me = Some(me.clone());
        Ok(me)
    }

    fn token(&mut self, pending: Pending) -> Token {
        let t = Token(self.next_token);
        self.next_token += 1;
        self.inflight.insert(t, pending);
        t
    }

    fn send(&mut self, out: &mut Vec<Action>, target: Target, command: Command, pending: Pending) {
        let token = self.token(pending);
        out.push(Action::Send {
            target,
            command,
            token,
        });
    }

    /// Runs `f` in one write transaction, with a [`Ctx`], and turns the
    /// changes it made into events.
    fn write<T>(
        &self,
        cx: &Context,
        me: &Me,
        out: &mut Vec<Action>,
        f: impl FnOnce(&mut Tx<'_>, &Ctx<'_>) -> Result<T, EngineError>,
    ) -> Result<T, EngineError> {
        let crypto = self.crypto()?;
        let now = self.now();
        let key = self.device_key(me);
        let ctx = Ctx {
            account: me.account,
            uid: &me.uid,
            host: &me.host,
            guest: me.guest,
            crypto: &crypto,
            hooks: self.hooks.as_ref(),
            device_key: key.as_deref(),
            now,
            config: &self.config,
        };
        let (value, changes) = cx.store.write_with(|tx| f(tx, &ctx))?;
        out.extend(changes.into_iter().map(|c| Action::Emit(Event::Changed(c))));
        Ok(value)
    }

    /// Whether a connection that follows and posts is up: anonymous, or a
    /// guest's.
    fn conversing(&self) -> bool {
        self.ready.iter().any(|(slot, kind)| {
            *slot != Slot::Watch
                && matches!(kind, ConnectionKind::Anonymous | ConnectionKind::Guest)
        })
    }

    fn signed_in(&self) -> bool {
        self.ready.values().any(|k| *k == ConnectionKind::SignedIn)
    }

    /// The target of a command that must go on a fresh anonymous
    /// connection (4.1), or a guest's only connection.
    fn fresh(&self, me: &Me) -> Target {
        if me.guest {
            Target::Conversing
        } else {
            Target::Own(SingleUse::Anonymous)
        }
    }

    // -----------------------------------------------------------------
    // Jobs

    /// Starts a job. Its end comes as [`ConversationEvent::JobDone`].
    pub(crate) fn start(&mut self, cx: &Context, job: Job) -> (JobId, Vec<Action>) {
        let id = JobId(self.next_job);
        self.next_job += 1;
        let mut out = Vec::new();
        if let Err(e) = self.start_job(cx, id, job, &mut out) {
            out.push(job_done(id, None, Some(e.to_string())));
        }
        (id, out)
    }

    fn start_job(
        &mut self,
        cx: &Context,
        id: JobId,
        job: Job,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let me = self.me(cx)?;
        // Guests join public rooms and make report conversations, and do
        // nothing else (4.2, 5.8, 6.1).
        let for_guests = matches!(job, Job::JoinPublic { .. } | Job::Report { .. });
        if me.guest && !for_guests {
            return Err(EngineError::Invalid("guests cannot do this".into()));
        }
        if !me.guest && matches!(job, Job::Report { .. }) {
            return Err(EngineError::Invalid(
                "only guests make report conversations".into(),
            ));
        }
        let mut uids: Vec<Uid> = match &job {
            Job::Direct { peer } => vec![peer.clone(), me.uid.clone()],
            Job::PrivateRoom { members, .. } => {
                let mut v = members.clone();
                v.push(me.uid.clone());
                v
            }
            Job::WithYourself => vec![me.uid.clone()],
            Job::Invite { uids, .. } => uids.clone(),
            Job::Replace { uid, .. } => vec![uid.clone()],
            Job::ReplaceAll { leaves, .. } => leaves.iter().map(|(u, _)| u.clone()).collect(),
            Job::Report { peer } => vec![peer.clone()],
            Job::PublicRoom { room } => return self.create_public(cx, &me, id, room.clone(), out),
            Job::JoinPublic { room, new_group } => {
                // 6.1: INFO finds the room's box, then GROUPINFO its group.
                self.send(
                    out,
                    Target::Conversing,
                    Command::Info {
                        room: Some(room.clone()),
                    },
                    Pending::RoomInfo {
                        job: id,
                        room: room.clone(),
                        new_group: *new_group,
                    },
                );
                return Ok(());
            }
        };
        uids.sort();
        uids.dedup();
        if let Job::Direct { peer } = &job
            && *peer == me.uid
        {
            return Err(EngineError::Invalid(
                "a direct conversation needs another identity".into(),
            ));
        }
        self.jobs.insert(
            id,
            JobState {
                job,
                waiting: uids.len(),
                key_packages: Vec::new(),
                error: None,
            },
        );
        let target = self.fresh(&me);
        for uid in uids {
            self.send(
                out,
                target.clone(),
                Command::KeyPkg(KeyPkgCommand::Get { uid: uid.clone() }),
                Pending::KeyPkgGet { job: id, uid },
            );
        }
        Ok(())
    }

    fn job_reply(
        &mut self,
        cx: &Context,
        id: JobId,
        uid: Uid,
        response: &Response,
        out: &mut Vec<Action>,
    ) {
        let Some(state) = self.jobs.get_mut(&id) else {
            return;
        };
        state.waiting = state.waiting.saturating_sub(1);
        match &response.end {
            End::Ok(_) => {
                for line in &response.lines {
                    if let ServerLine::KeyPkg {
                        uid: u,
                        key_package,
                        secret,
                    } = &line.line
                        && *u == uid
                    {
                        state.key_packages.push((
                            uid.clone(),
                            wire::Fetched {
                                key_package: key_package.decode(),
                                secret: secret.as_bytes().to_vec(),
                            },
                        ));
                    }
                }
            }
            End::Err(e) => {
                // An unknown identity fails the job, unless it is this
                // device's own, whose other devices are optional.
                let own = self.me.as_ref().is_some_and(|m| m.uid == uid);
                if !own {
                    state.error = Some(format!("KEYPKG GET {uid}: {}", e.code));
                }
            }
            End::Unparseable(l) => state.error = Some(format!("KEYPKG GET {uid}: {l}")),
        }
        if state.waiting > 0 {
            return;
        }
        let state = self.jobs.remove(&id).expect("the job");
        if let Some(e) = state.error {
            out.push(job_done(id, None, Some(e)));
            return;
        }
        match self.finish_job(cx, id, state, out) {
            Ok(Some(conv)) => out.push(job_done(id, Some(conv), None)),
            Ok(None) => {}
            Err(e) => out.push(job_done(id, None, Some(e.to_string()))),
        }
    }

    /// Continues a job once its KeyPackages are in. Returns the
    /// conversation, if the job is done; a new conversation is done once
    /// CREATE has answered.
    fn finish_job(
        &mut self,
        cx: &Context,
        id: JobId,
        state: JobState,
        out: &mut Vec<Action>,
    ) -> Result<Option<ConversationId>, EngineError> {
        let me = self.me(cx)?;
        let mut created = None;
        let job = state.job.clone();
        let result = self.write(cx, &me, out, |tx, c| {
            let own = group::own_identity(c)?;
            // Checked KeyPackages, without this device's own.
            let checked: Vec<(Uid, wire::Fetched, [u8; 48])> = state
                .key_packages
                .iter()
                .filter_map(|(uid, fetched)| {
                    let kp = group::check_fetched(tx, c, &fetched.key_package, uid)?;
                    let identity = risala_mls::identity::RisalaIdentity::from_credential(
                        kp.leaf_node().credential(),
                    )
                    .ok()?;
                    let device = *identity.device_id?.as_bytes();
                    (identity != own).then(|| (uid.clone(), fetched.clone(), device))
                })
                .collect();
            let kps_of = |filter: &dyn Fn(&Uid) -> bool| -> Vec<wire::Fetched> {
                checked
                    .iter()
                    .filter(|(u, ..)| filter(u))
                    .map(|(_, b, _)| b.clone())
                    .collect()
            };
            match &job {
                Job::Direct { peer } => {
                    if !checked.iter().any(|(u, ..)| u == peer) {
                        return Err(EngineError::Invalid(format!(
                            "{peer} has no devices to add"
                        )));
                    }
                    // 5.1: at most one direct conversation per pair.
                    if let Some(existing) = tx.conversations_of(c.account)?.into_iter().find(|r| {
                        r.kind == ConvKind::Direct
                            && r.peer.as_ref() == Some(peer)
                            && r.state.in_group()
                    }) {
                        return Ok(Some((existing.id, None)));
                    }
                    let adds = kps_of(&|_| true);
                    let made = group::create(
                        tx,
                        c,
                        |b| RisalaConversation::direct(c.host.clone(), b, c.uid, peer),
                        adds,
                    )?;
                    Ok(Some((made.conv, Some(made))))
                }
                Job::PrivateRoom { name, .. } => {
                    let adds = kps_of(&|_| true);
                    let made = group::create(
                        tx,
                        c,
                        |b| RisalaConversation::private_room(c.host.clone(), b, name, c.uid),
                        adds,
                    )?;
                    Ok(Some((made.conv, Some(made))))
                }
                Job::WithYourself => {
                    if let Some(existing) = tx
                        .conversations_of(c.account)?
                        .into_iter()
                        .find(|r| r.kind == ConvKind::WithYourself && r.state.in_group())
                    {
                        return Ok(Some((existing.id, None)));
                    }
                    let adds = kps_of(&|u| u == c.uid);
                    let made = group::create(
                        tx,
                        c,
                        |b| RisalaConversation::direct(c.host.clone(), b, c.uid, c.uid),
                        adds,
                    )?;
                    Ok(Some((made.conv, Some(made))))
                }
                Job::Invite { conv, .. } => {
                    let adds = kps_of(&|_| true);
                    if !adds.is_empty() {
                        group::queue_intent(
                            tx,
                            *conv,
                            &Intent {
                                add: adds,
                                ..Intent::default()
                            },
                            c.now,
                        )?;
                    }
                    Ok(Some((*conv, None)))
                }
                Job::Report { peer } => {
                    // 12.7: the guest's throwaway leaf, and the identity's
                    // devices, added in the first commit.
                    if !checked.iter().any(|(u, ..)| u == peer) {
                        return Err(EngineError::Invalid(format!(
                            "{peer} has no devices to add"
                        )));
                    }
                    let adds = kps_of(&|u| u == peer);
                    let made = group::create(
                        tx,
                        c,
                        |b| RisalaConversation::direct(c.host.clone(), b, c.uid, peer),
                        adds,
                    )?;
                    Ok(Some((made.conv, Some(made))))
                }
                Job::ReplaceAll { conv, leaves } => {
                    let mut adds = Vec::new();
                    for (uid, device) in leaves {
                        if let Some((_, f, _)) =
                            checked.iter().find(|(u, _, d)| u == uid && d == device)
                        {
                            adds.push(f.clone());
                        }
                    }
                    group::queue_intent(
                        tx,
                        *conv,
                        &Intent {
                            add: adds,
                            remove: leaves
                                .iter()
                                .map(|(u, d)| (u.to_string(), Some(*d)))
                                .collect(),
                            ..Intent::default()
                        },
                        c.now,
                    )?;
                    Ok(Some((*conv, None)))
                }
                Job::PublicRoom { .. } | Job::JoinPublic { .. } => {
                    Err(EngineError::Invalid("not a job with KeyPackages".into()))
                }
                Job::Replace { conv, uid, device } => {
                    let adds: Vec<wire::Fetched> = checked
                        .iter()
                        .filter(|(u, _, d)| u == uid && d == device)
                        .map(|(_, b, _)| b.clone())
                        .take(1)
                        .collect();
                    if adds.is_empty() {
                        return Err(EngineError::Invalid("no KeyPackage for that device".into()));
                    }
                    group::queue_intent(
                        tx,
                        *conv,
                        &Intent {
                            add: adds,
                            remove: vec![(uid.to_string(), Some(*device))],
                            ..Intent::default()
                        },
                        c.now,
                    )?;
                    Ok(Some((*conv, None)))
                }
            }
        });
        let result = result?;
        if let Some((conv, made)) = result {
            match made {
                Some(made) => created = Some((conv, made)),
                None => return Ok(Some(conv)),
            }
        }
        let Some((conv, made)) = created else {
            return Ok(None);
        };
        let target = self.fresh(&me);
        self.send(
            out,
            target,
            Command::Create {
                mailbox: made.mailbox,
                group_id: GroupId::from_bytes(made.group_id),
                token_hash: TokenHash::from_bytes(made.token_hash),
                form: CreateForm::NEW,
            },
            Pending::Create {
                job: Some(id),
                conv,
            },
        );
        Ok(None)
    }

    // -----------------------------------------------------------------
    // Inputs

    fn on_ready(
        &mut self,
        cx: &Context,
        slot: Slot,
        kind: ConnectionKind,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let me = self.me(cx)?;
        if !self.started {
            self.started = true;
            self.write(cx, &me, out, |tx, c| {
                // After a restart: what was in flight is sent again.
                for row in tx.account_outbox(c.account)? {
                    if row.state == OutboxState::Sent {
                        tx.update_outbox(row.id, OutboxState::Queued, None, None, None)?;
                    }
                }
                tx.reset_welcomes()?;
                Ok(())
            })?;
        }
        self.ready.insert(slot, kind);
        match kind {
            ConnectionKind::SignedIn => {
                self.welcomes_listed = false;
                self.send(
                    out,
                    Target::SignedIn,
                    Command::Welcome(WelcomeCommand::List),
                    Pending::WelcomeList,
                );
                self.send(
                    out,
                    Target::SignedIn,
                    Command::KeyPkg(KeyPkgCommand::Count),
                    Pending::KeyPkgCount,
                );
            }
            ConnectionKind::Anonymous | ConnectionKind::Guest if slot != Slot::Watch => {
                // Follow again what this connection followed, and what no
                // connection follows (7.4).
                self.follows.retain(|_, f| match f {
                    Follow::Following { slot: s, .. } => *s != slot,
                    Follow::Requested => false,
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn on_closed(&mut self, slot: Slot) {
        self.ready.remove(&slot);
        self.follows.retain(|_, f| match f {
            Follow::Following { slot: s, .. } => *s != slot,
            Follow::Requested => true,
        });
    }

    fn on_line(
        &mut self,
        cx: &Context,
        message: &ServerMessage,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        match &message.line {
            ServerLine::Post(post) => self.on_post(cx, post, out),
            ServerLine::Welcome { id, welcome, .. } => {
                self.on_welcome(cx, id, welcome, out)?;
                Ok(())
            }
            ServerLine::Drop { mailbox, reason } => {
                let me = self.me(cx)?;
                let conv = self.write(cx, &me, out, |tx, c| {
                    let Some(mb) = tx.mailbox(c.account, mailbox)? else {
                        return Ok(None);
                    };
                    if mb.current {
                        tx.set_state(mb.conv, ConvState::Dropped)?;
                    }
                    Ok(Some(mb.conv))
                })?;
                if let Some(conv) = conv {
                    self.follows.remove(mailbox);
                    out.push(Action::Emit(Event::Conversation(
                        ConversationEvent::Dropped {
                            conversation: conv,
                            reason: reason.clone(),
                        },
                    )));
                }
                Ok(())
            }
            ServerLine::Gone { mailbox, uid } => self.on_gone(cx, mailbox, uid, out),
            ServerLine::Presence { presence, uids } => {
                out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::Presence {
                        account: cx.account,
                        uids: uids.clone(),
                        online: *presence != risala_proto::types::Presence::Offline,
                    },
                )));
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn on_post(
        &mut self,
        cx: &Context,
        post: &Post,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let me = self.me(cx)?;
        let (bytes, blob) = match &post.message {
            OrBlob::Inline(message) => (message.decode(), None),
            // 12.12: a post too large for a line is kept with its hash,
            // and fetched through the blob store when its turn comes.
            OrBlob::Blob(blob) => (Vec::new(), Some(*blob.hash())),
        };
        if blob.is_some() && post.seq.is_none() {
            // A live post is never a blob worth waiting for.
            return Ok(());
        }
        match post.seq {
            Some(seq) => {
                let next = post.next.map(|n| *n.as_bytes());
                self.keep(
                    cx,
                    &me,
                    &post.mailbox,
                    seq.get(),
                    post.t.unix_millis(),
                    (bytes, blob),
                    next,
                    out,
                )?;
                let follow = self.follows.get(&post.mailbox).copied();
                if let Some(Follow::Following {
                    fetching: false, ..
                }) = follow
                {
                    self.advance(cx, &me, &post.mailbox, out)?;
                    // A live post beyond a hole: fetch what is missing. A
                    // kept post right after the sync point is no hole: it
                    // waits for its blob (12.12).
                    let behind = self.write(cx, &me, out, |tx, c| {
                        let Some(mb) = tx.mailbox(c.account, &post.mailbox)? else {
                            return Ok(None);
                        };
                        Ok(tx
                            .first_kept_seq(mb.conv, &post.mailbox)?
                            .filter(|f| *f > mb.sync_point + 1)
                            .map(|_| mb.sync_point))
                    })?;
                    if let Some(sync) = behind {
                        self.fetch(&post.mailbox, sync, out);
                    }
                }
            }
            None => self.on_live(cx, &me, post, &bytes, out)?,
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn keep(
        &mut self,
        cx: &Context,
        me: &Me,
        mailbox: &BoxName,
        seq: u64,
        t: u64,
        (message, blob): (Vec<u8>, Option<[u8; 48]>),
        next: Option<[u8; 48]>,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        self.write(cx, me, out, |tx, c| {
            if let Some(mb) = tx.mailbox(c.account, mailbox)? {
                tx.keep_post(
                    mb.conv,
                    mailbox,
                    &PostRow {
                        seq,
                        t,
                        message,
                        next,
                        blob,
                    },
                )?;
            }
            Ok(())
        })
    }

    /// A live post (5.2): read at once, and not kept.
    fn on_live(
        &mut self,
        cx: &Context,
        me: &Me,
        post: &Post,
        bytes: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let notes = self.write(cx, me, out, |tx, c| {
            let Some(mb) = tx.mailbox(c.account, &post.mailbox)? else {
                return Ok(Vec::new());
            };
            let conv = tx.conversation(mb.conv)?;
            if !conv.state.in_group() {
                return Ok(Vec::new());
            }
            if let Some(row) = tx.outbox_by_post(conv.id, bytes)? {
                tx.update_outbox(row.id, OutboxState::Done, None, None, None)?;
                return Ok(Vec::new());
            }
            let mut group = group::load(tx, c, &conv.group_id)?;
            let mut applied = group::Applied::default();
            let mut log = crate::store::messages::MessageLog::new(tx.conn(), conv.id);
            let received = risala_mls::message::receive(
                &tx.mls(c.crypto),
                &mut group,
                bytes,
                risala_mls::message::PostInfo {
                    t: post.t,
                    live: true,
                },
                &mut log,
            );
            log.finish()?;
            if let Ok(decrypted) = received {
                content::receive(
                    tx,
                    c,
                    &conv,
                    &group,
                    decrypted,
                    None,
                    post.t.unix_millis(),
                    &mut applied,
                )?;
            }
            Ok(applied.notes)
        })?;
        self.notes(cx, me, notes, out);
        Ok(())
    }

    /// Applies the kept posts of a mailbox that follow its sync point, in
    /// order, each in a transaction of its own (7.2, 7.4).
    fn advance(
        &mut self,
        cx: &Context,
        me: &Me,
        mailbox: &BoxName,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        loop {
            // 12.12: the next post came as a blob-ref: fetch it first.
            let blob = self.write(cx, me, out, |tx, c| {
                let Some(mb) = tx.mailbox(c.account, mailbox)? else {
                    return Ok(None);
                };
                let Some(post) = tx.post_at(mb.conv, mailbox, mb.sync_point + 1)? else {
                    return Ok(None);
                };
                Ok(post
                    .blob
                    .filter(|_| post.message.is_empty())
                    .map(|b| (mb.conv, post.seq, b)))
            })?;
            if let Some((conv, seq, hash)) = blob {
                match self.get_blob(me, &BlobRef::from_hash(hash)) {
                    rooms::Got::Bytes(bytes) => {
                        self.write(cx, me, out, |tx, _| {
                            Ok(tx.set_post_message(conv, mailbox, seq, &bytes)?)
                        })?;
                    }
                    rooms::Got::Waiting => {
                        self.blob_waiting.insert(*mailbox);
                        return Ok(());
                    }
                    // Skipped: it shows as a gap if it was a message.
                    rooms::Got::Unavailable => {
                        tracing::debug!("a post in a blob, and no blob store");
                    }
                }
            }
            let step = self.write(cx, me, out, |tx, c| {
                let Some(mb) = tx.mailbox(c.account, mailbox)? else {
                    return Ok(None);
                };
                let Some(post) = tx.post_at(mb.conv, mailbox, mb.sync_point + 1)? else {
                    return Ok(None);
                };
                let conv = tx.conversation(mb.conv)?;
                let applied = if post.message.is_empty() {
                    group::Applied::default()
                } else {
                    group::apply_post(tx, c, &conv, &mb, &post)?
                };
                tx.drop_post(mb.conv, mailbox, post.seq)?;
                tx.set_sync(mb.conv, mailbox, post.seq, None)?;
                Ok(Some(applied.notes))
            });
            match step {
                Ok(Some(notes)) => self.notes(cx, me, notes, out),
                Ok(None) => return Ok(()),
                Err(e) => {
                    // A post that cannot be applied at all is skipped, so
                    // that it cannot stop the mailbox.
                    tracing::warn!(error = %e, "a post could not be applied; skipped");
                    self.write(cx, me, out, |tx, c| {
                        if let Some(mb) = tx.mailbox(c.account, mailbox)? {
                            tx.drop_post(mb.conv, mailbox, mb.sync_point + 1)?;
                            tx.set_sync(mb.conv, mailbox, mb.sync_point + 1, None)?;
                        }
                        Ok(())
                    })?;
                }
            }
        }
    }

    /// Acts on what a step noted.
    fn notes(&mut self, cx: &Context, me: &Me, notes: Vec<Note>, out: &mut Vec<Action>) {
        let now = self.now();
        for note in notes {
            match note {
                Note::Hook(action) => out.push(*action),
                Note::Typing { conv, uid } => out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::Typing {
                        conversation: conv,
                        uid,
                    },
                ))),
                Note::Proposals { conv } => {
                    let wait = random_below(self.config.max_commit_wait_ms).unwrap_or(0);
                    self.proposal_timers.entry(conv).or_insert(now + wait);
                }
                Note::Resync { conv, leaf } => {
                    let wait = random_below(self.config.max_commit_wait_ms).unwrap_or(0);
                    self.resync_timers.entry((conv, leaf)).or_insert(now + wait);
                }
                Note::OwnResync { conv, seq, device } => {
                    // 12.7: another device of this identity cannot follow
                    // the group of `conv` since the commit at `seq`:
                    // replace its leaf there, after a random wait.
                    let _ = seq;
                    let leaf = device.and_then(|device| {
                        self.write(cx, me, out, |tx, c| {
                            Ok(crate::store::conversations::read::leaves(tx.conn(), conv)?
                                .into_iter()
                                .find(|l| l.uid == *c.uid && l.device_id == Some(device))
                                .map(|l| l.leaf))
                        })
                        .ok()
                        .flatten()
                    });
                    if let Some(leaf) = leaf {
                        let wait = random_below(self.config.max_commit_wait_ms).unwrap_or(0);
                        self.resync_timers.entry((conv, leaf)).or_insert(now + wait);
                    }
                }
                Note::JoinCheck { conv } => {
                    self.join_checks.insert(conv, now);
                }
                Note::PublicStuck { conv, epoch, seq } => {
                    let _ = seq;
                    self.on_stuck(conv, epoch, out);
                }
                Note::ResyncByOther { conv, by } => out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::Resynced {
                        conversation: conv,
                        by,
                    },
                ))),
                Note::Unprocessable { conv, epoch, seq } => {
                    self.unprocessable.insert(conv, (epoch, seq));
                }
                Note::Undecryptable { conv, epoch } => {
                    self.check_branch(cx, me, conv, out);
                    if let Some((held, seq)) = self.unprocessable.get(&conv).copied()
                        && epoch == held + 1
                        && self.resynced.insert(conv)
                    {
                        // 12.7: ask to be replaced, in the epoch it holds.
                        let r = self.write(cx, me, out, |tx, _| {
                            let row = tx.conversation(conv)?;
                            if matches!(row.kind, ConvKind::Public) {
                                return Ok(());
                            }
                            let seq = risala_proto::names::Seq::new(seq)
                                .ok_or(EngineError::Invalid("seq".into()))?;
                            content::queue_lines(
                                tx,
                                conv,
                                &me.uid,
                                vec![ContentLine::Resync { mailbox: None, seq }],
                                false,
                                now,
                            )?;
                            Ok(())
                        });
                        match r {
                            Ok(()) => {
                                self.resync_since.insert(conv, (now, seq));
                            }
                            Err(e) => tracing::warn!(error = %e, "could not queue RESYNC"),
                        }
                    }
                }
                Note::Committed { conv, own, removed } => {
                    self.proposal_timers.remove(&conv);
                    self.unprocessable.remove(&conv);
                    self.resynced.remove(&conv);
                    self.resync_since.remove(&conv);
                    self.replacing.retain(|(c, _)| *c != conv);
                    if !own
                        && !removed.is_empty()
                        && !removed.iter().any(|id| id.uid == me.uid)
                        && !self.move_timers.contains_key(&conv)
                    {
                        // 7.8: if no move has won within 10 minutes of
                        // another member's removal, any member makes it.
                        let r = self.write(cx, me, out, |tx, _| {
                            let row = tx.conversation(conv)?;
                            Ok(
                                (row.kind != ConvKind::Public && row.state == ConvState::Active)
                                    .then(|| tx.current_mailbox(conv).ok())
                                    .flatten(),
                            )
                        });
                        if let Ok(Some(mb)) = r {
                            let wait = random_below(self.config.max_commit_wait_ms).unwrap_or(0);
                            self.move_timers.insert(
                                conv,
                                (now + self.config.move_fallback_ms + wait, mb.mailbox),
                            );
                        }
                    }
                    if own && !removed.is_empty() {
                        // 7.8: the device that removed a leaf moves the
                        // group, once its removal has won. Public rooms do
                        // not move.
                        let r = self.write(cx, me, out, |tx, c| {
                            let row = tx.conversation(conv)?;
                            if row.kind != ConvKind::Public && row.state.in_group() {
                                group::queue_intent(
                                    tx,
                                    conv,
                                    &Intent {
                                        move_box: true,
                                        ..Intent::default()
                                    },
                                    c.now,
                                )?;
                            }
                            Ok(())
                        });
                        if let Err(e) = r {
                            tracing::warn!(error = %e, "could not queue a move");
                        }
                    }
                    let actions =
                        self.write(cx, me, out, |tx, _| Ok(self.hooks.leaves_changed(tx, conv)));
                    if let Ok(actions) = actions {
                        out.extend(actions);
                    }
                }
                Note::Removed { conv } => {
                    out.push(Action::Emit(Event::Conversation(ConversationEvent::Left {
                        conversation: conv,
                    })));
                }
                Note::Moved { conv, mailbox } => {
                    self.move_timers.remove(&conv);
                    self.follows.remove(&mailbox);
                }
                Note::InvalidCommit { conv, seq, reason } => {
                    tracing::info!(?conv, seq, %reason, "ignored an invalid commit");
                }
                Note::Split { conv } => out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::MaybeSplit { conversation: conv },
                ))),
                Note::NewMessage | Note::Read | Note::Blocks | Note::Won => {}
            }
        }
    }

    fn fetch(&mut self, mailbox: &BoxName, sync_point: u64, out: &mut Vec<Action>) {
        let jitter = random_below(self.config.fetch_jitter).unwrap_or(0);
        let after = sync_point.saturating_sub(jitter);
        if let Some(Follow::Following {
            fetching,
            caught_up,
            ..
        }) = self.follows.get_mut(mailbox)
        {
            if *fetching {
                return;
            }
            *fetching = true;
            *caught_up = false;
        }
        self.send(
            out,
            Target::Mailbox(*mailbox),
            Command::Fetch {
                mailbox: *mailbox,
                after,
                limit: None,
                leaf: None,
            },
            Pending::Fetch {
                mailbox: *mailbox,
                after,
            },
        );
    }

    fn on_reply(
        &mut self,
        cx: &Context,
        slot: Slot,
        token: Token,
        response: &Response,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let Some(pending) = self.inflight.remove(&token) else {
            return Ok(());
        };
        let me = self.me(cx)?;
        let now = self.now();
        match pending {
            Pending::Follow { mailbox } => match &response.end {
                End::Ok(ok) => {
                    let head = ok.head().ok().flatten().unwrap_or(0);
                    self.follows.insert(
                        mailbox,
                        Follow::Following {
                            slot,
                            caught_up: false,
                            fetching: false,
                        },
                    );
                    let sync = self.write(cx, &me, out, |tx, c| {
                        let Some(mb) = tx.mailbox(c.account, &mailbox)? else {
                            return Ok(None);
                        };
                        tx.clear_follow_after(mb.conv, &mailbox)?;
                        let mut sync = mb.sync_point;
                        if head < sync {
                            // 7.4: a head below the sync point; start again.
                            tx.drop_posts(mb.conv, &mailbox)?;
                            sync = 0;
                        }
                        tx.set_sync(mb.conv, &mailbox, sync, Some(head))?;
                        Ok(Some(sync))
                    })?;
                    match sync {
                        Some(sync) if sync < head => self.fetch(&mailbox, sync, out),
                        Some(_) => {
                            self.advance(cx, &me, &mailbox, out)?;
                            if let Some(Follow::Following { caught_up, .. }) =
                                self.follows.get_mut(&mailbox)
                            {
                                *caught_up = true;
                            }
                        }
                        None => {}
                    }
                }
                End::Err(e) => {
                    self.follows.remove(&mailbox);
                    if e.code == ErrorCode::NotFound {
                        tracing::info!(%mailbox, "a mailbox the server does not have");
                    }
                    // Not again at once: a refused FOLLOW is retried later.
                    self.follow_backoff
                        .insert(mailbox, now + self.config.retry_ms.max(1_000));
                }
                End::Unparseable(_) => {
                    self.follows.remove(&mailbox);
                }
            },
            Pending::Unfollow => {}
            Pending::Fetch { mailbox, after } => {
                if let Some(Follow::Following { fetching, .. }) = self.follows.get_mut(&mailbox) {
                    *fetching = false;
                }
                let End::Ok(ok) = &response.end else {
                    self.follows.remove(&mailbox);
                    return Ok(());
                };
                let more = ok.more().ok().flatten().unwrap_or(false);
                let before = self.write(cx, &me, out, |tx, c| {
                    Ok(tx
                        .mailbox(c.account, &mailbox)?
                        .map(|m| (m.sync_point, m.head)))
                })?;
                let Some((l, head)) = before else {
                    return Ok(());
                };
                let mut last = after;
                let mut first_after_l = None;
                for line in &response.lines {
                    if let ServerLine::Post(post) = &line.line
                        && post.mailbox == mailbox
                        && let Some(seq) = post.seq
                    {
                        let seq = seq.get();
                        last = last.max(seq);
                        if seq > l {
                            first_after_l = Some(first_after_l.map_or(seq, |f: u64| f.min(seq)));
                        }
                        let message = match &post.message {
                            OrBlob::Inline(m) => (m.decode(), None),
                            OrBlob::Blob(b) => (Vec::new(), Some(*b.hash())),
                        };
                        self.keep(
                            cx,
                            &me,
                            &mailbox,
                            seq,
                            post.t.unix_millis(),
                            message,
                            post.next.map(|n| *n.as_bytes()),
                            out,
                        )?;
                    }
                }
                self.advance(cx, &me, &mailbox, out)?;
                // Posts that expired (7.4): the first post after L is later
                // than L + 1, or none is left up to the head.
                let expired_to = match first_after_l {
                    Some(f) if f > l + 1 => Some(f - 1),
                    None if !more => head.filter(|h| *h > l),
                    _ => None,
                };
                if let Some(to) = expired_to {
                    let asked = self.write(cx, &me, out, |tx, c| {
                        let mut asked = Vec::new();
                        if let Some(mb) = tx.mailbox(c.account, &mailbox)?
                            && mb.sync_point < to
                        {
                            tx.set_sync(mb.conv, &mailbox, to, None)?;
                            // 12.13: ask the identity's other devices (C4).
                            asked = c.hooks.posts_expired(
                                tx,
                                c.account,
                                &mailbox,
                                mb.sync_point,
                                to + 1,
                            );
                        }
                        Ok(asked)
                    })?;
                    out.extend(asked);
                    self.advance(cx, &me, &mailbox, out)?;
                }
                if more {
                    self.send(
                        out,
                        Target::Mailbox(mailbox),
                        Command::Fetch {
                            mailbox,
                            after: last,
                            limit: None,
                            leaf: None,
                        },
                        Pending::Fetch {
                            mailbox,
                            after: last,
                        },
                    );
                    if let Some(Follow::Following { fetching, .. }) = self.follows.get_mut(&mailbox)
                    {
                        *fetching = true;
                    }
                } else {
                    let hole = self.write(cx, &me, out, |tx, c| {
                        let Some(mb) = tx.mailbox(c.account, &mailbox)? else {
                            return Ok(None);
                        };
                        Ok(tx
                            .first_kept_seq(mb.conv, &mailbox)?
                            .filter(|f| *f > mb.sync_point + 1)
                            .map(|_| mb.sync_point))
                    })?;
                    match hole {
                        Some(sync) => self.fetch(&mailbox, sync, out),
                        None => {
                            if let Some(Follow::Following { caught_up, .. }) =
                                self.follows.get_mut(&mailbox)
                            {
                                *caught_up = true;
                            }
                        }
                    }
                }
            }
            Pending::Post { conv, outbox, live } => {
                self.on_post_reply(cx, &me, conv, outbox, live, response, out)?;
            }
            Pending::Create { job, conv } => match &response.end {
                End::Ok(_) => {
                    if let Some(job) = job {
                        out.push(job_done(job, Some(conv), None));
                    }
                }
                _ => {
                    let why = match &response.end {
                        End::Err(e) => e.code.to_string(),
                        End::Unparseable(l) => l.clone(),
                        End::Ok(_) => unreachable!(),
                    };
                    self.write(cx, &me, out, |tx, _| {
                        tx.set_state(conv, ConvState::Failed)?;
                        Ok(())
                    })?;
                    if let Some(job) = job {
                        out.push(job_done(job, None, Some(format!("CREATE: {why}"))));
                    }
                }
            },
            Pending::Token { outbox } => {
                // Whatever the answer, post again; a second ERR stale
                // means the group has moved on, and catching up shows it.
                self.write(cx, &me, out, |tx, _| {
                    tx.update_outbox(outbox, OutboxState::Queued, None, None, None)?;
                    Ok(())
                })?;
            }
            Pending::CreateMove { conv, outbox } => {
                let created = match &response.end {
                    End::Ok(_) => true,
                    End::Err(e) => {
                        tracing::warn!(code = %e.code, "the server refused a move's mailbox");
                        false
                    }
                    End::Unparseable(_) => {
                        // Try again on the next connection.
                        return Ok(());
                    }
                };
                self.write(cx, &me, out, |tx, c| {
                    if created {
                        tx.set_moved(outbox)?;
                    } else {
                        // The move is dropped, not made again (7.8 allows a
                        // group not to move; the user is told by the log).
                        let row = tx.conversation(conv)?;
                        if let Ok(mut g) = group::load(tx, c, &row.group_id)
                            && g.pending_commit().is_some()
                        {
                            risala_mls::group::discard_own_commit(&tx.mls(c.crypto), &mut g)
                                .map_err(|e| EngineError::Mls(e.to_string()))?;
                        }
                        tx.update_outbox(outbox, OutboxState::Lost, None, None, None)?;
                    }
                    Ok(())
                })?;
            }
            Pending::KeyPkgCount => {
                if let End::Ok(ok) = &response.end {
                    let count = ok.count().ok().flatten().unwrap_or(0);
                    let last_resort = ok.last_resort().ok().flatten().unwrap_or(false);
                    let n = if count < self.config.key_packages_low {
                        self.config.key_packages.saturating_sub(count) as usize
                    } else {
                        0
                    };
                    if (n > 0 || !last_resort) && self.device_key(&me).is_some() {
                        let made = self.write(cx, &me, out, |tx, c| {
                            group::make_key_packages(tx, c, n, !last_resort)
                        })?;
                        for bytes in made {
                            let key_package = KeyPackageText::from_bytes(&bytes)
                                .map_err(|e| EngineError::Invalid(e.to_string()))?;
                            self.send(
                                out,
                                Target::SignedIn,
                                Command::KeyPkg(KeyPkgCommand::Add { key_package }),
                                Pending::KeyPkgAdd,
                            );
                        }
                    }
                }
            }
            Pending::KeyPkgAdd => {
                if let End::Err(e) = &response.end {
                    tracing::warn!(code = %e.code, "KEYPKG ADD refused");
                }
            }
            Pending::KeyPkgGet { job, uid } => self.job_reply(cx, job, uid, response, out),
            Pending::WelcomeList => {
                for line in &response.lines {
                    if let ServerLine::Welcome { id, welcome, .. } = &line.line {
                        self.on_welcome(cx, id, welcome, out)?;
                    }
                }
                self.welcomes_listed = true;
                self.maybe_self_conversation(cx, &me, out)?;
            }
            Pending::WelcomeDel => {}
            Pending::WelcomePut { id, conv, device } => {
                // 12.8: a refusal other than `rate-limited` means the
                // device cannot know who holds the added device's place.
                let refused = matches!(&response.end,
                    End::Err(e) if e.code != ErrorCode::RateLimited);
                let sent = matches!(response.end, End::Ok(_)) || refused;
                let retry = now + self.config.retry_ms.max(1_000);
                self.write(cx, &me, out, |tx, _| {
                    tx.welcome_done(id, sent, retry)?;
                    Ok(())
                })?;
                if refused {
                    self.welcome_refused(cx, &me, conv, device, out)?;
                }
            }
            Pending::RoomInfo {
                job,
                room,
                new_group,
            } => self.on_room_info(job, room, new_group, response, out),
            Pending::GroupInfo { purpose } => self.on_group_info(cx, purpose, response, out)?,
            Pending::JoinPost { conv } => self.on_join_post(conv, response, out),
            Pending::ServerInfo => match &response.end {
                End::Ok(ok) => {
                    self.info_answered = true;
                    self.blob_prefix = ok.blobs().map(str::to_owned);
                    if let Ok(Some(retention)) = ok.retention() {
                        self.config.retention_ms =
                            u64::from(retention.days()) * 24 * 60 * 60 * 1000;
                    }
                }
                _ => self.info_asked = false,
            },
            Pending::WelcomeGet { conv } => self.on_welcome_get(cx, conv, response, out)?,
        }
        Ok(())
    }

    /// A WELCOME PUT was refused (12.8): tell the user, and, where the Adds
    /// checks let this device, remove the leaf and add the device again
    /// from a new KeyPackage. A public room's joiner proposes again by
    /// itself.
    fn welcome_refused(
        &mut self,
        cx: &Context,
        me: &Me,
        conv: ConversationId,
        device: Option<(Uid, [u8; 48])>,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        out.push(Action::Emit(Event::Conversation(
            ConversationEvent::WelcomeRefused {
                conversation: conv,
                uid: device.as_ref().map(|(u, _)| u.clone()),
            },
        )));
        let Some((uid, device)) = device else {
            return Ok(());
        };
        if !self.readded.insert((conv, device)) {
            return Ok(());
        }
        let allowed = self.write(cx, me, out, |tx, c| {
            let row = tx.conversation(conv)?;
            if row.kind == ConvKind::Public || !row.state.in_group() {
                return Ok(false);
            }
            may_replace(tx, c, &row, &uid)
        })?;
        if allowed {
            let (_, actions) = self.start(cx, Job::Replace { conv, uid, device });
            out.extend(actions);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn on_post_reply(
        &mut self,
        cx: &Context,
        me: &Me,
        conv: ConversationId,
        outbox: i64,
        live: bool,
        response: &Response,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let now = self.now();
        let retry = now + self.config.retry_ms;
        let mut repair = None;
        let mut rejoin = false;
        self.write(cx, me, out, |tx, c| {
            let Some(row) = tx.outbox_row(outbox)? else {
                return Ok(());
            };
            let conv_row = tx.conversation(conv)?;
            match &response.end {
                End::Ok(ok) => {
                    if live {
                        tx.update_outbox(outbox, OutboxState::Done, None, None, None)?;
                    } else {
                        let seq = ok.seq().ok().flatten().map(|s| s.get());
                        // The post may have been applied already, from its
                        // live copy: then it is done.
                        if row.state == OutboxState::Sent {
                            tx.update_outbox(outbox, OutboxState::Posted, None, seq, None)?;
                        }
                    }
                }
                // 12.7: a refused external commit: join by proposal.
                End::Err(e) if row.kind == OutboxKind::External => {
                    tracing::info!(code = %e.code, "the server refused an external commit");
                    tx.update_outbox(outbox, OutboxState::Lost, None, None, None)?;
                    public::external_lost(tx, c, conv)?;
                    rejoin = true;
                }
                // A commit already decided, when its post came back or a
                // winner was applied first, is not made again twice.
                End::Err(_)
                    if row.kind == OutboxKind::Commit
                        && matches!(row.state, OutboxState::Lost | OutboxState::Done) => {}
                End::Err(e) if e.code == ErrorCode::Stale => match row.kind {
                    OutboxKind::Commit => group::commit_lost(tx, c, &conv_row, &row)?,
                    _ => {
                        // 7.2: a device that holds the token of the epoch
                        // before puts this epoch's hash back with TOKEN,
                        // then posts again. If the post was for an older
                        // epoch, catching up shows it.
                        let (token, epoch) = group::send_token(tx, c, &conv_row)?;
                        // 7.2: TOKEN gets `ERR forbidden` in a public room,
                        // whose commits the server checks; catch up instead.
                        let prev = if conv_row.kind == ConvKind::Public {
                            None
                        } else {
                            tx.prev_token(conv)?
                        };
                        let token_repair = match (row.epoch, prev) {
                            (Some(e), Some(prev)) if e == epoch && epoch > 0 => {
                                Some((epoch - 1, prev, token.hash()))
                            }
                            _ => None,
                        };
                        tx.update_outbox(outbox, OutboxState::Sent, None, None, None)?;
                        if token_repair.is_none() {
                            tx.update_outbox(outbox, OutboxState::Queued, None, None, Some(retry))?;
                        }
                        repair = Some(token_repair);
                    }
                },
                End::Err(e) => {
                    tracing::warn!(code = %e.code, "a post was refused");
                    match row.kind {
                        OutboxKind::Commit => group::commit_lost(tx, c, &conv_row, &row)?,
                        _ => tx.update_outbox(outbox, OutboxState::Lost, None, None, None)?,
                    }
                }
                End::Unparseable(_) => {
                    // The connection closed: post again on the next one
                    // (7.6), unless the post went through, which the fetch
                    // after reconnecting shows.
                    tx.update_outbox(outbox, OutboxState::Queued, None, None, Some(retry))?;
                }
            }
            Ok(())
        })?;
        match repair {
            Some(Some((epoch, prev, hash))) => {
                if let Some(mb) =
                    self.write(cx, me, out, |tx, _| Ok(tx.current_mailbox(conv).ok()))?
                {
                    self.send(
                        out,
                        Target::Mailbox(mb.mailbox),
                        Command::Token {
                            mailbox: mb.mailbox,
                            epoch,
                            token: SendTokenText::from_bytes(prev),
                            hash: TokenHash::from_bytes(hash),
                        },
                        Pending::Token { outbox },
                    );
                }
            }
            Some(None) => {
                // Catch up: a stale post usually means the group moved on.
                if let Some(mb) =
                    self.write(cx, me, out, |tx, _| Ok(tx.current_mailbox(conv).ok()))?
                {
                    self.fetch(&mb.mailbox, mb.sync_point, out);
                }
            }
            None => {}
        }
        if rejoin {
            let epoch = self.write(cx, me, out, |tx, _| Ok(tx.conversation(conv)?.epoch))?;
            self.stuck.insert(conv, (epoch, now));
        }
        // 12.7: an external commit the server took: the device is in.
        if matches!(response.end, End::Ok(_))
            && let Some(job) = self.join_jobs.remove(&conv)
        {
            let external = self.write(cx, me, out, |tx, _| {
                Ok(tx
                    .outbox_row(outbox)?
                    .is_some_and(|r| r.kind == OutboxKind::External))
            })?;
            if external {
                self.join_checks.remove(&conv);
                out.push(job_done(job, Some(conv), None));
                out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::Joined { conversation: conv },
                )));
            } else {
                self.join_jobs.insert(conv, job);
            }
        }
        Ok(())
    }

    fn on_welcome(
        &mut self,
        cx: &Context,
        id: &risala_proto::names::Id,
        welcome: &OrBlob<WelcomeText>,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let me = self.me(cx)?;
        // LR-M5: anyone who got one of the device's KeyPackages can put
        // Welcomes that name blobs. A few at a time are fetched; the rest
        // stay on the server, listed again on the next connection.
        if let OrBlob::Blob(_) = welcome
            && !self.welcome_blobs.iter().any(|(i, _)| i == id)
            && self.welcome_blobs.len() >= MAX_WELCOME_BLOBS
        {
            tracing::info!("a Welcome in a blob left for later: too many waiting");
            return Ok(());
        }
        let sealed = match welcome {
            OrBlob::Inline(welcome) => welcome.decode(),
            OrBlob::Blob(blob) => match self.get_blob(&me, blob) {
                rooms::Got::Bytes(bytes) => bytes,
                rooms::Got::Waiting => {
                    // 12.12: asked again on a later tick.
                    if !self.welcome_blobs.iter().any(|(i, _)| i == id) {
                        self.welcome_blobs.push((id.clone(), *blob));
                    }
                    return Ok(());
                }
                rooms::Got::Unavailable => {
                    tracing::info!("a Welcome in a blob, and no blob store");
                    return Ok(());
                }
            },
        };
        self.welcome_blobs.retain(|(i, _)| i != id);
        let joined = self.write(cx, &me, out, |tx, c| {
            group::join_welcome(tx, c, &sealed, false)
        });
        let delete = match joined {
            Ok(group::Joined::Joined { conv }) => {
                out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::Joined { conversation: conv },
                )));
                // 5.1: one direct conversation per pair.
                let left = self.write(cx, &me, out, |tx, c| group::keep_one_direct(tx, c, conv))?;
                if let Some(left) = left {
                    tracing::info!(%left, "left a second direct conversation with the same identity");
                }
                let actions = self.write(cx, &me, out, |tx, _| {
                    Ok(self.hooks.leaves_changed(tx, conv))
                })?;
                out.extend(actions);
                true
            }
            Ok(group::Joined::Refused(why)) => {
                tracing::info!(%why, "a Welcome refused");
                true
            }
            Err(EngineError::KnownGroup { conv, reason }) => {
                tracing::warn!(%conv, %reason, "a Welcome for a known group refused");
                out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::WelcomeForKnownGroupRefused {
                        conversation: conv,
                        reason,
                    },
                )));
                true
            }
            Err(EngineError::Hold(guest)) => {
                // 12.7: a guest's report conversation waits for the user.
                let held = self.write(cx, &me, out, |tx, c| {
                    Ok(tx.hold_welcome(c.account, &sealed, &guest, c.now)?)
                })?;
                out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::ReportOffered {
                        account: me.account,
                        offer: held,
                        guest,
                    },
                )));
                true
            }
            Err(e) => {
                // Kept, to try again (12.8).
                tracing::warn!(error = %e, "a Welcome could not be processed");
                false
            }
        };
        if delete && self.signed_in() {
            self.send(
                out,
                Target::SignedIn,
                Command::Welcome(WelcomeCommand::Del { id: id.clone() }),
                Pending::WelcomeDel,
            );
        }
        Ok(())
    }

    fn maybe_self_conversation(
        &mut self,
        cx: &Context,
        me: &Me,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        if !self.config.self_conversation
            || self.self_requested
            || me.guest
            || !self.welcomes_listed
        {
            return Ok(());
        }
        if self.device_key(me).is_none() {
            return Ok(());
        }
        let has = self.write(cx, me, out, |tx, c| {
            Ok(tx
                .conversations_of(c.account)?
                .iter()
                .any(|r| r.kind == ConvKind::WithYourself && r.state.in_group())
                || !c.hooks.start_self_conversation(tx, c.uid))
        })?;
        self.self_requested = true;
        if !has {
            let (_, actions) = self.start(cx, Job::WithYourself);
            out.extend(actions);
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Sending

    /// Does what is due: follows, unfollows, posts, Welcomes and timers.
    fn pump(&mut self, cx: &Context, out: &mut Vec<Action>) -> Result<(), EngineError> {
        let me = self.me(cx)?;
        let now = self.now();
        // 8.5: where blobs are fetched (12.12), and the retention period
        // that the own identity's stale leaves are judged by (12.7): asked
        // once, by an identity's device, or by a guest's once a blob-ref
        // comes.
        if self.conversing()
            && !self.info_asked
            && (!me.guest || self.need_info.load(std::sync::atomic::Ordering::Relaxed))
        {
            self.info_asked = true;
            self.send(
                out,
                Target::Conversing,
                Command::Info { room: None },
                Pending::ServerInfo,
            );
        }
        // Upkeep and timers first: what they queue is posted in the same
        // step.
        self.upkeep(cx, &me, now, out)?;
        self.timers_due(cx, &me, now, out)?;
        if self.conversing() {
            self.follow_due(cx, &me, now, out)?;
            self.post_due(cx, &me, out)?;
            self.welcomes_due(cx, &me, now, out)?;
        }
        // LR-M4: the timers that no other state brings back, kept.
        self.save_timers(cx, &me, out);
        Ok(())
    }

    fn follow_due(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let mailboxes = self.write(cx, me, out, |tx, c| Ok(tx.account_mailboxes(c.account)?))?;
        // A mailbox whose CREATE is in flight does not exist yet.
        let creating: HashSet<ConversationId> = self
            .inflight
            .values()
            .filter_map(|p| match p {
                Pending::Create { conv, .. } => Some(*conv),
                _ => None,
            })
            .collect();
        let mut to_follow = Vec::new();
        for mb in &mailboxes {
            if let Some(at) = mb.unfollow_at
                && at <= now
            {
                if self.follows.remove(&mb.mailbox).is_some() {
                    self.send(
                        out,
                        Target::Mailbox(mb.mailbox),
                        Command::Unfollow {
                            mailbox: mb.mailbox,
                        },
                        Pending::Unfollow,
                    );
                }
                self.write(cx, me, out, |tx, _| {
                    tx.remove_mailbox(mb.conv, &mb.mailbox)?;
                    Ok(())
                })?;
                continue;
            }
            if self.follows.contains_key(&mb.mailbox) {
                continue;
            }
            if mb.follow_after.is_some_and(|t| t > now) || creating.contains(&mb.conv) {
                continue;
            }
            if self
                .follow_backoff
                .get(&mb.mailbox)
                .is_some_and(|t| *t > now)
            {
                continue;
            }
            to_follow.push(mb.mailbox);
        }
        // 7.4: in a random order.
        shuffle(&mut to_follow);
        for mailbox in to_follow {
            self.follows.insert(mailbox, Follow::Requested);
            self.send(
                out,
                Target::Mailbox(mailbox),
                Command::Follow {
                    mailbox,
                    quiet: self.hooks.follow_quiet(&cx.store, cx.account, &mailbox),
                },
                Pending::Follow { mailbox },
            );
        }
        Ok(())
    }

    fn caught_up(&self, mailbox: &BoxName) -> bool {
        matches!(
            self.follows.get(mailbox),
            Some(Follow::Following {
                caught_up: true,
                fetching: false,
                ..
            })
        )
    }

    fn post_due(
        &mut self,
        cx: &Context,
        me: &Me,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let now = self.now();
        let in_flight: HashSet<ConversationId> = self
            .inflight
            .values()
            .filter_map(|p| match p {
                Pending::Post { conv, .. } | Pending::CreateMove { conv, .. } => Some(*conv),
                Pending::Token { .. } => None,
                _ => None,
            })
            .collect();
        let convs = self.write(cx, me, out, |tx, c| Ok(tx.conversations_of(c.account)?))?;
        let signed_in = self.signed_in();
        for conv in convs {
            if !conv.state.in_group() || in_flight.contains(&conv.id) {
                continue;
            }
            // 12.7: a public room this device cannot follow posts nothing
            // until it has resynced or joined again.
            if self.stuck.contains_key(&conv.id) {
                continue;
            }
            let Some(mailbox) =
                self.write(cx, me, out, |tx, _| Ok(tx.current_mailbox(conv.id).ok()))?
            else {
                continue;
            };
            if !self.caught_up(&mailbox.mailbox) {
                continue;
            }
            let posts = self.write(cx, me, out, |tx, c| {
                next_posts(tx, c, &conv, now, signed_in)
            });
            let posts = match posts {
                Ok(posts) => posts,
                Err(e) => {
                    tracing::warn!(error = %e, conv = %conv.id, "could not make a post");
                    continue;
                }
            };
            for p in posts {
                let token = SendTokenText::from_bytes(*p.token.as_bytes());
                if let Some(create) = p.create {
                    let next = p
                        .next
                        .ok_or(EngineError::Invalid("a move with no next".into()))?;
                    let epoch = std::num::NonZeroU64::new(create.epoch)
                        .ok_or(EngineError::Invalid("epoch 0".into()))?;
                    let target = self.fresh(me);
                    self.send(
                        out,
                        target,
                        Command::Create {
                            mailbox: create.mailbox,
                            group_id: GroupId::from_bytes(create.group_id),
                            token_hash: TokenHash::from_bytes(next),
                            form: CreateForm::Private {
                                moving: Some(risala_proto::command::mailbox::Move {
                                    epoch,
                                    from: create.from,
                                    token,
                                }),
                            },
                        },
                        Pending::CreateMove {
                            conv: conv.id,
                            outbox: p.outbox,
                        },
                    );
                    continue;
                }
                let message = MlsMessage::from_bytes(&p.post)
                    .map_err(|e| EngineError::Invalid(e.to_string()))?;
                // TODO(C4): a commit or GroupInfo too large for a line goes
                // as a blob (12.12), stored over an anonymous connection.
                let groupinfo = match &p.groupinfo {
                    Some(g) => Some(OrBlob::Inline(
                        risala_proto::mls::GroupInfo::from_bytes(g)
                            .map_err(|e| EngineError::Invalid(e.to_string()))?,
                    )),
                    None => None,
                };
                let command = Command::Post {
                    mailbox: mailbox.mailbox,
                    token: if p.external {
                        PostToken::Join
                    } else {
                        PostToken::Send(token)
                    },
                    message: OrBlob::Inline(message),
                    live: p.live,
                    groupinfo,
                    next: p.next.map(TokenHash::from_bytes),
                    cid: None,
                };
                // 12.6: a public room's commits and Updates come from the
                // signed-in connection of the device the credential names.
                let target = if p.signed_in {
                    Target::SignedIn
                } else {
                    Target::Mailbox(mailbox.mailbox)
                };
                self.send(
                    out,
                    target,
                    command,
                    Pending::Post {
                        conv: conv.id,
                        outbox: p.outbox,
                        live: p.live,
                    },
                );
            }
        }
        Ok(())
    }

    fn welcomes_due(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let due = self.write(cx, me, out, |tx, c| Ok(tx.due_welcomes(c.account, now)?))?;
        let signed_in = self.signed_in();
        for w in due {
            // 12.8: a public room's Welcome, for a join proposal, goes on
            // the signed-in connection of the device that committed it; a
            // sealed one on a fresh anonymous connection.
            let public = w.secret.len() != 32;
            if public && !signed_in {
                let retry = now + self.config.retry_ms.max(1_000);
                self.write(
                    cx,
                    me,
                    out,
                    |tx, _| Ok(tx.welcome_done(w.id, false, retry)?),
                )?;
                continue;
            }
            let target = if public {
                Target::SignedIn
            } else {
                self.fresh(me)
            };
            let Ok(reference) = <[u8; 48]>::try_from(w.reference.as_slice()) else {
                continue;
            };
            let welcome = WelcomeText::from_bytes(&w.welcome)
                .map_err(|e| EngineError::Invalid(e.to_string()))?;
            self.send(
                out,
                target.clone(),
                Command::Welcome(WelcomeCommand::Put {
                    key_package_ref: RefText::from_bytes(reference),
                    secret: match <[u8; 32]>::try_from(w.secret.as_slice()) {
                        Ok(s) => WelcomeSecret::Put(PutSecret::from_bytes(s)),
                        Err(_) => WelcomeSecret::Proposal,
                    },
                    welcome: OrBlob::Inline(welcome),
                }),
                Pending::WelcomePut {
                    id: w.id,
                    conv: w.conv,
                    device: w.device.clone(),
                },
            );
        }
        Ok(())
    }

    fn timers_due(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let due: Vec<ConversationId> = self
            .proposal_timers
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(c, _)| *c)
            .collect();
        for conv in due {
            self.proposal_timers.remove(&conv);
            // 6.1: only full clients of identities commit proposals.
            if me.guest {
                continue;
            }
            self.write(cx, me, out, |tx, c| {
                let row = tx.conversation(conv)?;
                if !row.state.in_group() || group::has_pending_commit(tx, conv)? {
                    return Ok(());
                }
                let queued = tx
                    .pending_outbox(conv)?
                    .iter()
                    .any(|o| o.kind == OutboxKind::Commit);
                let group = group::load(tx, c, &row.group_id)?;
                // A leaving device commits nothing more; another member
                // commits its SelfRemove (6.1).
                if !queued
                    && group.pending_proposals().next().is_some()
                    && row.state != ConvState::Leaving
                {
                    group::queue_intent(
                        tx,
                        conv,
                        &Intent {
                            proposals: true,
                            ..Intent::default()
                        },
                        c.now,
                    )?;
                }
                Ok(())
            })?;
        }
        let due: Vec<(ConversationId, u32)> = self
            .resync_timers
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(k, _)| *k)
            .collect();
        for (conv, leaf) in due {
            self.resync_timers.remove(&(conv, leaf));
            if me.guest || !self.replacing.insert((conv, leaf)) {
                continue;
            }
            let target = self.write(cx, me, out, |tx, _| {
                let Some(l) = tx.leaf(conv, leaf)? else {
                    return Ok(None);
                };
                Ok(l.device_id.map(|d| (l.uid, d)))
            })?;
            if let Some((uid, device)) = target {
                // 12.7: the leaf's own identity first; others only where
                // the checks let them, and plain members only warn.
                if self.answers_resync(cx, me, conv, &uid, out) {
                    let (_, actions) = self.start(cx, Job::Replace { conv, uid, device });
                    out.extend(actions);
                } else {
                    tracing::info!(%uid, "a member asked to be replaced; left to others");
                }
            }
        }
        self.rooms_due(cx, me, now, out)?;
        self.recovery_due(cx, me, now, out)?;
        // 12.12: Welcomes and posts whose blobs were being fetched.
        let waiting: Vec<(risala_proto::names::Id, BlobRef)> = self.welcome_blobs.clone();
        for (id, blob) in waiting {
            self.on_welcome(cx, &id, &OrBlob::Blob(blob), out)?;
        }
        let waiting: Vec<BoxName> = self.blob_waiting.drain().collect();
        for mailbox in waiting {
            self.advance(cx, me, &mailbox, out)?;
        }
        // 12.7: the weekly fresh-leaf commit, checked every ten minutes. A
        // guest's leaf never commits (12.6).
        if now >= self.last_refresh_check + 600_000 && !me.guest {
            self.last_refresh_check = now;
            self.replace_stale(cx, me, now, out)?;
            let refresh_after = self.config.refresh_after_ms;
            self.write(cx, me, out, |tx, c| {
                for row in tx.conversations_of(c.account)? {
                    if row.state != ConvState::Active || !tx.pending_outbox(row.id)?.is_empty() {
                        continue;
                    }
                    let Ok(group) = group::load(tx, c, &row.group_id) else {
                        continue;
                    };
                    let updated = group
                        .own_leaf_node()
                        .and_then(risala_mls::profile::RisalaProfile::of_leaf)
                        .map_or(0, |p| p.updated);
                    if c.now.saturating_sub(updated) > refresh_after {
                        group::queue_intent(tx, row.id, &Intent::default(), c.now)?;
                    }
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}

/// A post to make, or for a move, the new mailbox to create first
/// (7.8).
struct NextPost {
    outbox: i64,
    post: Vec<u8>,
    token: risala_mls::token::SendToken,
    next: Option<[u8; 48]>,
    live: bool,
    create: Option<CreateMove>,
    /// A public room commit's GroupInfo (12.6).
    groupinfo: Option<Vec<u8>>,
    /// An external commit, posted with the token `-` (12.7).
    external: bool,
    /// On the signed-in connection (12.6).
    signed_in: bool,
}

/// `CREATE <box> <group-id> <token-hash> epoch=<e> from=<old> token=<token>`
/// for a move (5.2, 7.8): `token` is the send token of `epoch` - 1, and
/// the token hash the move commit's `next`.
struct CreateMove {
    mailbox: BoxName,
    group_id: [u8; 32],
    epoch: u64,
    from: BoxName,
}

/// What a conversation posts next, made now: its pending commit, or a
/// commit to make from an intent, or a SelfRemove, or up to
/// [`POST_BATCH`] messages. Nothing while a commit or a post is waiting to
/// be applied (7.2).
fn next_posts(
    tx: &mut Tx<'_>,
    c: &Ctx<'_>,
    conv: &ConvRow,
    now: u64,
    signed_in: bool,
) -> Result<Vec<NextPost>, EngineError> {
    let mut rows = tx.pending_outbox(conv.id)?;
    let waiting = |r: &OutboxRow| r.not_before.is_some_and(|t| t > now);
    if rows.iter().any(|r| r.state == OutboxState::Sent) {
        return Ok(Vec::new());
    }
    let public = conv.kind == ConvKind::Public;
    // 12.6: a guest's leaf never commits, nor proposes an Update.
    if c.guest && public {
        for r in rows
            .iter()
            .filter(|r| matches!(r.kind, OutboxKind::Commit | OutboxKind::Update))
        {
            tx.update_outbox(r.id, OutboxState::Lost, None, None, None)?;
        }
        rows.retain(|r| !matches!(r.kind, OutboxKind::Commit | OutboxKind::Update));
    }
    // An external commit (12.7), merged already: posted with `-`.
    if let Some(row) = rows
        .iter()
        .find(|r| r.kind == OutboxKind::External && r.state == OutboxState::Queued)
    {
        if !signed_in {
            return Ok(Vec::new());
        }
        let (token, _) = group::send_token(tx, c, conv)?;
        tx.update_outbox(row.id, OutboxState::Sent, None, None, None)?;
        return Ok(vec![NextPost {
            outbox: row.id,
            post: row.post.clone().unwrap_or_default(),
            token,
            next: row.next,
            live: false,
            create: None,
            groupinfo: row.groupinfo.clone(),
            external: true,
            signed_in: true,
        }]);
    }
    if rows
        .iter()
        .any(|r| r.kind == OutboxKind::External && r.state == OutboxState::Posted)
    {
        return Ok(Vec::new());
    }
    // A public room's commits go on the signed-in connection (12.6).
    if public
        && !signed_in
        && rows
            .iter()
            .any(|r| matches!(r.kind, OutboxKind::Commit | OutboxKind::Update))
    {
        return Ok(Vec::new());
    }
    // A commit posted and not yet applied: wait for it to win or lose.
    if rows
        .iter()
        .any(|r| r.kind == OutboxKind::Commit && r.state == OutboxState::Posted)
    {
        return Ok(Vec::new());
    }
    let (token, epoch) = group::send_token(tx, c, conv)?;
    if let Some(row) = rows.iter().find(|r| r.kind == OutboxKind::Commit) {
        if waiting(row) {
            return Ok(Vec::new());
        }
        let row = row.clone();
        // 12.7: a new extension waits while sending is held.
        if row.post.is_none() && keycheck::commit_held(tx, conv.id, row.intent.as_deref())? {
            return Ok(Vec::new());
        }
        // A commit made for an earlier epoch lost: make it again.
        if row.post.is_none() || row.epoch != Some(epoch) {
            match group::build_commit(tx, c, conv, &row)? {
                group::Built::Made => {}
                group::Built::Nothing => return Ok(Vec::new()),
                group::Built::WaitUntil(t) => {
                    tx.update_outbox(row.id, OutboxState::Queued, None, None, Some(t))?;
                    return Ok(Vec::new());
                }
            }
        }
        let row = tx
            .outbox_row(row.id)?
            .ok_or(StoreError::NotFound("outbox row"))?;
        let post = row
            .post
            .clone()
            .ok_or(EngineError::Invalid("a commit with no post".into()))?;
        let (token, _) = group::send_token(tx, c, conv)?;
        // 7.8: a move creates its new mailbox before it posts.
        if let Some(mailbox) = row.move_box
            && !row.moved
        {
            let group_id = conv
                .group_id
                .as_slice()
                .try_into()
                .map_err(|_| EngineError::Invalid("a group id of another length".into()))?;
            return Ok(vec![NextPost {
                outbox: row.id,
                post: Vec::new(),
                token,
                next: row.next,
                live: false,
                groupinfo: None,
                external: false,
                signed_in: false,
                create: Some(CreateMove {
                    mailbox,
                    group_id,
                    epoch: epoch + 1,
                    from: tx.current_mailbox(conv.id)?.mailbox,
                }),
            }]);
        }
        tx.update_outbox(row.id, OutboxState::Sent, None, None, None)?;
        return Ok(vec![NextPost {
            outbox: row.id,
            post,
            token,
            next: row.next,
            live: false,
            create: None,
            groupinfo: row.groupinfo.clone(),
            external: false,
            signed_in: public,
        }]);
    }
    if let Some(row) = rows
        .iter()
        .find(|r| r.kind == OutboxKind::Proposal && !waiting(r))
    {
        let (post, epoch) = group::make_self_remove(tx, c, conv)?;
        tx.update_outbox(row.id, OutboxState::Sent, Some((&post, epoch)), None, None)?;
        return Ok(vec![NextPost {
            outbox: row.id,
            post,
            token,
            next: None,
            live: false,
            create: None,
            groupinfo: None,
            external: false,
            signed_in: false,
        }]);
    }
    if let Some(row) = rows
        .iter()
        .find(|r| r.kind == OutboxKind::Update && r.state == OutboxState::Queued && !waiting(r))
    {
        let row = row.clone();
        let (post, epoch) = group::make_update(tx, c, conv, &row)?;
        tx.update_outbox(row.id, OutboxState::Sent, Some((&post, epoch)), None, None)?;
        return Ok(vec![NextPost {
            outbox: row.id,
            post,
            token,
            next: None,
            live: false,
            create: None,
            groupinfo: None,
            external: false,
            signed_in: public,
        }]);
    }
    // No messages until the conversation is created, while it has a
    // last-resort leaf key (12.5), or once it is leaving (6.1).
    if conv.state != ConvState::Active || conv.last_resort {
        return Ok(Vec::new());
    }
    // 12.7: nothing while a leaf added by a commit the device could not
    // check is unconfirmed, since that leaf would read it.
    if tx.sending_held(conv.id)? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for row in rows
        .iter()
        .filter(|r| matches!(r.kind, OutboxKind::Message | OutboxKind::Live))
        .filter(|r| r.state == OutboxState::Queued && !waiting(r))
        .take(POST_BATCH)
    {
        let mut body = row
            .body
            .clone()
            .ok_or(EngineError::Invalid("a message with no body".into()))?;
        // 12.10: pending confirmation lines ride in the message. In a
        // public room, the period's pseudonym is settled first, so that
        // the ATTEST leaf confirmation (C3) writes carries the pseudonym
        // the message is sent with (7.3; task C5).
        if row.kind == OutboxKind::Message {
            if public {
                group::period_pseudonym(tx, c, conv)?;
            }
            match c.hooks.outgoing(tx, conv, row.id, &body) {
                super::confirm::Outgoing::Keep => {}
                super::confirm::Outgoing::Replace(b) => body = b,
                super::confirm::Outgoing::Wait => break,
            }
        }
        let (post, epoch) = group::encrypt(tx, c, conv, &body)?;
        tx.update_outbox(row.id, OutboxState::Sent, Some((&post, epoch)), None, None)?;
        out.push(NextPost {
            outbox: row.id,
            post,
            token: token.clone(),
            next: None,
            live: row.kind == OutboxKind::Live,
            create: None,
            groupinfo: None,
            external: false,
            signed_in: false,
        });
    }
    Ok(out)
}

fn job_done(job: JobId, conversation: Option<ConversationId>, error: Option<String>) -> Action {
    Action::Emit(Event::Conversation(ConversationEvent::JobDone {
        job,
        conversation,
        error,
    }))
}

impl Engine for ConversationEngine {
    fn handle(&mut self, cx: &Context, input: &Input<'_>) -> Vec<Action> {
        let mut out = Vec::new();
        let result = match input {
            Input::Ready { slot, kind } => self.on_ready(cx, *slot, *kind, &mut out),
            Input::Closed { slot } => {
                self.on_closed(*slot);
                Ok(())
            }
            Input::Line { message, .. } => self.on_line(cx, message, &mut out),
            Input::Reply {
                slot,
                token,
                response,
            } => self.on_reply(cx, *slot, *token, response, &mut out),
            Input::Tick { .. } => Ok(()),
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, "the group engine failed a step");
        }
        if let Err(e) = self.pump(cx, &mut out) {
            tracing::warn!(error = %e, "the group engine failed to send");
        }
        out
    }
}

/// Whether a change is the group engine's, for callers that wait on the
/// cache.
pub fn is_conversation_change(change: &Change) -> bool {
    matches!(change, Change::Conversation(_) | Change::Message(_))
}

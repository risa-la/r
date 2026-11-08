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
pub(crate) mod wire;

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
use risala_proto::names::{BoxName, Uid};
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

    /// Facts from key files and the key log, for the checks of 12.7. Task
    /// C1.
    fn key_facts<'a>(&'a self, tx: &'a Tx<'_>, account: AccountId) -> Box<dyn KeyFacts + 'a> {
        let _ = (tx, account);
        Box::new(UnknownFacts)
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
}

/// What an engine step works with.
pub(crate) struct Ctx<'a> {
    pub account: AccountId,
    pub uid: &'a Uid,
    pub host: &'a str,
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
    },
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
    host: String,
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
    started: bool,
    welcomes_listed: bool,
    self_requested: bool,
    last_refresh_check: u64,
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
            started: false,
            welcomes_listed: false,
            self_requested: false,
            last_refresh_check: 0,
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
            host: row.server.host().to_string().to_ascii_lowercase(),
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
        if me.guest {
            return Err(EngineError::Invalid("guests cannot do this".into()));
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
                    let device = identity.device_id?.0;
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
                        |b| RisalaConversation::direct(c.host, b, c.uid, peer),
                        adds,
                    )?;
                    Ok(Some((made.conv, Some(made))))
                }
                Job::PrivateRoom { name, .. } => {
                    let adds = kps_of(&|_| true);
                    let made = group::create(
                        tx,
                        c,
                        |b| RisalaConversation::private_room(c.host, b, name, c.uid),
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
                        |b| RisalaConversation::direct(c.host, b, c.uid, c.uid),
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
        let OrBlob::Inline(message) = &post.message else {
            // Blobs are task C4's (12.12): a post too large for a line is
            // skipped for now, and shows as a gap if it was a message.
            tracing::debug!("a post in a blob, not fetched yet");
            if let Some(seq) = post.seq {
                self.keep(
                    cx,
                    &me,
                    &post.mailbox,
                    seq.get(),
                    post.t.unix_millis(),
                    Vec::new(),
                    None,
                    out,
                )?;
            }
            return Ok(());
        };
        let bytes = message.decode();
        match post.seq {
            Some(seq) => {
                let next = post.next.map(|n| *n.as_bytes());
                self.keep(
                    cx,
                    &me,
                    &post.mailbox,
                    seq.get(),
                    post.t.unix_millis(),
                    bytes,
                    next,
                    out,
                )?;
                let follow = self.follows.get(&post.mailbox).copied();
                if let Some(Follow::Following {
                    fetching: false, ..
                }) = follow
                {
                    self.advance(cx, &me, &post.mailbox, out)?;
                    // A live post beyond a hole: fetch what is missing.
                    let behind = self.write(cx, &me, out, |tx, c| {
                        let Some(mb) = tx.mailbox(c.account, &post.mailbox)? else {
                            return Ok(None);
                        };
                        Ok(tx
                            .first_kept_seq(mb.conv, &post.mailbox)?
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
        message: Vec<u8>,
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
                    let _ = (seq, device);
                    // The sending device's leaf in that group is the own
                    // identity's leaf that is behind: replace each leaf of
                    // the own identity that posted nothing since; done as a
                    // RESYNC by leaf once the leaf is known. Not built yet.
                    tracing::debug!(?conv, "RESYNC from another own device");
                }
                Note::Unprocessable { conv, epoch, seq } => {
                    self.unprocessable.insert(conv, (epoch, seq));
                }
                Note::Undecryptable { conv, epoch } => {
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
                        if let Err(e) = r {
                            tracing::warn!(error = %e, "could not queue RESYNC");
                        }
                    }
                }
                Note::Committed { conv, own, removed } => {
                    self.proposal_timers.remove(&conv);
                    self.unprocessable.remove(&conv);
                    self.resynced.remove(&conv);
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
                    let _ = conv;
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
                        let (bytes, next) = match &post.message {
                            OrBlob::Inline(m) => (m.decode(), post.next.map(|n| *n.as_bytes())),
                            OrBlob::Blob(_) => (Vec::new(), None),
                        };
                        self.keep(
                            cx,
                            &me,
                            &mailbox,
                            seq,
                            post.t.unix_millis(),
                            bytes,
                            next,
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
                    self.write(cx, &me, out, |tx, c| {
                        if let Some(mb) = tx.mailbox(c.account, &mailbox)?
                            && mb.sync_point < to
                        {
                            tx.set_sync(mb.conv, &mailbox, to, None)?;
                        }
                        Ok(())
                    })?;
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
                        Ok(tx.first_kept_seq(mb.conv, &mailbox)?.map(|_| mb.sync_point))
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
            Pending::WelcomePut { id } => {
                let sent = match &response.end {
                    End::Ok(_) => true,
                    // The server will never take it (12.8).
                    End::Err(e) if e.code == ErrorCode::NotFound => true,
                    _ => false,
                };
                let retry = now + self.config.retry_ms.max(1_000);
                self.write(cx, &me, out, |tx, _| {
                    tx.welcome_done(id, sent, retry)?;
                    Ok(())
                })?;
            }
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
                End::Err(e) if e.code == ErrorCode::Stale => match row.kind {
                    OutboxKind::Commit => group::commit_lost(tx, c, &conv_row, &row)?,
                    _ => {
                        // 7.2: a device that holds the token of the epoch
                        // before puts this epoch's hash back with TOKEN,
                        // then posts again. If the post was for an older
                        // epoch, catching up shows it.
                        let (token, epoch) = group::send_token(tx, c, &conv_row)?;
                        let token_repair = match (row.epoch, tx.prev_token(conv)?) {
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
        let OrBlob::Inline(welcome) = welcome else {
            // A Welcome in a blob needs the blob store (12.12), task C4.
            tracing::info!("a Welcome in a blob, not fetched yet");
            return Ok(());
        };
        let sealed = welcome.decode();
        let joined = self.write(cx, &me, out, |tx, c| group::join_welcome(tx, c, &sealed));
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
                .any(|r| r.kind == ConvKind::WithYourself && r.state.in_group()))
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
        if self.conversing() {
            self.follow_due(cx, &me, now, out)?;
            self.post_due(cx, &me, out)?;
            self.welcomes_due(cx, &me, now, out)?;
        }
        self.timers_due(cx, &me, now, out)?;
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
            if mb.follow_after.is_some_and(|t| t > now) {
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
                    quiet: None,
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
        for conv in convs {
            if !conv.state.in_group() || in_flight.contains(&conv.id) {
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
            let posts = self.write(cx, me, out, |tx, c| next_posts(tx, c, &conv, now));
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
                let command = Command::Post {
                    mailbox: mailbox.mailbox,
                    token: PostToken::Send(token),
                    message: OrBlob::Inline(message),
                    live: p.live,
                    groupinfo: None,
                    next: p.next.map(TokenHash::from_bytes),
                    cid: None,
                };
                self.send(
                    out,
                    Target::Mailbox(mailbox.mailbox),
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
        let target = self.fresh(me);
        for w in due {
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
                Pending::WelcomePut { id: w.id },
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
                    group::queue_intent(tx, conv, &Intent::default(), c.now)?;
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
            let target = self.write(cx, me, out, |tx, _| {
                let Some(l) = tx.leaf(conv, leaf)? else {
                    return Ok(None);
                };
                Ok(l.device_id.map(|d| (l.uid, d)))
            })?;
            if let Some((uid, device)) = target {
                let (_, actions) = self.start(cx, Job::Replace { conv, uid, device });
                out.extend(actions);
            }
        }
        // 12.7: the weekly fresh-leaf commit, checked every ten minutes.
        if now >= self.last_refresh_check + 600_000 {
            self.last_refresh_check = now;
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
) -> Result<Vec<NextPost>, EngineError> {
    let rows = tx.pending_outbox(conv.id)?;
    let waiting = |r: &OutboxRow| r.not_before.is_some_and(|t| t > now);
    if rows.iter().any(|r| r.state == OutboxState::Sent) {
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
        }]);
    }
    // No messages until the conversation is created, while it has a
    // last-resort leaf key (12.5), or once it is leaving (6.1).
    if conv.state != ConvState::Active || conv.last_resort {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for row in rows
        .iter()
        .filter(|r| matches!(r.kind, OutboxKind::Message | OutboxKind::Live))
        .filter(|r| r.state == OutboxState::Queued && !waiting(r))
        .take(POST_BATCH)
    {
        let body = row
            .body
            .clone()
            .ok_or(EngineError::Invalid("a message with no body".into()))?;
        let (post, epoch) = group::encrypt(tx, c, conv, &body)?;
        tx.update_outbox(row.id, OutboxState::Sent, Some((&post, epoch)), None, None)?;
        out.push(NextPost {
            outbox: row.id,
            post,
            token: token.clone(),
            next: None,
            live: row.kind == OutboxKind::Live,
            create: None,
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

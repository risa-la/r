//! The sync engine: a state machine with no I/O that keeps the
//! [`Store`](crate::store::Store) in step with a server (7.1-7.3, 7.6).
//!
//! There is one [`SyncEngine`] per signed-in connection. Make a new one
//! after every reconnect: everything it keeps in memory is about the
//! connection, and everything else is in the store.
//!
//! # Driving it
//!
//! - Call [`SyncEngine::start`] right after signing in.
//! - Feed it every line the server sends, **in the order they arrive**:
//!   - Lines that are not part of a response (live events, READ, DROP and
//!     the rest) go to [`SyncEngine::handle_line`].
//!   - When the final OK or ERR of a command the engine asked for arrives,
//!     pass that command's `ref`-tagged lines and its final line to
//!     [`SyncEngine::handle_reply`], at that point in the stream.
//!
//!   The order matters: a live event that arrived before a response's
//!   final line must be handled before the response (3.6).
//! - Every call returns an [`Output`]: commands to send, each with the
//!   [`ReqId`] to answer it with, changes for the UI, and notifications.
//!   Send the commands in the order given.
//! - The UI asks for work with [`SyncEngine::send`],
//!   [`SyncEngine::join`], [`SyncEngine::part`], [`SyncEngine::mark_read`],
//!   [`SyncEngine::load_older`], [`SyncEngine::fetch`] and
//!   [`SyncEngine::download`], [`SyncEngine::delete`],
//!   [`SyncEngine::info`] and [`SyncEngine::request`]; and about people with
//!   [`SyncEngine::typing`], [`SyncEngine::set_name`],
//!   [`SyncEngine::members`], [`SyncEngine::whois`], [`SyncEngine::block`],
//!   [`SyncEngine::unblock`] and [`SyncEngine::blocks`].
//!
//! # People
//!
//! Display names (8.2), room members (8.3) and blocks (5.7) are stored.
//! Typing (8.1) and presence (8.3) are true only while connected, so they
//! are not: the engine reports them as [`Signal`]s, and the caller keeps
//! them in memory.
//! - If a call fails with a store error, drop the connection and the
//!   engine, and start again after reconnecting.
//!
//! # What it guarantees
//!
//! These are the invariants of the TLA+ model in `proofs/sync`:
//!
//! - **No mixed history.** A conversation's stored events all come from
//!   the conversation whose id is stored. Ids from SYNC, JOIN (event and
//!   OK), INFO, HISTORY and RELATED are compared with the stored one, and
//!   a different id discards the history first (7.1, 7.2, 6.1). So does a
//!   head below the sync point the conversation had when the command was
//!   sent (7.1), which keeps the outbox: the room is the same. Events
//!   stored past that point, by this connection or by another process
//!   sharing the cache, do not count. Live events are stored only
//!   once the conversation's id is known on this connection (7.1 step 6).
//! - **Truthful sync points.** The sync point is the seq up to which every
//!   event the server still keeps is stored. It moves over HISTORY pages
//!   and over stored events that directly follow it, never over a gap
//!   (7.1 step 3). Catching up starts from it, so a connection that drops
//!   halfway leaves nothing behind.
//! - **Caught up means complete.** When a conversation has caught up, the
//!   store holds every event the server keeps, with deletions applied.
//! - **At most once.** Each outbox message has its own cid and is bound to
//!   the conversation's id. Entries are picked and marked as sent in one
//!   write transaction, with a claim naming the connection, so two
//!   processes sharing the cache never send the same one, and neither
//!   settles one the other still waits on. It is resent after a
//!   reconnect only while that id still matches, only within 23 hours,
//!   and only by an identity or by a guest whose session was resumed
//!   ([`SyncEngine::set_resumed`]): a guest's cids count only within one
//!   session (7.6).

mod e2ee;
mod e2ee_keys;
mod engine;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::command::Command;
use risala_proto::names::{Conv, Room, Uid};
use risala_proto::server::{ErrResponse, OkResponse, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::Presence;

use crate::store::{Change, StoreError};

pub use e2ee_keys::OwnDeviceState;
pub use engine::{SyncEngine, TYPING_REPEAT};

/// Settings for a [`SyncEngine`].
#[derive(Clone)]
pub struct SyncConfig {
    /// The `limit` for HISTORY and RELATED pages (7.2, 7.3).
    pub page_size: u64,
    /// When a conversation is more than this many events behind, fetch only
    /// the newest page and load the rest as the user scrolls back (7.1 step
    /// 4), or on [`SyncEngine::download`]. `None` always catches up fully.
    pub lazy_gap: Option<u64>,
    /// How long after first sending it an unanswered message may be sent
    /// again. The server remembers cids for 24 hours (7.6).
    pub resend_window: Duration,
    /// How long a message another process sharing the cache sent stays
    /// its own to settle (7.6). Until then this engine neither sends it
    /// again nor marks it failed, since that process may still get its
    /// `OK`. After it, the other connection is taken to be gone. Pick it
    /// well above how long a connection may go without an answer before
    /// its keepalive closes it (11).
    pub claim_lease: Duration,
    /// Where the time comes from.
    pub clock: Clock,
    /// For an identity, ask BLOCKS on each connection (5.7), so that
    /// blocks made on the account's other devices are known. On by
    /// default.
    pub fetch_blocks: bool,
    /// For an identity with a device key, run end-to-end encryption
    /// (Section 12): KeyPackages, Welcomes, groups and encrypted messages.
    /// On by default. Without it, nothing is sent to direct conversations
    /// or encrypted rooms (12.3).
    pub encryption: bool,
    /// How often to ask KEYPKG GET again for the other participant of a
    /// direct conversation whose messages are held because none of their
    /// devices is in its group yet (12.6). Each new connection asks at
    /// once.
    pub peer_retry: Duration,
}

impl Default for SyncConfig {
    fn default() -> SyncConfig {
        SyncConfig {
            page_size: risala_proto::types::DEFAULT_LIMIT,
            lazy_gap: Some(500),
            resend_window: Duration::from_secs(23 * 3600),
            claim_lease: Duration::from_secs(300),
            clock: Clock::system(),
            fetch_blocks: true,
            encryption: true,
            peer_retry: Duration::from_secs(5 * 60),
        }
    }
}

impl fmt::Debug for SyncConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncConfig")
            .field("page_size", &self.page_size)
            .field("lazy_gap", &self.lazy_gap)
            .field("resend_window", &self.resend_window)
            .field("claim_lease", &self.claim_lease)
            .field("fetch_blocks", &self.fetch_blocks)
            .field("encryption", &self.encryption)
            .field("peer_retry", &self.peer_retry)
            .finish_non_exhaustive()
    }
}

/// A source of the current time, replaceable in tests.
#[derive(Clone)]
pub struct Clock(Arc<dyn Fn() -> Timestamp + Send + Sync>);

impl Clock {
    /// The system clock, [`Timestamp::now`].
    pub fn system() -> Clock {
        Clock(Arc::new(Timestamp::now))
    }

    /// A clock that calls `f`.
    pub fn new(f: impl Fn() -> Timestamp + Send + Sync + 'static) -> Clock {
        Clock(Arc::new(f))
    }

    /// The time now.
    pub fn now(&self) -> Timestamp {
        (self.0)()
    }
}

/// Identifies a command the engine asked to send, so that its reply can be
/// handed back with [`SyncEngine::handle_reply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReqId(u64);

impl ReqId {
    /// The number, unique within one engine.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// A command to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// The id to pass back with its reply.
    pub req: ReqId,
    /// The command. Give it a `ref` if the session wants one (3.6).
    pub command: Command,
}

/// The answer to one command: its `ref`-tagged lines and its final line
/// (3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The lines before the final response, in order.
    pub lines: Vec<ServerMessage>,
    /// The final response.
    pub outcome: Outcome,
}

impl Reply {
    /// A reply from its lines and its final line. A final line that is
    /// not OK or ERR gives [`Outcome::Failed`].
    pub fn new(lines: Vec<ServerMessage>, last: ServerLine) -> Reply {
        let outcome = match last {
            ServerLine::Ok(ok) => Outcome::Ok(ok),
            ServerLine::Err(err) => Outcome::Err(err),
            _ => Outcome::Failed,
        };
        Reply { lines, outcome }
    }
}

/// How a command ended (3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `OK`, with its result values.
    Ok(OkResponse),
    /// `ERR`.
    Err(ErrResponse),
    /// The final line could not be parsed, which counts as a general
    /// failure (2.3).
    Failed,
    /// The command could not be written to the connection, for example
    /// because the line would be too long, so the server never saw it.
    NotSent,
}

/// The result of a command the UI asked for (JOIN, PART, INFO, READ, NAME,
/// MEMBERS, WHOIS, BLOCK, UNBLOCK, BLOCKS, and those sent with
/// [`SyncEngine::request`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed {
    /// The request, as returned in [`Output::send`].
    pub req: ReqId,
    /// How it ended.
    pub outcome: Outcome,
}

/// Something to tell the user that is not history (6.4, 7.1, 10.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// Someone invited the account to a room it is not in (6.4).
    Invited {
        /// The room.
        room: Room,
        /// Who sent the invitation.
        by: Uid,
    },
    /// The account was kicked from a room (6.4).
    Kicked {
        /// The room.
        room: Room,
        /// Who kicked it.
        by: Uid,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// The account was banned from a room (6.4).
    Banned {
        /// The room.
        room: Room,
        /// Who banned it.
        by: Uid,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// A commit of an encrypted conversation failed a check of 12.6: the
    /// device can no longer follow its group, and sends nothing more in it
    /// (12.6). Warn the user.
    GroupRejected {
        /// The conversation.
        conv: Conv,
    },
    /// Two different history keys arrived for one epoch (12.9). The one
    /// kept is the device's own, then one from the identity's devices or
    /// backup, then the first. Warn the user.
    KeyConflict {
        /// The conversation's id.
        id: risala_proto::names::Id,
        /// The epoch.
        epoch: u64,
    },
    /// A new device of the identity joined its conversation with itself
    /// (12.9, 12.12). It gets no history keys from this device until the
    /// user confirms that it is theirs, with
    /// [`SyncEngine::confirm_device`].
    NewDevice {
        /// The device key's fingerprint (12.12).
        fingerprint: String,
    },
    /// SYNC no longer lists a conversation the account was in: it left, or
    /// was kicked or banned, or the room was dropped (7.1). Its history is
    /// kept.
    Left {
        /// The conversation.
        conv: Conv,
    },
    /// An operator dropped a room (10.4). Its history was removed.
    Dropped {
        /// The room.
        room: Room,
        /// The reason, escaped; empty if none.
        reason: String,
    },
}

/// Something about people that the engine does not store, because it is
/// only true while connected: typing and presence (8.1, 8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// Someone is typing in a conversation (8.1). It lasts 6 seconds,
    /// unless repeated.
    Typing {
        /// The conversation.
        conv: Conv,
        /// Who.
        from: Uid,
    },
    /// Someone else's message arrived live, which ends their typing (8.1).
    Spoke {
        /// The conversation.
        conv: Conv,
        /// Who.
        from: Uid,
    },
    /// A user's presence, from PRESENCE, MEMBER or USER (8.3).
    Presence {
        /// The user.
        uid: Uid,
        /// Their presence, as the server said it.
        presence: Presence,
    },
}

/// What a call to the engine produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Commands to send, in order.
    pub send: Vec<Outgoing>,
    /// Changes the store made, for the UI.
    pub changes: Vec<Change>,
    /// Things to tell the user.
    pub notifications: Vec<Notification>,
    /// Results of the commands the UI asked for.
    pub completed: Vec<Completed>,
    /// Call [`SyncEngine::resume_outbox`] after this long: the server asked
    /// to wait before sending more messages (`rate-limited`), or another
    /// process's claim on an outbox entry runs out then
    /// ([`SyncConfig::claim_lease`]), and the entry is this engine's to
    /// settle if that process has not.
    pub retry_after: Option<Duration>,
    /// Typing and presence, in the order they arrived.
    pub signals: Vec<Signal>,
    /// Identities whose key files to fetch (4.4, 12.12). Hand each back
    /// with [`SyncEngine::key_file`].
    pub key_files: Vec<Uid>,
    /// A recovery key another device of the identity sent (12.10). Keep it
    /// as the device key is kept.
    pub recovery: Option<risala_mls::RecoveryKey>,
}

impl Output {
    /// Whether there is nothing in it.
    pub fn is_empty(&self) -> bool {
        *self == Output::default()
    }
}

/// The engine could not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The store failed. Drop the connection and the engine.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The message is not valid: blank text, a reaction that is too long,
    /// or a file with an edit or a reaction (5.3, 5.6).
    #[error("invalid message: {0}")]
    Invalid(String),
    /// The account is not in this room, so there is nothing to bind a
    /// message to (7.6).
    #[error("not in {0}")]
    NotJoined(Conv),
}

#[cfg(test)]
mod e2ee_tests;
#[cfg(test)]
mod sim;
#[cfg(test)]
mod tests;

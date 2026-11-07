//! Persistent storage behind a trait, with a SQLite implementation.
//!
//! Owned by task A in docs/plans/M2-M5.md.
//!
//! The [`Store`] trait is synchronous: SQLite calls block, so the hub runs
//! them on tokio's blocking pool, never on its worker threads. The store
//! keeps everything that outlives a connection: server settings (10.6),
//! conversations and their ids (5.1), events (5.2), room settings (6.2),
//! the membership of identities (6.1), roles (6.3), invitations and bans
//! (6.4), read markers (7.4), cids (7.6) and, from M3 and M4 on, identities,
//! blocks, reports, uploads and push registrations. Guests and their room
//! memberships are never stored (4.2).
//!
//! Appending an event assigns the next seq, stores the event and applies
//! what it changes (membership, settings, roles and so on) in one
//! transaction, so a seq is never lost or used twice (5.2).

mod schema;
mod sqlite;

use std::fmt;

use risala_proto::names::{Id, Room, Seq, Uid};
use risala_proto::server::{Attachment, Event, EventBody, EventMeta, Message};
use risala_proto::time::Timestamp;
use risala_proto::types::{
    Cid, GuestAccess, Relation, Role, RoomRetention, RoomSetting, ServerRetention, ServerSetting,
};

pub use sqlite::SqliteStore;

/// How long a cid protects against a resent message (7.6).
pub const CID_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// The length of the ids the store makes for conversations (5.1) and
/// reports (5.8).
pub const ID_LEN: usize = 12;

/// An error from the store. The hub logs it and replies `ERR internal`
/// (3.7).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failed.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A stored value could not be read back, or the database is newer than
    /// this server.
    #[error("corrupt database: {0}")]
    Corrupt(String),
    /// The database could not be set up as the store needs, for example
    /// in WAL mode.
    #[error("database setup: {0}")]
    Setup(String),
    /// The operating system's random source failed.
    #[error("random source: {0}")]
    Random(String),
    /// The conversation does not exist (any more).
    #[error("no such conversation")]
    NoConversation,
    /// A blocking task panicked or was cancelled.
    #[error("store task failed: {0}")]
    Task(String),
}

/// A shorthand for store results.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// The store's own key for a conversation. Unlike the [`Id`] it is not sent
/// to clients. It is never reused either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConvKey(pub i64);

impl fmt::Display for ConvKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The server settings of ADMIN SET (10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSettings {
    /// Whether guests may connect (4.2).
    pub guests: bool,
    /// Whether REGISTER is accepted (4.6).
    pub registration: bool,
    /// The server's retention period (7.5).
    pub retention: ServerRetention,
    /// The greeting's welcome text, escaped, at most 512 bytes (4.1).
    pub welcome: String,
}

impl ServerSettings {
    /// Applies one ADMIN SET (10.6). Unknown keys change nothing.
    pub fn apply(&mut self, setting: &ServerSetting) {
        match setting {
            ServerSetting::Guests(v) => self.guests = *v,
            ServerSetting::Registration(v) => self.registration = *v,
            ServerSetting::Retention(v) => self.retention = *v,
            ServerSetting::Welcome(v) => self.welcome = v.clone(),
            ServerSetting::Other { .. } => {}
        }
    }

    /// The settings as ADMIN SET values, in a fixed order.
    pub fn to_settings(&self) -> [ServerSetting; 4] {
        [
            ServerSetting::Guests(self.guests),
            ServerSetting::Registration(self.registration),
            ServerSetting::Retention(self.retention),
            ServerSetting::Welcome(self.welcome.clone()),
        ]
    }
}

/// A room's settings (6.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoomSettings {
    /// `topic`: escaped text, at most 512 bytes, may be empty.
    pub topic: String,
    /// `public`: whether LIST shows the room and anyone may join.
    pub public: bool,
    /// `guests`: whether guests may join, read and send.
    pub guests: GuestAccess,
    /// `retention`: the room's own retention period (7.5).
    pub retention: RoomRetention,
}

impl RoomSettings {
    /// The settings of a new room: no topic, public, guests may write, and
    /// the server's retention (6.2).
    pub fn new() -> RoomSettings {
        RoomSettings {
            topic: String::new(),
            public: true,
            guests: GuestAccess::Write,
            retention: RoomRetention::Server,
        }
    }

    /// Applies a SET (6.2). Unknown keys change nothing.
    pub fn apply(&mut self, setting: &RoomSetting) {
        match setting {
            RoomSetting::Topic(v) => self.topic = v.clone(),
            RoomSetting::Public(v) => self.public = *v,
            RoomSetting::Guests(v) => self.guests = *v,
            RoomSetting::Retention(v) => self.retention = *v,
            RoomSetting::Other { .. } => {}
        }
    }

    /// The settings in the order of the snapshot after JOIN and INFO:
    /// `topic`, `public`, `guests`, `retention` (1.4, 6.1, 6.2).
    pub fn to_settings(&self) -> [RoomSetting; 4] {
        [
            RoomSetting::Topic(self.topic.clone()),
            RoomSetting::Public(self.public),
            RoomSetting::Guests(self.guests),
            RoomSetting::Retention(self.retention),
        ]
    }
}

/// A room as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRecord {
    /// The store's key for it.
    pub key: ConvKey,
    /// The room's name.
    pub room: Room,
    /// The room's id (5.1).
    pub id: Id,
    /// The newest seq, or `None` if the room has no events yet: a room from
    /// the configuration that nobody has joined.
    pub head: Option<Seq>,
    /// When the room was created.
    pub created: Timestamp,
    /// Its settings (6.2).
    pub settings: RoomSettings,
    /// The identities that are members (6.1), in order. Guests are never
    /// stored.
    pub members: Vec<Uid>,
    /// The holders of `owner` and `mod`, members or not (6.3).
    pub roles: Vec<(Uid, Role)>,
}

/// What an event says, apart from its conversation, seq, time and author.
///
/// Stored events do not name their conversation: in a direct conversation
/// the name depends on who receives the line (5.2), so it is filled in by
/// [`StoredEvent::to_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// MSG (5.3).
    Msg {
        /// The `reply`, `edit` or `react` tag.
        relation: Option<Relation>,
        /// The attached file (5.6).
        file: Option<Attachment>,
        /// The text, escaped. Empty once deleted (5.4).
        text: String,
    },
    /// DELETE of message `target` (5.4).
    Delete {
        /// The deleted message.
        target: Seq,
    },
    /// JOIN (6.1).
    Join,
    /// PART (6.1).
    Part {
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// INVITE (6.4).
    Invite {
        /// The invitee.
        uid: Uid,
    },
    /// KICK (6.4).
    Kick {
        /// Who was kicked.
        uid: Uid,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// BAN (6.4).
    Ban {
        /// Who was banned.
        uid: Uid,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// UNBAN (6.4).
    Unban {
        /// Who was unbanned.
        uid: Uid,
    },
    /// SET (6.2).
    Set(RoomSetting),
    /// ROLE (6.3).
    Role {
        /// Whose role changed.
        uid: Uid,
        /// The new role.
        role: Role,
    },
}

impl EventKind {
    /// The verb, in upper case (5.2).
    pub fn verb(&self) -> &'static str {
        match self {
            EventKind::Msg { .. } => "MSG",
            EventKind::Delete { .. } => "DELETE",
            EventKind::Join => "JOIN",
            EventKind::Part { .. } => "PART",
            EventKind::Invite { .. } => "INVITE",
            EventKind::Kick { .. } => "KICK",
            EventKind::Ban { .. } => "BAN",
            EventKind::Unban { .. } => "UNBAN",
            EventKind::Set(_) => "SET",
            EventKind::Role { .. } => "ROLE",
        }
    }
}

/// An event to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent {
    /// When the server accepted it.
    pub t: Timestamp,
    /// Its author.
    pub from: Uid,
    /// What it says.
    pub kind: EventKind,
    /// The cid of a MSG from an identity (7.6). If `from` sent a message
    /// with this cid to the same conversation in the last 24 hours, nothing
    /// is appended. Guests' cids are checked by the hub, per connection.
    pub cid: Option<Cid>,
}

/// The result of [`Store::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    /// The event was stored with this seq.
    New(Seq),
    /// The cid matched an earlier message, which has this seq (7.6).
    /// Nothing was stored.
    Duplicate(Seq),
}

/// An event as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// Its seq.
    pub seq: Seq,
    /// When the server accepted it.
    pub t: Timestamp,
    /// Its author.
    pub from: Uid,
    /// What it says. A deleted message has empty text and no file.
    pub kind: EventKind,
    /// Whether its content was removed (5.4).
    pub deleted: bool,
}

impl StoredEvent {
    /// The event as a line (5.2), for a conversation named `conv` as the
    /// receiver sees it, with id `id` for the `id` tag of JOIN (6.1). A
    /// deleted message is a placeholder: empty text and no file (5.4).
    pub fn to_event(&self, conv: impl Into<risala_proto::names::Conv>, id: &Id) -> Event {
        let conv = conv.into();
        let room = || match &conv {
            risala_proto::names::Conv::Room(room) => room.clone(),
            // Only MSG and DELETE happen in direct conversations.
            risala_proto::names::Conv::Uid(_) => unreachable!("room event outside a room"),
        };
        let body = match &self.kind {
            EventKind::Msg {
                relation,
                file,
                text,
            } => EventBody::Msg(Message {
                conv: conv.clone(),
                relation: *relation,
                file: if self.deleted { None } else { file.clone() },
                deleted: self.deleted,
                text: if self.deleted {
                    String::new()
                } else {
                    text.clone()
                },
            }),
            EventKind::Delete { target } => EventBody::Delete {
                conv: conv.clone(),
                seq: *target,
            },
            EventKind::Join => EventBody::Join {
                room: room(),
                id: id.clone(),
            },
            EventKind::Part { reason } => EventBody::Part {
                room: room(),
                reason: reason.clone(),
            },
            EventKind::Invite { uid } => EventBody::Invite {
                room: room(),
                uid: uid.clone(),
            },
            EventKind::Kick { uid, reason } => EventBody::Kick {
                room: room(),
                uid: uid.clone(),
                reason: reason.clone(),
            },
            EventKind::Ban { uid, reason } => EventBody::Ban {
                room: room(),
                uid: uid.clone(),
                reason: reason.clone(),
            },
            EventKind::Unban { uid } => EventBody::Unban {
                room: room(),
                uid: uid.clone(),
            },
            EventKind::Set(setting) => EventBody::Set {
                room: room(),
                setting: setting.clone(),
            },
            EventKind::Role { uid, role } => EventBody::Role {
                room: room(),
                uid: uid.clone(),
                role: *role,
            },
        };
        Event::new(
            EventMeta {
                seq: self.seq,
                t: self.t,
                from: self.from.clone(),
            },
            body,
        )
    }

    /// Whether this is a MSG that is not an edit or a reaction, and so may
    /// be the target of a relation (5.3).
    pub fn is_plain_message(&self) -> bool {
        matches!(
            self.kind,
            EventKind::Msg {
                relation: None | Some(Relation::Reply(_)),
                ..
            }
        )
    }
}

/// Which events [`Store::history`] returns (7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryQuery {
    /// With `Some`, the earliest events after this seq (0 means from the
    /// start). With `None`, the latest events.
    pub after: Option<u64>,
    /// Only events before this seq.
    pub before: Option<Seq>,
    /// The most events to return, at least 1.
    pub limit: u64,
}

/// A page of events, in ascending seq order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The events.
    pub events: Vec<StoredEvent>,
    /// With `after`: whether there are more events after the last one, still
    /// before `before`. Without: whether there are older events before the
    /// first one (7.2).
    pub more: bool,
}

/// Persistent storage for the hub.
///
/// Every method blocks. Implementations are shared between threads.
pub trait Store: Send + Sync + 'static {
    /// Returns the server settings (10.6), first storing `defaults` for any
    /// that are not stored yet. This is how the configuration file's
    /// `[server]` section reaches a new database.
    fn load_server_settings(&self, defaults: &ServerSettings) -> Result<ServerSettings>;

    /// Changes one server setting (10.6).
    fn set_server_setting(&self, setting: &ServerSetting) -> Result<()>;

    /// Returns the room, creating it first if it does not exist, with no
    /// owner, no events and the default settings. For the rooms of the
    /// configuration file.
    fn ensure_room(&self, room: &Room, now: Timestamp) -> Result<RoomRecord>;

    /// Every room, in name order.
    fn rooms(&self) -> Result<Vec<RoomRecord>>;

    /// One room, or `None` if it does not exist.
    fn room(&self, room: &Room) -> Result<Option<RoomRecord>>;

    /// Appends an event to a conversation: assigns the next seq (5.2),
    /// stores the event and applies its effects, all in one transaction.
    ///
    /// Effects: JOIN and PART change the membership of identities (guests
    /// are not stored); SET changes the room's settings; ROLE, INVITE, KICK,
    /// BAN and UNBAN change roles, invitations, bans and membership (6.3,
    /// 6.4); DELETE erases the text of its target and of the target's edits
    /// and reactions, and marks them deleted (5.4). With a matching cid
    /// (7.6) nothing is stored.
    fn append(&self, conv: ConvKey, event: &NewEvent) -> Result<Appended>;

    /// One event, or `None` if it does not exist or has expired.
    fn event(&self, conv: ConvKey, seq: Seq) -> Result<Option<StoredEvent>>;

    /// A page of events (7.2).
    fn history(&self, conv: ConvKey, query: HistoryQuery) -> Result<Page>;

    /// The seq of the message `from` sent with `cid` to the conversation
    /// within the 24 hours before `now` (7.6), if any.
    fn cid_seq(&self, conv: ConvKey, from: &Uid, cid: &Cid, now: Timestamp) -> Result<Option<Seq>>;

    /// Forgets cids older than `before` (7.6).
    fn prune_cids(&self, before: Timestamp) -> Result<u64>;
}

/// Makes a new id of [`ID_LEN`] random characters of `a-z 0-9` (5.1). The
/// caller makes sure it was never used before.
pub fn random_id() -> Result<Id> {
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(ID_LEN);
    let mut buf = [0u8; 32];
    while out.len() < ID_LEN {
        getrandom::fill(&mut buf).map_err(|e| StoreError::Random(e.to_string()))?;
        // 252 = 7 * 36: rejecting larger bytes keeps the choice uniform.
        for &b in buf.iter().filter(|&&b| b < 252) {
            if out.len() == ID_LEN {
                break;
            }
            out.push(char::from(ALPHABET[usize::from(b % 36)]));
        }
    }
    out.parse()
        .map_err(|e| StoreError::Corrupt(format!("made a bad id: {e}")))
}

#[cfg(test)]
mod tests;

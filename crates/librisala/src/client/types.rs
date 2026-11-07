//! The plain data types of the client API: owned values with no generics
//! or borrows, so that they cross an FFI boundary as they are.

use risala_proto::error::ErrorCode;
use risala_proto::server::{EventBody, ServerLine, ServerMessage};
use risala_proto::text::unescape;
use risala_proto::types::RoomSetting;

use crate::addr::TrustRecord;
use crate::conn::{self, TrustError};
use crate::store::{
    ConversationSummary, FailReason, OutboxItem, OutboxState, StoreError, TimelineItem,
};
use crate::sync::SyncError;

/// Something the client could not do.
///
/// Trust failures (2.2) carry the fingerprint, so the app can show it and
/// let the user accept it with
/// [`Client::accept_fingerprint`](super::Client::accept_fingerprint).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The server's certificate is not CA-valid and nothing is recorded
    /// for it yet (2.2). Show `fingerprint`, and if the user accepts,
    /// call [`Client::accept_fingerprint`](super::Client::accept_fingerprint)
    /// and connect again.
    #[error("unknown certificate for {server}: {fingerprint} ({reason})")]
    UnknownCertificate {
        /// The server address.
        server: String,
        /// The fingerprint of the certificate's public key, `sha256:...`.
        fingerprint: String,
        /// Why the certificate is not CA-valid.
        reason: String,
    },
    /// The certificate does not match what is recorded for the server: a
    /// different pin, or "CA" (2.2). The client refuses to connect until
    /// the user removes the record with
    /// [`Client::forget_trust`](super::Client::forget_trust).
    #[error("certificate for {server} is {presented}, but {recorded} is recorded ({reason})")]
    CertificateMismatch {
        /// The server address.
        server: String,
        /// What is recorded: `CA` or a fingerprint.
        recorded: String,
        /// The fingerprint the server showed.
        presented: String,
        /// Why the certificate is not CA-valid.
        reason: String,
    },
    /// [`Client::accept_fingerprint`](super::Client::accept_fingerprint)
    /// was asked to trust a fingerprint, but the server already has a
    /// different trust record (2.2). Nothing was changed. The user must
    /// remove the record first, with
    /// [`Client::forget_trust`](super::Client::forget_trust).
    #[error("{server} is already trusted with {recorded}")]
    AlreadyTrusted {
        /// The server address.
        server: String,
        /// What is recorded: `CA` or a fingerprint.
        recorded: String,
    },
    /// Connecting or signing in failed. `permanent` is set when retrying
    /// cannot help without the user, as with `auth-failed`.
    #[error("{message}")]
    Connection {
        /// What went wrong, to show in the user's language.
        kind: ConnectionErrorKind,
        /// What went wrong, in English, for logs.
        message: String,
        /// Whether retrying cannot help.
        permanent: bool,
    },
    /// The server refused to sign in, to register, or to change the
    /// identity's keys or delete it, or the client cannot ask it to (4.2,
    /// 4.5-4.8). `kind` says why.
    #[error("{message}")]
    Refused {
        /// Why, to show in the user's language.
        kind: RefusedKind,
        /// What went wrong, in English, for logs. The server's message
        /// if it sent one.
        message: String,
        /// The `retry` tag of the server's `ERR`, in seconds, if it sent
        /// one (3.2). A [`RefusedKind::Forbidden`] with it passes with
        /// time, like a rate limit. One without it does not: closed
        /// registration, a ban or server policy.
        retry_after_secs: Option<u64>,
    },
    /// The server answered `ERR` (3.7).
    #[error("{code}: {message}")]
    Server {
        /// The error code, such as `not-found` or `forbidden`.
        code: String,
        /// The message for people, unescaped; empty if none.
        message: String,
    },
    /// The account is not signed in, and this needs a connection.
    #[error("not connected")]
    NotConnected,
    /// The account is not in this room, so a message has nothing to be
    /// bound to (7.6).
    #[error("not in {0}")]
    NotJoined(String),
    /// A server address, name, room or message that is not valid.
    #[error("invalid {0}")]
    Invalid(String),
    /// The cache failed.
    #[error("cache: {0}")]
    Store(String),
    /// The key store failed, or holds no key for the identity.
    #[error("keys: {message}")]
    Keys {
        /// What went wrong, to show in the user's language.
        kind: KeyErrorKind,
        /// What went wrong, in English, for logs.
        message: String,
    },
}

/// Why connecting or signing in failed ([`ClientError::Connection`]), so
/// that apps can say it in the user's language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionErrorKind {
    /// The network failed: no route, refused, reset, or name resolution.
    Network,
    /// Connecting took too long.
    Timeout,
    /// TLS failed, for a reason other than the ones below.
    Tls,
    /// The server does not offer the post-quantum key exchange
    /// X25519MLKEM768, which risala requires (2.1).
    KeyExchange,
    /// The server's certificate could not be read (2.2).
    BadCertificate,
    /// The trust records could not be read or written (2.2).
    TrustStore,
    /// The server speaks another version of the protocol (3.8).
    UnsupportedVersion,
    /// The server broke the protocol: a bad greeting, or an answer that
    /// could not be read.
    Protocol,
    /// The connection closed.
    Closed,
    /// The sign-in nonce was used up; connecting again helps (4.5).
    NonceUsed,
    /// The client could not start its runtime.
    Runtime,
}

/// Why the key store failed ([`ClientError::Keys`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyErrorKind {
    /// No key store was given in the client's options.
    NoKeyStore,
    /// The key store holds no key for the identity.
    NoKey,
    /// The identity already has a different device key, and replacing it
    /// was not asked for.
    Exists,
    /// A private key to import is not a PEM PKCS#8 ML-DSA-44 key (App. A),
    /// or a public key or key file line is not valid (4.4).
    BadKey,
    /// The key store failed.
    Failed,
}

/// Why the server refused, or the client could not ask
/// ([`ClientError::Refused`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusedKind {
    /// `auth-failed`: the identity's key file does not list this device's
    /// key, or the server could not fetch the file (4.4, 4.5). For
    /// REGISTER, the signature did not verify (4.6).
    AuthFailed,
    /// `name-taken`: the name is registered already (4.6), or a guest
    /// name is in use (4.2).
    NameTaken,
    /// `forbidden`: registration is closed, the user or address is
    /// banned, or server policy says no. With
    /// [`retry_after_secs`](ClientError::Refused::retry_after_secs), a
    /// limit that passes with time.
    Forbidden,
    /// `rate-limited`: too many attempts; see
    /// [`retry_after_secs`](ClientError::Refused::retry_after_secs).
    RateLimited,
    /// The server does not offer registration: INFO says `register=no`,
    /// or REGISTER got `not-supported` (4.6, 8.5).
    NoRegistration,
    /// An identity cannot sign in to, or register on, a server given as
    /// an IP address, which sends no hostname (2.1, 4.5).
    NoHostname,
    /// The server does not host this identity, so KEY cannot change its
    /// keys: they are in the identity's own key file (4.4, 4.7).
    NotHosted,
    /// The server refused to remove the identity's last key (4.7).
    LastKey,
    /// UNREGISTER needs the account's own uid typed out, and this one is
    /// different (4.8).
    WrongUid,
    /// A guest has no keys and nothing to unregister (4.2).
    Guest,
    /// `not-supported`: the server does not offer this, for example
    /// signing in as an identity at all, or UNREGISTER's `purge`.
    NotSupported,
}

impl RefusedKind {
    /// The kind for a sign-in, REGISTER, KEY or UNREGISTER refused with
    /// `code`, or `None` for codes that are general failures.
    pub(crate) fn of(code: &ErrorCode) -> Option<RefusedKind> {
        Some(match code {
            ErrorCode::AuthFailed => RefusedKind::AuthFailed,
            ErrorCode::NameTaken => RefusedKind::NameTaken,
            ErrorCode::Forbidden => RefusedKind::Forbidden,
            ErrorCode::RateLimited => RefusedKind::RateLimited,
            ErrorCode::NotSupported => RefusedKind::NotSupported,
            _ => return None,
        })
    }

    /// The error code the server sent, if it sent one.
    fn code(self) -> Option<&'static str> {
        Some(match self {
            RefusedKind::AuthFailed => "auth-failed",
            RefusedKind::NameTaken => "name-taken",
            RefusedKind::Forbidden | RefusedKind::LastKey => "forbidden",
            RefusedKind::RateLimited => "rate-limited",
            RefusedKind::NotSupported | RefusedKind::NotHosted => "not-supported",
            RefusedKind::NoRegistration
            | RefusedKind::NoHostname
            | RefusedKind::WrongUid
            | RefusedKind::Guest => return None,
        })
    }
}

impl ConnectionErrorKind {
    pub(crate) fn of(e: &conn::Error) -> ConnectionErrorKind {
        use conn::Error as E;
        match e {
            E::Io(_) => ConnectionErrorKind::Network,
            E::Tls(_) => ConnectionErrorKind::Tls,
            E::KeyExchange(_) => ConnectionErrorKind::KeyExchange,
            E::Trust(_) => ConnectionErrorKind::BadCertificate,
            E::TrustStore(_) => ConnectionErrorKind::TrustStore,
            E::Timeout => ConnectionErrorKind::Timeout,
            E::UnsupportedVersion(_) => ConnectionErrorKind::UnsupportedVersion,
            E::BadGreeting(_)
            | E::InvalidCommand(_)
            | E::NoResponse
            | E::Rejected(conn::CommandError::Unparseable(_)) => ConnectionErrorKind::Protocol,
            // A server's ERR becomes ClientError::Server instead.
            E::Rejected(conn::CommandError::Server(_)) => ConnectionErrorKind::Protocol,
            E::Closed(_) => ConnectionErrorKind::Closed,
            E::NonceUsed => ConnectionErrorKind::NonceUsed,
            // These become ClientError::Refused instead.
            E::NoSni | E::NoRegistration => ConnectionErrorKind::Protocol,
        }
    }
}

impl ClientError {
    /// An `ERR` as a client error.
    pub(crate) fn server(err: &risala_proto::server::ErrResponse) -> ClientError {
        ClientError::Server {
            code: err.code.to_string(),
            message: unescape(&err.message).into_owned(),
        }
    }

    /// A refusal of this kind, with the client's own message.
    pub(crate) fn refused(kind: RefusedKind, message: impl Into<String>) -> ClientError {
        ClientError::Refused {
            kind,
            message: message.into(),
            retry_after_secs: None,
        }
    }

    /// A key store error.
    pub(crate) fn keys(kind: KeyErrorKind, message: impl Into<String>) -> ClientError {
        ClientError::Keys {
            kind,
            message: message.into(),
        }
    }

    /// The error code of an `ERR`, if this is one: a
    /// [`Server`](Self::Server) error, or a [`Refused`](Self::Refused)
    /// one the server sent.
    pub fn code(&self) -> Option<&str> {
        match self {
            ClientError::Server { code, .. } => Some(code),
            ClientError::Refused { kind, .. } => kind.code(),
            _ => None,
        }
    }

    /// Whether connecting failed in a way that retrying cannot fix without
    /// the user: a trust failure (2.2), a missing key, a permanent
    /// connection error such as a server without post-quantum key exchange
    /// (2.1), or a refused sign-in such as `auth-failed` (4.5). Meant for
    /// errors from connecting and signing in.
    pub fn is_permanent(&self) -> bool {
        match self {
            ClientError::UnknownCertificate { .. }
            | ClientError::CertificateMismatch { .. }
            | ClientError::Keys { .. }
            | ClientError::Invalid(_) => true,
            ClientError::Connection { permanent, .. } => *permanent,
            ClientError::Refused {
                kind,
                retry_after_secs,
                ..
            } => match kind {
                RefusedKind::NameTaken | RefusedKind::RateLimited => false,
                RefusedKind::Forbidden => retry_after_secs.is_none(),
                _ => true,
            },
            ClientError::Server { code, .. } => matches!(
                code.as_str(),
                "auth-failed" | "forbidden" | "not-supported" | "bad-syntax" | "unknown-command"
            ),
            ClientError::AlreadyTrusted { .. }
            | ClientError::NotConnected
            | ClientError::NotJoined(_)
            | ClientError::Store(_) => false,
        }
    }

    /// Whether this is a trust failure the user must decide on (2.2).
    pub fn is_trust(&self) -> bool {
        matches!(
            self,
            ClientError::UnknownCertificate { .. } | ClientError::CertificateMismatch { .. }
        )
    }

    pub(crate) fn from_conn(server: &str, e: &conn::Error) -> ClientError {
        match e {
            conn::Error::Trust(TrustError::Unknown {
                fingerprint,
                ca_error,
            }) => ClientError::UnknownCertificate {
                server: server.to_owned(),
                fingerprint: fingerprint.to_string(),
                reason: ca_error.clone(),
            },
            conn::Error::Trust(TrustError::Mismatch {
                recorded,
                presented,
                ca_error,
            }) => ClientError::CertificateMismatch {
                server: server.to_owned(),
                recorded: show_record(recorded),
                presented: presented.to_string(),
                reason: ca_error.clone(),
            },
            conn::Error::Rejected(conn::CommandError::Server(err)) => ClientError::server(err),
            conn::Error::NoSni => ClientError::refused(
                RefusedKind::NoHostname,
                format!(
                    "cannot sign in as an identity to {server}: an IP address sends no hostname"
                ),
            ),
            conn::Error::NoRegistration => ClientError::refused(
                RefusedKind::NoRegistration,
                format!("{server} offers no registration"),
            ),
            other => ClientError::Connection {
                kind: ConnectionErrorKind::of(other),
                message: other.to_string(),
                permanent: other.is_permanent(),
            },
        }
    }
}

impl ClientError {
    /// An error from connecting and signing in, or from REGISTER, KEY or
    /// UNREGISTER: an `ERR` with a code of [`RefusedKind`] becomes
    /// [`ClientError::Refused`], and the rest is as
    /// [`from_conn`](Self::from_conn).
    pub(crate) fn from_sign_in(server: &str, e: &conn::Error) -> ClientError {
        match e {
            conn::Error::Rejected(conn::CommandError::Server(err)) => {
                ClientError::from_err(err).unwrap_or_else(|| ClientError::server(err))
            }
            other => ClientError::from_conn(server, other),
        }
    }

    /// An `ERR` with a code of [`RefusedKind`], as [`ClientError::Refused`].
    pub(crate) fn from_err(err: &risala_proto::server::ErrResponse) -> Option<ClientError> {
        let kind = RefusedKind::of(&err.code)?;
        let message = match unescape(&err.message) {
            m if m.is_empty() => err.code.to_string(),
            m => format!("{}: {m}", err.code),
        };
        Some(ClientError::Refused {
            kind,
            message,
            retry_after_secs: err.retry,
        })
    }
}

pub(crate) fn show_record(record: &TrustRecord) -> String {
    match record {
        TrustRecord::Ca => "CA".to_owned(),
        TrustRecord::Pinned(fp) => fp.to_string(),
    }
}

impl From<StoreError> for ClientError {
    fn from(e: StoreError) -> ClientError {
        ClientError::Store(e.to_string())
    }
}

impl From<SyncError> for ClientError {
    fn from(e: SyncError) -> ClientError {
        match e {
            SyncError::Store(e) => e.into(),
            SyncError::Invalid(m) => ClientError::Invalid(m),
            SyncError::NotJoined(conv) => ClientError::NotJoined(conv.to_string()),
        }
    }
}

/// How a server's certificate is trusted (2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustInfo {
    /// The server showed a CA-valid certificate, and must keep doing so.
    Ca,
    /// The user accepted this fingerprint on first use.
    Pinned {
        /// The fingerprint, `sha256:...`.
        fingerprint: String,
    },
}

impl From<&TrustRecord> for TrustInfo {
    fn from(r: &TrustRecord) -> TrustInfo {
        match r {
            TrustRecord::Ca => TrustInfo::Ca,
            TrustRecord::Pinned(fp) => TrustInfo::Pinned {
                fingerprint: fp.to_string(),
            },
        }
    }
}

/// What [`Client::probe`](super::Client::probe) learned about a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// The server address.
    pub server: String,
    /// The host the greeting named (4.1). Informational only.
    pub host: String,
    /// The welcome text, unescaped; empty if none.
    pub welcome: String,
    /// The fingerprint of the certificate's public key (2.2).
    pub fingerprint: String,
    /// How the certificate was accepted.
    pub trust: TrustInfo,
}

/// Where an account's connection is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not started, or stopped. Reads come from the cache.
    Offline,
    /// Connecting. `attempt` counts failures in a row before this one.
    Connecting {
        /// Failures in a row so far.
        attempt: u32,
    },
    /// TLS is up; signing in.
    SigningIn,
    /// Signed in, and syncing or in sync.
    Online {
        /// The uid this connection signed in as. A guest whose name was
        /// still taken gets a numbered name, such as `~sam2` (4.2).
        uid: String,
    },
    /// The connection closed; reconnecting.
    Disconnected {
        /// Why it closed, to show in the user's language.
        kind: DisconnectKind,
        /// Why it closed, in English, for logs. For
        /// [`DisconnectKind::Server`], the server's BYE text if any.
        reason: String,
    },
    /// Waiting before the next attempt.
    Waiting {
        /// How long, in milliseconds.
        retry_in_ms: u64,
        /// What ended the last attempt, if it failed before signing in.
        error: Option<ClientError>,
    },
    /// Stopped for good: the user must act first, for example accept a
    /// certificate (2.2) or fix a key. Start the account again after.
    Failed {
        /// Why.
        error: ClientError,
    },
}

/// Why a connection closed ([`ConnectionState::Disconnected`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisconnectKind {
    /// The server closed it, perhaps with BYE (11).
    Server,
    /// The server stopped answering PING (11).
    PingTimeout,
    /// The network failed.
    Network,
    /// The server broke the protocol.
    Protocol,
    /// This client fell behind reading the server's lines.
    Overflow,
    /// This client closed it, for example to reconnect.
    Local,
}

impl DisconnectKind {
    pub(crate) fn of(reason: &conn::CloseReason) -> DisconnectKind {
        use conn::CloseReason as R;
        match reason {
            R::Server { .. } => DisconnectKind::Server,
            R::PingTimeout => DisconnectKind::PingTimeout,
            R::Io(_) => DisconnectKind::Network,
            R::Protocol(_) => DisconnectKind::Protocol,
            R::Overflow => DisconnectKind::Overflow,
            R::Local => DisconnectKind::Local,
        }
    }
}

impl ConnectionState {
    /// Whether the account is signed in.
    pub fn is_online(&self) -> bool {
        matches!(self, ConnectionState::Online { .. })
    }
}

/// A conversation in the cache, for the conversation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationInfo {
    /// Its name: a room such as `#general`, or the other person (5.1).
    pub name: String,
    /// The id it was last known by (5.1), if known.
    pub id: Option<String>,
    /// Whether the account is in it, as far as the client knows.
    pub joined: bool,
    /// Every event the server keeps up to this seq is stored (7.1).
    pub sync_point: u64,
    /// The newest head the server reported.
    pub head: u64,
    /// The read marker (7.4); 0 for none.
    pub read: u64,
    /// Messages from others after the read marker, counting events not
    /// stored yet above the sync point.
    pub unread: u64,
    /// The newest stored seq; 0 for none.
    pub newest: u64,
    /// Whether every event up to the head is stored.
    pub caught_up: bool,
    /// A room's topic (6.2), unescaped; empty if none or not known.
    pub topic: String,
    /// A room's settings (6.2) as far as the cache knows, in key order,
    /// the topic included. Empty for a direct conversation.
    pub settings: Vec<Setting>,
}

/// One room setting (6.2), such as `public` = `yes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The key: `topic`, `public`, `guests`, `retention` or another.
    pub key: String,
    /// The value, unescaped: text for `topic`, otherwise a keyword or a
    /// number, as on the wire (`yes`, `read`, `30`, `server` and so on).
    pub value: String,
}

impl From<ConversationSummary> for ConversationInfo {
    fn from(c: ConversationSummary) -> ConversationInfo {
        ConversationInfo {
            caught_up: c.caught_up(),
            name: c.name.to_string(),
            id: c.conv_id.map(|id| id.to_string()),
            joined: c.joined,
            sync_point: c.sync_point,
            head: c.head,
            read: c.read,
            unread: c.unread,
            newest: c.newest.map_or(0, |s| s.get()),
            topic: c
                .settings
                .iter()
                .find_map(|s| match s {
                    RoomSetting::Topic(t) => Some(unescape(t).into_owned()),
                    _ => None,
                })
                .unwrap_or_default(),
            settings: c
                .settings
                .iter()
                .map(|s| Setting {
                    key: s.key().to_owned(),
                    value: unescape(&s.value()).into_owned(),
                })
                .collect(),
        }
    }
}

/// The most items one page of [`Conversation::messages`](super::Conversation::messages),
/// [`Account::conversations`](super::Account::conversations), a
/// [`Timeline`](super::Timeline)'s first window or
/// [`Timeline::paginate_back`](super::Timeline::paginate_back) returns.
/// Larger requests get this many.
pub const MAX_PAGE: u32 = 200;

/// The page size used when a request asks for 0 items.
pub const DEFAULT_PAGE: u32 = 50;

/// A page size within the library's bounds.
pub(crate) fn page_size(limit: u32) -> u32 {
    match limit {
        0 => DEFAULT_PAGE,
        n => n.min(MAX_PAGE),
    }
}

/// One page of a conversation's messages from the cache, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePage {
    /// The messages, oldest first.
    pub messages: Vec<Message>,
    /// The cursor for the page of older messages, if the cache has any.
    /// It is opaque: pass it back as it is.
    pub older: Option<String>,
}

/// One page of an account's conversations from the cache, in byte order
/// of name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationPage {
    /// The conversations.
    pub conversations: Vec<ConversationInfo>,
    /// The cursor for the next page, if there are more. It is opaque: pass
    /// it back as it is.
    pub next: Option<String>,
}

/// What kind of event a timeline item is (5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// MSG (5.3).
    Message,
    /// JOIN (6.1).
    Join,
    /// PART (6.1).
    Part,
    /// INVITE (6.4).
    Invite,
    /// KICK (6.4).
    Kick,
    /// BAN (6.4).
    Ban,
    /// UNBAN (6.4).
    Unban,
    /// SET (6.2).
    Set,
    /// ROLE (6.3).
    Role,
    /// Anything else.
    Other,
}

/// The count of one reaction on a message (5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionCount {
    /// The reaction, unescaped, usually an emoji.
    pub reaction: String,
    /// How many people sent it.
    pub count: u64,
    /// Whether the account is one of them.
    pub mine: bool,
}

/// One item of a conversation's timeline: a message or another event, with
/// edits, deletion and reactions applied (5.3, 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its seq.
    pub seq: u64,
    /// When the server accepted it, in milliseconds since the Unix epoch.
    pub time_ms: u64,
    /// The same time as on the wire, such as `2026-11-06T15:41:02.377Z`.
    pub time: String,
    /// Who caused it.
    pub from: String,
    /// Whether the account sent it. A guest may have sent it under a
    /// numbered name, such as `~sam2` for the account `~sam` (4.2), so
    /// use this rather than comparing `from` with the account's uid.
    pub own: bool,
    /// What kind of event it is.
    pub kind: EventKind,
    /// The text, unescaped: a message's current text after edits (empty
    /// when deleted), the reason of a PART, KICK or BAN, or `key value`
    /// of a SET. `None` otherwise.
    pub text: Option<String>,
    /// The uid an INVITE, KICK, BAN, UNBAN or ROLE acts on.
    pub subject: Option<String>,
    /// The message this one replies to.
    pub reply_to: Option<u64>,
    /// Whether the text was edited.
    pub edited: bool,
    /// Whether the message was deleted (5.4).
    pub deleted: bool,
    /// Reactions to it, in byte order.
    pub reactions: Vec<ReactionCount>,
    /// The event as received, in canonical form. Empty for a message in
    /// the outbox.
    pub line: String,
    /// For a message still in the outbox (7.6), its entry: queued, sending
    /// or failed. Then `seq` is 0, the time is when it was queued, and
    /// `line` is empty. `None` for a stored event.
    pub outbox: Option<OutboxEntry>,
}

impl Message {
    /// A message in the outbox, shown as a timeline item from `uid`.
    pub(crate) fn outgoing(entry: OutboxEntry, uid: &str) -> Message {
        let time = risala_proto::time::Timestamp::from_unix_millis(entry.created_ms)
            .map(|t| t.to_string())
            .unwrap_or_default();
        Message {
            seq: 0,
            time_ms: entry.created_ms,
            time,
            from: uid.to_owned(),
            own: true,
            kind: EventKind::Message,
            text: Some(entry.text.clone()),
            subject: None,
            reply_to: entry.reply_to,
            edited: false,
            deleted: false,
            reactions: Vec::new(),
            line: String::new(),
            outbox: Some(entry),
        }
    }
}

impl From<TimelineItem> for Message {
    fn from(item: TimelineItem) -> Message {
        let (kind, text, subject, reply_to) = match &item.event.body {
            EventBody::Msg(m) => (
                EventKind::Message,
                item.text.as_deref().map(|t| unescape(t).into_owned()),
                None,
                match m.relation {
                    Some(risala_proto::types::Relation::Reply(s)) => Some(s.get()),
                    _ => None,
                },
            ),
            EventBody::Join { .. } => (EventKind::Join, None, None, None),
            EventBody::Part { reason, .. } => (EventKind::Part, opt_text(reason), None, None),
            EventBody::Invite { uid, .. } => (EventKind::Invite, None, Some(uid), None),
            EventBody::Kick { uid, reason, .. } => {
                (EventKind::Kick, opt_text(reason), Some(uid), None)
            }
            EventBody::Ban { uid, reason, .. } => {
                (EventKind::Ban, opt_text(reason), Some(uid), None)
            }
            EventBody::Unban { uid, .. } => (EventKind::Unban, None, Some(uid), None),
            EventBody::Set { setting, .. } => (
                EventKind::Set,
                Some(unescape(&setting.to_string()).into_owned()),
                None,
                None,
            ),
            EventBody::Role { uid, .. } => (EventKind::Role, None, Some(uid), None),
            _ => (EventKind::Other, None, None, None),
        };
        let subject = subject.map(|u| u.to_string());
        let line = ServerMessage::new(ServerLine::Event(item.event.clone()))
            .to_line()
            .to_string();
        Message {
            seq: item.seq.get(),
            time_ms: item.t.unix_millis(),
            time: item.t.to_string(),
            from: item.from.to_string(),
            own: item.own,
            kind,
            text,
            subject,
            reply_to,
            edited: item.edit.is_some(),
            deleted: item.deleted,
            reactions: item
                .reactions
                .iter()
                .map(|r| ReactionCount {
                    reaction: unescape(&r.reaction).into_owned(),
                    count: r.count,
                    mine: r.mine.is_some(),
                })
                .collect(),
            line,
            outbox: None,
        }
    }
}

fn opt_text(escaped: &str) -> Option<String> {
    (!escaped.is_empty()).then(|| unescape(escaped).into_owned())
}

/// Where a message in the outbox is (7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxStatus {
    /// Waiting to be sent, until the account is in the room on a
    /// connection.
    Queued,
    /// Sent, with no answer yet.
    Sending,
    /// The server accepted it as event `seq`.
    Sent {
        /// The seq.
        seq: u64,
    },
    /// It will not be sent.
    Failed {
        /// Why, to show in the user's language.
        kind: FailKind,
        /// Why, in English, for logs.
        reason: String,
        /// The connection dropped before the answer and resending was not
        /// safe (7.6): it may or may not have been sent. Show it as
        /// "possibly not sent".
        maybe_sent: bool,
        /// The server's error code, if it refused the message.
        code: Option<String>,
    },
}

/// Why a message in the outbox was not sent ([`OutboxStatus::Failed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailKind {
    /// The room was dropped and created again, so it is another room now
    /// (7.1, 7.6). Sending it there would put it in the wrong room.
    RoomChanged,
    /// The room was dropped (10.4).
    Dropped,
    /// The server refused it; the error code is in `code` (3.7).
    Rejected,
    /// The connection dropped before the answer, and sending it again was
    /// not safe (7.6). It may or may not have been sent.
    Unconfirmed,
    /// It could not be written as a line, for example because it is too
    /// long. It was not sent.
    Invalid,
}

impl OutboxStatus {
    /// Whether it will not change any more.
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            OutboxStatus::Sent { .. } | OutboxStatus::Failed { .. }
        )
    }
}

/// A message in the outbox (7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// The entry's id, for [`Account::wait_outbox`](super::Account::wait_outbox).
    pub id: i64,
    /// The conversation it goes to.
    pub conversation: String,
    /// The text, unescaped.
    pub text: String,
    /// Where it is.
    pub status: OutboxStatus,
    /// When it was queued, in milliseconds since the Unix epoch.
    pub created_ms: u64,
    /// The message it replies to, if it is a reply (5.3).
    pub reply_to: Option<u64>,
}

impl From<OutboxItem> for OutboxEntry {
    fn from(item: OutboxItem) -> OutboxEntry {
        let status = match item.state {
            OutboxState::Queued => OutboxStatus::Queued,
            OutboxState::Sending => OutboxStatus::Sending,
            OutboxState::Sent(seq) => OutboxStatus::Sent { seq: seq.get() },
            OutboxState::Failed(why) => OutboxStatus::Failed {
                kind: match &why {
                    FailReason::RoomChanged => FailKind::RoomChanged,
                    FailReason::Dropped => FailKind::Dropped,
                    FailReason::Unconfirmed => FailKind::Unconfirmed,
                    FailReason::Rejected(_) => FailKind::Rejected,
                    FailReason::Invalid => FailKind::Invalid,
                },
                reason: match &why {
                    FailReason::RoomChanged => "the room was replaced by a new one".to_owned(),
                    FailReason::Dropped => "the room was dropped".to_owned(),
                    FailReason::Unconfirmed => "possibly not sent".to_owned(),
                    FailReason::Invalid => "it could not be sent as it is".to_owned(),
                    FailReason::Rejected(code) => format!("refused: {code}"),
                },
                maybe_sent: why == FailReason::Unconfirmed,
                code: match &why {
                    FailReason::Rejected(code) => Some(code.to_string()),
                    _ => None,
                },
            },
        };
        OutboxEntry {
            id: item.id.get(),
            conversation: item.conv.to_string(),
            text: unescape(&item.draft.text).into_owned(),
            status,
            created_ms: item.created.unix_millis(),
            reply_to: match item.draft.relation {
                Some(risala_proto::types::Relation::Reply(s)) => Some(s.get()),
                _ => None,
            },
        }
    }
}

/// A room in the server's list (6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomListing {
    /// The room.
    pub room: String,
    /// How many members it has.
    pub members: u64,
    /// Its topic, unescaped; empty if none.
    pub topic: String,
}

/// A page of the server's room list (6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomList {
    /// The rooms, in byte order of name.
    pub rooms: Vec<RoomListing>,
    /// Whether there are more after the last one: pass its name as
    /// `after` to get them.
    pub more: bool,
}

/// Something to tell the user that is not history (6.4, 7.1, 8.4, 10.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// Someone invited the account to a room (6.4).
    Invited {
        /// The room.
        room: String,
        /// Who.
        by: String,
    },
    /// The account was kicked from a room (6.4).
    Kicked {
        /// The room.
        room: String,
        /// Who.
        by: String,
        /// The reason, unescaped; empty if none.
        reason: String,
    },
    /// The account was banned from a room (6.4).
    Banned {
        /// The room.
        room: String,
        /// Who.
        by: String,
        /// The reason, unescaped; empty if none.
        reason: String,
    },
    /// The account is no longer in a conversation: SYNC stopped listing it
    /// (7.1). Its history is kept.
    Left {
        /// The conversation.
        conversation: String,
    },
    /// An operator dropped a room; its history was removed (10.4).
    Dropped {
        /// The room.
        room: String,
        /// The reason, unescaped; empty if none.
        reason: String,
    },
    /// A guest could not join a room again after reconnecting (4.2). It
    /// is no longer joined automatically.
    RejoinFailed {
        /// The room.
        room: String,
        /// Why.
        error: ClientError,
    },
    /// A NOTICE from the server (8.4).
    Server {
        /// The text, unescaped.
        text: String,
    },
}

impl Notice {
    pub(crate) fn from_sync(n: &crate::sync::Notification) -> Notice {
        use crate::sync::Notification as N;
        let un = |s: &str| unescape(s).into_owned();
        match n {
            N::Invited { room, by } => Notice::Invited {
                room: room.to_string(),
                by: by.to_string(),
            },
            N::Kicked { room, by, reason } => Notice::Kicked {
                room: room.to_string(),
                by: by.to_string(),
                reason: un(reason),
            },
            N::Banned { room, by, reason } => Notice::Banned {
                room: room.to_string(),
                by: by.to_string(),
                reason: un(reason),
            },
            N::Left { conv } => Notice::Left {
                conversation: conv.to_string(),
            },
            N::Dropped { room, reason } => Notice::Dropped {
                room: room.to_string(),
                reason: un(reason),
            },
        }
    }
}

/// What an account reports to [`AccountEvents`](super::AccountEvents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountEvent {
    /// The connection changed state.
    State {
        /// The new state.
        state: ConnectionState,
    },
    /// A conversation was added or its summary changed: id, sync point,
    /// head, read marker, unread count or whether the account is in it.
    ConversationChanged {
        /// The conversation.
        conversation: String,
    },
    /// A conversation and its history were removed (10.4).
    ConversationRemoved {
        /// The conversation.
        conversation: String,
    },
    /// Messages of a conversation were stored, changed or discarded. A
    /// [`Timeline`](super::Timeline) has the details.
    MessagesChanged {
        /// The conversation.
        conversation: String,
    },
    /// An outbox entry was added or changed.
    Outbox {
        /// The entry as it is now.
        entry: OutboxEntry,
    },
    /// An outbox entry was removed.
    OutboxRemoved {
        /// Its id.
        id: i64,
    },
    /// Something to tell the user.
    Notice {
        /// What.
        notice: Notice,
    },
    /// Events were missed because they were not read in time. Read again
    /// whatever is shown.
    Lagged,
    /// Another process sharing the cache, such as a notification
    /// extension, wrote to it (see [`Client::check_for_external_changes`](super::Client::check_for_external_changes)).
    /// Read again whatever is shown: the conversation list and the outbox.
    /// [`Timeline`](super::Timeline)s reset themselves.
    CacheChanged,
}

/// Whether an error code means the room cannot be joined again as it is.
pub(crate) fn is_lasting_refusal(code: &ErrorCode) -> bool {
    matches!(code, ErrorCode::NotFound | ErrorCode::Forbidden)
}

/// This device's key for an identity (4.4), as the key store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    /// The identity it signs in as, such as `alice@example.org`.
    pub identity: String,
    /// The ML-DSA-44 public key, in base64, 1752 characters (4.4).
    pub public_key: String,
    /// The SHA-256 fingerprint of the public key, `sha256:...`, short
    /// enough to compare by eye.
    pub fingerprint: String,
}

impl DeviceKey {
    pub(crate) fn new(identity: &str, key: &risala_proto::auth::PublicKey) -> DeviceKey {
        DeviceKey {
            identity: identity.to_owned(),
            public_key: key.to_string(),
            fingerprint: key.fingerprint().to_string(),
        }
    }
}

/// One key of a hosted identity, from KEY LIST (4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The ML-DSA-44 public key, in base64.
    pub public_key: String,
    /// The label, usually the device's name, unescaped; empty if none.
    pub label: String,
    /// The SHA-256 fingerprint of the public key, `sha256:...`.
    pub fingerprint: String,
    /// Whether it is this device's key.
    pub this_device: bool,
}

/// What [`Account::unregister`](super::Account::unregister) did (4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unregistered {
    /// The identity deleted.
    pub uid: String,
    /// Whether the server hosted the identity (4.6). Then it deleted the
    /// identity's keys and key file, and the device key was deleted too.
    pub hosted: bool,
    /// Whether this device's key was deleted from the key store. It is
    /// kept for an identity the server does not host, since the key is
    /// still in the identity's own key file and works on other servers.
    pub key_deleted: bool,
}

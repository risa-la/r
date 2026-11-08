//! Persistent storage, behind a trait, with SQLite (draft-03).
//!
//! [`Store`] is the whole store: one supertrait per area of the spec, each
//! in its own module with the types it reads and writes, and each with its
//! SQLite implementation and tables in `sqlite/<area>.rs`:
//!
//! | Area | Trait | Sections | Tables |
//! |---|---|---|---|
//! | [`identity`] | [`IdentityStore`] | 4.6-4.9, 10.5 | `accounts`, `hosted`, `records`, `pairing` |
//! | [`keylog`] | [`KeyLogStore`] | 4.5 | `log_entries`, `log_checkpoints`, `log_key` |
//! | [`mailbox`] | [`MailboxStore`] | 5.2, 6.1, 6.4, 7 | `used_ids`, `mailboxes`, `token_hashes`, `posts`, `cids`, `public_rooms`, `room_members`, `mutes` |
//! | [`keys`] | [`KeysStore`] | 5.6, 12.5, 12.8, 12.12, 12.13 | `key_packages`, `handed_out`, `welcomes`, `blobs`, `blob_puts`, `uploads`, `backups` |
//! | [`misc`] | [`MiscStore`] | 5.8, 8.3, 9 | `presence`, `push_subscriptions`, `reports`, `report_posts` |
//! | [`admin`] | [`AdminStore`] | 10 | `settings`, `operators`, `server_bans` |
//!
//! The schema is `user_version` 1, and has the tables of all of draft-03
//! from the start, sketched from the spec. There are no migrations while
//! M5b is unreleased (docs/plans/M5b.md): an area changes its own tables
//! in its own file, and a database made by an older build is deleted, not
//! migrated. See `sqlite/schema.rs`.
//!
//! Conventions, for every area:
//!
//! - Times are `INTEGER` milliseconds since the Unix epoch ([`millis`],
//!   [`timestamp`]). Binary values (boxes, hashes, MLS objects) are
//!   `BLOB`s of their raw bytes, never base64. Uids and rooms are `TEXT`
//!   in lower case.
//! - Bearer secrets are stored only as hashes ([`crate::secret`]).
//! - Nothing links an anonymous or guest connection, or its network
//!   address, to what it stored (4.2).
//! - Every method is one transaction, and blocks. The hub calls them on
//!   the blocking pool.

pub mod admin;
pub mod identity;
pub mod keylog;
pub mod keys;
pub mod mailbox;
pub mod misc;
mod sqlite;

use risala_proto::time::Timestamp;

pub use admin::{AdminStore, ServerSettings};
pub use identity::IdentityStore;
pub use keylog::{KeyLogStore, LogEntry};
pub use keys::{BackupRecord, KeysStore};
pub use mailbox::{Created, MailboxRecord, MailboxStore, NewMailbox};
pub use misc::MiscStore;
pub use sqlite::{SCHEMA_VERSION, SqliteStore};

/// An error from the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failed.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A stored value could not be read back.
    #[error("corrupt database: {0}")]
    Corrupt(String),
    /// The database could not be set up as the store needs, for example in
    /// WAL mode, or it was made by another version of the server.
    #[error("database setup: {0}")]
    Setup(String),
    /// A blocking task panicked or was cancelled.
    #[error("store task failed: {0}")]
    Task(String),
}

/// A shorthand for store results.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// The whole store: every area's trait (see the [module](self) docs).
///
/// Implemented for every type that implements all of them, so an area adds
/// methods to its own trait and nothing else.
pub trait Store:
    IdentityStore
    + KeyLogStore
    + MailboxStore
    + KeysStore
    + MiscStore
    + AdminStore
    + Send
    + Sync
    + 'static
{
}

impl<T> Store for T where
    T: IdentityStore
        + KeyLogStore
        + MailboxStore
        + KeysStore
        + MiscStore
        + AdminStore
        + Send
        + Sync
        + 'static
{
}

/// A time as stored: milliseconds since the Unix epoch.
pub fn millis(t: Timestamp) -> i64 {
    i64::try_from(t.unix_millis()).unwrap_or(i64::MAX)
}

/// A stored time, read back.
pub fn timestamp(ms: i64) -> Result<Timestamp> {
    u64::try_from(ms)
        .ok()
        .and_then(Timestamp::from_unix_millis)
        .ok_or_else(|| StoreError::Corrupt(format!("time {ms} is out of range")))
}

/// A stored value that should parse, read back.
pub(crate) fn parsed<T: std::str::FromStr>(what: &str, s: &str) -> Result<T> {
    s.parse()
        .map_err(|_| StoreError::Corrupt(format!("{what} {s:?} does not parse")))
}

/// Stored bytes that should have length `N`, read back.
pub(crate) fn fixed<const N: usize>(what: &str, bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{what} has {} bytes, not {N}", bytes.len())))
}

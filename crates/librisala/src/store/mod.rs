//! The device's SQLite cache, encrypted with SQLCipher (PLAN.md 3.4, 43).
//!
//! The server keeps no history (Section 7), so this is where a device's
//! conversations, messages and what it knows of other identities live.
//! The schema starts again at version 1 for draft-03, with no migrations
//! from M5a (docs/plans/M5b.md, "Decided before starting").
//!
//! # Areas
//!
//! The tables are split by area, one module each, so that the area tasks
//! of M5b can work on them at the same time. Each module holds its part
//! of the schema as a `SCHEMA` constant, which [`schema`] runs in order,
//! its `impl Tx` and `impl Store` blocks, and its own [`Change`]s:
//!
//! | Module | Task | Tables |
//! |---|---|---|
//! | [`settings`] | C0 | `servers`, `trust`, `pin_notices`, `accounts`, `settings` |
//! | [`identity`] | C1 | `identities`, `records`, `devices`, `contacts` |
//! | [`keylog`] | C1 | `logs`, `witnesses`, `tiles`, `forks` |
//! | [`conversations`] | C2 | `conversations`, `leaves`, `posts`, `blocks` |
//! | [`messages`] | C2 | `messages`, `gaps`, `outbox` |
//! | `mls` | C2 | OpenMLS's `openmls_*` tables |
//! | [`confirm`] | C3 | `leaf_confirmations`, `period_keys`, `attestations` |
//! | [`transfer`] | C4 | `files`, `blobs`, `transfers`, `backups` |
//! | [`push`] | C4 | `push_subscriptions` |
//!
//! Until M5b's code is released, an area task changes its own `SCHEMA` in
//! place (adding columns, tables or indexes) without raising the version:
//! there are no caches to migrate. Caches made by an earlier build of the
//! same version are not supported; delete them.
//!
//! # Use
//!
//! - **Writes** go through `Store::write` (or `Store::write_with` for an
//!   operation with its own error type, such as an MLS one), in one short
//!   `BEGIN IMMEDIATE` transaction, as a `Tx`. Each returns the
//!   [`Change`]s it made, for the UI. OpenMLS's state is written on the
//!   same transaction (`mls`), so a group's state and the cache's rows
//!   commit or roll back together. Both are crate-internal; each area's
//!   public reads and writes are methods of [`Store`] in its module.
//! - **Reads** go through `Store::read`, on a connection of their own,
//!   in one read transaction: they see one snapshot and never wait for a
//!   writer.
//! - Two processes may open the same file at once, for example an app and
//!   its iOS notification extension (PLAN.md 3.4): WAL mode, a busy
//!   timeout and short transactions. Keep no copy of persistent state in
//!   memory across transactions.
//!
//! A [`Store`] is cheap to clone; clones share its connections. Calls
//! block, so async code makes them off the runtime's worker threads.

mod cipher;
pub mod confirm;
pub mod conversations;
pub mod identity;
pub mod keychecks;
pub mod keylog;
pub mod messages;
pub(crate) mod mls;
pub mod push;
pub mod schema;
pub mod settings;
pub mod transfer;

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::addr::ServerAddr;

pub use cipher::DatabaseKey;
pub use settings::{AccountId, AccountKind, AccountRow};

/// How long a write waits for another process's transaction to finish.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The cache failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite reported an error.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The file has a schema version this build does not know: newer, or
    /// from before draft-03.
    #[error("the cache has schema version {0}; this build reads only version {v}", v = schema::VERSION)]
    Version(u32),
    /// Something stored could not be read back.
    #[error("corrupt cache: {0}")]
    Corrupt(String),
    /// The system's random number generator failed.
    #[error("random number generator: {0}")]
    Random(String),
    /// A row does not exist.
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// The cache's file could not be created.
    #[error("cache file: {0}")]
    File(#[from] std::io::Error),
    /// The cache could not be read with the key given: the key is wrong,
    /// or the file is not a risala cache (a cache in the clear included).
    #[error("the cache's key is wrong, or the file is not a risala cache")]
    WrongKey,
    /// This build's SQLite is not SQLCipher, so the cache cannot be
    /// encrypted. Nothing was written.
    #[error("this build's SQLite cannot encrypt the cache: it is not SQLCipher")]
    NoCipher,
}

/// A change the cache made, for the UI to show, by area. Read the new
/// state with the area's reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Change {
    /// Servers, trust records and accounts.
    Settings(settings::SettingsChange),
    /// Identities, devices and contacts.
    Identity(identity::IdentityChange),
    /// Key logs and forks.
    KeyLog(keylog::KeyLogChange),
    /// Conversations and their members.
    Conversation(conversations::ConversationChange),
    /// Messages and the outbox.
    Message(messages::MessageChange),
    /// Confirmed leaves.
    Confirm(confirm::ConfirmChange),
    /// Files, transfers and backups.
    Transfer(transfer::TransferChange),
    /// Push subscriptions.
    Push(push::PushChange),
}

/// Creates the file at `path` with mode 0600 on Unix, if there is none.
/// SQLite takes an empty file for a new database.
fn create_private(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        // Not a file: SQLite's name for a database in memory.
        if path.as_os_str() == ":memory:" {
            return Ok(());
        }
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);
        match created {
            // The umask may have cleared bits of the mode asked for.
            Ok(file) => file.set_permissions(std::fs::Permissions::from_mode(0o600))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The device's cache. See the [module docs](self).
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    /// The connection for reads, on a file. In memory, reads use `conn`.
    reader: Option<Arc<Mutex<Connection>>>,
    /// The file, if the cache is on one.
    path: Option<std::path::PathBuf>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the cache at `path`, creating it if needed.
    ///
    /// The file is encrypted with `key` (SQLCipher, PLAN.md 43), which
    /// must be the same every time. A wrong key, or a file that is not an
    /// encrypted risala cache, gives [`StoreError::WrongKey`]. A file with
    /// another schema version gives [`StoreError::Version`].
    ///
    /// On Unix a new cache is readable and writable by its owner only
    /// (0600), whatever the umask. SQLite gives the `-wal` and `-shm`
    /// files the same mode. An existing file keeps its mode.
    pub fn open(path: impl AsRef<Path>, key: &DatabaseKey) -> Result<Store, StoreError> {
        let path = path.as_ref();
        create_private(path)?;
        let writer = Connection::open(path)?;
        writer.busy_timeout(BUSY_TIMEOUT)?;
        cipher::key(&writer, key)?;
        let mut store = Store::setup(writer)?;
        // After the writer, which has set WAL mode and the schema.
        let reader = Connection::open(path)?;
        reader.busy_timeout(BUSY_TIMEOUT)?;
        cipher::key(&reader, key)?;
        reader.pragma_update(None, "query_only", "ON")?;
        reader.pragma_update(None, "foreign_keys", "ON")?;
        store.reader = Some(Arc::new(Mutex::new(reader)));
        store.path = Some(path.to_path_buf());
        Ok(store)
    }

    /// The cache's file, if it is on one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Copies the WAL into the cache and truncates it to nothing, so that
    /// frames holding deleted keys and text do not stay in it (12.9, 5.4;
    /// LR-M1). Run after deleting secrets, and on the engines' ten-minute
    /// tick. A checkpoint that readers hold back is not an error: the
    /// next one finishes it.
    pub(crate) fn checkpoint(&self) -> Result<(), StoreError> {
        let conn = self.lock();
        let _: (i64, i64, i64) =
            conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?;
        Ok(())
    }

    /// A cache in memory, for tests and short-lived tools. It is never
    /// written to disk, so it has no key.
    pub fn open_in_memory() -> Result<Store, StoreError> {
        Store::setup(Connection::open_in_memory()?)
    }

    fn setup(mut conn: Connection) -> Result<Store, StoreError> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // In memory, the journal mode stays "memory"; that is fine.
        let _mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Deleted keys and text are overwritten with zeros, not left in
        // free pages (12.9, 5.4; LR-M1). What the WAL still holds goes at
        // the next checkpoint, see [`Store::checkpoint`].
        conn.pragma_update(None, "secure_delete", "ON")?;
        schema::create(&mut conn)?;
        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
            reader: None,
            path: None,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves no transaction open: an
        // uncommitted rusqlite transaction rolls back when dropped.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` for reads: on the read connection, in one read
    /// transaction, so that it sees one snapshot and never waits for a
    /// write.
    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let Some(reader) = &self.reader else {
            return f(&self.lock());
        };
        let mut conn = reader.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// Runs `f` in one write transaction (`BEGIN IMMEDIATE`), and returns
    /// its result with the changes it made. Nothing is written if `f`
    /// fails.
    pub(crate) fn write<T>(
        &self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, StoreError>,
    ) -> Result<(T, Vec<Change>), StoreError> {
        self.write_with(f)
    }

    /// [`Store::write`] for `f` with an error type of its own, such as an
    /// MLS operation's. Nothing is written if `f` fails: OpenMLS's state
    /// on the same transaction rolls back with the rest.
    pub(crate) fn write_with<T, E: From<StoreError>>(
        &self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, E>,
    ) -> Result<(T, Vec<Change>), E> {
        let mut conn = self.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let mut w = Tx {
            tx,
            changes: Vec::new(),
        };
        let out = f(&mut w)?;
        let changes = w.finish()?;
        Ok((out, changes))
    }

    /// A number that changes when another process commits a write to the
    /// cache (SQLite's `PRAGMA data_version`). Writes through this store
    /// and its clones do not change it. Compare it with an earlier value to
    /// learn cheaply whether to read again what is shown.
    ///
    /// `None` while this store is writing; ask again later. It never
    /// waits.
    pub fn data_version(&self) -> Result<Option<u64>, StoreError> {
        let conn = match self.conn.try_lock() {
            Ok(conn) => conn,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        };
        let v: i64 = conn.pragma_query_value(None, "data_version", |r| r.get(0))?;
        Ok(Some(v as u64))
    }
}

/// One write transaction, with the changes it made. Each area adds its
/// writes in an `impl Tx` block of its own module.
pub(crate) struct Tx<'a> {
    tx: Transaction<'a>,
    changes: Vec<Change>,
}

impl Tx<'_> {
    /// Commits, and returns the changes made, each once, in order.
    fn finish(self) -> Result<Vec<Change>, StoreError> {
        let Tx { tx, changes } = self;
        tx.commit()?;
        let mut seen = std::collections::HashSet::new();
        Ok(changes
            .into_iter()
            .filter(|c| seen.insert(c.clone()))
            .collect())
    }

    /// The connection, for plain statements.
    pub(crate) fn conn(&self) -> &Connection {
        &self.tx
    }

    /// Records a change for the UI.
    pub(crate) fn changed(&mut self, change: Change) {
        self.changes.push(change);
    }

    /// The row id of a server, created if needed.
    pub(crate) fn server_id(&self, addr: &ServerAddr) -> Result<i64, StoreError> {
        let addr = addr.to_string();
        self.tx.execute(
            "INSERT INTO servers (addr) VALUES (?1) ON CONFLICT (addr) DO NOTHING",
            [&addr],
        )?;
        Ok(self
            .tx
            .query_row("SELECT id FROM servers WHERE addr = ?1", [&addr], |row| {
                row.get(0)
            })?)
    }
}

/// Parses a value read back from the cache.
pub(crate) fn parse<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, StoreError> {
    s.parse()
        .map_err(|_| StoreError::Corrupt(format!("bad {what}: {s:?}")))
}

/// A row id type: stable for as long as the row exists, and never reused,
/// since its table is `AUTOINCREMENT`.
macro_rules! row_id {
    ($(#[$meta:meta])* $ty:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty(pub(crate) i64);

        impl $ty {
            /// The row id.
            pub fn get(self) -> i64 {
                self.0
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}
pub(crate) use row_id;

#[cfg(test)]
mod tests;

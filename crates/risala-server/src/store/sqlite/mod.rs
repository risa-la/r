//! The SQLite implementation of [`Store`](super::Store).
//!
//! [`SqliteStore`] holds one connection behind a mutex, in WAL mode with
//! `synchronous=FULL` and foreign keys on. Each area implements its trait
//! in its own file, next to the SQL of its tables (`SCHEMA`), with the
//! helpers here: [`SqliteStore::read`] and [`SqliteStore::write`] run a
//! closure in a transaction. An area's functions that take a
//! [`Connection`] can be called from another area's transaction, for
//! work that spans areas.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::{Result, StoreError};

mod admin;
mod identity;
mod keylog;
mod keys;
mod mailbox;
mod misc;
mod schema;

pub use schema::SCHEMA_VERSION;

/// How long a statement waits for another process's lock before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The store on a SQLite database (see the [module](self) docs).
#[derive(Debug)]
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Opens or creates the database at `path`. A new database gets the
    /// schema of [`SCHEMA_VERSION`]; one made by another version fails,
    /// since there are no migrations yet. Fails too if the database cannot
    /// use WAL mode.
    ///
    /// On Unix, the database and its `-wal` and `-shm` files are readable
    /// by the server's user only (mode 0600), whatever the umask: SQLite
    /// gives the `-wal` and `-shm` files the database file's mode.
    pub fn open(path: &Path) -> Result<SqliteStore> {
        private_files(path)
            .map_err(|e| StoreError::Setup(format!("making {} private: {e}", path.display())))?;
        SqliteStore::setup(Connection::open(path)?, true)
    }

    /// A store in memory, for tests.
    pub fn open_in_memory() -> Result<SqliteStore> {
        SqliteStore::setup(Connection::open_in_memory()?, false)
    }

    fn setup(mut conn: Connection, need_wal: bool) -> Result<SqliteStore> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if need_wal && !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Setup(format!(
                "the database cannot use WAL mode (journal mode is {mode:?})"
            )));
        }
        // FULL, not NORMAL: in WAL mode, NORMAL can lose the last commits
        // after a power failure, and a seq already sent would then be given
        // out again (7.5).
        conn.pragma_update(None, "synchronous", "FULL")?;
        let sync: i64 = conn.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        if sync < 2 {
            return Err(StoreError::Setup(format!(
                "cannot set synchronous=FULL (it is {sync})"
            )));
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        schema::create(&mut conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    /// The connection, for one area's statements.
    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave a transaction open:
        // rusqlite rolls back when a Transaction is dropped.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` in a DEFERRED transaction, which sees one snapshot of the
    /// database, and does not write.
    fn read<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let value = f(&tx)?;
        tx.finish()?;
        Ok(value)
    }

    /// Runs `f` in an IMMEDIATE transaction, which takes the write lock up
    /// front, and commits if it succeeds.
    fn write<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }
}

#[cfg(test)]
impl SqliteStore {
    /// The connection, for tests that set up rows that no method writes
    /// yet.
    pub(crate) fn raw(&self) -> MutexGuard<'_, Connection> {
        self.conn()
    }
}

/// A count or index as stored: SQLite integers are signed.
fn sql_u64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// A stored count or index, read back.
fn from_sql_u64(what: &str, n: i64) -> Result<u64> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt(format!("{what} {n} is negative")))
}

/// Creates the database file at `path` with mode 0600 if it is missing,
/// and takes away any access others have to it and its `-wal` and `-shm`
/// files.
#[cfg(unix)]
fn private_files(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    // An empty file is an empty database to SQLite.
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let with = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        std::path::PathBuf::from(name)
    };
    for file in [path.to_owned(), with("-wal"), with("-shm")] {
        let mode = match std::fs::metadata(&file) {
            Ok(meta) => meta.permissions().mode(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if mode & 0o077 != 0 {
            tracing::warn!(file = %file.display(), "taking away other users' access");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_files(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

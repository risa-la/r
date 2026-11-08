//! Encryption of the cache at rest, with SQLCipher (PLAN.md 43).
//!
//! Every connection to a cache file is keyed with [`key`] before anything
//! else reads it. The key is a raw 256-bit key, so SQLCipher skips its
//! passphrase KDF, and opening a connection stays cheap for a notification
//! extension. A cache from before encryption is encrypted in place on open,
//! by [`encrypt_plaintext`], so that an outbox with unsent messages is kept.

use std::fmt;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, ErrorCode, OptionalExtension as _};
use zeroize::Zeroizing;

use super::{BUSY_TIMEOUT, StoreError, create_private};

/// The 256-bit key a cache file is encrypted with.
///
/// Apps keep it in the platform key store; the CLI keeps it in its private
/// state directory. Losing it loses the cache, which can then only be
/// started afresh. It is wiped from memory when dropped.
#[derive(Clone)]
pub struct DatabaseKey(Zeroizing<[u8; 32]>);

impl DatabaseKey {
    /// The key with these bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> DatabaseKey {
        DatabaseKey(Zeroizing::new(bytes))
    }

    /// A new random key, from the system's random number generator.
    pub fn generate() -> Result<DatabaseKey, StoreError> {
        let mut key = DatabaseKey::from_bytes([0; 32]);
        getrandom::fill(&mut key.0[..]).map_err(|e| StoreError::Random(e.to_string()))?;
        Ok(key)
    }

    /// A fixed key, for tests.
    #[cfg(test)]
    pub(crate) fn for_tests() -> DatabaseKey {
        DatabaseKey::from_bytes([7; 32])
    }

    /// The key's bytes, to store it.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `PRAGMA key` with the raw key, as SQLCipher takes it: `x'<hex>'`.
    fn pragma(&self) -> Zeroizing<String> {
        let mut sql = Zeroizing::new(String::with_capacity(80));
        sql.push_str("PRAGMA key = \"x'");
        for b in self.0.iter() {
            sql.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            sql.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
        }
        sql.push_str("'\"");
        sql
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DatabaseKey(..)")
    }
}

/// Keys `conn`, before anything else reads the database, and checks that
/// the key opens it.
pub(super) fn key(conn: &Connection, key: &DatabaseKey) -> Result<(), StoreError> {
    // Without SQLCipher, PRAGMA key does nothing, and the cache would be
    // written in the clear.
    let cipher: Option<String> = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .optional()?;
    if cipher.is_none() {
        return Err(StoreError::NoCipher);
    }
    // SQLCipher logs a wrong key to stderr itself; the error says it.
    conn.execute_batch("PRAGMA cipher_log_level = NONE")?;
    conn.execute_batch(&key.pragma())?;
    // SQLCipher checks the key when the first page is read.
    match conn.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(())) {
        Ok(()) => Ok(()),
        Err(e) if e.sqlite_error_code() == Some(ErrorCode::NotADatabase) => {
            Err(StoreError::WrongKey)
        }
        Err(e) => Err(e.into()),
    }
}

/// The first 16 bytes of every SQLite file in the clear. An encrypted file
/// starts with a random salt instead.
const PLAINTEXT_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// Whether the file at `path` is a database in the clear. A file that is
/// missing or empty is a new cache.
///
/// A database in WAL mode always has its header in the main file, since
/// the header records the mode, so the `-wal` file need not be read.
fn is_plaintext(path: &Path) -> io::Result<bool> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut header = [0; 16];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(header == *PLAINTEXT_HEADER),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// `path` with `suffix` added to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Encrypts the cache at `path` with `key` if it is in the clear, as caches
/// made before encryption are. Does nothing otherwise.
///
/// The database is copied into a new encrypted file with
/// `sqlcipher_export`, which then replaces it, so that a crash leaves
/// either the old file or the new one. While it runs, a write transaction
/// on the old file keeps other processes from writing to it, or encrypting
/// it at the same time.
///
/// The old file's blocks are freed, not overwritten, so what it held may
/// stay on the disk until they are reused.
pub(super) fn encrypt_plaintext(path: &Path, key: &DatabaseKey) -> Result<(), StoreError> {
    if !is_plaintext(path)? {
        return Ok(());
    }
    let mut lock = Connection::open(path)?;
    lock.busy_timeout(BUSY_TIMEOUT)?;
    // Leaving WAL mode moves what the -wal file holds into the database and
    // removes it, so that the encrypted file never meets the old -wal.
    // SQLite refuses while another process has the file open.
    let mode: String =
        lock.pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") || with_suffix(path, "-wal").exists() {
        return Err(StoreError::Corrupt(format!(
            "could not take the cache out of WAL mode to encrypt it (journal mode {mode})"
        )));
    }
    let guard = lock.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Another process may have encrypted it while this one waited.
    if !is_plaintext(path)? {
        return Ok(());
    }
    let version: u32 = guard.pragma_query_value(None, "user_version", |row| row.get(0))?;

    // Left over from an attempt that was cut short, if any; only the
    // holder of the lock above touches it.
    let new = with_suffix(path, ".encrypting");
    for stale in [new.clone(), with_suffix(&new, "-journal")] {
        match std::fs::remove_file(&stale) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    create_private(&new)?;

    let export = (|| -> Result<(), StoreError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let attach = Zeroizing::new(format!(
            "ATTACH DATABASE ?1 AS encrypted KEY {}",
            // "x'<hex>'", the same literal PRAGMA key takes.
            &key.pragma()["PRAGMA key = ".len()..]
        ));
        let new = new
            .to_str()
            .ok_or_else(|| StoreError::Corrupt("the cache's path is not valid UTF-8".to_owned()))?;
        conn.execute(&attach, [new])?;
        conn.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))?;
        conn.pragma_update(Some("encrypted"), "user_version", version)?;
        conn.execute_batch("DETACH DATABASE encrypted")?;
        Ok(())
    })();
    if let Err(e) = export {
        let _ = std::fs::remove_file(&new);
        return Err(e);
    }

    std::fs::rename(&new, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    // Releases the lock only now, so that a process that waited for it
    // finds the encrypted file.
    drop(guard);
    tracing::info!(path = %path.display(), "encrypted the cache");
    Ok(())
}

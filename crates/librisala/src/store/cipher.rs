//! Encryption of the cache at rest, with SQLCipher (PLAN.md 43).
//!
//! Every connection to a cache file is keyed with [`key`] before anything
//! else reads it. The key is a raw 256-bit key, so SQLCipher skips its
//! passphrase KDF, and opening a connection stays cheap for a notification
//! extension. A cache in the clear is not read: it is
//! [`StoreError::WrongKey`].

use std::fmt;

use rusqlite::{Connection, ErrorCode, OptionalExtension as _};
use zeroize::Zeroizing;

use super::StoreError;

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

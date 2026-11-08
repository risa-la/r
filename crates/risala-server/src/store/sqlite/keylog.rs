//! [`KeyLogStore`] on SQLite, and the key log's tables (4.5).

use rusqlite::params;

use risala_proto::names::BlobRef;
use risala_proto::time::Timestamp;

use super::{SqliteStore, from_sql_u64, sql_u64};
use crate::store::{KeyLogStore, LogEntry, Result, millis, parsed};

/// The key log's tables.
pub(super) const SCHEMA: &str = "
-- The key log's entries (4.5), by index from 0. A log never removes an
-- entry.
CREATE TABLE log_entries (
    idx INTEGER PRIMARY KEY CHECK (idx >= 0),
    uid TEXT NOT NULL,              -- whose record it is
    record BLOB NOT NULL,           -- the encoded Record (4.4)
    hash BLOB NOT NULL UNIQUE,      -- its SHA-384 hash: no record twice
    added INTEGER NOT NULL          -- ms
) STRICT;
CREATE INDEX log_entries_uid ON log_entries (uid, idx);

-- The checkpoints the log signed (4.5, C2SP tlog-checkpoint), as served,
-- with the cosignatures witnesses returned.
CREATE TABLE log_checkpoints (
    size INTEGER PRIMARY KEY,       -- the tree size it covers
    root BLOB NOT NULL CHECK (length(root) = 32), -- the SHA-256 root hash
    note TEXT NOT NULL,             -- the signed note, cosignatures included
    signed INTEGER NOT NULL         -- ms
) STRICT;

-- The log's number in its origin, <host>/risala-log/<number>, and the seed
-- of its ML-DSA-44 key (4.5). At most one row.
CREATE TABLE log_key (
    number INTEGER PRIMARY KEY CHECK (number >= 1),
    seed BLOB NOT NULL CHECK (length(seed) = 32),
    created INTEGER NOT NULL        -- ms
) STRICT;
";

impl KeyLogStore for SqliteStore {
    fn log_size(&self) -> Result<u64> {
        self.read(|tx| {
            let size: i64 = tx.query_row("SELECT count(*) FROM log_entries", [], |r| r.get(0))?;
            from_sql_u64("log size", size)
        })
    }

    fn append_entries(&self, entries: &[LogEntry], now: Timestamp) -> Result<u64> {
        self.write(|tx| {
            let first: i64 = tx.query_row("SELECT count(*) FROM log_entries", [], |r| r.get(0))?;
            let mut insert = tx.prepare_cached(
                "INSERT INTO log_entries (idx, uid, record, hash, added) VALUES (?, ?, ?, ?, ?)",
            )?;
            for (i, entry) in (first..).zip(entries) {
                let hash = BlobRef::of(&entry.record);
                insert.execute(params![
                    i,
                    entry.uid.as_str(),
                    entry.record,
                    &hash.hash()[..],
                    millis(now)
                ])?;
            }
            from_sql_u64("log size", first)
        })
    }

    fn log_entries(&self, start: u64, count: u64) -> Result<Vec<LogEntry>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT uid, record FROM log_entries WHERE idx >= ? ORDER BY idx LIMIT ?",
            )?;
            let rows = select.query_map(params![sql_u64(start), sql_u64(count)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            rows.map(|row| {
                let (uid, record) = row?;
                Ok(LogEntry {
                    uid: parsed("uid", &uid)?,
                    record,
                })
            })
            .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(uid: &str, record: &[u8]) -> LogEntry {
        LogEntry {
            uid: uid.parse().unwrap(),
            record: record.to_vec(),
        }
    }

    #[test]
    fn entries_append_in_order_and_never_twice() {
        let store = SqliteStore::open_in_memory().unwrap();
        let t = "2026-11-09T00:00:00.000Z".parse().unwrap();
        assert_eq!(store.log_size().unwrap(), 0);
        let first = [
            entry("alice@example.org", b"m"),
            entry("alice@example.org", b"d"),
        ];
        assert_eq!(store.append_entries(&first, t).unwrap(), 0);
        assert_eq!(
            store
                .append_entries(&[entry("bob@example.org", b"b")], t)
                .unwrap(),
            2
        );
        assert_eq!(store.log_size().unwrap(), 3);
        assert_eq!(store.log_entries(1, 10).unwrap()[0], first[1]);
        assert_eq!(store.log_entries(0, 2).unwrap(), first);
        assert!(store.log_entries(3, 10).unwrap().is_empty());
        // The same record again is refused, and nothing of the batch stays.
        let again = [
            entry("carol@example.org", b"c"),
            entry("alice@example.org", b"m"),
        ];
        assert!(store.append_entries(&again, t).is_err());
        assert_eq!(store.log_size().unwrap(), 3);
    }
}

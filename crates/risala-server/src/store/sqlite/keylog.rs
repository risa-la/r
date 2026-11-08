//! [`KeyLogStore`] on SQLite, and the key log's tables (4.5).

use rusqlite::params;

use risala_proto::names::BlobRef;
use risala_proto::time::Timestamp;

use super::{SqliteStore, from_sql_u64, sql_u64};
use crate::store::{KeyLogStore, LogEntry, Result, fixed, millis, parsed};

/// The key log's tables.
pub(super) const SCHEMA: &str = "
-- The key log's entries (4.5), by index from 0: each an encoded LogEntry,
-- a record or a hand-off. A log never removes an entry.
CREATE TABLE log_entries (
    idx INTEGER PRIMARY KEY CHECK (idx >= 0),
    entry BLOB NOT NULL,            -- the encoded LogEntry
    uid TEXT,                       -- a record's uid; NULL for a hand-off
    record_hash BLOB UNIQUE CHECK (length(record_hash) = 48), -- SHA-384 of a
                                    -- record's Record (4.4): no record twice
    added INTEGER NOT NULL,         -- ms
    CHECK ((uid IS NULL) = (record_hash IS NULL))
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

-- Each log the server has run, by its number in the origin
-- <host>/risala-log/<number>, with the seed of its ML-DSA-44 key (4.5).
-- The newest is current; the ones before it handed off (4.10).
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
                "INSERT INTO log_entries (idx, entry, uid, record_hash, added)
                 VALUES (?, ?, ?, ?, ?)",
            )?;
            for (i, entry) in (first..).zip(entries) {
                let (uid, hash) = match &entry.record {
                    Some((uid, hash)) => (Some(uid.as_str()), Some(&hash.hash()[..])),
                    None => (None, None),
                };
                insert.execute(params![i, entry.entry, uid, hash, millis(now)])?;
            }
            from_sql_u64("log size", first)
        })
    }

    fn log_entries(&self, start: u64, count: u64) -> Result<Vec<LogEntry>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT entry, uid, record_hash FROM log_entries WHERE idx >= ?
                 ORDER BY idx LIMIT ?",
            )?;
            let rows = select.query_map(params![sql_u64(start), sql_u64(count)], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })?;
            rows.map(|row| {
                let (entry, uid, hash) = row?;
                let record = match (uid, hash) {
                    (Some(uid), Some(hash)) => Some((
                        parsed("uid", &uid)?,
                        BlobRef::from_hash(fixed("record hash", &hash)?),
                    )),
                    _ => None,
                };
                Ok(LogEntry { entry, record })
            })
            .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record entry of `uid` whose Record is `record` (the entry's
    /// bytes here are only the Record's, for the test).
    fn entry(uid: &str, record: &[u8]) -> LogEntry {
        LogEntry {
            entry: record.to_vec(),
            record: Some((uid.parse().unwrap(), BlobRef::of(record))),
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
        // A hand-off has no uid (4.5, 4.10).
        let handoff = LogEntry {
            entry: b"handoff".to_vec(),
            record: None,
        };
        assert_eq!(
            store
                .append_entries(std::slice::from_ref(&handoff), t)
                .unwrap(),
            3
        );
        assert_eq!(store.log_entries(3, 1).unwrap(), [handoff]);
        // The same record again is refused, and nothing of the batch stays.
        let again = [
            entry("carol@example.org", b"c"),
            entry("alice@example.org", b"m"),
        ];
        assert!(store.append_entries(&again, t).is_err());
        assert_eq!(store.log_size().unwrap(), 4);
    }
}

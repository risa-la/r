//! [`KeyLogStore`] on SQLite, and the key log's tables (4.5, 4.10).

use rusqlite::{OptionalExtension as _, params};

use risala_proto::names::{BlobRef, Uid};
use risala_proto::time::Timestamp;

use super::{SqliteStore, from_sql_u64, sql_u64};
use crate::store::keylog::{CheckpointRow, LogKeyRow, LoggedRecord, WitnessLogRow, uid_hash};
use crate::store::{KeyLogStore, LogEntry, Result, StoreError, fixed, millis, parsed, timestamp};

/// The key log's tables.
pub(super) const SCHEMA: &str = "
-- Each log the server has run, by its number in the origin
-- <host>/risala-log/<number>, with the seed of its ML-DSA-44 key (4.5).
-- The newest is current; the ones before it handed off (4.5, 4.10).
CREATE TABLE log_key (
    number INTEGER PRIMARY KEY CHECK (number >= 1),
    seed BLOB NOT NULL CHECK (length(seed) = 32),
    created INTEGER NOT NULL        -- ms
) STRICT;

-- Each log's entries (4.5), by index from 0: each an encoded LogEntry,
-- a record or a hand-off. A log never removes an entry.
CREATE TABLE log_entries (
    log INTEGER NOT NULL REFERENCES log_key (number),
    idx INTEGER NOT NULL CHECK (idx >= 0),
    entry BLOB NOT NULL,            -- the encoded LogEntry
    uid TEXT,                       -- a record's uid; NULL for a hand-off
    uid_hash BLOB CHECK (length(uid_hash) = 32), -- SHA-256 of the uid, for
                                    -- risala/uid/<hash> (4.5)
    record_hash BLOB UNIQUE CHECK (length(record_hash) = 48), -- SHA-384 of a
                                    -- record's Record (4.4): no record twice
    added INTEGER NOT NULL,         -- ms
    PRIMARY KEY (log, idx),
    CHECK ((uid IS NULL) = (record_hash IS NULL)),
    CHECK ((uid IS NULL) = (uid_hash IS NULL))
) STRICT;
CREATE INDEX log_entries_uid ON log_entries (uid, log, idx);
CREATE INDEX log_entries_uid_hash ON log_entries (log, uid_hash, idx);

-- The checkpoints the logs signed (4.5, C2SP tlog-checkpoint), as served,
-- with the cosignatures witnesses returned.
CREATE TABLE log_checkpoints (
    log INTEGER NOT NULL REFERENCES log_key (number),
    size INTEGER NOT NULL CHECK (size >= 0), -- the tree size it covers
    note TEXT NOT NULL,             -- the signed note, cosignatures included
    witnessed INTEGER NOT NULL CHECK (witnessed IN (0, 1)), -- k cosignatures
    signed INTEGER NOT NULL,        -- ms
    PRIMARY KEY (log, size)
) STRICT;

-- The seed of the server's witness key (4.10), once it is a witness.
CREATE TABLE witness_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seed BLOB NOT NULL CHECK (length(seed) = 32),
    created INTEGER NOT NULL        -- ms
) STRICT;

-- The logs the server's witness has enrolled (4.10). A row is never
-- removed, and its key never changes: one key per origin, ever.
CREATE TABLE witness_logs (
    origin TEXT PRIMARY KEY,        -- <host>/risala-log/<n>
    vkey TEXT NOT NULL,             -- the log's verifier key
    size INTEGER NOT NULL CHECK (size >= 0), -- the newest tree cosigned
    root BLOB NOT NULL CHECK (length(root) = 32),
    domain TEXT NOT NULL,           -- the host's registered domain
    enrolled_at INTEGER NOT NULL,   -- seconds
    last_cosigned INTEGER NOT NULL, -- seconds; 0 if never
    handoff_index INTEGER,          -- the hand-off entry taken, if any
    handoff_next TEXT,              -- the next log's verifier key
    CHECK ((handoff_index IS NULL) = (handoff_next IS NULL))
) STRICT;
CREATE INDEX witness_logs_domain ON witness_logs (domain, enrolled_at);
";

fn log_keys(tx: &rusqlite::Transaction<'_>) -> Result<Vec<LogKeyRow>> {
    let mut select = tx.prepare_cached("SELECT number, seed FROM log_key ORDER BY number")?;
    let rows = select.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
    rows.map(|row| {
        let (number, seed) = row?;
        Ok(LogKeyRow {
            number: from_sql_u64("log number", number)?,
            seed: fixed("log key seed", &seed)?,
        })
    })
    .collect()
}

fn size_of(tx: &rusqlite::Transaction<'_>, log: u64) -> Result<u64> {
    let size: i64 = tx.query_row(
        "SELECT count(*) FROM log_entries WHERE log = ?",
        [sql_u64(log)],
        |r| r.get(0),
    )?;
    from_sql_u64("log size", size)
}

impl KeyLogStore for SqliteStore {
    fn log_keys(&self) -> Result<Vec<LogKeyRow>> {
        self.read(log_keys)
    }

    fn first_log_key(&self, seed: [u8; 32], now: Timestamp) -> Result<Vec<LogKeyRow>> {
        self.write(|tx| {
            let any: bool =
                tx.query_row("SELECT EXISTS (SELECT 1 FROM log_key)", [], |r| r.get(0))?;
            if !any {
                tx.execute(
                    "INSERT INTO log_key (number, seed, created) VALUES (1, ?, ?)",
                    params![&seed[..], millis(now)],
                )?;
            }
            log_keys(tx)
        })
    }

    fn hand_off(&self, log: u64, handoff: &[u8], seed: [u8; 32], now: Timestamp) -> Result<u64> {
        self.write(|tx| {
            let newest: Option<i64> =
                tx.query_row("SELECT max(number) FROM log_key", [], |r| r.get(0))?;
            if newest != Some(sql_u64(log)) {
                return Err(StoreError::Corrupt(format!(
                    "log {log} is not the newest, and cannot hand off"
                )));
            }
            let index = size_of(tx, log)?;
            tx.execute(
                "INSERT INTO log_entries (log, idx, entry, added) VALUES (?, ?, ?, ?)",
                params![sql_u64(log), sql_u64(index), handoff, millis(now)],
            )?;
            tx.execute(
                "INSERT INTO log_key (number, seed, created) VALUES (?, ?, ?)",
                params![sql_u64(log + 1), &seed[..], millis(now)],
            )?;
            Ok(index)
        })
    }

    fn log_size(&self, log: u64) -> Result<u64> {
        self.read(|tx| size_of(tx, log))
    }

    fn append_entries(&self, log: u64, entries: &[LogEntry], now: Timestamp) -> Result<u64> {
        self.write(|tx| {
            let first = size_of(tx, log)?;
            let mut insert = tx.prepare_cached(
                "INSERT INTO log_entries (log, idx, entry, uid, uid_hash, record_hash, added)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )?;
            for (i, entry) in (first..).zip(entries) {
                let (uid, uid_h, hash) = match &entry.record {
                    Some(r) => (
                        Some(r.uid.as_str()),
                        Some(uid_hash(r.uid.as_str())),
                        Some(&r.hash.hash()[..]),
                    ),
                    None => (None, None, None),
                };
                insert.execute(params![
                    sql_u64(log),
                    sql_u64(i),
                    entry.entry,
                    uid,
                    uid_h.as_ref().map(|h| &h[..]),
                    hash,
                    millis(now)
                ])?;
            }
            Ok(first)
        })
    }

    fn log_entries(&self, log: u64, start: u64, count: u64) -> Result<Vec<LogEntry>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT entry, uid, record_hash FROM log_entries WHERE log = ? AND idx >= ?
                 ORDER BY idx LIMIT ?",
            )?;
            let rows = select.query_map(
                params![sql_u64(log), sql_u64(start), sql_u64(count)],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )?;
            rows.map(|row| {
                let (entry, uid, hash) = row?;
                let record = match (uid, hash) {
                    (Some(uid), Some(hash)) => Some(LoggedRecord {
                        uid: parsed("uid", &uid)?,
                        hash: BlobRef::from_hash(fixed("record hash", &hash)?),
                    }),
                    _ => None,
                };
                Ok(LogEntry { entry, record })
            })
            .collect()
        })
    }

    fn log_uid_indices(&self, log: u64, uid_hash: &[u8; 32]) -> Result<Vec<u64>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT idx FROM log_entries WHERE log = ? AND uid_hash = ? ORDER BY idx",
            )?;
            let rows =
                select.query_map(params![sql_u64(log), &uid_hash[..]], |r| r.get::<_, i64>(0))?;
            rows.map(|i| from_sql_u64("index", i?)).collect()
        })
    }

    fn log_newest_record(&self, uid: &Uid) -> Result<Option<BlobRef>> {
        self.read(|tx| {
            let hash: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT record_hash FROM log_entries WHERE uid = ?
                     ORDER BY log DESC, idx DESC LIMIT 1",
                    [uid.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            hash.map(|h| Ok(BlobRef::from_hash(fixed("record hash", &h)?)))
                .transpose()
        })
    }

    fn log_record_index(&self, hash: &BlobRef) -> Result<Option<(u64, u64)>> {
        self.read(|tx| {
            let found: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT log, idx FROM log_entries WHERE record_hash = ?",
                    [&hash.hash()[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            found
                .map(|(log, idx)| {
                    Ok((
                        from_sql_u64("log number", log)?,
                        from_sql_u64("index", idx)?,
                    ))
                })
                .transpose()
        })
    }

    fn put_log_checkpoint(&self, log: u64, c: &CheckpointRow) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO log_checkpoints (log, size, note, witnessed, signed)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (log, size) DO UPDATE SET
                    note = excluded.note, witnessed = excluded.witnessed,
                    signed = excluded.signed",
                params![
                    sql_u64(log),
                    sql_u64(c.size),
                    c.note,
                    c.witnessed,
                    millis(c.signed)
                ],
            )?;
            Ok(())
        })
    }

    fn log_checkpoint(&self, log: u64, witnessed_only: bool) -> Result<Option<CheckpointRow>> {
        self.read(|tx| {
            let row: Option<(i64, String, bool, i64)> = tx
                .query_row(
                    "SELECT size, note, witnessed, signed FROM log_checkpoints
                     WHERE log = ?1 AND (witnessed = 1 OR NOT ?2)
                     ORDER BY size DESC LIMIT 1",
                    params![sql_u64(log), witnessed_only],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            row.map(|(size, note, witnessed, signed)| {
                Ok(CheckpointRow {
                    size: from_sql_u64("checkpoint size", size)?,
                    note,
                    witnessed,
                    signed: timestamp(signed)?,
                })
            })
            .transpose()
        })
    }

    fn witness_seed(&self, fresh: [u8; 32], now: Timestamp) -> Result<[u8; 32]> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO witness_key (id, seed, created) VALUES (1, ?, ?)
                 ON CONFLICT (id) DO NOTHING",
                params![&fresh[..], millis(now)],
            )?;
            let seed: Vec<u8> =
                tx.query_row("SELECT seed FROM witness_key WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
            fixed("witness seed", &seed)
        })
    }

    fn witness_log(&self, origin: &str) -> Result<Option<WitnessLogRow>> {
        self.read(|tx| {
            type Row = (
                String,
                i64,
                Vec<u8>,
                String,
                i64,
                i64,
                Option<i64>,
                Option<String>,
            );
            let row: Option<Row> = tx
                .query_row(
                    "SELECT vkey, size, root, domain, enrolled_at, last_cosigned,
                            handoff_index, handoff_next
                     FROM witness_logs WHERE origin = ?",
                    [origin],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )
                .optional()?;
            row.map(
                |(vkey, size, root, domain, enrolled, last, h_index, h_next)| {
                    let handoff = match (h_index, h_next) {
                        (Some(i), Some(next)) => Some((from_sql_u64("hand-off index", i)?, next)),
                        _ => None,
                    };
                    Ok(WitnessLogRow {
                        origin: origin.to_owned(),
                        vkey,
                        size: from_sql_u64("size", size)?,
                        root: fixed("root", &root)?,
                        domain,
                        enrolled_at: from_sql_u64("time", enrolled)?,
                        last_cosigned: from_sql_u64("time", last)?,
                        handoff,
                    })
                },
            )
            .transpose()
        })
    }

    fn put_witness_log(&self, row: &WitnessLogRow) -> Result<()> {
        self.write(|tx| {
            let (h_index, h_next) = match &row.handoff {
                Some((i, next)) => (Some(sql_u64(*i)), Some(next.as_str())),
                None => (None, None),
            };
            // The key and the enrolment never change once stored.
            tx.execute(
                "INSERT INTO witness_logs (origin, vkey, size, root, domain, enrolled_at,
                                           last_cosigned, handoff_index, handoff_next)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (origin) DO UPDATE SET
                    size = excluded.size, root = excluded.root,
                    last_cosigned = excluded.last_cosigned,
                    handoff_index = excluded.handoff_index,
                    handoff_next = excluded.handoff_next
                 WHERE witness_logs.vkey = excluded.vkey",
                params![
                    row.origin,
                    row.vkey,
                    sql_u64(row.size),
                    &row.root[..],
                    row.domain,
                    sql_u64(row.enrolled_at),
                    sql_u64(row.last_cosigned),
                    h_index,
                    h_next
                ],
            )?;
            Ok(())
        })
    }

    fn witness_hosts_enrolled_since(&self, domain: &str, since: u64) -> Result<u64> {
        self.read(|tx| {
            let n: i64 = tx.query_row(
                "SELECT count(*) FROM witness_logs
                 WHERE domain = ? AND enrolled_at >= ? AND origin LIKE '%/risala-log/1'",
                params![domain, sql_u64(since)],
                |r| r.get(0),
            )?;
            from_sql_u64("count", n)
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
            record: Some(LoggedRecord {
                uid: uid.parse().unwrap(),
                hash: BlobRef::of(record),
            }),
        }
    }

    fn t() -> Timestamp {
        "2026-11-09T00:00:00.000Z".parse().unwrap()
    }

    #[test]
    fn entries_append_in_order_and_never_twice() {
        let store = SqliteStore::open_in_memory().unwrap();
        let logs = store.first_log_key([1; 32], t()).unwrap();
        assert_eq!(
            logs,
            [LogKeyRow {
                number: 1,
                seed: [1; 32]
            }]
        );
        // Log 1 is started once.
        assert_eq!(store.first_log_key([2; 32], t()).unwrap(), logs);
        assert_eq!(store.log_size(1).unwrap(), 0);
        let first = [
            entry("alice@example.org", b"m"),
            entry("alice@example.org", b"d"),
        ];
        assert_eq!(store.append_entries(1, &first, t()).unwrap(), 0);
        assert_eq!(
            store
                .append_entries(1, &[entry("bob@example.org", b"b")], t())
                .unwrap(),
            2
        );
        assert_eq!(store.log_size(1).unwrap(), 3);
        assert_eq!(store.log_entries(1, 1, 10).unwrap()[0], first[1]);
        assert_eq!(store.log_entries(1, 0, 2).unwrap(), first);
        assert!(store.log_entries(1, 3, 10).unwrap().is_empty());
        let alice: Uid = "alice@example.org".parse().unwrap();
        assert_eq!(
            store
                .log_uid_indices(1, &uid_hash("alice@example.org"))
                .unwrap(),
            [0, 1]
        );
        assert_eq!(
            store.log_newest_record(&alice).unwrap(),
            Some(BlobRef::of(b"d"))
        );
        assert_eq!(
            store.log_record_index(&BlobRef::of(b"b")).unwrap(),
            Some((1, 2))
        );
        assert_eq!(store.log_record_index(&BlobRef::of(b"x")).unwrap(), None);

        // The same record again is refused, and nothing of the batch stays.
        let again = [
            entry("carol@example.org", b"c"),
            entry("alice@example.org", b"m"),
        ];
        assert!(store.append_entries(1, &again, t()).is_err());
        assert_eq!(store.log_size(1).unwrap(), 3);

        // A hand-off ends log 1 and starts log 2 (4.5).
        assert!(store.hand_off(2, b"h", [3; 32], t()).is_err());
        assert_eq!(store.hand_off(1, b"handoff", [3; 32], t()).unwrap(), 3);
        assert_eq!(
            store.log_entries(1, 3, 1).unwrap(),
            [LogEntry {
                entry: b"handoff".to_vec(),
                record: None
            }]
        );
        assert!(store.hand_off(1, b"again", [4; 32], t()).is_err());
        assert_eq!(store.log_keys().unwrap().len(), 2);
        assert_eq!(
            store
                .append_entries(2, &[entry("alice@example.org", b"r")], t())
                .unwrap(),
            0
        );
        assert_eq!(
            store.log_newest_record(&alice).unwrap(),
            Some(BlobRef::of(b"r"))
        );
        assert_eq!(
            store.log_record_index(&BlobRef::of(b"r")).unwrap(),
            Some((2, 0))
        );
    }

    #[test]
    fn checkpoints_keep_the_newest() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.first_log_key([1; 32], t()).unwrap();
        assert_eq!(store.log_checkpoint(1, false).unwrap(), None);
        let row = |size, witnessed| CheckpointRow {
            size,
            note: format!("note {size}"),
            witnessed,
            signed: t(),
        };
        store.put_log_checkpoint(1, &row(1, true)).unwrap();
        store.put_log_checkpoint(1, &row(2, false)).unwrap();
        assert_eq!(store.log_checkpoint(1, false).unwrap(), Some(row(2, false)));
        assert_eq!(store.log_checkpoint(1, true).unwrap(), Some(row(1, true)));
        store.put_log_checkpoint(1, &row(2, true)).unwrap();
        assert_eq!(store.log_checkpoint(1, true).unwrap(), Some(row(2, true)));
    }

    #[test]
    fn witness_state() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert_eq!(store.witness_seed([5; 32], t()).unwrap(), [5; 32]);
        assert_eq!(store.witness_seed([6; 32], t()).unwrap(), [5; 32]);
        let origin = "chat.example.org/risala-log/1";
        assert_eq!(store.witness_log(origin).unwrap(), None);
        let mut row = WitnessLogRow {
            origin: origin.into(),
            vkey: "vkey".into(),
            size: 0,
            root: [0; 32],
            domain: "example.org".into(),
            enrolled_at: 100,
            last_cosigned: 0,
            handoff: None,
        };
        store.put_witness_log(&row).unwrap();
        row.size = 5;
        row.handoff = Some((4, "next".into()));
        store.put_witness_log(&row).unwrap();
        assert_eq!(store.witness_log(origin).unwrap(), Some(row.clone()));
        // The key never changes.
        let mut other = row.clone();
        other.vkey = "other".into();
        other.size = 9;
        store.put_witness_log(&other).unwrap();
        assert_eq!(store.witness_log(origin).unwrap(), Some(row));
        assert_eq!(
            store
                .witness_hosts_enrolled_since("example.org", 100)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .witness_hosts_enrolled_since("example.org", 101)
                .unwrap(),
            0
        );
    }
}

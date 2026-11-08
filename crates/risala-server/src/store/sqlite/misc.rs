//! [`MiscStore`] on SQLite, and the tables of presence, push and reports
//! (5.8, 8.3, 9).

use rusqlite::OptionalExtension as _;

use risala_proto::names::Uid;

use super::SqliteStore;
use crate::store::{MiscStore, Result};

/// The misc area's tables.
pub(super) const SCHEMA: &str = "
-- The identities that turned presence on (8.3). Off has no row.
CREATE TABLE presence (
    uid TEXT PRIMARY KEY
) STRICT, WITHOUT ROWID;

-- Push subscriptions (9.1): a mailbox subscription has a box, an account
-- subscription a device. The server must send to the URL, so it keeps it,
-- and looks it up by its hash.
CREATE TABLE push_subscriptions (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    url_hash BLOB NOT NULL CHECK (length(url_hash) = 48), -- SHA-384 of url
    tag TEXT NOT NULL,
    key BLOB NOT NULL CHECK (length(key) = 65), -- P-256 public key
    auth BLOB NOT NULL CHECK (length(auth) = 16),
    box BLOB CHECK (length(box) = 16),
    uid TEXT,                       -- an account subscription's identity...
    device BLOB CHECK (length(device) = 48), -- ...and device id
    last_push INTEGER,              -- ms, for one push per 10 seconds (9.2)
    failing_since INTEGER,          -- ms of the first of a run of failures (9.3)
    CHECK ((box IS NULL) != (device IS NULL))
) STRICT;
CREATE UNIQUE INDEX push_mailbox ON push_subscriptions (box, url_hash) WHERE box IS NOT NULL;
CREATE UNIQUE INDEX push_account ON push_subscriptions (device, url_hash) WHERE device IS NOT NULL;

-- Reports to the operators (5.8), open until resolved.
CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    box BLOB NOT NULL CHECK (length(box) = 16),
    report BLOB NOT NULL,           -- the RisalaReport, as received
    t INTEGER NOT NULL,             -- ms
    reporter TEXT,                  -- the reporter, if signed in
    resolved INTEGER                -- ms, or NULL while open
) STRICT;

-- Copies of the posts a report names, kept until it is resolved even if
-- they expire (5.8, 7.5).
CREATE TABLE report_posts (
    report TEXT NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    t INTEGER NOT NULL,             -- ms
    message BLOB NOT NULL,          -- the MLSMessage
    PRIMARY KEY (report, seq)
) STRICT;
";

impl MiscStore for SqliteStore {
    fn presence_on(&self, uid: &Uid) -> Result<bool> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT 1 FROM presence WHERE uid = ?",
                    [uid.as_str()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    fn set_presence(&self, uid: &Uid, on: bool) -> Result<()> {
        self.write(|tx| {
            if on {
                tx.execute(
                    "INSERT INTO presence (uid) VALUES (?) ON CONFLICT DO NOTHING",
                    [uid.as_str()],
                )?;
            } else {
                tx.execute("DELETE FROM presence WHERE uid = ?", [uid.as_str()])?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_is_off_by_default() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice: Uid = "alice@example.org".parse().unwrap();
        assert!(!store.presence_on(&alice).unwrap());
        store.set_presence(&alice, true).unwrap();
        store.set_presence(&alice, true).unwrap();
        assert!(store.presence_on(&alice).unwrap());
        store.set_presence(&alice, false).unwrap();
        assert!(!store.presence_on(&alice).unwrap());
    }
}

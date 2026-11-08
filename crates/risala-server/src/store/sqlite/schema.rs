//! The database schema, `user_version` [`SCHEMA_VERSION`].
//!
//! Each area keeps the SQL of its tables in its own file, as `SCHEMA`, and
//! [`create`] runs them in order on a new database. While M5b is
//! unreleased there are no migrations (docs/plans/M5b.md): an area changes
//! its tables in place, at version 1, and a database made before the
//! change is deleted. Once a release has shipped, a change bumps the
//! version and adds a migration here.

use rusqlite::Connection;

use super::{admin, identity, keylog, keys, mailbox, misc};
use crate::store::{Result, StoreError};

/// The schema version this build writes and reads.
pub const SCHEMA_VERSION: i64 = 1;

/// Every area's tables, in the order they are created. An area whose
/// tables refer to another's comes after it.
const AREAS: [(&str, &str); 6] = [
    ("identity", identity::SCHEMA),
    ("keylog", keylog::SCHEMA),
    ("mailbox", mailbox::SCHEMA),
    ("keys", keys::SCHEMA),
    ("misc", misc::SCHEMA),
    ("admin", admin::SCHEMA),
];

/// Creates the schema in a new database, or checks that an existing one
/// has this version.
pub(super) fn create(conn: &mut Connection) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        SCHEMA_VERSION => Ok(()),
        0 => {
            let tx = conn.transaction()?;
            let tables: i64 = tx.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table'",
                [],
                |row| row.get(0),
            )?;
            if tables != 0 {
                return Err(StoreError::Setup(
                    "the database has tables but no schema version: it was not made by risalad"
                        .into(),
                ));
            }
            for (area, sql) in AREAS {
                tx.execute_batch(sql).map_err(|e| {
                    StoreError::Setup(format!("creating the tables of {area}: {e}"))
                })?;
            }
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            tx.commit()?;
            Ok(())
        }
        other => Err(StoreError::Setup(format!(
            "the database has schema version {other}, and this server reads only \
             {SCHEMA_VERSION}; there are no migrations before the first release, so \
             move the old database away"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;

    fn tables(conn: &Connection) -> Vec<String> {
        conn.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// Every table of draft-03 is there from the start, in every area.
    #[test]
    fn a_new_database_has_every_table() {
        let store = SqliteStore::open_in_memory().unwrap();
        let conn = store.conn();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(
            tables(&conn),
            [
                "accounts",
                "backups",
                "blob_puts",
                "blobs",
                "cids",
                "handed_out",
                "hosted",
                "key_packages",
                "log_checkpoints",
                "log_entries",
                "log_key",
                "mailboxes",
                "mutes",
                "operators",
                "pairing",
                "posts",
                "presence",
                "public_rooms",
                "push_subscriptions",
                "records",
                "report_posts",
                "reports",
                "room_members",
                "server_bans",
                "settings",
                "token_hashes",
                "uploads",
                "used_ids",
                "welcomes",
                "witness_key",
                "witness_logs",
            ]
        );
        // Every table is STRICT, so a value of the wrong type is refused.
        let lax: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_list WHERE type = 'table' AND strict = 0 AND name NOT LIKE 'sqlite_%'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(lax.is_empty(), "not STRICT: {lax:?}");
    }

    #[test]
    fn reopening_keeps_the_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("risala.db");
        let uid = "alice@example.org".parse().unwrap();
        {
            let store = SqliteStore::open(&path).unwrap();
            use crate::store::IdentityStore as _;
            store
                .note_sign_in(&uid, "2026-11-09T00:00:00.000Z".parse().unwrap())
                .unwrap();
        }
        let store = SqliteStore::open(&path).unwrap();
        use crate::store::IdentityStore as _;
        assert!(store.knows(&uid).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn the_database_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("risala.db");
        drop(SqliteStore::open(&path).unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }

    #[test]
    fn other_versions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("risala.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", 7).unwrap();
        }
        let err = SqliteStore::open(&path).unwrap_err().to_string();
        assert!(err.contains("schema version 7"), "{err}");

        // An M5a database, or anything else, without a version.
        let other = dir.path().join("other.db");
        {
            let conn = Connection::open(&other).unwrap();
            conn.execute_batch("CREATE TABLE events (seq INTEGER)")
                .unwrap();
        }
        let err = SqliteStore::open(&other).unwrap_err().to_string();
        assert!(err.contains("not made by risalad"), "{err}");
    }
}

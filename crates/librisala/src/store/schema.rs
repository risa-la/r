//! The cache's schema: version 1, made of each area's part.
//!
//! The version lives in `PRAGMA user_version`. A new file gets every part
//! of [`PARTS`], in order, in one transaction, so two processes opening it
//! at once cannot both create it. A file of any other version is refused
//! with [`StoreError::Version`]: draft-03 starts again at 1, with no
//! migrations from M5a's caches (docs/plans/M5b.md).
//!
//! Conventions for every part:
//!
//! - Times are INTEGER milliseconds since 1970-01-01T00:00:00Z, the unit
//!   of every time in draft-03 (4.4, 12.9).
//! - Hashes, keys, ids and MLS values are BLOBs of their raw bytes.
//!   Values that are text on the wire and in the API (uids, boxes, rooms,
//!   blob-refs, URLs) are TEXT in their canonical form.
//! - Secrets the cache must hold are fine here, since the file is
//!   encrypted; the device key, device-signing key, attestation key and
//!   backup key belong in the platform key store instead
//!   ([`crate::keys`]), as PLAN.md 3.4 says.
//! - Tables whose rows the API names have `id INTEGER PRIMARY KEY
//!   AUTOINCREMENT`, so that an id is never reused.

use rusqlite::{Connection, TransactionBehavior};

use super::StoreError;

/// The schema version this build reads and writes.
pub const VERSION: u32 = 1;

/// The parts of version 1, by area, in the order they are created. Tables
/// may refer to tables of earlier parts.
pub const PARTS: &[(&str, &str)] = &[
    ("settings", super::settings::SCHEMA),
    ("identity", super::identity::SCHEMA),
    ("keylog", super::keylog::SCHEMA),
    ("conversations", super::conversations::SCHEMA),
    ("messages", super::messages::SCHEMA),
    ("mls", super::mls::SCHEMA),
    ("confirm", super::confirm::SCHEMA),
    ("transfer", super::transfer::SCHEMA),
    ("push", super::push::SCHEMA),
];

/// Creates the schema in a new database, or checks the version of an
/// existing one.
pub(super) fn create(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        VERSION => return Ok(()),
        0 => {}
        other => return Err(StoreError::Version(other)),
    }
    // Version 0 with tables in it is not a new cache.
    let tables: i64 = tx.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table'",
        [],
        |row| row.get(0),
    )?;
    if tables != 0 {
        return Err(StoreError::Version(0));
    }
    for (_, part) in PARTS {
        tx.execute_batch(part)?;
    }
    tx.pragma_update(None, "user_version", VERSION)?;
    tx.commit()?;
    Ok(())
}

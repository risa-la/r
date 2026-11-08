//! The SQLite schema and its migrations.
//!
//! `PRAGMA user_version` holds the number of migrations applied. Each
//! migration runs in its own transaction, with foreign keys off so that it
//! may rebuild a table, and must pass `PRAGMA foreign_key_check` to commit
//! (see [`migrate_with`]). Later milestones add migrations to the end of
//! [`MIGRATIONS`]; they never edit one that has shipped.
//!
//! The first migration has the tables of the whole protocol, though M2 uses
//! only some of them, so that M3 and M4 add behaviour rather than redo the
//! layout.
//!
//! Conventions:
//!
//! - Times are milliseconds since the Unix epoch (3.5).
//! - Names, uids, rooms and ids are stored in their wire form, lower case.
//! - Text is stored escaped, exactly as on the wire (3.4).
//! - `conv` is the store's own integer key for a conversation. The id sent
//!   to clients is `conversations.id` (5.1).

use rusqlite::{Connection, Transaction};

use super::{Result, StoreError};

/// The migrations, in order. Migration `i` takes the database from version
/// `i` to `i + 1`.
pub const MIGRATIONS: &[&str] = &[V1, V2, V3, V4, V5, V6];

/// Version 1: the whole protocol.
const V1: &str = r#"
-- Server settings (10.6): guests, registration, retention and welcome,
-- in their wire form. Filled from the configuration's [server] section
-- the first time the server starts.
CREATE TABLE server_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- Every conversation id (5.1) and report id (5.8) ever issued. Rows are
-- never deleted, so an id is never given out twice, even after the room
-- or report it named is gone.
CREATE TABLE used_ids (
    id      TEXT PRIMARY KEY,
    kind    TEXT NOT NULL CHECK (kind IN ('conversation', 'report')),
    created INTEGER NOT NULL
) WITHOUT ROWID;

-- Identities the server knows: they have signed in at least once (5.1).
-- Hosted identities (4.6) have `hosted = 1` and keys in hosted_keys.
CREATE TABLE identities (
    uid          TEXT PRIMARY KEY,
    hosted       INTEGER NOT NULL DEFAULT 0 CHECK (hosted IN (0, 1)),
    display_name TEXT NOT NULL DEFAULT '',
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL
) WITHOUT ROWID;

-- The keys of hosted identities (4.6, 4.7, 10.5), base64 as in key files.
CREATE TABLE hosted_keys (
    uid   TEXT NOT NULL REFERENCES identities (uid) ON DELETE CASCADE,
    key   TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    added INTEGER NOT NULL,
    PRIMARY KEY (uid, key)
) WITHOUT ROWID;

-- Hosted names that were unregistered and must not be registered again
-- (4.8, 10.5).
CREATE TABLE retired_names (
    name    TEXT PRIMARY KEY,
    retired INTEGER NOT NULL
) WITHOUT ROWID;

-- Operators added with ADMIN OP (10.1). Those from the configuration file
-- are not stored here, so they can never be removed with ADMIN DEOP.
CREATE TABLE operators (
    uid   TEXT PRIMARY KEY,
    added INTEGER NOT NULL
) WITHOUT ROWID;

-- Server-wide bans (10.2): an identity, `*@domain`, or an address or
-- prefix, in the wire form of SERVERBAN.
CREATE TABLE server_bans (
    target TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '',
    t      INTEGER NOT NULL
) WITHOUT ROWID;

-- Blocks (5.7): `target` is an identity or `*@domain`.
CREATE TABLE blocks (
    uid    TEXT NOT NULL,
    target TEXT NOT NULL,
    t      INTEGER NOT NULL,
    PRIMARY KEY (uid, target)
) WITHOUT ROWID;

-- Conversations (5.1). A room has a name. A direct conversation has its
-- two participants, `uid_a <= uid_b`; a conversation with yourself has
-- `uid_a = uid_b`. `head` is the newest seq ever assigned, kept here
-- rather than computed, so that seqs are never reused after events expire
-- (7.5). ADMIN DROP (10.4) deletes the row and everything that cascades
-- from it; the id stays in used_ids.
CREATE TABLE conversations (
    conv    INTEGER PRIMARY KEY,
    id      TEXT NOT NULL UNIQUE REFERENCES used_ids (id),
    kind    TEXT NOT NULL CHECK (kind IN ('room', 'direct')),
    room    TEXT UNIQUE,
    uid_a   TEXT,
    uid_b   TEXT,
    head    INTEGER NOT NULL DEFAULT 0 CHECK (head >= 0),
    created INTEGER NOT NULL,
    CHECK ((kind = 'room') = (room IS NOT NULL)),
    CHECK ((kind = 'direct') = (uid_a IS NOT NULL AND uid_b IS NOT NULL)),
    CHECK (uid_a IS NULL OR uid_a <= uid_b),
    UNIQUE (uid_a, uid_b)
);

-- Room settings (6.2), in their wire form.
CREATE TABLE room_settings (
    conv      INTEGER PRIMARY KEY REFERENCES conversations (conv) ON DELETE CASCADE,
    topic     TEXT NOT NULL DEFAULT '',
    public    INTEGER NOT NULL DEFAULT 1 CHECK (public IN (0, 1)),
    guests    TEXT NOT NULL DEFAULT 'write' CHECK (guests IN ('none', 'read', 'write')),
    retention TEXT NOT NULL DEFAULT 'server'
);

-- Events (5.2). Parameters that are names or keywords have columns; free
-- text is in event_text, so that DELETE can erase it (5.4).
--
-- - `relation`, `target`: the reply, edit or react tag of a MSG (5.3), or
--   for DELETE, `target` is the deleted message.
-- - `subject`: the uid of INVITE, KICK, BAN, UNBAN and ROLE.
-- - `arg`: the key of SET, or the role of ROLE.
-- - `file_*`: the attached file of a MSG (5.6).
-- - `deleted`: the content was removed (5.4).
--
-- Rows are removed only by retention (7.5) and ADMIN DROP (10.4).
CREATE TABLE events (
    conv      INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    seq       INTEGER NOT NULL CHECK (seq >= 1),
    t         INTEGER NOT NULL,
    author    TEXT NOT NULL,
    verb      TEXT NOT NULL CHECK (verb IN ('MSG', 'DELETE', 'JOIN', 'PART', 'INVITE',
                                            'KICK', 'BAN', 'UNBAN', 'SET', 'ROLE')),
    relation  TEXT CHECK (relation IN ('reply', 'edit', 'react')),
    target    INTEGER,
    subject   TEXT,
    arg       TEXT,
    file_url  TEXT,
    file_type TEXT,
    file_size INTEGER,
    deleted   INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    PRIMARY KEY (conv, seq)
) WITHOUT ROWID;

-- RELATED (7.3), deleting a message's edits and reactions (5.4), and
-- finding a repeated reaction (5.3).
CREATE INDEX events_target ON events (conv, target) WHERE target IS NOT NULL;
-- ADMIN PURGE (10.4) and UNREGISTER purge=yes (4.8).
CREATE INDEX events_author ON events (author, t);
-- Retention (7.5).
CREATE INDEX events_time ON events (conv, t);

-- The text of an event: MSG text, the reason of PART, KICK and BAN, and
-- the value of SET. Deleting a message deletes its row here (5.4).
CREATE TABLE event_text (
    conv INTEGER NOT NULL,
    seq  INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (conv, seq),
    FOREIGN KEY (conv, seq) REFERENCES events (conv, seq) ON DELETE CASCADE
) WITHOUT ROWID;

-- Room members who are identities (6.1). Guests' memberships end with
-- their connection (4.2) and are kept in memory only.
CREATE TABLE members (
    conv  INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    uid   TEXT NOT NULL,
    since INTEGER NOT NULL,
    PRIMARY KEY (conv, uid)
) WITHOUT ROWID;
CREATE INDEX members_uid ON members (uid);

-- Owners and moderators (6.3), whether or not they are members now.
CREATE TABLE roles (
    conv INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    uid  TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'mod')),
    PRIMARY KEY (conv, uid)
) WITHOUT ROWID;
CREATE INDEX roles_uid ON roles (uid);

-- Open invitations (6.4), until used or the invitee is banned.
CREATE TABLE invites (
    conv INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    uid  TEXT NOT NULL,
    seq  INTEGER NOT NULL,
    PRIMARY KEY (conv, uid)
) WITHOUT ROWID;

-- Room bans (6.4).
CREATE TABLE room_bans (
    conv   INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    uid    TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    seq    INTEGER NOT NULL,
    PRIMARY KEY (conv, uid)
) WITHOUT ROWID;

-- Read markers (7.4), for identities only.
CREATE TABLE read_markers (
    conv INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    uid  TEXT NOT NULL,
    seq  INTEGER NOT NULL CHECK (seq >= 1),
    PRIMARY KEY (conv, uid)
) WITHOUT ROWID;

-- Cids of messages from identities (7.6), scoped to the conversation, and
-- so to its id: a dropped room's cids go with it. Guests' cids are kept
-- per connection, in memory.
CREATE TABLE cids (
    conv   INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    author TEXT NOT NULL,
    cid    TEXT NOT NULL,
    seq    INTEGER NOT NULL,
    t      INTEGER NOT NULL,
    PRIMARY KEY (conv, author, cid)
) WITHOUT ROWID;
CREATE INDEX cids_time ON cids (t);

-- Open reports (5.8), with a copy of the reported event as it was, kept
-- even if the message is deleted or expires. A resolved report is deleted.
CREATE TABLE reports (
    id          TEXT PRIMARY KEY REFERENCES used_ids (id),
    conv        INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    reporter    TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    t           INTEGER NOT NULL,
    ev_t        INTEGER NOT NULL,
    ev_author   TEXT NOT NULL,
    ev_relation TEXT CHECK (ev_relation IN ('reply', 'edit', 'react')),
    ev_target   INTEGER,
    ev_file_url TEXT,
    ev_file_type TEXT,
    ev_file_size INTEGER,
    ev_text     TEXT NOT NULL,
    UNIQUE (conv, seq, reporter)
) WITHOUT ROWID;

-- Uploads (5.6). `get_url` is what a MSG's file tag names; it is attached
-- to at most one message.
CREATE TABLE uploads (
    get_url    TEXT PRIMARY KEY,
    put_token  TEXT NOT NULL UNIQUE,
    uid        TEXT NOT NULL,
    size       INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    name       TEXT NOT NULL,
    created    INTEGER NOT NULL,
    stored     INTEGER NOT NULL DEFAULT 0 CHECK (stored IN (0, 1)),
    conv       INTEGER REFERENCES conversations (conv) ON DELETE CASCADE,
    seq        INTEGER,
    UNIQUE (conv, seq)
) WITHOUT ROWID;

-- Push registrations (9.1), per device key.
CREATE TABLE push_registrations (
    device_key TEXT NOT NULL,
    url        TEXT NOT NULL,
    uid        TEXT NOT NULL,
    tag        TEXT NOT NULL,
    added      INTEGER NOT NULL,
    PRIMARY KEY (device_key, url)
) WITHOUT ROWID;
CREATE INDEX push_registrations_uid ON push_registrations (uid);
"#;

/// Version 2: guests' room memberships (4.2).
const V2: &str = r#"
-- Guests in rooms (4.2). A guest's membership ends with its connection,
-- with a PART. A row here outlives a crash, so that the PART can be
-- recorded when the server starts again. Written in the transaction of the
-- guest's JOIN or PART event.
CREATE TABLE guest_members (
    conv  INTEGER NOT NULL REFERENCES conversations (conv) ON DELETE CASCADE,
    uid   TEXT NOT NULL,
    since INTEGER NOT NULL,
    PRIMARY KEY (conv, uid)
) WITHOUT ROWID;
"#;

/// Version 3: key labels are at most 64 bytes (4.4, 4.7).
const V3: &str = r#"
-- Before draft-02 set the limit, KEY ADD took labels up to the line
-- limit. A longer one cannot be sent in a KEY line or written to a key
-- file any more, so it is dropped. Labels are stored escaped, which is
-- the form the limit counts (3.4).
UPDATE hosted_keys SET label = '' WHERE length(CAST(label AS BLOB)) > 64;
"#;

/// Version 4: rooms can be dropped (10.4). Conversation keys are never
/// reused, and reports outlive their room (5.8).
pub(super) const V4: &str = r#"
-- A room's key could be given again to the next conversation if the room
-- was the newest, since `conv` was a plain INTEGER PRIMARY KEY. ADMIN DROP
-- deletes rooms, and the hub may still hold a dropped room's key for a
-- moment (a HISTORY on its way, 7.2), so keys must never be reused:
-- AUTOINCREMENT ensures it.
CREATE TABLE conversations_v4 (
    conv    INTEGER PRIMARY KEY AUTOINCREMENT,
    id      TEXT NOT NULL UNIQUE REFERENCES used_ids (id),
    kind    TEXT NOT NULL CHECK (kind IN ('room', 'direct')),
    room    TEXT UNIQUE,
    uid_a   TEXT,
    uid_b   TEXT,
    head    INTEGER NOT NULL DEFAULT 0 CHECK (head >= 0),
    created INTEGER NOT NULL,
    CHECK ((kind = 'room') = (room IS NOT NULL)),
    CHECK ((kind = 'direct') = (uid_a IS NOT NULL AND uid_b IS NOT NULL)),
    CHECK (uid_a IS NULL OR uid_a <= uid_b),
    UNIQUE (uid_a, uid_b)
);
INSERT INTO conversations_v4 (conv, id, kind, room, uid_a, uid_b, head, created)
    SELECT conv, id, kind, room, uid_a, uid_b, head, created FROM conversations;
DROP TABLE conversations;
ALTER TABLE conversations_v4 RENAME TO conversations;

-- Reports named their conversation by its key, with ON DELETE CASCADE, so
-- ADMIN DROP would have deleted them. An open report must stay until an
-- operator resolves it (10.4), so a report now names the conversation by
-- its id, which is never reused, and a room by its name, which the REPORT
-- line needs once the room is gone. `room` is NULL for a direct
-- conversation, whose REPORT line names the author (5.8). `n` is the
-- order reports were made in, for paging REPORTS and ADMIN REPORTS.
CREATE TABLE reports_v4 (
    n            INTEGER PRIMARY KEY,
    id           TEXT NOT NULL UNIQUE REFERENCES used_ids (id),
    conv_id      TEXT NOT NULL REFERENCES used_ids (id),
    room         TEXT,
    seq          INTEGER NOT NULL CHECK (seq >= 1),
    reporter     TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    t            INTEGER NOT NULL,
    ev_t         INTEGER NOT NULL,
    ev_author    TEXT NOT NULL,
    ev_relation  TEXT CHECK (ev_relation IN ('reply', 'edit', 'react')),
    ev_target    INTEGER,
    ev_file_url  TEXT,
    ev_file_type TEXT,
    ev_file_size INTEGER,
    ev_text      TEXT NOT NULL,
    UNIQUE (conv_id, seq, reporter)
);
INSERT INTO reports_v4 (id, conv_id, room, seq, reporter, reason, t, ev_t, ev_author,
                        ev_relation, ev_target, ev_file_url, ev_file_type, ev_file_size,
                        ev_text)
    SELECT r.id, c.id, c.room, r.seq, r.reporter, r.reason, r.t, r.ev_t, r.ev_author,
           r.ev_relation, r.ev_target, r.ev_file_url, r.ev_file_type, r.ev_file_size,
           r.ev_text
    FROM reports r JOIN conversations c ON c.conv = r.conv
    ORDER BY r.t, r.id;
DROP TABLE reports;
ALTER TABLE reports_v4 RENAME TO reports;
-- REPORTS <room> (5.8).
CREATE INDEX reports_conv ON reports (conv_id, n);
"#;

/// Version 5: announcement-only rooms, the `send` setting (6.2).
pub(super) const V5: &str = r#"
ALTER TABLE room_settings
    ADD COLUMN send TEXT NOT NULL DEFAULT 'all' CHECK (send IN ('all', 'mods'));
"#;

/// Version 6: indexes for finding a user's rows in tables keyed by
/// conversation first.
pub(super) const V6: &str = r#"
-- SYNC lists the user's read markers (7.1, 7.4).
CREATE INDEX read_markers_uid ON read_markers (uid);
-- Forgetting an identity (4.8) deletes its invitations and cids; listing
-- the rooms it holds a role or invitation in reads invitations too.
CREATE INDEX invites_uid ON invites (uid);
CREATE INDEX cids_author ON cids (author);
"#;

/// Brings the database up to date. Fails if it is newer than this server.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    migrate_with(conn, MIGRATIONS)
}

/// Applies the migrations in `migrations` that the database does not have
/// yet.
///
/// Foreign keys are off while they run, so a migration can rebuild a table
/// (create a new one, copy the rows, drop the old one, rename the new one)
/// without the drop deleting the rows of other tables that refer to it
/// (`ON DELETE CASCADE`). Before each migration commits,
/// `PRAGMA foreign_key_check` must find nothing, or the migration is
/// rolled back. Foreign keys are on again afterwards, whatever happened.
/// SQLite ignores the `foreign_keys` pragma inside a transaction, so it is
/// set around them.
pub(super) fn migrate_with(conn: &mut Connection, migrations: &[&str]) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let latest = migrations.len() as i64;
    if version > latest {
        return Err(StoreError::Corrupt(format!(
            "database schema version {version} is newer than this server's ({latest})"
        )));
    }
    if version == latest {
        return Ok(());
    }
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let result = (|| -> Result<()> {
        for (i, sql) in migrations.iter().enumerate().skip(version as usize) {
            let tx = conn.transaction()?;
            apply(&tx, sql, i as i64 + 1)?;
            tx.commit()?;
            tracing::info!(version = i + 1, "migrated database schema");
        }
        Ok(())
    })();
    let restored = conn.pragma_update(None, "foreign_keys", "ON");
    result?;
    restored?;
    Ok(())
}

fn apply(tx: &Transaction<'_>, sql: &str, version: i64) -> Result<()> {
    tx.execute_batch(sql)?;
    let problems: Vec<String> = tx
        .prepare("PRAGMA foreign_key_check")?
        .query_map([], |row| {
            Ok(format!(
                "{} row {} refers to a missing row of {}",
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?
                    .map_or_else(|| "?".to_owned(), |r| r.to_string()),
                row.get::<_, String>(2)?,
            ))
        })?
        .take(10)
        .collect::<rusqlite::Result<_>>()?;
    if !problems.is_empty() {
        return Err(StoreError::Corrupt(format!(
            "migration to schema version {version} breaks foreign keys: {}",
            problems.join("; ")
        )));
    }
    tx.pragma_update(None, "user_version", version)?;
    Ok(())
}

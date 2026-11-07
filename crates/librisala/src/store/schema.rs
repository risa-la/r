//! The cache's schema and its migrations.
//!
//! The schema version lives in `PRAGMA user_version`. Each migration takes
//! the database from version `n` to `n + 1`, inside one transaction, so two
//! processes opening the cache at once cannot both run it.

use rusqlite::{Connection, TransactionBehavior};

use super::StoreError;

/// The migrations, in order. Entry `i` takes the schema from version `i` to
/// `i + 1`.
pub(super) const MIGRATIONS: &[&str] = &[V1, V2, V3, V4, V5, V6];

/// The schema version this build writes.
pub(super) const VERSION: u32 = MIGRATIONS.len() as u32;

/// Version 1: the whole cache.
///
/// Sequence numbers, times (Unix milliseconds) and counts are INTEGERs.
/// Text stays escaped, as on the wire (3.4).
const V1: &str = "
-- Servers by address (ServerAddr's display form), and their trust records
-- (2.2). No record means nothing is trusted yet.
CREATE TABLE servers (
    id   INTEGER PRIMARY KEY,
    addr TEXT NOT NULL UNIQUE
);
CREATE TABLE trust (
    server      INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('ca', 'pinned')),
    fingerprint TEXT,
    CHECK ((kind = 'pinned') = (fingerprint IS NOT NULL))
);

-- One account per signed-in uid on a server: a guest or an identity.
CREATE TABLE accounts (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    server INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    uid    TEXT NOT NULL,
    UNIQUE (server, uid)
);

-- Conversations, per account (5.1, 7.1).
--
-- conv_id is the id the conversation was last known by, or NULL when it is
-- not known; then no events are stored. epoch counts the times its history
-- was discarded, so that a page asked for before then is not stored.
-- sync_point is the seq up to which every event the server still keeps is
-- stored (7.1). head is the newest head the server reported. read is the
-- read marker (7.4). joined says whether the account is in it, as far as
-- the client knows.
--
-- AUTOINCREMENT, so that a conversation removed after DROP never shares a
-- row id with a later one.
CREATE TABLE convs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account    INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    conv_id    TEXT,
    epoch      INTEGER NOT NULL DEFAULT 0,
    sync_point INTEGER NOT NULL DEFAULT 0,
    head       INTEGER NOT NULL DEFAULT 0,
    read       INTEGER NOT NULL DEFAULT 0,
    joined     INTEGER NOT NULL DEFAULT 0,
    UNIQUE (account, name)
);

-- Events (5.2), keyed by conversation and seq.
--
-- line is the event as received, in canonical form, without ref. The
-- other columns are what the UI needs indexed:
-- - rel and target: a MSG's reply, edit or react tag (5.3); target is also
--   the seq a DELETE names (5.4).
-- - deleted: the content was removed (5.4). Then text is '', the file
--   columns are NULL and line is the placeholder HISTORY would send.
-- - text: a MSG's text, escaped; NULL for other verbs.
-- - subject: the uid that INVITE, KICK, BAN, UNBAN or ROLE acts on.
CREATE TABLE events (
    conv      INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
    seq       INTEGER NOT NULL,
    t         INTEGER NOT NULL,
    author    TEXT NOT NULL,
    verb      TEXT NOT NULL,
    rel       TEXT CHECK (rel IN ('reply', 'edit', 'react')),
    target    INTEGER,
    deleted   INTEGER NOT NULL DEFAULT 0,
    text      TEXT,
    file_url  TEXT,
    file_type TEXT,
    file_size INTEGER,
    subject   TEXT,
    line      TEXT NOT NULL,
    PRIMARY KEY (conv, seq)
) WITHOUT ROWID;
CREATE INDEX events_target ON events (conv, target) WHERE target IS NOT NULL;

-- Derived: the current text of each stored message that is not an edit or
-- a reaction, after its edits (5.3) and deletion (5.4). edit_seq is the
-- edit whose text is current, if any.
CREATE TABLE message_state (
    conv     INTEGER NOT NULL,
    seq      INTEGER NOT NULL,
    text     TEXT NOT NULL,
    edit_seq INTEGER,
    PRIMARY KEY (conv, seq),
    FOREIGN KEY (conv, seq) REFERENCES events (conv, seq) ON DELETE CASCADE
) WITHOUT ROWID;

-- Derived: reaction counts per message and reaction (5.3). mine is the seq
-- of the account's own reaction, which DELETE takes back.
CREATE TABLE reactions (
    conv     INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
    target   INTEGER NOT NULL,
    reaction TEXT NOT NULL,
    count    INTEGER NOT NULL,
    mine     INTEGER,
    PRIMARY KEY (conv, target, reaction)
) WITHOUT ROWID;

-- Derived: room settings (6.2), from SET events and snapshots. seq is the
-- event that set the value, or the head when a snapshot did, so an older
-- event loaded later does not overwrite a newer value.
CREATE TABLE room_settings (
    conv  INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
    key   TEXT NOT NULL,
    value TEXT NOT NULL,
    seq   INTEGER NOT NULL,
    PRIMARY KEY (conv, key)
) WITHOUT ROWID;

-- Derived: room membership, roles and bans (6.1, 6.3, 6.4), as far as the
-- stored events and snapshots show. Each part carries the seq that last
-- changed it, as for settings.
CREATE TABLE room_members (
    conv       INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
    uid        TEXT NOT NULL,
    joined     INTEGER,
    joined_seq INTEGER NOT NULL DEFAULT 0,
    role       TEXT,
    role_seq   INTEGER NOT NULL DEFAULT 0,
    banned     INTEGER NOT NULL DEFAULT 0,
    ban_seq    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conv, uid)
) WITHOUT ROWID;

-- Messages waiting to be sent, or sent (7.6). conv is the conversation's
-- name, so an entry outlives a dropped room. conv_id is the id the message
-- is bound to, or NULL for a direct conversation that has not started.
-- state is queued, sending, sent (seq is set) or failed (error is set).
CREATE TABLE outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account    INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    conv       TEXT NOT NULL,
    conv_id    TEXT,
    cid        TEXT NOT NULL UNIQUE,
    text       TEXT NOT NULL,
    rel        TEXT CHECK (rel IN ('reply', 'edit', 'react')),
    target     INTEGER,
    file_url   TEXT,
    state      TEXT NOT NULL CHECK (state IN ('queued', 'sending', 'sent', 'failed')),
    seq        INTEGER,
    error      TEXT,
    created    INTEGER NOT NULL,
    first_sent INTEGER
);
CREATE INDEX outbox_pending ON outbox (account, conv) WHERE state IN ('queued', 'sending');
";

/// Version 2: the rooms a guest account joins again after reconnecting.
///
/// Guests leave their rooms when they disconnect (4.2), so the client
/// layer keeps the rooms the user joined here, and joins them again on
/// each new connection. Rooms are kept by name.
const V2: &str = "
CREATE TABLE rejoin (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    room    TEXT NOT NULL,
    PRIMARY KEY (account, room)
) WITHOUT ROWID;
";

/// Version 3: guest sessions (4.2), and events marked as the account's own.
///
/// - `accounts.guest_name` and `guest_token`: the guest session the
///   account last signed in to, by the name it got (which may be a
///   numbered fallback such as `sam2`) and the token from its `OK`, to
///   resume it after reconnecting. Both are NULL for identities, and for
///   guests with no session yet.
/// - `events.own`: 1 for an event the account sent. A guest may sign in
///   under a fallback name, so this is decided when the event is stored,
///   from the uid of the connection then, and not from the account's uid
///   later. Events stored before this version, or with no connection, are
///   marked by the account's uid.
const V3: &str = "
ALTER TABLE accounts ADD COLUMN guest_name TEXT;
ALTER TABLE accounts ADD COLUMN guest_token TEXT;
ALTER TABLE events ADD COLUMN own INTEGER NOT NULL DEFAULT 0;
UPDATE events SET own = 1 WHERE author = (
    SELECT a.uid FROM convs c JOIN accounts a ON a.id = c.account WHERE c.id = events.conv
);
";

/// Version 4: outbox claims, so that two processes sharing the cache never
/// send the same entry (7.6).
///
/// `outbox.claim` names the connection that sent an entry in `sending`:
/// `<store instance>:<connection>`, where the store instance is random for
/// each [`Store`](super::Store) opened. `claimed_at` is when, in Unix
/// milliseconds. Another process leaves a claimed entry alone until its
/// lease runs out; the same store instance knows its earlier connections
/// are gone.
const V4: &str = "
ALTER TABLE outbox ADD COLUMN claim TEXT;
ALTER TABLE outbox ADD COLUMN claimed_at INTEGER;
";

/// Version 5: display names, blocks, and hiding blocked people (5.7, 8.2,
/// 8.3).
///
/// - `users`: the display names the account has learned, from MEMBER,
///   USER and NAME lines, escaped as on the wire. A row means the name is
///   known; `''` means the user has none. Presence is not stored: it is
///   only true while connected.
/// - `blocks`: the account's blocks (5.7), as written on the wire: an
///   identity, or `*@<domain>`.
/// - `accounts.hide_blocked`: 1 to hide blocked people's messages in rooms
///   (5.7). The messages stay stored, so unblocking shows them again.
const V5: &str = "
CREATE TABLE users (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    uid     TEXT NOT NULL,
    name    TEXT NOT NULL,
    PRIMARY KEY (account, uid)
) WITHOUT ROWID;
CREATE TABLE blocks (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    target  TEXT NOT NULL,
    PRIMARY KEY (account, target)
) WITHOUT ROWID;
ALTER TABLE accounts ADD COLUMN hide_blocked INTEGER NOT NULL DEFAULT 0;
";

/// Version 6: the device key an identity account last signed in with.
///
/// `accounts.accepted_key` is the fingerprint of the key the server last
/// accepted for the account (4.5), or NULL if it never has. When the
/// server refuses the same key later, it was most likely removed from the
/// identity's key file, which the client tells the user plainly.
const V6: &str = "
ALTER TABLE accounts ADD COLUMN accepted_key TEXT;
";

/// Brings the schema up to [`VERSION`].
pub(super) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    loop {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > VERSION {
            return Err(StoreError::TooNew(version));
        }
        if version == VERSION {
            return Ok(());
        }
        tx.execute_batch(MIGRATIONS[version as usize])?;
        tx.pragma_update(None, "user_version", version + 1)?;
        tx.commit()?;
    }
}

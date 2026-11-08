//! The cache's schema and its migrations.
//!
//! The schema version lives in `PRAGMA user_version`. Each migration takes
//! the database from version `n` to `n + 1`, inside one transaction, so two
//! processes opening the cache at once cannot both run it.

use rusqlite::{Connection, TransactionBehavior};

use super::StoreError;

/// The migrations, in order. Entry `i` takes the schema from version `i` to
/// `i + 1`.
pub(super) const MIGRATIONS: &[&str] = &[
    V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15,
];

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

/// Version 7: blocks changed one at a time, so that a BLOCKS reply that
/// is out of date cannot undo a newer change (5.7).
///
/// - `accounts.blocks_clock` counts the account's block changes: BLOCK and
///   UNBLOCK accepted, and BLOCK and UNBLOCK lines from its other devices.
///   Every process sharing the cache moves the same clock.
/// - `blocks.changed` is the clock value of a block's last change, and
///   `blocks.blocked` is 0 for a block lifted since the last BLOCKS. A
///   BLOCKS reply covers the account's blocks as they were when BLOCKS
///   was sent, so it leaves alone those changed since, as the head check
///   of 7.1 does with events.
const V7: &str = "
ALTER TABLE accounts ADD COLUMN blocks_clock INTEGER NOT NULL DEFAULT 0;
ALTER TABLE blocks ADD COLUMN blocked INTEGER NOT NULL DEFAULT 1;
ALTER TABLE blocks ADD COLUMN changed INTEGER NOT NULL DEFAULT 0;
";

/// Version 8: an UNREGISTER whose answer was lost (4.8).
///
/// `accounts.unregister_lost` is NULL normally. After UNREGISTER was sent
/// and its answer lost, it is 1 if the server hosted the identity and 0 if
/// not, until the user tries again, so that the account does not sign in
/// on its own meanwhile, even after a restart.
const V8: &str = "
ALTER TABLE accounts ADD COLUMN unregister_lost INTEGER;
";

/// Version 9: DELETE in the outbox (5.4).
///
/// `outbox.verb` is `MSG` for a message, or `DELETE` for a deletion of
/// message `target`, which has no text, relation or file. A DELETE entry
/// still gets a cid, to keep the column's constraints, but never sends
/// it: DELETE has no `cid` tag (7.6).
const V9: &str = "
ALTER TABLE outbox ADD COLUMN verb TEXT NOT NULL DEFAULT 'MSG' CHECK (verb IN ('MSG', 'DELETE'));
";

/// Version 10: finding the outbox entry a stored message was sent from.
///
/// A timeline item the account sent through the outbox keeps the entry's
/// id, so that a UI does not take it for a new message once it is stored.
/// The entry names the event by its `seq` once sent; this index finds it.
const V10: &str = "
CREATE INDEX outbox_sent ON outbox (account, conv, seq) WHERE state = 'sent';
";

/// Version 11: a REGISTER whose answer is not known yet (4.6).
///
/// `accounts.register_pending` is NULL normally. It is set before REGISTER
/// is sent for the account's identity and cleared once the answer is
/// known, so that a REGISTER whose answer was lost, never waited for, or
/// cut short by the process ending is settled later by signing in: 1 if
/// the account was added for the REGISTER, and goes if it is refused; 0
/// if the account was in the cache before, and stays.
const V11: &str = "
ALTER TABLE accounts ADD COLUMN register_pending INTEGER;
";

/// Version 12: the chat list.
///
/// - `convs.activity` orders the chat list, newest first: the newest of
///   the time of the conversation's newest message (a MSG that is not an
///   edit or a reaction), the time the account's newest message for it
///   was queued in the outbox, and when the conversation entered the
///   cache, in Unix milliseconds. It only moves forward. The writes that
///   change it keep it up to date in the same transaction. For the rows
///   that exist already it is worked out from their messages and outbox;
///   when they entered the cache is not known, so a conversation with
///   neither gets 0. Messages hidden as a blocked person's (5.7) do not
///   count, as they do not when stored, so a migrated cache sorts as a
///   fresh one would. The test for them is `people::HIDDEN` as it is at
///   this version, copied, so that this migration stays as it shipped.
/// - `convs.favourite` is 1 for a conversation the user marked as a
///   favourite. It is local: the spec has nowhere to keep it.
/// - `outbox_unsent` finds a conversation's newest message not sent yet,
///   for its preview.
const V12: &str = "
ALTER TABLE convs ADD COLUMN activity INTEGER NOT NULL DEFAULT 0;
ALTER TABLE convs ADD COLUMN favourite INTEGER NOT NULL DEFAULT 0;
UPDATE convs SET activity = MAX(
    COALESCE((SELECT MAX(e.t) FROM events e
              WHERE e.conv = convs.id AND e.verb = 'MSG' AND (e.rel IS NULL OR e.rel = 'reply')
                  AND NOT (e.own = 0 AND EXISTS (
                      SELECT 1 FROM convs hc
                      JOIN accounts ha ON ha.id = hc.account
                      JOIN blocks b ON b.account = ha.id
                      WHERE hc.id = e.conv AND ha.hide_blocked = 1
                          AND substr(hc.name, 1, 1) = '#' AND b.blocked = 1
                          AND (b.target = e.author
                              OR (substr(b.target, 1, 2) = '*@' AND instr(e.author, '@') > 0
                                  AND (substr(e.author, instr(e.author, '@') + 1)
                                          = substr(b.target, 3)
                                      OR substr(e.author, 1 - length(b.target))
                                          = '.' || substr(b.target, 3))))))),
             0),
    COALESCE((SELECT MAX(o.created) FROM outbox o
              WHERE o.account = convs.account AND o.conv = convs.name AND o.verb = 'MSG'
                  AND (o.rel IS NULL OR o.rel = 'reply')),
             0));
CREATE INDEX convs_activity ON convs (activity DESC, id);
CREATE INDEX outbox_unsent ON outbox (account, conv, id) WHERE state != 'sent';
";

/// Version 13: OpenMLS's state (SPEC 12, PLAN.md 42).
///
/// The `openmls_*` tables of `openmls_sqlite_storage`, which OpenMLS reads
/// and writes through [`MlsStorage`](super::mls::MlsStorage): groups,
/// KeyPackages, proposals and keys. They live in the cache, so that an MLS
/// operation and the cache's own rows commit or roll back together. A
/// later change to them comes as a new migration here.
const V13: &str = openmls_sqlite_storage::SCHEMA;

/// Version 14: end-to-end encryption (SPEC 12), around OpenMLS's own
/// tables.
///
/// - The columns added to `events`:
///   - `enc`, for an ENC event (12.8): `pending` until it is decrypted,
///     then `verified`, `unverified` (a restored epoch whose sender's key
///     is not known, 12.8 step 4), `failed` (the content must not be
///     shown; `enc_error` says why), `control` (KEY and RECOVERY lines,
///     not a message) or `ignored` (a message the room's rules drop,
///     12.11). NULL for every other verb, and for a deleted placeholder.
///   - `mls_epoch`: the epoch of an ENC event, or the epoch a COMMIT event
///     started.
///   - `message_id`, `content` and `frank_key`: a decrypted message's id,
///     content lines and franking key, kept for replies, edits, reactions
///     and reports (5.8, 12.8). `target_mid` is the `target` a reply,
///     edit or reaction names; `rel` and `target` are filled in as for MSG,
///     and the derived tables follow them only while the target's
///     `message_id` is `target_mid`.
/// - `mls_groups`: the group of each encrypted conversation the account
///   is in: OpenMLS's group id, the epoch and the seq of the COMMIT event
///   that started it, and its state. `init` while INIT waits for its
///   answer; `active`; `rejected` after a commit failed a check of 12.6,
///   when the device stops sending and never joins again; `broken` after
///   MLS itself refused a commit, when it may join again by external
///   commit (12.6); `left` once the account is no longer in the group,
///   when only its history keys are kept. `pending` is a commit sent and
///   not answered yet, in
///   base64, and `refreshed` when the device last committed a fresh leaf
///   (12.6), in Unix milliseconds.
/// - `history_keys`: every history key the account holds (12.9), by the
///   conversation's id, with where it came from and the seq of the COMMIT
///   event that started the epoch, if known (0 for epoch 0). `backed_up`
///   is the key id of the backup key it was last backed up under (12.10).
///   `send` is the room's `send` value in the group at that epoch, for an
///   epoch the device was in (12.11); NULL if not known.
/// - `epoch_leaves`: the signature keys of each epoch's leaves that the
///   device was in, by key id (SHA-384), for 12.8 step 4.
/// - `device_keys`: device keys the account has seen in groups and key
///   files (12.8 step 4, 12.12), by key id. `listed` says whether the
///   identity's key file listed the key when last fetched (NULL: never
///   checked). `key_files` says when each identity's key file was last
///   fetched and tried.
/// - `own_devices`: the identity's other devices, and whether the user
///   confirmed each one, so that this device sends it history keys
///   (12.9): `new`, `confirmed`, `sent` or `declined`.
const V14: &str = "
ALTER TABLE events ADD COLUMN enc TEXT
    CHECK (enc IN ('pending', 'verified', 'unverified', 'failed', 'control', 'ignored'));
ALTER TABLE events ADD COLUMN enc_error TEXT;
ALTER TABLE events ADD COLUMN mls_epoch INTEGER;
ALTER TABLE events ADD COLUMN message_id BLOB;
ALTER TABLE events ADD COLUMN target_mid BLOB;
ALTER TABLE events ADD COLUMN content BLOB;
ALTER TABLE events ADD COLUMN frank_key BLOB;
CREATE INDEX events_enc_pending ON events (conv, mls_epoch) WHERE enc = 'pending';
CREATE INDEX events_message_id ON events (conv, message_id) WHERE message_id IS NOT NULL;
CREATE INDEX events_commits ON events (conv, mls_epoch) WHERE verb = 'COMMIT';

CREATE TABLE mls_groups (
    conv       INTEGER PRIMARY KEY REFERENCES convs(id) ON DELETE CASCADE,
    group_id   BLOB NOT NULL,
    epoch      INTEGER NOT NULL,
    commit_seq INTEGER NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('init', 'active', 'rejected', 'broken', 'left')),
    pending    TEXT,
    refreshed  INTEGER NOT NULL
);

CREATE TABLE history_keys (
    account    INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    conv_id    TEXT NOT NULL,
    epoch      INTEGER NOT NULL,
    key        BLOB NOT NULL,
    source     TEXT NOT NULL CHECK (source IN ('own', 'device', 'backup', 'member')),
    commit_seq INTEGER,
    backed_up  BLOB,
    send       TEXT CHECK (send IN ('all', 'mods')),
    PRIMARY KEY (account, conv_id, epoch)
) WITHOUT ROWID;

CREATE TABLE epoch_leaves (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    conv_id TEXT NOT NULL,
    epoch   INTEGER NOT NULL,
    uid     TEXT NOT NULL,
    key_id  BLOB NOT NULL,
    PRIMARY KEY (account, conv_id, epoch, key_id)
) WITHOUT ROWID;

CREATE TABLE device_keys (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key_id  BLOB NOT NULL,
    uid     TEXT NOT NULL,
    key     BLOB NOT NULL,
    listed  INTEGER,
    label   TEXT,
    PRIMARY KEY (account, key_id)
) WITHOUT ROWID;

CREATE TABLE key_files (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    uid     TEXT NOT NULL,
    fetched INTEGER,
    tried   INTEGER NOT NULL,
    PRIMARY KEY (account, uid)
) WITHOUT ROWID;

CREATE TABLE own_devices (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key_id  BLOB NOT NULL,
    state   TEXT NOT NULL CHECK (state IN ('new', 'confirmed', 'sent', 'declined')),
    PRIMARY KEY (account, key_id)
) WITHOUT ROWID;
";

/// Version 15: `device_keys.seen` orders an identity's device keys by
/// when this device first saw them, since the table has no rowid. Keys
/// from before it have NULL, and come first.
const V15: &str = "
ALTER TABLE device_keys ADD COLUMN seen INTEGER;
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

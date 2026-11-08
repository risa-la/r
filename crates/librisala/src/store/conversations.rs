//! Conversations: the MLS groups this device is in, their mailboxes and
//! sync points, their leaves, the posts waiting to be applied, and blocks
//! (5, 6, 7, 12.4, 12.7).
//!
//! Owned by task C2. The tables are a sketch from the spec; C2 may add
//! and change columns and tables (see the [store docs](super)). The
//! groups' MLS state is OpenMLS's, in the `mls` module's tables.

use super::row_id;

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- One row per group this device is in, for one account (5.1). kind,
-- name, topic and room come from the conversation extension (12.4), never
-- from the server. mailbox is its box (5.2). sync_point and head are
-- those of 7.4, read the read marker (7.7). pseudonym is the own leaf's
-- (7.3); sent and last_sent its counter and previous message id (12.9).
CREATE TABLE conversations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account    INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    group_id   BLOB NOT NULL,
    mailbox    TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('direct', 'private', 'public')),
    room       TEXT,
    name       TEXT,
    topic      TEXT,
    epoch      INTEGER NOT NULL DEFAULT 0,
    sync_point INTEGER NOT NULL DEFAULT 0,
    head       INTEGER NOT NULL DEFAULT 0,
    read       INTEGER NOT NULL DEFAULT 0,
    pseudonym  BLOB NOT NULL,
    sent       INTEGER NOT NULL DEFAULT 0,
    last_sent  BLOB,
    state      TEXT NOT NULL DEFAULT 'active'
               CHECK (state IN ('joining', 'active', 'left', 'dropped', 'lost')),
    created    INTEGER NOT NULL,
    UNIQUE (account, group_id),
    UNIQUE (account, mailbox)
);

-- The leaves of each group as this device knows them (7.3, 12.3, 12.7,
-- 12.9). device_id is NULL for a guest's leaf. pseudonym is the first one
-- seen from the leaf (7.3). counter and last_message track its messages
-- for gaps (7.4). display_name and profile_updated come from its profile
-- extension (8.2).
CREATE TABLE leaves (
    conv            INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf            INTEGER NOT NULL,
    uid             TEXT NOT NULL,
    device_id       BLOB,
    pseudonym       BLOB,
    counter         INTEGER NOT NULL DEFAULT 0,
    last_message    BLOB,
    display_name    TEXT,
    profile_updated INTEGER,
    self_removed    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conv, leaf)
) WITHOUT ROWID;

-- Posts fetched or received but not yet applied, in seq order (7.2,
-- 7.4): commits wait for the first valid one of an epoch, and messages of
-- epochs not reached yet wait for theirs. message is the MLSMessage.
CREATE TABLE posts (
    conv    INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    t       INTEGER NOT NULL,
    message BLOB NOT NULL,
    PRIMARY KEY (conv, seq)
) WITHOUT ROWID;

-- Blocks (5.7), per identity of this device, synced with BLOCK and
-- UNBLOCK in the conversation with yourself.
CREATE TABLE blocks (
    owner  TEXT NOT NULL,
    target TEXT NOT NULL,
    t      INTEGER NOT NULL,
    PRIMARY KEY (owner, target)
) WITHOUT ROWID;
";

row_id!(
    /// A conversation in the cache.
    ConversationId
);

/// A change to conversations or their members.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConversationChange {
    /// A conversation was added, or its summary changed.
    Conversation(ConversationId),
    /// A conversation's leaves, members or profiles changed.
    Members(ConversationId),
    /// Blocks changed.
    Blocks,
}

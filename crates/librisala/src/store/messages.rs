//! Messages: what each conversation has shown, decrypted, its gaps, and
//! the outbox (5.3, 5.4, 7.4, 7.6, 12.9).
//!
//! Owned by task C2. The server keeps no history (Section 7), so these
//! rows are the history. The tables are a sketch from the spec; C2 may add
//! and change columns and tables.

use super::conversations::ConversationId;

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Messages, by conversation and message_id (12.9). seq and received are
-- the post's; sent is the sender's clock, and time_mismatch marks more
-- than 10 minutes between them (12.9). verified is whether the sender's
-- leaf was confirmed (12.10). restored marks messages from a backup or a
-- transfer (12.13). content holds the content lines as received; text,
-- reply_to, edit_of and react_to are a TEXT line's, after edits (5.3).
-- frank_key is kept to report the message (5.8).
CREATE TABLE messages (
    conv          INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id    BLOB NOT NULL,
    seq           INTEGER,
    sender        TEXT NOT NULL,
    leaf          INTEGER,
    sent          INTEGER NOT NULL,
    received      INTEGER,
    verified      INTEGER NOT NULL DEFAULT 0,
    time_mismatch INTEGER NOT NULL DEFAULT 0,
    restored      INTEGER NOT NULL DEFAULT 0,
    content       BLOB NOT NULL,
    text          TEXT,
    reply_to      BLOB,
    edit_of       BLOB,
    react_to      BLOB,
    deleted       INTEGER NOT NULL DEFAULT 0,
    frank_key     BLOB,
    PRIMARY KEY (conv, message_id)
) WITHOUT ROWID;
CREATE INDEX messages_seq ON messages (conv, seq);

-- Gaps in a leaf's messages (7.4): counters not received, and whether
-- retention explains them.
CREATE TABLE gaps (
    conv   INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf   INTEGER NOT NULL,
    first  INTEGER NOT NULL,
    last   INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('expired', 'withheld')),
    PRIMARY KEY (conv, leaf, first)
) WITHOUT ROWID;

-- Posts to send (7.6): messages, commits and proposals, each with the
-- epoch it is for and its cid. post is the MLSMessage.
CREATE TABLE outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('message', 'commit', 'proposal')),
    message_id BLOB,
    epoch      INTEGER NOT NULL,
    post       BLOB NOT NULL,
    cid        TEXT NOT NULL,
    state      TEXT NOT NULL DEFAULT 'queued'
               CHECK (state IN ('queued', 'sent', 'posted', 'failed')),
    seq        INTEGER,
    created    INTEGER NOT NULL
);
";

/// A change to messages or the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageChange {
    /// A conversation's messages changed: added, edited or deleted.
    Messages(ConversationId),
    /// The outbox changed.
    Outbox(ConversationId),
}

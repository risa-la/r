//! Push subscriptions (Section 9).
//!
//! Owned by task C4. The tables are a sketch from the spec; C4 may add
//! and change columns and tables.

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Push subscriptions (9.1): one per conversation's mailbox, made on an
-- anonymous connection, and one per account for Welcomes, made on the
-- signed-in one (conv NULL). Each has its own URL and tag, so they cannot
-- be linked by them (Section 14). p256dh and auth are the RFC 8291 keys
-- the bodies are encrypted to, and private_key the device's half.
CREATE TABLE push_subscriptions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    conv        INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
    url         TEXT NOT NULL UNIQUE,
    tag         TEXT NOT NULL UNIQUE,
    p256dh      BLOB NOT NULL,
    auth        BLOB NOT NULL,
    private_key BLOB NOT NULL,
    created     INTEGER NOT NULL
);
";

/// A change to push subscriptions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PushChange {
    /// Subscriptions were added or removed.
    Subscriptions,
}

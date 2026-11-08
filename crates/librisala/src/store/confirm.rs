//! Confirming leaves (12.10): pairwise challenges and answers, and
//! epochal period keys and attestations.
//!
//! Owned by task C3. The tables are a sketch from the spec; C3 may add
//! and change columns and tables.

use super::conversations::ConversationId;

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Pairwise confirmation (12.10) of each leaf key this device has seen
-- send, by the hash of the leaf's signature key.
CREATE TABLE leaf_confirmations (
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf       INTEGER NOT NULL,
    leaf_key   BLOB NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('challenged', 'confirmed', 'failed')),
    challenged INTEGER,
    confirmed  INTEGER,
    PRIMARY KEY (conv, leaf, leaf_key)
) WITHOUT ROWID;

-- This device's period keys in epochal groups (12.10), by UTC day, until
-- each is revealed.
CREATE TABLE period_keys (
    conv     INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    period   INTEGER NOT NULL,
    seed     BLOB NOT NULL,
    revealed INTEGER,
    PRIMARY KEY (conv, period)
) WITHOUT ROWID;

-- Other leaves' attestations (ATTEST) and reveals (REVEAL) (12.10).
CREATE TABLE attestations (
    conv        INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf        INTEGER NOT NULL,
    period      INTEGER NOT NULL,
    period_key  BLOB NOT NULL,
    certificate BLOB NOT NULL,
    attestation BLOB NOT NULL,
    revealed    BLOB,
    PRIMARY KEY (conv, leaf, period)
) WITHOUT ROWID;
";

/// A change to confirmations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfirmChange {
    /// A leaf of the conversation was confirmed, or failed to be.
    Leaves(ConversationId),
}

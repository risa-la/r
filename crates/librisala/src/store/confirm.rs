//! Confirming leaves (12.10): pairwise challenges and answers, and
//! epochal period keys and attestations.
//!
//! Owned by task C3. The state of each group is risala-mls's
//! [`Confirmer`](risala_mls::Confirmer), kept whole in `confirmers`: it
//! holds open challenges' shared secrets, which is fine here since the
//! cache is encrypted (PLAN.md 43). The device's period keys and the
//! REVEALs it has seen are kept per identity in `period_keys`, since one
//! period key serves every epochal group of a device (12.10).
//! `leaf_confirmations` repeats each leaf's state where the rest of the
//! client reads it, and `confirm_warnings` keeps what the user is told.

use rusqlite::{OptionalExtension as _, params};

use super::conversations::ConversationId;
use super::messages::MessageChange;
use super::{Change, StoreError, Tx};

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- The confirmation state of each group this device is in (12.10):
-- risala-mls's Confirmer, serialised. own_key is this device's leaf's
-- signature key as the Confirmer last knew it. wake is when the engine
-- next has something to do for the group: a deadline, a line to send on
-- its own, a REVEAL, a rotation.
CREATE TABLE confirmers (
    conv    INTEGER PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    state   BLOB NOT NULL,
    own_key BLOB NOT NULL,
    wake    INTEGER
);

-- Each leaf's state, for the rest of the client (12.9 step 6, 12.10).
-- state is 'unconfirmed', 'confirmed' or 'impostor'. until is when a
-- confirmation by ATTEST lapses, at the end of its period's grace hour.
-- since_seq is the newest seq of a message in the group when the leaf got
-- signature_key: its later messages were signed with that key, and show
-- as verified once it is confirmed. repair_at is when to remove an
-- impostor for a check (12.7), unless another device has.
CREATE TABLE leaf_confirmations (
    conv          INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf          INTEGER NOT NULL,
    signature_key BLOB NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('unconfirmed', 'confirmed', 'impostor')),
    until         INTEGER,
    since_seq     INTEGER NOT NULL DEFAULT 0,
    repair_at     INTEGER,
    PRIMARY KEY (conv, leaf)
) WITHOUT ROWID;

-- The period keys of each identity this device holds (12.10): its chains
-- of seeds and certificates (risala-mls's PeriodKeyring), and the REVEALs
-- it has seen from other devices (RevealRegistry), serialised.
CREATE TABLE period_keys (
    uid     TEXT PRIMARY KEY,
    keyring BLOB NOT NULL,
    reveals BLOB NOT NULL
) WITHOUT ROWID;

-- What leaf confirmation tells the user (12.7, 12.9, 12.10): impostors,
-- leaves that never answered, attestations that are not valid, REVEALs
-- that are wrong or missing. kind is the warning, detail its reason or
-- period.
CREATE TABLE confirm_warnings (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    conv   INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf   INTEGER NOT NULL,
    uid    TEXT NOT NULL,
    kind   TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    at     INTEGER NOT NULL
);
CREATE INDEX confirm_warnings_conv ON confirm_warnings (conv);
";

/// A change to confirmations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfirmChange {
    /// A leaf of the conversation was confirmed, found an impostor, or
    /// lost its confirmation.
    Leaves(ConversationId),
    /// The conversation has a new warning.
    Warnings(ConversationId),
}

/// A leaf's state (12.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafConfirmation {
    /// Not confirmed (yet).
    Unconfirmed,
    /// Confirmed.
    Confirmed,
    /// An impostor to this device (12.7).
    Impostor,
}

impl LeafConfirmation {
    fn as_str(self) -> &'static str {
        match self {
            LeafConfirmation::Unconfirmed => "unconfirmed",
            LeafConfirmation::Confirmed => "confirmed",
            LeafConfirmation::Impostor => "impostor",
        }
    }

    fn parse(s: &str) -> Result<LeafConfirmation, StoreError> {
        match s {
            "unconfirmed" => Ok(LeafConfirmation::Unconfirmed),
            "confirmed" => Ok(LeafConfirmation::Confirmed),
            "impostor" => Ok(LeafConfirmation::Impostor),
            other => Err(StoreError::Corrupt(format!("leaf state {other:?}"))),
        }
    }
}

/// A row of `leaf_confirmations`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafConfirmationRow {
    /// The leaf index.
    pub leaf: u32,
    /// The signature key the state is for.
    pub signature_key: Vec<u8>,
    /// Its state.
    pub state: LeafConfirmation,
    /// When a confirmation by ATTEST lapses.
    pub until: Option<u64>,
    /// The newest message seq in the group when the leaf got this key.
    pub since_seq: u64,
    /// When to remove it as an impostor.
    pub repair_at: Option<u64>,
}

impl LeafConfirmationRow {
    /// Whether the leaf counts as confirmed at `now`.
    pub fn confirmed_at(&self, now: u64) -> bool {
        self.state == LeafConfirmation::Confirmed && self.until.is_none_or(|u| now < u)
    }
}

/// A warning for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarningRow {
    /// Its id.
    pub id: i64,
    /// The conversation.
    pub conv: ConversationId,
    /// The leaf.
    pub leaf: u32,
    /// The leaf's uid.
    pub uid: String,
    /// What: `impostor`, `unanswered`, `invalid-attest`, `bad-reveal`,
    /// `reveal-missing`, `device-not-current`, `bad-attestation-key`.
    pub kind: String,
    /// The reason or period.
    pub detail: String,
    /// When.
    pub at: u64,
}

/// A `leaf_confirmations` row as SQLite gives it.
type LeafRaw = (u32, Vec<u8>, String, Option<i64>, i64, Option<i64>);

/// Two serialised values kept together: a Confirmer and its own leaf
/// key, or a keyring and its REVEAL registry.
type Pair = (Vec<u8>, Vec<u8>);

const LEAF_COLUMNS: &str = "leaf, signature_key, state, until, since_seq, repair_at";

fn leaf_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LeafRaw> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn into_leaf(raw: LeafRaw) -> Result<LeafConfirmationRow, StoreError> {
    let (leaf, signature_key, state, until, since_seq, repair_at) = raw;
    Ok(LeafConfirmationRow {
        leaf,
        signature_key,
        state: LeafConfirmation::parse(&state)?,
        until: until.map(|u| u as u64),
        since_seq: since_seq as u64,
        repair_at: repair_at.map(|r| r as u64),
    })
}

/// Reads, on any connection.
pub(crate) mod read {
    use super::*;

    /// The leaves' states of a conversation.
    pub fn leaves(
        conn: &rusqlite::Connection,
        conv: ConversationId,
    ) -> Result<Vec<LeafConfirmationRow>, StoreError> {
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {LEAF_COLUMNS} FROM leaf_confirmations WHERE conv = ?1 ORDER BY leaf"
        ))?;
        let rows = stmt.query_map([conv.0], leaf_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(into_leaf(row?)?);
        }
        Ok(out)
    }

    /// One leaf's state.
    pub fn leaf(
        conn: &rusqlite::Connection,
        conv: ConversationId,
        leaf: u32,
    ) -> Result<Option<LeafConfirmationRow>, StoreError> {
        conn.query_row(
            &format!("SELECT {LEAF_COLUMNS} FROM leaf_confirmations WHERE conv = ?1 AND leaf = ?2"),
            params![conv.0, leaf],
            leaf_row,
        )
        .optional()?
        .map(into_leaf)
        .transpose()
    }

    /// A conversation's warnings, oldest first.
    pub fn warnings(
        conn: &rusqlite::Connection,
        conv: ConversationId,
    ) -> Result<Vec<WarningRow>, StoreError> {
        let mut stmt = conn.prepare_cached(
            "SELECT id, conv, leaf, uid, kind, detail, at FROM confirm_warnings
             WHERE conv = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map([conv.0], |r| {
            Ok(WarningRow {
                id: r.get(0)?,
                conv: ConversationId(r.get(1)?),
                leaf: r.get(2)?,
                uid: r.get(3)?,
                kind: r.get(4)?,
                detail: r.get(5)?,
                at: r.get::<_, i64>(6)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

impl Tx<'_> {
    /// A group's serialised Confirmer and the own leaf key it knows.
    pub(crate) fn confirmer(&self, conv: ConversationId) -> Result<Option<Pair>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT state, own_key FROM confirmers WHERE conv = ?1",
                [conv.0],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Stores a group's Confirmer.
    pub(crate) fn set_confirmer(
        &mut self,
        conv: ConversationId,
        state: &[u8],
        own_key: &[u8],
        wake: Option<u64>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO confirmers (conv, state, own_key, wake) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (conv) DO UPDATE SET state = ?2, own_key = ?3, wake = ?4",
            params![conv.0, state, own_key, wake.map(|w| w as i64)],
        )?;
        Ok(())
    }

    /// Sets when a group's Confirmer next has something to do.
    pub(crate) fn set_confirmer_wake(
        &mut self,
        conv: ConversationId,
        wake: Option<u64>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE confirmers SET wake = ?2 WHERE conv = ?1",
            params![conv.0, wake.map(|w| w as i64)],
        )?;
        Ok(())
    }

    /// Sets or clears when to remove an impostor's leaf.
    pub(crate) fn set_repair_at(
        &mut self,
        conv: ConversationId,
        leaf: u32,
        at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE leaf_confirmations SET repair_at = ?3 WHERE conv = ?1 AND leaf = ?2",
            params![conv.0, leaf, at.map(|a| a as i64)],
        )?;
        Ok(())
    }

    /// The account's conversations whose Confirmer has something to do by
    /// `now`.
    pub(crate) fn confirmers_due(
        &self,
        account: super::AccountId,
        now: u64,
    ) -> Result<Vec<ConversationId>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT c.conv FROM confirmers c JOIN conversations v ON v.id = c.conv
             WHERE v.account = ?1 AND c.wake IS NOT NULL AND c.wake <= ?2
             ORDER BY c.conv",
        )?;
        let rows = stmt.query_map(params![account.0, now as i64], |r| r.get(0))?;
        Ok(rows
            .map(|r| r.map(ConversationId))
            .collect::<Result<_, _>>()?)
    }

    /// The account's conversations with impostors to remove by `now`.
    pub(crate) fn repairs_due(
        &self,
        account: super::AccountId,
        now: u64,
    ) -> Result<Vec<(ConversationId, u32, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT l.conv, l.leaf, l.signature_key FROM leaf_confirmations l
             JOIN conversations v ON v.id = l.conv
             WHERE v.account = ?1 AND l.repair_at IS NOT NULL AND l.repair_at <= ?2",
        )?;
        let rows = stmt.query_map(params![account.0, now as i64], |r| {
            Ok((ConversationId(r.get(0)?), r.get(1)?, r.get(2)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// One leaf's state.
    pub(crate) fn leaf_confirmation(
        &self,
        conv: ConversationId,
        leaf: u32,
    ) -> Result<Option<LeafConfirmationRow>, StoreError> {
        read::leaf(self.conn(), conv, leaf)
    }

    /// The leaves' states of a conversation.
    pub(crate) fn leaf_confirmations(
        &self,
        conv: ConversationId,
    ) -> Result<Vec<LeafConfirmationRow>, StoreError> {
        read::leaves(self.conn(), conv)
    }

    /// Writes the leaves' states, and forgets leaves not in `rows`.
    pub(crate) fn set_leaf_confirmations(
        &mut self,
        conv: ConversationId,
        rows: &[LeafConfirmationRow],
    ) -> Result<(), StoreError> {
        let old = self.leaf_confirmations(conv)?;
        let mut changed = old.len() != rows.len();
        for row in rows {
            let before = old.iter().find(|o| o.leaf == row.leaf);
            if before != Some(row) {
                if before.is_none_or(|b| b.state != row.state) {
                    changed = true;
                }
                self.conn().execute(
                    "INSERT INTO leaf_confirmations
                         (conv, leaf, signature_key, state, until, since_seq, repair_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT (conv, leaf) DO UPDATE SET signature_key = ?3, state = ?4,
                         until = ?5, since_seq = ?6, repair_at = ?7",
                    params![
                        conv.0,
                        row.leaf,
                        row.signature_key,
                        row.state.as_str(),
                        row.until.map(|u| u as i64),
                        row.since_seq as i64,
                        row.repair_at.map(|r| r as i64),
                    ],
                )?;
            }
        }
        for o in &old {
            if !rows.iter().any(|r| r.leaf == o.leaf) {
                self.conn().execute(
                    "DELETE FROM leaf_confirmations WHERE conv = ?1 AND leaf = ?2",
                    params![conv.0, o.leaf],
                )?;
            }
        }
        if changed {
            self.changed(Change::Confirm(ConfirmChange::Leaves(conv)));
        }
        Ok(())
    }

    /// The newest seq of a message in the group, or 0.
    pub(crate) fn newest_message_seq(&self, conv: ConversationId) -> Result<u64, StoreError> {
        let seq: Option<i64> = self.conn().query_row(
            "SELECT MAX(seq) FROM messages WHERE conv = ?1",
            [conv.0],
            |r| r.get(0),
        )?;
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Shows a leaf's messages after `since_seq` as verified: it was
    /// confirmed, and they were signed with the key it was confirmed for
    /// (12.10).
    pub(crate) fn mark_leaf_verified(
        &mut self,
        conv: ConversationId,
        leaf: u32,
        since_seq: u64,
    ) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE messages SET verified = 1
             WHERE conv = ?1 AND leaf = ?2 AND own = 0 AND verified = 0 AND seq > ?3",
            params![conv.0, leaf, since_seq as i64],
        )?;
        if n > 0 {
            self.changed(Change::Message(MessageChange::Messages(conv)));
        }
        Ok(())
    }

    /// Replaces a queued message's RisalaMessage, and the content kept of
    /// it, once confirmation lines were added to it (12.10).
    pub(crate) fn replace_queued_message(
        &mut self,
        conv: ConversationId,
        outbox: i64,
        message_id: &[u8; 16],
        body: &[u8],
        content: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE outbox SET body = ?2 WHERE id = ?1",
            params![outbox, body],
        )?;
        self.conn().execute(
            "UPDATE messages SET content = ?3 WHERE conv = ?1 AND message_id = ?2 AND own = 1",
            params![conv.0, &message_id[..], content],
        )?;
        Ok(())
    }

    /// Sets a public room's pseudonym for this device's leaf (7.3), picked
    /// anew with each period's leaf key.
    pub(crate) fn set_own_pseudonym(
        &mut self,
        conv: ConversationId,
        pseudonym: &[u8; 16],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE conversations SET pseudonym = ?2 WHERE id = ?1",
            params![conv.0, &pseudonym[..]],
        )?;
        Ok(())
    }

    /// An identity's serialised period keyring and REVEAL registry.
    pub(crate) fn period_keys(&self, uid: &str) -> Result<Option<Pair>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT keyring, reveals FROM period_keys WHERE uid = ?1",
                [uid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Stores an identity's period keyring and REVEAL registry.
    pub(crate) fn set_period_keys(
        &mut self,
        uid: &str,
        keyring: &[u8],
        reveals: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO period_keys (uid, keyring, reveals) VALUES (?1, ?2, ?3)
             ON CONFLICT (uid) DO UPDATE SET keyring = ?2, reveals = ?3",
            params![uid, keyring, reveals],
        )?;
        Ok(())
    }

    /// Adds a warning for the user.
    pub(crate) fn add_confirm_warning(
        &mut self,
        conv: ConversationId,
        leaf: u32,
        uid: &str,
        kind: &str,
        detail: &str,
        at: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO confirm_warnings (conv, leaf, uid, kind, detail, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![conv.0, leaf, uid, kind, detail, at as i64],
        )?;
        self.changed(Change::Confirm(ConfirmChange::Warnings(conv)));
        Ok(())
    }
}

impl super::Store {
    /// Whether leaf confirmation has anything to do for the account by
    /// `now`: a Confirmer to wake, or an impostor to remove. A read, so
    /// that the engine's ticks write only when there is work.
    pub(crate) fn confirm_due(
        &self,
        account: super::AccountId,
        now: u64,
    ) -> Result<bool, StoreError> {
        self.read(|conn| {
            Ok(conn.query_row(
                "SELECT EXISTS (SELECT 1 FROM confirmers c JOIN conversations v ON v.id = c.conv
                                WHERE v.account = ?1 AND c.wake <= ?2)
                     OR EXISTS (SELECT 1 FROM leaf_confirmations l
                                JOIN conversations v ON v.id = l.conv
                                WHERE v.account = ?1 AND l.repair_at <= ?2)",
                params![account.0, now as i64],
                |r| r.get(0),
            )?)
        })
    }

    /// The leaves' states of a conversation.
    pub fn leaf_confirmation_rows(
        &self,
        conv: ConversationId,
    ) -> Result<Vec<LeafConfirmationRow>, StoreError> {
        self.read(|conn| read::leaves(conn, conv))
    }

    /// A conversation's warnings from leaf confirmation, oldest first.
    pub fn confirm_warning_rows(
        &self,
        conv: ConversationId,
    ) -> Result<Vec<WarningRow>, StoreError> {
        self.read(|conn| read::warnings(conn, conv))
    }
}

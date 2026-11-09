//! What the group engine keeps between runs besides its groups (task R2):
//! the key checks of 12.7 that could not be made yet, or failed, and the
//! engine's timers that no other state brings back after a restart.

use rusqlite::{OptionalExtension as _, params};

use super::conversations::ConversationId;
use super::{AccountId, StoreError, Tx};
use risala_proto::names::Uid;

/// This part of the schema.
pub const SCHEMA: &str = r#"
-- Key checks of 12.7 that a device could not make yet, or that failed
-- (LR-C2). kind is 'add' (a leaf added by a commit: init_key,
-- encryption_key and binding are its KeyPackage's, to check the binding
-- once the device's record is accepted), 'joined' (a leaf already in the
-- group when this device joined it by Welcome: its device must be
-- current, since the tree no longer holds what its binding covers) or
-- 'committer' (whether the committer's device was removed by record).
-- signature_key is the leaf's when it was found, so that a repair is
-- skipped once the leaf is gone or replaced. first_needed is when the
-- device first needed a record for it: a record still pending 2 hours
-- later fails the check, while a key file that cannot be read never does.
-- state is 'unchecked' (the device sends nothing in the group while an
-- add or joined check is) or 'failed' (a repair is due at repair_at, and
-- nothing is sent until it is queued; or, where the device may not make
-- it, the leaf's messages are hidden). warned once the user was told.
CREATE TABLE key_checks (
    conv           INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    uid            TEXT NOT NULL,
    device_id      BLOB NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('add', 'joined', 'committer')),
    signature_key  BLOB NOT NULL,
    init_key       BLOB,
    encryption_key BLOB,
    binding        BLOB,
    first_needed   INTEGER NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('unchecked', 'failed')),
    repair_at      INTEGER,
    warned         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conv, uid, device_id, kind)
) WITHOUT ROWID;

-- The group engine's timers that no other state brings back after a
-- restart (LR-M4): its RESYNC escalation, the commits it could not
-- process and the 7.8 move fallback, as JSON.
CREATE TABLE engine_timers (
    account INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    timers  TEXT NOT NULL
);
"#;

/// What a key check is of (12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckKind {
    /// A leaf a commit added: its binding, under a current device.
    Add,
    /// A leaf already in the group when this device joined it by Welcome
    /// (12.7, Joining): its device, current. The tree no longer holds the
    /// KeyPackage's init key, which its binding covers.
    Joined,
    /// A commit's committer: whether its device was removed by record.
    Committer,
}

impl CheckKind {
    fn as_str(self) -> &'static str {
        match self {
            CheckKind::Add => "add",
            CheckKind::Joined => "joined",
            CheckKind::Committer => "committer",
        }
    }

    fn parse(s: &str) -> Result<CheckKind, StoreError> {
        match s {
            "add" => Ok(CheckKind::Add),
            "joined" => Ok(CheckKind::Joined),
            "committer" => Ok(CheckKind::Committer),
            other => Err(StoreError::Corrupt(format!("key check kind {other:?}"))),
        }
    }
}

/// A key check's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyCheckRow {
    pub conv: ConversationId,
    pub uid: Uid,
    pub device_id: [u8; 48],
    pub kind: CheckKind,
    pub signature_key: Vec<u8>,
    pub init_key: Option<Vec<u8>>,
    pub encryption_key: Option<Vec<u8>>,
    pub binding: Option<Vec<u8>>,
    pub first_needed: u64,
    pub failed: bool,
    pub repair_at: Option<u64>,
    pub warned: bool,
}

const COLUMNS: &str = "conv, uid, device_id, kind, signature_key, init_key, encryption_key, \
                       binding, first_needed, state, repair_at, warned";

type Raw = (
    i64,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    [Option<Vec<u8>>; 3],
    i64,
    String,
    Option<i64>,
    bool,
);

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        [r.get(5)?, r.get(6)?, r.get(7)?],
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
    ))
}

fn finish(raw: Raw) -> Result<KeyCheckRow, StoreError> {
    let (
        conv,
        uid,
        device,
        kind,
        signature_key,
        [init_key, encryption_key, binding],
        first,
        state,
        repair_at,
        warned,
    ) = raw;
    Ok(KeyCheckRow {
        conv: ConversationId(conv),
        uid: uid
            .parse()
            .map_err(|_| StoreError::Corrupt(format!("uid {uid:?}")))?,
        device_id: device
            .try_into()
            .map_err(|_| StoreError::Corrupt("a device id".into()))?,
        kind: CheckKind::parse(&kind)?,
        signature_key,
        init_key,
        encryption_key,
        binding,
        first_needed: first as u64,
        failed: state == "failed",
        repair_at: repair_at.map(|t| t as u64),
        warned,
    })
}

impl Tx<'_> {
    /// Notes a key check that could not be made yet (12.7). If it is noted
    /// already, its `first_needed` stays: the 2 hours run from the first
    /// time. A new leaf key for the same device starts it again.
    pub(crate) fn note_unchecked(&mut self, row: &KeyCheckRow) -> Result<(), StoreError> {
        self.conn().execute(
            &format!(
                "INSERT INTO key_checks ({COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'unchecked', NULL, 0)
                 ON CONFLICT (conv, uid, device_id, kind) DO UPDATE SET
                    signature_key = excluded.signature_key,
                    init_key = excluded.init_key,
                    encryption_key = excluded.encryption_key,
                    binding = excluded.binding,
                    state = CASE WHEN signature_key = excluded.signature_key
                                 THEN state ELSE 'unchecked' END,
                    repair_at = CASE WHEN signature_key = excluded.signature_key
                                     THEN repair_at ELSE NULL END"
            ),
            params![
                row.conv.0,
                row.uid.as_str(),
                &row.device_id[..],
                row.kind.as_str(),
                row.signature_key,
                row.init_key,
                row.encryption_key,
                row.binding,
                row.first_needed as i64,
            ],
        )?;
        Ok(())
    }

    /// Marks a key check failed, with its repair due at `repair_at` (or
    /// none, where the device may not make it).
    pub(crate) fn fail_check(
        &mut self,
        row: &KeyCheckRow,
        repair_at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.note_unchecked(row)?;
        self.conn().execute(
            "UPDATE key_checks SET state = 'failed', repair_at = ?5
             WHERE conv = ?1 AND uid = ?2 AND device_id = ?3 AND kind = ?4",
            params![
                row.conv.0,
                row.uid.as_str(),
                &row.device_id[..],
                row.kind.as_str(),
                repair_at.map(|t| t as i64),
            ],
        )?;
        Ok(())
    }

    /// Forgets a key check: it passed, or its leaf is gone.
    pub(crate) fn clear_check(&mut self, row: &KeyCheckRow) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM key_checks
             WHERE conv = ?1 AND uid = ?2 AND device_id = ?3 AND kind = ?4",
            params![
                row.conv.0,
                row.uid.as_str(),
                &row.device_id[..],
                row.kind.as_str()
            ],
        )?;
        Ok(())
    }

    /// Notes that the user was told of a key check.
    pub(crate) fn set_check_warned(&mut self, row: &KeyCheckRow) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE key_checks SET warned = 1
             WHERE conv = ?1 AND uid = ?2 AND device_id = ?3 AND kind = ?4",
            params![
                row.conv.0,
                row.uid.as_str(),
                &row.device_id[..],
                row.kind.as_str()
            ],
        )?;
        Ok(())
    }

    /// The key checks of the account's conversations.
    pub(crate) fn key_checks(&self, account: AccountId) -> Result<Vec<KeyCheckRow>, StoreError> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {} FROM key_checks k JOIN conversations c ON c.id = k.conv
             WHERE c.account = ?1 ORDER BY k.conv, k.uid",
            COLUMNS
                .split(", ")
                .map(|c| format!("k.{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
        let rows = stmt
            .query_map([account.0], row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(finish).collect()
    }

    /// The key checks of one conversation.
    pub(crate) fn conversation_checks(
        &self,
        conv: ConversationId,
    ) -> Result<Vec<KeyCheckRow>, StoreError> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLUMNS} FROM key_checks WHERE conv = ?1 ORDER BY uid"
        ))?;
        let rows = stmt
            .query_map([conv.0], row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(finish).collect()
    }

    /// Whether the device sends nothing in the conversation (12.7): a leaf
    /// was added, or was there when it joined, that it could not check
    /// yet, or one failed a check and its removal is still to be queued.
    /// Once queued, the removal commit goes before any message.
    pub(crate) fn sending_held(&self, conv: ConversationId) -> Result<bool, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM key_checks
                 WHERE conv = ?1
                   AND ((kind IN ('add', 'joined') AND state = 'unchecked')
                        OR repair_at IS NOT NULL)
                 LIMIT 1",
                [conv.0],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Whether the leaf with `signature_key` failed a key check that this
    /// device may not repair: what it sends is hidden (12.7, 12.14).
    pub(crate) fn leaf_hidden_by_check(
        &self,
        conv: ConversationId,
        signature_key: &[u8],
    ) -> Result<bool, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM key_checks
                 WHERE conv = ?1 AND signature_key = ?2 AND state = 'failed' LIMIT 1",
                params![conv.0, signature_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// The engine's saved timers, as JSON.
    pub(crate) fn engine_timers(&self, account: AccountId) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT timers FROM engine_timers WHERE account = ?1",
                [account.0],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Saves the engine's timers, as JSON.
    pub(crate) fn set_engine_timers(
        &mut self,
        account: AccountId,
        timers: &str,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO engine_timers (account, timers) VALUES (?1, ?2)
             ON CONFLICT (account) DO UPDATE SET timers = excluded.timers",
            params![account.0, timers],
        )?;
        Ok(())
    }
}

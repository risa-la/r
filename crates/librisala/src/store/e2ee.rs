//! End-to-end encryption in the cache (SPEC 12): groups, history keys,
//! the leaves of each epoch, device keys, and decrypting stored ENC
//! events into the derived tables. See schema version 14.
//!
//! OpenMLS's own state is in the `openmls_*` tables ([`super::mls`]); the
//! tables here are what librisala keeps around it, in the same
//! transactions.

use risala_mls::history::HistoryKey;
use risala_mls::message::{MessageError, sender_key_id};
use risala_proto::auth::{PUBLIC_KEY_LEN, PublicKey};
use risala_proto::names::{Conv, Id, Uid};
use risala_proto::server::EventBody;
use risala_proto::types::{Relation, SendMode};
use rusqlite::{OptionalExtension, params};

use super::events::{ConvRow, Tx, stored_event};
use super::{AccountId, Change, ConvId, StoreError, seq, sql};
use crate::e2ee::content::{Content, Control};

/// Where a group is (schema version 14, `mls_groups.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupState {
    /// INIT was sent and not answered yet (12.5).
    Init,
    /// The device follows the group.
    Active,
    /// A commit failed a check of 12.6: the device no longer follows the
    /// group, sends nothing in it, and does not join it again.
    Rejected,
    /// MLS refused a commit that passed the checks of 12.6: the device may
    /// join again by external commit (12.6).
    Broken,
    /// The account is no longer in the group. Its history keys stay.
    Left,
}

impl GroupState {
    fn as_str(self) -> &'static str {
        match self {
            GroupState::Init => "init",
            GroupState::Active => "active",
            GroupState::Rejected => "rejected",
            GroupState::Broken => "broken",
            GroupState::Left => "left",
        }
    }

    fn parse(s: &str) -> Result<GroupState, StoreError> {
        Ok(match s {
            "init" => GroupState::Init,
            "active" => GroupState::Active,
            "rejected" => GroupState::Rejected,
            "broken" => GroupState::Broken,
            "left" => GroupState::Left,
            _ => return Err(StoreError::Corrupt(format!("bad group state {s:?}"))),
        })
    }
}

/// A conversation's group, as stored (`mls_groups`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupRow {
    /// The conversation.
    pub conv: ConvId,
    /// OpenMLS's group id.
    pub group_id: Vec<u8>,
    /// The epoch the device is in.
    pub epoch: u64,
    /// The seq of the COMMIT event that started it, 0 for epoch 0 or
    /// before INIT's answer.
    pub commit_seq: u64,
    /// Where it is.
    pub state: GroupState,
    /// A commit sent and not answered yet, in base64.
    pub pending: Option<String>,
    /// When the device last committed a fresh leaf, or joined, in Unix
    /// milliseconds (12.6).
    pub refreshed: i64,
}

/// Where a history key came from (12.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// The device derived it in an epoch it was in.
    Own,
    /// Another device of the identity sent it, in the conversation with
    /// itself.
    Device,
    /// It was restored from a backup (12.10).
    Backup,
    /// A member of the room sent it when adding the account (12.9).
    Member,
}

impl KeySource {
    fn as_str(self) -> &'static str {
        match self {
            KeySource::Own => "own",
            KeySource::Device => "device",
            KeySource::Backup => "backup",
            KeySource::Member => "member",
        }
    }

    fn parse(s: &str) -> Result<KeySource, StoreError> {
        Ok(match s {
            "own" => KeySource::Own,
            "device" => KeySource::Device,
            "backup" => KeySource::Backup,
            "member" => KeySource::Member,
            _ => return Err(StoreError::Corrupt(format!("bad key source {s:?}"))),
        })
    }

    /// Which key wins when two differ (12.9): the device's own, then one
    /// from its identity's devices or backup, then the first one.
    fn rank(self) -> u8 {
        match self {
            KeySource::Own => 0,
            KeySource::Device | KeySource::Backup => 1,
            KeySource::Member => 2,
        }
    }
}

/// What storing a history key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyPut {
    /// It is new.
    New,
    /// The same key was stored already.
    Same,
    /// A different key was stored, and this one replaced it, since it
    /// came from a better source (12.9). Warn the user.
    Replaced,
    /// A different key was stored, and stays. Warn the user.
    Kept,
}

/// A stored history key.
#[derive(Debug, Clone)]
pub(crate) struct StoredKey {
    pub epoch: u64,
    pub key: HistoryKey,
    pub source: KeySource,
    pub commit_seq: Option<u64>,
    #[allow(dead_code, reason = "kept for restores and checks")]
    pub backed_up: Option<Vec<u8>>,
}

/// How far decrypting an ENC event got (`events.enc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncState {
    /// Not decrypted yet: the epoch's history key is not here yet.
    Pending,
    /// Decrypted, and its signature verified (12.8).
    Verified,
    /// Decrypted, in an epoch the device was not in, from a sender whose
    /// key it does not know (12.8, step 4).
    Unverified,
    /// It could not be read, and its content must not be shown (12.8).
    Failed(DecryptFailure),
}

/// Why an ENC event could not be read (12.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptFailure {
    /// Its epoch is not the group's at its place (step 1).
    Epoch,
    /// It does not decrypt under the epoch's history key (step 3).
    Decrypt,
    /// No leaf of its sender has its key (step 4).
    Sender,
    /// Its signature does not verify (step 4).
    Signature,
    /// The franking tag does not match (step 5).
    Frank,
    /// Its message id was seen before in the conversation (step 6).
    Replayed,
    /// The content is not lines this device accepts.
    Content,
}

impl DecryptFailure {
    fn as_str(self) -> &'static str {
        match self {
            DecryptFailure::Epoch => "epoch",
            DecryptFailure::Decrypt => "decrypt",
            DecryptFailure::Sender => "sender",
            DecryptFailure::Signature => "signature",
            DecryptFailure::Frank => "frank",
            DecryptFailure::Replayed => "replayed",
            DecryptFailure::Content => "content",
        }
    }

    pub(crate) fn parse(s: Option<&str>) -> DecryptFailure {
        match s {
            Some("epoch") => DecryptFailure::Epoch,
            Some("sender") => DecryptFailure::Sender,
            Some("signature") => DecryptFailure::Signature,
            Some("frank") => DecryptFailure::Frank,
            Some("replayed") => DecryptFailure::Replayed,
            Some("content") => DecryptFailure::Content,
            _ => DecryptFailure::Decrypt,
        }
    }

    fn of(e: &MessageError) -> DecryptFailure {
        match e {
            MessageError::Frank => DecryptFailure::Frank,
            MessageError::WrongSender => DecryptFailure::Sender,
            MessageError::Signature => DecryptFailure::Signature,
            _ => DecryptFailure::Decrypt,
        }
    }
}

impl EncState {
    /// Reads `events.enc` and `events.enc_error`. `None` for a row that is
    /// not an ENC event with a payload.
    pub(crate) fn from_columns(enc: Option<&str>, error: Option<&str>) -> Option<EncState> {
        Some(match enc? {
            "pending" => EncState::Pending,
            "verified" | "control" | "ignored" => EncState::Verified,
            "unverified" => EncState::Unverified,
            _ => EncState::Failed(DecryptFailure::parse(error)),
        })
    }
}

/// What decrypting with the keys at hand led to
/// ([`Tx::decrypt_cascade`]).
#[derive(Debug, Default)]
pub(crate) struct Cascade {
    /// Two different keys arrived for one epoch: the conversation's id and
    /// the epoch (12.9).
    pub conflicts: Vec<(Id, u64)>,
    /// A recovery key another device of the identity sent (12.10).
    pub recovery: Option<risala_mls::RecoveryKey>,
}

/// A KEY or RECOVERY line from a decrypted message, for the caller to act
/// on (12.9, 12.10).
#[derive(Debug, Clone)]
pub(crate) struct Received {
    /// Who sent it.
    pub from: Uid,
    /// The line.
    pub line: Control,
}

/// The SQL condition of a decrypted message: an ENC event whose content
/// may be shown.
pub(crate) const DECRYPTED: &str = "enc IN ('verified', 'unverified')";

fn key_id(key: &PublicKey) -> Vec<u8> {
    sender_key_id(key).to_vec()
}

/// A row of `mls_groups`, as read.
type RawGroup = (i64, Vec<u8>, i64, i64, String, Option<String>, i64);

fn group_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawGroup> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

fn finish_group(raw: RawGroup) -> Result<GroupRow, StoreError> {
    let (conv, group_id, epoch, commit_seq, state, pending, refreshed) = raw;
    Ok(GroupRow {
        conv: ConvId(conv),
        group_id,
        epoch: epoch.max(0) as u64,
        commit_seq: commit_seq.max(0) as u64,
        state: GroupState::parse(&state)?,
        pending,
        refreshed,
    })
}

const GROUP_COLS: &str = "conv, group_id, epoch, commit_seq, state, pending, refreshed";

impl Tx<'_> {
    // -----------------------------------------------------------------------
    // Groups

    /// The group of a conversation, if the account has one.
    pub(crate) fn group(&self, conv: ConvId) -> Result<Option<GroupRow>, StoreError> {
        let raw = self
            .conn()
            .query_row(
                &format!("SELECT {GROUP_COLS} FROM mls_groups WHERE conv = ?1"),
                [conv.0],
                group_row,
            )
            .optional()?;
        raw.map(finish_group).transpose()
    }
    #[expect(
        dead_code,
        reason = "key sharing, backups and reports (12.9, 12.10, 5.8) come next"
    )]
    /// Every group of an account, with its conversation.
    pub(crate) fn groups(
        &self,
        account: AccountId,
    ) -> Result<Vec<(ConvRow, GroupRow)>, StoreError> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn().prepare_cached(
                "SELECT g.conv FROM mls_groups g JOIN convs c ON c.id = g.conv
                 WHERE c.account = ?1 ORDER BY g.conv",
            )?;
            stmt.query_map([account.0], |r| r.get(0))?
                .collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for id in ids {
            if let (Some(row), Some(group)) = (self.conv(ConvId(id))?, self.group(ConvId(id))?) {
                out.push((row, group));
            }
        }
        Ok(out)
    }

    /// Stores a group, replacing the conversation's earlier one.
    pub(crate) fn save_group(&mut self, group: &GroupRow) -> Result<(), StoreError> {
        self.conn().execute(
            &format!(
                "INSERT OR REPLACE INTO mls_groups ({GROUP_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            ),
            params![
                group.conv.0,
                group.group_id,
                sql(group.epoch),
                sql(group.commit_seq),
                group.state.as_str(),
                group.pending,
                group.refreshed,
            ],
        )?;
        self.changed(Change::Conversation { conv: group.conv });
        Ok(())
    }

    /// Forgets a conversation's group, as when its history is discarded.
    pub(crate) fn delete_group(&mut self, conv: ConvId) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM mls_groups WHERE conv = ?1", [conv.0])?;
        self.changed(Change::Conversation { conv });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // History keys

    /// Stores a history key (12.9). Of two different keys for one epoch,
    /// it keeps the device's own, then one from its identity's devices or
    /// backup, then the first one. A commit seq or `send` value it did not
    /// have is filled in either way.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn put_history_key(
        &mut self,
        account: AccountId,
        conv_id: &Id,
        epoch: u64,
        key: &HistoryKey,
        source: KeySource,
        commit_seq: Option<u64>,
        send: Option<SendMode>,
    ) -> Result<KeyPut, StoreError> {
        let send = send.map(|s| match s {
            SendMode::All => "all",
            SendMode::Mods => "mods",
        });
        let old = self.history_key(account, conv_id, epoch)?;
        let put = match &old {
            None => KeyPut::New,
            Some(old) if old.key == *key => KeyPut::Same,
            Some(old) if source.rank() < old.source.rank() => KeyPut::Replaced,
            Some(_) => KeyPut::Kept,
        };
        match put {
            KeyPut::New | KeyPut::Replaced => {
                self.conn().execute(
                    "INSERT OR REPLACE INTO history_keys
                         (account, conv_id, epoch, key, source, commit_seq, backed_up, send)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
                    params![
                        account.0,
                        conv_id.as_str(),
                        sql(epoch),
                        &key.as_bytes()[..],
                        source.as_str(),
                        commit_seq.map(sql),
                        send,
                    ],
                )?;
            }
            KeyPut::Same | KeyPut::Kept => {
                let better = matches!(put, KeyPut::Same)
                    && old
                        .as_ref()
                        .is_some_and(|o| source.rank() < o.source.rank());
                self.conn().execute(
                    "UPDATE history_keys SET commit_seq = COALESCE(commit_seq, ?4),
                         send = COALESCE(send, ?5),
                         source = CASE WHEN ?6 THEN ?7 ELSE source END
                     WHERE account = ?1 AND conv_id = ?2 AND epoch = ?3",
                    params![
                        account.0,
                        conv_id.as_str(),
                        sql(epoch),
                        commit_seq.map(sql),
                        send,
                        better,
                        source.as_str(),
                    ],
                )?;
            }
        }
        Ok(put)
    }

    /// The history key of an epoch, if the account has it.
    pub(crate) fn history_key(
        &self,
        account: AccountId,
        conv_id: &Id,
        epoch: u64,
    ) -> Result<Option<StoredKey>, StoreError> {
        type Raw = (Vec<u8>, String, Option<i64>, Option<Vec<u8>>);
        let raw: Option<Raw> = self
            .conn()
            .query_row(
                "SELECT key, source, commit_seq, backed_up FROM history_keys
                 WHERE account = ?1 AND conv_id = ?2 AND epoch = ?3",
                params![account.0, conv_id.as_str(), sql(epoch)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        raw.map(|(key, source, commit_seq, backed_up)| {
            Ok(StoredKey {
                epoch,
                key: history_key_from(&key)?,
                source: KeySource::parse(&source)?,
                commit_seq: commit_seq.map(|s| s.max(0) as u64),
                backed_up,
            })
        })
        .transpose()
    }
    /// Every history key of a conversation, oldest epoch first.
    pub(crate) fn history_keys(
        &self,
        account: AccountId,
        conv_id: &Id,
    ) -> Result<Vec<StoredKey>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT epoch, key, source, commit_seq, backed_up FROM history_keys
             WHERE account = ?1 AND conv_id = ?2 ORDER BY epoch",
        )?;
        let rows = stmt.query_map(params![account.0, conv_id.as_str()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (epoch, key, source, commit_seq, backed_up) = row?;
            out.push(StoredKey {
                epoch: epoch.max(0) as u64,
                key: history_key_from(&key)?,
                source: KeySource::parse(&source)?,
                commit_seq: commit_seq.map(|s| s.max(0) as u64),
                backed_up,
            });
        }
        Ok(out)
    }
    /// The ids of every conversation the account holds history keys for.
    pub(crate) fn key_conversations(&self, account: AccountId) -> Result<Vec<Id>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT DISTINCT conv_id FROM history_keys WHERE account = ?1 ORDER BY conv_id",
        )?;
        let rows = stmt.query_map([account.0], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(super::parse(&row?, "conversation id")?);
        }
        Ok(out)
    }
    /// Records that a history key was backed up under the backup key with
    /// `key_id` (12.10).
    pub(crate) fn set_backed_up(
        &mut self,
        account: AccountId,
        conv_id: &Id,
        epoch: u64,
        key_id: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE history_keys SET backed_up = ?4
             WHERE account = ?1 AND conv_id = ?2 AND epoch = ?3",
            params![account.0, conv_id.as_str(), sql(epoch), key_id],
        )?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Leaves and device keys

    /// Records the leaves of an epoch the device is in (12.9), and their
    /// keys as keys seen in a group (12.8, step 4).
    pub(crate) fn put_epoch_leaves(
        &mut self,
        account: AccountId,
        conv_id: &Id,
        epoch: u64,
        leaves: &[(Uid, PublicKey)],
    ) -> Result<(), StoreError> {
        for (uid, key) in leaves {
            self.note_device_key(account, uid, key)?;
            self.conn().execute(
                "INSERT OR IGNORE INTO epoch_leaves (account, conv_id, epoch, uid, key_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    account.0,
                    conv_id.as_str(),
                    sql(epoch),
                    uid.as_str(),
                    key_id(key)
                ],
            )?;
        }
        Ok(())
    }

    /// Remembers a device key of `uid`, seen in a group or a key file.
    pub(crate) fn note_device_key(
        &mut self,
        account: AccountId,
        uid: &Uid,
        key: &PublicKey,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT OR IGNORE INTO device_keys (account, key_id, uid, key) VALUES (?1, ?2, ?3, ?4)",
            params![account.0, key_id(key), uid.as_str(), &key.as_bytes()[..]],
        )?;
        Ok(())
    }

    /// Records what `uid`'s key file listed when fetched now: its keys and
    /// labels, or `None` if the fetch failed (12.12). A key file that is
    /// gone lists no keys.
    pub(crate) fn key_file_fetched(
        &mut self,
        account: AccountId,
        uid: &Uid,
        keys: Option<&[(PublicKey, Option<String>)]>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let fetched: Option<i64> = keys.map(|_| now_ms);
        self.conn().execute(
            "INSERT INTO key_files (account, uid, fetched, tried) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (account, uid) DO UPDATE SET tried = excluded.tried,
                 fetched = COALESCE(excluded.fetched, key_files.fetched)",
            params![account.0, uid.as_str(), fetched, now_ms],
        )?;
        let Some(keys) = keys else {
            return Ok(());
        };
        self.conn().execute(
            "UPDATE device_keys SET listed = 0 WHERE account = ?1 AND uid = ?2",
            params![account.0, uid.as_str()],
        )?;
        for (key, label) in keys {
            self.note_device_key(account, uid, key)?;
            self.conn().execute(
                "UPDATE device_keys SET listed = 1, label = ?3 WHERE account = ?1 AND key_id = ?2",
                params![account.0, key_id(key), label],
            )?;
        }
        Ok(())
    }

    /// Whether `uid`'s key file listed `key` the last time it was fetched
    /// after the device first saw the key (12.6, 12.12): `None` if no
    /// fetch since then tells.
    pub(crate) fn key_listed(
        &self,
        account: AccountId,
        uid: &Uid,
        key: &PublicKey,
    ) -> Result<Option<bool>, StoreError> {
        let listed: Option<Option<bool>> = self
            .conn()
            .query_row(
                "SELECT listed FROM device_keys WHERE account = ?1 AND key_id = ?2 AND uid = ?3",
                params![account.0, key_id(key), uid.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(listed.flatten())
    }

    /// Whether the device knows a key of `uid` that no key file fetch has
    /// told about since the device first saw it (12.12).
    pub(crate) fn has_unknown_keys(
        &self,
        account: AccountId,
        uid: &Uid,
    ) -> Result<bool, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM device_keys WHERE account = ?1 AND uid = ?2 AND listed IS NULL
                 LIMIT 1",
                params![account.0, uid.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// When `uid`'s key file was last fetched and last tried, in Unix
    /// milliseconds.
    pub(crate) fn key_file_times(
        &self,
        account: AccountId,
        uid: &Uid,
    ) -> Result<(Option<i64>, Option<i64>), StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT fetched, tried FROM key_files WHERE account = ?1 AND uid = ?2",
                params![account.0, uid.as_str()],
                |r| Ok((r.get(0)?, Some(r.get(1)?))),
            )
            .optional()?
            .unwrap_or((None, None)))
    }

    /// The keys of `uid` the account has seen, whose hash is `id`.
    fn known_key(
        &self,
        account: AccountId,
        uid: &str,
        id: &[u8],
    ) -> Result<Option<PublicKey>, StoreError> {
        let raw: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT key FROM device_keys WHERE account = ?1 AND key_id = ?2 AND uid = ?3",
                params![account.0, id, uid],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|k| public_key_from(&k)).transpose()
    }

    // -----------------------------------------------------------------------
    // Decrypting

    /// Decrypts the stored ENC events of `row` whose epoch's history key
    /// the account now has (12.8), and applies them to the derived tables
    /// as MSG events are. KEY and RECOVERY lines are returned for the
    /// caller; they are accepted only where 12.9 and 12.10 allow, which
    /// the caller checks.
    ///
    /// `me` is the account's uid. Returns the lines received.
    pub(crate) fn decrypt_pending(
        &mut self,
        row: &ConvRow,
        me: &Uid,
    ) -> Result<Vec<Received>, StoreError> {
        let Some(conv_id) = row.conv_id.clone() else {
            return Ok(Vec::new());
        };
        let Some(group) = self.group(row.id)? else {
            return Ok(Vec::new());
        };
        let pending: Vec<(i64, String, i64)> = {
            let mut stmt = self.conn().prepare_cached(
                "SELECT e.seq, e.line, e.mls_epoch FROM events e
                 JOIN history_keys k ON k.account = ?2 AND k.conv_id = ?3 AND k.epoch = e.mls_epoch
                 WHERE e.conv = ?1 AND e.enc = 'pending' ORDER BY e.seq",
            )?;
            stmt.query_map(params![row.id.0, row.account.0, conv_id.as_str()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<Result<_, _>>()?
        };
        let mut received = Vec::new();
        for (n, line, epoch) in pending {
            let n = n.max(0) as u64;
            let epoch = epoch.max(0) as u64;
            let event = stored_event(&line)?;
            let (Some(meta), EventBody::Enc(enc)) = (&event.meta, &event.body) else {
                continue;
            };
            let (Some(payload), Some(frank)) = (&enc.payload, &enc.frank) else {
                continue;
            };
            let Some(key) = self.history_key(row.account, &conv_id, epoch)? else {
                continue;
            };
            let outcome = self.open_one(
                row,
                &conv_id,
                &group.group_id,
                (n, epoch),
                &key,
                &meta.from,
                (payload, frank),
            )?;
            match outcome {
                Opened::Failed(why) => self.set_failed(row.id, n, why)?,
                Opened::Message {
                    message,
                    verified,
                    content,
                } => match content {
                    Content::Text(text) => {
                        self.apply_text(row, n, &meta.from, &message, verified, text, epoch)?;
                    }
                    Content::Control(lines) => {
                        self.conn().execute(
                            "UPDATE events SET enc = 'control', message_id = ?3, content = ?4,
                                 frank_key = ?5
                             WHERE conv = ?1 AND seq = ?2",
                            params![
                                row.id.0,
                                sql(n),
                                &message.message_id[..],
                                &message.content,
                                &message.frank_key.as_bytes()[..],
                            ],
                        )?;
                        self.changed(Change::Updated {
                            conv: row.id,
                            seq: seq(sql(n))?,
                        });
                        // Lines from another device of the identity, or in
                        // a room, from a member; the caller decides.
                        if verified || meta.from != *me {
                            received.extend(lines.into_iter().map(|line| Received {
                                from: meta.from.clone(),
                                line,
                            }));
                        }
                    }
                },
            }
        }
        Ok(received)
    }

    /// Decrypts what it can in the conversations `start`, then in every
    /// conversation that a KEY line among them gave a key for, and so on
    /// (12.8, 12.9). KEY lines are taken only from the identity's own
    /// devices in the conversation with itself, or in a room for that
    /// room's own id; RECOVERY lines only in the conversation with itself
    /// (12.10).
    pub(crate) fn decrypt_cascade(
        &mut self,
        account: AccountId,
        me: &Uid,
        start: Vec<Conv>,
    ) -> Result<Cascade, StoreError> {
        let mut out = Cascade::default();
        let mut todo = start;
        let mut seen = std::collections::HashSet::new();
        while let Some(conv) = todo.pop() {
            if !seen.insert(conv.clone()) {
                continue;
            }
            let Some(row) = self.conv_by_name(account, &conv)? else {
                continue;
            };
            for r in self.decrypt_pending(&row, me)? {
                match r.line {
                    Control::Key { id, epoch, key } => {
                        let source = match &row.name {
                            Conv::Uid(u) if u == me && r.from == *me => KeySource::Device,
                            Conv::Room(_) if row.conv_id.as_ref() == Some(&id) => KeySource::Member,
                            _ => continue,
                        };
                        let put =
                            self.put_history_key(account, &id, epoch, &key, source, None, None)?;
                        if matches!(put, KeyPut::New | KeyPut::Replaced)
                            && let Some(other) = self.conv_by_id(account, &id)?
                        {
                            seen.remove(&other.name);
                            todo.push(other.name);
                        }
                        if matches!(put, KeyPut::Replaced | KeyPut::Kept) {
                            out.conflicts.push((id, epoch));
                        }
                    }
                    Control::Recovery(key) => {
                        if matches!(&row.name, Conv::Uid(u) if u == me) && r.from == *me {
                            out.recovery = Some(key);
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Steps 1 to 6 of decryption (12.8) for one event.
    #[allow(clippy::too_many_arguments)]
    fn open_one(
        &self,
        row: &ConvRow,
        conv_id: &Id,
        group_id: &[u8],
        (n, epoch): (u64, u64),
        key: &StoredKey,
        from: &Uid,
        (payload, frank): (&risala_proto::mls::Ciphertext, &risala_proto::mls::Frank),
    ) -> Result<Opened, StoreError> {
        // Step 1: the epoch at the event's place.
        if !self.epoch_fits(row, conv_id, epoch, n, key)? {
            return Ok(Opened::Failed(DecryptFailure::Epoch));
        }
        // Steps 3 and 5.
        let unverified =
            match risala_mls::message::decrypt(&key.key, group_id, epoch, payload, frank) {
                Ok(m) => m,
                Err(e) => return Ok(Opened::Failed(DecryptFailure::of(&e))),
            };
        // Step 4: the sender's key.
        let in_epoch: bool = self
            .conn()
            .query_row(
                "SELECT 1 FROM epoch_leaves WHERE account = ?1 AND conv_id = ?2 AND epoch = ?3
                 LIMIT 1",
                params![row.account.0, conv_id.as_str(), sql(epoch)],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let id = unverified.sender_key_id().to_vec();
        let sender =
            if in_epoch {
                let leaf: Option<i64> = self
                .conn()
                .query_row(
                    "SELECT 1 FROM epoch_leaves WHERE account = ?1 AND conv_id = ?2 AND epoch = ?3
                         AND uid = ?4 AND key_id = ?5",
                    params![row.account.0, conv_id.as_str(), sql(epoch), from.as_str(), id],
                    |r| r.get(0),
                )
                .optional()?;
                if leaf.is_none() {
                    return Ok(Opened::Failed(DecryptFailure::Sender));
                }
                match self.known_key(row.account, from.as_str(), &id)? {
                    Some(k) => Some(k),
                    None => return Ok(Opened::Failed(DecryptFailure::Sender)),
                }
            } else {
                self.known_key(row.account, from.as_str(), &id)?
            };
        let message = match sender {
            Some(k) => match unverified.verify(&k) {
                Ok(m) => m,
                Err(e) => return Ok(Opened::Failed(DecryptFailure::of(&e))),
            },
            // Not in the group then, and the key is not known: it may be
            // shown as unverified (12.8).
            None if key.source != KeySource::Own => unverified.into_unverified(),
            None => return Ok(Opened::Failed(DecryptFailure::Sender)),
        };
        // Step 6: not seen before in the conversation.
        let seen: Option<i64> = self
            .conn()
            .query_row(
                "SELECT seq FROM events WHERE conv = ?1 AND message_id = ?2 AND seq != ?3",
                params![row.id.0, &message.message_id[..], sql(n)],
                |r| r.get(0),
            )
            .optional()?;
        if seen.is_some() {
            return Ok(Opened::Failed(DecryptFailure::Replayed));
        }
        let content = match Content::parse(&message.content) {
            Ok(c) => c,
            Err(_) => return Ok(Opened::Failed(DecryptFailure::Content)),
        };
        Ok(Opened::Message {
            verified: message.sender.is_some(),
            message: Box::new(message),
            content,
        })
    }

    /// Step 1 of decryption (12.8): whether `epoch` is the group's epoch at
    /// seq `n`. The bounds are the seqs of the COMMIT events that started
    /// `epoch` and the next one, from the key or from stored COMMIT events.
    /// A device that knows neither, as after a restore, skips the check.
    fn epoch_fits(
        &self,
        row: &ConvRow,
        conv_id: &Id,
        epoch: u64,
        n: u64,
        key: &StoredKey,
    ) -> Result<bool, StoreError> {
        let start = match key.commit_seq {
            Some(s) => Some(s),
            None if epoch == 0 => Some(0),
            None => self.commit_seq_of(row.id, epoch)?,
        };
        let end = match self.history_key(row.account, conv_id, epoch + 1)? {
            Some(StoredKey {
                commit_seq: Some(s),
                ..
            }) => Some(s),
            _ => self.commit_seq_of(row.id, epoch + 1)?,
        };
        Ok(start.is_none_or(|s| s < n) && end.is_none_or(|e| n < e))
    }

    /// The seq of the stored COMMIT event that started `epoch`.
    fn commit_seq_of(&self, conv: ConvId, epoch: u64) -> Result<Option<u64>, StoreError> {
        let n: Option<i64> = self
            .conn()
            .query_row(
                "SELECT MIN(seq) FROM events WHERE conv = ?1 AND verb = 'COMMIT' AND mls_epoch = ?2",
                params![conv.0, sql(epoch)],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        Ok(n.map(|n| n.max(0) as u64))
    }

    fn set_failed(&mut self, conv: ConvId, n: u64, why: DecryptFailure) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE events SET enc = 'failed', enc_error = ?3 WHERE conv = ?1 AND seq = ?2",
            params![conv.0, sql(n), why.as_str()],
        )?;
        self.changed(Change::Updated {
            conv,
            seq: seq(sql(n))?,
        });
        Ok(())
    }

    /// Fills in a decrypted TEXT line as a MSG event's columns, and updates
    /// the derived tables (12.8, 12.11).
    #[allow(clippy::too_many_arguments)]
    fn apply_text(
        &mut self,
        row: &ConvRow,
        n: u64,
        from: &Uid,
        message: &risala_mls::Message,
        verified: bool,
        text: crate::e2ee::content::Text,
        epoch: u64,
    ) -> Result<(), StoreError> {
        let relation = text.target.map(|t| t.relation);
        // 12.11: in an announcement room, a message from anyone but an
        // owner or a moderator that is not a reaction is ignored.
        let ignored = !matches!(relation, Some(Relation::React(_)))
            && row.name.is_room()
            && self.mods_only(row, epoch)?
            && !self.is_owner_or_mod(row.id, from)?;
        let state = if ignored {
            "ignored"
        } else if verified {
            "verified"
        } else {
            "unverified"
        };
        self.conn().execute(
            "UPDATE events SET enc = ?3, message_id = ?4, content = ?5, frank_key = ?6,
                 text = ?7, rel = ?8, target = ?9, target_mid = ?10
             WHERE conv = ?1 AND seq = ?2",
            params![
                row.id.0,
                sql(n),
                state,
                &message.message_id[..],
                &message.content,
                &message.frank_key.as_bytes()[..],
                text.text,
                relation.map(Relation::key),
                relation.map(|r| sql(r.seq().get())),
                text.target.map(|t| t.message_id.to_vec()),
            ],
        )?;
        let conv = row.id;
        if ignored {
            self.changed(Change::Updated {
                conv,
                seq: seq(sql(n))?,
            });
            return Ok(());
        }
        match relation {
            None | Some(Relation::Reply(_)) => {
                // Edits and reactions decrypted before it now count.
                self.refresh_message(conv, n)?;
                self.refresh_reactions(conv, n)?;
                self.changed(Change::Updated {
                    conv,
                    seq: seq(sql(n))?,
                });
            }
            Some(Relation::Edit(t) | Relation::React(t)) => {
                // It was shown as an item until now.
                self.changed(Change::Updated {
                    conv,
                    seq: seq(sql(n))?,
                });
                // 12.11: edits and reactions of a deleted message are
                // hidden.
                if self.is_deleted(conv, t.get())? || self.delete_event_for(conv, t.get())? {
                    self.mark_deleted(conv, n)?;
                } else if matches!(relation, Some(Relation::Edit(_))) {
                    self.refresh_message(conv, t.get())?;
                    self.touch(conv, t.get())?;
                } else {
                    self.refresh_reactions(conv, t.get())?;
                    self.touch(conv, t.get())?;
                }
            }
        }
        Ok(())
    }

    /// Whether the room's `send` was `mods` at `epoch`: from the group at
    /// that epoch if the device was in it, and otherwise from the room's
    /// settings (12.11).
    fn mods_only(&self, row: &ConvRow, epoch: u64) -> Result<bool, StoreError> {
        let Some(conv_id) = &row.conv_id else {
            return Ok(false);
        };
        let send: Option<Option<String>> = self
            .conn()
            .query_row(
                "SELECT send FROM history_keys WHERE account = ?1 AND conv_id = ?2 AND epoch = ?3",
                params![row.account.0, conv_id.as_str(), sql(epoch)],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(Some(send)) = send {
            return Ok(send == "mods");
        }
        let value: Option<String> = self
            .conn()
            .query_row(
                "SELECT value FROM room_settings WHERE conv = ?1 AND key = 'send'",
                [row.id.0],
                |r| r.get(0),
            )
            .optional()?;
        Ok(value.as_deref() == Some("mods"))
    }

    fn is_owner_or_mod(&self, conv: ConvId, uid: &Uid) -> Result<bool, StoreError> {
        let role: Option<Option<String>> = self
            .conn()
            .query_row(
                "SELECT role FROM room_members WHERE conv = ?1 AND uid = ?2",
                params![conv.0, uid.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(matches!(role.flatten().as_deref(), Some("owner" | "mod")))
    }

    /// The account's own history keys for the conversation with `conv_id`
    /// and the rows of its stored events, for whichever row has it.
    pub(crate) fn conv_by_id(
        &self,
        account: AccountId,
        conv_id: &Id,
    ) -> Result<Option<ConvRow>, StoreError> {
        let id: Option<i64> = self
            .conn()
            .query_row(
                "SELECT id FROM convs WHERE account = ?1 AND conv_id = ?2",
                params![account.0, conv_id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        match id {
            Some(id) => self.conv(ConvId(id)),
            None => Ok(None),
        }
    }
    #[expect(
        dead_code,
        reason = "key sharing, backups and reports (12.9, 12.10, 5.8) come next"
    )]
    /// The decrypted content and franking key of ENC event `n`, for
    /// REPORTENC (5.8).
    pub(crate) fn franking(&self, conv: ConvId, n: u64) -> Result<Option<Franking>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                &format!(
                    "SELECT content, frank_key FROM events WHERE conv = ?1 AND seq = ?2
                         AND {DECRYPTED} AND deleted = 0"
                ),
                params![conv.0, sql(n)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// The `message_id` of decrypted message `n`, to refer to it (12.8).
    pub(crate) fn message_id_of(
        &self,
        conv: ConvId,
        n: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                &format!(
                    "SELECT message_id FROM events WHERE conv = ?1 AND seq = ?2 AND {DECRYPTED}"
                ),
                params![conv.0, sql(n)],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Whether the conversation is one this account keeps encrypted: a
    /// direct conversation, or a room it holds a group for (12.3).
    pub(crate) fn is_encrypted(&self, row: &ConvRow) -> Result<bool, StoreError> {
        Ok(matches!(row.name, Conv::Uid(_)) || self.group(row.id)?.is_some())
    }
}

/// A decrypted message's content and franking key, for REPORTENC (5.8).
pub(crate) type Franking = (Vec<u8>, Vec<u8>);

/// What decrypting one event gave.
enum Opened {
    Failed(DecryptFailure),
    Message {
        message: Box<risala_mls::Message>,
        verified: bool,
        content: Content,
    },
}

fn history_key_from(bytes: &[u8]) -> Result<HistoryKey, StoreError> {
    let bytes: [u8; 48] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("a history key is not 48 bytes".into()))?;
    Ok(HistoryKey::from_bytes(bytes))
}

fn public_key_from(bytes: &[u8]) -> Result<PublicKey, StoreError> {
    let bytes: &[u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("a device key is not 1312 bytes".into()))?;
    Ok(PublicKey::from_bytes(bytes))
}

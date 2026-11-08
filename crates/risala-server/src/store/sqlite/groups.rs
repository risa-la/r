//! [`GroupStore`] on SQLite.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use risala_proto::auth::PublicKey;
use risala_proto::names::Uid;

use super::e2ee::{add_welcomes_in, prune_welcome_commits};
use super::{SqliteStore, append_in, conv_exists, corrupt, parse, seq, sql_epoch, sql_seq};
use crate::store::{
    Appended, CommitStored, ConvKey, GroupCommit, GroupInit, GroupLeaf, GroupMeta, GroupParts,
    GroupRecord, GroupStore, NewEvent, Result, StoreError,
};

fn epoch(n: i64) -> Result<u64> {
    u64::try_from(n).map_err(|_| corrupt("epoch", n))
}

fn meta(epoch_n: i64, seq_n: i64) -> Result<GroupMeta> {
    Ok(GroupMeta {
        epoch: epoch(epoch_n)?,
        seq: if seq_n == 0 { None } else { Some(seq(seq_n)?) },
    })
}

/// Where the group of `conv` is, if it has one.
pub(super) fn group_meta(conn: &Connection, conv: ConvKey) -> Result<Option<GroupMeta>> {
    conn.prepare_cached("SELECT epoch, seq FROM groups WHERE conv = ?")?
        .query_row([conv.0], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?
        .map(|(e, s)| meta(e, s))
        .transpose()
}

/// Replaces the leaves of the group of `conv`.
fn write_leaves(tx: &Transaction<'_>, conv: ConvKey, leaves: &[GroupLeaf]) -> Result<()> {
    tx.execute("DELETE FROM group_leaves WHERE conv = ?", [conv.0])?;
    let mut insert = tx.prepare_cached(
        "INSERT INTO group_leaves (conv, leaf, uid, device_key) VALUES (?, ?, ?, ?)",
    )?;
    for leaf in leaves {
        insert.execute(params![
            conv.0,
            leaf.index,
            leaf.uid.as_str(),
            leaf.key.to_string()
        ])?;
    }
    Ok(())
}

/// Appends `events` in order, returning their seqs.
fn append_all(
    tx: &Transaction<'_>,
    conv: ConvKey,
    events: &[NewEvent],
) -> Result<Vec<risala_proto::names::Seq>> {
    events
        .iter()
        .map(|event| match append_in(tx, conv, event)? {
            Appended::New(seq) => Ok(seq),
            // Only MSG and ENC carry cids.
            Appended::Duplicate(seq) => Err(corrupt("group event with a cid", seq)),
        })
        .collect()
}

impl GroupStore for SqliteStore {
    fn group(&self, conv: ConvKey) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        type Row = (
            Vec<u8>,
            i64,
            i64,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        );
        let row: Option<Row> = conn
            .prepare_cached(
                "SELECT g.group_id, g.epoch, g.seq, g.group_info, g.tree, g.context, \
                 g.interim_hash, g.confirmation_tag FROM groups g \
                 JOIN conversations c ON c.conv = g.conv \
                 WHERE g.conv = ? AND c.dropping = 0",
            )?
            .query_row([conv.0], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .optional()?;
        let Some((group_id, e, s, group_info, tree, context, interim_hash, confirmation_tag)) = row
        else {
            return Ok(None);
        };
        Ok(Some(GroupRecord {
            group_id,
            meta: meta(e, s)?,
            group_info: parse("GroupInfo", &group_info)?,
            parts: GroupParts {
                tree,
                context,
                interim_hash,
                confirmation_tag,
            },
        }))
    }

    fn init_group(
        &self,
        conv: ConvKey,
        group: &GroupRecord,
        leaves: &[GroupLeaf],
        events: &[NewEvent],
        end_invites: bool,
    ) -> Result<GroupInit> {
        self.write(|tx| {
            conv_exists(tx, conv)?;
            if group_meta(tx, conv)?.is_some() {
                return Ok(GroupInit::Exists);
            }
            let fresh = tx.execute(
                "INSERT OR IGNORE INTO group_ids (group_id) VALUES (?)",
                [&group.group_id],
            )?;
            if fresh == 0 {
                return Ok(GroupInit::IdTaken);
            }
            let p = &group.parts;
            tx.execute(
                "INSERT INTO groups (conv, group_id, epoch, seq, group_info, tree, context, \
                 interim_hash, confirmation_tag) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?)",
                params![
                    conv.0,
                    group.group_id,
                    sql_epoch(group.meta.epoch),
                    group.group_info.as_str(),
                    p.tree,
                    p.context,
                    p.interim_hash,
                    p.confirmation_tag
                ],
            )?;
            write_leaves(tx, conv, leaves)?;
            if end_invites {
                tx.execute("DELETE FROM invites WHERE conv = ?", [conv.0])?;
            }
            Ok(GroupInit::Done(append_all(tx, conv, events)?))
        })
    }

    fn commit_group(&self, conv: ConvKey, commit: &GroupCommit) -> Result<Option<CommitStored>> {
        self.write(|tx| {
            conv_exists(tx, conv)?;
            match group_meta(tx, conv)? {
                Some(m) if m.epoch == commit.from_epoch => {}
                Some(_) => return Ok(None),
                None => return Err(StoreError::NoConversation),
            }
            let commit_seq = match append_in(tx, conv, &commit.event)? {
                Appended::New(seq) => seq,
                Appended::Duplicate(seq) => return Err(corrupt("COMMIT with a cid", seq)),
            };
            let mut seqs = vec![commit_seq];
            seqs.extend(append_all(tx, conv, &commit.then)?);
            let g = &commit.group;
            let p = &g.parts;
            tx.execute(
                "UPDATE groups SET epoch = ?, seq = ?, group_info = ?, tree = ?, context = ?, \
                 interim_hash = ?, confirmation_tag = ? WHERE conv = ?",
                params![
                    sql_epoch(g.meta.epoch),
                    sql_seq(commit_seq),
                    g.group_info.as_str(),
                    p.tree,
                    p.context,
                    p.interim_hash,
                    p.confirmation_tag,
                    conv.0
                ],
            )?;
            write_leaves(tx, conv, &commit.leaves)?;
            // A removed device's pending Welcomes of this conversation go
            // (12.7).
            for (uid, key) in &commit.removed {
                tx.execute(
                    "DELETE FROM pending_welcomes WHERE uid = ? AND device_key = ? AND \
                     commit_n IN (SELECT n FROM welcome_commits WHERE conv = ?)",
                    params![uid.as_str(), key.to_string(), conv.0],
                )?;
            }
            prune_welcome_commits(tx)?;
            let welcome_ids = match &commit.welcome {
                Some(w) => add_welcomes_in(tx, conv, commit_seq, &w.welcome, &w.tree, &w.devices)?,
                None => Vec::new(),
            };
            Ok(Some(CommitStored { seqs, welcome_ids }))
        })
    }

    fn has_leaf(&self, conv: ConvKey, uid: &Uid, key: &PublicKey) -> Result<bool> {
        Ok(self
            .conn()
            .prepare_cached(
                "SELECT 1 FROM group_leaves WHERE conv = ? AND uid = ? AND device_key = ?",
            )?
            .query_row(params![conv.0, uid.as_str(), key.to_string()], |_| Ok(()))
            .optional()?
            .is_some())
    }

    fn leaf_uids(&self, conv: ConvKey) -> Result<Vec<Uid>> {
        self.conn()
            .prepare_cached("SELECT DISTINCT uid FROM group_leaves WHERE conv = ? ORDER BY uid")?
            .query_map([conv.0], |row| row.get::<_, String>(0))?
            .map(|uid| parse("leaf uid", &uid?))
            .collect()
    }

    fn has_removed_leaf(&self, conv: ConvKey) -> Result<bool> {
        Ok(self
            .conn()
            .prepare_cached(
                "SELECT 1 FROM group_leaves l JOIN removed_keys r \
                 ON r.uid = l.uid AND r.device_key = l.device_key WHERE l.conv = ? LIMIT 1",
            )?
            .query_row([conv.0], |_| Ok(()))
            .optional()?
            .is_some())
    }
}

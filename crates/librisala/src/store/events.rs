//! Writing conversations and events, and keeping the derived tables in step
//! with them, inside one transaction.

use std::collections::HashSet;

use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::server::{Event, EventBody, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::Relation;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{AccountId, Change, ConvId, StoreError, opt_id, parse, seq, sql};
use crate::addr::ServerAddr;

/// A conversation as stored (the `convs` table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConvRow {
    pub id: ConvId,
    pub account: AccountId,
    pub name: Conv,
    /// The id it was last known by (5.1), `None` if unknown.
    pub conv_id: Option<Id>,
    /// Bumped each time the history is discarded.
    pub epoch: i64,
    /// Every event the server keeps up to here is stored (7.1).
    pub sync_point: u64,
    /// The newest head reported.
    pub head: u64,
    /// The read marker (7.4), 0 for none.
    pub read: u64,
    /// Whether the account is in the conversation, as far as we know.
    pub joined: bool,
}

const CONV_COLS: &str = "id, account, name, conv_id, epoch, sync_point, head, read, joined";

fn conv_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(ConvRowRaw, String, Option<String>)> {
    Ok((
        ConvRowRaw {
            id: row.get(0)?,
            account: row.get(1)?,
            epoch: row.get(4)?,
            sync_point: row.get(5)?,
            head: row.get(6)?,
            read: row.get(7)?,
            joined: row.get(8)?,
        },
        row.get(2)?,
        row.get(3)?,
    ))
}

struct ConvRowRaw {
    id: i64,
    account: i64,
    epoch: i64,
    sync_point: i64,
    head: i64,
    read: i64,
    joined: bool,
}

fn finish_conv(raw: (ConvRowRaw, String, Option<String>)) -> Result<ConvRow, StoreError> {
    let (r, name, conv_id) = raw;
    Ok(ConvRow {
        id: ConvId(r.id),
        account: AccountId(r.account),
        name: parse(&name, "conversation")?,
        conv_id: opt_id(conv_id)?,
        epoch: r.epoch,
        sync_point: r.sync_point.max(0) as u64,
        head: r.head.max(0) as u64,
        read: r.read.max(0) as u64,
        joined: r.joined,
    })
}

/// One write transaction. See [`Store::write`](super::Store::write).
pub(crate) struct Tx<'a> {
    tx: Transaction<'a>,
    changes: Vec<Change>,
    /// The uid the connection signed in as: the events it sent are the
    /// account's own.
    me: Option<Uid>,
    /// The time now, for a conversation's activity; the system clock if
    /// not set.
    now: Option<Timestamp>,
}

impl<'a> Tx<'a> {
    pub(super) fn new(tx: Transaction<'a>) -> Tx<'a> {
        Tx {
            tx,
            changes: Vec::new(),
            me: None,
            now: None,
        }
    }

    /// Sets the uid the connection signed in as. Events stored from now on
    /// are marked as the account's own if that uid sent them. Without it,
    /// the account's uid decides. A guest that signed in under a fallback
    /// name, such as `~sam2` for the account `~sam`, needs this (4.2):
    /// then `~sam` is someone else.
    pub(crate) fn signed_in_as(&mut self, me: &Uid) {
        self.me = Some(me.clone());
    }

    /// Sets the time now, from the caller's clock: a conversation added in
    /// this transaction counts as active from then. Without it, the system
    /// clock decides.
    pub(crate) fn at(&mut self, now: Timestamp) {
        self.now = Some(now);
    }

    /// The time now, in Unix milliseconds.
    fn now_ms(&self) -> i64 {
        sql(self.now.unwrap_or_else(Timestamp::now).unix_millis())
    }

    /// Moves a conversation's activity forward to `ms`, for the chat list.
    /// It never moves back.
    pub(super) fn bump_activity(&self, conv: ConvId, ms: i64) -> Result<(), StoreError> {
        self.tx.execute(
            "UPDATE convs SET activity = ?2 WHERE id = ?1 AND activity < ?2",
            params![conv.0, ms],
        )?;
        Ok(())
    }

    /// Commits, and returns the changes made, each once, in order.
    pub(super) fn finish(self) -> Result<Vec<Change>, StoreError> {
        let Tx { tx, changes, .. } = self;
        tx.commit()?;
        let mut seen = HashSet::new();
        Ok(changes
            .into_iter()
            .filter(|c| seen.insert(c.clone()))
            .collect())
    }

    /// The connection, for plain statements.
    pub(crate) fn conn(&self) -> &Connection {
        &self.tx
    }

    /// Records a change for the UI.
    pub(crate) fn changed(&mut self, change: Change) {
        self.changes.push(change);
    }

    /// The row id of a server, created if needed.
    pub(crate) fn server_id(&self, addr: &ServerAddr) -> Result<i64, StoreError> {
        let addr = addr.to_string();
        self.tx.execute(
            "INSERT INTO servers (addr) VALUES (?1) ON CONFLICT (addr) DO NOTHING",
            [&addr],
        )?;
        Ok(self
            .tx
            .query_row("SELECT id FROM servers WHERE addr = ?1", [&addr], |row| {
                row.get(0)
            })?)
    }

    // -----------------------------------------------------------------------
    // Conversations

    /// A conversation by row id.
    pub(crate) fn conv(&self, id: ConvId) -> Result<Option<ConvRow>, StoreError> {
        let raw = self
            .tx
            .query_row(
                &format!("SELECT {CONV_COLS} FROM convs WHERE id = ?1"),
                [id.0],
                conv_row,
            )
            .optional()?;
        raw.map(finish_conv).transpose()
    }

    /// A conversation by name.
    pub(crate) fn conv_by_name(
        &self,
        account: AccountId,
        name: &Conv,
    ) -> Result<Option<ConvRow>, StoreError> {
        let raw = self
            .tx
            .query_row(
                &format!("SELECT {CONV_COLS} FROM convs WHERE account = ?1 AND name = ?2"),
                params![account.0, name.as_str()],
                conv_row,
            )
            .optional()?;
        raw.map(finish_conv).transpose()
    }

    /// A conversation by name, created (with no id) if it does not exist.
    pub(crate) fn conv_or_create(
        &mut self,
        account: AccountId,
        name: &Conv,
    ) -> Result<ConvRow, StoreError> {
        if let Some(row) = self.conv_by_name(account, name)? {
            return Ok(row);
        }
        // It is active from when it entered the cache, or from its newest
        // message queued before then, as for a direct conversation not
        // started yet.
        self.tx.execute(
            "INSERT INTO convs (account, name, activity) VALUES (?1, ?2, MAX(?3,
                 COALESCE((SELECT MAX(created) FROM outbox
                           WHERE account = ?1 AND conv = ?2 AND verb = 'MSG'
                               AND (rel IS NULL OR rel = 'reply')), 0)))",
            params![account.0, name.as_str(), self.now_ms()],
        )?;
        let id = ConvId(self.tx.last_insert_rowid());
        self.changed(Change::Conversation { conv: id });
        self.conv(id)?
            .ok_or(StoreError::NotFound("conversation just created"))
    }

    /// Every conversation of an account.
    pub(crate) fn convs(&self, account: AccountId) -> Result<Vec<ConvRow>, StoreError> {
        let mut stmt = self.tx.prepare_cached(&format!(
            "SELECT {CONV_COLS} FROM convs WHERE account = ?1 ORDER BY id"
        ))?;
        let rows = stmt.query_map([account.0], conv_row)?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(finish_conv(raw?)?);
        }
        Ok(out)
    }

    fn save_conv(&mut self, row: &ConvRow) -> Result<(), StoreError> {
        self.tx.execute(
            "UPDATE convs SET conv_id = ?2, epoch = ?3, sync_point = ?4, head = ?5, read = ?6,
                 joined = ?7
             WHERE id = ?1",
            params![
                row.id.0,
                row.conv_id.as_ref().map(Id::as_str),
                row.epoch,
                sql(row.sync_point),
                sql(row.head),
                sql(row.read),
                row.joined,
            ],
        )?;
        self.changed(Change::Conversation { conv: row.id });
        Ok(())
    }

    /// Records whether the account is in the conversation.
    pub(crate) fn set_joined(&mut self, row: &mut ConvRow, joined: bool) -> Result<(), StoreError> {
        if row.joined != joined {
            row.joined = joined;
            self.save_conv(row)?;
        }
        Ok(())
    }

    /// Raises the head reported for the conversation.
    pub(crate) fn note_head(&mut self, row: &mut ConvRow, head: u64) -> Result<(), StoreError> {
        if head > row.head {
            row.head = head;
            self.save_conv(row)?;
        }
        Ok(())
    }

    /// Moves the read marker forward to `read` (7.4), but no further than
    /// the newest seq known: the reported head or the newest stored event,
    /// as the server would (a value beyond the head sets the marker to the
    /// head). Returns whether it moved.
    pub(crate) fn mark_read(&mut self, row: &mut ConvRow, read: u64) -> Result<bool, StoreError> {
        let known = row.head.max(self.max_seq(row.id)?);
        self.set_read(row, read.min(known))
    }

    /// Moves the read marker forward (7.4). A lower value is ignored.
    pub(crate) fn set_read(&mut self, row: &mut ConvRow, read: u64) -> Result<bool, StoreError> {
        if read > row.read {
            row.read = read;
            self.save_conv(row)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Compares an id the server reported with the stored one (7.1, 7.2,
    /// 6.1), and a reported head with the sync point (7.1). When either
    /// disagrees, discards the history first. Then stores the id and the
    /// head. Returns whether the history was discarded.
    ///
    /// Only the sync point counts for the head check, not the newest
    /// stored seq: another process sharing the cache may have stored
    /// events after the server computed the head (7.1). A lower head with
    /// the same id keeps the outbox entries bound to that id, since the
    /// room is the same.
    pub(crate) fn learn_id(
        &mut self,
        row: &mut ConvRow,
        id: &Id,
        head: Option<u64>,
    ) -> Result<bool, StoreError> {
        let reset = match &row.conv_id {
            Some(old) => old != id,
            // No id means nothing is stored, but be sure.
            None => self.max_seq(row.id)? > 0,
        } || head.is_some_and(|h| h < row.sync_point);
        if reset {
            self.discard(row, Some(id.clone()))?;
        } else if row.conv_id.is_none() {
            row.conv_id = Some(id.clone());
            self.save_conv(row)?;
        }
        if let Some(head) = head {
            self.note_head(row, head)?;
        }
        Ok(reset)
    }

    /// Discards the conversation's history and derived state, in this
    /// transaction (7.1): the server's conversation under this name is not
    /// the stored one, or the server reported a head below the sync point.
    /// The new id, if known, is stored. Messages in the outbox bound to the
    /// old id fail (7.6), unless the new id is the same one.
    pub(crate) fn discard(
        &mut self,
        row: &mut ConvRow,
        new_id: Option<Id>,
    ) -> Result<(), StoreError> {
        for table in ["events", "reactions", "room_settings", "room_members"] {
            self.tx
                .execute(&format!("DELETE FROM {table} WHERE conv = ?1"), [row.id.0])?;
        }
        if let Some(old) = row.conv_id.take()
            && new_id.as_ref() != Some(&old)
        {
            self.fail_bound(row.account, &row.name, &old, super::FailReason::RoomChanged)?;
        }
        row.conv_id = new_id;
        row.epoch += 1;
        row.sync_point = 0;
        row.head = 0;
        row.read = 0;
        self.save_conv(row)?;
        self.changed(Change::Cleared { conv: row.id });
        Ok(())
    }

    /// Removes the conversation and its history, after DROP (10.4).
    pub(crate) fn remove(&mut self, row: &ConvRow) -> Result<(), StoreError> {
        if let Some(old) = &row.conv_id {
            self.fail_bound(row.account, &row.name, old, super::FailReason::Dropped)?;
        }
        self.tx
            .execute("DELETE FROM convs WHERE id = ?1", [row.id.0])?;
        self.changed(Change::ConversationRemoved {
            conv: row.id,
            name: row.name.clone(),
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sync points

    /// The newest stored seq, 0 if none.
    pub(crate) fn max_seq(&self, conv: ConvId) -> Result<u64, StoreError> {
        let n: Option<i64> = self.tx.query_row(
            "SELECT MAX(seq) FROM events WHERE conv = ?1",
            [conv.0],
            |row| row.get(0),
        )?;
        Ok(n.unwrap_or(0).max(0) as u64)
    }

    /// The author of stored event `seq`.
    pub(crate) fn author_of(&self, conv: ConvId, seq: u64) -> Result<Option<String>, StoreError> {
        Ok(self
            .tx
            .query_row(
                "SELECT author FROM events WHERE conv = ?1 AND seq = ?2",
                params![conv.0, sql(seq)],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Whether event `seq` is stored.
    pub(crate) fn has_event(&self, conv: ConvId, seq: u64) -> Result<bool, StoreError> {
        Ok(self
            .tx
            .query_row(
                "SELECT 1 FROM events WHERE conv = ?1 AND seq = ?2",
                params![conv.0, sql(seq)],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// The first seq after `after` that is not stored.
    pub(crate) fn first_missing_after(&self, conv: ConvId, after: u64) -> Result<u64, StoreError> {
        if !self.has_event(conv, after + 1)? {
            return Ok(after + 1);
        }
        let end: i64 = self.tx.query_row(
            "SELECT MIN(seq) FROM events e WHERE conv = ?1 AND seq > ?2
                 AND NOT EXISTS (SELECT 1 FROM events f WHERE f.conv = e.conv AND f.seq = e.seq + 1)",
            params![conv.0, sql(after)],
            |row| row.get(0),
        )?;
        Ok(end.max(0) as u64 + 1)
    }

    /// The lowest seq of the run of stored events that ends at the newest
    /// one, if that run starts above `sync_point + 1`: the place to load
    /// older pages from (7.1 step 4). `None` when there is no gap above the
    /// sync point.
    pub(crate) fn gap_top(&self, row: &ConvRow) -> Result<Option<u64>, StoreError> {
        let bottom: Option<i64> = self.tx.query_row(
            "SELECT MAX(seq) FROM events e WHERE conv = ?1 AND seq > ?2
                 AND NOT EXISTS (SELECT 1 FROM events f WHERE f.conv = e.conv AND f.seq = e.seq - 1)",
            params![row.id.0, sql(row.sync_point)],
            |r| r.get(0),
        )?;
        Ok(bottom
            .map(|b| b.max(0) as u64)
            .filter(|&b| b > row.sync_point + 1))
    }

    /// Raises the sync point to at least `to`, then moves it on over any
    /// stored events that directly follow (7.1 step 3).
    pub(crate) fn raise_sync_point(
        &mut self,
        row: &mut ConvRow,
        to: u64,
    ) -> Result<(), StoreError> {
        let mut sp = row.sync_point.max(to);
        sp = self.first_missing_after(row.id, sp)? - 1;
        if sp != row.sync_point {
            row.sync_point = sp;
            self.save_conv(row)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Events

    /// Stores an event of `row`, which the caller has checked belongs to the
    /// conversation with the stored id. A seq already stored is a duplicate
    /// (7.1 step 5), except that a deleted placeholder marks the stored
    /// event deleted (5.4). Updates the derived tables. Returns whether the
    /// event was new.
    ///
    /// Snapshots (no `seq`) are not events; use [`Tx::apply_snapshot`].
    pub(crate) fn store_event(&mut self, row: &ConvRow, event: &Event) -> Result<bool, StoreError> {
        let Some(meta) = &event.meta else {
            self.apply_snapshot(row, event)?;
            return Ok(false);
        };
        let conv = row.id;
        let n = meta.seq.get();
        if self.has_event(conv, n)? {
            if let EventBody::Msg(m) = &event.body
                && m.deleted
            {
                self.mark_deleted(conv, n)?;
            }
            return Ok(false);
        }

        let mut event = event.clone();
        if let EventBody::Msg(m) = &mut event.body {
            // A DELETE stored before its target, or a deleted target of an
            // edit or reaction, means this copy is out of date (5.4).
            let deleted = m.deleted
                || self.delete_event_for(conv, n)?
                || match m.relation {
                    Some(Relation::Edit(t) | Relation::React(t)) => {
                        self.is_deleted(conv, t.get())? || self.delete_event_for(conv, t.get())?
                    }
                    _ => false,
                };
            if deleted {
                make_placeholder(m);
            }
        }
        let line = event_line(&event)?;
        let c = Columns::of(&event);
        self.tx.execute(
            "INSERT INTO events (conv, seq, t, author, verb, rel, target, deleted, text,
                 file_url, file_type, file_size, subject, line, own)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?4 = COALESCE(?15, (SELECT a.uid FROM convs c
                                     JOIN accounts a ON a.id = c.account WHERE c.id = ?1)))",
            params![
                conv.0,
                sql(n),
                meta.t.unix_millis() as i64,
                meta.from.as_str(),
                event.body.verb(),
                c.rel,
                c.target.map(sql),
                c.deleted,
                c.text,
                c.file_url,
                c.file_type,
                c.file_size.map(sql),
                c.subject,
                line,
                self.me.as_ref().map(Uid::as_str),
            ],
        )?;

        let seq = meta.seq;
        let from = meta.from.as_str();
        match &event.body {
            EventBody::Msg(m) => match m.relation {
                None | Some(Relation::Reply(_)) => {
                    self.refresh_message(conv, n)?;
                    if m.deleted {
                        self.delete_related(conv, n)?;
                    }
                    // A message moves the conversation up the chat list,
                    // unless it is hidden as a blocked person's (5.7).
                    if !self.is_hidden_event(conv, n)? {
                        self.bump_activity(conv, meta.t.unix_millis() as i64)?;
                    }
                    self.changed(Change::Inserted { conv, seq });
                }
                Some(Relation::Edit(t)) => {
                    self.refresh_message(conv, t.get())?;
                    self.target_changed(conv, t.get())?;
                }
                Some(Relation::React(t)) => {
                    self.refresh_reactions(conv, t.get())?;
                    self.target_changed(conv, t.get())?;
                }
            },
            EventBody::Delete { seq: t, .. } => {
                self.apply_delete(row, *t)?;
                self.target_changed(conv, t.get())?;
            }
            body => {
                self.apply_state(conv, body, from, n)?;
                self.changed(Change::Inserted { conv, seq });
            }
        }
        Ok(true)
    }

    /// Applies a snapshot line (5.2) to the derived tables. It describes
    /// the state now, so it counts as being at the newest seq known.
    pub(crate) fn apply_snapshot(
        &mut self,
        row: &ConvRow,
        event: &Event,
    ) -> Result<(), StoreError> {
        let at = row.head.max(self.max_seq(row.id)?);
        self.apply_state(row.id, &event.body, "", at)?;
        self.changed(Change::Conversation { conv: row.id });
        Ok(())
    }

    /// Updates settings and membership for a SET, JOIN, PART, KICK, BAN,
    /// UNBAN or ROLE at `at`. `from` is the event's author.
    fn apply_state(
        &mut self,
        conv: ConvId,
        body: &EventBody,
        from: &str,
        at: u64,
    ) -> Result<(), StoreError> {
        match body {
            EventBody::Set { setting, .. } => {
                self.tx.execute(
                    "INSERT INTO room_settings (conv, key, value, seq) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (conv, key) DO UPDATE SET value = excluded.value,
                         seq = excluded.seq
                     WHERE excluded.seq >= room_settings.seq",
                    params![conv.0, setting.key(), setting.value(), sql(at)],
                )?;
            }
            EventBody::Join { .. } => {
                self.member_field(conv, from, "joined", Some(true), at)?;
                self.changed(Change::Members { conv });
            }
            EventBody::Part { .. } => {
                self.member_field(conv, from, "joined", Some(false), at)?;
                self.changed(Change::Members { conv });
            }
            EventBody::Kick { uid, .. } => {
                // KICK and BAN take the role away (6.3).
                self.member_field(conv, uid.as_str(), "joined", Some(false), at)?;
                self.member_role(conv, uid.as_str(), "member", at)?;
                self.changed(Change::Members { conv });
            }
            EventBody::Ban { uid, .. } => {
                if !from.is_empty() {
                    self.member_field(conv, uid.as_str(), "joined", Some(false), at)?;
                    self.member_role(conv, uid.as_str(), "member", at)?;
                }
                self.member_field(conv, uid.as_str(), "banned", Some(true), at)?;
                self.changed(Change::Members { conv });
            }
            EventBody::Unban { uid, .. } => {
                self.member_field(conv, uid.as_str(), "banned", Some(false), at)?;
            }
            EventBody::Role { uid, role, .. } => {
                self.member_role(conv, uid.as_str(), role.as_str(), at)?;
                self.changed(Change::Members { conv });
            }
            EventBody::Msg(_)
            | EventBody::Delete { .. }
            | EventBody::Invite { .. }
            | EventBody::Enc(_)
            | EventBody::Commit { .. } => {}
        }
        Ok(())
    }

    /// Sets `joined` or `banned` for a member, unless a later event set it.
    pub(super) fn member_field(
        &mut self,
        conv: ConvId,
        uid: &str,
        field: &str,
        value: Option<bool>,
        at: u64,
    ) -> Result<(), StoreError> {
        let seq_col = if field == "joined" {
            "joined_seq"
        } else {
            "ban_seq"
        };
        self.tx.execute(
            &format!(
                "INSERT INTO room_members (conv, uid, {field}, {seq_col}) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (conv, uid) DO UPDATE SET {field} = excluded.{field},
                     {seq_col} = excluded.{seq_col}
                 WHERE excluded.{seq_col} >= room_members.{seq_col}"
            ),
            params![conv.0, uid, value, sql(at)],
        )?;
        Ok(())
    }

    pub(super) fn member_role(
        &mut self,
        conv: ConvId,
        uid: &str,
        role: &str,
        at: u64,
    ) -> Result<(), StoreError> {
        self.tx.execute(
            "INSERT INTO room_members (conv, uid, role, role_seq) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (conv, uid) DO UPDATE SET role = excluded.role,
                 role_seq = excluded.role_seq
             WHERE excluded.role_seq >= room_members.role_seq",
            params![conv.0, uid, role, sql(at)],
        )?;
        // The account's own role shows in its conversation's summary.
        let own: Option<i64> = self
            .tx
            .query_row(
                "SELECT 1 FROM convs c JOIN accounts a ON a.id = c.account
                 WHERE c.id = ?1 AND a.uid = ?2",
                params![conv.0, uid],
                |r| r.get(0),
            )
            .optional()?;
        if own.is_some() {
            self.changed(Change::Conversation { conv });
        }
        Ok(())
    }

    /// Records the account's own role in `row`'s room as INFO said it
    /// (6.2): `None` for no role and not a member, which is stored as
    /// `member`. It describes the room now, so it counts as being at the
    /// newest seq known, as a snapshot does.
    pub(crate) fn set_own_role(
        &mut self,
        row: &ConvRow,
        role: Option<risala_proto::types::Role>,
    ) -> Result<(), StoreError> {
        let at = row.head.max(self.max_seq(row.id)?);
        let uid: String = self.tx.query_row(
            "SELECT uid FROM accounts WHERE id = ?1",
            [row.account.0],
            |r| r.get(0),
        )?;
        let role = role.unwrap_or(risala_proto::types::Role::Member);
        self.member_role(row.id, &uid, role.as_str(), at)
    }

    /// Whether stored event `seq` is hidden as a blocked person's (5.7).
    fn is_hidden_event(&self, conv: ConvId, seq: u64) -> Result<bool, StoreError> {
        Ok(self
            .tx
            .query_row(
                &format!(
                    "SELECT 1 FROM events e WHERE e.conv = ?1 AND e.seq = ?2 AND {}",
                    super::people::HIDDEN
                ),
                params![conv.0, sql(seq)],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Whether a stored DELETE names `seq`.
    fn delete_event_for(&self, conv: ConvId, seq: u64) -> Result<bool, StoreError> {
        Ok(self
            .tx
            .query_row(
                "SELECT 1 FROM events WHERE conv = ?1 AND target = ?2 AND verb = 'DELETE'",
                params![conv.0, sql(seq)],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Whether stored event `seq` is deleted.
    fn is_deleted(&self, conv: ConvId, seq: u64) -> Result<bool, StoreError> {
        Ok(self
            .tx
            .query_row(
                "SELECT deleted FROM events WHERE conv = ?1 AND seq = ?2",
                params![conv.0, sql(seq)],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false))
    }

    /// Records what a newly stored edit, reaction or DELETE of message
    /// `target` changed: the target, if it is stored, or else the
    /// conversation. The new event fills its place in the history either
    /// way, which an unread count depends on, so something must be told.
    fn target_changed(&mut self, conv: ConvId, target: u64) -> Result<(), StoreError> {
        if self.has_event(conv, target)? {
            self.touch(conv, target)
        } else {
            self.changed(Change::Conversation { conv });
            Ok(())
        }
    }

    /// Records an Updated change for `seq` if it is a stored timeline item.
    fn touch(&mut self, conv: ConvId, n: u64) -> Result<(), StoreError> {
        if self.has_event(conv, n)? {
            self.changed(Change::Updated {
                conv,
                seq: seq(sql(n))?,
            });
        }
        Ok(())
    }

    /// Deletes stored message `target` of `row` as a DELETE event does
    /// (5.4), with its edits and reactions. For a DELETE whose event is not
    /// stored, such as the account's own in a room it has left, whose `OK`
    /// is all it gets.
    pub(crate) fn apply_delete(&mut self, row: &ConvRow, target: Seq) -> Result<(), StoreError> {
        self.mark_deleted(row.id, target.get())?;
        // Only messages have edits and reactions, so whatever names the
        // target goes too, even if the target is not stored.
        self.delete_related(row.id, target.get())
    }

    /// Marks stored MSG `n` deleted, erasing its text and file (5.4), and
    /// applies what follows: deleting a message deletes its edits and
    /// reactions, deleting an edit brings back the previous version, and
    /// deleting a reaction removes it.
    fn mark_deleted(&mut self, conv: ConvId, n: u64) -> Result<(), StoreError> {
        type Row = (String, bool, String, Option<String>, Option<i64>);
        let row: Option<Row> = self
            .tx
            .query_row(
                "SELECT verb, deleted, line, rel, target FROM events WHERE conv = ?1 AND seq = ?2",
                params![conv.0, sql(n)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((verb, deleted, line, rel, target)) = row else {
            return Ok(());
        };
        if verb != "MSG" || deleted {
            return Ok(());
        }
        let mut event = stored_event(&line)?;
        if let EventBody::Msg(m) = &mut event.body {
            make_placeholder(m);
        }
        self.tx.execute(
            "UPDATE events SET deleted = 1, text = '', file_url = NULL, file_type = NULL,
                 file_size = NULL, line = ?3
             WHERE conv = ?1 AND seq = ?2",
            params![conv.0, sql(n), event_line(&event)?],
        )?;
        let target = target.map(|t| t.max(0) as u64);
        match (rel.as_deref(), target) {
            (Some("edit"), Some(t)) => {
                self.refresh_message(conv, t)?;
                self.touch(conv, t)?;
            }
            (Some("react"), Some(t)) => {
                self.refresh_reactions(conv, t)?;
                self.touch(conv, t)?;
            }
            _ => {
                self.refresh_message(conv, n)?;
                self.delete_related(conv, n)?;
                self.touch(conv, n)?;
            }
        }
        Ok(())
    }

    /// Marks the stored edits and reactions of message `n` deleted (5.4).
    fn delete_related(&mut self, conv: ConvId, n: u64) -> Result<(), StoreError> {
        let related: Vec<i64> = {
            let mut stmt = self.tx.prepare_cached(
                "SELECT seq FROM events WHERE conv = ?1 AND target = ?2
                     AND rel IN ('edit', 'react') AND deleted = 0",
            )?;
            stmt.query_map(params![conv.0, sql(n)], |r| r.get(0))?
                .collect::<Result<_, _>>()?
        };
        for s in related {
            self.mark_deleted(conv, s.max(0) as u64)?;
        }
        Ok(())
    }

    /// Recomputes the current text of message `n`: its newest edit by the
    /// same author that is not deleted, or its own text (5.3).
    fn refresh_message(&mut self, conv: ConvId, n: u64) -> Result<(), StoreError> {
        let base: Option<(Option<String>, bool, String, Option<String>)> = self
            .tx
            .query_row(
                "SELECT rel, deleted, author, text FROM events
                 WHERE conv = ?1 AND seq = ?2 AND verb = 'MSG'",
                params![conv.0, sql(n)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((rel, deleted, author, text)) = base else {
            return Ok(());
        };
        if matches!(rel.as_deref(), Some("edit" | "react")) {
            return Ok(());
        }
        let (text, edit) = if deleted {
            (String::new(), None)
        } else {
            let edit: Option<(i64, String)> = self
                .tx
                .query_row(
                    "SELECT seq, text FROM events
                     WHERE conv = ?1 AND target = ?2 AND rel = 'edit' AND deleted = 0
                         AND author = ?3
                     ORDER BY seq DESC LIMIT 1",
                    params![conv.0, sql(n), author],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match edit {
                Some((s, t)) => (t, Some(s)),
                None => (text.unwrap_or_default(), None),
            }
        };
        self.tx.execute(
            "INSERT INTO message_state (conv, seq, text, edit_seq) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (conv, seq) DO UPDATE SET text = excluded.text,
                 edit_seq = excluded.edit_seq",
            params![conv.0, sql(n), text, edit],
        )?;
        Ok(())
    }

    /// Recomputes the reaction counts of message `n` (5.3). Each person
    /// counts once per reaction.
    fn refresh_reactions(&mut self, conv: ConvId, n: u64) -> Result<(), StoreError> {
        self.tx.execute(
            "DELETE FROM reactions WHERE conv = ?1 AND target = ?2",
            params![conv.0, sql(n)],
        )?;
        self.tx.execute(
            "INSERT INTO reactions (conv, target, reaction, count, mine)
             SELECT e.conv, e.target, e.text, COUNT(DISTINCT e.author),
                 MAX(CASE WHEN e.own THEN e.seq END)
             FROM events e
             WHERE e.conv = ?1 AND e.target = ?2 AND e.rel = 'react' AND e.deleted = 0
             GROUP BY e.text",
            params![conv.0, sql(n)],
        )?;
        Ok(())
    }
}

/// Turns a message into the placeholder HISTORY sends for a deleted one:
/// no text, no file, the relation kept (5.4).
fn make_placeholder(m: &mut risala_proto::server::Message) {
    m.deleted = true;
    m.text.clear();
    m.file = None;
}

/// The line to store for an event: canonical form, without `ref`.
fn event_line(event: &Event) -> Result<String, StoreError> {
    ServerMessage::new(ServerLine::Event(event.clone()))
        .try_to_line()
        .map(|l| l.to_string())
        .map_err(|e| StoreError::Corrupt(format!("event does not serialise: {e}")))
}

/// Parses a stored line back into its event.
pub(crate) fn stored_event(line: &str) -> Result<Event, StoreError> {
    match line.parse::<ServerMessage>() {
        Ok(ServerMessage {
            line: ServerLine::Event(e),
            ..
        }) => Ok(e),
        _ => Err(StoreError::Corrupt(format!("bad stored line {line:?}"))),
    }
}

/// The indexed columns of an event.
struct Columns {
    rel: Option<&'static str>,
    target: Option<u64>,
    deleted: bool,
    text: Option<String>,
    file_url: Option<String>,
    file_type: Option<String>,
    file_size: Option<u64>,
    subject: Option<String>,
}

impl Columns {
    fn of(event: &Event) -> Columns {
        let mut c = Columns {
            rel: None,
            target: None,
            deleted: false,
            text: None,
            file_url: None,
            file_type: None,
            file_size: None,
            subject: None,
        };
        match &event.body {
            EventBody::Msg(m) => {
                c.rel = m.relation.map(Relation::key);
                c.target = m.relation.map(|r| r.seq().get());
                c.deleted = m.deleted;
                c.text = Some(m.text.clone());
                if let Some(f) = &m.file {
                    c.file_url = Some(f.url.as_str().to_owned());
                    c.file_type = f.media_type.as_ref().map(|t| t.as_str().to_owned());
                    c.file_size = f.size;
                }
            }
            EventBody::Delete { seq, .. } => c.target = Some(seq.get()),
            EventBody::Invite { uid, .. }
            | EventBody::Kick { uid, .. }
            | EventBody::Ban { uid, .. }
            | EventBody::Unban { uid, .. }
            | EventBody::Role { uid, .. } => c.subject = Some(uid.as_str().to_owned()),
            // Encrypted conversations (12) keep only the stored line for now.
            EventBody::Join { .. }
            | EventBody::Part { .. }
            | EventBody::Set { .. }
            | EventBody::Enc(_)
            | EventBody::Commit { .. } => {}
        }
        c
    }
}

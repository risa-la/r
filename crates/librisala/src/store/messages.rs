//! Messages: what each conversation has shown, decrypted, its gaps, the
//! outbox, and Welcomes waiting to be sent (5.3, 5.4, 7.4, 7.6, 12.8,
//! 12.9).
//!
//! Owned by task C2. The server keeps no history (Section 7), so these
//! rows are the history.

use rusqlite::{OptionalExtension as _, Row, params};

use super::conversations::ConversationId;
use super::{Change, Store, StoreError, Tx, parse};
use risala_proto::names::Uid;

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Messages, by conversation and message_id (12.9). Every TEXT line is a
-- row, edits and reactions included; reads put them together (5.3). seq
-- and received are the post's, NULL until an own message is posted;
-- sent is the sender's clock, and time_mismatch marks more than 10
-- minutes between them (12.9). verified is whether the sender's leaf was
-- confirmed (12.10). restored marks messages from a backup or a transfer
-- (12.13). content holds the content as received, for reports (5.8) and
-- transfers; frank_key too. hidden: from someone the user has blocked
-- (5.7). deleted: a DELETE erased it (5.4), and text and content are
-- gone. epoch is the epoch it was posted in, for READ checks (7.7).
CREATE TABLE messages (
    conv          INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id    BLOB NOT NULL,
    seq           INTEGER,
    epoch         INTEGER,
    sender        TEXT NOT NULL,
    leaf          INTEGER,
    own           INTEGER NOT NULL DEFAULT 0,
    sent          INTEGER NOT NULL,
    received      INTEGER,
    verified      INTEGER NOT NULL DEFAULT 0,
    time_mismatch INTEGER NOT NULL DEFAULT 0,
    restored      INTEGER NOT NULL DEFAULT 0,
    hidden        INTEGER NOT NULL DEFAULT 0,
    content       BLOB,
    text          TEXT,
    reply_to      BLOB,
    edit_of       BLOB,
    react_to      BLOB,
    deleted       INTEGER NOT NULL DEFAULT 0,
    frank_key     BLOB,
    PRIMARY KEY (conv, message_id)
) WITHOUT ROWID;
CREATE INDEX messages_seq ON messages (conv, seq);
CREATE INDEX messages_target ON messages (conv, edit_of, react_to);

-- Message ids seen in each group that are not shown as messages (other
-- lines than TEXT), so that a replay is noticed (12.9, step 3).
CREATE TABLE seen (
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id BLOB NOT NULL,
    PRIMARY KEY (conv, message_id)
) WITHOUT ROWID;

-- DELETEs whose target has not arrived yet (5.4): applied when it does.
-- by is the deleting identity, by_role whether it held a role that may
-- delete others' messages.
CREATE TABLE deletes (
    conv    INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    target  BLOB NOT NULL,
    by      TEXT NOT NULL,
    by_role INTEGER NOT NULL,
    PRIMARY KEY (conv, target, by)
) WITHOUT ROWID;

-- Gaps in a leaf's messages (7.4): counters not received, and whether
-- retention explains them.
CREATE TABLE gaps (
    conv   INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender TEXT NOT NULL,
    leaf   INTEGER NOT NULL,
    first  INTEGER NOT NULL,
    last   INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('expired', 'withheld')),
    PRIMARY KEY (conv, leaf, first)
) WITHOUT ROWID;

-- Posts to send (7.6). kind: 'message' (body is the RisalaMessage,
-- encrypted afresh in the current epoch each time it is posted, 12.9),
-- 'live' (the same, posted with live=yes), 'commit' (post is the commit,
-- next its next hash, welcome the Welcome, intent what it does so that it
-- can be made again if it loses, 7.2), 'proposal' (a SelfRemove, posted
-- again in each new epoch until applied, 6.1). epoch is the epoch post
-- was made for. state: 'queued', 'sent' (POST in flight), 'posted' (OK
-- seq=), 'done' (applied in order: won, or seen), 'lost' (a commit that
-- lost its epoch, or was refused). not_before delays a retry.
CREATE TABLE outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('message', 'live', 'commit', 'proposal')),
    message_id BLOB,
    body       BLOB,
    epoch      INTEGER,
    post       BLOB,
    next       BLOB,
    groupinfo  BLOB,
    welcome    BLOB,
    intent     BLOB,
    state      TEXT NOT NULL DEFAULT 'queued'
               CHECK (state IN ('queued', 'sent', 'posted', 'done', 'lost')),
    seq        INTEGER,
    attempts   INTEGER NOT NULL DEFAULT 0,
    not_before INTEGER,
    created    INTEGER NOT NULL
);
CREATE INDEX outbox_conv ON outbox (conv, state);

-- Sealed Welcomes waiting for their random time (12.8), each for one
-- KeyPackage by its ref. sent_at is set while WELCOME PUT is in flight.
CREATE TABLE welcomes_out (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    ref        BLOB NOT NULL,
    welcome    BLOB NOT NULL,
    send_after INTEGER NOT NULL,
    in_flight  INTEGER NOT NULL DEFAULT 0
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

/// A message row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    /// The conversation.
    pub conv: ConversationId,
    /// The message id.
    pub message_id: [u8; 16],
    /// The post's seq.
    pub seq: Option<u64>,
    /// The epoch it was posted in.
    pub epoch: Option<u64>,
    /// The sender's uid.
    pub sender: Uid,
    /// The sender's leaf.
    pub leaf: Option<u32>,
    /// Whether this device sent it.
    pub own: bool,
    /// The sender's time.
    pub sent: u64,
    /// The server's time.
    pub received: Option<u64>,
    /// Whether the sender's leaf was confirmed.
    pub verified: bool,
    /// Whether the times differ by more than 10 minutes.
    pub time_mismatch: bool,
    /// From a backup or transfer.
    pub restored: bool,
    /// From someone blocked.
    pub hidden: bool,
    /// The content as received.
    pub content: Option<Vec<u8>>,
    /// The TEXT line's text, escaped.
    pub text: Option<String>,
    /// `reply=`.
    pub reply_to: Option<[u8; 16]>,
    /// `edit=`.
    pub edit_of: Option<[u8; 16]>,
    /// `react=`.
    pub react_to: Option<[u8; 16]>,
    /// Deleted by a DELETE.
    pub deleted: bool,
    /// The frank key, for reports (5.8).
    pub frank_key: Option<[u8; 32]>,
}

const MESSAGE_COLUMNS: &str = "conv, message_id, seq, epoch, sender, leaf, own, sent, received, \
     verified, time_mismatch, restored, hidden, content, text, reply_to, edit_of, react_to, \
     deleted, frank_key";

fn opt_fixed<const N: usize>(b: Option<Vec<u8>>) -> rusqlite::Result<Option<[u8; N]>> {
    b.map(|b| {
        b.try_into().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                "bad length".into(),
            )
        })
    })
    .transpose()
}

/// A uid that is replaced at once by [`finish_message`].
const PLACEHOLDER: &str = "placeholder@example.org";

fn message_row(row: &Row<'_>) -> rusqlite::Result<(MessageRow, String)> {
    let message_id: Vec<u8> = row.get(1)?;
    let sender: String = row.get(4)?;
    Ok((
        MessageRow {
            conv: ConversationId(row.get(0)?),
            message_id: opt_fixed(Some(message_id))?.unwrap_or_default(),
            seq: row.get::<_, Option<i64>>(2)?.map(|s| s as u64),
            epoch: row.get::<_, Option<i64>>(3)?.map(|s| s as u64),
            // Set by finish_message, from the column read above.
            sender: PLACEHOLDER.parse().expect("a valid uid"),
            leaf: row.get::<_, Option<i64>>(5)?.map(|l| l as u32),
            own: row.get(6)?,
            sent: row.get::<_, i64>(7)? as u64,
            received: row.get::<_, Option<i64>>(8)?.map(|t| t as u64),
            verified: row.get(9)?,
            time_mismatch: row.get(10)?,
            restored: row.get(11)?,
            hidden: row.get(12)?,
            content: row.get(13)?,
            text: row.get(14)?,
            reply_to: opt_fixed(row.get(15)?)?,
            edit_of: opt_fixed(row.get(16)?)?,
            react_to: opt_fixed(row.get(17)?)?,
            deleted: row.get(18)?,
            frank_key: opt_fixed(row.get(19)?)?,
        },
        sender,
    ))
}

fn finish_message((mut row, sender): (MessageRow, String)) -> Result<MessageRow, StoreError> {
    row.sender = parse(&sender, "uid")?;
    Ok(row)
}

/// An outbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// Its id.
    pub id: i64,
    /// The conversation.
    pub conv: ConversationId,
    /// What it is.
    pub kind: OutboxKind,
    /// A message's id.
    pub message_id: Option<[u8; 16]>,
    /// A message's RisalaMessage.
    pub body: Option<Vec<u8>>,
    /// The epoch `post` was made for.
    pub epoch: Option<u64>,
    /// The MLSMessage, as last posted or to post.
    pub post: Option<Vec<u8>>,
    /// A commit's `next`.
    pub next: Option<[u8; 48]>,
    /// A public room commit's GroupInfo.
    pub groupinfo: Option<Vec<u8>>,
    /// A commit's Welcome.
    pub welcome: Option<Vec<u8>>,
    /// A commit's intent, to make it again if it loses.
    pub intent: Option<Vec<u8>>,
    /// Its state.
    pub state: OutboxState,
    /// Its seq, once posted.
    pub seq: Option<u64>,
    /// How many times it was posted.
    pub attempts: u32,
    /// Not to be tried before this time.
    pub not_before: Option<u64>,
}

/// What an outbox row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboxKind {
    /// A message.
    Message,
    /// A live message (5.2).
    Live,
    /// A commit.
    Commit,
    /// A proposal, a SelfRemove.
    Proposal,
}

impl OutboxKind {
    fn as_str(self) -> &'static str {
        match self {
            OutboxKind::Message => "message",
            OutboxKind::Live => "live",
            OutboxKind::Commit => "commit",
            OutboxKind::Proposal => "proposal",
        }
    }

    fn parse(s: &str) -> Result<OutboxKind, StoreError> {
        Ok(match s {
            "message" => OutboxKind::Message,
            "live" => OutboxKind::Live,
            "commit" => OutboxKind::Commit,
            "proposal" => OutboxKind::Proposal,
            other => return Err(StoreError::Corrupt(format!("outbox kind {other:?}"))),
        })
    }
}

/// Where an outbox row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboxState {
    /// Waiting to be posted.
    Queued,
    /// POST in flight.
    Sent,
    /// The server accepted it.
    Posted,
    /// Applied in order: a commit that won, or a message seen.
    Done,
    /// A commit that lost, or was refused.
    Lost,
}

impl OutboxState {
    fn as_str(self) -> &'static str {
        match self {
            OutboxState::Queued => "queued",
            OutboxState::Sent => "sent",
            OutboxState::Posted => "posted",
            OutboxState::Done => "done",
            OutboxState::Lost => "lost",
        }
    }

    fn parse(s: &str) -> Result<OutboxState, StoreError> {
        Ok(match s {
            "queued" => OutboxState::Queued,
            "sent" => OutboxState::Sent,
            "posted" => OutboxState::Posted,
            "done" => OutboxState::Done,
            "lost" => OutboxState::Lost,
            other => return Err(StoreError::Corrupt(format!("outbox state {other:?}"))),
        })
    }
}

const OUTBOX_COLUMNS: &str = "id, conv, kind, message_id, body, epoch, post, next, groupinfo, \
     welcome, intent, state, seq, attempts, not_before";

type OutboxRaw = (OutboxRow, String, String);

fn outbox_row(row: &Row<'_>) -> rusqlite::Result<OutboxRaw> {
    Ok((
        OutboxRow {
            id: row.get(0)?,
            conv: ConversationId(row.get(1)?),
            kind: OutboxKind::Message,
            message_id: opt_fixed(row.get(3)?)?,
            body: row.get(4)?,
            epoch: row.get::<_, Option<i64>>(5)?.map(|e| e as u64),
            post: row.get(6)?,
            next: opt_fixed(row.get(7)?)?,
            groupinfo: row.get(8)?,
            welcome: row.get(9)?,
            intent: row.get(10)?,
            state: OutboxState::Queued,
            seq: row.get::<_, Option<i64>>(12)?.map(|s| s as u64),
            attempts: row.get::<_, i64>(13)? as u32,
            not_before: row.get::<_, Option<i64>>(14)?.map(|t| t as u64),
        },
        row.get(2)?,
        row.get(11)?,
    ))
}

fn finish_outbox((mut row, kind, state): OutboxRaw) -> Result<OutboxRow, StoreError> {
    row.kind = OutboxKind::parse(&kind)?;
    row.state = OutboxState::parse(&state)?;
    Ok(row)
}

/// A new outbox row.
#[derive(Debug, Clone, Default)]
pub struct NewOutbox {
    /// A message's id.
    pub message_id: Option<[u8; 16]>,
    /// A message's RisalaMessage.
    pub body: Option<Vec<u8>>,
    /// The epoch `post` was made for.
    pub epoch: Option<u64>,
    /// The MLSMessage.
    pub post: Option<Vec<u8>>,
    /// A commit's `next`.
    pub next: Option<[u8; 48]>,
    /// A public room commit's GroupInfo.
    pub groupinfo: Option<Vec<u8>>,
    /// A commit's Welcome.
    pub welcome: Option<Vec<u8>>,
    /// A commit's intent.
    pub intent: Option<Vec<u8>>,
}

/// A Welcome waiting to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeOut {
    /// Its id.
    pub id: i64,
    /// The conversation.
    pub conv: ConversationId,
    /// The KeyPackageRef.
    pub reference: Vec<u8>,
    /// The sealed Welcome.
    pub welcome: Vec<u8>,
}

/// A gap in a sender's messages (7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapRow {
    /// The sender.
    pub sender: Uid,
    /// Its leaf.
    pub leaf: u32,
    /// The first missing counter.
    pub first: u64,
    /// The last missing counter.
    pub last: u64,
    /// Whether retention explains it.
    pub expired: bool,
}

/// A new message, for [`Tx::insert_message`].
#[derive(Debug, Clone, Default)]
pub struct NewMessage<'a> {
    /// The message id.
    pub message_id: [u8; 16],
    /// The post's seq.
    pub seq: Option<u64>,
    /// The epoch.
    pub epoch: Option<u64>,
    /// The sender.
    pub sender: Option<&'a Uid>,
    /// The sender's leaf.
    pub leaf: Option<u32>,
    /// Sent by this device.
    pub own: bool,
    /// The sender's time.
    pub sent: u64,
    /// The server's time.
    pub received: Option<u64>,
    /// Confirmed sender.
    pub verified: bool,
    /// Times differ.
    pub time_mismatch: bool,
    /// Restored.
    pub restored: bool,
    /// From someone blocked.
    pub hidden: bool,
    /// The content.
    pub content: Option<&'a [u8]>,
    /// The text.
    pub text: Option<&'a str>,
    /// `reply=`.
    pub reply_to: Option<[u8; 16]>,
    /// `edit=`.
    pub edit_of: Option<[u8; 16]>,
    /// `react=`.
    pub react_to: Option<[u8; 16]>,
    /// The frank key.
    pub frank_key: Option<[u8; 32]>,
}

impl Tx<'_> {
    /// Whether the group has seen `message_id` (12.9, step 3).
    pub(crate) fn message_seen(
        &self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<bool, StoreError> {
        let n: i64 = self.conn().query_row(
            "SELECT (SELECT count(*) FROM messages WHERE conv = ?1 AND message_id = ?2)
                  + (SELECT count(*) FROM seen WHERE conv = ?1 AND message_id = ?2)",
            params![conv.0, &message_id[..]],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Notes a message id that is not stored as a message.
    pub(crate) fn mark_seen(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO seen (conv, message_id) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![conv.0, &message_id[..]],
        )?;
        Ok(())
    }

    /// Stores a message, unless its id is already stored.
    pub(crate) fn insert_message(
        &mut self,
        conv: ConversationId,
        m: &NewMessage<'_>,
    ) -> Result<bool, StoreError> {
        let sender = m
            .sender
            .ok_or(StoreError::Corrupt("a message without a sender".into()))?;
        let n = self.conn().execute(
            &format!(
                "INSERT INTO messages ({MESSAGE_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                         ?17, ?18, 0, ?19)
                 ON CONFLICT DO NOTHING"
            ),
            params![
                conv.0,
                &m.message_id[..],
                m.seq.map(|s| s as i64),
                m.epoch.map(|e| e as i64),
                sender.as_str(),
                m.leaf,
                m.own,
                m.sent as i64,
                m.received.map(|t| t as i64),
                m.verified,
                m.time_mismatch,
                m.restored,
                m.hidden,
                m.content,
                m.text,
                m.reply_to.as_ref().map(|i| &i[..]),
                m.edit_of.as_ref().map(|i| &i[..]),
                m.react_to.as_ref().map(|i| &i[..]),
                m.frank_key.as_ref().map(|k| &k[..]),
            ],
        )?;
        if n > 0 {
            self.changed(Change::Message(MessageChange::Messages(conv)));
        }
        Ok(n > 0)
    }

    /// Sets the seq, epoch and time of an own message once it is posted.
    pub(crate) fn message_posted(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
        seq: u64,
        epoch: u64,
        received: u64,
    ) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE messages SET seq = ?3, epoch = ?4, received = ?5
             WHERE conv = ?1 AND message_id = ?2",
            params![
                conv.0,
                &message_id[..],
                seq as i64,
                epoch as i64,
                received as i64
            ],
        )?;
        if n > 0 {
            self.changed(Change::Message(MessageChange::Messages(conv)));
        }
        Ok(())
    }

    /// A stored message.
    pub(crate) fn message(
        &self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<Option<MessageRow>, StoreError> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {MESSAGE_COLUMNS} FROM messages WHERE conv = ?1 AND message_id = ?2"
                ),
                params![conv.0, &message_id[..]],
                message_row,
            )
            .optional()?
            .map(finish_message)
            .transpose()
    }

    /// Erases a message, and its edits and reactions (5.4): their text
    /// and content go.
    pub(crate) fn erase_message(
        &mut self,
        conv: ConversationId,
        message_id: &[u8; 16],
    ) -> Result<(), StoreError> {
        let id = &message_id[..];
        self.conn().execute(
            "UPDATE messages SET deleted = 1, text = NULL, content = NULL, frank_key = NULL
             WHERE conv = ?1 AND (message_id = ?2 OR edit_of = ?2 OR react_to = ?2)",
            params![conv.0, id],
        )?;
        self.changed(Change::Message(MessageChange::Messages(conv)));
        Ok(())
    }

    /// Keeps a DELETE whose target has not arrived (5.4).
    pub(crate) fn keep_delete(
        &mut self,
        conv: ConversationId,
        target: &[u8; 16],
        by: &Uid,
        by_role: bool,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO deletes (conv, target, by, by_role) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO UPDATE SET by_role = max(by_role, excluded.by_role)",
            params![conv.0, &target[..], by.as_str(), by_role],
        )?;
        Ok(())
    }

    /// The DELETEs kept for `target`: who, and whether with a role.
    pub(crate) fn kept_deletes(
        &self,
        conv: ConversationId,
        target: &[u8; 16],
    ) -> Result<Vec<(Uid, bool)>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare_cached("SELECT by, by_role FROM deletes WHERE conv = ?1 AND target = ?2")?;
        let rows = stmt.query_map(params![conv.0, &target[..]], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (by, role) = row?;
            out.push((parse(&by, "uid")?, role));
        }
        Ok(out)
    }

    /// Records a gap in a leaf's messages (7.4).
    pub(crate) fn add_gap(
        &mut self,
        conv: ConversationId,
        sender: &Uid,
        leaf: u32,
        first: u64,
        last: u64,
        expired: bool,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO gaps (conv, sender, leaf, first, last, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT DO NOTHING",
            params![
                conv.0,
                sender.as_str(),
                leaf,
                first as i64,
                last as i64,
                if expired { "expired" } else { "withheld" }
            ],
        )?;
        self.changed(Change::Message(MessageChange::Messages(conv)));
        Ok(())
    }

    /// Fills a gap with a message that arrived late: counter `counter` of
    /// `leaf`.
    pub(crate) fn fill_gap(
        &mut self,
        conv: ConversationId,
        leaf: u32,
        counter: u64,
    ) -> Result<(), StoreError> {
        let gap: Option<(i64, i64, String)> = self
            .conn()
            .query_row(
                "SELECT first, last, reason FROM gaps
                 WHERE conv = ?1 AND leaf = ?2 AND first <= ?3 AND last >= ?3",
                params![conv.0, leaf, counter as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((first, last, reason)) = gap else {
            return Ok(());
        };
        let sender: String = self.conn().query_row(
            "SELECT sender FROM gaps WHERE conv = ?1 AND leaf = ?2 AND first = ?3",
            params![conv.0, leaf, first],
            |r| r.get(0),
        )?;
        self.conn().execute(
            "DELETE FROM gaps WHERE conv = ?1 AND leaf = ?2 AND first = ?3",
            params![conv.0, leaf, first],
        )?;
        let c = counter as i64;
        for (a, b) in [(first, c - 1), (c + 1, last)] {
            if a <= b {
                self.conn().execute(
                    "INSERT INTO gaps (conv, sender, leaf, first, last, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![conv.0, sender, leaf, a, b, reason],
                )?;
            }
        }
        self.changed(Change::Message(MessageChange::Messages(conv)));
        Ok(())
    }

    // ---- the outbox

    /// Queues something to post.
    pub(crate) fn queue_outbox(
        &mut self,
        conv: ConversationId,
        kind: OutboxKind,
        new: &NewOutbox,
        now: u64,
    ) -> Result<i64, StoreError> {
        self.conn().execute(
            "INSERT INTO outbox (conv, kind, message_id, body, epoch, post, next, groupinfo, welcome,
                                 intent, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                conv.0,
                kind.as_str(),
                new.message_id.as_ref().map(|i| &i[..]),
                new.body,
                new.epoch.map(|e| e as i64),
                new.post,
                new.next.as_ref().map(|n| &n[..]),
                new.groupinfo,
                new.welcome,
                new.intent,
                now as i64
            ],
        )?;
        self.changed(Change::Message(MessageChange::Outbox(conv)));
        Ok(self.conn().last_insert_rowid())
    }

    /// One outbox row.
    pub(crate) fn outbox_row(&self, id: i64) -> Result<Option<OutboxRow>, StoreError> {
        self.conn()
            .query_row(
                &format!("SELECT {OUTBOX_COLUMNS} FROM outbox WHERE id = ?1"),
                [id],
                outbox_row,
            )
            .optional()?
            .map(finish_outbox)
            .transpose()
    }

    /// A conversation's outbox rows that are not done, oldest first.
    pub(crate) fn pending_outbox(
        &self,
        conv: ConversationId,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let mut stmt = self.conn().prepare_cached(&format!(
            "SELECT {OUTBOX_COLUMNS} FROM outbox
             WHERE conv = ?1 AND state IN ('queued', 'sent', 'posted') ORDER BY id"
        ))?;
        let rows = stmt.query_map([conv.0], outbox_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(finish_outbox(row?)?);
        }
        Ok(out)
    }

    /// Every outbox row of the account that is not done.
    pub(crate) fn account_outbox(
        &self,
        account: super::AccountId,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let mut stmt = self.conn().prepare_cached(&format!(
            "SELECT {} FROM outbox o JOIN conversations c ON c.id = o.conv
             WHERE c.account = ?1 AND o.state IN ('queued', 'sent', 'posted') ORDER BY o.id",
            OUTBOX_COLUMNS
                .split(", ")
                .map(|c| format!("o.{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
        let rows = stmt.query_map([account.0], outbox_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(finish_outbox(row?)?);
        }
        Ok(out)
    }

    /// Updates an outbox row's state, post and seq.
    pub(crate) fn update_outbox(
        &mut self,
        id: i64,
        state: OutboxState,
        post: Option<(&[u8], u64)>,
        seq: Option<u64>,
        not_before: Option<u64>,
    ) -> Result<(), StoreError> {
        let conv: Option<i64> = self
            .conn()
            .query_row("SELECT conv FROM outbox WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        let Some(conv) = conv else {
            return Ok(());
        };
        self.conn().execute(
            "UPDATE outbox SET state = ?2, seq = coalesce(?3, seq), not_before = ?4,
                    attempts = attempts + (?2 = 'sent')
             WHERE id = ?1",
            params![
                id,
                state.as_str(),
                seq.map(|s| s as i64),
                not_before.map(|t| t as i64)
            ],
        )?;
        if let Some((post, epoch)) = post {
            self.conn().execute(
                "UPDATE outbox SET post = ?2, epoch = ?3 WHERE id = ?1",
                params![id, post, epoch as i64],
            )?;
        }
        self.changed(Change::Message(MessageChange::Outbox(ConversationId(conv))));
        Ok(())
    }

    /// Sets a commit's next hash and GroupInfo after it is made again.
    pub(crate) fn set_outbox_commit(
        &mut self,
        id: i64,
        next: &[u8; 48],
        groupinfo: Option<&[u8]>,
        welcome: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE outbox SET next = ?2, groupinfo = ?3, welcome = ?4 WHERE id = ?1",
            params![id, &next[..], groupinfo, welcome],
        )?;
        Ok(())
    }

    /// The outbox row whose last post is `post`, if any.
    pub(crate) fn outbox_by_post(
        &self,
        conv: ConversationId,
        post: &[u8],
    ) -> Result<Option<OutboxRow>, StoreError> {
        self.conn()
            .query_row(
                &format!("SELECT {OUTBOX_COLUMNS} FROM outbox WHERE conv = ?1 AND post = ?2"),
                params![conv.0, post],
                outbox_row,
            )
            .optional()?
            .map(finish_outbox)
            .transpose()
    }

    // ---- Welcomes to send

    /// Queues a sealed Welcome, to send after `send_after` (12.8).
    pub(crate) fn queue_welcome(
        &mut self,
        conv: ConversationId,
        reference: &[u8],
        welcome: &[u8],
        send_after: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO welcomes_out (conv, ref, welcome, send_after) VALUES (?1, ?2, ?3, ?4)",
            params![conv.0, reference, welcome, send_after as i64],
        )?;
        Ok(())
    }

    /// The account's Welcomes whose time has come, and marks them in
    /// flight.
    pub(crate) fn due_welcomes(
        &mut self,
        account: super::AccountId,
        now: u64,
    ) -> Result<Vec<WelcomeOut>, StoreError> {
        let mut out = Vec::new();
        {
            let mut stmt = self.conn().prepare_cached(
                "SELECT w.id, w.conv, w.ref, w.welcome FROM welcomes_out w
                 JOIN conversations c ON c.id = w.conv
                 WHERE c.account = ?1 AND w.in_flight = 0 AND w.send_after <= ?2 ORDER BY w.id",
            )?;
            let rows = stmt.query_map(params![account.0, now as i64], |r| {
                Ok(WelcomeOut {
                    id: r.get(0)?,
                    conv: ConversationId(r.get(1)?),
                    reference: r.get(2)?,
                    welcome: r.get(3)?,
                })
            })?;
            for row in rows {
                out.push(row?);
            }
        }
        for w in &out {
            self.conn().execute(
                "UPDATE welcomes_out SET in_flight = 1 WHERE id = ?1",
                [w.id],
            )?;
        }
        Ok(out)
    }

    /// Forgets a Welcome once sent, or puts it back to try again.
    pub(crate) fn welcome_done(
        &mut self,
        id: i64,
        sent: bool,
        retry_at: u64,
    ) -> Result<(), StoreError> {
        if sent {
            self.conn()
                .execute("DELETE FROM welcomes_out WHERE id = ?1", [id])?;
        } else {
            self.conn().execute(
                "UPDATE welcomes_out SET in_flight = 0, send_after = ?2 WHERE id = ?1",
                params![id, retry_at as i64],
            )?;
        }
        Ok(())
    }

    /// Puts every Welcome in flight back, after a restart.
    pub(crate) fn reset_welcomes(&mut self) -> Result<(), StoreError> {
        self.conn()
            .execute("UPDATE welcomes_out SET in_flight = 0", [])?;
        Ok(())
    }
}

/// Reads for the API.
pub(crate) mod read {
    use super::*;

    pub fn messages(
        conn: &rusqlite::Connection,
        conv: ConversationId,
    ) -> Result<Vec<MessageRow>, StoreError> {
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE conv = ?1
             ORDER BY seq IS NULL, seq, sent, message_id"
        ))?;
        let rows = stmt.query_map([conv.0], message_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(finish_message(row?)?);
        }
        Ok(out)
    }

    pub fn gaps(
        conn: &rusqlite::Connection,
        conv: ConversationId,
    ) -> Result<Vec<GapRow>, StoreError> {
        let mut stmt = conn.prepare_cached(
            "SELECT sender, leaf, first, last, reason FROM gaps WHERE conv = ?1 ORDER BY leaf, first",
        )?;
        let rows = stmt.query_map([conv.0], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (sender, leaf, first, last, reason) = row?;
            out.push(GapRow {
                sender: parse(&sender, "uid")?,
                leaf: leaf as u32,
                first: first as u64,
                last: last as u64,
                expired: reason == "expired",
            });
        }
        Ok(out)
    }
}

impl Store {
    /// Every message row of a conversation, in post order, own messages
    /// not yet posted last.
    pub fn message_rows(&self, conv: ConversationId) -> Result<Vec<MessageRow>, StoreError> {
        self.read(|conn| read::messages(conn, conv))
    }

    /// The gaps of a conversation (7.4).
    pub fn gap_rows(&self, conv: ConversationId) -> Result<Vec<GapRow>, StoreError> {
        self.read(|conn| read::gaps(conn, conv))
    }
}

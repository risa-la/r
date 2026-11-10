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

-- DELETEs not yet applied (5.4): their target has not arrived, or it
-- is more trusted than the DELETE's leaf (12.10). by is the deleting
-- identity, by_role whether it held a role that may delete others'
-- messages. leaf and leaf_key are the DELETE's leaf and its signature
-- key when this device had not confirmed it: the DELETE then waits for
-- that leaf to be confirmed, and goes if it turns out an impostor or
-- leaves the tree with that key. leaf_key is empty for a DELETE from a
-- confirmed leaf. kept is the `t` of the post that carried it: at most
-- MAX_KEPT_DELETES are kept per sender, and none past retention (LR-L3).
CREATE TABLE deletes (
    conv     INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    target   BLOB NOT NULL,
    by       TEXT NOT NULL,
    by_role  INTEGER NOT NULL,
    kept     INTEGER NOT NULL DEFAULT 0,
    leaf     INTEGER,
    leaf_key BLOB NOT NULL DEFAULT x'',
    PRIMARY KEY (conv, target, by, leaf_key)
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
-- again in each new epoch until applied, 6.1), 'update' (an Update
-- proposal of the own leaf in an epochal group, groupinfo its ProposalRef
-- once made, 12.10; no seed is ever kept here, LR-M2), 'external' (an external commit to a public room, already
-- merged here, posted with the token `-`, 12.7). epoch is the epoch post
-- was made for. state: 'queued', 'sent' (POST in flight), 'posted' (OK
-- seq=), 'done' (applied in order: won, or seen), 'lost' (a commit that
-- lost its epoch, or was refused). not_before delays a retry. A move's
-- commit (7.8) has its new box in move_box, and moved once CREATE made
-- that mailbox.
CREATE TABLE outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL
               CHECK (kind IN ('message', 'live', 'commit', 'proposal', 'update', 'external')),
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
    created    INTEGER NOT NULL,
    move_box   TEXT,
    moved      INTEGER NOT NULL DEFAULT 0,
    -- When it was first seen done or lost, for purge_outbox (LR-M2).
    done_at    INTEGER
);
CREATE INDEX outbox_conv ON outbox (conv, state);

-- What the device knows of each leaf index's messages (12.9, 7.3, 7.4):
-- risala-mls's SenderLog. pseudonym is the pinned one; last_counter and
-- last_id the highest counter seen and its message; gaps the counters
-- missing below it, as pairs of u64; left_group whether it posted a
-- SelfRemove; removals the epochs that commits removing a leaf at this
-- index ended, oldest first, as u64s: the newest, and while a mailbox the
-- group moved from is followed, the newest before that move (12.9).
CREATE TABLE sender_logs (
    conv         INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf         INTEGER NOT NULL,
    pseudonym    BLOB,
    pin_period   INTEGER,
    last_counter INTEGER,
    last_id      BLOB,
    gaps         BLOB NOT NULL,
    left_group   INTEGER NOT NULL DEFAULT 0,
    removals     BLOB NOT NULL DEFAULT x'',
    PRIMARY KEY (conv, leaf)
) WITHOUT ROWID;

-- The t of the commits that ended recent epochs (12.9, late messages),
-- and of the epochs before each move whose old mailbox is followed.
CREATE TABLE epoch_ends (
    conv  INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    t     INTEGER NOT NULL,
    PRIMARY KEY (conv, epoch)
) WITHOUT ROWID;

-- The derived pseudonyms of the leaves of recent past epochs, and of the
-- epochs before each move whose old mailbox is followed, outside public
-- rooms (7.3), to check their late messages (12.9).
CREATE TABLE epoch_pseudonyms (
    conv      INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    epoch     INTEGER NOT NULL,
    leaf      INTEGER NOT NULL,
    pseudonym BLOB NOT NULL,
    PRIMARY KEY (conv, epoch, leaf)
) WITHOUT ROWID;

-- Sealed Welcomes waiting for their random time (12.8), each for one
-- KeyPackage by its ref, with the put secret of its handout (12.5).
-- in_flight is set while WELCOME PUT is in flight.
CREATE TABLE welcomes_out (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    conv       INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    ref        BLOB NOT NULL,
    secret     BLOB NOT NULL,
    welcome    BLOB NOT NULL,
    send_after INTEGER NOT NULL,
    in_flight  INTEGER NOT NULL DEFAULT 0,
    uid        TEXT,
    device     BLOB
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

impl MessageRow {
    /// Whether this device checked the message itself: it sent it, or
    /// received it from a leaf it had confirmed (12.10), not by transfer or
    /// backup (12.13). Only as trusted an edit or DELETE changes it.
    pub fn checked_here(&self) -> bool {
        self.own || (self.verified && !self.restored)
    }
}

/// A DELETE kept until its target arrives or its leaf is confirmed (5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeptDelete {
    /// The deleting identity.
    pub by: Uid,
    /// Whether it held a role that may delete others' messages.
    pub by_role: bool,
    /// The DELETE's leaf and signature key, if this device had not
    /// confirmed it (12.10).
    pub waits_for: Option<(u32, Vec<u8>)>,
}

/// The most DELETEs whose target has not arrived that one sender keeps in
/// a conversation (5.4; LR-L3).
pub(crate) const MAX_KEPT_DELETES: usize = 256;

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
    /// A move's new box (7.8).
    pub move_box: Option<risala_proto::names::BoxName>,
    /// Whether the move's new mailbox was created.
    pub moved: bool,
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
    /// An Update proposal of the own leaf, in an epochal group (12.10).
    Update,
    /// An external commit to a public room, merged already (12.7).
    External,
}

impl OutboxKind {
    fn as_str(self) -> &'static str {
        match self {
            OutboxKind::Message => "message",
            OutboxKind::Live => "live",
            OutboxKind::Commit => "commit",
            OutboxKind::Proposal => "proposal",
            OutboxKind::Update => "update",
            OutboxKind::External => "external",
        }
    }

    fn parse(s: &str) -> Result<OutboxKind, StoreError> {
        Ok(match s {
            "message" => OutboxKind::Message,
            "live" => OutboxKind::Live,
            "commit" => OutboxKind::Commit,
            "proposal" => OutboxKind::Proposal,
            "update" => OutboxKind::Update,
            "external" => OutboxKind::External,
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
     welcome, intent, state, seq, attempts, not_before, move_box, moved";

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
            move_box: row
                .get::<_, Option<String>>(15)?
                .and_then(|b| b.parse().ok()),
            moved: row.get(16)?,
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
    /// The put secret of its handout (12.5).
    pub secret: Vec<u8>,
    /// The sealed Welcome.
    pub welcome: Vec<u8>,
    /// The added device, by uid and device id, to add again if the server
    /// refuses the Welcome (12.8); `None` for a public room's.
    pub device: Option<(Uid, [u8; 48])>,
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

/// A new message, for `Tx::insert_message`.
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
        // 5.4, LR-M2: this device's own copies of what it sent go too: not
        // yet posted, it is not sent; posting, only the post is kept.
        let targets = "SELECT message_id FROM messages
             WHERE conv = ?1 AND own = 1 AND (message_id = ?2 OR edit_of = ?2 OR react_to = ?2)";
        self.conn().execute(
            &format!(
                "DELETE FROM outbox WHERE conv = ?1 AND state IN ('queued', 'done', 'lost')
                   AND message_id IN ({targets})"
            ),
            params![conv.0, id],
        )?;
        self.conn().execute(
            &format!("UPDATE outbox SET body = NULL WHERE conv = ?1 AND message_id IN ({targets})"),
            params![conv.0, id],
        )?;
        self.conn().execute(
            "UPDATE messages SET deleted = 1, text = NULL, content = NULL, frank_key = NULL
             WHERE conv = ?1 AND (message_id = ?2 OR edit_of = ?2 OR react_to = ?2)",
            params![conv.0, id],
        )?;
        self.changed(Change::Message(MessageChange::Messages(conv)));
        Ok(())
    }

    /// Keeps a DELETE whose target has not arrived, or that waits for its
    /// leaf to be confirmed (5.4, 12.10), from a post with `t`.
    /// `waits_for` is the DELETE's leaf and signature key, if this device
    /// has not confirmed it. Any member can send DELETEs for ids that never
    /// come, so each sender keeps at most [`MAX_KEPT_DELETES`] in a
    /// conversation, the newest (LR-L3).
    pub(crate) fn keep_delete(
        &mut self,
        conv: ConversationId,
        target: &[u8; 16],
        by: &Uid,
        by_role: bool,
        waits_for: Option<(u32, &[u8])>,
        t: u64,
    ) -> Result<(), StoreError> {
        let (leaf, key) = match waits_for {
            Some((leaf, key)) => (Some(leaf), key),
            None => (None, &[][..]),
        };
        self.conn().execute(
            "INSERT INTO deletes (conv, target, by, by_role, kept, leaf, leaf_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT DO UPDATE SET by_role = max(by_role, excluded.by_role)",
            params![
                conv.0,
                &target[..],
                by.as_str(),
                by_role,
                t as i64,
                leaf,
                key
            ],
        )?;
        self.conn().execute(
            "DELETE FROM deletes WHERE conv = ?1 AND by = ?2 AND (target, leaf_key) NOT IN (
                 SELECT target, leaf_key FROM deletes WHERE conv = ?1 AND by = ?2
                 ORDER BY kept DESC, target, leaf_key LIMIT ?3)",
            params![conv.0, by.as_str(), MAX_KEPT_DELETES as i64],
        )?;
        if waits_for.is_some() {
            self.changed(Change::Message(MessageChange::Messages(conv)));
        }
        Ok(())
    }

    /// Forgets kept DELETEs from posts before `before`: their targets
    /// would have expired from the mailbox by now (7.5; LR-L3).
    pub(crate) fn expire_deletes(&mut self, before: u64) -> Result<usize, StoreError> {
        Ok(self
            .conn()
            .execute("DELETE FROM deletes WHERE kept < ?1", [before as i64])?)
    }

    /// The DELETEs kept for `target`.
    pub(crate) fn kept_deletes(
        &self,
        conv: ConversationId,
        target: &[u8; 16],
    ) -> Result<Vec<KeptDelete>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT by, by_role, leaf, leaf_key FROM deletes WHERE conv = ?1 AND target = ?2",
        )?;
        let rows = stmt.query_map(params![conv.0, &target[..]], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, Option<u32>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (by, by_role, leaf, key) = row?;
            out.push(KeptDelete {
                by: parse(&by, "uid")?,
                by_role,
                waits_for: leaf.filter(|_| !key.is_empty()).map(|l| (l, key)),
            });
        }
        Ok(out)
    }

    /// The leaves, with their signature keys, that kept DELETEs wait for
    /// (12.10).
    pub(crate) fn delete_leaves(
        &self,
        conv: ConversationId,
    ) -> Result<Vec<(u32, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn().prepare_cached(
            "SELECT DISTINCT leaf, leaf_key FROM deletes
             WHERE conv = ?1 AND leaf IS NOT NULL AND length(leaf_key) > 0",
        )?;
        let rows = stmt.query_map([conv.0], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The DELETEs that waited for a leaf, now confirmed with `key`
    /// (12.10): they count as from a confirmed leaf from now on. Returns
    /// each one's target, sender, and whether it held a role.
    pub(crate) fn confirm_deletes(
        &mut self,
        conv: ConversationId,
        leaf: u32,
        key: &[u8],
    ) -> Result<Vec<([u8; 16], Uid, bool)>, StoreError> {
        let mut out = Vec::new();
        {
            let mut stmt = self.conn().prepare_cached(
                "SELECT target, by, by_role FROM deletes
                 WHERE conv = ?1 AND leaf = ?2 AND leaf_key = ?3",
            )?;
            let rows = stmt.query_map(params![conv.0, leaf, key], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?, r.get(2)?))
            })?;
            for row in rows {
                let (target, by, by_role) = row?;
                let target = opt_fixed(Some(target))?.unwrap_or_default();
                out.push((target, parse(&by, "uid")?, by_role));
            }
        }
        // Where one from a confirmed leaf is kept already, it stays.
        self.conn().execute(
            "UPDATE OR IGNORE deletes SET leaf = NULL, leaf_key = x''
             WHERE conv = ?1 AND leaf = ?2 AND leaf_key = ?3",
            params![conv.0, leaf, key],
        )?;
        self.drop_deletes(conv, leaf, key)?;
        Ok(out)
    }

    /// Drops the DELETEs that wait for a leaf with `key` (12.10): it is an
    /// impostor, or it will never be confirmed with that key.
    pub(crate) fn drop_deletes(
        &mut self,
        conv: ConversationId,
        leaf: u32,
        key: &[u8],
    ) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "DELETE FROM deletes WHERE conv = ?1 AND leaf = ?2 AND leaf_key = ?3",
            params![conv.0, leaf, key],
        )?;
        if n > 0 {
            self.changed(Change::Message(MessageChange::Messages(conv)));
        }
        Ok(())
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
        read::pending_outbox(self.conn(), conv)
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
        // Once posted and applied, or lost, the RisalaMessage and the
        // intent are not needed again: they go at once, and the row a day
        // later (LR-M2, [`Tx::purge_outbox`]).
        self.conn().execute(
            "UPDATE outbox SET state = ?2, seq = coalesce(?3, seq), not_before = ?4,
                    attempts = attempts + (?2 = 'sent'),
                    body = CASE WHEN ?2 IN ('done', 'lost') THEN NULL ELSE body END,
                    intent = CASE WHEN ?2 IN ('done', 'lost') THEN NULL ELSE intent END
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

    /// Sets a move's new box (7.8).
    pub(crate) fn set_outbox_move(
        &mut self,
        id: i64,
        mailbox: &risala_proto::names::BoxName,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE outbox SET move_box = ?2, moved = 0 WHERE id = ?1",
            params![id, mailbox.to_string()],
        )?;
        Ok(())
    }

    /// Notes that a move's new mailbox was created (7.8).
    pub(crate) fn set_moved(&mut self, id: i64) -> Result<(), StoreError> {
        self.conn()
            .execute("UPDATE outbox SET moved = 1 WHERE id = ?1", [id])?;
        Ok(())
    }

    /// The outbox row whose last post is `post`, if any.
    /// Deletes outbox rows that have been done or lost for `keep` ms
    /// (LR-M2): long enough for a post to come back from the mailbox and
    /// be matched to its row; after that the mailbox's sync point is past
    /// it (7.4). Rows are stamped with `now` the first time this sees them
    /// done, so run it every few minutes. Returns how many went.
    pub(crate) fn purge_outbox(&mut self, now: u64, keep: u64) -> Result<usize, StoreError> {
        self.conn().execute(
            "UPDATE outbox SET done_at = ?1 WHERE state IN ('done', 'lost') AND done_at IS NULL",
            [now as i64],
        )?;
        Ok(self.conn().execute(
            "DELETE FROM outbox WHERE state IN ('done', 'lost') AND done_at <= ?1",
            [now.saturating_sub(keep) as i64],
        )?)
    }

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

    /// Queues a Welcome, to send after `send_after` (12.8), for the device
    /// `device` if it is known.
    pub(crate) fn queue_welcome(
        &mut self,
        conv: ConversationId,
        reference: &[u8],
        secret: &[u8],
        welcome: &[u8],
        send_after: u64,
        device: Option<(&Uid, &[u8; 48])>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO welcomes_out (conv, ref, secret, welcome, send_after, uid, device)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                conv.0,
                reference,
                secret,
                welcome,
                send_after as i64,
                device.map(|(u, _)| u.as_str()),
                device.map(|(_, d)| &d[..])
            ],
        )?;
        Ok(())
    }

    /// Notes an Update proposal's ProposalRef, kept in its row's
    /// `groupinfo` (12.3, 12.10).
    pub(crate) fn set_outbox_reference(
        &mut self,
        id: i64,
        reference: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE outbox SET groupinfo = ?2 WHERE id = ?1",
            params![id, reference],
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
                "SELECT w.id, w.conv, w.ref, w.secret, w.welcome, w.uid, w.device
                 FROM welcomes_out w JOIN conversations c ON c.id = w.conv
                 WHERE c.account = ?1 AND w.in_flight = 0 AND w.send_after <= ?2 ORDER BY w.id",
            )?;
            let rows = stmt.query_map(params![account.0, now as i64], |r| {
                let uid: Option<String> = r.get(5)?;
                let device: Option<Vec<u8>> = r.get(6)?;
                let device = match (uid.and_then(|u| u.parse().ok()), device) {
                    (Some(u), Some(d)) => <[u8; 48]>::try_from(d.as_slice()).ok().map(|d| (u, d)),
                    _ => None,
                };
                Ok(WelcomeOut {
                    id: r.get(0)?,
                    conv: ConversationId(r.get(1)?),
                    reference: r.get(2)?,
                    secret: r.get(3)?,
                    welcome: r.get(4)?,
                    device,
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

    pub fn pending_outbox(
        conn: &rusqlite::Connection,
        conv: ConversationId,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        let mut stmt = conn.prepare_cached(&format!(
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

    /// The messages of a conversation that a DELETE from a leaf this
    /// device has not confirmed asks to delete (5.4, 12.10): shown as
    /// deleted but unconfirmed, until the leaf is confirmed or found an
    /// impostor.
    pub fn unconfirmed_deletes(
        &self,
        conv: ConversationId,
    ) -> Result<std::collections::BTreeSet<[u8; 16]>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT DISTINCT d.target FROM deletes d
                 JOIN messages m ON m.conv = d.conv AND m.message_id = d.target
                 WHERE d.conv = ?1 AND length(d.leaf_key) > 0 AND m.deleted = 0
                   AND (d.by = m.sender OR d.by_role)",
            )?;
            let rows = stmt.query_map([conv.0], |r| r.get::<_, Vec<u8>>(0))?;
            let mut out = std::collections::BTreeSet::new();
            for row in rows {
                if let Some(id) = opt_fixed(Some(row?))? {
                    out.insert(id);
                }
            }
            Ok(out)
        })
    }

    /// A conversation's outbox rows that are not done, oldest first.
    pub(crate) fn pending_outbox_rows(
        &self,
        conv: ConversationId,
    ) -> Result<Vec<OutboxRow>, StoreError> {
        self.read(|conn| read::pending_outbox(conn, conv))
    }

    /// The gaps of a conversation (7.4).
    pub fn gap_rows(&self, conv: ConversationId) -> Result<Vec<GapRow>, StoreError> {
        self.read(|conn| read::gaps(conn, conv))
    }
}

/// The message history of one group in the cache (12.9): risala-mls's
/// [`MessageHistory`](risala_mls::message::MessageHistory), on a
/// connection that may be a write transaction's. Its methods cannot fail,
/// so the first error is kept in [`error`](Self::error) for the caller to
/// check.
pub(crate) struct MessageLog<'c> {
    conn: &'c rusqlite::Connection,
    conv: ConversationId,
    /// The first error, if any.
    pub error: Option<StoreError>,
}

impl<'c> MessageLog<'c> {
    /// The log of `conv`, on `conn`.
    pub(crate) fn new(conn: &'c rusqlite::Connection, conv: ConversationId) -> MessageLog<'c> {
        MessageLog {
            conn,
            conv,
            error: None,
        }
    }

    fn keep<T: Default>(&mut self, r: Result<T, rusqlite::Error>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => {
                self.error.get_or_insert(e.into());
                T::default()
            }
        }
    }

    /// Gives back the first error.
    pub(crate) fn finish(self) -> Result<(), StoreError> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn encode_gaps(gaps: &[(u64, u64)]) -> Vec<u8> {
    gaps.iter()
        .flat_map(|(a, b)| a.to_be_bytes().into_iter().chain(b.to_be_bytes()))
        .collect()
}

/// A list of epochs as a JSON array, for `json_each` in SQL.
fn json_list(epochs: &[u64]) -> String {
    let items: Vec<String> = epochs.iter().map(u64::to_string).collect();
    format!("[{}]", items.join(","))
}

fn encode_removals(removals: &[u64]) -> Vec<u8> {
    removals.iter().flat_map(|e| e.to_be_bytes()).collect()
}

fn decode_removals(bytes: &[u8]) -> Vec<u64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_be_bytes(*c))
        .collect()
}

impl MessageLog<'_> {
    /// The epochs that [`MessageHistory::moves`] keep, as a list for SQL.
    ///
    /// [`MessageHistory::moves`]: risala_mls::message::MessageHistory::moves
    fn moved_epochs(&self) -> Vec<u64> {
        use risala_mls::message::MessageHistory as _;
        self.moves().iter().flat_map(|m| m.epochs()).collect()
    }
}

fn decode_gaps(bytes: &[u8]) -> Vec<(u64, u64)> {
    bytes
        .as_chunks::<16>()
        .0
        .iter()
        .map(|c| {
            let (a, b) = c.split_at(8);
            (
                u64::from_be_bytes(a.try_into().expect("8 bytes")),
                u64::from_be_bytes(b.try_into().expect("8 bytes")),
            )
        })
        .collect()
}

impl risala_mls::message::MessageHistory for MessageLog<'_> {
    fn seen(&self, id: &risala_proto::content::MessageId) -> bool {
        self.conn
            .query_row(
                "SELECT (SELECT count(*) FROM messages WHERE conv = ?1 AND message_id = ?2)
                      + (SELECT count(*) FROM seen WHERE conv = ?1 AND message_id = ?2)",
                params![self.conv.0, &id.as_bytes()[..]],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            // Unknown: treated as seen, so nothing is shown twice.
            .unwrap_or(true)
    }

    fn add_seen(&mut self, id: risala_proto::content::MessageId) {
        let r = self
            .conn
            .execute(
                "INSERT INTO seen (conv, message_id) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![self.conv.0, &id.as_bytes()[..]],
            )
            .map(drop);
        self.keep(r);
    }

    fn sender(
        &self,
        leaf: risala_mls::openmls::prelude::LeafNodeIndex,
    ) -> risala_mls::message::SenderLog {
        type Row = (
            Option<Vec<u8>>,
            Option<i64>,
            Option<Vec<u8>>,
            Vec<u8>,
            bool,
            Vec<u8>,
            Option<i64>,
        );
        let row: Option<Row> = self
            .conn
            .query_row(
                "SELECT pseudonym, last_counter, last_id, gaps, left_group, removals, pin_period
                 FROM sender_logs WHERE conv = ?1 AND leaf = ?2",
                params![self.conv.0, leaf.u32()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .unwrap_or_default();
        let Some((pseudonym, counter, id, gaps, left, removals, pin_period)) = row else {
            return risala_mls::message::SenderLog::default();
        };
        let fixed16 = |b: Vec<u8>| <[u8; 16]>::try_from(b.as_slice()).ok();
        risala_mls::message::SenderLog {
            pseudonym: pseudonym.and_then(fixed16).map(risala_mls::Pseudonym),
            pin_period: pin_period.map(|p| p as u64),
            last: match (counter, id.and_then(fixed16)) {
                (Some(c), Some(id)) => {
                    Some((c as u64, risala_proto::content::MessageId::from_bytes(id)))
                }
                _ => None,
            },
            gaps: decode_gaps(&gaps),
            left,
            removals: decode_removals(&removals),
        }
    }

    fn set_sender(
        &mut self,
        leaf: risala_mls::openmls::prelude::LeafNodeIndex,
        log: risala_mls::message::SenderLog,
    ) {
        let r = self
            .conn
            .execute(
                "INSERT INTO sender_logs (conv, leaf, pseudonym, last_counter, last_id, gaps,
                                          left_group, removals, pin_period)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (conv, leaf) DO UPDATE SET pseudonym = excluded.pseudonym,
                    last_counter = excluded.last_counter, last_id = excluded.last_id,
                    gaps = excluded.gaps, left_group = excluded.left_group,
                    removals = excluded.removals, pin_period = excluded.pin_period",
                params![
                    self.conv.0,
                    leaf.u32(),
                    log.pseudonym.map(|p| p.0.to_vec()),
                    log.last.map(|(c, _)| c as i64),
                    log.last.map(|(_, id)| id.as_bytes().to_vec()),
                    encode_gaps(&log.gaps),
                    log.left,
                    encode_removals(&log.removals),
                    log.pin_period.map(|p| p as i64),
                ],
            )
            .map(drop);
        self.keep(r);
    }

    fn epoch_end(&self, epoch: u64) -> Option<risala_proto::time::Timestamp> {
        self.conn
            .query_row(
                "SELECT t FROM epoch_ends WHERE conv = ?1 AND epoch = ?2",
                params![self.conv.0, epoch as i64],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .and_then(|t| risala_proto::time::Timestamp::from_unix_millis(t as u64))
    }

    fn epoch_pseudonym(
        &self,
        epoch: u64,
        leaf: risala_mls::openmls::prelude::LeafNodeIndex,
    ) -> Option<risala_mls::Pseudonym> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT pseudonym FROM epoch_pseudonyms WHERE conv = ?1 AND epoch = ?2 AND leaf = ?3",
                params![self.conv.0, epoch as i64, leaf.u32()],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        bytes
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .map(risala_mls::Pseudonym)
    }

    fn set_epoch_pseudonyms(&mut self, pseudonyms: risala_mls::aad::EpochPseudonyms) {
        let epoch = pseudonyms.epoch as i64;
        let mut r = Ok(());
        for (leaf, p) in &pseudonyms.leaves {
            if r.is_ok() {
                r = self
                    .conn
                    .execute(
                        "INSERT INTO epoch_pseudonyms (conv, epoch, leaf, pseudonym)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT (conv, epoch, leaf) DO UPDATE SET pseudonym = excluded.pseudonym",
                        params![self.conv.0, epoch, leaf, &p.0[..]],
                    )
                    .map(drop);
            }
        }
        // A device holds the secrets of at most 2 past epochs (12.9),
        // besides those of the moves it follows.
        let kept = self.moved_epochs();
        let r = r.and_then(|_| {
            self.conn
                .execute(
                    "DELETE FROM epoch_pseudonyms WHERE conv = ?1 AND epoch + 2 < ?2
                       AND epoch NOT IN (SELECT value FROM json_each(?3))",
                    params![self.conv.0, epoch, json_list(&kept)],
                )
                .map(drop)
        });
        self.keep(r);
    }

    fn moves(&self) -> Vec<risala_mls::message::Moved> {
        // As apply_one judges a post in a mailbox the group moved from:
        // as of the epoch the next mailbox starts at (12.9).
        let mut stmt = match self.conn.prepare_cached(
            "SELECT o.first_epoch,
                    (SELECT min(n.first_epoch) FROM mailboxes n
                     WHERE n.conv = o.conv AND n.first_epoch > o.first_epoch)
             FROM mailboxes o WHERE o.conv = ?1 AND o.current = 0
             ORDER BY o.first_epoch",
        ) {
            Ok(stmt) => stmt,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params![self.conv.0], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<i64>>(1)?))
        });
        let Ok(rows) = rows else {
            return Vec::new();
        };
        rows.filter_map(|r| match r {
            Ok((from, Some(to))) => Some(risala_mls::message::Moved {
                from: from as u64,
                to: to as u64,
            }),
            _ => None,
        })
        .collect()
    }

    fn set_epoch_end(&mut self, epoch: u64, t: risala_proto::time::Timestamp) {
        let r = self
            .conn
            .execute(
                "INSERT INTO epoch_ends (conv, epoch, t) VALUES (?1, ?2, ?3)
                 ON CONFLICT (conv, epoch) DO UPDATE SET t = excluded.t",
                params![self.conv.0, epoch as i64, t.unix_millis() as i64],
            )
            .and_then(|_| {
                // The rules of 12.9 look back two epochs; keep 16, and
                // those of the moves followed.
                self.conn.execute(
                    "DELETE FROM epoch_ends WHERE conv = ?1 AND epoch + 16 < ?2
                       AND epoch NOT IN (SELECT value FROM json_each(?3))",
                    params![self.conv.0, epoch as i64, json_list(&self.moved_epochs())],
                )
            })
            .map(drop);
        self.keep(r);
    }
}

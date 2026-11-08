//! Conversations: the MLS groups this device is in, their mailboxes and
//! sync points, their leaves, the posts waiting to be applied, the
//! KeyPackages this device made, and blocks (5, 6, 7, 12.4, 12.5, 12.7).
//!
//! Owned by task C2. The groups' MLS state is OpenMLS's, in the `mls`
//! module's tables; the rows here are what the cache keeps beside it.
//! Every value shown comes from the group (5.1): kind, name, topic and
//! roles are read from the conversation extension (12.4) each time a
//! commit is applied, never from the server.

use rusqlite::{OptionalExtension as _, Row, params};

use risala_proto::names::{BoxName, Uid};

use super::{AccountId, Change, Store, StoreError, Tx, parse, row_id};

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- One row per group this device is in, or was in, for one account (5.1).
-- kind is from the conversation extension (12.4), with 'self' for the
-- conversation with yourself. name, topic and room come from the
-- extension too; peer is the other identity of a direct conversation.
-- epoch is the epoch the device holds, epoch_t the t of the post that
-- started it (12.9, late messages). pseudonym is this device's leaf's
-- (7.3); sent and last_sent its counter and previous message id (12.9).
-- read_seq is the read marker (7.7) on the current mailbox. state:
-- 'creating' until its first commit won, 'active', 'leaving' after its
-- PART, 'left' once removed, 'dropped' after DROP (6.1), 'failed' if
-- creating it failed. last_resort: joined with a last-resort KeyPackage,
-- so it must commit a new leaf key before it sends (12.5). prev_token is
-- the send token of the epoch before the current one, for TOKEN (7.2).
CREATE TABLE conversations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account       INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    group_id      BLOB NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('direct', 'self', 'private', 'public')),
    room          TEXT,
    name          TEXT NOT NULL DEFAULT '',
    topic         TEXT NOT NULL DEFAULT '',
    peer          TEXT,
    epoch         INTEGER NOT NULL DEFAULT 0,
    epoch_t       INTEGER,
    pseudonym     BLOB NOT NULL,
    sent          INTEGER NOT NULL DEFAULT 0,
    last_sent     BLOB,
    read_seq      INTEGER NOT NULL DEFAULT 0,
    state         TEXT NOT NULL DEFAULT 'active'
                  CHECK (state IN ('creating', 'active', 'leaving', 'left', 'dropped', 'failed')),
    last_resort   INTEGER NOT NULL DEFAULT 0,
    created       INTEGER NOT NULL,
    last_activity INTEGER,
    prev_token    BLOB,
    UNIQUE (account, group_id)
);

-- The mailboxes of each conversation (5.2, 7.8): the current one, where
-- the device posts, and an old one it keeps following for a day after a
-- move. sync_point and head are those of 7.4. follow_after delays the
-- first FOLLOW of a mailbox learned from a Welcome (7.4). first_epoch is
-- the epoch a moved mailbox starts at; posts of earlier epochs in it, and
-- of that epoch or later in the one it moved from, are ignored (7.8).
CREATE TABLE mailboxes (
    conv         INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    box          TEXT NOT NULL,
    current      INTEGER NOT NULL DEFAULT 1,
    first_epoch  INTEGER NOT NULL DEFAULT 0,
    sync_point   INTEGER NOT NULL DEFAULT 0,
    head         INTEGER,
    follow_after INTEGER,
    unfollow_at  INTEGER,
    PRIMARY KEY (conv, box)
) WITHOUT ROWID;
CREATE INDEX mailboxes_box ON mailboxes (box);

-- Posts received or fetched but not yet applied, by mailbox and seq
-- (7.2, 7.4). They are applied in seq order once every earlier one has
-- been, then deleted. next is a commit's (5.2).
CREATE TABLE posts (
    conv    INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    box     TEXT NOT NULL,
    seq     INTEGER NOT NULL,
    t       INTEGER NOT NULL,
    message BLOB NOT NULL,
    next    BLOB,
    PRIMARY KEY (conv, box, seq)
) WITHOUT ROWID;

-- The leaves of each group as this device knows them, refreshed from the
-- group's tree after each commit (12.3, 12.7). device_id is NULL for a
-- guest's leaf. What is known of its messages is in sender_logs
-- (messages.rs). display_name and
-- updated come from its profile (8.2, 12.3). self_removed: it posted a
-- SelfRemove (6.1). resync_seq: it posted RESYNC for the commit at that
-- seq (12.7).
CREATE TABLE leaves (
    conv         INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    leaf         INTEGER NOT NULL,
    uid          TEXT NOT NULL,
    device_id    BLOB,
    signature_key BLOB NOT NULL,
    display_name TEXT,
    updated      INTEGER,
    self_removed INTEGER NOT NULL DEFAULT 0,
    resync_seq   INTEGER,
    PRIMARY KEY (conv, leaf)
) WITHOUT ROWID;

-- What the device saw of each group's recent commits, for the group
-- checks that look back (12.7): risala-mls's History, as JSON.
CREATE TABLE group_state (
    conv    INTEGER PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    history TEXT NOT NULL
);

-- The KeyPackages this device made and uploaded with KEYPKG ADD (12.5), by
-- KeyPackageRef, so that a sealed Welcome can be opened with the right
-- one (12.8). Their private keys are OpenMLS's.
CREATE TABLE key_packages (
    account     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    ref         BLOB NOT NULL,
    last_resort INTEGER NOT NULL DEFAULT 0,
    created     INTEGER NOT NULL,
    PRIMARY KEY (account, ref)
) WITHOUT ROWID;

-- Blocks (5.7), per account, synced with BLOCK and UNBLOCK in the
-- conversation with yourself. target is a uid or `*@<domain>`.
CREATE TABLE blocks (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    target  TEXT NOT NULL,
    t       INTEGER NOT NULL,
    PRIMARY KEY (account, target)
) WITHOUT ROWID;
";

row_id!(
    /// A conversation in the cache.
    ConversationId
);

/// A change to conversations or their members.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConversationChange {
    /// A conversation was added, or its summary changed.
    Conversation(ConversationId),
    /// A conversation's leaves, members or profiles changed.
    Members(ConversationId),
    /// Blocks changed.
    Blocks,
}

/// The kind of a conversation, as the cache keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConvKind {
    /// A direct conversation between two identities (5.1).
    Direct,
    /// The conversation with yourself (5.1, 12.13).
    WithYourself,
    /// A private room.
    Private,
    /// A public room.
    Public,
}

impl ConvKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ConvKind::Direct => "direct",
            ConvKind::WithYourself => "self",
            ConvKind::Private => "private",
            ConvKind::Public => "public",
        }
    }

    fn parse(s: &str) -> Result<ConvKind, StoreError> {
        Ok(match s {
            "direct" => ConvKind::Direct,
            "self" => ConvKind::WithYourself,
            "private" => ConvKind::Private,
            "public" => ConvKind::Public,
            other => return Err(StoreError::Corrupt(format!("conversation kind {other:?}"))),
        })
    }
}

/// Where a conversation is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConvState {
    /// Created here; its first commit has not won yet.
    Creating,
    /// In the group.
    Active,
    /// Left with PART (6.1), until a commit removes the leaf.
    Leaving,
    /// No longer in the group: removed, or left.
    Left,
    /// An operator dropped its mailbox (6.1).
    Dropped,
    /// Creating it failed.
    Failed,
}

impl ConvState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ConvState::Creating => "creating",
            ConvState::Active => "active",
            ConvState::Leaving => "leaving",
            ConvState::Left => "left",
            ConvState::Dropped => "dropped",
            ConvState::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Result<ConvState, StoreError> {
        Ok(match s {
            "creating" => ConvState::Creating,
            "active" => ConvState::Active,
            "leaving" => ConvState::Leaving,
            "left" => ConvState::Left,
            "dropped" => ConvState::Dropped,
            "failed" => ConvState::Failed,
            other => return Err(StoreError::Corrupt(format!("conversation state {other:?}"))),
        })
    }

    /// Whether the device is still in the group.
    pub fn in_group(self) -> bool {
        matches!(
            self,
            ConvState::Creating | ConvState::Active | ConvState::Leaving
        )
    }
}

/// A conversation row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvRow {
    /// Its id.
    pub id: ConversationId,
    /// The account.
    pub account: AccountId,
    /// The MLS group id.
    pub group_id: Vec<u8>,
    /// Its kind.
    pub kind: ConvKind,
    /// A public room's name.
    pub room: Option<String>,
    /// Its name, from the extension.
    pub name: String,
    /// Its topic.
    pub topic: String,
    /// The other identity of a direct conversation.
    pub peer: Option<Uid>,
    /// The epoch the device holds.
    pub epoch: u64,
    /// The `t` of the post that started that epoch.
    pub epoch_t: Option<u64>,
    /// This device's leaf's pseudonym (7.3).
    pub pseudonym: [u8; 16],
    /// How many messages this leaf has written (12.9).
    pub sent: u64,
    /// The id of this leaf's previous message.
    pub last_sent: Option<[u8; 16]>,
    /// The read marker (7.7).
    pub read_seq: u64,
    /// Where it is in its life.
    pub state: ConvState,
    /// Joined with a last-resort KeyPackage, and not yet replaced (12.5).
    pub last_resort: bool,
    /// When it was created here.
    pub created: u64,
    /// When the newest message was sent.
    pub last_activity: Option<u64>,
}

const CONV_COLUMNS: &str = "id, account, group_id, kind, room, name, topic, peer, epoch, \
     epoch_t, pseudonym, sent, last_sent, read_seq, state, last_resort, created, last_activity";

fn fixed<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("bad {what}")))
}

fn conv_row(row: &Row<'_>) -> rusqlite::Result<ConvRowRaw> {
    Ok(ConvRowRaw {
        id: row.get(0)?,
        account: row.get(1)?,
        group_id: row.get(2)?,
        kind: row.get(3)?,
        room: row.get(4)?,
        name: row.get(5)?,
        topic: row.get(6)?,
        peer: row.get(7)?,
        epoch: row.get(8)?,
        epoch_t: row.get(9)?,
        pseudonym: row.get(10)?,
        sent: row.get(11)?,
        last_sent: row.get(12)?,
        read_seq: row.get(13)?,
        state: row.get(14)?,
        last_resort: row.get(15)?,
        created: row.get(16)?,
        last_activity: row.get(17)?,
    })
}

struct ConvRowRaw {
    id: i64,
    account: i64,
    group_id: Vec<u8>,
    kind: String,
    room: Option<String>,
    name: String,
    topic: String,
    peer: Option<String>,
    epoch: i64,
    epoch_t: Option<i64>,
    pseudonym: Vec<u8>,
    sent: i64,
    last_sent: Option<Vec<u8>>,
    read_seq: i64,
    state: String,
    last_resort: bool,
    created: i64,
    last_activity: Option<i64>,
}

impl ConvRowRaw {
    fn into_row(self) -> Result<ConvRow, StoreError> {
        Ok(ConvRow {
            id: ConversationId(self.id),
            account: AccountId(self.account),
            group_id: self.group_id,
            kind: ConvKind::parse(&self.kind)?,
            room: self.room,
            name: self.name,
            topic: self.topic,
            peer: self.peer.map(|p| parse(&p, "uid")).transpose()?,
            epoch: self.epoch as u64,
            epoch_t: self.epoch_t.map(|t| t as u64),
            pseudonym: fixed(self.pseudonym, "pseudonym")?,
            sent: self.sent as u64,
            last_sent: self.last_sent.map(|b| fixed(b, "message id")).transpose()?,
            read_seq: self.read_seq as u64,
            state: ConvState::parse(&self.state)?,
            last_resort: self.last_resort,
            created: self.created as u64,
            last_activity: self.last_activity.map(|t| t as u64),
        })
    }
}

/// A new conversation, for [`Tx::insert_conversation`].
#[derive(Debug, Clone)]
pub struct NewConversation<'a> {
    /// The account.
    pub account: AccountId,
    /// The MLS group id.
    pub group_id: &'a [u8],
    /// Its kind.
    pub kind: ConvKind,
    /// A public room's name.
    pub room: Option<&'a str>,
    /// Its name.
    pub name: &'a str,
    /// Its topic.
    pub topic: &'a str,
    /// The other identity of a direct conversation.
    pub peer: Option<&'a Uid>,
    /// The epoch the device holds.
    pub epoch: u64,
    /// This device's leaf's pseudonym.
    pub pseudonym: [u8; 16],
    /// Its state.
    pub state: ConvState,
    /// Joined with a last-resort KeyPackage.
    pub last_resort: bool,
    /// Now, in ms.
    pub now: u64,
}

/// A mailbox of a conversation (7.4, 7.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRow {
    /// The conversation.
    pub conv: ConversationId,
    /// The box.
    pub mailbox: BoxName,
    /// Whether the device posts here.
    pub current: bool,
    /// The first epoch of a moved mailbox.
    pub first_epoch: u64,
    /// The sync point (7.4).
    pub sync_point: u64,
    /// The head FOLLOW last reported.
    pub head: Option<u64>,
    /// Not to be followed before this time.
    pub follow_after: Option<u64>,
    /// An old mailbox, to unfollow at this time (7.8).
    pub unfollow_at: Option<u64>,
}

fn mailbox_row(row: &Row<'_>) -> rusqlite::Result<MailboxRaw> {
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
}

type MailboxRaw = (
    i64,
    String,
    bool,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn into_mailbox(raw: MailboxRaw) -> Result<MailboxRow, StoreError> {
    let (conv, mailbox, current, first_epoch, sync_point, head, follow_after, unfollow_at) = raw;
    Ok(MailboxRow {
        conv: ConversationId(conv),
        mailbox: parse(&mailbox, "box")?,
        current,
        first_epoch: first_epoch as u64,
        sync_point: sync_point as u64,
        head: head.map(|h| h as u64),
        follow_after: follow_after.map(|t| t as u64),
        unfollow_at: unfollow_at.map(|t| t as u64),
    })
}

const MAILBOX_COLUMNS: &str =
    "conv, box, current, first_epoch, sync_point, head, follow_after, unfollow_at";

/// A post waiting to be applied (7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostRow {
    /// Its seq.
    pub seq: u64,
    /// The server's time, in ms.
    pub t: u64,
    /// The MLSMessage.
    pub message: Vec<u8>,
    /// A commit's `next` (5.2).
    pub next: Option<[u8; 48]>,
}

/// A leaf of a group, as the cache keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRow {
    /// Its index.
    pub leaf: u32,
    /// Its identity or guest uid.
    pub uid: Uid,
    /// Its device id; `None` for a guest.
    pub device_id: Option<[u8; 48]>,
    /// Its signature key.
    pub signature_key: Vec<u8>,
    /// Its display name (8.2).
    pub display_name: Option<String>,
    /// Its profile's `updated`.
    pub updated: Option<u64>,
    /// Whether it posted a SelfRemove (6.1).
    pub self_removed: bool,
    /// The seq of the commit it posted RESYNC for (12.7).
    pub resync_seq: Option<u64>,
}

const LEAF_COLUMNS: &str =
    "leaf, uid, device_id, signature_key, display_name, updated, self_removed, resync_seq";

fn leaf_row(row: &Row<'_>) -> rusqlite::Result<LeafRaw> {
    Ok(LeafRaw {
        leaf: row.get(0)?,
        uid: row.get(1)?,
        device_id: row.get(2)?,
        signature_key: row.get(3)?,
        display_name: row.get(4)?,
        updated: row.get(5)?,
        self_removed: row.get(6)?,
        resync_seq: row.get(7)?,
    })
}

struct LeafRaw {
    leaf: i64,
    uid: String,
    device_id: Option<Vec<u8>>,
    signature_key: Vec<u8>,
    display_name: Option<String>,
    updated: Option<i64>,
    self_removed: bool,
    resync_seq: Option<i64>,
}

impl LeafRaw {
    fn into_row(self) -> Result<LeafRow, StoreError> {
        Ok(LeafRow {
            leaf: self.leaf as u32,
            uid: parse(&self.uid, "uid")?,
            device_id: self.device_id.map(|d| fixed(d, "device id")).transpose()?,
            signature_key: self.signature_key,
            display_name: self.display_name,
            updated: self.updated.map(|u| u as u64),
            self_removed: self.self_removed,
            resync_seq: self.resync_seq.map(|s| s as u64),
        })
    }
}

/// A leaf as the group's tree has it, for [`Tx::sync_leaves`].
#[derive(Debug, Clone)]
pub struct TreeLeaf {
    /// Its index.
    pub leaf: u32,
    /// Its uid.
    pub uid: Uid,
    /// Its device id; `None` for a guest.
    pub device_id: Option<[u8; 48]>,
    /// Its signature key.
    pub signature_key: Vec<u8>,
    /// Its display name.
    pub display_name: Option<String>,
    /// Its profile's `updated`.
    pub updated: Option<u64>,
}

fn query_all<T, R>(
    conn: &rusqlite::Connection,
    sql: &str,
    params: impl rusqlite::Params,
    map: fn(&Row<'_>) -> rusqlite::Result<R>,
    into: impl Fn(R) -> Result<T, StoreError>,
) -> Result<Vec<T>, StoreError> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(params, map)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(into(row?)?);
    }
    Ok(out)
}

/// Reads shared by [`Tx`] and [`Store`].
pub(crate) mod read {
    use super::*;

    pub fn conversation(
        conn: &rusqlite::Connection,
        id: ConversationId,
    ) -> Result<Option<ConvRow>, StoreError> {
        conn.query_row(
            &format!("SELECT {CONV_COLUMNS} FROM conversations WHERE id = ?1"),
            [id.0],
            conv_row,
        )
        .optional()?
        .map(ConvRowRaw::into_row)
        .transpose()
    }

    pub fn conversations(
        conn: &rusqlite::Connection,
        account: AccountId,
    ) -> Result<Vec<ConvRow>, StoreError> {
        query_all(
            conn,
            &format!(
                "SELECT {CONV_COLUMNS} FROM conversations WHERE account = ?1
                 ORDER BY coalesce(last_activity, created) DESC, id DESC"
            ),
            [account.0],
            conv_row,
            ConvRowRaw::into_row,
        )
    }

    pub fn by_group(
        conn: &rusqlite::Connection,
        account: AccountId,
        group_id: &[u8],
    ) -> Result<Option<ConvRow>, StoreError> {
        conn.query_row(
            &format!(
                "SELECT {CONV_COLUMNS} FROM conversations WHERE account = ?1 AND group_id = ?2"
            ),
            params![account.0, group_id],
            conv_row,
        )
        .optional()?
        .map(ConvRowRaw::into_row)
        .transpose()
    }

    pub fn mailboxes(
        conn: &rusqlite::Connection,
        conv: ConversationId,
    ) -> Result<Vec<MailboxRow>, StoreError> {
        query_all(
            conn,
            &format!(
                "SELECT {MAILBOX_COLUMNS} FROM mailboxes WHERE conv = ?1 ORDER BY current DESC"
            ),
            [conv.0],
            mailbox_row,
            into_mailbox,
        )
    }

    pub fn account_mailboxes(
        conn: &rusqlite::Connection,
        account: AccountId,
    ) -> Result<Vec<MailboxRow>, StoreError> {
        query_all(
            conn,
            "SELECT m.conv, m.box, m.current, m.first_epoch, m.sync_point, m.head,
                    m.follow_after, m.unfollow_at
             FROM mailboxes m JOIN conversations c ON c.id = m.conv
             WHERE c.account = ?1 AND c.state IN ('creating', 'active', 'leaving')
             ORDER BY m.conv, m.current DESC",
            [account.0],
            mailbox_row,
            into_mailbox,
        )
    }

    pub fn mailbox(
        conn: &rusqlite::Connection,
        account: AccountId,
        mailbox: &BoxName,
    ) -> Result<Option<MailboxRow>, StoreError> {
        conn.query_row(
            "SELECT m.conv, m.box, m.current, m.first_epoch, m.sync_point, m.head,
                    m.follow_after, m.unfollow_at
             FROM mailboxes m JOIN conversations c ON c.id = m.conv
             WHERE c.account = ?1 AND m.box = ?2",
            params![account.0, mailbox.to_string()],
            mailbox_row,
        )
        .optional()?
        .map(into_mailbox)
        .transpose()
    }

    pub fn leaves(
        conn: &rusqlite::Connection,
        conv: ConversationId,
    ) -> Result<Vec<LeafRow>, StoreError> {
        query_all(
            conn,
            &format!("SELECT {LEAF_COLUMNS} FROM leaves WHERE conv = ?1 ORDER BY leaf"),
            [conv.0],
            leaf_row,
            LeafRaw::into_row,
        )
    }

    pub fn leaf(
        conn: &rusqlite::Connection,
        conv: ConversationId,
        leaf: u32,
    ) -> Result<Option<LeafRow>, StoreError> {
        conn.query_row(
            &format!("SELECT {LEAF_COLUMNS} FROM leaves WHERE conv = ?1 AND leaf = ?2"),
            params![conv.0, leaf],
            leaf_row,
        )
        .optional()?
        .map(LeafRaw::into_row)
        .transpose()
    }

    pub fn blocks(
        conn: &rusqlite::Connection,
        account: AccountId,
    ) -> Result<Vec<String>, StoreError> {
        query_all(
            conn,
            "SELECT target FROM blocks WHERE account = ?1 ORDER BY target",
            [account.0],
            |r| r.get::<_, String>(0),
            Ok,
        )
    }

    pub fn key_package_refs(
        conn: &rusqlite::Connection,
        account: AccountId,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        query_all(
            conn,
            "SELECT ref FROM key_packages WHERE account = ?1 ORDER BY last_resort, created",
            [account.0],
            |r| r.get::<_, Vec<u8>>(0),
            Ok,
        )
    }
}

impl Tx<'_> {
    /// Adds a conversation.
    pub(crate) fn insert_conversation(
        &mut self,
        new: &NewConversation<'_>,
    ) -> Result<ConversationId, StoreError> {
        self.conn().execute(
            "INSERT INTO conversations
               (account, group_id, kind, room, name, topic, peer, epoch, pseudonym, state,
                last_resort, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                new.account.0,
                new.group_id,
                new.kind.as_str(),
                new.room,
                new.name,
                new.topic,
                new.peer.map(Uid::as_str),
                new.epoch as i64,
                &new.pseudonym[..],
                new.state.as_str(),
                new.last_resort,
                new.now as i64,
            ],
        )?;
        let id = ConversationId(self.conn().last_insert_rowid());
        self.changed(Change::Conversation(ConversationChange::Conversation(id)));
        Ok(id)
    }

    /// A conversation.
    pub(crate) fn conversation(&self, id: ConversationId) -> Result<ConvRow, StoreError> {
        read::conversation(self.conn(), id)?.ok_or(StoreError::NotFound("conversation"))
    }

    /// The conversation of a group, if the account has it.
    pub(crate) fn conversation_by_group(
        &self,
        account: AccountId,
        group_id: &[u8],
    ) -> Result<Option<ConvRow>, StoreError> {
        read::by_group(self.conn(), account, group_id)
    }

    /// The account's conversations.
    pub(crate) fn conversations_of(&self, account: AccountId) -> Result<Vec<ConvRow>, StoreError> {
        read::conversations(self.conn(), account)
    }

    /// Updates what the conversation extension says (12.4).
    pub(crate) fn set_conversation_info(
        &mut self,
        id: ConversationId,
        name: &str,
        topic: &str,
        room: Option<&str>,
    ) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE conversations SET name = ?2, topic = ?3, room = ?4
             WHERE id = ?1 AND (name IS NOT ?2 OR topic IS NOT ?3 OR room IS NOT ?4)",
            params![id.0, name, topic, room],
        )?;
        if n > 0 {
            self.changed(Change::Conversation(ConversationChange::Conversation(id)));
        }
        Ok(())
    }

    /// Sets the epoch the device holds, and the `t` of the post that
    /// started it.
    pub(crate) fn set_epoch(
        &mut self,
        id: ConversationId,
        epoch: u64,
        t: Option<u64>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE conversations SET epoch = ?2, epoch_t = ?3 WHERE id = ?1",
            params![id.0, epoch as i64, t.map(|t| t as i64)],
        )?;
        Ok(())
    }

    /// Sets the conversation's state.
    pub(crate) fn set_state(
        &mut self,
        id: ConversationId,
        state: ConvState,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE conversations SET state = ?2 WHERE id = ?1",
            params![id.0, state.as_str()],
        )?;
        self.changed(Change::Conversation(ConversationChange::Conversation(id)));
        Ok(())
    }

    /// Keeps the send token of the epoch just ended, for TOKEN (7.2).
    pub(crate) fn set_prev_token(
        &mut self,
        id: ConversationId,
        token: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE conversations SET prev_token = ?2 WHERE id = ?1",
            params![id.0, &token[..]],
        )?;
        Ok(())
    }

    /// The send token of the epoch before the current one (7.2).
    pub(crate) fn prev_token(&self, id: ConversationId) -> Result<Option<[u8; 32]>, StoreError> {
        let token: Option<Vec<u8>> = self.conn().query_row(
            "SELECT prev_token FROM conversations WHERE id = ?1",
            [id.0],
            |r| r.get(0),
        )?;
        Ok(token.and_then(|t| t.try_into().ok()))
    }

    /// Clears the last-resort mark, once a new leaf key is committed (12.5).
    pub(crate) fn clear_last_resort(&mut self, id: ConversationId) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE conversations SET last_resort = 0 WHERE id = ?1",
            [id.0],
        )?;
        Ok(())
    }

    /// Keeps the leaf's send counter (12.9): how many messages it has
    /// written, and the last one's id. Stored before the message is
    /// posted, so that a crash never makes two messages with one counter.
    pub(crate) fn set_send_counter(
        &mut self,
        id: ConversationId,
        written: u64,
        last: Option<[u8; 16]>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE conversations SET sent = ?2, last_sent = ?3 WHERE id = ?1",
            params![id.0, written as i64, last.as_ref().map(|l| &l[..])],
        )?;
        Ok(())
    }

    /// Notes activity at `t`, for the chat list.
    pub(crate) fn touch(&mut self, id: ConversationId, t: u64) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE conversations SET last_activity = max(coalesce(last_activity, 0), ?2)
             WHERE id = ?1",
            params![id.0, t as i64],
        )?;
        self.changed(Change::Conversation(ConversationChange::Conversation(id)));
        Ok(())
    }

    /// Moves the read marker forward to `seq` (7.7). Returns whether it
    /// moved.
    pub(crate) fn mark_read(&mut self, id: ConversationId, seq: u64) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE conversations SET read_seq = ?2 WHERE id = ?1 AND read_seq < ?2",
            params![id.0, seq as i64],
        )?;
        if n > 0 {
            self.changed(Change::Conversation(ConversationChange::Conversation(id)));
        }
        Ok(n > 0)
    }

    // ---- mailboxes

    /// Adds a mailbox to a conversation. A current one makes every other
    /// one old.
    pub(crate) fn add_mailbox(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
        current: bool,
        first_epoch: u64,
        follow_after: Option<u64>,
    ) -> Result<(), StoreError> {
        if current {
            self.conn()
                .execute("UPDATE mailboxes SET current = 0 WHERE conv = ?1", [conv.0])?;
        }
        self.conn().execute(
            "INSERT INTO mailboxes (conv, box, current, first_epoch, follow_after)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (conv, box) DO UPDATE SET current = excluded.current",
            params![
                conv.0,
                mailbox.to_string(),
                current,
                first_epoch as i64,
                follow_after.map(|t| t as i64)
            ],
        )?;
        Ok(())
    }

    /// A conversation's mailboxes, the current one first.
    pub(crate) fn mailboxes(&self, conv: ConversationId) -> Result<Vec<MailboxRow>, StoreError> {
        read::mailboxes(self.conn(), conv)
    }

    /// The current mailbox of a conversation.
    pub(crate) fn current_mailbox(&self, conv: ConversationId) -> Result<MailboxRow, StoreError> {
        self.mailboxes(conv)?
            .into_iter()
            .find(|m| m.current)
            .ok_or(StoreError::NotFound("current mailbox"))
    }

    /// The mailbox `mailbox` of the account, with its conversation.
    pub(crate) fn mailbox(
        &self,
        account: AccountId,
        mailbox: &BoxName,
    ) -> Result<Option<MailboxRow>, StoreError> {
        read::mailbox(self.conn(), account, mailbox)
    }

    /// Every mailbox the account follows: those of conversations it is
    /// in.
    pub(crate) fn account_mailboxes(
        &self,
        account: AccountId,
    ) -> Result<Vec<MailboxRow>, StoreError> {
        read::account_mailboxes(self.conn(), account)
    }

    /// Sets a mailbox's sync point and head.
    pub(crate) fn set_sync(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
        sync_point: u64,
        head: Option<u64>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE mailboxes SET sync_point = ?3, head = coalesce(?4, head)
             WHERE conv = ?1 AND box = ?2",
            params![
                conv.0,
                mailbox.to_string(),
                sync_point as i64,
                head.map(|h| h as i64)
            ],
        )?;
        Ok(())
    }

    /// Clears a mailbox's `follow_after`, once it is followed.
    pub(crate) fn clear_follow_after(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE mailboxes SET follow_after = NULL WHERE conv = ?1 AND box = ?2",
            params![conv.0, mailbox.to_string()],
        )?;
        Ok(())
    }

    /// Marks a mailbox old, to unfollow at `at` (7.8).
    pub(crate) fn retire_mailbox(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
        at: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE mailboxes SET current = 0, unfollow_at = ?3 WHERE conv = ?1 AND box = ?2",
            params![conv.0, mailbox.to_string(), at as i64],
        )?;
        Ok(())
    }

    /// Removes a mailbox from a conversation, with its waiting posts.
    pub(crate) fn remove_mailbox(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
    ) -> Result<(), StoreError> {
        let b = mailbox.to_string();
        self.conn().execute(
            "DELETE FROM posts WHERE conv = ?1 AND box = ?2",
            params![conv.0, b],
        )?;
        self.conn().execute(
            "DELETE FROM mailboxes WHERE conv = ?1 AND box = ?2",
            params![conv.0, b],
        )?;
        Ok(())
    }

    // ---- posts

    /// Keeps a post until it is applied. A post already kept, or at or
    /// before the sync point, is a duplicate: returns false.
    pub(crate) fn keep_post(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
        post: &PostRow,
    ) -> Result<bool, StoreError> {
        let b = mailbox.to_string();
        let sync: Option<i64> = self
            .conn()
            .query_row(
                "SELECT sync_point FROM mailboxes WHERE conv = ?1 AND box = ?2",
                params![conv.0, b],
                |r| r.get(0),
            )
            .optional()?;
        let Some(sync) = sync else {
            return Ok(false);
        };
        if post.seq <= sync as u64 {
            return Ok(false);
        }
        let n = self.conn().execute(
            "INSERT INTO posts (conv, box, seq, t, message, next) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT DO NOTHING",
            params![
                conv.0,
                b,
                post.seq as i64,
                post.t as i64,
                post.message,
                post.next.as_ref().map(|n| &n[..])
            ],
        )?;
        Ok(n > 0)
    }

    /// The kept post right after the sync point, if there is one.
    pub(crate) fn post_at(
        &self,
        conv: ConversationId,
        mailbox: &BoxName,
        seq: u64,
    ) -> Result<Option<PostRow>, StoreError> {
        self.conn()
            .query_row(
                "SELECT seq, t, message, next FROM posts WHERE conv = ?1 AND box = ?2 AND seq = ?3",
                params![conv.0, mailbox.to_string(), seq as i64],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()?
            .map(|(seq, t, message, next)| {
                Ok(PostRow {
                    seq: seq as u64,
                    t: t as u64,
                    message,
                    next: next.map(|n| fixed(n, "next")).transpose()?,
                })
            })
            .transpose()
    }

    /// The lowest seq kept for a mailbox, if any.
    pub(crate) fn first_kept_seq(
        &self,
        conv: ConversationId,
        mailbox: &BoxName,
    ) -> Result<Option<u64>, StoreError> {
        let seq: Option<i64> = self.conn().query_row(
            "SELECT min(seq) FROM posts WHERE conv = ?1 AND box = ?2",
            params![conv.0, mailbox.to_string()],
            |r| r.get(0),
        )?;
        Ok(seq.map(|s| s as u64))
    }

    /// Drops a kept post, once applied.
    pub(crate) fn drop_post(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
        seq: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM posts WHERE conv = ?1 AND box = ?2 AND seq = ?3",
            params![conv.0, mailbox.to_string(), seq as i64],
        )?;
        Ok(())
    }

    /// Drops every kept post of a mailbox, when its sync point starts
    /// again (7.4).
    pub(crate) fn drop_posts(
        &mut self,
        conv: ConversationId,
        mailbox: &BoxName,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM posts WHERE conv = ?1 AND box = ?2",
            params![conv.0, mailbox.to_string()],
        )?;
        Ok(())
    }

    // ---- leaves

    /// Replaces the conversation's leaves with the tree's, keeping what the
    /// cache knows of leaves that are still the same leaf (same index and
    /// credential). Returns whether anything changed.
    pub(crate) fn sync_leaves(
        &mut self,
        conv: ConversationId,
        tree: &[TreeLeaf],
    ) -> Result<bool, StoreError> {
        let old = read::leaves(self.conn(), conv)?;
        let mut changed = old.len() != tree.len();
        for leaf in tree {
            let same = old.iter().find(|o| {
                o.leaf == leaf.leaf && o.uid == leaf.uid && o.device_id == leaf.device_id
            });
            match same {
                Some(o) => {
                    if o.signature_key != leaf.signature_key
                        || o.display_name != leaf.display_name
                        || o.updated != leaf.updated
                    {
                        changed = true;
                        self.conn().execute(
                            "UPDATE leaves SET signature_key = ?3, display_name = ?4, updated = ?5
                             WHERE conv = ?1 AND leaf = ?2",
                            params![
                                conv.0,
                                leaf.leaf,
                                leaf.signature_key,
                                leaf.display_name,
                                leaf.updated.map(|u| u as i64)
                            ],
                        )?;
                    }
                }
                None => {
                    changed = true;
                    self.conn().execute(
                        "DELETE FROM leaves WHERE conv = ?1 AND leaf = ?2",
                        params![conv.0, leaf.leaf],
                    )?;
                    self.conn().execute(
                        "INSERT INTO leaves (conv, leaf, uid, device_id, signature_key, display_name, updated)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            conv.0,
                            leaf.leaf,
                            leaf.uid.as_str(),
                            leaf.device_id.as_ref().map(|d| &d[..]),
                            leaf.signature_key,
                            leaf.display_name,
                            leaf.updated.map(|u| u as i64)
                        ],
                    )?;
                }
            }
        }
        for o in &old {
            if !tree.iter().any(|l| l.leaf == o.leaf) {
                changed = true;
                self.conn().execute(
                    "DELETE FROM leaves WHERE conv = ?1 AND leaf = ?2",
                    params![conv.0, o.leaf],
                )?;
            }
        }
        if changed {
            self.changed(Change::Conversation(ConversationChange::Members(conv)));
        }
        Ok(changed)
    }

    /// One leaf.
    pub(crate) fn leaf(
        &self,
        conv: ConversationId,
        leaf: u32,
    ) -> Result<Option<LeafRow>, StoreError> {
        read::leaf(self.conn(), conv, leaf)
    }

    /// Marks that a leaf posted a SelfRemove (6.1).
    pub(crate) fn mark_self_removed(
        &mut self,
        conv: ConversationId,
        leaf: u32,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE leaves SET self_removed = 1 WHERE conv = ?1 AND leaf = ?2",
            params![conv.0, leaf],
        )?;
        self.changed(Change::Conversation(ConversationChange::Members(conv)));
        Ok(())
    }

    /// Marks that a leaf posted RESYNC for the commit at `seq` (12.7).
    pub(crate) fn mark_resync(
        &mut self,
        conv: ConversationId,
        leaf: u32,
        seq: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE leaves SET resync_seq = ?3 WHERE conv = ?1 AND leaf = ?2",
            params![conv.0, leaf, seq as i64],
        )?;
        Ok(())
    }

    // ---- the group's history (12.7)

    /// The group's [`History`](risala_mls::checks::History), for the
    /// checks that look back.
    pub(crate) fn group_history(
        &self,
        conv: ConversationId,
    ) -> Result<risala_mls::checks::History, StoreError> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT history FROM group_state WHERE conv = ?1",
                [conv.0],
                |r| r.get(0),
            )
            .optional()?;
        match json {
            None => Ok(risala_mls::checks::History::default()),
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| StoreError::Corrupt(format!("a group's history: {e}"))),
        }
    }

    /// Keeps the group's history.
    pub(crate) fn set_group_history(
        &mut self,
        conv: ConversationId,
        history: &risala_mls::checks::History,
    ) -> Result<(), StoreError> {
        let json = serde_json::to_string(history)
            .map_err(|e| StoreError::Corrupt(format!("a group's history: {e}")))?;
        self.conn().execute(
            "INSERT INTO group_state (conv, history) VALUES (?1, ?2)
             ON CONFLICT (conv) DO UPDATE SET history = excluded.history",
            params![conv.0, json],
        )?;
        Ok(())
    }

    // ---- KeyPackages

    /// Records a KeyPackage this device uploaded (12.5).
    pub(crate) fn add_key_package(
        &mut self,
        account: AccountId,
        reference: &[u8],
        last_resort: bool,
        now: u64,
    ) -> Result<(), StoreError> {
        if last_resort {
            self.conn().execute(
                "DELETE FROM key_packages WHERE account = ?1 AND last_resort = 1",
                [account.0],
            )?;
        }
        self.conn().execute(
            "INSERT INTO key_packages (account, ref, last_resort, created) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO NOTHING",
            params![account.0, reference, last_resort, now as i64],
        )?;
        Ok(())
    }

    /// The refs of the KeyPackages this device made, ordinary ones first.
    pub(crate) fn key_package_refs(&self, account: AccountId) -> Result<Vec<Vec<u8>>, StoreError> {
        read::key_package_refs(self.conn(), account)
    }

    /// Forgets a KeyPackage that a Welcome used, unless it is the last
    /// resort, which stays (12.5).
    pub(crate) fn used_key_package(
        &mut self,
        account: AccountId,
        reference: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM key_packages WHERE account = ?1 AND ref = ?2 AND last_resort = 0",
            params![account.0, reference],
        )?;
        Ok(())
    }

    // ---- blocks

    /// Blocks or unblocks `target` (5.7). Returns whether anything
    /// changed.
    pub(crate) fn set_block(
        &mut self,
        account: AccountId,
        target: &str,
        blocked: bool,
        now: u64,
    ) -> Result<bool, StoreError> {
        let n = if blocked {
            self.conn().execute(
                "INSERT INTO blocks (account, target, t) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                params![account.0, target, now as i64],
            )?
        } else {
            self.conn().execute(
                "DELETE FROM blocks WHERE account = ?1 AND target = ?2",
                params![account.0, target],
            )?
        };
        if n > 0 {
            self.changed(Change::Conversation(ConversationChange::Blocks));
        }
        Ok(n > 0)
    }

    /// The account's blocks.
    pub(crate) fn blocks(&self, account: AccountId) -> Result<Vec<String>, StoreError> {
        read::blocks(self.conn(), account)
    }
}

/// Whether `uid` is covered by one of `blocks` (5.7): the uid itself, or
/// `*@<domain>` for its domain or a parent domain.
pub fn is_blocked(blocks: &[String], uid: &Uid) -> bool {
    let uid = uid.as_str().to_ascii_lowercase();
    let domain = uid.rsplit_once('@').map(|(_, d)| d.to_owned());
    blocks.iter().any(|b| {
        let b = b.to_ascii_lowercase();
        if b == uid {
            return true;
        }
        match (b.strip_prefix("*@"), &domain) {
            (Some(blocked), Some(d)) => d == blocked || d.ends_with(&format!(".{blocked}")),
            _ => false,
        }
    })
}

impl Store {
    /// The account's conversations, newest activity first.
    pub fn conversation_rows(&self, account: AccountId) -> Result<Vec<ConvRow>, StoreError> {
        self.read(|conn| read::conversations(conn, account))
    }

    /// One conversation.
    pub fn conversation_row(&self, id: ConversationId) -> Result<Option<ConvRow>, StoreError> {
        self.read(|conn| read::conversation(conn, id))
    }

    /// A conversation's mailboxes.
    pub fn mailbox_rows(&self, id: ConversationId) -> Result<Vec<MailboxRow>, StoreError> {
        self.read(|conn| read::mailboxes(conn, id))
    }

    /// A conversation's leaves.
    pub fn leaf_rows(&self, id: ConversationId) -> Result<Vec<LeafRow>, StoreError> {
        self.read(|conn| read::leaves(conn, id))
    }

    /// The account's blocks (5.7).
    pub fn block_rows(&self, account: AccountId) -> Result<Vec<String>, StoreError> {
        self.read(|conn| read::blocks(conn, account))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_cover_domains() {
        let blocks = vec!["*@example.net".to_owned(), "eve@example.org".to_owned()];
        let uid = |s: &str| s.parse::<Uid>().unwrap();
        assert!(is_blocked(&blocks, &uid("eve@example.org")));
        assert!(is_blocked(&blocks, &uid("bob@example.net")));
        assert!(is_blocked(&blocks, &uid("bob@chat.example.net")));
        assert!(!is_blocked(&blocks, &uid("bob@example.org")));
        assert!(!is_blocked(&blocks, &uid("bob@badexample.net")));
    }
}

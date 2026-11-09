//! [`MailboxStore`] on SQLite, and the tables of mailboxes, posts and
//! public rooms (5.2, 6, 7).

use rusqlite::{OptionalExtension as _, Transaction, params};
use sha2::{Digest as _, Sha384};

use std::time::Duration;

use risala_proto::mls::{GroupId, Pseudonym, TokenHash};
use risala_proto::names::{BlobRef, BoxName, Room, Uid};
use risala_proto::time::Timestamp;
use risala_proto::types::Role;

use super::{SqliteStore, from_sql_u64, sql_u64};
use crate::secret::ct_eq;
use crate::store::mailbox::{
    AddedBy, CID_LIFETIME, MAX_SET_NEXT_HASHES, MAX_SET_TOKEN_HASHES, MAX_SETS, post_line_bytes,
};
use crate::store::{
    Created, Expired, KeptPost, MailboxRecord, MailboxStore, NewMailbox, NewPost, NewRoom,
    PostBody, Posted, PublicRoomRecord, Result, RoomChange, RoomGroup, RoomUpdate, StoreError,
    StoredPost, coarse, fixed, millis, parsed, timestamp,
};

/// The mailbox area's tables.
pub(super) const SCHEMA: &str = "
-- Every box and group id the server has seen, by SHA-384 hash (5.2): a
-- box is never used again, and a group id gets a new mailbox only as a
-- move (7.8), even once its mailboxes are gone.
CREATE TABLE used_ids (
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)), -- 1 a box, 2 a group id
    hash BLOB NOT NULL CHECK (length(hash) = 48),
    PRIMARY KEY (kind, hash)
) STRICT, WITHOUT ROWID;

-- The mailboxes the server holds (5.2). A dropped or ended one is deleted
-- (7.5, 10.4); used_ids remembers its box.
CREATE TABLE mailboxes (
    box BLOB PRIMARY KEY CHECK (length(box) = 16),
    group_id BLOB NOT NULL,         -- shared by the mailboxes a group moved through
    first_epoch INTEGER NOT NULL DEFAULT 0 CHECK (first_epoch >= 0), -- 0, or a move's (7.8)
    moved_from BLOB REFERENCES mailboxes (box) ON DELETE SET NULL, -- for TOKEN (7.2, 7.8)
    created INTEGER NOT NULL,       -- ms, to the hour (4.2)
    head INTEGER NOT NULL DEFAULT 0 CHECK (head >= 0), -- the newest seq given out
    bytes INTEGER NOT NULL DEFAULT 0 CHECK (bytes >= 0), -- of its kept posts, for its quota (7.5)
    active INTEGER NOT NULL         -- ms of its newest post, or of its creation, to the hour (7.5)
) STRICT;
CREATE INDEX mailboxes_group ON mailboxes (group_id, created);

-- The sets of send token hashes (7.2), per mailbox and epoch: at most 16
-- hashes that commits and CREATE added and 64 that TOKEN added, each with
-- when it was added and last used by a post.
CREATE TABLE token_hashes (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    hash BLOB NOT NULL CHECK (length(hash) = 48),
    added INTEGER NOT NULL,         -- ms, to the hour (4.2)
    used INTEGER,                   -- ms of the last post that used it, to the hour
    token INTEGER NOT NULL DEFAULT 0 CHECK (token IN (0, 1)), -- 1 if TOKEN added it, 0 a commit or CREATE
    PRIMARY KEY (box, epoch, hash)
) STRICT; -- with a rowid, the order hashes were added in

-- Kept posts (5.2), until they expire (7.5): their box, seq, time and
-- message, and a commit's next, only (4.2).
CREATE TABLE posts (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    seq INTEGER NOT NULL CHECK (seq >= 1),
    t INTEGER NOT NULL,             -- ms, when the server accepted it
    message BLOB,                   -- the MLSMessage, or NULL if it is a blob
    blob BLOB CHECK (length(blob) = 48), -- the blob's hash, if it is one (12.12)
    next BLOB CHECK (length(next) = 48), -- a commit's next= token hash (5.2, 7.2)
    handshake INTEGER NOT NULL DEFAULT 0 CHECK (handshake IN (0, 1)), -- 1 for a commit or
                                    -- proposal, which do not expire early (7.5)
    UNIQUE (box, seq),
    CHECK ((message IS NULL) != (blob IS NULL))
) STRICT;
-- Retention expires each mailbox's posts oldest first (7.5).
CREATE INDEX posts_t ON posts (t);
-- The bytes of each mailbox's kept posts, for its quota (7.5).
CREATE TRIGGER posts_bytes_in AFTER INSERT ON posts BEGIN
    UPDATE mailboxes SET bytes = bytes + coalesce(length(NEW.message), 0) WHERE box = NEW.box;
END;
CREATE TRIGGER posts_bytes_out AFTER DELETE ON posts BEGIN
    UPDATE mailboxes SET bytes = max(0, bytes - coalesce(length(OLD.message), 0)) WHERE box = OLD.box;
END;

-- Client post ids (7.6), for 24 hours.
CREATE TABLE cids (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    cid TEXT NOT NULL,
    seq INTEGER NOT NULL,           -- the post it made
    t INTEGER NOT NULL,             -- ms
    PRIMARY KEY (box, cid)
) STRICT;
CREATE INDEX cids_t ON cids (t);

-- Public rooms (6.1): the public state of each one's group as of its
-- newest epoch (12.6), and what LIST, INFO and the join checks read from
-- it. Deleting the mailbox frees the name (7.5, 10.4).
CREATE TABLE public_rooms (
    box BLOB PRIMARY KEY REFERENCES mailboxes (box) ON DELETE CASCADE,
    room TEXT NOT NULL UNIQUE,      -- '#name', in lower case
    creator TEXT NOT NULL,          -- the identity that created it
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    epoch_seq INTEGER NOT NULL,     -- the seq of the commit that began the epoch, 0 in epoch 0
    group_info BLOB NOT NULL,       -- the GroupInfo, or its blob's hash
    group_info_is_blob INTEGER NOT NULL DEFAULT 0,
    tree BLOB NOT NULL,             -- the ratchet tree, or its blob's hash
    tree_is_blob INTEGER NOT NULL DEFAULT 0,
    members INTEGER NOT NULL DEFAULT 1, -- identities and guests with a leaf (6.1)
    topic TEXT NOT NULL DEFAULT '', -- escaped, from the conversation extension (6.2)
    guests TEXT NOT NULL DEFAULT 'write' CHECK (guests IN ('none', 'read', 'write')),
    epoch_state BLOB NOT NULL DEFAULT x'' -- what the group checks need of the epoch (12.7)
) STRICT;

-- The proposals pending in each public room's current epoch (12.6), one
-- row each, in the order they were posted.
CREATE TABLE room_proposals (
    box BLOB NOT NULL REFERENCES public_rooms (box) ON DELETE CASCADE,
    n INTEGER NOT NULL CHECK (n >= 0), -- its place in the epoch's proposals
    message BLOB NOT NULL,          -- the MLSMessage
    PRIMARY KEY (box, n)
) STRICT, WITHOUT ROWID;

-- The uids with a leaf in each public room's group (6.1, 8.3), and their
-- roles in its conversation extension (6.3).
CREATE TABLE room_members (
    box BLOB NOT NULL REFERENCES public_rooms (box) ON DELETE CASCADE,
    uid TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'mod', 'member')),
    PRIMARY KEY (box, uid)
) STRICT, WITHOUT ROWID;
CREATE INDEX room_members_uid ON room_members (uid);

-- Muted pseudonyms (6.4, 10.4).
CREATE TABLE mutes (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    pseudonym BLOB NOT NULL CHECK (length(pseudonym) = 16),
    until INTEGER NOT NULL,         -- ms
    PRIMARY KEY (box, pseudonym)
) STRICT, WITHOUT ROWID;
";

/// The kinds of `used_ids`.
const USED_BOX: i64 = 1;
const USED_GROUP: i64 = 2;

/// Whether a box or group id (`kind`) with these bytes was seen before.
fn used(tx: &Transaction<'_>, kind: i64, bytes: &[u8]) -> Result<bool> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM used_ids WHERE kind = ? AND hash = ?",
            params![kind, &Sha384::digest(bytes)[..]],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Remembers a box or group id (`kind`) by its hash.
fn remember(tx: &Transaction<'_>, kind: i64, bytes: &[u8]) -> Result<()> {
    tx.execute(
        "INSERT INTO used_ids (kind, hash) VALUES (?, ?) ON CONFLICT DO NOTHING",
        params![kind, &Sha384::digest(bytes)[..]],
    )?;
    Ok(())
}

/// The `before` of a time `ago` before `now`, in ms.
fn ms_before(now: Timestamp, ago: Duration) -> i64 {
    millis(now).saturating_sub(i64::try_from(ago.as_millis()).unwrap_or(i64::MAX))
}

/// Checks a new mailbox against the boxes and group ids seen before (5.2,
/// 7.8): `Ok(moved_from)`, the newest mailbox of the group for a move, or
/// why it cannot be created.
fn check_new(tx: &Transaction<'_>, new: &NewMailbox) -> Result<Result<Option<Vec<u8>>, Created>> {
    let mailbox = &new.mailbox.as_bytes()[..];
    let group = &new.group_id.as_bytes()[..];
    // A move comes from a mailbox of the same group (7.8).
    let moved_from = match (new.first_epoch, &new.moved_from) {
        (0, _) => None,
        (_, None) => return Ok(Err(Created::NoGroup)),
        (_, Some(from)) => {
            let from = &from.as_bytes()[..];
            let same_group = tx
                .query_row(
                    "SELECT 1 FROM mailboxes WHERE box = ? AND group_id = ?",
                    params![from, group],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !same_group {
                return Ok(Err(Created::NoGroup));
            }
            Some(from.to_vec())
        }
    };
    if used(tx, USED_BOX, mailbox)? {
        // A move to a box that is already the group's mailbox from that
        // epoch changes nothing (7.8).
        let same = new.first_epoch > 0
            && tx
                .query_row(
                    "SELECT 1 FROM mailboxes WHERE box = ? AND group_id = ? AND first_epoch = ?",
                    params![mailbox, group, sql_u64(new.first_epoch)],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
        return Ok(Err(if same {
            Created::Exists
        } else {
            Created::Taken
        }));
    }
    if new.first_epoch == 0 && used(tx, USED_GROUP, group)? {
        return Ok(Err(Created::Taken));
    }
    Ok(Ok(moved_from))
}

/// Inserts a mailbox that [`check_new`] allowed, and its first token set.
fn insert_mailbox(
    tx: &Transaction<'_>,
    new: &NewMailbox,
    moved_from: Option<Vec<u8>>,
) -> Result<()> {
    let mailbox = &new.mailbox.as_bytes()[..];
    let group = &new.group_id.as_bytes()[..];
    remember(tx, USED_BOX, mailbox)?;
    remember(tx, USED_GROUP, group)?;
    let created = coarse(new.created);
    tx.execute(
        "INSERT INTO mailboxes (box, group_id, first_epoch, moved_from, created, active)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![
            mailbox,
            group,
            sql_u64(new.first_epoch),
            moved_from,
            created,
            created
        ],
    )?;
    add_token(
        tx,
        mailbox,
        new.first_epoch,
        &new.token_hash,
        AddedBy::Commit,
        created,
    )
}

/// [`MailboxStore::add_token`], in a transaction.
fn add_token(
    tx: &Transaction<'_>,
    mailbox: &[u8],
    epoch: u64,
    hash: &TokenHash,
    by: AddedBy,
    now: i64,
) -> Result<()> {
    let (part, max) = match by {
        AddedBy::Commit => (0, MAX_SET_NEXT_HASHES),
        AddedBy::Token => (1, MAX_SET_TOKEN_HASHES),
    };
    let epoch = sql_u64(epoch);
    let hash = &hash.as_bytes()[..];
    let held = tx
        .query_row(
            "SELECT 1 FROM token_hashes WHERE box = ? AND epoch = ? AND hash = ?",
            params![mailbox, epoch, hash],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if held {
        return Ok(());
    }
    let in_set: i64 = tx.query_row(
        "SELECT count(*) FROM token_hashes WHERE box = ? AND epoch = ?",
        params![mailbox, epoch],
        |row| row.get(0),
    )?;
    let in_part: i64 = tx.query_row(
        "SELECT count(*) FROM token_hashes WHERE box = ? AND epoch = ? AND token = ?",
        params![mailbox, epoch, part],
        |row| row.get(0),
    )?;
    if in_set == 0 {
        // A new set: the mailbox keeps the MAX_SETS used most recently.
        let sets: i64 = tx.query_row(
            "SELECT count(DISTINCT epoch) FROM token_hashes WHERE box = ?",
            [mailbox],
            |row| row.get(0),
        )?;
        if sets >= MAX_SETS as i64 {
            tx.execute(
                "DELETE FROM token_hashes WHERE box = ?1 AND epoch = (
                     SELECT epoch FROM token_hashes WHERE box = ?1 GROUP BY epoch
                     ORDER BY max(max(added, coalesce(used, 0))), epoch LIMIT 1)",
                [mailbox],
            )?;
        }
    } else if in_part >= max as i64 {
        // A full part drops the hash added first among those no post has
        // used, or the one a post used least recently.
        tx.execute(
            "DELETE FROM token_hashes WHERE rowid = (
                 SELECT rowid FROM token_hashes WHERE box = ?1 AND epoch = ?2 AND token = ?3
                 ORDER BY used IS NOT NULL, coalesce(used, added), rowid LIMIT 1)",
            params![mailbox, epoch, part],
        )?;
    }
    tx.execute(
        "INSERT INTO token_hashes (box, epoch, hash, added, token) VALUES (?, ?, ?, ?, ?)",
        params![mailbox, epoch, hash, now, part],
    )?;
    Ok(())
}

/// Stores a public room's group as of `epoch_seq`, and its members.
fn store_room_group(
    tx: &Transaction<'_>,
    mailbox: &[u8],
    group: &RoomUpdate,
    epoch_seq: u64,
) -> Result<()> {
    let members = group.members.len() as i64;
    tx.execute(
        "UPDATE public_rooms SET epoch = ?, epoch_seq = ?, group_info = ?, tree = ?,
             members = ?, topic = ?, guests = ?, epoch_state = ?
         WHERE box = ?",
        params![
            sql_u64(group.epoch),
            sql_u64(epoch_seq),
            &group.group_info,
            &group.tree,
            members,
            &group.topic,
            group.guests.to_string(),
            &group.state,
            mailbox
        ],
    )?;
    tx.execute("DELETE FROM room_proposals WHERE box = ?", [mailbox])?;
    tx.execute("DELETE FROM room_members WHERE box = ?", [mailbox])?;
    let mut insert =
        tx.prepare_cached("INSERT INTO room_members (box, uid, role) VALUES (?, ?, ?)")?;
    for (uid, role) in &group.members {
        insert.execute(params![mailbox, uid.as_str(), role.to_string()])?;
    }
    Ok(())
}

/// The bytes of the posts `mailbox` keeps (7.5).
fn post_bytes(tx: &Transaction<'_>, mailbox: &[u8]) -> Result<u64> {
    let bytes: Option<i64> = tx
        .query_row(
            "SELECT bytes FROM mailboxes WHERE box = ?",
            [mailbox],
            |row| row.get(0),
        )
        .optional()?;
    from_sql_u64("bytes", bytes.unwrap_or(0))
}

/// Expires the oldest posts of `mailbox` that are not commits or
/// proposals until it keeps at most `max` bytes of posts (7.5). Commits
/// and proposals never expire early: a device that missed one could not
/// read anything after it. Returns how many expired, and whether the
/// posts now fit.
fn trim_posts(tx: &Transaction<'_>, mailbox: &[u8], max: u64) -> Result<(usize, bool)> {
    let mut expired = 0;
    loop {
        if post_bytes(tx, mailbox)? <= max {
            return Ok((expired, true));
        }
        let deleted = tx.execute(
            "DELETE FROM posts WHERE box = ?1 AND seq = (
                 SELECT min(seq) FROM posts WHERE box = ?1 AND handshake = 0)",
            [mailbox],
        )?;
        if deleted == 0 {
            return Ok((expired, false));
        }
        expired += deleted;
    }
}

impl MailboxStore for SqliteStore {
    fn create_mailbox(&self, new: &NewMailbox) -> Result<Created> {
        self.write(|tx| {
            let moved_from = match check_new(tx, new)? {
                Ok(from) => from,
                Err(not) => return Ok(not),
            };
            insert_mailbox(tx, new, moved_from)?;
            Ok(Created::Created)
        })
    }

    fn create_room(&self, new: &NewMailbox, room: &NewRoom) -> Result<Created> {
        self.write(|tx| {
            let moved_from = match check_new(tx, new)? {
                Ok(from) => from,
                Err(not) => return Ok(not),
            };
            let taken = tx
                .query_row(
                    "SELECT 1 FROM public_rooms WHERE room = ?",
                    [room.room.as_str()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if taken {
                return Ok(Created::Taken);
            }
            insert_mailbox(tx, new, moved_from)?;
            let mailbox = &new.mailbox.as_bytes()[..];
            tx.execute(
                "INSERT INTO public_rooms (box, room, creator, epoch, epoch_seq, group_info, tree)
                 VALUES (?, ?, ?, 0, 0, x'', x'')",
                params![mailbox, room.room.as_str(), room.creator.as_str()],
            )?;
            store_room_group(tx, mailbox, &room.group, 0)?;
            Ok(Created::Created)
        })
    }

    fn mailbox(&self, mailbox: &BoxName) -> Result<Option<MailboxRecord>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT m.group_id, m.first_epoch, m.moved_from, m.head, m.created, r.room
                     FROM mailboxes m LEFT JOIN public_rooms r ON r.box = m.box
                     WHERE m.box = ?",
                    [&mailbox.as_bytes()[..]],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .optional()?;
            let Some((group_id, first_epoch, moved_from, head, created, room)) = row else {
                return Ok(None);
            };
            Ok(Some(MailboxRecord {
                mailbox: *mailbox,
                group_id: GroupId::from_bytes(fixed("group id", &group_id)?),
                first_epoch: from_sql_u64("first epoch", first_epoch)?,
                moved_from: moved_from
                    .map(|from| fixed("box", &from).map(BoxName::from_bytes))
                    .transpose()?,
                head: from_sql_u64("head", head)?,
                created: timestamp(created)?,
                room: room.map(|r| parsed("room", &r)).transpose()?,
            }))
        })
    }

    fn cid_post(&self, mailbox: &BoxName, cid: &str, since: Timestamp) -> Result<Option<u64>> {
        self.read(|tx| {
            let seq: Option<i64> = tx
                .query_row(
                    "SELECT seq FROM cids WHERE box = ? AND cid = ? AND t >= ?",
                    params![&mailbox.as_bytes()[..], cid, millis(since)],
                    |row| row.get(0),
                )
                .optional()?;
            seq.map(|seq| from_sql_u64("seq", seq)).transpose()
        })
    }

    fn has_token(&self, mailbox: &BoxName, epoch: u64, hash: &TokenHash) -> Result<bool> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT hash FROM token_hashes WHERE box = ? AND epoch = ? ORDER BY rowid",
            )?;
            let rows = select
                .query_map(params![&mailbox.as_bytes()[..], sql_u64(epoch)], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?;
            // Every hash of the set is compared, each in constant time, so
            // the time says nothing about which one matched (7.2).
            let mut found = false;
            for row in rows {
                found |= ct_eq(&row?, &hash.as_bytes()[..]);
            }
            Ok(found)
        })
    }

    fn has_token_any(&self, mailbox: &BoxName, hash: &TokenHash) -> Result<bool> {
        self.read(|tx| {
            let mut select =
                tx.prepare_cached("SELECT hash FROM token_hashes WHERE box = ? ORDER BY rowid")?;
            let rows =
                select.query_map([&mailbox.as_bytes()[..]], |row| row.get::<_, Vec<u8>>(0))?;
            let mut found = false;
            for row in rows {
                found |= ct_eq(&row?, &hash.as_bytes()[..]);
            }
            Ok(found)
        })
    }

    fn add_token(
        &self,
        mailbox: &BoxName,
        epoch: u64,
        hash: &TokenHash,
        now: Timestamp,
    ) -> Result<()> {
        self.write(|tx| {
            add_token(
                tx,
                &mailbox.as_bytes()[..],
                epoch,
                hash,
                AddedBy::Token,
                coarse(now),
            )
        })
    }

    fn add_post(&self, post: &NewPost) -> Result<Posted> {
        self.write(|tx| {
            let mailbox = &post.mailbox.as_bytes()[..];
            let head: Option<i64> = tx
                .query_row(
                    "SELECT head FROM mailboxes WHERE box = ?",
                    [mailbox],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(head) = head else {
                return Ok(Posted::NoMailbox);
            };
            let size = post.message.size();
            if size > post.quota {
                return Ok(Posted::OverQuota);
            }
            // Over its quota, the mailbox's oldest posts expire early (7.5),
            // but not its commits and proposals: if those alone fill it, the
            // post waits until they expire.
            let (_, fits) = trim_posts(tx, mailbox, post.quota - size)?;
            if !fits {
                return Ok(Posted::OverQuota);
            }
            let seq = head + 1;
            let t = millis(post.t);
            let (message, blob) = match &post.message {
                PostBody::Inline(bytes) => (Some(&bytes[..]), None),
                PostBody::Blob(blob) => (None, Some(&blob.hash()[..])),
            };
            tx.execute(
                "INSERT INTO posts (box, seq, t, message, blob, next, handshake)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    mailbox,
                    seq,
                    t,
                    message,
                    blob,
                    post.next.as_ref().map(|(_, next)| &next.as_bytes()[..]),
                    post.handshake
                ],
            )?;
            // Times kept only for retention and order are coarse (4.2).
            let hour = coarse(post.t);
            tx.execute(
                "UPDATE mailboxes SET head = ?, active = ? WHERE box = ?",
                params![seq, hour, mailbox],
            )?;
            if let Some((epoch, hash)) = &post.token {
                tx.execute(
                    "UPDATE token_hashes SET used = ? WHERE box = ? AND epoch = ? AND hash = ?",
                    params![hour, mailbox, sql_u64(*epoch), &hash.as_bytes()[..]],
                )?;
            }
            if let Some((epoch, next)) = &post.next {
                add_token(
                    tx,
                    mailbox,
                    epoch.saturating_add(1),
                    next,
                    AddedBy::Commit,
                    hour,
                )?;
            }
            if let Some(cid) = &post.cid {
                tx.execute(
                    "INSERT INTO cids (box, cid, seq, t) VALUES (?, ?, ?, ?)
                     ON CONFLICT (box, cid) DO UPDATE SET seq = excluded.seq, t = excluded.t",
                    params![mailbox, cid, seq, t],
                )?;
            }
            let seq = from_sql_u64("seq", seq)?;
            match &post.room {
                Some(RoomChange::Commit(group)) => store_room_group(tx, mailbox, group, seq)?,
                Some(RoomChange::Proposal { message, state }) => {
                    tx.execute(
                        "INSERT INTO room_proposals (box, n, message) VALUES (?1, (
                             SELECT count(*) FROM room_proposals WHERE box = ?1), ?2)",
                        params![mailbox, message],
                    )?;
                    tx.execute(
                        "UPDATE public_rooms SET epoch_state = ? WHERE box = ?",
                        params![state, mailbox],
                    )?;
                }
                None => {}
            }
            Ok(Posted::Seq(seq))
        })
    }

    fn posts(
        &self,
        mailbox: &BoxName,
        after: u64,
        limit: u64,
        budget: u64,
    ) -> Result<(Vec<StoredPost>, bool)> {
        self.read(|tx| {
            let box_ = &mailbox.as_bytes()[..];
            // First the page's end, from the lengths of the messages alone,
            // so that no post past the budget is read: `length` of a BLOB
            // does not read it (7.1).
            let mut lengths = tx.prepare_cached(
                "SELECT seq, length(message) FROM posts
                 WHERE box = ? AND seq > ? ORDER BY seq LIMIT ?",
            )?;
            let mut rows = lengths.query(params![
                box_,
                sql_u64(after),
                sql_u64(limit.saturating_add(1))
            ])?;
            let (mut last, mut taken, mut bytes, mut more) = (None, 0u64, 0u64, false);
            while let Some(row) = rows.next()? {
                let inline = row.get::<_, Option<i64>>(1)?.unwrap_or(0);
                let size = post_line_bytes(u64::try_from(inline).unwrap_or(0));
                // The first post always comes, however long, so that a
                // page moves on.
                if taken == limit || (taken > 0 && bytes.saturating_add(size) > budget) {
                    more = true;
                    break;
                }
                last = Some(row.get::<_, i64>(0)?);
                taken += 1;
                bytes = bytes.saturating_add(size);
            }
            drop(rows);
            let Some(last) = last else {
                return Ok((Vec::new(), false));
            };
            let mut select = tx.prepare_cached(
                "SELECT seq, t, message, blob, next FROM posts
                 WHERE box = ? AND seq > ? AND seq <= ? ORDER BY seq",
            )?;
            let rows = select.query_map(params![box_, sql_u64(after), last], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?;
            let mut posts = Vec::new();
            for row in rows {
                let (seq, t, message, blob, next) = row?;
                let message = match (message, blob) {
                    (Some(bytes), _) => PostBody::Inline(bytes),
                    (None, Some(blob)) => PostBody::Blob(BlobRef::from_hash(fixed("blob", &blob)?)),
                    (None, None) => {
                        return Err(StoreError::Corrupt("a post without a message".into()));
                    }
                };
                posts.push(StoredPost {
                    seq: from_sql_u64("seq", seq)?,
                    t: timestamp(t)?,
                    message,
                    next: next
                        .map(|next| fixed("next", &next).map(TokenHash::from_bytes))
                        .transpose()?,
                });
            }
            Ok((posts, more))
        })
    }

    fn mailbox_bytes(&self, mailbox: &BoxName) -> Result<u64> {
        self.read(|tx| post_bytes(tx, &mailbox.as_bytes()[..]))
    }

    fn trim_posts(&self, mailbox: &BoxName, max: u64) -> Result<(usize, bool)> {
        self.write(|tx| trim_posts(tx, &mailbox.as_bytes()[..], max))
    }

    fn muted(&self, mailbox: &BoxName, pseudonym: &Pseudonym, now: Timestamp) -> Result<bool> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT 1 FROM mutes WHERE box = ? AND pseudonym = ? AND until > ?",
                    params![
                        &mailbox.as_bytes()[..],
                        &pseudonym.as_bytes()[..],
                        millis(now)
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    fn room_group(&self, mailbox: &BoxName) -> Result<Option<RoomGroup>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT room, epoch, epoch_seq, group_info, tree, epoch_state
                     FROM public_rooms WHERE box = ?",
                    [&mailbox.as_bytes()[..]],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                        ))
                    },
                )
                .optional()?;
            let Some((room, epoch, epoch_seq, group_info, tree, state)) = row else {
                return Ok(None);
            };
            let mut select =
                tx.prepare_cached("SELECT message FROM room_proposals WHERE box = ? ORDER BY n")?;
            let proposals = select
                .query_map([&mailbox.as_bytes()[..]], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Some(RoomGroup {
                room: parsed("room", &room)?,
                epoch: from_sql_u64("epoch", epoch)?,
                epoch_seq: from_sql_u64("epoch seq", epoch_seq)?,
                group_info,
                tree,
                proposals,
                state,
            }))
        })
    }

    fn room_member(&self, mailbox: &BoxName, uid: &Uid) -> Result<Option<Role>> {
        self.read(|tx| {
            let role: Option<String> = tx
                .query_row(
                    "SELECT role FROM room_members WHERE box = ? AND uid = ?",
                    params![&mailbox.as_bytes()[..], uid.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            role.map(|role| parsed("role", &role)).transpose()
        })
    }

    fn rooms_with_member(&self, uid: &Uid) -> Result<Vec<BoxName>> {
        self.read(|tx| {
            let mut select =
                tx.prepare_cached("SELECT box FROM room_members WHERE uid = ? ORDER BY box")?;
            let rows = select.query_map([uid.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
            rows.map(|row| Ok(BoxName::from_bytes(fixed("box", &row?)?)))
                .collect()
        })
    }

    // What the misc and admin areas read (SV5).

    fn public_rooms(
        &self,
        after: Option<&Room>,
        limit: u64,
        for_guest: bool,
    ) -> Result<(Vec<PublicRoomRecord>, bool)> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT room, box, members, topic, guests, epoch FROM public_rooms
                 WHERE room > ? AND (? = 0 OR guests != 'none')
                 ORDER BY room LIMIT ?",
            )?;
            let mut rows = select.query(params![
                after.map_or("", Room::as_str),
                for_guest,
                sql_u64(limit.saturating_add(1))
            ])?;
            let mut rooms = Vec::new();
            while let Some(row) = rows.next()? {
                rooms.push(public_room(row)?);
            }
            let more = rooms.len() as u64 > limit;
            rooms.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            Ok((rooms, more))
        })
    }

    fn public_room(&self, room: &Room) -> Result<Option<PublicRoomRecord>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT room, box, members, topic, guests, epoch FROM public_rooms WHERE room = ?",
            )?;
            let mut rows = select.query([room.as_str()])?;
            rows.next()?.map(public_room).transpose()
        })
    }

    fn room_members(&self, mailbox: &BoxName) -> Result<Vec<(Uid, Role)>> {
        self.read(|tx| {
            let mut select =
                tx.prepare_cached("SELECT uid, role FROM room_members WHERE box = ? ORDER BY uid")?;
            let rows = select.query_map([&mailbox.as_bytes()[..]], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.map(|row| {
                let (uid, role) = row?;
                Ok((parsed("member", &uid)?, parsed("role", &role)?))
            })
            .collect()
        })
    }

    fn kept_post(&self, mailbox: &BoxName, seq: u64) -> Result<Option<KeptPost>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT t, message, blob FROM posts WHERE box = ? AND seq = ?",
                    params![&mailbox.as_bytes()[..], sql_u64(seq)],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<Vec<u8>>>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((t, message, blob)) = row else {
                return Ok(None);
            };
            let message = match (message, blob) {
                (Some(message), None) => Ok(message),
                (None, Some(blob)) => Err(BlobRef::from_hash(fixed("blob", &blob)?)),
                _ => return Err(StoreError::Corrupt("a post is a message or a blob".into())),
            };
            Ok(Some(KeptPost {
                t: timestamp(t)?,
                message,
            }))
        })
    }

    fn set_mute(&self, mailbox: &BoxName, pseudonym: &Pseudonym, until: Timestamp) -> Result<bool> {
        self.write(|tx| {
            let exists = tx
                .query_row(
                    "SELECT 1 FROM mailboxes WHERE box = ?",
                    [&mailbox.as_bytes()[..]],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if exists {
                tx.execute(
                    "INSERT OR REPLACE INTO mutes (box, pseudonym, until) VALUES (?, ?, ?)",
                    params![
                        &mailbox.as_bytes()[..],
                        &pseudonym.as_bytes()[..],
                        millis(until)
                    ],
                )?;
            }
            Ok(exists)
        })
    }

    fn remove_mute(&self, mailbox: &BoxName, pseudonym: &Pseudonym) -> Result<bool> {
        self.write(|tx| {
            Ok(tx.execute(
                "DELETE FROM mutes WHERE box = ? AND pseudonym = ?",
                params![&mailbox.as_bytes()[..], &pseudonym.as_bytes()[..]],
            )? > 0)
        })
    }

    fn drop_mailbox(&self, mailbox: &BoxName) -> Result<bool> {
        self.write(|tx| {
            Ok(tx.execute(
                "DELETE FROM mailboxes WHERE box = ?",
                [&mailbox.as_bytes()[..]],
            )? > 0)
        })
    }

    fn expire(&self, now: Timestamp, retention: Duration) -> Result<Expired> {
        self.write(|tx| {
            let before = ms_before(now, retention);
            // Oldest first in each mailbox, stopping at its first post that
            // is not old enough, even if a later one is older (7.5).
            let posts = tx.execute(
                "DELETE FROM posts WHERE t < ?1 AND seq < coalesce(
                     (SELECT min(q.seq) FROM posts q WHERE q.box = posts.box AND q.t >= ?1),
                     9223372036854775807)",
                [before],
            )?;
            let cids = tx.execute(
                "DELETE FROM cids WHERE t < ?",
                [ms_before(now, CID_LIFETIME)],
            )?;
            let token_hashes = tx.execute(
                "DELETE FROM token_hashes WHERE (box, epoch) IN (
                     SELECT box, epoch FROM token_hashes GROUP BY box, epoch
                     HAVING max(max(added, coalesce(used, 0))) < ?)",
                [before],
            )?;
            let mutes = tx.execute("DELETE FROM mutes WHERE until <= ?", [millis(now)])?;
            Ok(Expired {
                posts,
                cids,
                token_hashes,
                mutes,
            })
        })
    }

    fn drop_idle_mailbox(&self, mailbox: &BoxName, before: Timestamp) -> Result<bool> {
        self.write(|tx| {
            Ok(tx.execute(
                "DELETE FROM mailboxes WHERE box = ?1 AND active < ?2
                 AND NOT EXISTS (SELECT 1 FROM posts WHERE box = ?1)",
                params![&mailbox.as_bytes()[..], millis(before)],
            )? > 0)
        })
    }

    fn idle_mailboxes(&self, before: Timestamp) -> Result<Vec<BoxName>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT box FROM mailboxes m WHERE active < ?
                 AND NOT EXISTS (SELECT 1 FROM posts p WHERE p.box = m.box) ORDER BY box",
            )?;
            let rows = select.query_map([millis(before)], |row| row.get::<_, Vec<u8>>(0))?;
            rows.map(|row| Ok(BoxName::from_bytes(fixed("box", &row?)?)))
                .collect()
        })
    }
}

/// Reads a row of `room, box, members, topic, guests, epoch` from
/// `public_rooms`.
fn public_room(row: &rusqlite::Row<'_>) -> Result<PublicRoomRecord> {
    let room: String = row.get(0)?;
    let mailbox: Vec<u8> = row.get(1)?;
    let guests: String = row.get(4)?;
    Ok(PublicRoomRecord {
        room: parsed("room", &room)?,
        mailbox: BoxName::from_bytes(fixed("box", &mailbox)?),
        members: from_sql_u64("members", row.get(2)?)?,
        topic: row.get(3)?,
        guests: parsed("guests", &guests)?,
        epoch: from_sql_u64("epoch", row.get(5)?)?,
    })
}

#[cfg(test)]
mod tests {
    use risala_proto::types::GuestAccess;

    use super::*;

    const T0: &str = "2026-11-09T00:00:00.000Z";

    fn t(secs: u64) -> Timestamp {
        T0.parse::<Timestamp>()
            .unwrap()
            .checked_add(Duration::from_secs(secs))
            .unwrap()
    }

    fn hash(n: u8) -> TokenHash {
        TokenHash::from_bytes([n; 48])
    }

    /// A post of `mailbox` at `t` seconds, of `size` bytes.
    fn post(mailbox: BoxName, secs: u64, size: usize) -> NewPost {
        NewPost {
            mailbox,
            t: t(secs),
            message: PostBody::Inline(vec![7; size]),
            token: None,
            next: None,
            cid: None,
            quota: u64::MAX,
            room: None,
            handshake: false,
        }
    }

    fn seqs(store: &SqliteStore, mailbox: &BoxName) -> Vec<u64> {
        let (posts, more) = store.posts(mailbox, 0, 1000, u64::MAX).unwrap();
        assert!(!more);
        posts.iter().map(|p| p.seq).collect()
    }

    fn set(store: &SqliteStore, mailbox: &BoxName, epoch: u64) -> Vec<u8> {
        let conn = store.raw();
        let mut select = conn
            .prepare("SELECT hash FROM token_hashes WHERE box = ? AND epoch = ? ORDER BY rowid")
            .unwrap();
        select
            .query_map(params![&mailbox.as_bytes()[..], epoch as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .unwrap()
            .map(|h| h.unwrap()[0])
            .collect()
    }

    fn new_mailbox(n: u8) -> NewMailbox {
        NewMailbox {
            mailbox: BoxName::from_bytes([n; 16]),
            group_id: GroupId::from_bytes([n; 32]),
            first_epoch: 0,
            moved_from: None,
            token_hash: TokenHash::from_bytes([n; 48]),
            created: "2026-11-09T00:00:00.000Z".parse::<Timestamp>().unwrap(),
        }
    }

    #[test]
    fn boxes_and_group_ids_are_never_used_twice() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = new_mailbox(1);
        assert_eq!(store.mailbox(&first.mailbox).unwrap(), None);
        assert_eq!(store.create_mailbox(&first).unwrap(), Created::Created);
        let record = store.mailbox(&first.mailbox).unwrap().unwrap();
        assert_eq!(record.group_id, first.group_id);
        assert_eq!((record.first_epoch, record.head), (0, 0));
        assert_eq!((record.moved_from, record.room.clone()), (None, None));
        assert_eq!(record.created, first.created);

        // The same box, or the same group id, is taken (5.2).
        let same_box = NewMailbox {
            group_id: GroupId::from_bytes([9; 32]),
            ..first.clone()
        };
        assert_eq!(store.create_mailbox(&same_box).unwrap(), Created::Taken);
        let same_group = NewMailbox {
            mailbox: BoxName::from_bytes([9; 16]),
            ..first.clone()
        };
        assert_eq!(store.create_mailbox(&same_group).unwrap(), Created::Taken);
        assert_eq!(store.mailbox(&same_group.mailbox).unwrap(), None);

        // Its box stays taken once the mailbox is gone (7.5, 10.4), and
        // only its hash is kept.
        let conn = store.raw();
        conn.execute("DELETE FROM mailboxes", []).unwrap();
        let kept: i64 = conn
            .query_row(
                "SELECT count(*) FROM used_ids WHERE length(hash) = 48",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, 2);
        drop(conn);
        assert_eq!(store.mailbox(&first.mailbox).unwrap(), None);
        assert_eq!(store.create_mailbox(&first).unwrap(), Created::Taken);
    }

    /// A group that moves gets a new mailbox with the same group id,
    /// linked to the one it moves from (7.8).
    #[test]
    fn groups_move_to_new_mailboxes() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = new_mailbox(1);
        let moved = |n: u8, epoch: u64, from: u8| NewMailbox {
            mailbox: BoxName::from_bytes([n; 16]),
            first_epoch: epoch,
            moved_from: Some(BoxName::from_bytes([from; 16])),
            ..first.clone()
        };
        // No mailbox to move from yet, or none named.
        assert_eq!(
            store.create_mailbox(&moved(2, 5, 1)).unwrap(),
            Created::NoGroup
        );
        store.create_mailbox(&first).unwrap();
        let unnamed = NewMailbox {
            moved_from: None,
            ..moved(2, 5, 1)
        };
        assert_eq!(store.create_mailbox(&unnamed).unwrap(), Created::NoGroup);
        // Another group's mailbox is no mailbox of this one.
        store.create_mailbox(&new_mailbox(7)).unwrap();
        assert_eq!(
            store.create_mailbox(&moved(2, 5, 7)).unwrap(),
            Created::NoGroup
        );
        assert_eq!(
            store.create_mailbox(&moved(2, 5, 1)).unwrap(),
            Created::Created
        );
        let second = store.mailbox(&moved(2, 5, 1).mailbox).unwrap().unwrap();
        assert_eq!(second.first_epoch, 5);
        assert_eq!(second.moved_from, Some(first.mailbox));
        assert_eq!(second.group_id, first.group_id);
        // A box is never used again, moves included.
        assert_eq!(
            store.create_mailbox(&moved(2, 9, 1)).unwrap(),
            Created::Taken
        );
        // A move from the moved mailbox.
        assert_eq!(
            store.create_mailbox(&moved(3, 9, 2)).unwrap(),
            Created::Created
        );
        // The first epoch's set has the hash.
        let epoch: i64 = store
            .raw()
            .query_row(
                "SELECT epoch FROM token_hashes WHERE box = ?",
                [&second.mailbox.as_bytes()[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(epoch, 5);
    }

    #[test]
    fn members_of_public_rooms() {
        let store = SqliteStore::open_in_memory().unwrap();
        let sam: Uid = "~sam".parse().unwrap();
        assert!(store.rooms_with_member(&sam).unwrap().is_empty());
        for n in [2, 1] {
            let new = new_mailbox(n);
            store.create_mailbox(&new).unwrap();
            let conn = store.raw();
            conn.execute(
                "INSERT INTO public_rooms (box, room, creator, epoch, epoch_seq, group_info, tree)
                 VALUES (?, ?, 'alice@example.org', 0, 0, x'00', x'00')",
                params![&new.mailbox.as_bytes()[..], format!("#room{n}")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO room_members (box, uid) VALUES (?, '~sam')",
                [&new.mailbox.as_bytes()[..]],
            )
            .unwrap();
        }
        assert_eq!(
            store.rooms_with_member(&sam).unwrap(),
            [new_mailbox(1).mailbox, new_mailbox(2).mailbox]
        );
        let room = store.mailbox(&new_mailbox(1).mailbox).unwrap().unwrap();
        assert_eq!(room.room.unwrap().as_str(), "#room1");
    }

    /// A page of posts stops at its budget of bytes, with more, and the
    /// first post comes however long it is; blob posts count as short
    /// lines (7.1).
    #[test]
    fn posts_stop_at_the_budget() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        for i in 1..=10 {
            assert_eq!(
                store.add_post(&post(m.mailbox, i, 3000)).unwrap(),
                Posted::Seq(i)
            );
        }
        let line = post_line_bytes(3000);
        let seqs = |after, limit, budget| {
            let (posts, more) = store.posts(&m.mailbox, after, limit, budget).unwrap();
            (posts.iter().map(|p| p.seq).collect::<Vec<_>>(), more)
        };
        // Three lines' worth, and a byte short of four: three posts.
        assert_eq!(seqs(0, 50, 4 * line - 1), (vec![1, 2, 3], true));
        assert_eq!(seqs(0, 50, 4 * line), (vec![1, 2, 3, 4], true));
        // The limit still cuts first.
        assert_eq!(seqs(0, 2, 4 * line), (vec![1, 2], true));
        // A budget too small for one post: the first comes, alone.
        assert_eq!(seqs(4, 50, 1), (vec![5], true));
        // The end of the mailbox within the budget: no more.
        assert_eq!(seqs(7, 50, 4 * line), (vec![8, 9, 10], false));
        assert_eq!(seqs(10, 50, 1), (vec![], false));
        // Blob posts take a short line each.
        let mut blob = post(m.mailbox, 11, 0);
        blob.message = PostBody::Blob(BlobRef::from_hash([4; 48]));
        assert_eq!(store.add_post(&blob).unwrap(), Posted::Seq(11));
        assert_eq!(
            seqs(9, 50, line + post_line_bytes(0)),
            (vec![10, 11], false)
        );
    }

    /// Posts get the next seq; a commit's next goes into the next epoch's
    /// set and stays with the post; the token is marked used; a cid finds
    /// its post (5.2, 7.2, 7.6).
    #[test]
    fn posts_and_what_comes_with_them() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        assert!(store.has_token(&m.mailbox, 0, &m.token_hash).unwrap());
        assert!(!store.has_token(&m.mailbox, 0, &hash(2)).unwrap());
        assert!(!store.has_token(&m.mailbox, 1, &m.token_hash).unwrap());
        assert!(store.has_token_any(&m.mailbox, &m.token_hash).unwrap());
        assert!(!store.has_token_any(&m.mailbox, &hash(2)).unwrap());

        let mut first = post(m.mailbox, 1, 10);
        first.token = Some((0, m.token_hash));
        first.next = Some((0, hash(5)));
        first.cid = Some("c".repeat(16));
        assert_eq!(store.add_post(&first).unwrap(), Posted::Seq(1));
        assert!(store.has_token(&m.mailbox, 1, &hash(5)).unwrap());
        let used: Option<i64> = store
            .raw()
            .query_row("SELECT used FROM token_hashes WHERE epoch = 0", [], |r| {
                r.get(0)
            })
            .unwrap();
        // To the hour (4.2).
        assert_eq!(used, Some(coarse(t(1))));
        assert_eq!(
            store.add_post(&post(m.mailbox, 2, 20)).unwrap(),
            Posted::Seq(2)
        );
        let record = store.mailbox(&m.mailbox).unwrap().unwrap();
        assert_eq!(record.head, 2);
        assert_eq!(store.mailbox_bytes(&m.mailbox).unwrap(), 30);

        let (posts, more) = store.posts(&m.mailbox, 0, 1, u64::MAX).unwrap();
        assert!(more);
        assert_eq!(posts[0].seq, 1);
        assert_eq!(posts[0].t, t(1));
        assert_eq!(posts[0].next, Some(hash(5)));
        assert_eq!(posts[0].message, PostBody::Inline(vec![7; 10]));
        let (posts, more) = store.posts(&m.mailbox, 1, 50, u64::MAX).unwrap();
        assert!(!more);
        assert_eq!((posts.len(), posts[0].next), (1, None));
        assert!(
            store
                .posts(&m.mailbox, 2, 50, u64::MAX)
                .unwrap()
                .0
                .is_empty()
        );

        assert_eq!(
            store.cid_post(&m.mailbox, &"c".repeat(16), t(0)).unwrap(),
            Some(1)
        );
        assert_eq!(
            store.cid_post(&m.mailbox, &"c".repeat(16), t(2)).unwrap(),
            None
        );
        assert_eq!(
            store.cid_post(&m.mailbox, &"d".repeat(16), t(0)).unwrap(),
            None
        );

        // A blob post counts nothing against the quota here (12.12).
        let mut blob = post(m.mailbox, 3, 0);
        blob.message = PostBody::Blob(BlobRef::from_hash([4; 48]));
        assert_eq!(store.add_post(&blob).unwrap(), Posted::Seq(3));
        assert_eq!(
            store.posts(&m.mailbox, 2, 1, u64::MAX).unwrap().0[0].message,
            blob.message
        );
        assert_eq!(store.mailbox_bytes(&m.mailbox).unwrap(), 30);

        assert_eq!(
            store
                .add_post(&post(BoxName::from_bytes([9; 16]), 1, 1))
                .unwrap(),
            Posted::NoMailbox
        );
    }

    /// A set keeps what commits and CREATE added apart from what TOKEN
    /// added, at most 16 and 64; a full part drops the hash added first
    /// that no post has used, then the one a post used least recently; a
    /// hash the set holds already changes nothing (7.2).
    #[test]
    fn token_sets_are_bounded() {
        // Times of token hashes are kept to the hour (4.2): these are hours.
        let t = |hours: u64| t(hours * 3600);
        let post = |m: BoxName, hours: u64, size: usize| post(m, hours * 3600, size);
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(200);
        store.create_mailbox(&m).unwrap();
        // TOKEN's part: 64 hashes, besides CREATE's.
        for n in 0..64 {
            store
                .add_token(&m.mailbox, 0, &hash(n), t(u64::from(n)))
                .unwrap();
        }
        assert_eq!(set(&store, &m.mailbox, 0).len(), 65);
        store.add_token(&m.mailbox, 0, &hash(5), t(100)).unwrap();
        assert_eq!(set(&store, &m.mailbox, 0).len(), 65);
        // Posts use hashes 0 and 1, 1 before 0.
        for (n, secs) in [(1, 200), (0, 201)] {
            let mut p = post(m.mailbox, secs, 1);
            p.token = Some((0, hash(n)));
            store.add_post(&p).unwrap();
        }
        // New hashes push out TOKEN's unused ones, oldest first, never
        // CREATE's.
        store.add_token(&m.mailbox, 0, &hash(100), t(300)).unwrap();
        store.add_token(&m.mailbox, 0, &hash(101), t(301)).unwrap();
        let held = set(&store, &m.mailbox, 0);
        assert_eq!(held.len(), 65);
        assert!(held.contains(&200) && held.contains(&0) && held.contains(&1));
        assert!(!held.contains(&2) && !held.contains(&3) && held.contains(&4));
        // Once every one of TOKEN's hashes has been used, the least
        // recently used goes.
        for n in held.clone() {
            if n != 0 && n != 1 && n != 200 {
                let mut p = post(m.mailbox, 400, 1);
                p.token = Some((0, hash(n)));
                store.add_post(&p).unwrap();
            }
        }
        store.add_token(&m.mailbox, 0, &hash(102), t(500)).unwrap();
        let held = set(&store, &m.mailbox, 0);
        assert!(!held.contains(&1) && held.contains(&0) && held.contains(&102));

        // Commits' part: 16 hashes. TOKEN's hashes do not count.
        for n in 0..17u8 {
            let mut p = post(m.mailbox, 600 + u64::from(n), 1);
            p.next = Some((0, hash(150 + n)));
            store.add_post(&p).unwrap();
            store.add_token(&m.mailbox, 1, &hash(n), t(600)).unwrap();
        }
        let held = set(&store, &m.mailbox, 1);
        assert_eq!(held.len(), 16 + 17);
        assert!(!held.contains(&150) && held.contains(&151) && held.contains(&166));
    }

    /// A move to a box that is already the group's mailbox from that epoch
    /// changes nothing (7.8).
    #[test]
    fn moving_twice_to_the_same_box() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = new_mailbox(1);
        store.create_mailbox(&first).unwrap();
        let moved = NewMailbox {
            mailbox: BoxName::from_bytes([2; 16]),
            first_epoch: 5,
            moved_from: Some(first.mailbox),
            ..first.clone()
        };
        assert_eq!(store.create_mailbox(&moved).unwrap(), Created::Created);
        assert_eq!(store.create_mailbox(&moved).unwrap(), Created::Exists);
        let other_epoch = NewMailbox {
            first_epoch: 6,
            ..moved.clone()
        };
        assert_eq!(store.create_mailbox(&other_epoch).unwrap(), Created::Taken);
        // Another group cannot move from this one's mailbox.
        let other_group = NewMailbox {
            group_id: GroupId::from_bytes([9; 32]),
            ..moved.clone()
        };
        assert_eq!(
            store.create_mailbox(&other_group).unwrap(),
            Created::NoGroup
        );
        // Without epoch, a box seen before is taken.
        assert_eq!(store.create_mailbox(&first).unwrap(), Created::Taken);
    }

    /// A mailbox keeps the 256 sets used most recently (7.2).
    #[test]
    fn a_mailbox_keeps_256_sets() {
        // Times of token sets are kept to the hour (4.2): these are hours.
        let t = |hours: u64| t(hours * 3600);
        let post = |m: BoxName, hours: u64, size: usize| post(m, hours * 3600, size);
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        for epoch in 1..256 {
            store
                .add_token(&m.mailbox, epoch, &hash(2), t(epoch))
                .unwrap();
        }
        // Epoch 0's set is the oldest, but a post uses it now.
        let mut p = post(m.mailbox, 1000, 1);
        p.token = Some((0, m.token_hash));
        store.add_post(&p).unwrap();
        store.add_token(&m.mailbox, 256, &hash(2), t(1001)).unwrap();
        assert!(store.has_token(&m.mailbox, 0, &m.token_hash).unwrap());
        assert!(!store.has_token(&m.mailbox, 1, &hash(2)).unwrap());
        assert!(store.has_token(&m.mailbox, 2, &hash(2)).unwrap());
        assert!(store.has_token(&m.mailbox, 256, &hash(2)).unwrap());
    }

    /// Over its quota, a mailbox's oldest posts expire early; a post larger
    /// than the quota is refused (7.5).
    #[test]
    fn quotas() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        for secs in 0..4 {
            let mut p = post(m.mailbox, secs, 30);
            p.quota = 100;
            store.add_post(&p).unwrap();
        }
        assert_eq!(seqs(&store, &m.mailbox), [2, 3, 4]);
        assert_eq!(store.mailbox_bytes(&m.mailbox).unwrap(), 90);
        let mut big = post(m.mailbox, 5, 101);
        big.quota = 100;
        assert_eq!(store.add_post(&big).unwrap(), Posted::OverQuota);
        big.message = PostBody::Inline(vec![1; 100]);
        assert_eq!(store.add_post(&big).unwrap(), Posted::Seq(5));
        assert_eq!(seqs(&store, &m.mailbox), [5]);
    }

    /// Files and blobs make room by expiring the oldest posts (7.5).
    #[test]
    fn trimming_posts() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        for secs in 0..4 {
            store.add_post(&post(m.mailbox, secs, 30)).unwrap();
        }
        assert_eq!(store.trim_posts(&m.mailbox, 120).unwrap(), (0, true));
        assert_eq!(store.trim_posts(&m.mailbox, 70).unwrap(), (2, true));
        assert_eq!(seqs(&store, &m.mailbox), [3, 4]);
        assert_eq!(store.trim_posts(&m.mailbox, 0).unwrap(), (2, true));
        assert_eq!(store.mailbox_bytes(&m.mailbox).unwrap(), 0);
        assert_eq!(
            store.trim_posts(&new_mailbox(2).mailbox, 0).unwrap(),
            (0, true)
        );
    }

    /// Commits and proposals never expire early (7.5): application
    /// messages go first, and a post that does not fit beside the commits
    /// and proposals is refused.
    #[test]
    fn early_expiry_spares_commits_and_proposals() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        // seq 1 a commit, 2 a message, 3 a proposal, 4 a message.
        for (secs, handshake) in [(0, true), (1, false), (2, true), (3, false)] {
            let mut p = post(m.mailbox, secs, 30);
            p.handshake = handshake;
            store.add_post(&p).unwrap();
        }
        assert_eq!(store.trim_posts(&m.mailbox, 90).unwrap(), (1, true));
        assert_eq!(seqs(&store, &m.mailbox), [1, 3, 4]);
        assert_eq!(store.trim_posts(&m.mailbox, 0).unwrap(), (1, false));
        assert_eq!(seqs(&store, &m.mailbox), [1, 3]);
        // A post over the quota with only commits and proposals left.
        let mut p = post(m.mailbox, 4, 30);
        p.quota = 80;
        assert_eq!(store.add_post(&p).unwrap(), Posted::OverQuota);
        p.quota = 90;
        assert_eq!(store.add_post(&p).unwrap(), Posted::Seq(5));
        assert_eq!(seqs(&store, &m.mailbox), [1, 3, 5]);
    }

    /// The idle clean-up deletes a mailbox only if it is still idle in the
    /// same transaction (7.5).
    #[test]
    fn idle_mailboxes_are_dropped_only_while_idle() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        let later = t(40 * 24 * 3600);
        assert_eq!(store.idle_mailboxes(later).unwrap(), [m.mailbox]);
        // A post arrives after the list was read.
        store.add_post(&post(m.mailbox, 39 * 24 * 3600, 1)).unwrap();
        assert!(!store.drop_idle_mailbox(&m.mailbox, later).unwrap());
        assert!(store.mailbox(&m.mailbox).unwrap().is_some());
        let n = new_mailbox(2);
        store.create_mailbox(&n).unwrap();
        assert!(store.drop_idle_mailbox(&n.mailbox, later).unwrap());
        assert!(store.mailbox(&n.mailbox).unwrap().is_none());
    }

    /// Retention expires posts oldest first, stopping at the first that is
    /// not old enough; cids last 24 hours; token sets go once unused for a
    /// retention period; mutes end (6.4, 7.2, 7.5, 7.6).
    #[test]
    fn expiry() {
        let store = SqliteStore::open_in_memory().unwrap();
        let m = new_mailbox(1);
        store.create_mailbox(&m).unwrap();
        let day = 24 * 60 * 60;
        // Seq 2 has an earlier time than seq 1, as a clock that went back
        // would give it.
        for secs in [10, 5, 20, 3 * day] {
            let mut p = post(m.mailbox, secs, 1);
            p.cid = Some(format!("{secs:016}"));
            store.add_post(&p).unwrap();
        }
        store
            .add_token(&m.mailbox, 1, &hash(3), t(2 * day))
            .unwrap();
        let pseudonym = Pseudonym::from_bytes([1; 16]);
        assert!(store.set_mute(&m.mailbox, &pseudonym, t(day)).unwrap());
        assert!(store.muted(&m.mailbox, &pseudonym, t(0)).unwrap());

        let retention = Duration::from_secs(day);
        let expired = store.expire(t(day + 15), retention).unwrap();
        assert_eq!(seqs(&store, &m.mailbox), [3, 4]);
        assert_eq!(expired.posts, 2);
        assert_eq!(expired.cids, 2);
        // Epoch 0's set was added at the mailbox's creation, and used by no
        // post: it is gone. Epoch 1's is newer.
        assert_eq!(expired.token_hashes, 1);
        assert_eq!(expired.mutes, 1);
        assert!(!store.muted(&m.mailbox, &pseudonym, t(0)).unwrap());
        assert!(!store.has_token(&m.mailbox, 0, &m.token_hash).unwrap());
        assert!(store.has_token(&m.mailbox, 1, &hash(3)).unwrap());

        // A mailbox with no posts, idle since before the time asked about,
        // may end (7.5).
        assert!(store.idle_mailboxes(t(10 * day)).unwrap().is_empty());
        store.expire(t(10 * day), retention).unwrap();
        assert!(seqs(&store, &m.mailbox).is_empty());
        assert!(store.idle_mailboxes(t(3 * day)).unwrap().is_empty());
        assert_eq!(store.idle_mailboxes(t(3 * day + 1)).unwrap(), [m.mailbox]);
        assert!(store.drop_mailbox(&m.mailbox).unwrap());
        assert!(!store.drop_mailbox(&m.mailbox).unwrap());
        assert_eq!(store.mailbox(&m.mailbox).unwrap(), None);
        assert!(!store.set_mute(&m.mailbox, &pseudonym, t(day)).unwrap());
        assert!(!store.remove_mute(&m.mailbox, &pseudonym).unwrap());
    }

    /// A public room: its group's state, members and pending proposals,
    /// replaced by each commit; its name is taken until it is dropped
    /// (5.2, 6.1, 12.6).
    #[test]
    fn public_rooms() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice: Uid = "alice@example.org".parse().unwrap();
        let sam: Uid = "~sam".parse().unwrap();
        let group = |epoch: u64, members: Vec<(Uid, Role)>| RoomUpdate {
            epoch,
            group_info: vec![epoch as u8; 3],
            tree: vec![epoch as u8; 5],
            members,
            topic: "hello\\sthere".into(),
            guests: GuestAccess::Read,
            state: vec![epoch as u8; 2],
        };
        let room = NewRoom {
            room: "#general".parse().unwrap(),
            creator: alice.clone(),
            group: group(0, vec![(alice.clone(), Role::Owner)]),
        };
        let m = new_mailbox(1);
        assert_eq!(store.create_room(&m, &room).unwrap(), Created::Created);
        assert_eq!(
            store.create_room(&new_mailbox(2), &room).unwrap(),
            Created::Taken
        );
        assert_eq!(store.mailbox(&new_mailbox(2).mailbox).unwrap(), None);
        let record = store.mailbox(&m.mailbox).unwrap().unwrap();
        assert_eq!(record.room, Some(room.room.clone()));
        let state = store.room_group(&m.mailbox).unwrap().unwrap();
        assert_eq!(
            state,
            RoomGroup {
                room: room.room.clone(),
                epoch: 0,
                epoch_seq: 0,
                group_info: vec![0; 3],
                tree: vec![0; 5],
                proposals: vec![],
                state: vec![0; 2],
            }
        );
        assert_eq!(
            store.room_member(&m.mailbox, &alice).unwrap(),
            Some(Role::Owner)
        );
        assert_eq!(store.room_member(&m.mailbox, &sam).unwrap(), None);
        assert_eq!(store.room_group(&new_mailbox(2).mailbox).unwrap(), None);

        for message in [vec![1, 2, 3], vec![], vec![4; 300]] {
            let mut p = post(m.mailbox, 1, 1);
            p.room = Some(RoomChange::Proposal {
                state: vec![9; message.len() % 7],
                message,
            });
            store.add_post(&p).unwrap();
        }
        let state = store.room_group(&m.mailbox).unwrap().unwrap();
        assert_eq!(state.proposals, [vec![1, 2, 3], vec![], vec![4; 300]]);
        assert_eq!(state.state, vec![9; 300 % 7]);

        let mut commit = post(m.mailbox, 2, 1);
        commit.room = Some(RoomChange::Commit(group(
            1,
            vec![(alice.clone(), Role::Owner), (sam.clone(), Role::Member)],
        )));
        assert_eq!(store.add_post(&commit).unwrap(), Posted::Seq(4));
        let state = store.room_group(&m.mailbox).unwrap().unwrap();
        assert_eq!((state.epoch, state.epoch_seq), (1, 4));
        assert_eq!(state.tree, vec![1; 5]);
        assert!(state.proposals.is_empty());
        assert_eq!(state.state, vec![1; 2]);
        assert_eq!(
            store.room_member(&m.mailbox, &sam).unwrap(),
            Some(Role::Member)
        );
        assert_eq!(store.rooms_with_member(&sam).unwrap(), [m.mailbox]);
        let (members, topic, guests): (i64, String, String) = store
            .raw()
            .query_row("SELECT members, topic, guests FROM public_rooms", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(
            (members, topic.as_str(), guests.as_str()),
            (2, "hello\\sthere", "read")
        );

        // Dropping it frees the name, but not the box or group id.
        assert!(store.drop_mailbox(&m.mailbox).unwrap());
        assert!(store.rooms_with_member(&sam).unwrap().is_empty());
        assert_eq!(store.create_room(&m, &room).unwrap(), Created::Taken);
        assert_eq!(
            store.create_room(&new_mailbox(3), &room).unwrap(),
            Created::Created
        );
    }
}

//! [`MailboxStore`] on SQLite, and the tables of mailboxes, posts and
//! public rooms (5.2, 6, 7).

use rusqlite::{OptionalExtension as _, Transaction, params};
use sha2::{Digest as _, Sha384};

use risala_proto::mls::{GroupId, Pseudonym};
use risala_proto::names::{BlobRef, BoxName, Room, Uid};
use risala_proto::time::Timestamp;
use risala_proto::types::Role;

use super::{SqliteStore, from_sql_u64, sql_u64};
use crate::store::{
    Created, KeptPost, MailboxRecord, MailboxStore, NewMailbox, PublicRoomRecord, Result,
    StoreError, fixed, millis, parsed, timestamp,
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
    created INTEGER NOT NULL,       -- ms
    head INTEGER NOT NULL DEFAULT 0 CHECK (head >= 0) -- the newest seq given out
) STRICT;
CREATE INDEX mailboxes_group ON mailboxes (group_id, created);

-- The sets of send token hashes (7.2), per mailbox and epoch: at most 64
-- hashes a set, each with when it was added and last used by a post.
CREATE TABLE token_hashes (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    hash BLOB NOT NULL CHECK (length(hash) = 48),
    added INTEGER NOT NULL,         -- ms
    used INTEGER,                   -- ms of the last post that used it
    PRIMARY KEY (box, epoch, hash)
) STRICT, WITHOUT ROWID;

-- Kept posts (5.2), until they expire (7.5): their box, seq, time and
-- message, and a commit's next, only (4.2).
CREATE TABLE posts (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    seq INTEGER NOT NULL CHECK (seq >= 1),
    t INTEGER NOT NULL,             -- ms, when the server accepted it
    message BLOB,                   -- the MLSMessage, or NULL if it is a blob
    blob BLOB CHECK (length(blob) = 48), -- the blob's hash, if it is one (12.12)
    next BLOB CHECK (length(next) = 48), -- a commit's next= token hash (5.2, 7.2)
    UNIQUE (box, seq),
    CHECK ((message IS NULL) != (blob IS NULL))
) STRICT;
-- Retention expires each mailbox's posts oldest first (7.5).
CREATE INDEX posts_t ON posts (t);

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
    guests TEXT NOT NULL DEFAULT 'write' CHECK (guests IN ('none', 'read', 'write'))
) STRICT;

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

impl MailboxStore for SqliteStore {
    fn create_mailbox(&self, new: &NewMailbox) -> Result<Created> {
        self.write(|tx| {
            let mailbox = &new.mailbox.as_bytes()[..];
            let group = &new.group_id.as_bytes()[..];
            if used(tx, USED_BOX, mailbox)? {
                return Ok(Created::Taken);
            }
            let moved_from: Option<Vec<u8>> = if new.first_epoch == 0 {
                if used(tx, USED_GROUP, group)? {
                    return Ok(Created::Taken);
                }
                None
            } else {
                let newest = tx
                    .query_row(
                        "SELECT box FROM mailboxes WHERE group_id = ?
                         ORDER BY created DESC, rowid DESC LIMIT 1",
                        [group],
                        |row| row.get(0),
                    )
                    .optional()?;
                match newest {
                    Some(from) => Some(from),
                    None => return Ok(Created::NoGroup),
                }
            };
            remember(tx, USED_BOX, mailbox)?;
            remember(tx, USED_GROUP, group)?;
            let created = millis(new.created);
            tx.execute(
                "INSERT INTO mailboxes (box, group_id, first_epoch, moved_from, created)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    mailbox,
                    group,
                    sql_u64(new.first_epoch),
                    moved_from,
                    created
                ],
            )?;
            tx.execute(
                "INSERT INTO token_hashes (box, epoch, hash, added) VALUES (?, ?, ?, ?)",
                params![
                    mailbox,
                    sql_u64(new.first_epoch),
                    &new.token_hash.as_bytes()[..],
                    created
                ],
            )?;
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

    fn rooms_with_member(&self, uid: &Uid) -> Result<Vec<BoxName>> {
        self.read(|tx| {
            let mut select =
                tx.prepare_cached("SELECT box FROM room_members WHERE uid = ? ORDER BY box")?;
            let rows = select.query_map([uid.as_str()], |row| row.get::<_, Vec<u8>>(0))?;
            rows.map(|row| Ok(BoxName::from_bytes(fixed("box", &row?)?)))
                .collect()
        })
    }

    // What the misc and admin areas read and change (SV5). TODO(SV3):
    // reconcile with the mailbox area's own methods when they meet.

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

    fn drop_mailbox(&self, mailbox: &BoxName) -> Result<bool> {
        self.write(|tx| {
            Ok(tx.execute(
                "DELETE FROM mailboxes WHERE box = ?",
                [&mailbox.as_bytes()[..]],
            )? > 0)
        })
    }

    fn set_mute(
        &self,
        mailbox: &BoxName,
        pseudonym: &Pseudonym,
        until: Timestamp,
    ) -> Result<bool> {
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
    use risala_proto::mls::TokenHash;
    use risala_proto::time::Timestamp;

    use super::*;

    fn new_mailbox(n: u8) -> NewMailbox {
        NewMailbox {
            mailbox: BoxName::from_bytes([n; 16]),
            group_id: GroupId::from_bytes([n; 32]),
            first_epoch: 0,
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
    /// linked to the newest one it had (7.8).
    #[test]
    fn groups_move_to_new_mailboxes() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = new_mailbox(1);
        let moved = |n: u8, epoch: u64| NewMailbox {
            mailbox: BoxName::from_bytes([n; 16]),
            first_epoch: epoch,
            ..first.clone()
        };
        // No mailbox of the group yet.
        assert_eq!(
            store.create_mailbox(&moved(2, 5)).unwrap(),
            Created::NoGroup
        );
        store.create_mailbox(&first).unwrap();
        assert_eq!(
            store.create_mailbox(&moved(2, 5)).unwrap(),
            Created::Created
        );
        let second = store.mailbox(&moved(2, 5).mailbox).unwrap().unwrap();
        assert_eq!(second.first_epoch, 5);
        assert_eq!(second.moved_from, Some(first.mailbox));
        assert_eq!(second.group_id, first.group_id);
        // A box is never used again, moves included.
        assert_eq!(store.create_mailbox(&moved(2, 9)).unwrap(), Created::Taken);
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
}

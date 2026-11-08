//! [`MailboxStore`] on SQLite, and the tables of mailboxes, posts and
//! public rooms (5.2, 6, 7).

use rusqlite::{OptionalExtension as _, params};

use risala_proto::mls::GroupId;
use risala_proto::names::{BoxName, Uid};

use super::{SqliteStore, from_sql_u64};
use crate::store::{
    MailboxRecord, MailboxStore, NewMailbox, Result, fixed, millis, parsed, timestamp,
};

/// The mailbox area's tables.
pub(super) const SCHEMA: &str = "
-- Every mailbox (5.2). A dropped one keeps its row, so that its box and
-- group id are never used again (5.2, 10.4) and its seqs never reused
-- (7.5).
CREATE TABLE mailboxes (
    box BLOB PRIMARY KEY CHECK (length(box) = 16),
    group_id BLOB NOT NULL UNIQUE,
    created INTEGER NOT NULL,       -- ms
    head INTEGER NOT NULL DEFAULT 0 CHECK (head >= 0), -- the newest seq given out
    dropped INTEGER                 -- ms when an operator dropped it (10.4)
) STRICT;

-- The hashes of each mailbox's send tokens (7.2): a set for each of the
-- newest 16 epochs seen.
CREATE TABLE token_hashes (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    hash BLOB NOT NULL CHECK (length(hash) = 48),
    PRIMARY KEY (box, epoch, hash)
) STRICT, WITHOUT ROWID;

-- Kept posts (5.2), until they expire (7.5), with what the server read
-- from their framing.
CREATE TABLE posts (
    box BLOB NOT NULL REFERENCES mailboxes (box) ON DELETE CASCADE,
    seq INTEGER NOT NULL CHECK (seq >= 1),
    t INTEGER NOT NULL,             -- ms, when the server accepted it
    epoch INTEGER NOT NULL,
    content_type INTEGER NOT NULL,  -- RFC 9420: 1 application, 2 proposal, 3 commit
    pseudonym BLOB NOT NULL CHECK (length(pseudonym) = 16), -- from its RisalaAAD (7.3)
    message BLOB,                   -- the MLSMessage, or NULL if it is a blob
    blob BLOB CHECK (length(blob) = 48), -- the blob's hash, if it is one (12.12)
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
-- it. A dropped room loses its row, which frees its name (10.4).
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

impl MailboxStore for SqliteStore {
    fn create_mailbox(&self, new: &NewMailbox) -> Result<bool> {
        self.write(|tx| {
            let added = tx.execute(
                "INSERT INTO mailboxes (box, group_id, created) VALUES (?, ?, ?)
                 ON CONFLICT DO NOTHING",
                params![
                    &new.mailbox.as_bytes()[..],
                    &new.group_id.as_bytes()[..],
                    millis(new.created)
                ],
            )?;
            if added == 0 {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO token_hashes (box, epoch, hash) VALUES (?, 0, ?)",
                params![&new.mailbox.as_bytes()[..], &new.token_hash.as_bytes()[..]],
            )?;
            Ok(true)
        })
    }

    fn mailbox(&self, mailbox: &BoxName) -> Result<Option<MailboxRecord>> {
        self.read(|tx| {
            let row = tx
                .query_row(
                    "SELECT m.group_id, m.head, m.created, r.room
                     FROM mailboxes m LEFT JOIN public_rooms r ON r.box = m.box
                     WHERE m.box = ? AND m.dropped IS NULL",
                    [&mailbox.as_bytes()[..]],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .optional()?;
            let Some((group_id, head, created, room)) = row else {
                return Ok(None);
            };
            Ok(Some(MailboxRecord {
                mailbox: *mailbox,
                group_id: GroupId::from_bytes(fixed("group id", &group_id)?),
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
            token_hash: TokenHash::from_bytes([n; 48]),
            created: "2026-11-09T00:00:00.000Z".parse::<Timestamp>().unwrap(),
        }
    }

    #[test]
    fn boxes_and_group_ids_are_never_used_twice() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = new_mailbox(1);
        assert_eq!(store.mailbox(&first.mailbox).unwrap(), None);
        assert!(store.create_mailbox(&first).unwrap());
        let record = store.mailbox(&first.mailbox).unwrap().unwrap();
        assert_eq!(record.group_id, first.group_id);
        assert_eq!((record.head, record.room.clone()), (0, None));
        assert_eq!(record.created, first.created);

        // The same box, or the same group id, is taken (5.2).
        let same_box = NewMailbox {
            group_id: GroupId::from_bytes([9; 32]),
            ..first.clone()
        };
        assert!(!store.create_mailbox(&same_box).unwrap());
        let same_group = NewMailbox {
            mailbox: BoxName::from_bytes([9; 16]),
            ..first.clone()
        };
        assert!(!store.create_mailbox(&same_group).unwrap());
        assert_eq!(store.mailbox(&same_group.mailbox).unwrap(), None);

        // A dropped mailbox is gone, and its box and group id stay taken
        // (10.4).
        store
            .conn()
            .execute("UPDATE mailboxes SET dropped = 1", [])
            .unwrap();
        assert_eq!(store.mailbox(&first.mailbox).unwrap(), None);
        assert!(!store.create_mailbox(&first).unwrap());
    }

    #[test]
    fn members_of_public_rooms() {
        let store = SqliteStore::open_in_memory().unwrap();
        let sam: Uid = "~sam".parse().unwrap();
        assert!(store.rooms_with_member(&sam).unwrap().is_empty());
        for n in [2, 1] {
            let new = new_mailbox(n);
            store.create_mailbox(&new).unwrap();
            let conn = store.conn();
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

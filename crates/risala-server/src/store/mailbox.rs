//! Mailboxes and their posts (5.2, 7), public rooms (6.1), and mutes
//! (6.4, 10.4).
//!
//! Tables (`sqlite/mailbox.rs`):
//!
//! - `mailboxes`: every box and group id the server has seen, with the
//!   newest seq given out. A dropped mailbox keeps its row, so that its box
//!   and group id are never used again (5.2, 10.4), and seqs are never
//!   reused (7.5).
//! - `token_hashes`: the hashes of the send tokens of each mailbox's
//!   newest 16 epochs (7.2).
//! - `posts`: kept posts until they expire (7.5), with what the server
//!   read from their framing: epoch, content type and pseudonym (5.2,
//!   7.3).
//! - `cids`: client post ids for 24 hours (7.6).
//! - `public_rooms`: the public state of each public room's group, its
//!   GroupInfo and ratchet tree as of the newest epoch, and what LIST,
//!   INFO and the join checks read from it (6.1, 6.2, 12.6).
//! - `room_members`: the uids with a leaf in each public room, and their
//!   roles (6.1, 8.3), for MEMBERS and GONE.
//! - `mutes`: muted pseudonyms per mailbox, until a time (6.4, 10.4).

use risala_proto::mls::{GroupId, TokenHash};
use risala_proto::names::{BoxName, Room, Uid};
use risala_proto::time::Timestamp;

use super::Result;

/// A mailbox to create (5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMailbox {
    /// Its box.
    pub mailbox: BoxName,
    /// The id of its group.
    pub group_id: GroupId,
    /// The hash of the group's send token for epoch 0 (7.2).
    pub token_hash: TokenHash,
    /// When it was created.
    pub created: Timestamp,
}

/// A mailbox, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRecord {
    /// Its box.
    pub mailbox: BoxName,
    /// The id of its group.
    pub group_id: GroupId,
    /// The newest seq given out, or 0 before the first post (7.1).
    pub head: u64,
    /// When it was created.
    pub created: Timestamp,
    /// The public room it is, if it is one (6.1).
    pub room: Option<Room>,
}

/// Mailboxes and public rooms (5.2, 6, 7).
pub trait MailboxStore {
    /// Creates a mailbox for a group in epoch 0 (5.2). Returns `false`,
    /// and changes nothing, if the server has seen its box or group id
    /// before, even in a dropped mailbox (`ERR name-taken`).
    fn create_mailbox(&self, new: &NewMailbox) -> Result<bool>;

    /// The mailbox `mailbox`, unless there is none or it was dropped.
    fn mailbox(&self, mailbox: &BoxName) -> Result<Option<MailboxRecord>>;

    /// The public rooms in whose group `uid` has a leaf, as boxes (6.1).
    /// When a guest's session ends, they get GONE (4.2).
    fn rooms_with_member(&self, uid: &Uid) -> Result<Vec<BoxName>>;
}

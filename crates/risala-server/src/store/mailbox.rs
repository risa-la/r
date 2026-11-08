//! Mailboxes and their posts (5.2, 7), public rooms (6.1), and mutes
//! (6.4, 10.4).
//!
//! Tables (`sqlite/mailbox.rs`):
//!
//! - `used_ids`: every box and group id the server has seen, by SHA-384
//!   hash, so that a box is never used again and a group id gets a new
//!   mailbox only as a move, even once its mailboxes are gone (5.2, 7.8).
//! - `mailboxes`: the mailboxes the server holds, with the newest seq
//!   given out, the epoch each starts at, and the mailbox a moved group
//!   came from (7.8).
//! - `token_hashes`: the sets of send token hashes, per mailbox and epoch,
//!   with when each hash was added and last used, for their bounds (7.2).
//! - `posts`: kept posts until they expire (7.5), with their box, seq,
//!   time and message only (4.2, 5.2).
//! - `cids`: client post ids for 24 hours (7.6).
//! - `public_rooms`: the public state of each public room's group, its
//!   GroupInfo and ratchet tree as of the newest epoch, and what LIST,
//!   INFO and the join checks read from it (6.1, 6.2, 12.6).
//! - `room_members`: the uids with a leaf in each public room, and their
//!   roles (6.1, 8.3), for MEMBERS and GONE.
//! - `mutes`: muted pseudonyms per mailbox, until a time (6.4, 10.4).
//!
//! Nothing here says which connection or address made a mailbox, a post
//! or a token hash (4.2).

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
    /// The epoch it starts at: 0 for a new group, or the epoch of a move
    /// (7.8).
    pub first_epoch: u64,
    /// The hash of the group's send token for that epoch (7.2).
    pub token_hash: TokenHash,
    /// When it was created.
    pub created: Timestamp,
}

/// What [`MailboxStore::create_mailbox`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Created {
    /// The mailbox exists now.
    Created,
    /// The box was seen before, or, for a new group, the group id was
    /// (`ERR name-taken`, 5.2).
    Taken,
    /// A move, but the server holds no mailbox of the group
    /// (`ERR not-found`, 7.8).
    NoGroup,
}

/// A mailbox, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRecord {
    /// Its box.
    pub mailbox: BoxName,
    /// The id of its group.
    pub group_id: GroupId,
    /// The epoch it starts at: 0, or the epoch of a move (7.8).
    pub first_epoch: u64,
    /// The mailbox the group moved from, while the server still holds it
    /// (7.8).
    pub moved_from: Option<BoxName>,
    /// The newest seq given out, or 0 before the first post (7.1).
    pub head: u64,
    /// When it was created.
    pub created: Timestamp,
    /// The public room it is, if it is one (6.1).
    pub room: Option<Room>,
}

/// Mailboxes and public rooms (5.2, 6, 7).
pub trait MailboxStore {
    /// Creates a mailbox (5.2): for a new group, unless its box or group
    /// id was seen before; or, with a first epoch over 0, for a group that
    /// moves from the newest mailbox the server holds of it (7.8), unless
    /// its box was seen before. The first epoch's set of token hashes gets
    /// `token_hash`.
    fn create_mailbox(&self, new: &NewMailbox) -> Result<Created>;

    /// The mailbox `mailbox`, if the server holds it.
    fn mailbox(&self, mailbox: &BoxName) -> Result<Option<MailboxRecord>>;

    /// The public rooms in whose group `uid` has a leaf, as boxes (6.1).
    /// When a guest's session ends, they get GONE (4.2).
    fn rooms_with_member(&self, uid: &Uid) -> Result<Vec<BoxName>>;
}

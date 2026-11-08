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
//!   time and message, and a commit's `next`, only (4.2, 5.2).
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

use risala_proto::mls::{GroupId, Pseudonym, TokenHash};
use risala_proto::names::{BlobRef, BoxName, Room, Uid};
use risala_proto::time::Timestamp;
use risala_proto::types::{GuestAccess, Role};

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

    // What the misc and admin areas read and change (SV5: LIST, INFO,
    // MEMBERS, REPORT, ADMIN ROOMS, DROP, MUTE). TODO(SV3): reconcile with
    // the mailbox area's own methods when they meet.

    /// A page of public rooms in order of name (6.1, 10.4): at most
    /// `limit` rooms whose names sort after `after`, leaving out rooms
    /// whose `guests` setting is `none` if `for_guest`. The flag says
    /// whether more rooms follow.
    fn public_rooms(
        &self,
        after: Option<&Room>,
        limit: u64,
        for_guest: bool,
    ) -> Result<(Vec<PublicRoomRecord>, bool)>;

    /// The public room `room`, if there is one (6.1).
    fn public_room(&self, room: &Room) -> Result<Option<PublicRoomRecord>>;

    /// The uids with a leaf in a public room's group, with their roles, in
    /// order of uid (8.3).
    fn room_members(&self, mailbox: &BoxName) -> Result<Vec<(Uid, Role)>>;

    /// The kept post `seq` of `mailbox`, if it is still kept (5.8).
    fn kept_post(&self, mailbox: &BoxName, seq: u64) -> Result<Option<KeptPost>>;

    /// Deletes a mailbox with all of its posts, and its public room if it
    /// is one (10.4). Its box stays used (5.2). Returns whether there was
    /// one.
    fn drop_mailbox(&self, mailbox: &BoxName) -> Result<bool>;

    /// Refuses the posts of `pseudonym` in `mailbox` until `until` (6.4,
    /// 10.4). Returns `false` if the server holds no such mailbox.
    fn set_mute(&self, mailbox: &BoxName, pseudonym: &Pseudonym, until: Timestamp)
    -> Result<bool>;

    /// Lifts a mute (6.4, 10.4). Returns `false` if there was none.
    fn remove_mute(&self, mailbox: &BoxName, pseudonym: &Pseudonym) -> Result<bool>;
}

/// A public room, as LIST, INFO and MEMBERS see it (6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRoomRecord {
    /// Its name.
    pub room: Room,
    /// Its mailbox.
    pub mailbox: BoxName,
    /// The number of identities and guests with a leaf in its group.
    pub members: u64,
    /// Its topic, escaped; empty if none.
    pub topic: String,
    /// Its `guests` setting (6.2).
    pub guests: GuestAccess,
    /// Its group's current epoch.
    pub epoch: u64,
}

/// A kept post (5.2), as REPORT reads it (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptPost {
    /// When the server accepted it.
    pub t: Timestamp,
    /// The MLSMessage, or the blob that holds it (12.12).
    pub message: Result<Vec<u8>, BlobRef>,
}

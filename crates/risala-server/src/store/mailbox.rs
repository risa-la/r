//! Mailboxes and their posts (5.2, 7), public rooms (6.1), and mutes
//! (6.4, 10.4).
//!
//! Tables (`sqlite/mailbox.rs`):
//!
//! - `used_ids`: every box and group id the server has seen, by SHA-384
//!   hash, so that a box is never used again and a group id gets a new
//!   mailbox only as a move, even once its mailboxes are gone (5.2, 7.8).
//! - `mailboxes`: the mailboxes the server holds, with the newest seq
//!   given out, the epoch each starts at, the mailbox a moved group came
//!   from (7.8), the bytes of its kept posts (7.5), and when it was last
//!   posted to.
//! - `token_hashes`: the sets of send token hashes, per mailbox and epoch,
//!   with when each hash was added and last used, for their bounds (7.2).
//! - `posts`: kept posts until they expire (7.5), with their box, seq,
//!   time and message, and a commit's `next`, only (4.2, 5.2).
//! - `cids`: client post ids for 24 hours (7.6).
//! - `public_rooms`: the public state of each public room's group, its
//!   GroupInfo and ratchet tree as of the newest epoch and the proposals
//!   pending in it, and what LIST, INFO and the join checks read from it
//!   (6.1, 6.2, 12.6).
//! - `room_members`: the uids with a leaf in each public room, and their
//!   roles (6.1, 8.3), for MEMBERS, MUTE and GONE.
//! - `mutes`: muted pseudonyms per mailbox, until a time (6.4, 10.4).
//!
//! Nothing here says which connection or address made a mailbox, a post
//! or a token hash (4.2).

use std::time::Duration;

use risala_proto::mls::{GroupId, Pseudonym, TokenHash};
use risala_proto::names::{BlobRef, BoxName, Room, Uid};
use risala_proto::time::Timestamp;
use risala_proto::types::{GuestAccess, Role};

use super::Result;

/// The most hashes that commits and CREATE add to one set of send token
/// hashes (7.2).
pub const MAX_SET_NEXT_HASHES: usize = 16;

/// The most hashes that TOKEN adds to one set of send token hashes (7.2).
pub const MAX_SET_TOKEN_HASHES: usize = 64;

/// Who added a hash to a set of send token hashes (7.2): a set keeps the
/// two apart, each part with its own bound, so that TOKEN never pushes
/// out a hash that a commit added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddedBy {
    /// A commit's `next`, or CREATE.
    Commit,
    /// TOKEN.
    Token,
}

/// The most sets of send token hashes the server keeps for one mailbox: it
/// keeps those used most recently (7.2).
pub const MAX_SETS: usize = 256;

/// How long a `cid` is remembered (7.6).
pub const CID_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

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
    /// For a move, the mailbox the group moves from (7.8).
    pub moved_from: Option<BoxName>,
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
    /// The box was seen before, or, for a new group, the group id was, or,
    /// for a public room, its name is in use (`ERR name-taken`, 5.2).
    Taken,
    /// A move, but the server holds no mailbox `moved_from` of the group
    /// (`ERR not-found`, 7.8).
    NoGroup,
    /// A move whose box is already the mailbox of that group from that
    /// epoch: nothing changes (`OK`, 7.8).
    Exists,
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

/// A post's message: the MLSMessage, or the blob that holds it (5.2,
/// 12.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostBody {
    /// The MLSMessage's bytes.
    Inline(Vec<u8>),
    /// The blob that holds them.
    Blob(BlobRef),
}

impl PostBody {
    /// The bytes it counts against its mailbox's quota (7.5): a blob counts
    /// when BLOB stores it, not here.
    pub fn size(&self) -> u64 {
        match self {
            PostBody::Inline(bytes) => bytes.len() as u64,
            PostBody::Blob(_) => 0,
        }
    }
}

/// A post, as kept (4.2, 5.2): its seq, time and message, and a commit's
/// `next`. Nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPost {
    /// Its seq.
    pub seq: u64,
    /// When the server accepted it.
    pub t: Timestamp,
    /// The message.
    pub message: PostBody,
    /// A commit's `next` (5.2, 7.2).
    pub next: Option<TokenHash>,
}

/// The public state of a public room's group (12.6), as the server holds
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomGroup {
    /// The room's name.
    pub room: Room,
    /// The group's current epoch.
    pub epoch: u64,
    /// The seq of the commit that started the epoch, or 0 in epoch 0
    /// (6.1).
    pub epoch_seq: u64,
    /// The current GroupInfo, an MLSMessage.
    pub group_info: Vec<u8>,
    /// The current ratchet tree.
    pub tree: Vec<u8>,
    /// The proposals posted in the current epoch, as MLSMessages, in the
    /// order they were posted (12.6), for commits to refer to.
    pub proposals: Vec<Vec<u8>>,
    /// What the group checks need of the epoch besides the tree (12.7):
    /// who started it, and the times of its proposals, as the hub encodes
    /// it.
    pub state: Vec<u8>,
}

/// A public room's group as of a new epoch, or as created (6.1, 12.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomUpdate {
    /// The epoch.
    pub epoch: u64,
    /// Its GroupInfo, an MLSMessage.
    pub group_info: Vec<u8>,
    /// Its ratchet tree.
    pub tree: Vec<u8>,
    /// Each uid with a leaf in the group, identity or guest, once, with its
    /// role in the conversation extension (6.3).
    pub members: Vec<(Uid, Role)>,
    /// The topic of the conversation extension, escaped (3.4, 6.2).
    pub topic: String,
    /// Its `guests` setting (6.2).
    pub guests: GuestAccess,
    /// The epoch's state for the group checks (12.7), as the hub encodes
    /// it.
    pub state: Vec<u8>,
}

/// A public room to create with its mailbox (5.2, 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRoom {
    /// Its name.
    pub room: Room,
    /// The identity that creates it.
    pub creator: Uid,
    /// Its group in epoch 0.
    pub group: RoomUpdate,
}

/// What a post changes in a public room's group, besides the post itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomChange {
    /// An accepted commit moved the group to a new epoch (12.6). The
    /// epoch's seq is the post's, and the pending proposals are dropped.
    Commit(RoomUpdate),
    /// A proposal for the current epoch, kept for commits to refer to, and
    /// the epoch's state with its time (12.7).
    Proposal {
        /// The MLSMessage.
        message: Vec<u8>,
        /// The epoch's state.
        state: Vec<u8>,
    },
}

/// A post to keep (5.2), with everything that changes with it, in one
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPost {
    /// The mailbox.
    pub mailbox: BoxName,
    /// When the server accepted it.
    pub t: Timestamp,
    /// The message.
    pub message: PostBody,
    /// The epoch and hash of the token it was posted with, which is now
    /// used (7.2); `None` for a post with `-`.
    pub token: Option<(u64, TokenHash)>,
    /// A commit's epoch and `next`: `next` goes into the set of the epoch
    /// after (7.2), and is kept with the post.
    pub next: Option<(u64, TokenHash)>,
    /// The `cid` it was tagged with (7.6).
    pub cid: Option<String>,
    /// The bytes the mailbox's posts may take (7.5): its quota less its
    /// files and blobs. Its oldest posts expire early to make room.
    pub quota: u64,
    /// What it changes in a public room.
    pub room: Option<RoomChange>,
}

/// What [`MailboxStore::add_post`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posted {
    /// It is kept with this seq.
    Seq(u64),
    /// It is larger than the quota on its own (`ERR rate-limited`, 7.5).
    OverQuota,
    /// The mailbox is gone.
    NoMailbox,
}

/// What [`MailboxStore::expire`] deleted (7.2, 7.5, 7.6, 6.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Expired {
    /// Posts.
    pub posts: usize,
    /// Cids.
    pub cids: usize,
    /// Token hashes, in sets unused for a retention period.
    pub token_hashes: usize,
    /// Mutes that ended.
    pub mutes: usize,
}

/// Mailboxes and public rooms (5.2, 6, 7).
pub trait MailboxStore {
    /// Creates a mailbox (5.2): for a new group, unless its box or group
    /// id was seen before; or, with a first epoch over 0, for a group that
    /// moves from `moved_from`, a mailbox of the same group (7.8), unless
    /// its box was seen before. The first epoch's set of token hashes gets
    /// `token_hash`.
    fn create_mailbox(&self, new: &NewMailbox) -> Result<Created>;

    /// Creates the mailbox of a new public room (5.2, 6.1), as
    /// [`create_mailbox`](Self::create_mailbox) does for a new group, and
    /// the room, unless its name is in use.
    fn create_room(&self, new: &NewMailbox, room: &NewRoom) -> Result<Created>;

    /// The mailbox `mailbox`, if the server holds it.
    fn mailbox(&self, mailbox: &BoxName) -> Result<Option<MailboxRecord>>;

    /// The seq of the post of `mailbox` tagged `cid` since `since` (7.6).
    fn cid_post(&self, mailbox: &BoxName, cid: &str, since: Timestamp) -> Result<Option<u64>>;

    /// Whether the set of `epoch` of `mailbox` holds `hash`, compared in
    /// constant time (7.2).
    fn has_token(&self, mailbox: &BoxName, epoch: u64, hash: &TokenHash) -> Result<bool>;

    /// Whether any set of `mailbox` holds `hash`, compared in constant time:
    /// the check of a send token that comes without its epoch, for UPLOAD
    /// and BLOB (5.6, 12.12).
    fn has_token_any(&self, mailbox: &BoxName, hash: &TokenHash) -> Result<bool>;

    /// Adds `hash`, which TOKEN brings, to the set of `epoch` of `mailbox`
    /// at `now`, within the bounds of 7.2: the part of a set that TOKEN
    /// added holds at most [`MAX_SET_TOKEN_HASHES`], and the part that
    /// commits and CREATE added at most [`MAX_SET_NEXT_HASHES`]; a full
    /// part drops the hash added first among those no post has used, or if
    /// every one has been used, the one a post used least recently; a
    /// mailbox keeps at most [`MAX_SETS`] sets, and drops the one used
    /// least recently. A hash the set holds already changes nothing.
    fn add_token(
        &self,
        mailbox: &BoxName,
        epoch: u64,
        hash: &TokenHash,
        now: Timestamp,
    ) -> Result<()>;

    /// Keeps a post, gives it the mailbox's next seq, and makes the changes
    /// that come with it (5.2, 7.2, 7.5, 7.6, 12.6).
    fn add_post(&self, post: &NewPost) -> Result<Posted>;

    /// The earliest `limit` posts of `mailbox` whose seq is greater than
    /// `after`, in ascending order, and whether there are more (7.1).
    fn posts(&self, mailbox: &BoxName, after: u64, limit: u64) -> Result<(Vec<StoredPost>, bool)>;

    /// The bytes of the posts `mailbox` keeps (7.5).
    fn mailbox_bytes(&self, mailbox: &BoxName) -> Result<u64>;

    /// Expires the oldest posts of `mailbox` early until it keeps at most
    /// `max` bytes of posts, to make room within its quota for files and
    /// blobs (7.5). Returns how many expired.
    fn trim_posts(&self, mailbox: &BoxName, max: u64) -> Result<usize>;

    /// Whether `pseudonym` is muted in `mailbox` at `now` (6.4).
    fn muted(&self, mailbox: &BoxName, pseudonym: &Pseudonym, now: Timestamp) -> Result<bool>;

    /// The public state of the public room of `mailbox` (12.6).
    fn room_group(&self, mailbox: &BoxName) -> Result<Option<RoomGroup>>;

    /// The role of `uid` in the public room of `mailbox`, if it has a leaf
    /// in its group (6.3, 6.4).
    fn room_member(&self, mailbox: &BoxName, uid: &Uid) -> Result<Option<Role>>;

    /// The public rooms in whose group `uid` has a leaf, as boxes (6.1).
    /// When a guest's session ends, they get GONE (4.2).
    fn rooms_with_member(&self, uid: &Uid) -> Result<Vec<BoxName>>;

    // What the misc and admin areas read and change (SV5: LIST, INFO,
    // MEMBERS, REPORT, ADMIN ROOMS, ADMIN MUTE).

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

    /// Refuses the posts of `pseudonym` in `mailbox` until `until` (6.4,
    /// 10.4). Returns `false` if the server holds no such mailbox.
    fn set_mute(&self, mailbox: &BoxName, pseudonym: &Pseudonym, until: Timestamp) -> Result<bool>;

    /// Lifts a mute (6.4, 10.4). Returns `false` if there was none.
    fn remove_mute(&self, mailbox: &BoxName, pseudonym: &Pseudonym) -> Result<bool>;

    /// Deletes a mailbox with its posts, token sets, cids, mutes and, for
    /// a public room, the room, whose name is then free (7.5, 10.4). Its
    /// box and group id stay used (5.2). Returns whether it existed.
    fn drop_mailbox(&self, mailbox: &BoxName) -> Result<bool>;

    /// Deletes, as of `now`: posts older than `retention`, oldest first in
    /// each mailbox, stopping at its first post that is not old enough
    /// (7.5); cids older than [`CID_LIFETIME`] (7.6); the token sets in
    /// which no hash has been added or used for `retention` (7.2); and
    /// mutes that ended (6.4).
    fn expire(&self, now: Timestamp, retention: Duration) -> Result<Expired>;

    /// Mailboxes that keep no post and have had none, nor been created,
    /// since `before`: once nobody follows them either, their group cannot
    /// go on there, and they may end (7.5).
    fn idle_mailboxes(&self, before: Timestamp) -> Result<Vec<BoxName>>;
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

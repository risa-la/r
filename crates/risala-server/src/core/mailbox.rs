//! Mailboxes and delivery (5.2, 6.1, 6.4, 7): CREATE, POST, GROUPINFO,
//! MUTE, UNMUTE, FOLLOW, UNFOLLOW, FETCH and TOKEN, the GONE and DROP
//! lines, moves (7.8), retention and quotas (7.5).
//!
//! # Order
//!
//! Each mailbox has a lock, an async mutex, held while a post is checked,
//! kept and sent to the mailbox's followers, while TOKEN changes its token
//! sets, and while FOLLOW reads its head, starts following and queues its
//! `OK`. So followers get posts in seq order, and FOLLOW's `OK` agrees with
//! the live posts as 3.6 says: every post queued before it is covered by
//! its head, and every post queued after it is newer.
//!
//! # What is kept
//!
//! The store keeps mailboxes, token hashes, posts, cids, public rooms,
//! their members and mutes ([`MailboxStore`]), and nothing about the
//! connections or addresses that made them (4.2). Which connections follow
//! which mailboxes, and the counts behind the limits per connection and
//! per network address, are kept in memory only, for the life of the
//! connection or the limit's window.
//!
//! Public rooms' groups, which the server checks (12.6), are in [`room`].

pub(super) mod room;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use risala_mls::framing::{ContentType, Sender, read_post};
use risala_proto::command::{Command, CreateForm, Move};
use risala_proto::error::ErrorCode;
use risala_proto::mls::{
    GroupId, GroupInfo, MlsMessage, OrBlob, PostToken, Pseudonym, SendToken, TokenHash,
};
use risala_proto::names::{BlobRef, BoxName, Seq, Uid};
use risala_proto::server::{ErrResponse, OkResponse, Post, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::{DEFAULT_FETCH_LIMIT, MIN_FETCH_LIMIT_CAP, PushTag, Role};
use tokio::sync::OwnedMutexGuard;

use super::command::{Cx, Reply, err, misrouted};
use super::rate::{WindowLimit, network};
use super::state::{ConnEntry, Who};
use super::{Inner, keys, misc};
use crate::config::Config;
use crate::handler::{ConnId, OutLine};
use crate::store::{
    Created, MailboxRecord, NewMailbox, NewPost, PostBody, Posted, RoomChange, Store, StoreError,
    StoredPost,
};

/// The window of the limits on CREATE, commits and TOKEN, and on the bytes
/// an address stores (5.2, 7.2, 7.5).
const HOUR: Duration = Duration::from_secs(60 * 60);

/// The window of the limit on posts (4.2, 5.2).
const MINUTE: Duration = Duration::from_secs(60);

/// How often the area's background work runs.
const MAINTAIN_EVERY: Duration = Duration::from_secs(60);

/// What the mailbox area keeps in memory.
pub(crate) struct State {
    follows: Mutex<Follows>,
    /// Each mailbox's lock, while anyone holds it.
    locks: Mutex<HashMap<BoxName, Weak<tokio::sync::Mutex<()>>>>,
    /// Limits per connection and per network address (4.2, 5.2, 7.2).
    creates: Limit,
    posts: Limit,
    commits: Limit,
    /// Join proposals with `-`, per network address (6.1, 12.6).
    joins: WindowLimit<IpAddr>,
    /// Public rooms' groups (12.6).
    rooms: room::Rooms,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").finish_non_exhaustive()
    }
}

/// Which connections follow which mailboxes (7.1), both ways, with each
/// follow's `quiet` tag (9.2).
#[derive(Debug, Default)]
struct Follows {
    by_box: HashMap<BoxName, BTreeMap<ConnId, Option<PushTag>>>,
    by_conn: HashMap<ConnId, BTreeSet<BoxName>>,
}

/// A limit in a sliding window, per connection and per network address.
#[derive(Debug)]
struct Limit {
    conns: WindowLimit<ConnId>,
    addresses: WindowLimit<IpAddr>,
}

impl Limit {
    fn new(window: Duration) -> Limit {
        Limit {
            conns: WindowLimit::new(window),
            addresses: WindowLimit::new(window),
        }
    }

    /// Takes a slot of `max` for the connection and for its network
    /// address, and keeps both, or fails with `ERR rate-limited` and the
    /// seconds to wait.
    fn take(&self, cx: &Cx, max: u32, now: Timestamp) -> Result<(), ErrResponse> {
        self.slots(cx, max, now)?.keep();
        Ok(())
    }

    /// Takes a slot of `max` for the connection and for its network
    /// address, given back unless [`Slots::keep`] is called.
    fn slots(&self, cx: &Cx, max: u32, now: Timestamp) -> Result<Slots<'_>, ErrResponse> {
        let conn = self.conns.take(cx.conn, max, now).map_err(rate_limited)?;
        let address = self
            .addresses
            .take(network(cx.peer.ip()), max, now)
            .map_err(rate_limited)?;
        Ok(Slots { conn, address })
    }
}

/// The slots [`Limit::slots`] took.
struct Slots<'a> {
    conn: Option<super::rate::Slot<'a, ConnId>>,
    address: Option<super::rate::Slot<'a, IpAddr>>,
}

impl Slots<'_> {
    fn keep(self) {
        self.conn.into_iter().for_each(|slot| slot.keep());
        self.address.into_iter().for_each(|slot| slot.keep());
    }
}

fn rate_limited(retry: u64) -> ErrResponse {
    err(ErrorCode::RateLimited).with_retry(retry)
}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {
            follows: Mutex::default(),
            locks: Mutex::default(),
            creates: Limit::new(HOUR),
            posts: Limit::new(MINUTE),
            commits: Limit::new(HOUR),
            joins: WindowLimit::new(HOUR),
            rooms: room::Rooms::new(),
        })
    }

    fn follows(&self) -> MutexGuard<'_, Follows> {
        self.follows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The lock of `mailbox` (see the [module](self) docs).
    async fn lock(&self, mailbox: BoxName) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            match locks.get(&mailbox).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    if locks.len() >= 1024 {
                        locks.retain(|_, lock| lock.strong_count() > 0);
                    }
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    locks.insert(mailbox, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }

    /// Connection `conn` follows `mailbox` from now on (7.1), with `quiet`
    /// (9.2). Returns `false` if it already follows `max` others.
    pub(crate) fn follow(
        &self,
        mailbox: BoxName,
        conn: ConnId,
        quiet: Option<PushTag>,
        max: usize,
    ) -> bool {
        let mut follows = self.follows();
        let boxes = follows.by_conn.entry(conn).or_default();
        if !boxes.contains(&mailbox) && boxes.len() >= max {
            return false;
        }
        boxes.insert(mailbox);
        follows
            .by_box
            .entry(mailbox)
            .or_default()
            .insert(conn, quiet);
        true
    }

    /// Connection `conn` no longer follows `mailbox`.
    fn unfollow(&self, mailbox: &BoxName, conn: ConnId) {
        let mut follows = self.follows();
        if let Some(boxes) = follows.by_conn.get_mut(&conn) {
            boxes.remove(mailbox);
            if boxes.is_empty() {
                follows.by_conn.remove(&conn);
            }
        }
        if let Some(conns) = follows.by_box.get_mut(mailbox) {
            conns.remove(&conn);
            if conns.is_empty() {
                follows.by_box.remove(mailbox);
            }
        }
    }

    /// The connections that follow `mailbox`.
    pub(crate) fn followers(&self, mailbox: &BoxName) -> Vec<ConnId> {
        self.follows()
            .by_box
            .get(mailbox)
            .map(|conns| conns.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Forgets the public room's group kept in memory, as a restart does.
    #[cfg(test)]
    pub(crate) fn forget_room(&self, mailbox: &BoxName) {
        self.rooms.forget(mailbox);
    }

    /// Whether the public room's group is kept in memory (12.6).
    #[cfg(test)]
    pub(crate) fn room_cached(&self, mailbox: &BoxName) -> bool {
        self.rooms.is_cached(mailbox)
    }

    /// Whether any connection follows `mailbox`.
    fn followed(&self, mailbox: &BoxName) -> bool {
        self.follows().by_box.contains_key(mailbox)
    }

    /// Connection `conn` follows nothing any more.
    fn forget(&self, conn: ConnId) {
        let mut follows = self.follows();
        for mailbox in follows.by_conn.remove(&conn).unwrap_or_default() {
            if let Some(conns) = follows.by_box.get_mut(&mailbox) {
                conns.remove(&conn);
                if conns.is_empty() {
                    follows.by_box.remove(&mailbox);
                }
            }
        }
    }

    /// Nobody follows `mailbox` any more: it is gone. Returns who did.
    fn forget_mailbox(&self, mailbox: &BoxName) -> Vec<ConnId> {
        let mut follows = self.follows();
        let conns: Vec<ConnId> = follows
            .by_box
            .remove(mailbox)
            .map(|conns| conns.into_keys().collect())
            .unwrap_or_default();
        for conn in &conns {
            if let Some(boxes) = follows.by_conn.get_mut(conn) {
                boxes.remove(mailbox);
                if boxes.is_empty() {
                    follows.by_conn.remove(conn);
                }
            }
        }
        conns
    }
}

/// What the mailbox area keeps about one connection: nothing, beyond what
/// [`State`] keeps.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles CREATE, POST, GROUPINFO, MUTE, UNMUTE, FOLLOW, UNFOLLOW, FETCH
/// and TOKEN.
pub(super) async fn handle(cx: &Cx, command: Command) -> Reply {
    match command {
        Command::Create {
            mailbox,
            group_id,
            token_hash,
            form,
        } => match form {
            CreateForm::Private { moving } => {
                create(cx, mailbox, group_id, token_hash, moving).await
            }
            CreateForm::Public(public) => {
                room::create(cx, mailbox, group_id, token_hash, public).await
            }
        },
        Command::Post {
            mailbox,
            token,
            message,
            live,
            groupinfo,
            next,
            cid,
        } => {
            let post = PostCommand {
                mailbox,
                token,
                message,
                live,
                groupinfo,
                next,
                cid: cid.map(|cid| cid.as_str().to_owned()),
            };
            handle_post(cx, post).await
        }
        Command::GroupInfo { mailbox } => room::group_info(cx, mailbox).await,
        Command::Mute {
            mailbox,
            pseudonym,
            hours,
        } => room::mute(cx, mailbox, pseudonym, hours.map(|h| h.get())).await,
        Command::Unmute { mailbox, pseudonym } => room::unmute(cx, mailbox, pseudonym).await,
        Command::Follow { mailbox, quiet } => follow(cx, mailbox, quiet).await,
        Command::Unfollow { mailbox } => unfollow(cx, mailbox).await,
        Command::Fetch {
            mailbox,
            after,
            limit,
            leaf,
        } => fetch(cx, mailbox, after, limit.map(|l| l.get()), leaf).await,
        Command::Token {
            mailbox,
            epoch,
            token,
            hash,
        } => handle_token(cx, mailbox, epoch, token, hash).await,
        other => misrouted("mailbox", &other),
    }
}

/// The mailbox `mailbox`, or `ERR not-found`.
async fn mailbox(cx: &Cx, mailbox: BoxName) -> Result<MailboxRecord, ErrResponse> {
    cx.db(move |store| store.mailbox(&mailbox))
        .await?
        .ok_or_else(|| err(ErrorCode::NotFound))
}

/// `CREATE <box> <group-id> <token-hash> [epoch=<epoch> from=<box>
/// token=<token>]` (5.2, 7.8): the mailbox of a direct conversation or a
/// private room, or with the options, of a group that moves from `from`,
/// which only a holder of a send token of the epoch before can create.
async fn create(
    cx: &Cx,
    mailbox: BoxName,
    group_id: GroupId,
    token_hash: TokenHash,
    moving: Option<Move>,
) -> Reply {
    let inner = &cx.inner;
    let now = inner.now();
    inner
        .mailbox
        .creates
        .take(cx, inner.config.limits.creates_per_hour, now)?;
    let (first_epoch, moved_from) = match &moving {
        None => (0, None),
        Some(Move { epoch, from, token }) => {
            let (epoch, from, hash) = (epoch.get(), *from, token.hash());
            let held = cx
                .db(move |store| {
                    let Some(old) = store.mailbox(&from)? else {
                        return Ok(Err(ErrorCode::NotFound));
                    };
                    if old.group_id != group_id {
                        return Ok(Err(ErrorCode::NotFound));
                    }
                    // Public rooms never move (5.2, 7.8).
                    if old.room.is_some() {
                        return Ok(Err(ErrorCode::Forbidden));
                    }
                    store.has_token(&from, epoch - 1, &hash).map(Ok)
                })
                .await?;
            match held {
                Err(code) => return Err(err(code)),
                Ok(false) => return Err(err(ErrorCode::Stale)),
                Ok(true) => (epoch, Some(from)),
            }
        }
    };
    let new = NewMailbox {
        mailbox,
        group_id,
        first_epoch,
        moved_from,
        token_hash,
        created: now,
    };
    match cx.db(move |store| store.create_mailbox(&new)).await? {
        Created::Created | Created::Exists => Ok(OkResponse::new()),
        Created::Taken => Err(err(ErrorCode::NameTaken)),
        Created::NoGroup => Err(err(ErrorCode::NotFound)),
    }
}

/// A POST, as parsed.
struct PostCommand {
    mailbox: BoxName,
    token: PostToken,
    message: OrBlob<MlsMessage>,
    live: bool,
    groupinfo: Option<OrBlob<GroupInfo>>,
    next: Option<TokenHash>,
    cid: Option<String>,
}

/// What POST read from a message's framing (5.2).
pub(super) struct PostFraming {
    /// Whether it is a PrivateMessage.
    pub(super) private: bool,
    /// Its epoch.
    pub(super) epoch: u64,
    /// Its content type.
    pub(super) content_type: ContentType,
    /// A PublicMessage's sender.
    pub(super) sender: Option<Sender>,
    /// A PrivateMessage's pseudonym (7.3).
    pub(super) pseudonym: Option<Pseudonym>,
}

/// Reads and checks a post's framing (5.2, points 1 and 2): `ERR invalid`
/// unless it is a PrivateMessage or PublicMessage of `mls10` with a
/// RisalaAAD that fits it, of the mailbox's group.
fn read_framing(bytes: &[u8], group_id: &GroupId) -> Result<PostFraming, ErrResponse> {
    let invalid = |what: &str| err(ErrorCode::Invalid).with_message(what);
    let (framing, aad) = read_post(bytes).map_err(|e| invalid(&e.to_string()))?;
    if framing.group_id != &group_id.as_bytes()[..] {
        return Err(invalid("the message is not of the mailbox's group"));
    }
    Ok(PostFraming {
        private: framing.private,
        epoch: framing.epoch,
        content_type: framing.content_type,
        sender: framing.sender,
        pseudonym: framing
            .private
            .then_some(aad_pseudonym(&aad))
            .flatten()
            .map(Pseudonym::from_bytes),
    })
}

/// The pseudonym of a RisalaAAD (7.3): 16 bytes in a PrivateMessage, which
/// `read_post` has checked.
fn aad_pseudonym(aad: &risala_mls::RisalaAad) -> Option<[u8; 16]> {
    aad.pseudonym.map(|p| p.0)
}

/// The bytes of a public room's message, GroupInfo or tree in a line,
/// which the server reads whole to check them (12.6): decoded, or read
/// from its blob in the keys area's store (12.12), up to
/// `limits.max_room_blob`, in the room `memory` took for it: `ERR
/// not-found` if the server holds no such blob, `ERR too-long` past the
/// limit.
pub(super) async fn line_bytes<T>(
    inner: &Inner,
    memory: &mut keys::BlobMemory,
    value: &OrBlob<T>,
    decode: impl FnOnce(&T) -> Vec<u8>,
) -> Result<keys::BlobBytes, ErrResponse> {
    match value {
        OrBlob::Inline(inline) => Ok(keys::BlobBytes::inline(decode(inline))),
        OrBlob::Blob(blob) => memory
            .read(inner, blob, inner.config.limits.max_room_blob)
            .await
            .map_err(no_blob),
    }
}

/// Room in `limits.blob_memory` for the values of `values` that are
/// blobs, which the command then reads with [`line_bytes`]: taken once
/// for them all, so that the command never waits for room while it holds
/// some (12.12).
pub(super) async fn reserve_lines(
    inner: &Inner,
    values: impl IntoIterator<Item = Option<BlobRef>>,
) -> Result<keys::BlobMemory, ErrResponse> {
    let max = inner.config.limits.max_room_blob;
    keys::reserve(inner, values.into_iter().flatten().map(|blob| (blob, max)))
        .await
        .map_err(no_blob)
}

/// The blob a line's value names, if it is one.
pub(super) fn blob_of<T>(value: &OrBlob<T>) -> Option<BlobRef> {
    match value {
        OrBlob::Inline(_) => None,
        OrBlob::Blob(blob) => Some(*blob),
    }
}

/// The answer when a line's blob cannot be read.
fn no_blob(why: keys::NoBlob) -> ErrResponse {
    match why {
        keys::NoBlob::NotFound => err(ErrorCode::NotFound).with_message("no such blob"),
        why => ErrResponse::from(why),
    }
}

/// How much of a blob POST reads to find a message's framing (5.2): its
/// group id, epoch, content type, RisalaAAD and the lengths after them
/// take a few hundred bytes.
const FRAMING_PREFIX: usize = 16 * 1024;

/// A PrivateMessage of `size` bytes in all, from its first bytes: those
/// bytes up to its ciphertext's length, and a ciphertext of one byte in
/// place of its own. It reads as the message does for its framing (5.2),
/// whose checks do not look into the ciphertext, so the server need not
/// hold the whole message. `None` if `prefix` is not the start of a
/// well-formed PrivateMessage of exactly `size` bytes.
pub(super) fn private_message_stub(prefix: &[u8], size: u64) -> Option<Vec<u8>> {
    // version (2 bytes), then wire_format mls_private_message (2).
    if prefix.get(2..4)? != [0, 2] {
        return None;
    }
    let mut at = 4;
    let vector = |at: &mut usize| -> Option<()> {
        let (len, took) = keys::varint(prefix.get(*at..)?)?;
        *at = at.checked_add(took)?.checked_add(len)?;
        (*at <= prefix.len()).then_some(())
    };
    vector(&mut at)?; // group_id
    at += 8 + 1; // epoch, content_type
    vector(&mut at)?; // authenticated_data
    vector(&mut at)?; // encrypted_sender_data
    let (len, took) = keys::varint(prefix.get(at..)?)?;
    let end = (at as u64)
        .checked_add(took as u64)?
        .checked_add(len as u64)?;
    if end != size || len == 0 {
        return None;
    }
    let mut stub = prefix[..at].to_vec();
    stub.extend_from_slice(&[1, 0]);
    Some(stub)
}

/// The bytes of a post's message to read its framing from (5.2), and,
/// for a PublicMessage, which the server checks whole (12.6), the whole
/// message. A message in a blob is not read whole otherwise: only its
/// first bytes, so that POST never holds a large blob for a message it
/// does not check.
///
/// With them, the room in `limits.blob_memory` for every blob the post
/// reads whole: the message's, and in a public room its GroupInfo's,
/// which 12.6's checks read after the framing's. Both are taken at once,
/// so that POST never waits for room while it holds some (12.12).
async fn post_bytes(
    inner: &Inner,
    post: &PostCommand,
    public_room: bool,
) -> Result<(keys::BlobBytes, keys::BlobMemory), ErrResponse> {
    let message = &post.message;
    let groupinfo = post.groupinfo.as_ref().filter(|_| public_room);
    let framing_only = match message {
        OrBlob::Inline(inline) => Some(keys::BlobBytes::inline(MlsMessage::decode(inline))),
        OrBlob::Blob(blob) => {
            let (prefix, size) = keys::blob_prefix(inner, blob, FRAMING_PREFIX)
                .await
                .map_err(no_blob)?;
            if prefix.len() as u64 == size {
                Some(keys::BlobBytes::inline(prefix))
            } else if let Some(stub) = private_message_stub(&prefix, size) {
                Some(keys::BlobBytes::inline(stub))
            } else if !public_room {
                // Not a PrivateMessage, and outside a public room a post is one.
                return Err(err(ErrorCode::Invalid).with_message("not a PrivateMessage"));
            } else {
                None
            }
        }
    };
    let whole = framing_only.is_none().then(|| blob_of(message)).flatten();
    let mut memory = reserve_lines(inner, [whole, groupinfo.and_then(blob_of)]).await?;
    let bytes = match framing_only {
        Some(bytes) => bytes,
        None => line_bytes(inner, &mut memory, message, MlsMessage::decode).await?,
    };
    Ok((bytes, memory))
}

/// `POST <box> <token> <message> [live=yes] [groupinfo=<groupinfo>]
/// [next=<hash>]` (5.2), with the checks in the spec's order.
async fn handle_post(cx: &Cx, post: PostCommand) -> Reply {
    let inner = &cx.inner;
    let mailbox = post.mailbox;
    let _lock = inner.mailbox.lock(mailbox).await;
    let now = inner.now();

    // The cid comes before anything else about the post (7.6). A live
    // post gets no seq, so its cid is not kept.
    let cid = post.cid.clone().filter(|_| !post.live);
    let since = now
        .checked_sub(crate::store::mailbox::CID_LIFETIME)
        .unwrap_or(Timestamp::MIN);
    let (record, seen) = cx
        .db({
            let cid = cid.clone();
            move |store| {
                let record = store.mailbox(&mailbox)?;
                let seen = match (&record, &cid) {
                    (Some(_), Some(cid)) => store.cid_post(&mailbox, cid, since)?,
                    _ => None,
                };
                Ok((record, seen))
            }
        })
        .await?;
    if let Some(seq) = seen {
        return Ok(OkResponse::new().with("seq", seq));
    }
    // 1. The mailbox exists, and the message is of its group.
    let record = record.ok_or_else(|| err(ErrorCode::NotFound))?;
    let public_room = record.room.is_some();
    let limits = &inner.config.limits;
    // A post whose message is a blob uses up its slot before the server
    // reads any of the blob, whatever then becomes of it, so that failing
    // posts cannot make the server read blobs for nothing.
    let blob = matches!(post.message, OrBlob::Blob(_));
    if blob {
        inner.mailbox.posts.take(cx, limits.posts_per_minute, now)?;
    }
    let (bytes, mut memory) = post_bytes(inner, &post, public_room).await?;
    let (bytes, _held) = bytes.into_parts();
    // 2. The framing.
    let framing = read_framing(&bytes, &record.group_id)?;
    let invalid = |what: &str| Err(err(ErrorCode::Invalid).with_message(what));
    let commit = framing.content_type == ContentType::Commit;
    if !framing.private && !public_room {
        return invalid("a PublicMessage outside a public room");
    }
    if framing.private && public_room && framing.content_type != ContentType::Application {
        // A public room's commits and proposals are PublicMessages, which
        // the server checks (12.6).
        return invalid("a public room's commits and proposals are PublicMessages");
    }
    if commit != post.next.is_some() {
        return invalid("a commit has next, and nothing else does");
    }
    if post.live && framing.content_type != ContentType::Application {
        return invalid("only application messages may be live");
    }
    if post.groupinfo.is_some() != (commit && public_room) {
        return invalid("a public room's commit has groupinfo, and nothing else does");
    }
    // 5, the kind of connection: a signed-in connection posts a public
    // room's PublicMessages only (13).
    if matches!(cx.who, Who::SignedIn(_)) && framing.private {
        return Err(err(ErrorCode::WrongConnection));
    }
    // 3. The token.
    let used = match &post.token {
        PostToken::Join => {
            let join = matches!(
                framing.sender,
                Some(Sender::NewMemberCommit | Sender::NewMemberProposal)
            );
            if !(public_room && join) {
                return Err(
                    err(ErrorCode::Forbidden).with_message("- is only for joining a public room")
                );
            }
            None
        }
        PostToken::Send(token) => {
            let hash = token.hash();
            let epoch = framing.epoch;
            let held = cx
                .db(move |store| store.has_token(&mailbox, epoch, &hash))
                .await?;
            if !held {
                return Err(err(ErrorCode::Stale));
            }
            Some((epoch, hash))
        }
    };
    // Join proposals, which need no membership, have a limit of their own
    // per network address, far below that of posts (6.1, 12.6); kept once
    // the post's other limits pass. Limits per network address are the
    // free tier: past them a client will go on by proof of work, from M6a
    // (PLAN items 42 and 63).
    let join_slot = if matches!(post.token, PostToken::Join)
        && framing.sender == Some(Sender::NewMemberProposal)
    {
        inner
            .mailbox
            .joins
            .take(network(cx.peer.ip()), limits.joins_per_hour, now)
            .map_err(rate_limited)?
    } else {
        None
    };
    // 4. Mutes and limits.
    if let Some(pseudonym) = framing.pseudonym {
        let muted = cx
            .db(move |store| store.muted(&mailbox, &pseudonym, now))
            .await?;
        if muted {
            return Err(err(ErrorCode::Forbidden).with_message("muted"));
        }
    }
    // At most so many proposals from one network address pending in one
    // epoch of a public room (12.6); proof of work past it comes in M6a
    // (PLAN items 42 and 63).
    let proposal_from = (public_room && framing.content_type == ContentType::Proposal)
        .then(|| network(cx.peer.ip()));
    if let Some(from) = proposal_from
        && !inner.mailbox.rooms.may_propose(
            mailbox,
            framing.epoch,
            from,
            limits.pending_per_address,
        )
    {
        return Err(rate_limited(60));
    }
    // A post and a commit use up their slots together, or neither.
    let post_slots = if blob {
        None
    } else {
        Some(
            inner
                .mailbox
                .posts
                .slots(cx, limits.posts_per_minute, now)?,
        )
    };
    let commit_slots = if commit {
        Some(
            inner
                .mailbox
                .commits
                .slots(cx, limits.commits_per_hour, now)?,
        )
    } else {
        None
    };
    post_slots.into_iter().for_each(Slots::keep);
    commit_slots.into_iter().for_each(Slots::keep);
    if let Some(slot) = join_slot {
        slot.keep();
    }
    let message = match &post.message {
        OrBlob::Inline(_) => PostBody::Inline(bytes.clone()),
        OrBlob::Blob(blob) => PostBody::Blob(*blob),
    };
    // One window per network address, with UPLOAD and BLOB (7.5).
    if !post.live {
        keys::charge_address(inner, cx.peer.ip(), message.size())?;
    }
    // 5. A public room's commits and proposals.
    let room = if public_room && !framing.private {
        let groupinfo = match &post.groupinfo {
            Some(groupinfo) => {
                Some(line_bytes(inner, &mut memory, groupinfo, GroupInfo::decode).await?)
            }
            None => None,
        };
        let (groupinfo, _held_info) = match groupinfo.map(keys::BlobBytes::into_parts) {
            Some((bytes, held)) => (Some(bytes), held),
            None => (None, None),
        };
        Some(room::check_post(cx, &record, &framing, bytes, groupinfo, post.next, now).await?)
    } else {
        None
    };

    if post.live {
        // Not kept, numbered or pushed (5.2).
        let line = Post::live(now, mailbox, post.message);
        send_to_followers(inner, &mailbox, &OutLine::new(ServerMessage::new(line)));
        return Ok(OkResponse::new());
    }
    // A commit's tree too long for GROUPINFO's line is stored as a blob
    // now, once for the epoch, so that GROUPINFO writes nothing (6.1,
    // 12.12).
    let mut room = room;
    if let Some(room::CheckedPost {
        change: RoomChange::Commit(update),
        ..
    }) = room.as_mut()
    {
        room::store_tree_blob(&cx.inner, update).await?;
    }
    // One quota for the mailbox's posts, files and blobs (7.5): its posts
    // take what its files and blobs leave.
    let files = keys::stored_bytes(inner, mailbox).await.map_err(|e| {
        tracing::error!("mailbox: {e}");
        err(ErrorCode::Internal)
    })?;
    let quota = limits.mailbox_quota.saturating_sub(files);
    let new = NewPost {
        mailbox,
        t: now,
        message,
        token: used,
        next: post.next.map(|next| (framing.epoch, next)),
        cid,
        quota,
        room: room.as_ref().map(|room| room.change.clone()),
        handshake: framing.content_type != ContentType::Application,
    };
    let seq = match cx.db(move |store| store.add_post(&new)).await? {
        Posted::Seq(seq) => seq,
        Posted::OverQuota => return Err(rate_limited(HOUR.as_secs())),
        Posted::NoMailbox => return Err(err(ErrorCode::NotFound)),
    };
    if let Some(from) = proposal_from {
        inner.mailbox.rooms.proposed(mailbox, framing.epoch, from);
    }
    if let Some(room) = room
        && let Some(joins) = inner.mailbox.rooms.applied(mailbox, room)
    {
        // Before the OK, so that the committer's WELCOME PUT with `-` finds
        // the joins (12.6, 12.8). The post is kept by now, so a failure
        // here costs the joiners only their Welcomes: they propose again.
        let room::Joins {
            epoch,
            committer_uid,
            committer,
            refs,
            tree,
        } = joins;
        if let Err(e) = keys::room_joins_committed(
            &cx.inner,
            mailbox,
            epoch,
            committer_uid,
            committer,
            refs,
            tree,
        )
        .await
        {
            tracing::error!("keeping a public room's joins for Welcomes: {e}");
        }
    }
    let seq = Seq::new(seq).ok_or_else(|| err(ErrorCode::Internal))?;
    let mut line = Post::new(seq, now, mailbox, post.message);
    if let Some(next) = post.next {
        line = line.with_next(next);
    }
    send_to_followers(inner, &mailbox, &OutLine::new(ServerMessage::new(line)));
    // A kept post is pushed; a live one is not (5.2, 9.2).
    misc::post_kept(&cx.inner, mailbox);
    Ok(OkResponse::new().with("seq", seq))
}

/// Sends `line` to every connection that follows `mailbox`.
fn send_to_followers(inner: &Inner, mailbox: &BoxName, line: &OutLine) {
    let followers = inner.mailbox.followers(mailbox);
    if followers.is_empty() {
        return;
    }
    let handles: Vec<_> = {
        let reg = inner.reg();
        followers
            .iter()
            .filter_map(|id| reg.conns.get(id))
            .map(|conn| conn.handle.clone())
            .collect()
    };
    for handle in handles {
        handle.send_line(line.clone());
    }
}

/// `TOKEN <box> <epoch> <token> <hash>` (7.2): adds `hash` to the set of
/// epoch `epoch + 1`, for a holder of a token of `epoch`.
async fn handle_token(
    cx: &Cx,
    mailbox: BoxName,
    epoch: u64,
    token: SendToken,
    hash: TokenHash,
) -> Reply {
    let inner = &cx.inner;
    let _lock = inner.mailbox.lock(mailbox).await;
    let now = inner.now();
    let record = self::mailbox(cx, mailbox).await?;
    // In a public room, the server takes one commit an epoch, so a wrong
    // hash leads to a resync, never to TOKEN (7.2, 12.7).
    if record.room.is_some() {
        return Err(err(ErrorCode::Forbidden).with_message("not in a public room"));
    }
    // An epoch of 2^63-1 has no next epoch (3.3, 7.2).
    let next_epoch = epoch.saturating_add(1);
    if next_epoch > Seq::MAX.get() {
        return Err(err(ErrorCode::Stale));
    }
    // For the epoch just before a moved mailbox's first, the token is
    // checked against the set of the mailbox the group moved from (7.8).
    let checked_in = if next_epoch == record.first_epoch {
        record.moved_from
    } else {
        Some(mailbox)
    };
    let token_hash = token.hash();
    let held = match checked_in {
        Some(from) => {
            cx.db(move |store| store.has_token(&from, epoch, &token_hash))
                .await?
        }
        None => false,
    };
    if !held {
        return Err(err(ErrorCode::Stale));
    }
    inner
        .mailbox
        .commits
        .take(cx, inner.config.limits.commits_per_hour, now)?;
    cx.db(move |store| store.add_token(&mailbox, next_epoch, &hash, now))
        .await?;
    Ok(OkResponse::new())
}

/// `FOLLOW <box> [quiet=<tag>]` (7.1). The `OK` is queued while no post of
/// the mailbox can be (3.6).
async fn follow(cx: &Cx, mailbox: BoxName, quiet: Option<PushTag>) -> Reply {
    let inner = &cx.inner;
    let _lock = inner.mailbox.lock(mailbox).await;
    let record = self::mailbox(cx, mailbox).await?;
    if !inner.mailbox.follow(
        mailbox,
        cx.conn,
        quiet.clone(),
        inner.config.limits.max_follows,
    ) {
        return Err(err(ErrorCode::Forbidden).with_message("following too many mailboxes"));
    }
    // The push subscription that `quiet` names is held back meanwhile (9.2).
    misc::follow_quiet(inner, cx.conn, mailbox, quiet);
    cx.reply_now(Ok(OkResponse::new().with("head", record.head)));
    Ok(OkResponse::new())
}

/// `UNFOLLOW <box>` (7.1).
async fn unfollow(cx: &Cx, mailbox: BoxName) -> Reply {
    self::mailbox(cx, mailbox).await?;
    cx.inner.mailbox.unfollow(&mailbox, cx.conn);
    misc::unfollow(&cx.inner, cx.conn, &mailbox);
    Ok(OkResponse::new())
}

/// `FETCH <box> after=<position> [limit=<n>] [leaf=<n>]` (7.1).
async fn fetch(
    cx: &Cx,
    mailbox: BoxName,
    after: u64,
    limit: Option<u64>,
    leaf: Option<u32>,
) -> Reply {
    let record = self::mailbox(cx, mailbox).await?;
    if leaf.is_some() {
        if record.room.is_none() {
            return Err(err(ErrorCode::Invalid).with_message("leaf is for public rooms"));
        }
        // Light clients (12.6) are not in this version (docs/plans/M5b.md).
        return Err(err(ErrorCode::NotSupported).with_message("light clients"));
    }
    let limits = &cx.inner.config.limits;
    let cap = limits.max_page.max(MIN_FETCH_LIMIT_CAP);
    let limit = limit.unwrap_or(DEFAULT_FETCH_LIMIT).min(cap);
    // A page stops once its lines pass a budget of bytes, with `more=1`,
    // so that a page of long posts never overflows the connection's queue,
    // and the store reads no post past it, so that a FETCH holds no more
    // than about the budget while it waits for room (7.1 lets the server
    // return fewer posts than asked for).
    let budget = fetch_budget(limits);
    let (posts, more) = cx
        .db(move |store| store.posts(&mailbox, after, limit, budget))
        .await?;
    for (i, post) in posts.into_iter().enumerate() {
        if i > 0 {
            // Room for one long line, as KEYPKG GET and WELCOME LIST wait.
            cx.wait_for_room().await;
        }
        cx.send(post_line(mailbox, post)?);
    }
    Ok(OkResponse::new().with("more", u8::from(more)))
}

/// The most bytes of POST lines one FETCH queues (7.1): half of what a
/// connection's queue holds, and at most 8 MiB.
fn fetch_budget(limits: &crate::config::Limits) -> u64 {
    (u64::try_from(limits.out_queue_bytes).unwrap_or(u64::MAX) / 2).min(8 * 1024 * 1024)
}

/// A kept post as a POST line (5.2).
fn post_line(mailbox: BoxName, post: StoredPost) -> Result<Post, ErrResponse> {
    let internal = |what: &str| {
        tracing::error!("a stored post's {what} cannot be sent");
        err(ErrorCode::Internal)
    };
    let seq = Seq::new(post.seq).ok_or_else(|| internal("seq"))?;
    let message = match post.message {
        PostBody::Inline(bytes) => {
            OrBlob::Inline(MlsMessage::from_bytes(&bytes).map_err(|_| internal("message"))?)
        }
        PostBody::Blob(blob) => OrBlob::Blob(blob),
    };
    let line = Post::new(seq, post.t, mailbox, message);
    Ok(match post.next {
        Some(next) => line.with_next(next),
        None => line,
    })
}

/// Checks a send token that comes without its epoch, as PUSH ADD, UPLOAD
/// and BLOB carry one (9.1, 5.6, 12.12), against every set of `mailbox`:
/// `ERR not-found` for a mailbox that does not exist, `ERR stale` for a
/// token in none.
pub(crate) async fn check_token(
    inner: &Inner,
    mailbox: &BoxName,
    token: &SendToken,
) -> Result<(), ErrorCode> {
    let mailbox = *mailbox;
    let hash = token.hash();
    let found = inner
        .db(move |store| {
            if store.mailbox(&mailbox)?.is_none() {
                return Ok(None);
            }
            store.has_token_any(&mailbox, &hash).map(Some)
        })
        .await
        .map_err(|e| {
            tracing::error!("checking a send token: {e}");
            ErrorCode::Internal
        })?;
    match found {
        None => Err(ErrorCode::NotFound),
        Some(false) => Err(ErrorCode::Stale),
        Some(true) => Ok(()),
    }
}

/// Deletes `mailbox` with its posts, and for a public room the room, and
/// sends `DROP <box> [<reason...>]` to every connection that follows it
/// (6.1, 10.4). `reason` is escaped text. Returns whether it existed.
pub(crate) async fn drop_mailbox(
    inner: &Inner,
    mailbox: &BoxName,
    reason: &str,
) -> Result<bool, StoreError> {
    let mailbox = *mailbox;
    let _lock = inner.mailbox.lock(mailbox).await;
    let existed = inner.db(move |store| store.drop_mailbox(&mailbox)).await?;
    inner.mailbox.rooms.forget(&mailbox);
    keys::room_ended(inner, mailbox).await?;
    misc::mailbox_dropped(inner, mailbox).await;
    if existed {
        let line = OutLine::new(ServerMessage::new(ServerLine::Drop {
            mailbox,
            reason: reason.to_owned(),
        }));
        send_to_followers(inner, &mailbox, &line);
    }
    for conn in inner.mailbox.forget_mailbox(&mailbox) {
        misc::unfollow(inner, conn, &mailbox);
    }
    Ok(existed)
}

/// The session of the guest `uid` has ended (4.2): every connection that
/// follows a public room the guest had a leaf in gets `GONE <box> <uid>`,
/// so that members' devices remove its leaves (6.1).
pub(super) async fn guest_session_ended(inner: &Inner, uid: &Uid) {
    let who = uid.clone();
    let rooms = match inner.db(move |store| store.rooms_with_member(&who)).await {
        Ok(rooms) => rooms,
        Err(e) => {
            tracing::error!("finding a guest's rooms for GONE: {e}");
            return;
        }
    };
    for mailbox in rooms {
        let line = OutLine::new(ServerMessage::new(ServerLine::Gone {
            mailbox,
            uid: uid.clone(),
        }));
        send_to_followers(inner, &mailbox, &line);
    }
}

/// Connection `id` has closed: it follows nothing any more.
pub(super) fn conn_closed(inner: &Arc<Inner>, id: ConnId, _conn: &ConnEntry) {
    inner.mailbox.forget(id);
}

/// The area's background work, every minute: expiring posts (7.5) and cids
/// (7.6), forgetting unused token sets (7.2) and ended mutes (6.4), and
/// ending mailboxes (7.5).
pub(super) async fn maintain(inner: Arc<Inner>) {
    let mut every = tokio::time::interval(MAINTAIN_EVERY);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut rounds: u64 = 0;
    loop {
        every.tick().await;
        if let Err(e) = run_maintenance(&inner).await {
            tracing::error!("mailbox maintenance: {e}");
        }
        // Every so often, what expiry deleted leaves the write-ahead log
        // too (4.2).
        rounds += 1;
        if rounds.is_multiple_of(CHECKPOINT_EVERY)
            && let Err(e) = inner.db(|store| store.checkpoint()).await
        {
            tracing::error!("checkpointing the database: {e}");
        }
    }
}

/// How many maintenance rounds go between checkpoints of the database.
const CHECKPOINT_EVERY: u64 = 10;

/// One round of [`maintain`].
pub(super) async fn run_maintenance(inner: &Inner) -> Result<(), StoreError> {
    let now = inner.now();
    let retention = Duration::from_secs(u64::from(inner.settings().retention.days()) * 86_400);
    let expired = inner.db(move |store| store.expire(now, retention)).await?;
    if expired != Default::default() {
        tracing::debug!(?expired, "expired");
    }
    // A mailbox whose posts have all expired, and that nobody follows, has
    // had no device of its group online for a retention period: it ends,
    // and its box is never used again (7.5).
    let before = now.checked_sub(retention).unwrap_or(Timestamp::MIN);
    let idle = inner.db(move |store| store.idle_mailboxes(before)).await?;
    for mailbox in idle {
        let _lock = inner.mailbox.lock(mailbox).await;
        if inner.mailbox.followed(&mailbox) {
            continue;
        }
        // With its token sets and push subscriptions (7.5), if it is still
        // idle now that no post can come in: one may have since the list
        // was read.
        if !inner
            .db(move |store| store.drop_idle_mailbox(&mailbox, before))
            .await?
        {
            continue;
        }
        inner.mailbox.rooms.forget(&mailbox);
        keys::room_ended(inner, mailbox).await?;
        misc::mailbox_dropped(inner, mailbox).await;
    }
    Ok(())
}

/// Files or blobs of `mailbox` will take `files` bytes of its quota (7.5):
/// its oldest posts expire early until its posts fit in the rest, but
/// never its commits and proposals. Returns whether they fit then. Under
/// the mailbox's lock, so that it does not run within a POST. The keys
/// area calls this for UPLOAD and BLOB.
pub(crate) async fn make_room(
    inner: &Inner,
    mailbox: BoxName,
    files: u64,
) -> Result<bool, StoreError> {
    let _lock = inner.mailbox.lock(mailbox).await;
    let max = inner.config.limits.mailbox_quota.saturating_sub(files);
    let (expired, fits) = inner
        .db(move |store| store.trim_posts(&mailbox, max))
        .await?;
    if expired > 0 {
        tracing::debug!(expired, "posts expired early for files");
    }
    Ok(fits)
}

/// The role that lets an identity mute in a public room (6.4).
fn may_mute(role: Option<Role>) -> bool {
    matches!(role, Some(Role::Owner | Role::Mod))
}

/// The most a mailbox may hold at once, for INFO's `quota=` (7.5, 8.5).
pub(crate) fn quota(inner: &Inner) -> Option<u64> {
    Some(inner.config.limits.mailbox_quota)
}

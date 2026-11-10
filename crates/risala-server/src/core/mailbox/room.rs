//! Public rooms (6.1, 6.4, 12.6): the second form of CREATE, the checks of
//! every commit and proposal posted to a room, GROUPINFO, MUTE and UNMUTE.
//!
//! The server holds the public state of each room's group, its ratchet
//! tree and GroupInfo as of the newest epoch and the proposals pending in
//! it, and checks every commit and proposal as far as someone outside the
//! group can (12.6): MLS's own checks through OpenMLS's [`PublicGroup`],
//! the group checks of risala-mls ([`check_commit`]), who may post what on
//! which connection, and the GroupInfo a commit carries. It holds no
//! group's secrets.
//!
//! The groups of rooms that were posted to recently are kept in memory,
//! with the epoch and the number of proposals they are at, and rebuilt from
//! the store when those do not match. A post that fails its checks leaves
//! the group as it was, so it stays in memory. When there are too many,
//! those used least recently go, by the bytes of their trees.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openmls_memory_storage::MemoryStorage;
use risala_mls::RisalaCrypto;
use risala_mls::checks::{
    CommitError, CommitView, EpochState, GroupView, JoinExpectation, check_commit, check_join,
    group_info_keys_ok,
};
use risala_mls::conversation::{ConversationKind, GuestMode, RisalaConversation, Role as MlsRole};
use risala_mls::framing::ContentType;
use risala_mls::identity::{DeviceId, RisalaIdentity};
use risala_mls::keypackage::{
    KeyPackageError, check_key_package_contents, has_no_binding, lifetime_acceptable_at,
};
use risala_mls::openmls::group::ProposalStore;
use risala_mls::openmls::prelude::{
    LeafNodeIndex, ProcessedMessageContent, Proposal, PublicGroup, Sender as MlsSender,
};
use risala_mls::wire::{read_group_info, read_protocol_message, read_tree, tree_to_bytes};
use risala_proto::command::PublicRoom;
use risala_proto::error::ErrorCode;
use risala_proto::frame::MAX_LONG_SERVER_LINE;
use risala_proto::mls::{
    GroupId, GroupInfo, KeyPackageRef, OrBlob, Pseudonym, RatchetTree, TokenHash,
};
use risala_proto::names::{BoxName, Seq, ServerAddr, Uid};
use risala_proto::server::{ErrResponse, OkResponse, ServerLine};
use risala_proto::time::Timestamp;
use risala_proto::types::{GuestAccess, Role};
use tls_codec::Serialize as _;

use super::super::command::{Cx, Reply, err};
use super::super::rate::WindowLimit;
use super::super::state::{Device, Who};
use super::super::{Inner, admin, keys};
use super::{PostFraming, blob_of, line_bytes, may_mute, reserve_lines};
use crate::config::RoomCreation;
use crate::store::{
    Created, MailboxRecord, NewMailbox, NewRoom, RoomChange, RoomGroup, RoomUpdate,
};

/// The most proposals pending in one epoch of a room: enough for the joins
/// and Updates that full clients commit, at most 256 devices a commit
/// (6.1). Further ones get `ERR rate-limited` until a commit.
const MAX_PENDING: usize = 512;

/// The most rooms whose groups are kept in memory.
const CACHED_ROOMS: usize = 256;

/// The most bytes of trees the groups kept in memory may have, together.
/// A group in memory takes some times its tree's encoded size.
const CACHED_TREE_BYTES: usize = 64 * 1024 * 1024;

/// A room's group as of an epoch, in memory.
struct RoomCache {
    /// The bytes of its tree, encoded, to weigh it in the cache.
    tree_bytes: usize,
    /// The epoch.
    epoch: u64,
    /// How many proposals of the epoch it holds.
    proposals: usize,
    group: PublicGroup,
    /// OpenMLS's state of the group: its pending proposals.
    storage: MemoryStorage,
    /// What the group checks need of the epoch besides the tree: the leaf
    /// that started it, and its proposals' times (12.7).
    state: EpochState,
}

/// The public rooms' groups in memory, and the limit on rooms created.
pub(super) struct Rooms {
    cache: Mutex<Cache>,
    crypto: Option<Arc<RisalaCrypto>>,
    /// Rooms each identity created in the last day (5.2, 14).
    created: WindowLimit<Uid>,
    /// For each room, the epoch its pending proposals are of, and how many
    /// each network address posted (12.6). Kept in memory for the epoch
    /// only (4.2).
    pending: Mutex<HashMap<BoxName, Pending>>,
}

/// The epoch a room's pending proposals are of, and how many each network
/// address posted.
type Pending = (u64, HashMap<IpAddr, u32>);

/// The groups in memory, each with when it was last used.
#[derive(Default)]
struct Cache {
    rooms: HashMap<BoxName, (u64, RoomCache)>,
    /// The bytes of their trees.
    tree_bytes: usize,
    /// The use count, which orders them.
    clock: u64,
}

impl Cache {
    fn remove(&mut self, mailbox: &BoxName) -> Option<RoomCache> {
        let (_, room) = self.rooms.remove(mailbox)?;
        self.tree_bytes -= room.tree_bytes;
        Some(room)
    }

    /// Keeps `room`, then lets go of the groups used least recently while
    /// there are too many or their trees are too large together; the one
    /// just kept stays.
    fn insert(&mut self, mailbox: BoxName, room: RoomCache) {
        self.remove(&mailbox);
        self.clock += 1;
        self.tree_bytes += room.tree_bytes;
        self.rooms.insert(mailbox, (self.clock, room));
        while self.rooms.len() > 1
            && (self.rooms.len() > CACHED_ROOMS || self.tree_bytes > CACHED_TREE_BYTES)
        {
            let oldest = self
                .rooms
                .iter()
                .filter(|(m, _)| **m != mailbox)
                .min_by_key(|(_, (used, _))| *used)
                .map(|(m, _)| *m);
            match oldest {
                Some(oldest) => {
                    self.remove(&oldest);
                }
                None => break,
            }
        }
    }
}

/// A post to a room that passed its checks: what it changes, and the
/// group after it.
pub(super) struct CheckedPost {
    /// What to store with the post.
    pub(super) change: RoomChange,
    /// A commit's external joins, which may then get Welcomes (12.8).
    pub(super) joins: Option<Joins>,
    group: RoomCache,
}

/// The external Add proposals a public room's commit applied (12.6, 12.8):
/// one Welcome each may come from the committing device.
pub(super) struct Joins {
    /// The epoch the commit started.
    pub(super) epoch: u64,
    /// The committer's identity and device id (4.4).
    pub(super) committer_uid: Uid,
    pub(super) committer: [u8; 48],
    /// The KeyPackageRefs of the proposals' KeyPackages.
    pub(super) refs: Vec<KeyPackageRef>,
    /// The ratchet tree of the new epoch.
    pub(super) tree: Vec<u8>,
}

impl Rooms {
    pub(super) fn new() -> Rooms {
        let crypto = match RisalaCrypto::new() {
            Ok(crypto) => Some(Arc::new(crypto)),
            Err(e) => {
                tracing::error!("no crypto for public rooms: {e}");
                None
            }
        };
        Rooms {
            cache: Mutex::default(),
            crypto,
            created: WindowLimit::new(Duration::from_secs(24 * 60 * 60)),
            pending: Mutex::default(),
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<BoxName, Pending>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the network address `from` may post another proposal for
    /// `epoch` of `mailbox`: fewer than `max` of its proposals are pending
    /// in that epoch (12.6). A `max` of 0 means no limit.
    pub(super) fn may_propose(&self, mailbox: BoxName, epoch: u64, from: IpAddr, max: u32) -> bool {
        if max == 0 {
            return true;
        }
        match self.pending().get(&mailbox) {
            Some((at, counts)) if *at == epoch => counts.get(&from).copied().unwrap_or(0) < max,
            _ => true,
        }
    }

    /// The network address `from` posted a proposal for `epoch` of
    /// `mailbox`, which is now pending.
    pub(super) fn proposed(&self, mailbox: BoxName, epoch: u64, from: IpAddr) {
        let mut pending = self.pending();
        let entry = pending
            .entry(mailbox)
            .or_insert_with(|| (epoch, HashMap::new()));
        if entry.0 != epoch {
            *entry = (epoch, HashMap::new());
        }
        *entry.1.entry(from).or_default() += 1;
    }

    fn crypto(&self) -> Result<Arc<RisalaCrypto>, ErrResponse> {
        self.crypto.clone().ok_or_else(|| err(ErrorCode::Internal))
    }

    /// The group of `mailbox` as stored: from memory if it is there at the
    /// same epoch and proposals, otherwise rebuilt. Removes it from memory
    /// meanwhile; [`applied`](Self::applied) puts it back.
    fn take(&self, mailbox: &BoxName, stored: &RoomGroup) -> Option<RoomCache> {
        self.cache()
            .remove(mailbox)
            .filter(|c| c.epoch == stored.epoch && c.proposals == stored.proposals.len())
    }

    /// A post to `mailbox` was kept: its group is now `post`'s. Returns
    /// the commit's external joins.
    pub(super) fn applied(&self, mailbox: BoxName, post: CheckedPost) -> Option<Joins> {
        if matches!(post.change, RoomChange::Commit(_)) {
            // A new epoch: no proposal of it is pending yet.
            self.pending().remove(&mailbox);
        }
        self.keep(mailbox, post.group);
        post.joins
    }

    fn keep(&self, mailbox: BoxName, group: RoomCache) {
        self.cache().insert(mailbox, group);
    }

    /// `mailbox` is gone.
    pub(super) fn forget(&self, mailbox: &BoxName) {
        self.cache().remove(mailbox);
        self.pending().remove(mailbox);
    }

    /// Whether the group of `mailbox` is in memory, as of the stored
    /// epoch and proposals.
    #[cfg(test)]
    pub(super) fn is_cached(&self, mailbox: &BoxName) -> bool {
        self.cache().rooms.contains_key(mailbox)
    }
}

/// A room's epoch state (12.7), as the store keeps it.
fn encode_state(state: &EpochState) -> Result<Vec<u8>, ErrResponse> {
    rmp_serde::to_vec(state).map_err(|e| {
        tracing::error!("encoding a public room's epoch state: {e}");
        err(ErrorCode::Internal)
    })
}

/// A room's epoch state (12.7), read back from the store.
fn decode_state(bytes: &[u8]) -> Result<EpochState, ErrResponse> {
    rmp_serde::from_slice(bytes).map_err(|e| {
        tracing::error!("reading a public room's epoch state: {e}");
        err(ErrorCode::Internal)
    })
}

/// A time as the group checks take it: ms since 1970-01-01T00:00:00Z.
fn ms(t: Timestamp) -> u64 {
    t.unix_millis()
}

fn invalid(what: impl std::fmt::Display) -> ErrResponse {
    err(ErrorCode::Invalid).with_message(what.to_string())
}

fn forbidden(what: impl std::fmt::Display) -> ErrResponse {
    err(ErrorCode::Forbidden).with_message(what.to_string())
}

/// Runs `f` on the blocking pool: MLS's checks verify many signatures.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ErrResponse> + Send + 'static,
) -> Result<T, ErrResponse> {
    tokio::task::spawn_blocking(f).await.map_err(|e| {
        tracing::error!("a public room's check failed: {e}");
        err(ErrorCode::Internal)
    })?
}

/// A room's group from its GroupInfo and tree (12.6), checked by OpenMLS:
/// the GroupInfo's signature, and the tree against its group context.
/// Also returns the GroupInfo's signer.
fn build(
    crypto: &RisalaCrypto,
    group_info: &[u8],
    tree: &[u8],
) -> Result<(PublicGroup, MemoryStorage, LeafNodeIndex), ErrResponse> {
    let storage = MemoryStorage::default();
    let verifiable = read_group_info(group_info).map_err(invalid)?;
    let extensions = verifiable.extensions();
    if extensions.external_pub().is_none() || extensions.ratchet_tree().is_some() {
        return Err(invalid(
            "a public room's GroupInfo has external_pub and no ratchet_tree",
        ));
    }
    // Servers reject a GroupInfo that carries an X-Wing key that fails
    // (12.2): resyncs and rejoins encrypt to it.
    if !group_info_keys_ok(&verifiable) {
        return Err(invalid(
            "a GroupInfo's external_pub fails the X-Wing checks",
        ));
    }
    let signer = verifiable.signer();
    // OpenMLS checks the signature under the signer's leaf, and the tree
    // against the group context's tree hash, but not the lifetimes of the
    // tree's leaves, which 12.5 leaves to the commits that add them.
    let (group, _) = PublicGroup::from_external(
        crypto,
        &storage,
        read_tree(tree).map_err(invalid)?,
        verifiable,
        ProposalStore::new(),
    )
    .map_err(invalid)?;
    Ok((group, storage, signer))
}

/// A room's group as stored, with its pending proposals.
fn rebuild(crypto: &RisalaCrypto, stored: &RoomGroup) -> Result<RoomCache, ErrResponse> {
    let internal = |e: &dyn std::fmt::Display| {
        tracing::error!("rebuilding a public room's group: {e}");
        err(ErrorCode::Internal)
    };
    let (mut group, storage, _) =
        build(crypto, &stored.group_info, &stored.tree).map_err(|e| internal(&e.message))?;
    for message in &stored.proposals {
        let processed = read_protocol_message(message)
            .map_err(|e| internal(&e))
            .and_then(|m| group.process_message(crypto, m).map_err(|e| internal(&e)))?;
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(queued)
            | ProcessedMessageContent::ExternalJoinProposalMessage(queued) => {
                group
                    .add_proposal(&storage, *queued)
                    .map_err(|e| internal(&e))?;
            }
            _ => return Err(internal(&"a stored proposal is not one")),
        }
    }
    Ok(RoomCache {
        tree_bytes: stored.tree.len(),
        epoch: stored.epoch,
        proposals: stored.proposals.len(),
        group,
        storage,
        state: decode_state(&stored.state)?,
    })
}

/// A role in the conversation extension, as the server's lines write it.
fn role(role: MlsRole) -> Role {
    match role {
        MlsRole::Owner => Role::Owner,
        MlsRole::Mod => Role::Mod,
        MlsRole::Member => Role::Member,
    }
}

/// What the store keeps of a room's group as of its epoch: the uids with a
/// leaf and their roles, its topic and `guests`.
fn room_update(
    group: &PublicGroup,
    conversation: &RisalaConversation,
    group_info: Vec<u8>,
    state: &EpochState,
) -> Result<RoomUpdate, ErrResponse> {
    let view = GroupView::of(group, state);
    let members: BTreeMap<Uid, Role> = view
        .leaves
        .iter()
        .filter_map(|leaf| leaf.identity.as_ref())
        .map(|identity| (identity.uid.clone(), role(conversation.role(&identity.uid))))
        .collect();
    Ok(RoomUpdate {
        epoch: group.group_context().epoch().as_u64(),
        group_info,
        group_info_blob: None,
        tree: tree_to_bytes(&group.export_ratchet_tree()),
        tree_blob: None,
        members: members.into_iter().collect(),
        topic: escape(&conversation.topic),
        guests: match conversation.guests {
            GuestMode::None => GuestAccess::None,
            GuestMode::Read => GuestAccess::Read,
            GuestMode::Write => GuestAccess::Write,
        },
        state: encode_state(state)?,
    })
}

/// The topic, escaped for ROOM lines (3.4).
fn escape(topic: &str) -> String {
    risala_proto::text::escape(topic)
}

/// Whether the connection is the device that `identity` names (12.6, point
/// 4): a signed-in connection of that identity, whose device key has the
/// credential's device id.
fn is_device(who: &Who, identity: &RisalaIdentity) -> bool {
    match (who, identity.device_id) {
        (Who::SignedIn(Device { uid, key }), Some(device_id)) => {
            *uid == identity.uid && DeviceId::of(key) == device_id
        }
        _ => false,
    }
}

/// `CREATE <box> <group-id> <token-hash> <room> <groupinfo> <tree>` (5.2,
/// 6.1): a public room, on a signed-in connection, checked as 12.6 says.
pub(super) async fn create(
    cx: &Cx,
    mailbox: BoxName,
    group_id: GroupId,
    token_hash: TokenHash,
    public: PublicRoom,
) -> Reply {
    let inner = &cx.inner;
    let Who::SignedIn(device) = cx.who.clone() else {
        return Err(err(ErrorCode::WrongConnection));
    };
    let operator = admin::is_operator(inner, &device.uid);
    let allowed = match inner.config.room_creation {
        RoomCreation::Identities => true,
        RoomCreation::Hosted => {
            operator
                || inner
                    .identity_domain
                    .as_ref()
                    .is_some_and(|domain| device.uid.domain() == Some(domain.as_str()))
        }
        RoomCreation::Operators => operator,
        RoomCreation::Nobody => false,
    };
    if !allowed {
        return Err(forbidden("this server does not let you create rooms"));
    }
    let now = inner.now();
    let rooms = &inner.mailbox.rooms;
    let slot = if operator {
        None
    } else {
        rooms
            .created
            .take(device.uid.clone(), inner.config.limits.rooms_per_day, now)
            .map_err(super::rate_limited)?
    };
    inner
        .mailbox
        .creates
        .take(cx, inner.config.limits.creates_per_hour, now)?;
    // Room for both blobs at once, so that CREATE never waits for room
    // while it holds some (12.12).
    let mut memory =
        reserve_lines(inner, [blob_of(&public.groupinfo), blob_of(&public.tree)]).await?;
    let (group_info, _held_info) =
        line_bytes(inner, &mut memory, &public.groupinfo, GroupInfo::decode)
            .await?
            .into_parts();
    let (tree, _held_tree) = line_bytes(inner, &mut memory, &public.tree, RatchetTree::decode)
        .await?
        .into_parts();
    let crypto = rooms.crypto()?;
    // The server's address as the extension writes it (12.4): its
    // hostname, on the default port.
    let host: ServerAddr = inner
        .config
        .hostname
        .parse()
        .map_err(|_| invalid("the server's hostname is not a server address"))?;
    let room = public.room.clone();
    let (cache, update) = blocking(move || {
        let (group, storage, signer) = build(&crypto, &group_info, &tree)?;
        let context = group.group_context();
        if context.epoch().as_u64() != 0 || context.group_id().as_slice() != group_id.as_bytes() {
            return Err(invalid("not the group of the CREATE, in epoch 0"));
        }
        let state = EpochState::created();
        let view = GroupView::of(&group, &state);
        check_join(
            &view,
            &JoinExpectation {
                host,
                own_uid: device.uid.clone(),
                public_room: Some((room, *mailbox.as_bytes())),
            },
        )
        .map_err(invalid)?;
        // One leaf, of the connection's own device (12.6).
        let [leaf] = &view.leaves[..] else {
            return Err(invalid("a new room's group has one leaf"));
        };
        // Its GroupInfo is signed by that leaf (5.2).
        if leaf.index != signer {
            return Err(invalid("the GroupInfo is not signed by the one leaf"));
        }
        if !leaf
            .identity
            .as_ref()
            .is_some_and(|identity| is_device(&Who::SignedIn(device.clone()), identity))
        {
            return Err(invalid("the leaf is not this device's"));
        }
        let conversation = view.conversation.clone().map_err(invalid)?;
        if conversation.kind != ConversationKind::PublicRoom
            || conversation.role(&device.uid) != MlsRole::Owner
        {
            return Err(invalid("a public room with the creator as an owner"));
        }
        let update = room_update(&group, &conversation, group_info, &state)?;
        Ok((
            RoomCache {
                tree_bytes: update.tree.len(),
                epoch: 0,
                proposals: 0,
                group,
                storage,
                state,
            },
            update,
        ))
    })
    .await?;
    let mut update = update;
    store_room_blobs(&cx.inner, &mut update).await?;
    let new = NewMailbox {
        mailbox,
        group_id,
        first_epoch: 0,
        moved_from: None,
        token_hash,
        created: now,
    };
    let room = NewRoom {
        room: public.room,
        creator: cx
            .who
            .uid()
            .cloned()
            .ok_or_else(|| err(ErrorCode::Internal))?,
        group: update,
    };
    match cx.db(move |store| store.create_room(&new, &room)).await? {
        Created::Created => {
            if let Some(slot) = slot {
                slot.keep();
            }
            rooms.keep(mailbox, cache);
            Ok(OkResponse::new())
        }
        Created::Taken | Created::Exists => Err(err(ErrorCode::NameTaken)),
        Created::NoGroup => Err(err(ErrorCode::NotFound)),
    }
}

/// A commit or proposal posted to a public room, for [`check_post`].
pub(super) struct PostToRoom<'a> {
    pub(super) framing: &'a PostFraming,
    /// The bytes of the room's state as stored, which POST took room for
    /// in `limits.blob_memory` with its blobs, under the mailbox's lock.
    pub(super) state_size: u64,
    pub(super) message: Vec<u8>,
    pub(super) group_info: Option<Vec<u8>>,
    pub(super) next: Option<TokenHash>,
    pub(super) now: Timestamp,
}

/// The checks of 12.6 on a commit or proposal posted to a public room, as a
/// PublicMessage, after the checks of 5.2's points 1 to 4.
///
/// The room's state is read whole from the store, its tree with it, in
/// the room `memory` took for it with the post's blobs (12.12, PLAN item
/// 66), so that POST never waits for room while it holds some.
///
/// A post that fails them leaves the group as it was, and it goes back
/// into memory: OpenMLS checks a message without changing the group, and
/// only a commit that passed every check before its GroupInfo is merged.
pub(super) async fn check_post(
    cx: &Cx,
    record: &MailboxRecord,
    memory: &mut keys::BlobMemory,
    post: PostToRoom<'_>,
) -> Result<CheckedPost, ErrResponse> {
    let PostToRoom {
        framing,
        state_size,
        message,
        group_info,
        next,
        now,
    } = post;
    let mailbox = record.mailbox;
    let rooms = &cx.inner.mailbox.rooms;
    let _held_state = memory.hold(state_size).map_err(ErrResponse::from)?;
    let stored = cx
        .db(move |store| store.room_group(&mailbox))
        .await?
        .ok_or_else(|| err(ErrorCode::NotFound))?;
    if stored.size() > state_size {
        // The mailbox's lock keeps the state as it was sized.
        tracing::error!("a public room's state grew under its mailbox's lock");
        return Err(err(ErrorCode::Internal));
    }
    // 1. For the current epoch.
    if framing.epoch != stored.epoch {
        return Err(err(ErrorCode::Stale));
    }
    if framing.content_type == ContentType::Proposal && stored.proposals.len() >= MAX_PENDING {
        return Err(super::rate_limited(60));
    }
    let cached = rooms.take(&mailbox, &stored);
    let crypto = rooms.crypto()?;
    let post = PostToCheck {
        who: cx.who.clone(),
        commit: framing.content_type == ContentType::Commit,
        message,
        group_info,
        next,
        now,
        inner: cx.inner.clone(),
    };
    let checked = tokio::task::spawn_blocking(move || {
        let mut room = match cached {
            Some(room) => room,
            None => rebuild(&crypto, &stored).map_err(|e| (e, None))?,
        };
        match check_in(&crypto, &mut room, post) {
            Ok((change, joins)) => Ok(CheckedPost {
                change,
                joins,
                group: room,
            }),
            Err(failed) => Err((failed.err, (!failed.changed).then(|| Box::new(room)))),
        }
    })
    .await
    .map_err(|e| {
        tracing::error!("a public room's check failed: {e}");
        err(ErrorCode::Internal)
    })?;
    match checked {
        Ok(post) => Ok(post),
        Err((e, unchanged)) => {
            if let Some(room) = unchanged {
                rooms.keep(mailbox, *room);
            }
            Err(e)
        }
    }
}

/// What [`check_in`] checks a post with.
struct PostToCheck {
    who: Who,
    commit: bool,
    message: Vec<u8>,
    group_info: Option<Vec<u8>>,
    next: Option<TokenHash>,
    now: Timestamp,
    inner: Arc<super::super::Inner>,
}

/// Why a post failed its checks, and whether the group changed before it
/// did.
struct Failed {
    err: ErrResponse,
    changed: bool,
}

impl From<ErrResponse> for Failed {
    fn from(err: ErrResponse) -> Failed {
        Failed {
            err,
            changed: false,
        }
    }
}

/// After a commit is merged, a failure leaves the group changed.
fn changed(err: ErrResponse) -> Failed {
    Failed { err, changed: true }
}

/// The checks of [`check_post`] on the group `room`, which changes only if
/// they pass, or once a commit is merged.
fn check_in(
    crypto: &RisalaCrypto,
    room: &mut RoomCache,
    post: PostToCheck,
) -> Result<(RoomChange, Option<Joins>), Failed> {
    let PostToCheck {
        who,
        commit,
        message,
        group_info,
        next,
        now,
        inner,
    } = post;
    // 2. Valid MLS, as far as an outsider can check.
    let protocol = read_protocol_message(&message).map_err(invalid)?;
    let processed = room
        .group
        .process_message(crypto, protocol)
        .map_err(invalid)?;
    let sender = processed.sender().clone();
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) if commit => {
            let view = GroupView::of(&room.group, &room.state);
            let post = room.state.post(ms(now), next.map(|next| *next.as_bytes()));
            let commit_view = CommitView::of(&sender, &staged);
            // The committer's leaf: its credential, as of the commit.
            let committer = commit_view
                .path_leaf
                .as_ref()
                .and_then(|leaf| leaf.identity.clone())
                .ok_or_else(|| invalid("a commit without a path"))?;
            // 3. The group checks that need only the public state.
            if committer.is_guest() {
                return Err(forbidden("a guest's leaf does not commit").into());
            }
            check_commit(&view, &commit_view, &post).map_err(commit_error)?;
            // A device of an identity the server bans does not join by an
            // external commit either (10.2, 6.1).
            if matches!(sender, MlsSender::NewMemberCommit) && admin::banned(&inner, &committer.uid)
            {
                return Err(forbidden("banned from this server").into());
            }
            // 4. From the leaf's own device.
            if !is_device(&who, &committer) {
                return Err(forbidden(
                    "an identity's commit comes from its device's signed-in connection",
                )
                .into());
            }
            let new_signature_key = staged
                .update_path_leaf_node()
                .map(|leaf| leaf.signature_key().as_slice().to_vec());
            let conversation = commit_view.new_conversation.clone().map_err(invalid)?;
            // The KeyPackages of the external Adds it applies, which
            // the committer may then send Welcomes to (12.8).
            let refs = staged
                .add_proposals()
                .filter(|add| matches!(add.sender(), MlsSender::NewMemberProposal))
                .map(|add| {
                    let r = add
                        .add_proposal()
                        .key_package()
                        .hash_ref(crypto)
                        .map_err(|e| invalid(format!("{e:?}")))?;
                    let bytes: [u8; 48] = r
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid("a KeyPackageRef is 48 bytes"))?;
                    Ok(KeyPackageRef::from_bytes(bytes))
                })
                .collect::<Result<Vec<_>, ErrResponse>>()?;
            let group_info = group_info.ok_or_else(|| invalid("a commit carries its GroupInfo"))?;
            room.group
                .merge_commit(&room.storage, *staged)
                .map_err(|e| changed(invalid(format!("{e:?}"))))?;
            // 5. The new GroupInfo. The group has changed from here: a
            // failure leaves it to be rebuilt from the store.
            let tree = tree_to_bytes(&room.group.export_ratchet_tree());
            let (from_info, _, signer) = build(crypto, &group_info, &tree).map_err(changed)?;
            let context = |g: &PublicGroup| g.group_context().tls_serialize_detached().ok();
            if context(&from_info) != context(&room.group)
                || from_info.confirmation_tag() != room.group.confirmation_tag()
            {
                return Err(changed(invalid("the GroupInfo is not the commit's")));
            }
            let signer_key = room
                .group
                .leaf(signer)
                .map(|leaf| leaf.signature_key().as_slice().to_vec());
            if signer_key.is_none() || signer_key != new_signature_key {
                return Err(changed(invalid(
                    "the GroupInfo is not signed by the committer",
                )));
            }
            // The committer, which signed the GroupInfo, started the
            // new epoch (12.3).
            room.state = EpochState::started_by(signer);
            let update = room_update(&room.group, &conversation, group_info, &room.state)
                .map_err(changed)?;
            room.epoch = update.epoch;
            room.proposals = 0;
            room.tree_bytes = update.tree.len();
            let joins = match committer.device_id {
                Some(device_id) if !refs.is_empty() => Some(Joins {
                    epoch: update.epoch,
                    committer_uid: committer.uid.clone(),
                    committer: *device_id.as_bytes(),
                    refs,
                    tree,
                }),
                _ => None,
            };
            Ok((RoomChange::Commit(update), joins))
        }
        ProcessedMessageContent::ProposalMessage(queued) if !commit => {
            let MlsSender::Member(index) = sender else {
                return Err(invalid("a proposal from outside the group").into());
            };
            let leaf = GroupView::of(&room.group, &room.state)
                .leaf(index)
                .and_then(|leaf| leaf.identity.clone())
                .ok_or_else(|| invalid("a proposal from no leaf"))?;
            match queued.proposal() {
                // A SelfRemove, from any connection that may post (6.1).
                Proposal::SelfRemove => {}
                // An Update, from the leaf's own device (12.6, 12.10). Its
                // post's time is what its `updated` is checked against
                // when a commit applies it (12.3).
                Proposal::Update(_) => {
                    if leaf.is_guest() {
                        return Err(forbidden("a guest's leaf does not propose Updates").into());
                    }
                    if !is_device(&who, &leaf) {
                        return Err(forbidden(
                            "an identity's Update comes from its device's signed-in connection",
                        )
                        .into());
                    }
                }
                _ => return Err(invalid("a proposal that is not posted on its own").into()),
            }
            keep_proposal(room, *queued, message, now)
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(queued) if !commit => {
            let Proposal::Add(add) = queued.proposal() else {
                return Err(invalid("a join proposal that is not an Add").into());
            };
            let key_package = add.key_package();
            let conversation = GroupView::of(&room.group, &room.state)
                .conversation
                .map_err(invalid)?;
            // A KeyPackage made for this join, with no device binding,
            // within its lifetime at the post's time (6.1, 12.3, 12.5).
            let (identity, _) = check_key_package_contents(key_package).map_err(invalid)?;
            if !lifetime_acceptable_at(key_package.life_time(), ms(now)) {
                return Err(invalid(KeyPackageError::Lifetime).into());
            }
            if !has_no_binding(key_package) {
                return Err(invalid(KeyPackageError::Binding).into());
            }
            if identity.is_guest() {
                if conversation.guests == GuestMode::None {
                    return Err(forbidden("this room does not let guests in").into());
                }
                // A guest joins from its own connection (12.6, point 4).
                if who != Who::Guest(identity.uid) {
                    return Err(forbidden("a guest joins from its own connection").into());
                }
            } else {
                // An identity's join comes from an anonymous or signed-in
                // connection, never a guest's (12.6, point 4).
                if matches!(who, Who::Guest(_)) {
                    return Err(forbidden("a guest connection joins only its own guest").into());
                }
                if conversation.is_banned(&identity.uid) {
                    return Err(forbidden("banned").into());
                }
                // The server refuses joins of public rooms by the devices
                // of identities and domains it bans (10.2).
                if admin::banned(&inner, &identity.uid) {
                    return Err(forbidden("banned from this server").into());
                }
            }
            keep_proposal(room, *queued, message, now)
        }
        _ => Err(invalid("not a commit or proposal as its content type says").into()),
    }
}

/// A proposal that passed its checks joins the epoch's pending ones.
fn keep_proposal(
    room: &mut RoomCache,
    queued: risala_mls::openmls::group::QueuedProposal,
    message: Vec<u8>,
    now: Timestamp,
) -> Result<(RoomChange, Option<Joins>), Failed> {
    // A commit that applies it is judged by its post's time (12.3, 12.7).
    let reference = queued.proposal_reference_ref().as_slice().to_vec();
    let mut state = room.state.clone();
    state.note_proposal(&reference, ms(now));
    let encoded = encode_state(&state)?;
    room.group
        .add_proposal(&room.storage, queued)
        .map_err(|e| changed(invalid(format!("{e:?}"))))?;
    room.state = state;
    room.proposals += 1;
    Ok((
        RoomChange::Proposal {
            message,
            state: encoded,
        },
        None,
    ))
}

/// The answer to a commit that fails the group checks: `ERR invalid` for
/// what is not valid MLS as 12.6's point 2 says, `ERR forbidden` for what
/// point 3 forbids.
fn commit_error(e: CommitError) -> ErrResponse {
    match e {
        CommitError::NoPath
        | CommitError::NextToken
        | CommitError::Proposal(_)
        | CommitError::Group
        | CommitError::Leaf
        | CommitError::KeyPackage(_) => invalid(e),
        CommitError::External
        | CommitError::Guest
        | CommitError::Updated
        | CommitError::Streak
        | CommitError::Extension(_)
        | CommitError::Add
        | CommitError::Remove
        | CommitError::CheckRemovals
        | CommitError::Bulk
        | CommitError::SameDevice
        | CommitError::LeftBehind
        | CommitError::TooLarge => forbidden(e),
    }
}

/// `GROUPINFO <box>` (6.1): a public room's current GroupInfo and ratchet
/// tree.
///
/// It writes nothing: a GroupInfo or tree too long for the line is the
/// blob the server stored when it applied the epoch's commit
/// ([`store_room_blobs`]), and what of them is inline counts against
/// `limits.blob_memory` while it is read and sent (12.12, PLAN item 63).
pub(super) async fn group_info(cx: &Cx, mailbox: BoxName) -> Reply {
    let inner = &cx.inner;
    let size = cx
        .db(move |store| store.room_group_info_size(&mailbox))
        .await?
        .ok_or_else(|| err(ErrorCode::NotFound))?;
    let _held = keys::hold_memory(inner, size)
        .await
        .map_err(ErrResponse::from)?;
    let stored = cx
        .db(move |store| store.room_group_info(&mailbox))
        .await?
        .ok_or_else(|| err(ErrorCode::NotFound))?;
    let internal = |what: &str| {
        tracing::error!("a public room's {what} cannot be sent");
        err(ErrorCode::Internal)
    };
    let groupinfo = match stored.group_info {
        OrBlob::Inline(bytes) => {
            OrBlob::Inline(GroupInfo::from_bytes(&bytes).map_err(|_| internal("GroupInfo"))?)
        }
        OrBlob::Blob(hash) => OrBlob::Blob(hash),
    };
    let tree = match stored.tree {
        OrBlob::Inline(tree) => {
            OrBlob::Inline(RatchetTree::from_bytes(&tree).map_err(|_| internal("tree"))?)
        }
        OrBlob::Blob(hash) => OrBlob::Blob(hash),
    };
    cx.send(ServerLine::GroupInfo {
        mailbox,
        epoch: stored.epoch,
        seq: Seq::new(stored.epoch_seq),
        groupinfo,
        tree,
    });
    Ok(OkResponse::new())
}

/// Stores the GroupInfo and the tree of `update` as blobs where they are
/// too long for GROUPINFO's line (6.1, 12.12), once per epoch, when the
/// commit that starts it is applied, or when the room is created. The
/// GroupInfo goes first: a room whose extension lists many bans has one
/// too long for a line by itself. The tree then has what the GroupInfo
/// leaves of the line. The store keeps both while the epoch is current.
pub(super) async fn store_room_blobs(
    inner: &Arc<Inner>,
    update: &mut RoomUpdate,
) -> Result<(), ErrResponse> {
    let blob = |inner: &Arc<Inner>, bytes: Vec<u8>| {
        let inner = inner.clone();
        async move {
            keys::store_room_blob(&inner, bytes).await.map_err(|e| {
                tracing::error!("storing a public room's blob: {e}");
                err(ErrorCode::Internal)
            })
        }
    };
    update.group_info_blob = None;
    update.tree_blob = None;
    let inline_group_info = if group_info_fits(update.group_info.len()) {
        update.group_info.len()
    } else {
        let (bytes, hash) = blob(inner, std::mem::take(&mut update.group_info)).await?;
        update.group_info = bytes;
        update.group_info_blob = Some(hash);
        0
    };
    if !fits_line(inline_group_info, update.tree.len()) {
        let (bytes, hash) = blob(inner, std::mem::take(&mut update.tree)).await?;
        update.tree = bytes;
        update.tree_blob = Some(hash);
    }
    Ok(())
}

/// Whether a GroupInfo of this size fits a GROUPINFO line in base64 by
/// itself, as one base64 value may (2.3, 3.5).
fn group_info_fits(group_info: usize) -> bool {
    let base64 = group_info.div_ceil(3) * 4;
    #[cfg(test)]
    if let Some(max) = test_hooks::INLINE_GROUP_INFO.with(std::cell::Cell::get) {
        return base64 <= max;
    }
    fits_line(group_info, 0) && base64 <= risala_proto::mls::MAX_BASE64_LEN
}

/// Whether a GroupInfo and tree of these sizes fit a GROUPINFO line in
/// base64, with room for the rest of the line (2.3): a GroupInfo that is a
/// blob takes 0 bytes here, its blob-ref fitting in the rest.
fn fits_line(group_info: usize, tree: usize) -> bool {
    /// More than `GROUPINFO`, a box, an epoch, a seq, the spaces and a
    /// blob-ref (103 characters) take.
    const REST: usize = 256;
    let base64 = |n: usize| n.div_ceil(3) * 4;
    #[cfg(test)]
    if let Some(max) = test_hooks::INLINE_TREE.with(std::cell::Cell::get) {
        return base64(tree) <= max;
    }
    base64(group_info) + base64(tree) + REST <= MAX_LONG_SERVER_LINE
        && base64(tree) <= risala_proto::mls::MAX_BASE64_LEN
}

#[cfg(test)]
pub(crate) mod test_hooks {
    thread_local! {
        /// The longest tree in base64 that a GROUPINFO line carries on this
        /// thread, instead of what a line holds, so that a test can make a
        /// tree that is a blob without a group of hundreds of leaves.
        pub(crate) static INLINE_TREE: std::cell::Cell<Option<usize>> =
            const { std::cell::Cell::new(None) };
        /// The same for the GroupInfo, as a room with many bans would
        /// have.
        pub(crate) static INLINE_GROUP_INFO: std::cell::Cell<Option<usize>> =
            const { std::cell::Cell::new(None) };
    }
}

/// Checks that the connection's identity may mute in the public room of
/// `mailbox` (6.4): an owner or moderator with a leaf in its group.
async fn may_mute_in(cx: &Cx, mailbox: BoxName) -> Result<(), ErrResponse> {
    let uid = cx
        .who
        .uid()
        .cloned()
        .ok_or_else(|| err(ErrorCode::WrongConnection))?;
    let (room, role) = cx
        .db(move |store| {
            let room = store.mailbox(&mailbox)?.and_then(|m| m.room);
            let role = store.room_member(&mailbox, &uid)?;
            Ok((room, role))
        })
        .await?;
    // A mailbox that is not a public room is not found, so that a signed-in
    // connection learns nothing of private ones (4.2).
    if room.is_none() {
        return Err(err(ErrorCode::NotFound));
    }
    if !may_mute(role) {
        return Err(forbidden("only the room's owners and moderators mute"));
    }
    Ok(())
}

/// The end of the period (12.10) that `now` is in: the next midnight UTC.
fn end_of_period(now: Timestamp) -> Timestamp {
    let day = risala_mls::checks::PERIOD_MS;
    let end = (now.unix_millis() / day + 1).saturating_mul(day);
    Timestamp::from_unix_millis(end).unwrap_or(Timestamp::MAX)
}

/// `MUTE <box> <pseudonym> [hours=<n>]` (6.4): until `hours` from now, 24
/// by default, but not past the end of the current period, since a public
/// room's pseudonyms last one period (7.3).
pub(super) async fn mute(
    cx: &Cx,
    mailbox: BoxName,
    pseudonym: Pseudonym,
    hours: Option<u64>,
) -> Reply {
    may_mute_in(cx, mailbox).await?;
    let now = cx.inner.now();
    let hours = Duration::from_secs(hours.unwrap_or(24).saturating_mul(60 * 60));
    let until = now
        .checked_add(hours)
        .unwrap_or(Timestamp::MAX)
        .min(end_of_period(now));
    if !cx
        .db(move |store| store.set_mute(&mailbox, &pseudonym, until))
        .await?
    {
        return Err(err(ErrorCode::NotFound));
    }
    Ok(OkResponse::new())
}

/// `UNMUTE <box> <pseudonym>` (6.4).
pub(super) async fn unmute(cx: &Cx, mailbox: BoxName, pseudonym: Pseudonym) -> Reply {
    may_mute_in(cx, mailbox).await?;
    cx.db(move |store| store.remove_mute(&mailbox, &pseudonym))
        .await?;
    Ok(OkResponse::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_trees_do_not_fit_a_line() {
        assert!(fits_line(10_000, 500_000));
        assert!(!fits_line(10_000, 800_000));
        assert!(!fits_line(800_000, 10_000));
        // A GroupInfo that fits a line alone, and one over 1 MiB, as a
        // room with many bans has, which is a blob; the tree then has the
        // whole line (12.12).
        assert!(group_info_fits(700_000));
        assert!(!group_info_fits(800_000));
        assert!(!group_info_fits(1024 * 1024 + 1));
        assert!(fits_line(0, 780_000));
    }

    #[test]
    fn periods_end_at_midnight_utc() {
        let t: Timestamp = "2026-11-09T23:59:59.999Z".parse().unwrap();
        assert_eq!(end_of_period(t).to_string(), "2026-11-10T00:00:00.000Z");
        let t: Timestamp = "2026-11-10T00:00:00.000Z".parse().unwrap();
        assert_eq!(end_of_period(t).to_string(), "2026-11-11T00:00:00.000Z");
    }
}

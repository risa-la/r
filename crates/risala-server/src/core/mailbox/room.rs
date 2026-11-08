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
//! the store when those do not match.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openmls_memory_storage::MemoryStorage;
use risala_mls::RisalaCrypto;
use risala_mls::checks::{
    CommitError, CommitView, Fact, GroupView, JoinExpectation, KeyFacts, check_commit, check_join,
};
use risala_mls::conversation::{ConversationKind, GuestMode, RisalaConversation, Role as MlsRole};
use risala_mls::framing::ContentType;
use risala_mls::identity::{DeviceId, RisalaIdentity};
use risala_mls::keypackage::{check_guest_key_package, check_key_package_contents};
use risala_mls::openmls::group::ProposalStore;
use risala_mls::openmls::prelude::{
    LeafNodeIndex, ProcessedMessageContent, Proposal, PublicGroup, Sender as MlsSender,
};
use risala_mls::wire::{read_group_info, read_protocol_message, read_tree, tree_to_bytes};
use risala_proto::command::PublicRoom;
use risala_proto::error::ErrorCode;
use risala_proto::mls::{GroupId, GroupInfo, OrBlob, Pseudonym, RatchetTree, TokenHash};
use risala_proto::names::{BoxName, Seq, Uid};
use risala_proto::server::{ErrResponse, OkResponse, ServerLine};
use risala_proto::time::Timestamp;
use risala_proto::types::{GuestAccess, Role};
use tls_codec::{Serialize as _, Size as _};

use super::super::admin;
use super::super::command::{Cx, Reply, err};
use super::super::rate::WindowLimit;
use super::super::state::{Device, Who};
use super::{PostFraming, line_bytes, may_mute};
use crate::config::RoomCreation;
use crate::store::{
    Created, MailboxRecord, NewMailbox, NewRoom, RoomChange, RoomGroup, RoomUpdate,
};

/// The most proposals pending in one epoch of a room: enough for the joins
/// and Updates that full clients commit, at most 256 devices a commit
/// (6.1). Further ones get `ERR rate-limited` until a commit.
const MAX_PENDING: usize = 512;

/// The most rooms whose groups are kept in memory.
const CACHED_ROOMS: usize = 64;

/// A room's group as of an epoch, in memory.
struct RoomCache {
    /// The epoch.
    epoch: u64,
    /// How many proposals of the epoch it holds.
    proposals: usize,
    group: PublicGroup,
    /// OpenMLS's state of the group: its pending proposals.
    storage: MemoryStorage,
}

/// The public rooms' groups in memory, and the limit on rooms created.
pub(super) struct Rooms {
    cache: Mutex<HashMap<BoxName, RoomCache>>,
    crypto: Option<Arc<RisalaCrypto>>,
    /// Rooms each identity created in the last day (5.2, 14).
    created: WindowLimit<Uid>,
}

/// A post to a room that passed its checks: what it changes, and the
/// group after it.
pub(super) struct CheckedPost {
    /// What to store with the post.
    pub(super) change: RoomChange,
    group: RoomCache,
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
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<BoxName, RoomCache>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
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

    /// A post to `mailbox` was kept: its group is now `post`'s.
    pub(super) fn applied(&self, mailbox: BoxName, post: CheckedPost) {
        let mut cache = self.cache();
        if cache.len() >= CACHED_ROOMS {
            cache.clear();
        }
        cache.insert(mailbox, post.group);
    }

    /// `mailbox` is gone.
    pub(super) fn forget(&self, mailbox: &BoxName) {
        self.cache().remove(mailbox);
    }
}

/// Facts from key files and the key log, which the server does not fetch
/// for public rooms (12.6): it checks neither device bindings nor removals
/// by key files there, so every one of them is unknown.
struct NoKeyFacts;

impl KeyFacts for NoKeyFacts {
    fn current_device_key(&self, _uid: &Uid, _device_id: &DeviceId) -> Fact<Option<Vec<u8>>> {
        Fact::Unknown
    }

    fn device_removed(&self, _uid: &Uid, _device_id: &DeviceId) -> Fact<bool> {
        Fact::Unknown
    }
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
    let (group, info) = PublicGroup::from_external(
        crypto,
        &storage,
        read_tree(tree).map_err(invalid)?,
        verifiable,
        ProposalStore::new(),
    )
    .map_err(invalid)?;
    // The signer is the u32 before the signature, at the end of the
    // GroupInfo (RFC 9420, 12.4.3).
    // TODO: use VerifiableGroupInfo::signer once the patched OpenMLS makes
    // it public (task M1b).
    let signature_len = info.signature().tls_serialized_len();
    let signer = group_info
        .len()
        .checked_sub(signature_len + 4)
        .and_then(|at| group_info.get(at..at + 4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| invalid("a GroupInfo without a signer"))?;
    Ok((group, storage, LeafNodeIndex::new(signer)))
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
        epoch: stored.epoch,
        proposals: stored.proposals.len(),
        group,
        storage,
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
) -> RoomUpdate {
    let view = GroupView::of(group);
    let members: BTreeMap<Uid, Role> = view
        .leaves
        .iter()
        .filter_map(|leaf| leaf.identity.as_ref())
        .map(|identity| (identity.uid.clone(), role(conversation.role(&identity.uid))))
        .collect();
    RoomUpdate {
        epoch: group.group_context().epoch().as_u64(),
        group_info,
        tree: tree_to_bytes(&group.export_ratchet_tree()),
        members: members.into_iter().collect(),
        topic: escape(&conversation.topic),
        guests: match conversation.guests {
            GuestMode::None => GuestAccess::None,
            GuestMode::Read => GuestAccess::Read,
            GuestMode::Write => GuestAccess::Write,
        },
    }
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
            *uid == identity.uid && DeviceId::of_device_key(key.as_bytes()) == device_id
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
    let group_info = line_bytes(inner, &public.groupinfo, GroupInfo::decode).await?;
    let tree = line_bytes(inner, &public.tree, RatchetTree::decode).await?;
    let crypto = rooms.crypto()?;
    let host = inner.config.hostname.clone();
    let room = public.room.clone();
    let (cache, update) = blocking(move || {
        let (group, storage, _) = build(&crypto, &group_info, &tree)?;
        let context = group.group_context();
        if context.epoch().as_u64() != 0 || context.group_id().as_slice() != group_id.as_bytes() {
            return Err(invalid("not the group of the CREATE, in epoch 0"));
        }
        let view = GroupView::of(&group);
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
        let update = room_update(&group, &conversation, group_info);
        Ok((
            RoomCache {
                epoch: 0,
                proposals: 0,
                group,
                storage,
            },
            update,
        ))
    })
    .await?;
    let new = NewMailbox {
        mailbox,
        group_id,
        first_epoch: 0,
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
            rooms.applied(
                mailbox,
                CheckedPost {
                    change: RoomChange::Proposal(Vec::new()),
                    group: cache,
                },
            );
            Ok(OkResponse::new())
        }
        Created::Taken => Err(err(ErrorCode::NameTaken)),
        Created::NoGroup => Err(err(ErrorCode::NotFound)),
    }
}

/// The checks of 12.6 on a commit or proposal posted to a public room, as a
/// PublicMessage, after the checks of 5.2's points 1 to 4.
pub(super) async fn check_post(
    cx: &Cx,
    record: &MailboxRecord,
    framing: &PostFraming,
    message: Vec<u8>,
    group_info: Option<Vec<u8>>,
    now: Timestamp,
) -> Result<CheckedPost, ErrResponse> {
    let mailbox = record.mailbox;
    let rooms = &cx.inner.mailbox.rooms;
    let stored = cx
        .db(move |store| store.room_group(&mailbox))
        .await?
        .ok_or_else(|| err(ErrorCode::NotFound))?;
    // 1. For the current epoch.
    if framing.epoch != stored.epoch {
        return Err(err(ErrorCode::Stale));
    }
    if framing.content_type == ContentType::Proposal && stored.proposals.len() >= MAX_PENDING {
        return Err(super::rate_limited(60));
    }
    let cached = rooms.take(&mailbox, &stored);
    let crypto = rooms.crypto()?;
    let who = cx.who.clone();
    let commit = framing.content_type == ContentType::Commit;
    blocking(move || {
        let mut room = match cached {
            Some(room) => room,
            None => rebuild(&crypto, &stored)?,
        };
        // 2. Valid MLS, as far as an outsider can check.
        let protocol = read_protocol_message(&message).map_err(invalid)?;
        let processed = room
            .group
            .process_message(&*crypto, protocol)
            .map_err(invalid)?;
        let sender = processed.sender().clone();
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) if commit => {
                let view = GroupView::of(&room.group);
                let pending = room
                    .group
                    .queued_proposals(&room.storage)
                    .map_err(|e| invalid(format!("{e:?}")))?;
                let commit_view = CommitView::of(&sender, &staged, pending.iter().map(|(_, q)| q));
                // The committer's leaf: its credential, as of the commit.
                let committer = commit_view
                    .path_leaf
                    .as_ref()
                    .and_then(|leaf| leaf.identity.clone())
                    .ok_or_else(|| invalid("a commit without a path"))?;
                // 3. The group checks that need only the public state.
                if committer.is_guest() {
                    return Err(forbidden("a guest's leaf does not commit"));
                }
                check_commit(&view, &commit_view, &NoKeyFacts, now.to_system_time())
                    .map_err(commit_error)?;
                // 4. From the leaf's own device.
                if !is_device(&who, &committer) {
                    return Err(forbidden(
                        "an identity's commit comes from its device's signed-in connection",
                    ));
                }
                let new_signature_key = staged
                    .update_path_leaf_node()
                    .map(|leaf| leaf.signature_key().as_slice().to_vec());
                let conversation = commit_view.new_conversation.clone().map_err(invalid)?;
                room.group
                    .merge_commit(&room.storage, *staged)
                    .map_err(|e| invalid(format!("{e:?}")))?;
                // 5. The new GroupInfo.
                let group_info =
                    group_info.ok_or_else(|| invalid("a commit carries its GroupInfo"))?;
                let tree = tree_to_bytes(&room.group.export_ratchet_tree());
                let (from_info, _, signer) = build(&crypto, &group_info, &tree)?;
                let context = |g: &PublicGroup| g.group_context().tls_serialize_detached().ok();
                if context(&from_info) != context(&room.group)
                    || from_info.confirmation_tag() != room.group.confirmation_tag()
                {
                    return Err(invalid("the GroupInfo is not the commit's"));
                }
                let signer_key = room
                    .group
                    .leaf(signer)
                    .map(|leaf| leaf.signature_key().as_slice().to_vec());
                if signer_key.is_none() || signer_key != new_signature_key {
                    return Err(invalid("the GroupInfo is not signed by the committer"));
                }
                let update = room_update(&room.group, &conversation, group_info);
                room.epoch = update.epoch;
                room.proposals = 0;
                Ok(CheckedPost {
                    change: RoomChange::Commit(update),
                    group: room,
                })
            }
            ProcessedMessageContent::ProposalMessage(queued) if !commit => {
                let MlsSender::Member(index) = sender else {
                    return Err(invalid("a proposal from outside the group"));
                };
                let leaf = GroupView::of(&room.group)
                    .leaf(index)
                    .and_then(|leaf| leaf.identity.clone())
                    .ok_or_else(|| invalid("a proposal from no leaf"))?;
                match queued.proposal() {
                    // A SelfRemove, from any connection that may post (6.1).
                    Proposal::SelfRemove => {}
                    // An Update, from the leaf's own device (12.6, 12.10).
                    Proposal::Update(_) => {
                        if leaf.is_guest() {
                            return Err(forbidden("a guest's leaf does not propose Updates"));
                        }
                        if !is_device(&who, &leaf) {
                            return Err(forbidden(
                                "an identity's Update comes from its device's signed-in connection",
                            ));
                        }
                    }
                    _ => return Err(invalid("a proposal that is not posted on its own")),
                }
                keep_proposal(room, *queued, message)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(queued) if !commit => {
                let Proposal::Add(add) = queued.proposal() else {
                    return Err(invalid("a join proposal that is not an Add"));
                };
                let key_package = add.key_package();
                let conversation = GroupView::of(&room.group).conversation.map_err(invalid)?;
                let guest = RisalaIdentity::from_credential(key_package.leaf_node().credential())
                    .is_ok_and(|identity| identity.is_guest());
                let now = now.to_system_time();
                if guest {
                    let identity = check_guest_key_package(key_package, now).map_err(invalid)?;
                    if conversation.guests == GuestMode::None {
                        return Err(forbidden("this room does not let guests in"));
                    }
                    // A guest joins from its own connection (12.6, point 4).
                    if who != Who::Guest(identity.uid) {
                        return Err(forbidden("a guest joins from its own connection"));
                    }
                } else {
                    let (identity, _) =
                        check_key_package_contents(key_package, now).map_err(invalid)?;
                    if conversation.is_banned(&identity.uid) {
                        return Err(forbidden("banned"));
                    }
                }
                keep_proposal(room, *queued, message)
            }
            _ => Err(invalid("not a commit or proposal as its content type says")),
        }
    })
    .await
}

/// A proposal that passed its checks joins the epoch's pending ones.
fn keep_proposal(
    mut room: RoomCache,
    queued: risala_mls::openmls::group::QueuedProposal,
    message: Vec<u8>,
) -> Result<CheckedPost, ErrResponse> {
    room.group
        .add_proposal(&room.storage, queued)
        .map_err(|e| invalid(format!("{e:?}")))?;
    room.proposals += 1;
    Ok(CheckedPost {
        change: RoomChange::Proposal(message),
        group: room,
    })
}

/// The answer to a commit that fails the group checks: `ERR invalid` for
/// what is not valid MLS as 12.6's point 2 says, `ERR forbidden` for what
/// point 3 forbids.
fn commit_error(e: CommitError) -> ErrResponse {
    match e {
        CommitError::NoPath
        | CommitError::Proposal(_)
        | CommitError::Group
        | CommitError::Leaf
        | CommitError::KeyPackage(_) => invalid(e),
        CommitError::External
        | CommitError::Extension(_)
        | CommitError::NotCurrentDevice
        | CommitError::Add
        | CommitError::Remove
        | CommitError::LeftBehind
        | CommitError::TooLarge => forbidden(e),
    }
}

/// `GROUPINFO <box>` (6.1): a public room's current GroupInfo and ratchet
/// tree.
pub(super) async fn group_info(cx: &Cx, mailbox: BoxName) -> Reply {
    let stored = cx
        .db(move |store| store.room_group(&mailbox))
        .await?
        .ok_or_else(|| err(ErrorCode::NotFound))?;
    // A tree too large for a line would be a blob (12.12), which the keys
    // area stores (docs/plans/M5b.md, SV4): until it can, such a room's
    // GROUPINFO fails.
    let too_large = |what: &str| {
        tracing::error!("a public room's {what} is too large for a line");
        err(ErrorCode::Internal)
    };
    let groupinfo =
        GroupInfo::from_bytes(&stored.group_info).map_err(|_| too_large("GroupInfo"))?;
    let tree = RatchetTree::from_bytes(&stored.tree).map_err(|_| too_large("tree"))?;
    cx.send(ServerLine::GroupInfo {
        mailbox,
        epoch: stored.epoch,
        seq: Seq::new(stored.epoch_seq),
        groupinfo: OrBlob::Inline(groupinfo),
        tree: OrBlob::Inline(tree),
    });
    Ok(OkResponse::new())
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
        .db(move |store| store.mute(&mailbox, &pseudonym, until))
        .await?
    {
        return Err(err(ErrorCode::NotFound));
    }
    Ok(OkResponse::new())
}

/// `UNMUTE <box> <pseudonym>` (6.4).
pub(super) async fn unmute(cx: &Cx, mailbox: BoxName, pseudonym: Pseudonym) -> Reply {
    may_mute_in(cx, mailbox).await?;
    cx.db(move |store| store.unmute(&mailbox, &pseudonym))
        .await?;
    Ok(OkResponse::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods_end_at_midnight_utc() {
        let t: Timestamp = "2026-11-09T23:59:59.999Z".parse().unwrap();
        assert_eq!(end_of_period(t).to_string(), "2026-11-10T00:00:00.000Z");
        let t: Timestamp = "2026-11-10T00:00:00.000Z".parse().unwrap();
        assert_eq!(end_of_period(t).to_string(), "2026-11-11T00:00:00.000Z");
    }

    #[test]
    fn the_server_checks_no_key_facts() {
        let uid: Uid = "alice@example.org".parse().unwrap();
        let id = DeviceId([1; 48]);
        assert_eq!(NoKeyFacts.current_device_key(&uid, &id), Fact::Unknown);
        assert_eq!(NoKeyFacts.device_removed(&uid, &id), Fact::Unknown);
    }
}

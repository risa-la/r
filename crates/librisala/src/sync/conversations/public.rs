//! Public rooms (6.1, 12.6, 12.7, 12.8), each step inside one write
//! transaction of the cache, like [`super::group`]:
//!
//! - [`start_join`]: a join by external proposal, from the room's
//!   GroupInfo and tree.
//! - [`check_join`]: after a commit, whether it added the join's leaf, and
//!   if not, the proposal again in the new epoch, or an owner's or
//!   moderator's rejoin by external commit after 30 minutes.
//! - [`join_by_welcome`]: the Welcome from WELCOME GET, with the tree of
//!   its epoch, which MLS checks against the Welcome's tree hash.
//! - [`external_join`]: a resync commit or a rejoin (12.7), merged at once
//!   and posted with the token `-` on the signed-in connection.
//!
//! Before it joins a room again, a device compares the room's extension
//! with the one it kept ("Rejoining a public room"): a difference that no
//! commit it checked explains stops the join until the user accepts it
//! ([`EngineError::RoomChanged`]).

use openmls_memory_storage::MemoryStorage;
use risala_mls::checks::{EpochState, External, GroupView, JoinExpectation};
use risala_mls::conversation::{ConversationKind, RisalaConversation, Role};
use risala_mls::group as mls_group;
use risala_mls::keypackage::read_key_package;
use risala_mls::mldsa::{KEY_PACKAGE_SCOPE, LeafKey};
use risala_mls::openmls::prelude::{GroupId, LeafNodeIndex, MlsMessageOut};
use risala_mls::profile::RisalaProfile;
use risala_proto::names::{BoxName, Room};

use super::group::{self, load, own_identity, tree_leaves};
use super::{Ctx, EngineError};
use crate::store::Tx;
use crate::store::conversations::{ConvKind, ConvState, ConversationId, JoinRow, NewConversation};
use crate::store::messages::{NewOutbox, OutboxKind};

type Result<T> = std::result::Result<T, EngineError>;

fn mls(e: impl std::fmt::Display) -> EngineError {
    EngineError::Mls(e.to_string())
}

/// How long an owner's or moderator's join proposal may wait for a commit
/// before it joins by external commit instead (6.1, 12.7): 30 minutes.
pub(crate) const REJOIN_AFTER_MS: u64 = 30 * 60 * 1000;

/// A public room as GROUPINFO shows it (6.1), its blobs fetched.
#[derive(Debug, Clone)]
pub(crate) struct RoomState {
    /// Its box.
    pub mailbox: BoxName,
    /// The current epoch.
    pub epoch: u64,
    /// The seq of the commit that started it, or 0.
    pub seq: u64,
    /// The GroupInfo.
    pub group_info: Vec<u8>,
    /// The ratchet tree.
    pub tree: Vec<u8>,
}

/// The room's group as an outsider sees it: the view the group checks use,
/// the GroupInfo's signer, and the group id.
fn room_view(cx: &Ctx<'_>, room: &RoomState) -> Result<(GroupView, LeafNodeIndex, Vec<u8>)> {
    let scratch = MemoryStorage::default();
    let public =
        mls_group::public_group(cx.crypto.as_ref(), &scratch, &room.group_info, &room.tree)
            .map_err(mls)?;
    let info = risala_mls::wire::read_group_info(&room.group_info).map_err(mls)?;
    let signer = info.signer();
    let view = GroupView::of(&public, &EpochState::started_by(signer));
    let group_id = public.group_context().group_id().as_slice().to_vec();
    Ok((view, signer, group_id))
}

fn expectation(cx: &Ctx<'_>, room: &str, mailbox: &BoxName) -> Result<JoinExpectation> {
    let room: Room = room
        .parse()
        .map_err(|_| EngineError::Invalid(format!("not a room name: {room}")))?;
    Ok(JoinExpectation {
        host: cx.host.to_owned(),
        own_uid: cx.uid.clone(),
        public_room: Some((room, *mailbox.as_bytes())),
    })
}

/// The own leaf's profile for a join (12.3): the display name, `updated`
/// now. A guest's leaf carries one too.
fn join_profile(tx: &Tx<'_>, cx: &Ctx<'_>) -> Result<RisalaProfile> {
    let name = group::display_name(tx, cx)?;
    RisalaProfile::new(&name, cx.now).ok_or(EngineError::Invalid("display name".into()))
}

/// 12.7: before joining a room again, the extension it would join is
/// compared with the one kept, unless the user accepted the change.
fn compare_kept(tx: &Tx<'_>, conv: ConversationId, ext: &RisalaConversation) -> Result<()> {
    let state = tx.public_state(conv)?;
    if state.accept_change {
        return Ok(());
    }
    let Some(kept) = state.kept_ext else {
        return Ok(());
    };
    let Ok(kept) = RisalaConversation::decode(&kept) else {
        return Ok(());
    };
    let changed = kept.unexplained_changes(ext);
    if changed.is_empty() {
        Ok(())
    } else {
        Err(EngineError::RoomChanged {
            conv,
            fields: changed.into_iter().map(str::to_owned).collect(),
        })
    }
}

/// A join started: the conversation, in state `joining`, and the proposal
/// to post with the token `-`.
#[derive(Debug)]
pub(crate) struct Started {
    pub conv: ConversationId,
    pub proposal: Vec<u8>,
}

/// What [`start_join`] did.
#[derive(Debug)]
pub(crate) enum StartJoin {
    /// The device is in the room already.
    AlreadyIn(ConversationId),
    /// A join by proposal.
    Proposal(Started),
}

/// Starts a join of `room` by external proposal (6.1), or of a room the
/// device is in but cannot follow, `existing` (12.7): checks the group as
/// 12.7 says, makes a KeyPackage for this join, with no device binding,
/// and the proposal. The conversation waits in state `joining` for its
/// Welcome, and follows the mailbox meanwhile.
///
/// A name that leads to another group than the one the device joined
/// before fails, unless `new_group` (6.1).
pub(crate) fn start_join(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    room: &str,
    state: &RoomState,
    existing: Option<ConversationId>,
    new_group: bool,
) -> Result<StartJoin> {
    let (view, _, group_id) = room_view(cx, state)?;
    let ext = view.conversation.clone().map_err(mls)?;
    if ext.kind != ConversationKind::PublicRoom || ext.name != room {
        return Err(EngineError::Invalid(format!(
            "{room} is not that public room"
        )));
    }
    // 6.1: the group id of a room joined before, by name.
    if let Some(known) = tx.room_group(cx.account, room)?
        && known != group_id
        && !new_group
    {
        return Err(EngineError::Invalid(format!(
            "{room} now leads to a different group than the one joined before"
        )));
    }
    let conv = match existing {
        Some(conv) => Some(conv),
        None => tx
            .conversation_by_group(cx.account, &group_id)?
            .map(|r| r.id),
    };
    if let Some(conv) = conv {
        let row = tx.conversation(conv)?;
        if row.state.in_group() && existing.is_none() {
            return Ok(StartJoin::AlreadyIn(conv));
        }
        compare_kept(tx, conv, &ext)?;
    }
    let identity = own_identity(cx)?;
    let profile = join_profile(tx, cx)?;
    let expect = expectation(cx, room, &state.mailbox)?;
    let request = mls_group::join_public_room(
        &tx.mls(cx.crypto),
        &identity,
        Some(&profile),
        &state.group_info,
        &state.tree,
        &expect,
        group::ts(cx.now),
    )
    .map_err(mls)?;
    let conv = match conv {
        Some(conv) => {
            tx.set_state(conv, ConvState::Joining)?;
            if tx.mailbox(cx.account, &state.mailbox)?.is_none() {
                tx.add_mailbox(conv, &state.mailbox, true, 0, None)?;
            }
            conv
        }
        None => {
            let pseudonym =
                risala_mls::aad::Pseudonym::generate().map_err(|_| EngineError::Random)?;
            let conv = tx.insert_conversation(&NewConversation {
                account: cx.account,
                group_id: &group_id,
                kind: ConvKind::Public,
                room: Some(room),
                name: &ext.name,
                topic: &ext.topic,
                peer: None,
                epoch: state.epoch,
                pseudonym: pseudonym.0,
                state: ConvState::Joining,
                last_resort: false,
                now: cx.now,
            })?;
            // 7.4: follow after a random wait; posts before the current
            // epoch's commit are of no use to a device that joins now.
            let wait = super::random_below(cx.config.max_follow_wait_ms)?;
            tx.add_mailbox(conv, &state.mailbox, true, 0, Some(cx.now + wait))?;
            tx.set_sync(conv, &state.mailbox, state.seq, None)?;
            conv
        }
    };
    let key_package = risala_mls::wire::to_bytes(&MlsMessageOut::from(request.key_package));
    tx.add_join(
        cx.account,
        conv,
        room,
        &state.mailbox,
        &key_package,
        &request.key_package_ref,
        state.epoch,
        cx.now,
    )?;
    Ok(StartJoin::Proposal(Started {
        conv,
        proposal: request.message,
    }))
}

/// What [`check_join`] found.
#[derive(Debug)]
pub(crate) enum JoinStep {
    /// Nothing new: no commit since the proposal.
    Wait,
    /// A commit added the leaf: fetch the Welcome with this ref.
    Fetch(Vec<u8>),
    /// No commit added it: post the proposal again, for the new epoch.
    Propose(Vec<u8>),
    /// An owner or moderator whose proposal waited 30 minutes: join by
    /// external commit (12.7).
    Rejoin,
}

/// The join's KeyPackage and its leaf key.
fn join_key_package(
    tx: &Tx<'_>,
    cx: &Ctx<'_>,
    join: &JoinRow,
) -> Result<(risala_mls::openmls::prelude::KeyPackage, LeafKey)> {
    let kp = risala_mls::keypackage::verify_key_package(
        cx.crypto.as_ref(),
        read_key_package(&join.key_package).map_err(mls)?,
    )
    .map_err(mls)?;
    let key = LeafKey::load(
        &tx.mls_storage(),
        KEY_PACKAGE_SCOPE,
        kp.leaf_node().signature_key().as_slice(),
    )
    .map_err(|e| EngineError::Mls(format!("{e:?}")))?
    .ok_or(EngineError::Invalid("the join's leaf key is gone".into()))?;
    Ok((kp, key))
}

/// Checks a join against the room as it is now (6.1).
pub(crate) fn check_join(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    join: &JoinRow,
    state: &RoomState,
) -> Result<JoinStep> {
    let (view, _, group_id) = room_view(cx, state)?;
    let (kp, key) = join_key_package(tx, cx, join)?;
    let own_key = kp.leaf_node().signature_key().as_slice();
    if view.leaves.iter().any(|l| l.signature_key == own_key) {
        // The first check after the commit that added it knows its seq.
        let seq = (state.epoch == join.epoch + 1).then_some(state.seq);
        tx.set_join_added(join.id, state.epoch, seq)?;
        return Ok(JoinStep::Fetch(join.reference.clone()));
    }
    // 12.7: an owner or moderator whose proposal nobody committed within 30
    // minutes may join by external commit.
    let role = view
        .conversation
        .as_ref()
        .map_or(Role::Member, |c| c.role(cx.uid));
    if !cx.guest && role >= Role::Mod && cx.now >= join.proposed_at + REJOIN_AFTER_MS {
        return Ok(JoinStep::Rejoin);
    }
    if state.epoch == join.epoch {
        return Ok(JoinStep::Wait);
    }
    // A proposal belongs to its epoch: the same KeyPackage again (6.1).
    let proposal = mls_group::join_proposal::<crate::store::mls::MlsProvider<'_>>(
        &kp,
        &GroupId::from_slice(&group_id),
        state.epoch,
        &key,
    )
    .map_err(mls)?;
    tx.set_join_epoch(join.id, state.epoch)?;
    Ok(JoinStep::Propose(proposal))
}

/// Joins a public room by the Welcome that WELCOME GET returned, with the
/// tree of its epoch (12.8). MLS checks the tree against the tree hash in
/// the Welcome's group context, and the group is checked as 12.7 says.
/// The device then applies the posts from the Welcome's epoch on.
pub(crate) fn join_by_welcome(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    join: &JoinRow,
    welcome: &[u8],
    tree: &[u8],
) -> Result<ConversationId> {
    let row = tx.conversation(join.conv)?;
    // The group this device could not follow, if any: it joins anew.
    if let Ok(mut old) = load(tx, cx, &row.group_id) {
        mls_group::forget_group(&tx.mls(cx.crypto), &mut old).map_err(mls)?;
    }
    let expect = expectation(cx, &join.room, &join.mailbox)?;
    let joined = mls_group::join_by_welcome(&tx.mls(cx.crypto), welcome, Some(tree), &expect)
        .map_err(mls)?;
    let group = joined.group;
    if group.group_id().as_slice() != row.group_id.as_slice() {
        return Err(EngineError::Invalid(
            "a Welcome to another group than the room's".into(),
        ));
    }
    let ext = mls_group::conversation(&group)
        .ok_or(EngineError::Mls("no conversation extension".into()))?;
    compare_kept(tx, row.id, &ext)?;
    let epoch = group.epoch().as_u64();
    tx.set_group_history(row.id, &joined.state)?;
    tx.set_epoch(row.id, epoch, None)?;
    tx.set_conversation_info(row.id, &ext.name, &ext.topic, Some(&ext.name))?;
    tx.set_kept_ext(row.id, &ext.encode())?;
    tx.set_accept_change(row.id, false)?;
    tx.set_room_group(cx.account, &join.room, &row.group_id)?;
    tx.sync_leaves(row.id, &tree_leaves(&group))?;
    tx.set_state(row.id, ConvState::Active)?;
    tx.set_joined(row.id, cx.now)?;
    // Back to the commit that started the Welcome's epoch, if it is known,
    // so that no post of that epoch is missed.
    if join.added_epoch == Some(epoch)
        && let Some(seq) = join.added_seq
        && let Some(mb) = tx.mailbox(cx.account, &join.mailbox)?
        && seq < mb.sync_point
    {
        tx.drop_posts(row.id, &join.mailbox)?;
        tx.set_sync(row.id, &join.mailbox, seq, None)?;
    }
    tx.delete_join(join.id)?;
    Ok(row.id)
}

/// Makes an external commit to a public room (12.7), merged at once, and
/// queues it to post with the token `-`, `groupinfo=` and `next=` on the
/// signed-in connection: a resync commit, which removes the leaf that
/// signed the GroupInfo, or an owner's or moderator's rejoin. Either
/// removes this device's earlier leaves. If the server refuses it, the
/// device joins by proposal instead ([`external_lost`]).
pub(crate) fn external_join(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: ConversationId,
    room: &str,
    state: &RoomState,
    kind: External,
) -> Result<()> {
    if cx.guest {
        return Err(EngineError::Invalid(
            "only an identity's device commits externally".into(),
        ));
    }
    let row = tx.conversation(conv)?;
    let (view, _, group_id) = room_view(cx, state)?;
    if group_id != row.group_id {
        return Err(EngineError::Invalid("the room's group changed".into()));
    }
    let ext = view.conversation.clone().map_err(mls)?;
    compare_kept(tx, conv, &ext)?;
    let identity = own_identity(cx)?;
    // 12.7 says a resync commit removes the GroupInfo's signer and the
    // device's own earlier leaf. OpenMLS processes no external commit with
    // more than one Remove (valn0402), so a resync removes the signer only,
    // and a rejoin one earlier leaf; the device removes the rest in its
    // next commit, as leaves of its own identity (public_cleanup), which
    // the group checks allow.
    let own_leaves: Vec<LeafNodeIndex> = match kind {
        External::Resync => Vec::new(),
        External::Rejoin => view
            .leaves
            .iter()
            .filter(|l| l.identity.as_ref() == Some(&identity))
            .map(|l| l.index)
            .take(1)
            .collect(),
    };
    if let Ok(mut old) = load(tx, cx, &row.group_id) {
        mls_group::forget_group(&tx.mls(cx.crypto), &mut old).map_err(mls)?;
    }
    let profile = join_profile(tx, cx)?;
    let expect = expectation(cx, room, &state.mailbox)?;
    let made = mls_group::external_commit(
        &tx.mls(cx.crypto),
        &identity,
        &profile,
        &state.group_info,
        &state.tree,
        &expect,
        kind,
        &own_leaves,
    )
    .map_err(mls)?;
    let group = made.group;
    let ext = mls_group::conversation(&group)
        .ok_or(EngineError::Mls("no conversation extension".into()))?;
    tx.set_group_history(conv, &made.state)?;
    tx.set_epoch(conv, group.epoch().as_u64(), None)?;
    tx.set_conversation_info(conv, &ext.name, &ext.topic, Some(&ext.name))?;
    tx.set_kept_ext(conv, &ext.encode())?;
    tx.set_accept_change(conv, false)?;
    tx.set_room_group(cx.account, room, &row.group_id)?;
    tx.sync_leaves(conv, &tree_leaves(&group))?;
    tx.set_state(conv, ConvState::Active)?;
    if tx.mailbox(cx.account, &state.mailbox)?.is_none() {
        tx.add_mailbox(conv, &state.mailbox, true, 0, None)?;
    }
    if let Some(join) = tx.join_of(conv)? {
        tx.delete_join(join.id)?;
    }
    tx.queue_outbox(
        conv,
        OutboxKind::External,
        &NewOutbox {
            epoch: Some(state.epoch),
            post: Some(made.message),
            next: Some(made.next_token_hash),
            groupinfo: Some(made.group_info),
            ..NewOutbox::default()
        },
        cx.now,
    )?;
    Ok(())
}

/// The server refused an external commit: the group it made is of no use,
/// and the device joins by proposal instead (12.7).
pub(crate) fn external_lost(tx: &mut Tx<'_>, cx: &Ctx<'_>, conv: ConversationId) -> Result<()> {
    let row = tx.conversation(conv)?;
    if let Ok(mut group) = load(tx, cx, &row.group_id) {
        mls_group::forget_group(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
    }
    tx.set_state(conv, ConvState::Joining)?;
    Ok(())
}

/// The room name of a public room conversation.
pub(crate) fn room_of(tx: &Tx<'_>, conv: ConversationId) -> Result<(String, BoxName)> {
    let row = tx.conversation(conv)?;
    let room = row
        .room
        .clone()
        .ok_or(EngineError::Invalid("not a public room".into()))?;
    let mailbox = tx.current_mailbox(conv)?.mailbox;
    Ok((room, mailbox))
}

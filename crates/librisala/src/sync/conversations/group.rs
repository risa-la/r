//! The group engine's MLS operations, each inside one write transaction
//! of the cache, so that a group's OpenMLS state and the cache's rows
//! commit or roll back together (store/mls.rs).
//!
//! - [`create`]: a new group and its conversation (12.6).
//! - [`build_commit`]: a commit from an [`Intent`], left pending (7.2).
//! - [`apply_post`]: one post of a mailbox, in seq order: the first valid
//!   commit of each epoch wins (7.2), messages are read (12.9).
//! - [`join_welcome`]: a sealed Welcome (12.8).

use std::time::{Duration, UNIX_EPOCH};

use risala_mls::aad::Pseudonym;
use risala_mls::checks::{GroupView, JoinExpectation, check_commit};
use risala_mls::conversation::{ConversationKind, RisalaConversation};
use risala_mls::framing::{ContentType, read_post};
use risala_mls::group::{self as mls_group, Changes, Incoming, ProcessError};
use risala_mls::identity::{DeviceId, RisalaIdentity};
use risala_mls::keypackage::{check_key_package_contents, read_key_package, verify_key_package};
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::{
    GroupId, KeyPackage, KeyPackageBundle, KeyPackageRef, LeafNodeIndex,
};
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::openmls_traits::storage::StorageProvider as _;
use risala_mls::profile::RisalaProfile;
use risala_mls::token::SendToken;
use risala_proto::names::{BoxName, Uid};

use super::wire::{self, Intent, Then};
use super::{Ctx, EngineError, Note};
use crate::store::Tx;
use crate::store::conversations::{
    ConvKind, ConvRow, ConvState, ConversationId, MailboxRow, NewConversation, PostRow, TreeLeaf,
    is_blocked,
};
use crate::store::messages::{NewOutbox, OutboxKind, OutboxRow, OutboxState};

type Result<T> = std::result::Result<T, EngineError>;

fn mls(e: impl std::fmt::Display) -> EngineError {
    EngineError::Mls(e.to_string())
}

/// Loads a group by id. Another process may have changed it, so this is
/// done in every transaction that uses it (store/mls.rs).
pub(crate) fn load(tx: &Tx<'_>, cx: &Ctx<'_>, group_id: &[u8]) -> Result<MlsGroup> {
    let p = tx.mls(cx.crypto);
    MlsGroup::load(p.storage(), &GroupId::from_slice(group_id))
        .map_err(|e| EngineError::Mls(format!("{e:?}")))?
        .ok_or(EngineError::Mls("the group is not in the cache".into()))
}

/// The kind of conversation the cache keeps for a conversation extension.
pub(crate) fn conv_kind(ext: &RisalaConversation, own: &Uid) -> ConvKind {
    match ext.kind {
        ConversationKind::Direct => {
            let participants = ext.direct_participants().unwrap_or_default();
            if participants.len() == 1 || participants.iter().all(|p| p == own) {
                ConvKind::WithYourself
            } else {
                ConvKind::Direct
            }
        }
        ConversationKind::PrivateRoom => ConvKind::Private,
        ConversationKind::PublicRoom => ConvKind::Public,
    }
}

/// The other participant of a direct conversation.
pub(crate) fn peer_of(ext: &RisalaConversation, own: &Uid) -> Option<Uid> {
    ext.direct_participants()?.into_iter().find(|p| p != own)
}

/// The box of a conversation extension.
pub(crate) fn box_of(ext: &RisalaConversation) -> BoxName {
    BoxName::from_bytes(ext.mailbox)
}

/// The group's leaves, for the cache.
pub(crate) fn tree_leaves(group: &MlsGroup) -> Vec<TreeLeaf> {
    GroupView::of(group.public_group())
        .leaves
        .into_iter()
        .filter_map(|leaf| {
            let identity = leaf.identity?;
            Some(TreeLeaf {
                leaf: leaf.index.u32(),
                uid: identity.uid,
                device_id: identity.device_id.map(|d| d.0),
                signature_key: leaf.signature_key,
                display_name: leaf.profile.as_ref().map(|p| p.display_name.clone()),
                updated: leaf.profile.as_ref().map(|p| p.updated),
            })
        })
        .collect()
}

/// This device's credential in the account's groups (12.3).
pub(crate) fn own_identity(cx: &Ctx<'_>) -> Result<RisalaIdentity> {
    if cx.guest {
        return Ok(RisalaIdentity::guest(cx.uid.clone()));
    }
    let key = cx
        .hooks
        .device_key(cx.account, cx.uid)
        .ok_or(EngineError::Invalid(
            "this device's device key is not available".into(),
        ))?;
    Ok(RisalaIdentity::device(
        cx.uid.clone(),
        DeviceId::of_device_key(key.public_key()),
    ))
}

/// This device's display name for the account (8.2).
pub(crate) fn display_name(tx: &Tx<'_>, cx: &Ctx<'_>) -> Result<String> {
    use rusqlite::OptionalExtension as _;
    let name: Option<String> = tx
        .conn()
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [display_name_key(cx.account)],
            |r| r.get(0),
        )
        .optional()
        .map_err(crate::store::StoreError::from)?;
    Ok(name.unwrap_or_default())
}

/// The settings key of an account's display name (8.2).
pub(crate) fn display_name_key(account: crate::store::AccountId) -> String {
    format!("display-name/{account}")
}

/// The own leaf's profile for a commit made now (12.3): the display name,
/// and `updated` from the clock, never below the leaf's previous one.
fn own_profile(
    tx: &Tx<'_>,
    cx: &Ctx<'_>,
    group: &MlsGroup,
    name: Option<&str>,
) -> Result<RisalaProfile> {
    let previous = group.own_leaf_node().and_then(RisalaProfile::of_leaf);
    let name = match name {
        Some(name) => name.to_owned(),
        None => match &previous {
            Some(p) => p.display_name.clone(),
            None => display_name(tx, cx)?,
        },
    };
    let updated = cx.now.max(previous.map_or(0, |p| p.updated));
    RisalaProfile::new(&name, updated)
        .ok_or(EngineError::Invalid("a display name over 128 bytes".into()))
}

/// What [`create`] made.
#[derive(Debug)]
pub(crate) struct Created {
    pub conv: ConversationId,
    pub mailbox: BoxName,
    pub group_id: [u8; 32],
    pub token_hash: [u8; 48],
}

/// Creates a group for a new conversation (12.6), its row and its
/// mailbox's, and queues the commit that adds `adds` (12.7). The mailbox
/// is not created on the server yet.
pub(crate) fn create(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    ext_for: impl FnOnce([u8; 16]) -> RisalaConversation,
    adds: Vec<Vec<u8>>,
) -> Result<Created> {
    let box_bytes: [u8; 16] = risala_mls::primitives::random().map_err(|_| EngineError::Random)?;
    let ext = ext_for(box_bytes);
    let identity = own_identity(cx)?;
    let name = display_name(tx, cx)?;
    let profile =
        RisalaProfile::new(&name, cx.now).ok_or(EngineError::Invalid("display name".into()))?;
    let (group, _) =
        mls_group::create_group(&tx.mls(cx.crypto), &identity, &profile, &ext).map_err(mls)?;
    let token_hash = SendToken::of_group(&group, cx.crypto.as_ref())
        .map_err(mls)?
        .hash();
    let group_id: [u8; 32] = group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| EngineError::Mls("a group id of another length".into()))?;
    let pseudonym = Pseudonym::generate().map_err(|_| EngineError::Random)?;
    let kind = conv_kind(&ext, cx.uid);
    let peer = peer_of(&ext, cx.uid);
    let mailbox = box_of(&ext);
    let room = (kind == ConvKind::Public).then(|| ext.name.clone());
    let conv = tx.insert_conversation(&NewConversation {
        account: cx.account,
        group_id: &group_id,
        kind,
        room: room.as_deref(),
        name: &ext.name,
        topic: &ext.topic,
        peer: peer.as_ref(),
        epoch: 0,
        pseudonym: pseudonym.0,
        state: if adds.is_empty() {
            ConvState::Active
        } else {
            ConvState::Creating
        },
        last_resort: false,
        now: cx.now,
    })?;
    tx.add_mailbox(conv, &mailbox, true, 0, None)?;
    tx.sync_leaves(conv, &tree_leaves(&group))?;
    if !adds.is_empty() {
        queue_intent(
            tx,
            conv,
            &Intent {
                add: adds,
                ..Intent::default()
            },
            cx.now,
        )?;
    }
    Ok(Created {
        conv,
        mailbox,
        group_id,
        token_hash,
    })
}

/// Queues a commit of `intent`, to make when the conversation is caught
/// up (see [`build_commit`]).
pub(crate) fn queue_intent(
    tx: &mut Tx<'_>,
    conv: ConversationId,
    intent: &Intent,
    now: u64,
) -> Result<i64> {
    Ok(tx.queue_outbox(
        conv,
        OutboxKind::Commit,
        &NewOutbox {
            intent: Some(intent.encode()),
            ..NewOutbox::default()
        },
        now,
    )?)
}

/// A KeyPackage fetched with KEYPKG GET, read and checked as far as the
/// group can (12.5, 12.7): valid MLS, of the suite, a device's credential,
/// a profile and an acceptable lifetime. Its binding is checked against
/// the key file through the hooks; one that cannot be checked yet is
/// accepted, and the added leaf stays unconfirmed (12.7).
pub(crate) fn check_fetched(cx: &Ctx<'_>, bytes: &[u8], uid: &Uid) -> Option<KeyPackage> {
    let kp = verify_key_package(cx.crypto.as_ref(), read_key_package(bytes).ok()?).ok()?;
    let now = UNIX_EPOCH + Duration::from_millis(cx.now);
    let (identity, _) = check_key_package_contents(&kp, now).ok()?;
    if &identity.uid != uid {
        return None;
    }
    let device = identity.device_id?;
    if let Some(key) = cx.hooks.device_key_of(cx.account, uid, &device) {
        // `None`: not a current device of the identity.
        let key = key?;
        risala_mls::keypackage::check_binding(&kp, &identity, &key).ok()?;
    }
    Some(kp)
}

/// Whether a commit of this device is pending in the conversation: posted
/// or about to be.
pub(crate) fn has_pending_commit(tx: &Tx<'_>, conv: ConversationId) -> Result<bool> {
    Ok(tx
        .pending_outbox(conv)?
        .iter()
        .any(|o| o.kind == OutboxKind::Commit && o.post.is_some()))
}

/// Makes the commit of an outbox row from its intent, against the group
/// as it is, and leaves it pending (7.2). Returns `false` if there is
/// nothing left to do, and marks the row done.
pub(crate) fn build_commit(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    row: &OutboxRow,
) -> Result<bool> {
    let intent = Intent::decode(row.intent.as_deref().unwrap_or_default())
        .map_err(|e| EngineError::Invalid(e.to_string()))?;
    let mut group = load(tx, cx, &conv.group_id)?;
    if group.pending_commit().is_some() {
        mls_group::discard_own_commit(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
    }
    let view = GroupView::of(group.public_group());
    let own = group.own_leaf_index();
    let remove: Vec<LeafNodeIndex> = view
        .leaves
        .iter()
        .filter(|leaf| leaf.index != own)
        .filter(|leaf| {
            leaf.identity.as_ref().is_some_and(|id| {
                intent.remove.iter().any(|(uid, device)| {
                    id.uid.as_str() == uid && id.device_id.map(|d| d.0) == *device
                })
            })
        })
        .map(|leaf| leaf.index)
        .collect();
    let mut add = Vec::new();
    for bytes in &intent.add {
        let Ok(kp) = read_key_package(bytes) else {
            continue;
        };
        let Ok(kp) = verify_key_package(cx.crypto.as_ref(), kp) else {
            continue;
        };
        let Ok(identity) = RisalaIdentity::from_credential(kp.leaf_node().credential()) else {
            continue;
        };
        // A device that has a leaf already, which this commit does not
        // remove, is not added twice (12.7, one leaf per device).
        let present = view
            .leaves
            .iter()
            .any(|leaf| leaf.identity.as_ref() == Some(&identity) && !remove.contains(&leaf.index));
        if !present {
            add.push(kp);
        }
    }
    let conversation = match &intent.conversation {
        Some(bytes) => Some(
            RisalaConversation::decode(bytes).map_err(|e| EngineError::Invalid(e.0.to_owned()))?,
        ),
        None => None,
    };
    let proposals = group.pending_proposals().next().is_some();
    let meaningful = !add.is_empty()
        || !remove.is_empty()
        || conversation.is_some()
        || intent.new_leaf_key
        || intent.display_name.is_some()
        || proposals
        || intent == Intent::default()
        || intent.then != Then::Nothing;
    if !meaningful {
        tx.update_outbox(row.id, OutboxState::Done, None, None, None)?;
        return Ok(false);
    }
    let profile = own_profile(tx, cx, &group, intent.display_name.as_deref())?;
    let out = mls_group::commit(
        &tx.mls(cx.crypto),
        &mut group,
        Pseudonym(conv.pseudonym),
        &profile,
        Changes {
            add,
            remove,
            conversation,
            new_leaf_key: intent.new_leaf_key,
        },
    )
    .map_err(mls)?;
    let epoch = group.epoch().as_u64();
    tx.set_outbox_commit(
        row.id,
        &out.next_token_hash,
        out.group_info.as_deref(),
        out.welcome.as_deref(),
    )?;
    tx.update_outbox(
        row.id,
        OutboxState::Queued,
        Some((&out.message, epoch)),
        None,
        None,
    )?;
    Ok(true)
}

/// Drops this device's pending commit, which lost or was refused, and
/// queues its intent again if it is still needed (7.2).
pub(crate) fn commit_lost(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    row: &OutboxRow,
) -> Result<()> {
    if let Ok(mut group) = load(tx, cx, &conv.group_id)
        && group.pending_commit().is_some()
    {
        mls_group::discard_own_commit(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
    }
    tx.update_outbox(row.id, OutboxState::Lost, None, None, None)?;
    if conv.state.in_group()
        && let Some(intent) = &row.intent
    {
        let intent = Intent::decode(intent).map_err(|e| EngineError::Invalid(e.to_string()))?;
        queue_intent(tx, conv.id, &intent, cx.now)?;
    }
    Ok(())
}

/// What applying a post did, for the engine.
#[derive(Debug, Default)]
pub(crate) struct Applied {
    /// Things to tell the engine.
    pub notes: Vec<Note>,
}

/// Applies one post of a mailbox, the next after its sync point (7.2,
/// 7.4, 12.9).
pub(crate) fn apply_post(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    mailbox: &MailboxRow,
    post: &PostRow,
) -> Result<Applied> {
    let mut applied = Applied::default();
    if !conv.state.in_group() {
        return Ok(applied);
    }
    let Ok((framing, _aad)) = read_post(&post.message) else {
        return Ok(applied);
    };
    if framing.group_id != conv.group_id.as_slice() {
        return Ok(applied);
    }
    // 7.8: in a mailbox the group moved to, posts of earlier epochs are
    // ignored; in the one it moved from, those of the move's epoch on.
    if framing.epoch < mailbox.first_epoch {
        return Ok(applied);
    }
    if !mailbox.current
        && let Some(current) = tx.mailboxes(conv.id)?.into_iter().find(|m| m.current)
        && current.first_epoch > 0
        && framing.epoch >= current.first_epoch
    {
        return Ok(applied);
    }
    let content_type = framing.content_type;
    let post_epoch = framing.epoch;
    let mut group = load(tx, cx, &conv.group_id)?;
    let epoch = group.epoch().as_u64();

    // This device's own post: matched by its bytes, since it cannot
    // decrypt its own PrivateMessages.
    if let Some(row) = tx.outbox_by_post(conv.id, &post.message)? {
        match row.kind {
            // Already decided: it lost, and its intent was queued again.
            OutboxKind::Commit if matches!(row.state, OutboxState::Lost | OutboxState::Done) => {}
            OutboxKind::Commit => {
                if post_epoch == epoch && group.pending_commit().is_some() {
                    let intent = row
                        .intent
                        .as_deref()
                        .and_then(|i| Intent::decode(i).ok())
                        .unwrap_or_default();
                    let removed = removed_without_readd(&group);
                    mls_group::merge_own_commit(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
                    tx.update_outbox(row.id, OutboxState::Done, None, Some(post.seq), None)?;
                    after_commit(tx, cx, conv, &group, post, true, removed, &mut applied)?;
                    own_commit_won(tx, cx, conv, &row, &intent, &mut applied)?;
                } else {
                    // A commit for an epoch it no longer holds: it lost.
                    commit_lost(tx, cx, conv, &row)?;
                }
            }
            OutboxKind::Message | OutboxKind::Live | OutboxKind::Proposal => {
                tx.update_outbox(row.id, OutboxState::Done, None, Some(post.seq), None)?;
                if let Some(id) = row.message_id {
                    tx.message_posted(conv.id, &id, post.seq, post_epoch, post.t)?;
                }
            }
        }
        return Ok(applied);
    }

    match content_type {
        ContentType::Commit => {
            if post_epoch != epoch {
                // Of an earlier epoch, whose commit has been chosen, or of
                // a later one, of a branch this device does not follow.
                return Ok(applied);
            }
            let processed =
                mls_group::process_message(&tx.mls(cx.crypto), &mut group, &post.message);
            let commit = match processed {
                Ok(Incoming::Commit(commit)) => commit,
                Ok(_) => return Ok(applied),
                Err(e) => {
                    // It fails MLS here: invalid for this device (12.7,
                    // "Commits a device cannot process").
                    tracing::debug!(error = %e, seq = post.seq, "a commit this device cannot process");
                    applied.notes.push(Note::Unprocessable {
                        conv: conv.id,
                        epoch,
                        seq: post.seq,
                    });
                    return Ok(applied);
                }
            };
            // The group checks (12.7): next, then the rest.
            // A device that the commit removes cannot compute the next
            // epoch's token, and checks only that `next` is there: whether
            // the others accept the commit no longer matters to it.
            let next_ok = match post.next {
                None => false,
                Some(_) if commit.staged.self_removed() => true,
                Some(next) => {
                    mls_group::next_token_hash_ok(&commit.staged, cx.crypto.as_ref(), &next)
                }
            };
            if !next_ok {
                tracing::debug!(seq = post.seq, "a commit with a wrong or missing next");
                return Ok(applied);
            }
            let facts = cx.hooks.key_facts(tx, cx.account);
            let at = UNIX_EPOCH + Duration::from_millis(post.t);
            let view = GroupView::of(group.public_group());
            if let Err(e) = check_commit(&view, &commit.view, facts.as_ref(), at) {
                tracing::debug!(error = %e, seq = post.seq, "an invalid commit");
                applied.notes.push(Note::InvalidCommit {
                    conv: conv.id,
                    seq: post.seq,
                    reason: e.to_string(),
                });
                return Ok(applied);
            }
            drop(facts);
            let own_pending = tx
                .pending_outbox(conv.id)?
                .into_iter()
                .find(|o| o.kind == OutboxKind::Commit && o.post.is_some());
            let removed = removed_by_staged(&group, &commit.staged);
            let previous_ext = mls_group::conversation(&group);
            let active =
                mls_group::apply_commit(&tx.mls(cx.crypto), &mut group, *commit).map_err(mls)?;
            if let Some(row) = own_pending {
                // Another commit won the epoch: this device's lost (7.2).
                tx.update_outbox(row.id, OutboxState::Lost, None, None, None)?;
                if let Some(intent) = &row.intent {
                    let intent =
                        Intent::decode(intent).map_err(|e| EngineError::Invalid(e.to_string()))?;
                    if active {
                        queue_intent(tx, conv.id, &intent, cx.now)?;
                    }
                }
            }
            if !active {
                tx.set_state(conv.id, ConvState::Left)?;
                mls_group::forget_group(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
                applied.notes.push(Note::Removed { conv: conv.id });
                return Ok(applied);
            }
            let _ = previous_ext;
            after_commit(tx, cx, conv, &group, post, false, removed, &mut applied)?;
        }
        ContentType::Proposal => {
            if post_epoch != epoch {
                return Ok(applied);
            }
            match mls_group::process_message(&tx.mls(cx.crypto), &mut group, &post.message) {
                Ok(Incoming::Proposal { .. }) => {
                    for queued in group.pending_proposals() {
                        if let (
                            risala_mls::openmls::prelude::Proposal::SelfRemove,
                            risala_mls::openmls::prelude::Sender::Member(index),
                        ) = (queued.proposal(), queued.sender())
                        {
                            tx.mark_self_removed(conv.id, index.u32())?;
                        }
                    }
                    applied.notes.push(Note::Proposals { conv: conv.id });
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "a proposal this device cannot use"),
            }
        }
        ContentType::Application => {
            if post_epoch > epoch {
                applied.notes.push(Note::Undecryptable {
                    conv: conv.id,
                    epoch: post_epoch,
                });
                return Ok(applied);
            }
            // Late messages (12.9): an epoch at most 2 behind, posted within
            // an hour of the commit that ended it, as far as the cache
            // knows when that was.
            if post_epoch + 2 < epoch {
                return Ok(applied);
            }
            if post_epoch < epoch
                && let Some(ended) = conv.epoch_t
                && post_epoch + 1 == epoch
                && post.t > ended + 3_600_000
            {
                return Ok(applied);
            }
            let incoming =
                mls_group::process_message(&tx.mls(cx.crypto), &mut group, &post.message);
            match incoming {
                Ok(Incoming::Application {
                    sender,
                    aad,
                    content,
                }) => {
                    super::content::receive(
                        tx,
                        cx,
                        conv,
                        super::content::Received {
                            leaf: sender.u32(),
                            pseudonym: aad.pseudonym.0,
                            frank: aad.frank,
                            body: &content,
                            seq: Some(post.seq),
                            t: post.t,
                            epoch: post_epoch,
                        },
                        &mut applied,
                    )?;
                }
                Ok(_) => {}
                Err(ProcessError::Mls(e)) => {
                    tracing::debug!(error = %e, seq = post.seq, "a message this device cannot read");
                }
                Err(e) => tracing::debug!(error = %e, "a message this device cannot use"),
            }
        }
    }
    Ok(applied)
}

/// The (uid, device) of every leaf that `staged` removes and does not
/// add again, for the move of 7.8.
fn removed_by_staged(
    group: &MlsGroup,
    staged: &risala_mls::openmls::group::StagedCommit,
) -> Vec<RisalaIdentity> {
    let view = GroupView::of(group.public_group());
    let mut removed: Vec<RisalaIdentity> = Vec::new();
    for queued in staged.queued_proposals() {
        let index = match queued.proposal() {
            risala_mls::openmls::prelude::Proposal::Remove(r) => Some(r.removed()),
            risala_mls::openmls::prelude::Proposal::SelfRemove => match queued.sender() {
                risala_mls::openmls::prelude::Sender::Member(i) => Some(*i),
                _ => None,
            },
            _ => None,
        };
        if let Some(index) = index
            && let Some(identity) = view.leaf(index).and_then(|l| l.identity.clone())
        {
            removed.push(identity);
        }
    }
    let added: Vec<RisalaIdentity> = staged
        .add_proposals()
        .filter_map(|add| {
            RisalaIdentity::from_credential(
                add.add_proposal().key_package().leaf_node().credential(),
            )
            .ok()
        })
        .collect();
    removed.retain(|r| !added.contains(r));
    removed
}

/// [`removed_by_staged`] for this device's own pending commit.
fn removed_without_readd(group: &MlsGroup) -> Vec<RisalaIdentity> {
    match group.pending_commit() {
        Some(staged) => removed_by_staged(group, staged),
        None => Vec::new(),
    }
}

/// Brings the cache in line with the group after a commit: its epoch,
/// what the conversation extension says, its mailbox and its leaves.
#[allow(clippy::too_many_arguments)]
fn after_commit(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    group: &MlsGroup,
    post: &PostRow,
    own: bool,
    removed: Vec<RisalaIdentity>,
    applied: &mut Applied,
) -> Result<()> {
    tx.set_epoch(conv.id, group.epoch().as_u64(), Some(post.t))?;
    if let Some(ext) = mls_group::conversation(group) {
        let room = (ext.kind == ConversationKind::PublicRoom).then(|| ext.name.clone());
        tx.set_conversation_info(conv.id, &ext.name, &ext.topic, room.as_deref())?;
        // A move (7.8): the group's box changed.
        let new_box = box_of(&ext);
        let current = tx.current_mailbox(conv.id)?;
        if current.mailbox != new_box {
            tx.retire_mailbox(conv.id, &current.mailbox, cx.now + super::OLD_MAILBOX_MS)?;
            tx.add_mailbox(conv.id, &new_box, true, group.epoch().as_u64(), None)?;
            applied.notes.push(Note::Moved {
                conv: conv.id,
                mailbox: new_box,
            });
        }
    }
    tx.sync_leaves(conv.id, &tree_leaves(group))?;
    if conv.state == ConvState::Creating {
        tx.set_state(conv.id, ConvState::Active)?;
    }
    if conv.state == ConvState::Leaving {
        // The SelfRemove belongs to its epoch: post it again (6.1).
        queue_self_remove(tx, conv.id, cx.now)?;
    }
    applied.notes.push(Note::Committed {
        conv: conv.id,
        own,
        removed,
    });
    Ok(())
}

/// Queues a SelfRemove, made when it is posted (6.1).
pub(crate) fn queue_self_remove(tx: &mut Tx<'_>, conv: ConversationId, now: u64) -> Result<()> {
    let pending = tx
        .pending_outbox(conv)?
        .into_iter()
        .any(|o| o.kind == OutboxKind::Proposal && o.state == OutboxState::Queued);
    if !pending {
        tx.queue_outbox(conv, OutboxKind::Proposal, &NewOutbox::default(), now)?;
    }
    Ok(())
}

/// After this device's own commit won: its Welcomes, sealed one per
/// device, each after a random wait (12.8), and what the intent does next.
fn own_commit_won(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    row: &OutboxRow,
    intent: &Intent,
    applied: &mut Applied,
) -> Result<()> {
    if intent.new_leaf_key {
        tx.clear_last_resort(conv.id)?;
    }
    if let Some(welcome) = &row.welcome {
        let parts =
            wire::split_welcome(welcome).map_err(|e| EngineError::Invalid(e.to_string()))?;
        for bytes in &intent.add {
            let Ok(kp) = read_key_package(bytes) else {
                continue;
            };
            let Ok(kp) = verify_key_package(cx.crypto.as_ref(), kp) else {
                continue;
            };
            let Ok(reference) = kp.hash_ref(cx.crypto.as_ref()) else {
                continue;
            };
            let Some(part) = parts.iter().find(|p| p.reference == reference.as_slice()) else {
                continue;
            };
            let sealed = wire::seal_welcome(cx.crypto.as_ref(), &kp, part)
                .map_err(|e| EngineError::Invalid(e.to_string()))?;
            let wait = super::random_below(cx.config.max_welcome_wait_ms)?;
            tx.queue_welcome(conv.id, reference.as_slice(), &sealed, cx.now + wait)?;
        }
    }
    if intent.then == Then::SelfRemove {
        tx.set_state(conv.id, ConvState::Leaving)?;
        queue_self_remove(tx, conv.id, cx.now)?;
    }
    applied.notes.push(Note::Won);
    Ok(())
}

/// Makes a SelfRemove of this device's leaf, to post now (6.1).
pub(crate) fn make_self_remove(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
) -> Result<(Vec<u8>, u64)> {
    let mut group = load(tx, cx, &conv.group_id)?;
    let message = mls_group::self_remove(&tx.mls(cx.crypto), &mut group, Pseudonym(conv.pseudonym))
        .map_err(mls)?;
    Ok((message, group.epoch().as_u64()))
}

/// Encrypts a RisalaMessage in the group's current epoch (12.9), with a
/// new RisalaAAD whose `frank` is the message's.
pub(crate) fn encrypt(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    body: &[u8],
) -> Result<(Vec<u8>, u64)> {
    let message =
        wire::RisalaMessage::decode(body).map_err(|e| EngineError::Invalid(e.to_string()))?;
    let mut group = load(tx, cx, &conv.group_id)?;
    let aad = risala_mls::aad::RisalaAad::application(Pseudonym(conv.pseudonym), message.frank());
    let post =
        mls_group::encrypt_application(&tx.mls(cx.crypto), &mut group, &aad, body).map_err(mls)?;
    Ok((post, group.epoch().as_u64()))
}

/// The send token of the group's current epoch (7.2).
pub(crate) fn send_token(tx: &Tx<'_>, cx: &Ctx<'_>, conv: &ConvRow) -> Result<(SendToken, u64)> {
    let group = load(tx, cx, &conv.group_id)?;
    let token = SendToken::of_group(&group, cx.crypto.as_ref()).map_err(mls)?;
    Ok((token, group.epoch().as_u64()))
}

/// The first 8 bytes of the epoch authenticator of the group's current
/// epoch, for READ (7.7, 12.9).
pub(crate) fn epoch_check(tx: &Tx<'_>, cx: &Ctx<'_>, conv: &ConvRow) -> Result<[u8; 8]> {
    let group = load(tx, cx, &conv.group_id)?;
    let auth = group.epoch_authenticator().as_slice();
    auth.get(..8)
        .and_then(|b| b.try_into().ok())
        .ok_or(EngineError::Mls("a short epoch authenticator".into()))
}

/// A KeyPackageRef from its bytes: a `HashReference`, whose encoding is
/// one vector.
fn key_package_ref(bytes: &[u8]) -> Result<KeyPackageRef> {
    use risala_mls::openmls::prelude::tls_codec::DeserializeBytes as _;
    let mut encoded = Vec::with_capacity(bytes.len() + 2);
    wire::write_varint(&mut encoded, bytes.len());
    encoded.extend_from_slice(bytes);
    KeyPackageRef::tls_deserialize_exact_bytes(&encoded)
        .map_err(|e| EngineError::Mls(e.to_string()))
}

/// What [`join_welcome`] did.
#[derive(Debug)]
pub(crate) enum Joined {
    /// Joined the conversation.
    Joined {
        conv: ConversationId,
        mailbox: BoxName,
    },
    /// The Welcome is not for this device, or its group fails the checks
    /// of 12.7 or 5.7: delete it.
    Refused(String),
}

/// Opens a sealed Welcome with one of this device's KeyPackages, and joins
/// its group if it passes the checks of 12.7 and is not refused for a
/// block (5.7) (12.8).
pub(crate) fn join_welcome(tx: &mut Tx<'_>, cx: &Ctx<'_>, sealed: &[u8]) -> Result<Joined> {
    let mut opened = None;
    for reference in tx.key_package_refs(cx.account)? {
        let kp_ref = key_package_ref(&reference)?;
        let bundle: Option<KeyPackageBundle> = tx
            .mls(cx.crypto)
            .storage()
            .key_package(&kp_ref)
            .map_err(|e| EngineError::Mls(format!("{e:?}")))?;
        let Some(bundle) = bundle else { continue };
        if let Ok(welcome) = wire::open_welcome(
            cx.crypto.as_ref(),
            bundle.init_private_key(),
            &reference,
            sealed,
        ) {
            opened = Some((reference, welcome));
            break;
        }
    }
    let Some((reference, welcome)) = opened else {
        return Ok(Joined::Refused(
            "no KeyPackage of this device opens it".into(),
        ));
    };
    let expect = JoinExpectation {
        host: cx.host.to_owned(),
        own_uid: cx.uid.clone(),
        public_room: None,
    };
    let joined = match mls_group::join_by_welcome(&tx.mls(cx.crypto), &welcome, None, &expect) {
        Ok(joined) => joined,
        Err(risala_mls::group::GroupError::Storage(e)) => {
            return Err(EngineError::Mls(format!("{e:?}")));
        }
        Err(e) => return Ok(Joined::Refused(e.to_string())),
    };
    let mut group = joined.group;
    let ext = mls_group::conversation(&group)
        .ok_or(EngineError::Mls("no conversation extension".into()))?;
    // 5.7: a direct conversation with someone blocked, or a room in which
    // someone blocked has a leaf.
    let blocks = tx.blocks(cx.account)?;
    let blocked = tree_leaves(&group)
        .iter()
        .any(|leaf| is_blocked(&blocks, &leaf.uid));
    if blocked {
        mls_group::forget_group(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
        tx.used_key_package(cx.account, &reference)?;
        return Ok(Joined::Refused("someone the user blocked is in it".into()));
    }
    if tx
        .conversation_by_group(cx.account, group.group_id().as_slice())?
        .is_some()
    {
        return Ok(Joined::Refused("a group this device is in already".into()));
    }
    let kind = conv_kind(&ext, cx.uid);
    let peer = peer_of(&ext, cx.uid);
    let mailbox = box_of(&ext);
    let pseudonym = Pseudonym::generate().map_err(|_| EngineError::Random)?;
    let room = (kind == ConvKind::Public).then(|| ext.name.clone());
    let conv = tx.insert_conversation(&NewConversation {
        account: cx.account,
        group_id: group.group_id().as_slice(),
        kind,
        room: room.as_deref(),
        name: &ext.name,
        topic: &ext.topic,
        peer: peer.as_ref(),
        epoch: group.epoch().as_u64(),
        pseudonym: pseudonym.0,
        state: ConvState::Active,
        last_resort: joined.last_resort,
        now: cx.now,
    })?;
    // 7.4: follow after a random wait, so that the FOLLOW does not match
    // the WELCOME line.
    let wait = super::random_below(cx.config.max_follow_wait_ms)?;
    tx.add_mailbox(conv, &mailbox, true, 0, Some(cx.now + wait))?;
    tx.sync_leaves(conv, &tree_leaves(&group))?;
    tx.used_key_package(cx.account, &reference)?;
    if joined.last_resort {
        // 12.5: a new leaf key before it sends anything.
        queue_intent(
            tx,
            conv,
            &Intent {
                new_leaf_key: true,
                ..Intent::default()
            },
            cx.now,
        )?;
    }
    Ok(Joined::Joined { conv, mailbox })
}

/// Makes `n` ordinary KeyPackages and, if `last_resort`, one of last
/// resort, records their refs, and returns them for KEYPKG ADD (12.5).
pub(crate) fn make_key_packages(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    n: usize,
    last_resort: bool,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let key = cx
        .hooks
        .device_key(cx.account, cx.uid)
        .ok_or(EngineError::Invalid(
            "this device's device key is not available".into(),
        ))?;
    let profile = RisalaProfile::new("", cx.now).expect("an empty name");
    let mut out = Vec::new();
    for i in 0..n + usize::from(last_resort) {
        let resort = i == n;
        let made = risala_mls::keypackage::make_key_package(
            &tx.mls(cx.crypto),
            &key,
            cx.uid,
            &profile,
            resort,
        )
        .map_err(mls)?;
        let reference = made.key_package.hash_ref(cx.crypto.as_ref()).map_err(mls)?;
        tx.add_key_package(cx.account, reference.as_slice(), resort, cx.now)?;
        let message = risala_mls::openmls::prelude::MlsMessageOut::from(made.key_package);
        out.push((
            reference.as_slice().to_vec(),
            risala_mls::wire::to_bytes(&message),
        ));
    }
    Ok(out)
}

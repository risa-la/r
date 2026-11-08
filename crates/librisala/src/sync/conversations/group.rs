//! The group engine's MLS operations, each inside one write transaction
//! of the cache, so that a group's OpenMLS state and the cache's rows
//! commit or roll back together (store/mls.rs).
//!
//! - [`create`]: a new group and its conversation (12.6).
//! - [`build_commit`]: a commit from an [`Intent`], left pending (7.2).
//! - [`apply_post`]: one post of a mailbox, in seq order: the first valid
//!   commit of each epoch wins (7.2), messages are read (12.9).
//! - [`join_welcome`]: a sealed Welcome (12.8).
//!
//! The group checks and their [`History`](risala_mls::checks::History) are
//! `risala_mls::checks`'s, and messages are read by
//! `risala_mls::message::receive`, with the cache's [`MessageLog`] as its
//! history.

use risala_mls::aad::Pseudonym;
use risala_mls::checks::{CommitPost, GroupView, JoinExpectation};
use risala_mls::conversation::{ConversationKind, RisalaConversation};
use risala_mls::framing::{ContentType, read_post};
use risala_mls::group::{self as mls_group, Changes, Incoming, ProposalKind};
use risala_mls::identity::{DeviceId, RisalaIdentity};
use risala_mls::keypackage::{
    check_key_package_contents, lifetime_acceptable_at, read_key_package, verify_key_package,
};
use risala_mls::message::{self as mls_message, MessageHistory as _, PostInfo, ReceiveError};
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::{GroupId, KeyPackage, LeafNodeIndex};
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::profile::RisalaProfile;
use risala_mls::token::SendToken;
use risala_proto::names::{BoxName, Uid};
use risala_proto::time::Timestamp;

use super::wire::{Fetched, Intent, Then};
use super::{Ctx, EngineError, Note};
use crate::store::Tx;
use crate::store::conversations::{
    ConvKind, ConvRow, ConvState, ConversationId, MailboxRow, NewConversation, PostRow, TreeLeaf,
    is_blocked,
};
use crate::store::messages::{MessageLog, NewOutbox, OutboxKind, OutboxRow, OutboxState};

type Result<T> = std::result::Result<T, EngineError>;

fn mls(e: impl std::fmt::Display) -> EngineError {
    EngineError::Mls(e.to_string())
}

fn ts(ms: u64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap_or(Timestamp::MAX)
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
    let key = cx.device_key.ok_or(EngineError::Invalid(
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
/// and `updated` from the clock. `risala_mls::group::commit` raises it to
/// the leaf's previous one and sets the streak.
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
    RisalaProfile::new(&name, cx.now)
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
    adds: Vec<Fetched>,
) -> Result<Created> {
    let box_bytes: [u8; 16] = risala_mls::primitives::random().map_err(|_| EngineError::Random)?;
    let ext = ext_for(box_bytes);
    let identity = own_identity(cx)?;
    let name = display_name(tx, cx)?;
    let profile =
        RisalaProfile::new(&name, cx.now).ok_or(EngineError::Invalid("display name".into()))?;
    let (group, _, history) =
        mls_group::create_group(&tx.mls(cx.crypto), &identity, &profile, &ext, cx.now)
            .map_err(mls)?;
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
    tx.set_group_history(conv, &history)?;
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

/// Reads and verifies a KeyPackage's MLSMessage.
fn read_kp(cx: &Ctx<'_>, bytes: &[u8]) -> Option<KeyPackage> {
    verify_key_package(cx.crypto.as_ref(), read_key_package(bytes).ok()?).ok()
}

/// A KeyPackage fetched with KEYPKG GET, read and checked as far as the
/// group can (12.5, 12.7): valid MLS, of the suite, a device's credential
/// of `uid`, a profile, and a lifetime acceptable now. Its binding is
/// checked against the key file through the hooks; one that cannot be
/// checked yet is accepted, and the added leaf stays unconfirmed (12.7).
pub(crate) fn check_fetched(
    tx: &Tx<'_>,
    cx: &Ctx<'_>,
    bytes: &[u8],
    uid: &Uid,
) -> Option<KeyPackage> {
    let kp = read_kp(cx, bytes)?;
    let (identity, _) = check_key_package_contents(&kp).ok()?;
    if &identity.uid != uid || !lifetime_acceptable_at(kp.life_time(), cx.now) {
        return None;
    }
    let device = identity.device_id?;
    if let Some(key) = cx.hooks.device_key_of(tx, cx.account, uid, &device) {
        // `None`: not a current device of the identity.
        let key = key?;
        risala_mls::keypackage::check_binding(&kp, &identity, &key).ok()?;
    }
    Some(kp)
}

/// Whether a commit of this device is pending in the conversation: made,
/// and posted or about to be.
pub(crate) fn has_pending_commit(tx: &Tx<'_>, conv: ConversationId) -> Result<bool> {
    Ok(tx
        .pending_outbox(conv)?
        .iter()
        .any(|o| o.kind == OutboxKind::Commit && o.post.is_some()))
}

/// What [`build_commit`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Built {
    /// The commit is made, and pending.
    Made,
    /// There was nothing left to do; the row is done.
    Nothing,
    /// The leaf has started the last 3 epochs: it may commit again only
    /// once its `updated` can be 10 minutes after its previous one, at
    /// this time (12.7, streaks).
    WaitUntil(u64),
}

/// Makes the commit of an outbox row from its intent, against the group
/// as it is, and leaves it pending (7.2).
pub(crate) fn build_commit(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    row: &OutboxRow,
) -> Result<Built> {
    let intent = Intent::decode(row.intent.as_deref().unwrap_or_default())
        .map_err(|e| EngineError::Invalid(e.to_string()))?;
    let mut group = load(tx, cx, &conv.group_id)?;
    if group.pending_commit().is_some() {
        mls_group::discard_own_commit(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
    }
    let history = tx.group_history(conv.id)?;
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
    for fetched in &intent.add {
        let Some(kp) = read_kp(cx, &fetched.key_package) else {
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
    // An intent to add or remove leaves that are all added or removed
    // already, and that does nothing else, needs no commit.
    let membership = !intent.add.is_empty() || !intent.remove.is_empty();
    if membership
        && add.is_empty()
        && remove.is_empty()
        && conversation.is_none()
        && !intent.new_leaf_key
        && intent.display_name.is_none()
        && intent.then == Then::Nothing
        && group.pending_proposals().next().is_none()
    {
        tx.update_outbox(row.id, OutboxState::Done, None, None, None)?;
        return Ok(Built::Nothing);
    }
    // 12.7, streaks: a fourth commit in a row needs `updated` at least 10
    // minutes after the previous one, unless it only removes leaves of
    // the committer's own identity.
    let previous = group.own_leaf_node().and_then(RisalaProfile::of_leaf);
    let streak = history.expected_streak(own, previous.as_ref().map_or(0, |p| p.streak));
    let own_removals_only = add.is_empty()
        && conversation.is_none()
        && !intent.new_leaf_key
        && intent.display_name.is_none()
        && !remove.is_empty()
        && remove.iter().all(|i| {
            view.leaf(*i)
                .and_then(|l| l.identity.as_ref())
                .is_some_and(|id| id.uid == *cx.uid)
        });
    if streak > risala_mls::checks::STREAK_LIMIT
        && !own_removals_only
        && let Some(previous) = &previous
    {
        let earliest = previous.updated + risala_mls::checks::UPDATED_SKEW_MS;
        if cx.now < earliest {
            return Ok(Built::WaitUntil(earliest));
        }
    }
    let profile = own_profile(tx, cx, &group, intent.display_name.as_deref())?;
    // 7.8: a move's box is derived from the exporter of the epoch the
    // commit is made in.
    let move_box = if intent.move_box {
        let b = derived_box(cx, &group)?;
        tx.set_outbox_move(row.id, &BoxName::from_bytes(b))?;
        Some(b)
    } else {
        None
    };
    let out = mls_group::commit(
        &tx.mls(cx.crypto),
        &mut group,
        Pseudonym(conv.pseudonym),
        &profile,
        &history,
        Changes {
            add,
            remove,
            conversation,
            move_box,
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
    Ok(Built::Made)
}

/// The exporter label of a moved mailbox's box (7.8, 15).
pub(crate) const BOX_LABEL: &str = "risala/1 box";

/// The box a group moves to from the epoch it is in (7.8):
/// `MLS-Exporter("risala/1 box", "", 16)`.
pub(crate) fn derived_box(cx: &Ctx<'_>, group: &MlsGroup) -> Result<[u8; 16]> {
    let bytes = group
        .export_secret(cx.crypto.as_ref(), BOX_LABEL, b"", 16)
        .map_err(mls)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| EngineError::Mls("an exporter of another length".into()))
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
    let Ok((framing, _)) = read_post(&post.message) else {
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
    let commit_post = CommitPost {
        t: post.t,
        next: post.next,
    };

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
                    let removed = group
                        .pending_commit()
                        .map(mls_message::removed_leaves)
                        .unwrap_or_default();
                    let removed_ids = removed_identities(&group, &removed);
                    let old_token = SendToken::of_group(&group, cx.crypto.as_ref()).map_err(mls)?;
                    let mut history = tx.group_history(conv.id)?;
                    mls_group::merge_own_commit(
                        &tx.mls(cx.crypto),
                        &mut group,
                        &mut history,
                        &commit_post,
                    )
                    .map_err(mls)?;
                    tx.set_group_history(conv.id, &history)?;
                    tx.set_prev_token(conv.id, old_token.as_bytes())?;
                    note_commit(tx, cx, conv.id, &mut group, epoch, post.t, &removed)?;
                    tx.update_outbox(row.id, OutboxState::Done, None, Some(post.seq), None)?;
                    after_commit(tx, cx, conv, &group, post, true, removed_ids, &mut applied)?;
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
            // The group checks (12.7), next included.
            let mut history = tx.group_history(conv.id)?;
            let verdict = match mls_group::check_received_commit(
                &group,
                &commit,
                &history,
                &commit_post,
                cx.crypto.as_ref(),
            ) {
                Ok(verdict) => verdict,
                Err(e) => {
                    tracing::debug!(error = %e, seq = post.seq, "an invalid commit");
                    applied.notes.push(Note::InvalidCommit {
                        conv: conv.id,
                        seq: post.seq,
                        reason: e.to_string(),
                    });
                    return Ok(applied);
                }
            };
            // The key checks never make it invalid (12.7); their repairs
            // are the identity area's (task C1).
            {
                let facts = cx.hooks.key_facts(tx, cx.account);
                let report =
                    mls_group::check_received_keys(&group, &commit, &verdict, facts.as_ref());
                if report != risala_mls::checks::KeyReport::default() {
                    tracing::info!(?report, "a commit whose key checks need a repair");
                }
            }
            let own_pending = tx
                .pending_outbox(conv.id)?
                .into_iter()
                .find(|o| o.kind == OutboxKind::Commit && o.post.is_some());
            let removed = mls_message::removed_leaves(&commit.staged);
            let removed_ids = removed_identities(&group, &removed);
            let old_token = SendToken::of_group(&group, cx.crypto.as_ref()).map_err(mls)?;
            let active = mls_group::apply_commit(
                &tx.mls(cx.crypto),
                &mut group,
                *commit,
                &verdict,
                &mut history,
                &commit_post,
            )
            .map_err(mls)?;
            tx.set_group_history(conv.id, &history)?;
            if let Some(row) = own_pending {
                // Another commit won the epoch: this device's lost (7.2).
                tx.update_outbox(row.id, OutboxState::Lost, None, None, None)?;
                if active && let Some(intent) = &row.intent {
                    let intent =
                        Intent::decode(intent).map_err(|e| EngineError::Invalid(e.to_string()))?;
                    queue_intent(tx, conv.id, &intent, cx.now)?;
                }
            }
            if !active {
                tx.set_state(conv.id, ConvState::Left)?;
                mls_group::forget_group(&tx.mls(cx.crypto), &mut group).map_err(mls)?;
                applied.notes.push(Note::Removed { conv: conv.id });
                return Ok(applied);
            }
            tx.set_prev_token(conv.id, old_token.as_bytes())?;
            note_commit(tx, cx, conv.id, &mut group, epoch, post.t, &removed)?;
            after_commit(tx, cx, conv, &group, post, false, removed_ids, &mut applied)?;
        }
        ContentType::Proposal => {
            if post_epoch != epoch {
                return Ok(applied);
            }
            match mls_group::process_message(&tx.mls(cx.crypto), &mut group, &post.message) {
                Ok(Incoming::Proposal {
                    kind,
                    sender,
                    reference,
                    ..
                }) => {
                    match kind {
                        ProposalKind::SelfRemove => {
                            if let Some(sender) = sender {
                                tx.mark_self_removed(conv.id, sender.u32())?;
                            }
                            let mut log = MessageLog::new(tx.conn(), conv.id);
                            mls_message::note_self_removes(&group, &mut log);
                            log.finish()?;
                        }
                        ProposalKind::Update => {
                            let mut history = tx.group_history(conv.id)?;
                            history.note_update(&reference, post.t);
                            tx.set_group_history(conv.id, &history)?;
                        }
                        ProposalKind::Join => {}
                    }
                    applied.notes.push(Note::Proposals { conv: conv.id });
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "a proposal this device cannot use"),
            }
        }
        ContentType::Application => {
            let mut log = MessageLog::new(tx.conn(), conv.id);
            let received = mls_message::receive(
                &tx.mls(cx.crypto),
                &mut group,
                &post.message,
                PostInfo {
                    t: ts(post.t),
                    live: false,
                },
                &mut log,
            );
            log.finish()?;
            match received {
                Ok(decrypted) => {
                    super::content::receive(
                        tx,
                        cx,
                        conv,
                        &group,
                        decrypted,
                        Some(post.seq),
                        post.t,
                        &mut applied,
                    )?;
                }
                Err(ReceiveError::Process(e)) if post_epoch > epoch => {
                    tracing::debug!(error = %e, "a message of a later epoch");
                    applied.notes.push(Note::Undecryptable {
                        conv: conv.id,
                        epoch: post_epoch,
                    });
                }
                Err(ReceiveError::Storage(e)) => return Err(EngineError::Mls(format!("{e:?}"))),
                Err(e) => tracing::debug!(error = %e, seq = post.seq, "a message not shown"),
            }
        }
    }
    Ok(applied)
}

/// Notes a commit in the message history (12.9): the end of the epoch it
/// ended, and its removed leaves; then deletes past epochs' secrets that
/// are past the limits.
fn note_commit(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: ConversationId,
    group: &mut MlsGroup,
    ended_epoch: u64,
    t: u64,
    removed: &[LeafNodeIndex],
) -> Result<()> {
    let mut log = MessageLog::new(tx.conn(), conv);
    log.note_commit(ended_epoch, ts(t), removed);
    mls_message::expire_past_epochs(&tx.mls(cx.crypto), group, &log, ts(t)).map_err(mls)?;
    log.finish()?;
    Ok(())
}

/// The identities of leaves, for the move of 7.8.
fn removed_identities(group: &MlsGroup, removed: &[LeafNodeIndex]) -> Vec<RisalaIdentity> {
    let view = GroupView::of(group.public_group());
    removed
        .iter()
        .filter_map(|i| view.leaf(*i).and_then(|l| l.identity.clone()))
        .collect()
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
    let tree = tree_leaves(group);
    tx.sync_leaves(conv.id, &tree)?;
    // 7.8: a removal that adds the same device back is no reason to move.
    let removed: Vec<RisalaIdentity> = removed
        .into_iter()
        .filter(|id| {
            !tree
                .iter()
                .any(|l| l.uid == id.uid && l.device_id == id.device_id.map(|d| d.0))
        })
        .collect();
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

/// Leaves a conversation (6.1): a commit that removes this identity's
/// other leaves, if it has any, followed by a SelfRemove once it wins;
/// otherwise the SelfRemove alone.
pub(crate) fn leave(tx: &mut Tx<'_>, conv: ConversationId, own: &Uid, now: u64) -> Result<()> {
    let row = tx.conversation(conv)?;
    if !row.state.in_group() || row.state == ConvState::Leaving {
        return Ok(());
    }
    let own_leaves: Vec<(String, Option<[u8; 48]>)> =
        crate::store::conversations::read::leaves(tx.conn(), conv)?
            .into_iter()
            .filter(|l| l.uid == *own)
            .map(|l| (l.uid.to_string(), l.device_id))
            .collect();
    if own_leaves.len() > 1 {
        // This device's own leaf is left out when the commit is made.
        queue_intent(
            tx,
            conv,
            &Intent {
                remove: own_leaves,
                then: Then::SelfRemove,
                ..Intent::default()
            },
            now,
        )?;
    } else {
        tx.set_state(conv, ConvState::Leaving)?;
        queue_self_remove(tx, conv, now)?;
    }
    Ok(())
}

/// 5.1: devices keep one direct conversation per pair of identities. If
/// `conv` is a second one, the one whose group id is lower stays, and this
/// device leaves the other. Returns the one it leaves, if any.
pub(crate) fn keep_one_direct(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: ConversationId,
) -> Result<Option<ConversationId>> {
    let row = tx.conversation(conv)?;
    if row.kind != ConvKind::Direct {
        return Ok(None);
    }
    let other = tx.conversations_of(cx.account)?.into_iter().find(|r| {
        r.id != conv && r.kind == ConvKind::Direct && r.peer == row.peer && r.state.in_group()
    });
    let Some(other) = other else { return Ok(None) };
    let higher = if other.group_id < row.group_id {
        row.id
    } else {
        other.id
    };
    leave(tx, higher, cx.uid, cx.now)?;
    Ok(Some(higher))
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
        // The KeyPackages the commit added, with their put secrets.
        let mut kps = Vec::new();
        let mut secrets = Vec::new();
        for fetched in &intent.add {
            let Some(kp) = read_kp(cx, &fetched.key_package) else {
                continue;
            };
            let Ok(reference) = kp.hash_ref(cx.crypto.as_ref()) else {
                continue;
            };
            if risala_mls::welcome::split_welcome(welcome, &[reference.as_slice()]).is_ok() {
                secrets.push((reference.as_slice().to_vec(), fetched.secret.clone()));
                kps.push(kp);
            }
        }
        let sealed = risala_mls::welcome::seal_welcomes(cx.crypto.as_ref(), welcome, &kps)
            .map_err(|e| EngineError::Mls(e.to_string()))?;
        for s in sealed {
            let secret = secrets
                .iter()
                .find(|(r, _)| *r == s.key_package_ref)
                .map(|(_, secret)| secret.clone())
                .unwrap_or_default();
            let wait = super::random_below(cx.config.max_welcome_wait_ms)?;
            tx.queue_welcome(
                conv.id,
                &s.key_package_ref,
                &secret,
                &s.sealed,
                cx.now + wait,
            )?;
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
    let message = mls_message::RisalaMessage::decode(body)
        .map_err(|e| EngineError::Invalid(e.to_string()))?;
    let mut group = load(tx, cx, &conv.group_id)?;
    let post = mls_message::encrypt(
        &tx.mls(cx.crypto),
        &mut group,
        Pseudonym(conv.pseudonym),
        &message,
    )
    .map_err(mls)?;
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

/// What [`join_welcome`] did.
#[derive(Debug)]
pub(crate) enum Joined {
    /// Joined the conversation.
    Joined { conv: ConversationId },
    /// The Welcome is not for this device, or its group fails the checks
    /// of 12.7 or 5.7: delete it.
    Refused(String),
}

/// Opens a sealed Welcome with one of this device's KeyPackages, and joins
/// its group if it passes the checks of 12.7 and is not refused for a
/// block (5.7) (12.8).
pub(crate) fn join_welcome(tx: &mut Tx<'_>, cx: &Ctx<'_>, sealed: &[u8]) -> Result<Joined> {
    let candidates = tx.key_package_refs(cx.account)?;
    let opened = risala_mls::welcome::open_sealed_welcome(&tx.mls(cx.crypto), sealed, &candidates);
    let (reference, welcome) = match opened {
        Ok(opened) => opened,
        Err(e) => return Ok(Joined::Refused(e.to_string())),
    };
    let expect = JoinExpectation {
        host: cx.host.to_owned(),
        own_uid: cx.uid.clone(),
        public_room: None,
    };
    let joined =
        match mls_group::join_by_welcome(&tx.mls(cx.crypto), &welcome, None, &expect, cx.now) {
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
    tx.set_group_history(conv, &joined.history)?;
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
    Ok(Joined::Joined { conv })
}

/// Makes `n` ordinary KeyPackages and, if `last_resort`, one of last
/// resort, records their refs, and returns them for KEYPKG ADD (12.5).
pub(crate) fn make_key_packages(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    n: usize,
    last_resort: bool,
) -> Result<Vec<Vec<u8>>> {
    let key = cx.device_key.ok_or(EngineError::Invalid(
        "this device's device key is not available".into(),
    ))?;
    let profile = RisalaProfile::new("", cx.now).expect("an empty name");
    let mut out = Vec::new();
    for i in 0..n + usize::from(last_resort) {
        let resort = i == n;
        let made = risala_mls::keypackage::make_key_package(
            &tx.mls(cx.crypto),
            key,
            cx.uid,
            &profile,
            resort,
        )
        .map_err(mls)?;
        let reference = made.key_package.hash_ref(cx.crypto.as_ref()).map_err(mls)?;
        tx.add_key_package(cx.account, reference.as_slice(), resort, cx.now)?;
        let message = risala_mls::openmls::prelude::MlsMessageOut::from(made.key_package);
        out.push(risala_mls::wire::to_bytes(&message));
    }
    Ok(out)
}

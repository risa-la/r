//! The key checks of 12.7 acting in the engine (task R2, LR-C2).
//!
//! The checks themselves are risala-mls's [`key_checks`], against the facts
//! that [`Hooks::key_facts`](super::Hooks::key_facts) gives (the identity
//! area's, task C1). This module acts on what they find:
//!
//! - **Unchecked adds.** A leaf added by a commit that the device could
//!   not check yet, by another member or by itself, is noted in
//!   `key_checks`, and the device sends nothing in the group while it is:
//!   no messages, no typing, and no commit with a new conversation
//!   extension. Repairs and other commits still go. The same holds from a
//!   failed check until its removal is queued, which then goes first.
//! - **Checking again.** [`recheck`] runs every minute: a check whose facts
//!   are now known passes or fails; one whose record is still pending 2
//!   hours after the device first needed it fails.
//! - **Repairs.** A failed check is repaired after a random wait of up to
//!   10 minutes, unless another device has made it first: the leaf is
//!   removed, for a check, where the group checks let this device
//!   ([`GroupView::may_remove_for_check`]). Where they do not, the device
//!   warns its user and hides what the leaf sends.
//! - **Warnings** go to the UI as [`ConversationEvent`]s.

use risala_mls::checks::{
    CommitView, Committer, EpochState, Fact, GroupView, KeyReport, Seen, Verdict, key_checks,
};
use risala_mls::identity::RisalaIdentity;
use risala_mls::keypackage::encryption_key_bytes;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::{LeafNodeIndex, Sender};
use risala_proto::names::Uid;

use super::group::{self, Applied};
use super::wire::Intent;
use super::{Ctx, EngineError, Note};
use crate::client::Event;
use crate::client::conversations::ConversationEvent;
use crate::store::Tx;
use crate::store::conversations::{ConvRow, ConversationId};
use crate::store::keychecks::{CheckKind, KeyCheckRow};
use crate::sync::Action;

type Result<T> = std::result::Result<T, EngineError>;

/// How long a record may stay pending for a check before the check fails
/// (12.7): a log must witness a record within an hour (4.5).
pub(crate) const PENDING_LIMIT_MS: u64 = 2 * 60 * 60 * 1000;

/// How often [`recheck`] runs.
pub(crate) const RECHECK_EVERY_MS: u64 = 60 * 1000;

fn emit(applied: &mut Applied, event: ConversationEvent) {
    applied
        .notes
        .push(Note::Hook(Box::new(Action::Emit(Event::Conversation(event)))));
}

/// What the device itself saw that explains a removal for a check (12.7):
/// the leaves that posted RESYNC in this epoch, and those that are
/// impostors to it (12.10).
pub(super) fn seen_leaves(
    tx: &Tx<'_>,
    conv: ConversationId,
) -> Result<(Vec<LeafNodeIndex>, Vec<LeafNodeIndex>)> {
    let resyncs = crate::store::conversations::read::leaves(tx.conn(), conv)?
        .into_iter()
        .filter(|l| l.resync_seq.is_some())
        .map(|l| LeafNodeIndex::new(l.leaf))
        .collect();
    let mut stmt = tx
        .conn()
        .prepare("SELECT leaf FROM leaf_confirmations WHERE conv = ?1 AND state = 'impostor'")
        .map_err(crate::store::StoreError::from)?;
    let impostors = stmt
        .query_map([conv.0], |r| r.get::<_, u32>(0))
        .map_err(crate::store::StoreError::from)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(crate::store::StoreError::from)?
        .into_iter()
        .map(LeafNodeIndex::new)
        .collect();
    Ok((resyncs, impostors))
}

/// The row of an added device's check, from the commit's Add proposal.
fn add_row(
    conv: ConversationId,
    identity: &RisalaIdentity,
    commit: &CommitView,
    now: u64,
) -> Option<KeyCheckRow> {
    let device_id = identity.device_id?;
    let key_package = commit.proposals.iter().find_map(|p| match p {
        risala_mls::checks::ProposalView::Add { key_package, .. }
            if RisalaIdentity::from_credential(key_package.leaf_node().credential()).ok()
                == Some(identity.clone()) =>
        {
            Some(key_package)
        }
        _ => None,
    })?;
    let binding = risala_mls::keypackage::leaf_binding(key_package)
        .and_then(std::result::Result::ok)
        .map(|b| b.encode());
    Some(KeyCheckRow {
        conv,
        uid: identity.uid.clone(),
        device_id: *device_id.as_bytes(),
        kind: CheckKind::Add,
        signature_key: key_package.leaf_node().signature_key().as_slice().to_vec(),
        init_key: Some(key_package.hpke_init_key().as_slice().to_vec()),
        encryption_key: Some(encryption_key_bytes(
            key_package.leaf_node().encryption_key(),
        )),
        binding,
        first_needed: now,
        failed: false,
        repair_at: None,
        warned: false,
    })
}

/// Whether this device may remove `target`'s leaves for a check in the
/// group as it is now (12.7).
fn may_repair(tx: &Tx<'_>, cx: &Ctx<'_>, conv: &ConvRow, target: &Uid) -> bool {
    let Ok(group) = group::load(tx, cx, &conv.group_id) else {
        return false;
    };
    GroupView::of(group.public_group(), &EpochState::default())
        .may_remove_for_check(cx.uid, target)
}

/// Marks a check failed: the repair after a random wait where this device
/// may make it, a warning either way.
fn fail(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    row: &KeyCheckRow,
    events: &mut Vec<ConversationEvent>,
) -> Result<()> {
    let repairing = may_repair(tx, cx, conv, &row.uid);
    let repair_at = if repairing {
        Some(cx.now + super::random_below(cx.config.max_commit_wait_ms)?)
    } else {
        None
    };
    tx.fail_check(row, repair_at)?;
    tracing::info!(conv = %conv.id, uid = %row.uid, repairing, "a key check failed");
    events.push(ConversationEvent::KeyCheckFailed {
        conversation: conv.id,
        uid: row.uid.clone(),
        repairing,
    });
    tx.set_check_warned(row)?;
    Ok(())
}

/// Acts on what a received commit's key checks found (12.7), before it is
/// applied: `view` and `commit` are as of the commit's epoch.
pub(super) fn record_received(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    view: &GroupView,
    commit: &CommitView,
    report: &KeyReport,
    applied: &mut Applied,
) -> Result<()> {
    if *report == KeyReport::default() {
        return Ok(());
    }
    if !cx.hooks.enforce_key_checks() {
        tracing::info!(?report, "key checks not enforced");
        return Ok(());
    }
    let held = tx.sending_held(conv.id)?;
    let mut events = Vec::new();
    record_adds(tx, cx, conv, commit, report, &mut events)?;
    let committer = match commit.committer {
        Committer::Member(index) => view.leaf(index),
        Committer::External => None,
    };
    if let Some(leaf) = committer
        && let Some(identity) = &leaf.identity
        && let Some(device_id) = identity.device_id
        && (report.committer_removed || report.committer_unchecked)
    {
        let row = KeyCheckRow {
            conv: conv.id,
            uid: identity.uid.clone(),
            device_id: *device_id.as_bytes(),
            kind: CheckKind::Committer,
            // The leaf's key after the commit, whose path may bring a new
            // one (12.3).
            signature_key: commit
                .path_leaf
                .as_ref()
                .map_or_else(|| leaf.signature_key.clone(), |l| l.signature_key.clone()),
            init_key: None,
            encryption_key: None,
            binding: None,
            first_needed: cx.now,
            failed: false,
            repair_at: None,
            warned: false,
        };
        if report.committer_removed {
            // 12.7: removed as an impostor's leaf.
            fail(tx, cx, conv, &row, &mut events)?;
        } else {
            tx.note_unchecked(&row)?;
        }
    }
    if !report.unexplained_removals.is_empty() || !report.unchecked_removals.is_empty() {
        events.push(ConversationEvent::RemovalUnchecked {
            conversation: conv.id,
            by: commit.committer_uid().cloned(),
        });
    }
    if !report.failed_removals.is_empty() {
        // 12.7: a removal of the own identity's current devices failed.
        // They are added again from new KeyPackages by whoever adds the
        // identity's current devices that have no leaf (the identity
        // area's upkeep, task C5); here the user is told.
        events.push(ConversationEvent::KeyCheckFailed {
            conversation: conv.id,
            uid: cx.uid.clone(),
            repairing: false,
        });
    }
    if !report.own_removed_by_own.is_empty() {
        events.push(ConversationEvent::OwnLeafRemoved {
            conversation: conv.id,
        });
    }
    if !held && tx.sending_held(conv.id)? {
        events.push(ConversationEvent::SendingHeld {
            conversation: conv.id,
        });
    }
    for event in events {
        emit(applied, event);
    }
    Ok(())
}

fn record_adds(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    commit: &CommitView,
    report: &KeyReport,
    events: &mut Vec<ConversationEvent>,
) -> Result<()> {
    for identity in &report.unchecked_adds {
        if let Some(row) = add_row(conv.id, identity, commit, cx.now) {
            tx.note_unchecked(&row)?;
        }
    }
    for identity in &report.failed_adds {
        if let Some(row) = add_row(conv.id, identity, commit, cx.now) {
            fail(tx, cx, conv, &row, events)?;
        }
    }
    Ok(())
}

/// Checks the devices that this device's own pending commit adds (12.7),
/// before it is merged: one added while its key file could not be read is
/// unchecked, as one another member added.
pub(super) fn record_own(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    group: &MlsGroup,
    state: &EpochState,
    applied: &mut Applied,
) -> Result<()> {
    let Some(staged) = group.pending_commit() else {
        return Ok(());
    };
    let commit = CommitView::of(&Sender::Member(group.own_leaf_index()), staged);
    if !commit
        .proposals
        .iter()
        .any(|p| matches!(p, risala_mls::checks::ProposalView::Add { .. }))
    {
        return Ok(());
    }
    if !cx.hooks.enforce_key_checks() {
        return Ok(());
    }
    let report = {
        let facts = cx.hooks.key_facts(tx, cx.account);
        let seen = Seen {
            own_uid: cx.uid,
            resyncs: &[],
            impostors: &[],
        };
        let view = GroupView::of(group.public_group(), state);
        key_checks(&view, &commit, &Verdict::default(), facts.as_ref(), &seen)
    };
    let report = KeyReport {
        failed_adds: report.failed_adds,
        unchecked_adds: report.unchecked_adds,
        ..KeyReport::default()
    };
    if report == KeyReport::default() {
        return Ok(());
    }
    let held = tx.sending_held(conv.id)?;
    let mut events = Vec::new();
    record_adds(tx, cx, conv, &commit, &report, &mut events)?;
    if !held && tx.sending_held(conv.id)? {
        events.push(ConversationEvent::SendingHeld {
            conversation: conv.id,
        });
    }
    for event in events {
        emit(applied, event);
    }
    Ok(())
}

/// What a check finds now.
enum Outcome {
    Passed,
    Failed,
    Pending,
}

fn evaluate(tx: &Tx<'_>, cx: &Ctx<'_>, row: &KeyCheckRow) -> Outcome {
    let facts = cx.hooks.key_facts(tx, cx.account);
    let device = risala_mls::identity::DeviceId::from_bytes(row.device_id);
    let outcome = match row.kind {
        CheckKind::Committer => match facts.device_removed(&row.uid, &device) {
            Fact::Known(true) => Outcome::Failed,
            Fact::Known(false) => Outcome::Passed,
            Fact::Unknown => Outcome::Pending,
        },
        CheckKind::Add => match (
            facts.current_device_key(&row.uid, &device),
            facts.device_removed(&row.uid, &device),
        ) {
            (_, Fact::Known(true)) | (Fact::Known(None), _) => Outcome::Failed,
            (Fact::Known(Some(key)), _) => {
                if binding_ok(row, &key) {
                    Outcome::Passed
                } else {
                    Outcome::Failed
                }
            }
            (Fact::Unknown, _) => Outcome::Pending,
        },
    };
    match outcome {
        // 12.7: still pending 2 hours after the device first needed it.
        Outcome::Pending if cx.now >= row.first_needed.saturating_add(PENDING_LIMIT_MS) => {
            Outcome::Failed
        }
        other => other,
    }
}

/// Whether an added leaf's KeyPackage binding verifies under `key`
/// (12.3, 12.7).
fn binding_ok(row: &KeyCheckRow, key: &[u8]) -> bool {
    let (Some(binding), Some(init), Some(encryption)) =
        (&row.binding, &row.init_key, &row.encryption_key)
    else {
        return false;
    };
    let Ok(binding) = risala_mls::binding::DeviceBinding::decode(binding) else {
        return false;
    };
    *binding.device_id.as_bytes() == row.device_id
        && binding.verify(key, &row.uid, init, encryption)
}

/// Checks again what could not be checked, and makes the repairs that
/// are due (12.7). Returns the warnings for the UI.
pub(super) fn recheck(tx: &mut Tx<'_>, cx: &Ctx<'_>) -> Result<Vec<Action>> {
    let rows = tx.key_checks(cx.account)?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    let mut held_before = std::collections::BTreeSet::new();
    for row in &rows {
        // As [`Tx::sending_held`] counts them.
        if (row.kind == CheckKind::Add && !row.failed) || row.repair_at.is_some() {
            held_before.insert(row.conv);
        }
    }
    for row in rows {
        let conv = tx.conversation(row.conv)?;
        // Gone with its leaf: removed, replaced, or this device left.
        let present = conv.state.in_group()
            && crate::store::conversations::read::leaves(tx.conn(), conv.id)?
                .iter()
                .any(|l| l.signature_key == row.signature_key);
        if !present {
            tx.clear_check(&row)?;
            continue;
        }
        if !row.failed {
            match evaluate(tx, cx, &row) {
                Outcome::Passed => tx.clear_check(&row)?,
                Outcome::Failed => fail(tx, cx, &conv, &row, &mut events)?,
                Outcome::Pending => {}
            }
            continue;
        }
        let Some(at) = row.repair_at else { continue };
        if at > cx.now {
            continue;
        }
        if may_repair(tx, cx, &conv, &row.uid) {
            let intent = Intent {
                remove: vec![(row.uid.to_string(), Some(row.device_id))],
                ..Intent::default()
            };
            group::queue_intent(tx, conv.id, &intent, cx.now)?;
            tracing::info!(conv = %conv.id, uid = %row.uid, "removing a leaf for a check");
        } else {
            events.push(ConversationEvent::KeyCheckFailed {
                conversation: conv.id,
                uid: row.uid.clone(),
                repairing: false,
            });
        }
        // Failed still: hidden until the leaf is gone.
        tx.fail_check(&row, None)?;
    }
    for conv in held_before {
        if !tx.sending_held(conv)? {
            events.push(ConversationEvent::SendingResumed { conversation: conv });
        }
    }
    Ok(events
        .into_iter()
        .map(|e| Action::Emit(Event::Conversation(e)))
        .collect())
}

/// Whether a queued commit waits while sending is held: one with a new
/// conversation extension would tell the unchecked leaf what it changes.
pub(super) fn commit_held(tx: &Tx<'_>, conv: ConversationId, intent: Option<&[u8]>) -> Result<bool> {
    let changes_extension = intent
        .and_then(|i| Intent::decode(i).ok())
        .is_some_and(|i| i.conversation.is_some() || i.display_name.is_some());
    Ok(changes_extension && tx.sending_held(conv)?)
}

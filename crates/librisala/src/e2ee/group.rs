//! MLS operations on a conversation's group (12.4-12.7, 12.9), each
//! inside one write transaction of the store, with the device-side checks
//! of 12.6.
//!
//! Every function loads the group from the cache, works on it, and writes
//! librisala's rows around it. An error leaves nothing behind: the caller
//! runs it in [`Store::write_with`](crate::store::Store), which rolls back.

use std::collections::HashSet;
use std::time::SystemTime;

use risala_mls::conversation::{ConversationKind, RisalaConversation};
use risala_mls::group::Changes;
use risala_mls::openmls::group::{MlsGroup, StagedCommit};
use risala_mls::openmls::prelude::{
    Credential, Extension, GroupId, KeyPackage, LeafNodeIndex, ProcessedMessageContent, Proposal,
    Sender,
};
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::signer::{credential_uid, signature_key};
use risala_mls::wire;
use risala_mls::{HistoryKey, check_key_package};
use risala_proto::auth::PublicKey;
use risala_proto::mls;
use risala_proto::names::{Conv, Uid};
use risala_proto::types::SendMode;

use super::{Device, E2eeError, mls};
use crate::store::e2ee::{GroupRow, GroupState, KeySource};
use crate::store::{ConvRow, Tx};

/// A leaf of a group: its index, identity and signature key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Leaf {
    pub index: LeafNodeIndex,
    pub uid: Uid,
    pub key: PublicKey,
}

/// The identity and key of a credential and signature key, or `None` if
/// they are not a leaf of risala's (12.2).
fn leaf_of(credential: &Credential, key: &[u8]) -> Option<(Uid, PublicKey)> {
    let uid: Uid = credential_uid(credential)?.parse().ok()?;
    Some((uid, signature_key(key)?))
}

/// The leaves of a group.
pub(crate) fn leaves(group: &MlsGroup) -> Result<Vec<Leaf>, E2eeError> {
    group
        .members()
        .map(|m| {
            let (uid, key) = leaf_of(&m.credential, &m.signature_key).ok_or(
                E2eeError::Rejected("a leaf that is not an identity's device"),
            )?;
            Ok(Leaf {
                index: m.index,
                uid,
                key,
            })
        })
        .collect()
}

/// The conversation extension a conversation's group must carry (12.2),
/// as far as the device can tell: for a room, the room's id must be known.
pub(crate) fn expected(me: &Uid, row: &ConvRow) -> Option<(ConversationKind, String)> {
    match &row.name {
        Conv::Uid(other) => {
            let c = RisalaConversation::direct(me, other);
            Some((c.kind, c.name))
        }
        Conv::Room(_) => Some((ConversationKind::Room, row.conv_id.as_ref()?.to_string())),
    }
}

/// Checks a group the device is about to join (12.6, "Joining"): the
/// conversation extension names the conversation; in a direct
/// conversation every leaf is a participant's; and in a room every leaf
/// belongs to an identity that the room's events show to be a member or
/// invited at seq `at`, other than `own`, the device's own leaf when it
/// joins by external commit.
fn check_joining(
    tx: &Tx<'_>,
    me: &Uid,
    row: &ConvRow,
    conversation: &RisalaConversation,
    leaves: &[Leaf],
    (at, own): (u64, Option<&PublicKey>),
) -> Result<(), E2eeError> {
    let (kind, name) =
        expected(me, row).ok_or(E2eeError::Rejected("the room's id is not known"))?;
    if conversation.kind != kind || conversation.name != name {
        return Err(E2eeError::Rejected("the group is for another conversation"));
    }
    match &row.name {
        Conv::Uid(other) => {
            if leaves.iter().any(|l| l.uid != *me && l.uid != *other) {
                return Err(E2eeError::Rejected(
                    "a direct conversation's group has an outsider",
                ));
            }
        }
        Conv::Room(_) => {
            for leaf in leaves {
                if Some(&leaf.key) == own {
                    continue;
                }
                if !tx.member_at(row.id, &leaf.uid, at)? {
                    return Err(E2eeError::Rejected(
                        "a room's group has a leaf of someone who is not a member",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn load(tx: &Tx<'_>, group_id: &[u8]) -> Result<MlsGroup, E2eeError> {
    MlsGroup::load(&tx.mls_storage(), &GroupId::from_slice(group_id))
        .map_err(mls)?
        .ok_or_else(|| E2eeError::Mls("the group is not in storage".into()))
}

/// The `send` value of a group's conversation extension.
fn send_mode(group: &MlsGroup) -> Option<SendMode> {
    RisalaConversation::from_extensions(group.extensions())
        .ok()
        .map(|c| c.send)
}

// ---------------------------------------------------------------------------
// KeyPackages (12.4)

/// Makes `n` KeyPackages for KEYPKG ADD, with the `last_resort` extension
/// if asked. Their private keys stay in the cache's OpenMLS storage.
pub(crate) fn key_packages(
    tx: &Tx<'_>,
    dev: &Device,
    n: usize,
    last_resort: bool,
) -> Result<Vec<mls::KeyPackage>, E2eeError> {
    let provider = dev.provider(tx.mls_storage());
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let bundle = risala_mls::key_package(&provider, &dev.signer(), &dev.uid, last_resort)
            .map_err(mls)?;
        out.push(wire::key_package_to_wire(bundle.key_package()).map_err(mls)?);
    }
    Ok(out)
}

/// Reads a KeyPackage from KEYPKG GET for `uid`'s device (12.4), with the
/// checks a server makes on upload, against the key it carries.
pub(crate) fn checked_key_package(
    dev: &Device,
    uid: &Uid,
    value: &mls::KeyPackage,
) -> Result<(KeyPackage, PublicKey), E2eeError> {
    let unchecked = wire::key_package_from_wire(value).map_err(mls)?;
    let key = signature_key(unchecked.unverified_credential().signature_key.as_slice())
        .ok_or_else(|| E2eeError::Malformed("a KeyPackage's key".into()))?;
    let checked = check_key_package(&*dev.crypto, value, uid, &key, SystemTime::now())
        .map_err(|e| E2eeError::Malformed(e.to_string()))?;
    Ok((checked.key_package, key))
}

// ---------------------------------------------------------------------------
// Entering epochs (12.9)

/// Records that the device is in `group`'s current epoch, which the
/// COMMIT event at `commit_seq` started (0 for epoch 0): its history key
/// (12.9), its leaves (12.8, step 4) and the room's `send` value (12.11).
/// A history key is derived before the next commit is applied, as 12.9
/// requires, by doing this as soon as the device enters an epoch.
fn enter_epoch(
    tx: &mut Tx<'_>,
    dev: &Device,
    row: &ConvRow,
    group: &MlsGroup,
    commit_seq: u64,
    state: GroupState,
    refreshed: i64,
) -> Result<(), E2eeError> {
    let conv_id = row
        .conv_id
        .clone()
        .ok_or(E2eeError::Rejected("the conversation's id is not known"))?;
    let epoch = group.epoch().as_u64();
    let key = HistoryKey::of_group(group, &*dev.crypto).map_err(mls)?;
    let leaves: Vec<(Uid, PublicKey)> =
        leaves(group)?.into_iter().map(|l| (l.uid, l.key)).collect();
    tx.put_history_key(
        row.account,
        &conv_id,
        epoch,
        &key,
        KeySource::Own,
        Some(commit_seq),
        send_mode(group),
    )?;
    tx.put_epoch_leaves(row.account, &conv_id, epoch, &leaves)?;
    tx.save_group(&GroupRow {
        conv: row.id,
        group_id: group.group_id().as_slice().to_vec(),
        epoch,
        commit_seq,
        state,
        pending: None,
        refreshed,
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// INIT (12.5)

/// What INIT sends: the GroupInfo of epoch 0 and the ratchet tree.
#[derive(Debug, Clone)]
pub(crate) struct Init {
    pub group_info: mls::GroupInfo,
    pub tree: mls::RatchetTree,
}

/// Creates the group of `row` for INIT (12.5), with this device alone in
/// it, and records it as waiting for INIT's answer. A group the
/// conversation had that is not active is forgotten first.
pub(crate) fn create(
    tx: &mut Tx<'_>,
    dev: &Device,
    row: &ConvRow,
    conversation: &RisalaConversation,
    now_ms: i64,
) -> Result<Init, E2eeError> {
    if let Some(old) = tx.group(row.id)? {
        match old.state {
            GroupState::Active => {
                return Err(E2eeError::Rejected("the conversation has a group"));
            }
            // 12.6: a rejection is undone only by the user (reset).
            GroupState::Rejected => {
                return Err(E2eeError::Rejected("the device rejected this group"));
            }
            _ => tx.forget_group(row.id)?,
        }
    }
    let (group_id, init) = {
        let provider = dev.provider(tx.mls_storage());
        let group = risala_mls::create_group(&provider, &dev.signer(), &dev.uid, conversation)
            .map_err(mls)?;
        let info = group
            .export_group_info(&*dev.crypto, &dev.signer(), false)
            .map_err(mls)?;
        let init = Init {
            group_info: wire::group_info_to_wire(&info).map_err(mls)?,
            tree: wire::tree_to_wire(&group.export_ratchet_tree()).map_err(mls)?,
        };
        (group.group_id().as_slice().to_vec(), init)
    };
    tx.save_group(&GroupRow {
        conv: row.id,
        group_id,
        epoch: 0,
        commit_seq: 0,
        state: GroupState::Init,
        pending: None,
        refreshed: now_ms,
    })?;
    Ok(init)
}

/// INIT was accepted (12.5): the group is the conversation's. `row` has
/// the id INIT's answer gave.
pub(crate) fn init_accepted(tx: &mut Tx<'_>, dev: &Device, row: &ConvRow) -> Result<(), E2eeError> {
    let Some(g) = tx.group(row.id)? else {
        return Ok(());
    };
    if g.state != GroupState::Init || g.pending.is_some() {
        return Ok(());
    }
    let group = load(tx, &g.group_id)?;
    enter_epoch(tx, dev, row, &group, 0, GroupState::Active, g.refreshed)
}

/// INIT, or an external commit, was refused: forget the group, if it was
/// still waiting for the answer.
pub(crate) fn abandon(tx: &mut Tx<'_>, row: &ConvRow) -> Result<(), E2eeError> {
    if tx
        .group(row.id)?
        .is_some_and(|g| g.state == GroupState::Init)
    {
        tx.forget_group(row.id)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Commits (12.5, 12.6)

/// What applying a COMMIT event did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Applied {
    /// It moved the group to its epoch.
    Merged {
        /// The new epoch.
        epoch: u64,
        /// It was this device's own commit.
        own: bool,
        /// Leaves it added, for the key check (12.6): every leaf, for the
        /// device's own external commit.
        added: Vec<(Uid, PublicKey)>,
        /// It removed a leaf for a reason only a key file that could not be
        /// fetched for 24 hours would show (12.6). Warn the user.
        unchecked: bool,
    },
    /// The device is not in the group any more.
    Removed,
    /// It is for an epoch the group has passed: nothing to do.
    Old,
    /// It is for a later epoch than the next: commits are missing.
    Ahead,
}

/// Facts about the conversation for the checks of 12.6 that MLS does not
/// make.
struct Checks<'a> {
    me: &'a Uid,
    row: &'a ConvRow,
    /// Identities whose key files were fetched for this commit.
    fresh: &'a HashSet<Uid>,
    /// The commit waited 24 hours for key files that could not be fetched:
    /// a removal only they could explain is applied (12.6).
    unchecked: bool,
}

impl Checks<'_> {
    /// Why a leaf of `uid` with `key` may be removed by `committer`
    /// (12.6), or `Err(KeyFiles)` if only the key file can tell. A key
    /// file the device fetched before the commit may be out of date, so
    /// only one fetched for it says that a key is still listed.
    fn removal(
        &self,
        tx: &Tx<'_>,
        committer: &Uid,
        uid: &Uid,
        key: &PublicKey,
        re_added: &HashSet<Vec<u8>>,
    ) -> Result<bool, E2eeError> {
        if uid == committer || re_added.contains(&key.as_bytes()[..]) {
            return Ok(true);
        }
        if self.row.name.is_room() && tx.left_room(self.row.id, uid)? {
            return Ok(true);
        }
        match tx.key_listed(self.row.account, uid, key)? {
            Some(false) => Ok(true),
            _ if self.fresh.contains(uid) => Ok(false),
            _ => Err(E2eeError::KeyFiles(vec![uid.clone()])),
        }
    }
}

/// The extensions of a group context other than the conversation
/// extension, and the conversation extension.
fn split_extensions(
    extensions: &risala_mls::openmls::prelude::Extensions<
        risala_mls::openmls::prelude::GroupContext,
    >,
) -> (Vec<Extension>, Option<RisalaConversation>) {
    let others = extensions
        .iter()
        .filter(|e| {
            !matches!(e, Extension::Unknown(t, _) if *t == risala_proto::mls::CONVERSATION_EXTENSION_TYPE)
        })
        .cloned()
        .collect();
    (others, RisalaConversation::from_extensions(extensions).ok())
}

/// The checks of 12.6 on a staged commit from `sender`, in `group` as it
/// is before the commit. They need none of the group's secrets, so they
/// are made on the commit as the group's public part stages it, before
/// MLS processes it: a commit that fails them is rejected even if MLS
/// would refuse it too.
fn check_commit(
    tx: &Tx<'_>,
    checks: &Checks<'_>,
    group: &MlsGroup,
    sender: &Sender,
    committer_credential: &Credential,
    staged: &StagedCommit,
) -> Result<(Vec<(Uid, PublicKey)>, bool), E2eeError> {
    let before = leaves(group)?;
    let committer: Uid = credential_uid(committer_credential)
        .and_then(|u| u.parse().ok())
        .ok_or(E2eeError::Rejected("the committer is not an identity"))?;
    let external = matches!(sender, Sender::NewMemberCommit);

    // The committer's leaf keeps its credential and key (12.2).
    let path = staged
        .update_path_leaf_node()
        .map(|leaf| leaf_of(leaf.credential(), leaf.signature_key().as_slice()))
        .map(|l| {
            l.ok_or(E2eeError::Rejected(
                "a path leaf that is not an identity's device",
            ))
        })
        .transpose()?;
    let joiner_key = match (sender, &path) {
        (Sender::Member(i), path) => {
            let leaf = before
                .iter()
                .find(|l| l.index == *i)
                .ok_or(E2eeError::Rejected("the committer has no leaf"))?;
            if leaf.uid != committer {
                return Err(E2eeError::Rejected("the committer's credential changed"));
            }
            if let Some((uid, key)) = path
                && (*uid != leaf.uid || *key != leaf.key)
            {
                return Err(E2eeError::Rejected("a path changes the committer's leaf"));
            }
            None
        }
        (Sender::NewMemberCommit, Some((uid, key))) => {
            if *uid != committer {
                return Err(E2eeError::Rejected(
                    "the joiner's credential is not its leaf's",
                ));
            }
            Some(key.clone())
        }
        _ => return Err(E2eeError::Rejected("a commit from no member")),
    };

    // An external commit by an identity with no leaf, except a direct
    // conversation's participant.
    if external && checks.row.name.is_room() && !before.iter().any(|l| l.uid == committer) {
        return Err(E2eeError::Rejected("an external commit by an outsider"));
    }

    // Only `history` and `send` may change.
    let (old_rest, old_conv) = split_extensions(group.extensions());
    let (new_rest, new_conv) = split_extensions(staged.group_context().extensions());
    match (&old_conv, &new_conv) {
        (Some(old), Some(new)) if old.same_conversation(new) && old_rest == new_rest => {
            if old != new && old.kind == ConversationKind::Direct {
                return Err(E2eeError::Rejected(
                    "a direct conversation's settings changed",
                ));
            }
        }
        _ => return Err(E2eeError::Rejected("the group's extensions changed")),
    }

    let mut added = Vec::new();
    let mut re_added = HashSet::new();
    for add in staged.add_proposals() {
        let leaf = add.add_proposal().key_package().leaf_node();
        let (uid, key) = leaf_of(leaf.credential(), leaf.signature_key().as_slice()).ok_or(
            E2eeError::Rejected("an added leaf that is not an identity's device"),
        )?;
        // 12.4: the lifetime of a KeyPackage a commit adds.
        if !risala_mls::lifetime_acceptable(
            add.add_proposal().key_package().life_time(),
            SystemTime::now(),
        ) {
            return Err(E2eeError::Rejected("an added KeyPackage's lifetime"));
        }
        re_added.insert(key.as_bytes().to_vec());
        added.push((uid, key));
    }
    if let Some(path) = path {
        added.push(path);
    }
    // A direct conversation gains no outsider, whether a commit adds the
    // leaf or an external commit's path brings it (12.6).
    if let Conv::Uid(other) = &checks.row.name
        && added
            .iter()
            .any(|(uid, _)| uid != checks.me && uid != other)
    {
        return Err(E2eeError::Rejected(
            "a direct conversation gains an outsider",
        ));
    }

    let mut need = Vec::new();
    let mut unchecked = false;
    for remove in staged.remove_proposals() {
        let index = remove.remove_proposal().removed();
        let Some(leaf) = before.iter().find(|l| l.index == index) else {
            return Err(E2eeError::Rejected("a removal of no leaf"));
        };
        if external {
            if Some(&leaf.key) != joiner_key.as_ref() {
                return Err(E2eeError::Rejected(
                    "an external commit removes another leaf",
                ));
            }
            continue;
        }
        match checks.removal(tx, &committer, &leaf.uid, &leaf.key, &re_added) {
            Ok(true) => {}
            Ok(false) => return Err(E2eeError::Rejected("a removal for no reason")),
            Err(E2eeError::KeyFiles(_)) if checks.unchecked => unchecked = true,
            Err(E2eeError::KeyFiles(uids)) => need.extend(uids),
            Err(e) => return Err(e),
        }
    }
    if !need.is_empty() {
        return Err(E2eeError::KeyFiles(need));
    }
    for proposal in staged.queued_proposals() {
        match proposal.proposal() {
            Proposal::Add(_)
            | Proposal::Remove(_)
            | Proposal::GroupContextExtensions(_)
            | Proposal::ExternalInit(_) => {}
            _ => {
                return Err(E2eeError::Rejected(
                    "a proposal of a kind risala does not use",
                ));
            }
        }
    }
    Ok((added, unchecked))
}

/// Applies the COMMIT event at `seq`, which starts `epoch` (12.5, 12.6),
/// with every check of 12.6. Commits are applied in seq order.
///
/// - A commit for an epoch the group has passed is [`Applied::Old`]; one
///   past the next is [`Applied::Ahead`].
/// - This device's own commit, sent and not answered yet, is merged.
/// - [`E2eeError::Rejected`]: it fails a check of 12.6. The caller marks
///   the group rejected, in a transaction of its own.
/// - [`E2eeError::Mls`]: MLS refused it. The caller marks the group
///   broken, and may join again by external commit.
/// - [`E2eeError::KeyFiles`]: a removal can be checked only against key
///   files fetched for it. `fresh` are the identities whose key files
///   were. With `unchecked`, the commit waited 24 hours for them, and such
///   a removal is applied.
pub(crate) fn apply_commit(
    tx: &mut Tx<'_>,
    dev: &Device,
    row: &ConvRow,
    (seq, epoch): (u64, u64),
    commit: &mls::CommitMessage,
    (fresh, unchecked): (&HashSet<Uid>, bool),
) -> Result<Applied, E2eeError> {
    let Some(g) = tx.group(row.id)? else {
        return Ok(Applied::Old);
    };
    match g.state {
        GroupState::Active => {}
        // An external commit of this device's, waiting for its answer.
        GroupState::Init if g.pending.as_deref() == Some(commit.as_str()) => {
            let group = load(tx, &g.group_id)?;
            if group.epoch().as_u64() != epoch {
                return Err(E2eeError::Mls("the external commit's epoch".into()));
            }
            enter_epoch(tx, dev, row, &group, seq, GroupState::Active, now_ms())?;
            // Every leaf of a group joined this way gets the key check
            // (12.6).
            let all = leaves(&group)?
                .into_iter()
                .map(|l| (l.uid, l.key))
                .collect();
            return Ok(Applied::Merged {
                epoch,
                own: true,
                added: all,
                unchecked: false,
            });
        }
        _ => return Ok(Applied::Old),
    }
    if epoch <= g.epoch {
        return Ok(Applied::Old);
    }
    if epoch > g.epoch + 1 {
        return Ok(Applied::Ahead);
    }
    let mut group = load(tx, &g.group_id)?;
    if g.pending.as_deref() == Some(commit.as_str()) {
        // This device's own commit (12.5).
        {
            let provider = dev.provider(tx.mls_storage());
            group.merge_pending_commit(&provider).map_err(mls)?;
        }
        let refreshed = now_ms();
        enter_epoch(tx, dev, row, &group, seq, GroupState::Active, refreshed)?;
        return Ok(Applied::Merged {
            epoch,
            own: true,
            added: Vec::new(),
            unchecked: false,
        });
    }
    let message = || wire::commit_from_wire(commit).map_err(|e| E2eeError::Mls(e.to_string()));
    // 12.6 first, on what the commit shows without the group's secrets,
    // so that one that fails the checks is rejected, never merely refused
    // by MLS (which would let the device join again).
    let (added, unchecked) = {
        let processed = group
            .public_group()
            .process_message(&*dev.crypto, message()?)
            .map_err(mls)?;
        let sender = processed.sender().clone();
        let credential = processed.credential().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(E2eeError::Mls("the COMMIT event holds no commit".into()));
        };
        let checks = Checks {
            me: &dev.uid,
            row,
            fresh,
            unchecked,
        };
        check_commit(tx, &checks, &group, &sender, &credential, &staged)?
    };
    let removed = {
        let provider = dev.provider(tx.mls_storage());
        if g.pending.is_some() {
            // Another commit came first: this device's own will be
            // refused as stale (12.5).
            group
                .clear_pending_commit(provider.storage())
                .map_err(mls)?;
        }
        let processed = group.process_message(&provider, message()?).map_err(mls)?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(E2eeError::Mls("the COMMIT event holds no commit".into()));
        };
        let removed = staged.self_removed();
        group.merge_staged_commit(&provider, *staged).map_err(mls)?;
        removed
    };
    if removed {
        let mut left = g.clone();
        left.state = GroupState::Left;
        left.pending = None;
        tx.delete_mls_state(&g.group_id)?;
        tx.save_group(&left)?;
        return Ok(Applied::Removed);
    }
    if group.epoch().as_u64() != epoch {
        return Err(E2eeError::Mls(
            "the commit's epoch is not the event's".into(),
        ));
    }
    enter_epoch(tx, dev, row, &group, seq, GroupState::Active, g.refreshed)?;
    Ok(Applied::Merged {
        epoch,
        own: false,
        added,
        unchecked,
    })
}

/// Forgets a group the device rejected, so that it may join or start the
/// conversation's group again: only on the user's word (12.6). Returns
/// whether there was one.
pub(crate) fn reset_rejected(tx: &mut Tx<'_>, row: &ConvRow) -> Result<bool, E2eeError> {
    if tx
        .group(row.id)?
        .is_some_and(|g| g.state == GroupState::Rejected)
    {
        tx.forget_group(row.id)?;
        return Ok(true);
    }
    Ok(false)
}

/// Marks the group `state` after a commit it could not follow (12.6), and
/// drops a commit of its own that was waiting.
pub(crate) fn mark(tx: &mut Tx<'_>, row: &ConvRow, state: GroupState) -> Result<(), E2eeError> {
    if let Some(mut g) = tx.group(row.id)? {
        g.state = state;
        g.pending = None;
        tx.save_group(&g)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// This device's commits

/// What COMMIT sends (12.5).
#[derive(Debug, Clone)]
pub(crate) struct Commit {
    pub commit: mls::CommitMessage,
    pub group_info: mls::GroupInfo,
    pub welcome: Option<mls::Welcome>,
}

/// Makes a commit of `changes` and records it as waiting for its answer
/// (12.5). It is merged when its COMMIT event comes back
/// ([`apply_commit`]), and dropped if the server refuses it
/// ([`commit_refused`]).
pub(crate) fn own_commit(
    tx: &mut Tx<'_>,
    dev: &Device,
    row: &ConvRow,
    changes: Changes,
) -> Result<Commit, E2eeError> {
    let Some(mut g) = tx.group(row.id)? else {
        return Err(E2eeError::Rejected("no group"));
    };
    if g.state != GroupState::Active || g.pending.is_some() {
        return Err(E2eeError::Rejected("the group is not ready for a commit"));
    }
    let mut group = load(tx, &g.group_id)?;
    let out = {
        let provider = dev.provider(tx.mls_storage());
        let bundle =
            risala_mls::commit(&provider, &mut group, &dev.signer(), changes).map_err(mls)?;
        let (commit, welcome, info) = bundle.into_messages();
        Commit {
            commit: wire::commit_to_wire(&commit).map_err(mls)?,
            group_info: wire::group_info_to_wire(
                &info.ok_or_else(|| E2eeError::Mls("a commit without a GroupInfo".into()))?,
            )
            .map_err(mls)?,
            welcome: welcome
                .map(|w| wire::welcome_to_wire(&w))
                .transpose()
                .map_err(mls)?,
        }
    };
    g.pending = Some(out.commit.as_str().to_owned());
    tx.save_group(&g)?;
    Ok(out)
}

/// The server refused this device's commit, or it never got there: drop
/// it (12.5). A commit whose event was applied already is not waiting any
/// more, and stays.
pub(crate) fn commit_refused(
    tx: &mut Tx<'_>,
    dev: &Device,
    row: &ConvRow,
    commit: &mls::CommitMessage,
) -> Result<(), E2eeError> {
    let Some(mut g) = tx.group(row.id)? else {
        return Ok(());
    };
    if g.pending.as_deref() != Some(commit.as_str()) {
        return Ok(());
    }
    if g.state == GroupState::Init {
        // An external commit: the group was never joined.
        tx.forget_group(row.id)?;
        return Ok(());
    }
    let mut group = load(tx, &g.group_id)?;
    {
        let provider = dev.provider(tx.mls_storage());
        group
            .clear_pending_commit(provider.storage())
            .map_err(mls)?;
    }
    g.pending = None;
    tx.save_group(&g)?;
    Ok(())
}

/// The `history` setting of the conversation's active group (12.9).
pub(crate) fn history_mode(
    tx: &Tx<'_>,
    row: &ConvRow,
) -> Result<Option<risala_proto::types::HistoryMode>, E2eeError> {
    let Some(g) = tx.group(row.id)? else {
        return Ok(None);
    };
    if g.state != GroupState::Active {
        return Ok(None);
    }
    Ok(
        RisalaConversation::from_extensions(load(tx, &g.group_id)?.extensions())
            .ok()
            .map(|c| c.history),
    )
}

/// The current leaves of the conversation's group, if it has an active one.
pub(crate) fn current_leaves(tx: &Tx<'_>, row: &ConvRow) -> Result<Option<Vec<Leaf>>, E2eeError> {
    let Some(g) = tx.group(row.id)? else {
        return Ok(None);
    };
    if g.state != GroupState::Active {
        return Ok(None);
    }
    Ok(Some(leaves(&load(tx, &g.group_id)?)?))
}

// ---------------------------------------------------------------------------
// Joining (12.6, 12.7)

/// What processing a Welcome did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Joined {
    /// The device joined the group in the epoch the COMMIT event at the
    /// Welcome's seq started. Its leaves are returned for the key check.
    Joined {
        epoch: u64,
        leaves: Vec<(Uid, PublicKey)>,
    },
    /// The device is in the group already, at or past that commit.
    Already,
}

/// Joins a group by Welcome (12.7), after the checks of 12.6. The COMMIT
/// event that added the device is at `seq`. Run it in a transaction of
/// its own: if it fails, the KeyPackage's private keys must be kept.
pub(crate) fn join_welcome(
    tx: &mut Tx<'_>,
    dev: &Device,
    row: &ConvRow,
    welcome: &mls::Welcome,
    tree: &mls::RatchetTree,
    seq: u64,
) -> Result<Joined, E2eeError> {
    if let Some(g) = tx.group(row.id)? {
        if g.state == GroupState::Active && g.commit_seq >= seq {
            return Ok(Joined::Already);
        }
        // 12.6: joining another group would undo the rejection.
        if g.state == GroupState::Rejected {
            return Err(E2eeError::Rejected("the device rejected this group"));
        }
    }
    let welcome =
        wire::welcome_from_wire(welcome).map_err(|e| E2eeError::Malformed(e.to_string()))?;
    let tree = wire::tree_from_wire(tree).map_err(|e| E2eeError::Malformed(e.to_string()))?;
    let group = {
        let provider = dev.provider(tx.mls_storage());
        let staged = risala_mls::stage_welcome(&provider, welcome, tree).map_err(mls)?;
        let conversation = RisalaConversation::from_extensions(staged.group_context().extensions())
            .map_err(|_| E2eeError::Rejected("the group has no conversation extension"))?;
        let leaves: Vec<Leaf> = staged
            .members()
            .map(|m| {
                leaf_of(&m.credential, &m.signature_key)
                    .map(|(uid, key)| Leaf {
                        index: m.index,
                        uid,
                        key,
                    })
                    .ok_or(E2eeError::Rejected(
                        "a leaf that is not an identity's device",
                    ))
            })
            .collect::<Result<_, _>>()?;
        check_joining(tx, &dev.uid, row, &conversation, &leaves, (seq, None))?;
        staged.into_group(&provider).map_err(mls)?
    };
    // An earlier group of the conversation, not followed any more, goes.
    if let Some(old) = tx.group(row.id)?
        && old.group_id != group.group_id().as_slice()
    {
        tx.delete_mls_state(&old.group_id)?;
    }
    let epoch = group.epoch().as_u64();
    let all = leaves(&group)?
        .into_iter()
        .map(|l| (l.uid, l.key))
        .collect();
    enter_epoch(tx, dev, row, &group, seq, GroupState::Active, now_ms())?;
    Ok(Joined::Joined { epoch, leaves: all })
}

/// Makes an external commit to join the conversation's group (12.6), from
/// GROUPINFO's GroupInfo and tree, after the checks of joining as of `at`,
/// the seq of the COMMIT event that started the GroupInfo's epoch. The group
/// waits for the commit's answer: it is the device's once its COMMIT event
/// comes back ([`apply_commit`]), and is forgotten if the server refuses it
/// ([`commit_refused`]).
pub(crate) fn external_join(
    tx: &mut Tx<'_>,
    dev: &Device,
    row: &ConvRow,
    (group_info, tree, at): (&mls::GroupInfo, &mls::RatchetTree, u64),
) -> Result<Commit, E2eeError> {
    if let Some(old) = tx.group(row.id)? {
        if matches!(old.state, GroupState::Active | GroupState::Rejected) {
            return Err(E2eeError::Rejected(
                "the device may not join this group again",
            ));
        }
        tx.forget_group(row.id)?;
    }
    let info =
        wire::group_info_from_wire(group_info).map_err(|e| E2eeError::Malformed(e.to_string()))?;
    let tree = wire::tree_from_wire(tree).map_err(|e| E2eeError::Malformed(e.to_string()))?;
    let (group, out) = {
        let provider = dev.provider(tx.mls_storage());
        let (group, bundle) =
            risala_mls::join_by_external_commit(&provider, &dev.signer(), &dev.uid, info, tree)
                .map_err(mls)?;
        let conversation = RisalaConversation::from_extensions(group.extensions())
            .map_err(|_| E2eeError::Rejected("the group has no conversation extension"))?;
        let own = dev.key.public_key();
        check_joining(
            tx,
            &dev.uid,
            row,
            &conversation,
            &leaves(&group)?,
            (at, Some(&own)),
        )?;
        let (commit, _, info) = bundle.into_messages();
        let out = Commit {
            commit: wire::commit_to_wire(&commit).map_err(mls)?,
            group_info: wire::group_info_to_wire(
                &info.ok_or_else(|| E2eeError::Mls("a commit without a GroupInfo".into()))?,
            )
            .map_err(mls)?,
            welcome: None,
        };
        (group, out)
    };
    tx.save_group(&GroupRow {
        conv: row.id,
        group_id: group.group_id().as_slice().to_vec(),
        epoch: group.epoch().as_u64(),
        commit_seq: 0,
        state: GroupState::Init,
        pending: Some(out.commit.as_str().to_owned()),
        refreshed: now_ms(),
    })?;
    Ok(out)
}

/// The time now, in Unix milliseconds.
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

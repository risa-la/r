//! The checks devices make of every group they join and every commit
//! they apply (12.7, 6.1-6.4), and that a server makes of a public room's
//! commits as far as the public state allows (12.6).
//!
//! The checks are pure functions over a [`GroupView`], the group as of the
//! epoch a commit is for, and a [`CommitView`], what the commit does. Both
//! are read from OpenMLS's types ([`GroupView::of`], [`CommitView::of`]),
//! by a member's [`MlsGroup`](openmls::group::MlsGroup) or a server's
//! [`PublicGroup`]. Facts from key files and the key log come through
//! [`KeyFacts`], which may not know yet (12.7): a removal it cannot check
//! stands, and an add it cannot check leaves the added leaf unconfirmed.
//!
//! Every check depends only on the group, the commit and facts that never
//! go away, so every device that sees the same commits picks the same
//! winner (7.2). The one exception is the lifetime of added KeyPackages,
//! which 12.5 checks against the current time; see [`check_commit`].

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use openmls::group::{QueuedProposal, StagedCommit};
use openmls::prelude::{
    KeyPackage, LeafNode, LeafNodeIndex, Proposal, ProposalOrRefType, PublicGroup, Sender,
};
use openmls::treesync::LeafNodeSource;
use risala_proto::names::{Room, Uid};

use crate::binding::DeviceBinding;
use crate::conversation::{
    ConfirmMode, ConversationError, ConversationKind, GuestMode, RisalaConversation, Role,
};
use crate::identity::{DeviceId, RisalaIdentity};
use crate::keypackage::{
    KeyPackageError, check_binding, check_guest_key_package, check_key_package_contents,
    encryption_key_bytes,
};
use crate::profile::RisalaProfile;

/// The most identities in a private room (6.1).
pub const MAX_PRIVATE_IDENTITIES: usize = 1_000;
/// The most leaves in a private room (6.1).
pub const MAX_PRIVATE_LEAVES: usize = 4_096;
/// The most identities, guests included, in a public room (6.1).
pub const MAX_PUBLIC_IDENTITIES: usize = 10_000;
/// The most leaves in a public room (6.1).
pub const MAX_PUBLIC_LEAVES: usize = 32_768;
/// The most members a private room may have while it is `pairwise`
/// (6.2, 12.10).
pub const MAX_PAIRWISE_MEMBERS: usize = 256;
/// How much older than the committer's own leaf a leaf's `updated` must
/// be for anyone to remove it as stale: 35 days, in ms (12.7).
pub const STALE_AFTER_MS: u64 = 35 * 24 * 60 * 60 * 1000;
/// How long a device may go without committing its own leaf in a group:
/// a week, in ms (12.7).
pub const REFRESH_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// A period of epochal confirmation, a UTC day, in ms (12.10).
pub const PERIOD_MS: u64 = 24 * 60 * 60 * 1000;

/// Whether a fact from a key file or the key log is known yet (12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact<T> {
    /// It is known.
    Known(T),
    /// It could not be fetched right now (4.4). Check again later.
    Unknown,
}

/// What the checks need from key files and the key log (4.4, 4.5). The
/// caller fetches and caches them.
pub trait KeyFacts {
    /// The raw device key of `uid`'s device `device_id`, if that device is
    /// current in `uid`'s key file and its record is in the key log (4.5):
    /// `Known(Some(key))`, or `Known(None)` if it is not.
    fn current_device_key(&self, uid: &Uid, device_id: &DeviceId) -> Fact<Option<Vec<u8>>>;

    /// Whether `uid`'s key file has removed the device `device_id` (4.4).
    fn device_removed(&self, uid: &Uid, device_id: &DeviceId) -> Fact<bool>;
}

/// One leaf of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafView {
    /// Its index.
    pub index: LeafNodeIndex,
    /// Its credential, or `None` if it is not a RisalaIdentity.
    pub identity: Option<RisalaIdentity>,
    /// Its profile, if it has a well-formed one.
    pub profile: Option<RisalaProfile>,
    /// Its signature key.
    pub signature_key: Vec<u8>,
    /// Whether it has not committed since it was added: it still holds the
    /// leaf node of its KeyPackage.
    pub from_key_package: bool,
}

impl LeafView {
    /// Reads a leaf node.
    pub fn of(index: LeafNodeIndex, leaf: &LeafNode) -> LeafView {
        LeafView {
            index,
            identity: RisalaIdentity::from_credential(leaf.credential()).ok(),
            profile: RisalaProfile::of_leaf(leaf),
            signature_key: leaf.signature_key().as_slice().to_vec(),
            from_key_package: matches!(leaf.leaf_node_source(), LeafNodeSource::KeyPackage(_)),
        }
    }

    fn uid(&self) -> Option<&Uid> {
        self.identity.as_ref().map(|identity| &identity.uid)
    }
}

/// A group as of one epoch: its conversation extension and its leaves.
#[derive(Debug, Clone)]
pub struct GroupView {
    /// The conversation extension, or why it is not acceptable.
    pub conversation: Result<RisalaConversation, ConversationError>,
    /// The leaves, in index order.
    pub leaves: Vec<LeafView>,
}

impl GroupView {
    /// Reads a group's public state.
    pub fn of(group: &PublicGroup) -> GroupView {
        let leaves = group
            .members()
            .filter_map(|member| {
                group
                    .leaf(member.index)
                    .map(|leaf| LeafView::of(member.index, leaf))
            })
            .collect();
        GroupView {
            conversation: RisalaConversation::from_extensions(group.group_context().extensions()),
            leaves,
        }
    }

    /// The leaf at `index`.
    pub fn leaf(&self, index: LeafNodeIndex) -> Option<&LeafView> {
        self.leaves.iter().find(|leaf| leaf.index == index)
    }

    /// The leaves of `uid`.
    pub fn leaves_of<'a>(&'a self, uid: &'a Uid) -> impl Iterator<Item = &'a LeafView> + 'a {
        self.leaves.iter().filter(move |leaf| leaf.uid() == Some(uid))
    }

    /// The leaves whose profile's `updated` is more than 35 days older than
    /// `own_updated`, which any member may remove (12.7).
    pub fn stale_leaves(&self, own_updated: u64) -> Vec<LeafNodeIndex> {
        self.leaves
            .iter()
            .filter(|leaf| {
                leaf.profile
                    .as_ref()
                    .is_some_and(|profile| is_stale(profile.updated, own_updated))
            })
            .map(|leaf| leaf.index)
            .collect()
    }
}

fn is_stale(updated: u64, own_updated: u64) -> bool {
    own_updated.saturating_sub(updated) > STALE_AFTER_MS
}

/// Whether the device should commit a fresh leaf now: its own leaf's
/// profile says it last committed more than a week ago, by `now_ms` (12.7).
/// A leaf that has not committed since it joined counts from its
/// KeyPackage's profile.
pub fn needs_refresh(own_profile: &RisalaProfile, now_ms: u64) -> bool {
    now_ms.saturating_sub(own_profile.updated) > REFRESH_AFTER_MS
}

/// Why a group fails the checks of joining (12.7). The device MUST NOT
/// join it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JoinError {
    /// The conversation extension is missing or not well formed.
    #[error(transparent)]
    Conversation(#[from] ConversationError),
    /// It names another server, or another room or box than expected.
    #[error("the group is not the conversation expected")]
    WrongConversation,
    /// A leaf's credential is not a RisalaIdentity, or a device's leaf has
    /// no profile.
    #[error("a leaf without a RisalaIdentity or a profile")]
    Leaf,
    /// A leaf of a direct conversation belongs to someone else.
    #[error("a leaf of a direct conversation belongs to someone else")]
    NotAParticipant,
    /// A leaf belongs to a banned identity.
    #[error("a leaf of a banned identity")]
    Banned,
    /// A guest leaf where guests may not be.
    #[error("a guest leaf where guests may not be")]
    Guest,
    /// The group is over its size limits.
    #[error("the group is over its size limits")]
    TooLarge,
}

/// What the joining device expects of a group (12.7).
#[derive(Debug, Clone)]
pub struct JoinExpectation {
    /// The server the device is joining on.
    pub host: String,
    /// The device's own uid.
    pub own_uid: Uid,
    /// For a public room joined by name, its name and box.
    pub public_room: Option<(Room, [u8; 16])>,
}

/// Checks a group the device is about to join, by Welcome or by external
/// commit (12.7). Leaves it cannot confirm yet are allowed.
pub fn check_join(group: &GroupView, expect: &JoinExpectation) -> Result<(), JoinError> {
    let conversation = group.conversation.clone()?;
    if conversation.host != expect.host.to_ascii_lowercase() {
        return Err(JoinError::WrongConversation);
    }
    if let Some((room, mailbox)) = &expect.public_room
        && (conversation.kind != ConversationKind::PublicRoom
            || conversation.name != room.as_str()
            || conversation.mailbox != *mailbox)
    {
        return Err(JoinError::WrongConversation);
    }
    let participants = conversation.direct_participants();
    if let Some(participants) = &participants
        && !participants.contains(&expect.own_uid)
    {
        return Err(JoinError::NotAParticipant);
    }
    for leaf in &group.leaves {
        let identity = leaf.identity.as_ref().ok_or(JoinError::Leaf)?;
        if !identity.is_guest() && leaf.profile.is_none() {
            return Err(JoinError::Leaf);
        }
        if conversation.is_banned(&identity.uid) {
            return Err(JoinError::Banned);
        }
        match &participants {
            Some(participants) => {
                // A guest may be a participant of a direct conversation, to
                // report (4.2, 5.8), although 12.7 allows guest leaves only
                // in public rooms; see the report of task M1.
                if !participants.contains(&identity.uid) {
                    return Err(JoinError::NotAParticipant);
                }
            }
            None => {
                if identity.is_guest()
                    && (conversation.kind != ConversationKind::PublicRoom
                        || conversation.guests == GuestMode::None)
                {
                    return Err(JoinError::Guest);
                }
            }
        }
    }
    if !within_limits(&conversation, group.leaves.iter().filter_map(LeafView::uid)) {
        return Err(JoinError::TooLarge);
    }
    Ok(())
}

/// Whether a group of these leaves' uids is within the limits of 6.1.
/// Direct conversations have no limits of their own in 6.1: they get a
/// private room's (see the report of task M1).
fn within_limits<'a>(
    conversation: &RisalaConversation,
    uids: impl Iterator<Item = &'a Uid>,
) -> bool {
    let mut leaves = 0;
    let mut identities = BTreeSet::new();
    for uid in uids {
        leaves += 1;
        identities.insert(uid);
    }
    let (max_identities, max_leaves) = match conversation.kind {
        ConversationKind::PublicRoom => (MAX_PUBLIC_IDENTITIES, MAX_PUBLIC_LEAVES),
        _ => (MAX_PRIVATE_IDENTITIES, MAX_PRIVATE_LEAVES),
    };
    identities.len() <= max_identities && leaves <= max_leaves
}

/// Who made a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Committer {
    /// A member, by its leaf index as of the commit's epoch.
    Member(LeafNodeIndex),
    /// A new member, by external commit.
    External,
}

/// A proposal in a commit.
#[derive(Debug, Clone)]
pub enum ProposalView {
    /// An Add, by value from a member, or by reference from an external
    /// Add proposal (`by_external_proposal`).
    Add {
        /// The KeyPackage.
        key_package: Box<KeyPackage>,
        /// Whether it came by reference from a `new_member_proposal`.
        by_external_proposal: bool,
    },
    /// A Remove of a leaf, by value.
    Remove(LeafNodeIndex),
    /// A SelfRemove of its sender's leaf, by reference.
    SelfRemove(LeafNodeIndex),
    /// A GroupContextExtensions proposal, by value.
    GroupContextExtensions,
    /// An ExternalInit, in an external commit.
    ExternalInit,
    /// Anything else, or one of the above sent the wrong way (by value or
    /// by reference): never allowed (12.6).
    NotAllowed(&'static str),
}

/// What a commit does, as the checks need it.
#[derive(Debug, Clone)]
pub struct CommitView {
    /// Who made it.
    pub committer: Committer,
    /// Its proposals.
    pub proposals: Vec<ProposalView>,
    /// The committer's new leaf from the commit's path, or `None` if it has
    /// no path.
    pub path_leaf: Option<LeafView>,
    /// The device binding of the path leaf, which an external commit's
    /// leaf carries (12.3).
    pub path_binding: Option<DeviceBinding>,
    /// The path leaf's encryption key.
    pub path_encryption_key: Vec<u8>,
    /// The conversation extension of the epoch the commit creates.
    pub new_conversation: Result<RisalaConversation, ConversationError>,
    /// The leaves that have posted a SelfRemove that is pending in the
    /// group, besides those the commit itself includes.
    pub pending_self_removes: Vec<LeafNodeIndex>,
}

impl CommitView {
    /// Reads a commit from OpenMLS: its sender, the staged commit, and the
    /// SelfRemoves pending in the group's proposal store.
    pub fn of<'a>(
        sender: &Sender,
        staged: &StagedCommit,
        pending: impl Iterator<Item = &'a QueuedProposal>,
    ) -> CommitView {
        let committer = match sender {
            Sender::Member(index) => Committer::Member(*index),
            _ => Committer::External,
        };
        let proposals = staged.queued_proposals().map(proposal_view).collect();
        let path = staged.update_path_leaf_node();
        CommitView {
            committer,
            proposals,
            // The new leaf's index is not known here; the checks use the
            // committer's.
            path_leaf: path.map(|leaf| LeafView::of(LeafNodeIndex::new(u32::MAX), leaf)),
            path_binding: path
                .and_then(|leaf| DeviceBinding::from_extensions(leaf.extensions()))
                .and_then(Result::ok),
            path_encryption_key: path
                .map(|leaf| encryption_key_bytes(leaf.encryption_key()))
                .unwrap_or_default(),
            new_conversation: RisalaConversation::from_extensions(
                staged.group_context().extensions(),
            ),
            pending_self_removes: pending
                .filter(|queued| matches!(queued.proposal(), Proposal::SelfRemove))
                .filter_map(|queued| match queued.sender() {
                    Sender::Member(index) => Some(*index),
                    _ => None,
                })
                .collect(),
        }
    }
}

fn proposal_view(queued: &QueuedProposal) -> ProposalView {
    let by_reference = queued.proposal_or_ref_type() == ProposalOrRefType::Reference;
    match (queued.proposal(), by_reference, queued.sender()) {
        (Proposal::Add(add), false, _) => ProposalView::Add {
            key_package: Box::new(add.key_package().clone()),
            by_external_proposal: false,
        },
        (Proposal::Add(add), true, Sender::NewMemberProposal) => ProposalView::Add {
            key_package: Box::new(add.key_package().clone()),
            by_external_proposal: true,
        },
        (Proposal::Remove(remove), false, _) => ProposalView::Remove(remove.removed()),
        (Proposal::SelfRemove, true, Sender::Member(index)) => ProposalView::SelfRemove(*index),
        (Proposal::GroupContextExtensions(_), false, _) => ProposalView::GroupContextExtensions,
        (Proposal::ExternalInit(_), false, _) => ProposalView::ExternalInit,
        (Proposal::Add(_), ..) => ProposalView::NotAllowed("an Add by reference"),
        (Proposal::Remove(_), ..) => ProposalView::NotAllowed("a Remove by reference"),
        (Proposal::SelfRemove, ..) => ProposalView::NotAllowed("a SelfRemove by value"),
        (Proposal::GroupContextExtensions(_), ..) => {
            ProposalView::NotAllowed("a GroupContextExtensions by reference")
        }
        (Proposal::ExternalInit(_), ..) => ProposalView::NotAllowed("an ExternalInit by reference"),
        _ => ProposalView::NotAllowed("a proposal type risala does not use"),
    }
}

/// Why a commit is invalid (12.6, 12.7). Devices ignore it, and a server
/// refuses it in a public room.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    /// It has no path.
    #[error("the commit has no path")]
    NoPath,
    /// It holds a proposal that 12.6 does not allow, or one sent the wrong
    /// way.
    #[error("the commit holds {0}")]
    Proposal(&'static str),
    /// An external commit outside a public room, or one that adds more
    /// than the joiner.
    #[error("an external commit that is not allowed")]
    External,
    /// The group before the commit is not one this device would be in.
    #[error("the group's conversation extension is not acceptable")]
    Group,
    /// The committer's leaf changes its credential, or its signature key
    /// where 12.3 does not allow it, or has no profile.
    #[error("the committer's leaf changes in a way 12.3 does not allow")]
    Leaf,
    /// The conversation extension changes in a way the committer may not
    /// make.
    #[error("the commit changes the conversation extension: {0}")]
    Extension(String),
    /// An added KeyPackage is not acceptable.
    #[error("an added KeyPackage is not acceptable: {0}")]
    KeyPackage(KeyPackageError),
    /// An added device's key is not a current, logged device of its
    /// identity, or its binding does not verify under it.
    #[error("an added device is not a current device of its identity")]
    NotCurrentDevice,
    /// The committer may not add this identity.
    #[error("the committer may not add this identity")]
    Add,
    /// The committer may not remove this leaf.
    #[error("the committer may not remove this leaf")]
    Remove,
    /// A ban that leaves the banned identity in the group, `guests none`
    /// that leaves guests, or a commit that leaves a leaf of a banned
    /// identity.
    #[error("a ban or guests setting that leaves leaves behind")]
    LeftBehind,
    /// The group goes over its limits, or past 256 members while
    /// `pairwise` (6.1, 6.2).
    #[error("the group goes over its limits")]
    TooLarge,
}

/// The result of checks that passed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Added devices whose key file or log could not be fetched: their
    /// leaves are unconfirmed, and the device sends nothing in the group
    /// until a later check passes. If one fails, it commits the leaf's
    /// removal and warns the user (12.7).
    pub unchecked_adds: Vec<RisalaIdentity>,
    /// Removed leaves whose only reason was a key file that could not be
    /// fetched: the removal stands, and the device warns the user (12.7).
    pub unchecked_removals: Vec<LeafNodeIndex>,
}

/// Checks a commit against the group as of the epoch it is for (12.6,
/// 12.7). `now` is the time to check the lifetimes of added KeyPackages
/// at.
///
/// 12.5 says devices check those lifetimes against the current time, as
/// OpenMLS also does while processing the commit. A device that processes
/// the commit after a lifetime has ended then rejects a commit that
/// others applied; see the report of task M1.
///
/// The `next_token_hash` of the commit's RisalaAAD is checked separately,
/// since it needs the next epoch's secrets
/// ([`crate::group::next_token_hash_ok`]).
pub fn check_commit(
    group: &GroupView,
    commit: &CommitView,
    facts: &dyn KeyFacts,
    now: SystemTime,
) -> Result<Verdict, CommitError> {
    let old = group.conversation.as_ref().map_err(|_| CommitError::Group)?;
    let new = commit
        .new_conversation
        .as_ref()
        .map_err(|e| CommitError::Extension(e.to_string()))?;
    let path_leaf = commit.path_leaf.as_ref().ok_or(CommitError::NoPath)?;
    let path_identity = path_leaf.identity.as_ref().ok_or(CommitError::Leaf)?;
    let mut verdict = Verdict::default();

    // Proposal types and how they travel (12.6).
    for proposal in &commit.proposals {
        if let ProposalView::NotAllowed(what) = proposal {
            return Err(CommitError::Proposal(what));
        }
    }
    let changes_extensions = commit
        .proposals
        .iter()
        .any(|p| matches!(p, ProposalView::GroupContextExtensions));

    // The committer and its leaf (12.3, 12.7).
    let committer_old = match commit.committer {
        Committer::Member(index) => {
            let old_leaf = group.leaf(index).ok_or(CommitError::Leaf)?;
            if old_leaf.identity.as_ref() != Some(path_identity) {
                return Err(CommitError::Leaf);
            }
            if old_leaf.signature_key != path_leaf.signature_key
                && !signature_key_change_allowed(old, old_leaf, path_leaf)
            {
                return Err(CommitError::Leaf);
            }
            if commit
                .proposals
                .iter()
                .any(|p| matches!(p, ProposalView::ExternalInit))
            {
                return Err(CommitError::Proposal("an ExternalInit in a member's commit"));
            }
            Some(old_leaf)
        }
        Committer::External => {
            check_external(old, commit, path_identity, facts, &mut verdict)?;
            None
        }
    };
    if !path_identity.is_guest() && path_leaf.profile.is_none() {
        return Err(CommitError::Leaf);
    }
    let committer_uid = &path_identity.uid;
    let committer_updated = path_leaf.profile.as_ref().map_or(0, |p| p.updated);

    // The conversation extension (12.4, 6.2, 6.3).
    if changes_extensions {
        old.check_change(new, committer_uid)
            .map_err(|e| CommitError::Extension(e.to_string()))?;
    } else if new != old {
        return Err(CommitError::Extension("changed without a proposal".into()));
    }

    // Removes (12.7, 6.3, 6.4).
    let mut removed: BTreeSet<LeafNodeIndex> = BTreeSet::new();
    for proposal in &commit.proposals {
        if let ProposalView::Remove(index) | ProposalView::SelfRemove(index) = proposal
            && !removed.insert(*index)
        {
            return Err(CommitError::Proposal("a leaf removed twice"));
        }
    }
    let removed_uids: BTreeMap<&Uid, usize> =
        removed
            .iter()
            .filter_map(|i| group.leaf(*i)?.uid())
            .fold(BTreeMap::new(), |mut counts, uid| {
                *counts.entry(uid).or_default() += 1;
                counts
            });
    for proposal in &commit.proposals {
        let ProposalView::Remove(index) = proposal else {
            continue;
        };
        let leaf = group.leaf(*index).ok_or(CommitError::Remove)?;
        let identity = leaf.identity.as_ref().ok_or(CommitError::Remove)?;
        let kicks_all = removed_uids.get(&identity.uid).copied()
            == Some(group.leaves_of(&identity.uid).count());
        let allowed = committer_old.is_some() && identity.uid == *committer_uid
            || commit.pending_self_removes.contains(index)
            || identity.is_guest()
            || leaf
                .profile
                .as_ref()
                .is_some_and(|p| is_stale(p.updated, committer_updated))
            || (commit.committer == Committer::External
                && identity.uid == *committer_uid
                && identity.device_id == path_identity.device_id)
            || (old.kind != ConversationKind::Direct
                && kicks_all
                && may_kick(old, committer_uid, &identity.uid));
        if allowed {
            continue;
        }
        let Some(device_id) = identity.device_id else {
            return Err(CommitError::Remove);
        };
        match facts.device_removed(&identity.uid, &device_id) {
            Fact::Known(true) => {}
            Fact::Known(false) => return Err(CommitError::Remove),
            Fact::Unknown => verdict.unchecked_removals.push(*index),
        }
    }

    // Adds (12.7, 6.1).
    let mut added_uids: Vec<Uid> = Vec::new();
    for proposal in &commit.proposals {
        let ProposalView::Add {
            key_package,
            by_external_proposal,
        } = proposal
        else {
            continue;
        };
        if commit.committer == Committer::External {
            return Err(CommitError::External);
        }
        let identity = check_add(
            old,
            new,
            group,
            committer_uid,
            key_package,
            *by_external_proposal,
            facts,
            now,
            &mut verdict,
        )?;
        added_uids.push(identity.uid);
    }

    // The group after the commit.
    let mut after: Vec<&Uid> = group
        .leaves
        .iter()
        .filter(|leaf| !removed.contains(&leaf.index))
        .filter_map(LeafView::uid)
        .collect();
    after.extend(added_uids.iter());
    if commit.committer == Committer::External {
        after.push(committer_uid);
    }
    for uid in &after {
        if new.is_banned(uid) {
            return Err(CommitError::LeftBehind);
        }
        if uid.is_guest()
            && new.kind == ConversationKind::PublicRoom
            && new.guests == GuestMode::None
        {
            return Err(CommitError::LeftBehind);
        }
    }
    if !within_limits(new, after.iter().copied()) {
        return Err(CommitError::TooLarge);
    }
    if new.kind == ConversationKind::PrivateRoom && new.confirm == ConfirmMode::Pairwise {
        let members: BTreeSet<&&Uid> = after.iter().collect();
        if members.len() > MAX_PAIRWISE_MEMBERS {
            return Err(CommitError::TooLarge);
        }
    }
    Ok(verdict)
}

/// Whether a leaf may commit a new signature key (12.3): once right after
/// joining, while it still holds its KeyPackage's leaf node, which covers
/// a last-resort KeyPackage; and in an epochal group, in a later period
/// than its last commit, by the `updated` of the profiles.
///
/// The leaf's own claims decide, rather than the time a device processes
/// the commit, so that every device decides alike (7.2). Any leaf that
/// has not committed since joining may rotate once, not only one from a
/// last-resort KeyPackage, since a device that joins later cannot tell
/// which KeyPackage a leaf came from.
fn signature_key_change_allowed(
    conversation: &RisalaConversation,
    old: &LeafView,
    new: &LeafView,
) -> bool {
    if old.from_key_package {
        return true;
    }
    match (conversation.confirm, &old.profile, &new.profile) {
        (ConfirmMode::Epochal, Some(old), Some(new)) => {
            new.updated / PERIOD_MS > old.updated / PERIOD_MS
        }
        _ => false,
    }
}

/// Whether `committer` may kick `target` from a room (6.3, 6.4): owners
/// anyone but the last owner, moderators plain members, by their roles as
/// of the commit's epoch.
fn may_kick(conversation: &RisalaConversation, committer: &Uid, target: &Uid) -> bool {
    match (conversation.role(committer), conversation.role(target)) {
        (Role::Owner, Role::Owner) => conversation.owners.len() > 1,
        (Role::Owner, _) => true,
        (Role::Mod, Role::Member) => true,
        _ => false,
    }
}

/// The checks of an external commit (12.7): only in public rooms; only the
/// joiner, a guest if `guests` allows it, never a banned identity; a
/// device's leaf carries a binding by a current device key.
fn check_external(
    conversation: &RisalaConversation,
    commit: &CommitView,
    joiner: &RisalaIdentity,
    facts: &dyn KeyFacts,
    verdict: &mut Verdict,
) -> Result<(), CommitError> {
    if conversation.kind != ConversationKind::PublicRoom {
        return Err(CommitError::External);
    }
    let inits = commit
        .proposals
        .iter()
        .filter(|p| matches!(p, ProposalView::ExternalInit))
        .count();
    if inits != 1 || commit
        .proposals
        .iter()
        .any(|p| matches!(p, ProposalView::Add { .. } | ProposalView::GroupContextExtensions))
    {
        return Err(CommitError::External);
    }
    if conversation.is_banned(&joiner.uid) {
        return Err(CommitError::Add);
    }
    let Some(device_id) = joiner.device_id else {
        return if conversation.guests == GuestMode::None {
            Err(CommitError::Add)
        } else {
            Ok(())
        };
    };
    let binding = commit.path_binding.as_ref().ok_or(CommitError::NotCurrentDevice)?;
    match facts.current_device_key(&joiner.uid, &device_id) {
        Fact::Known(Some(key)) => {
            if !binding.verify(&key, &joiner.uid, b"", &commit.path_encryption_key) {
                return Err(CommitError::NotCurrentDevice);
            }
        }
        Fact::Known(None) => return Err(CommitError::NotCurrentDevice),
        Fact::Unknown => verdict.unchecked_adds.push(joiner.clone()),
    }
    Ok(())
}

/// The checks of one Add (12.7). Returns the added identity.
#[allow(clippy::too_many_arguments)]
fn check_add(
    old: &RisalaConversation,
    new: &RisalaConversation,
    group: &GroupView,
    committer: &Uid,
    key_package: &KeyPackage,
    by_external_proposal: bool,
    facts: &dyn KeyFacts,
    now: SystemTime,
    verdict: &mut Verdict,
) -> Result<RisalaIdentity, CommitError> {
    let guest = RisalaIdentity::from_credential(key_package.leaf_node().credential())
        .is_ok_and(|identity| identity.is_guest());
    if guest {
        // A guest only by external proposal, into a public room that
        // allows guests (12.7).
        let identity =
            check_guest_key_package(key_package, now).map_err(CommitError::KeyPackage)?;
        if !by_external_proposal
            || old.kind != ConversationKind::PublicRoom
            || old.guests == GuestMode::None
        {
            return Err(CommitError::Add);
        }
        return Ok(identity);
    }
    let (identity, _last_resort) =
        check_key_package_contents(key_package, now).map_err(CommitError::KeyPackage)?;
    let uid = &identity.uid;
    if old.is_banned(uid) || new.is_banned(uid) {
        return Err(CommitError::Add);
    }
    let allowed = if by_external_proposal {
        // Anyone not banned may join a public room (6.1).
        old.kind == ConversationKind::PublicRoom
    } else if uid == committer {
        true
    } else {
        match old.kind {
            ConversationKind::Direct => old
                .direct_participants()
                .is_some_and(|participants| participants.contains(uid)),
            _ => {
                group.leaves_of(uid).next().is_some() || old.role(committer) >= Role::Mod
            }
        }
    };
    if !allowed {
        return Err(CommitError::Add);
    }
    let device_id = identity.device_id.expect("not a guest");
    match facts.current_device_key(uid, &device_id) {
        Fact::Known(Some(key)) => check_binding(key_package, &identity, &key)
            .map_err(|_| CommitError::NotCurrentDevice)?,
        Fact::Known(None) => return Err(CommitError::NotCurrentDevice),
        Fact::Unknown => verdict.unchecked_adds.push(identity.clone()),
    }
    Ok(identity)
}

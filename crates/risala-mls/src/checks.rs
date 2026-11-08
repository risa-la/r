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

#[cfg(test)]
mod tests {
    use super::*;

    struct NoFacts;

    impl KeyFacts for NoFacts {
        fn current_device_key(&self, _: &Uid, _: &DeviceId) -> Fact<Option<Vec<u8>>> {
            Fact::Known(None)
        }

        fn device_removed(&self, _: &Uid, _: &DeviceId) -> Fact<bool> {
            Fact::Known(false)
        }
    }

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    fn leaf(index: u32, who: &str, updated: u64) -> LeafView {
        let uid = uid(who);
        let identity = if uid.is_guest() {
            RisalaIdentity::guest(uid)
        } else {
            RisalaIdentity::device(uid, DeviceId([index as u8; 48]))
        };
        LeafView {
            index: LeafNodeIndex::new(index),
            identity: Some(identity),
            profile: Some(RisalaProfile::new("", updated).unwrap()),
            signature_key: vec![index as u8; 4],
            from_key_package: false,
        }
    }

    fn room(kind: ConversationKind) -> RisalaConversation {
        let owner = uid("o@x.org");
        let mut conv = match kind {
            ConversationKind::PublicRoom => RisalaConversation::public_room(
                "h.org",
                [0; 16],
                &"#r".parse().unwrap(),
                &owner,
            ),
            _ => RisalaConversation::private_room("h.org", [0; 16], "R", &owner),
        };
        conv.mods.push(uid("m@x.org"));
        conv
    }

    /// Owner o (leaf 0), moderator m (1), member p (2 and 3).
    fn group(conv: &RisalaConversation) -> GroupView {
        GroupView {
            conversation: Ok(conv.clone()),
            leaves: vec![
                leaf(0, "o@x.org", 1000),
                leaf(1, "m@x.org", 1000),
                leaf(2, "p@x.org", 1000),
                leaf(3, "p@x.org", 1000),
            ],
        }
    }

    /// A commit by leaf `by` that refreshes its leaf at time `updated`.
    fn commit(group: &GroupView, by: u32, updated: u64, proposals: Vec<ProposalView>) -> CommitView {
        let mut path = group.leaf(LeafNodeIndex::new(by)).unwrap().clone();
        path.profile = Some(RisalaProfile::new("", updated).unwrap());
        path.from_key_package = false;
        CommitView {
            committer: Committer::Member(LeafNodeIndex::new(by)),
            proposals,
            path_leaf: Some(path),
            path_binding: None,
            path_encryption_key: Vec::new(),
            new_conversation: group.conversation.clone(),
            pending_self_removes: Vec::new(),
        }
    }

    fn check(group: &GroupView, commit: &CommitView) -> Result<Verdict, CommitError> {
        check_commit(group, commit, &NoFacts, SystemTime::now())
    }

    fn remove(indices: &[u32]) -> Vec<ProposalView> {
        indices
            .iter()
            .map(|i| ProposalView::Remove(LeafNodeIndex::new(*i)))
            .collect()
    }

    #[test]
    fn paths_and_proposal_kinds() {
        let g = group(&room(ConversationKind::PrivateRoom));
        assert_eq!(check(&g, &commit(&g, 2, 2000, vec![])), Ok(Verdict::default()));
        let mut no_path = commit(&g, 2, 2000, vec![]);
        no_path.path_leaf = None;
        assert_eq!(check(&g, &no_path), Err(CommitError::NoPath));
        let odd = commit(&g, 2, 2000, vec![ProposalView::NotAllowed("x")]);
        assert_eq!(check(&g, &odd), Err(CommitError::Proposal("x")));
        let init = commit(&g, 2, 2000, vec![ProposalView::ExternalInit]);
        assert!(matches!(check(&g, &init), Err(CommitError::Proposal(_))));
        // The extension changes only through a proposal.
        let mut sneaky = commit(&g, 0, 2000, vec![]);
        sneaky.new_conversation.as_mut().unwrap().topic = "t".into();
        assert!(matches!(check(&g, &sneaky), Err(CommitError::Extension(_))));
        let mut topic = sneaky.clone();
        topic.proposals.push(ProposalView::GroupContextExtensions);
        assert_eq!(check(&g, &topic), Ok(Verdict::default()));
        // External commits only in public rooms.
        let mut external = commit(&g, 2, 2000, vec![ProposalView::ExternalInit]);
        external.committer = Committer::External;
        assert_eq!(check(&g, &external), Err(CommitError::External));
    }

    #[test]
    fn leaves_keep_their_credential_and_key() {
        let conv = room(ConversationKind::PrivateRoom);
        let g = group(&conv);
        let mut other = commit(&g, 2, 2000, vec![]);
        other.path_leaf.as_mut().unwrap().identity = Some(RisalaIdentity::device(
            uid("p@x.org"),
            DeviceId([9; 48]),
        ));
        assert_eq!(check(&g, &other), Err(CommitError::Leaf));
        let mut no_profile = commit(&g, 2, 2000, vec![]);
        no_profile.path_leaf.as_mut().unwrap().profile = None;
        assert_eq!(check(&g, &no_profile), Err(CommitError::Leaf));

        // A new signature key: not in a pairwise group, once the leaf has
        // committed; yes while it holds its KeyPackage's leaf (12.3).
        let mut rotate = commit(&g, 2, 2000, vec![]);
        rotate.path_leaf.as_mut().unwrap().signature_key = vec![42; 4];
        assert_eq!(check(&g, &rotate), Err(CommitError::Leaf));
        let mut fresh = g.clone();
        fresh.leaves[2].from_key_package = true;
        assert_eq!(check(&fresh, &rotate), Ok(Verdict::default()));

        // In an epochal group, once per period by the profiles' times.
        let mut epochal = conv.clone();
        epochal.confirm = ConfirmMode::Epochal;
        let g = group(&epochal);
        let same_day = |updated| {
            let mut c = commit(&g, 2, updated, vec![]);
            c.path_leaf.as_mut().unwrap().signature_key = vec![42; 4];
            check(&g, &c)
        };
        assert_eq!(same_day(PERIOD_MS - 1), Err(CommitError::Leaf));
        assert_eq!(same_day(PERIOD_MS), Ok(Verdict::default()));
    }

    #[test]
    fn removes_and_kicks() {
        let conv = room(ConversationKind::PrivateRoom);
        let g = group(&conv);
        // Your own leaves, a SelfRemove's, a stale one.
        assert!(check(&g, &commit(&g, 2, 2000, remove(&[3]))).is_ok());
        assert_eq!(
            check(&g, &commit(&g, 0, 2000, remove(&[1]))),
            Ok(Verdict::default()),
            "an owner kicks a moderator"
        );
        let mut pending = commit(&g, 2, 2000, remove(&[0]));
        assert_eq!(check(&g, &pending), Err(CommitError::Remove));
        pending.pending_self_removes.push(LeafNodeIndex::new(0));
        assert!(check(&g, &pending).is_ok());
        let stale = 1000 + STALE_AFTER_MS + 1;
        assert!(check(&g, &commit(&g, 2, stale, remove(&[0]))).is_ok());
        assert!(check(&g, &commit(&g, 2, stale - 1, remove(&[0]))).is_err());
        // A kick removes every leaf of the identity.
        assert!(check(&g, &commit(&g, 1, 2000, remove(&[2, 3]))).is_ok());
        assert_eq!(
            check(&g, &commit(&g, 1, 2000, remove(&[2]))),
            Err(CommitError::Remove)
        );
        // Moderators kick plain members only; nobody kicks the last owner.
        assert_eq!(
            check(&g, &commit(&g, 1, 2000, remove(&[0]))),
            Err(CommitError::Remove)
        );
        let mut two_owners = conv.clone();
        two_owners.owners.push(uid("m@x.org"));
        two_owners.mods.clear();
        let g2 = group(&two_owners);
        assert!(check(&g2, &commit(&g2, 1, 2000, remove(&[0]))).is_ok());
        let g1 = group(&conv);
        assert_eq!(
            check(&g1, &commit(&g1, 1, 2000, remove(&[0]))),
            Err(CommitError::Remove)
        );
        // A leaf removed twice.
        let twice = commit(
            &g,
            2,
            2000,
            vec![
                ProposalView::Remove(LeafNodeIndex::new(3)),
                ProposalView::SelfRemove(LeafNodeIndex::new(3)),
            ],
        );
        assert!(matches!(check(&g, &twice), Err(CommitError::Proposal(_))));
        // In a direct conversation, nobody is kicked.
        let direct = RisalaConversation::direct("h.org", [0; 16], &uid("o@x.org"), &uid("p@x.org"));
        let mut gd = group(&direct);
        gd.leaves.remove(1);
        assert_eq!(
            check(&gd, &commit(&gd, 0, 2000, remove(&[2, 3]))),
            Err(CommitError::Remove)
        );
    }

    #[test]
    fn guests_and_bans() {
        let conv = room(ConversationKind::PublicRoom);
        let mut g = group(&conv);
        g.leaves.push(leaf(4, "~sam", 1000));
        // Anyone may remove a guest leaf (6.1).
        assert!(check(&g, &commit(&g, 2, 2000, remove(&[4]))).is_ok());
        // Guests none must remove the guests in the same commit.
        let mut none = commit(&g, 0, 2000, vec![ProposalView::GroupContextExtensions]);
        none.new_conversation.as_mut().unwrap().guests = GuestMode::None;
        assert_eq!(check(&g, &none), Err(CommitError::LeftBehind));
        none.proposals.push(ProposalView::Remove(LeafNodeIndex::new(4)));
        assert!(check(&g, &none).is_ok());
        // A ban must remove the identity's leaves.
        let mut ban = commit(&g, 1, 2000, vec![ProposalView::GroupContextExtensions]);
        ban.new_conversation
            .as_mut()
            .unwrap()
            .bans
            .push(uid("p@x.org"));
        assert_eq!(check(&g, &ban), Err(CommitError::LeftBehind));
        ban.proposals.extend(remove(&[2, 3]));
        assert!(check(&g, &ban).is_ok());
    }

    fn crowd(conv: &RisalaConversation, identities: u32, per: u32) -> GroupView {
        let mut leaves = vec![leaf(0, "o@x.org", 1000)];
        for i in 1..identities {
            for j in 0..per {
                let mut l = leaf(i * per + j, &format!("u{i}@x.org"), 1000);
                l.index = LeafNodeIndex::new(i * per + j);
                leaves.push(l);
            }
        }
        GroupView {
            conversation: Ok(conv.clone()),
            leaves,
        }
    }

    #[test]
    fn limits() {
        let conv = room(ConversationKind::PrivateRoom);
        // 256 members while pairwise is fine, 257 is not (6.2).
        let g = crowd(&conv, 256, 1);
        assert!(check(&g, &commit(&g, 0, 2000, vec![])).is_ok());
        let g = crowd(&conv, 257, 1);
        assert_eq!(check(&g, &commit(&g, 0, 2000, vec![])), Err(CommitError::TooLarge));
        let mut epochal = conv.clone();
        epochal.confirm = ConfirmMode::Epochal;
        let g = crowd(&epochal, 257, 1);
        assert!(check(&g, &commit(&g, 0, 2000, vec![])).is_ok());
        // 1,000 identities and 4,096 leaves in a private room (6.1).
        let g = crowd(&epochal, 1001, 1);
        assert_eq!(check(&g, &commit(&g, 0, 2000, vec![])), Err(CommitError::TooLarge));
        let g = crowd(&epochal, 400, 11);
        assert_eq!(check(&g, &commit(&g, 0, 2000, vec![])), Err(CommitError::TooLarge));
        let public = room(ConversationKind::PublicRoom);
        let g = crowd(&public, 1001, 1);
        assert!(check(&g, &commit(&g, 0, 2000, vec![])).is_ok());
    }

    #[test]
    fn joining() {
        let conv = room(ConversationKind::PrivateRoom);
        let expect = JoinExpectation {
            host: "h.org".into(),
            own_uid: uid("p@x.org"),
            public_room: None,
        };
        let g = group(&conv);
        assert_eq!(check_join(&g, &expect), Ok(()));
        let mut other_host = expect.clone();
        other_host.host = "x.org".into();
        assert_eq!(check_join(&g, &other_host), Err(JoinError::WrongConversation));
        let mut public = expect.clone();
        public.public_room = Some(("#r".parse().unwrap(), [0; 16]));
        assert_eq!(check_join(&g, &public), Err(JoinError::WrongConversation));
        let mut guest = g.clone();
        guest.leaves.push(leaf(4, "~sam", 1));
        assert_eq!(check_join(&guest, &expect), Err(JoinError::Guest));
        let mut banned = g.clone();
        banned.conversation.as_mut().unwrap().bans.push(uid("p@x.org"));
        assert_eq!(check_join(&banned, &expect), Err(JoinError::Banned));
        let mut no_profile = g.clone();
        no_profile.leaves[1].profile = None;
        assert_eq!(check_join(&no_profile, &expect), Err(JoinError::Leaf));
        let mut no_identity = g.clone();
        no_identity.leaves[1].identity = None;
        assert_eq!(check_join(&no_identity, &expect), Err(JoinError::Leaf));
        let big = crowd(&conv, 1001, 1);
        assert_eq!(check_join(&big, &expect), Err(JoinError::TooLarge));
        // Stale leaves and the weekly refresh.
        assert_eq!(g.stale_leaves(1000 + STALE_AFTER_MS + 1).len(), 4);
        assert!(g.stale_leaves(1000 + STALE_AFTER_MS).is_empty());
    }
}

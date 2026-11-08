//! The checks devices make of every group they join and every commit they
//! apply (12.7, 6.1-6.4), and that a server makes of a public room's
//! commits (12.6).
//!
//! A commit gets two kinds of check (12.7):
//!
//! - **Group checks** ([`check_commit`]) depend only on the group's state
//!   in the commit's epoch ([`GroupView`]: the tree with each leaf's
//!   credential, profile, lifetime and `leaf_node_source`, the conversation
//!   extension, and the leaf that started the epoch), on the commit
//!   ([`CommitView`]), and on the posts of the commit and of the proposals
//!   it applies by reference ([`CommitPost`]: their `t`, and the commit's
//!   `next`). Nothing else: no earlier epochs, no other posts, no key
//!   files, no clock. So every device that applied the same posts reaches
//!   the same answer, whenever it joined. A commit that fails one is
//!   invalid. A server runs the same checks on a public room's commits,
//!   with `t` from its own clock.
//! - **Key checks** ([`key_checks`]) use key files and the key log, which
//!   devices fetch at different times. They never make a commit invalid:
//!   they only lead to repairs by later commits.
//!
//! What a device keeps of a group's epoch besides OpenMLS's state is an
//! [`EpochState`]: which leaf started the epoch, and the `t` of the posts
//! of the epoch's proposals.

use std::collections::{BTreeMap, BTreeSet};

use openmls::group::{QueuedProposal, StagedCommit};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::{
    KeyPackage, LeafNode, LeafNodeIndex, Proposal, ProposalOrRefType, PublicGroup, Sender,
};
use openmls::treesync::LeafNodeSource;
use risala_proto::names::{Room, ServerAddr, Uid};
use serde::{Deserialize, Serialize};

use crate::conversation::{
    ChangeRights, ConfirmMode, ConversationError, ConversationKind, GuestMode, RisalaConversation,
    Role,
};
use crate::crypto::x_wing_public_key_ok;
use crate::identity::{DeviceId, RisalaIdentity};
use crate::keypackage::{
    KeyPackageError, binding_fits_credential, check_binding, check_key_package_contents,
    encryption_key_bytes, has_no_binding, lifetime_acceptable_at,
};
use crate::primitives::HASH_LEN;
use crate::profile::RisalaProfile;

/// The most identities in a private room (6.1).
pub const MAX_PRIVATE_IDENTITIES: usize = 1_000;
/// The most leaves in a private room (6.1).
pub const MAX_PRIVATE_LEAVES: usize = 4_096;
/// The most leaves in a direct conversation: 64 current devices for each
/// of its two participants (12.7, 4.4).
pub const MAX_DIRECT_LEAVES: usize = 128;
/// The most identities, guests included, in a public room (6.1).
pub const MAX_PUBLIC_IDENTITIES: usize = 10_000;
/// The most leaves in a public room (6.1).
pub const MAX_PUBLIC_LEAVES: usize = 32_768;
/// The most identities with leaves a private room may have while it is
/// `pairwise` (6.2, 12.7).
pub const MAX_PAIRWISE_MEMBERS: usize = 256;
/// How much older than the group's median activity time a leaf's must be
/// for anyone to remove it as stale: 35 days, in ms (12.7).
pub const STALE_AFTER_MS: u64 = 35 * 24 * 60 * 60 * 1000;
/// How long a device may go without committing its own leaf in a group:
/// a week, in ms (12.7).
pub const REFRESH_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// How old, by its `updated`, a public room's leaf that has never
/// committed or been Updated must be for any member to remove it: 8 days,
/// in ms (12.7).
pub const UNUSED_AFTER_MS: u64 = 8 * 24 * 60 * 60 * 1000;
/// A period of epochal confirmation, a UTC day, in ms (12.10).
pub const PERIOD_MS: u64 = 24 * 60 * 60 * 1000;
/// How far a leaf's new `updated` may be from the `t` of the post that
/// carries it, and how long after its identity's highest one a commit may
/// go past its streak: 10 minutes, in ms (12.3, 12.7).
pub const UPDATED_SKEW_MS: u64 = 10 * 60 * 1000;
/// The most epochs in a row an identity's leaves may start before they
/// have to wait (12.7).
pub const STREAK_LIMIT: u8 = 3;

/// Whether a fact from a key file or the key log is known yet (12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact<T> {
    /// It is known.
    Known(T),
    /// It could not be fetched right now (4.4), or a record it needs is
    /// still pending (4.5). Check again later.
    Unknown,
}

/// What the key checks need from key files and the key log (4.4, 4.5). The
/// caller fetches and caches them. Every fact stays true once it is true,
/// so devices that fetch later reach the same answer (12.7).
///
/// A record still pending 2 hours after the device first needed it counts
/// as failed (12.7): the caller answers `Known` then, as if the record had
/// been refused, and `Unknown` only before.
pub trait KeyFacts {
    /// The raw device key of `uid`'s device `device_id`, if that device is
    /// current in `uid`'s key file and its record has been accepted (4.5):
    /// `Known(Some(key))`, or `Known(None)` if it is not.
    fn current_device_key(&self, uid: &Uid, device_id: &DeviceId) -> Fact<Option<Vec<u8>>>;

    /// Whether `uid`'s chain has removed the device `device_id` by record
    /// (4.4), as far as the device has accepted it.
    fn device_removed(&self, uid: &Uid, device_id: &DeviceId) -> Fact<bool>;

    /// Whether `uid`'s chain ends with a `retire` record (4.9).
    fn identity_retired(&self, uid: &Uid) -> Fact<bool>;

    /// Whether `uid` is forked (4.5), or has its keys missing (4.4), as the
    /// device sees it now (12.14).
    fn forked_or_missing(&self, uid: &Uid) -> Fact<bool>;
}

/// What a device keeps of a group's current epoch besides OpenMLS's state,
/// for the group checks (12.3, 12.7). Every member of the epoch knows the
/// same: a device that joins by Welcome or external commit learns the leaf
/// that started the epoch from the GroupInfo's signer. The caller stores it
/// with the group; [`crate::group`]'s functions keep it up to date.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochState {
    /// The leaf that made the commit that started the epoch, which signed
    /// its GroupInfo (12.3); `None` in a group's first epoch.
    pub started_by: Option<u32>,
    /// The `t` of the post of each of the epoch's proposals that the device
    /// processed, by ProposalRef (12.3, 12.7). A commit that applies an
    /// Update by reference is judged by the `t` of the Update's own post.
    pub proposal_times: Vec<(Vec<u8>, u64)>,
}

impl EpochState {
    /// The state of a group's first epoch, which nobody's commit started.
    pub fn created() -> EpochState {
        EpochState::default()
    }

    /// The state of an epoch whose GroupInfo `started_by` signed.
    pub fn started_by(started_by: LeafNodeIndex) -> EpochState {
        EpochState {
            started_by: Some(started_by.u32()),
            proposal_times: Vec::new(),
        }
    }

    /// Notes the `t` of the post of a proposal of this epoch, by its
    /// ProposalRef (12.3). Do this for every proposal processed, before a
    /// commit that applies it is checked.
    pub fn note_proposal(&mut self, reference: &[u8], t: u64) {
        if !self.proposal_times.iter().any(|(r, _)| r == reference) {
            self.proposal_times.push((reference.to_vec(), t));
        }
    }

    /// The post of a commit of this epoch, with `t` and `next`, and the
    /// times of the proposals noted (5.2).
    pub fn post(&self, t: u64, next: Option<[u8; HASH_LEN]>) -> CommitPost {
        CommitPost {
            t,
            next,
            proposal_times: self.proposal_times.clone(),
        }
    }
}

/// The posts that carry a commit and the proposals it applies by
/// reference, as the group checks need them (5.2, 12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPost {
    /// The commit's post's `t`, when the server accepted it, in ms since
    /// 1970-01-01T00:00:00Z. A server checking a public room's commit uses
    /// its own clock, which gives the post its `t`.
    pub t: u64,
    /// The post's `next`, the SHA-384 hash of the send token of the epoch a
    /// commit creates (5.2, 12.6).
    pub next: Option<[u8; HASH_LEN]>,
    /// The `t` of the posts of the proposals the commit may apply by
    /// reference, by ProposalRef ([`EpochState::post`]).
    pub proposal_times: Vec<(Vec<u8>, u64)>,
}

impl CommitPost {
    /// The post of a commit with no proposals by reference to time.
    pub fn at(t: u64, next: Option<[u8; HASH_LEN]>) -> CommitPost {
        CommitPost {
            t,
            next,
            proposal_times: Vec::new(),
        }
    }

    fn proposal_time(&self, reference: &[u8]) -> Option<u64> {
        self.proposal_times
            .iter()
            .find(|(r, _)| r == reference)
            .map(|(_, t)| *t)
    }
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
    /// Whether it has neither committed nor been Updated since it was
    /// added: its `leaf_node_source` is still `key_package`.
    pub from_key_package: bool,
    /// The end of its KeyPackage's lifetime, in ms, while it still holds
    /// its KeyPackage's leaf node (12.5).
    pub lifetime_end: Option<u64>,
    /// Whether its encryption key passes the checks of 12.2.
    pub encryption_key_ok: bool,
}

impl LeafView {
    /// Reads a leaf node.
    pub fn of(index: LeafNodeIndex, leaf: &LeafNode) -> LeafView {
        let lifetime_end = match leaf.leaf_node_source() {
            LeafNodeSource::KeyPackage(lifetime) => Some(lifetime.not_after().saturating_mul(1000)),
            _ => None,
        };
        LeafView {
            index,
            identity: RisalaIdentity::from_credential(leaf.credential()).ok(),
            profile: RisalaProfile::of_leaf(leaf),
            signature_key: leaf.signature_key().as_slice().to_vec(),
            from_key_package: lifetime_end.is_some(),
            lifetime_end,
            encryption_key_ok: x_wing_public_key_ok(&encryption_key_bytes(leaf.encryption_key())),
        }
    }

    /// The leaf's uid.
    pub fn uid(&self) -> Option<&Uid> {
        self.identity.as_ref().map(|identity| &identity.uid)
    }

    fn device_id(&self) -> Option<DeviceId> {
        self.identity
            .as_ref()
            .and_then(|identity| identity.device_id)
    }

    fn is_guest(&self) -> bool {
        self.identity.as_ref().is_some_and(RisalaIdentity::is_guest)
    }

    fn updated(&self) -> u64 {
        self.profile.as_ref().map_or(0, |p| p.updated)
    }

    fn streak(&self) -> u8 {
        self.profile.as_ref().map_or(0, |p| p.streak)
    }

    /// The leaf's activity time as of a commit whose post has `t` (12.7):
    /// its `updated`, or, while it has neither committed nor been Updated,
    /// the end of its KeyPackage's lifetime if that is later; never later
    /// than `t`.
    pub fn activity_time(&self, t: u64) -> u64 {
        self.updated().max(self.lifetime_end.unwrap_or(0)).min(t)
    }

    /// Whether the two leaves are of the same device: the same uid and
    /// `device_id`.
    fn same_device(&self, other: &LeafView) -> bool {
        self.identity.is_some() && self.identity == other.identity
    }
}

/// A group as of one epoch: the state its group checks may depend on
/// (12.7).
#[derive(Debug, Clone)]
pub struct GroupView {
    /// The epoch.
    pub epoch: u64,
    /// The conversation extension, or why it is not acceptable.
    pub conversation: Result<RisalaConversation, ConversationError>,
    /// The leaves, in index order.
    pub leaves: Vec<LeafView>,
    /// The leaf that made the commit that started the epoch, the GroupInfo's
    /// signer (12.3); `None` in a group's first epoch.
    pub started_by: Option<LeafNodeIndex>,
    /// The box that a move made in this epoch goes to (7.8), from the
    /// epoch's exporter; `None` for a server, which cannot compute it, and
    /// never sees a move (public rooms do not move).
    pub moved_box: Option<[u8; 16]>,
}

impl GroupView {
    /// Reads a group's public state, with what the device keeps of its
    /// epoch.
    pub fn of(group: &PublicGroup, state: &EpochState) -> GroupView {
        let leaves = group
            .members()
            .filter_map(|member| {
                group
                    .leaf(member.index)
                    .map(|leaf| LeafView::of(member.index, leaf))
            })
            .collect();
        GroupView {
            epoch: group.group_context().epoch().as_u64(),
            conversation: RisalaConversation::from_extensions(group.group_context().extensions()),
            leaves,
            started_by: state.started_by.map(LeafNodeIndex::new),
            moved_box: None,
        }
    }

    /// The leaf at `index`.
    pub fn leaf(&self, index: LeafNodeIndex) -> Option<&LeafView> {
        self.leaves.iter().find(|leaf| leaf.index == index)
    }

    /// The leaves of `uid`.
    pub fn leaves_of<'a>(&'a self, uid: &'a Uid) -> impl Iterator<Item = &'a LeafView> + 'a {
        self.leaves
            .iter()
            .filter(move |leaf| leaf.uid() == Some(uid))
    }

    /// The group's median activity time as of a commit whose post has `t`
    /// (12.7): the value at position floor(n/2), counting from 0, of the
    /// sorted activity times of the leaves that carry a profile. `None` if
    /// no leaf has one.
    pub fn median_activity(&self, t: u64) -> Option<u64> {
        let mut values: Vec<u64> = self
            .leaves
            .iter()
            .filter(|leaf| leaf.profile.is_some())
            .map(|leaf| leaf.activity_time(t))
            .collect();
        values.sort_unstable();
        values.get(values.len() / 2).copied()
    }

    /// Whether the leaf is stale as of a commit whose post has `t`: its
    /// activity time is more than 35 days before the group's median
    /// (12.7).
    pub fn is_stale(&self, leaf: &LeafView, t: u64) -> bool {
        self.median_activity(t)
            .is_some_and(|median| median.saturating_sub(leaf.activity_time(t)) > STALE_AFTER_MS)
    }

    /// The stale leaves as of a commit whose post has `t` (12.7).
    pub fn stale_leaves(&self, t: u64) -> Vec<LeafNodeIndex> {
        self.leaves
            .iter()
            .filter(|leaf| self.is_stale(leaf, t))
            .map(|leaf| leaf.index)
            .collect()
    }

    /// The most stale leaves, guest leaves, copies and never-used leaves
    /// that a member without a role may remove in one commit:
    /// max(1, floor(n/10)), where n is the number of leaves (12.7).
    pub fn bulk_limit(&self) -> usize {
        (self.leaves.len() / 10).max(1)
    }

    /// Whether `leaf` is a copy in a public room (12.7): another leaf of
    /// the same uid and `device_id` has committed or been Updated since it
    /// was added, and has a higher `updated`.
    pub fn is_copy(&self, leaf: &LeafView) -> bool {
        self.leaves.iter().any(|other| {
            other.index != leaf.index
                && other.same_device(leaf)
                && !other.from_key_package
                && other.updated() > leaf.updated()
        })
    }

    /// Whether some identity in `owners` has a leaf in the group as it is
    /// before a commit, in the epoch the commit is for (6.3). In a room
    /// whose owners are gone, moderators may do what owners may; since this
    /// looks at the group before the commit, a moderator cannot remove the
    /// owners and take their place in one commit.
    fn owner_present(&self, conversation: &RisalaConversation) -> bool {
        conversation
            .owners
            .iter()
            .any(|uid| self.leaves_of(uid).next().is_some())
    }

    /// The role of `uid` for what a commit may do, as of this epoch: a
    /// moderator counts as an owner in a room whose owners are gone (6.3).
    pub fn effective_role(&self, uid: &Uid) -> Role {
        let Ok(conversation) = &self.conversation else {
            return Role::Member;
        };
        match conversation.role(uid) {
            Role::Mod if !self.owner_present(conversation) => Role::Owner,
            role => role,
        }
    }

    /// Whether, in a room, a leaf of `committer` may act on the leaves of
    /// `target`, as the Adds and Removes checks limit it (12.7): those of an
    /// identity listed in `owners` only a leaf of that identity or of an
    /// owner, those of one listed in `mods` only that identity, an owner or
    /// a moderator, and other members' anyone. Roles are as of this epoch,
    /// a moderator counting as an owner in a room whose owners are gone
    /// (6.3). In a direct conversation it is always true.
    pub fn may_act_on(&self, committer: &Uid, target: &Uid) -> bool {
        let Ok(conversation) = &self.conversation else {
            return committer == target;
        };
        if conversation.kind == ConversationKind::Direct || committer == target {
            return true;
        }
        may_act_on_role(self.effective_role(committer), conversation.role(target))
    }

    /// Whether a device of `committer` may remove `target`'s leaves for a
    /// check (12.7), as a repair of a key check that failed, a fork, keys
    /// missing, an impostor or a RESYNC. Where it may not, as for a plain
    /// member's device and a leaf of an owner, the device warns its user,
    /// hides what the leaf sends, and keeps sending (12.7, 12.14): the
    /// leaf's own identity, or an owner or moderator, makes the repair.
    /// Public rooms have no removals for a check.
    pub fn may_remove_for_check(&self, committer: &Uid, target: &Uid) -> bool {
        match &self.conversation {
            Ok(conversation) if conversation.kind == ConversationKind::PublicRoom => false,
            _ => self.may_act_on(committer, target),
        }
    }

    /// The stale leaves (12.7) that a device of `committer` may replace in
    /// a commit whose post has `t`. Outside public rooms, it MUST add each
    /// device again in the same commit, so it removes only stale leaves
    /// that the Adds checks let it add again: a plain member's device
    /// leaves those of owners and moderators to their own identity's
    /// devices and to owners (and moderators, for moderators). In a public
    /// room nobody adds them again, and any member may remove them. The
    /// bulk limit still applies to a member without a role.
    pub fn stale_leaves_for(&self, committer: &Uid, t: u64) -> Vec<LeafNodeIndex> {
        let public = self
            .conversation
            .as_ref()
            .is_ok_and(|c| c.kind == ConversationKind::PublicRoom);
        self.leaves
            .iter()
            .filter(|leaf| self.is_stale(leaf, t))
            .filter(|leaf| {
                public
                    || leaf
                        .uid()
                        .is_some_and(|uid| self.may_act_on(committer, uid))
            })
            .map(|leaf| leaf.index)
            .collect()
    }

    /// The `streak` that a commit by a leaf of `uid` must carry (12.3): the
    /// streak of the leaf that started the epoch, plus 1, if that leaf is
    /// of the same identity; 1 if not, or in the group's first epoch; at
    /// most 255.
    pub fn expected_streak(&self, uid: &Uid) -> u8 {
        match self.started_by.and_then(|index| self.leaf(index)) {
            Some(started) if started.uid() == Some(uid) => started.streak().saturating_add(1),
            _ => 1,
        }
    }

    /// Whether this is the conversation with yourself (12.4).
    fn with_yourself(&self) -> bool {
        self.conversation
            .as_ref()
            .ok()
            .and_then(RisalaConversation::direct_participants)
            .is_some_and(|participants| participants.len() == 1)
    }
}

/// Whether the device should commit a fresh leaf now: its own leaf's
/// profile says it was last committed, or updated through an Update, more
/// than a week ago, by `now_ms` (12.7).
pub fn needs_refresh(own_profile: &RisalaProfile, now_ms: u64) -> bool {
    now_ms.saturating_sub(own_profile.updated) > REFRESH_AFTER_MS
}

/// How far the `t` of a commit that reaches a device as it is posted may be
/// from the device's clock before it warns its user: an hour, in ms
/// (12.7).
pub const CLOCK_WARNING_MS: u64 = 60 * 60 * 1000;

/// Whether a live commit's `t` differs from the device's clock, `now_ms`,
/// by more than an hour, so that the device SHOULD warn its user: every
/// time window of the group checks runs on the server's `t` (12.7).
pub fn clock_disagrees(t: u64, now_ms: u64) -> bool {
    t.abs_diff(now_ms) > CLOCK_WARNING_MS
}

/// The leaves of other devices of `uid` that a device of that identity
/// MUST replace, outside public rooms, by removing each and adding its
/// device again from a new KeyPackage (12.7): those whose activity time is
/// older than the server's retention period, `retention_ms` (8.5), plus
/// one day, by the device's clock, `now_ms`. `own` is the device's own
/// leaf.
pub fn own_leaves_to_replace(
    group: &GroupView,
    uid: &Uid,
    own: LeafNodeIndex,
    retention_ms: u64,
    now_ms: u64,
) -> Vec<LeafNodeIndex> {
    if group
        .conversation
        .as_ref()
        .is_ok_and(|c| c.kind == ConversationKind::PublicRoom)
    {
        return Vec::new();
    }
    let limit = retention_ms.saturating_add(PERIOD_MS);
    group
        .leaves_of(uid)
        .filter(|leaf| leaf.index != own)
        .filter(|leaf| now_ms.saturating_sub(leaf.activity_time(now_ms)) > limit)
        .map(|leaf| leaf.index)
        .collect()
}

// ---------------------------------------------------------------------
// Joining

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
    /// A leaf's credential is not a RisalaIdentity, a device's leaf has no
    /// profile, or a leaf's or parent node's encryption key, or a
    /// GroupInfo's `external_pub`, fails the checks of 12.2.
    #[error("a leaf without a RisalaIdentity or a profile, or a bad key")]
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
    /// Two leaves of one device, outside a public room.
    #[error("two leaves of one device")]
    SameDevice,
    /// The group is over its size limits.
    #[error("the group is over its size limits")]
    TooLarge,
    /// No leaf has the signature key of the KeyPackage the device was added
    /// from: someone may have added the device with a key of their own
    /// (12.7). The device tells the user.
    #[error("the device's leaf does not have its KeyPackage's key")]
    NotOwnLeaf,
}

/// What the joining device expects of a group (12.7).
#[derive(Debug, Clone)]
pub struct JoinExpectation {
    /// The server the device is joining on, as a server address (3.5).
    pub host: ServerAddr,
    /// The device's own uid.
    pub own_uid: Uid,
    /// For a public room joined by name, its name and box.
    pub public_room: Option<(Room, [u8; 16])>,
}

/// Checks a group the device is about to join, by Welcome or by external
/// commit (12.7). Leaves it cannot confirm yet are allowed.
pub fn check_join(group: &GroupView, expect: &JoinExpectation) -> Result<(), JoinError> {
    let conversation = group.conversation.clone()?;
    if conversation.host != expect.host {
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
    let mut devices = BTreeSet::new();
    let mut guests_in_direct = BTreeMap::<&Uid, usize>::new();
    for leaf in &group.leaves {
        let identity = leaf.identity.as_ref().ok_or(JoinError::Leaf)?;
        if (!identity.is_guest() && leaf.profile.is_none()) || !leaf.encryption_key_ok {
            return Err(JoinError::Leaf);
        }
        if conversation.is_banned(&identity.uid) {
            return Err(JoinError::Banned);
        }
        match &participants {
            Some(participants) => {
                // A guest's report conversation: the guest is a named
                // participant, with exactly one leaf (12.7, 5.8).
                if !participants.contains(&identity.uid) {
                    return Err(JoinError::NotAParticipant);
                }
                if identity.is_guest() {
                    let count = guests_in_direct.entry(&identity.uid).or_default();
                    *count += 1;
                    if *count > 1 {
                        return Err(JoinError::Guest);
                    }
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
        if conversation.kind != ConversationKind::PublicRoom
            && let Some(device_id) = identity.device_id
            && !devices.insert((&identity.uid, device_id))
        {
            return Err(JoinError::SameDevice);
        }
    }
    if !within_limits(&conversation, group.leaves.iter().filter_map(LeafView::uid)) {
        return Err(JoinError::TooLarge);
    }
    Ok(())
}

/// Whether every parent node of a group's tree has an encryption key that
/// passes the checks of 12.2. A device checks this of every group it joins,
/// by Welcome or by external commit, since a tree's parent nodes are keys
/// that members' paths encrypt to (12.2); a commit's own parent nodes are
/// checked with it ([`CommitView::parent_keys_ok`]).
pub fn parent_keys_ok(group: &PublicGroup) -> bool {
    group
        .treesync()
        .full_parents()
        .all(|(_, node)| x_wing_public_key_ok(node.public_key().as_slice()))
}

/// Whether a GroupInfo's `external_pub`, if it has one, passes the checks
/// of 12.2. A device rejects a GroupInfo whose key fails before it makes an
/// external commit with it, and a server refuses one it is given (12.2):
/// otherwise every resync and rejoin of a public room would fail.
pub fn group_info_keys_ok(group_info: &VerifiableGroupInfo) -> bool {
    group_info
        .extensions()
        .external_pub()
        .is_none_or(|ext| x_wing_public_key_ok(ext.external_pub().as_slice()))
}

/// Whether a group of these leaves' uids is within the limits of 6.1 and
/// 12.7: a direct conversation holds at most 128 leaves.
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
        ConversationKind::Direct => (2, MAX_DIRECT_LEAVES),
        _ => (MAX_PRIVATE_IDENTITIES, MAX_PRIVATE_LEAVES),
    };
    identities.len() <= max_identities && leaves <= max_leaves
}

// ---------------------------------------------------------------------
// Commits

/// Who made a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Committer {
    /// A member, by its leaf index as of the commit's epoch.
    Member(LeafNodeIndex),
    /// A device joining a public room by external commit: a resync commit
    /// or a rejoin (12.7).
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
    /// An Update of its sender's leaf, by reference (12.6, 12.10).
    Update {
        /// The sender, whose leaf it replaces.
        sender: LeafNodeIndex,
        /// The new leaf node.
        leaf: Box<LeafView>,
        /// Its ProposalRef, to find the `t` of its post in the
        /// [`CommitPost`].
        reference: Vec<u8>,
    },
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
    /// The conversation extension of the epoch the commit creates.
    pub new_conversation: Result<RisalaConversation, ConversationError>,
    /// Whether every parent node that the commit sets, from its path or as
    /// the parents of the leaves it adds, has an encryption key that passes
    /// the checks of 12.2. A device rejects a commit that carries a key
    /// that fails, and a server one it is given (12.2): otherwise every
    /// member whose path must encrypt to that node could no longer commit.
    pub parent_keys_ok: bool,
}

impl CommitView {
    /// Reads a commit from OpenMLS: its sender and the staged commit. Only
    /// the SelfRemoves that the commit applies count (12.7): one that is
    /// merely pending in some device's proposal store does not, since the
    /// group checks depend only on the commit's own posts.
    pub fn of(sender: &Sender, staged: &StagedCommit) -> CommitView {
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
            new_conversation: RisalaConversation::from_extensions(
                staged.group_context().extensions(),
            ),
            parent_keys_ok: staged
                .changed_parent_nodes()
                .into_iter()
                .all(|node| x_wing_public_key_ok(node.public_key().as_slice())),
        }
    }

    /// Every leaf it removes, by Remove or SelfRemove.
    pub fn removed_indices(&self) -> BTreeSet<LeafNodeIndex> {
        self.proposals
            .iter()
            .filter_map(|p| match p {
                ProposalView::Remove(i) | ProposalView::SelfRemove(i) => Some(*i),
                _ => None,
            })
            .collect()
    }

    fn self_removes(&self, index: LeafNodeIndex) -> bool {
        self.proposals
            .iter()
            .any(|p| matches!(p, ProposalView::SelfRemove(i) if *i == index))
    }

    /// The identities of the leaves it adds from KeyPackages.
    pub fn added_identities(&self) -> Vec<RisalaIdentity> {
        self.proposals
            .iter()
            .filter_map(|p| match p {
                ProposalView::Add { key_package, .. } => {
                    RisalaIdentity::from_credential(key_package.leaf_node().credential()).ok()
                }
                _ => None,
            })
            .collect()
    }

    /// The uid of the committer's credential, from the commit's path.
    pub fn committer_uid(&self) -> Option<&Uid> {
        self.path_leaf.as_ref().and_then(LeafView::uid)
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
        (Proposal::Update(update), true, Sender::Member(index)) => ProposalView::Update {
            sender: *index,
            leaf: Box::new(LeafView::of(*index, update.leaf_node())),
            reference: queued.proposal_reference_ref().as_slice().to_vec(),
        },
        (Proposal::GroupContextExtensions(_), false, _) => ProposalView::GroupContextExtensions,
        (Proposal::ExternalInit(_), false, _) => ProposalView::ExternalInit,
        (Proposal::Add(_), ..) => ProposalView::NotAllowed("an Add by reference"),
        (Proposal::Remove(_), ..) => ProposalView::NotAllowed("a Remove by reference"),
        (Proposal::SelfRemove, ..) => ProposalView::NotAllowed("a SelfRemove by value"),
        (Proposal::Update(_), ..) => ProposalView::NotAllowed("an Update by value"),
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
    /// Its post has no `next`, or one that is not the hash of the new
    /// epoch's send token (12.6).
    #[error("the commit's next token hash is missing or wrong")]
    NextToken,
    /// It holds a proposal that 12.6 does not allow, or one sent the wrong
    /// way, or an Update whose post the device has no `t` for.
    #[error("the commit holds {0}")]
    Proposal(&'static str),
    /// An external commit that is neither a resync commit nor a rejoin
    /// (12.7).
    #[error("an external commit that is neither a resync commit nor a rejoin")]
    External,
    /// The group before the commit is not one this device would be in.
    #[error("the group's conversation extension is not acceptable")]
    Group,
    /// The committer's leaf, or an Update's, changes its credential, or its
    /// signature key where 12.3 does not allow it, or has no profile, or an
    /// encryption key that fails the checks of 12.2; or a parent node that
    /// the commit sets has such a key.
    #[error("a leaf changes in a way 12.3 does not allow")]
    Leaf,
    /// A guest's leaf commits or proposes an Update in a public room, or
    /// adds someone in its report conversation after the first commit.
    #[error("a guest's leaf may not do this")]
    Guest,
    /// A new `updated` is below the leaf's previous one, or more than 10
    /// minutes from its post's `t`, or an added leaf's is more than 10
    /// minutes after the commit's post's `t` (12.3, 12.7).
    #[error("an updated time out of bounds")]
    Updated,
    /// The committer's `streak` is not the one 12.3 gives, or is past 3
    /// without a reason, or an added leaf's or an Update's is not 0 (12.7).
    #[error("a streak is wrong or too long")]
    Streak,
    /// The conversation extension changes in a way the committer may not
    /// make.
    #[error("the commit changes the conversation extension: {0}")]
    Extension(String),
    /// An added KeyPackage is not acceptable.
    #[error("an added KeyPackage is not acceptable: {0}")]
    KeyPackage(KeyPackageError),
    /// The committer may not add this identity.
    #[error("the committer may not add this identity")]
    Add,
    /// The committer may not remove this leaf.
    #[error("the committer may not remove this leaf")]
    Remove,
    /// It removes for a check the leaves of more than one identity (12.7).
    #[error("removals for a check of more than one identity")]
    CheckRemovals,
    /// A member without a role removes more stale leaves, guest leaves,
    /// copies and never-used leaves than max(1, floor(n/10)) (12.7).
    #[error("too many removals by a member without a role")]
    Bulk,
    /// Two leaves of one device after the commit, outside a public room.
    #[error("two leaves of one device")]
    SameDevice,
    /// A ban that leaves the banned identity in the group, `guests none`
    /// that leaves guests, or a commit that leaves a leaf of a banned
    /// identity.
    #[error("a ban or guests setting that leaves leaves behind")]
    LeftBehind,
    /// The group goes over its limits, or past 256 identities while
    /// `pairwise` (6.1, 6.2, 12.7).
    #[error("the group goes over its limits")]
    TooLarge,
}

/// An external commit's kind (12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum External {
    /// A resync commit: it removes the leaf that started the epoch. A
    /// device that applied without trouble the commit it undoes shows it to
    /// the user as possible abuse, and names its maker.
    Resync,
    /// An owner's or moderator's rejoin.
    Rejoin,
}

/// What the group checks of a valid commit found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// The leaves it removes for a check (12.7), outside public rooms: all
    /// of one identity. The commit carries no reason, so [`key_checks`]
    /// looks for one the device can see.
    pub check_removals: Vec<LeafNodeIndex>,
    /// Whether it is a public room's external commit, and which kind.
    pub external: Option<External>,
    /// Whether it is an authority commit (12.7): one that only a role
    /// allows, that removes leaves of the committer's own identity other
    /// than its own, or that removes leaves of another identity for a
    /// check. Devices challenge its committer if they have not confirmed it
    /// (12.10).
    pub authority: bool,
}

/// Why a leaf may be removed (12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoveReason {
    /// A leaf of the committer's own identity.
    Own,
    /// By its SelfRemove.
    SelfRemove,
    /// A kick or ban, by role.
    Kick,
    /// Within the bulk limit: a guest's, a stale, a copy or a never-used
    /// leaf. `by_role` if only an owner's or moderator's role allows it.
    Bulk { by_role: bool },
    /// For a check, outside public rooms.
    Check,
}

/// Checks a commit against the group as of the epoch it is for and the
/// posts that carry it and the proposals it applies (12.6, 12.7). These are
/// the group checks: they decide whether the commit is valid, and depend on
/// nothing else.
///
/// That `next` is the hash of the new epoch's send token needs that
/// epoch's secrets, so [`crate::group::check_received_commit`] checks it;
/// here it only has to be there. Likewise a move's box needs the epoch's
/// exporter: [`GroupView::moved_box`].
pub fn check_commit(
    group: &GroupView,
    commit: &CommitView,
    post: &CommitPost,
) -> Result<Verdict, CommitError> {
    let old = group
        .conversation
        .as_ref()
        .map_err(|_| CommitError::Group)?;
    let new = commit
        .new_conversation
        .as_ref()
        .map_err(|e| CommitError::Extension(e.to_string()))?;
    if post.next.is_none() {
        return Err(CommitError::NextToken);
    }
    let path_leaf = commit.path_leaf.as_ref().ok_or(CommitError::NoPath)?;
    let path_identity = path_leaf.identity.as_ref().ok_or(CommitError::Leaf)?;
    let committer_uid = &path_identity.uid;
    let public = old.kind == ConversationKind::PublicRoom;
    let t = post.t;
    let mut verdict = Verdict::default();

    // Proposal types and how they travel (12.6).
    for proposal in &commit.proposals {
        match proposal {
            ProposalView::NotAllowed(what) => return Err(CommitError::Proposal(what)),
            ProposalView::Update { .. } if old.confirm != ConfirmMode::Epochal => {
                return Err(CommitError::Proposal("an Update outside an epochal group"));
            }
            _ => {}
        }
    }
    let mut removed: BTreeSet<LeafNodeIndex> = BTreeSet::new();
    for proposal in &commit.proposals {
        if let ProposalView::Remove(index) | ProposalView::SelfRemove(index) = proposal
            && !removed.insert(*index)
        {
            return Err(CommitError::Proposal("a leaf removed twice"));
        }
    }

    // The committer and its leaf (12.3, 12.7).
    let committer_old = match commit.committer {
        Committer::Member(index) => {
            let old_leaf = group.leaf(index).ok_or(CommitError::Leaf)?;
            if commit
                .proposals
                .iter()
                .any(|p| matches!(p, ProposalView::ExternalInit))
            {
                return Err(CommitError::Proposal(
                    "an ExternalInit in a member's commit",
                ));
            }
            if public && old_leaf.is_guest() {
                return Err(CommitError::Guest);
            }
            check_new_leaf(old, old_leaf, path_leaf, t)?;
            Some(old_leaf)
        }
        Committer::External => {
            verdict.external = Some(check_external(group, old, commit, path_identity)?);
            let profile = path_leaf.profile.as_ref().ok_or(CommitError::Leaf)?;
            if profile.updated.abs_diff(t) > UPDATED_SKEW_MS {
                return Err(CommitError::Updated);
            }
            None
        }
    };
    if !path_leaf.encryption_key_ok || !commit.parent_keys_ok {
        return Err(CommitError::Leaf);
    }
    check_streak(group, commit, committer_uid, path_leaf)?;

    // Updates (12.3, 12.7, 12.10), each judged by its own post's `t`.
    for proposal in &commit.proposals {
        let ProposalView::Update {
            sender,
            leaf,
            reference,
        } = proposal
        else {
            continue;
        };
        let old_leaf = group.leaf(*sender).ok_or(CommitError::Leaf)?;
        if old_leaf.is_guest() {
            return Err(CommitError::Guest);
        }
        // The device processed the proposal, so it saw its post; a caller
        // that did not note its `t` cannot judge it (12.7).
        let update_t = post
            .proposal_time(reference)
            .ok_or(CommitError::Proposal("an Update whose post's t is unknown"))?;
        check_new_leaf(old, old_leaf, leaf, update_t)?;
        if leaf.streak() != 0 {
            return Err(CommitError::Streak);
        }
    }

    // Removes (12.7, 6.3, 6.4).
    let mut uses_role = false;
    let mut removes_own_others = false;
    let mut bulk = 0;
    let mut checked: BTreeSet<&Uid> = BTreeSet::new();
    if commit.committer != Committer::External {
        let role = old.role(committer_uid);
        for index in &removed {
            let leaf = group.leaf(*index).ok_or(CommitError::Remove)?;
            match removal_reason(group, old, commit, committer_uid, leaf, &removed, t)? {
                RemoveReason::Own => {
                    if Some(*index) != committer_old.map(|l| l.index) {
                        removes_own_others = true;
                    }
                }
                RemoveReason::SelfRemove => {}
                RemoveReason::Kick => uses_role = true,
                RemoveReason::Bulk { by_role } => {
                    uses_role |= by_role;
                    bulk += 1;
                }
                RemoveReason::Check => {
                    checked.insert(leaf.uid().ok_or(CommitError::Remove)?);
                    verdict.check_removals.push(*index);
                }
            }
        }
        // Bulk (12.7): owners and moderators are exempt, since `guests
        // none` removes every guest leaf in one commit (6.2).
        if role == Role::Member && bulk > group.bulk_limit() {
            return Err(CommitError::Bulk);
        }
        // For a check: one identity at most.
        if checked.len() > 1 {
            return Err(CommitError::CheckRemovals);
        }
    }

    // Adds (12.7, 6.1).
    let mut added: Vec<RisalaIdentity> = Vec::new();
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
        let (identity, by_role) = check_add(
            group,
            old,
            new,
            &removed,
            committer_uid,
            key_package,
            *by_external_proposal,
            t,
        )?;
        uses_role |= by_role;
        added.push(identity);
    }

    // The conversation extension (12.4, 12.7, 6.2-6.4, 7.8).
    let changes_extensions = commit
        .proposals
        .iter()
        .any(|p| matches!(p, ProposalView::GroupContextExtensions));
    let after: Vec<&LeafView> = group
        .leaves
        .iter()
        .filter(|leaf| !removed.contains(&leaf.index))
        .collect();
    let mut after_uids: Vec<&Uid> = after.iter().filter_map(|leaf| leaf.uid()).collect();
    after_uids.extend(added.iter().map(|identity| &identity.uid));
    if commit.committer == Committer::External {
        after_uids.push(committer_uid);
    }
    let identities_after = after_uids
        .iter()
        .filter(|uid| !uid.is_guest())
        .collect::<BTreeSet<_>>()
        .len();
    if changes_extensions {
        if new.mailbox != old.mailbox && group.moved_box != Some(new.mailbox) {
            return Err(CommitError::Extension(
                "a move to a box that is not derived from the epoch".into(),
            ));
        }
        let rights = ChangeRights {
            role: group.effective_role(committer_uid),
            may_move_box: commit.proposals.len() == 1,
            may_go_epochal: old.kind == ConversationKind::PrivateRoom
                && old.confirm == ConfirmMode::Pairwise
                && identities_after > MAX_PAIRWISE_MEMBERS,
        };
        let change = old
            .check_change(new, &rights)
            .map_err(|e| CommitError::Extension(e.to_string()))?;
        uses_role |= change.used_role;
    } else if new != old {
        return Err(CommitError::Extension("changed without a proposal".into()));
    }

    // The group after the commit (6.1, 6.2, 6.4, 12.7).
    for uid in &after_uids {
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
    if !public {
        let mut devices = BTreeSet::new();
        let existing = after
            .iter()
            .filter_map(|leaf| Some((leaf.uid()?.clone(), leaf.device_id()?)));
        let new_ones = added
            .iter()
            .filter_map(|identity| Some((identity.uid.clone(), identity.device_id?)));
        for device in existing.chain(new_ones) {
            if !devices.insert(device) {
                return Err(CommitError::SameDevice);
            }
        }
    }
    if !within_limits(new, after_uids.iter().copied()) {
        return Err(CommitError::TooLarge);
    }
    // A private room past 256 identities is epochal (6.2, 12.7).
    if new.kind == ConversationKind::PrivateRoom
        && new.confirm == ConfirmMode::Pairwise
        && identities_after > MAX_PAIRWISE_MEMBERS
    {
        return Err(CommitError::TooLarge);
    }
    verdict.authority = uses_role || removes_own_others || !verdict.check_removals.is_empty();
    Ok(verdict)
}

/// The checks of a leaf's new leaf node, from a commit's path or an
/// Update, against its old one (12.3, 12.7): the same credential, a
/// profile for an identity's leaf, an `updated` no lower than before and
/// within 10 minutes of the `t` of the post that carries it, an encryption
/// key that passes 12.2, and a new signature key only where 12.3 allows.
fn check_new_leaf(
    conversation: &RisalaConversation,
    old: &LeafView,
    new: &LeafView,
    t: u64,
) -> Result<(), CommitError> {
    if old.identity != new.identity || !new.encryption_key_ok {
        return Err(CommitError::Leaf);
    }
    match &new.profile {
        None if old.is_guest() => {}
        None => return Err(CommitError::Leaf),
        Some(profile) => {
            if profile.updated < old.updated() || profile.updated.abs_diff(t) > UPDATED_SKEW_MS {
                return Err(CommitError::Updated);
            }
        }
    }
    if old.signature_key != new.signature_key && !signature_key_change_allowed(conversation, old, t)
    {
        return Err(CommitError::Leaf);
    }
    Ok(())
}

/// Whether a leaf may take a new signature key, in a leaf node carried by a
/// post with `t` (12.3): outside epochal groups, only while its
/// `leaf_node_source` is still `key_package`; in an epochal group, only if
/// `t` falls in a later period than the leaf's previous `updated` minus 10
/// minutes. That is once a period, or twice if the first change comes in
/// the period's first 20 minutes, since `updated` may run up to 10 minutes
/// ahead of `t`.
fn signature_key_change_allowed(conversation: &RisalaConversation, old: &LeafView, t: u64) -> bool {
    match conversation.confirm {
        ConfirmMode::Epochal => {
            t / PERIOD_MS > old.updated().saturating_sub(UPDATED_SKEW_MS) / PERIOD_MS
        }
        ConfirmMode::Pairwise => old.from_key_package,
    }
}

/// The committer's `streak` (12.3, 12.7): the value 12.3 gives, and past 3,
/// outside the conversation with yourself, only for a commit whose only
/// proposals remove leaves of its own identity, or whose new `updated` is
/// at least 10 minutes after the highest `updated` among its identity's
/// leaves that have committed or been Updated.
fn check_streak(
    group: &GroupView,
    commit: &CommitView,
    committer: &Uid,
    path_leaf: &LeafView,
) -> Result<(), CommitError> {
    let Some(profile) = &path_leaf.profile else {
        // A guest's leaf in its report conversation carries none (12.7).
        return Ok(());
    };
    let expected = group.expected_streak(committer);
    if profile.streak != expected {
        return Err(CommitError::Streak);
    }
    if expected <= STREAK_LIMIT || group.with_yourself() {
        return Ok(());
    }
    let own_removes_only = !commit.proposals.is_empty()
        && commit.proposals.iter().all(|p| match p {
            ProposalView::Remove(i) | ProposalView::SelfRemove(i) => {
                group.leaf(*i).and_then(LeafView::uid) == Some(committer)
            }
            _ => false,
        });
    // Leaves that never committed or were Updated are left out, so that a
    // copy of the credential cannot hold the identity back.
    let highest = group
        .leaves_of(committer)
        .filter(|leaf| !leaf.from_key_package)
        .map(LeafView::updated)
        .max()
        .unwrap_or(0);
    let waited = profile.updated >= highest.saturating_add(UPDATED_SKEW_MS);
    if own_removes_only || waited {
        Ok(())
    } else {
        Err(CommitError::Streak)
    }
}

/// Whether `committer` may kick `target` from a room (6.3, 6.4): owners
/// anyone but the last owner, moderators plain members, by their roles as
/// of the commit's epoch, a moderator counting as an owner in a room whose
/// owners are gone.
fn may_kick(
    conversation: &RisalaConversation,
    group: &GroupView,
    committer: &Uid,
    target: &Uid,
) -> bool {
    if conversation.kind == ConversationKind::Direct {
        return false;
    }
    match (group.effective_role(committer), conversation.role(target)) {
        (Role::Owner, Role::Owner) => conversation.owners.len() > 1,
        (Role::Owner, _) => true,
        (Role::Mod, Role::Member) => true,
        _ => false,
    }
}

/// Whether a member whose role is `committer` may act on the leaves of an
/// identity whose role is `target`, in a room (12.7): an owner's only an
/// owner, a moderator's an owner or a moderator, a plain member's anyone.
/// Leaves of the committer's own identity are always its own to act on.
fn may_act_on_role(committer: Role, target: Role) -> bool {
    match target {
        Role::Owner => committer == Role::Owner,
        Role::Mod => committer >= Role::Mod,
        Role::Member => true,
    }
}

/// The checks of an external commit (12.7), which appear only in public
/// rooms, by a leaf whose credential names an identity, with one
/// ExternalInit, adding only the committer's own leaf:
///
/// - a resync commit, by an identity that has a leaf before it, removes
///   the leaf that started the epoch, and may remove leaves of its own
///   identity, and nothing else;
/// - a rejoin, by an identity listed in `owners` or `mods`, removes only
///   leaves of its own identity.
fn check_external(
    group: &GroupView,
    conversation: &RisalaConversation,
    commit: &CommitView,
    joiner: &RisalaIdentity,
) -> Result<External, CommitError> {
    if conversation.kind != ConversationKind::PublicRoom || joiner.is_guest() {
        return Err(CommitError::External);
    }
    if conversation.is_banned(&joiner.uid) {
        return Err(CommitError::Add);
    }
    let mut inits = 0;
    let mut foreign = Vec::new();
    for proposal in &commit.proposals {
        match proposal {
            ProposalView::ExternalInit => inits += 1,
            ProposalView::Remove(index) => {
                let leaf = group.leaf(*index).ok_or(CommitError::Remove)?;
                if leaf.uid() != Some(&joiner.uid) {
                    foreign.push(*index);
                }
            }
            _ => return Err(CommitError::External),
        }
    }
    if inits != 1 {
        return Err(CommitError::External);
    }
    let had_leaf = group.leaves_of(&joiner.uid).next().is_some();
    let listed = conversation.role(&joiner.uid) != Role::Member;
    if !had_leaf && !listed {
        return Err(CommitError::External);
    }
    let removes_starter = group
        .started_by
        .is_some_and(|s| commit.removed_indices().contains(&s));
    match foreign.as_slice() {
        [index] if Some(*index) == group.started_by && had_leaf => Ok(External::Resync),
        [] if listed => Ok(External::Rejoin),
        // The leaf that started the epoch was of the joiner's own identity.
        [] if had_leaf && removes_starter => Ok(External::Resync),
        [] => Err(CommitError::External),
        _ => Err(CommitError::Remove),
    }
}

/// Why one leaf may be removed by a member's commit (12.7), or why not.
fn removal_reason(
    group: &GroupView,
    conversation: &RisalaConversation,
    commit: &CommitView,
    committer: &Uid,
    leaf: &LeafView,
    removed: &BTreeSet<LeafNodeIndex>,
    t: u64,
) -> Result<RemoveReason, CommitError> {
    let identity = leaf.identity.as_ref().ok_or(CommitError::Remove)?;
    let public = conversation.kind == ConversationKind::PublicRoom;
    if identity.uid == *committer {
        return Ok(RemoveReason::Own);
    }
    if commit.self_removes(leaf.index) {
        return Ok(RemoveReason::SelfRemove);
    }
    let kicks_all = group
        .leaves_of(&identity.uid)
        .all(|l| removed.contains(&l.index));
    if kicks_all && may_kick(conversation, group, committer, &identity.uid) {
        return Ok(RemoveReason::Kick);
    }
    if identity.is_guest() || group.is_stale(leaf, t) {
        return Ok(RemoveReason::Bulk { by_role: false });
    }
    if public {
        // A copy, whose other leaf stays (12.7): removing both would need
        // a reason for the other too, which it gets on its own.
        let copy = group.leaves.iter().any(|other| {
            other.index != leaf.index
                && !removed.contains(&other.index)
                && other.same_device(leaf)
                && !other.from_key_package
                && other.updated() > leaf.updated()
        });
        if copy {
            return Ok(RemoveReason::Bulk { by_role: false });
        }
        if leaf.from_key_package {
            if leaf.updated().saturating_add(UNUSED_AFTER_MS) < t {
                return Ok(RemoveReason::Bulk { by_role: false });
            }
            if group.effective_role(committer) >= Role::Mod {
                return Ok(RemoveReason::Bulk { by_role: true });
            }
        }
        return Err(CommitError::Remove);
    }
    // For a check. In a room, a leaf of an identity listed in `owners` only
    // by a leaf of that identity or of an owner, and one listed in `mods`
    // only by that identity, an owner or a moderator, as of the epoch the
    // commit is for: no member can take out, by a claim that nobody can
    // check, those who could add it back (12.7, 6.3). The committer's own
    // identity was handled above.
    if conversation.kind != ConversationKind::Direct
        && !may_act_on_role(
            group.effective_role(committer),
            conversation.role(&identity.uid),
        )
    {
        return Err(CommitError::Remove);
    }
    Ok(RemoveReason::Check)
}

/// The checks of one Add (12.7). Returns the added identity, and whether
/// only a role allowed it (an invitation).
#[allow(clippy::too_many_arguments)]
fn check_add(
    group: &GroupView,
    old: &RisalaConversation,
    new: &RisalaConversation,
    removed: &BTreeSet<LeafNodeIndex>,
    committer: &Uid,
    key_package: &KeyPackage,
    by_external_proposal: bool,
    t: u64,
) -> Result<(RisalaIdentity, bool), CommitError> {
    let (identity, _last_resort) =
        check_key_package_contents(key_package).map_err(CommitError::KeyPackage)?;
    if !lifetime_acceptable_at(key_package.life_time(), t) {
        return Err(CommitError::KeyPackage(KeyPackageError::Lifetime));
    }
    match RisalaProfile::of_leaf(key_package.leaf_node()) {
        Some(profile) => {
            if profile.streak != 0 {
                return Err(CommitError::Streak);
            }
            if profile.updated > t.saturating_add(UPDATED_SKEW_MS) {
                return Err(CommitError::Updated);
            }
        }
        None if identity.is_guest() => {}
        None => return Err(CommitError::KeyPackage(KeyPackageError::Profile)),
    }
    let uid = &identity.uid;
    if old.is_banned(uid) || new.is_banned(uid) {
        return Err(CommitError::Add);
    }
    let public = old.kind == ConversationKind::PublicRoom;
    if public {
        // Every device joins a public room by itself, by external proposal,
        // from a KeyPackage with no binding, committed by an identity's
        // leaf (6.1, 12.3); nobody adds anyone by value.
        if !by_external_proposal {
            return Err(CommitError::Add);
        }
        if !has_no_binding(key_package) {
            return Err(CommitError::KeyPackage(KeyPackageError::Binding));
        }
        if committer.is_guest() || (identity.is_guest() && old.guests == GuestMode::None) {
            return Err(CommitError::Add);
        }
        return Ok((identity, false));
    }
    if by_external_proposal || identity.is_guest() {
        return Err(CommitError::Add);
    }
    binding_fits_credential(key_package, &identity).map_err(CommitError::KeyPackage)?;
    if uid == committer {
        return Ok((identity, false));
    }
    if old.kind == ConversationKind::Direct {
        let participant = old
            .direct_participants()
            .is_some_and(|participants| participants.contains(uid));
        // A guest's report conversation: after the commit that adds the
        // identity's devices, the guest's leaf adds nobody (12.7).
        if committer.is_guest() && group.leaves_of(uid).next().is_some() {
            return Err(CommitError::Guest);
        }
        return if participant {
            Ok((identity, false))
        } else {
            Err(CommitError::Add)
        };
    }
    // A room. Whichever rule below allows it, a device of an identity
    // listed in `owners`, before or after the commit, is added only by a
    // leaf of that identity or of an owner, and one listed in `mods` only
    // by that identity, an owner or a moderator: whoever adds a leaf may
    // hold it, so no Add hands anyone control of a leaf with a role above
    // its own (12.7). The committer's own identity was handled above, so
    // here that takes a role: an authority commit.
    let role = group.effective_role(committer);
    let listed = old.role(uid).max(new.role(uid));
    if !may_act_on_role(role, listed) {
        return Err(CommitError::Add);
    }
    let by_role = listed != Role::Member;
    // An identity that has a leaf after the commit, by any member: only
    // leaves the commit keeps count, so a plain member cannot remove an
    // identity's last leaf for a check and add it back (12.7).
    if group
        .leaves_of(uid)
        .any(|leaf| !removed.contains(&leaf.index))
    {
        return Ok((identity, by_role));
    }
    // A device whose stale leaf the same commit removes, by any member.
    if group.leaves.iter().any(|leaf| {
        removed.contains(&leaf.index)
            && leaf.identity.as_ref() == Some(&identity)
            && group.is_stale(leaf, t)
    }) {
        return Ok((identity, by_role));
    }
    // An invitation: owners and moderators, and only owners for an
    // identity listed in `owners` or `mods` (12.7).
    let allowed = if listed != Role::Member {
        role == Role::Owner
    } else {
        role >= Role::Mod
    };
    if allowed {
        Ok((identity, true))
    } else {
        Err(CommitError::Add)
    }
}

// ---------------------------------------------------------------------
// Key checks

/// What the device itself has seen that may explain a removal for a check
/// (12.7), besides key files and the key log.
#[derive(Debug, Clone, Copy)]
pub struct Seen<'a> {
    /// The device's own uid.
    pub own_uid: &'a Uid,
    /// The leaves whose RESYNC lines (12.9) the device read in this epoch.
    pub resyncs: &'a [LeafNodeIndex],
    /// The leaves that are impostors to the device (12.10, 12.7).
    pub impostors: &'a [LeafNodeIndex],
}

/// What the key checks of a valid commit found (12.7). None of it makes
/// the commit invalid; each failure leads to a repair commit after a random
/// wait of up to 10 minutes, unless another device makes it first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyReport {
    /// Added devices whose binding does not verify under a current device
    /// key of the identity, or that were removed by record: the repair
    /// removes their leaves, for a check.
    pub failed_adds: Vec<RisalaIdentity>,
    /// Added devices whose key file or record is not known yet: their
    /// leaves are unconfirmed, and the device sends nothing in the group
    /// until a later check passes.
    pub unchecked_adds: Vec<RisalaIdentity>,
    /// Devices of the device's own identity removed for a check with no
    /// reason it can see, whose device is current and whose identity is
    /// neither forked nor missing its keys: the removal failed, and the
    /// repair adds them again from new KeyPackages, as its own identity's.
    pub failed_removals: Vec<RisalaIdentity>,
    /// Leaves of another identity removed for a check with no reason the
    /// device can see: the removal stands, as one it could not check, and
    /// the device warns the user, naming the member who made the commit.
    /// Removing never lets anyone new read, and another device may have
    /// seen a fork, missing keys or an impostor that this one does not.
    pub unexplained_removals: Vec<LeafNodeIndex>,
    /// Leaves of the device's own identity removed for a check whose facts
    /// it cannot fetch yet: the removal stands for now, and the device
    /// checks again later.
    pub unchecked_removals: Vec<LeafNodeIndex>,
    /// Leaves of the device's own identity that a commit by another leaf
    /// of its identity removed, whose device is still current, and that
    /// the commit does not add again: the device tells the user, as for
    /// ALERT (4.5), since it may be a stolen device racing its own removal
    /// (4.8).
    pub own_removed_by_own: Vec<LeafNodeIndex>,
    /// Whether the committer's device has been removed by record: the
    /// device removes its leaf, for a check, as an impostor's.
    pub committer_removed: bool,
    /// Whether that could not be checked yet.
    pub committer_unchecked: bool,
}

/// The key checks of a commit that passed the group checks (12.7), outside
/// public rooms, which have none. `group` is the group as of the commit's
/// epoch, and `seen` what the device itself saw.
pub fn key_checks(
    group: &GroupView,
    commit: &CommitView,
    verdict: &Verdict,
    facts: &dyn KeyFacts,
    seen: &Seen<'_>,
) -> KeyReport {
    let mut report = KeyReport::default();
    if group
        .conversation
        .as_ref()
        .is_ok_and(|c| c.kind == ConversationKind::PublicRoom)
    {
        return report;
    }
    for proposal in &commit.proposals {
        let ProposalView::Add { key_package, .. } = proposal else {
            continue;
        };
        let Ok(identity) = RisalaIdentity::from_credential(key_package.leaf_node().credential())
        else {
            continue;
        };
        let Some(device_id) = identity.device_id else {
            continue;
        };
        match (
            facts.current_device_key(&identity.uid, &device_id),
            facts.device_removed(&identity.uid, &device_id),
        ) {
            (_, Fact::Known(true)) | (Fact::Known(None), _) => report.failed_adds.push(identity),
            (Fact::Known(Some(key)), _) => {
                if check_binding(key_package, &identity, &key).is_err() {
                    report.failed_adds.push(identity);
                }
            }
            (Fact::Unknown, _) => report.unchecked_adds.push(identity),
        }
    }
    let committer = match commit.committer {
        Committer::Member(index) => group.leaf(index).and_then(|leaf| leaf.identity.as_ref()),
        Committer::External => None,
    };
    if let Some(identity) = committer
        && let Some(device_id) = identity.device_id
    {
        match facts.device_removed(&identity.uid, &device_id) {
            Fact::Known(removed) => report.committer_removed = removed,
            Fact::Unknown => report.committer_unchecked = true,
        }
    }
    let added = commit.added_identities();
    // Removals of the device's own identity's leaves by its own identity
    // (12.7): fine, but suspicious if the device is still current.
    if let Some(committer) = committer
        && committer.uid == *seen.own_uid
    {
        for index in commit.removed_indices() {
            let Some(identity) = group.leaf(index).and_then(|leaf| leaf.identity.as_ref()) else {
                continue;
            };
            let Some(device_id) = identity.device_id else {
                continue;
            };
            if identity == committer || identity.uid != *seen.own_uid || added.contains(identity) {
                continue;
            }
            if let Fact::Known(Some(_)) = facts.current_device_key(&identity.uid, &device_id) {
                report.own_removed_by_own.push(index);
            }
        }
    }
    for index in &verdict.check_removals {
        let Some(identity) = group.leaf(*index).and_then(|leaf| leaf.identity.clone()) else {
            continue;
        };
        let Some(device_id) = identity.device_id else {
            continue;
        };
        // Added again in the same commit: nothing to repair.
        if added.contains(&identity) {
            continue;
        }
        // A reason the device can see itself.
        if seen.resyncs.contains(index) || seen.impostors.contains(index) {
            continue;
        }
        let removed = facts.device_removed(&identity.uid, &device_id);
        let retired = facts.identity_retired(&identity.uid);
        let forked = facts.forked_or_missing(&identity.uid);
        let reason = [&removed, &retired, &forked]
            .iter()
            .any(|fact| **fact == Fact::Known(true));
        if reason {
            continue;
        }
        // Only for its own identity does a device know whether the removal
        // failed; the others' removals it could not check stand (12.7).
        if identity.uid != *seen.own_uid {
            report.unexplained_removals.push(*index);
            continue;
        }
        match (facts.current_device_key(&identity.uid, &device_id), forked) {
            (Fact::Known(Some(_)), Fact::Known(false)) => report.failed_removals.push(identity),
            (Fact::Known(None), _) => {}
            _ => report.unchecked_removals.push(*index),
        }
    }
    report
}

#[cfg(test)]
mod tests;

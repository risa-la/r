//! The checks devices make of every group they join and every commit they
//! apply (12.7, 6.1-6.4), and that a server makes of a public room's
//! commits (12.6).
//!
//! A commit gets two kinds of check (12.7):
//!
//! - **Group checks** ([`check_commit`]) use only the group's state, the
//!   commit, the post that carries it (its `t` and `next`, [`CommitPost`]),
//!   and what the device saw of the group's recent commits ([`History`]).
//!   Every device that applied the same posts reaches the same answer. A
//!   commit that fails one is invalid. A server runs the same checks on a
//!   public room's commits, with `t` from its own clock.
//! - **Key checks** ([`key_checks`]) use key files and the key log, which
//!   devices fetch at different times. They never make a commit invalid:
//!   they only lead to repairs by later commits.
//!
//! Some group checks look back up to 16 epochs or 24 hours. A device that
//! joined since, by Welcome, cannot make them, and applies the commit as it
//! would one whose key checks it cannot make yet; [`Verdict::unchecked`]
//! says which (12.7).
//!
//! The checks are pure functions over a [`GroupView`], the group as of the
//! epoch a commit is for, and a [`CommitView`], what the commit does. Both
//! are read from OpenMLS's types ([`GroupView::of`], [`CommitView::of`]).

use std::collections::{BTreeMap, BTreeSet};

use openmls::group::{QueuedProposal, StagedCommit};
use openmls::prelude::{
    KeyPackage, LeafNode, LeafNodeIndex, Proposal, ProposalOrRefType, PublicGroup, Sender,
};
use openmls::treesync::LeafNodeSource;
use risala_proto::names::{Room, Uid};
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
/// The most identities, guests included, in a public room (6.1).
pub const MAX_PUBLIC_IDENTITIES: usize = 10_000;
/// The most leaves in a public room (6.1).
pub const MAX_PUBLIC_LEAVES: usize = 32_768;
/// The most members a private room may have while it is `pairwise`
/// (6.2, 12.10).
pub const MAX_PAIRWISE_MEMBERS: usize = 256;
/// How much older than the group's median `updated` a leaf's must be for
/// anyone to remove it as stale: 35 days, in ms (12.7).
pub const STALE_AFTER_MS: u64 = 35 * 24 * 60 * 60 * 1000;
/// How long a device may go without committing its own leaf in a group:
/// a week, in ms (12.7).
pub const REFRESH_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// A period of epochal confirmation, a UTC day, in ms (12.10).
pub const PERIOD_MS: u64 = 24 * 60 * 60 * 1000;
/// How far a leaf's new `updated` may be from the `t` of the post that
/// carries it, and how long after its previous one a leaf may commit again
/// past its streak: 10 minutes, in ms (12.3, 12.7).
pub const UPDATED_SKEW_MS: u64 = 10 * 60 * 1000;
/// The most epochs in a row a leaf may start before it has to wait
/// (12.7).
pub const STREAK_LIMIT: u8 = 3;
/// How many epochs back the group checks look: 16 (12.7).
pub const LOOKBACK_EPOCHS: u64 = 16;
/// How far back by `t` an impostor repair undoes, and how long after a
/// resync commit its stragglers may be removed: 24 hours, in ms (12.7).
pub const LOOKBACK_MS: u64 = 24 * 60 * 60 * 1000;
/// How long a public room's leaf must have been quiet to be removed as
/// inactive by a later leaf of the same device: 48 hours, in ms (12.7).
pub const INACTIVE_AFTER_MS: u64 = 48 * 60 * 60 * 1000;
/// The most commits a [`History`] keeps; older ones beyond the look-back
/// windows are dropped first.
pub const MAX_HISTORY_COMMITS: usize = 8_192;

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
pub trait KeyFacts {
    /// The raw device key of `uid`'s device `device_id`, if that device is
    /// current in `uid`'s key file and its record has been accepted (4.5):
    /// `Known(Some(key))`, or `Known(None)` if it is not.
    fn current_device_key(&self, uid: &Uid, device_id: &DeviceId) -> Fact<Option<Vec<u8>>>;

    /// Whether `uid`'s chain has removed the device `device_id` by record
    /// (4.4), as far as the device has accepted it.
    fn device_removed(&self, uid: &Uid, device_id: &DeviceId) -> Fact<bool>;

    /// Whether `uid`'s chain ends with a `retire` record (4.4).
    fn identity_retired(&self, uid: &Uid) -> Fact<bool>;
}

/// The post that carries a commit or proposal, as the checks need it
/// (5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitPost {
    /// The post's `t`, when the server accepted it, in ms since
    /// 1970-01-01T00:00:00Z. A server checking a public room's commit uses
    /// its own clock, which gives the post its `t`.
    pub t: u64,
    /// The post's `next`, the SHA-384 hash of the send token of the epoch a
    /// commit creates (5.2, 12.6). Only commits have one.
    pub next: Option<[u8; HASH_LEN]>,
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

    /// The `updated` that the stale rule uses (12.7): for a leaf that has
    /// not committed since it was added, the end of its KeyPackage's
    /// lifetime if that is later.
    pub fn stale_updated(&self) -> u64 {
        self.updated().max(self.lifetime_end.unwrap_or(0))
    }

    /// Whether this leaf may have committed since `since`, by its own
    /// `updated`, which stays within 10 minutes of the `t` of each of its
    /// commits (12.3): a leaf that has never committed, or whose `updated`
    /// is older, cannot have.
    fn may_have_committed_since(&self, since: u64) -> bool {
        !self.from_key_package && self.updated().saturating_add(UPDATED_SKEW_MS) >= since
    }
}

/// A group as of one epoch: its conversation extension and its leaves.
#[derive(Debug, Clone)]
pub struct GroupView {
    /// The epoch.
    pub epoch: u64,
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
            epoch: group.group_context().epoch().as_u64(),
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
        self.leaves
            .iter()
            .filter(move |leaf| leaf.uid() == Some(uid))
    }

    /// The group's median `updated` (12.7): the value at position
    /// floor(n/2), counting from 0, of the sorted `updated` of the leaves
    /// that carry a profile. `None` if no leaf has one.
    ///
    /// 12.7 also says that a leaf that never committed counts the end of
    /// its KeyPackage's lifetime as its `updated`. That is used for the
    /// leaf being judged ([`LeafView::stale_updated`]) but not here: a group
    /// whose leaves were mostly just added would otherwise have a median up
    /// to 12 weeks in the future, and every leaf that had committed would
    /// be stale at once.
    pub fn median_updated(&self) -> Option<u64> {
        let mut values: Vec<u64> = self
            .leaves
            .iter()
            .filter_map(|leaf| leaf.profile.as_ref().map(|p| p.updated))
            .collect();
        values.sort_unstable();
        values.get(values.len() / 2).copied()
    }

    /// Whether the leaf is stale: its `updated` is more than 35 days older
    /// than the group's median `updated` (12.7).
    pub fn is_stale(&self, leaf: &LeafView) -> bool {
        self.median_updated()
            .is_some_and(|median| median.saturating_sub(leaf.stale_updated()) > STALE_AFTER_MS)
    }

    /// The stale leaves, which any member may remove, at most
    /// [`max_stale_removals`](Self::max_stale_removals) in a commit (12.7).
    pub fn stale_leaves(&self) -> Vec<LeafNodeIndex> {
        self.leaves
            .iter()
            .filter(|leaf| self.is_stale(leaf))
            .map(|leaf| leaf.index)
            .collect()
    }

    /// The most stale leaves one commit may remove: max(1, floor(n/10)),
    /// where n is the number of leaves (12.7).
    pub fn max_stale_removals(&self) -> usize {
        (self.leaves.len() / 10).max(1)
    }

    /// Whether some identity in `owners` has a leaf (6.3). In a room whose
    /// owners are gone, moderators may do what owners may.
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
}

/// Whether the device should commit a fresh leaf now: its own leaf's
/// profile says it was last committed, or updated through an Update, more
/// than a week ago, by `now_ms` (12.7).
pub fn needs_refresh(own_profile: &RisalaProfile, now_ms: u64) -> bool {
    now_ms.saturating_sub(own_profile.updated) > REFRESH_AFTER_MS
}

// ---------------------------------------------------------------------
// History

/// How a leaf left a group, for the rule that lets any member add back a
/// device that had a leaf in the last 16 epochs (12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Removal {
    /// By the commit of its own SelfRemove (6.1).
    SelfRemove,
    /// By a commit of an owner or moderator who may kick it (6.4).
    Kick,
    /// For any other reason, for example a key check.
    Other,
}

/// A leaf a commit removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedLeaf {
    /// Its index.
    pub index: u32,
    /// Its uid.
    pub uid: String,
    /// Its device id, empty for a guest.
    pub device_id: Vec<u8>,
    /// How it was removed.
    pub how: Removal,
}

/// A leaf a commit added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddedLeaf {
    /// Its index.
    pub index: u32,
    /// Its uid.
    pub uid: String,
    /// Its device id, empty for a guest.
    pub device_id: Vec<u8>,
}

/// A commit a device applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRecord {
    /// The epoch it was for; it started the next one.
    pub epoch: u64,
    /// Its post's `t`.
    pub t: u64,
    /// The committer's leaf index after the commit (a resync commit's
    /// joiner has a new one).
    pub committer: u32,
    /// The committer's uid.
    pub committer_uid: String,
    /// The encoded conversation extension before and after, if it changed.
    pub extension_change: Option<(Vec<u8>, Vec<u8>)>,
    /// The leaves it removed.
    pub removed: Vec<RemovedLeaf>,
    /// The leaves it added, the joiner of an external commit included.
    pub added: Vec<AddedLeaf>,
    /// Whether it was an authority commit (12.7), which an impostor repair
    /// may undo.
    pub authority: bool,
}

/// What a public room's devices remember of the last resync commit
/// (12.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResyncState {
    /// The resync commit's `t`.
    pub t: u64,
    /// The leaves that have committed or been added since.
    pub active: BTreeSet<u32>,
}

/// What a device, or a public room's server, saw of a group's recent
/// commits and proposals, for the group checks that look back (12.7). The
/// caller keeps it with the group, and updates it with each commit it
/// applies ([`crate::group::apply_commit`],
/// [`crate::group::merge_own_commit`]) and each RESYNC line and Update
/// proposal it reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct History {
    /// The first epoch whose commit this history holds: the epoch the
    /// device joined in.
    pub since_epoch: u64,
    /// The earliest `t` from which this history holds every commit.
    pub since_t: u64,
    /// The leaf that started the current epoch: the committer of the last
    /// commit, or for a device that joined by Welcome, the GroupInfo's
    /// signer (12.3). `None` in epoch 0.
    pub started_by: Option<u32>,
    /// Recent commits, oldest first, for 16 epochs and 24 hours.
    pub commits: Vec<CommitRecord>,
    /// The `t` of the commit that added each leaf added since
    /// `since_epoch`, by leaf index.
    pub added_at: BTreeMap<u32, u64>,
    /// The newest epoch in which each leaf posted RESYNC (12.9), by leaf
    /// index.
    pub resyncs: BTreeMap<u32, u64>,
    /// The `t` of the posts of the current epoch's Update proposals, by
    /// ProposalRef (12.3).
    pub update_times: Vec<(Vec<u8>, u64)>,
    /// In a public room, the last resync commit, for 24 hours (12.7).
    pub resync: Option<ResyncState>,
}

/// Whether a group check that looks back could be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup<T> {
    Known(T),
    Unknown,
}

impl History {
    /// The history of a group this device has just created, in epoch 0, at
    /// `t`: it holds everything.
    pub fn created(t: u64) -> History {
        History {
            since_epoch: 0,
            since_t: 0,
            added_at: BTreeMap::from([(0, t)]),
            ..History::default()
        }
    }

    /// The history of a group this device has just joined by Welcome, in
    /// `epoch`, whose GroupInfo `started_by` signed, at about `t` (by the
    /// first post it applies, or its clock), with its own leaf at
    /// `own_index`. It holds nothing earlier.
    pub fn joined(epoch: u64, started_by: u32, t: u64, own_index: u32) -> History {
        History {
            since_epoch: epoch,
            since_t: t,
            started_by: Some(started_by),
            added_at: BTreeMap::from([(own_index, t)]),
            ..History::default()
        }
    }

    /// Notes that the leaf at `index` posted RESYNC in `epoch` (12.7,
    /// 12.9).
    pub fn note_resync(&mut self, index: LeafNodeIndex, epoch: u64) {
        let entry = self.resyncs.entry(index.u32()).or_insert(epoch);
        *entry = (*entry).max(epoch);
    }

    /// Notes the `t` of the post of an Update proposal, by its ProposalRef
    /// (12.3).
    pub fn note_update(&mut self, reference: &[u8], t: u64) {
        if !self.update_times.iter().any(|(r, _)| r == reference) {
            self.update_times.push((reference.to_vec(), t));
        }
    }

    fn update_time(&self, reference: &[u8]) -> Option<u64> {
        self.update_times
            .iter()
            .find(|(r, _)| r == reference)
            .map(|(_, t)| *t)
    }

    /// Whether this history holds every commit of the epochs from `epoch`
    /// on.
    fn covers_epoch(&self, epoch: u64) -> bool {
        self.since_epoch <= epoch
    }

    /// Whether this history holds every commit whose `t` is `t` or later.
    fn covers_time(&self, t: u64) -> bool {
        self.since_t <= t
    }

    /// The first epoch of the last 16, as of `epoch` (12.7).
    fn lookback_epoch(epoch: u64) -> u64 {
        epoch.saturating_sub(LOOKBACK_EPOCHS - 1)
    }

    /// The `t` of the commit that ended `epoch`, if this history holds it
    /// (12.9).
    pub fn epoch_end(&self, epoch: u64) -> Option<u64> {
        self.commits
            .iter()
            .rev()
            .find(|record| record.epoch == epoch)
            .map(|record| record.t)
    }

    /// The commits whose committer was the leaf now at `index`, newest
    /// first, back to the commit that added it.
    fn commits_by(&self, index: u32) -> Vec<&CommitRecord> {
        let mut out = Vec::new();
        for record in self.commits.iter().rev() {
            if record.committer == index {
                out.push(record);
            }
            // Before this, another leaf held the index; a resync commit's
            // joiner added itself, and counts.
            if record.added.iter().any(|a| a.index == index)
                || record.removed.iter().any(|r| r.index == index)
            {
                break;
            }
        }
        out
    }

    /// When the leaf at `index` was added: `Known(Some(t))`, `Known(None)`
    /// if it was added before this history starts, which is known to be
    /// before `t_floor`, or `Unknown`.
    fn added_time(&self, index: u32, t_floor: u64) -> Lookup<Option<u64>> {
        match self.added_at.get(&index) {
            Some(t) => Lookup::Known(Some(*t)),
            None if self.covers_time(t_floor) => Lookup::Known(None),
            None => Lookup::Unknown,
        }
    }

    /// Whether `uid`'s device may be added back by any member: it had a
    /// leaf in one of the last 16 epochs, and its last leaf was not removed
    /// by its SelfRemove or a kick (12.7).
    fn may_add_back(&self, uid: &Uid, epoch: u64) -> Lookup<bool> {
        let from = History::lookback_epoch(epoch);
        let last = self
            .commits
            .iter()
            .rev()
            .filter(|record| record.epoch >= from)
            .flat_map(|record| record.removed.iter().rev())
            .find(|removed| removed.uid == uid.as_str());
        match last {
            Some(removed) => Lookup::Known(removed.how == Removal::Other),
            None if self.covers_epoch(from) => Lookup::Known(false),
            None => Lookup::Unknown,
        }
    }

    /// Whether the leaf at `index` posted RESYNC in one of the last 16
    /// epochs (12.7).
    fn posted_resync(&self, index: LeafNodeIndex, epoch: u64) -> Lookup<bool> {
        let from = History::lookback_epoch(epoch);
        match self.resyncs.get(&index.u32()) {
            Some(e) if *e >= from => Lookup::Known(true),
            _ if self.covers_epoch(from) => Lookup::Known(false),
            _ => Lookup::Unknown,
        }
    }

    /// The commits of the leaf at `index` whose `t` is at most 24 hours
    /// before `t`, oldest first, for an impostor repair (12.7); none unless
    /// one of them was an authority commit, since only those make a device
    /// challenge the leaf and find an impostor.
    fn repairable_commits(&self, index: u32, t: u64) -> Vec<&CommitRecord> {
        let from = t.saturating_sub(LOOKBACK_MS);
        let mut out: Vec<&CommitRecord> = self
            .commits_by(index)
            .into_iter()
            .filter(|record| record.t >= from)
            .collect();
        if !out.iter().any(|record| record.authority) {
            return Vec::new();
        }
        out.reverse();
        out
    }

    /// Whether the leaf at `index` has committed or been added since this
    /// history starts.
    fn active_since_start(&self, index: u32) -> bool {
        !self.commits_by(index).is_empty() || self.added_at.contains_key(&index)
    }

    /// Records a commit the device applied, or a public room's server
    /// accepted: `before` and `after` are the group as of the epoch it was
    /// for and the one it started, `commit` what it did, `verdict` what its
    /// checks found, and `post` its post (12.7).
    pub fn record(
        &mut self,
        before: &GroupView,
        commit: &CommitView,
        verdict: &Verdict,
        after: &GroupView,
        post: &CommitPost,
    ) {
        let removed_indices = commit.removed_indices();
        let old = before.conversation.as_ref().ok();
        let committer_uid = commit.path_leaf.as_ref().and_then(LeafView::uid).cloned();
        let mut removed = Vec::new();
        for index in &removed_indices {
            let Some(leaf) = before.leaf(*index) else {
                continue;
            };
            let Some(identity) = &leaf.identity else {
                continue;
            };
            let how = if commit.self_removes(*index) {
                Removal::SelfRemove
            } else if let (Some(old), Some(committer), Committer::Member(_)) =
                (old, committer_uid.as_ref(), commit.committer)
            {
                if *committer != identity.uid && may_kick(old, before, committer, &identity.uid) {
                    Removal::Kick
                } else {
                    Removal::Other
                }
            } else {
                Removal::Other
            };
            removed.push(RemovedLeaf {
                index: index.u32(),
                uid: identity.uid.as_str().to_owned(),
                device_id: identity
                    .device_id
                    .map(|d| d.as_bytes().to_vec())
                    .unwrap_or_default(),
                how,
            });
        }
        let added: Vec<AddedLeaf> = after
            .leaves
            .iter()
            .filter(|leaf| {
                before.leaf(leaf.index).is_none() || removed_indices.contains(&leaf.index)
            })
            .filter_map(|leaf| {
                let identity = leaf.identity.as_ref()?;
                Some(AddedLeaf {
                    index: leaf.index.u32(),
                    uid: identity.uid.as_str().to_owned(),
                    device_id: identity
                        .device_id
                        .map(|d| d.as_bytes().to_vec())
                        .unwrap_or_default(),
                })
            })
            .collect();
        let committer = match commit.committer {
            Committer::Member(index) => index.u32(),
            Committer::External => after
                .leaves
                .iter()
                .find(|leaf| {
                    !leaf.from_key_package
                        && added.iter().any(|a| a.index == leaf.index.u32())
                        && leaf.identity.as_ref()
                            == commit.path_leaf.as_ref().and_then(|p| p.identity.as_ref())
                })
                .map_or(u32::MAX, |leaf| leaf.index.u32()),
        };
        let extension_change = match (&before.conversation, &after.conversation) {
            (Ok(a), Ok(b)) if a != b => Some((a.encode(), b.encode())),
            _ => None,
        };
        for leaf in &removed {
            self.added_at.remove(&leaf.index);
            self.resyncs.remove(&leaf.index);
        }
        for leaf in &added {
            self.added_at.insert(leaf.index, post.t);
        }
        self.update_times.clear();
        self.started_by = Some(committer);
        if verdict.resync {
            self.resync = Some(ResyncState {
                t: post.t,
                active: BTreeSet::from([committer]),
            });
        } else if let Some(resync) = &mut self.resync {
            if post.t.saturating_sub(resync.t) > LOOKBACK_MS {
                self.resync = None;
            } else {
                for leaf in &removed {
                    resync.active.remove(&leaf.index);
                }
                resync.active.insert(committer);
                resync.active.extend(added.iter().map(|a| a.index));
            }
        }
        self.commits.push(CommitRecord {
            epoch: before.epoch,
            t: post.t,
            committer,
            committer_uid: committer_uid
                .map(|u| u.as_str().to_owned())
                .unwrap_or_default(),
            extension_change,
            removed,
            added,
            authority: verdict.authority,
        });
        self.prune(after.epoch, post.t);
    }

    /// Drops commits outside both look-back windows, and the oldest beyond
    /// [`MAX_HISTORY_COMMITS`], after which this history starts later.
    fn prune(&mut self, epoch: u64, t: u64) {
        let from_epoch = History::lookback_epoch(epoch);
        let from_t = t.saturating_sub(LOOKBACK_MS + INACTIVE_AFTER_MS);
        self.commits
            .retain(|record| record.epoch >= from_epoch || record.t >= from_t);
        if self.commits.len() > MAX_HISTORY_COMMITS {
            let excess = self.commits.len() - MAX_HISTORY_COMMITS;
            self.commits.drain(..excess);
            if let Some(oldest) = self.commits.first() {
                self.since_epoch = self.since_epoch.max(oldest.epoch);
                self.since_t = self.since_t.max(oldest.t);
            }
        }
    }

    /// The leaf whose commit would start the next epoch's streak count for
    /// `index`: the `streak` a commit by that leaf must carry (12.3).
    pub fn expected_streak(&self, index: LeafNodeIndex, previous: u8) -> u8 {
        if self.started_by == Some(index.u32()) {
            previous.saturating_add(1)
        } else {
            1
        }
    }
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
    /// profile, or a leaf's encryption key fails the checks of 12.2.
    #[error("a leaf without a RisalaIdentity or a profile, or with a bad key")]
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

/// Whether a group of these leaves' uids is within the limits of 6.1.
/// Direct conversations have no limits of their own in 6.1: they get a
/// private room's.
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

// ---------------------------------------------------------------------
// Commits

/// Who made a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Committer {
    /// A member, by its leaf index as of the commit's epoch.
    Member(LeafNodeIndex),
    /// A device joining by external commit: in risala, a resync commit.
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
        /// Its ProposalRef, to find the `t` of its post in the [`History`].
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
        self.pending_self_removes.contains(&index)
            || self
                .proposals
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
    /// way.
    #[error("the commit holds {0}")]
    Proposal(&'static str),
    /// An external commit that is not a resync commit (12.7).
    #[error("an external commit that is not a resync commit")]
    External,
    /// The group before the commit is not one this device would be in.
    #[error("the group's conversation extension is not acceptable")]
    Group,
    /// The committer's leaf, or an Update's, changes its credential, or its
    /// signature key where 12.3 does not allow it, or has no profile, or an
    /// encryption key that fails the checks of 12.2.
    #[error("a leaf changes in a way 12.3 does not allow")]
    Leaf,
    /// A guest's leaf commits or proposes an Update in a public room, or
    /// adds someone in its report conversation after the first commit.
    #[error("a guest's leaf may not do this")]
    Guest,
    /// A new `updated` is below the leaf's previous one, or more than 10
    /// minutes from its post's `t` (12.3).
    #[error("an updated time out of bounds")]
    Updated,
    /// The committer's `streak` is not the one 12.3 gives, or is past 3
    /// without a reason (12.7).
    #[error("the commit's streak is wrong or too long")]
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
    /// Two leaves of one device after the commit, outside a public room.
    #[error("two leaves of one device")]
    SameDevice,
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

/// What the group checks of a valid commit found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Leaves that only a key check allows to be removed, outside public
    /// rooms (12.7): [`key_checks`] checks them.
    pub key_check_removals: Vec<LeafNodeIndex>,
    /// Leaves it removes as an impostor repair (12.7). A device that has
    /// confirmed one tells the user, and names the committer.
    pub repairs: Vec<LeafNodeIndex>,
    /// Whether it is a public room's resync commit (12.7).
    pub resync: bool,
    /// Whether it is an authority commit (12.7): one that only a role
    /// allows, that removes leaves of the committer's own identity other
    /// than its own, or that only an impostor repair allows. Devices
    /// challenge its committer if they have not confirmed it (12.10).
    pub authority: bool,
    /// The group checks that look back which this device could not make,
    /// since it joined since (12.7). The commit is applied all the same.
    pub unchecked: Vec<&'static str>,
}

/// Why a leaf may be removed (12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoveReason {
    Own,
    SelfRemove,
    Guest,
    Kick,
    Stale,
    Resync,
    Repair,
    KeyCheck,
    Inactive,
    AfterResync,
    /// A reason that looks back further than this device saw: the removal
    /// stands (12.7).
    Unchecked,
}

/// Checks a commit against the group as of the epoch it is for, the
/// device's [`History`], and the post that carries it (12.6, 12.7). These
/// are the group checks: they decide whether the commit is valid.
///
/// That `next` is the hash of the new epoch's send token needs that
/// epoch's secrets, so [`crate::group::check_received_commit`] checks it;
/// here it only has to be there.
pub fn check_commit(
    group: &GroupView,
    commit: &CommitView,
    history: &History,
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
            if let Some(new_profile) = &path_leaf.profile {
                let previous = old_leaf.profile.as_ref().map_or(0, |p| p.streak);
                let expected = history.expected_streak(index, previous);
                if new_profile.streak != expected {
                    return Err(CommitError::Streak);
                }
                if expected > STREAK_LIMIT {
                    let own_removes_only = !commit.proposals.is_empty()
                        && commit.proposals.iter().all(|p| match p {
                            ProposalView::Remove(i) | ProposalView::SelfRemove(i) => {
                                group.leaf(*i).and_then(LeafView::uid) == Some(committer_uid)
                            }
                            _ => false,
                        });
                    let waited =
                        new_profile.updated >= old_leaf.updated().saturating_add(UPDATED_SKEW_MS);
                    if !own_removes_only && !waited {
                        return Err(CommitError::Streak);
                    }
                }
            }
            Some(old_leaf)
        }
        Committer::External => {
            check_resync(group, old, commit, history, post, &mut verdict)?;
            None
        }
    };
    if !path_leaf.encryption_key_ok {
        return Err(CommitError::Leaf);
    }

    // Updates (12.3, 12.7, 12.10).
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
        match history.update_time(reference) {
            Some(update_t) => check_new_leaf(old, old_leaf, leaf, update_t)?,
            None => {
                // The device has not seen the Update's post, for example
                // after a restart that lost it: the rest still holds.
                check_new_leaf(old, old_leaf, leaf, leaf.updated())?;
                verdict.unchecked.push("the time of an Update proposal");
            }
        }
        if leaf.profile.as_ref().is_some_and(|p| p.streak != 0) {
            return Err(CommitError::Streak);
        }
    }

    // Impostor repairs: leaves of another identity that may have commits
    // to undo (12.7).
    let repair = RepairScope::of(group, commit, history, committer_uid, t);
    if !repair.unknown.is_empty() {
        verdict.unchecked.push("an impostor repair");
    }

    // Adds (12.7, 6.1).
    let mut added: Vec<RisalaIdentity> = Vec::new();
    let mut uses_role = false;
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
            commit,
            history,
            &repair,
            committer_uid,
            key_package,
            *by_external_proposal,
            t,
            &mut verdict,
        )?;
        uses_role |= by_role;
        added.push(identity);
    }

    // Removes (12.7, 6.3, 6.4).
    let mut stale_left = group.max_stale_removals();
    let mut removes_own_others = false;
    if commit.committer != Committer::External {
        for index in &removed {
            let leaf = group.leaf(*index).ok_or(CommitError::Remove)?;
            let reason = removal_reason(
                group,
                old,
                commit,
                history,
                &repair,
                committer_uid,
                &added,
                leaf,
                &removed,
                &mut stale_left,
                t,
                &mut verdict,
            )?;
            match reason {
                RemoveReason::Own if Some(*index) != committer_old.map(|l| l.index) => {
                    removes_own_others = true;
                }
                RemoveReason::Kick => uses_role = true,
                RemoveReason::Repair => verdict.repairs.push(*index),
                RemoveReason::KeyCheck => verdict.key_check_removals.push(*index),
                _ => {}
            }
        }
    }

    // The conversation extension (12.4, 12.7, 6.2-6.4, 7.8).
    let changes_extensions = commit
        .proposals
        .iter()
        .any(|p| matches!(p, ProposalView::GroupContextExtensions));
    let mut after: Vec<&LeafView> = group
        .leaves
        .iter()
        .filter(|leaf| !removed.contains(&leaf.index))
        .collect();
    let mut after_uids: Vec<&Uid> = after.iter().filter_map(|leaf| leaf.uid()).collect();
    after_uids.extend(added.iter().map(|identity| &identity.uid));
    if commit.committer == Committer::External {
        after_uids.push(committer_uid);
    }
    if changes_extensions {
        let crosses_pairwise_limit = old.kind == ConversationKind::PrivateRoom
            && old.confirm == ConfirmMode::Pairwise
            && after_uids.iter().collect::<BTreeSet<_>>().len() > MAX_PAIRWISE_MEMBERS;
        let rights = ChangeRights {
            role: group.effective_role(committer_uid),
            may_move_box: commit.proposals.len() == 1,
            may_go_epochal: crosses_pairwise_limit,
        };
        let restored = repair.restore(old, new);
        let candidate = restored.as_ref().unwrap_or(new);
        match old.check_change(candidate, &rights) {
            Ok(change) => uses_role |= change.used_role,
            Err(e) if repair.unknown.is_empty() => {
                return Err(CommitError::Extension(e.to_string()));
            }
            Err(_) => {}
        }
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
        after.retain(|leaf| leaf.device_id().is_some());
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
    if new.kind == ConversationKind::PrivateRoom && new.confirm == ConfirmMode::Pairwise {
        let members: BTreeSet<&&Uid> = after_uids.iter().collect();
        if members.len() > MAX_PAIRWISE_MEMBERS {
            return Err(CommitError::TooLarge);
        }
    }
    verdict.authority = uses_role || removes_own_others || !verdict.repairs.is_empty();
    verdict.unchecked.sort_unstable();
    verdict.unchecked.dedup();
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
    if old.signature_key != new.signature_key
        && !signature_key_change_allowed(conversation, old, new)
    {
        return Err(CommitError::Leaf);
    }
    Ok(())
}

/// Whether a leaf may take a new signature key (12.3): once right after
/// joining, while it still holds its KeyPackage's leaf node, which covers
/// a last-resort KeyPackage; and in an epochal group, in a later period
/// than its last commit or Update, by the `updated` of the profiles.
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

/// The checks of a resync commit, the only external commit risala has
/// (12.7): in a public room, by an identity that already has a leaf, with
/// one ExternalInit and no other proposal than Removes of the GroupInfo's
/// signer, the leaf that started the current epoch, and of the joiner's own
/// earlier leaves that are inactive.
fn check_resync(
    group: &GroupView,
    conversation: &RisalaConversation,
    commit: &CommitView,
    history: &History,
    post: &CommitPost,
    verdict: &mut Verdict,
) -> Result<(), CommitError> {
    let joiner = commit
        .path_leaf
        .as_ref()
        .and_then(|leaf| leaf.identity.as_ref())
        .ok_or(CommitError::Leaf)?;
    if conversation.kind != ConversationKind::PublicRoom
        || joiner.is_guest()
        || group.leaves_of(&joiner.uid).next().is_none()
    {
        return Err(CommitError::External);
    }
    if conversation.is_banned(&joiner.uid) {
        return Err(CommitError::Add);
    }
    let mut inits = 0;
    let mut signer_removed = false;
    let signer = history.started_by.map(LeafNodeIndex::new);
    for proposal in &commit.proposals {
        match proposal {
            ProposalView::ExternalInit => inits += 1,
            ProposalView::Remove(index) if Some(*index) == signer => signer_removed = true,
            ProposalView::Remove(index) => {
                let leaf = group.leaf(*index).ok_or(CommitError::Remove)?;
                if leaf.identity.as_ref() != Some(joiner) {
                    return Err(CommitError::Remove);
                }
                match inactive(leaf, history, post.t) {
                    Lookup::Known(true) => {}
                    Lookup::Known(false) => return Err(CommitError::Remove),
                    Lookup::Unknown => verdict.unchecked.push("an inactive leaf"),
                }
            }
            _ => return Err(CommitError::External),
        }
    }
    if inits != 1 || !signer_removed || signer.and_then(|s| group.leaf(s)).is_none() {
        return Err(CommitError::External);
    }
    let path = commit.path_leaf.as_ref().ok_or(CommitError::NoPath)?;
    let profile = path.profile.as_ref().ok_or(CommitError::Leaf)?;
    if profile.updated.abs_diff(post.t) > UPDATED_SKEW_MS {
        return Err(CommitError::Updated);
    }
    if profile.streak != 1 {
        return Err(CommitError::Streak);
    }
    verdict.resync = true;
    Ok(())
}

/// Whether a public room's leaf is inactive (12.7): its `updated`, or the
/// `t` of the commit that added it if later, is more than 48 hours before
/// `t`.
fn inactive(leaf: &LeafView, history: &History, t: u64) -> Lookup<bool> {
    let cutoff = t.saturating_sub(INACTIVE_AFTER_MS);
    if leaf.updated() >= cutoff {
        return Lookup::Known(false);
    }
    match history.added_time(leaf.index.u32(), cutoff) {
        Lookup::Known(added) => Lookup::Known(added.is_none_or(|added| added < cutoff)),
        Lookup::Unknown => Lookup::Unknown,
    }
}

/// What an impostor repair may undo (12.7): the commits, at most 24 hours
/// before the repair's `t`, of the leaves of another identity that the
/// commit removes.
struct RepairScope<'a> {
    /// The repairable leaves this device knows commits of, with those
    /// commits, oldest first.
    known: Vec<(LeafNodeIndex, Vec<&'a CommitRecord>)>,
    /// The removed leaves of another identity that may have committed in
    /// the window, but whose commits this device does not know, since it
    /// joined since.
    unknown: Vec<LeafNodeIndex>,
}

impl<'a> RepairScope<'a> {
    fn of(
        group: &GroupView,
        commit: &CommitView,
        history: &'a History,
        committer: &Uid,
        t: u64,
    ) -> RepairScope<'a> {
        let mut scope = RepairScope {
            known: Vec::new(),
            unknown: Vec::new(),
        };
        if commit.committer == Committer::External {
            return scope;
        }
        let from = t.saturating_sub(LOOKBACK_MS);
        for index in commit.removed_indices() {
            let Some(leaf) = group.leaf(index) else {
                continue;
            };
            if leaf.uid() == Some(committer) || !leaf.may_have_committed_since(from) {
                continue;
            }
            let commits = history.repairable_commits(index.u32(), t);
            if !commits.is_empty() {
                scope.known.push((index, commits));
            } else if !history.covers_time(from) {
                scope.unknown.push(index);
            }
        }
        scope
    }

    fn targets(&self, index: LeafNodeIndex) -> Lookup<bool> {
        if self.known.iter().any(|(i, _)| *i == index) {
            Lookup::Known(true)
        } else if self.unknown.contains(&index) {
            Lookup::Unknown
        } else {
            Lookup::Known(false)
        }
    }

    /// Whether the repair may add back `uid`'s device `device_id`: a commit
    /// it undoes removed a leaf of that device.
    fn may_re_add(&self, uid: &Uid, device_id: &DeviceId) -> Lookup<bool> {
        let known = self.known.iter().any(|(_, commits)| {
            commits.iter().any(|record| {
                record.removed.iter().any(|removed| {
                    removed.uid == uid.as_str() && removed.device_id == device_id.as_bytes()
                })
            })
        });
        match (known, self.unknown.is_empty()) {
            (true, _) => Lookup::Known(true),
            (false, true) => Lookup::Known(false),
            (false, false) => Lookup::Unknown,
        }
    }

    /// `new` with each field that the repair puts back to the value it had
    /// before the first of the undone commits that changed it set to
    /// `old`'s instead, so that the rest is checked as an ordinary change;
    /// `None` if the repair puts nothing back.
    fn restore(
        &self,
        old: &RisalaConversation,
        new: &RisalaConversation,
    ) -> Option<RisalaConversation> {
        let mut out = new.clone();
        let mut any = false;
        for (_, commits) in &self.known {
            let changes: Vec<(RisalaConversation, RisalaConversation)> = commits
                .iter()
                .filter_map(|record| {
                    let (before, after) = record.extension_change.as_ref()?;
                    Some((
                        RisalaConversation::decode(before).ok()?,
                        RisalaConversation::decode(after).ok()?,
                    ))
                })
                .collect();
            for field in Field::ALL {
                let Some((first_before, _)) = changes.iter().find(|(b, a)| !field.same(b, a))
                else {
                    continue;
                };
                if !field.same(old, new) && field.same(new, first_before) {
                    field.copy(old, &mut out);
                    any = true;
                }
            }
        }
        any.then_some(out)
    }
}

/// A field of the conversation extension that an impostor repair may put
/// back (12.7).
#[derive(Debug, Clone, Copy)]
enum Field {
    Name,
    Topic,
    Confirm,
    Guests,
    Send,
    Owners,
    Mods,
    Bans,
}

impl Field {
    const ALL: [Field; 8] = [
        Field::Name,
        Field::Topic,
        Field::Confirm,
        Field::Guests,
        Field::Send,
        Field::Owners,
        Field::Mods,
        Field::Bans,
    ];

    fn same(self, a: &RisalaConversation, b: &RisalaConversation) -> bool {
        match self {
            Field::Name => a.name == b.name,
            Field::Topic => a.topic == b.topic,
            Field::Confirm => a.confirm == b.confirm,
            Field::Guests => a.guests == b.guests,
            Field::Send => a.send == b.send,
            Field::Owners => a.owners == b.owners,
            Field::Mods => a.mods == b.mods,
            Field::Bans => a.bans == b.bans,
        }
    }

    fn copy(self, from: &RisalaConversation, to: &mut RisalaConversation) {
        match self {
            Field::Name => to.name.clone_from(&from.name),
            Field::Topic => to.topic.clone_from(&from.topic),
            Field::Confirm => to.confirm = from.confirm,
            Field::Guests => to.guests = from.guests,
            Field::Send => to.send = from.send,
            Field::Owners => to.owners.clone_from(&from.owners),
            Field::Mods => to.mods.clone_from(&from.mods),
            Field::Bans => to.bans.clone_from(&from.bans),
        }
    }
}

/// Why one leaf may be removed (12.7), or why not.
#[allow(clippy::too_many_arguments)]
fn removal_reason(
    group: &GroupView,
    conversation: &RisalaConversation,
    commit: &CommitView,
    history: &History,
    repair: &RepairScope<'_>,
    committer: &Uid,
    added: &[RisalaIdentity],
    leaf: &LeafView,
    removed: &BTreeSet<LeafNodeIndex>,
    stale_left: &mut usize,
    t: u64,
    verdict: &mut Verdict,
) -> Result<RemoveReason, CommitError> {
    let identity = leaf.identity.as_ref().ok_or(CommitError::Remove)?;
    let public = conversation.kind == ConversationKind::PublicRoom;
    let mut unknown = None;
    if identity.uid == *committer {
        return Ok(RemoveReason::Own);
    }
    if commit.self_removes(leaf.index) {
        return Ok(RemoveReason::SelfRemove);
    }
    if identity.is_guest() {
        return Ok(RemoveReason::Guest);
    }
    let kicks_all = group
        .leaves_of(&identity.uid)
        .all(|l| removed.contains(&l.index));
    if kicks_all && may_kick(conversation, group, committer, &identity.uid) {
        return Ok(RemoveReason::Kick);
    }
    if *stale_left > 0 && group.is_stale(leaf) {
        *stale_left -= 1;
        return Ok(RemoveReason::Stale);
    }
    let same_device_added = || {
        added
            .iter()
            .any(|a| a.uid == identity.uid && a.device_id == identity.device_id)
    };
    if !public && same_device_added() {
        match history.posted_resync(leaf.index, group.epoch) {
            Lookup::Known(true) => return Ok(RemoveReason::Resync),
            Lookup::Known(false) => {}
            Lookup::Unknown => unknown = Some("a removal after RESYNC"),
        }
    }
    match repair.targets(leaf.index) {
        Lookup::Known(true) => return Ok(RemoveReason::Repair),
        Lookup::Known(false) => {}
        Lookup::Unknown => unknown = Some("an impostor repair"),
    }
    if !public {
        // Outside public rooms any other leaf, for a key check, which each
        // device makes afterwards (12.7). A Resync or repair it could not
        // check is one too.
        return Ok(RemoveReason::KeyCheck);
    }
    // A public room's later leaf of the same device (12.7).
    let later_copy = group
        .leaves
        .iter()
        .any(|other| other.index != leaf.index && other.identity.as_ref() == Some(identity))
        || same_device_added();
    if later_copy {
        match inactive(leaf, history, t) {
            Lookup::Known(true) => return Ok(RemoveReason::Inactive),
            Lookup::Known(false) => {}
            Lookup::Unknown => unknown = Some("an inactive leaf"),
        }
    }
    // Within 24 hours of a resync commit, its stragglers (12.7). A resync
    // this device did not see was before its history starts, so a leaf that
    // has committed or been added since then, or whose `updated` says it
    // committed since, is no straggler.
    match &history.resync {
        Some(resync) if t.saturating_sub(resync.t) <= LOOKBACK_MS => {
            if !resync.active.contains(&leaf.index.u32()) {
                return Ok(RemoveReason::AfterResync);
            }
        }
        _ if !history.covers_time(t.saturating_sub(LOOKBACK_MS))
            && !history.active_since_start(leaf.index.u32())
            && !leaf
                .may_have_committed_since(history.since_t.saturating_add(2 * UPDATED_SKEW_MS)) =>
        {
            unknown = Some("a removal after a resync");
        }
        _ => {}
    }
    match unknown {
        Some(what) => {
            verdict.unchecked.push(what);
            Ok(RemoveReason::Unchecked)
        }
        None => Err(CommitError::Remove),
    }
}

/// The checks of one Add (12.7). Returns the added identity, and whether
/// only a role allowed it (an invitation).
#[allow(clippy::too_many_arguments)]
fn check_add(
    group: &GroupView,
    old: &RisalaConversation,
    new: &RisalaConversation,
    commit: &CommitView,
    history: &History,
    repair: &RepairScope<'_>,
    committer: &Uid,
    key_package: &KeyPackage,
    by_external_proposal: bool,
    t: u64,
    verdict: &mut Verdict,
) -> Result<(RisalaIdentity, bool), CommitError> {
    let (identity, _last_resort) =
        check_key_package_contents(key_package).map_err(CommitError::KeyPackage)?;
    if !lifetime_acceptable_at(key_package.life_time(), t) {
        return Err(CommitError::KeyPackage(KeyPackageError::Lifetime));
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
    let device_id = identity.device_id.expect("not a guest");
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
    // A room.
    if group.leaves_of(uid).next().is_some() {
        return Ok((identity, false));
    }
    let removed_now = commit.removed_indices();
    if group
        .leaves
        .iter()
        .any(|leaf| removed_now.contains(&leaf.index) && leaf.identity.as_ref() == Some(&identity))
    {
        return Ok((identity, false));
    }
    match repair.may_re_add(uid, &device_id) {
        Lookup::Known(true) => return Ok((identity, false)),
        Lookup::Known(false) => {}
        Lookup::Unknown => {
            verdict.unchecked.push("an impostor repair");
            return Ok((identity, false));
        }
    }
    match history.may_add_back(uid, group.epoch) {
        Lookup::Known(true) => return Ok((identity, false)),
        Lookup::Known(false) => {}
        Lookup::Unknown => {
            verdict
                .unchecked
                .push("adding back a device of the last 16 epochs");
            return Ok((identity, false));
        }
    }
    // An invitation: owners and moderators, and only owners for an
    // identity listed in `owners` or `mods` (12.7).
    let role = group.effective_role(committer);
    let listed = old.role(uid) != Role::Member || new.role(uid) != Role::Member;
    let allowed = if listed {
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

/// What the key checks of a valid commit found (12.7). None of it makes
/// the commit invalid; each failure leads to a repair commit after a random
/// wait of up to 10 minutes, unless another device makes it first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyReport {
    /// Added devices whose binding does not verify under a current device
    /// key of the identity, or that were removed by record: the repair
    /// removes their leaves, for a key check.
    pub failed_adds: Vec<RisalaIdentity>,
    /// Added devices whose key file or record is not known yet: their
    /// leaves are unconfirmed, and the device sends nothing in the group
    /// until a later check passes.
    pub unchecked_adds: Vec<RisalaIdentity>,
    /// Devices removed for a key check that is false, since they are still
    /// current: the repair adds them again from new KeyPackages.
    pub failed_removals: Vec<RisalaIdentity>,
    /// Leaves removed for a key check that could not be made yet: the
    /// removal stands, and the device warns the user.
    pub unchecked_removals: Vec<LeafNodeIndex>,
    /// Whether the committer's device has been removed by record: its leaf
    /// is repaired as an impostor's.
    pub committer_removed: bool,
    /// Whether that could not be checked yet.
    pub committer_unchecked: bool,
}

/// The key checks of a commit that passed the group checks (12.7), outside
/// public rooms, which have none. `group` is the group as of the commit's
/// epoch.
pub fn key_checks(
    group: &GroupView,
    commit: &CommitView,
    verdict: &Verdict,
    facts: &dyn KeyFacts,
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
    if let Committer::Member(index) = commit.committer
        && let Some(identity) = group.leaf(index).and_then(|leaf| leaf.identity.as_ref())
        && let Some(device_id) = identity.device_id
    {
        match facts.device_removed(&identity.uid, &device_id) {
            Fact::Known(removed) => report.committer_removed = removed,
            Fact::Unknown => report.committer_unchecked = true,
        }
    }
    let added = commit.added_identities();
    for index in &verdict.key_check_removals {
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
        match (
            facts.device_removed(&identity.uid, &device_id),
            facts.identity_retired(&identity.uid),
        ) {
            (Fact::Known(true), _) | (_, Fact::Known(true)) => {}
            (Fact::Known(false), Fact::Known(false)) => report.failed_removals.push(identity),
            _ => report.unchecked_removals.push(*index),
        }
    }
    report
}

#[cfg(test)]
mod tests;

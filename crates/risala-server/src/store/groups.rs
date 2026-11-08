//! The groups of encrypted conversations (12.5): each group's public
//! state, as OpenMLS keeps it in a `PublicGroup`, with the GroupInfo of
//! its last commit and who each leaf is.
//!
//! # How a group is kept
//!
//! [`GroupState`] is the `PublicStorageProvider` OpenMLS loads a
//! `PublicGroup` from and writes it to. It holds the four parts of the
//! group, the ratchet tree, the group context, the interim transcript hash
//! and the confirmation tag, each encoded with MessagePack, the codec of
//! librisala's MLS storage. The store reads them into one with
//! [`GroupStore::group`], and writes them back, with the events of the
//! command that changed them, in one transaction ([`GroupStore::init_group`],
//! [`GroupStore::commit_group`]).
//!
//! The server never queues proposals: every proposal is inside its commit
//! (12.5). So the proposal queue is always empty, and queuing one fails.
//!
//! A group is not rebuilt from its GroupInfo and tree, since OpenMLS would
//! then check the lifetimes of every leaf, which 12.4 says not to (PLAN.md
//! 5, item 22).

use std::cell::RefCell;

use risala_mls::openmls_traits::public_storage::PublicStorageProvider;
use risala_mls::openmls_traits::storage::{CURRENT_VERSION, traits};
use risala_proto::auth::PublicKey;
use risala_proto::mls::{GroupInfo, RatchetTree, Welcome};
use risala_proto::names::{Id, Seq, Uid};

use super::{ConvKey, NewEvent, Result};

/// The four parts of a group's public state, each encoded with
/// MessagePack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupParts {
    /// The ratchet tree, OpenMLS's `TreeSync`.
    pub tree: Vec<u8>,
    /// The group context.
    pub context: Vec<u8>,
    /// The interim transcript hash.
    pub interim_hash: Vec<u8>,
    /// The confirmation tag of the last commit.
    pub confirmation_tag: Vec<u8>,
}

/// An error of [`GroupState`]: a part could not be encoded or decoded, or
/// a proposal was to be queued.
#[derive(Debug, thiserror::Error)]
#[error("group state: {0}")]
pub struct GroupStateError(String);

#[derive(Debug, Default, Clone)]
struct Items {
    tree: Option<Vec<u8>>,
    context: Option<Vec<u8>>,
    interim_hash: Option<Vec<u8>>,
    confirmation_tag: Option<Vec<u8>>,
}

/// A group's public state as OpenMLS reads and writes it: its
/// `PublicStorageProvider`, for one group.
///
/// It lives only as long as one command: made from what the store read,
/// handed to OpenMLS, and its parts written back.
#[derive(Debug, Default)]
pub struct GroupState {
    items: RefCell<Items>,
}

impl GroupState {
    /// An empty state, for a new group.
    pub fn new() -> GroupState {
        GroupState::default()
    }

    /// The state with these parts.
    pub fn from_parts(parts: GroupParts) -> GroupState {
        GroupState {
            items: RefCell::new(Items {
                tree: Some(parts.tree),
                context: Some(parts.context),
                interim_hash: Some(parts.interim_hash),
                confirmation_tag: Some(parts.confirmation_tag),
            }),
        }
    }

    /// The parts, once OpenMLS has written all four.
    pub fn parts(&self) -> Option<GroupParts> {
        let items = self.items.borrow();
        Some(GroupParts {
            tree: items.tree.clone()?,
            context: items.context.clone()?,
            interim_hash: items.interim_hash.clone()?,
            confirmation_tag: items.confirmation_tag.clone()?,
        })
    }

    fn put<T: serde::Serialize>(
        &self,
        value: &T,
        slot: impl FnOnce(&mut Items) -> &mut Option<Vec<u8>>,
    ) -> Result<(), GroupStateError> {
        let bytes =
            rmp_serde::to_vec_named(value).map_err(|e| GroupStateError(format!("encode: {e}")))?;
        *slot(&mut self.items.borrow_mut()) = Some(bytes);
        Ok(())
    }

    fn get<T: serde::de::DeserializeOwned>(
        &self,
        slot: impl FnOnce(&Items) -> &Option<Vec<u8>>,
    ) -> Result<Option<T>, GroupStateError> {
        slot(&self.items.borrow())
            .as_deref()
            .map(|bytes| {
                rmp_serde::from_slice(bytes).map_err(|e| GroupStateError(format!("decode: {e}")))
            })
            .transpose()
    }
}

impl PublicStorageProvider<CURRENT_VERSION> for GroupState {
    type PublicError = GroupStateError;

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), GroupStateError> {
        self.put(tree, |i| &mut i.tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
        hash: &InterimTranscriptHash,
    ) -> Result<(), GroupStateError> {
        self.put(hash, |i| &mut i.interim_hash)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
        context: &GroupContext,
    ) -> Result<(), GroupStateError> {
        self.put(context, |i| &mut i.context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
        tag: &ConfirmationTag,
    ) -> Result<(), GroupStateError> {
        self.put(tag, |i| &mut i.confirmation_tag)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
        _: &ProposalRef,
        _: &QueuedProposal,
    ) -> Result<(), GroupStateError> {
        Err(GroupStateError(
            "the server keeps no proposals: they are inside commits (12.5)".into(),
        ))
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, GroupStateError> {
        Ok(Vec::new())
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
    ) -> Result<Option<TreeSync>, GroupStateError> {
        self.get(|i| &i.tree)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
    ) -> Result<Option<GroupContext>, GroupStateError> {
        self.get(|i| &i.context)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, GroupStateError> {
        self.get(|i| &i.interim_hash)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
    ) -> Result<Option<ConfirmationTag>, GroupStateError> {
        self.get(|i| &i.confirmation_tag)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _: &GroupId,
    ) -> Result<(), GroupStateError> {
        self.items.borrow_mut().tree = None;
        Ok(())
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _: &GroupId,
    ) -> Result<(), GroupStateError> {
        self.items.borrow_mut().confirmation_tag = None;
        Ok(())
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _: &GroupId,
    ) -> Result<(), GroupStateError> {
        self.items.borrow_mut().context = None;
        Ok(())
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _: &GroupId,
    ) -> Result<(), GroupStateError> {
        self.items.borrow_mut().interim_hash = None;
        Ok(())
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
        _: &ProposalRef,
    ) -> Result<(), GroupStateError> {
        Ok(())
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        _: &GroupId,
    ) -> Result<(), GroupStateError> {
        Ok(())
    }
}

/// Where a group is: its epoch, and the seq of the COMMIT event that
/// started it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMeta {
    /// The current epoch.
    pub epoch: u64,
    /// The seq of the COMMIT event that started the epoch, or `None` in
    /// epoch 0.
    pub seq: Option<Seq>,
}

/// A group as stored (12.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    /// The group id, 32 bytes for groups INIT accepted.
    pub group_id: Vec<u8>,
    /// Its epoch and the COMMIT that started it.
    pub meta: GroupMeta,
    /// The GroupInfo sent with the last commit, or with INIT.
    pub group_info: GroupInfo,
    /// The public state.
    pub parts: GroupParts,
}

/// One leaf of a group (12.2): whose device it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLeaf {
    /// The leaf index.
    pub index: u32,
    /// The uid in its credential.
    pub uid: Uid,
    /// Its signature key, a device key.
    pub key: PublicKey,
}

/// The result of [`GroupStore::init_group`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupInit {
    /// The group was stored, and these events appended, in order.
    Done(Vec<Seq>),
    /// The conversation has a group already (`ERR stale`, 12.5).
    Exists,
    /// The group id was used before (`ERR invalid`, 12.5).
    IdTaken,
}

/// The Welcome of a commit that adds devices, for each device it adds
/// (12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWelcome {
    /// The Welcome.
    pub welcome: Welcome,
    /// The ratchet tree of the new epoch.
    pub tree: RatchetTree,
    /// The devices it adds.
    pub devices: Vec<(Uid, PublicKey)>,
}

/// An accepted commit, to store (12.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCommit {
    /// The epoch the commit was for. If the stored group is in another
    /// one, nothing is stored.
    pub from_epoch: u64,
    /// The group in the new epoch. Its `meta.seq` is ignored: it becomes
    /// the seq of the COMMIT event.
    pub group: GroupRecord,
    /// Its leaves in the new epoch.
    pub leaves: Vec<GroupLeaf>,
    /// The COMMIT event.
    pub event: NewEvent,
    /// Events after it: INVITE and SET (12.5).
    pub then: Vec<NewEvent>,
    /// The Welcome, if the commit adds devices.
    pub welcome: Option<NewWelcome>,
    /// The devices whose leaves the commit removed: their pending
    /// Welcomes of this conversation go (12.7).
    pub removed: Vec<(Uid, PublicKey)>,
}

/// What [`GroupStore::commit_group`] stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitStored {
    /// The seq of the COMMIT event, then those of the events after it.
    pub seqs: Vec<Seq>,
    /// The id of the Welcome of each device the commit adds, in order.
    pub welcome_ids: Vec<Id>,
}

/// The groups of encrypted conversations (12.5, 12.6, 12.8).
pub trait GroupStore {
    /// A conversation's group, or `None` if it has none.
    fn group(&self, conv: ConvKey) -> Result<Option<GroupRecord>>;

    /// Stores the new group of a conversation, in epoch 0 (12.5), with its
    /// leaves, and appends `events` after it, all in one transaction. With
    /// `end_invites`, the conversation's open invitations end too.
    fn init_group(
        &self,
        conv: ConvKey,
        group: &GroupRecord,
        leaves: &[GroupLeaf],
        events: &[NewEvent],
        end_invites: bool,
    ) -> Result<GroupInit>;

    /// Stores an accepted commit (12.5): the group in its new epoch, its
    /// leaves, the COMMIT event and the events after it, the Welcome for
    /// the devices it adds, and the end of the pending Welcomes of the
    /// devices it removes (12.7), all in one transaction. `None` if the
    /// group is no longer in `from_epoch`, and then nothing is stored.
    fn commit_group(&self, conv: ConvKey, commit: &GroupCommit) -> Result<Option<CommitStored>>;

    /// Whether the device `uid` and `key` has a leaf in the group (12.8).
    fn has_leaf(&self, conv: ConvKey, uid: &Uid, key: &PublicKey) -> Result<bool>;

    /// The identities that have leaves in the group, in order.
    fn leaf_uids(&self, conv: ConvKey) -> Result<Vec<Uid>>;

    /// Whether the group has a leaf whose key the server knows has left
    /// its identity's key file (12.6).
    fn has_removed_leaf(&self, conv: ConvKey) -> Result<bool>;
}

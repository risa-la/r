//! Groups (12.6-12.9, 6.1, 7.8): how risala sets up OpenMLS, and the
//! operations a device performs on its groups.
//!
//! Every group:
//!
//! - uses the cipher suite `0x0020` and `basic` credentials holding a
//!   RisalaIdentity (12.2, 12.3), with a fresh leaf key per device;
//! - has exactly two group context extensions, `required_capabilities`
//!   and the conversation extension (12.4);
//! - in a direct conversation or private room, frames every handshake
//!   message as a PrivateMessage, SelfRemove too, and puts the ratchet
//!   tree in its Welcomes (12.6, 12.8); in a public room, frames commits
//!   and proposals as PublicMessages, and leaves the tree out of its
//!   GroupInfo, since the server holds it (12.6);
//! - commits always with a path, proposals by value except SelfRemoves,
//!   Updates in epochal groups and a public room's external Adds (12.6);
//! - keeps the secrets of at most 2 past epochs, and the keys of skipped
//!   messages for at most 1,000 generations, and pads messages to 256
//!   bytes (12.9).
//!
//! Each operation that posts sets the RisalaAAD (12.9): the leaf's
//! pseudonym (7.3), which the caller keeps with the group, in a
//! PrivateMessage, and none in a public room's PublicMessages.
//!
//! **Commits and the first valid commit.** A device makes a commit with
//! [`commit`], which leaves it pending, and posts it with
//! [`CommitOutput::next_token_hash`] as `next=` (5.2). Once the server
//! accepts it and the device knows it won (7.2), it calls
//! [`merge_own_commit`]; if another valid commit for the same epoch came
//! first, [`discard_own_commit`], then processes the winner. Incoming posts
//! go through [`process_message`]; a commit comes back as a
//! [`ReceivedCommit`] to check with [`check_received_commit`] (the group
//! checks, with the post's `t` and `next`) and [`check_received_keys`]
//! (the key checks), then apply with [`apply_commit`], or to drop if it is
//! invalid. The caller keeps a [`History`] with each group for the checks
//! that look back, which these functions update.

use openmls::group::{
    CommitBuilderStageError, CreateCommitError, ExternalCommitBuilderError,
    ExternalCommitBuilderFinalizeError, LeaveGroupError, MergeCommitError, MergePendingCommitError,
    MlsGroup, MlsGroupJoinConfig, NewGroupError, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProcessMessageError, ProposalStore, ProposeSelfUpdateError,
    PublicGroup, StagedCommit, StagedWelcome, WelcomeError, WireFormatPolicy,
};
use openmls::prelude::{
    Capabilities, CreateMessageError, CredentialType, Extension, Extensions, GroupContext, GroupId,
    JoinProposal, KeyPackage, KeyPackageBundle, LeafNode, LeafNodeIndex, LeafNodeParameters,
    NewSignerBundle, ProcessedMessageContent, Proposal, ProposalOrRefType, ProposalType,
    ProtocolVersion, RequiredCapabilitiesExtension, Sender, SenderRatchetConfiguration,
};
use openmls::storage::OpenMlsProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::storage::StorageProvider as _;

use crate::CIPHERSUITE;
use crate::aad::{AadError, Pseudonym, RisalaAad};
use crate::binding::DEVICE_BINDING_EXTENSION;
use crate::checks::{
    CommitError, CommitPost, CommitView, GroupView, History, JoinError, JoinExpectation, KeyFacts,
    KeyReport, ResyncState, Verdict, check_commit, check_join, key_checks,
};
use crate::conversation::{
    CONVERSATION_EXTENSION, ConfirmMode, ConversationKind, RisalaConversation,
};
use crate::framing::{ContentType, GROUP_ID_LEN};
use crate::identity::RisalaIdentity;
use crate::keypackage::{
    APP_DATA_DICTIONARY_EXTENSION, NewKeyPackageError, is_last_resort, make_join_key_package,
};
use crate::mldsa::{KEY_PACKAGE_SCOPE, LeafKey};
use crate::primitives::{HASH_LEN, ct_eq};
use crate::profile::{PROFILE_EXTENSION, RisalaProfile};
use crate::token::SendToken;
use crate::wire::{WireError, read_group_info, read_protocol_message, read_tree, read_welcome};

/// How many past epochs a device keeps the secrets of, at most (12.9).
/// [`crate::message::expire_past_epochs`] deletes them sooner, an hour
/// after the commit that ended them.
pub const MAX_PAST_EPOCHS: usize = 2;

/// How many generations behind the newest one a device keeps the keys of
/// skipped messages for, from each sender, and how far ahead it accepts a
/// message: 1,000 (12.9).
pub const MAX_SKIPPED_GENERATIONS: u32 = 1_000;

/// The multiple of bytes that PrivateMessage contents are padded to
/// (12.9).
pub const PADDING_SIZE: usize = 256;

/// The most devices a commit adds (12.6, 6.1). A client that adds more
/// splits them over several commits; [`commit`] commits at most this many
/// pending join proposals at once.
pub const MAX_ADDS_PER_COMMIT: usize = 256;

/// A leaf's capabilities (12.3): `mls10`, the suite, the extension types
/// `0xF2A1`, `0xF2A2`, `0xF2A3` and `app_data_dictionary` (`0x0006`), the
/// proposal type `self_remove`, and `basic` credentials.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[
            CONVERSATION_EXTENSION,
            DEVICE_BINDING_EXTENSION,
            PROFILE_EXTENSION,
            APP_DATA_DICTIONARY_EXTENSION,
        ]),
        Some(&[ProposalType::SelfRemove]),
        Some(&[CredentialType::Basic]),
    )
}

/// Whether a leaf's capabilities list everything of [`capabilities`]
/// (12.3).
pub fn has_capabilities(capabilities: &Capabilities) -> bool {
    capabilities.versions().contains(&ProtocolVersion::Mls10)
        && capabilities.ciphersuites().contains(&CIPHERSUITE.into())
        && capabilities.credentials().contains(&CredentialType::Basic)
        && capabilities.proposals().contains(&ProposalType::SelfRemove)
        && [
            CONVERSATION_EXTENSION,
            DEVICE_BINDING_EXTENSION,
            PROFILE_EXTENSION,
            APP_DATA_DICTIONARY_EXTENSION,
        ]
        .iter()
        .all(|t| capabilities.extensions().contains(t))
}

/// The group's `required_capabilities` (12.4): the extension types
/// `0xF2A1`, `0xF2A2` and `0xF2A3`, the proposal type `self_remove`, and
/// `basic` credentials.
pub fn required_capabilities() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(
        &[
            CONVERSATION_EXTENSION,
            DEVICE_BINDING_EXTENSION,
            PROFILE_EXTENSION,
        ],
        &[ProposalType::SelfRemove],
        &[CredentialType::Basic],
    )
}

/// A group context's extensions (12.4): `required_capabilities`, then the
/// conversation extension.
pub fn group_context_extensions(conversation: &RisalaConversation) -> Extensions<GroupContext> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(required_capabilities()),
        conversation.to_extension(),
    ])
    .expect("two extensions of different types")
}

/// The wire format policy of a kind of conversation (12.6).
pub fn wire_format_policy(kind: ConversationKind) -> WireFormatPolicy {
    match kind {
        ConversationKind::PublicRoom => PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        _ => PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    }
}

/// The sender ratchets' limits (12.9): skipped messages' keys for at most
/// 1,000 generations behind, and nothing more than 1,000 ahead.
pub fn sender_ratchet_configuration() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(MAX_SKIPPED_GENERATIONS, MAX_SKIPPED_GENERATIONS)
}

/// The configuration of a group of `kind` (12.6, 12.8, 12.9).
pub fn join_config(kind: ConversationKind) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(wire_format_policy(kind))
        .use_ratchet_tree_extension(kind != ConversationKind::PublicRoom)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(sender_ratchet_configuration())
        .padding_size(PADDING_SIZE)
        .build()
}

/// The RisalaAAD of a commit or proposal in a group of `kind` (12.9, 7.3):
/// the pseudonym in a PrivateMessage, none in a public room's
/// PublicMessage.
pub fn handshake_aad(kind: ConversationKind, pseudonym: Pseudonym) -> RisalaAad {
    match kind {
        ConversationKind::PublicRoom => RisalaAad::public(),
        _ => RisalaAad::handshake(pseudonym),
    }
}

/// The parameters of a leaf this device commits or proposes: the
/// capabilities and the profile. A device binding is checked only where
/// a leaf enters a group from a KeyPackage (12.3), so later leaf nodes
/// carry none.
fn leaf_parameters(profile: &RisalaProfile) -> LeafNodeParameters {
    LeafNodeParameters::builder()
        .with_capabilities(capabilities())
        .with_extensions(
            Extensions::single(profile.to_extension()).expect("a profile is a leaf extension"),
        )
        .build()
}

/// Why a group operation failed.
#[derive(Debug, thiserror::Error)]
pub enum GroupError<E> {
    /// No randomness.
    #[error("no randomness")]
    Random,
    /// The leaf key or a KeyPackage could not be stored or loaded.
    #[error("storage: {0:?}")]
    Storage(E),
    /// The conversation extension, or something else of the group, is not
    /// acceptable, or the operation does not fit the group.
    #[error("the group is not acceptable: {0}")]
    Group(String),
    /// A value from the wire is not what it should be.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The group fails the checks of joining (12.7).
    #[error(transparent)]
    Join(#[from] JoinError),
    /// OpenMLS failed.
    #[error("MLS: {0}")]
    Mls(String),
}

fn mls<E, T: std::fmt::Display>(e: T) -> GroupError<E> {
    GroupError::Mls(e.to_string())
}

/// The device's own leaf: its key, from storage.
pub fn own_leaf_key<P: OpenMlsProvider>(
    provider: &P,
    group: &MlsGroup,
) -> Result<LeafKey, GroupError<P::StorageError>> {
    let leaf = group
        .own_leaf_node()
        .ok_or_else(|| GroupError::Group("no own leaf".into()))?;
    LeafKey::load(
        provider.storage(),
        group.group_id().as_slice(),
        leaf.signature_key().as_slice(),
    )
    .map_err(GroupError::Storage)?
    .ok_or_else(|| GroupError::Group("own leaf key not in storage".into()))
}

/// The conversation extension of a group.
pub fn conversation(group: &MlsGroup) -> Option<RisalaConversation> {
    RisalaConversation::from_extensions(group.extensions()).ok()
}

fn kind_of<E>(group: &MlsGroup) -> Result<ConversationKind, GroupError<E>> {
    conversation(group)
        .map(|c| c.kind)
        .ok_or_else(|| GroupError::Group("no conversation extension".into()))
}

fn own_identity<E>(group: &MlsGroup) -> Result<RisalaIdentity, GroupError<E>> {
    RisalaIdentity::from_credential(
        group
            .own_leaf_node()
            .ok_or_else(|| GroupError::Group("no own leaf".into()))?
            .credential(),
    )
    .map_err(|e| GroupError::Group(e.to_string()))
}

fn own_profile(group: &MlsGroup) -> Option<RisalaProfile> {
    group.own_leaf_node().and_then(RisalaProfile::of_leaf)
}

/// Creates the group of a new conversation (12.6): a new random 32-byte
/// group id, this device the only member with a new leaf key, and
/// `conversation` in the group context. The leaf key is stored with the
/// group. The [`History`] starts at `t`, the device's clock.
pub fn create_group<P: OpenMlsProvider>(
    provider: &P,
    identity: &RisalaIdentity,
    profile: &RisalaProfile,
    conversation: &RisalaConversation,
    t: u64,
) -> Result<(MlsGroup, LeafKey, History), GroupError<P::StorageError>> {
    conversation
        .check()
        .map_err(|e| GroupError::Group(e.to_string()))?;
    let id: [u8; GROUP_ID_LEN] = provider
        .rand()
        .random_array()
        .map_err(|_| GroupError::Random)?;
    let leaf_key = LeafKey::generate().map_err(|_| GroupError::Random)?;
    leaf_key
        .store(provider.storage(), &id)
        .map_err(GroupError::Storage)?;
    let kind = conversation.kind;
    let group = MlsGroup::builder()
        .ciphersuite(CIPHERSUITE)
        .with_group_id(GroupId::from_slice(&id))
        .with_capabilities(capabilities())
        .with_leaf_node_extensions(
            Extensions::single(profile.clone().with_streak(0).to_extension())
                .expect("a profile is a leaf extension"),
        )
        .map_err(mls)?
        .with_group_context_extensions(group_context_extensions(conversation))
        .with_wire_format_policy(wire_format_policy(kind))
        .use_ratchet_tree_extension(kind != ConversationKind::PublicRoom)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(sender_ratchet_configuration())
        .padding_size(PADDING_SIZE)
        .build(
            provider,
            &leaf_key,
            identity.credential_with_key(leaf_key.public_key()),
        )
        .map_err(|e: NewGroupError<_>| mls(e))?;
    Ok((group, leaf_key, History::created(t)))
}

/// What a commit changes (12.6, 12.7). Proposals pending in the group are
/// committed too, by reference: SelfRemoves, Updates in an epochal group
/// and a public room's join proposals, at most 256 of these (6.1), except
/// in a move.
#[derive(Debug, Default, Clone)]
pub struct Changes {
    /// KeyPackages of devices to add, already checked (12.5, 12.7). Not in
    /// a public room, where devices join by proposal (6.1).
    pub add: Vec<KeyPackage>,
    /// Leaves to remove.
    pub remove: Vec<LeafNodeIndex>,
    /// A new conversation extension (6.2, 6.3, 6.4).
    pub conversation: Option<RisalaConversation>,
    /// A move to a new mailbox (7.8): a commit that changes the `box` of
    /// the conversation extension and nothing else, with no other
    /// proposal.
    pub move_box: Option<[u8; 16]>,
    /// Whether to commit a new leaf key: right after joining with a
    /// last-resort KeyPackage, and, in an epochal group, once a period if
    /// an Update proposal has not been committed within 30 minutes
    /// (12.3, 12.10).
    pub new_leaf_key: bool,
}

/// A commit this device made, pending in its group.
#[derive(Debug)]
pub struct CommitOutput {
    /// The commit, a `<message>` to post.
    pub message: Vec<u8>,
    /// The Welcome for the devices it adds, as `<welcome>` bytes: an
    /// MLSMessage. Outside public rooms, seal a copy for each device with
    /// [`crate::welcome::seal_welcomes`] (12.8).
    pub welcome: Option<Vec<u8>>,
    /// In a public room, the new epoch's GroupInfo, with `external_pub`
    /// and without the tree, for POST's `groupinfo=` (12.6).
    pub group_info: Option<Vec<u8>>,
    /// The SHA-384 hash of the send token of the epoch the commit creates,
    /// for POST's `next=` (5.2, 12.6).
    pub next_token_hash: [u8; HASH_LEN],
    /// The new leaf key, if the commit has one. It is in storage; once the
    /// commit is merged, the old one is deleted.
    pub new_leaf_key: Option<LeafKey>,
    /// The KeyPackages the commit adds, by value or from join proposals,
    /// for the Welcomes (12.8).
    pub added: Vec<KeyPackage>,
}

/// Makes a commit (12.6) with `changes`, always with a path, and leaves it
/// pending in `group`. The committer's leaf gets `profile`, whose
/// `updated` should be the current time (12.3), raised to the leaf's
/// previous one if that is later, and the `streak` that 12.3 gives, from
/// `history`. Post the commit with `next=`; then [`merge_own_commit`] if
/// it wins, or [`discard_own_commit`].
///
/// With no changes, it is the weekly fresh-leaf commit (12.7).
pub fn commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    pseudonym: Pseudonym,
    profile: &RisalaProfile,
    history: &History,
    changes: Changes,
) -> Result<CommitOutput, GroupError<P::StorageError>> {
    let current =
        conversation(group).ok_or_else(|| GroupError::Group("no conversation extension".into()))?;
    let kind = current.kind;
    let epochal = current.confirm == ConfirmMode::Epochal;
    let leaf_key = own_leaf_key(provider, group)?;
    let identity = own_identity(group)?;
    let own_index = group.own_leaf_index();
    let previous = own_profile(group);
    let mut profile = profile
        .clone()
        .with_streak(history.expected_streak(own_index, previous.as_ref().map_or(0, |p| p.streak)));
    if let Some(previous) = &previous {
        profile.updated = profile.updated.max(previous.updated);
    }
    group.set_aad(handshake_aad(kind, pseudonym).encode());
    let group_id = group.group_id().as_slice().to_vec();
    let Changes {
        add,
        remove,
        conversation: new_conversation,
        move_box,
        new_leaf_key,
    } = changes;
    if kind == ConversationKind::PublicRoom && !add.is_empty() {
        return Err(GroupError::Group(
            "devices join a public room by proposal".into(),
        ));
    }
    let new_conversation = match (new_conversation, move_box) {
        (Some(_), Some(_)) => {
            return Err(GroupError::Group(
                "a move changes nothing but the box".into(),
            ));
        }
        (Some(c), None) => Some(c),
        (None, Some(mailbox)) => {
            if !add.is_empty() || !remove.is_empty() || new_leaf_key {
                return Err(GroupError::Group("a move has no other proposal".into()));
            }
            let mut moved = current.clone();
            moved.mailbox = mailbox;
            Some(moved)
        }
        (None, None) => None,
    };
    let mut builder = group
        .commit_builder()
        .propose_adds(add)
        .propose_removals(remove)
        .force_self_update(true)
        .consume_proposal_store(move_box.is_none())
        .leaf_node_parameters(leaf_parameters(&profile));
    if let Some(conversation) = new_conversation {
        builder = builder
            .propose_group_context_extensions(group_context_extensions(&conversation))
            .map_err(|e: CreateCommitError| mls(e))?;
    }
    let builder = builder
        .load_psks(provider.storage())
        .map_err(mls)?
        .create_group_info(kind == ConversationKind::PublicRoom);
    // Only SelfRemoves, Updates in an epochal group and a public room's
    // join proposals are committed by reference (12.6), at most 256 joins
    // at a time (6.1). OpenMLS passes this device's own proposals, by
    // value, through the same filter.
    let mut joins = 0;
    let by_reference_ok = move |queued: &openmls::group::QueuedProposal| {
        if queued.proposal_or_ref_type() == ProposalOrRefType::Proposal {
            return true;
        }
        match (queued.proposal(), queued.sender()) {
            (Proposal::SelfRemove, Sender::Member(_)) => true,
            (Proposal::Update(_), Sender::Member(sender)) => epochal && *sender != own_index,
            (Proposal::Add(_), Sender::NewMemberProposal) => {
                joins += 1;
                kind == ConversationKind::PublicRoom && joins <= MAX_ADDS_PER_COMMIT
            }
            _ => false,
        }
    };
    let fresh = if new_leaf_key {
        let key = LeafKey::generate().map_err(|_| GroupError::Random)?;
        key.store(provider.storage(), &group_id)
            .map_err(GroupError::Storage)?;
        Some(key)
    } else {
        None
    };
    let complete = match &fresh {
        Some(new) => builder.build_with_new_signer(
            provider.rand(),
            provider.crypto(),
            &leaf_key,
            NewSignerBundle {
                signer: new,
                credential_with_key: identity.credential_with_key(new.public_key()),
            },
            by_reference_ok,
        ),
        None => builder.build(
            provider.rand(),
            provider.crypto(),
            &leaf_key,
            by_reference_ok,
        ),
    }
    .map_err(|e: CreateCommitError| mls(e))?;
    let bundle = complete
        .stage_commit(provider)
        .map_err(|e: CommitBuilderStageError<_>| mls(e))?;
    let staged = group
        .pending_commit()
        .ok_or_else(|| GroupError::Mls("no pending commit".into()))?;
    let next_token_hash = SendToken::of_staged_commit(staged, provider.crypto())
        .map_err(mls)?
        .hash();
    let added = staged
        .add_proposals()
        .map(|queued| queued.add_proposal().key_package().clone())
        .collect();
    let (message, welcome, group_info) = bundle.into_messages();
    Ok(CommitOutput {
        message: crate::wire::to_bytes(&message),
        welcome: welcome.as_ref().map(crate::wire::to_bytes),
        group_info: group_info.as_ref().map(crate::wire::to_bytes),
        next_token_hash,
        new_leaf_key: fresh,
        added,
    })
}

/// Merges this device's pending commit, once it has won its epoch (7.2),
/// records it in `history` with its post, and deletes the leaf key it
/// replaced, if any.
pub fn merge_own_commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    history: &mut History,
    post: &CommitPost,
) -> Result<(), GroupError<P::StorageError>> {
    let before = GroupView::of(group.public_group());
    let view = {
        let staged = group
            .pending_commit()
            .ok_or_else(|| GroupError::Group("no pending commit".into()))?;
        CommitView::of(
            &Sender::Member(group.own_leaf_index()),
            staged,
            group.pending_proposals(),
        )
    };
    let old_key = group
        .own_leaf_node()
        .map(|leaf| leaf.signature_key().as_slice().to_vec());
    group
        .merge_pending_commit(provider)
        .map_err(|e: MergePendingCommitError<_>| mls(e))?;
    let after = GroupView::of(group.public_group());
    // The device's own commit passed its checks when it made it; they are
    // run again here only for what the history keeps of it.
    let verdict = check_commit(&before, &view, history, post).unwrap_or_default();
    history.record(&before, &view, &verdict, &after, post);
    let new_key = group
        .own_leaf_node()
        .map(|leaf| leaf.signature_key().as_slice().to_vec());
    if let Some(old) = old_key
        && Some(&old) != new_key.as_ref()
    {
        LeafKey::delete(provider.storage(), group.group_id().as_slice(), &old)
            .map_err(GroupError::Storage)?;
    }
    Ok(())
}

/// Drops this device's pending commit, which lost its epoch or which the
/// server refused (7.2), and the new leaf key it would have installed.
pub fn discard_own_commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
) -> Result<(), GroupError<P::StorageError>> {
    let current = group
        .own_leaf_node()
        .map(|leaf| leaf.signature_key().as_slice().to_vec());
    let pending_key = group
        .pending_commit()
        .and_then(|staged| staged.update_path_leaf_node())
        .map(|leaf| leaf.signature_key().as_slice().to_vec());
    group
        .clear_pending_commit(provider.storage())
        .map_err(GroupError::Storage)?;
    if let Some(pending) = pending_key
        && Some(&pending) != current.as_ref()
    {
        LeafKey::delete(provider.storage(), group.group_id().as_slice(), &pending)
            .map_err(GroupError::Storage)?;
    }
    Ok(())
}

/// Posts a SelfRemove of this device's own leaf (6.1), framed as the
/// group's other handshake messages: a PrivateMessage outside public rooms
/// (12.6), through the patched OpenMLS (`crates/openmls/RISALA.md`). If a
/// commit that leaves it out wins the epoch, post it again in the new one.
pub fn self_remove<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    pseudonym: Pseudonym,
) -> Result<Vec<u8>, GroupError<P::StorageError>> {
    let kind = kind_of(group)?;
    let leaf_key = own_leaf_key(provider, group)?;
    group.set_aad(handshake_aad(kind, pseudonym).encode());
    let message = group
        .leave_group_via_self_remove(provider, &leaf_key)
        .map_err(|e: LeaveGroupError<_>| mls(e))?;
    Ok(crate::wire::to_bytes(&message))
}

/// An Update proposal this device made (12.6, 12.10).
#[derive(Debug)]
pub struct UpdateOutput {
    /// The proposal, a `<message>` to post.
    pub message: Vec<u8>,
    /// Its ProposalRef.
    pub reference: Vec<u8>,
}

/// Proposes an Update of this device's own leaf, in an epochal group
/// (12.10): a fresh leaf node with `profile`, whose `streak` is 0 and
/// whose `updated` should be the current time, and with the signature key
/// of `new_key` if one is given: once a period, or right after a join with
/// a last-resort KeyPackage (12.3, 12.5). The new key is stored with the
/// group, and the old one deleted once a commit applies the Update
/// ([`apply_commit`]).
///
/// A proposal belongs to its epoch: if a commit leaves it out, propose it
/// again, with the same `new_key`, in the new epoch. If none has applied
/// it after 30 minutes, a full client commits its fresh leaf itself
/// ([`Changes::new_leaf_key`]), and deletes `new_key` with
/// [`LeafKey::delete`].
pub fn propose_update<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    pseudonym: Pseudonym,
    profile: &RisalaProfile,
    new_key: Option<&LeafKey>,
) -> Result<UpdateOutput, GroupError<P::StorageError>> {
    let current =
        conversation(group).ok_or_else(|| GroupError::Group("no conversation extension".into()))?;
    if current.confirm != ConfirmMode::Epochal {
        return Err(GroupError::Group(
            "Update proposals only in epochal groups".into(),
        ));
    }
    let leaf_key = own_leaf_key(provider, group)?;
    let identity = own_identity(group)?;
    let mut profile = profile.clone().with_streak(0);
    if let Some(previous) = own_profile(group) {
        profile.updated = profile.updated.max(previous.updated);
    }
    group.set_aad(handshake_aad(current.kind, pseudonym).encode());
    let (message, reference) = match new_key {
        Some(new) => {
            new.store(provider.storage(), group.group_id().as_slice())
                .map_err(GroupError::Storage)?;
            group.propose_self_update_with_new_signer(
                provider,
                &leaf_key,
                NewSignerBundle {
                    signer: new,
                    credential_with_key: identity.credential_with_key(new.public_key()),
                },
                leaf_parameters(&profile),
            )
        }
        None => group.propose_self_update(provider, &leaf_key, leaf_parameters(&profile)),
    }
    .map_err(|e: ProposeSelfUpdateError<_>| mls(e))?;
    Ok(UpdateOutput {
        message: crate::wire::to_bytes(&message),
        reference: reference.as_slice().to_vec(),
    })
}

/// The leaves of this device's identity other than its own, which it
/// removes with a commit before its SelfRemove when it leaves (6.1).
pub fn own_identity_other_leaves(group: &MlsGroup) -> Vec<LeafNodeIndex> {
    let view = GroupView::of(group.public_group());
    let own = group.own_leaf_index();
    let Some(uid) = view
        .leaf(own)
        .and_then(|leaf| leaf.identity.as_ref())
        .map(|identity| identity.uid.clone())
    else {
        return Vec::new();
    };
    view.leaves_of(&uid)
        .map(|leaf| leaf.index)
        .filter(|index| *index != own)
        .collect()
}

/// Encrypts an application message whose RisalaAAD is `aad`, for
/// [`crate`]'s callers that build RisalaMessages (12.9). The sending leaf
/// signs it, and MLS pads it to a multiple of 256 bytes.
pub fn encrypt_application<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    aad: &RisalaAad,
    content: &[u8],
) -> Result<Vec<u8>, GroupError<P::StorageError>> {
    if aad.check_for(ContentType::Application, true).is_err() {
        return Err(GroupError::Group("not an application message's AAD".into()));
    }
    let leaf_key = own_leaf_key(provider, group)?;
    group.set_aad(aad.encode());
    let message = group
        .create_message(provider, &leaf_key, content)
        .map_err(|e: CreateMessageError| mls(e))?;
    Ok(crate::wire::to_bytes(&message))
}

/// A group joined by Welcome (12.8).
#[derive(Debug)]
pub struct Joined {
    /// The group, in the Welcome's epoch.
    pub group: MlsGroup,
    /// Whether the device joined with its KeyPackage of last resort, and so
    /// must replace its leaf node with one with a new signature key before
    /// it sends anything (12.3, 12.5): [`commit`] with
    /// [`Changes::new_leaf_key`], or in an epochal group [`propose_update`]
    /// with a new key.
    pub last_resort: bool,
    /// The group's history from the Welcome's epoch on.
    pub history: History,
}

/// Joins a group by Welcome (12.8): decrypts it with one of this device's
/// KeyPackages, takes the tree from the Welcome's GroupInfo or from `tree`
/// (a public room's, from GROUPINFO), skips the lifetimes of leaves
/// already in the tree (12.5), and checks the group as 12.7 says. A group
/// that fails is deleted from storage again, and the error says why. `t`
/// is when the device joins, by the first post it applies or its clock,
/// for the [`History`].
///
/// If no leaf has the signature key of the KeyPackage the device was added
/// from, someone may have added it with a key of their own: the error is
/// [`JoinError::NotOwnLeaf`], and the device tells the user (12.7).
///
/// OpenMLS deletes an ordinary KeyPackage's private keys here, so run this
/// in a transaction that is rolled back if joining is cut short, to be
/// able to try again (12.8). A last-resort KeyPackage's are kept for
/// further Welcomes (12.5).
pub fn join_by_welcome<P: OpenMlsProvider>(
    provider: &P,
    welcome: &[u8],
    tree: Option<&[u8]>,
    expect: &JoinExpectation,
    t: u64,
) -> Result<Joined, GroupError<P::StorageError>> {
    let welcome = read_welcome(welcome)?;
    let tree = tree.map(read_tree).transpose()?;
    // A last-resort KeyPackage is kept: find it before OpenMLS deletes it.
    let mut found = None;
    for secrets in welcome.secrets() {
        let bundle: Option<KeyPackageBundle> = provider
            .storage()
            .key_package(&secrets.new_member())
            .map_err(GroupError::Storage)?;
        if let Some(bundle) = bundle {
            found = Some(bundle);
            break;
        }
    }
    let keep = found
        .as_ref()
        .filter(|bundle| is_last_resort(bundle.key_package()).unwrap_or(false))
        .cloned();
    // The kind is not known until the Welcome is open; the configuration
    // is set again below.
    let mut builder = StagedWelcome::build_from_welcome(
        provider,
        &join_config(ConversationKind::PrivateRoom),
        welcome,
    )
    .map_err(|e: WelcomeError<_>| mls(e))?;
    if let Some(tree) = tree {
        builder = builder.with_ratchet_tree(tree);
    }
    let staged =
        match builder.skip_lifetime_validation().build() {
            Ok(staged) => staged,
            // OpenMLS finds the device's leaf by its KeyPackage's signature
            // key, and fails thus if no leaf has it (12.7).
            Err(WelcomeError::PublicTreeError(
                openmls::prelude::PublicTreeError::MalformedTree,
            )) if found.is_some() => return Err(JoinError::NotOwnLeaf.into()),
            Err(e) => return Err(mls(e)),
        };
    let started_by = staged.welcome_sender_index();
    let mut group = staged
        .into_group(provider)
        .map_err(|e: WelcomeError<_>| mls(e))?;
    if let Some(bundle) = &keep {
        let hash_ref = bundle
            .key_package()
            .hash_ref(provider.crypto())
            .map_err(mls)?;
        provider
            .storage()
            .write_key_package(&hash_ref, bundle)
            .map_err(GroupError::Storage)?;
    }
    // The leaf key moves from the KeyPackage's scope to the group's; a
    // last-resort KeyPackage keeps its own copy for further groups.
    let own_key = group
        .own_leaf_node()
        .ok_or_else(|| GroupError::Mls("no own leaf".into()))?
        .signature_key()
        .as_slice()
        .to_vec();
    let leaf_key = LeafKey::load(provider.storage(), KEY_PACKAGE_SCOPE, &own_key)
        .map_err(GroupError::Storage)?
        .ok_or_else(|| GroupError::Group("the KeyPackage's leaf key is not in storage".into()))?;
    leaf_key
        .store(provider.storage(), group.group_id().as_slice())
        .map_err(GroupError::Storage)?;
    if keep.is_none() {
        LeafKey::delete(provider.storage(), KEY_PACKAGE_SCOPE, &own_key)
            .map_err(GroupError::Storage)?;
    }
    let view = GroupView::of(group.public_group());
    let checked = check_join(&view, expect).and_then(|()| Ok(view.conversation.clone()?.kind));
    let kind = match checked {
        Ok(kind) => kind,
        Err(e) => {
            LeafKey::delete(provider.storage(), group.group_id().as_slice(), &own_key)
                .map_err(GroupError::Storage)?;
            group
                .delete(provider.storage())
                .map_err(GroupError::Storage)?;
            return Err(e.into());
        }
    };
    group
        .set_configuration(provider.storage(), &join_config(kind))
        .map_err(GroupError::Storage)?;
    let history = History::joined(
        group.epoch().as_u64(),
        started_by.u32(),
        t,
        group.own_leaf_index().u32(),
    );
    Ok(Joined {
        group,
        last_resort: keep.is_some(),
        history,
    })
}

/// A public room's group as the server holds it, or as a device sees it
/// before it joins: from a GroupInfo and a ratchet tree (12.6), without
/// checking the lifetimes of the leaves in the tree (12.5), with
/// `storage` for OpenMLS's state.
pub fn public_group<S: openmls::storage::PublicStorageProvider>(
    crypto: &impl OpenMlsCrypto,
    storage: &S,
    group_info: &[u8],
    tree: &[u8],
) -> Result<PublicGroup, GroupError<<S as openmls::storage::PublicStorageProvider>::Error>> {
    let (group, _) = PublicGroup::from_external(
        crypto,
        storage,
        read_tree(tree)?,
        read_group_info(group_info)?,
        ProposalStore::new(),
    )
    .map_err(mls)?;
    Ok(group)
}

/// A join proposal for a public room, made and ready to post (6.1).
#[derive(Debug)]
pub struct JoinRequest {
    /// The external Add proposal, a `<message>` to post with the token `-`.
    pub message: Vec<u8>,
    /// The KeyPackage it carries, made for this join alone, with no device
    /// binding (12.3). Its private keys and leaf key are in storage, for
    /// the Welcome. Propose it again with [`join_proposal`] in each new
    /// epoch until a commit adds it.
    pub key_package: KeyPackage,
    /// Its KeyPackageRef, for `WELCOME GET` (12.8).
    pub key_package_ref: Vec<u8>,
    /// Its leaf key, which signs the proposal.
    pub leaf_key: LeafKey,
}

/// Joins a public room by external proposal (6.1): checks the group from
/// GROUPINFO's GroupInfo and tree as 12.7 says, makes a KeyPackage for
/// this join with no device binding, whose credential is `identity`, a
/// device's or a guest's, and whose leaf carries `profile` (a guest's may
/// carry none), and the proposal. Once a full client commits it, fetch the
/// Welcome with `WELCOME GET` and join with [`join_by_welcome`] and the
/// room's tree.
pub fn join_public_room<P: OpenMlsProvider>(
    provider: &P,
    identity: &RisalaIdentity,
    profile: Option<&RisalaProfile>,
    group_info: &[u8],
    tree: &[u8],
    expect: &JoinExpectation,
) -> Result<JoinRequest, GroupError<P::StorageError>> {
    let scratch = MemoryStorage::default();
    let public = public_group(provider.crypto(), &scratch, group_info, tree)
        .map_err(|e| GroupError::Mls(e.to_string()))?;
    let view = GroupView::of(&public);
    check_join(&view, expect)?;
    if view
        .conversation
        .as_ref()
        .is_ok_and(|c| c.kind != ConversationKind::PublicRoom)
    {
        return Err(JoinError::WrongConversation.into());
    }
    let made = make_join_key_package(provider, identity, profile).map_err(|e| match e {
        NewKeyPackageError::Storage(e) => GroupError::Storage(e),
        NewKeyPackageError::Random => GroupError::Random,
        other => GroupError::Mls(other.to_string()),
    })?;
    let context = public.group_context();
    let message = join_proposal::<P>(
        &made.key_package,
        context.group_id(),
        context.epoch().as_u64(),
        &made.leaf_key,
    )?;
    let key_package_ref = made
        .key_package
        .hash_ref(provider.crypto())
        .map_err(mls)?
        .as_slice()
        .to_vec();
    Ok(JoinRequest {
        message,
        key_package: made.key_package,
        key_package_ref,
        leaf_key: made.leaf_key,
    })
}

/// An external Add proposal of `key_package` for the epoch `epoch` of the
/// group `group_id`, signed with its leaf key, with an empty RisalaAAD as a
/// PublicMessage has (6.1, 12.9).
pub fn join_proposal<P: OpenMlsProvider>(
    key_package: &KeyPackage,
    group_id: &GroupId,
    epoch: u64,
    leaf_key: &LeafKey,
) -> Result<Vec<u8>, GroupError<P::StorageError>> {
    let message = JoinProposal::new_with_aad::<P::StorageProvider>(
        key_package.clone(),
        group_id.clone(),
        epoch.into(),
        RisalaAad::public().encode(),
        leaf_key,
    )
    .map_err(mls)?;
    Ok(crate::wire::to_bytes(&message))
}

/// A resync commit, made and pending the server's answer (12.7).
#[derive(Debug)]
pub struct ExternalJoin {
    /// The group, already in the new epoch. If the server refuses the
    /// commit, delete it from storage with [`MlsGroup::delete`], and the
    /// leaf key with [`LeafKey::delete`] under the group id.
    pub group: MlsGroup,
    /// The new leaf key, in storage.
    pub leaf_key: LeafKey,
    /// The external commit, a `<message>` to post with the token `-`.
    pub message: Vec<u8>,
    /// The new epoch's GroupInfo, for `groupinfo=` (12.6).
    pub group_info: Vec<u8>,
    /// The hash of the new epoch's send token, for `next=` (5.2, 12.6).
    pub next_token_hash: [u8; HASH_LEN],
    /// The group's history from the new epoch on.
    pub history: History,
}

/// Makes a resync commit for a public room whose devices could not apply
/// a commit that the server accepted (12.7): an external commit against
/// GROUPINFO's GroupInfo and tree, checked as 12.7 says, that removes the
/// GroupInfo's signer, the leaf whose commit could not be applied, and
/// the leaves in `inactive_own`, this device's own earlier leaves that are
/// inactive, and nothing else. `identity` must be an identity's that has a
/// leaf in the room. Before calling it, compare the GroupInfo's extension
/// with the one kept for the room
/// ([`RisalaConversation::unexplained_changes`]).
#[allow(clippy::too_many_arguments)]
pub fn resync_public_room<P: OpenMlsProvider>(
    provider: &P,
    identity: &RisalaIdentity,
    profile: &RisalaProfile,
    group_info: &[u8],
    tree: &[u8],
    expect: &JoinExpectation,
    inactive_own: &[LeafNodeIndex],
    t: u64,
) -> Result<ExternalJoin, GroupError<P::StorageError>> {
    if identity.is_guest() {
        return Err(GroupError::Group(
            "only an identity's device resyncs".into(),
        ));
    }
    let scratch = MemoryStorage::default();
    let public = public_group(provider.crypto(), &scratch, group_info, tree)
        .map_err(|e| GroupError::Mls(e.to_string()))?;
    check_join(&GroupView::of(&public), expect)?;
    let group_info = read_group_info(group_info)?;
    let signer = group_info.signer();
    let mut removals = vec![signer];
    removals.extend(inactive_own.iter().filter(|i| **i != signer));
    let tree = read_tree(tree)?;
    let leaf_key = LeafKey::generate().map_err(|_| GroupError::Random)?;
    leaf_key
        .store(provider.storage(), group_info.group_id().as_slice())
        .map_err(GroupError::Storage)?;
    let profile = profile.clone().with_streak(1);
    let (group, bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree)
        .with_config(join_config(ConversationKind::PublicRoom))
        .with_aad(RisalaAad::public().encode())
        .with_removals(removals)
        .skip_lifetime_validation()
        .build_group(
            provider,
            group_info,
            identity.credential_with_key(leaf_key.public_key()),
        )
        .map_err(|e: ExternalCommitBuilderError<_>| mls(e))?
        .leaf_node_parameters(leaf_parameters(&profile))
        .load_psks(provider.storage())
        .map_err(|e: CreateCommitError| mls(e))?
        .create_group_info(true)
        .build(provider.rand(), provider.crypto(), &leaf_key, |_| true)
        .map_err(|e: CreateCommitError| mls(e))?
        .finalize(provider)
        .map_err(|e: ExternalCommitBuilderFinalizeError<_>| mls(e))?;
    let next_token_hash = SendToken::of_group(&group, provider.crypto())
        .map_err(mls)?
        .hash();
    let (message, _welcome, group_info) = bundle.into_messages();
    let group_info = group_info.ok_or_else(|| GroupError::Mls("no GroupInfo".into()))?;
    let own = group.own_leaf_index().u32();
    let mut history = History::joined(group.epoch().as_u64(), own, t, own);
    history.resync = Some(ResyncState {
        t,
        active: [own].into(),
    });
    Ok(ExternalJoin {
        group,
        leaf_key,
        message: crate::wire::to_bytes(&message),
        group_info: crate::wire::to_bytes(&group_info),
        next_token_hash,
        history,
    })
}

/// A commit received for the group's current epoch, processed but not
/// applied. It is large, so [`Incoming`] holds it boxed.
#[derive(Debug)]
pub struct ReceivedCommit {
    /// The staged commit.
    pub staged: Box<StagedCommit>,
    /// What it does, for the checks.
    pub view: CommitView,
    /// Its RisalaAAD.
    pub aad: RisalaAad,
}

/// The kinds of proposal a device posts on its own, for members to commit
/// by reference (12.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalKind {
    /// A SelfRemove (6.1).
    SelfRemove,
    /// An Update of its sender's leaf, in an epochal group (12.10). Note
    /// its post's `t` with [`History::note_update`].
    Update,
    /// An external Add proposal, a join of a public room (6.1).
    Join,
}

/// What an incoming post holds.
#[derive(Debug)]
pub enum Incoming {
    /// An application message: its sending leaf, RisalaAAD and content.
    Application {
        /// The sending leaf.
        sender: LeafNodeIndex,
        /// The RisalaAAD.
        aad: RisalaAad,
        /// The decrypted content, a RisalaMessage (12.9).
        content: Vec<u8>,
    },
    /// A proposal, now pending in the group until a commit covers it.
    Proposal {
        /// The RisalaAAD.
        aad: RisalaAad,
        /// What it is.
        kind: ProposalKind,
        /// Its sender's leaf, for a member's proposal.
        sender: Option<LeafNodeIndex>,
        /// Its ProposalRef.
        reference: Vec<u8>,
    },
    /// A commit, to check and then apply or drop.
    Commit(Box<ReceivedCommit>),
    /// This device's own PrivateMessage, which it cannot decrypt.
    Own,
}

/// Why an incoming post could not be used. Devices ignore it.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError<E> {
    /// Not an MLS message of `mls10`.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// OpenMLS rejected it: for example, it is for another epoch, does not
    /// decrypt, or its signature fails.
    #[error("MLS: {0}")]
    Mls(String),
    /// Its RisalaAAD is malformed or does not fit (12.9).
    #[error(transparent)]
    Aad(#[from] AadError),
    /// A proposal risala does not take on its own: anything but a
    /// SelfRemove, an Update in an epochal group, or an external Add in a
    /// public room (12.6).
    #[error("a proposal risala does not allow")]
    Proposal,
    /// A handshake message framed the wrong way for the conversation
    /// (12.6), or the group is not acceptable.
    #[error("not acceptable in this group")]
    Group,
    /// Storage failed.
    #[error("storage: {0:?}")]
    Storage(E),
}

/// Processes an incoming post of `group` (12.6, 12.9). A commit comes back
/// unapplied, to check with [`check_received_commit`].
///
/// Application messages go through [`crate::message::receive`], which also
/// deletes past epochs' secrets once 12.9 says they must go.
pub fn process_message<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    message: &[u8],
) -> Result<Incoming, ProcessError<P::StorageError>> {
    let current = conversation(group).ok_or(ProcessError::Group)?;
    let kind = current.kind;
    let message = read_protocol_message(message)?;
    // Outside public rooms everything is a PrivateMessage (12.6). OpenMLS
    // applies its wire format policy only to members' messages, so this
    // also refuses external commits and proposals there.
    let private = message.wire_format() == openmls::prelude::WireFormat::PrivateMessage;
    if kind != ConversationKind::PublicRoom && !private {
        return Err(ProcessError::Group);
    }
    let processed = group
        .process_message(provider, message)
        .map_err(|e: ProcessMessageError<_>| ProcessError::Mls(e.to_string()))?;
    let sender = processed.sender().clone();
    let aad_bytes = processed.aad().to_vec();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            let Sender::Member(index) = sender else {
                return Err(ProcessError::Group);
            };
            Ok(Incoming::Application {
                sender: index,
                aad: RisalaAad::decode_for(&aad_bytes, ContentType::Application, private)?,
                content: message.into_bytes(),
            })
        }
        ProcessedMessageContent::ProposalMessage(queued) => {
            let aad = RisalaAad::decode_for(&aad_bytes, ContentType::Proposal, private)?;
            let Sender::Member(index) = queued.sender().clone() else {
                return Err(ProcessError::Proposal);
            };
            let proposal_kind = match queued.proposal() {
                Proposal::SelfRemove => ProposalKind::SelfRemove,
                Proposal::Update(_) if current.confirm == ConfirmMode::Epochal => {
                    ProposalKind::Update
                }
                _ => return Err(ProcessError::Proposal),
            };
            let reference = queued.proposal_reference_ref().as_slice().to_vec();
            group
                .store_pending_proposal(provider.storage(), *queued)
                .map_err(ProcessError::Storage)?;
            Ok(Incoming::Proposal {
                aad,
                kind: proposal_kind,
                sender: Some(index),
                reference,
            })
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(queued) => {
            let aad = RisalaAad::decode_for(&aad_bytes, ContentType::Proposal, private)?;
            if kind != ConversationKind::PublicRoom {
                return Err(ProcessError::Proposal);
            }
            let reference = queued.proposal_reference_ref().as_slice().to_vec();
            group
                .store_pending_proposal(provider.storage(), *queued)
                .map_err(ProcessError::Storage)?;
            Ok(Incoming::Proposal {
                aad,
                kind: ProposalKind::Join,
                sender: None,
                reference,
            })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            let aad = RisalaAad::decode_for(&aad_bytes, ContentType::Commit, private)?;
            let view = CommitView::of(&sender, &staged, group.pending_proposals());
            Ok(Incoming::Commit(Box::new(ReceivedCommit {
                staged,
                view,
                aad,
            })))
        }
        ProcessedMessageContent::OwnPrivateMessage => Ok(Incoming::Own),
        #[allow(unreachable_patterns)]
        _ => Err(ProcessError::Proposal),
    }
}

/// The group checks of a received commit (12.7), against the group as of
/// its epoch, the device's `history`, and its post's `t` and `next`, which
/// must be the hash of the send token of the epoch the commit creates
/// (12.6). An error means the commit is invalid: the device ignores it, and
/// the messages of the epoch it would have started (7.2).
pub fn check_received_commit(
    group: &MlsGroup,
    commit: &ReceivedCommit,
    history: &History,
    post: &CommitPost,
    crypto: &impl OpenMlsCrypto,
) -> Result<Verdict, CommitError> {
    let view = GroupView::of(group.public_group());
    let verdict = check_commit(&view, &commit.view, history, post)?;
    // A device the commit removes has no keys for the new epoch, and so
    // cannot check its token; the others can.
    if commit.staged.self_removed() {
        return Ok(verdict);
    }
    match &post.next {
        Some(next) if next_token_hash_ok(&commit.staged, crypto, next) => Ok(verdict),
        _ => Err(CommitError::NextToken),
    }
}

/// The key checks of a received commit that passed the group checks
/// (12.7), against the group as of its epoch: call it before
/// [`apply_commit`]. They never make the commit invalid.
pub fn check_received_keys(
    group: &MlsGroup,
    commit: &ReceivedCommit,
    verdict: &Verdict,
    facts: &dyn KeyFacts,
) -> KeyReport {
    key_checks(
        &GroupView::of(group.public_group()),
        &commit.view,
        verdict,
        facts,
    )
}

/// Whether `claimed` is the hash of the send token of the epoch `staged`
/// creates (7.2, 12.6), compared in constant time.
pub fn next_token_hash_ok(
    staged: &StagedCommit,
    crypto: &impl OpenMlsCrypto,
    claimed: &[u8; HASH_LEN],
) -> bool {
    SendToken::of_staged_commit(staged, crypto).is_ok_and(|token| ct_eq(&token.hash(), claimed))
}

/// Whether `claimed` is the hash of the send token of `group`'s current
/// epoch (7.2): after applying a commit, a device can check the post's
/// `next` against its own token this way too.
pub fn next_token_hash_matches(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
    claimed: &[u8; HASH_LEN],
) -> bool {
    SendToken::of_group(group, crypto).is_ok_and(|token| ct_eq(&token.hash(), claimed))
}

/// Applies a commit that passed the group checks, with their `verdict`,
/// and records it in `history` with its post. Returns whether this
/// device's leaf is still in the group; if not, its leaf key is deleted,
/// and the caller deletes the group with [`forget_group`] once it no
/// longer needs it. If the commit applied this device's own Update with a
/// new signature key, the old key is deleted.
pub fn apply_commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    commit: ReceivedCommit,
    verdict: &Verdict,
    history: &mut History,
    post: &CommitPost,
) -> Result<bool, GroupError<P::StorageError>> {
    // Another commit won this epoch: this device's own, if any, lost.
    if group.pending_commit().is_some() {
        discard_own_commit(provider, group)?;
    }
    let before = GroupView::of(group.public_group());
    let own_key = group
        .own_leaf_node()
        .map(|leaf| leaf.signature_key().as_slice().to_vec());
    group
        .merge_staged_commit(provider, *commit.staged)
        .map_err(|e: MergeCommitError<_>| mls(e))?;
    let after = GroupView::of(group.public_group());
    history.record(&before, &commit.view, verdict, &after, post);
    let active = group.is_active();
    let new_key = group
        .own_leaf_node()
        .map(|leaf| leaf.signature_key().as_slice().to_vec());
    // Removed, or rotated by an Update: the old leaf key goes now.
    if let Some(key) = own_key
        && (!active || new_key.as_ref() != Some(&key))
    {
        LeafKey::delete(provider.storage(), group.group_id().as_slice(), &key)
            .map_err(GroupError::Storage)?;
    }
    Ok(active)
}

/// Deletes a group this device has left or been removed from, with its
/// leaf key, from storage.
pub fn forget_group<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
) -> Result<(), GroupError<P::StorageError>> {
    if group.is_active()
        && let Some(leaf) = group.own_leaf_node()
    {
        let key = leaf.signature_key().as_slice().to_vec();
        LeafKey::delete(provider.storage(), group.group_id().as_slice(), &key)
            .map_err(GroupError::Storage)?;
    }
    group
        .delete(provider.storage())
        .map_err(GroupError::Storage)
}

/// The leaf node of `index` in `group`.
pub fn leaf(group: &MlsGroup, index: LeafNodeIndex) -> Option<&LeafNode> {
    group.public_group().leaf(index)
}

//! Groups (12.6, 12.7, 6.1): how risala sets up OpenMLS, and the
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
//! - commits always with a path, proposals by value except SelfRemove and
//!   a public room's external Adds (12.6);
//! - keeps a few past epochs for late messages, and pads messages to 256
//!   bytes (12.9).
//!
//! Each operation that posts sets the RisalaAAD (12.9) from the leaf's
//! pseudonym (7.3), which the caller keeps with the group.
//!
//! **Commits and the first valid commit.** A device makes a commit with
//! [`commit`], which leaves it pending. Once the server accepts it and the
//! device knows it won (7.2), it calls [`merge_own_commit`]; if another
//! valid commit for the same epoch came first, [`discard_own_commit`],
//! then processes the winner. Incoming posts go through
//! [`process_message`]; a commit comes back as a [`ReceivedCommit`] to
//! check with [`check_received_commit`] and then apply with
//! [`apply_commit`], or to drop if it is invalid.

use std::time::SystemTime;

use openmls::group::{
    CommitBuilderStageError, CreateCommitError, ExternalCommitBuilderError,
    ExternalCommitBuilderFinalizeError, LeaveGroupError, MergeCommitError, MergePendingCommitError,
    MlsGroup, MlsGroupJoinConfig, NewGroupError,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProcessMessageError,
    StagedCommit, StagedWelcome, WelcomeError, WireFormatPolicy,
};
use openmls::storage::OpenMlsProvider;
use openmls::prelude::{
    Capabilities, CreateMessageError, CredentialType, ExportSecretError, Extension, Extensions,
    GroupContext, GroupId, KeyPackage, KeyPackageBundle, LeafNode, LeafNodeIndex,
    LeafNodeParameters, NewSignerBundle, ProcessedMessageContent, Proposal, ProposalOrRefType,
    ProposalType,
    ProtocolVersion, RequiredCapabilitiesExtension, Sender,
};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::storage::StorageProvider as _;

use crate::CIPHERSUITE;
use crate::aad::{AadError, Pseudonym, RisalaAad};
use crate::binding::{DEVICE_BINDING_EXTENSION, DeviceBinding};
use crate::checks::{
    CommitError, CommitView, GroupView, JoinError, JoinExpectation, KeyFacts, Verdict,
    check_commit, check_join,
};
use crate::conversation::{CONVERSATION_EXTENSION, ConversationKind, RisalaConversation};
use crate::framing::{ContentType, GROUP_ID_LEN};
use crate::identity::RisalaIdentity;
use crate::keypackage::{APP_DATA_DICTIONARY_EXTENSION, encryption_key_bytes, is_last_resort};
use crate::mldsa::{KEY_PACKAGE_SCOPE, LeafKey, SigningKey};
use crate::primitives::{HASH_LEN, ct_eq};
use crate::profile::{PROFILE_EXTENSION, RisalaProfile};
use crate::seeded::{Parts, SeededRand};
use crate::token::SendToken;
use crate::wire::{WireError, read_group_info, read_protocol_message, read_tree, read_welcome};

/// How many past epochs a device keeps the secrets of, to decrypt messages
/// that arrive late (12.9: "a few epochs").
pub const MAX_PAST_EPOCHS: usize = 4;

/// The multiple of bytes that PrivateMessage contents are padded to
/// (12.9).
pub const PADDING_SIZE: usize = 256;

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
        &[CONVERSATION_EXTENSION, DEVICE_BINDING_EXTENSION, PROFILE_EXTENSION],
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

/// The configuration of a group of `kind` (12.6, 12.8, 12.9).
pub fn join_config(kind: ConversationKind) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(wire_format_policy(kind))
        .use_ratchet_tree_extension(kind != ConversationKind::PublicRoom)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .padding_size(PADDING_SIZE)
        .build()
}

/// The parameters of a leaf this device commits: the capabilities and the
/// profile, and a device binding only in an external commit (12.3). A
/// leaf's binding covers the encryption key it was made with, so its later
/// commits leave it out; it is checked only when the leaf joins.
fn leaf_parameters(profile: &RisalaProfile, binding: Option<&DeviceBinding>) -> LeafNodeParameters {
    let mut extensions = vec![profile.to_extension()];
    extensions.extend(binding.map(DeviceBinding::to_extension));
    LeafNodeParameters::builder()
        .with_capabilities(capabilities())
        .with_extensions(Extensions::from_vec(extensions).expect("distinct leaf extensions"))
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
    /// acceptable.
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

/// Creates the group of a new conversation (12.6): a new random 32-byte
/// group id, this device the only member with a new leaf key, and
/// `conversation` in the group context. The leaf key is stored with the
/// group.
pub fn create_group<P: OpenMlsProvider>(
    provider: &P,
    identity: &RisalaIdentity,
    profile: &RisalaProfile,
    conversation: &RisalaConversation,
) -> Result<(MlsGroup, LeafKey), GroupError<P::StorageError>> {
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
            Extensions::single(profile.to_extension()).expect("a profile is a leaf extension"),
        )
        .map_err(mls)?
        .with_group_context_extensions(group_context_extensions(conversation))
        .with_wire_format_policy(wire_format_policy(kind))
        .use_ratchet_tree_extension(kind != ConversationKind::PublicRoom)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .padding_size(PADDING_SIZE)
        .build(
            provider,
            &leaf_key,
            identity.credential_with_key(leaf_key.public_key()),
        )
        .map_err(|e: NewGroupError<_>| mls(e))?;
    Ok((group, leaf_key))
}

/// What a commit changes (12.6, 12.7). Proposals pending in the group,
/// SelfRemoves and a public room's external Adds, are always committed
/// too, by reference; nothing else is.
#[derive(Debug, Default, Clone)]
pub struct Changes {
    /// KeyPackages of devices to add, already checked (12.5, 12.7).
    pub add: Vec<KeyPackage>,
    /// Leaves to remove.
    pub remove: Vec<LeafNodeIndex>,
    /// A new conversation extension (6.2, 6.3, 6.4).
    pub conversation: Option<RisalaConversation>,
    /// Whether to commit a new leaf key: right after joining with a
    /// last-resort KeyPackage, and once a period in an epochal group
    /// (12.3).
    pub new_leaf_key: bool,
}

/// A commit this device made, pending in its group.
#[derive(Debug)]
pub struct CommitOutput {
    /// The commit, a `<message>` to post.
    pub message: Vec<u8>,
    /// The Welcome for the devices it adds, as `<welcome>` bytes.
    pub welcome: Option<Vec<u8>>,
    /// In a public room, the new epoch's GroupInfo, with `external_pub`
    /// and without the tree, for POST's `groupinfo=` (12.6).
    pub group_info: Option<Vec<u8>>,
    /// The SHA-384 hash of the send token of the epoch the commit creates
    /// (7.2). It cannot be in the commit's own RisalaAAD (see
    /// [`crate::aad`]); it travels next to the commit.
    pub next_token_hash: [u8; HASH_LEN],
    /// The new leaf key, if the commit has one. It is in storage; once the
    /// commit is merged, the old one is deleted.
    pub new_leaf_key: Option<LeafKey>,
}

/// Makes a commit (12.6) with `changes`, always with a path, and leaves it
/// pending in `group`. The committer's leaf gets `profile`, whose
/// `updated` should be the current time (12.3). Post the commit; then
/// [`merge_own_commit`] if it wins, or [`discard_own_commit`].
///
/// With no changes, it is the weekly fresh-leaf commit (12.7).
pub fn commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    pseudonym: Pseudonym,
    profile: &RisalaProfile,
    changes: Changes,
) -> Result<CommitOutput, GroupError<P::StorageError>> {
    let kind = conversation(group)
        .ok_or_else(|| GroupError::Group("no conversation extension".into()))?
        .kind;
    let leaf_key = own_leaf_key(provider, group)?;
    let identity = RisalaIdentity::from_credential(
        group
            .own_leaf_node()
            .ok_or_else(|| GroupError::Group("no own leaf".into()))?
            .credential(),
    )
    .map_err(|e| GroupError::Group(e.to_string()))?;
    group.set_aad(RisalaAad::handshake(pseudonym).encode());
    let group_id = group.group_id().as_slice().to_vec();
    let Changes {
        add,
        remove,
        conversation: new_conversation,
        new_leaf_key,
    } = changes;
    let mut builder = group
        .commit_builder()
        .propose_adds(add)
        .propose_removals(remove)
        .force_self_update(true)
        .consume_proposal_store(true)
        .leaf_node_parameters(leaf_parameters(profile, None));
    if let Some(conversation) = new_conversation {
        builder = builder
            .propose_group_context_extensions(group_context_extensions(&conversation))
            .map_err(|e: CreateCommitError| mls(e))?;
    }
    let builder = builder
        .load_psks(provider.storage())
        .map_err(mls)?
        .create_group_info(kind == ConversationKind::PublicRoom);
    // Only SelfRemoves and a public room's external Adds are committed by
    // reference (12.6).
    // OpenMLS passes this device's own proposals, by value, through the
    // same filter.
    let by_reference_ok = |queued: &openmls::group::QueuedProposal| {
        queued.proposal_or_ref_type() == ProposalOrRefType::Proposal
            || match (queued.proposal(), queued.sender()) {
                (Proposal::SelfRemove, Sender::Member(_)) => true,
                (Proposal::Add(_), Sender::NewMemberProposal) => {
                    kind == ConversationKind::PublicRoom
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
        None => builder.build(provider.rand(), provider.crypto(), &leaf_key, by_reference_ok),
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
    let (message, welcome, group_info) = bundle.into_messages();
    Ok(CommitOutput {
        message: crate::wire::to_bytes(&message),
        welcome: welcome.as_ref().map(crate::wire::to_bytes),
        group_info: group_info.as_ref().map(crate::wire::to_bytes),
        next_token_hash,
        new_leaf_key: fresh,
    })
}

/// Merges this device's pending commit, once it has won its epoch (7.2),
/// and deletes the leaf key it replaced, if any.
pub fn merge_own_commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
) -> Result<(), GroupError<P::StorageError>> {
    let old_key = group
        .own_leaf_node()
        .map(|leaf| leaf.signature_key().as_slice().to_vec());
    group
        .merge_pending_commit(provider)
        .map_err(|e: MergePendingCommitError<_>| mls(e))?;
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
/// (12.6), through the patched OpenMLS (`crates/openmls/RISALA.md`).
pub fn self_remove<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    pseudonym: Pseudonym,
) -> Result<Vec<u8>, GroupError<P::StorageError>> {
    let leaf_key = own_leaf_key(provider, group)?;
    group.set_aad(RisalaAad::handshake(pseudonym).encode());
    let message = group
        .leave_group_via_self_remove(provider, &leaf_key)
        .map_err(|e: LeaveGroupError<_>| mls(e))?;
    Ok(crate::wire::to_bytes(&message))
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
    if aad.check_for(ContentType::Application).is_err() {
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
    /// must commit a new leaf key before it sends anything (12.3, 12.5):
    /// [`commit`] with [`Changes::new_leaf_key`].
    pub last_resort: bool,
}

/// Joins a group by Welcome (12.8): decrypts it with one of this device's
/// KeyPackages, takes the tree from the Welcome's GroupInfo or from `tree`
/// (a public room's, from GROUPINFO), skips the lifetimes of leaves
/// already in the tree (12.5), and checks the group as 12.7 says. A group
/// that fails is deleted from storage again, and the error says why.
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
) -> Result<Joined, GroupError<P::StorageError>> {
    let welcome = read_welcome(welcome)?;
    let tree = tree.map(read_tree).transpose()?;
    // A last-resort KeyPackage is kept: find it before OpenMLS deletes it.
    let mut keep = None;
    for secrets in welcome.secrets() {
        let bundle: Option<KeyPackageBundle> = provider
            .storage()
            .key_package(&secrets.new_member())
            .map_err(GroupError::Storage)?;
        if let Some(bundle) = bundle {
            if is_last_resort(bundle.key_package()).unwrap_or(false) {
                keep = Some(bundle);
            }
            break;
        }
    }
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
    let mut group = builder
        .skip_lifetime_validation()
        .build()
        .map_err(|e: WelcomeError<_>| mls(e))?
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
    Ok(Joined {
        group,
        last_resort: keep.is_some(),
    })
}

/// A join by external commit, made and pending the server's answer.
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
    /// The hash of the new epoch's send token (7.2, see [`crate::aad`]).
    pub next_token_hash: [u8; HASH_LEN],
    /// This device's own earlier leaves, with the same device id, which it
    /// removes in its next commit (12.7). OpenMLS 0.9 does not let an
    /// external commit remove them itself, unless they share its leaf key.
    pub earlier_leaves: Vec<LeafNodeIndex>,
}

/// Joins a public room by external commit (6.1, 12.6), from GROUPINFO's
/// GroupInfo and tree, without checking the lifetimes of leaves in the tree
/// (12.5). The group is checked as 12.7 says before anything is sent.
///
/// A device's leaf carries a device binding by `device_key` over its
/// encryption key (12.3); a guest's (`device_key` `None`) carries none.
/// This device's own earlier leaves come back in
/// [`ExternalJoin::earlier_leaves`].
#[allow(clippy::too_many_arguments)]
pub fn join_by_external_commit<P: OpenMlsProvider>(
    provider: &P,
    identity: &RisalaIdentity,
    device_key: Option<&SigningKey>,
    profile: &RisalaProfile,
    pseudonym: Pseudonym,
    group_info: &[u8],
    tree: &[u8],
    expect: &JoinExpectation,
) -> Result<ExternalJoin, GroupError<P::StorageError>> {
    if identity.is_guest() != device_key.is_none() {
        return Err(GroupError::Group("a device key for a device, none for a guest".into()));
    }
    let group_info = read_group_info(group_info)?;
    let tree = read_tree(tree)?;
    let leaf_key = LeafKey::generate().map_err(|_| GroupError::Random)?;
    let credential = identity.credential_with_key(leaf_key.public_key());
    let aad = RisalaAad::handshake(pseudonym).encode();
    let seed = SeededRand::fresh().map_err(|_| GroupError::Random)?;

    // First pass, against throwaway storage: the group as it is, for the
    // checks, and the leaf's encryption key, for the binding.
    let scratch = MemoryStorage::default();
    let rand = SeededRand::new(&seed);
    let parts = Parts {
        crypto: provider.crypto(),
        rand: &rand,
        storage: &scratch,
    };
    let (first, _) = external_commit(
        &parts,
        &leaf_key,
        credential.clone(),
        group_info.clone(),
        tree.clone(),
        aad.clone(),
        profile,
        None,
    )
    .map_err(|e| GroupError::Mls(e.to_string()))?;
    let own_index = first.own_leaf_index();
    let mut view = GroupView::of(first.public_group());
    view.leaves.retain(|leaf| leaf.index != own_index);
    check_join(&view, expect)?;
    let earlier: Vec<LeafNodeIndex> = view
        .leaves
        .iter()
        .filter(|leaf| leaf.identity.as_ref() == Some(identity) && !identity.is_guest())
        .map(|leaf| leaf.index)
        .collect();
    let encryption_key = encryption_key_bytes(
        first
            .own_leaf_node()
            .ok_or_else(|| GroupError::Mls("no own leaf".into()))?
            .encryption_key(),
    );
    let binding =
        device_key.map(|key| DeviceBinding::sign(key, &identity.uid, b"", &encryption_key));

    // Second pass, for real, with the same randomness and so the same keys.
    leaf_key
        .store(provider.storage(), first.group_id().as_slice())
        .map_err(GroupError::Storage)?;
    let rand = SeededRand::new(&seed);
    let parts = Parts {
        crypto: provider.crypto(),
        rand: &rand,
        storage: provider.storage(),
    };
    let (group, bundle) = external_commit(
        &parts,
        &leaf_key,
        credential,
        group_info,
        tree,
        aad,
        profile,
        binding.as_ref(),
    )
    .map_err(|e| GroupError::Mls(e.to_string()))?;
    let own = group
        .own_leaf_node()
        .ok_or_else(|| GroupError::Mls("no own leaf".into()))?;
    if encryption_key_bytes(own.encryption_key()) != encryption_key {
        return Err(GroupError::Mls(
            "OpenMLS made another leaf key on the second pass".into(),
        ));
    }
    let next_token_hash = SendToken::of_group(&group, provider.crypto())
        .map_err(|e: ExportSecretError| mls(e))?
        .hash();
    let (message, _welcome, group_info) = bundle.into_messages();
    let group_info = group_info.ok_or_else(|| GroupError::Mls("no GroupInfo".into()))?;
    Ok(ExternalJoin {
        group,
        leaf_key,
        message: crate::wire::to_bytes(&message),
        group_info: crate::wire::to_bytes(&group_info),
        next_token_hash,
        earlier_leaves: earlier,
    })
}

/// Why an external commit failed in OpenMLS.
#[derive(Debug, thiserror::Error)]
enum ExternalError<E: std::fmt::Debug> {
    #[error("{0}")]
    Build(ExternalCommitBuilderError<E>),
    #[error("{0}")]
    Commit(CreateCommitError),
    #[error("{0}")]
    Finalize(ExternalCommitBuilderFinalizeError<E>),
}

#[allow(clippy::too_many_arguments)]
fn external_commit<P: OpenMlsProvider>(
    provider: &P,
    leaf_key: &LeafKey,
    credential: openmls::prelude::CredentialWithKey,
    group_info: openmls::messages::group_info::VerifiableGroupInfo,
    tree: openmls::prelude::RatchetTreeIn,
    aad: Vec<u8>,
    profile: &RisalaProfile,
    binding: Option<&DeviceBinding>,
) -> Result<(MlsGroup, openmls::group::CommitMessageBundle), ExternalError<P::StorageError>> {
    MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree)
        .with_config(join_config(ConversationKind::PublicRoom))
        .with_aad(aad)
        .skip_lifetime_validation()
        .build_group(provider, group_info, credential)
        .map_err(ExternalError::Build)?
        .leaf_node_parameters(leaf_parameters(profile, binding))
        .load_psks(provider.storage())
        .map_err(ExternalError::Commit)?
        .create_group_info(true)
        .build(provider.rand(), provider.crypto(), leaf_key, |_| true)
        .map_err(ExternalError::Commit)?
        .finalize(provider)
        .map_err(ExternalError::Finalize)
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
    /// A SelfRemove, or in a public room an external Add proposal, now
    /// pending in the group until a commit covers it (6.1).
    Proposal {
        /// The RisalaAAD.
        aad: RisalaAad,
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
    /// A proposal that is not a SelfRemove, or an external Add outside a
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
pub fn process_message<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    message: &[u8],
) -> Result<Incoming, ProcessError<P::StorageError>> {
    let kind = conversation(group).ok_or(ProcessError::Group)?.kind;
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
                aad: RisalaAad::decode_for(&aad_bytes, ContentType::Application)?,
                content: message.into_bytes(),
            })
        }
        ProcessedMessageContent::ProposalMessage(queued) => {
            let aad = RisalaAad::decode_for(&aad_bytes, ContentType::Proposal)?;
            match (queued.proposal(), queued.sender()) {
                (Proposal::SelfRemove, Sender::Member(_)) => {}
                _ => return Err(ProcessError::Proposal),
            }
            group
                .store_pending_proposal(provider.storage(), *queued)
                .map_err(ProcessError::Storage)?;
            Ok(Incoming::Proposal { aad })
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(queued) => {
            let aad = RisalaAad::decode_for(&aad_bytes, ContentType::Proposal)?;
            if kind != ConversationKind::PublicRoom {
                return Err(ProcessError::Proposal);
            }
            group
                .store_pending_proposal(provider.storage(), *queued)
                .map_err(ProcessError::Storage)?;
            Ok(Incoming::Proposal { aad })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            let aad = RisalaAad::decode_for(&aad_bytes, ContentType::Commit)?;
            let view = CommitView::of(&sender, &staged, group.pending_proposals());
            Ok(Incoming::Commit(Box::new(ReceivedCommit { staged, view, aad })))
        }
        ProcessedMessageContent::OwnPrivateMessage => Ok(Incoming::Own),
        #[allow(unreachable_patterns)]
        _ => Err(ProcessError::Proposal),
    }
}

/// Checks a received commit as 12.7 says, against the group as of its
/// epoch, and its `next_token_hash` if it carries one (7.2).
pub fn check_received_commit(
    group: &MlsGroup,
    commit: &ReceivedCommit,
    facts: &dyn KeyFacts,
    crypto: &impl OpenMlsCrypto,
    now: SystemTime,
) -> Result<Verdict, CommitError> {
    let view = GroupView::of(group.public_group());
    let verdict = check_commit(&view, &commit.view, facts, now)?;
    if let Some(claimed) = &commit.aad.next_token_hash
        && !next_token_hash_ok(&commit.staged, crypto, claimed)
    {
        return Err(CommitError::Proposal("a wrong next token hash"));
    }
    Ok(verdict)
}

/// Whether `claimed` is the hash of the send token of the epoch `staged`
/// creates (7.2, 12.7), compared in constant time.
pub fn next_token_hash_ok(
    staged: &StagedCommit,
    crypto: &impl OpenMlsCrypto,
    claimed: &[u8; HASH_LEN],
) -> bool {
    SendToken::of_staged_commit(staged, crypto).is_ok_and(|token| ct_eq(&token.hash(), claimed))
}

/// Applies a commit that passed the checks. Returns whether this device's
/// leaf is still in the group; if not, delete the group and its leaf key.
pub fn apply_commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    commit: ReceivedCommit,
) -> Result<bool, GroupError<P::StorageError>> {
    // Another commit won this epoch: this device's own, if any, lost.
    if group.pending_commit().is_some() {
        discard_own_commit(provider, group)?;
    }
    group
        .merge_staged_commit(provider, *commit.staged)
        .map_err(|e: MergeCommitError<_>| mls(e))?;
    Ok(group.is_active())
}

/// The leaf node of `index` in `group`.
pub fn leaf(group: &MlsGroup, index: LeafNodeIndex) -> Option<&LeafNode> {
    group.public_group().leaf(index)
}

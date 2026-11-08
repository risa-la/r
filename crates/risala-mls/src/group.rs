//! How risala configures OpenMLS (12.2, 12.4-12.7): leaf capabilities,
//! group context extensions, creating a group, KeyPackages, joining, and
//! commits.
//!
//! Every group:
//!
//! - uses the cipher suite `0x0020` and `basic` credentials (12.2)
//! - carries the conversation extension, and requires it of every leaf
//!   through `required_capabilities` (12.2)
//! - sends commits as PublicMessages, so the server can check them (12.5),
//!   and never puts the ratchet tree in an extension: it travels as
//!   `<tree>` (12.2, 12.5)
//!
//! Devices skip the lifetime check of leaves already in the tree when they
//! join, by Welcome or by external commit (12.4, 12.6).

use openmls::group::{
    CommitBuilderStageError, CommitMessageBundle, CreateCommitError, ExternalCommitBuilderError,
    ExternalCommitBuilderFinalizeError, MlsGroup, MlsGroupJoinConfig, NewGroupError,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, StagedWelcome, WelcomeError,
};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::{
    Capabilities, CredentialType, Extension, ExtensionType, Extensions, GroupContext, GroupId,
    KeyPackage, KeyPackageBundle, KeyPackageNewError, LeafNodeIndex, LeafNodeParameters, Lifetime,
    ProtocolVersion, RatchetTreeIn, RequiredCapabilitiesExtension, Welcome,
};
use openmls::storage::OpenMlsProvider;
use openmls_traits::random::OpenMlsRand;
use risala_proto::mls::CONVERSATION_EXTENSION_TYPE;
use risala_proto::names::Uid;

use crate::CIPHERSUITE;
use crate::conversation::RisalaConversation;
use crate::signer::{DeviceSigner, credential_with_key};

/// How long a KeyPackage is valid after it is made: 12 weeks, OpenMLS's
/// default (12.4). OpenMLS starts the lifetime an hour early, for clocks
/// that are behind, so it spans [`MAX_LIFETIME_SPAN`].
pub const KEY_PACKAGE_LIFETIME: u64 = 12 * 7 * 24 * 60 * 60;

/// The longest lifetime a KeyPackage may span, from `not_before` to
/// `not_after`: 12 weeks and one hour, 7261200 seconds (12.4).
pub const MAX_LIFETIME_SPAN: u64 = KEY_PACKAGE_LIFETIME + 60 * 60;

/// The length of a new group's id (12.5).
pub const GROUP_ID_LEN: usize = 32;

/// The conversation extension's type, as OpenMLS names it.
pub const CONVERSATION_EXTENSION: ExtensionType =
    ExtensionType::Unknown(CONVERSATION_EXTENSION_TYPE);

/// A leaf's capabilities (12.2): `mls10`, the suite, `basic` credentials,
/// and the extensions `0xF2A1` and `last_resort`.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[CONVERSATION_EXTENSION, ExtensionType::LastResort]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

/// Whether a leaf's capabilities list what 12.2 requires: the suite,
/// `basic` credentials, and the extensions `0xF2A1` and `last_resort`.
pub fn has_capabilities(capabilities: &Capabilities) -> bool {
    capabilities.ciphersuites().contains(&CIPHERSUITE.into())
        && capabilities.credentials().contains(&CredentialType::Basic)
        && capabilities.extensions().contains(&CONVERSATION_EXTENSION)
        && capabilities
            .extensions()
            .contains(&ExtensionType::LastResort)
}

/// The group's `required_capabilities` (12.2): the conversation extension
/// and `basic` credentials.
pub fn required_capabilities() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(&[CONVERSATION_EXTENSION], &[], &[CredentialType::Basic])
}

/// A group context's extensions (12.2): `required_capabilities` and the
/// conversation extension. An owner's commit that changes `history` or
/// `send` proposes these with the new values (12.5).
pub fn group_context_extensions(conversation: &RisalaConversation) -> Extensions<GroupContext> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(required_capabilities()),
        conversation.to_extension(),
    ])
    .expect("two extensions of different types")
}

/// The configuration of a group a device joins (12.6, 12.7): commits as
/// PublicMessages, and no ratchet tree extension.
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
        .build()
}

/// Creates the group of a conversation for INIT (12.5): a new random
/// 32-byte group id, this device the only member, and `conversation` in
/// the group context.
///
/// Send its GroupInfo, from
/// [`MlsGroup::export_group_info`] without the ratchet tree, and its tree
/// from [`MlsGroup::export_ratchet_tree`].
pub fn create_group<P: OpenMlsProvider>(
    provider: &P,
    signer: &DeviceSigner<'_>,
    uid: &Uid,
    conversation: &RisalaConversation,
) -> Result<MlsGroup, CreateGroupError<P::StorageError>> {
    let id: [u8; GROUP_ID_LEN] = provider
        .rand()
        .random_array()
        .map_err(|_| CreateGroupError::Random)?;
    Ok(MlsGroup::builder()
        .ciphersuite(CIPHERSUITE)
        .with_group_id(GroupId::from_slice(&id))
        .with_capabilities(capabilities())
        .with_group_context_extensions(group_context_extensions(conversation))
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
        .build(
            provider,
            signer,
            credential_with_key(uid.as_str(), &signer.public_key()),
        )?)
}

/// Why a group could not be created.
#[derive(Debug, thiserror::Error)]
pub enum CreateGroupError<E> {
    /// No random group id could be had.
    #[error("no randomness for the group id")]
    Random,
    /// OpenMLS could not create the group.
    #[error(transparent)]
    Group(#[from] NewGroupError<E>),
}

/// Makes a KeyPackage for KEYPKG ADD (12.4), with a lifetime of
/// [`KEY_PACKAGE_LIFETIME`]. A `last_resort` one carries the `last_resort`
/// extension. OpenMLS keeps its private keys in the provider's storage
/// until a Welcome uses them.
pub fn key_package<P: OpenMlsProvider>(
    provider: &P,
    signer: &DeviceSigner<'_>,
    uid: &Uid,
    last_resort: bool,
) -> Result<KeyPackageBundle, KeyPackageNewError> {
    let mut builder = KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME));
    if last_resort {
        builder = builder.mark_as_last_resort();
    }
    builder.build(
        CIPHERSUITE,
        provider,
        signer,
        credential_with_key(uid.as_str(), &signer.public_key()),
    )
}

/// Starts joining a group by Welcome (12.7), with the tree from the
/// WELCOME line, and without checking the lifetimes of leaves in the tree
/// (12.4).
///
/// Check the group as 12.6 says, through [`StagedWelcome::group_context`]
/// and [`StagedWelcome::members`], before
/// [`StagedWelcome::into_group`]. OpenMLS deletes the KeyPackage's private
/// keys from storage here, so run this in a transaction that is rolled
/// back if joining fails, to be able to try again (12.7).
pub fn stage_welcome<P: OpenMlsProvider>(
    provider: &P,
    welcome: Welcome,
    tree: RatchetTreeIn,
) -> Result<StagedWelcome, WelcomeError<P::StorageError>> {
    StagedWelcome::build_from_welcome(provider, &join_config(), welcome)?
        .with_ratchet_tree(tree)
        .skip_lifetime_validation()
        .build()
}

/// Why an external commit could not be made.
#[derive(Debug, thiserror::Error)]
pub enum ExternalJoinError<E> {
    /// The GroupInfo or tree are not usable.
    #[error(transparent)]
    Build(#[from] ExternalCommitBuilderError<E>),
    /// The commit could not be made.
    #[error(transparent)]
    Commit(#[from] CreateCommitError),
    /// The commit could not be finished.
    #[error(transparent)]
    Finalize(#[from] ExternalCommitBuilderFinalizeError<E>),
}

/// Joins a group by external commit (12.6), from the GroupInfo and tree of
/// GROUPINFO, without checking the lifetimes of leaves in the tree (12.4).
///
/// OpenMLS removes a leaf that has this device's signature key by itself,
/// as 12.6 requires. Check the group as 12.6 says before sending the
/// commit. The group comes back already in the new epoch; if the server
/// refuses the commit, drop it. The bundle has the commit and the new
/// epoch's GroupInfo for COMMIT.
pub fn join_by_external_commit<P: OpenMlsProvider>(
    provider: &P,
    signer: &DeviceSigner<'_>,
    uid: &Uid,
    group_info: VerifiableGroupInfo,
    tree: RatchetTreeIn,
) -> Result<(MlsGroup, CommitMessageBundle), ExternalJoinError<P::StorageError>> {
    Ok(MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree)
        .with_config(join_config())
        .skip_lifetime_validation()
        .build_group(
            provider,
            group_info,
            credential_with_key(uid.as_str(), &signer.public_key()),
        )?
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(capabilities())
                .build(),
        )
        .load_psks(provider.storage())?
        .create_group_info(true)
        .build(provider.rand(), provider.crypto(), signer, |_| true)?
        .finalize(provider)?)
}

/// What a commit changes (12.5, 12.6). All proposals go inside the commit.
/// A commit with nothing in it refreshes the committer's own leaf.
#[derive(Debug, Default)]
pub struct Changes {
    /// KeyPackages of devices to add, already checked (12.4, 12.6).
    pub add: Vec<KeyPackage>,
    /// Leaves to remove.
    pub remove: Vec<LeafNodeIndex>,
    /// New `history` and `send` values, from a room's owner (12.5).
    pub conversation: Option<RisalaConversation>,
}

/// Why a commit could not be made.
#[derive(Debug, thiserror::Error)]
pub enum CommitError<E> {
    /// The commit could not be made.
    #[error(transparent)]
    Create(#[from] CreateCommitError),
    /// The commit could not be staged.
    #[error(transparent)]
    Stage(#[from] CommitBuilderStageError<E>),
}

/// Makes a commit for COMMIT (12.5), and leaves it pending in `group`.
///
/// The bundle has the commit, the new epoch's GroupInfo with
/// `external_pub` and without the ratchet tree, and a Welcome when the
/// commit adds devices. Before the server accepts it, derive the current
/// epoch's history key if not done yet (12.9). Then merge it with
/// [`MlsGroup::merge_pending_commit`] once the server accepts it, or
/// clear it with [`MlsGroup::clear_pending_commit`] if it refuses.
pub fn commit<P: OpenMlsProvider>(
    provider: &P,
    group: &mut MlsGroup,
    signer: &DeviceSigner<'_>,
    changes: Changes,
) -> Result<CommitMessageBundle, CommitError<P::StorageError>> {
    let Changes {
        add,
        remove,
        conversation,
    } = changes;
    let refresh = add.is_empty() && remove.is_empty() && conversation.is_none();
    let mut builder = group
        .commit_builder()
        .propose_adds(add)
        .propose_removals(remove)
        .force_self_update(refresh);
    if let Some(conversation) = conversation {
        builder =
            builder.propose_group_context_extensions(group_context_extensions(&conversation))?;
    }
    Ok(builder
        .load_psks(provider.storage())?
        .create_group_info(true)
        .build(provider.rand(), provider.crypto(), signer, |_| true)?
        .stage_commit(provider)?)
}

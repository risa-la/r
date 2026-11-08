//! The MLS side of INIT and COMMIT (12.5): what the server can check of a
//! group, a commit and a GroupInfo with OpenMLS's `PublicGroup` alone,
//! holding no secrets.
//!
//! [`check_init`] and [`check_commit`] are plain functions, run on the
//! blocking pool, since they verify ML-DSA signatures and hash the tree.
//! They check everything that needs only the group and the command, and
//! return what the rest needs: who the commit adds and removes, and the
//! group in its new epoch, ready to store. The checks that need the
//! conversation's membership or key files are the hub's (`encrypted`).
//!
//! On top of what OpenMLS checks, these are the rules the spike found it
//! does not enforce (PLAN.md 5, item 22): a leaf's credential and
//! signature key never change; the lifetimes of the KeyPackages a commit
//! adds are checked with [`risala_mls::lifetime_acceptable`]; an external
//! commit removes at most the joiner's own earlier leaf; the GroupInfo is
//! the new epoch's, with the commit's confirmation tag, signed by the
//! committer; and the group's extensions are exactly
//! [`risala_mls::group::group_context_extensions`] of its conversation.
//!
//! Every HPKE public key that devices may encrypt to must have the length
//! of an X-Wing key: each leaf's and parent node's in the tree, the
//! GroupInfo's `external_pub`, and the init keys of the KeyPackages a
//! commit adds. OpenMLS does not check their length, and the libcrux-kem
//! that devices use panics on a short one (PLAN.md 5, item 50), so the
//! server does not hand such a group to devices. A commit's Welcome must be
//! for exactly the KeyPackages it adds.

use std::time::SystemTime;

use risala_mls::conversation::RisalaConversation;
use risala_mls::group::group_context_extensions;
use risala_mls::openmls::ciphersuite::signable::Verifiable as _;
use risala_mls::openmls::messages::group_info::VerifiableGroupInfo;
use risala_mls::openmls::prelude::{ConfirmationTag, ProposalStore};
use risala_mls::openmls::prelude::{
    ContentType, Extensions, GroupContext, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn,
    OpenMlsSignaturePublicKey, ParentNode, ProcessedMessageContent, Proposal, ProposalOrRefType,
    ProposalType, ProtocolVersion, PublicGroup, PublicProcessMessageError, Sender,
    StageCommitError,
};
use risala_mls::signer::{credential_uid, signature_key};
use risala_mls::{CIPHERSUITE, RisalaCrypto, wire};
use risala_proto::auth::PublicKey;
use risala_proto::error::ErrorCode;
use risala_proto::mls;
use risala_proto::names::Uid;
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

use super::commands::{Fail, fail};
use crate::store::{GroupLeaf, GroupMeta, GroupParts, GroupRecord, GroupState};

fn invalid(message: &str) -> Fail {
    fail(ErrorCode::Invalid, message)
}

fn forbidden(message: &str) -> Fail {
    fail(ErrorCode::Forbidden, message)
}

/// The device that sent the command: the connection's identity and the
/// key it signed in with (4.5).
#[derive(Debug, Clone, Copy)]
pub(super) struct Device<'a> {
    pub(super) uid: &'a Uid,
    pub(super) key: &'a PublicKey,
}

/// A leaf's identity and key, or `None` if its credential is not a uid of
/// an identity in lower case, or its key not an ML-DSA-44 key (12.2).
fn leaf_of(
    credential: &risala_mls::openmls::prelude::Credential,
    key: &[u8],
) -> Option<(Uid, PublicKey)> {
    let uid: Uid = credential_uid(credential)?.parse().ok()?;
    if !uid.is_identity() {
        return None;
    }
    Some((uid, signature_key(key)?))
}

/// The leaves of `group`, each as whose device it is.
fn leaves(group: &PublicGroup) -> Result<Vec<GroupLeaf>, Fail> {
    group
        .members()
        .map(|m| {
            let (uid, key) = leaf_of(&m.credential, &m.signature_key)
                .ok_or_else(|| invalid("a leaf is not a device of an identity"))?;
            Ok(GroupLeaf {
                index: m.index.u32(),
                uid,
                key,
            })
        })
        .collect()
}

/// The group's state, once OpenMLS has written it to `state`.
fn parts(state: &GroupState) -> Result<GroupParts, Fail> {
    state.parts().ok_or_else(|| {
        Fail::Store(crate::store::StoreError::Corrupt(
            "group state is missing a part".into(),
        ))
    })
}

fn state_error(e: impl std::fmt::Debug) -> Fail {
    Fail::Store(crate::store::StoreError::Corrupt(format!(
        "group state: {e:?}"
    )))
}

/// Reads a `<groupinfo>`.
fn group_info(value: &mls::GroupInfo) -> Result<VerifiableGroupInfo, Fail> {
    wire::group_info_from_wire(value).map_err(|e| invalid(&e.to_string()))
}

/// The checks of a GroupInfo's extensions (12.5): `external_pub`, and no
/// `ratchet_tree`.
fn check_group_info_extensions(gi: &VerifiableGroupInfo) -> Result<(), Fail> {
    let Some(external) = gi.extensions().external_pub() else {
        return Err(invalid("the GroupInfo has no external_pub extension"));
    };
    if !risala_mls::hpke_public_key_ok(external.external_pub().as_slice()) {
        return Err(invalid(
            "the GroupInfo's external_pub is not an X-Wing public key",
        ));
    }
    if gi.extensions().ratchet_tree().is_some() {
        return Err(invalid("the GroupInfo has a ratchet_tree extension"));
    }
    Ok(())
}

/// Whether a parent node's encryption key is an X-Wing public key. OpenMLS
/// keeps the key private, so it is read from the node's encoding, where it
/// comes first (RFC 9420, 7.1).
fn parent_key_ok(parent: &ParentNode) -> bool {
    let Ok(bytes) = parent.tls_serialize_detached() else {
        return false;
    };
    matches!(
        VLBytes::tls_deserialize(&mut bytes.as_slice()),
        Ok(key) if risala_mls::hpke_public_key_ok(key.as_slice())
    )
}

/// Checks that every leaf's and parent node's encryption key in `group`'s
/// tree is an X-Wing public key (12.2).
fn check_tree_keys(group: &PublicGroup) -> Result<(), Fail> {
    let tree = group.treesync();
    if !tree
        .full_leaves()
        .all(|(_, leaf)| risala_mls::encryption_key_ok(leaf.encryption_key()))
    {
        return Err(invalid(
            "a leaf's encryption key is not an X-Wing public key",
        ));
    }
    if !tree.full_parents().all(|(_, parent)| parent_key_ok(parent)) {
        return Err(invalid(
            "a parent node's encryption key is not an X-Wing public key",
        ));
    }
    Ok(())
}

/// Checks the conversation extension and the rest of the group's
/// extensions: they must be exactly those of `conversation` (12.2).
fn check_extensions(context: &GroupContext, conversation: &RisalaConversation) -> Result<(), Fail> {
    if context.extensions() != &group_context_extensions(conversation) {
        return Err(invalid(
            "the group's extensions are not those of this conversation",
        ));
    }
    Ok(())
}

/// A group that INIT may store (12.5).
#[derive(Debug)]
pub(super) struct NewGroup {
    pub(super) record: GroupRecord,
    pub(super) leaves: Vec<GroupLeaf>,
    /// Its conversation extension.
    pub(super) conversation: RisalaConversation,
}

/// The checks of INIT that need only the group (12.5): the GroupInfo of
/// epoch 0 with `external_pub` and no `ratchet_tree`, signed by the only
/// leaf of `tree`, whose credential and key are `device`'s; a 32-byte
/// group id; the suite of 12.2; and a conversation extension that names
/// this conversation (`names`), with the rest of the extensions as 12.2
/// has them.
pub(super) fn check_init(
    crypto: &RisalaCrypto,
    device: Device<'_>,
    gi_value: &mls::GroupInfo,
    tree: &mls::RatchetTree,
    names: impl Fn(&RisalaConversation) -> bool,
) -> Result<NewGroup, Fail> {
    let gi = group_info(gi_value)?;
    if gi.ciphersuite() != CIPHERSUITE {
        return Err(invalid("the group uses another cipher suite"));
    }
    if gi.epoch().as_u64() != 0 {
        return Err(invalid("INIT is for epoch 0"));
    }
    if gi.group_id().as_slice().len() != risala_mls::group::GROUP_ID_LEN {
        return Err(invalid("a group id is 32 bytes"));
    }
    check_group_info_extensions(&gi)?;
    let tree = wire::tree_from_wire(tree).map_err(|e| invalid(&e.to_string()))?;
    let state = GroupState::new();
    // This checks the tree, its hashes and leaves, and the GroupInfo's
    // signature by its signer's leaf. The only leaf was just made, so its
    // lifetime holds.
    let (group, _) = PublicGroup::from_external(crypto, &state, tree, gi, ProposalStore::new())
        .map_err(|e| invalid(&format!("the group is not valid: {e}")))?;
    if group.version() != ProtocolVersion::Mls10 {
        return Err(invalid("the group is not mls10"));
    }
    check_tree_keys(&group)?;
    let leaves = leaves(&group)?;
    let [leaf] = leaves.as_slice() else {
        return Err(invalid("a new group has one leaf"));
    };
    if leaf.key != *device.key || leaf.uid != *device.uid {
        return Err(invalid("the leaf is not this device's"));
    }
    let conversation = RisalaConversation::from_extensions(group.group_context().extensions())
        .map_err(|e| invalid(&e.to_string()))?;
    if !names(&conversation) {
        return Err(invalid(
            "the conversation extension names another conversation",
        ));
    }
    check_extensions(group.group_context(), &conversation)?;
    Ok(NewGroup {
        record: GroupRecord {
            group_id: group.group_id().as_slice().to_vec(),
            meta: GroupMeta {
                epoch: 0,
                seq: None,
            },
            group_info: gi_value.clone(),
            parts: parts(&state)?,
        },
        leaves,
        conversation,
    })
}

/// A leaf that a commit removes, and whether the commit itself shows why
/// it may (12.5): it is a leaf of the committer's own identity, or the
/// commit adds its key again. The hub checks the other reasons.
#[derive(Debug, Clone)]
pub(super) struct Removed {
    pub(super) leaf: GroupLeaf,
    pub(super) justified: bool,
}

/// What [`check_commit`] found: the commit's changes, and the group in the
/// new epoch.
#[derive(Debug)]
pub(super) struct CheckedCommit {
    /// An external commit (12.6).
    pub(super) external: bool,
    /// For an external commit, whether the joiner's identity had a leaf
    /// before it.
    pub(super) had_leaf: bool,
    /// The devices it adds.
    pub(super) adds: Vec<(Uid, PublicKey)>,
    /// The leaves it removes.
    pub(super) removes: Vec<Removed>,
    /// The conversation extension, before the commit.
    pub(super) before: RisalaConversation,
    /// The new conversation extension, if the commit has a
    /// GroupContextExtensions proposal.
    pub(super) extensions: Option<RisalaConversation>,
    /// The group in the new epoch. Its `meta.seq` is not known yet.
    pub(super) group: GroupRecord,
    /// Its leaves.
    pub(super) leaves: Vec<GroupLeaf>,
    /// Its ratchet tree, for the Welcome (12.7).
    pub(super) tree: mls::RatchetTree,
}

/// The fields of a GroupInfo after its group context: extensions, the
/// confirmation tag and the signer's leaf index.
fn group_info_fields(
    gi: &VerifiableGroupInfo,
    context: &GroupContext,
) -> Result<(Vec<u8>, u32), Fail> {
    let bytes = gi
        .tls_serialize_detached()
        .map_err(|_| invalid("the GroupInfo cannot be encoded"))?;
    let context = context
        .tls_serialize_detached()
        .map_err(|_| invalid("the group context cannot be encoded"))?;
    let rest = bytes
        .strip_prefix(context.as_slice())
        .ok_or_else(|| invalid("the GroupInfo is not for the commit's new epoch"))?;
    let mut r = rest;
    let malformed = |_| invalid("the GroupInfo is malformed");
    VLBytes::tls_deserialize(&mut r).map_err(malformed)?;
    let tag = VLBytes::tls_deserialize(&mut r).map_err(malformed)?;
    let signer = u32::tls_deserialize(&mut r).map_err(malformed)?;
    let tag = tag.tls_serialize_detached().map_err(malformed)?;
    Ok((tag, signer))
}

/// Checks the GroupInfo of a commit's new epoch (12.5): its group context
/// is `context`, its confirmation tag is the commit's, its signer is
/// leaf `signer` with key `signer_key`, its signature verifies, and it has
/// `external_pub` and no `ratchet_tree`.
fn check_commit_group_info(
    crypto: &RisalaCrypto,
    gi: VerifiableGroupInfo,
    context: &GroupContext,
    tag: &ConfirmationTag,
    signer: LeafNodeIndex,
    signer_key: &PublicKey,
) -> Result<(), Fail> {
    let (gi_tag, gi_signer) = group_info_fields(&gi, context)?;
    let tag = tag
        .tls_serialize_detached()
        .map_err(|_| invalid("the confirmation tag cannot be encoded"))?;
    if gi_tag != tag {
        return Err(invalid(
            "the GroupInfo's confirmation tag is not the commit's",
        ));
    }
    if gi_signer != signer.u32() {
        return Err(invalid("the GroupInfo is not signed by the committer"));
    }
    check_group_info_extensions(&gi)?;
    let key = OpenMlsSignaturePublicKey::new(
        signer_key.as_bytes().to_vec().into(),
        CIPHERSUITE.signature_algorithm(),
    )
    .map_err(|_| invalid("the committer's key is not an ML-DSA-44 key"))?;
    gi.verify(crypto, &key)
        .map_err(|_| invalid("the GroupInfo's signature does not verify"))?;
    Ok(())
}

/// The checks of COMMIT that need only the group and the command (12.5):
///
/// 1. the commit is for the current epoch (`ERR stale`)
/// 2. it is valid as far as someone outside the group can check, with the
///    lifetimes of the KeyPackages it adds acceptable at `now`, a Welcome
///    exactly when it adds devices, and the GroupInfo of its new epoch
///    (`ERR invalid`)
/// 3. its committer is `device`, and its path keeps the credential and key
///    of the committer's leaf (`ERR forbidden`)
/// 4. its proposals are all by value and of the kinds allowed, an external
///    commit removes at most the joiner's own earlier leaf, a key it adds
///    that has a leaf has that leaf removed, and a GroupContextExtensions
///    changes only `history` and `send` (`ERR forbidden`)
/// 5. the group has at most `max_leaves` leaves after it, which is
///    [`MAX_GROUP_LEAVES`](risala_proto::mls::MAX_GROUP_LEAVES) but in tests
///    (`ERR forbidden`)
///
/// What needs the conversation's membership or key files is left to the
/// hub.
#[allow(clippy::too_many_arguments)]
pub(super) fn check_commit(
    crypto: &RisalaCrypto,
    record: &GroupRecord,
    device: Device<'_>,
    commit: &mls::CommitMessage,
    gi_value: &mls::GroupInfo,
    welcome: Option<&mls::Welcome>,
    now: SystemTime,
    max_leaves: usize,
) -> Result<CheckedCommit, Fail> {
    let state = GroupState::from_parts(record.parts.clone());
    let group_id = risala_mls::openmls::prelude::GroupId::from_slice(&record.group_id);
    let mut group = PublicGroup::load(&state, &group_id)
        .map_err(state_error)?
        .ok_or_else(|| state_error("no group"))?;

    let message = MlsMessageIn::tls_deserialize_exact(commit.decode())
        .map_err(|_| invalid("the commit is not an MLSMessage"))?;
    let MlsMessageBodyIn::PublicMessage(message) = message.extract() else {
        return Err(invalid("the commit is not a PublicMessage"));
    };
    // Rule 1.
    let epoch = group.group_context().epoch();
    if message.epoch() != epoch {
        return Err(fail(
            ErrorCode::Stale,
            &format!(
                "the commit is for epoch {}, and the group is in epoch {}",
                message.epoch().as_u64(),
                epoch.as_u64()
            ),
        ));
    }
    if message.content_type() != ContentType::Commit {
        return Err(invalid("not a commit"));
    }
    let tag = message
        .confirmation_tag()
        .cloned()
        .ok_or_else(|| invalid("the commit has no confirmation tag"))?;

    // Rule 2: OpenMLS checks the signatures, the tree, its parent hashes
    // and the proposals as far as it can.
    // A proposal by reference names one the server never has, since there
    // are no separate proposals: that is rule 4's refusal, not rule 2's.
    let processed = group
        .process_message(crypto, message)
        .map_err(|e| match e {
            PublicProcessMessageError::InvalidCommit(StageCommitError::MissingProposal) => {
                forbidden(BY_VALUE)
            }
            e => invalid(&format!("the commit is not valid: {e}")),
        })?;
    let sender = processed.sender().clone();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(invalid("not a commit"));
    };
    let external = match sender {
        Sender::Member(_) => false,
        Sender::NewMemberCommit => true,
        _ => return Err(invalid("a commit comes from a member or a joiner")),
    };
    let mut adds = Vec::new();
    for add in staged.add_proposals() {
        let kp = add.add_proposal().key_package();
        if !risala_mls::lifetime_acceptable(kp.life_time(), now) {
            return Err(invalid("an added KeyPackage's lifetime is not acceptable"));
        }
        let leaf = kp.leaf_node();
        if !risala_mls::hpke_public_key_ok(kp.hpke_init_key().as_slice())
            || !risala_mls::encryption_key_ok(leaf.encryption_key())
        {
            return Err(invalid(
                "an added KeyPackage has an HPKE key of the wrong length",
            ));
        }
        let device = leaf_of(leaf.credential(), leaf.signature_key().as_slice())
            .ok_or_else(|| invalid("an added leaf is not a device of an identity"))?;
        adds.push(device);
    }
    match (adds.is_empty(), welcome) {
        (false, None) => return Err(invalid("a commit that adds devices comes with a Welcome")),
        (true, Some(_)) => return Err(invalid("only a commit that adds devices has a Welcome")),
        (false, Some(w)) => {
            let w = wire::welcome_from_wire(w).map_err(|e| invalid(&e.to_string()))?;
            if w.ciphersuite() != CIPHERSUITE {
                return Err(invalid("the Welcome uses another cipher suite"));
            }
            // Addressed to exactly the KeyPackages the commit adds, each
            // once.
            let mut added = staged
                .add_proposals()
                .map(|add| {
                    let r = add.add_proposal().key_package().hash_ref(crypto);
                    r.map(|r| r.as_slice().to_vec())
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| invalid("an added KeyPackage cannot be hashed"))?;
            let mut welcomed: Vec<Vec<u8>> = w
                .secrets()
                .iter()
                .map(|s| s.new_member().as_slice().to_vec())
                .collect();
            added.sort();
            welcomed.sort();
            if added != welcomed {
                return Err(invalid(
                    "the Welcome is not for exactly the KeyPackages the commit adds",
                ));
            }
        }
        (true, None) => {}
    }
    let gi = group_info(gi_value)?;

    // Rule 3: the committer is this device.
    let (signer, committer) = match sender {
        Sender::Member(index) => {
            let leaf = group
                .leaf(index)
                .ok_or_else(|| invalid("the committer has no leaf"))?;
            let committer = leaf_of(leaf.credential(), leaf.signature_key().as_slice())
                .ok_or_else(|| invalid("the committer's leaf is not a device"))?;
            (index, committer)
        }
        _ => {
            let leaf = staged
                .update_path_leaf_node()
                .ok_or_else(|| invalid("an external commit has a path"))?;
            let committer = leaf_of(leaf.credential(), leaf.signature_key().as_slice())
                .ok_or_else(|| invalid("the joiner's leaf is not a device"))?;
            let index = group
                .ext_commit_sender_index(&staged)
                .map_err(|_| invalid("the joiner has no leaf"))?;
            (index, committer)
        }
    };
    check_commit_group_info(
        crypto,
        gi,
        staged.group_context(),
        &tag,
        signer,
        &committer.1,
    )?;
    if committer.0 != *device.uid || committer.1 != *device.key {
        return Err(forbidden("the committer is not this connection's device"));
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        let path = leaf_of(leaf.credential(), leaf.signature_key().as_slice());
        if path.as_ref() != Some(&committer) {
            return Err(forbidden(
                "a commit keeps the credential and key of the committer's leaf",
            ));
        }
    }

    // Rule 4: the proposals.
    let before = RisalaConversation::from_extensions(group.group_context().extensions())
        .map_err(|e| invalid(&e.to_string()))?;
    let added_keys: Vec<&PublicKey> = adds.iter().map(|(_, k)| k).collect();
    let seen = staged.queued_proposals().map(|queued| {
        let by_value = queued.proposal_or_ref_type() == ProposalOrRefType::Proposal;
        let proposal = match queued.proposal() {
            Proposal::Add(_) => Seen::Add,
            Proposal::Remove(remove) => {
                let leaf = group
                    .leaf(remove.removed())
                    .map(|leaf| leaf_of(leaf.credential(), leaf.signature_key().as_slice()));
                Seen::Remove(remove.removed().u32(), leaf)
            }
            Proposal::GroupContextExtensions(proposal) => {
                Seen::GroupContextExtensions(proposal.extensions())
            }
            Proposal::ExternalInit(_) => Seen::ExternalInit,
            other => Seen::Other(other.proposal_type()),
        };
        (by_value, proposal)
    });
    let (removes, extensions) = check_proposals(seen, external, device, &added_keys, &before)?;
    // A key that has a leaf is added only with that leaf removed.
    for (_, key) in &adds {
        if let Some(member) = group.members().find(|m| m.signature_key == key.as_bytes())
            && !removes.iter().any(|r| r.leaf.index == member.index.u32())
        {
            return Err(forbidden(
                "a key that has a leaf is added only with it removed",
            ));
        }
    }
    let had_leaf = external
        && group.members().any(|m| {
            leaf_of(&m.credential, &m.signature_key).is_some_and(|(uid, _)| uid == *device.uid)
        });
    let after = extensions.as_ref().unwrap_or(&before);
    check_extensions(staged.group_context(), after)?;

    let new_epoch = staged.group_context().epoch().as_u64();
    group
        .merge_commit(&state, *staged)
        .map_err(|e| state_error(format!("{e:?}")))?;
    // Rule 2: the new path's keys, and those of the leaves it adds.
    check_tree_keys(&group)?;
    // Rule 5.
    let leaves = leaves(&group)?;
    if leaves.len() > max_leaves {
        return Err(forbidden(&format!(
            "a group has at most {max_leaves} leaves"
        )));
    }
    let tree = wire::tree_to_wire(&group.export_ratchet_tree())
        .map_err(|_| invalid("the new ratchet tree is too long for a line"))?;
    Ok(CheckedCommit {
        external,
        had_leaf,
        adds,
        removes,
        before,
        extensions,
        group: GroupRecord {
            group_id: record.group_id.clone(),
            meta: GroupMeta {
                epoch: new_epoch,
                seq: None,
            },
            group_info: gi_value.clone(),
            parts: parts(&state)?,
        },
        leaves,
        tree,
    })
}

/// Why rule 4 refuses a proposal by reference (12.5).
const BY_VALUE: &str = "proposals are inside the commit, by value";

/// A proposal of a commit, as rule 4 of 12.5 sees it.
#[derive(Debug, Clone)]
pub(super) enum Seen<'a> {
    Add,
    /// A Remove of the leaf at this index: whose device it is, `None` for
    /// a blank leaf, and `Some(None)` for a leaf that is not a device of
    /// an identity.
    Remove(u32, Option<Option<(Uid, PublicKey)>>),
    /// A GroupContextExtensions, with its extensions.
    GroupContextExtensions(&'a Extensions<GroupContext>),
    ExternalInit,
    /// Any other kind.
    Other(ProposalType),
}

/// Checks a commit's proposals, each with whether it is by value, under
/// rule 4 of 12.5: all by value, of the kinds allowed, an external commit
/// removing at most one leaf, the joiner's own, and a GroupContextExtensions
/// that keeps the conversation and changes only `history` and `send`.
/// `device` is the committer, `added` the keys the commit adds, and
/// `before` the conversation extension before it.
///
/// Returns the leaves removed, each with whether the commit itself shows
/// why, and the new conversation extension if there is one.
pub(super) fn check_proposals<'a>(
    proposals: impl IntoIterator<Item = (bool, Seen<'a>)>,
    external: bool,
    device: Device<'_>,
    added: &[&PublicKey],
    before: &RisalaConversation,
) -> Result<(Vec<Removed>, Option<RisalaConversation>), Fail> {
    let mut removes = Vec::new();
    let mut extensions = None;
    for (by_value, proposal) in proposals {
        if !by_value {
            return Err(forbidden(BY_VALUE));
        }
        match proposal {
            Seen::Add => {}
            Seen::Remove(index, leaf) => {
                let leaf = leaf.ok_or_else(|| invalid("a Remove of a blank leaf"))?;
                let (uid, key) = leaf.ok_or_else(|| invalid("a removed leaf is not a device"))?;
                if external && key != *device.key {
                    return Err(forbidden(
                        "an external commit removes only the joiner's earlier leaf",
                    ));
                }
                let justified = external || uid == *device.uid || added.contains(&&key);
                removes.push(Removed {
                    leaf: GroupLeaf { index, uid, key },
                    justified,
                });
            }
            Seen::GroupContextExtensions(proposed) => {
                let new = RisalaConversation::from_extensions(proposed).map_err(|_| {
                    forbidden("GroupContextExtensions keeps the conversation extension")
                })?;
                if !new.same_conversation(before) || proposed != &group_context_extensions(&new) {
                    return Err(forbidden(
                        "GroupContextExtensions changes only history and send",
                    ));
                }
                extensions = Some(new);
            }
            Seen::ExternalInit if external => {}
            Seen::ExternalInit => {
                return Err(forbidden("ExternalInit is only in an external commit"));
            }
            Seen::Other(kind) => {
                return Err(forbidden(&format!(
                    "a kind of proposal that is not allowed: {kind:?}"
                )));
            }
        }
    }
    if external && removes.len() > 1 {
        return Err(forbidden("an external commit removes at most one leaf"));
    }
    Ok((removes, extensions))
}

/// The current ratchet tree of a stored group, for GROUPINFO (12.5).
pub(super) fn tree_of(record: &GroupRecord) -> Result<mls::RatchetTree, Fail> {
    let state = GroupState::from_parts(record.parts.clone());
    let group_id = risala_mls::openmls::prelude::GroupId::from_slice(&record.group_id);
    let group = PublicGroup::load(&state, &group_id)
        .map_err(state_error)?
        .ok_or_else(|| state_error("no group"))?;
    wire::tree_to_wire(&group.export_ratchet_tree()).map_err(state_error)
}

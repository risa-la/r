# openmls, patched for risala

This is openmls 0.9.2 from crates.io, changed in six ways for risala:
how it frames a SelfRemove proposal (draft-ietf-mls-extensions), where it
checks KeyPackage lifetimes, removals in external commits, the
authenticated data of join proposals, `VerifiableGroupInfo::signer`,
which is public, and access to the keys of parent nodes. The root Cargo.toml puts it in place
of the crates.io release with `[patch.crates-io]`. Each place is marked
`risala:`.

## SelfRemove

- `MlsGroup::create_self_remove_proposal` frames the proposal with the
  group's outgoing wire format, instead of always as a PublicMessage.
- `MlsGroup::leave_group_via_self_remove` no longer refuses groups whose
  wire format policy is pure ciphertext.

So in direct conversations and private rooms, whose handshake messages
are all PrivateMessages, a SelfRemove is a PrivateMessage too, and the
server does not learn which leaf left (the spec, 12.6; PLAN.md 60). This
departs from draft-ietf-mls-extensions, which sends SelfRemove as a
PublicMessage. Receiving one needs no change: OpenMLS already accepts any
proposal in a PrivateMessage.

`git diff` against the crates.io release shows the whole change, in
`src/group/mls_group/proposal.rs` and `src/group/mls_group/membership.rs`;
each place is marked `risala:`. risala-mls tests that a SelfRemove in a
pure-ciphertext group is a PrivateMessage, so an upgrade that loses the
patch fails a test.

Drop the patch if OpenMLS adds a way to choose the wire format of a
SelfRemove, or if risala stops needing it.

## Lifetimes (the spec, 12.5)

risala checks the lifetime of a KeyPackage that a commit adds against the
`t` of the post that carries the commit, give or take an hour, never
against the device's clock, so that every device reaches the same answer
however late it processes the commit. And it never checks the lifetimes of
leaves already in a tree.

- `KeyPackageIn::validate_without_lifetime` is `validate` without the
  clock; `AddProposalIn::validate` uses it, so incoming Add proposals,
  by value or in join proposals, are not checked against the clock.
- `PublicGroup::validate_add_proposals` validates the added leaf node with
  `LeafNodeLifetimePolicy::Skip`.
- `PublicGroup::from_external` skips the lifetimes of the tree's leaves,
  as the external commit and Welcome builders can already be told to.

risala-mls checks the lifetimes itself (`checks::check_commit`); its tests
show that a commit whose added KeyPackage has expired by the clock, but not
at the post's time, is accepted.

## Removals in external commits (the spec, 12.7)

`ExternalCommitBuilder::with_removals` adds Remove proposals for other
leaves. A resync commit removes the leaf whose commit the room's devices
could not apply, which RFC 9420 does not foresee: it lets an external
commit remove only the joiner's own earlier leaf. Processing needs no
change, since OpenMLS leaves the check of external commits' removals to
the application, which risala-mls makes.

## Join proposals with authenticated data (the spec, 12.9, 6.1)

`JoinProposal::new_with_aad` sets the proposal's `authenticated_data`,
which `JoinProposal::new` leaves empty, so that a public room's join
proposals carry a RisalaAAD like every other post.

## The GroupInfo's signer (the spec, 12.6, 12.7)

`VerifiableGroupInfo::signer` is public, so that a resync commit can
remove the GroupInfo's signer, and a server can check that a public room's
GroupInfo is signed by the committer.

## The keys of parent nodes (the spec, 12.2)

Devices reject a commit or Welcome that carries an X-Wing key that fails
12.2's check, and servers one they are given, whether the key is a
leaf's or a parent node's. OpenMLS checks neither, and exposes neither a
staged commit's parent nodes nor a parent node's key.

- `StagedCommit::changed_parent_nodes` returns the non-blank parent nodes
  that a staged commit sets: its path's, and those an Add changes. It
  reads them from the staged diff (`StagedAbDiff::changed_parents`,
  `StagedTreeSyncDiff::changed_parent_nodes`,
  `StagedPublicGroupDiff::changed_parent_nodes`, all crate-private).
- `ParentNode::public_key` is public, so that the whole tree of a group
  being joined (`PublicGroup::treesync().full_parents()`) can be checked.

risala-mls checks them (`checks::CommitView::parent_keys_ok`,
`checks::parent_keys_ok`) and tests that a commit's view reads its parent
nodes. Drop the patch if OpenMLS checks HPKE public keys itself, or
exposes the nodes another way.

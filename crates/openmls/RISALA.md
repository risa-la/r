# openmls, patched for risala

This is openmls 0.9.2 from crates.io, unchanged except for how it frames
a SelfRemove proposal (draft-ietf-mls-extensions). The root Cargo.toml
puts it in place of the crates.io release with `[patch.crates-io]`.

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

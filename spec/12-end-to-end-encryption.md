## 12. End-to-End Encryption

### 12.1. Overview

Every conversation is an MLS group [RFC9420], with post-quantum
algorithms (12.2):

- Each device in a conversation is one member of its group, called a
  **leaf**. A device signs in MLS with a **leaf key** that it makes for
  that group alone (12.3).
- A group moves through numbered **epochs**. Each commit, for example
  one that adds or removes devices, starts a new epoch with new keys.
- Messages are MLS application messages. Each one is encrypted with its
  own key from the group's secret tree, which devices delete once they
  have used it. That gives per-message forward secrecy, and commits give
  post-compromise security.
- The server is the group's delivery service, through its mailbox
  (5.2). It never holds a group's secrets. In direct conversations and
  private rooms, commits are encrypted too, so the server does not see
  the group's members (12.6). In public rooms it sees them, and checks
  commits.
- Devices post on anonymous connections, proving only that they are
  members of the epoch, with a send token (7.2).
- Devices check every change to a group themselves (12.7), and every
  key against the key log (4.5). They confirm whose leaf is whose
  deniably (12.10).
- History stays on devices. A device passes it to a new device of the
  same identity directly, and MAY keep an encrypted backup on the server
  (12.13).

Clients need an MLS implementation. Servers need one too, to read the
framing of posts and to check the commits of public rooms.

### 12.2. Algorithms

Every conversation uses one MLS cipher suite, `0x0020` [MLS-PQ]:

| Part | Algorithm |
|---|---|
| KEM | X-Wing, which combines ML-KEM-768 and X25519 [XWING] |
| AEAD | ChaCha20-Poly1305 [RFC8439] |
| Hash | SHA-384 |
| Signatures | ML-DSA-44 [FIPS204] |

- The KEM is post-quantum and classical at once. Its keys stay secret as
  long as either ML-KEM-768 or X25519 holds.
- Within HPKE [RFC9180], the suite uses the KEM `0x647a` (X-Wing
  [XWING]), the KDF HKDF-SHA384 (`0x0002`) and the AEAD
  ChaCha20-Poly1305 (`0x0003`).
- Everywhere else MLS needs a hash or a KDF, for example in
  ExpandWithLabel, DeriveSecret, the tree and transcript hashes and the
  exporter, it uses SHA-384 and HKDF-SHA384 [RFC5869].
- Signatures are ML-DSA-44 alone, as for signing in (4.6): plain
  ML-DSA.Sign, with an empty context string and no prehash. Signers
  SHOULD use the hedged variant.
- [MLS-PQ] calls this suite
  `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44`. OpenMLS 0.9
  has it under the placeholder value `0x0052`, which risala does not
  use.
- The MLS protocol version is `mls10`.
- `0x0020` is the value [MLS-PQ] requests, which IANA has not yet
  assigned (Section 15). Implementations MUST check that the suite
  their MLS library uses under `0x0020` is the one in this table, for
  example by running known-answer tests of each of its algorithms on
  every build, from the vectors published with them (Appendix B), so
  that a library upgrade cannot change it unnoticed.
- Before it encrypts to an X-Wing public key, of a leaf, a parent node,
  a KeyPackage or a device's attestation key (12.10), an implementation
  MUST check it as [XWING] and [FIPS203] require: it is 1216 bytes, and
  its ML-KEM-768 part passes FIPS 203's encapsulation key check. Devices
  reject a KeyPackage, Welcome, commit or key file record that carries a
  key that fails, and servers reject one they are given.
- A device MUST reject a KeyPackage, Welcome, GroupInfo or commit whose
  cipher suite is not `0x0020`, or whose protocol version is not
  `mls10`, whatever the server accepted.
- `<keypackage>`, `<groupinfo>`, `<message>` and `<welcome>` in this
  document are each an MLSMessage [RFC9420] in base64 with padding
  [RFC4648]. `<tree>` is a ratchet tree, encoded as the data of a
  `ratchet_tree` extension (the `optional<Node>` vector of [RFC9420]),
  in base64 with padding. Each of them may instead be a blob-ref, naming
  a blob that holds the same bytes without base64 (12.12).

### 12.3. Credentials and Leaf Keys

A leaf's credential is an MLS `basic` credential. Its identity is an
encoded RisalaIdentity:

```
struct {
    uint8 version;          // 1
    opaque uid<V>;          // in lower case
    opaque device_id<V>;    // the device id (4.4), 48 bytes; empty for a guest
} RisalaIdentity;
```

**Leaf keys.** A leaf's signature key is a fresh ML-DSA-44 key that its
device makes for that one group. It is never listed in a key file or a
log, never used in another group, and never signed by any of the
identity's keys. So nothing outside the group ties it to the identity:
the members confirm that themselves, deniably (12.10). A device MUST NOT
use its device key, or any key it uses elsewhere, as a leaf key.

- **The credential never changes.** A commit's path MUST NOT change the
  credential of the committer's leaf. A device of another identity, or
  another device, means a new leaf.
- **The signature key changes only** in a group whose `confirm` is
  `epochal`, once per period in which the device sends (12.10), and once
  right after a device joins with its last-resort KeyPackage (12.5). In
  both cases the device commits a fresh leaf of its own with a new
  signature key, and deletes the old one. Otherwise a new signature key
  means a new leaf.
- Two leaves of a group never share a signature key [RFC9420].

**Guests** (4.2) have leaves whose credential names their guest uid and
has an empty `device_id`. Nothing confirms them, and devices show them
as unverified guests.

**Device bindings.** Leaf keys are not bound to the identity, but the
keys that others encrypt to are. A KeyPackage, and the leaf of a device
that joins a public room by external commit, carry a **device binding**,
an extension of type `0xF2A2`:

```
struct {
    uint8 version;               // 1
    opaque device_id[48];
    opaque signature<V>;
} DeviceBinding;

struct {
    opaque uid<V>;
    opaque init_key<V>;          // empty in a leaf node
    opaque encryption_key<V>;    // the leaf's HPKE key
} DeviceBindingContent;
```

`signature` is RisalaSign(device key, "keypackage", DeviceBindingContent)
(4.3), by the device whose id is `device_id`. It shows that only that
device can read what is encrypted to the KeyPackage, so that neither the
server nor a member can slip in a KeyPackage of their own under someone
else's name. It says nothing about the leaf's signature key or about any
message, so it does not weaken deniability. It does show that the device
was given a way into some group.

**Profiles.** A leaf MAY carry a profile, an extension of type `0xF2A3`:

```
struct {
    uint8 version;               // 1
    opaque display_name<V>;      // UTF-8, at most 128 bytes, may be empty
    uint64 updated;              // when the leaf was last committed, in ms
    uint8 streak;                // epochs in a row this leaf has started
} RisalaProfile;
```

The display name is shown as 8.2 says. Every leaf of an identity's
device carries a profile.

- **`updated`** is set by the leaf's device each time it commits its own
  leaf, and lets devices find leaves that have stopped keeping up
  (12.7). Devices treat as invalid a commit whose new `updated` for the
  committer's leaf is lower than the leaf's previous one, or more than
  10 minutes before or after the `t` of the post that carries the commit
  (5.2). So a device sets it from its clock, or, if its clock disagrees
  by minutes with the `t` of the posts it receives, from the time those
  suggest, and never below the leaf's previous `updated`. In a
  KeyPackage it is the time the KeyPackage was made.
- **`streak`** counts the epochs in a row, up to and including the one
  the commit starts, that this leaf has started with its own commits:
  the previous `streak` plus 1 if the leaf made the commit that started
  the current epoch, or 1 if it did not, at most 255. It is 0 in a
  KeyPackage. Devices treat a commit whose `streak` is not this value as
  invalid, and limit commits by it (12.7). Every device knows which leaf
  started the current epoch, including one that has just joined: it is
  the signer of the GroupInfo it joined with.

**Capabilities.** Leaves list in their capabilities the extension types
`0xF2A1`, `0xF2A2` and `0xF2A3`, the `app_data_dictionary` extension
type (`0x0006`) [MLS-EXT], the proposal type `self_remove` (`0x000A`)
[MLS-EXT], and the credential type `basic`.

### 12.4. The Conversation Extension

Every group carries a **conversation extension** in its group context,
of type `0xF2A1` (Section 15). It ties the group to one conversation,
mailbox and server, and holds the room's roles and settings:

```
enum {
    reserved(0),
    direct(1),
    private_room(2),
    public_room(3),
    (255)
} ConversationKind;

enum { reserved(0), pairwise(1), epochal(2), (255) } ConfirmMode;
enum { reserved(0), none(1), read(2), write(3), (255) } GuestMode;
enum { reserved(0), all(1), mods(2), (255) } SendMode;

opaque Uid<V>;

struct {
    uint8 version;               // 1
    ConversationKind kind;
    opaque host<V>;              // the server, in lower case
    opaque box[16];              // the mailbox
    opaque name<V>;
    opaque topic<V>;             // UTF-8, at most 512 bytes
    ConfirmMode confirm;
    GuestMode guests;
    SendMode send;
    Uid owners<V>;
    Uid mods<V>;
    Uid bans<V>;
} RisalaConversation;
```

- **Direct conversations:** `name` is the uids of the two participants
  in lower case, sorted byte by byte and joined by one space, or the
  identity's own uid alone for a conversation with yourself. `topic` is
  empty, `confirm` is `pairwise`, `guests` is `none`, `send` is `all`,
  and the lists are empty.
- **Private rooms:** `name` is the room's name, 1 to 128 bytes of UTF-8
  that members see. It need not be unique. `guests` is `none`.
- **Public rooms:** `name` is the room name, such as `#general` (3.5),
  and `confirm` is `epochal`.
- `owners` holds at least one uid, and every uid in `owners`, `mods` and
  `bans` is an identity, not a guest. A uid is in at most one of
  `owners` and `mods`.

The group context has exactly two extensions: `required_capabilities`
first, which lists the extension types `0xF2A1`, `0xF2A2` and `0xF2A3`,
the proposal type `self_remove` and the credential type `basic`; then
the conversation extension. A commit may change only the fields that
6.2 and 6.3 allow, through a GroupContextExtensions proposal, and never
`version`, `kind`, `host` or `box`, nor the `name` of a direct
conversation or a public room.

### 12.5. Key Packages

To add a device to a group, a member needs one of that device's
KeyPackages. Devices upload KeyPackages in advance, so that others can
add them while they are offline.

```
KEYPKG ADD <keypackage>
KEYPKG COUNT
KEYPKG GET <uid>
```

- **`KEYPKG ADD`** stores a KeyPackage for this connection's device, and
  replies `OK`. It needs a signed-in connection. The server checks that
  the KeyPackage uses the cipher suite of 12.2, that its credential is a
  RisalaIdentity of the connection's uid and device, that it has a
  device binding (12.3) that verifies under the connection's device key
  and covers its init and encryption keys, that its leaf lists the
  capabilities of 12.3, that its keys pass the checks of 12.2, that its
  signatures verify, and that its lifetime is acceptable (below).
  Otherwise it replies `ERR invalid`. A server MAY limit how many
  KeyPackages it keeps for each device (`ERR forbidden`), and how large
  a KeyPackage may be (`ERR too-long`). KeyPackages of this suite are
  about 9 KiB, so a limit MUST NOT be below 16 KiB.
- **`KEYPKG COUNT`** replies `OK count=<n> last-resort=<yes or no>`: the
  number of ordinary KeyPackages the server holds for this device, and
  whether it holds a last-resort one. It needs a signed-in connection.
- **`KEYPKG GET`** sends one `KEYPKG <uid> <keypackage>` line for each
  current device of `<uid>` (4.4) that has a KeyPackage, then `OK`. It
  works on any kind of connection, and a device SHOULD send it on an
  anonymous one, since it shows whom the device is about to talk to. A
  uid the server does not know gets `ERR not-found`. If the server
  cannot fetch the key file (4.4) and has no cached copy still valid, it
  replies `ERR unavailable` rather than hand out KeyPackages of devices
  that may have been removed.

Each KeyPackage has a leaf key of its own, so that each group a device
joins gets a different one (12.3). The server hands out each ordinary
KeyPackage once, then deletes it. A device MAY also upload one
KeyPackage of last resort, marked as [MLS-EXT] marks it: its
`app_data_dictionary` extension (`0x0006`) holds the
`last_resort_key_package` component (`0x0004`), with empty data. The
server hands
that one out only when the device has no ordinary KeyPackage left, and
keeps it, so the device can always be added. A new one replaces it.
Since its leaf key may be used in several groups, a device that joins
with it commits a fresh leaf with a new signature key before it sends
anything (12.3).

A device SHOULD keep about ten ordinary KeyPackages on the server, and
upload more when KEYPKG COUNT reports fewer than five. Servers delete
KeyPackages whose lifetime has ended, and SHOULD rate-limit KEYPKG GET,
since every request uses KeyPackages up.

**Lifetimes.** A KeyPackage's lifetime is acceptable if the current time
is within it, and it spans at most 12 weeks and one hour (7261200
seconds from `not_before` to `not_after`). The server checks this when a
KeyPackage is uploaded, and the server and every device check it again
when a commit adds the KeyPackage to a group (12.6, 12.7).

A leaf keeps its KeyPackage's lifetime until its device commits a fresh
leaf (12.7), which has none [RFC9420]. So the lifetime can end while the
leaf is still in the group. The server, and devices that join by Welcome
or by external commit, do not check the lifetimes of leaves already in
the group's tree. This departs from Section 7.3 of [RFC9420], which
recommends that a client check the lifetime of every leaf it receives,
including the leaves of a group it joins. With that check, one device
that stayed offline for longer than its lifetime would stop everyone
else from joining the group, until someone removed it.

### 12.6. Groups and Commits

**Creating a group.** A device creates an MLS group with a new random
32-byte group id, in which its own device is the only member, and whose
conversation extension (12.4) describes the conversation. It creates the
mailbox with CREATE (5.2), then adds the other devices (12.7).

**Wire formats.** In a direct conversation or a private room, every
application message, commit and proposal is a PrivateMessage, so that
the server sees only the group id, the epoch, the content type and the
RisalaAAD (12.9). In a public room, application messages are
PrivateMessages, and commits and proposals are PublicMessages, so that
the server can check them. A SelfRemove proposal [MLS-EXT] follows the
same rule: it is a PrivateMessage outside public rooms.

**Commits.** Every commit has a path, so that it gives post-compromise
security and updates the committer's profile (12.3). All proposals are
inside the commit, by value, except a SelfRemove, and in a public room
an external Add proposal (6.1), which are committed by reference. The
proposal types allowed are Add, Remove, GroupContextExtensions,
SelfRemove and, in an external commit, ExternalInit. A client that adds
many devices SHOULD split them over several commits of at most 256
devices each, bearing in mind that a leaf's fourth commit in a row has
to wait (12.7). A commit too large for a line travels as a blob (12.12).

Each commit's RisalaAAD carries the hash of the next epoch's send token
(7.2). Devices check it once they have applied the commit, and treat a
commit whose hash is wrong as invalid.

**Public rooms.** The server holds the public state of a public room's
group: its ratchet tree and its GroupInfo, as of the newest epoch. It
checks every commit and proposal posted to the room, as far as someone
outside the group can, and refuses one that fails:

1. **It is for the current epoch,** and no other commit for that epoch
   has been accepted (`ERR stale`).
2. **It is valid MLS** as far as an outsider can check: its signatures,
   the lifetimes of the KeyPackages it adds (12.5), the new ratchet tree
   and its parent hashes (`ERR invalid`). The server cannot check the
   confirmation tag, or that the path's secrets decrypt, since both need
   the group's secrets.
3. **It passes the checks of 12.7** that need only the public state:
   who may add and remove whom, which fields of the conversation
   extension change and by whom, bans, the `guests` setting, the size
   limits of 6.1, the committer's `updated` (against its own clock,
   which gives the post its `t`) and `streak` (12.3), and that every
   key it adds is a current device of its
   identity, from the key file the server fetches (4.4)
   (`ERR forbidden`, or `ERR unavailable` if a key file cannot be
   fetched).
4. **A commit carries the new GroupInfo,** with the `external_pub`
   extension and no `ratchet_tree` extension, as the option
   `groupinfo=<groupinfo>` of POST. Its group context must be the one
   the commit produces, its confirmation tag must be the commit's, and
   its signer must be the committer's leaf (`ERR invalid`).

The server then keeps the new tree and GroupInfo, and serves them with
GROUPINFO (6.1). It never holds a group's secrets, so it can still
accept a commit that members' devices reject (12.7). Those devices can
then follow the room only by joining it again, and they check before
they do that the server has not changed the room's roles or settings
on the way (12.7, "Rejoining a public room").

**Light clients.** A full tree of 30,000 leaves is close to 200 MB, too
much for a phone to keep for each large room. In a public room, a device
MAY be a **light client** (a partial client in [MLS-PARTIAL]) that does
not hold the tree:

- It joins by external proposal (6.1), and fetches its Welcome with
  `WELCOME GET <ref> light=yes`, which returns an AnnotatedWelcome that
  the server builds from the tree it holds.
- It fetches with `FETCH <box> after=<seq> leaf=<n>`, where `<n>` is its
  leaf index. The server then returns each commit as an AnnotatedCommit
  for that leaf.
- It checks the membership proofs in these, as [MLS-PARTIAL] requires,
  and gets members and roles from them and from MEMBERS (8.3).
- It cannot commit. It replaces its leaf at least weekly, by joining
  again with a new leaf and posting a SelfRemove of the old one.

A light client tells the server its leaf index, which the server can
tie to its identity in a public room. It SHOULD use a separate anonymous
connection for fetching with `leaf` and for posting (Section 14).

### 12.7. Membership

Devices check every change to a group themselves, besides what MLS
requires. They never take membership, roles or settings from the
server.

**Joining.** When a device joins a group, by Welcome (12.8) or by
external commit, it checks the whole group, and MUST NOT join one that
fails:

- The conversation extension is well formed (12.4), names the server
  the device is joining on, and, for a public room it joins by name,
  that room and its box.
- Every leaf's credential is a RisalaIdentity, and every leaf of an
  identity carries a profile (12.3).
- In a direct conversation, every leaf belongs to one of the two
  participants named in the extension, one of whom is the device's own
  identity, or in a conversation with yourself, to you.
- No leaf belongs to a banned identity. Guest leaves appear only in a
  public room whose `guests` is not `none`, and in a guest's report
  conversation (below).
- The group is within its size limits (6.1).

Leaves that the device cannot confirm yet are allowed: they stay
unverified until it does (12.10). A device ignores a Welcome from a
group in which someone the user has blocked has a leaf (5.7).

**A guest's report conversation** (5.8) is a direct conversation whose
participants are a guest uid and an identity. The guest's device
creates it, with its throwaway leaf as the only leaf of the guest, and
adds the identity's devices. A device of the identity joins it only if
the user accepts it, and only if its identity is an owner or moderator
of a public room on that server whose `guests` is not `none`. In it:

- the guest has exactly one leaf, which never changes its credential
  and is never confirmed, since a guest has no attestation key (12.10);
- after the commit that adds the identity's devices, the guest's leaf
  adds nobody: devices treat any later Add by it as invalid;
- devices act only on REPORT lines from the guest's leaf, and ignore
  every other content line it sends (5.8).

**Commits.** For each commit, a device checks the following, as of the
epoch the commit is for. A commit that fails any of them is invalid,
and the device ignores it (7.2):

- **Adds.** Each added KeyPackage is valid MLS with an acceptable
  lifetime (12.5), and its device binding verifies under the device key
  of a device that the credential's identity has added in its key file
  and whose record is in the key log (4.5). Who may add:
  - a device of the committer's own identity, by anyone in the group;
  - in a direct conversation, a device of either participant, and of
    nobody else;
  - in a room, a device of an identity that already has a leaf, by any
    member, and of a new identity, by an owner or moderator only (an
    invitation), never of a banned one;
  - in a public room, a guest by external commit or proposal, if
    `guests` is not `none`.
- **Removes.** Each removed leaf is:
  - a leaf of the committer's own identity;
  - a leaf whose device has been removed from its identity's key file;
  - in a room, a leaf of an identity that an owner or moderator kicks or
    bans, as 6.3 and 6.4 allow;
  - a leaf that has posted a SelfRemove;
  - a guest leaf;
  - a **stale** leaf (below);
  - or, in an external commit, the joiner's own earlier leaf, with the
    same `device_id`.
- **Extensions.** A GroupContextExtensions proposal changes only the
  fields of the conversation extension that the committer may change
  (6.2, 6.3), and the other extension is unchanged. A commit that adds a
  uid to `bans` also takes it out of `owners` and `mods` (6.4).
- **Leaves.** The commit's path keeps the committer's credential, and
  changes its signature key only as 12.3 allows. The committer's new
  `updated` and `streak` are as 12.3 requires.
- **Streaks.** A commit whose `streak` is more than 3, so that its leaf
  has started each of the last 3 epochs, is invalid, unless its only
  proposals remove leaves of the committer's own identity, or its new
  `updated` is at least 10 minutes after the leaf's previous `updated`.
  Since `updated` stays within 10 minutes of the server's `t`, no leaf
  can win every epoch: after three commits in a row, a leaf can commit
  about once every 10 minutes, and others have that long to commit
  first.
- **External commits** appear only in public rooms, and add only the
  joiner.
- **Size.** The group stays within the limits of 6.1.
- **Next token.** The RisalaAAD's `next_token_hash` matches the epoch
  the commit creates (12.6).

Some of these checks need a key file or the key log. A device never
holds a commit back for them: the first valid commit of an epoch wins
(7.2), so a device that waited could end up in a fork of the group. If
it cannot fetch what a check needs right now (4.4), it applies the
commit and checks again from time to time. Every fact these checks rely
on, such as a record in a log, stays true once it is true, so devices
that fetch later reach the same answer. Until the check passes:

- **A removal it could not check** stands, and the device warns the user
  that a leaf was removed for a reason it could not check. Removing a
  leaf never lets anyone new read.
- **A leaf added by a commit it could not check** is unconfirmed, and
  the device sends nothing in the group while it is, since that leaf
  would read it. If the check later fails, the device commits the
  leaf's removal and warns the user.

A device may also fail to process a commit that passes these checks,
because MLS itself rejects it: for example, its path secrets do not
decrypt, or its confirmation tag is wrong. Such a commit is invalid too,
for that device. Where the server checks commits, in public rooms, this
can split the group. A device that cannot follow a public room joins it
again (6.1), as below. In other conversations it waits to be added
again (below).

**Rejoining a public room.** For each public room it is in, a device
keeps the conversation extension of the newest epoch that it applied
and checked itself. When it finds that the server accepted a commit
that the device holds invalid, it MUST tell the user that the server
accepted an invalid commit in that room. Before it joins the room
again, it compares the extension of the GroupInfo it would join with
the one it kept:

- If `owners`, `mods`, `bans`, `guests`, `send` or `topic` differ in a
  way that no commit it checked explains, it MUST NOT join silently. It
  shows the room as changed by the server, with what changed, and
  joins again only if the user chooses to.
- If the user does, the device keeps the roles it kept for the room's
  content: an identity that gained `owner` or `mod` through the change
  counts as a plain member for `send mods` (5.3), for deleting others'
  messages (5.4) and for how the device shows it, and an identity that
  the change took out of `bans` is still hidden. This lasts as long as
  the device stays in the room. Commits it judges by the group, as every
  other device does.

A device that joins a public room for the first time has nothing to
compare with, and takes the roles that the GroupInfo shows (Section
14).

**Adding devices.** Every device of an identity that is current, logged
and has no leaf in one of the identity's groups gets added:

- A device of the same identity adds it, as soon as it learns of it, for
  example right after pairing (4.8).
- Otherwise, any member's device that finds it, when it checks key
  files (12.14), adds it after a random wait of up to an hour, unless
  someone has done so first. This is how a device that recovered an
  identity (4.8) gets back into its conversations.
- A device that commits the removal of an identity's removed devices
  adds that identity's current devices without a leaf in the same
  commit, so that the identity never drops out of the group by
  accident.

**Replacing stale leaves.** A device that has been offline for longer
than retention cannot catch up from the server (7.5). Its leaves are
replaced, so that it gets back in by Welcome:

- **By its own identity's devices, first.** A device MUST replace, by
  removing it and adding the same device again from a new KeyPackage,
  the leaf of another device of its own identity whose `updated` is
  older than the server's retention period (8.5) plus one day, by the
  device's clock. The extra day leaves room for the weekly fresh-leaf
  commit (below) where retention is 7 days.
  It SHOULD do so as soon as it notices, in every group they share,
  starting with the conversation with yourself. Both are allowed for
  one's own leaves, and removing a leaf never lets anyone new read, so
  relying on INFO's retention here is safe.
- **By anyone, after 35 days.** A leaf is **stale** if its `updated` is
  more than 35 days older than the group's median `updated`. For a leaf
  that has not committed since it was added, the end of its
  KeyPackage's lifetime (12.5) counts as its `updated`, if that is
  later. The median is taken over every leaf that carries a profile, as
  the group was before the commit: sort their values, and take the one
  at position floor(n/2), counting from 0. No one member can move it,
  and every device computes the same value. Any member's device MAY
  remove stale leaves, at most max(1, floor(n/10)) of them in one
  commit, where n is the number of leaves before the commit. It MUST,
  in the same commit, add the same devices again from new KeyPackages,
  for each that KEYPKG GET returns one.

A device that finds it has fallen behind (7.4) uploads fresh
KeyPackages, and waits to be added again. Once it is back in the
conversation with yourself, it asks its identity's other devices for
what it missed with WANT lines, which they answer with transfers
(12.13).

**Refreshing keys.** A device MUST commit a fresh leaf of its own, with
a commit that has no proposals, in each group where it has not
committed for a week, the next time it is online. After that commit,
keys that someone may have stolen from the device no longer decrypt new
messages. A light client replaces its leaf instead (12.6).

These rules mean that the server cannot, on its own, let anyone else
read a conversation. A direct conversation only ever holds the devices
of its two participants, every new identity in a room is added by an
owner or moderator, every added device holds a key that its identity
bound to it, and every key is checked against the witnessed log. Section
14 covers the exceptions.

### 12.8. Welcome Messages

A device that a commit adds gets a Welcome, encrypted to its
KeyPackage.

```
WELCOME PUT <ref> <welcome>
WELCOME LIST
WELCOME DEL <id>
WELCOME GET <ref> [light=yes]
```

- **`WELCOME PUT`** hands the server a Welcome for the KeyPackage whose
  KeyPackageRef [RFC9420] is `<ref>`, 48 bytes in base64 with padding,
  and replies `OK`. It works on any kind of connection, and the
  committer SHOULD send it on an anonymous one. The server accepts it
  only for a KeyPackage it handed out with KEYPKG GET, or one in an
  external Add proposal in a public room (`ERR not-found`). A Welcome
  that adds several devices is sent once for each of their refs, or
  once as a blob that each PUT names.
- For a KeyPackage uploaded with KEYPKG ADD, the server sends
  `WELCOME <id> <welcome>` to the device's signed-in connections at
  once, and pushes to its account subscriptions (9.2). **`WELCOME
  LIST`** sends every Welcome pending for the device, the same way, then
  `OK`. `<id>` is chosen by the server, in the form of an id (3.5).
- **`WELCOME DEL`** deletes a pending Welcome once the device has joined,
  and replies `OK`. It replies `OK` too for an id that is not pending
  for the device, so that a device whose first `OK` was lost can send it
  again.
- **`WELCOME GET`** returns the Welcome for a KeyPackage of an external
  proposal, as `WELCOME <id> <welcome>`, then `OK`, or `ERR not-found`
  if there is none yet. It works on any kind of connection, so that a
  device or guest that joined a public room anonymously can fetch it.
  With `light=yes`, `<welcome>` is an AnnotatedWelcome (12.6).

A committer SHOULD wait a random time of up to a minute after its
commit's `OK` before it sends the Welcomes, so that the server cannot
easily tie the new device to the commit by timing. In a direct
conversation or a private room, the Welcome's GroupInfo MUST carry the
`ratchet_tree` extension, since the server does not hold the tree.

The device checks the group as in 12.7, then joins it in the Welcome's
epoch. It follows the mailbox, fetches what the server keeps (7.4), and
applies the posts from that epoch on, ignoring those of earlier epochs.
It SHOULD NOT delete the Welcome, or the private keys of the KeyPackage
it was made for, before it has joined, so that it can try again if
joining is cut short, for example by a crash. It also deletes a Welcome
whose group fails the checks of 12.7. The server deletes Welcomes that
are not fetched within its retention period, and the pending Welcomes of
a device that has been removed.

### 12.9. Messages

Everything a device posts carries, as the MLS `authenticated_data`, a
RisalaAAD. MLS leaves it in the clear for the server, and authenticates
it for members:

```
struct {
    uint8 version;               // 1
    opaque pseudonym[16];        // the leaf's pseudonym (7.3)
    opaque frank<V>;             // 48 bytes in an application message, otherwise empty
    opaque next_token_hash<V>;   // 48 bytes in a commit, otherwise empty
} RisalaAAD;
```

The content of an application message is a RisalaMessage:

```
struct {
    uint8 version;               // 1
    opaque message_id[16];
    uint64 counter;
    opaque previous<V>;          // 16 bytes, or empty
    uint64 time;                 // the sender's clock, ms since 1970-01-01T00:00:00Z
    opaque frank_key[32];
    opaque content<V>;
} RisalaMessage;
```

To send a message, a device:

1. Writes the content lines (below) as `content`.
2. Sets `message_id` and `frank_key` to new random values, and `time`
   to its clock.
3. Sets `counter` to the number of messages its leaf has sent in the
   group, this one included, and `previous` to the `message_id` of the
   leaf's previous message, or leaves it empty for the first. A live
   message (5.2) has `counter` 0 and an empty `previous`, and does not
   count.
4. Sets `frank` in the RisalaAAD to HMAC-SHA-384(`frank_key`, `content`)
   [RFC2104], over the bytes of `content` alone, without their length
   prefix.
5. Encrypts the RisalaMessage as an MLS application message. It SHOULD
   pad the PrivateMessageContent with zero bytes to a multiple of 256
   bytes, so that the server learns less about lengths.
6. Posts it (5.2).

MLS signs the message with the sender's leaf key, and encrypts it with a
key used only for this message, which every device deletes once it has
decrypted it. To receive a message, a device decrypts it with MLS, which
also checks its signature, and then:

1. Checks that the RisalaAAD's pseudonym is the one it first saw from
   that leaf (7.3).
2. Checks that HMAC-SHA-384(`frank_key`, `content`) equals `frank`,
   comparing in constant time. ChaCha20-Poly1305 is not key-committing,
   so this check is what makes sure that no message decrypts to
   different contents for different devices, and that a report can only
   reveal what was sent (5.8). It MUST NOT be skipped.
3. Checks that it has not already seen `message_id` in the group, so
   that the server cannot replay a message under a new seq.
4. Checks `counter` and `previous` against the leaf's earlier messages,
   and notes a gap (7.4).
5. Compares `time` with the `t` of the post. If they differ by more than
   10 minutes, it shows the message with the sender's time and a mark
   that the times disagree.
6. Shows the message as verified only if the sender's leaf is confirmed
   (12.10), and as unverified otherwise.

If any of steps 1 to 3 fails, or the leaf has posted a SelfRemove, the
device MUST NOT show the content, and MAY show that a message could not
be read.

**Late messages.** Devices apply posts in seq order (7.2), and judge a
message by where it falls in that order, not only by its epoch:

- A device MUST ignore a message from a leaf that a commit with a lower
  seq has removed, even if the message is of an earlier epoch.
- A line that depends on a role, such as a DELETE of someone else's
  message (5.4), or a TEXT line or typing in a room with `send mods`
  (6.2), counts only if its sender has the role both in the extension
  of the message's epoch and in that of the newest epoch the device has
  applied at the message's seq.
- A device decrypts a message of a past epoch e only if the newest
  epoch it has applied at the message's seq is at most e + 2, and the
  post's `t` is within an hour of the `t` of the commit that ended
  epoch e. It shows a later one as unreadable,
  and SHOULD delete a past epoch's secrets as soon as it has applied a
  post that puts the epoch past either limit. These rules depend only on
  the posts, so every device reaches the same result.

The content is one or more lines in UTF-8, in the format of Section 3,
each ending in LF. The rules of 2.3 for characters apply to these lines,
but its length limits do not: TEXT has its own limit (5.3), and the
content as a whole is at most 4 MiB (4194304 bytes). Devices ignore
lines with verbs they do not know, and lines in a conversation where
the table does not allow them.

| Line | Where | Section |
|---|---|---|
| `[@<tags>] TEXT <text...>` | any conversation | 5.3 |
| `DELETE <id>` | any conversation | 5.4 |
| `TYPING` | any conversation, live | 8.1 |
| `[@<tags>] REPORT [<reason...>]` | a direct conversation, to a room's moderator | 5.8 |
| `CHALLENGE <leaf> <ciphertext>`, `ANSWER <leaf> <mac>` | groups whose `confirm` is `pairwise` | 12.10 |
| `ATTEST <period> <period-key> <certificate> <attestation>`, `REVEAL <period> <seed>` | groups whose `confirm` is `epochal` | 12.10 |
| `READ <box> <seq>` | the conversation with yourself | 7.7 |
| `BLOCK <target>`, `UNBLOCK <target>` | the conversation with yourself | 5.7 |
| `RECORD <hash>`, `ALERT <hash>` | the conversation with yourself | 4.5 |
| `SIGNINGKEY <seed>`, `BACKUPKEY <generation> <key>` | the conversation with yourself | 4.8, 12.13 |
| `WANT <box> <after> <before>`, `TRANSFER <ref>` | the conversation with yourself | 12.13 |

A TEXT line may carry these tags:

- `reply`, `edit` and `react`, each with a `message_id` in base64 with
  padding (5.3).
- `file`, the file's `get` URL; `file-key`, the file key in base64 with
  padding; `file-type`, its media type, as `type/subtype` [RFC6838];
  `file-size`, its size in bytes before encryption; and `file-hash`, the
  SHA-384 hash of the exact bytes uploaded, in base64 with padding
  (12.11). A TEXT line that has `file` without both `file-key` and
  `file-hash`, or whose `file-key` is not 32 bytes or `file-hash` not 48
  bytes, is shown as a message with no file.

For example, a reply as it appears inside the encryption:

```
@reply=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12
```

In RECORD and ALERT, `<hash>` is a record's SHA-384 hash as a blob-ref
(3.5). In SIGNINGKEY, `<seed>` is the new device-signing key's 32-byte
seed, and in BACKUPKEY, `<key>` is a backup key (12.13), each in base64
with padding. Devices accept the lines of the conversation with
yourself only from leaves of their own identity that they have
confirmed (12.10), and send SIGNINGKEY and BACKUPKEY only while every
leaf in that conversation is confirmed, since every leaf there reads
them.

### 12.10. Confirming Leaves

Leaf keys are not signed by anything the identity publishes (12.3). A
device **confirms** a leaf when it has made sure that the leaf belongs
to the device named in its credential, a current, logged device of that
identity (4.5). Until then the leaf is **unconfirmed**, and its messages
are shown as unverified. Once it is confirmed, so are its earlier
messages, since they were signed by the same leaf key.

Confirmation must convince the members of a group, and nobody else.
Signing the leaf key with the device key would convince anyone who sees
the signature, and so would prove who wrote every message the leaf
signed. Instead, the group's `confirm` field (12.4) picks one of two
ways. Direct conversations, and private rooms of up to 256 members, use
`pairwise`. Public rooms, and private rooms that have grown past 256
members, use `epochal`.

**Pairwise.** Each pair of devices confirms each other's leaf with a
post-quantum KEM challenge and a MAC. For device B to confirm the leaf
of device A:

1. B encapsulates to A's attestation key (4.4) with X-Wing: (`ct`,
   `ss`) = Encap(A's attestation key). B keeps `ss`, and sends
   `CHALLENGE <a> <ct>` in the group, where `<a>` is A's leaf index, in
   decimal, and `<ct>` the 1120-byte ciphertext in base64 with padding.
2. A decapsulates `ct` with its attestation key to get `ss`, and sends
   `ANSWER <b> <mac>`, where `<b>` is B's leaf index and `<mac>` is the
   48-byte MAC below, in base64 with padding.
3. B computes the same MAC and compares it, in constant time. If they
   match, B has confirmed A's leaf.

```
struct {
    uint8 version;                  // 1
    opaque group_id<V>;
    opaque challenge_hash[48];      // SHA-384 of ct
    opaque answerer_key_hash[48];   // SHA-384 of A's leaf signature key
    opaque challenger_key_hash[48]; // SHA-384 of B's leaf signature key
} ConfirmContent;
```

The MAC is HMAC-SHA-384(K, ConfirmContent) [RFC2104], where K =
HKDF-Expand(HKDF-Extract("", `ss`), "risala/1 confirm", 48) [RFC5869]
with SHA-384. Only A could decapsulate `ct`, so the MAC shows B that A's
device signed the message holding it with the leaf key. Since B knows
`ss` too, B could have made the same MAC, so the exchange proves nothing
to anyone else. It uses only X-Wing and HMAC.

A device confirms only leaves that send. The first time it processes a
message from an unconfirmed leaf that has something to show (a TEXT,
DELETE or REPORT line), it challenges that leaf. CHALLENGE and ANSWER
lines alone do not count, so a member that never sends is never
challenged and costs nothing. Guest leaves have no attestation key, and
are never challenged or confirmed. A device puts its pending CHALLENGE
and ANSWER lines in its next message in the group, or, if it sends none,
in a message of their own within a minute. It answers only the newest
challenge from each leaf, and ignores challenges whose `<a>` is not its
own leaf. The sender's messages show as unverified until its answer
arrives.

This costs one extra flight, and about 2.4 KiB for each pair of a
sending leaf and a device that reads it, once per pair and group. The
first message from a new sender in a private room of 256 members, about
770 devices, brings about 1.8 MB of challenges and answers.

**Epochal.** In a large group, confirming every pair would cost too
much. Instead, devices confirm leaves with epochal signatures
[EPOCHAL]: keys that sign for a single day, and whose private halves are
published once the day is over. Until then, a leaf's binding convinces
the members. Afterwards, anyone could have made it, so messages are
deniable once the key is out.

- **Periods.** A period is a UTC day, numbered from 1970-01-01 as 0:
  `period` = floor(ms since 1970-01-01T00:00:00Z / 86400000).
- **Period keys.** For each period in which it sends in an epochal
  group, a device makes a fresh ML-DSA-44 **period key**, and a
  certificate for it: RisalaSign(device key, "period", PeriodCert)
  (4.3). The certificate says only that the key is the device's for
  that period.
- **A new leaf key each period.** Before its first message of a period
  in an epochal group, the device commits a fresh leaf with a new
  signature key (12.3), and deletes the old one. So no leaf key is used
  in more than one period.
- **Attesting.** In its first message after that commit, the device
  sends `ATTEST <period> <period-key> <certificate> <attestation>`.
  `<period>` is in decimal, and the rest are the period key, the
  certificate's signature and RisalaSign(period key, "attest",
  AttestContent), each in base64 with padding.
- **Revealing.** Once the period and a grace hour after it are over, the
  device sends `REVEAL <period> <seed>`, the period key's 32-byte seed
  in base64 with padding, in each group where it attested in that
  period, in its next message there or within a day.

```
struct {
    uint8 version;               // 1
    opaque uid<V>;
    opaque device_id[48];
    uint32 period;
    opaque period_key<V>;        // ML-DSA-44 public key
} PeriodCert;

struct {
    uint8 version;               // 1
    opaque group_id<V>;
    uint32 period;
    opaque leaf_key_hash[48];    // SHA-384 of the leaf's signature key
} AttestContent;
```

A device confirms a leaf from an ATTEST line that the leaf sent if the
certificate verifies under the device key of the device in the leaf's
credential, a current, logged device of that identity (4.5); the
attestation verifies under the period key; `leaf_key_hash` is the
leaf's; and, by the device's own clock as it processes the line, the
period is the current one, or the one before it within its grace hour.
The leaf stays confirmed only until that grace hour ends. A device that
processes a leaf's messages after that, for example because it was
offline, shows them as unverified: by then the period key may be out,
and anyone could have made the attestation.

A device checks that a REVEAL's seed derives the period key that the
leaf attested with, and otherwise warns the user, since a device that
does not reveal its keys does not give the deniability the group
expects.

This construction is new, and needs a review by cryptographers before
it is relied on (Section 14).

### 12.11. Files

Devices encrypt every file before they upload it (5.6). The message that
shares it carries, on its TEXT line, the `get` URL as `file`, and the
file's key, media type, size and hash as `file-key`, `file-type`,
`file-size` and `file-hash` (12.9). The server learns only the padded
size of the encrypted file.

**Encrypting a file.** A device:

1. Picks a new random 32-byte file key.
2. Builds the plain text: the file's length in bytes as an 8-byte
   big-endian number, then the file, then zero bytes up to the padded
   length. The padded length is Padmé [PADME] of 8 plus the file's
   length: for a length L of at least 2, with E = floor(log2(L)),
   S = floor(log2(E)) + 1, z = E - S and m = 2^z - 1, it is
   (L + m) with its lowest z bits cleared. So the server learns the
   size only roughly, at a cost of at most about 12%.
3. Splits the plain text into chunks of 65536 bytes. The last chunk may
   be shorter, but not empty.
4. Encrypts chunk number i, counting from 0, with ChaCha20-Poly1305
   [RFC8439] under the file key, with a nonce of i as an 11-byte
   big-endian number followed by one byte: `0x01` for the last chunk,
   `0x00` for the others. The associated data of every chunk is the
   ASCII label `risala/1 file`, or `risala/1 archive` for a history
   archive (12.13), without a length or a terminator.
5. The upload is one `version` byte, `0x01`, followed by the encrypted
   chunks in order, each followed by its 16-byte tag.

The label keeps a file from being taken for an archive, and the reverse,
even under the same key. A device that downloads a file:

- checks that the SHA-384 hash of what it downloaded equals `file-hash`,
  comparing in constant time, before it decrypts anything;
- rejects it if its first byte is not `0x01` (2.4), or if what follows
  is empty, or would leave a last piece of 16 bytes or fewer when cut
  into pieces of 65552 bytes;
- decrypts chunk by chunk, and checks that only the last chunk has the
  last-chunk flag, that the length L fits in the plain text, that the
  plain text is exactly Padmé of 8 + L bytes long, and that the padding
  is all zero bytes;
- MUST NOT show or save any part of the file unless every check passes.

**Where devices download from.** A `file` URL can point at any host,
and whoever runs that host learns the network address of each device
that fetches it, and when. INFO lists the origins of the server's own
`get` URLs (8.5). A device downloads a file without asking only if its
URL is on one of those origins of the server of the conversation it
was shared in. Any other URL it fetches only when the user asks, after
telling them that the host will learn their network address.

The TEXT line is authenticated by the sender's leaf and franked (12.9),
so a file that a member or the server swaps after the message was sent
fails the hash, and so does an attempt to frame the sender through a
report. Whoever reviews a report (5.8) fetches the file only when they
ask to, and checks it the same way.

A device MUST NOT trust `file-size` or `file-type` over what the
decrypted file holds: `file-size` is for showing before the download,
and the length inside the plain text is the one that counts.

### 12.12. Blobs

Some MLS objects are too large for a line: the ratchet tree of a large
group, a Welcome that carries one, or a commit that adds many devices.
These travel as **blobs** over HTTPS, and lines carry their hashes. A
blob is named by the SHA-384 hash of its bytes, written as a blob-ref
(3.5), so that anyone who fetches it can check it.

```
BLOB <hash> <size> [box=<box> token=<token>]
```

→ `OK put=<url>`, or `OK exists=yes`

- `<hash>` is the blob-ref, and `<size>` the blob's size in bytes. The
  blob holds the raw bytes of the object, without base64.
- On an anonymous connection, `box` and `token` are required, and are
  checked as for POST (5.2), so that only members of some group can
  store blobs. On a signed-in connection they are not needed.
- The client sends the blob in an HTTP PUT request to the `put` URL,
  which works for one upload within 10 minutes. The server MUST reject a
  body whose length differs from `<size>`, or whose SHA-384 hash differs
  from `<hash>`.
- `exists=yes` means the server already has the blob. Nothing needs to
  be uploaded.
- A blob larger than the server allows gets `ERR too-long`. A server
  MUST allow blobs of at least 256 MiB, which holds the tree of the
  largest public room.

Anyone fetches a blob with an HTTP GET request to the `blobs` URL prefix
of INFO (8.5), followed by the 96 hex digits of its hash. The fetcher
MUST check the hash of what it gets before it uses it. Blobs expire with
retention (7.5), except that the server keeps the tree of a public
room's current epoch for as long as it is current, and the blobs of an
identity's current backup for as long as it is current (12.13).

Blobs are public to anyone who knows their hash. Everything a device
stores in one is either public already, such as a public room's tree,
or encrypted, such as a Welcome or a history archive (12.13).

### 12.13. History on New Devices and Backups

The server keeps no history (Section 7). A device keeps the messages it
has received, decrypted, under the protection it gives its own keys,
and deletes each message key as soon as it has used it (12.9). So the
history of a conversation exists only on its members' devices. It
reaches a new device in two ways: from the identity's other devices,
and from a backup.

**The conversation with yourself.** An identity's devices share a
direct conversation of their own (5.1) on each server they use. They
use it to keep each other up to date: read markers (7.7), blocks (5.7),
records they make (4.5), new device-signing keys (4.8), backup keys
(below), and requests for history and transfers (below), as lines
inside the encryption (12.9).

**History archives.** History travels as HistoryArchives:

```
struct {
    opaque message_id[16];
    opaque sender<V>;            // uid, in lower case
    opaque device_id<V>;         // the sender's device id (4.4), 48 bytes; empty for a guest
    uint64 counter;              // the RisalaMessage's counter (12.9)
    opaque previous<V>;          // the RisalaMessage's previous: 16 bytes, or empty
    uint8 verified;              // 1 if the archiving device had confirmed the sender's leaf (12.10), else 0
    uint64 sent;                 // the sender's time, ms
    uint64 received;             // the server's time, ms
    uint64 seq;                  // the post's seq
    opaque content<V>;           // the content lines, as received
} ArchivedMessage;

struct {
    opaque group_id<V>;
    opaque host<V>;              // the server, in lower case
    opaque box[16];
    ArchivedMessage messages<V>; // in seq order, oldest first
} ArchivedConversation;

struct {
    opaque file_hash[48];        // the file-hash of the original upload (12.9)
    opaque blob_hash[48];        // the blob that holds the file now
    opaque key[32];              // that blob's file key
} ArchivedFile;

struct {
    uint8 version;               // 1
    opaque blob_hash[48];
    opaque key[32];
} TransferRef;

struct {
    uint8 version;               // 1
    opaque uid<V>;
    uint64 made;                 // when the archive was made, ms
    ArchivedConversation conversations<V>;
    ArchivedFile files<V>;
    TransferRef more<V>;         // the other archives of the same transfer or backup
} HistoryArchive;
```

- **Messages** are archived as the archiving device received them. It
  leaves out deleted messages (5.4). It keeps DELETE lines, edits and
  reactions as messages of their own, so that a device that holds their
  target applies them as it would on receipt. A device ignores those
  whose target it neither holds nor receives in the same transfer.
- **Files.** For each file that it has downloaded and checked (12.11),
  and chooses to include, the archiving device encrypts the file again
  as a new file under a new random key, with the label `risala/1 file`,
  stores it as a blob (12.12), and lists it in `files` under the
  original `file-hash`. A device that reads a TEXT line whose
  `file-hash` is listed fetches that blob, rather than the `file` URL,
  checks its hash against `blob_hash`, and decrypts and checks it as a
  file (12.11) under `key`. A device SHOULD reuse the same blob and key
  for the same file in later backups, so that it uploads each file
  once.
- **Encryption.** Each archive is encrypted as a file (12.11), with the
  label `risala/1 archive`, under a new random 32-byte key, and stored
  as a blob. A TransferRef names the blob by its hash, and holds the
  key. A device that opens one fetches the blob, checks its hash,
  decrypts it, and rejects an archive whose `version` or whose
  TransferRef's `version` is not 1 (2.4).
- **Splitting.** History too large for one blob, by the device's choice
  or the server's limit (12.12), is split over several archives. The
  **first** archive is the one that the IdentityBundle, the TRANSFER
  line or the backup names. Its `more` lists the TransferRefs of all
  the others, in order. They have an empty `more`, and the same `uid`
  and `made` as the first, and a device rejects any that does not. The
  first archive may hold conversations and files of its own, or none.
- **Merging.** A conversation may span archives. A device reads the
  first archive, then the others in the order of `more`, and joins the
  ArchivedConversations that have the same `group_id`, `host` and `box`
  by appending their messages in that order. The messages of each
  conversation MUST then be in strictly increasing seq order, and a
  device ignores a conversation in which they are not. A device that
  cannot fetch or open an archive uses the others, and tells the user
  that part of the history is missing.

**Transfer at pairing.** When a device pairs a new one (4.8), it MAY
send it the history of the conversations it chooses: it builds and
stores the archives, and puts the TransferRef of the first in the
`transfer` field of the IdentityBundle. The new device opens them and
stores the history, for the conversations its identity's devices are
in. The server sees only blobs of ciphertext.

**Catching up from your own devices.** A device that has a gap it
cannot fill from the server, because the posts in it have expired
(7.4), or because it was added to a group again after falling behind
(12.7), asks the identity's other devices for it:

```
WANT <box> <after> <before>
TRANSFER <ref>
```

- **`WANT`**, in the conversation with yourself, says that the device
  lacks the posts of mailbox `<box>` whose seqs are greater than
  `<after>` and less than `<before>`, each in decimal. `<before>` is `-`
  if the device does not know where the gap ends.
- **`TRANSFER`** answers it. A device of the identity that holds some of
  those messages SHOULD send them as archives, with `TRANSFER <ref>` in
  the conversation with yourself, where `<ref>` is the TransferRef of
  the first archive in base64 with padding.

A device applies a transfer, whether at pairing or by TRANSFER, under
these rules, since a device that sends one may have been compromised:

- It applies messages only of conversations whose group it is in, or,
  at pairing, is added to. After pairing, it applies only messages whose
  seqs lie in a range it has asked for with WANT and not yet filled.
- It never replaces or changes a message it holds, and skips archived
  messages whose `message_id` it has already seen in the group.
- It shows each message it applies as copied from the device that sent
  it, by that device's label, and the `verified` flag as that device's
  verification, never as its own.
- It matches each message to its sender's leaf by `device_id`, and
  takes its `counter` and `previous` into its record of that leaf's
  messages, so that a gap the transfer fills is not shown as held back
  (7.4).

Only an identity whose every device was offline for longer than
retention loses messages.

**Backups.** A person MAY keep an encrypted backup of their history on
the server, so that it survives losing every device. Only the recovery
key can read it. Servers MUST support backups.

- **Generations.** An identity's backup **generation** is the number of
  records in its key file's chain, after the first, that name a new
  device-signing key: `signing` records and later `master` records
  (4.4). The first generation is 0. Removing a device and recovering the
  identity each add such a record (4.8), and so move to the next
  generation, since the removed or lost device knew the old backup key.
- **Backup keys.** A backup key is derived from the recovery key with
  HKDF-SHA384 [RFC5869]: HKDF-Expand(HKDF-Extract("", recovery key),
  info, 32), where `info` is `risala/1 backup `, the uid, a space, and
  the generation in decimal. Every device keeps the current
  generation's backup key, which it got at pairing or in a BACKUPKEY
  line, but never the recovery key.
- **Making a backup.** At most once a day, one device of the identity
  builds archives of everything it has, with the files it chooses, and
  stores them as blobs. It then wraps the first archive's key under the
  current backup key, as a WrappedKey (below).
- **New generations.** A device that moves the identity to a new
  generation, by removing a device or by recovering, MUST make a new
  backup at once if the identity keeps one, so that an honest server
  replaces the backup of the old generation.

```
struct {
    uint8 version;               // 1
    opaque nonce[12];            // random
    opaque ciphertext[48];       // the 32-byte key, then its 16-byte tag
} WrappedKey;
```

`ciphertext` is the first archive's key encrypted with
ChaCha20-Poly1305 [RFC8439] under the backup key and `nonce`. Its
associated data is the ASCII text `risala/1 backup `, the uid, a space,
the generation in decimal, a space, and the first archive's blob-ref as
BACKUP PUT sends it (`sha384:` and 96 lower-case hex digits), for
example `risala/1 backup alice@example.org 2 sha384:5d0c9a1e…`. The
wrapped key is 61 bytes.

```
BACKUP PUT <generation> <hash> <key> [files=<list>]
BACKUP GET
BACKUP DEL
```

- **`BACKUP PUT`** stores a backup, and replies `OK`. `<hash>` is the
  blob-ref of the first archive, and `<key>` the WrappedKey in base64
  with padding. `files` is the blob-ref of a **list**: a blob that holds
  the 48-byte hashes of every other blob of the backup, the archives in
  `more` and the files in `files`, one after another without anything
  between them. It is needed only if there are any.
  - Every blob it names, directly or in the list, must still be stored
    on the server (`ERR not-found`). A list whose length is not a
    multiple of 48 bytes, or a wrapped key that is not 61 bytes starting
    with `0x01`, gets `ERR invalid`.
  - From then on, the server keeps every blob the backup names for as
    long as it is the current backup, whatever the retention period. It
    replaces the identity's previous backup, and deletes the blobs of
    that one that the new one does not name.
- **`BACKUP GET`** sends `BACKUP <generation> <hash> <key> [files=<list>]`,
  then `OK`, or `ERR not-found` if there is no backup.
- **`BACKUP DEL`** deletes the backup and its blobs, and replies `OK`.
- They need a signed-in connection. Backups belong to the identity, not
  to a device. A server MAY limit their total size (`ERR too-long`).

**Restoring.** A device restores a backup only after it has recovered
the identity (4.8):

1. From the identity's key file, checked against the key log (4.5), it
   computes the generation that was current just before its own
   recovery record.
2. It sends BACKUP GET, and refuses a backup of any other generation:
   it tells the user that there is no usable backup. The generation
   comes from the log, not from the server, so a server cannot hand it
   a backup made with a key that a removed or lost device holds.
3. It derives that generation's backup key, checks that the wrapped
   key's `version` is 1, unwraps it, and opens the archives.
4. It shows when the backup was made, from the first archive's `made`,
   which the wrap covers through the blob's hash. Within one generation
   the server can still hand out an older backup than the newest
   (Section 14), and this lets the user notice.
5. It shows the messages as restored from a backup, and their `verified`
   flag as verified by the user's device at the time, not as a check it
   has made itself.

**Forward secrecy.** A backup is not forward secret. Backup keys depend
only on the recovery key and the generation, and the server is not
trusted to delete what it is told to delete. So whoever gets the
recovery key can read every backup that the server has kept, replaced
and deleted ones included, back to the first. A new recovery key means
a new master key (4.4, 4.8), which every contact sees (12.14).

### 12.14. Checking Devices and Safety Numbers

A device does not take the server's word for which keys belong to whom:

- It fetches key files itself, under the rules of 4.4, and checks every
  record it acts on against the key log (4.5).
- For each identity it shares a conversation with, it SHOULD fetch the
  key file again at least once a day. It then removes the leaves of
  devices that have been removed, and adds devices that have none
  (12.7). A failed fetch changes nothing.
- Clients SHOULD show each identity's devices, and tell the user when one
  is added or removed. A new device under the same master key is a
  notice, not a warning.

**Safety numbers.** Each identity has one **safety number**, which
covers its master key and its uid, and so all of its devices:

```
struct {
    opaque label<V>;             // "risala-fp-1"
    opaque uid<V>;
    opaque master_key<V>;
} SafetyNumberContent;
```

The fingerprint is the SHA-384 hash of the encoded SafetyNumberContent.
Clients show it as 40 digits, in eight groups of five: each group is the
next 5 bytes of the fingerprint as a big-endian number, modulo 100000,
written with leading zeros. They also show it as a QR code holding the
text `RISALA-FP:` followed by the encoded struct below in upper-case
base32 [RFC4648] without padding:

```
struct {
    uint8 version;               // 1
    opaque uid<V>;
    opaque fingerprint[48];
} SafetyNumberCode;
```

Two people compare safety numbers through another channel, for example
in person, by scanning each other's codes. A client then marks the
identity as **verified**.

- A **new master key** (4.5) clears "verified". In a direct
  conversation and in a private room, the device stops sending until the
  user acknowledges the new key. In a public room, it shows a warning.
- A new log for the identity counts as a new master key (4.5).
- A fork (4.5) stops sending as 4.5 says, whether or not the identity was
  verified.

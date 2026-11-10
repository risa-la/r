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
  members of the epoch, with a send token (7.2). The exception is a
  public room's commits, whose sender the server sees anyway (12.6).
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
  that a library upgrade cannot change it unnoticed. The tests MUST
  cover how X-Wing expands a 32-byte seed into a key pair, for leaf and
  KeyPackage keys and for attestation keys, which are stored as seeds
  (4.3): X-Wing's drafts have changed this expansion, and a change would
  silently give every device a different attestation key.
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
  [RFC4648], except where 12.6 and 12.8 say otherwise: a `<welcome>`
  is a SealedWelcome for a KeyPackage that KEYPKG GET handed out, and an
  AnnotatedWelcome with `light=yes`, and a commit's `<message>` is an
  AnnotatedCommit on a FETCH with `leaf`. `<tree>` is a ratchet tree,
  encoded as the data of a `ratchet_tree` extension (the
  `optional<Node>` vector of [RFC9420]), in base64 with padding. Each
  of them may instead be a blob-ref, naming a blob that holds the same
  bytes without base64 (12.12), except in an external commit and a new
  public room's CREATE, which must fit in their lines.

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
- **The signature key changes** in a group whose `confirm` is
  `epochal`, once per period in which the device sends or sent the
  period before (12.10), and right after a device joins with its
  last-resort KeyPackage (12.5). In both cases the device replaces its
  leaf node with a fresh one that has a new signature key, by an Update
  proposal in an epochal group (12.10) or by a commit of its own
  otherwise, and deletes the old key once that has taken effect.
  Otherwise a new signature key means a new leaf.
- **Which changes are valid** is a group check (12.7), decided from the
  tree and the post alone. Outside epochal groups, a leaf node may bring
  a new signature key only while the leaf has neither committed nor
  been Updated since it was added: its `leaf_node_source` [RFC9420] is
  still `key_package`. In an epochal group, a leaf node may bring one
  only if the `t` of the post that carries it (5.2) falls in a later
  period (12.10) than the time 10 minutes before the leaf's previous
  `updated`. Since `updated` may be up to 10 minutes after `t`, this
  keeps a device whose clock runs a little ahead, and that commits just
  before midnight, from being barred for the whole next period. So a
  leaf changes its signature key at most once a period, or twice if the
  first change comes in the period's first 20 minutes. Which periods a
  device must rotate in is up to the device, and not checked.
- A fresh leaf node keeps the leaf's index. Pseudonyms are not part of
  the leaf: 7.3 says how they are found.
- Two leaves of a group never share a signature key [RFC9420].

**Guests** (4.2) have leaves whose credential names their guest uid and
has an empty `device_id`. Nothing confirms them, and devices show them
as unverified guests.

**Device bindings.** Leaf keys are not bound to the identity, but in
direct conversations and private rooms the keys that others encrypt to
are. Every KeyPackage that a device uploads with KEYPKG ADD (12.5)
carries a **device binding**, an extension of type `0xF2A2` in the
KeyPackage's leaf node, not in `KeyPackage.extensions`, so that it goes
into the group's tree with the leaf:

```
struct {
    uint8 version;               // 1
    opaque device_id[48];
    opaque signature<V>;
} DeviceBinding;

struct {
    opaque uid<V>;
    opaque init_key<V>;          // the KeyPackage's init_key
    opaque encryption_key<V>;    // the leaf node's HPKE key
} DeviceBindingContent;
```

`signature` is RisalaSign(device key, "keypackage", DeviceBindingContent)
(4.3), by the device whose id is `device_id`. `device_id` MUST be the
`device_id` of the leaf's credential, and `uid` the credential's uid.
The binding shows that only that device can read what is encrypted to
the KeyPackage, so that neither the server nor a member can slip in a
KeyPackage of their own under someone else's name. It says nothing about
the leaf's signature key or about any message, so it does not weaken
deniability. It does show that the device was given a way into some
group.

- Devices and servers check a binding only where a leaf enters a group
  from a KeyPackage, at an Add (12.5, 12.7).
- A leaf node that a leaf's own commit or Update proposal brings has a
  new `encryption_key`, which the binding does not cover. It MAY carry
  the binding unchanged, or none, and devices ignore it there.
- **Public rooms carry none.** A leaf that joins a public room (6.1)
  comes from a KeyPackage that the device makes for that join, with no
  device binding, never one uploaded with KEYPKG ADD. Anyone may join a
  public room and read it, so a binding would protect nothing there,
  while the room's public commits would chain every later leaf key of
  the device back to it, and so tie the device to its messages (Section
  14). In a public room, whose leaf is whose rests only on epochal
  confirmation (12.10).

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
  leaf or proposes an Update of it, and lets devices find leaves that
  have stopped keeping up (12.7). Devices treat as invalid a commit
  whose new `updated` for the committer's leaf, or for a leaf whose
  Update it commits, is lower than the leaf's previous one, or more than
  10 minutes before or after the `t` of the post that carries the commit
  or the Update proposal (5.2). So a device sets it from its clock, or, if its clock disagrees
  by minutes with the `t` of the posts it receives, from the time those
  suggest, and never below the leaf's previous `updated`. In a
  KeyPackage it is the time the KeyPackage was made, except in a
  last-resort one (12.5), where it is the start of the period (12.10)
  before the one it was made in, so that a device added from it can
  change its signature key at once in an epochal group. Devices treat
  as invalid a commit that adds a KeyPackage whose `updated` is more
  than 10 minutes after the `t` of the commit's post (12.7).
- **`streak`** counts the epochs in a row, up to and including the one
  the commit starts, that leaves of the committer's **identity** have
  started with their commits. Let S be the leaf that made the commit
  that started the current epoch. The committer's new `streak` is S's
  `streak` plus 1 if S's credential has the same uid as the
  committer's, and 1 if it does not, at most 255. So two devices of one
  identity that take turns count as one. It is 0 in a KeyPackage and in
  an Update proposal. Devices treat a commit whose `streak` is not this
  value as invalid, and limit commits by it (12.7). Every device knows
  S, including one that has just joined: S is the signer of the
  GroupInfo it joined with, and is still in the group, since a commit
  never removes its own committer [RFC9420].

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
    opaque host<V>;              // the server, as a server (3.5)
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
- `host` is the server, written as a `server` of 3.5: its host name in
  lower case, followed by `:` and the port only if the port is not
  7472, as in `chat.example.org` or `chat.example.org:7000`. It is
  compared byte for byte (12.7).
- In a room, `owners` holds at least one uid. In a direct conversation
  the lists are empty. Every uid in `owners`, `mods` and `bans` is an
  identity, not a guest. A uid is in at most one of `owners` and `mods`,
  and appears at most once in each of `owners`, `mods` and `bans`.
  `bans` holds at most 10,000 uids, the member limit of the largest
  room (6.1).

The rules on the lists, like the rest of this section, are format rules:
an extension that breaks one is not well formed. Everyone who reads an
extension checks them, wherever it comes from: a device that joins by
Welcome or by external commit (12.7), a device that applies a commit
(12.7) or checks its own before posting it, and the server, in a new
public room's CREATE (5.2) and in every commit it checks in a public
room (12.6). Since `bans` may be long, implementations find repeats with
a hash set or by sorting, not by comparing every pair.

The group context has exactly two extensions: `required_capabilities`
first, which lists the extension types `0xF2A1`, `0xF2A2` and `0xF2A3`,
the proposal type `self_remove` and the credential type `basic`; then
the conversation extension. A commit may change only the fields that
6.2 and 6.3 allow, through a GroupContextExtensions proposal, and never
`version`, `kind` or `host`, nor the `name` of a direct conversation or
a public room. `box` changes only when a direct conversation or a
private room moves to a new mailbox, and then only to the box that 7.8
derives from the group's secrets.

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
  RisalaIdentity of the connection's uid and device, that its leaf node
  has a device binding (12.3) that names the connection's device and
  uid, verifies under the connection's device key and covers its init
  and encryption keys, that its leaf lists the
  capabilities of 12.3, that its keys pass the checks of 12.2, that its
  signatures verify, and that its lifetime is acceptable (below).
  Otherwise it replies `ERR invalid`. A server MAY limit how many
  KeyPackages it keeps for each device (`ERR forbidden`), and how large
  a KeyPackage may be (`ERR too-long`). KeyPackages of this suite are
  about 11 KiB with a device binding, so a limit MUST NOT be below 16
  KiB.
- **`KEYPKG COUNT`** replies `OK count=<n> last-resort=<yes or no>`: the
  number of ordinary KeyPackages the server holds for this device, and
  whether it holds a last-resort one. It needs a signed-in connection.
- **`KEYPKG GET`** sends one `KEYPKG <uid> <keypackage> <secret>` line
  for each current device of `<uid>` (4.4) that has a KeyPackage, then
  `OK`. `<secret>` is a **put secret**: 32 random bytes, in base64 with
  padding, that the server makes for this one handout and keeps only
  as a hash. The Welcome for that KeyPackage must carry it (12.8), so
  that only whoever fetched the KeyPackage can deliver its Welcome. It
  works on anonymous, guest and signed-in connections (Section 13).
  Since it shows whom the device is
  about to talk to, a device SHOULD send it on a fresh anonymous
  connection for each identity it fetches, rather than one after another
  on the same connection (4.1). A uid the server does not know gets
  `ERR not-found`. An identity whose keys are missing to the server
  (4.4, 4.6) has no current devices, so it gets no KEYPKG lines. If the
  server cannot fetch the key file (4.4) and has no cached copy still
  valid, it replies `ERR unavailable` rather than hand out KeyPackages of
  devices that may have been removed.

```
C: KEYPKG GET bob@example.net
S: KEYPKG bob@example.net AAEABQBA… Hc2vQ0mX4t9bLr7kWz1pYf8eNa3sJd6uGq5iTo2lVyE=
S: KEYPKG bob@example.net AAEABQBA… 8kLw2sQe9rTz4nVb7mXc1aPd6fGh3jYu0iKo5lBq2Rs=
S: OK
```

Each KeyPackage has a leaf key of its own, so that each group a device
joins gets a different one (12.3). The server hands out each ordinary
KeyPackage once, then deletes it, keeping only its KeyPackageRef and the
hash of its put secret until its Welcome arrives (12.8). A device MAY
also upload one KeyPackage of last resort, marked as [MLS-EXT] marks it:
its `app_data_dictionary` extension (`0x0006`) holds the
`last_resort_key_package` component (`0x0004`), with empty data. The
server hands that one out only when the device has no ordinary
KeyPackage left, and keeps it, so the device can always be added, with a
new put secret for each handout. A new one replaces it. Since its leaf
key may be used in several groups, a device that joins with it replaces
its leaf node with one that has a new signature key, as 12.3 says,
before it sends anything.

A device SHOULD keep about ten ordinary KeyPackages on the server, and
upload more when KEYPKG COUNT reports fewer than five. Servers delete
KeyPackages whose lifetime has ended. Every KEYPKG GET uses KeyPackages
up, and once a device's ordinary ones are gone, groups fall back to its
last-resort one. So servers MUST rate-limit KEYPKG GET per network
address and per `<uid>` asked for (`ERR rate-limited`), and will
require proof of work for it on anonymous and guest connections once a
later draft specifies it (4.1).

**Lifetimes.** A KeyPackage's lifetime is acceptable if it spans at most
12 weeks and one hour (7261200 seconds from `not_before` to `not_after`),
and a time is within it:

- When a KeyPackage is uploaded, the server checks this against its own
  clock.
- When a commit adds the KeyPackage to a group, the server of a public
  room and every device check it again, against the `t` of the post
  that carries the commit (5.2), give or take an hour, never against
  their own clocks (12.6, 12.7). So every device reaches the same
  answer, however late it processes the commit.
- When a device makes such a commit, it does not know its post's `t`
  yet. It checks the lifetime against its own clock at the time it
  posts, with the hour taken inward: a time at least an hour after
  `not_before` and at least an hour before `not_after`. So the commit
  passes wherever the server's `t` falls within an hour of the device's
  clock. A KeyPackage that fails, it leaves out, and fetches the
  device's KeyPackage again (12.7).

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
same rule: it is a PrivateMessage outside public rooms. This departs
from [MLS-EXT], which sends SelfRemove as a PublicMessage so that the
delivery service can see it. Risala's server has no use for it, and a
PublicMessage would tell it which leaf left a private conversation.

**Commits.** Every commit has a path, so that it gives post-compromise
security and updates the committer's profile (12.3). All proposals are
inside the commit, by value, except three kinds, which their senders
post on their own and members commit by reference: a SelfRemove (6.1),
an Update of a leaf in an epochal group (12.10), and in a public room
an external Add proposal (6.1). The proposal types allowed are Add,
Remove, Update (only in epochal groups), GroupContextExtensions,
SelfRemove and, in an external commit, ExternalInit. There is no ReInit
or PSK proposal: a group never changes its cipher suite or protocol
version, and a conversation that moves to new ones (Section 15) will
start a new group with a new mailbox. A client that adds
many devices SHOULD split them over several commits of at most 256
devices each, bearing in mind that an identity's fourth commit in a row has
to wait (12.7). A commit too large for a line travels as a blob (12.12).
A commit's size, like a Welcome's, shows roughly how large the group
is, so commits and proposals sent as PrivateMessages SHOULD be padded
with MLS's padding, so that the length of their PrivateMessageContent
is a Padmé length (12.11).

**The next token.** A commit is posted with the option `next=<hash>`
(5.2): the SHA-384 hash of the send token (7.2) of the epoch that the
commit creates. It cannot travel inside the commit, since the commit is
part of what that epoch's keys are derived from [RFC9420], so nobody
could compute it before signing. The server adds it to the next epoch's
token set (7.2), and repeats it on the post. A device that applies a
commit computes the new epoch's send token, and treats the commit as
invalid if `next` is not its hash (12.7). So every valid commit opens
its epoch to the members, and one that names a wrong hash loses. The
server could change `next` on the way, but that only splits the group,
which it can do anyway (Section 14).

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
3. **It passes the group checks of 12.7** that need only the public
   state, which in a public room is all of them but the path secrets and
   the confirmation tag: who may add and remove whom, and how many,
   which fields of the conversation extension change and by whom, bans
   (by the uids in credentials), that the conversation extension stays
   well formed (12.4), the `guests` setting, the size limits
   of 6.1, external commits only as resync commits and rejoins (12.7),
   signature key changes, the `updated` (against its own clock, which
   gives the post its `t`) and `streak` of the committer, of each Update
   and of each added leaf (12.3), and that no guest's leaf commits or
   proposes an Update (`ERR forbidden`).
4. **It comes from the leaf's own device.** A commit, an external commit
   or an Update proposal whose sender's credential names an identity is
   posted on a signed-in connection of the device that the credential
   names, and a join proposal whose credential names a guest on that
   guest's connection (`ERR forbidden`). This is how the server keeps a
   public room's commits to its identities' devices, and holds bans and
   limits against them, without device bindings (12.3). It tells the
   server nothing that the credential does not already show, and proves
   nothing to anyone else. Devices cannot check it, so a server that
   skips it can commit in any identity's name (12.7, "Commits in
   another's name", Section 14). A join proposal whose credential names
   an identity may come from any anonymous or signed-in connection: the
   server does not check it, and devices treat the leaf as unverified
   until it attests (12.10). A commit too large for a line is first
   stored as a blob, over an anonymous connection (4.1, 12.12), and then
   posted on the signed-in one, which ties the two connections together.
   That tells the server nothing the commit does not, since the commit
   names its sender. An external commit is posted with the token `-`,
   and so cannot be a blob, and must fit in a line (5.2, 12.12).
5. **A commit carries the new GroupInfo,** with the `external_pub`
   extension and no `ratchet_tree` extension, as the option
   `groupinfo=<groupinfo>` of POST. Its group context must be the one
   the commit produces, its confirmation tag must be the commit's, and
   its signer must be the committer's leaf (`ERR invalid`).

The server then keeps the new tree and GroupInfo, and serves them with
GROUPINFO (6.1). A public room's Welcomes carry no tree (12.8), and in
a busy room the group has often moved on by the time a joiner fetches
its Welcome. So the server also keeps the tree of each epoch for which
a Welcome is pending, and hands it out with that Welcome (12.8), until
every Welcome of that epoch has been fetched or has expired. It MUST
keep such a tree for at least 24 hours after the commit that started
the epoch, and MAY drop it after that, together with the Welcomes that
need it, whose devices then join again by a new proposal (6.1). It MAY
store the trees as differences from one epoch to the next, which share
most of their nodes. A joiner checks the tree against the tree hash in
the Welcome's group context [RFC9420], so the server cannot change it.
The server holds these trees anyway, so keeping them a while longer
tells it nothing new.

The server never holds a group's secrets, so it can still
accept a commit that members' devices reject (12.7), for example one
whose path secrets do not decrypt, or whose `next` is wrong. Those
devices then recover the room with a resync commit, and check before
they take its state that the server has not changed the room's roles or
settings on the way (12.7, "Resyncing a public room").

**Light clients.** A full tree of 30,000 leaves is close to 200 MB, too
much for a phone to keep for each large room. In a public room, a device
MAY be a **light client** (a partial client in [MLS-PARTIAL]) that does
not hold the tree:

- It joins by external proposal (6.1), and fetches its Welcome with
  `WELCOME GET <ref> light=yes`. In the WELCOME line (12.8),
  `<welcome>` is then an AnnotatedWelcome, which the server builds from
  the Welcome and the tree of its epoch (above).
- It fetches with `FETCH <box> after=<position> leaf=<n>`, where `<n>`
  is its leaf index, in decimal. In the event line (5.2) of each commit
  that the server returns, `<message>` is then an AnnotatedCommit for
  that leaf, which the server builds from the commit and the trees it
  holds. Every other post comes as it is.
- Both are encoded with the TLS presentation language [RFC9420], and
  sent in base64 with padding, or as a blob-ref (12.12) if too large for
  a line.
- It checks the membership proofs in these, as [MLS-PARTIAL] requires,
  and gets roles and settings from the conversation extension it
  computes. It shows as members only the leaves for which it holds a
  membership proof, such as committers and senders of messages. It
  shows a list from MEMBERS (8.3) only as the server's word, since the
  server could leave a leaf out of it, its own included.
- It cannot commit. It replaces its leaf node with Update proposals,
  each period it sends in as 12.10 says, and at least weekly (12.7).

The structures are those of draft-ietf-mls-partial-02 [MLS-PARTIAL],
Sections 6 to 10, where `Node`, `Welcome` and `MLSMessage` are as in
[RFC9420]. Risala follows that draft's version, and will follow a later
one only with a new protocol version:

```
struct {
    opaque hash_value<V>;
} CopathHash;

struct {
    uint32 leaf_index;
    uint32 n_leaves;
    optional<Node> direct_path_nodes<V>;
    CopathHash copath_hashes<V>;
} MembershipProof;

struct {
    T message;
    MembershipProof sender_membership_proof;
} SenderAuthenticatedMessage<T>;

struct {
    SenderAuthenticatedMessage<Welcome> welcome;
    MembershipProof joiner_membership_proof;
} AnnotatedWelcome;

struct {
    MLSMessage commit;
    optional<MembershipProof> sender_membership_proof;
    opaque tree_hash_after<V>;
    optional<uint32> resolution_index;
    MembershipProof sender_membership_proof_after;
    MembershipProof receiver_membership_proof_after;
} AnnotatedCommit;
```

A light client tells the server its leaf index, which the server can
tie to its identity in a public room. So it MUST fetch with `leaf` on an
anonymous connection that it uses for nothing else, and post on others
(4.1).

### 12.7. Membership

Devices check every change to a group themselves, besides what MLS
requires. They never take membership, roles or settings from the
server.

**Joining.** When a device joins a group, by Welcome (12.8) or by
external commit, it checks the whole group, and MUST NOT join one that
fails:

- The conversation extension is well formed (12.4), its `host` names
  the server the device is joining on, written as 12.4 says, and, for
  a public room it joins by name, it names that room and its box.
- Every leaf's credential is a RisalaIdentity, and every leaf of an
  identity carries a profile (12.3).
- In a direct conversation, every leaf belongs to one of the two
  participants named in the extension, one of whom is the device's own
  identity, or in a conversation with yourself, to you.
- No leaf's credential names a banned identity. Guest leaves appear only
  in a public room whose `guests` is not `none`, and in a guest's report
  conversation (below).
- Outside public rooms, no two leaves have the same uid and `device_id`.
- The group is within its size limits (6.1).

Leaves that the device cannot confirm yet are allowed: they stay
unverified until it does (12.10). A device ignores a Welcome from a
group in which someone the user has blocked has a leaf (5.7).

Outside public rooms, a device that joins by Welcome then checks every
leaf of another device already in the group: that its device is a
current device (4.4) of the credential's identity, whose record the
device has accepted (4.5), and which it has never seen removed by
record. It cannot check the leaf's device binding, which covers the
init key of the KeyPackage the leaf came from (12.3), since the tree
no longer holds that key. The members present when the leaf was added
checked its binding (below), and confirmation (12.10) catches the
rest. The device sends no messages in the group until each leaf
passes, and one that fails it repairs as an add that failed (below).
Otherwise a leaf planted before the device joined would be checked
only when it sends (12.10).

**A guest's report conversation** (5.8) is a direct conversation whose
participants are a guest uid and an identity. The guest's device
creates it, with its throwaway leaf as the only leaf of the guest, and
adds the identity's devices. A device of the identity joins it only if
the user accepts it, and only if its identity is an owner or moderator
of a public room on that server whose `guests` is not `none`. In it:

- the guest has exactly one leaf, which never changes its credential
  and is never confirmed, since a guest has no attestation key (12.10);
- the guest's leaf adds devices only while it is the only leaf in the
  group, that is, in the commit that adds the identity's devices:
  devices treat any other Add by it as invalid;
- devices act only on REPORT lines from the guest's leaf, and ignore
  every other content line it sends (5.8).

**Commits.** A device makes two kinds of check on each commit, as of
the epoch the commit is for:

- **Group checks** decide whether the commit is valid. They depend only
  on the group's state in that epoch, on the commit, and on the posts
  that carry the commit and the proposals it applies by reference, with
  their `t` and the commit's `next` (5.2). The group's state is what
  every member of the epoch holds, including one that has just joined
  it by Welcome or by external commit: the ratchet tree, with each
  leaf's credential, profile, lifetime and `leaf_node_source`
  [RFC9420]; the group context, with the conversation extension; and
  which leaf made the commit that started the epoch, which is the
  signer of the GroupInfo that a joiner joins with. Group checks MUST
  NOT depend on anything else: not on earlier epochs, on other posts,
  on key files or on the device's clock. So every device that has
  applied the same posts reaches the same answer, whenever it joined
  and however late it looks. A commit that fails one is invalid, and
  the device ignores it (7.2).
- **Key checks** use key files and the key log (4.4, 4.5), which devices
  fetch at different times, and which may answer differently for a
  while. They never make a commit invalid. A device applies a commit
  that passes the group checks, whatever its key checks say, and
  repairs afterwards (below), so that devices never split over what
  they have fetched.

Every time window of the group checks therefore runs on the server's
`t`, which a server could set to suit a member (Section 14). Devices
SHOULD warn their user when the `t` of a commit that reaches them as it
is posted (5.2) differs from their own clock by more than an hour.

A device MUST run the group checks on its own commit before it posts
it, as every other member will, and MUST NOT post one that fails. Since
its post's `t` is not known yet, it checks time windows against its own
clock at the time it posts, and KeyPackage lifetimes with the hour
taken inward (12.5). A commit rebuilt later, for example after another
commit won the epoch, is checked again.

Below, an identity **has a leaf** if the group keeps a leaf of it after
the commit, and n is the number of leaves before the commit. The group
checks:

- **MLS.** The commit is valid MLS [RFC9420], and the device can process
  it: its path secrets decrypt, and its confirmation tag is right (but
  see "Commits a device cannot process", below).
- **Next token.** `next` (5.2) is the hash of the send token of the
  epoch that the commit creates (12.6).
- **Adds.** Each added KeyPackage is valid MLS, with a lifetime that is
  acceptable at the post's `t` (12.5), and its leaf's profile has a
  `streak` of 0 and an `updated` no more than 10 minutes after the
  post's `t` (12.3). Outside public rooms, its leaf node has a device
  binding whose `device_id` and uid are those of its credential (12.3).
  In a public room it has none. Who may add:
  - outside public rooms, a device of the committer's own identity, by
    anyone in the group;
  - in a direct conversation, a device of either participant, and of
    nobody else;
  - in a private room, a device of an identity that has a leaf, by any
    member;
  - outside public rooms, a device whose stale leaf (below) the same
    commit removes, by any member;
  - in a private room, a device of any other identity, by an owner or
    moderator only (an invitation), and of an identity listed in
    `owners` or `mods`, by an owner only;
  - in a public room, only the leaf of an external Add proposal (6.1),
    by reference, by any member whose leaf is an identity's;
  - never a leaf whose credential names a banned identity, nor, in a
    public room whose `guests` is `none`, a guest's.

  Whichever of these rules allows it, in a private room, a device of an
  identity listed in `owners`, before or after the commit, is added only
  in a commit by a leaf of that identity or of an owner, and a device of
  an identity listed in `mods` only by a leaf of that identity, of an
  owner or of a moderator. Whoever adds a leaf may hold it (below), so
  no Add hands anyone control of a leaf with a role above its own.
- **One leaf per device.** Outside public rooms, no two leaves of the
  group have the same uid and `device_id` after the commit. In a public
  room they may, until one is removed as a copy (below).
- **Removes.** Each removed leaf is:
  - a leaf of the committer's own identity;
  - in a room, a leaf of an identity that the committer may kick or ban
    (6.3, 6.4);
  - a leaf whose SelfRemove the commit applies (6.1);
  - a guest leaf;
  - a **stale** leaf (below);
  - in a resync commit, the leaf that made the commit that started the
    epoch (below);
  - outside public rooms, a leaf of another identity, removed **for a
    check** that the group cannot make: a key check (below), including
    that its identity is forked or has its keys missing (12.14), a leaf
    found to be an impostor (below), or a device that posted RESYNC
    (below). A commit removes for a check the leaves of **one**
    identity at most. Every such reason concerns one identity's leaves,
    and the limit keeps any one member from emptying a group in a
    single commit. In a room, a leaf of an identity listed in `owners`
    is removed for a check only in a commit by a leaf of that identity
    or of an owner, and a leaf of an identity listed in `mods` only by a
    leaf of that identity, of an owner or of a moderator, as of the
    epoch the commit is for. So no member can take out, by a claim that
    nobody can check, those who could add it back (6.3);
  - in a public room, a **copy**: a leaf with the same uid and
    `device_id` as another leaf that has committed or been Updated since
    it was added (its `leaf_node_source` is `commit` or `update`), and
    whose `updated` is lower than that other leaf's. In a public room,
    only the device that a credential names can commit or propose an
    Update of an identity's leaf (12.6), so a copy of someone's
    credential never pushes their leaf out, while a device that joins
    again has its old leaf removed once its new one has committed or
    been Updated;
  - in a public room, a leaf that has neither committed nor been Updated
    since it was added (its `leaf_node_source` is `key_package`): by an
    owner or moderator, whatever its uid, without kicking that uid; and
    by any member, once the leaf's `updated` is more than 8 days before
    the post's `t`. Devices commit or propose an Update at least weekly
    (below), so this removes only joins that nobody uses, such as leaves
    whose credential names a device that does not hold them.
- **Bulk.** In a commit by a member that is not an owner or moderator,
  the stale leaves, guest leaves, copies and leaves that have never
  committed that it removes, other than leaves of its own identity,
  number at most max(1, floor(n/10)) together.
- **Extensions.** A GroupContextExtensions proposal changes only the
  fields of the conversation extension that the committer may change
  (6.2, 6.3), and the other extension is unchanged. A commit that adds a
  uid to `bans` also takes it out of `owners` and `mods` (6.4), and the
  extension it leaves is well formed (12.4), which caps `bans` at
  10,000 uids and allows no uid twice in a list. In a
  direct conversation or a private room, any member may instead change
  `box` alone, to move the mailbox, in a commit with no other proposal,
  and the new `box` is the one that 7.8 derives from the epoch the
  commit is made in.
- **Leaves.** The commit's path keeps the committer's credential, and
  brings a new signature key only as 12.3 allows. The committer's new
  `updated` and `streak` are as 12.3 requires.
- **Updates.** Each Update proposal it commits is in an epochal group,
  keeps its sender's credential, brings a new signature key only as
  12.3 allows, and has a `streak` of 0 and an `updated` as 12.3
  requires, against the `t` of the post that carried the proposal.
- **Streaks.** Outside the conversation with yourself, a commit whose
  `streak` is more than 3, so that leaves of the committer's identity
  have started each of the last 3 epochs, is invalid, unless its only
  proposals remove leaves of the committer's own identity, or its new
  `updated` is at least 10 minutes after the highest `updated` among the
  leaves of its identity that have committed or been Updated. Since
  `updated` stays within 10 minutes of the server's `t`, no identity can
  win every epoch: after three commits in a row, its devices between
  them can commit about once every 10 minutes, and others have that
  long to commit first.
- **External commits** appear only in public rooms, by a leaf whose
  credential names an identity, and add only the committer's own leaf.
  Each is one of:
  - a **resync commit** (below), by an identity that had a leaf in the
    group before it: it removes the leaf that made the commit that
    started the epoch, which signed the GroupInfo, and nothing else;
  - a **rejoin** (below), by an identity listed in `owners` or `mods`:
    it removes at most one leaf, of its own identity.

  An external commit removes at most one leaf, as Section 12.4.3.2 of
  [RFC9420] allows. That section lets it remove only the joiner's own
  earlier leaf; a resync commit removes another identity's instead,
  which departs from [RFC9420], and the checks above bound what it may
  remove.

  An external commit cannot be a blob (12.12), so a device uses one
  only if it fits in a line with its GroupInfo (2.3). Its path is
  encrypted to every node in the resolution of the joiner's copath,
  and each takes an HPKE ciphertext of 1,188 bytes, so a line of 1 MiB
  holds about 620 of them: a tree with many blank nodes there, after
  many removals, can need far more, up to 39 MB in the largest public
  room. A device whose external commit would not fit does not post it.
  Instead, it joins the room again by external proposal (6.1), and an
  owner or moderator waits for its proposal to be committed. Outside
  public rooms, a device that cannot follow a group never uses an
  external commit: it sends RESYNC to its own devices (below).
- **Size.** The group stays within the limits of 6.1. A direct
  conversation holds at most 128 leaves, one for each current device of
  its participants, which have at most 64 each (4.4). In a private room,
  a commit after which more than 256 identities have leaves sets
  `confirm` to `epochal`, unless it is already (6.2).

A device that sees a commit by a leaf of its own identity that removes
another leaf of its identity, whose device is still current, without
adding that device again in the same commit, tells the user, as for
ALERT (4.5): it may be a stolen device racing its own removal (4.8).
This holds for a leave commit too (6.1), which removes every other leaf
of the identity. A removed device cannot tell a leave from a theft, so
it words the alert for both, for example: "your device X left C and
removed this device; if that wasn't you, it may be stolen".

**Key checks.** Outside public rooms, after it applies a commit, a
device checks:

- **Adds.** Each added leaf's device binding verifies under the device
  key of a current device (4.4) of the credential's identity, whose
  record the device has accepted (4.5), and which it has never seen
  removed by record.
- **Committer.** The committer's device has not been removed by record
  (4.4) in its identity's chain, as far as the device has accepted it.
  A device MUST NOT show a message, or act on a line, from a leaf of a
  device removed by record (12.9).
- **Removals for a check.** A commit does not say why it removed a leaf
  for a check, so for each such leaf the device looks for a reason that
  it can see: the leaf's device has been removed by record (4.4), its
  identity's chain ends with a `retire` record (4.9), its device binding
  does not verify, its identity is forked or has its keys missing
  (12.14), or a record of its device was still pending for the device 2
  hours after it first needed it, or the device had to wait for it
  before accepting it, so that another device may have given up on it
  after 2 hours (below); the leaf posted RESYNC; or the leaf is an
  impostor to the device itself (below). If it finds none, it cannot
  tell whether another device saw a fork, missing keys, a late record or
  an impostor that it does not, since what one device sees of a key file
  or a log another may not. The removal then stands, as one it could not
  check, and the device warns its user that it disagrees with the
  removal, naming the member who made the commit. Only for a leaf of its
  own identity does a device know: if that leaf's device is still
  current, and the identity is neither forked nor missing its keys, the
  removal failed.

Public rooms have no key checks, since their leaves carry no device
binding: attestation does that work there (12.10).

A device that cannot make a key check yet, because it cannot fetch a
key file now (4.4), or because a record the check needs is still
pending (4.5), has not failed it. It applies the commit, and checks
again from time to time. Every fact these checks rely on, such as a
record in a log, stays true once it is true, so devices that fetch later
reach the same answer. But a record that is still pending 2 hours after
the device first needed it counts as failed: a log must witness a record
within an hour (4.5), and otherwise whoever controls a log could keep a
group waiting for ever. An outage (4.4) never fails a check, however
long it lasts: anyone on the network path can cause one, and a check
that failed for it would let them have honest leaves removed. Until a
check passes or fails:

- **A removal it could not check** stands, and the device warns the user
  that a leaf was removed for a reason it could not check. Removing a
  leaf never lets anyone new read.
- **A leaf added by a commit it could not check** is unconfirmed, and
  the device sends no messages in the group while it is, since that
  leaf would read it.
- **A committer it could not check** counts as checked as far as the
  records the device has accepted go: the device acts on its commits
  and lines unless one of those records removed its device.
- **During an outage,** the device warns its user once a check has
  waited 2 hours, and removes nothing for it.

When a key check fails, the device warns the user, and, after a random
wait of up to 10 minutes, unless another device has done so first,
repairs it in a commit:

- **An add failed:** it removes the leaf, for a check. If the record
  that it waited for is accepted later, the device is added again
  (below), since the facts only ever move towards a check that passes.
- **A removal failed,** of a leaf of its own identity: it adds the
  removed devices that are still current again, from new KeyPackages
  (12.5), as its own identity's. A removal of another identity's leaves
  that it could not check stands. If that identity has no leaf left in
  a room, the devices of owners and moderators SHOULD offer their users
  to add its devices again (6.1), as far as the Adds checks let them,
  once its keys are present and no fork is known (12.14). Nobody else
  can: in a private room, an identity with no leaf left comes back only
  by such an Add, and an identity listed in `owners` only by an
  owner's (6.3).
- **The committer's device had been removed by record:** it removes the
  committer's leaf as an impostor (below).

A device makes a repair only where the group checks let it. Where they
do not, as for a plain member's device and a leaf of an owner, it warns
its user, hides what the leaf sends, as for an identity it cannot check
(12.14), and keeps sending; the leaf's own identity, or an owner or
moderator as the Removes checks allow, makes the repair.

Repairs, and removals of leaves removed by record or for a check, go
before any other commit the device has queued for the group, and the
device never holds them back, for a key check or anything else: a
removal never lets anyone new read. A commit it was holding back it
builds again after them, and checks again (above).

**Leaves that use authority.** Whoever adds a device builds its leaf
from the device's KeyPackage, and the device binding does not cover the
leaf's signature key (12.3). So a member who adds a device can give its
leaf a signature key of its own, and then act as that device, with the
role of its identity, until devices confirm the leaf (12.10). Devices
therefore check every leaf that uses authority:

- A device challenges (12.10), at once, every new leaf of its own
  identity, in every pairwise group, and every leaf that it has not
  confirmed and that makes an **authority commit**: a commit that only a
  role allows (6.3), that removes leaves of the committer's own identity
  other than its own, or that removes leaves of another identity for a
  check: outside public rooms, any removal of another identity's leaf
  that the committer's role does not allow, other than of a stale or
  guest leaf. It does the same for a leaf that sends a line that only a
  role allows, such as a DELETE of someone else's message (5.4). In an
  epochal group, where there is no challenge, the leaf's device sends
  ATTEST (12.10), in a message of its own if it has nothing else to
  send, within an hour of each authority commit it makes in a period for
  which it has not attested yet. There, a device expects a valid ATTEST
  in the first message of each new leaf of its own identity.
- A leaf that answers wrongly, or not within an hour, or a new leaf of
  the device's own identity that sends in an epochal group without a
  valid ATTEST, is an **impostor** to that device. The device shows that
  leaf's messages and actions as unconfirmed, and warns the user, with
  what the leaf's commits changed. After a random wait of up to 10
  minutes, unless another device has done so first, it removes the leaf,
  for a check (above). Any member may do this, whatever its role, except
  that in a room only those whom the Removes checks name remove a leaf
  of an owner or a moderator: removing a leaf never lets anyone new
  read. The leaf's own identity adds its device again if it still has a
  leaf in the group; otherwise, in a private room, only an owner or
  moderator can (above). A leaf whose device has been removed by record
  (above) is removed the same way.
- Removing an impostor does not undo what it did. That takes ordinary
  commits, which need the role that each change needs now (6.3): that
  of the impostor's own identity, whose devices hold the role that the
  impostor used unless its commits took it away, or that of the room's
  other owners and moderators. Such a device SHOULD offer its user to
  undo, in one commit, what the impostor's commits changed in the 24
  hours before it was found out, as far as its role allows: to put back
  fields of the conversation extension, and to add again, from new
  KeyPackages, the devices whose leaves those commits removed. The
  group judges that commit like any other, so a member without the role
  cannot undo an owner's moderation by calling the owner an impostor.
- A device that sees a leaf that it has confirmed removed for a check,
  with no reason that it can see (above), tells the user, and names the
  member who made the commit, since the removal may then itself be
  abuse, or a disagreement over what each device has fetched. The
  removed leaf's own identity adds its device again, where the Adds
  checks let it (below).
- A device that is welcomed to a group in which no leaf has the
  signature key of the KeyPackage it was added from does not join. It
  tells the user that someone may have added the device with a key of
  their own.
- Public rooms have no removals for a check. Only the device that a
  credential names commits there (12.6), so a leaf can use authority in
  another's name only with the server's help or from a stolen device.
  Owners and moderators remove such a leaf within their roles, and the
  identity's own devices as one of their own. The server alone checks
  who commits as whom there, so a server can commit in an owner's name,
  and devices apply what it commits (Section 14). For the room's
  content, they SHOULD keep the roles they had before such a leaf's
  commits ("Commits in another's name", below).

In a private room, only an owner, or the identity's own devices, add a
device of an identity listed in `owners`, and only those or a moderator
a device of one listed in `mods` (above), so that no Add hands anyone
control of a leaf with a role above its own. Until a device has
confirmed a leaf, that leaf may still be held by whoever added it, with
the role of the leaf's identity, for up to an hour after it first uses
that role (Section 14).

**Commits a device cannot process.** A commit can fail MLS for some
devices only: its committer may, for example, encrypt its path secrets
so that they decrypt for every member but a few. Such a commit is
invalid for those devices, which then cannot follow the group: they see
posts of the epoch it created that they cannot decrypt. In a public
room they recover as "Resyncing a public room" says (below). In a direct
conversation or a private room:

- Such a device posts `RESYNC <seq>` (12.9) in the epoch it holds, at
  once, where `<seq>` is the seq of the commit it could not process.
  The others can still decrypt it for a while (12.9, "Late messages").
  If nobody acts on it within an hour, the device sends
  `RESYNC <box> <seq>` in the conversation with itself instead.
- A device of the same identity that reads a RESYNC, after a random wait
  of up to 10 minutes and unless another has done so first, commits the
  removal of that leaf together with an Add of the same device from a
  new KeyPackage (12.5), as its own identity's. If the identity has no
  other leaf in the group, the other participant's device does the same
  in a direct conversation, and an owner's or moderator's in a room,
  removing the leaf for a check (above), as far as the Removes and Adds
  checks let it: only an owner's for an owner's device. Other members
  only warn their users: a plain member who could replace another
  identity's leaf could also hold the new one (above). The device then
  gets a Welcome, and asks its own devices for what it missed (12.13).
- Devices tell the user when one member's commits keep leading to RESYNC
  lines from others: that member may be cutting devices out on purpose.

**Devices that found a gap.** A device that finds that posts after its
sync point expired before it applied them can no longer follow the group
either (7.4, 7.5). Outside public rooms, it sends `RESYNC <box> <seq>`
in the conversation with itself at once, where `<seq>` is the first seq
it found after the gap, or the head if every post up to the head had
expired (12.9). A device of the same identity that reads it replaces
that leaf as above, after a random wait of up to 10 minutes and unless
another has done so first, without waiting for the leaf to go stale
(below). Only the identity's own devices read that line, so a leaf whose
identity has no other leaf in the group is replaced only once it is
stale. A device that cannot follow the conversation with itself cannot
send the line at all, and its own devices replace its leaves there and
elsewhere as stale ones.

The server orders the posts, so it can also show different devices
different commits for the same epoch, and split the group with no
member's help (7.2). A device that, an hour after it applied a commit,
still sees new posts in that commit's epoch number that it cannot
decrypt warns the user that the group may have split (Section 14).

**Resyncing a public room.** When the server has accepted a commit in a
public room that devices cannot apply, because it fails a group check or
MLS, the room cannot go on from the epoch they hold, and the server takes
no other commit for the next. Devices recover with one external commit,
then in batches:

1. After a random wait of up to 10 minutes, unless another device has
   done so first, a full client of an identity that has a leaf in the
   room makes a **resync commit**: an external commit against the
   GroupInfo the server holds, after the comparison that "Rejoining a
   public room" requires (below). It removes the leaf that made the
   commit the devices could not apply, which is the GroupInfo's signer,
   and nothing else: an external commit removes at most one leaf
   (above). The device removes its own earlier leaf in its next commit,
   as in step 3. A resync commit that would not fit in a line (above)
   is not posted, and the device joins again as in step 2. Every
   device's resync commit would be about as large, so the room then goes
   on only if a full client that could apply the commit commits the join
   proposals. Devices whose proposals no commit has applied within 30
   minutes tell their users that the room could not be resynced.
2. Every other device that cannot follow joins again by external
   proposal, as for a first join (6.1). Full clients commit these
   proposals as 6.1 says, at most 256 devices in a commit.
3. A device that joined again removes its earlier leaf: a full client in
   its next commit, as a leaf of its own identity, and a light client by
   proposing an Update of its new leaf (12.10), after which full clients
   remove the earlier one as a copy (above). Until then, the device has
   two leaves. Leaves of devices that never come back are removed once
   they are stale (below).

This costs one external commit and a few batched commits, rather than an
external commit from every device in the room, each racing the others
for the next epoch. Devices tell their users which leaf made the commit
they could not apply. The server took that commit only from the device
its credential names (12.6), so an owner or moderator can ban that
identity, and the server then refuses its commits (6.4).

A resync commit removes one leaf of another identity, and the group
checks it like any other commit, so it gives its maker no hold over the
room. But nothing shows whether any device needed it. So a device that
applied without trouble the commit that a resync commit undoes shows the
resync to its user as possible abuse, and names the identity that made
it, so that owners and moderators can ban it.

**Owners and moderators rejoining.** Only full clients in the group
commit join proposals, so a room whose only full client online is
hostile could keep everyone else out. An owner or moderator whose join
proposal no commit has applied within 30 minutes MAY join again by an
external commit instead, a **rejoin**, which adds only its own leaf and
may remove one earlier leaf of its identity (above); it removes any
other in its next commit. The server checks the
role in the conversation extension it holds, and that the commit comes
from the device that its credential names (12.6). The owner or
moderator can then commit the waiting proposals, and ban whoever kept
them out. A rejoin that would not fit in a line (above) is not posted:
the owner or moderator keeps waiting for its proposal, and its device
tells the user why.

**Rejoining a public room.** For each public room it is in, a device
keeps the conversation extension of the newest epoch that it applied
and checked itself. When it finds that the server accepted a commit
that the device holds invalid, it MUST tell the user that the server
accepted an invalid commit in that room. Before it joins the room
again, by a resync commit, a rejoin, or a Welcome after a resync
(above), it
compares the extension of the GroupInfo it would join with the one it
kept:

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

**Commits in another's name.** In a public room, only the server checks
that a commit or Update comes from the device its credential names
(12.6), and the group checks do not depend on attestation. So a server
can join, commit and Update under a credential that names an owner's
device, and every device applies what it commits. A device SHOULD
treat what such a leaf does as it treats a change by the server above.
Once a leaf that made an authority commit is an impostor to it, having
sent no valid ATTEST within the hour (above), the device keeps, for the
room's content, the roles it held before that leaf's first authority
commit: an identity that gained `owner` or `mod` through the leaf's
commits counts as a plain member for `send mods`, for deleting others'
messages and for how the device shows it, and a ban that those commits
made hides nobody. It shows the user what those commits changed. This
is display only: commits it still judges by the group, so devices never
split over it.

A device that joins a public room for the first time has nothing to
compare with, and takes the roles that the GroupInfo shows (Section
14).

**Adding devices.** Every device of an identity that is current, whose
record has been accepted (4.5), and that has no leaf in one of the
identity's groups outside public rooms gets added:

- A device of the same identity adds it as soon as it has accepted its
  record, which is usually within a minute of pairing (4.5, 4.8), not
  before: members who cannot yet accept the record would see a leaf
  they cannot check, and stop sending.
- Otherwise, any member's device that finds it, when it checks key
  files (12.14), and that the Adds checks let add it (above), adds it
  after a random wait of up to an hour, unless someone has done so
  first. In a direct conversation that is either participant's device.
  In a private room, while the identity keeps a leaf there, it is any
  member's device for a plain member's devices, but only an owner's or
  the identity's own for an owner's, and also a moderator's for a
  moderator's; once the identity has no leaf left, only an owner's or a
  moderator's, as an invitation, and only an owner's for an identity
  listed in `owners`.
- A device that commits the removal of an identity's devices removed by
  record adds that identity's current devices without a leaf in the same
  commit, where the Adds checks let it. In a private room they do not
  let a plain member do so once the commit removes the identity's last
  leaf, since added leaves do not count as kept.

So a device that recovered an identity (4.8), or whose identity's
leaves were all removed for a check, gets back into its direct
conversations, where the other participant's devices add it, but into
a private room in which its identity has no leaf left only when an
owner or moderator adds it, and into one in which it was the only
owner not at all (4.8, 6.3, Section 14).

A device adds another identity's devices only from a key file that
extends the head it holds for that identity (4.5), never a device it has
once seen removed by record, and none while the identity is stale (4.5),
forked (4.5) or its keys are missing (4.4), or while the identity has a
SelfRemove in the group that no commit has applied yet (6.1). In a
public room, devices join by themselves (6.1), and nobody adds them.

A device MUST NOT add an identity whose key file it has never read. If
it cannot read it, for example during an outage (4.4), starting a direct
conversation with that identity or inviting it to a private room fails,
and the device tells its user to try again later; an Add it owes under
the rules above it tries again later by itself. During an outage, it
still adds devices of the chain it holds from an earlier read (4.4).

An identity that left a group (6.1) is not added back by these rules.
In a direct conversation, a participant who left never is: the
remaining participant's devices leave too, without a commit (6.1), and
show the conversation as left by the other participant. Talking again
starts a new direct conversation (5.1). In a private room, coming back
takes a new invitation (6.1). A participant whose leaves were removed
for a check, or replaced after a recovery (4.8), did not leave, and is
added back as above.

**Replacing stale leaves.** A device that has been offline for longer
than retention cannot catch up from the server (7.5). Its leaves are
replaced, so that it gets back in by Welcome. A leaf's **activity time**
is its `updated`, or, for a leaf that has neither committed nor been
Updated since it was added, the end of its KeyPackage's lifetime (12.5)
if that is later; but never later than the `t` of the commit's post.

- **By its own identity's devices, first.** Outside public rooms, a
  device MUST replace, by removing it and adding the same device again
  from a new KeyPackage, the leaf of another device of its own identity
  whose activity time is older than the server's retention period (8.5)
  plus one day, by the device's clock. The extra day leaves room for the
  weekly fresh-leaf commit (below) where retention is 7 days. It SHOULD
  do so as soon as it notices, in every group they share outside public
  rooms, starting with the conversation with yourself. Both are allowed
  for one's own leaves, and removing a leaf never lets anyone new read,
  so relying on INFO's retention here is safe. In a public room, the
  device that fell behind joins again by itself (6.1). A device that
  leaves locally therefore first removes the leaves of its identity's
  other devices (6.1), so that none of them replaces its own leaf, and
  so brings it back. One that leaves a group it can no longer follow
  cannot, and ignores such a Welcome instead (6.1).
- **By anyone, after 35 days.** A leaf is **stale** if its activity time
  is more than 35 days before the group's median activity time. The
  median is taken over every leaf that carries a profile, as the group
  was before the commit: sort their values, and take the one at
  position floor(n/2), counting from 0. No leaf counts as newer than the
  commit, so leaves added from long-lived KeyPackages cannot push the
  median into the future, a leaf just added is never stale, and every
  device computes the same value. Any member's device MAY remove stale
  leaves, within the bulk limit above. Outside public rooms, it MUST,
  in the same commit, add the same devices again from new KeyPackages,
  for each that KEYPKG GET returns one, and so it removes there only
  stale leaves that the Adds checks let it add again: a plain member's
  device leaves those of owners and moderators to their own identity's
  devices and to owners (and moderators, for moderators). In a public
  room nobody adds them: their devices join again by themselves
  (6.1).

A device that finds it has fallen behind (7.4) uploads fresh
KeyPackages, sends `RESYNC <box> <seq>` where it can (above), and waits
to be added again. Once it is back in the conversation with yourself,
it asks its identity's other devices for what it missed with WANT
lines, which they answer with transfers (12.13).

**Refreshing keys.** A device MUST commit a fresh leaf of its own, with
a commit that has no proposals, in each group where its leaf has not
been committed for a week, by itself or through an Update, the next time
it is online. In an epochal group it MAY propose an Update instead
(12.10), and a light client always does (12.6). After that, keys that
someone may have stolen from the device no longer decrypt new messages.

These rules mean that the server cannot, on its own, let anyone else
read a conversation. A direct conversation only ever holds the devices
of its two participants, every new identity in a private room is added
by an owner or moderator, every device added outside public rooms holds
a key that its identity bound to it, and every such key is checked
against the witnessed log. Anyone may join a public room. Section 14
covers the exceptions.

### 12.8. Welcome Messages

A device that a commit adds gets a Welcome, encrypted to its
KeyPackage.

```
WELCOME PUT <ref> <secret> <welcome>
WELCOME LIST
WELCOME DEL <id>
WELCOME GET <ref> [light=yes]
```

- **`WELCOME PUT`** hands the server a Welcome for the KeyPackage whose
  KeyPackageRef [RFC9420] is `<ref>`, 48 bytes in base64 with padding,
  and replies `OK`. It works on anonymous, guest and signed-in
  connections (Section 13). The server accepts it only for a KeyPackage
  that it handed out with KEYPKG GET, or that is in an external Add
  proposal in a public room (`ERR not-found`), and only from whoever
  added it (`ERR forbidden`):
  - For a KeyPackage from KEYPKG GET, `<secret>` is the put secret of
    that handout (12.5), which the server checks against its hash, in
    constant time. Other members see the KeyPackage inside the commit,
    but never its secret. The committer SHOULD send each such Welcome on
    a fresh anonymous connection (4.1).
  - For a KeyPackage of an external Add proposal, `<secret>` is `-`. The
    server accepts the Welcome only once it has accepted a commit that
    applies the proposal (12.6), and only on a signed-in connection of
    the device that made that commit, which it knows already. So someone
    who follows the room, and sees the proposal, cannot deliver a
    Welcome first.
  Each handout has at most one Welcome: for a last-resort KeyPackage,
  each KEYPKG GET is a handout of its own. A PUT for a handout that
  already has a Welcome, from whoever may put it, replaces that Welcome
  while it has not been fetched, so that a committer whose `OK` was lost
  can send it again. A server MUST limit how many Welcomes are pending
  for each device (`ERR rate-limited`).
- `<welcome>` is a SealedWelcome (below) for a KeyPackage handed out by
  KEYPKG GET, and the MLSMessage that holds the Welcome for one in an
  external Add proposal. Either is in base64 with padding, or a
  blob-ref (12.12) if it is too large for a line.
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
  proposal, as `WELCOME <id> <welcome> tree=<tree>`, then `OK`, or
  `ERR not-found` if there is none yet. `<tree>` is the ratchet tree of
  the Welcome's epoch, which the server keeps for it (12.6), in base64
  with padding or, for a large room, as a blob-ref (12.12). With
  `light=yes`, `<welcome>` is an AnnotatedWelcome (12.6), and the line
  has no `tree`. WELCOME GET works on anonymous, guest and signed-in
  connections, so that a device or guest that joined a public room
  anonymously can fetch it, on a connection of its own (4.1).

**One Welcome per device.** An MLS Welcome lists, in the clear, the
KeyPackageRef of every device it adds, and the part that every new
member decrypts is the same for all of them. Sent as it is, it would
tell the server exactly which devices were added together, and so who
shares a new direct conversation or private room. So for each device
added from a KeyPackage that KEYPKG GET handed out, the committer:

1. Makes a Welcome of its own, whose `secrets` holds only that device's
   entry.
2. Seals it to the device, so that no two devices' copies share any
   bytes: HPKE SealBase [RFC9180] with the cipher suite's HPKE (12.2),
   to the KeyPackage's `init_key`, with info `risala/1 welcome` and the
   KeyPackageRef as associated data. The plain text is the MLSMessage
   that holds the Welcome, followed by zero bytes up to the Padmé length
   (12.11) of the MLSMessage's length.

```
struct {
    uint8 version;               // 1
    opaque kem_output<V>;
    opaque ciphertext<V>;
} SealedWelcome;
```

The device opens it with its KeyPackage's init private key, checks that
the bytes after the MLSMessage are all zero, and hands the Welcome to
MLS. A sealed Welcome too large for a line is a blob of its own. In a
large private room each new device then has a copy of the tree to
itself, which costs the committer one upload of the tree per device.

Welcomes for external Add proposals in a public room, whose membership
the server knows anyway, are not sealed, so that the server can build
an AnnotatedWelcome from them (12.6). The committer makes one Welcome
for all the devices that its commit adds, without the `ratchet_tree`
extension, since the server holds the tree (12.6). It stores that
Welcome once as a blob if it is too large for a line (12.12), and puts
it under each added device's ref.

A committer MUST NOT send any Welcome for its commit before it has
fetched the posts before the commit and found that the commit won
(7.2): a Welcome for a commit that lost would put the new device in a
branch of the group that nobody else follows. It then sends each sealed
Welcome after a random wait of its own, of up to 10 minutes after its
commit's `OK`, chosen independently for each Welcome, so that the
server cannot easily tell by timing which devices were added together,
or tie them to the commit. In a direct conversation or a private room,
the Welcome's GroupInfo MUST carry the `ratchet_tree` extension, since
the server does not hold the tree.

A committer whose WELCOME PUT is refused, other than with
`ERR rate-limited`, cannot know who holds the device's place. It tells
its user, and, where the Adds checks let it (12.7), removes that leaf
and adds the device again from a new KeyPackage.

```
C: WELCOME PUT kq3V0X2l7r0o5yZ1TQm1bHk4Rk5r0Q2c8Jx7Vb9pL3dE6Gf1Ha2Ij4Kl5Mn6Op7Q Hc2vQ0mX4t9bLr7kWz1pYf8eNa3sJd6uGq5iTo2lVyE= AURgBA…
S: OK
```

On the new device's signed-in connection:

```
S: WELCOME 7f3k2m9q AURgBA…
C: WELCOME DEL 7f3k2m9q
S: OK
```

A device that joined a public room by proposal, on a connection of its
own:

```
C: WELCOME GET Vb9pL3dE6Gf1Ha2Ij4Kl5Mn6Op7Qkq3V0X2l7r0o5yZ1TQm1bHk4Rk5r0Q2c8Jx7
S: WELCOME 2hq8w5vn AAEAAwBA… tree=sha384:5d0c9a1e…
S: OK
```

The device checks the group as in 12.7, then joins it in the Welcome's
epoch. It follows the mailbox, fetches what the server keeps (7.4), and
applies the posts from that epoch on, ignoring those of earlier epochs.
It SHOULD NOT delete the Welcome, or the private keys of the KeyPackage
it was made for, before it has joined, so that it can try again if
joining is cut short, for example by a crash. It also deletes a Welcome
whose group fails the checks of 12.7. A device that, a day after it
joined, has seen no post in its epoch from any other leaf, while posts
of that epoch number or later ones arrive that it cannot decrypt, tells
the user that it may have joined a branch of the group that the others
do not follow, and uploads fresh KeyPackages so that it can be added
again (12.7). The server deletes Welcomes that
are not fetched within its retention period, and the pending Welcomes of
a device that has been removed.

**Nudges.** A device that has recovered its identity after losing every
device (4.8) has no leaf in any group, so it cannot send REFETCH (12.9).
Its contacts would otherwise learn of the recovery only at their daily
fetch (12.14), and until then the old devices, which may be in someone
else's hands, keep their leaves. So once it has accepted its records
(4.5), the device nudges, for each conversation of the backup it
restored (12.13), the identities other than its own that sent its three
most recent messages: in a direct conversation that is the other
participant, and in a room any one member who fetches removes the old
devices' leaves (12.14). It MAY also nudge identities its user names.
For each identity, on that conversation's server, it:

1. sends KEYPKG GET for the identity's uid (12.5);
2. for each KeyPackage handed out, after a random wait of its own of up
   to 10 minutes, sends WELCOME PUT with that KeyPackage's ref and put
   secret, and a KeyNudge as `<welcome>`, sealed as a Welcome is
   (above) but with the info `risala/1 nudge`.

It sends these on fresh anonymous connections (4.1), as a committer
sends Welcomes.

```
struct {
    uint8 version;               // 1
    opaque uid<V>;               // the recovered identity, in lower case
} KeyNudge;
```

The server cannot tell a nudge from a Welcome except by its size, and
handles it as one. A device that cannot open a sealed Welcome with the
info `risala/1 welcome` tries `risala/1 nudge`. If that opens it, the
KeyNudge's `version` is 1, `uid` is a uid (3.5) and the bytes after it
are all zero, it is a nudge; otherwise the device ignores it. Either
way, it deletes it with WELCOME DEL and treats the KeyPackage as used.
A nudge is not signed, and anyone can send one for any uid, so it gives
the device only a reason to fetch: for an identity it shares a direct
conversation or a private room with, it fetches the key file as 12.14
says, and then removes and adds leaves as after any fetch (12.7). It
ignores a nudge for any other uid, and shows the user nothing for a
nudge itself.

### 12.9. Messages

Everything a device posts carries, as the MLS `authenticated_data`, a
RisalaAAD. MLS leaves it in the clear for the server, and authenticates
it for members:

```
struct {
    uint8 version;               // 1
    opaque pseudonym<V>;         // 16 bytes in a PrivateMessage, empty in a PublicMessage (7.3)
    opaque frank<V>;             // 48 bytes in an application message, otherwise empty
} RisalaAAD;
```

The hash of the next epoch's send token travels outside MLS, as the
`next` option of POST (12.6).

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

A RisalaMessage's fields are fixed once it is written. If its post gets
`ERR stale` because a commit moved the group on, or the device must
post it again for another reason (7.6), it encrypts the same
RisalaMessage again under the keys of the group's current epoch, with a
new RisalaAAD, whose `frank` is the same. `counter` counts the messages
a leaf has written, not its posts, so a message sent again neither
leaves a gap nor counts twice, and receivers that get both copies show
it once (step 3 below).

MLS signs the message with the sender's leaf key, and encrypts it with a
key used only for this message, which every device deletes once it has
decrypted it. To receive a message, a device decrypts it with MLS, which
also checks its signature, and then:

1. Checks that the RisalaAAD's pseudonym is the sender's pseudonym for
   the message's epoch (7.3): the one derived from the epoch outside
   public rooms, and in a public room the one it pinned for the leaf in
   that period, or pins it.
2. Checks that HMAC-SHA-384(`frank_key`, `content`) equals `frank`,
   comparing in constant time. This check is what makes sure that a
   report can only reveal what was sent (5.8): ChaCha20-Poly1305 is not
   key-committing, so without it a sender could make a ciphertext that
   decrypts to other content under another key. It MUST NOT be
   skipped.
3. Checks that it has not already seen `message_id` in the group, so
   that the server cannot replay a message under a new seq. It keeps
   each `message_id` at least until it has deleted the secrets of the
   message's epoch (below), after which MLS could not decrypt a replay
   anyway. It also checks that a stored message has a `counter` of at
   least 1, and a live one (5.2) a `counter` of 0 and an empty
   `previous`.
4. Checks `counter` and `previous` against the leaf's earlier messages,
   and notes a gap (7.4). If it holds the leaf's message whose `counter`
   is one less, and `previous` is not that message's `message_id`, the
   sender or the server has shown devices different messages: it shows
   the message with a mark that the sender's history disagrees.
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
  seq has removed, even if the message is of an earlier epoch. The leaf
  is the one that sent the message in its epoch. A later commit may put
  another leaf at the same index, or remove that one too, so a device
  keeps every removal it may still need, not only the newest at each
  index: every removal made since the oldest past epoch whose secrets it
  still holds, and after a move (below), every one made in the old
  mailbox up to the move, for as long as it follows that mailbox. A
  removal in the new mailbox, which does not count for a post in the old
  one, never hides one that does.
- A line that depends on a role, such as a DELETE of someone else's
  message (5.4), or a TEXT line or typing in a room with `send mods`
  (6.2), counts only if its sender has the role both in the extension
  of the message's epoch and in that of the newest epoch the device has
  applied at the message's seq.
- A device decrypts a message of a past epoch e only if the newest
  epoch it has applied at the message's seq is at most e + 2, and the
  post's `t` is within an hour of the `t` of the commit that ended
  epoch e. It shows a later one as unreadable, and MUST delete a past
  epoch's secrets, with the keys it kept for skipped messages of that
  epoch, as soon as it has applied a stored post that puts the epoch
  past either limit. These rules depend only on the posts, so every
  device reaches the same result.
- Whatever posts arrive, a device MUST also delete a past epoch's
  secrets, with its skipped-message keys, 2 hours after it applied the
  commit that ended the epoch, by its own clock. Otherwise a group that
  goes quiet, or a server that holds back later posts, would keep them
  on the device. A late message that it can then no longer decrypt is
  unreadable, as above. This depends on when a device fetched, so it
  can make a message unreadable on one device and not on another, but
  it changes only what devices show, never which commit is valid
  (12.7). After a move, the old mailbox's last epochs are kept longer
  (below).
- Within an epoch, a device keeps the keys of skipped messages for at
  most 1,000 generations behind the newest it has seen from each
  sender, and rejects a message more than 1,000 generations ahead of
  it, or ahead of generation 0 if it has seen none from that sender.
  With the rules above, a device holds the secrets of at most 2 past
  epochs, and of none for more than 2 hours after it applied the commit
  that ended it, except for a day after a move (below).
- After a move (7.8), a post in the old mailbox that comes after the
  move has no place in the new mailbox's order. A device judges it by
  the old mailbox's order alone, as of the move: the commits that count
  above are those up to the move in the old mailbox, never those in the
  new one, whether it has applied them yet or not. So the rules that
  depend only on the posts give every device the same result, whichever
  mailbox it read first.
- For the same reason, a device keeps the secrets of the old mailbox's
  last epochs, with their skipped-message keys, for as long as it
  follows the old mailbox, a day after it applied the move (7.8), and
  deletes them when it stops, rather than 2 hours after the commits
  that ended them. These are the past epochs whose secrets it still
  holds when it applies the move: at most the 2 before the move's
  epoch, since the move's epoch is the newest that counts in the old
  mailbox. So whether a late post there can be read does not depend on
  when each device fetched it after the move. The limits above still
  apply to them, judged by the old mailbox's order alone: posts in the
  old mailbox can put them past a limit, and the device then deletes
  them at once, but commits in the new mailbox cannot. It holds these
  secrets besides those of at most 2 past epochs of the new mailbox.

The content is one or more lines in UTF-8, in the format of Section 3,
each ending in LF. The rules of 2.3 for characters apply to these lines,
but its length limits do not: TEXT has its own limit (5.3), and the
content as a whole is at most 4 MiB (4194304 bytes). Devices ignore
lines with verbs they do not know, and lines in a conversation where
the table does not allow them. Also:

- Content lines end in LF alone. Content that holds a CR, or any other
  character that 2.3 forbids, or that does not end in LF, is not valid
  content: the device treats the message as one it could not read.
- A line whose verb is known but which does not follow that verb's
  syntax is ignored, and the rest of the message stands.
- A live message (5.2) holds only a TYPING line, and a kept one never
  does. A device ignores any other line in a live message, and a TYPING
  line in a kept one.
- File tags go only on a TEXT line that is a new message or a reply,
  never on an edit or a reaction. A device ignores them there.

| Line | Where | Section |
|---|---|---|
| `[@<tags>] TEXT <text...>` | any conversation | 5.3 |
| `DELETE <id>` | any conversation | 5.4 |
| `TYPING` | any conversation, live | 8.1 |
| `@box=<box>;target=<id>[;context=<ids>] REPORT [<reason...>]` | a direct conversation with an owner or moderator of a room, never the conversation with yourself | 5.8 |
| `CHALLENGE <leaf> <ciphertext>`, `ANSWER <leaf> <mac>` | groups whose `confirm` is `pairwise` | 12.10 |
| `ATTEST <period> <period-key> <certificate> <attestation> <pseudonym>`, `REVEAL <period> <seed>` | groups whose `confirm` is `epochal` | 12.10 |
| `RESYNC <seq>` | direct conversations and private rooms | 12.7 |
| `REFETCH <hash>` | direct conversations and private rooms | 4.5, 12.14 |
| `READ <box> <seq> <check>`, `RESYNC <box> <seq>` | the conversation with yourself | 7.7, 12.7 |
| `BLOCK <target>`, `UNBLOCK <target>` | the conversation with yourself | 5.7 |
| `RECORD <hash>`, `ALERT <hash>`, `RECORDS [<hashes...>]` | the conversation with yourself | 4.5 |
| `SIGNINGKEY <seed>`, `BACKUPKEY <generation> <key>` | the conversation with yourself | 4.8, 12.13 |
| `WANT <box> <after> <before>`, `TRANSFER <ref>` | the conversation with yourself | 12.13 |
| `SERVERS <hosts...>` | the conversation with yourself | 12.13 |
| `PIN <uid> <master> <origin> <head> <verified>` | the conversation with yourself | 4.5, 12.14 |

A TEXT line may carry these tags:

- `reply`, `edit` and `react`, each with a `message_id` in base64 with
  padding (5.3).
- `file`, the file's `get` URL; `file-key`, the file key in base64 with
  padding; `file-type`, its media type, as `type/subtype` [RFC6838];
  `file-size`, its size in bytes before encryption; and `file-hash`, the
  SHA-384 hash of the exact bytes uploaded, in base64 with padding
  (12.11). A TEXT line that has `file` without both `file-key` and
  `file-hash`, or whose `file-key` is not 32 bytes or `file-hash` not 48
  bytes, is shown as a message with no file. File tags go only on a
  plain TEXT line or a reply, never with `edit` or `react`, where
  devices ignore them.

For example, a reply as it appears inside the encryption:

```
@reply=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12
```

In `RESYNC <seq>`, `<seq>` is the seq of the commit that the device
could not process (12.7), in decimal. In the conversation with yourself,
`RESYNC <box> <seq>` asks the identity's other devices to replace the
sending device's leaf in the group of that box. There `<seq>` is either
the seq of a commit that the device could not process, or, for a device
that found a gap (7.4), the first seq it found after the gap, or the
head (7.1) if every post up to it had expired. A device acts on it
only if it holds a group whose mailbox has that box, now or before a
move (7.8), and has applied the posts there up to that seq.

In `REFETCH <hash>`, `<hash>` is the SHA-384 hash of a record of the
sender's identity, as a blob-ref (3.5). A device sends it once it has
accepted a record that it made itself (4.5), in each direct
conversation and private room it is in, so that the other members fetch
its identity's key file within minutes rather than at their next daily
fetch (12.14). A device ignores REFETCH from a leaf of its own identity,
whose records reach it with RECORD.

The lines of the conversation with yourself:

- In READ, `<check>` is the first 8 bytes of the `epoch_authenticator`
  [RFC9420] of the epoch the device had applied at `<seq>`, in base64
  with padding. A device that had applied an epoch with a different
  authenticator at that seq warns the user that the group may have been
  split by the server (12.7), since its devices are then in different
  branches of it.
- In RECORD and ALERT, `<hash>` is a record's SHA-384 hash as a blob-ref
  (3.5).
- `RECORDS` without hashes asks the identity's other devices which
  records they know were announced (4.5). A device answers with
  `RECORDS` followed by the hashes, as blob-refs separated by spaces, of
  every record of the chain that it knows was announced with RECORD, or
  with `RECORDS -` if it knows of none.
- In SIGNINGKEY, `<seed>` is the new device-signing key's 32-byte seed,
  in base64 with padding. A device accepts it only if the seed derives
  the device-signing key of the newest `signing` or `master` record of
  the chain that it has accepted, and ignores it otherwise.
- In BACKUPKEY, `<key>` is a backup key (12.13), in base64 with padding.
  A device accepts it only if `<generation>` is the chain's generation
  (4.4).
- `SERVERS` lists the servers the identity uses, each as a server
  (3.5), separated by spaces, at least one and without repeats, its home
  first (12.13). A device that starts or stops using
  a server sends the new list. Every device keeps KeyPackages on each
  of them (12.5).
- `PIN` carries a pin (4.5) and the verified mark (12.14) of another
  identity: `<master>` is the SHA-384 hash of the pinned master key and
  `<head>` the hash of the head record, each as a blob-ref; `<origin>`
  is the pinned log's origin; and `<verified>` is `yes` or `no`. A
  device sends it when it pins an identity or a pin or mark changes,
  and for every identity it has pinned when a new device of its own
  identity joins the conversation with yourself. A device that receives
  it still checks the identity's records itself: it takes the master
  key and log as its pin if it has none, treats a different master key
  than its own pin as a new master key (12.14), and moves its head
  forward only to records it has accepted.

Devices accept the lines of the conversation with yourself only from
leaves of their own identity that they have confirmed (12.10). Every
leaf there reads SIGNINGKEY and BACKUPKEY, and a stolen device's leaf is
confirmed too. So a device sends them only while every leaf in that
conversation is confirmed, no leaf in it belongs to a device removed by
record (4.4) or to a device whose removal the sender is carrying out
(4.8), and the commits that removed such leaves have won (7.2). So in
that conversation, a device challenges every other leaf as soon as it
appears, whether or not it sends (12.10). If a leaf there has not
answered within 24 hours, the device tells the user, and removes it if
the user agrees, which it may, since the leaf is of its own identity.

### 12.10. Confirming Leaves

Leaf keys are not signed by anything the identity publishes (12.3). A
device **confirms** a leaf when it has made sure that the leaf belongs
to the device named in its credential, a current, logged device of that
identity (4.5). Until then the leaf is **unconfirmed**, and its messages
are shown as unverified. Once it is confirmed, so are its earlier
messages, since they were signed by the same leaf key, and its edits
and DELETEs that waited for it take effect (5.3, 5.4). Those of a leaf
found to be an impostor (12.7) never do.

Confirmation must convince the members of a group, and nobody else.
Signing the leaf key with the device key would convince anyone who sees
the signature, and so would prove who wrote every message the leaf
signed. Instead, the group's `confirm` field (12.4) picks one of two
ways. Direct conversations, and private rooms of up to 256 identities,
use `pairwise`. Public rooms, and private rooms that have grown past
256 identities, use `epochal`.

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
challenged and costs nothing. There are three exceptions, where a device
challenges a leaf at once, whether or not it sends: every leaf of the
conversation with yourself, where every line counts (12.9); every new
leaf of the device's own identity, in every pairwise group; and every
leaf that makes an authority commit (12.7). In an epochal group, where
there are no challenges, a device instead expects a valid ATTEST in the
first message of each new leaf of its own identity, and treats one that
sends without it as an impostor (12.7). Guest leaves have no attestation
key, and are never challenged or confirmed.

A device puts its pending CHALLENGE and ANSWER lines in its next message
in the group, or, if it sends none, in a message of their own, at a
random time within 10 minutes, so that more of them ride in ordinary
messages. A challenge for an authority commit, or in the conversation
with yourself, goes within a minute. The bookkeeping:

- B keeps at most one open challenge for each leaf it challenges, and
  records with it that leaf's signature key at the time it sent it. A
  new challenge to the same leaf replaces the old one.
- B drops the challenge if the leaf is removed, or its signature key
  changes, and checks an ANSWER from that leaf only against that one
  challenge, with the key it recorded.
- A answers only the newest challenge from each leaf, and ignores
  challenges whose `<a>` is not its own leaf.

The sender's messages show as unverified until its answer arrives.

This costs one extra flight. A CHALLENGE in a message of its own is
about 4.2 KB once signed, framed and padded, and an ANSWER rides with
others in one message. The first message from a new sender in a private
room of 256 members, about 770 devices, so brings each device about
3.2 MB of challenges, and the server sends about 2.5 GB in all, less as
more challenges ride in ordinary messages.

**Epochal.** In a large group, confirming every pair would cost too
much. Instead, devices confirm leaves with epochal signatures
[EPOCHAL]: keys that sign for a single day, and whose private halves are
published once the day is over. Until then, a leaf's attestation
convinces the members. Afterwards, anyone could have made it, so messages are
deniable once the key is out.

- **Periods.** A period is a UTC day, numbered from 1970-01-01 as 0:
  `period` = floor(ms since 1970-01-01T00:00:00Z / 86400000).
- **Period keys.** For each period in which it sends in an epochal
  group, a device has an ML-DSA-44 **period key**, and a certificate
  for it: RisalaSign(device key, "period", PeriodCert) (4.3). The
  certificate says only that the key is the device's for that period.
  The key is made from a 32-byte seed [FIPS204], and the seeds form a
  chain made in advance, for up to 90 periods at a time: the device
  picks the seed of the last period at random, and the seed of each
  period before it is `seed(p-1) = HKDF-Expand(HKDF-Extract("",
  seed(p)), "risala/1 period seed", 32)` [RFC5869] with SHA-384. So a
  REVEAL of one period's seed also reveals the seeds of every earlier
  period of its chain, and a device that missed a REVEAL makes up for
  it at its next one.
- **A new leaf key each period.** Before its first message of a period
  in an epochal group, the device replaces its leaf node with one that
  has a new signature key (12.3), and deletes the old key once that has
  taken effect. So no leaf key is used in more than one period. In a
  public room, it also picks a new pseudonym (7.3). Rotating limits what
  a revealed period key lets anyone forge. It does not keep the periods
  apart: in a public room, each Update is a PublicMessage, signed with
  the leaf's old key and carrying its new one, so anyone who follows the
  room can chain a leaf's keys from one period to the next, and an
  ATTEST that someone timestamped in one period ties the leaf to its
  device in every period (Section 14).
- **By Update.** The device does this with an Update proposal, posted
  on its own, which full clients in the group commit with others in
  batches: each waits a random time of up to 10 minutes after the
  oldest pending proposal, then commits them all, unless another commit
  has done so first (6.1). An Update proposal belongs to its epoch, so
  the device posts it again in each new epoch until a commit applies it.
  If none has after 30 minutes, a full client commits its fresh leaf
  itself. A light client only proposes. The device sends with its new
  key once the commit lands. So the members' rotations do not race each
  other for epochs at the start of each period.
- **When to rotate.** In a public room, the server sees whose Update or
  commit brings each new leaf key (12.6). One made just before the
  first post under a new pseudonym would tie the two. So a device that
  sent in the group in the period before proposes its new leaf at a
  random time in the first 12 hours of the period, whether or not it
  has anything to send yet, and not just before its first message. A
  device that has to send before then, or that did not send in the
  period before, rotates first, and the server may then link the
  rotation to its first post by timing (Section 14).
- **Attesting.** In its first message after its new leaf key takes
  effect, the device
  sends `ATTEST <period> <period-key> <certificate> <attestation>
  <pseudonym>`. `<period>` is in decimal, and the rest are the period
  key, the certificate's signature, RisalaSign(period key, "attest",
  AttestContent) and the leaf's pseudonym, each in base64 with padding.
  The pseudonym is the one in that message's RisalaAAD: in a public room
  the leaf's pseudonym for the period, and elsewhere the one derived for
  the message's epoch (7.3).
- **Revealing.** Once 3 hours have passed since the end of the period,
  the device sends `REVEAL <period> <seed>`, the period key's 32-byte seed
  in base64 with padding, in each group where it attested in that
  period, in its next message there or within a day. The 2 hours
  between the end of the grace hour and the earliest REVEAL cover the
  revealing and the checking device's clocks being off by up to an hour
  each (D.4).

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

An ATTEST line is **valid** if the certificate verifies under the
device key of the device in the leaf's credential, a current, logged
device of that identity (4.5); the attestation verifies under the
period key; `leaf_key_hash` is the leaf's; the `t` of the post that
carries it falls within the period or the grace hour after it; and the
device has not yet seen, in any group, a REVEAL by that device whose
seed derives that period's key, directly or through the chain of seeds,
since one period key serves all of a device's epochal groups.

A device confirms a leaf from a valid ATTEST line that the leaf sent if,
by the device's own clock as it processes the line, the period is the
current one, or the one before it within its grace hour. The leaf stays
confirmed only until that grace hour ends. A device that processes a
leaf's messages after that, for example because it was offline, shows
them as unverified: by then the period key may be out, and anyone could
have made the attestation.

**Public rooms.** A public room's leaves carry no device binding (12.3),
so anyone can join one with a credential that names any identity's
device. Only attestation shows whose a leaf is. So, in a public room:

- A device treats a leaf that has sent no valid ATTEST for the period of
  a message as it treats a guest (6.2): it shows the leaf's messages as
  an unverified guest's where `guests` is `write`, and ignores its TEXT
  lines where `guests` is `read` or `none`. It still counts as a member
  for commits, which do not depend on attestation (12.7).
- Bans hold against attested leaves. A device ignores the content lines
  of a leaf that attests as a device of a banned identity, and an owner
  or moderator's device removes it. Someone who is banned can join again
  only under a credential that never attests, and so only as a guest
  would.
- Owners' and moderators' devices SHOULD kick, ban, mute or report only
  leaves that they have confirmed, or whose commit they could not apply
  (12.7, "Resyncing a public room"), since an unconfirmed leaf's
  credential may name someone else. They MAY remove single leaves that
  have never committed or been Updated, whatever uid these name (12.7),
  which kicks and bans nobody, for example to clear joins that fill the
  room.

A device checks that a REVEAL's seed derives the period key that the
leaf attested with, directly or through the chain of seeds above, and
otherwise warns the user, since a device that does not reveal its keys
does not give the deniability the group expects.

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
- On an anonymous or guest connection, `box` and `token` are required,
  and are checked as for POST (5.2), so that only members of some group
  can store blobs. The blob counts against that mailbox's quota and the
  network address's limits (7.5). On a signed-in connection they are not
  needed, and the blob counts against the identity's limits. A device
  stores there only blobs that belong to the account, such as backups
  and history transfers (12.13), and never one that a post or a Welcome
  names (4.1).
- So a device that holds no send token the server can check cannot
  store a blob for a group: one that makes an external commit (12.7),
  which is not a member yet, and one that creates a public room (5.2),
  whose mailbox does not exist yet. An external commit with its
  GroupInfo, and a new public room's GroupInfo and tree, MUST fit in
  the line that carries them (2.3). A device makes an external commit
  only if it fits, and otherwise joins by proposal (12.7). A line that
  does not fit gets `ERR too-long`. The server refuses a blob-ref in their place with
  `ERR bad-syntax`: for `<groupinfo>` or `<tree>` in CREATE, and for
  `<message>` or `groupinfo` in a POST with the token `-`, which an
  external commit or an external proposal has (5.2).
- The client sends the blob in an HTTP PUT request to the `put` URL,
  which works for one upload within 10 minutes. The server MUST reject a
  body whose length differs from `<size>`, or whose SHA-384 hash differs
  from `<hash>`.
- `exists=yes` means the server already has the blob. Nothing needs to
  be uploaded.
- A blob larger than the server allows gets `ERR too-long`. A server
  MUST allow blobs of at least 256 MiB, which holds the tree of the
  largest public room.

```
C: BLOB sha384:5d0c9a1e… 2483211 box=ujzdegxdncf32epf3dhodzdoci token=3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE=
S: OK put=https://files.example.org/put/q8c2…
```

Anyone fetches a blob with an HTTP GET request to the `blobs` URL prefix
of INFO (8.5), followed by the 96 hex digits of its hash. The fetcher
MUST check the hash of what it gets before it uses it. Blobs expire
with retention (7.5), counted from the last BLOB command that named
them, except that the server keeps the tree of a public room's current
epoch for as long as it is current, and the blobs of an identity's
current backup for as long as it is current (12.13).

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

**The conversation with yourself.** An identity's devices share one
direct conversation of their own (5.1), on the identity's **home**
server: the first in its SERVERS list (12.9) and in the IdentityBundle's
`hosts` (4.8). They use it to keep each other up to date: the servers
they use, read markers (7.7), blocks (5.7), records they make (4.5),
pins (12.14), new device-signing keys (4.8), backup keys (below), and
requests for history and transfers (below), as lines inside the
encryption (12.9).

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
    opaque host<V>;              // the server, as a server (3.5)
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
  original `file-hash`. A device that reads, in the same transfer or
  backup, a TEXT line whose `file-hash` is listed fetches that blob,
  rather than the `file` URL, checks its hash against `blob_hash`, and
  decrypts and checks it as a file (12.11) under `key`. Nothing ties
  `blob_hash` to the original file, so the device uses an ArchivedFile
  only for the messages of the transfer or backup that lists it, which
  it shows as copied or restored (below), and shows such a file as
  copied or restored too. It never keeps the mapping for, or uses it
  on, a message it received itself. A device SHOULD reuse the same blob
  and key for the same file in later backups, so that it uploads each
  file once.
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
  and `made` as the first. An archive that does not, which only a faulty
  or dishonest device makes, since the server cannot read or forge an
  archive, makes the device reject the whole transfer or backup, and
  tell the user. The first archive may hold conversations and files of
  its own, or none.
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
  if the device does not know where the gap ends. A WANT whose range
  holds no seq, because `<before>` is at most `<after>` + 1, is ignored.
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
- It shows each message it applies, and each file of the transfer, as
  copied from the device that sent it, by that device's label, and the
  `verified` flag as that device's verification, never as its own.
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
  info, 32), where `info` is `risala/1 backup `, the uid, a space, and a
  **generation** number in decimal. The generation is the chain's
  (4.4), so no server can choose it: it starts at 0, and each `signing`
  record and each later `master` record moves to the next one. So
  removing a device, recovering an identity and changing the recovery
  key all move to the next generation (4.8), since the removed device
  knew the old key. The device that publishes the record that moves to
  a new generation MUST replace the current backup at once with one
  under it. Every device
  keeps the current generation's backup key, which it got at pairing or
  in a BACKUPKEY line, but never the recovery key.
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
  a `version` byte, `0x01`, and then the 48-byte hashes of every other
  blob of the backup, the archives in `more` and then the files in
  `files`, one after another without anything between them. It is
  needed only if there are any.
  - Every blob it names, directly or in the list, must still be stored
    on the server (`ERR not-found`). A list whose first byte is not
    `0x01`, or whose length is not 1 plus a multiple of 48 bytes, and a
    wrapped key whose first byte is not `0x01`, get `ERR invalid`. A
    wrapped key that is not 61 bytes long gets `ERR bad-syntax`, as any
    value of the wrong length does (3.7).
  - From then on, the server keeps every blob the backup names for as
    long as it is the current backup, whatever the retention period. It
    replaces the identity's previous backup, and deletes the blobs of
    that one that the new one does not name.
- **`BACKUP GET`** sends `BACKUP <generation> <hash> <key> [files=<list>]`,
  then `OK`, or `ERR not-found` if there is no backup.
- **`BACKUP DEL`** deletes the backup and its blobs, and replies `OK`.
- They need a signed-in connection. Backups belong to the identity, not
  to a device. A server MAY limit their total size (`ERR too-long`).

```
C: BACKUP PUT 2 sha384:5d0c9a1e… AdmS0r1xYc2L…
S: OK
C: BACKUP GET
S: BACKUP 2 sha384:5d0c9a1e… AdmS0r1xYc2L…
S: OK
```

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
   key's `version` is 1, unwraps it, and opens the archives. A backup
   made before the recovery key was changed (4.8) needs the old recovery
   key.
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
- It MUST fetch the key file again at least once a day for each
  identity it shares a direct conversation or a private room with, and
  for each sender in a public room whose leaf it has confirmed in the
  current period (12.10). It spreads these fetches over the day at
  random times, and checks the identity's freshness each time (4.5).
- It also fetches an identity's key file within minutes, rather than at
  its next daily fetch, when a leaf of that identity sends REFETCH (12.9)
  in a direct conversation or a private room, unless the device already
  holds the record that the line names, and when it gets a nudge (12.8)
  for an identity it shares a direct conversation or a private room
  with. It waits a random time of up to 5 minutes first, so that a
  room's members do not all fetch at once, then fetches without using a
  cached copy (4.4), and fetches each identity at most once every 10
  minutes for these reasons. Neither the line nor the nudge proves
  anything: a device takes from them only a reason to fetch, and acts
  only on what the key file says. Public rooms have no key checks
  (12.10), so REFETCH is not sent there, and their members catch up at
  their daily fetch.
- After a fetch, outside public rooms, it removes the leaves of devices
  removed by record, and adds devices that have none, where the Adds
  checks of 12.7 let it. In a public
  room, devices join by themselves (6.1), and their leaves carry no
  device binding to check (12.10). An outage changes nothing: the
  device goes on with the chain it holds, never fails a check for it,
  and never adds an identity whose key file it has never read (12.7).
- An identity other than the device's own whose keys are missing
  (4.4), or that is forked (4.5), is one the device cannot check. Until
  a valid key file is back, or the user resolves the fork, the device
  tells the user why, and:
  - in a direct conversation with the identity, sends no messages. It
    still makes commits, including those that remove or repair leaves;
  - in a room, treats the identity's leaves as unverified, hides what
    they send, showing that it hid a message from an identity it cannot
    check, and keeps sending;
  - in a room that is not public, removes the identity's leaves, for
    that key check (12.7), where the Removes checks let it: a leaf of an
    identity listed in `owners` only if the device's identity is an
    owner, and one listed in `mods` only if it is an owner or a
    moderator. Removing a leaf never lets anyone new read, and it keeps
    an identity that may be in someone else's hands from reading what
    the room sends next. The other devices only hide and warn, so a
    forked owner or moderator stays in the room, and reads it, until its
    own devices or an owner (or moderator) remove it. Once its keys are
    back and no fork is known, the identity's devices come back only as
    12.7's Adds allow: where it has no leaf left, by an owner's or
    moderator's Add, an owner's for an owner, which their devices offer
    their users (12.7), and never by a plain member's;
  - in a public room, which has no key checks, if its identity is an
    owner or moderator, SHOULD ban the uid of a forked identity (6.4),
    and MAY kick one whose keys are missing.

  So an identity that forks its own chain, or takes its key file down,
  stops only its own direct conversations, not the rooms it is in.
- If the device's own identity is forked or has its keys missing, the
  device keeps sending in the conversation with yourself (5.1): ALERT,
  RECORD and the other lines of 12.9 there, so that the identity's
  devices can act on it. SIGNINGKEY and BACKUPKEY stay limited as 12.9
  says. Other identities' devices treat it as above.
- These fetches tell the host of each key file and log which network
  addresses look up which identities, and how often (Section 14). A
  device SHOULD fetch whole entry bundles and tiles rather than single
  entries, so that a log learns less about which records it reads.
- Clients SHOULD show each identity's devices, and tell the user when one
  is added or removed. A new device under the same master key is a
  notice, not a warning. A device is shown by its label, the date of its
  record and a short id, the first 8 characters of its device id in
  lower-case base32 [RFC4648], since a label alone can imitate another
  device. Labels are compared and shown as display names are (8.2).

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
identity as **verified**. A device that has just met an identity cannot
tell whether the chain it was shown is the one the identity's owner
watches (4.3, Section 14), so users SHOULD compare safety numbers before
they trust a new direct conversation, and clients SHOULD suggest it.

Verifying a safety number vouches for the identity's master key. The
devices added under it are trusted on the strength of the key log and of
the owner's own devices watching it (4.5), and a new one is a notice.

- A **new master key** (4.5) clears "verified". In a direct
  conversation and in a private room, the device stops sending until the
  user acknowledges the new key. In a public room, it shows a warning.
  Once the user has acknowledged it, the device's head is the new chain,
  and it adds the new chain's devices to private rooms where the Adds
  checks of 12.7 let it. Section 14 says what this lets a member, or
  its domain's controller, do.
- A fork or a rollback (4.5) is treated as above, whether or not the
  identity was verified.
- The pins and verified marks of an identity's devices are kept in step
  with PIN lines (12.9), so that a new device does not meet its user's
  contacts afresh.

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
  every build, so that a library upgrade cannot change it unnoticed.
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
} RisalaProfile;
```

The display name is shown as 8.2 says. `updated` is set by the leaf's
device each time it commits its own leaf, from its clock, and lets
devices find leaves that have stopped keeping up (12.7). Every leaf of
an identity's device carries a profile.

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
devices each. A commit too large for a line travels as a blob (12.12).

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
   limits of 6.1, and that every key it adds is a current device of its
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
accept a commit that members' devices reject (12.7). Those devices then
join again (6.1).

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
  public room whose `guests` is not `none`.
- The group is within its size limits (6.1).

Leaves that the device cannot confirm yet are allowed: they stay
unverified until it does (12.10). A device ignores a Welcome from a
group in which someone the user has blocked has a leaf (5.7).

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
  - a leaf whose profile's `updated` is more than 35 days older than the
    `updated` of the committer's own new leaf (below);
  - or, in an external commit, the joiner's own earlier leaf, with the
    same `device_id`.
- **Extensions.** A GroupContextExtensions proposal changes only the
  fields of the conversation extension that the committer may change
  (6.2, 6.3), and the other extension is unchanged.
- **Leaves.** The commit's path keeps the committer's credential, and
  changes its signature key only as 12.3 allows.
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
again (6.1). In other conversations it waits to be added again
(below).

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
than retention cannot catch up from the server (7.5). Any member's
device MAY remove a leaf whose profile's `updated` is more than 35 days
older than its own, and SHOULD in the same commit add the same device
again from a new KeyPackage, if KEYPKG GET returns one. The device then
gets a Welcome, and the messages it missed come from its identity's
other devices (12.13).

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
be read. Devices keep the past epochs' secrets only as long as they need
them to decrypt messages that arrive late, and SHOULD delete them after
at most a few epochs.

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
| `TRANSFER <ref>` | the conversation with yourself | 12.13 |

A TEXT line may carry these tags:

- `reply`, `edit` and `react`, each with a `message_id` in base64 with
  padding (5.3).
- `file`, the file's `get` URL; `file-key`, the file key in base64 with
  padding; `file-type`, its media type, as `type/subtype` [RFC6838];
  `file-size`, its size in bytes before encryption; and `file-hash`, the
  SHA-384 hash of the exact bytes uploaded, in base64 with padding
  (12.11).

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
challenged and costs nothing. A device puts its pending CHALLENGE and
ANSWER lines in its next message in the group, or, if it sends none, in
a message of their own within a minute. It answers only the newest
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
   [RFC8439] under the file key, with no associated data and a nonce of
   i as an 11-byte big-endian number followed by one byte: `0x01` for the
   last chunk, `0x00` for the others. The upload is the encrypted chunks
   in order, each followed by its 16-byte tag.

A device that downloads a file:

- checks that the SHA-384 hash of what it downloaded equals `file-hash`,
  comparing in constant time, before it decrypts anything;
- decrypts chunk by chunk, and checks that only the last chunk has the
  last-chunk flag, that the length fits in the plain text, and that the
  padding is all zero bytes;
- MUST NOT show or save any part of the file unless every check passes.

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
room's current epoch for as long as it is current.

Blobs are public to anyone who knows their hash. Everything a device
stores in one is either public already, such as a public room's tree,
or encrypted, such as a Welcome or a history archive (12.13).

### 12.13. History on New Devices and Backups

The server keeps no history (Section 7). A device keeps the messages it
has received, decrypted, under the protection it gives its own keys,
and deletes each message key as soon as it has used it (12.9). So the
history of a conversation exists only on its members' devices. It
reaches a new device in two ways.

**The conversation with yourself.** An identity's devices share a
direct conversation of their own (5.1) on each server they use. They
use it to keep each other up to date: read markers (7.7), blocks (5.7),
records they make (4.5), new device-signing keys (4.8) and backup keys
(below), as lines inside the encryption (12.9).

**Transfer at pairing.** When a device pairs a new one (4.8), it MAY
send it the history it has:

1. It builds a HistoryArchive (below) of the conversations it chooses,
   with the files it chooses.
2. It encrypts the archive under a new random 32-byte key, as a file
   (12.11), and stores it as a blob (12.12).
3. It puts the blob's hash and the key in the `transfer` field of the
   IdentityBundle, as a TransferRef.

```
struct {
    opaque blob_hash[48];
    opaque key[32];
} TransferRef;
```

The new device fetches the blob, checks its hash, decrypts it as a file,
and stores the history. The server sees only a blob of ciphertext. A
transfer too large for one blob is split over several archives, the
first of which names the others in `more`.

**Catching up from your own devices.** A device that was offline for
longer than retention (7.5), or that rejoined a group (12.7), has a gap
in its history. When an identity's device sees another of its devices
come back with a gap, for example by its READ lines (7.7) or by its
leaf being added again, it SHOULD send it the missing messages the same
way: a HistoryArchive of the conversations and seqs it lacks, as a blob,
named by `TRANSFER <ref>` in the conversation with yourself, where
`<ref>` is the TransferRef in base64 with padding. Only an identity
whose every device was offline loses messages.

```
struct {
    opaque message_id[16];
    opaque sender<V>;            // uid
    uint8 verified;              // 1 if the sender's leaf was confirmed (12.10), else 0
    uint64 sent;                 // the sender's time, ms
    uint64 received;             // the server's time, ms
    uint64 seq;                  // the post's seq
    opaque content<V>;           // the content lines, as received
} ArchivedMessage;

struct {
    opaque group_id<V>;
    opaque host<V>;
    opaque box[16];
    ArchivedMessage messages<V>; // oldest first
} ArchivedConversation;

struct {
    uint8 version;               // 1
    opaque uid<V>;
    uint64 made;                 // when the archive was made, ms
    ArchivedConversation conversations<V>;
    TransferRef more<V>;         // further archives of the same transfer
} HistoryArchive;
```

Deleted messages are left out, and the content of edited messages is
the newest version, with the edits kept as messages of their own. Files
travel as the messages that share them: the new device fetches them as
any device does, while the server still has them (5.6).

**Backups.** A person MAY keep an encrypted backup of their history on
the server, so that it survives losing every device. Only the recovery
key can read it. Servers MUST support backups.

- **Backup keys.** A backup key is derived from the recovery key with
  HKDF-SHA384 [RFC5869]: HKDF-Expand(HKDF-Extract("", recovery key),
  info, 32), where `info` is `risala/1 backup `, the uid, a space, and a
  **generation** number in decimal. The first generation is 0. Removing
  a device moves to the next generation (4.8), since the removed device
  knew the old key. Every device keeps the current generation's backup
  key, which it got at pairing or in a BACKUPKEY line, but never the
  recovery key.
- **Making a backup.** At most once a day, one device of the identity
  builds a HistoryArchive of everything it has, encrypts it as a file
  under a new random key, stores it as a blob, and wraps the key: a
  random 12-byte nonce, followed by the key encrypted with
  ChaCha20-Poly1305 [RFC8439] under the backup key and that nonce, with
  associated data `risala/1 backup`, a space, the uid, a space, the
  generation and a space, followed by the blob's hash. The wrapped key
  is 60 bytes.

```
BACKUP PUT <generation> <hash> <key>
BACKUP GET
BACKUP DEL
```

- **`BACKUP PUT`** stores a backup, and replies `OK`. `<hash>` is the
  blob-ref of the archive, and `<key>` the wrapped key in base64 with
  padding. It replaces the identity's previous backup, whose blob the
  server deletes, and keeps the new blob for as long as it is the
  current backup, whatever the retention period.
- **`BACKUP GET`** sends `BACKUP <generation> <hash> <key>`, then `OK`,
  or `ERR not-found` if there is no backup.
- **`BACKUP DEL`** deletes the backup, and replies `OK`.
- They need a signed-in connection. Backups belong to the identity, not
  to a device. A server MAY limit their size (`ERR too-long`).

To restore, a device with the recovery key sends BACKUP GET, derives the
backup key of that generation, unwraps the key, fetches the blob, checks
its hash, and decrypts it. Messages restored this way are shown as
restored, with the verification they had when they were backed up.

A backup is not forward secret: whoever gets the recovery key can read
the newest backup, until it is replaced or deleted (Section 14).

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

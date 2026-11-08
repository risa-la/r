## 6. Rooms

### 6.1. Joining and Leaving

A room is **public** or **private** from the moment it is created, and
stays so (12.4).

| | Private room | Public room |
|---|---|---|
| Members | at most 1,000 identities and 4,096 leaves | at most 10,000 identities and 32,768 leaves |
| Who may join | only those invited (below) | anyone not banned, and guests if the room allows them |
| Listed by LIST | no | yes |
| Membership | hidden from the server: commits are encrypted | visible to the server, which checks commits (12.6) |
| Leaf confirmation | pairwise up to 256 members, then epochal (12.10) | epochal (12.10) |

Devices refuse a commit that takes a room over its limits, and in public
rooms the server refuses it too (12.6, 12.7). A direct conversation
holds at most 128 leaves, the most that the current devices of its two
participants can have (12.7). These limits will be revisited once
ML-DSA and X-Wing have been measured on phones.

```
LIST [after=<room>] [limit=<n>]
```

→ one `ROOM <room> <box> <members> [<topic...>]` line per public room,
then `OK more=<0 or 1>`

- `<members>` is the number of identities and guests with a leaf in the
  room's group, and `<topic...>` the topic in its conversation extension
  (6.2). The server reads both from the group, which it holds for public
  rooms. A device checks them once it has joined.
- A guest's LIST leaves out rooms whose `guests` setting is `none`.
- Rooms come in order of name, compared byte by byte.
- **`after`** returns only rooms whose names sort after `<room>`, which
  need not exist. To fetch the next page, send LIST again with `after`
  set to the last room returned.
- **`limit`** is at least 1 and defaults to 100. A server MAY return
  fewer rooms than asked for. `more=1` means there are more rooms after
  the last one returned.

```
INFO <room>
```

→ `OK box=<box> members=<n> epoch=<epoch>`

Looks up one public room by name. A name that is not a public room on
this server gets `ERR not-found`.

```
GROUPINFO <box>
```

→ `GROUPINFO <box> <epoch> <seq> <groupinfo> <tree>`, then `OK`

Returns a public room's current GroupInfo and ratchet tree, as the
server holds them (12.6). `<seq>` is a position (3.5): the seq of the
commit that started the epoch, or `0` in epoch 0. `<groupinfo>` and
`<tree>` are each base64 with padding, or a blob-ref (12.12): the tree
of a large room is always a blob. A mailbox that is not a public room
gets `ERR not-found`.

**Joining a public room.** A device fetches GROUPINFO, checks the group
as in 12.7, and joins by external proposal: it posts an external Add
proposal (`new_member_proposal` [RFC9420]) holding a KeyPackage that it
makes for this join, with no device binding (12.3), with the token `-`
(5.2). A full client in the room commits it (below), and the device then
fetches its Welcome with WELCOME GET (12.8), which comes with the tree
of the Welcome's epoch, since the server keeps that tree for it (12.6).
Every device joins this way, full client or light client (12.6),
identity or guest. External commits are used only to resync a room that
its devices could not follow, and for owners and moderators to get back
in when nobody commits their proposals (12.7), so that nobody else who
is not yet a member can force the room's devices to join again.

A device remembers the group id of each public room it has joined, by
host and room name. Before it joins a room of the same name again, or
one that a link names (Section 15), it compares the group id. If it
differs, it tells the user that the name now leads to a different
group, and joins only if they choose to. A link MAY carry the group id,
which the device then checks too. A device that joins again a room it
was in also checks its roles and settings (12.7, "Rejoining a public
room").

A guest joins the same way, with a leaf whose credential names its guest
uid (12.3), from its guest connection. The server refuses a join
(`ERR forbidden`) whose credential names a banned identity, or a guest
where `guests` is `none`. It does not check that a joining identity's
device is current, since the join carries no device binding: anyone may
post a join whose credential names any device, and devices treat the
leaf as unverified, like a guest's, until it attests (12.10). The
server MAY ask for proof of work first (4.1). A leaf that its device
does not use, because it never joined after all or because its
credential names a device that does not hold it, never commits or
proposes an Update. Owners and moderators may remove such a leaf
without kicking the uid it names, and any member may once it is 8 days
old (12.7), so such joins cannot fill a room for ever.

Full clients in a public room commit pending join proposals, Update
proposals (12.10) and SelfRemove proposals (below), at most 256 devices
in a commit. Each one waits a random time of up to 10 minutes after the
oldest pending proposal, then commits them all at once, unless another
commit has done so first. A room in which no
full client is online cannot admit anyone by proposal. An owner can keep
a full client online for the room, for example on a desktop. Owners and
moderators whose proposals nobody commits within 30 minutes may join by
external commit instead (12.7).

**Joining a private room.** Only by invitation. An owner or moderator
invites someone by fetching KeyPackages of the invitee's devices
(12.5), and committing an Add of each of them (12.7). The invitee's
devices get Welcomes (12.8), and their client shows the invitation. The
invitee accepts by following the mailbox and taking part, and declines
by leaving (below). There is no INVITE command, and the server does not
know about invitations.

**Starting a direct conversation.** A device creates the group and the
mailbox, and adds the other participant's devices and its own other
devices (12.7). A conversation with yourself is started the same way,
with only your own devices.

**Leaving.** A device leaves a group with a commit that removes the
leaves of every other device of its identity, and a SelfRemove proposal
[MLS-EXT] for its own leaf, which it posts right after. An MLS member
cannot remove itself in its own commit, so another member's device
commits the SelfRemove, and SHOULD do so within a few minutes. A
proposal belongs to its epoch, so if a commit that leaves the SelfRemove
out wins the epoch, the leaving device posts the SelfRemove again in the
new epoch, and so on, until a commit removes its leaf. Devices treat the
identity as having left once they have seen both, and do not add its
devices back meanwhile (12.7). A device whose identity has no other
leaves in the group sends only the SelfRemove.

Devices ignore messages from a leaf that has posted a SelfRemove. In a
private room, coming back always takes a new invitation.

**Guests.** When a guest's session ends (4.2), the server sends
`GONE <box> <uid>` to the connections that follow each public room the
guest had a leaf in. A full client then removes the guest's leaf in its
next commit. A GONE line is not a post, and devices act on it only for
guest leaves, since removing one never lets anyone new read.

**Dropped rooms.** When an operator drops a room or a mailbox (10.4),
the server sends `DROP <box> [<reason...>]` to the connections that
follow it. The conversation cannot go on there. Clients SHOULD tell the
user, and MAY keep what they have stored.

### 6.2. Settings

A room's settings live in its conversation extension (12.4), where
every device reads them. They change only by a commit that carries a
GroupContextExtensions proposal, made by someone the table allows. There
is no SET command.

| Field | Values | Default | Who may change it |
|---|---|---|---|
| `name` | private rooms: text up to 128 bytes; public rooms: the room name (3.5) | | owners, in private rooms only |
| `topic` | text up to 512 bytes, may be empty | empty | owners, moderators |
| `guests` | `none`, `read` or `write` | `write` in public rooms, `none` in private ones | owners, in public rooms only |
| `send` | `all` or `mods` | `all` | owners |
| `confirm` | `pairwise` or `epochal` | `pairwise` in private rooms, `epochal` in public ones | owners, from `pairwise` to `epochal` only; anyone, in the commit that takes the room past 256 identities |
| `owners`, `mods` | lists of uids | the creator is the only owner | owners (6.3) |
| `bans` | a list of uids | empty | owners, moderators (6.4) |

- `guests none`: guests cannot join. `guests read`: guests may join, and
  devices ignore their TEXT lines and typing. `guests write`: guests may
  also send. If guests start sending spam, an owner can switch the room
  to `read`.
- Changing `guests` to `none` also removes the guests' leaves, in the
  same commit.
- `send mods`: the room is for announcements. Devices ignore TEXT lines
  from plain members and guests, other than reactions, and their typing
  (5.3, 8.1).
- `confirm`: how devices confirm whose leaf is whose (12.10). A private
  room in which more than 256 identities have leaves moves to
  `epochal`, in the commit that takes it over 256 or before. It does not
  move back. Since the move is forced, whoever makes the commit that
  takes the room past 256, such as a moderator who invites someone,
  changes `confirm` in it, and devices refuse that commit if it does not
  (12.7).

Devices refuse a commit that changes a field it may not change, or any
other field of the extension (12.7). In a public room the server
refuses it too.

### 6.3. Roles

Each identity in a room is an `owner`, a `mod` (moderator) or a plain
member. The `owners` and `mods` lists of the conversation extension say
which. Whoever creates a room is its first owner. Guests are always
plain members, and cannot be added to either list.

A role belongs to the identity, not to its leaves. It stays when the
identity leaves the room of its own accord, but not when it is banned
(6.4). Coming back to a private room still takes an invitation.

| Action | member | mod | owner |
|---|---|---|---|
| Send messages; edit, react to and delete your own | ✓ | ✓ | ✓ |
| Send messages in a room with `send mods` (6.2) | | ✓ | ✓ |
| Delete anyone's messages (5.4) | | ✓ | ✓ |
| Set `topic` | | ✓ | ✓ |
| Invite (6.1); kick, ban and unban plain members (6.4) | | ✓ | ✓ |
| Kick, ban and unban moderators and owners | | | ✓ |
| Change `name`, `guests`, `send`, `confirm`, `owners` and `mods` | | | ✓ |

- A room always keeps at least one owner. Devices refuse a commit that
  removes the last one from `owners`, or kicks or bans them.
- **A room whose owners are gone.** If no identity in `owners` has a
  leaf in the group, for example because the last owner left, a
  moderator may do what an owner may, including adding itself to
  `owners`. Without moderators either, the room's settings can no
  longer change.
- Devices check the role of whoever made a commit against the extension
  of the epoch the commit is for. They check the role behind a message
  against that epoch's extension and against the newest one applied at
  the message's place in the order of posts, so that a kick or a
  demotion takes effect at once (12.9).
- Server operators have no role in rooms, and no way to act as one,
  since devices take roles only from the group. They can mute and drop
  (Section 10).

### 6.4. Moderation

Owners and moderators moderate with commits:

- **Kick** is a commit that removes every leaf of an identity. They may
  be invited again, or join a public room again.
- **Ban** is a kick that also adds the identity's uid to `bans`, and
  takes it out of `owners` and `mods`. Devices refuse a ban that leaves
  the uid in either list, and a commit that adds a leaf of a banned
  identity. In public rooms the server refuses both too, by the uids in
  credentials, which it does not check there (6.1): someone banned can
  still join under another uid, but then never attests, and devices
  treat their leaf as a guest's (12.10). Banning a guest uid has little
  effect, because guest names get reused: mute its
  pseudonym instead (below), or ask an operator to ban its network
  address (10.2).
- **Unban** is a commit that takes a uid out of `bans`.
- **Kicking a moderator.** A kick leaves roles as they are, since a
  kicked member may be invited back. An owner who kicks a moderator for
  abuse SHOULD take them out of `mods` in the same commit.

Moderators may kick and ban only plain members. Owners may act on
anyone except the last owner (6.3).

**Muting.** In a public room, the server can refuse the posts of a
pseudonym (7.3). It does not learn from the pseudonym whose it is,
though it may guess from timing (Section 14). An owner or moderator
whose device sees abuse from a member asks for it:

```
MUTE <box> <pseudonym> [hours=<n>]
UNMUTE <box> <pseudonym>
```

→ `OK`

`<pseudonym>` is 16 bytes in base64 with padding. The command needs a
signed-in connection whose identity is an owner or moderator in the
public room's conversation extension, which the server holds, and has at
least one leaf in the room's group (`ERR forbidden`). The server refuses
that pseudonym's posts in that mailbox for `<n>` hours, 24 by default,
or until UNMUTE, and in any case only until the end of the current
period (12.10), since a public room is epochal and its pseudonyms last
one period (7.3). A mute is a stopgap until a moderator's device bans
the member. A member who joins again with a new leaf, or reaches a new
period, has a new pseudonym, which a moderator mutes again if needed.

For moderation across a whole server, see Section 10.

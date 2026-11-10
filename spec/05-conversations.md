## 5. Conversations

### 5.1. Kinds of Conversation

Every conversation is an MLS group (Section 12), and every conversation
is end-to-end encrypted. There are three kinds:

- A **direct conversation** is between two identities. A conversation
  with yourself, which an identity's devices also use to keep each other
  up to date (12.13), is a direct conversation of one identity.
- A **private room** has up to 1,000 members. Nobody can join it without
  being invited, and the server does not know who is in it.
- A **public room**, such as `#general`, has up to 10,000 members. The
  server lists it, anyone may join it, and its membership is visible to
  the server (6.1). Its messages are still end-to-end encrypted.

There are no group direct conversations: a group of people talks in a
room.

The group's **conversation extension** (12.4) says which kind a
conversation is, which server and mailbox it lives on, who its owners
and moderators are, and its settings. Devices read all of this from the
group, never from the server.

A conversation lives on one server, the one its mailbox is on. Every
identity in it needs to have signed in to that server at least once, so
that its devices have KeyPackages there (12.5). There is no federation.
Guests (4.2) have no KeyPackages: they join public rooms, and start the
report conversations of 5.8, with a throwaway leaf.

Devices keep at most one direct conversation for each pair of
identities on a server, and one conversation with yourself. If they find
two, for example because both people started one at about the same time,
they keep the one whose group id is lower, compared byte by byte, and
leave the other (6.1). A direct conversation that either participant
has left does not count: once one leaves, both sides leave it (6.1),
and talking again starts a new one.

### 5.2. Mailboxes and Posts

Each conversation has a **mailbox** on its server, named by a box
(3.5). The server keeps the mailbox's posts, and hands them to anyone
who follows or fetches the mailbox (Section 7). For a direct
conversation or a private room, the server keeps nothing else: no name,
no members, no roles and no settings. A private conversation's box is
known only to its members, and the server cannot tell who they are.

```
CREATE <box> <group-id> <token-hash> [epoch=<epoch> from=<box> token=<token>]
CREATE <box> <group-id> <token-hash> <room> <groupinfo> <tree>
```

→ `OK`

Creates a mailbox, for a group in epoch 0. The client picks `<box>`
from 16 new random bytes. `<group-id>` is the group's 32-byte id (12.6),
in base64 with padding, and `<token-hash>` the SHA-384 hash of the group's send token
for epoch 0 (7.2), in base64 with padding.

- **The first form** creates the mailbox of a direct conversation or a
  private room. It needs an anonymous connection, or a guest connection
  for a guest's report conversation (4.2). With `epoch`, a number
  greater than 0, it creates the new mailbox of a group that is moving
  (7.8): the mailbox starts at that epoch, and `<token-hash>` is the
  hash of that epoch's token. `from` and `token` then come too: `from`
  is the box of the mailbox the group moves from, and `token` the
  group's send token for the epoch before `epoch`, in base64 with
  padding. Each of the three options needs the other two
  (`ERR bad-syntax`).
- **The second form** creates a public room named `<room>` (6.1). It
  needs a signed-in connection. `<groupinfo>` and `<tree>` are the
  group's GroupInfo and ratchet tree (12.2), each in base64 with
  padding: the device cannot store them as blobs, since the mailbox
  does not exist yet, so they must fit in the line (12.12). The server
  checks them as in 12.6: one leaf, whose credential names the
  connection's identity, and a well-formed conversation extension
  (12.4) of kind `public_room` that names this server, `<box>` and
  `<room>`, with that identity as an owner. As for a commit's (12.6), the GroupInfo carries
  the `external_pub` extension and no `ratchet_tree` extension, its
  group context's tree hash is that of `<tree>`, and its signer is the
  one leaf (`ERR invalid`).

The server replies `ERR name-taken` to a box it has seen before, to a
room name that is in use, and, without `epoch`, to a group id it has
seen before. With `epoch`, `from` must be a mailbox that the server
holds with the same group id (`ERR not-found`), and not a public
room's, since public rooms never move (`ERR forbidden`, 7.8), and its
token set for the epoch before `epoch` must hold `token` (`ERR stale`,
7.2). A box that is
already the mailbox of that group from that epoch gets `OK`, and
nothing changes (7.8).

```
C: CREATE m4qkz7xw2rjv5tbnhc3pfyd6ea q1Zx8bN3vR7tY2wK5mP9sD4fG6hJ0lC3xV8bN1mQ2wE= OWLXhHTd2X+O1uwHQ2Ylsj9LLdW2htn4UhwDp6x6TDrnYCbdMAQ4Hu4/aEVDqmGm
S: OK
```

The new mailbox of a group whose move creates epoch 42 (7.8):

```
C: CREATE 7tz3w5ka2qnmxhfyvd4pcr6bje q1Zx8bN3vR7tY2wK5mP9sD4fG6hJ0lC3xV8bN1mQ2wE= OWLXhHTd2X+O1uwHQ2Ylsj9LLdW2htn4UhwDp6x6TDrnYCbdMAQ4Hu4/aEVDqmGm epoch=42 from=m4qkz7xw2rjv5tbnhc3pfyd6ea token=Xk2pV9rT4mW7qZ1nB8cF3sH6jL0dG5yA2eR9uK4oP1w=
S: OK
```

A server never uses a box again, even once its mailbox is gone (7.5,
10.4), and MAY remember boxes and group ids by their hashes only.

Servers MUST limit how many mailboxes one connection and one network
address create (`ERR rate-limited`), and SHOULD limit how often one
identity creates public rooms. Servers will be able to require proof
of work for CREATE once a later draft specifies it (4.1).

```
POST <box> <token> <message> [live=yes] [groupinfo=<groupinfo>] [next=<hash>]
```

→ the post, then `OK seq=<seq>`; with `live=yes`, `OK`

Posts an MLS message (12.2) to a mailbox. `<message>` is the MLSMessage
in base64 with padding, or a blob-ref (12.12) if it is too large for a
line. `<token>` is the group's send token for the message's epoch, in
base64 with padding, or `-` for a join of a public room (6.1).
`<groupinfo>` is base64 with padding, or a blob-ref. `<hash>` is the
SHA-384 hash of the send token of the epoch that a commit creates, in
base64 with padding (7.2, 12.6).

The server reads the group id, epoch, content type and authenticated
data from the message's framing, which MLS leaves in the clear, and
checks that:

1. The mailbox exists (`ERR not-found`), and the message's group id is
   the one it was created with (`ERR invalid`).
2. The message is a PrivateMessage, or, in a public room only, a
   PublicMessage that holds a commit or a proposal. Its cipher suite is
   `0x0020` and its version `mls10` (12.2). Its authenticated data is a
   RisalaAAD (12.9) with the fields its content type needs, and a
   pseudonym of 16 bytes in a PrivateMessage and an empty one in a
   PublicMessage. A commit has `next`, and nothing else does; a commit
   in a public room has `groupinfo`, and nothing else does
   (`ERR invalid`).
3. The SHA-384 hash of `<token>` is one of the token hashes it holds for
   the message's epoch (7.2), compared in constant time
   (`ERR stale`). A token of `-` is allowed only for an external commit
   or an external Add proposal in a public room (6.1); anything else
   gets `ERR forbidden`.
4. The post's pseudonym (7.3) is not muted in this mailbox
   (`ERR forbidden`), and the connection and its network address are
   within the server's limits (`ERR rate-limited`). Limits are not kept
   per pseudonym, since anyone who holds the token can post under any
   pseudonym.
5. In a public room, a commit or proposal passes the checks of 12.6.
   A PublicMessage there may come on a signed-in connection, and a
   commit or Update proposal by an identity's leaf MUST (12.6). Every
   other post needs an anonymous or guest connection.

The server then gives the post the mailbox's next sequence number,
keeps it until it expires (7.5), and sends it to every connection that
follows the mailbox, as an **event line**:

```
@seq=<seq>;t=<timestamp> POST <box> <message> [next=<hash>]
```

`t` is when the server accepted it. The line does not repeat the token,
but repeats a commit's `next`, which the server adds to the next
epoch's token set (7.2), and which every device checks (12.7). The
server stores the post as 4.2 says: with its box, seq, time, message
and, for a commit, `next`, only.

```
C: POST m4qkz7xw2rjv5tbnhc3pfyd6ea 3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE= AAEAAgBA… next=OWLXhHTd2X+O1uwHQ2Ylsj9LLdW2htn4UhwDp6x6TDrnYCbdMAQ4Hu4/aEVDqmGm
S: @seq=9310;t=2026-11-09T08:12:44.051Z POST m4qkz7xw2rjv5tbnhc3pfyd6ea AAEAAgBA… next=OWLXhHTd2X+O1uwHQ2Ylsj9LLdW2htn4UhwDp6x6TDrnYCbdMAQ4Hu4/aEVDqmGm
S: OK seq=9310
```

With `live=yes`, the post is not kept: it gets no seq, goes only to the
connections that follow the mailbox now, with `t` but without `seq`,
and is not pushed. Typing notifications are live (8.1). Only application messages
may be live (`ERR invalid`).

A commit in a public room carries its new GroupInfo as `groupinfo`
(12.6). A POST MAY carry a `cid` tag (7.6).

The server does not learn from a post who sent it, except a
PublicMessage, whose sender leaf is in the clear (12.6). It learns
which connection sent it, the pseudonym in it, and when, and can
sometimes link these to a sender by timing and network address
(Section 14).

### 5.3. Messages

A message is an MLS application message whose content is a
RisalaMessage (12.9). Inside it are one or more lines in the format of
Section 3, which only the conversation's members can read. A message
that people see has a TEXT line:

```
[@<tags>] TEXT <text...>
```

The text follows the rules of 3.4. It MUST NOT be empty: text made only
of spaces, TABs and line breaks, once unescaped, counts as empty. It is
at most 8192 bytes. Every message has an id, `message_id`, which other
messages use to refer to it. It may carry at most one of these tags:

- `reply=<id>` replies to the message whose id is `<id>`.
- `edit=<id>` replaces the text of message `<id>`. Devices ignore an
  edit from anyone other than the author of `<id>`. Clients show the
  text of the newest edit in the original's place, and MAY show every
  earlier version. An edit from a leaf less trusted than the message's
  (5.4) does not replace its text until that leaf is confirmed; clients
  MAY show it apart, as an unverified edit.
- `react=<id>` reacts to message `<id>`. The text is the reaction,
  usually a single emoji, and MUST be at most 64 bytes. Devices ignore a
  longer one, and a second identical reaction from the same person to
  the same message. Reactions are the same if their escaped text (3.4)
  is the same, byte for byte. To take a reaction back, delete it (5.4).

`<id>` is a `message_id` in base64 with padding. A `reply` may also be
combined with the file tags of 5.6. The target must be a message in the
same conversation, not deleted, and not itself an edit or a reaction.
Devices ignore a reference that is not, and show a reply whose target
they do not have, for example because it was sent before they joined,
without the quote.

Every message also says, inside the encryption, which device sent it,
when the sender's clock says it was sent, how many messages that device
has sent in the group, and which was its previous one (12.9). The server
sees none of this.

In a room with `send mods` (6.2), devices ignore TEXT lines from plain
members and guests, except reactions.

### 5.4. Deleting Messages

```
DELETE <id>
```

A DELETE line in a message asks every device to delete message `<id>`
of the same conversation. Devices act on it only if its sender is the
author of `<id>`, or, in a room, an owner or moderator both at the epoch
of the DELETE and at its place in the order of posts (6.3, 12.9).

A DELETE also needs a leaf at least as trusted as the message's: one
that the device has confirmed (12.10), unless the device shows the
message as unverified too. Otherwise a leaf that another member planted
under the author's credential could erase what the author really wrote
(12.7). The device then shows the message as deleted but unconfirmed,
and keeps its text. It acts on the DELETE once the DELETE's leaf is
confirmed, and drops it if that leaf is found to be an impostor (12.7).

Devices that act on it erase the stored text of the target, and of its
edits and reactions, and show a placeholder in its place. Deleting an
edit makes the previous version current again. Deleting a reaction
removes it. Replies to a deleted message stay. A device deletes a file
it has stored for the message too, and SHOULD ask the server to delete
an upload it made itself (5.6).

The server cannot delete a message, since it cannot read it. The post
stays on the server, encrypted, until it expires (7.5). Deletion cannot
reach copies that people have already made.

### 5.5. Mentions

A mention is `@` followed by a uid, for example `@alice@example.org` or
`@~sam`. The `@` must be at the start of the text or follow whitespace,
after unescaping. The mention is the longest uid that follows the `@`.
Uids never end with `.` (3.5), so in `thanks @~sam.` the mention is
`~sam`.

Clients SHOULD highlight mentions of the user, and use them to decide
which notifications to show (9.3). They SHOULD also let users type a
display name and insert the matching uid. Mentions are inside the
encryption, so the server never sees them.

### 5.6. Files

Servers MAY support file uploads. INFO reports the largest file allowed
as `upload=<bytes>`, or `upload=no` (8.5). Files never travel over the
chat connection. They go over HTTPS, so a client that uploads or
downloads files also needs an HTTPS client. Devices encrypt every file
before they upload it (12.11).

```
UPLOAD <box> <token> <size>
```

→ `OK put=<url> get=<url> del=<url>`

Asks to upload a file of `<size>` bytes for the conversation of
`<box>`. `<token>` is a send token of the group, checked as for POST
(5.2), so that only members can upload, without saying who they are.
It needs an anonymous connection. The file counts against the mailbox's
quota and the network address's limits (7.5). Sharing a file takes
three steps:

1. The client encrypts the file (12.11) and sends UPLOAD with the size
   of the result. The server replies with three URLs: `put` to upload
   it to, `get` to download it from, and `del` to delete it.
2. The client sends the file in an HTTP PUT request to the `put` URL,
   with a matching `Content-Length` and the `Content-Type`
   `application/octet-stream`. A 2xx response means the server has
   stored it.
3. The client sends a message whose TEXT line carries the `get` URL and
   the file's key, type, size and hash (12.11). The text is a caption,
   or the file name if there is no caption.

```
C: upload ujzdegxdncf32epf3dhodzdoci 3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE= 52311
S: OK put=https://files.example.org/put/pqk3vdz7m2xwa5hc4ntf6ry2je get=https://files.example.org/f/h7qwn3zc5ka2vmd4xpe6tyr5bu del=https://files.example.org/del/c2mz7wqa4hv5kt3dpr6nx2yfge
```

Rules:

- **The `put` URL** works for one upload within 10 minutes. The server
  MUST reject a body whose length differs from `<size>`.
- **Size.** A file larger than the server allows gets `ERR too-long`.
- **Storage.** A server can keep files on its own disk or hand out
  presigned URLs for object storage. Its `get` URLs MUST be on the
  origins that INFO lists as `files` (8.5). Devices download a file
  without asking only from those origins of the conversation's own
  server (12.11).
- **`get` URLs** MUST use `https`, MUST NOT contain `;`, and MUST be at
  most 512 bytes. They are capabilities: anyone who has one can
  download the file. They MUST therefore contain at least 128 bits of
  randomness. They lead only to ciphertext.
- **`del` URLs** are capabilities too. An HTTP DELETE request to one
  deletes the file. A device that deletes a message it sent with a file
  (5.4) SHOULD delete the file this way.
- **Expiry.** Files expire with the server's retention period (7.5),
  counted from the upload. A moderator's DELETE (5.4) cannot remove a
  file: it stays on the server until it expires, unless its uploader
  deletes it. A file named in an open report is kept until the report
  is resolved (5.8).

### 5.7. Blocking

Blocks belong to the account, and the server never sees them. A client
keeps the list of identities and domains (`*@example.net`, which also
covers subdomains) that the user has blocked, and shares it with the
identity's other devices with BLOCK and UNBLOCK lines in the
conversation with itself (12.9). In those lines, `<target>` is a uid
(3.5) or `*@` followed by a domain:

```abnf
block-target = uid / "*@" domain
```

While the user has blocked someone, their devices:

- ignore Welcomes (12.8) that add them to a direct conversation with
  the blocked person, or to a room in which the blocked person already
  has a leaf, and leave such a conversation if they are added to it
  anyway. A blocked person who joins a room the user is already in does
  not make the user's devices leave: they treat that person's messages
  as the next item says;
- do not show the blocked person's messages, typing or reactions in
  direct conversations, and SHOULD offer to hide them in rooms;
- do not notify the user of anything the blocked person sends.

The blocked person is not told, and can still read rooms they share
with the user.

### 5.8. Reporting

A report of abuse goes to the people who can act on it. The reporter's
client tells the reporter, before sending, exactly who will see the
report.

**In a room, to its moderators.** Owners and moderators are members, so
they can see who wrote a message themselves, from their own copy of it.
A report to them names the message by its id. The reporter's device
sends a REPORT line, inside the encryption, in a direct conversation
with each owner and moderator of the room (12.9):

```
@box=<box>;target=<id>[;context=<ids>] REPORT [<reason...>]
```

- `box` is the room's mailbox, and `target` the reported message's id.
- `context` lists up to 10 earlier messages of the same room, as ids
  separated by commas, that the reporter adds to show what led up to
  it.
- `<reason...>` is free text of up to 512 bytes.

The moderator's device shows the reported message and its context from
its own copies, with their authors as it confirmed them (12.10).

**Guests** report the same way, in a **report conversation**: a direct
conversation between the guest uid and an owner or moderator of a
public room it is in (12.7). The guest's device creates it with its
throwaway leaf (4.2), fetches the moderator's KeyPackages, creates the
mailbox and sends the Welcomes as any device does (12.5, 5.2, 12.8).
In it:

- The moderator's devices join only if the moderator accepts, and only
  for a public room on that server that allows guests and in which
  their identity is an owner or moderator (12.7).
- They act only on REPORT lines from the guest whose `box` is such a
  room, show each as a report from that guest uid, and ignore every
  other content line the guest sends there.
- They show that the guest uid is not tied to the guest of that name
  they may have seen in the room, since guest names are reused (4.2).
- Clients SHOULD limit how many report conversations from guests they
  accept, and MAY leave one once its reports have been dealt with.

**To the server's operators.** Operators are not members, and cannot
confirm who wrote a message: deniability (12.10) means that nothing a
member can show them proves it. A report to them proves what the
message said, by franking (12.9), and carries the reporter's claim of
who wrote it.

```
REPORT <box> <report>
```

→ `OK id=<id>`

```
C: report ujzdegxdncf32epf3dhodzdoci AQAAAAAAACPx…
S: OK id=r7k2qm
```

`<report>` is a RisalaReport, in base64 with padding, or a blob-ref
(3.5) naming a blob that holds its bytes without base64 (12.12), for a
report too large for a line. The server keeps such a blob for as long
as it keeps the report, and sends operators the report line with the
same blob-ref.

```
struct {
    uint64 seq;              // the post's seq in the mailbox
    opaque frank_key[32];
    opaque content<V>;       // the RisalaMessage's content
} ReportedPost;

struct {
    uint8 version;           // 1
    ReportedPost target;
    ReportedPost context<V>; // up to 10 earlier posts, oldest first
    opaque author<V>;        // the uid the reporter says wrote the target
    opaque reason<V>;        // UTF-8, at most 512 bytes
} RisalaReport;
```

The server checks that:

- every post named is still kept in `<box>` (`ERR not-found`), and is
  an application message;
- HMAC-SHA-384(`frank_key`, `content`) [RFC2104] equals the franking
  tag in the post's RisalaAAD (12.9), compared in constant time;
- there are at most 10 context posts, their seqs are strictly
  increasing, and each is lower than the target's;
- `author` is a uid (3.5), and `reason` UTF-8 of at most 512 bytes.

Otherwise it replies `ERR invalid`. So the content can only be
what was posted. The seqs show how many posts lie between the messages,
which the reporter does not choose. REPORT works on anonymous, guest and
signed-in connections (Section 13): a reporter who is signed in tells
the operators who they are.

When a report is made, the server keeps copies of the posts it names
until the report is resolved, even if they expire in the meantime. If
the content of a post it names has a TEXT line whose `file` is a `get`
URL of this server (5.6), the server keeps that file too, even if its
uploader deletes it or it expires. The content is in the clear in the
report, so the server can read the URL. It SHOULD discard these copies
once the report is resolved, and MAY close reports on its own after a
time it chooses. Servers SHOULD rate-limit reports.

Operators receive each report as one line:

```
@report=<id>;t=<timestamp>;pseudonym=<pseudonym>[;from=<uid>] REPORT <box> <report>
```

`t` is when the report was made, and `from` the reporter, if they were
signed in. `pseudonym` is the pseudonym in the target post's RisalaAAD
(7.3), in base64 with padding, so that an operator can mute it. The
server sends the line to every operator's signed-in connections when
the report is made.

```
ADMIN REPORTS
RESOLVE <id>
```

- **`ADMIN REPORTS`** sends the line of every open report, then `OK`. It
  is for operators only.
- **`RESOLVE <id>`** closes a report, and replies `OK`. Any operator may
  resolve it. The server sends `RESOLVED <id>` to every operator's
  connections except the one that sent RESOLVE. RESOLVE by someone who
  is not an operator gets `ERR not-found`, as for an id that does not
  exist.

**`author` is not evidence.** It is the reporter's claim. A member can
post something abusive, then report it naming someone else as its
author, and the franking still checks. The same goes for the post's
`pseudonym`: the server does not check it (5.2), and every member can
learn the others' pseudonyms (7.3), so a member can post under another
member's pseudonym, which devices ignore, and report that post. So:

- Operators act on a report with the commands of Section 10, and then
  resolve it: they mute the target's pseudonym (ADMIN MUTE), or drop
  the mailbox or room (ADMIN DROP). They SHOULD NOT mute a pseudonym on
  a single report. Outside public rooms a mute matters only until the
  next commit anyway, which changes every pseudonym (7.3), and in a
  public room it ends with the period (10.4).
- Operators MUST NOT ban or unregister an identity (10.2, 10.5) on
  reports alone, only on evidence from outside them.
- An operator's client shows `author` as claimed by the reporter.

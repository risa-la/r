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

Devices keep at most one direct conversation for each pair of
identities on a server, and one conversation with yourself. If they find
two, for example because both people started one at about the same time,
they keep the one whose group id is lower, compared byte by byte, and
leave the other (6.1).

### 5.2. Mailboxes and Posts

Each conversation has a **mailbox** on its server, named by a box
(3.5). The server keeps the mailbox's posts, and hands them to anyone
who follows or fetches the mailbox (Section 7). For a direct
conversation or a private room, the server keeps nothing else: no name,
no members, no roles and no settings. A private conversation's box is
known only to its members, and the server cannot tell who they are.

```
CREATE <box> <group-id> <token-hash>
CREATE <box> <group-id> <token-hash> <room> <groupinfo> <tree>
```

→ `OK`

Creates a mailbox, for a group in epoch 0. The client picks `<box>`
from 16 new random bytes. `<group-id>` is the group's id, in base64 with
padding, and `<token-hash>` the SHA-384 hash of the group's send token
for epoch 0 (7.2), in base64 with padding.

- **The first form** creates the mailbox of a direct conversation or a
  private room. It needs an anonymous connection.
- **The second form** creates a public room named `<room>` (6.1). It
  needs a signed-in connection. `<groupinfo>` and `<tree>` are the
  group's GroupInfo and ratchet tree (12.2), which the server checks as
  in 12.6: one leaf, whose credential names the connection's identity,
  and a conversation extension of kind `public_room` that names this
  server, `<box>` and `<room>`, with that identity as an owner.

A box or group id that the server has seen before gets
`ERR name-taken`, and so does a room name that is in use. Servers SHOULD
limit how often one identity creates public rooms, and one connection
creates mailboxes (`ERR rate-limited`).

```
POST <box> <token> <message> [live=yes] [groupinfo=<groupinfo>]
```

→ the post, then `OK seq=<seq>`; with `live=yes`, `OK`

Posts an MLS message (12.2) to a mailbox. `<message>` is the MLSMessage
in base64 with padding, or a blob-ref (12.12) if it is too large for a
line. `<token>` is the group's send token for the message's epoch, in
base64 with padding, or `-` for a join of a public room (6.1).

The server reads the group id, epoch, content type and authenticated
data from the message's framing, which MLS leaves in the clear, and
checks that:

1. The mailbox exists (`ERR not-found`), and the message's group id is
   the one it was created with (`ERR invalid`).
2. The message is a PrivateMessage, or, in a public room only, a
   PublicMessage that holds a commit or a proposal. Its cipher suite is
   `0x0020` and its version `mls10` (12.2). Its authenticated data is a
   RisalaAAD (12.9) with the fields its content type needs
   (`ERR invalid`).
3. The SHA-384 hash of `<token>` is one of the token hashes it holds for
   the message's epoch (7.2), compared in constant time
   (`ERR stale`). A token of `-` is allowed only for an external commit
   or an external Add proposal in a public room (6.1); anything else
   gets `ERR forbidden`.
4. The post's pseudonym (7.3) is not muted in this mailbox
   (`ERR forbidden`), and is within the server's limits
   (`ERR rate-limited`).
5. In a public room, a commit or proposal passes the checks of 12.6.

The server then gives the post the mailbox's next sequence number,
keeps it until it expires (7.5), and sends it to every connection that
follows the mailbox, as an **event line**:

```
@seq=<seq>;t=<timestamp> POST <box> <message>
```

`t` is when the server accepted it. The line does not repeat the token.
A commit also gives the server the hash of the next epoch's send token
(7.2).

With `live=yes`, the post is not kept: it gets no seq, goes only to the
connections that follow the mailbox now, without `seq`, and is not
pushed. Typing notifications are live (8.1). Only application messages
may be live (`ERR invalid`).

A commit in a public room carries its new GroupInfo as `groupinfo`
(12.6). A POST MAY carry a `cid` tag (7.6).

The server never learns who sent a post. It learns which connection
sent it, the pseudonym in it, and when (Section 14).

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
  earlier version.
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
author of `<id>`, or, in a room, an owner or moderator at the epoch of
the DELETE (6.3).

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
It needs an anonymous connection. Sharing a file takes three steps:

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

Rules:

- **The `put` URL** works for one upload within 10 minutes. The server
  MUST reject a body whose length differs from `<size>`.
- **Size.** A file larger than the server allows gets `ERR too-long`.
- **Storage.** The URLs may point anywhere. A server can keep files on
  its own disk or hand out presigned URLs for object storage.
- **`get` URLs** MUST use `https`, MUST NOT contain `;`, and MUST be at
  most 512 bytes. They are capabilities: anyone who has one can
  download the file. They MUST therefore contain at least 128 bits of
  randomness. They lead only to ciphertext.
- **`del` URLs** are capabilities too. An HTTP DELETE request to one
  deletes the file. A device that deletes a message it sent with a file
  (5.4) SHOULD delete the file this way.
- **Expiry.** Files expire with the server's retention period (7.5),
  counted from the upload.

### 5.7. Blocking

Blocks belong to the account, and the server never sees them. A client
keeps the list of identities and domains (`*@example.net`, which also
covers subdomains) that the user has blocked, and shares it with the
identity's other devices with BLOCK and UNBLOCK lines in the
conversation with itself (12.9). While the user has blocked someone,
their devices:

- ignore Welcomes (12.8) that add them to a conversation with the
  blocked person, and leave such a conversation if someone adds them;
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

Guests report the same way. A guest may start a direct conversation
with an owner or moderator of a room it is in, using its throwaway key
(4.2), only to send REPORT lines. The moderator's device shows it as a
report from that guest, and ignores any other content line the guest
sends there.

**To the server's operators.** Operators are not members, and cannot
confirm who wrote a message: deniability (12.10) means that nothing a
member can show them proves it. A report to them proves what the
message said, by franking (12.9), and carries the reporter's claim of
who wrote it.

```
REPORT <box> <report>
```

→ `OK id=<id>`

`<report>` is a RisalaReport, in base64 with padding:

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

The server checks that every post named is still kept in `<box>`, that
it is an application message, and that HMAC-SHA-384(`frank_key`,
`content`) [RFC2104] equals the franking tag in its RisalaAAD (12.9),
comparing in constant time. Otherwise it replies `ERR invalid`, or
`ERR not-found` for a post it no longer has. So the content can only be
what was posted. The seqs show how many posts lie between the messages,
which the reporter does not choose. REPORT works on any kind of
connection: a reporter who is signed in tells the operators who they
are.

When a report is made, the server keeps copies of the posts it names
until the report is resolved, even if they expire in the meantime. It
SHOULD discard them once the report is resolved, and MAY close reports
on its own after a time it chooses. Servers SHOULD rate-limit reports.

Operators receive each report as one line:

```
@report=<id>;t=<timestamp>[;from=<uid>] REPORT <box> <report>
```

`t` is when the report was made, and `from` the reporter, if they were
signed in. The server sends it to every operator's signed-in connections
when the report is made.

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

Operators act on a report with the commands of Section 10, such as
ADMIN MUTE, ADMIN DROP or ADMIN BAN, and then resolve it. They act on
mailboxes, rooms and accounts, since they cannot attribute a single
message.

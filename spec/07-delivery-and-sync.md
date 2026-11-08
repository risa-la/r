## 7. Delivery and Sync

The server keeps a mailbox's posts only for its retention period (7.5).
There is no history on the server beyond that, and no command that lists
a person's conversations: devices know their own groups, and learn of
new ones from Welcomes (12.8).

### 7.1. Following and Fetching

```
FOLLOW <box> [quiet=<tag>]
UNFOLLOW <box>
FETCH <box> after=<position> [limit=<n>] [leaf=<n>]
```

- **`FOLLOW`** sends the connection every new post of the mailbox from
  now on, as event lines (5.2), and replies `OK head=<position>`, where
  `<position>` (3.5) is the mailbox's newest seq, or `0` if it has none.
  The `OK` agrees with the live posts as 3.6 says: every post newer than
  the head reaches the connection live. `quiet` names a push
  subscription that the server holds back while this connection
  follows (9.2).
- **`UNFOLLOW`** stops that, and replies `OK`. Following a mailbox the
  connection already follows, or unfollowing one it does not, gets `OK`.
- **`FETCH`** sends the earliest `limit` posts whose seq is greater than
  `after`, in ascending order, then `OK more=<0 or 1>`. `more=1` means
  there are more. `after` may be `0`. `limit` is at least 1 and
  defaults to 50. A server MAY cap `limit`, but MUST allow at least 50,
  and MAY return fewer posts than asked for.
- **`leaf`** asks for a light client's view of a public room (12.6).

These commands need an anonymous or guest connection. A box that does
not exist gets `ERR not-found`. A server MAY limit how many mailboxes
one connection follows, but MUST allow at least 1,000.

A box is the only thing needed to read a mailbox's ciphertext, so a
device keeps the boxes of private conversations to itself.

### 7.2. Epochs and Send Tokens

Only members of a group may post to its mailbox. The server checks this
without learning who they are, with a **send token** for each epoch of
the group:

```
send_token = MLS-Exporter("risala/1 send", "", 32)
```

This is the exporter of Section 8.5 of [RFC9420], in the epoch the post
belongs to. Every member of the epoch can compute it, and nobody else.
Commands carry it in base64 with padding. It is a bearer secret: the
server keeps only its SHA-384 hash, and compares hashes in constant
time.

For each mailbox, the server keeps a set of token hashes for each
epoch number:

- CREATE gives the hash for the mailbox's first epoch: 0, or the epoch
  of a move (5.2, 7.8).
- A commit that the server accepts for epoch `e`, posted with a token of
  epoch `e`, or with `-` as an external commit in a public room (12.7),
  adds its `next` (5.2) to the set of epoch `e+1`.
- TOKEN (below) adds a hash to the set of epoch `e+1`, for anyone who
  holds a token of epoch `e`.
- POST checks a post's token against the set of the post's epoch.

```
TOKEN <box> <epoch> <token> <hash>
```

→ `OK`

Adds `<hash>`, a SHA-384 hash in base64 with padding, to the set of
epoch `<epoch>` + 1, if `<token>` is a send token of epoch `<epoch>`,
checked as for POST (5.2): `ERR not-found` for a mailbox that does not
exist, `ERR stale` for a token that is not in the set. `<epoch>` is a
number (3.3). TOKEN needs an anonymous or guest connection. A hash that
the set already holds gets `OK` and changes nothing. For the epoch just
before a moved mailbox's first epoch, the server checks the token
against the set of the mailbox the group moved from (7.8).

```
C: TOKEN ujzdegxdncf32epf3dhodzdoci 41 3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE= OWLXhHTd2X+O1uwHQ2Ylsj9LLdW2htn4UhwDp6x6TDrnYCbdMAQ4Hu4/aEVDqmGm
S: OK
```

Every device checks a commit's `next`, and a commit whose `next` is
wrong is invalid (12.7). So the set of the epoch that a valid commit
creates always holds that epoch's hash, unless the server has dropped it
(below). TOKEN is how members put it back:

- A device that holds the token of epoch `e`, and whose post for epoch
  `e+1` gets `ERR stale`, sends TOKEN with its hash of epoch `e+1`'s
  token, then posts again. This is how an epoch gets its hash back when
  someone who holds a token of the epoch before has pushed it out of
  the set with hashes of no use (below).
- It also repairs a moved mailbox whose first epoch has a wrong hash
  (7.8).

A member can add hashes that are of no use, but gains nothing by it,
since it can post already.

**Bounds.** The sets are bounded, so that nobody can fill the server's
storage with them, or push out the hashes that members use:

- A set holds at most 64 hashes. When a full set gets a new hash, the
  server drops the hash in it that was added first among those that no
  post has used, or, if every hash in it has been used, the one that a
  post used least recently.
- The server keeps each set until no hash in it has been added or used
  for a retention period (7.5). It MAY keep fewer sets, but then MUST
  keep at least the 256 sets of the mailbox that were used most
  recently, and drops the set used least recently first. A post for an
  epoch whose set is gone gets `ERR stale`.
- Servers MUST limit how many commits, and how many TOKEN commands, each
  connection and each network address sends.

In a public room the server checks every commit (12.6), so only one
commit wins each epoch, and it refuses another commit for an epoch that
already has one with `ERR stale`. In a direct conversation or a private
room it cannot check commits, since they are encrypted, and accepts
every commit that carries a valid token. Devices then decide:

- **The first valid commit wins.** Devices apply posts in seq order. For
  each epoch, the first commit whose checks pass (12.7) is the one they
  apply. They ignore later commits for the same epoch, and invalid ones,
  and messages of epochs that those commits would have started.
- **The checks are the same everywhere.** Whether a commit is valid
  depends only on its group checks (12.7): the group's state, the commit,
  and the `t` and `next` of its post. Checks against key files and the
  key log never make a commit invalid, since devices fetch those at
  different times; they only lead to repairs by later commits. So every
  device that sees the same posts picks the same commit, however late it
  looks.
- **A committer checks that it won.** After the `OK` of its commit, a
  device fetches the posts before it. If an earlier commit for the same
  epoch is valid, its own lost: it applies the winner, and makes its
  change again if it is still needed. Until it knows that its commit
  won, it MUST NOT send Welcomes for it (12.8), nor post anything in the
  epoch it creates, which would be lost with it.

This holds only if the server shows every device the same posts in the
same order. A server that shows different devices different commits for
an epoch splits the group, and each side sees only that the other has
gone quiet. Devices look for signs of it (12.7, 7.7), but cannot prevent
it (Section 14).

A removed member still holds the token of the epoch in which it was
removed, so the server would accept its posts there, and the commits it
chains from them, each of which names the hash of a token it chose. In
direct conversations and private rooms, the group therefore moves to a
new mailbox after a removal (7.8).

### 7.3. Pseudonyms

Each leaf has a **pseudonym**: 16 random bytes that its device picks
when it creates the leaf, and puts in the RisalaAAD (12.9) of every
PrivateMessage it posts in the group. A PublicMessage, whose sender the
server reads anyway (12.6), carries an empty pseudonym, so that it does
not tie the pseudonym to the leaf.

- A pseudonym belongs to its leaf, at its leaf index, from the commit
  that adds the leaf until the commit that removes it. A fresh leaf
  node, by commit or Update (12.3), does not change it, except in groups
  whose `confirm` is `epochal`.
- In an **epochal group** (12.10), pseudonyms last one period. A device
  picks a new pseudonym whenever its new leaf key of a period takes
  effect, and announces it in that period's ATTEST line. So the
  pseudonyms of different periods cannot be linked to each other from
  the posts.

The server sees pseudonyms, and can mute one (6.4). It does not learn
from a pseudonym whose leaf it is, but may guess it from timing and
network addresses: for example, from a public room's commits, which
show their leaves, and from the first post of a new pseudonym soon
after one of them (Section 14). It does not limit posts per pseudonym,
since anyone who holds the token can post under any pseudonym (5.2).

Members see pseudonyms too, since the RisalaAAD is authenticated by MLS.
A device pins each leaf's pseudonym: the one in the first PrivateMessage
it gets from that leaf, or in an epochal group, the one in the leaf's
ATTEST line for the current period, which must match the pseudonym of
the message that carries it. It ignores PrivateMessages from the leaf
that carry another. So a member cannot dodge a mute by changing it,
short of a new leaf, which needs an invitation in a private room and a
new join in a public one, or, in an epochal group, the next period.

### 7.4. Catching Up

For each mailbox, a device keeps a **sync point**: the seq up to which
it has applied every post the server still keeps. Posts it has stored
beyond the sync point, such as live posts that arrived while it was
catching up, do not move it.

A device catches up like this:

1. Open an anonymous connection, and send FOLLOW for each of its
   mailboxes, in a random order.
2. For each mailbox, let L be its sync point. If L is less than the
   head that FOLLOW reported, send `FETCH <box> after=F`, and repeat
   while the response says `more=1`. F is L less a random number of
   posts, from 0 to 20, and not less than 0, so that the sync points a
   device sends do not single it out. The posts up to L that come back
   are duplicates (step 3). After each page, the sync point moves
   forward to the last seq in it, and on over any stored posts that directly
   follow. If the response holds no post after L and says `more=0`,
   every post after L up to the head has expired (7.5), and the sync
   point moves to that head.
3. Live posts may arrive in the meantime. A duplicate has the same seq
   as the post already received, so it can be dropped. A live post moves
   the sync point only if it directly follows it.
4. Apply the posts in seq order (7.2), decrypting messages as 12.9 says.

If the first post returned after L is later than L + 1, the posts in
between have expired. If they include commits, the device can no longer
follow the group (7.5).

Each message carries its sender's counter and the id of the sender's
previous message (12.9). So devices notice a gap in a sender's messages
once a later message from that sender arrives. A gap that retention
explains is shown as expired, and one that a transfer from the
identity's own devices fills is not shown (12.13). Any other gap is
shown as messages that the server held back. The server can still hold
back a sender's last messages, or everything a sender posts from some
point on, without anyone noticing (Section 14).

A device that finds the head lower than its sync point discards its
sync point for that mailbox and starts again from 0. This cannot happen
with a correct server, but it keeps the device consistent.

**Not linking sessions.** The set of mailboxes a connection follows, the
order of its FOLLOWs, its sync points, its `quiet` tags and its `cid`s
stay much the same from one session of a device to the next, whatever
network address it uses. If any one of them is tied to the identity
once, every conversation it follows is, past and future (Section 14).
So, besides the random order and starting points above, devices SHOULD:

- wait a random time, of up to 10 minutes, before following a mailbox
  they learned of from a Welcome (12.8), so that the FOLLOW does not
  match the WELCOME line on the signed-in connection;
- close their anonymous and signed-in connections at independent random
  times, rather than all at once, and send QUIT (9.2) only on the
  connections they are closing;
- not send a `cid` again on another connection (7.6);
- leave `quiet` out of FOLLOW (9.2), and drop pushes that arrive while
  the app is showing the conversation, unless the battery cost is too
  high for the platform.

Spreading one device's mailboxes over several anonymous connections,
opened at different times, would help only together with these, and
only for devices that share their network address with others. It is
left for a version with Tor.

### 7.5. Retention

A server keeps a mailbox's posts for its retention period, which INFO
reports (8.5), and then deletes them. The period is at least 7 days, and
SHOULD be at least 30, so that devices that are offline for a while
still catch up. Files (5.6), blobs (12.12), mailbox push subscriptions
(9.1), and the Welcomes and pairing data that are waiting for someone
expire the same way, except that pairing data lasts 10 minutes (4.8),
and blobs and push subscriptions count from the last command that named
them.

A server expires a mailbox's posts in seq order, oldest first, so that
no post it keeps is older than one it has expired. It stops at the first
post that is not old enough, even if a later one has an older time. The
sequence numbers of expired posts are never reused. Copies kept for open
reports do not expire (5.8).

A device that has been offline for longer than the retention period
misses commits, and cannot follow its groups any more. In a public room
it joins again (6.1). In other conversations, its identity's other
devices replace its leaf at once, and other members' devices after 35
days (12.7): the device then gets a Welcome, as a new device does, and
asks its own devices for what it missed (12.13).

Retention is also the limit of what the server holds: once a post has
expired, nobody can fetch it, even with every key.

**Quotas.** Anyone can create a mailbox, and hold its token. So a server
MUST limit:

- the bytes it keeps for each mailbox, counting its kept posts and the
  files and blobs stored with its token (5.6, 12.12). INFO reports this
  limit as `quota=<bytes>` (8.5). When a mailbox is over its quota, the
  server either refuses new posts, files and blobs for it with
  `ERR rate-limited`, or expires its oldest posts early, which devices
  then see as expired (7.4).
- the bytes each network address stores in a sliding window, counting
  POST, UPLOAD and BLOB together (`ERR rate-limited`).

**Mailboxes end.** A mailbox whose posts have all expired, and which no
connection follows, has had no device of its group online for a whole
retention period, since devices commit at least weekly (12.7). Its group
cannot go on there. The server MAY delete such a mailbox, with its token
sets and push subscriptions. It never uses the box again (5.2). Deleting
a public room's mailbox ends the room and frees its name, as ADMIN DROP
does (10.4).

### 7.6. Resending Safely

A connection might drop after a client sends POST but before the OK
arrives. The client then cannot know whether the post went through. To
make resending safe:

- A client MAY tag POST with `cid=<token>`. The token is a random value
  of at least 16 characters, chosen anew for each post.
- If the same mailbox has had a post with that cid in the last 24 hours,
  the server MUST NOT create a new post. It replies `OK seq=<seq>` with
  the existing post's seq. It checks the cid before anything else about
  the post, including its token.
- The cid is not part of the post, and other connections never see it.
- A cid links the connections it is sent on, and a dropped connection
  is usually followed by a new one. So a device SHOULD NOT send a cid
  again on another connection. On the new connection, it fetches the
  mailbox to see whether the post arrived instead (7.4), and if it did
  not, posts the message again, encrypted afresh, with a new cid or
  none. For a commit, the fetch also says whether it won (7.2).

Devices also ignore a message whose `message_id` they have already seen
in the group (12.9), so a post that went through twice shows once.

### 7.7. Read Markers

A device that has shown a conversation up to a post tells the identity's
other devices with a READ line (12.9) in the conversation with itself:

```
READ <box> <seq> <check>
```

`<check>` is a short check of the epoch the device was in at `<seq>`
(12.9), so that an identity's devices notice if the server has put them
in different branches of a group (7.2). Read markers only move forward. Devices use them for unread counts and
to clear notifications that another device has already shown. Nobody
else sees them, and the server cannot read them.

### 7.8. Moving a Mailbox

A member that is removed from a group still knows the box, and still
holds the send token of the epoch in which it was removed. With them it
could follow the mailbox, see when the group talks and how much,
subscribe to its pushes, and post junk that the server keeps and pushes
to every member, chaining one junk commit to the next (7.2). So in a
direct conversation or a private room, the group moves to a new mailbox
after a removal, and the removed member never learns where. Public rooms
do not move: their box is public, and anyone not banned may join.

- **When.** After a commit that removes a leaf and does not add the same
  device back (12.7), the device that made it commits the move, as soon
  as its removal has won (7.2). If no move has won within 10 minutes of
  the removal, any member's device commits it, after a random wait of up
  to 10 minutes, unless another has done so first. When an identity
  leaves (6.1), the move follows the commit of its SelfRemove, and its
  own devices never make it. Devices SHOULD NOT let this move lapse
  after removing someone for abuse, who is the member most likely to
  flood the old mailbox. A group MAY also move at other times, for
  example when its mailbox is flooded.
- **How.** The device picks a new box (5.2) and makes a commit in the
  epoch that the removal created, or a later one, holding one
  GroupContextExtensions
  proposal that changes only the `box` of the conversation extension
  (12.4), and no other proposal. Before it posts this commit to the old
  mailbox, it creates the new mailbox with
  `CREATE <box> <group-id> <token-hash> epoch=<e>`, where `<e>` is the
  epoch the move creates, and `<token-hash>` the hash of that epoch's
  send token. The server accepts this only if it holds a mailbox of the
  same group id (`ERR not-found`), and links the new mailbox to the
  newest such one, for TOKEN (7.2).
- **Why the epoch after.** The removal is encrypted for an epoch the
  removed member is in, so it could read a new box there. The epoch the
  removal creates is the first one it cannot read.
- **Following.** A device that applies a move follows the new mailbox,
  and posts there from the move's epoch on. It keeps following the old
  mailbox for a day, for messages of earlier epochs that arrive late,
  then unfollows it, and deletes its push subscription for it (9.1). In
  the old mailbox, devices ignore posts for the move's epoch and later.
  The device that made a move follows both mailboxes until it knows
  whether its move won. A move that lost leaves a new mailbox that no
  one uses, which ends as 7.5 says.
- **Wrong hashes.** If the new mailbox does not take a member's token for
  the move's epoch, for example because whoever moved it gave a wrong
  hash, the member sends TOKEN to the new mailbox with its token of the
  epoch before, which the server checks against the old mailbox's set
  (7.2).

The server sees that a group moved, since the group id stays the same.
It can tell that someone left or was removed, but not who.

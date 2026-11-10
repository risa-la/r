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
  `<position>` (3.5) is the newest seq the server has given out in the
  mailbox, even if that post has expired (7.5), or `0` if it has given
  out none.
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
- **`leaf`** asks for a light client's view of a public room (12.6): the
  event line of each commit then carries an AnnotatedCommit for leaf
  `<n>` in place of the commit. A box that is not a public room's gets
  `ERR invalid`.

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
  holds a token of epoch `e`, outside public rooms.
- POST checks a post's token against the set of the post's epoch.

```
TOKEN <box> <epoch> <token> <hash>
```

→ `OK`

Adds `<hash>`, a SHA-384 hash in base64 with padding, to the set of
epoch `<epoch>` + 1, if `<token>` is a send token of epoch `<epoch>`,
checked as for POST (5.2): `ERR not-found` for a mailbox that does not
exist, `ERR stale` for a token that is not in the set, and for an
`<epoch>` of 2^63-1, which has no next epoch. `<epoch>` is a number
(3.3). TOKEN needs an anonymous or guest connection. A hash that the
set already holds gets `OK` and changes nothing. For the epoch just
before a moved mailbox's first epoch, the server checks the token
against the set of the mailbox the group moved from (7.8). In a public
room, the server checks every commit and takes one for each epoch, so a
wrong hash there leads to a resync (12.7), never to TOKEN: TOKEN for a
public room's mailbox gets `ERR forbidden`.

```
C: TOKEN m4qkz7xw2rjv5tbnhc3pfyd6ea 41 3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE= OWLXhHTd2X+O1uwHQ2Ylsj9LLdW2htn4UhwDp6x6TDrnYCbdMAQ4Hu4/aEVDqmGm
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
  the set with commits of no use (below).
- It also repairs a moved mailbox whose first epoch has a wrong hash
  (7.8).

A member can add hashes that are of no use, but gains nothing by it,
since it can post already.

**Bounds.** The sets are bounded, so that nobody can fill the server's
storage with them, or push out the hashes that members use:

- A set keeps the hashes that commits and CREATE added apart from those
  that TOKEN added: at most 16 of the first kind, and at most 64 of the
  second. When one part of a set is full and gets a new hash, the
  server drops from that part the hash that was added first among those
  that no post has used, or, if every hash in it has been used, the one
  that a post used least recently. So TOKEN never pushes out a hash
  that a commit added, and only further commits for the same epoch,
  each a post that the server keeps and limits, can do that.
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
  depends only on its group checks (12.7), which depend only on the
  group's state in the commit's epoch, the commit, and the `t` and
  `next` of its post (and the `t` of the posts of the proposals it
  applies). Implementations MUST NOT let validity depend on anything
  else, such as earlier epochs, key files, the key log or their own
  clock: checks against key files and the key log only lead to repairs
  by later commits. So every device that sees the same posts picks the
  same commit, whenever it joined the group and however late it looks.
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

Every PrivateMessage carries a **pseudonym** in its RisalaAAD (12.9):
16 bytes that stand for its sender's leaf, so that the server can mute
a sender without learning who it is (6.4). A PublicMessage, whose
sender the server reads anyway (12.6), carries an empty pseudonym, so
that it does not tie a pseudonym to a leaf.

- **Outside public rooms,** a leaf's pseudonym is derived anew in each
  epoch:

  ```
  pseudonym = MLS-Exporter("risala/1 pseudonym", leaf_index, 16)
  ```

  This is the exporter of the message's epoch [RFC9420], with the
  sender's leaf index as a `uint32` [RFC9420] for its context. Every
  member of the epoch computes it, and devices check it on each message
  rather than pin it (12.9). The server cannot compute it, and sees it
  change with every commit, so it cannot link a leaf's posts across
  commits from the posts alone. Every leaf is refreshed at least weekly
  (12.7), so a pseudonym lasts a week at most, and in an active group
  far less.
- **In a public room,** anyone can join and compute the exporter, the
  server included, so a derived pseudonym would hide nothing. There a
  device picks 16 random bytes as its leaf's pseudonym for each period
  (12.10), when its new leaf key of the period takes effect, and
  announces it in that period's ATTEST line. A device pins each leaf's
  pseudonym for a period: the one in its ATTEST line for the period,
  which must match the pseudonym of the message that carries it, or,
  for a leaf that sends without attesting, such as a guest's, the one
  in its first PrivateMessage of the period. It ignores PrivateMessages
  from the leaf that carry another in that period. So the pseudonyms of
  different periods cannot be linked to each other from the posts, and
  a member cannot dodge a mute by changing its pseudonym, short of a new
  join or the next period.

The server sees pseudonyms. It can mute one in a public room (6.4). An
operator's mute in another mailbox (10.4) lasts only until the next
commit, which changes every pseudonym there. The server does not learn
from a pseudonym whose leaf it is, but may guess it from timing and
network addresses: for example, from a public room's commits, which
show their leaves, and from the first post of a new pseudonym soon
after one of them (Section 14). It does not limit posts per pseudonym,
since anyone who holds the token can post under any pseudonym (5.2).
Members see pseudonyms too, since the RisalaAAD is authenticated by
MLS, and ignore a member's posts under any pseudonym but its own.

### 7.4. Catching Up

For each mailbox, a device keeps a **sync point**: the seq up to which
it has applied every post the server still keeps. Posts it has stored
beyond the sync point, such as live posts that arrived while it was
catching up, do not move it.

A device catches up like this:

1. Open an anonymous connection, and send FOLLOW for each of its
   mailboxes, in a random order.
2. For each mailbox, let L be its sync point. If L is less than the
   head that FOLLOW reported, send `FETCH <box> after=F`, and while the
   response says `more=1`, repeat it with `after=` the last seq of the
   page. F is L less a random number of posts, from 0 to 20, and not
   less than 0, so that the sync points a device sends do not single it
   out. The posts up to L that come back are duplicates (step 3). After
   each page, the sync point moves forward to the last seq in it, and on
   over any stored posts that directly follow. If the response holds no
   post after L and says `more=0`, every post after L up to the head has
   expired (7.5), and the sync point moves to that head.
3. Live posts may arrive in the meantime. A duplicate has the same seq
   as the post already received, so it can be dropped. A live post moves
   the sync point only if it directly follows it.
4. Apply the posts in seq order (7.2), decrypting messages as 12.9 says.

**Gaps.** If the first post returned after L is later than L + 1, or
every post after L up to the head has expired (step 2), posts after the
sync point expired before the device applied them. The device cannot
tell whether they included commits, so it treats the group as one it
can no longer follow (7.5), and applies nothing after the gap. Two
gaps do not count:

- **Posts that expired before the device joined.** A device that joins
  a group by Welcome (12.8) has no sync point in its mailbox until its
  first catch-up there, which fetches with `after=0`. Posts that expired
  before the first one that comes back, or before the head if none
  does, are not a gap: the device applies only the posts of its
  Welcome's epoch and later, and its sync point starts from there as
  step 2 says.
- **A gap in a mailbox the group has moved away from.** Once the device
  has applied a move (7.8), it follows the group's commits in the new
  mailbox. A gap in the old one can lose only late messages of earlier
  epochs there (12.9), which the device shows as expired.

Any other gap counts.

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
  times, each up to 10 minutes after the device stops needing it,
  rather than all at once, and send QUIT (9.2) only on the connections
  they are closing;
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

A device that finds that posts after its sync point expired before it
applied them cannot tell whether it missed commits, and so can no
longer follow the group (7.4). This happens to a device that has been
offline for longer than the retention period, or whose mailbox's posts
expired early under a quota (below). In a public room it joins again
(6.1). In other conversations, it asks its own devices at once: it sends
`RESYNC <box> <seq>` in the conversation with itself (12.9), where
`<box>` is the mailbox it found the gap in, and `<seq>` the first seq it
found after the gap, or the head if every post up to the head had
expired (7.4). Its identity's other devices then replace its leaf,
without waiting for the leaf to go stale (12.7). If it cannot follow the
conversation with itself either, it cannot ask, and its own devices
replace its leaf once it is stale; if its identity has no other device
in the group, only other members' devices replace it, after 35 days
(12.7). Either way, the device then gets a Welcome, as a new device
does, and asks its own devices for what it missed (12.13). A device that
is leaving the group, or whose user leaves it while the device cannot
follow it, sends no RESYNC, and leaves locally instead (6.1).

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

A server MAY also cap what it stores in all. Such a cap applies to
files and blobs alone (UPLOAD and BLOB, `ERR rate-limited`), and the
server keeps room beyond it for posts, so that when files and blobs
fill it, posts and commits still go through, and groups can go on.
Files and blobs kept for open reports (5.8) count apart, under a bound
of their own, so that reports cannot fill the server either.

**Mailboxes end.** A mailbox that was created more than a retention
period ago, whose posts have all expired, and which no connection
follows, has had no device of its group online for a whole retention
period, since devices commit at least weekly (12.7). Its group cannot
go on there. The server MAY delete such a mailbox, with its token sets
and push subscriptions, but no mailbox created more recently, even one
with no posts: a device that moves a group creates the new mailbox
before it follows it or posts there (7.8). The server never uses the
box again (5.2). Deleting a public room's mailbox ends the room and
frees its name, as ADMIN DROP does (10.4).

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
  not, posts it again, with a new cid or none: a message encrypted
  afresh, and a commit as it was (below). For a commit, the fetch also
  says whether it won (7.2).
- **A commit is posted again as it was.** A device whose POST of a
  commit went unanswered, and which finds that the commit has not
  arrived, posts the same commit again, not a new one. It keeps the
  commit's state, which it needs to apply the commit, until a commit
  for that epoch has been applied: its own, or one that came before it
  (7.2). The first POST may still reach the server after the device has
  looked, and win the epoch. A device that had made a new commit
  meanwhile could not apply the first one, and would apply its new one,
  which lost, and so leave the group without knowing it.
- **Unless it is too old.** A commit's `updated` must be within 10
  minutes of its post's `t` (12.3). So once more than 10 minutes have
  passed since a device made a commit, by the `t` of the posts it
  receives, any copy of it that reaches the server from then on,
  including a first POST that was held up on the way, fails that check
  wherever it lands, and cannot win the epoch; and the device's own
  checks would not let it post it again (12.7). If the commit has not
  arrived by then, the device MAY drop it and its state, and make a new
  one if the change is still needed.

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
- **Messages do not wait.** After another member's removal, a device
  sends its messages in the current epoch at once, in the mailbox the
  group is in, and does not hold them back until a move has won. The
  removed member cannot read them, and sees only that the group talks,
  as it could until the move anyway.
- **How.** The device makes a commit in the epoch that the removal
  created, or a later one, holding one GroupContextExtensions proposal
  that changes only the `box` of the conversation extension (12.4), and
  no other proposal. The new box is not chosen but derived, from the
  exporter of the epoch the commit is made in [RFC9420]:

  ```
  box = MLS-Exporter("risala/1 box", "", 16)
  ```

  Every member of that epoch computes it, and devices treat a move to
  any other box as invalid (12.7). So the removed member cannot learn
  it, and no member can move the group to a mailbox that cannot be
  used, such as another group's or one that is never created.
- **Creating it.** Before it posts the move to the old mailbox, the
  device creates the new one with
  `CREATE <box> <group-id> <token-hash> epoch=<e> from=<old> token=<token>`
  (5.2), where `<e>` is the epoch the move creates, `<token-hash>` the
  hash of that epoch's send token, `<old>` the old mailbox's box, and
  `<token>` the send token of epoch `<e>`-1. The server accepts this
  only if `<old>` is a mailbox with the same group id (`ERR not-found`)
  whose set for epoch `<e>`-1 holds `<token>` (`ERR stale`), and links
  the new mailbox to `<old>`, for TOKEN (7.2). So only a member of the
  epoch before the move can create it. If the box is already the
  mailbox of that group from epoch `<e>`, the server replies `OK` and
  changes nothing: two members who both move find the same box, and a
  member that finds the new mailbox missing after a move creates it the
  same way.
- **Why the epoch after.** The removal is encrypted for an epoch the
  removed member is in, so it could read a new box there. The epoch the
  removal creates is the first one it cannot read.
- **Following.** A device that applies a move follows the new mailbox,
  and posts there from the move's epoch on. It keeps following the old
  mailbox for a day, for messages of earlier epochs that arrive late,
  then unfollows it, deletes its push subscription for it (9.1), and
  deletes the secrets it kept for those epochs (12.9). In
  the old mailbox, devices ignore posts for the move's epoch and later,
  and judge the other posts that come after the move by the old
  mailbox's order alone (12.9).
  The device that made a move follows both mailboxes until it knows
  whether its move won. A move that lost leaves a new mailbox that no
  one uses, which ends as 7.5 says.
- **Wrong hashes.** If the new mailbox does not take a member's token for
  the move's epoch, for example because whoever created it gave a wrong
  hash, the member sends TOKEN to the new mailbox with its token of the
  epoch before, which the server checks against the old mailbox's set
  (7.2).

The server sees that a group moved, since the group id stays the same.
It can tell that someone left or was removed, but not who.

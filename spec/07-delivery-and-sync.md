## 7. Delivery and Sync

The server keeps a mailbox's posts only for its retention period (7.5).
There is no history on the server beyond that, and no command that lists
a person's conversations: devices know their own groups, and learn of
new ones from Welcomes (12.8).

### 7.1. Following and Fetching

```
FOLLOW <box> [quiet=<tag>]
UNFOLLOW <box>
FETCH <box> after=<seq> [limit=<n>] [leaf=<n>]
```

- **`FOLLOW`** sends the connection every new post of the mailbox from
  now on, as event lines (5.2), and replies `OK head=<seq>`, where
  `<seq>` is the mailbox's newest seq, or `0` if it has none. The `OK`
  agrees with the live posts as 3.6 says: every post newer than the head
  reaches the connection live. `quiet` names a push subscription that
  the server holds back while this connection follows (9.2).
- **`UNFOLLOW`** stops that, and replies `OK`. Following a mailbox the
  connection already follows, or unfollowing one it does not, gets `OK`.
- **`FETCH`** sends the earliest `limit` posts whose seq is greater than
  `after`, in ascending order, then `OK more=<0 or 1>`. `more=1` means
  there are more. `after` may be `0`. `limit` is at least 1 and
  defaults to 50. A server MAY return fewer posts than asked for.
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

- CREATE gives the hash for epoch 0 (5.2).
- A commit for epoch `e`, posted with a token of epoch `e`, adds the
  `next_token_hash` of its RisalaAAD (12.9) to the set of epoch `e+1`.
  The committer computes it from the epoch its commit creates.
- POST checks a post's token against the set of the post's epoch.
- The server keeps the sets of the newest 16 epoch numbers it has seen,
  and MAY forget older ones. A post for an epoch it has forgotten gets
  `ERR stale`.

In a public room the server checks every commit (12.6), so only one
commit wins each epoch, and it refuses another commit for an epoch that
already has one with `ERR stale`. In a direct conversation or a private
room it cannot check commits, since they are encrypted, and accepts
every commit that carries a valid token. Devices then decide:

- **The first valid commit wins.** Devices apply posts in seq order. For
  each epoch, the first commit whose checks pass (12.7) is the one they
  apply. They ignore later commits for the same epoch, and invalid ones,
  and messages of epochs that those commits would have started.
- **The checks are the same everywhere.** They depend only on the group
  and on facts that never go away once they exist, such as records in a
  key log. So every device that sees the same posts picks the same
  commit, however late it looks.
- **A committer checks that it won.** After the `OK` of its commit, a
  device fetches the posts before it. If an earlier commit for the same
  epoch is valid, its own lost: it applies the winner, and makes its
  change again if it is still needed.

A device that sends a commit's next token hash that does not match the
epoch the commit creates has made an invalid commit, which devices
ignore.

### 7.3. Pseudonyms

Each leaf has a **pseudonym**: 16 random bytes that its device picks
when it creates the leaf, and puts in the RisalaAAD (12.9) of everything
it posts in the group. The server sees it, and can count and limit posts
per pseudonym, or mute one (6.4), without knowing whose leaf it is.

Members see it too, since the RisalaAAD is authenticated by MLS. A
device remembers the first pseudonym it sees from each leaf, and ignores
posts from that leaf with any other. So a member cannot dodge a mute or
a limit by changing it, short of leaving and joining with a new leaf,
which needs an invitation in a private room and a new external join in a
public one.

### 7.4. Catching Up

For each mailbox, a device keeps a **sync point**: the seq up to which
it has applied every post the server still keeps. Posts it has stored
beyond the sync point, such as live posts that arrived while it was
catching up, do not move it.

A device catches up like this:

1. Open an anonymous connection, and send FOLLOW for each of its
   mailboxes.
2. For each mailbox, let L be its sync point. If L is less than the
   head that FOLLOW reported, send `FETCH <box> after=L`, and repeat
   while the response says `more=1`. After each page, the sync point
   moves to the last seq in it, and on over any stored posts that
   directly follow. If the response holds no posts and says `more=0`,
   every post after L up to the head has expired (7.5), and the sync
   point moves to that head.
3. Live posts may arrive in the meantime. A duplicate has the same seq
   as the post already received, so it can be dropped. A live post moves
   the sync point only if it directly follows it.
4. Apply the posts in seq order (7.2), decrypting messages as 12.9 says.

If the first post returned is later than L + 1, the posts in between
have expired. If they include commits, the device can no longer follow
the group (7.5).

The server cannot leave out a single message unnoticed: each message
carries its sender's counter and the id of the sender's previous message
(12.9), so devices see a gap in any one sender's messages. A gap that
retention explains is shown as expired. Any other gap is shown as
messages that the server held back.

A device that finds the head lower than its sync point discards its
sync point for that mailbox and starts again from 0. This cannot happen
with a correct server, but it keeps the device consistent.

### 7.5. Retention

A server keeps a mailbox's posts for its retention period, which INFO
reports (8.5), and then deletes them. The period is at least 7 days, and
SHOULD be at least 30, so that devices that are offline for a while
still catch up. Files (5.6), blobs (12.12) and the Welcomes and pairing
data that are waiting for someone expire the same way, except that
pairing data lasts 10 minutes (4.8).

A server expires a mailbox's posts in seq order, oldest first, so that
no post it keeps is older than one it has expired. It stops at the first
post that is not old enough, even if a later one has an older time. The
sequence numbers of expired posts are never reused. Copies kept for open
reports do not expire (5.8).

A device that has been offline for longer than the retention period
misses commits, and cannot follow its groups any more. In a public room
it joins again (6.1). In other conversations, the members' devices
replace its leaf (12.7): the device then gets a Welcome, as a new device
does.

Retention is also the limit of what the server holds: once a post has
expired, nobody can fetch it, even with every key.

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

Devices also ignore a message whose `message_id` they have already seen
in the group (12.9), so a post that went through twice shows once.

### 7.7. Read Markers

A device that has shown a conversation up to a post tells the identity's
other devices with a READ line (12.9) in the conversation with itself:

```
READ <box> <seq>
```

Read markers only move forward. Devices use them for unread counts and
to clear notifications that another device has already shown. Nobody
else sees them, and the server cannot read them.

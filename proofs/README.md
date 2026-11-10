# Proofs

Formal models of parts of the risala protocol. They model the spec
([`spec/`](../spec/README.md), draft-03), not the Rust code. Each model
checks claims that the spec makes, or that a client relies on, over
every possible interleaving of events, within small bounds.

The tools come with the dev shell (`nix develop`), as `tlc`.

[`archive/`](archive/) keeps models of earlier drafts, as history:
[`archive/draft-02-sync`](archive/draft-02-sync/README.md) modelled
draft-02's room sync, and its findings shaped draft-03's sync points,
cids and FOLLOW.

## delivery/

[`RisalaDelivery.tla`](delivery/RisalaDelivery.tla) models how a device
keeps a conversation's mailbox in step with the server. It covers:

- mailboxes, CREATE and POST (5.2)
- FOLLOW and FETCH (7.1), with FOLLOW's head agreeing with the live
  posts (3.6)
- epochs, send tokens, TOKEN, and the rule that the first valid commit
  wins (7.2)
- sync points and catching up (7.4)
- retention, and mailboxes that end (7.5)
- resending, with and without a cid (7.6)
- moving a mailbox (7.8)
- ADMIN DROP (10.4), and DROP as devices see it (6.1)

The model has one conversation, a direct conversation or private room,
whose commits the server cannot read: it takes every commit that carries
a valid token (7.2). It starts in one mailbox, and can move to the box
derived from the epoch the move is made in (7.8), so two moves made in
the same epoch find the same box. It observes one identity with up to
two devices. Each has one anonymous connection at a time, with one
command in flight. When a connection drops, a POST in flight is lost, or
reaches the server anyway and is handled later, its answer going
nowhere. Everyone else acts at any time: other members post, commit,
make commits that lose a race for an epoch, and move the mailbox;
retention expires posts; an operator drops mailboxes; the server ends
mailboxes as 7.5 allows.

Abstractions:

- An epoch state is named by the commit that started it, and its send
  token and hash by that same name.
- There is no clock. Retention expires the oldest post at any time, and
  cids are remembered for good, which covers resends within 24 hours.
- Other members are taken to follow every mailbox of the group, so the
  server ends only a mailbox they do not know. An operator drops at
  most one mailbox.
- The server handles FOLLOW, FETCH, CREATE and TOKEN as soon as they
  are sent: whatever could happen in between could as well happen
  before, and a connection that drops in between loses the command, as
  if it was never sent. POST is handled in a step of its own.
- Bounds: posts in each mailbox (`MaxPosts`), commits in all
  (`MaxCommits`), moves (`MaxMoves`), messages from other members
  (`MaxEnvMsgs`), and messages and commits the observed devices decide
  to post (`MaxOwn`). FETCH returns `PageSize` posts, and starts up to
  `Jitter` posts below the sync point.
- The server keeps the content of every post after it expires, as a
  ghost that only the properties read. The **canonical chain** is what
  "the first valid commit wins" gives over every post ever kept, the
  expired ones included: the epochs the group went through. A device
  that applies a commit outside it has split from the group.

It checks eight properties:

| Property | Meaning |
|---|---|
| `SyncPointSound` | A sync point never moves over a post the server still keeps that the device has not applied (7.4). |
| `CaughtUpHasAll` | A device that follows a mailbox, has caught up and has nothing left to read has applied every post the server still keeps there. |
| `NoMixedMailboxes` | A device's sync point and stored posts for a box only name posts the server gave out under that box. It holds by design: draft-03 never uses a box twice (5.2, 10.4). |
| `OnCanonicalChain` | A device that still follows the group is in one of the group's epochs: it never applies a commit that lost (7.2). |
| `OwnPostsCanonical` | A device posts only in the group's epochs, so that the other members read what it posts. |
| `CidOkIsOwn` | The OK for a cid names the device's own post (7.6). |
| `AtMostOnce` | Resending with a cid never creates a second copy (7.6). |
| `ConversationGoesOn` | A conversation ends for a device only if an operator dropped one of its mailboxes (10.4). |

The constant `Fixes` turns on the spec changes that TLC's findings led
to (below). They were proposals when the model was written, and are in
the spec since PLAN.md item 66; with `Fixes = {}` the model follows
draft-03 as it was before them.

| Fix | Change |
|---|---|
| `GapLost` | 7.4: a device that finds that posts after its sync point expired before it applied them treats the group as one it can no longer follow (7.5), and applies nothing after the gap. |
| `SameCommit` | 7.6: a device whose POST of a commit went unanswered, and which finds that the commit has not arrived, posts the same commit again, not a new one, and keeps the commit's state until a commit for that epoch has been applied. |
| `EndAfterUse` | 7.5: the server ends only a mailbox created more than a retention period ago. In the model: one that has had posts, all expired. |

Run it, one run at a time:

```
cd proofs/delivery
export JAVA_TOOL_OPTIONS=-Xmx4g   # cap TLC's memory
tlc -workers 1 -config AsWritten.cfg RisalaDelivery.tla           # draft-03 before item 66
tlc -workers 1 -config ProposedOneDevice.cfg RisalaDelivery.tla   # with all fixes, as the spec is now
tlc -workers 1 -config Proposed.cfg RisalaDelivery.tla            # the same, two devices
```

TLC stops at the first property that fails and prints the steps that
led there. With one worker, it gives the shortest trace. To see a later
finding, turn on the fixes for the earlier ones. Without the memory cap,
and with several workers, TLC can take most of a machine's memory.

## Results

These results are history: they are for draft-03 as it was before PLAN.md
item 66, which put the three fixes into the spec (7.4, 7.5, 7.6), with
the three wordings under "Found while modelling" (7.1, 7.4, 12.9). The
configuration names keep the old terms: `AsWritten.cfg` is the text
before item 66, and the `Proposed` ones are the spec as it is now.

Starting from the spec as written then (`Fixes = {}`) and turning on one
fix at a time, TLC finds the three problems below, each a shortest trace
with one device, in under 30 seconds. The constants are those of
`AsWritten.cfg`.

1. **A commit that lost, applied after a gap (7.2, 7.4, 7.5).** Another
   member commits for the group's epoch, and a second member, who has
   not yet seen that commit, commits for the same epoch too. The first
   wins: every device that sees both applies the first and ignores the
   second. The device has been away. Before it catches up, retention
   expires the first commit but not yet the second. Its FETCH returns
   the second commit with a gap before it, and the device applies it,
   since it is the first commit for its epoch that it sees. It has left
   the group without knowing it: what it posts from then on, others
   ignore. 7.4 says that a device can no longer follow the group if the
   expired posts include commits, but a device cannot tell what they
   included. 8 steps (`OnCanonicalChain`, 14,259 states, 1 second).
   Fixed by `GapLost`.
2. **A new mailbox ended before it was used (7.5, 7.8).** A device
   moves the group: it creates the new mailbox, and before it follows
   it or posts the move, the server ends it. Its posts have "all
   expired", since it has none, and no connection follows it. The move
   then wins, and the device finds the new mailbox missing. Creating it
   again, as 7.8 says, gets `name-taken`, since a box is never used
   again, so the conversation is over. 13 steps (`ConversationGoesOn`,
   350,956 states, 18 seconds, with `GapLost`). Fixed by `EndAfterUse`.
3. **The first copy of a commit wins after the device made a new one
   (7.6, 7.2).** A device posts a commit, and its connection drops
   before the OK. The POST still reaches the server, but has not been
   handled yet. On a new connection the device catches up, finds that
   its commit has not arrived, and, as 7.6 says, posts it again,
   encrypted afresh: for a commit, a new commit, which replaces the
   pending one, since MLS keeps one. The server then handles the first
   POST, and the old commit wins its epoch. The device cannot apply it,
   having dropped its state, and applies its new commit, which lost. It
   has left the group. 14 steps (`OnCanonicalChain`, 536,464 states, 27
   seconds, with `GapLost` and `EndAfterUse`). Fixed by `SameCommit`.
   A cid would avoid it, but 7.6 says not to send a cid again on another
   connection.

With all three fixes:

- One device (`ProposedOneDevice.cfg`, which has smaller bounds: 2
  posts in each mailbox, one move, one message from another member, and
  one message or commit from the device): TLC checked every reachable
  state, 12,175,060 distinct states to a depth of 63, in 13 minutes, and
  no property failed.
- Two devices (`Proposed.cfg`, the bounds of `AsWritten.cfg`): no
  property failed in 30,049,919 distinct states, to a depth of 18. This
  is not the complete state space: the run was stopped after about 40
  minutes.

What holds as written: the fixes do not change how sync points move or
how the server handles cids, and `SyncPointSound`, `CaughtUpHasAll`,
`CidOkIsOwn` and `AtMostOnce` held in every state of the one-device run. Sync points never
skip a post the server keeps, a device that has caught up has every
post, and cids behave, through dropped connections, posts handled after
their connection dropped, live posts during a FETCH, FETCH pages that
start below the sync point, retention, a move and DROP.

Two members who move in the same epoch find the same box, and the new
mailbox keeps the hash from whichever CREATE came first, which may be
the move that lost. TLC reaches the repair 7.8 describes (16 steps,
with every fix): the device's post there gets `ERR stale`, and its TOKEN,
checked against the old mailbox's set, puts the hash back. That needs
two moves, so the one-device run, with one move, does not cover it.

When the model was written, the Rust code already did what two of the
fixes ask: `librisala` posts a commit it has built again rather than a
new one, and the server ends only mailboxes that have not been created,
nor had a post, within the retention period. `librisala`'s FETCH
handling moved the sync point over a gap and went on applying posts, as
in finding 1; item 66 has it stop at the gap.

### Found while modelling

These came from reading the spec closely for the model. TLC does not
check them. Item 66 put each suggested wording into the spec.

- **FETCH's loop.** 7.4 says to send `FETCH <box> after=F` and repeat
  while the response says `more=1`, but not with what `after`. The
  model, like `librisala`, repeats with `after=` the last seq of the
  page. Sending F again would return the same page.
- **FOLLOW's head.** 7.1 says the head is the newest seq, "or `0` if it
  has none". Once every post has expired, a server could read that as
  0. A device whose sync point is above 0 would then start again from 0
  (7.4), which "cannot happen with a correct server", and would no
  longer see that posts expired. The server gives the newest seq it has
  given out. Suggested wording: "the newest seq it has given out, or `0`
  if it has given out none".
- **Late messages across a move.** 12.9 judges a late message by where
  it falls in the order of posts: whether a commit "with a lower seq"
  removed its sender, and the newest epoch applied "at the message's
  seq". After a move (7.8), a late message in the old mailbox and a
  commit in the new one have no common order. A device that applied a
  removal in the new mailbox before it read the late message, and one
  that read it first, can reach different results, which 12.9 says
  cannot happen. Suggested: a device judges a post in the old mailbox
  that comes after the move by the old mailbox's order alone, as of the
  move.

## Not modelled yet

- Public rooms, whose commits the server checks, taking one per epoch
  (12.6), and light clients (`leaf=`).
- The bounds on token sets (16 hashes from commits, 64 from TOKEN, 256
  sets), and members who flood them with commits or TOKEN commands that
  are of no use. The model's token sets are unbounded.
- Time: cids last 24 hours, devices follow an old mailbox for a day
  after a move, and late messages have their own limits (12.9).
- Welcomes and joining (12.8), pseudonyms (7.3), read markers (7.7),
  RELATED, and several commands in flight on one connection.
- Liveness: that a device that keeps its connection eventually catches
  up, and that its posts eventually go through. The model checks only
  that what it has done is right.

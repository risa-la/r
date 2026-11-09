# The draft-02 sync model (archived)

[`RisalaSync.tla`](RisalaSync.tla) models room sync in draft-02 of the
spec, which was then one file, `SPEC.md`: JOIN and PART, SYNC, HISTORY,
KICK, rooms whose history the server kept, DELETE, retention, resending
with cid, and ADMIN DROP followed by creating the room again. Draft-03
(`spec/`) replaced all of that with mailboxes of end-to-end encrypted
groups, so this model no longer describes the protocol. It is kept as
history. The section numbers below are draft-02's, and the model of
draft-03 is [`proofs/delivery`](../../delivery/RisalaDelivery.tla),
described in [`proofs/README.md`](../../README.md).

## What its findings led to

TLC found five problems in draft-02 (Results, below). Draft-03 was
written with them in mind:

1. **A HISTORY page from a different room.** Draft-03 names each
   mailbox by a random box that the server never uses again, even after
   ADMIN DROP (5.2, 10.4). A room created again under the same name is a
   new group with a new box, and devices compare its group id before
   joining (6.1). The server also checks each post's group id against
   its mailbox's (5.2).
2. **A gap that is never filled.** The proposed `ContiguousCursor` is
   draft-03's sync point (7.4): the seq up to which a device has applied
   every post the server still keeps. Posts stored beyond it, such as
   live posts that arrive while it catches up, do not move it.
3. **Another device's JOIN lands in old history.** There are no JOIN
   events: devices learn of their groups from Welcomes (12.8), and keep
   everything by box, which is never reused.
4. **Live events before SYNC answers.** FOLLOW's OK reports the
   mailbox's head and agrees with the live posts (3.6): every post sent
   before the OK is covered by it, and every post sent after is newer.
5. **A resent cid gets someone else's seq.** A cid matches only within
   one mailbox (7.6), as `CidPerRoom` proposed, and a box is never used
   again.

The note for client authors, that a client must remember what it asked
HISTORY for, became 7.4's rule that a FETCH page moves the sync point
only forward.

Run it as before, from this folder:

```
export JAVA_TOOL_OPTIONS=-Xmx4g   # cap TLC's memory
tlc -workers 1 -config AsWritten.cfg RisalaSync.tla
tlc -workers 1 -config ProposedOneDevice.cfg RisalaSync.tla
```

## The model as it was described

[`RisalaSync.tla`](RisalaSync.tla) models how a client keeps its
copy of a room in step with the server. It covers:

- live events (5.2)
- DELETE (5.4)
- JOIN and PART (6.1)
- KICK (6.4)
- SYNC (7.1)
- HISTORY (7.2)
- retention (7.5)
- resending with cid (7.6)
- ADMIN DROP followed by creating the room again (10.4)

The model has one room name, which can be dropped and created again. It
observes one identity with two devices. Everyone else (another user, a
moderator, an operator, retention) acts at any time.

It checks four properties:

| Property | Meaning |
|---|---|
| `NoMixedHistory` | A device never stores events from two different rooms under one name. |
| `SettledMeansCaughtUp` | When a device is in the room, has caught up and has nothing left to read, it has every event the server still keeps, with the right deleted state. |
| `CidOkIsOwnMessage` | The OK for a cid always names the client's own message. |
| `AtMostOnce` | Resending with a cid never creates a second copy. |

The constant `Fixes` turns on proposed spec changes, one at a time:

| Fix | Change |
|---|---|
| `HistoryId` | HISTORY's OK carries the room's id. A client ignores a page from another id and sends SYNC. |
| `JoinId` | JOIN events carry the room's id. A device that sees its own identity join with a new id discards what it stored first. |
| `ConfirmBeforeStore` | A device stores live events for a room only once it has learned the room's id on this connection. Earlier ones have a seq no higher than the head it is about to learn, so HISTORY returns them. |
| `ContiguousCursor` | In 7.1 step 3, L is the newest seq up to which the client has *everything*, not the newest seq it has stored. |
| `ResyncOnOwnJoin` | A device that sees its own identity join a room it was not in sends SYNC, then catches up. |
| `CidPerRoom` | A cid only matches within the room it was first sent to. |

TLC stops at the first property that fails and prints the steps that
led there. To see a particular property fail, list only it under
`INVARIANTS`. With one worker, TLC gives the shortest trace.

`AsWritten.cfg` fails within seconds. `Proposed.cfg` has no failure to
stop at, and with two devices its state space is too large to finish
(see Results), so give it a time limit, for example with `timeout 40m`.
With `Devices = {d1}` it finishes in about two minutes. Without the
memory cap, and with several workers, TLC can take most of a machine's
memory.

### Results

Starting from the spec as written (`Fixes = {}`) and turning on one fix
at a time, TLC finds the problems below. Each trace is the shortest TLC
found with one worker, in seconds to minutes. Some only show up once the
earlier ones are fixed.

1. **A HISTORY page from a different room (7.2, 10.4).** A device
   joins and starts catching up. Before its HISTORY request is handled,
   it is kicked, the room is dropped and someone creates it again. The
   page comes from the new room and nothing says so, so the device
   stores it with the old room's events. One device, 14 steps. Fixed by
   `HistoryId`.
2. **A gap that is never filled (7.1 step 3).** A device is catching
   up and stores a live event. Its connection drops before the HISTORY
   page arrives. On reconnect, L is "the newest seq stored", which is
   past the gap, so the device believes it is caught up and never
   fetches the events in between. One device, 14 steps, and no DROP is
   involved. This is the most likely of the five in practice. Fixed by
   `ContiguousCursor`.
3. **Another device's JOIN lands in old history (6.1, 7.1).** A device
   is kicked and keeps the room's history. The room is dropped (the
   device is not told, since it is not a member) and created again, and
   the identity joins it from its other device. The first device gets
   the new room's events live, with nothing to tell them apart, and
   stores them with the old ones. The duplicate rule in 7.1 step 5 even
   drops new events whose seq matches an old one. 19 steps. Fixed by
   `JoinId`.
4. **Live events before SYNC answers (7.1).** A device signs in while
   its identity is in a room that was dropped and created again since
   the device last saw it. Before the SYNC reply, the identity is
   kicked. The KICK arrives live, and SYNC then lists no such room, so
   the device never learns the new id and files the KICK under the old
   room. 20 steps. Fixed by `ConfirmBeforeStore`.
5. **A resent cid gets someone else's seq (7.6, 10.4).** A device
   sends a message, and the connection drops before the OK. The room is
   dropped. The device joins, which creates the room again, and resends
   with the same cid. The server finds the cid and answers with the seq
   from the old room. The message is lost, and the client thinks it has
   a seq that belongs to another event. One device, 26 steps. Fixed by
   `CidPerRoom`. The spec does not say what happens to cids when a room
   is dropped.

With all fixes (`Proposed.cfg`):

- Two devices, up to 3 events per room: no property failed in 68
  million distinct states, to a depth of 32 steps. This is not the
  complete state space. The run was stopped after 40 minutes.
- One device, up to 4 events per room: TLC checked every reachable
  state (3.5 million distinct states, up to 61 steps) and no property
  failed. This does not cover findings 3 and 4, which need two devices.

The model also showed one thing for client authors that needs no spec
change: a client must remember what it asked HISTORY for. If it starts a
room afresh (after DROP, say) while a request is in flight, the page that
comes back does not continue from where the client now is.

`ResyncOnOwnJoin` is not needed by any property above. Without it, a
device that sees its identity join from another device keeps receiving
live events but never fetches what it missed while it was out of the
room. That is a liveness problem, which the model does not check yet.

### Not modelled then

- RELATED (7.3), and clients that load only the newest page and fill
  older pages later (7.1 step 4).
- Direct conversations, which have no DROP but are written differently
  for each participant.
- Several requests in flight on one connection.
- Liveness: that a client that keeps its connection eventually catches
  up. The model checks only that it is right once it says it has.
- AUTH (4.5). TLA+ is a poor fit for an attacker who can relay messages.
  A Tamarin or ProVerif model of the signed bytes would be the right
  tool.

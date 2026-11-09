--------------------------- MODULE RisalaDelivery ---------------------------
(***************************************************************************)
(* How a device keeps a conversation's mailbox in step with the server,    *)
(* in draft-03 of the spec (spec/).                                        *)
(*                                                                         *)
(* Covers 5.2 (mailboxes, CREATE, POST), 7.1 (FOLLOW, FETCH), 7.2 (epochs, *)
(* send tokens, TOKEN, the first valid commit wins), 7.4 (sync points and  *)
(* catching up), 7.5 (retention, mailboxes that end), 7.6 (resending,      *)
(* cid), 7.8 (moving a mailbox), 3.6 (FOLLOW's head agrees with live       *)
(* posts) and 10.4 (ADMIN DROP).                                           *)
(*                                                                         *)
(* There is one conversation: a direct conversation or a private room,     *)
(* whose commits the server cannot read, so it takes every commit that     *)
(* carries a valid token (7.2). It starts in mailbox 0. A move made in     *)
(* epoch state k goes to mailbox MoveBox(k), since the box is derived from *)
(* that epoch (7.8): two moves made in the same epoch find the same box.   *)
(*                                                                         *)
(* An epoch state is named by the commit that started it, 0 for the       *)
(* group's first epoch. Commit ids grow, so a commit's id is greater than  *)
(* its parent's. The send token of state k, and its hash, are just k.      *)
(*                                                                         *)
(* One identity is observed, with the devices in Devices. Each has one     *)
(* anonymous connection at a time, with at most one command in flight. A   *)
(* connection that drops loses what is in flight, except that a POST the   *)
(* server has received may still be handled after the drop (an orphan),   *)
(* with its answer going nowhere. Everyone else is the environment: other  *)
(* members post and commit, sometimes for an epoch that another commit has *)
(* already started (a commit that loses), and move the mailbox; retention  *)
(* expires posts; an operator drops mailboxes; the server ends mailboxes   *)
(* as 7.5 allows. Other members are taken to follow every mailbox of the   *)
(* group, so the server ends only a mailbox they do not know.              *)
(*                                                                         *)
(* The server keeps every post's content after it expires or its mailbox  *)
(* is gone, as a ghost: the invariants read it, the devices never do. The  *)
(* canonical chain is what "the first valid commit wins" (7.2) gives over  *)
(* every post ever kept, the expired ones included: the epochs the group   *)
(* went through. A device that applies a commit outside it has split from  *)
(* the group.                                                              *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Devices,      \* the observed identity's devices
    MaxPosts,     \* most posts in one mailbox
    MaxCommits,   \* most commits made in all; bounds epochs
    MaxMoves,     \* most of those commits that move the mailbox
    MaxEnvMsgs,   \* most messages other members post
    MaxOwn,       \* most messages and commits the identity's devices decide to post
    PageSize,     \* the posts one FETCH returns (7.1's limit)
    Jitter,       \* most posts a first FETCH starts before the sync point (7.4: 20)
    Fixes         \* proposed spec changes to apply, see below

(***************************************************************************)
(* Fixes is a subset of these proposed changes to the spec. With           *)
(* Fixes = {} the model follows draft-03 as written.                       *)
(*                                                                         *)
(* "GapLost"     7.4: a device that finds that posts after its sync point  *)
(*               expired before it applied them (a gap) treats the group   *)
(*               as one it can no longer follow (7.5), and applies nothing *)
(*               after the gap. As written, it stops only if the gap holds *)
(*               commits, which it cannot tell; the model lets it stop     *)
(*               when a later post shows a later epoch than its own.       *)
(* "SameCommit"  7.6: a device whose POST of a commit went unanswered, and *)
(*               which then finds that the commit has not arrived, posts   *)
(*               the same commit again, not a new one. As written it posts *)
(*               "the message again, encrypted afresh": for a commit, a    *)
(*               new commit, which replaces the device's pending one.      *)
(* "EndAfterUse" 7.5: the server ends only a mailbox that has had posts,   *)
(*               all expired (in prose: one created more than a retention  *)
(*               period ago). As written, a mailbox whose posts have all   *)
(*               expired, and which no connection follows, may end, which  *)
(*               includes a new mailbox with no posts yet.                 *)
(***************************************************************************)
AllFixes == {"GapLost", "SameCommit", "EndAfterUse"}

ASSUME Fixes \subseteq AllFixes
ASSUME MaxPosts >= 1 /\ MaxCommits >= 1 /\ MaxOwn >= 0
ASSUME MaxMoves \in Nat /\ MaxEnvMsgs \in Nat
ASSUME PageSize >= 1 /\ Jitter \in Nat
ASSUME "env" \notin Devices

States == 0..MaxCommits
MoveBox(k) == k + 1
Boxes == 0..(MaxCommits + 1)
NoBox == MaxCommits + 2

VARIABLES
    mb,        \* mb[b]: mailbox b on the server, with its ghost log
    cinfo,     \* cinfo[k]: commit k: the state it was made in, whether it moves, who made it, its mailbox
    nextId,    \* the next commit id
    orphans,   \* POSTs from dropped connections that the server may still handle
    dv,        \* dv[d]: what device d keeps across connections
    cn,        \* cn[d]: device d's connection, both ends
    ownCount,  \* messages and commits the devices decided to post
    skipped,   \* ghost: a sync point moved over a post the server still keeps
    badAck     \* ghost: an OK named a post other than the one the device sent

vars == <<mb, cinfo, nextId, orphans, dv, cn, ownCount, skipped, badAck>>

-----------------------------------------------------------------------------
(* Helpers *)

Max(x, y) == IF x > y THEN x ELSE y
SetMax(S) == CHOOSE x \in S : \A y \in S : y <= x
SetMin(S) == CHOOSE x \in S : \A y \in S : x <= y

\* A device's mode: "in" the group, "lost" (it can no longer follow
\* the group, 7.5) or "ended" (its mailbox is gone).
In(d) == dv[d].mode = "in"

\* The epoch number of state k.
RECURSIVE Depth(_)
Depth(k) == IF k = 0 THEN 0 ELSE 1 + Depth(cinfo[k].ep)

\* A post: a message or commit made in state ep, by a device or "env". A
\* commit's id is the state it starts. m numbers a device's own message,
\* cid is its cid (0 for none).
Post(kind, ep, id, by, m, cid) ==
    [kind |-> kind, ep |-> ep, id |-> id, by |-> by, m |-> m, cid |-> cid]

NoMailbox == [status |-> "new", log |-> <<>>, lo |-> 0, tok |-> {},
              from |-> NoBox, first |-> 0, cids |-> {}]

\* CREATE (5.2): first is the mailbox's first epoch number, tok the hash it
\* is given, from the mailbox a moving group comes from.
NewMailbox(first, k, from) ==
    [status |-> "live", log |-> <<>>, lo |-> 0, tok |-> {k},
     from |-> from, first |-> first, cids |-> {}]

\* The posts the server still keeps: retention expires the oldest first (7.5).
Kept(b) == IF mb[b].status = "live" THEN (mb[b].lo + 1)..Len(mb[b].log) ELSE {}

\* "The first valid commit wins" (7.2), over every post ever kept, from
\* mailbox b's post i on, in state k. A move continues in the new mailbox;
\* devices ignore the old one's posts for the move's epoch and later (7.8).
RECURSIVE Walk(_, _, _, _, _)
Walk(b, i, k, sts, bxs) ==
    IF i > Len(mb[b].log) THEN [states |-> sts, st |-> k, box |-> b, boxes |-> bxs]
    ELSE LET p == mb[b].log[i] IN
         IF p.kind = "commit" /\ cinfo[p.id].ep = k
         THEN IF cinfo[p.id].move
              THEN Walk(MoveBox(k), 1, p.id, sts \cup {p.id}, bxs \cup {MoveBox(k)})
              ELSE Walk(b, i + 1, p.id, sts \cup {p.id}, bxs)
         ELSE Walk(b, i + 1, k, sts, bxs)

\* The canonical chain: the group's epochs, its current state and mailbox.
Canon == Walk(0, 1, 0, {0}, {0})

\* Whether the server takes a token of state p in mailbox b for TOKEN: from
\* b's sets, or, for the epoch just before a moved mailbox's first epoch,
\* from the old mailbox's (7.2, 7.8).
TokenCheck(b, p) ==
    IF mb[b].from # NoBox /\ Depth(p) + 1 = mb[b].first
    THEN mb[mb[b].from].status = "live" /\ p \in mb[mb[b].from].tok
    ELSE p \in mb[b].tok

\* b's token hashes after another member who holds a token of the state
\* before k has put k's hash back with TOKEN, if it was missing (7.2).
EnvTok(b, k) ==
    IF k \in mb[b].tok THEN mb[b].tok
    ELSE IF k # 0 /\ TokenCheck(b, cinfo[k].ep) THEN mb[b].tok \cup {k}
    ELSE mb[b].tok

\* The moves made so far, and the messages other members posted.
Moves == Cardinality({k \in 1..(nextId - 1) : cinfo[k].move})
EnvMsgs == Cardinality({<<b, s>> \in Boxes \X (1..MaxPosts) :
                          s <= Len(mb[b].log) /\ mb[b].log[s].by = "env" /\ mb[b].log[s].kind = "msg"})

\* Mailbox record r after it keeps post p: a commit adds its `next`, the
\* hash of the state it starts (7.2); a cid is remembered (7.6).
WithPost(r, p) ==
    [r EXCEPT !.log = Append(@, p),
              !.tok = IF p.kind = "commit" THEN @ \cup {p.id} ELSE @,
              !.cids = IF p.cid # 0 THEN @ \cup {<<p.cid, Len(r.log) + 1>>} ELSE @]

-----------------------------------------------------------------------------
(* Connections *)

NoReq == [op |-> "none"]
NoOut == [k |-> "none", m |-> 0, id |-> 0, move |-> FALSE, cid |-> 0, ep |-> 0, ph |-> "none"]

Offline == [up |-> FALSE, fol |-> {}, head |-> [b \in Boxes |-> 0], caught |-> {},
            req |-> NoReq, inbox |-> <<>>, sfol |-> {}]

\* The connections that follow b: sfol is the server's side of FOLLOW.
Followers(b) == {d \in Devices : cn[d].up /\ b \in cn[d].sfol}

\* The server sends `line` to every connection that follows b, then the
\* final response `resp` to d ("none" for no one). 3.6: the connection
\* that sent the command receives the post before its response.
Send(b, line, d, resp) ==
    [x \in Devices |->
        [cn[x] EXCEPT
            !.inbox = @ \o (IF x \in Followers(b) THEN <<line>> ELSE <<>>)
                        \o (IF x = d THEN <<resp>> ELSE <<>>),
            !.req = IF x = d THEN [@ EXCEPT !.done = TRUE] ELSE @]]

Reply(d, resp) ==
    [cn EXCEPT ![d].inbox = Append(@, resp), ![d].req.done = TRUE]

LiveLine(b, s) == [t |-> "post", b |-> b, s |-> s]

-----------------------------------------------------------------------------
(* The environment: other members, retention, operators *)

\* Another member posts a message in the group's current epoch.
EnvMsg ==
    LET c == Canon IN
    /\ EnvMsgs < MaxEnvMsgs
    /\ mb[c.box].status = "live" /\ Len(mb[c.box].log) < MaxPosts
    /\ c.st \in EnvTok(c.box, c.st)
    /\ mb' = [mb EXCEPT ![c.box] = WithPost([@ EXCEPT !.tok = EnvTok(c.box, c.st)],
                                            Post("msg", c.st, 0, "env", 0, 0))]
    /\ cn' = Send(c.box, LiveLine(c.box, Len(mb[c.box].log) + 1), "none", "none")
    /\ UNCHANGED <<cinfo, nextId, orphans, dv, ownCount, skipped, badAck>>

\* Another member commits in the group's current epoch, and may move the
\* group: it creates the new mailbox, unless it exists, then posts (7.8).
EnvCommit(move) ==
    LET c == Canon
        k == nextId
        nb == MoveBox(c.st)
    IN
    /\ k <= MaxCommits
    /\ mb[c.box].status = "live" /\ Len(mb[c.box].log) < MaxPosts
    /\ c.st \in EnvTok(c.box, c.st)
    /\ move => (Moves < MaxMoves /\ (mb[nb].status = "new" \/ mb[nb].status = "live"))
    /\ cinfo' = [cinfo EXCEPT ![k] = [ep |-> c.st, move |-> move, by |-> "env", box |-> c.box]]
    /\ nextId' = k + 1
    /\ mb' = [mb EXCEPT
                ![c.box] = WithPost([@ EXCEPT !.tok = EnvTok(c.box, c.st)],
                                    Post("commit", c.st, k, "env", 0, 0)),
                ![nb] = IF move /\ @.status = "new"
                        THEN NewMailbox(Depth(c.st) + 1, k, c.box) ELSE @]
    /\ cn' = Send(c.box, LiveLine(c.box, Len(mb[c.box].log) + 1), "none", "none")
    /\ UNCHANGED <<orphans, dv, ownCount, skipped, badAck>>

\* Another member commits for the epoch before the current one, not yet
\* having seen the commit that won it. The server takes it (7.2); devices
\* ignore it.
EnvRace ==
    LET c == Canon
        w == cinfo[c.st]
        k == nextId
    IN
    /\ c.st # 0 /\ k <= MaxCommits
    /\ mb[w.box].status = "live" /\ Len(mb[w.box].log) < MaxPosts
    /\ w.ep \in mb[w.box].tok
    /\ cinfo' = [cinfo EXCEPT ![k] = [ep |-> w.ep, move |-> FALSE, by |-> "env", box |-> w.box]]
    /\ nextId' = k + 1
    /\ mb' = [mb EXCEPT ![w.box] = WithPost(@, Post("commit", w.ep, k, "env", 0, 0))]
    /\ cn' = Send(w.box, LiveLine(w.box, Len(mb[w.box].log) + 1), "none", "none")
    /\ UNCHANGED <<orphans, dv, ownCount, skipped, badAck>>

\* Retention expires the oldest kept post (7.5).
Expire(b) ==
    /\ mb[b].status = "live" /\ mb[b].lo < Len(mb[b].log)
    /\ mb' = [mb EXCEPT ![b].lo = @ + 1]
    /\ UNCHANGED <<cinfo, nextId, orphans, dv, cn, ownCount, skipped, badAck>>

\* ADMIN DROP (10.4): DROP goes to every connection that follows it. To
\* bound the model, an operator drops at most one mailbox.
OpDrop(b) ==
    /\ mb[b].status = "live"
    /\ \A x \in Boxes : mb[x].status # "dropped"
    /\ mb' = [mb EXCEPT ![b].status = "dropped"]
    /\ cn' = [x \in Devices |->
                IF x \in Followers(b)
                THEN [cn[x] EXCEPT !.inbox = Append(@, [t |-> "drop", b |-> b]),
                                   !.sfol = @ \ {b}]
                ELSE cn[x]]
    /\ UNCHANGED <<cinfo, nextId, orphans, dv, ownCount, skipped, badAck>>

\* 7.5, "Mailboxes end": a mailbox whose posts have all expired, and which
\* no connection follows, may be deleted. Its box is never used again.
ServerEnd(b) ==
    /\ mb[b].status = "live"
    /\ mb[b].lo = Len(mb[b].log)
    /\ Followers(b) = {}
    /\ b \notin Canon.boxes          \* other members follow the group's mailboxes
    /\ "EndAfterUse" \in Fixes => Len(mb[b].log) > 0
    /\ mb' = [mb EXCEPT ![b].status = "ended"]
    /\ UNCHANGED <<cinfo, nextId, orphans, dv, cn, ownCount, skipped, badAck>>

-----------------------------------------------------------------------------
(* The server handling the devices' commands *)

\* What POST of p with the token of state tk to b leads to (5.2, 7.6). The
\* cid comes before anything else about the post.
PostOutcome(b, p, tk) ==
    LET dup == {e \in mb[b].cids : e[1] = p.cid} IN
    IF mb[b].status = "live" /\ p.cid # 0 /\ dup # {}
    THEN [r |-> "dup", seq |-> (CHOOSE e \in dup : TRUE)[2]]
    ELSE IF mb[b].status # "live" THEN [r |-> "err", code |-> "not-found"]
    ELSE IF tk \notin mb[b].tok THEN [r |-> "err", code |-> "stale"]
    ELSE IF Len(mb[b].log) >= MaxPosts THEN [r |-> "full"]   \* the model's bound only
    ELSE [r |-> "new", seq |-> Len(mb[b].log) + 1]

HandlePost(d, b, p, tk) ==
    LET o == PostOutcome(b, p, tk) IN
    /\ o.r # "full"
    /\ IF o.r = "new"
       THEN /\ mb' = [mb EXCEPT ![b] = WithPost(@, p)]
            /\ cn' = Send(b, LiveLine(b, o.seq), d, [t |-> "ok", seq |-> o.seq])
       ELSE /\ cn' = Reply(d, IF o.r = "dup" THEN [t |-> "ok", seq |-> o.seq]
                                             ELSE [t |-> "err", code |-> o.code])
            /\ UNCHANGED mb

\* A POST from a dropped connection: kept as any other, answered to no one.
HandleOrphan(o) ==
    LET r == PostOutcome(o.b, o.p, o.tk) IN
    /\ o \in orphans
    /\ r.r # "full"
    /\ orphans' = orphans \ {o}
    /\ IF r.r = "new"
       THEN /\ mb' = [mb EXCEPT ![o.b] = WithPost(@, o.p)]
            /\ cn' = Send(o.b, LiveLine(o.b, r.seq), "none", "none")
       ELSE UNCHANGED <<mb, cn>>
    /\ UNCHANGED <<cinfo, nextId, dv, ownCount, skipped, badAck>>

\* The server handles FOLLOW, FETCH, CREATE and TOKEN as soon as a device
\* sends them: what may happen in between could as well happen before, and
\* a connection that drops in between loses the command, as if it was never
\* sent. POST is handled in a step of its own, so that a dropped connection
\* can leave it to be handled later.

\* FOLLOW (7.1): its OK's head agrees with the live posts (3.6).
\* FETCH (7.1): the earliest PageSize kept posts after `after`, and more.
\* CREATE <box> <group-id> <hash k> epoch=<Depth(tk)+1> from=<from>
\* token=<tk> (5.2, 7.8): a box already the group's mailbox from that epoch
\* gets OK and nothing changes; a box seen before gets name-taken.
\* TOKEN <box> <epoch of p> <token p> <hash k> (7.2).
Resp(r) ==
    LET b == r.b
        live == mb[b].status = "live"
    IN
    CASE r.op = "follow" ->
            IF live THEN [t |-> "followed", b |-> b, head |-> Len(mb[b].log)]
            ELSE [t |-> "err", code |-> "not-found"]
      [] r.op = "fetch" ->
            IF live
            THEN LET s == {x \in Kept(b) : x > r.after}
                     page == IF s = {} THEN {} ELSE {x \in s : x < SetMin(s) + PageSize}
                 IN [t |-> "page", b |-> b, seqs |-> page, more |-> s # page]
            ELSE [t |-> "err", code |-> "not-found"]
      [] r.op = "create" ->
            IF live /\ mb[b].first = Depth(r.tk) + 1 THEN [t |-> "ok", seq |-> 0]
            ELSE IF mb[b].status # "new" THEN [t |-> "err", code |-> "name-taken"]
            ELSE IF mb[r.from].status # "live" \/ r.tk \notin mb[r.from].tok
            THEN [t |-> "err", code |-> "stale"]
            ELSE [t |-> "ok", seq |-> 0]
      [] r.op = "token" ->
            IF live /\ TokenCheck(b, r.p) THEN [t |-> "ok", seq |-> 0]
            ELSE [t |-> "err", code |-> IF live THEN "stale" ELSE "not-found"]

\* The mailboxes after the server handles r.
MbAfter(r) ==
    IF r.op = "create" /\ mb[r.b].status = "new" /\ Resp(r).t = "ok"
    THEN [mb EXCEPT ![r.b] = NewMailbox(Depth(r.tk) + 1, r.k, r.from)]
    ELSE IF r.op = "token" /\ Resp(r).t = "ok"
    THEN [mb EXCEPT ![r.b].tok = @ \cup {r.k}]
    ELSE mb

\* Connection record x once r is sent and handled.
Sent(x, r) ==
    [x EXCEPT !.req = [r EXCEPT !.done = TRUE],
              !.inbox = Append(@, Resp(r)),
              !.sfol = IF r.op = "follow" /\ mb[r.b].status = "live" THEN @ \cup {r.b} ELSE @]

\* POST, sent earlier.
Handle(d) ==
    LET r == cn[d].req IN
    /\ cn[d].up /\ r.op = "post" /\ ~r.done
    /\ HandlePost(d, r.b, r.p, r.tk)
    /\ UNCHANGED <<cinfo, nextId, orphans, dv, ownCount, skipped, badAck>>

-----------------------------------------------------------------------------
(* Devices: applying posts *)

\* What device d does with post s of mailbox b, from its local state ds.
\* Devices apply posts in seq order; in each epoch the first commit they
\* can apply wins, and they ignore later ones (7.2).
ApplyOne(d, ds, b, s) ==
    LET p == mb[b].log[s]
        mine == p.by = d /\ p.kind = "msg" /\ ds.out.k = "msg" /\ p.m = ds.out.m
    IN
    IF ds.mode # "in" THEN ds
    ELSE IF b # ds.cur
    THEN \* The old mailbox after a move: late messages change no state (7.8).
         IF mine THEN [ds EXCEPT !.out = NoOut] ELSE ds
    ELSE IF p.kind = "msg"
    THEN IF Depth(p.ep) > Depth(ds.st) THEN [ds EXCEPT !.mode = "lost"]   \* it missed a commit
         ELSE IF mine THEN [ds EXCEPT !.out = NoOut]
         ELSE ds
    ELSE LET c == cinfo[p.id] IN
         IF c.ep = ds.st
         THEN IF c.by = d /\ p.id # ds.pend
              THEN ds   \* its own commit, whose state it no longer has: it cannot apply it
              ELSE LET own == c.by = d
                       ds1 == [ds EXCEPT
                                 !.st = p.id,
                                 !.pend = 0,
                                 \* A commit of its own that lost is made again if
                                 \* it is still needed (7.2): a move is not, once
                                 \* another move has won.
                                 !.out = IF own THEN NoOut
                                         ELSE IF ds.out.k = "commit" /\ ds.out.move /\ c.move
                                         THEN NoOut
                                         ELSE IF ds.out.k = "commit"
                                         THEN [ds.out EXCEPT !.id = 0, !.ph = "ready"]
                                         ELSE ds.out]
                   IN IF c.move
                      THEN [ds1 EXCEPT !.prev = ds.cur, !.cur = MoveBox(c.ep),
                                       !.boxes = @ \cup {MoveBox(c.ep)}]
                      ELSE ds1
         ELSE IF Depth(c.ep) > Depth(ds.st) THEN [ds EXCEPT !.mode = "lost"]   \* it missed a commit
         ELSE ds

\* Applies the posts of b numbered i to hi that it holds (`have`).
RECURSIVE ApplyFrom(_, _, _, _, _, _)
ApplyFrom(d, ds, b, i, hi, have) ==
    IF i > hi THEN ds
    ELSE ApplyFrom(d, IF i \in have THEN ApplyOne(d, ds, b, i) ELSE ds, b, i + 1, hi, have)

\* n, moved on over the posts in `have` that directly follow it.
RECURSIVE RunOn(_, _)
RunOn(n, have) == IF n + 1 \in have THEN RunOn(n + 1, have) ELSE n

Local(d) == [mode |-> dv[d].mode, st |-> dv[d].st, pend |-> dv[d].pend, out |-> dv[d].out,
             cur |-> dv[d].cur, prev |-> dv[d].prev, boxes |-> dv[d].boxes]

\* dv[d] with its local state set to ds and b's sync point moved to n.
Moved(d, ds, b, n, have) ==
    [dv[d] EXCEPT !.mode = ds.mode, !.st = ds.st, !.pend = ds.pend, !.out = ds.out, !.cur = ds.cur,
                  !.prev = ds.prev, !.boxes = ds.boxes,
                  !.sp[b] = n,
                  !.stored[b] = {x \in have : x > n}]

\* Ghost: moving b's sync point from l to n skips a post the server keeps.
Skips(b, l, n, have) == \E x \in (l + 1)..n : x \notin have /\ x \in Kept(b)

-----------------------------------------------------------------------------
(* Devices: connections and catching up (7.4) *)

Idle(d) == cn[d].up /\ cn[d].req = NoReq

Connect(d) ==
    /\ ~cn[d].up /\ In(d)
    /\ cn' = [cn EXCEPT ![d] = [Offline EXCEPT !.up = TRUE]]
    /\ UNCHANGED <<mb, cinfo, nextId, orphans, dv, ownCount, skipped, badAck>>

\* The connection drops. A POST the server has not handled is lost, or
\* reaches the server anyway and waits to be handled (an orphan).
Disconnect(d) ==
    LET r == cn[d].req
        o == dv[d].out
        out1 == IF r.op = "post" /\ o.ph = "sent" THEN [o EXCEPT !.ph = "unknown"]
                ELSE IF r.op \in {"create", "token"} /\ o.ph \in {"creating", "token"}
                THEN [o EXCEPT !.ph = "ready"]
                ELSE o
    IN
    /\ cn[d].up
    /\ cn' = [cn EXCEPT ![d] = Offline]
    /\ dv' = [dv EXCEPT ![d].out = out1]
    /\ \/ UNCHANGED orphans
       \/ /\ r.op = "post" /\ ~r.done
          /\ orphans' = orphans \cup {[b |-> r.b, p |-> r.p, tk |-> r.tk]}
    /\ UNCHANGED <<mb, cinfo, nextId, ownCount, skipped, badAck>>

\* 7.4 step 1: FOLLOW each of its mailboxes.
ClientFollow(d, b) ==
    /\ Idle(d) /\ In(d)
    /\ b \in dv[d].boxes \ cn[d].fol
    /\ cn' = [cn EXCEPT ![d] = Sent(@, [op |-> "follow", b |-> b, done |-> FALSE])]
    /\ UNCHANGED <<mb, cinfo, nextId, orphans, dv, ownCount, skipped, badAck>>

\* 7.4 step 2: if the sync point L is below the head, FETCH after F, with F
\* up to Jitter posts below L.
ClientFetch(d, b) ==
    /\ Idle(d) /\ In(d)
    /\ b \in cn[d].fol /\ b \notin cn[d].caught
    /\ dv[d].sp[b] < cn[d].head[b]
    /\ \E f \in Max(0, dv[d].sp[b] - Jitter)..dv[d].sp[b] :
         cn' = [cn EXCEPT ![d] = Sent(@, [op |-> "fetch", b |-> b, after |-> f, done |-> FALSE])]
    /\ UNCHANGED <<mb, cinfo, nextId, orphans, dv, ownCount, skipped, badAck>>

RecvFollowed(d, l) ==
    /\ cn' = [cn EXCEPT ![d].fol = @ \cup {l.b},
                        ![d].head[l.b] = l.head,
                        ![d].caught = IF dv[d].sp[l.b] >= l.head THEN @ \cup {l.b} ELSE @,
                        ![d].req = NoReq,
                        ![d].inbox = Tail(@)]
    /\ UNCHANGED <<mb, dv, skipped, badAck>>

\* A FETCH page (7.4 step 2). The sync point moves forward to the last seq
\* in it, and on over stored posts that directly follow; if no post after
\* L came back and more=0, every post up to the head expired, and it moves
\* to the head. Repeat while more=1.
RecvPage(d, l) ==
    LET b == l.b
        L == dv[d].sp[b]
        after == {x \in l.seqs : x > L}
        have == dv[d].stored[b] \cup after
        n == IF after # {} THEN RunOn(SetMax(l.seqs), have)
             ELSE IF ~l.more THEN Max(L, cn[d].head[b])
             ELSE L
        gap == \/ (after # {} /\ SetMin(after) > L + 1)
               \/ (after = {} /\ ~l.more /\ cn[d].head[b] > L)
        ds == IF gap /\ "GapLost" \in Fixes
              THEN [Local(d) EXCEPT !.mode = IF @ = "in" THEN "lost" ELSE @]
              ELSE ApplyFrom(d, Local(d), b, L + 1, n, have)
    IN
    /\ dv' = [dv EXCEPT ![d] = Moved(d, ds, b, n, have)]
    /\ skipped' = (skipped \/ Skips(b, L, n, have))
    /\ cn' = [cn EXCEPT ![d] =
                LET x == [@ EXCEPT !.inbox = Tail(@)] IN
                IF l.more
                THEN Sent(x, [op |-> "fetch", b |-> b, after |-> SetMax(l.seqs), done |-> FALSE])
                ELSE [x EXCEPT !.req = NoReq, !.caught = @ \cup {b}]]
    /\ UNCHANGED <<mb, badAck>>

\* A live post (7.4 step 3): it moves the sync point only if it directly
\* follows it. A duplicate is dropped.
RecvLive(d, l) ==
    LET b == l.b
        L == dv[d].sp[b]
    IN
    /\ cn' = [cn EXCEPT ![d].inbox = Tail(@)]
    /\ IF b \notin dv[d].boxes \/ l.s <= L
       THEN UNCHANGED dv
       ELSE IF l.s = L + 1
       THEN LET have == dv[d].stored[b] \cup {l.s}
                n == RunOn(L, have)
            IN dv' = [dv EXCEPT ![d] = Moved(d, ApplyFrom(d, Local(d), b, L + 1, n, have), b, n, have)]
       ELSE dv' = [dv EXCEPT ![d].stored[b] = @ \cup {l.s}]
    /\ UNCHANGED <<mb, skipped, badAck>>

\* DROP (6.1, 10.4): the conversation cannot go on in that mailbox.
RecvDrop(d, l) ==
    /\ cn' = [cn EXCEPT ![d].inbox = Tail(@), ![d].fol = @ \ {l.b}, ![d].caught = @ \ {l.b}]
    /\ dv' = [dv EXCEPT ![d].boxes = @ \ {l.b},
                        ![d].mode = IF l.b = dv[d].cur /\ @ = "in" THEN "ended" ELSE @]
    /\ UNCHANGED <<mb, skipped, badAck>>

\* A mailbox that FOLLOW or FETCH finds missing. If it is the one the
\* device moved to, it creates it as the mover did (7.8); otherwise the
\* conversation cannot go on there.
Missing(d, b) ==
    LET k == dv[d].st
        r == [op |-> "create", b |-> b, k |-> k, from |-> dv[d].prev,
              tk |-> cinfo[k].ep, why |-> "retry", done |-> FALSE]
    IN
    IF b = dv[d].cur /\ In(d) /\ k # 0 /\ cinfo[k].move
    THEN /\ cn' = [cn EXCEPT ![d] = Sent([@ EXCEPT !.inbox = Tail(@)], r)]
         /\ mb' = MbAfter(r)
         /\ UNCHANGED dv
    ELSE /\ cn' = [cn EXCEPT ![d].inbox = Tail(@), ![d].req = NoReq]
         /\ dv' = [dv EXCEPT ![d].boxes = @ \ {b},
                             ![d].mode = IF b = dv[d].cur /\ @ = "in" THEN "ended" ELSE @]
         /\ UNCHANGED mb

-----------------------------------------------------------------------------
(* Devices: posting (5.2, 7.2, 7.6, 7.8) *)

DecideMsg(d) ==
    /\ In(d) /\ dv[d].out = NoOut /\ ownCount < MaxOwn
    /\ dv' = [dv EXCEPT ![d].out = [NoOut EXCEPT !.k = "msg", !.m = ownCount + 1, !.ph = "ready"]]
    /\ ownCount' = ownCount + 1
    /\ UNCHANGED <<mb, cinfo, nextId, orphans, cn, skipped, badAck>>

DecideCommit(d, move) ==
    /\ In(d) /\ dv[d].out = NoOut /\ ownCount < MaxOwn
    /\ move => Moves < MaxMoves
    /\ dv' = [dv EXCEPT ![d].out = [NoOut EXCEPT !.k = "commit", !.move = move, !.ph = "ready"]]
    /\ ownCount' = ownCount + 1
    /\ UNCHANGED <<mb, cinfo, nextId, orphans, cn, skipped, badAck>>

PostReq(b, p, tk) == [op |-> "post", b |-> b, p |-> p, tk |-> tk, done |-> FALSE]

\* A message, once the device has caught up on its mailbox. After a POST
\* that went unanswered and did not arrive, it posts the message again,
\* encrypted afresh in its current epoch, with a new cid or none; or,
\* though it SHOULD NOT, resends the same post with the same cid (7.6).
ClientPostMsg(d) ==
    LET o == dv[d].out
        s == dv[d].st
        b == dv[d].cur
    IN
    /\ Idle(d) /\ In(d) /\ b \in cn[d].caught
    /\ o.k = "msg" /\ o.ph \in {"ready", "unknown"}
    /\ \/ \E cid \in (IF o.ph = "unknown" THEN {0} ELSE {0, o.m}) :
            /\ dv' = [dv EXCEPT ![d].out = [o EXCEPT !.ph = "sent", !.cid = cid, !.ep = s]]
            /\ cn' = [cn EXCEPT ![d].req = PostReq(b, Post("msg", s, 0, d, o.m, cid), s)]
       \/ /\ o.ph = "unknown" /\ o.cid # 0
          /\ dv' = [dv EXCEPT ![d].out = [o EXCEPT !.ph = "sent"]]
          /\ cn' = [cn EXCEPT ![d].req = PostReq(b, Post("msg", o.ep, 0, d, o.m, o.cid), o.ep)]
    /\ UNCHANGED <<mb, cinfo, nextId, orphans, ownCount, skipped, badAck>>

\* A commit, made from its intent just before it is posted. MLS keeps one
\* pending commit, so a new one replaces the old. A move creates its
\* mailbox first (7.8).
ClientPostCommit(d) ==
    LET o == dv[d].out
        s == dv[d].st
        b == dv[d].cur
        same == /\ o.id # 0 /\ cinfo[o.id].ep = s /\ dv[d].pend = o.id
                /\ (o.ph = "ready" \/ "SameCommit" \in Fixes)
        k == IF same THEN o.id ELSE nextId
        \* A move creates its mailbox before its first POST. The same commit,
        \* posted again after an unanswered POST, needs no CREATE: the
        \* mailbox was created before, and the first copy may land anyway.
        create == o.move /\ ~(same /\ o.ph = "unknown")
    IN
    /\ Idle(d) /\ In(d) /\ b \in cn[d].caught
    /\ o.k = "commit" /\ o.ph \in {"ready", "unknown"}
    /\ k <= MaxCommits
    /\ (o.move /\ ~same) => Moves < MaxMoves
    /\ IF same THEN UNCHANGED <<cinfo, nextId>>
       ELSE /\ cinfo' = [cinfo EXCEPT ![k] = [ep |-> s, move |-> o.move, by |-> d, box |-> b]]
            /\ nextId' = k + 1
    /\ dv' = [dv EXCEPT ![d].pend = k,
                        ![d].out = [o EXCEPT !.id = k, !.ep = s,
                                             !.ph = IF create THEN "creating" ELSE "sent"]]
    /\ LET r == [op |-> "create", b |-> MoveBox(s), k |-> k, from |-> b, tk |-> s,
                 why |-> "move", done |-> FALSE]
       IN IF create
          THEN /\ cn' = [cn EXCEPT ![d] = Sent(@, r)]
               /\ mb' = MbAfter(r)
          ELSE /\ cn' = [cn EXCEPT ![d].req = PostReq(b, Post("commit", s, k, d, 0, 0), s)]
               /\ UNCHANGED mb
    /\ UNCHANGED <<orphans, ownCount, skipped, badAck>>

\* Ghost: whether OK seq=n for the POST in r names the post it sent.
Names(r, n) ==
    /\ n \in 1..Len(mb[r.b].log)
    /\ LET q == mb[r.b].log[n] IN
       q.by = r.p.by /\ q.kind = r.p.kind /\ q.m = r.p.m /\ q.id = r.p.id

\* The final response to the command in flight.
RecvResp(d, l) ==
    LET r == cn[d].req
        o == dv[d].out
        s == dv[d].st
        pop == [cn EXCEPT ![d].inbox = Tail(@), ![d].req = NoReq]
    IN
    CASE r.op = "follow" ->
            \* only an ERR gets here: FOLLOW's OK is a "followed" line
            Missing(d, r.b) /\ UNCHANGED <<skipped, badAck>>
      [] r.op = "fetch" ->
            Missing(d, r.b) /\ UNCHANGED <<skipped, badAck>>
      [] r.op = "post" ->
            /\ badAck' = (badAck \/ (l.t = "ok" /\ ~Names(r, l.seq)))
            /\ \/ /\ l.t = "ok"
                  /\ cn' = pop
                  /\ dv' = [dv EXCEPT ![d].out = IF o.ph = "sent" THEN [o EXCEPT !.ph = "posted"] ELSE o]
                  /\ UNCHANGED mb
               \/ /\ l.t = "err" /\ l.code = "stale" /\ o.ph = "sent"
                  \* 7.2: put the epoch's hash back with TOKEN and the token
                  \* of the epoch before, then post again; or catch up and
                  \* post again (3.7).
                  /\ IF In(d) /\ s # 0 /\ o.ep = s
                     THEN LET t == [op |-> "token", b |-> r.b, p |-> cinfo[s].ep, k |-> s, done |-> FALSE]
                          IN /\ cn' = [pop EXCEPT ![d] = Sent(@, t)]
                             /\ mb' = MbAfter(t)
                             /\ dv' = [dv EXCEPT ![d].out.ph = "token"]
                     ELSE /\ cn' = pop
                          /\ dv' = [dv EXCEPT ![d].out.ph = "ready"]
                          /\ UNCHANGED mb
               \/ /\ l.t = "err" /\ (l.code # "stale" \/ o.ph # "sent")
                  /\ cn' = pop
                  /\ dv' = [dv EXCEPT ![d].out = IF o.ph = "sent" THEN [o EXCEPT !.ph = "ready"] ELSE o]
                  /\ UNCHANGED mb
            /\ UNCHANGED skipped
      [] r.op = "create" /\ r.why = "move" ->
            /\ IF l.t = "ok" /\ o.ph = "creating"
               THEN /\ cn' = [pop EXCEPT ![d].req = PostReq(dv[d].cur, Post("commit", o.ep, o.id, d, 0, 0), o.ep)]
                    /\ dv' = [dv EXCEPT ![d].out.ph = "sent"]
                    /\ UNCHANGED mb
               ELSE \* The move cannot be made: the device gives it up.
                    /\ cn' = pop
                    /\ dv' = [dv EXCEPT ![d].out = IF o.ph = "creating" THEN NoOut ELSE o,
                                        ![d].pend = IF o.ph = "creating" THEN 0 ELSE @]
                    /\ UNCHANGED mb
            /\ UNCHANGED <<skipped, badAck>>
      [] r.op = "create" /\ r.why = "retry" ->
            /\ cn' = pop
            /\ IF l.t = "ok" THEN UNCHANGED dv
               ELSE dv' = [dv EXCEPT ![d].mode = IF @ = "in" THEN "ended" ELSE @]
            /\ UNCHANGED <<mb, skipped, badAck>>
      [] r.op = "token" ->
            /\ cn' = pop
            /\ dv' = [dv EXCEPT ![d].out = IF o.ph = "token" THEN [o EXCEPT !.ph = "ready"] ELSE o]
            /\ UNCHANGED <<mb, skipped, badAck>>

Recv(d) ==
    LET l == Head(cn[d].inbox) IN
    /\ cn[d].up /\ cn[d].inbox # <<>>
    /\ CASE l.t = "post"     -> RecvLive(d, l)
         [] l.t = "followed" -> RecvFollowed(d, l)
         [] l.t = "page"     -> RecvPage(d, l)
         [] l.t = "drop"     -> RecvDrop(d, l)
         [] l.t \in {"ok", "err"} -> RecvResp(d, l)
    /\ UNCHANGED <<cinfo, nextId, orphans, ownCount>>

-----------------------------------------------------------------------------
(* The system *)

Init ==
    /\ mb = [b \in Boxes |-> IF b = 0 THEN NewMailbox(0, 0, NoBox) ELSE NoMailbox]
    /\ cinfo = [k \in 1..MaxCommits |-> [ep |-> 0, move |-> FALSE, by |-> "env", box |-> 0]]
    /\ nextId = 1
    /\ orphans = {}
    /\ dv = [d \in Devices |->
               [mode |-> "in", st |-> 0, pend |-> 0, out |-> NoOut, cur |-> 0, prev |-> NoBox,
                boxes |-> {0}, sp |-> [b \in Boxes |-> 0], stored |-> [b \in Boxes |-> {}]]]
    /\ cn = [d \in Devices |-> Offline]
    /\ ownCount = 0
    /\ skipped = FALSE
    /\ badAck = FALSE

Next ==
    \/ EnvMsg \/ EnvCommit(FALSE) \/ EnvCommit(TRUE) \/ EnvRace
    \/ \E b \in Boxes : Expire(b) \/ OpDrop(b) \/ ServerEnd(b)
    \/ \E o \in orphans : HandleOrphan(o)
    \/ \E d \in Devices :
         \/ Connect(d) \/ Disconnect(d) \/ Handle(d) \/ Recv(d)
         \/ ClientPostMsg(d) \/ ClientPostCommit(d)
         \/ DecideMsg(d) \/ DecideCommit(d, FALSE) \/ DecideCommit(d, TRUE)
         \/ \E b \in Boxes : ClientFollow(d, b) \/ ClientFetch(d, b)

Spec == Init /\ [][Next]_vars

Sym == Permutations(Devices)

-----------------------------------------------------------------------------
(* Properties *)

\* 7.4: a sync point never moves over a post the server still keeps that
\* the device has not applied.
SyncPointSound == ~skipped

\* A device that follows a mailbox, has caught up, and has nothing left to
\* read or wait for, has applied every post the server still keeps there.
Settled(d, b) ==
    /\ cn[d].up /\ In(d)
    /\ b \in cn[d].fol /\ b \in cn[d].caught
    /\ mb[b].status = "live"
    /\ cn[d].req = NoReq /\ cn[d].inbox = <<>>

CaughtUpHasAll ==
    \A d \in Devices, b \in Boxes : Settled(d, b) => \A s \in Kept(b) : s <= dv[d].sp[b]

\* A device's sync point and stored posts of box b only ever name posts
\* the server gave out under b. This would fail if a box were used again,
\* with seqs from 1 again; draft-03 never uses a box twice (5.2, 10.4).
NoMixedMailboxes ==
    \A d \in Devices, b \in Boxes :
        /\ dv[d].sp[b] <= Len(mb[b].log)
        /\ dv[d].stored[b] \subseteq (dv[d].sp[b] + 1)..Len(mb[b].log)

\* 7.2: every device that still follows the group is in one of its epochs:
\* it never applies a commit that lost.
OnCanonicalChain ==
    \A d \in Devices : In(d) => dv[d].st \in Canon.states

\* 7.2: a device posts only in the group's epochs, so that others read
\* its posts (it MUST NOT post in an epoch it created before it knows
\* that its commit won).
OwnPostsCanonical ==
    \A b \in Boxes : \A s \in 1..Len(mb[b].log) :
        mb[b].log[s].by \in Devices => mb[b].log[s].ep \in Canon.states

\* 7.6: the OK for a cid names the client's own post.
CidOkIsOwn == ~badAck

\* 7.6: resending with a cid never creates a second copy.
AtMostOnce ==
    \A b \in Boxes : \A s, t \in 1..Len(mb[b].log) :
        (mb[b].log[s].cid # 0 /\ mb[b].log[s].cid = mb[b].log[t].cid) => s = t

\* A conversation ends for a device only if an operator dropped one of its
\* mailboxes (10.4). The model's other members follow the group's
\* mailboxes, so 7.5 ends none the group uses.
ConversationGoesOn ==
    \A d \in Devices : dv[d].mode = "ended" => \E b \in Boxes : mb[b].status = "dropped"

=============================================================================

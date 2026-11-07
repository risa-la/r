----------------------------- MODULE RisalaSync -----------------------------
(***************************************************************************)
(* How a client keeps its copy of a room in step with the server.          *)
(*                                                                         *)
(* Covers SPEC.md 5.2 (events), 5.4 (deleting), 6.1 (JOIN, PART), 6.4      *)
(* (KICK), 7.1 (SYNC), 7.2 (HISTORY), 7.5 (retention), 7.6 (cid) and 10.4  *)
(* (ADMIN DROP).                                                           *)
(*                                                                         *)
(* There is one room name. It can be dropped and created again, so it can  *)
(* have several incarnations, each with its own id and its own seq         *)
(* numbers starting at 1. In the model the id of an incarnation is just    *)
(* its number, `inc`.                                                      *)
(*                                                                         *)
(* One identity, "a", is observed. It has several devices, each with its   *)
(* own connection and its own local store. Everyone else is the            *)
(* environment: "b" creates the room, posts, edits, and also acts as the   *)
(* moderator who deletes and kicks and the operator who drops the room.    *)
(*                                                                         *)
(* The server handles one request at a time, so each server step is       *)
(* atomic. Each connection is a FIFO queue of lines from the server, plus  *)
(* at most one request in flight (the client waits for each response). A   *)
(* dropped connection loses both.                                          *)
(*                                                                         *)
(* Events carry a ghost field `inc`, the incarnation they came from. The   *)
(* client logic never reads it. Only the invariants do.                    *)
(***************************************************************************)
EXTENDS Naturals, Sequences, TLC

CONSTANTS
    Devices,          \* the devices of identity "a"
    MsgDevice,        \* the device that sends one message with a cid
    MaxSeq,           \* most events in one incarnation
    MaxInc,           \* most incarnations of the room
    PageSize,         \* the server's HISTORY page size
    Fixes             \* which proposed spec changes to apply, see below

(***************************************************************************)
(* Fixes is a subset of these proposed changes to SPEC.md. With Fixes = {} *)
(* the model follows the spec as written.                                  *)
(*                                                                         *)
(* "HistoryId"         HISTORY's OK carries the room's id. A client that   *)
(*                     gets a page from an id other than the one it        *)
(*                     stored ignores it and sends SYNC.                   *)
(* "ContiguousCursor"  In 7.1 step 3, L is the newest seq up to which the  *)
(*                     client has fetched or received everything, not the  *)
(*                     newest seq it has stored.                           *)
(* "ResyncOnOwnJoin"   A device that sees its own identity join a room it  *)
(*                     was not in (from another device) sends SYNC and     *)
(*                     catches up as after sign-in.                        *)
(* "JoinId"            JOIN events carry the room's id. A device that sees *)
(*                     its own identity join with an id other than the one *)
(*                     it stored discards what it stored first.            *)
(* "ConfirmBeforeStore" A device stores live events for a room only once it *)
(*                     has learned the room's id on this connection, from  *)
(*                     SYNC, JOIN's OK or (with "JoinId") its own JOIN.    *)
(*                     It drops earlier ones: their seq is at most the     *)
(*                     head that SYNC or JOIN's OK then reports, so        *)
(*                     HISTORY fetches them again.                         *)
(* "CidPerRoom"        The server matches a cid only within the room it    *)
(*                     was first sent to, so a dropped room's cids are     *)
(*                     forgotten.                                          *)
(***************************************************************************)
AllFixes == {"HistoryId", "JoinId", "ConfirmBeforeStore", "ContiguousCursor",
             "ResyncOnOwnJoin", "CidPerRoom"}

ASSUME MsgDevice \in Devices
ASSUME Fixes \subseteq AllFixes
ASSUME PageSize >= 1 /\ MaxSeq >= 1 /\ MaxInc >= 1

NoReq == [op |-> "none"]

VARIABLES
    \* Server
    exists,     \* whether the room exists right now
    inc,        \* the current (or last) incarnation, and so its id
    log,        \* the current incarnation's events, index = seq
    members,    \* subset of {"a", "b"}
    cidAt,      \* {} or {[inc, seq]}: where a's cid message landed
    \* Connections
    up,         \* up[d]: device d is connected and signed in
    req,        \* req[d]: the request in flight, or NoReq
    inbox,      \* inbox[d]: lines from the server not yet read
    \* Clients
    stId,       \* the room id the device has stored, 0 for none
    store,      \* function from seq to stored event
    known,      \* the "contiguous" cursor (unused for "newest")
    member,     \* whether the device believes "a" is a member
    waiting,    \* which response the device is waiting for
    caughtUp,   \* whether the device has finished catching up
    needResync, \* the device wants to send SYNC again
    msgState,   \* MsgDevice's message: unsent, waiting, unknown, acked, failed
    confirmed,  \* the device has learned the room's id on this connection
    \* Ghost
    badAck      \* MsgDevice got an OK that points at someone else's event

serverVars == <<exists, inc, log, members, cidAt>>
clientVars == <<stId, store, known, member, waiting, caughtUp, needResync, msgState, confirmed>>
vars == <<serverVars, up, req, inbox, clientVars, badAck>>

Max(x, y) == IF x > y THEN x ELSE y
Min(x, y) == IF x < y THEN x ELSE y

-----------------------------------------------------------------------------
(* Events *)

NewEv(kind, author, target, cid) ==
    [kind |-> kind, author |-> author, target |-> target, cid |-> cid,
     deleted |-> FALSE, expired |-> FALSE]

\* An event as the client sees it, in a live line or a HISTORY page.
\* `id` is the room id, which the client reads only from a JOIN and only
\* with "JoinId". `inc` is the ghost copy of it for the invariants.
Wire(s, e, i) ==
    [seq |-> s, kind |-> e.kind, author |-> e.author, target |-> e.target,
     deleted |-> e.deleted, id |-> i, inc |-> i]

EvLine(s, e) == [t |-> "ev", ev |-> Wire(s, e, inc)]

\* Retention removes the oldest events first, so expired events are a prefix.
FirstLive ==
    IF \E s \in 1..Len(log) : ~log[s].expired
    THEN CHOOSE s \in 1..Len(log) : ~log[s].expired /\ \A t \in 1..(s - 1) : log[t].expired
    ELSE Len(log) + 1

Present(s) == ~log[s].expired /\ ~log[s].deleted

\* 7.2, with `after`: the earliest PageSize events after `after`.
HistLine(after) ==
    LET lo == Max(after + 1, FirstLive)
        hi == Min(Len(log), lo + PageSize - 1)
    IN [t |-> "hist",
        evs |-> [i \in 1..(hi - lo + 1) |-> Wire(lo + i - 1, log[lo + i - 1], inc)],
        more |-> hi < Len(log),
        id |-> inc,
        after |-> after]   \* not on the wire: the client remembers what it asked

-----------------------------------------------------------------------------
(* Delivery *)

\* "a"'s open connections, if "a" is in `mem`. 5.2: every new event goes
\* to every connection of every member.
AConns(mem) == IF "a" \in mem THEN {d \in Devices : up[d]} ELSE {}

Send(ds, l) == [d \in Devices |-> IF d \in ds THEN Append(inbox[d], l) ELSE inbox[d]]

\* An event to `ds`, then the response to `d`, which made the request.
SendAndReply(d, ds, l, resp) ==
    [x \in Devices |->
        inbox[x] \o (IF x \in ds THEN <<l>> ELSE <<>>) \o (IF x = d THEN <<resp>> ELSE <<>>)]

Reply(d, resp) == inbox' = [inbox EXCEPT ![d] = Append(@, resp)]

-----------------------------------------------------------------------------
(* The environment: other people, moderators, operators, retention *)

Appendable == exists /\ Len(log) < MaxSeq

\* "b" acts only while it is in the room.
BActs == Appendable /\ "b" \in members

AppendEv(e) ==
    /\ log' = Append(log, e)
    /\ inbox' = Send(AConns(members), EvLine(Len(log) + 1, e))

OthersMsg ==
    /\ BActs
    /\ AppendEv(NewEv("msg", "b", 0, FALSE))
    /\ UNCHANGED <<exists, inc, members, cidAt, up, req, clientVars, badAck>>

OthersEdit ==
    /\ BActs
    /\ \E m \in 1..Len(log) :
         /\ log[m].kind = "msg" /\ log[m].author = "b" /\ Present(m)
         /\ AppendEv(NewEv("edit", "b", m, FALSE))
    /\ UNCHANGED <<exists, inc, members, cidAt, up, req, clientVars, badAck>>

\* 5.4: deleting a message also deletes its edits.
ModDelete ==
    /\ BActs
    /\ \E m \in 1..Len(log) :
         /\ log[m].kind \in {"msg", "edit"} /\ Present(m)
         /\ LET hit(s) == s = m \/ (log[m].kind = "msg" /\ log[s].kind = "edit" /\ log[s].target = m)
                marked == [s \in 1..Len(log) |->
                             IF hit(s) THEN [log[s] EXCEPT !.deleted = TRUE] ELSE log[s]]
                e == NewEv("delete", "b", m, FALSE)
            IN /\ log' = Append(marked, e)
               /\ inbox' = Send(AConns(members), EvLine(Len(log) + 1, e))
    /\ UNCHANGED <<exists, inc, members, cidAt, up, req, clientVars, badAck>>

\* 6.4: the KICK goes to the target before they stop receiving the room.
ModKickA ==
    /\ BActs /\ "a" \in members
    /\ AppendEv(NewEv("kick", "b", 0, FALSE))
    /\ members' = members \ {"a"}
    /\ UNCHANGED <<exists, inc, cidAt, up, req, clientVars, badAck>>

Expire ==
    /\ exists /\ FirstLive <= Len(log)
    /\ log' = [log EXCEPT ![FirstLive].expired = TRUE]
    /\ UNCHANGED <<exists, inc, members, cidAt, up, req, inbox, clientVars, badAck>>

\* 10.4: DROP goes to every connection in the room. No event is recorded.
\* The spec does not say what happens to cids, so they are kept.
OperatorDrop ==
    /\ exists
    /\ inbox' = Send(AConns(members), [t |-> "drop"])
    /\ exists' = FALSE /\ log' = <<>> /\ members' = {}
    /\ UNCHANGED <<inc, cidAt, up, req, clientVars, badAck>>

OthersJoin ==
    /\ Appendable /\ "b" \notin members
    /\ AppendEv(NewEv("join", "b", 0, FALSE))
    /\ members' = members \cup {"b"}
    /\ UNCHANGED <<exists, inc, cidAt, up, req, clientVars, badAck>>

OthersCreate ==
    /\ ~exists /\ inc < MaxInc
    /\ exists' = TRUE /\ inc' = inc + 1
    /\ log' = <<NewEv("join", "b", 0, FALSE)>> /\ members' = {"b"}
    /\ UNCHANGED <<cidAt, up, req, inbox, clientVars, badAck>>

-----------------------------------------------------------------------------
(* The server handling a's requests *)

HandleSync(d) ==
    /\ Reply(d, [t |-> "sync", member |-> exists /\ "a" \in members,
                 id |-> inc, head |-> Len(log)])
    /\ UNCHANGED serverVars

HandleHistory(d, after) ==
    /\ Reply(d, IF exists THEN HistLine(after) ELSE [t |-> "err"])
    /\ UNCHANGED serverVars

HandleJoin(d) ==
    LET e == NewEv("join", "a", 0, FALSE) IN
    \/ /\ ~exists /\ inc < MaxInc   \* 6.1: creates the room
       /\ exists' = TRUE /\ inc' = inc + 1 /\ log' = <<e>> /\ members' = {"a"}
       /\ inbox' = SendAndReply(d, AConns({"a"}), [t |-> "ev", ev |-> Wire(1, e, inc + 1)],
                                [t |-> "joinok", id |-> inc + 1, head |-> 1])
       /\ UNCHANGED cidAt
    \/ /\ exists /\ "a" \notin members /\ Len(log) < MaxSeq
       /\ log' = Append(log, e) /\ members' = members \cup {"a"}
       /\ inbox' = SendAndReply(d, AConns(members'), EvLine(Len(log) + 1, e),
                                [t |-> "joinok", id |-> inc, head |-> Len(log) + 1])
       /\ UNCHANGED <<exists, inc, cidAt>>
    \/ /\ exists /\ "a" \in members   \* already a member: no event
       /\ Reply(d, [t |-> "joinok", id |-> inc, head |-> Len(log)])
       /\ UNCHANGED serverVars
    \/ /\ (~exists /\ inc = MaxInc) \/ (exists /\ "a" \notin members /\ Len(log) = MaxSeq)
       /\ Reply(d, [t |-> "err"])     \* only the model's bounds get here
       /\ UNCHANGED serverVars

HandlePart(d) ==
    \/ /\ Appendable /\ "a" \in members
       /\ log' = Append(log, NewEv("part", "a", 0, FALSE))
       /\ inbox' = SendAndReply(d, AConns(members),
                                EvLine(Len(log) + 1, NewEv("part", "a", 0, FALSE)), [t |-> "ok"])
       /\ members' = members \ {"a"}
       /\ UNCHANGED <<exists, inc, cidAt>>
    \/ /\ ~(Appendable /\ "a" \in members)
       /\ Reply(d, [t |-> "err"])
       /\ UNCHANGED serverVars

\* 7.6: a cid the identity has used before gets OK with the existing seq.
\* cidAt holds every place the cid landed (more than one only with
\* "CidPerRoom").
HandleMsg(d) ==
    LET seen == {c \in cidAt : "CidPerRoom" \notin Fixes \/ c.inc = inc} IN
    \/ /\ exists /\ "a" \in members /\ seen # {}
       /\ LET c == CHOOSE c \in seen : TRUE
          IN Reply(d, [t |-> "msgok", seq |-> c.seq, good |-> c.inc = inc])
       /\ UNCHANGED serverVars
    \/ /\ Appendable /\ "a" \in members /\ seen = {}
       /\ LET e == NewEv("msg", "a", 0, TRUE)
          IN /\ log' = Append(log, e)
             /\ inbox' = SendAndReply(d, AConns(members), EvLine(Len(log) + 1, e),
                                      [t |-> "msgok", seq |-> Len(log) + 1, good |-> TRUE])
       /\ cidAt' = cidAt \cup {[inc |-> inc, seq |-> Len(log) + 1]}
       /\ UNCHANGED <<exists, inc, members>>
    \/ /\ ~(exists /\ "a" \in members) \/ (seen = {} /\ Len(log) = MaxSeq)
       /\ Reply(d, [t |-> "err"])
       /\ UNCHANGED serverVars

Handle(d) ==
    /\ up[d] /\ req[d] # NoReq
    /\ req' = [req EXCEPT ![d] = NoReq]
    /\ CASE req[d].op = "sync"    -> HandleSync(d)
         [] req[d].op = "history" -> HandleHistory(d, req[d].after)
         [] req[d].op = "join"    -> HandleJoin(d)
         [] req[d].op = "part"    -> HandlePart(d)
         [] req[d].op = "msg"     -> HandleMsg(d)
    /\ UNCHANGED <<up, clientVars, badAck>>

-----------------------------------------------------------------------------
(* Clients *)

Newest(st) ==
    IF DOMAIN st = {} THEN 0 ELSE CHOOSE s \in DOMAIN st : \A t \in DOMAIN st : t <= s

Set(f, d, v) == [f EXCEPT ![d] = v]

\* Sign in, then send SYNC straight away (7.1 step 1).
Connect(d) ==
    /\ ~up[d]
    /\ up' = Set(up, d, TRUE)
    /\ req' = Set(req, d, [op |-> "sync"])
    /\ waiting' = Set(waiting, d, "sync")
    /\ caughtUp' = Set(caughtUp, d, FALSE)
    /\ needResync' = Set(needResync, d, FALSE)
    /\ confirmed' = Set(confirmed, d, FALSE)
    /\ UNCHANGED <<serverVars, inbox, stId, store, known, member, msgState, badAck>>

\* The connection drops. A request not yet handled is lost, and so is a
\* response not yet read.
Disconnect(d) ==
    /\ up[d]
    /\ up' = Set(up, d, FALSE)
    /\ inbox' = Set(inbox, d, <<>>)
    /\ req' = Set(req, d, NoReq)
    /\ waiting' = Set(waiting, d, "none")
    /\ caughtUp' = Set(caughtUp, d, FALSE)
    /\ needResync' = Set(needResync, d, FALSE)
    /\ msgState' = IF d = MsgDevice /\ waiting[d] = "msg" THEN "unknown" ELSE msgState
    /\ confirmed' = Set(confirmed, d, FALSE)
    /\ UNCHANGED <<serverVars, stId, store, known, member, badAck>>

Idle(d) == up[d] /\ waiting[d] = "none"

Request(d, r, w) == req' = Set(req, d, r) /\ waiting' = Set(waiting, d, w)

ClientResync(d) ==
    /\ Idle(d) /\ needResync[d]
    /\ Request(d, [op |-> "sync"], "sync")
    /\ needResync' = Set(needResync, d, FALSE)
    /\ UNCHANGED <<serverVars, up, inbox, stId, store, known, member, caughtUp, msgState, confirmed, badAck>>

ClientJoin(d) ==
    /\ Idle(d) /\ ~member[d]
    /\ Request(d, [op |-> "join"], "join")
    /\ UNCHANGED <<serverVars, up, inbox, stId, store, known, member, caughtUp, needResync, msgState, confirmed, badAck>>

ClientPart(d) ==
    /\ Idle(d) /\ member[d]
    /\ Request(d, [op |-> "part"], "part")
    /\ UNCHANGED <<serverVars, up, inbox, stId, store, known, member, caughtUp, needResync, msgState, confirmed, badAck>>

\* Send the message, or resend it with the same cid after a drop (7.6).
ClientMsg ==
    /\ Idle(MsgDevice) /\ member[MsgDevice] /\ msgState \in {"unsent", "unknown"}
    /\ Request(MsgDevice, [op |-> "msg"], "msg")
    /\ msgState' = "waiting"
    /\ UNCHANGED <<serverVars, up, inbox, stId, store, known, member, caughtUp, needResync, confirmed, badAck>>

\* A live event. 7.1 step 5: a seq already stored is a duplicate and is
\* dropped.
RecvEv(d, w) ==
    LET own    == (w.kind \in {"join", "part"} /\ w.author = "a") \/ w.kind = "kick"
        joined == own /\ w.kind = "join"
        left   == own /\ w.kind \in {"part", "kick"}
        \* "a" joined on another device while this one was not in the room
        joinedElsewhere == joined /\ ~member[d] /\ waiting[d] # "join"
        \* "JoinId": a JOIN into a room with a new id starts it afresh
        reset == "JoinId" \in Fixes /\ joined /\ w.id # stId[d]
        st == IF reset THEN <<>> ELSE store[d]
        kn == IF reset THEN 0 ELSE known[d]
        \* "ConfirmBeforeStore": keep the event only if the id is known
        keep == \/ "ConfirmBeforeStore" \notin Fixes
                \/ confirmed[d]
                \/ ("JoinId" \in Fixes /\ joined)
        fresh == keep /\ w.seq \notin DOMAIN st
    IN
    /\ store' = Set(store, d, IF fresh THEN (w.seq :> w) @@ st ELSE st)
    /\ known' = Set(known, d, IF "ContiguousCursor" \in Fixes /\ keep /\ w.seq = kn + 1
                              THEN w.seq ELSE kn)
    /\ confirmed' = Set(confirmed, d, IF left THEN FALSE
                                      ELSE IF "JoinId" \in Fixes /\ joined THEN TRUE
                                      ELSE confirmed[d])
    /\ stId' = IF reset THEN Set(stId, d, w.id) ELSE stId
    /\ member' = Set(member, d, IF joined THEN TRUE ELSE IF left THEN FALSE ELSE member[d])
    /\ needResync' = IF joinedElsewhere /\ "ResyncOnOwnJoin" \in Fixes THEN Set(needResync, d, TRUE) ELSE needResync
    /\ caughtUp' = IF left \/ joinedElsewhere THEN Set(caughtUp, d, FALSE) ELSE caughtUp
    /\ UNCHANGED <<req, waiting, msgState, badAck>>

\* A CONV line from SYNC (7.1) or the OK of JOIN (6.1). Both give the id
\* and head. The spec only states the id check for SYNC; the model also
\* applies it to JOIN, to give the client the benefit of the doubt.
RecvHead(d, isMember, id, head) ==
    IF isMember THEN
        LET reset == id # stId[d] \/ Newest(store[d]) > head   \* 7.1 step 2
            st    == IF reset THEN <<>> ELSE store[d]
            kn    == IF reset THEN 0 ELSE known[d]
            l     == IF "ContiguousCursor" \in Fixes THEN kn ELSE Newest(st)
        IN /\ store' = Set(store, d, st)
           /\ known' = Set(known, d, kn)
           /\ stId' = Set(stId, d, id)
           /\ member' = Set(member, d, TRUE)
           /\ IF l < head   \* 7.1 step 3
                THEN /\ Request(d, [op |-> "history", after |-> l], "history")
                     /\ caughtUp' = Set(caughtUp, d, FALSE)
                ELSE /\ waiting' = Set(waiting, d, "none")
                     /\ caughtUp' = Set(caughtUp, d, TRUE)
                     /\ UNCHANGED req
           /\ confirmed' = Set(confirmed, d, TRUE)
           /\ UNCHANGED <<needResync, msgState, badAck>>
    ELSE \* Not in the room. The client keeps what it has stored.
        /\ member' = Set(member, d, FALSE)
        /\ confirmed' = Set(confirmed, d, FALSE)
        /\ waiting' = Set(waiting, d, "none")
        /\ caughtUp' = Set(caughtUp, d, FALSE)
        /\ UNCHANGED <<req, stId, store, known, needResync, msgState, badAck>>

\* A HISTORY page. Its events replace what is stored, since they show the
\* current state (deleted placeholders). Repeat while more=1.
RecvHist(d, l) ==
    IF "HistoryId" \in Fixes /\ l.id # stId[d]
    THEN \* A page from another room with the same name. Start again.
         /\ waiting' = Set(waiting, d, "none")
         /\ caughtUp' = Set(caughtUp, d, FALSE)
         /\ needResync' = Set(needResync, d, TRUE)
         /\ confirmed' = Set(confirmed, d, FALSE)
         /\ UNCHANGED <<req, stId, store, known, member, msgState, badAck>>
    ELSE
    LET n    == Len(l.evs)
        seqs == {l.evs[i].seq : i \in 1..n}
        st   == [s \in DOMAIN store[d] \cup seqs |->
                   IF s \in seqs THEN l.evs[CHOOSE i \in 1..n : l.evs[i].seq = s]
                   ELSE store[d][s]]
        last == l.evs[n].seq
        \* With "ContiguousCursor", the page moves the cursor only if it was
        \* asked for from the cursor. A page asked for before the device
        \* started the room afresh (after a DROP, say) does not, and the
        \* device asks again from the cursor.
        contig == "ContiguousCursor" \in Fixes
        stale  == contig /\ l.after # known[d]
    IN /\ store' = Set(store, d, st)
       /\ known' = IF contig /\ ~stale /\ n > 0 THEN Set(known, d, last) ELSE known
       /\ IF stale
            THEN /\ Request(d, [op |-> "history", after |-> known[d]], "history")
                 /\ UNCHANGED caughtUp
          ELSE IF l.more
            THEN /\ Request(d, [op |-> "history", after |-> last], "history")
                 /\ UNCHANGED caughtUp
            ELSE /\ waiting' = Set(waiting, d, "none")
                 /\ caughtUp' = Set(caughtUp, d, TRUE)
                 /\ UNCHANGED req
       /\ UNCHANGED <<stId, member, needResync, msgState, confirmed, badAck>>

RecvOk(d) ==
    /\ waiting' = Set(waiting, d, "none")
    /\ UNCHANGED <<req, stId, store, known, member, caughtUp, needResync, msgState, confirmed, badAck>>

RecvErr(d) ==
    /\ waiting' = Set(waiting, d, "none")
    /\ msgState' = IF d = MsgDevice /\ waiting[d] = "msg" THEN "failed" ELSE msgState
    /\ UNCHANGED <<req, stId, store, known, member, caughtUp, needResync, confirmed, badAck>>

RecvMsgOk(d, l) ==
    /\ waiting' = Set(waiting, d, "none")
    /\ msgState' = "acked"
    /\ badAck' = (badAck \/ ~l.good)
    /\ UNCHANGED <<req, stId, store, known, member, caughtUp, needResync, confirmed>>

\* 10.4: clients SHOULD remove the room and its history.
RecvDrop(d) ==
    /\ store' = Set(store, d, <<>>)
    /\ stId' = Set(stId, d, 0)
    /\ known' = Set(known, d, 0)
    /\ member' = Set(member, d, FALSE)
    /\ caughtUp' = Set(caughtUp, d, FALSE)
    /\ confirmed' = Set(confirmed, d, FALSE)
    /\ UNCHANGED <<req, waiting, needResync, msgState, badAck>>

Recv(d) ==
    /\ up[d] /\ inbox[d] # <<>>
    /\ inbox' = Set(inbox, d, Tail(inbox[d]))
    /\ LET l == Head(inbox[d]) IN
       CASE l.t = "ev"     -> RecvEv(d, l.ev)
         [] l.t = "sync"   -> RecvHead(d, l.member, l.id, l.head)
         [] l.t = "joinok" -> RecvHead(d, TRUE, l.id, l.head)
         [] l.t = "hist"   -> RecvHist(d, l)
         [] l.t = "ok"     -> RecvOk(d)
         [] l.t = "err"    -> RecvErr(d)
         [] l.t = "msgok"  -> RecvMsgOk(d, l)
         [] l.t = "drop"   -> RecvDrop(d)
    /\ UNCHANGED <<serverVars, up>>

-----------------------------------------------------------------------------
(* The system *)

Init ==
    /\ exists = TRUE /\ inc = 1
    /\ log = <<NewEv("join", "b", 0, FALSE)>>
    /\ members = {"b"}
    /\ cidAt = {}
    /\ up = [d \in Devices |-> FALSE]
    /\ req = [d \in Devices |-> NoReq]
    /\ inbox = [d \in Devices |-> <<>>]
    /\ stId = [d \in Devices |-> 0]
    /\ store = [d \in Devices |-> <<>>]
    /\ known = [d \in Devices |-> 0]
    /\ member = [d \in Devices |-> FALSE]
    /\ waiting = [d \in Devices |-> "none"]
    /\ caughtUp = [d \in Devices |-> FALSE]
    /\ needResync = [d \in Devices |-> FALSE]
    /\ msgState = "unsent"
    /\ confirmed = [d \in Devices |-> FALSE]
    /\ badAck = FALSE

Next ==
    \/ OthersMsg \/ OthersEdit \/ ModDelete \/ ModKickA
    \/ OthersJoin \/ Expire \/ OperatorDrop \/ OthersCreate
    \/ ClientMsg
    \/ \E d \in Devices :
         \/ Connect(d) \/ Disconnect(d) \/ Handle(d) \/ Recv(d)
         \/ ClientResync(d) \/ ClientJoin(d) \/ ClientPart(d)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

\* A connected device with nothing left to read or wait for holds only
\* events from the room whose id it stored, not from an earlier or later
\* room with the same name.
\*
\* Live events carry no room id, so a device can briefly store one before
\* the line that gives the id (the JOIN event comes before JOIN's OK). If
\* the connection drops in between, the stale mix stays until the next
\* SYNC discards it. The check skips those windows. What a device stores
\* before it knows any id (stId = 0) is also skipped: the first SYNC or
\* JOIN OK gives a different id, so it gets discarded.
Quiet(d) == up[d] /\ waiting[d] = "none" /\ ~needResync[d] /\ inbox[d] = <<>>

NoMixedHistory ==
    \A d \in Devices : (Quiet(d) /\ stId[d] # 0) =>
        \A s \in DOMAIN store[d] : store[d][s].inc = stId[d]

\* Whether the device would show event s as deleted, from what it stored.
ClientDeleted(d, s) ==
    LET st == store[d]
        e  == st[s]
        deletedBy(x) == \E t \in DOMAIN st : st[t].kind = "delete" /\ st[t].target = x
    IN \/ e.deleted
       \/ deletedBy(s)
       \/ /\ e.kind = "edit"
          /\ \/ deletedBy(e.target)
             \/ (e.target \in DOMAIN st /\ st[e.target].deleted)

Settled(d) ==
    /\ up[d] /\ exists /\ "a" \in members
    /\ member[d] /\ caughtUp[d] /\ ~needResync[d]
    /\ waiting[d] = "none" /\ inbox[d] = <<>>

\* A device that is in the room, has caught up and has nothing left to
\* read has the server's view: every event the server still keeps, with
\* the right deleted state.
SettledMeansCaughtUp ==
    \A d \in Devices : Settled(d) =>
        /\ stId[d] = inc
        /\ \A s \in 1..Len(log) : ~log[s].expired =>
             /\ s \in DOMAIN store[d]
             /\ store[d][s].inc = inc
             /\ store[d][s].kind = log[s].kind
             /\ store[d][s].author = log[s].author
             /\ ClientDeleted(d, s) = log[s].deleted

\* 7.6: the OK for a cid always names the client's own message.
CidOkIsOwnMessage == ~badAck

\* 7.6: resending never creates a second copy.
AtMostOnce ==
    \A s, t \in 1..Len(log) : (log[s].cid /\ log[t].cid) => s = t

=============================================================================

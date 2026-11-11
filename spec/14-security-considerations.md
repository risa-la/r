## 14. Security Considerations

This section lists what risala protects, what the server and others can
still do, and the risks it accepts. Appendix D sums it up by adversary.

- **Zero trust in the server.** Devices take nothing that matters from
  the server: not membership, roles or settings (12.4, 12.7), not whose
  keys are whose (4.5, 12.14), and not who wrote a message (12.9,
  12.10). What the server can still do is listed below, and devices can
  see most of it. The largest exception is public rooms, where only the
  server checks who commits as whom, so that it can commit in an
  owner's name (below).

- **What is encrypted end to end.** Every conversation, public rooms
  included (Section 12). The server cannot read messages, files, display
  names in private conversations, topics, typing, read markers, blocks
  or reports to moderators. Anyone can join a public room, so a server
  that wants to read one can join it under an identity of its own, like
  anyone else. Its leaf then shows in the room's membership, which is
  public, to every full client. A light client shows only the members
  it holds proofs for, and the server's member list only as the
  server's word, since the server could leave its own leaf out (12.6).
  Encryption still keeps a public room's messages from an operator who
  does not join, or who is compelled to hand over what it stores, and
  keeps the server from changing them.

- **Post-quantum.** Connections use a hybrid key exchange (2.1), and
  groups X-Wing (12.2). Both stay secret as long as either their
  classical or their post-quantum half holds, so traffic recorded today
  cannot be decrypted later by a quantum computer. Signatures are
  ML-DSA-44, and so are the key log's checkpoints and its witnesses'
  cosignatures (4.5). Two things are still classical: TLS certificates,
  since certificate authorities issue no other kind yet, so a quantum
  attacker could impersonate a server in real time, but not read what is
  encrypted end to end; and the encryption of push bodies, which is P-256
  (9.3) and hides only which mailbox has news.

- **Forward secrecy and post-compromise security.** Each message has its
  own key, which devices delete once they have used it (12.9), and
  devices delete a past epoch's secrets once they have applied the third
  epoch after it, once posts arrive more than an hour after the commit
  that ended it, and in any case once they have caught up after the
  server's time has passed 2 hours after that commit (12.9). So a device
  stolen today does not decrypt what the server stored earlier. A device
  that goes offline keeps the secrets of its last 2 past epochs until it
  next catches up, since it judges by the server's time and not its own
  clock; they decrypt only messages of those epochs that it has not
  received, since it deleted each key it used. Commits give
  post-compromise security: once a device has committed a fresh leaf,
  which it does at least weekly (12.7), keys stolen earlier do not
  decrypt new messages. Healing is as frequent as commits, not every
  round trip as in a double ratchet.

- **No history on the server.** The server holds ciphertext for its
  retention period only (7.5), and new members of a room cannot read
  what came before. History lives on devices, decrypted, so a device
  that is taken while unlocked gives up the history it holds. Devices
  SHOULD keep their stores encrypted under keys held in hardware.

- **Backups.** A backup (12.13) is readable by whoever has the recovery
  key, and is not forward secret. The server is not trusted to delete
  what it is told to, so whoever gets the recovery key can read every
  backup the server has kept, replaced and deleted ones included. The
  server holds only encrypted blobs. A restoring device takes the
  backup's generation from the key log, so the server cannot hand it a
  backup made with the key of a removed or lost device. Within one
  generation, the server can hand it an older backup than the newest,
  and the device only shows when the backup was made. Someone who
  steals a device can make a backup in that device's generation until
  the device is removed, and a device that restores it shows its
  messages as they were backed up, marked as restored.

- **Recovery keys.** The recovery key derives the master key, which can
  replace every device of the identity, and the backup keys. Whoever
  holds it controls the identity, so it should be stored like a
  password, offline. Devices never keep it (4.8). Changing it means a
  new master key, which every contact sees as such (12.14).

- **Pairing.** The pairing QR code holds a secret that the server never
  sees, and the reply is sealed to a key that never leaves the new
  device (4.8). So someone who sees the QR code, even together with the
  server, learns nothing from the reply. They can still answer first,
  with a bundle for an identity of their own, since the QR code holds
  all they need to build one. The new device then shows that identity's
  uid and devices, and asks its user to confirm before it does anything,
  and the device that scanned the code tells its user that someone else
  answered (4.8).

- **Deniability.** Nothing an identity publishes signs a message or a
  leaf key (4.3, 12.3), and members confirm leaves in ways that convince
  only themselves (12.10). So a message that leaks does not prove to a
  third party who wrote it. The limits:
  - In groups whose `confirm` is `epochal`, a message is deniable only
    once its period key is published, up to about two days after it was
    sent: the rest of its day, 3 hours, and up to a day more (12.10).
    Until then, a member who captures a message and its attestation can
    prove it. A member who publishes a message's hash somewhere public
    before the key comes out, such as in a public log, can prove later
    that it existed while only its sender could have signed it. Anyone
    can join a public room, so a bot that joins every public room and
    timestamps every ATTEST and message it sees defeats delayed
    deniability for everything it archived. A new leaf key each period
    limits what a revealed period key lets anyone forge, but does not
    keep the periods apart: in a public room, the Updates that bring
    each period's leaf key are public and signed with the key before, so
    one timestamped ATTEST ties a leaf to its device in every period
    (12.10).
  - Public rooms carry no device bindings (12.3), so their public
    commits tie no leaf key to a device: whose leaf is whose rests only
    on attestation, which becomes forgeable once the period key is out.
    The price is that anyone can join a public room under a credential
    that names someone else's device. Such a leaf never attests, and
    devices treat it as a guest's (12.10).
  - Outside public rooms, a device binding (12.3) shows that a device's
    KeyPackage was used, and a member can show that its key is in a
    group's tree. So being in such a group is not deniable to someone
    who has the group's tree, even though what was said is.
  - Sign-in signatures (4.6) give the server proof that a device
    connected at a given time.
  - Pairwise confirmation is deniable only if X-Wing's ciphertexts do
    not show who made them, which rests on the KEM's
    plaintext-awareness.
  - Franking (5.8) proves what a message said, but not who sent it.
  - Pairwise confirmation, epochal confirmation with its chained seeds,
    send tokens with `next` and TOKEN and "the first valid commit wins"
    (7.2), the split of commit checks into group checks and key checks
    with their repairs, removals for a check, RESYNC, resync commits and
    rejoins (12.7), derived pseudonyms (7.3) and derived mailbox moves
    (7.8) are risala's own constructions. They need a formal model and an
    outside review before they are relied on.
  - Epochal confirmation assumes that devices' clocks are never off by
    more than an hour (12.10). Group checks never use a device's clock,
    only the server's `t` on posts (12.7).

- **What the server learns.** Devices post on anonymous connections
  (4.2), so a post does not say who sent it, except for a public room's
  commits and proposals, which show their sender (12.6). In direct
  conversations and private rooms, commits are encrypted and Welcomes
  are sealed to each device (12.8), so the server does not learn the
  members from them. It still learns:
  - every connection's network address and timing. There is no support
    for Tor in this version. A device's anonymous and signed-in
    connections usually come from the same address, at about the same
    times, so a server that watches can link them, on a large server as
    on a small one. Anonymous connections then protect against later
    analysis of what the server stores, which 4.2 keeps from holding
    these links, and protect users who share their address with many
    others, behind a large NAT or a VPN. Clients do not resume TLS
    sessions (2.1), which would link connections even across addresses.
  - which connections follow which mailboxes, which mailboxes one
    connection follows, and each post's pseudonym, size within its
    padding, and time. Outside public rooms, a leaf's pseudonym changes
    with every commit (7.3), so it groups that leaf's posts only within
    an epoch, a week at most; in a public room, within a period. A
    device's set of mailboxes, its sync points, its `quiet` tags and its
    `cid`s stay much the same from one session to the next. So once any
    one of them is tied to its identity, by address, by timing, or by an
    identifying command sent on the wrong connection (4.1), every
    conversation the device follows is, past and future. 7.4 makes them
    less stable. Spreading a device's mailboxes over several connections
    is left for a version with Tor.
  - which push subscriptions follow which mailbox (9.1), and, through
    their URLs and timing, which subscriptions may belong to one device;
  - which device gets a Welcome, and when (12.8). Welcomes are sealed to
    each device and sent at independent random times, but Welcomes for
    several identities' devices that arrive within minutes of each other,
    with about the same size, still suggest that those identities were
    added to one group;
  - for a Welcome too large for a line, which mailbox it belongs to. Its
    blob is stored with the box and token of the group's mailbox
    (12.12), and its blob-ref goes to the welcomed device, so the server
    can link that device to the mailbox. Only the Welcomes of large
    groups are blobs;
  - whose KeyPackages someone asked for (12.5), and whose presence
    someone watches (8.3);
  - that an identity has an account on the server: sign-ins, KeyPackages,
    backups and its records in the key log;
  - for the identities whose key files or logs it serves, which network
    addresses fetch which identity's key file and records, and how often
    (12.14). Every device fetches its contacts' key files daily, so this
    shows who is in touch with whom, which sealed sending otherwise
    hides. The host of a self-hosted identity's key file learns the
    same. After each new record, REFETCH (12.9) and nudges (12.8) make
    contacts fetch within minutes of each other, which ties their
    addresses to the identity more closely than fetches spread over
    the day;
  - after a recovery (4.8), whose uids someone asked KeyPackages for,
    and which devices then got small Welcomes: the nudges (12.8). Fresh
    connections and random waits blur this, but on a quiet server it
    suggests who the recovered identity's contacts are;
  - roughly how many devices a direct conversation or private room has,
    from the size of its commits and Welcomes, and from the followers and
    push subscriptions of its mailbox;
  - that a direct conversation or private room moved its mailbox (7.8),
    which shows that a member left or was removed, though not who;
  - in a public room, its members and their display names, the leaf of
    each light client (12.6), its topic, and who commits or rotates a
    leaf key, whose commits and Updates come from their devices'
    signed-in connections (12.6), as their credentials already say. The
    blobs of a commit too large for a line, an external one's included,
    may be stored on the same connection (4.1, 12.12), which ties
    nothing further to the identity. Commits carry no pseudonym (7.3),
    and pseudonyms change every period, so the server does not learn
    from the posts which are whose. But it sees which members' devices
    rotate their leaf key each day (12.10), which is roughly who sent
    the day before, and in a quiet room it can often tie a new pseudonym
    to the commit made just before its first post;
  - that an identity is online whenever it has a signed-in connection.
    Others learn it only if the identity turned presence on, which is
    off by default (8.3);
  - how many devices an identity has, since KEYPKG GET answers one line
    per device, and KEYPKG COUNT and sign-ins are per device;
  - for files: how many are uploaded to each mailbox, their padded
    sizes and when, and for each download, which network address fetched
    which file, and when. Downloads can tie addresses to a mailbox, and
    so help the server guess who is in a private conversation;
  - for blobs: when an identity's devices store large ones, such as at
    pairing or in a transfer, and their sizes;
  - for backups: their size and how often they are made, and their
    generation, which counts how many times the identity has removed a
    device or recovered;
  - from a guest's report conversation (5.8), which guest contacted
    which owners or moderators, through the KeyPackages it asked for.
  Appendix D lists these as accepted risks.

- **What the server can still do.** It can withhold, delay or reorder
  posts, refuse posts and commits, and drop mailboxes:
  - Devices notice a gap in a member's messages once a later message
    from that member arrives (7.4), and they notice replayed messages
    (12.9). They do not notice if the server holds back a member's last
    messages, or everything a member posts from some point on, and
    cannot tell a mailbox the server hides entirely from one where
    nothing is said.
  - In direct conversations and private rooms it chooses, by the order
    of posts, which of two commits for the same epoch wins (7.2), for
    example an owner's demotion of a moderator or that moderator's own
    commit. It can also refuse a commit forever, such as the removal of
    a kicked member. The committer sees this, the other members do not.
    Commit streaks (12.7) keep one member from winning every epoch on
    its own, but not with the server's help.
  - It can split a direct conversation or a private room: by showing
    different devices different commits for the same epoch, by holding
    a commit back from some of them, or by changing a commit's `next`
    for some. Each branch then sees the other go quiet. Devices warn
    when posts of their epoch keep arriving that they cannot decrypt
    (12.7), and an identity's own devices compare epochs through their
    read markers (7.7), but the split stands for as long as the server
    keeps it up, and a group can move only to another mailbox on the
    same server.
  - In a public room it can accept a commit that members' devices
    reject, which makes them recover with a resync commit (12.7).
    Devices that were in the room warn their users, and do not take the
    room's new roles silently (12.7). Devices that join the room
    afterwards cannot tell, so a server can set the roles and settings
    that newcomers to a public room see, and even which group they join
    under the room's name.
  - It is the authority for public room names, and can make up a room,
    hide one, or put a different group under a name. Devices that know
    the room, or follow a link that carries its group id, notice the
    change (6.1). Until a device has joined a public room, the topic and
    member count that LIST shows are the server's word.
  - It can send a false GONE that makes members' devices remove a
    guest's leaf, or hold one back, so that a reused guest name appears
    twice (6.1).
  - Every time window in the group checks runs on the server's `t`,
    so that all devices agree (12.7): KeyPackage lifetimes, the bounds
    on `updated` and the streak's 10 minutes, stale leaves, and the 8
    days after which anyone may remove a public-room leaf that never
    committed. A server that colludes with a member can open or close
    any of these, for example accept an expired KeyPackage or make a
    leaf stale early. Devices warn when the `t` of commits disagrees
    with their own clock by more than an hour (12.7).
  - It can leave members out of the list that MEMBERS gives a light
    client (8.3), which shows that list only as the server's word
    (12.6).
  - In a public room, it can join, commit and propose Updates in any
    identity's name, since its leaves carry no device binding, and only
    the server checks that a commit or Update comes from the device that
    its credential names (12.6). The group checks do not depend on
    attestation, so every device applies what it commits. A server can
    so join under a credential that names an owner's device, as a rejoin
    (12.7), and then remove the real owner's leaves, ban the other
    owners and moderators, add uids to `owners` and change any setting,
    and push out any member by Updating a copy of its leaf and removing
    the real one as a copy. Devices find such a leaf unconfirmed within
    the hour, since it sends no valid ATTEST, warn their users, and keep
    for the room's content the roles they had before its commits
    (12.7, "Commits in another's name"). But nobody who still holds a
    role can undo its commits, the server can refuse the real owners'
    posts as banned, and devices that join afterwards see a normal room.
    In direct conversations and private rooms the server cannot do this,
    since it holds no group secrets and cannot sign as any leaf.
  - Within a generation, it can serve an older backup (above).

- **Insiders.** A member can read the conversation, and can leak it. A
  member can post invalid commits, which cost every device some work
  and which devices ignore (7.2); send tokens, limits per connection and
  per network address, and proof of work bound how many. In a public
  room the server cannot tell an invalid commit from a valid one, so
  one invalid commit makes every device recover with a resync commit
  and batched rejoins (12.7). Only identities' devices commit there,
  each from its own signed-in connection, so the member who did it is
  known, and can be banned; guests and anyone not yet a member cannot
  do it, since they join only by proposal (6.1).
- **Removals for a check.** Whether a commit is valid never depends on
  key files (12.7), so in a direct conversation or a private room any
  member can remove the leaves of one other identity in a commit, by
  claiming that a key check fails for them, that a leaf is an impostor,
  or that it asked to be replaced. In a room, only an owner or the
  identity's own devices can remove an owner's leaves so, and only those
  or a moderator a moderator's (12.7), so that no member can take out
  those who could add it back. Every device checks a key-check claim and
  warns, and devices that had confirmed a removed leaf name whoever
  removed it. The removed devices come back only as the group checks
  allow, which never depend on history: through their identity's own
  devices if some are still in the group, the other participant of a
  direct conversation, or, in a private room, an owner's or moderator's
  Add, which their devices offer their users but do not make by
  themselves. So a plain member who removes all of a plain member's
  leaves keeps it out until an owner or moderator acts. One identity per
  commit and commit streaks per identity (12.7) mean that emptying a
  room takes a member many commits over hours, in view of every device,
  and the room keeps its owners and moderators, who can add back, unless
  they leave. The price is that a forked or compromised owner or
  moderator, or one missing its keys, stays in a private room, and its
  leaves go on reading it, until its own devices or an owner (or, for a
  moderator, a moderator) remove it. Other devices hide what it sends,
  and keep sending (12.14). A device that was removed misses what was
  said in between until its own devices fill the gap (12.13). The same
  goes for a member who encrypts a commit's path secrets so that a few
  devices cannot follow: they post RESYNC, and their identity's devices,
  or an owner or moderator, add them back (12.7). A later version may
  carry a bounded history of recent commits in the group context, which
  every commit updates and joiners read from the GroupInfo, so that
  plain members could again add back what a false removal took out, and
  undo an impostor's commits, without the group checks depending on
  anything a joiner lacks. This version keeps every group check to the
  current state, and leaves such repairs to roles.
- **Leaves held by whoever added them.** A device binding covers the
  keys that others encrypt to, not the leaf's signature key (12.3). So
  the member who adds a device, or the server that hands out its
  KeyPackage, can give its leaf a signature key of their own. The
  server holds no group secrets, so it only keeps the device out with a
  leaf nobody can use, until the identity's own devices find that leaf
  unanswering and replace it (12.7). A member
  who does it holds a leaf in the name of another identity's device,
  with that identity's role, until devices confirm it (12.10). Devices
  challenge such a leaf as soon as it uses a role, and the identity's
  own devices challenge every new leaf of it, or, in an epochal group,
  expect an ATTEST in its first message, so within about an hour
  devices find it out and remove it (12.7). Removing it does not undo
  what its commits did: the identity's own devices, or the room's other
  owners and moderators, undo that with ordinary commits, within their
  roles. Its messages show as unverified throughout. No Add hands anyone
  a leaf with a role above its own: in a private room, only an owner or
  the identity's own devices add an owner's devices, and only those or
  a moderator a moderator's (12.7). So a leaf held this way has at most
  the role of whoever added it. Any member can also remove, as an
  impostor, a leaf that is not one, within the limits of the Removes
  checks; devices that had confirmed that leaf then name the member who
  did it, and its identity adds its device back where the Adds checks
  let it. Calling a leaf an impostor gives no power to undo what it
  did, so a member cannot reverse an owner's moderation that way.
  A device that joins by Welcome cannot check the device bindings of
  the leaves already in the group, since the tree no longer holds the
  init keys they cover (12.7). For those leaves it relies on the members
  that were present when each was added, and on confirmation (12.10).
- **Public rooms.** Anyone can join a public room under a credential
  that names any device (12.3). Such a leaf never attests, so devices
  treat it as a guest's. It cannot commit or propose an Update, since
  the server takes those only from the device a credential names (12.6),
  and so it cannot push the device it names out of the room: a copy of a
  leaf is removed only once the other leaf has committed or been
  Updated, which, while the server is honest, only the named device can
  do, while that device can remove the copy at once (12.7). The server
  itself can do all of this (above). Owners and moderators remove such
  leaves without kicking the uid they name, and any member may once they
  are 8 days old; until then, joins that nobody uses count towards the
  room's limits, which only rate limits bound until proof of work is
  specified (4.1). An identity in the room can make a resync commit at
  any time, which removes the last committer's leaf until that device
  joins again; devices that had no trouble with the commit it undid name
  its maker. Apart from owners and moderators, who act within their
  roles, a commit removes at most a tenth of a room's leaves, and only
  leaves that are stale, guests', copies or never used, so no member can
  empty a public room. A hostile member that is the only full client
  online can hold back joins, but owners and moderators can still get in
  by external commit (12.7). Anyone who joins a public room can post
  under another member's pseudonym, which the server cannot tell apart,
  though members' devices ignore such posts (7.3).
- **Other insiders.** In a direct conversation or a private room, a
  member can add useless hashes to a token set with TOKEN, but cannot
  push out the hashes that commits added (7.2). A member can move its
  group's mailbox, but only to the box that the group's secrets derive
  for that epoch (7.8). A removed member keeps the old box and its last
  token: it can watch the old mailbox and post junk there until the
  group moves, which it does right after the removal. A blocked person
  in a direct conversation stays in it, and so sees its activity. A
  member can take part in confirming leaves only for itself: it cannot
  make another member's leaf look confirmed. Any member can remove
  others' leaves that are stale, more than 35 days behind the group's
  median (12.7), at most a tenth of the group in one commit, and outside
  public rooms must add those devices again if they have KeyPackages. No
  leaf counts as newer than the post that carries the commit, so joiners
  cannot drag the median forward. The devices of one identity can
  together commit in at most 3 epochs in a row before they have to wait
  about 10 minutes (12.7). A removed or demoted member loses its role
  from the commit that removes or demotes it (12.9). A compromised
  device of an identity can, until it is removed, send that identity's
  other devices made-up history for the gaps they ask it to fill. They
  show it as copied from that device, and never let it replace what they
  hold (12.13).

- **Who can add a device.** Any device of an identity holds the
  device-signing key, and so can add a device. That shows in the key
  log, which the chain names and the identity's own devices watch daily
  (4.5). Whoever controls the identity's domain can publish a key file
  with a new chain, or an older one, but every device that knows the
  identity sees a new master key, a fork or a rollback, and stops
  trusting it until the user acts (12.14). A server that
  hosts an identity holds none of its keys, and can do no more than the
  domain's controller. No operator can reset an identity.

- **New master keys freeze private rooms.** A new master key stops
  sending in direct conversations and private rooms until each user
  acknowledges it (12.14). Any member can cause that by changing its
  own recovery key (4.8), and so can whoever controls any member's
  domain, by serving a valid key file with a new chain, whose records
  need not be logged, and as often as it likes, by switching between
  files. Stopping protects little in a room, whose leaves of that
  identity are its old devices. And acknowledging is risky: once one
  member's device has acknowledged, its head is the new chain, and it
  may add the new chain's devices to every private room where the
  identity still has a leaf, for everyone (12.7, "Adding devices"). The
  identity's own devices then remove them as a failed key check, and
  that member's device may add them again within the hour, so they can
  read in between. So one member, or the controller of one member's
  domain, can stop a private room until every user acknowledges, and
  one user who acknowledges carelessly lets the new key's devices in.

- **First contact.** A device that meets an identity for the first time
  cannot tell whether the chain it is shown is the one the identity's
  owner watches. Within one host, logs form a hand-off chain (4.5,
  4.10), so a second chain for an identity in its own host's logs shows
  up in the log its devices watch. But the controller of the identity's
  domain can show a first-time contact a chain of its own in a log on
  another host, which the owner never reads. Only comparing safety
  numbers catches that (12.14), which is why clients suggest it for new
  direct conversations. A monitor service that indexes every log by uid
  could close this gap, and is left for a later version.

- **A stolen device.** Until the `signing` record that removes it is
  accepted, a stolen device is current: it can remove its identity's
  other leaves from groups and add itself back. The identity's devices
  show this as an alert (12.7), and its removal stands once the record
  is accepted, which logs SHOULD witness within a minute (4.5). Devices
  then remove its leaves, as for an impostor, and the identity's other
  devices undo what it did, within the identity's role (12.7). A user
  who lost every device recovers instead (4.8), and has no leaf left to
  remove the stolen ones with. Its contacts remove them once they fetch
  the key file: within minutes for those it nudges (12.8), and for the
  rest at their daily fetch, which devices MUST make (12.14). Until
  then, the stolen devices still read what those contacts send.

- **Missing key files and forks.** A key file that is gone or invalid is
  unsigned, so it removes no device by record (4.4). Devices cannot
  check such an identity, nor one whose chain or log has forked (4.5),
  so they stop sending in direct conversations with it, hide what its
  leaves send in rooms, and remove its leaves from rooms that are not
  public (12.14), apart from owners and moderators, whose leaves only
  their own devices and those at or above them in role may remove there.
  So the host of a key file can make an identity unreachable, visibly,
  and push it out of private rooms in which it is a plain member. Once
  the file is back, it does not come back by itself: see below. Only a
  `retire` record, which needs the recovery key, removes an identity for
  good from every conversation (4.9). And an identity that forks its own
  chain, or takes down its own key file, stops only its direct
  conversations: a room goes on without it. The cost is that, in rooms,
  a device keeps sending while the identity's leaves are being removed,
  so those leaves can read what is sent in between. Devices that see the
  key file or log differently can also disagree about such a removal,
  and one may add the identity back while another removes it again
  (12.7), which each device shows.
  An outage is different: it fails no check, however long it lasts
  (12.7), so nobody who can block a key file gets a leaf removed by it.
  But for as long as it lasts, nobody who has never read the file can
  add the identity, and a device that cannot check a leaf just added
  sends no messages in that group, and warns after 2 hours. So whoever
  can block a key file can stall a conversation, visibly, but not take
  anyone out of it.

- **Losing every leaf in a private room.** In a direct conversation,
  either participant's devices add the other's. In a private room, an
  identity that has no leaf left comes back only when an owner's or
  moderator's device adds it, and only an owner's for an identity
  listed in `owners` (12.7). Devices offer this to their users, but do
  not do it by themselves. Ordinary events take every leaf of an
  identity out of a private room: recovery after losing every device,
  whose `signing` record removes every old device (4.8); a key file
  that answers 404 for a while, during a move or after ADMIN
  UNREGISTER (12.14); and a fork, even one the user later resolves. In
  each case the identity is out until an owner or moderator acts. A
  device whose identity has no other leaf there, and that posts RESYNC,
  likewise cannot follow the room until an owner or moderator replaces
  its leaf (12.7).
  Owners and moderators are not removed for a fork or missing keys by
  those below them (above), but recovery hits them too. A room's only
  owner that recovers never comes back, whether or not the room has
  moderators: only an owner may remove an owner's leaves or add its
  devices, so its old leaves stay in the room, showing nothing but
  still able to read, and the room keeps no owner who can act (4.8,
  6.3).

- **Accounts on other servers.** A server that has never seen an
  identity takes its first chain from whoever controls the identity's
  domain, and pins it (4.6). Before that pin exists, the domain's
  controller can serve that server a chain of its own and sign in there
  as the identity: delete its KeyPackages, Welcomes, push registrations
  and backup on that server, and lock its devices out. A server that
  checks records against the key log narrows this to the first-contact
  gap above. None of it lets anyone read a conversation, since devices
  check every record themselves.

- **The key log.** A log could show different trees to different people.
  Witnesses refuse to cosign a checkpoint that is not consistent with
  the last one they saw, so this needs k witnesses to collude; and each
  witness enrols one key per origin, with k more than half a client's
  list, so two keys of one log cannot both be witnessed for one client
  (4.10). A witness enrols a host's first log only under the key that
  the host's own HTTPS server publishes (4.10), so nobody can claim
  another host's origin first, unless they control the host's name, or
  get a certificate for it, at the moment of enrolment. A host whose
  name was hijacked at that moment is locked out of that witness for
  good, unless its operator has a manual procedure to replace the key,
  which cannot change what devices accept. A log or a key file host that
  withholds a record leaves it pending for devices that know of it.
  Devices that do not know of it find it through the uid's hint within a
  day, unless the log leaves it out of the hint as well; then the
  owner's devices find it in their weekly read of the whole log (4.5),
  and contacts see the identity as stale after 7 days without a fresh
  witnessed view. Watching costs each device a few bytes a day for the
  hint, and the size of the log's new entries each week. A log lists
  every uid whose records it holds, so anyone can list the identities a
  server hosts. A log that is unreachable stops devices from accepting
  new records of its identities, but not from using the ones they
  already accepted. A host that loses its log's key cannot hand off to a
  new log (4.5), and its identities can then add or remove no device, so
  the key needs a backup kept offline.

- **Trust on first use.** Someone can intercept the first connection to
  a server that has a self-signed certificate. Users can compare the
  fingerprint through another channel (Appendix A). Servers with CA
  certificates do not have this weakness. Nothing that is end-to-end
  encrypted depends on it.

- **Identity follows the domain.** Whoever controls
  `https://<domain>/.well-known/risala/` controls which key file is
  published for every identity under that domain, including after the
  domain changes hands. The key log makes a change visible, but a person
  who loses their domain loses their identity.

- **Signatures.** The signed bytes of AUTH (4.6) bind a signature to one
  server, one connection and one identity, so a signature cannot be
  replayed, or used on another server. This relies on servers accepting
  sign-ins only on connections whose SNI is a name they serve. Every
  other signature uses RisalaSign (4.3) or MLS's own labels, so that no
  signature made for one purpose is valid for another.

- **Server secrets.** Guest tokens (4.2), send tokens (7.2), put secrets
  (12.5), `put`, `get` and `del` URLs (5.6, 12.12) and pairing ids (4.8)
  work for whoever holds them. Servers SHOULD store only a hash of each,
  and look it up by that hash, or by a part that is not secret where it
  has one, such as the mailbox and epoch of a send token or the
  KeyPackageRef of a put secret, comparing any secret part in constant
  time. These secrets carry at least 128 bits of randomness, so a lookup
  by hash does not leak them through its timing. Franking tags are
  compared in constant time too (5.8, 12.9). Push URLs and their keys
  (Section 9) are kept in the clear, since the server must send to them
  and encrypt to them. PUSH DEL looks a subscription up by a hash of its
  URL.

- **Requests from the server.** Fetching key files and sending pushes
  both mean connecting to hosts that users choose. The rules in Sections
  4.4 and 9.3 stop these requests from reaching the server's internal
  network.

- **Open registration.** Each REGISTER creates an identity that works on
  every server. A server with open registration SHOULD rate-limit it,
  for example per network address, and close it if it is abused. The
  limit counts registrations that have succeeded or are still in
  progress, so that parallel connections cannot get around it (4.7).
  Other servers can answer abuse from such a server only by banning
  single identities or its whole domain (10.2).

- **Spam and abuse.** The server cannot see who posts, so it limits load
  per connection and per network address. It does not limit per
  pseudonym, since anyone who holds a group's token can post under any
  pseudonym (5.2). It bounds what anyone can store: mailboxes have
  quotas and end when unused (7.5), token sets are bounded (7.2), and so
  are push subscriptions (9.1). A cap on what it stores in all covers
  files and blobs only, and leaves room for posts, so that filling it
  stops uploads but not conversations (7.5). A later draft will let it
  require proof of work to open anonymous connections, to become a
  guest, to register, to create mailboxes, to fetch KeyPackages and to
  join public rooms (4.1). Until then, only rate limits stand in the way
  of bots. Room moderators remove spammers with commits, and ask the
  server to mute a pseudonym in the meantime (6.4). Operators can ban
  network addresses for anonymous and guest connections (10.2). Limits
  per network address are shared by everyone behind one, such as the
  users of a Tor exit or of a carrier-grade NAT, so one of them can use
  up the others' share, and a ban of the address shuts out all of them
  (10.6). Proof of work will let a client go on past those limits, but
  until a later draft specifies it, they are the only bound.

- **Display names** can be used to imitate other people (8.2).
  Bidirectional text controls can make one name look like another, or
  make the text after a name look like part of it. So clients compare
  names without them, and show the uid apart from the name.

- **Reports.** Moderators of a room see who wrote a reported message,
  from their own copy. Operators see what it said, proven by franking,
  but only the reporter's claim of who wrote it. A member can report its
  own post as someone else's, so operators act on pseudonyms, mailboxes
  and rooms, and never ban an identity on reports alone (5.8). The
  pseudonym is a claim too: a member can post under another member's
  pseudonym, which devices ignore, and report that post, so that an
  operator mutes the other member. Operators SHOULD NOT mute on a
  single report, and outside public rooms a mute matters only until
  the next commit (5.8, 7.3). The
  reporter is told who will see the report. Operators learn who reported
  only if the reporter was signed in.

- **Blocks** are kept by devices, and the server never sees them (5.7).
  Someone who is blocked can still add the person who blocked them to a
  group, which their devices then ignore.

- **Push.** Push bodies are encrypted to the device, and padded to one
  size (9.3). The push service, and any gateway in between, still see
  when pushes happen and for which subscription, and so, over many
  pushes, which devices are woken together, which suggests who shares a
  conversation. The server delays each subscription's pushes by its own
  random time (9.2), which blurs this but does not hide it.

- **Deletion** removes a message from devices that honour it, not from
  copies that people have already made, nor from the server, which
  holds the ciphertext until it expires. A file stays fetchable with its
  `get` URL until it expires, unless its uploader deletes it, even after
  a moderator deletes its message.

- **Files.** `get` URLs are capabilities (5.6). Anyone a URL is passed to
  can download the file, but gets only ciphertext of a padded size
  (12.11). People will open these URLs in web browsers, so servers
  SHOULD serve files from a domain that is used for nothing else, and
  with the header `X-Content-Type-Options: nosniff`. A member can share
  a file whose URL is on a host of its own, which would learn the
  address of everyone who fetches it, so devices fetch such a file only
  when their user asks (12.11). ChaCha20-Poly1305 is not
  key-committing, but every recipient gets the same key in the franked
  content, and `file-hash` commits to the ciphertext, so a file cannot
  decrypt differently for different recipients.

- **Sizes.** Private rooms of 1,000 members and public rooms of 10,000
  (6.1) are limits chosen before ML-DSA and X-Wing have been measured on
  phones, and may change. Every message carries a 2420-byte signature,
  which dominates traffic in large rooms. Sealing each Welcome to its
  device (12.8) means that a committer uploads a large private room's
  tree once for each device it adds.

- **Operators** see what the server sees, and can refuse service: drop
  rooms and mailboxes, mute pseudonyms and ban identities and addresses
  (Section 10). They cannot read any conversation, act as a private
  room's moderator, or change anyone's keys. In a public room, though, a
  server can commit in any identity's name (above). ADMIN WHO shows them
  every open connection's network address (10.3), but servers do not
  keep the addresses of anonymous and guest connections once they close
  (4.2).

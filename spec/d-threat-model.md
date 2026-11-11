## Appendix D. Threat Model (Informative)

This appendix sums up, for each adversary, what it can and cannot do
against a correct implementation of this document. Section 14 gives the
details.

### D.1. Adversaries

**Someone on the network**, passive or active, including one who records
traffic now to decrypt it with a quantum computer later.

- Can: see which hosts a device connects to, when, and how much it
  sends. Block connections. Intercept the first connection to a server
  with a self-signed certificate (2.2). With a quantum computer, forge a
  classical TLS certificate in real time.
- Cannot: read or change anything inside TLS, or anything end-to-end
  encrypted, now or later.

**The server and its operators**, curious or compelled, passive or
active.

- Can: see every connection's network address and timing, which
  mailboxes each connection follows, push subscriptions, the size and
  pseudonym of each post, sign-ins, KeyPackage fetches and how many
  devices each identity has, watched presence, and which device got a
  Welcome, and when. Learn, from key file and log fetches, who looks up
  the identities it hosts. See file uploads and who downloads them, the
  size and timing of blobs and backups, and backup generations. See the
  members, display names and topic of public rooms, and who commits in
  them, and so roughly who sent the day before. See that a private
  conversation moved its mailbox, so that someone left it. Join a public
  room under an identity of its own and read it from then on, in view of
  its members. Withhold, delay and reorder posts, refuse service, drop
  mailboxes and rooms, and mute pseudonyms. Hold back a member's last messages
  unnoticed. Choose which of two concurrent commits wins in a private
  conversation, and refuse a commit forever. Split a direct
  conversation or a private room into branches that each see the other
  go quiet, which devices warn about but cannot undo. Make a public
  room's devices resync, and set the roles and settings that newcomers
  to a public room see, by accepting a commit that members' devices
  reject, which they warn about. Swap the group behind
  a public room's name, which devices that knew the room notice. Send
  or hold back GONE for guests. Serve an older backup of the same
  generation. Link a device's anonymous connections to its signed-in
  one by address and timing, and then every mailbox it follows. In a
  quiet public room, tie a pseudonym to the commit made just before its
  first post (Section 14). With a member's help, open or close the time
  windows of the group checks through the `t` it gives posts. Leave
  members out of what a light client is told, which it shows only as
  the server's word (12.6). In a public room, join, commit and Update
  in any identity's name, owners' included, since it alone checks who
  commits as whom there: change the room's roles, bans and settings,
  and push members out as copies, which every device applies, though
  devices find the leaf unconfirmed within an hour, warn, and keep the
  roles they had for the room's content (12.7, Section 14).
- Cannot: read any message, file, private display name or topic. Learn
  who sent a post, or who is in a direct conversation or a private room,
  except by the links above. Keep those links in what it stores, if it
  follows 4.2, so that a database seized or handed over later does not
  hold them. Add anyone to a conversation, change the roles or
  settings of a private room for its members' devices, change or forge
  a message, replay one unnoticed, or hide a gap in one member's
  messages once a later message from that member arrives. Reset an
  identity or add a device to one. Serve a backup of an older generation
  to a restoring device. Read history, since it keeps none beyond
  retention.

**The controller of an identity's domain**, which includes the server
that hosts an identity.

- Can: publish a key file with a new chain, an older one, or none at
  all. With no key file, or an invalid one, it makes devices stop
  sending in direct conversations with the identity, hide its messages
  in rooms, remove its leaves from rooms that are not public where it is
  a plain member, from which it then comes back only when an owner or
  moderator adds it, and warn their users (12.14). With a new chain,
  whose records need not be logged, it makes every device that knows the
  identity stop sending in each private room it is in until each user
  acknowledges the new master key, and a device whose user does may add
  the new chain's devices to those rooms (Section 14). Show someone
  meeting the identity for the first time a chain of its own in a log on
  another host, which only safety numbers catch (Section 14). Sign in as
  the identity on servers that have not seen it before, and use its
  account there. Stop the identity from signing in to servers that have
  no cached key file. By an outage, keep devices that have never read
  the key file from adding the identity, and devices that cannot check
  a newly added device from sending in that group, for as long as it
  lasts (12.7).
- Cannot: change the keys of an identity that a device already knows
  unseen: a new chain is a new master key, a fork or a rollback, and
  devices stop trusting it until their users act (4.5, 12.14). Add a
  device unseen by the identity's own devices. Get a leaf removed by an
  outage, which fails no check (12.7). Make anyone remove the
  identity from a direct conversation for good, which takes a `retire`
  record (4.9). Sign a record of an existing chain without its keys.

**A key log and its witnesses.**

- Can: refuse or delay records, which then stay pending (4.5). Leave a
  record out of its hints, which the owner's devices catch within a week
  (4.5). A log and k colluding witnesses can show different trees to
  different people. Lose its key, after which its identities' chains
  cannot grow.
- Cannot: change a record, which the identity's keys sign. Show two
  trees while fewer than k of a client's witnesses collude. Enrol a log
  under another host's origin at a witness, which fetches the first
  key from that host's own HTTPS server (4.10), unless it controls that
  host's name, or a certificate for it, at that moment.

**A member of a conversation,** including a moderator or owner.

- Can: read and leak the conversation from when it joined. Post invalid
  commits, which cost others some work (7.2), and in a public room make
  every device resync, after which it can be banned (12.7). In a public
  room, make a resync commit, which removes one other leaf and which
  devices that did not need it attribute. Outside public rooms, remove
  the leaves of one other identity per commit by claiming that a check
  fails for them, which devices attribute (12.7), though in a room not
  those of an owner or moderator above its own role; a plain member
  who removes all of a plain member's leaves keeps it out of a private
  room until an owner or moderator adds it back. Hold a leaf of a
  device it adds, in that device's name and with at most its own role,
  until devices confirm the leaf or find it out, about an hour after it
  first uses a role. Within its role, invite,
  kick, ban, delete and change settings. Remove others' stale leaves,
  and in a public room copies and joins that nobody uses, within the
  limits of 12.7. With its identity's other devices, commit in up to 3
  epochs in a row, then about once every 10 minutes. Move its group's
  mailbox, to the box that the group's secrets derive (7.8). Make a
  transcript that proves nothing to others, since members can forge each
  other's messages for third parties. In an epochal group, prove a
  message to others until its period key is published, or later if it
  timestamped the message's hash in public beforehand. Post abuse and
  report it to operators as someone else's, or under someone else's
  pseudonym, which an operator may mute until the next commit (5.8).
  Change its own recovery key, which stops every other device from
  sending in the private rooms it is in until each user acknowledges
  the new master key (12.14). Once removed, watch the old mailbox and
  post junk there, until the group moves (7.8), which it does right
  after the removal. Fork its own chain, or take its key file down,
  which stops only its own direct conversations, and has its leaves
  hidden in rooms, and removed from rooms that are not public, unless
  it is an owner or moderator there, in which case it stays and reads
  until its own devices or one at or above its role remove it (12.14).
- Cannot: post as another member to the other members, make another
  member's leaf look confirmed, get control of a leaf with a role above
  its own by an Add, remove an owner's or moderator's leaves without a
  role that allows it, read anything sent after it is removed, post or
  act on a role it has lost after the commit that removed or demoted it,
  or add new identities to a room without a role that allows it. Undo
  moderation without the role that it needed, by calling a leaf an
  impostor or otherwise. Give devices that joined recently a different
  view of the group than older ones, since group checks depend only on
  the group's state (12.7). Empty a public room, or keep its owners and
  moderators out of it. Move its group to a mailbox that cannot be used,
  or deliver a Welcome for a device that someone else added (12.8). Get
  anyone banned by operators on a report alone. Learn a member's network
  address by sharing a file from a host of its own, unless that member
  chooses to fetch it.

**A guest,** or anyone who opens anonymous connections.

- Can: join public rooms that allow guests, and post where `guests` is
  `write`. Join a public room under a credential that names someone
  else's device, which devices then treat as a guest's leaf. Open a report conversation with an owner or moderator of such
  a room, if they accept it, to send reports (5.8). Use up server
  resources within rate limits and quotas, and, once it is specified,
  proof of work (4.1).
- Cannot: take part in private rooms or in other direct conversations,
  send anything but reports in a report conversation, or appear as
  anything but an unverified guest. Commit in a public room, force
  its devices to join again, or block joins to it by delivering
  Welcomes first (12.8). Change a TOKEN set of a public room (7.2).

**Someone who steals a device,** or compromises one for a while.

- Can: read the history stored on it, and everything sent to its groups
  until its leaves are removed. Use its device-signing key to add a
  device, which the key log shows. Remove the identity's other devices
  from groups, and add itself back, until the record that removes it is
  accepted, which the identity's devices see (12.7). Read the backups
  made with the backup key it holds, and make backups with it, until the
  owner moves to the next generation and replaces it.
  Send the identity's other devices made-up history for gaps they ask
  it to fill, which they show as copied from it.
- Cannot: read messages whose keys the device had already deleted, or
  messages sent after the device's leaves are removed, or after the
  device itself commits fresh keys, once the attacker has lost access
  (post-compromise security). Remove the identity's other devices from
  its key file, which needs the recovery key.

**Someone who gets the recovery key.**

- Can: control the identity: replace its devices, and read every backup
  the server has kept, including replaced and deleted ones, since the
  server is not trusted to delete them.
- Cannot: read conversations without joining them as a new device, which
  the identity's contacts see.

**Someone who sees a pairing QR code,** with or without the server.

- Can: read the new device's public keys, and spoil the pairing by
  storing something under its ids first, so that it starts again.
  Answer the pairing first, with a bundle for an identity of its own,
  which the new device shows by uid before it does anything, and which
  the scanning device reports (4.8).
- Cannot: read the reply, which is sealed to the new device's own key
  (4.8), or pair the new device into its own identity without the user
  confirming that identity.

**Push services and gateways.**

- Can: see when each subscription gets a push, and so, over many
  pushes, which devices are woken together, which suggests who shares a
  conversation (9.2).
- Cannot: read push bodies, which are encrypted to the device and padded
  to one size (9.3), or tell which identity a subscription belongs to
  from the push itself.

**Someone shown a transcript afterwards,** such as a court or the public.

- Can: be shown messages, and check franked content in a report.
- Cannot: tell from the transcript alone who wrote a message, once it is
  deniable (12.10).

### D.2. Non-goals

- Hiding network addresses and timing from the server or the network.
- Hiding that someone uses a server, or is online, from that server.
- Hiding who is in a public room, from the server or from anyone who
  joins it.
- Keeping history on the server, or giving new members of a room what
  was said before they joined.
- Protecting a device's stored history from someone who controls the
  unlocked device.
- Recovering an identity whose recovery key and every device are lost.
- Federation, and protection across servers.

### D.3. Accepted Risks

Each risk is marked **Mitigated**, where this document limits it, or
**Open**, where it stands as written.

- **No Tor in this version** (Mitigated: servers keep no links in
  stored data, 4.2). The server sees every connection's network address
  and timing, and can link a device's anonymous connections to its
  signed-in one by them, on any server. Sealed sending then protects
  against later analysis of what the server stores, and users who share
  their network address with many others.
- **Stable sessions** (Mitigated: random order and starting points,
  7.4). The mailboxes a device follows, its sync points and its push
  tags change little between sessions, so one link to its identity
  exposes all of its conversations.
- **Senders in public rooms** (Mitigated: no pseudonym on commits, and
  new pseudonyms each period, 7.3, 12.10). The server sees who commits
  in a public room, and so roughly who sends each day, and in a quiet
  room it may tie a pseudonym to its sender by timing.
- **Presence stays on the server** (Mitigated: off by default). It knows
  when each identity is online. Presence is off by default; an identity
  that turns it on is shown to anyone on the server who asks (8.3).
- **Public rooms show their membership** (Open) to the server and to
  anyone who joins, so that the server can check commits and serve light
  clients. A light client also tells the server its leaf.
- **Delayed deniability in large rooms** (Open). In epochal groups, a
  message is deniable only once its period key is out, up to about two
  days later, and a member who timestamps a message in public before
  then can prove it later.
- **Enrolment by host name** (Mitigated: witnesses fetch a host's first
  log key from the host itself, 4.10). Whoever controls a host's name,
  or holds a certificate for it, when a witness first enrols its log
  holds that origin at that witness for good.
- **Few post-quantum witnesses** (Open). Clients count only ML-DSA-44
  cosignatures (4.5), and few public witnesses may offer them at first.
  Until enough do, a client's witness list is short, and k colluding
  witnesses are easier to find.
- **Classical parts** (Open). TLS certificates and push encryption still
  use classical algorithms.
- **Metadata from KeyPackages, Welcomes and watch lists** (Mitigated:
  devices fetch KeyPackages on anonymous connections, and Welcomes are
  sealed per device and sent at random times, 12.8). The server sees
  whose KeyPackages are fetched, how many devices an identity has, which
  device gets a Welcome, and whose presence is watched, and, from timing
  and size, roughly which devices were added to a group together. A
  Welcome too large for a line is a blob stored under its group's
  mailbox, which ties the device it is for to that mailbox (12.12).
- **Push timing** (Mitigated: independent random delays, 9.2). Push
  services and gateways see which devices are woken together.
- **Sizes of private conversations** (Open). The server sees roughly how
  many devices a private conversation has, from its commits, Welcomes,
  followers and push subscriptions.
- **The key log lists identities** (Open). Anyone can list the uids
  whose records a log holds.
- **First contact** (Open). Meeting an identity for the first time
  relies on safety numbers when its domain's controller is malicious
  (Section 14).
- **Key file fetches show contacts** (Open) to the host of each key
  file and log.
- **Backups are not forward secret** (Open). Whoever gets the recovery
  key reads every backup the server kept. Within a generation, a server
  can serve an older backup, and a device shows only its age.
- **New constructions** (Open until reviewed). Pairwise and epochal
  confirmation, send tokens with "the first valid commit wins", and
  pseudonyms are this document's own, and have not yet been reviewed or
  formally modelled. So are commit streaks and the stale-leaf median,
  group checks and key checks with their repairs, removals for a check,
  RESYNC, resync commits and rejoins (12.7), chained period seeds
  (12.10), derived pseudonyms (7.3), and `next`, TOKEN and derived
  mailbox moves (7.2, 7.8).
- **Sizes are not yet measured** (Open). The room limits may change once
  ML-DSA and X-Wing have been measured on phones.
- **Metadata from files, blobs and backups** (Open). The server sees
  uploads per mailbox and who downloads them, the size and timing of
  blobs and backups, and how often an identity moves to a new backup
  generation.
- **Partitions** (Open). The server can split a direct conversation or
  a private room into branches. Devices warn when they see posts of
  their epoch that they cannot decrypt, and an identity's devices
  compare epochs through read markers (12.7, 7.7), but cannot end the
  split.
- **Leaves held by whoever added them** (Mitigated: challenged at their
  first use of a role, removed within about an hour, and never with a
  role above the adder's own, 12.7). A member who adds a device can hold
  its leaf until devices confirm it. Undoing what such a leaf did takes
  ordinary commits by those whose role allows each change.
- **Removals for a check** (Mitigated: one identity per commit, streaks
  per identity, owners and moderators only by those at or above their
  role, and attribution, 12.7). In a direct conversation or a private
  room, any member can remove another plain member's leaves by
  claiming a check that the group cannot make, and in a private room,
  if it removes all of them, only owners and moderators can add them
  back. In return, a forked, compromised or keys-missing owner or
  moderator stays in a private room, and its leaves go on reading it,
  until its own devices or an owner (or moderator) remove it.
- **Losing every leaf in a private room** (Open). An identity with no
  leaf left in a private room, after recovery, a key file that was
  missing for a while, a fork or a RESYNC, comes back only when an
  owner or moderator adds it. A room's only owner that recovers never
  comes back, and its old leaves stay, able to read (Section 14).
- **New master keys in private rooms** (Open). A member, or the
  controller of a member's domain, can stop every device from sending
  in a private room until each user acknowledges a new master key, and
  one user who acknowledges lets the new key's devices in (Section 14).
- **Public-room roles rest on the server** (Open). In a public room,
  only the server checks that a commit or Update comes from the device
  its credential names, so the server can commit in an owner's name and
  take over the room's roles, bans and settings. Devices find the leaf
  unconfirmed within an hour, warn, and keep the roles they had for the
  room's content, but cannot undo its commits (12.7, Section 14).
- **Resyncs in public rooms** (Mitigated: only identities commit, from
  their signed-in connections, a resync removes one leaf and is
  attributed, and recovery is one commit and batches, 12.7). A member's
  invalid commit makes every device of a public room recover.
- **Unused joins in public rooms** (Mitigated: owners and moderators
  remove them, and anyone after 8 days, 12.7). Joins that nobody uses
  count towards a room's limits until then, bounded only by rate limits
  until proof of work is specified (4.1).
- **Shared network addresses** (Open until proof of work is specified,
  4.1). Limits per network address are shared by everyone behind one
  Tor exit or carrier-grade NAT, so one user there can use up the
  others' share, and an address ban shuts out all of them (10.6,
  Section 14).
- **Time windows on the server's clock** (Open). Every time window of
  the group checks runs on the `t` the server gives posts, so that
  devices agree; a server that colludes with a member can shift them
  (Section 14).
- **Past epochs until a catch-up** (Open). A device deletes a past
  epoch's secrets once it has caught up past 2 hours after the commit
  that ended it, by the server's time (12.9). A server that withholds
  posts, or holds back its time, keeps them on devices longer, where a
  device stolen meanwhile decrypts the messages of those epochs that it
  had not received (Section 14).
- **Archivers in public rooms** (Open). Anyone can join a public room, so
  an archiver that timestamps what it sees defeats delayed deniability
  for it (Section 14).
- **Withheld tails and commit order** (Mitigated: gaps show once a later
  message arrives, and streaks limit one committer). The server can hold
  back a member's last messages unnoticed, choose between concurrent
  commits in private conversations, and refuse a commit forever.
- **Public room roles for newcomers** (Mitigated: members' devices
  warn). A server that accepts an invalid commit sets the roles that
  devices joining afterwards see.
- **Guest names are reused** (Open). A server can forge or withhold
  GONE, and a guest uid in a report conversation says nothing about
  which guest of that name was in the room.

### D.4. Assumptions

The claims above rest on these assumptions. If one fails, so do the
claims that depend on it.

- **ML-DSA-44** [FIPS204] is existentially unforgeable under chosen
  message attack: key file records, sign-ins, device bindings, leaf
  signatures, period certificates and the key log's checkpoints.
- **X-Wing** [XWING] is IND-CCA secure as long as either ML-KEM-768 or
  X25519 holds, and, for the deniability of pairwise confirmation,
  plaintext-aware, so that a ciphertext does not show who made it.
- **ChaCha20-Poly1305** [RFC8439] is IND-CPA and INT-CTXT secure under
  keys that are never used with the same nonce twice: messages, files,
  archives, pairing messages and wrapped backup keys.
- **HMAC-SHA-384** [RFC2104] is a PRF, and, for franking, a binding
  commitment to the content under its key.
- **SHA-384** is collision resistant: `file-hash`, blob-refs, device
  ids, record chains and send token hashes.
- **HKDF-SHA384** [RFC5869] is a PRF and a randomness extractor: master
  keys, backup keys, pairing keys and confirmation keys.
- **MLS** [RFC9420] gives its stated security with this cipher suite,
  and the OpenMLS implementation follows it.
- **Witnesses.** Fewer than k of each client's n witnesses collude with
  a log (4.5).
- **The WebPKI** issues certificates for a domain only to whoever
  controls it, for fetching key files (4.4) and for witnesses enrolling
  a host's first log (4.10).
- **Devices** keep their stored keys and history away from other
  software, and their clocks within minutes of the right time, and
  never more than an hour off, which epochal confirmation needs
  (12.10).

### D.5. Changes

- **draft-03** (2026-11-08): the zero-trust redesign. First version of
  this appendix.
- **draft-03, review round 1** (2026-11-09): commit streaks and the
  stale-leaf median (12.3, 12.7); seq-ordered roles and a bounded
  past-epoch window (12.9); checks before rejoining a public room
  (12.7); backup generations from the key log, and restored and
  transferred history marked as such (12.13); WANT before a transfer;
  files in archives as blobs; version bytes and labels for files,
  archives, TransferRefs and wrapped keys (12.11, 12.13); report
  conversations for guests (5.8, 12.7); reports are not evidence
  against an identity (5.8); downloads only from the server's own
  origins without asking (12.11); this appendix's risk statuses and
  assumptions; the log pinned in the chain, chain heads, three key file
  states, `retire` records, sealed pairing and witnessing (4.3-4.10).
  Metadata: no TLS resumption (2.1); identifying commands on connections
  of their own, and what the server keeps (4.1, 4.2); TOKEN and bounded
  token sets (7.2); per-period pseudonyms, none on PublicMessages, and no
  limits per pseudonym (7.3, 12.10); mailbox moves after removals (7.8);
  quotas and mailbox expiry (7.5); sealed per-device Welcomes (12.8);
  push delays, padding and expiry (9). MLS: the next token's hash as
  POST's `next`, checked by every device (5.2, 12.6); group checks and
  key checks with repairs, impostor repairs, RESYNC, and resyncing
  public rooms (12.7); public rooms joined only by proposal, without
  device bindings, with commits only from the named device (6.1, 12.3,
  12.6); leaf rotation by Update proposals, a margin before REVEAL, and
  chained period seeds (12.10); one leaf per device and bindings in the
  leaf node (12.3); a committer's Welcomes only once it has won (12.8);
  past-epoch and skipped-key limits, and resends (12.9); read markers
  that check the epoch (7.7).
- **draft-03, review round 2** (2026-11-09), identity and the rest:
  witnesses enrol a host's first log from the key its HTTPS server
  publishes, and log URLs follow from origins (4.4, 4.5, 4.10); one
  definition of a fresh checkpoint (4.5); forked identities and missing
  key files stop only direct conversations, and their leaves are
  removed from rooms that are not public (4.5, 12.14); the new device
  confirms its identity at pairing (4.8); server addresses written one
  way (2.1, 3.5); proof of work not required until it is specified
  (4.1); archived files scoped to their transfer (12.13).
- **draft-03, review round 2** (2026-11-09), groups and MLS: group checks that
  depend only on the group's state, the commit and its post, with no
  look-backs; removals for a check limited to one identity a commit,
  and impostor removals that undo nothing; copies and unused joins in
  public rooms, with no resync window, a bulk limit, and rejoins by
  owners and moderators; streaks per identity; signature key changes
  decided from the tree; activity times capped at the post's `t`
  (12.3, 12.7); per-epoch pseudonyms outside public rooms (7.3); put
  secrets for Welcomes, and public-room Welcomes only from the
  committer, with the server keeping their trees (12.5, 12.6, 12.8);
  derived mailbox boxes and CREATE `from` (7.8, 5.2); TOKEN apart from
  commits' hashes and not in public rooms (7.2); past-epoch secrets
  deleted 2 hours after the commit (12.9); pending records failing
  after 2 hours; the light client's wire format (12.6).
- **draft-03, review round 3** (2026-11-09): in a private room, only an
  identity's own devices or an owner add an owner's devices or remove
  its leaves for a check, and also a moderator for a moderator's
  (12.7); a room's owners are gone only as of the epoch before a commit
  (6.3); devices keep the roles they had in a public room against
  commits made in another's name (12.7); what a server can do in a
  public room's name, who brings back an identity that lost every leaf
  in a private room, and what a new master key does to private rooms,
  stated (Section 14); epochal leaf rotation near midnight and after a
  last-resort KeyPackage (12.3); a mailbox push subscription needs a
  send token (9.1).
- **draft-03, implementation review** (2026-11-09): an outage fails no
  key check, and nobody adds an identity whose key file they have never
  read; a device joining by Welcome checks the leaves already there;
  repairs and removals go first; devices check their own commits before
  posting; an external commit removes at most one leaf (12.5, 12.7,
  12.14); DELETEs and edits from a less trusted leaf wait for it (5.3,
  5.4, 12.10); a leaving device makes no other commit, a lone device
  leaves without one, and a direct participant who left is not added
  back (5.1, 6.1, 12.7); a storage cap that spares posts (7.5); push
  URLs without userinfo, and hosts compared one way (9.1); limits per
  network address, and slow transfers (10.6, Section 14).
- **draft-03, delivery model** (2026-11-10): a model of delivery found
  three problems, now fixed: a device that finds that posts after its
  sync point expired unread can no longer follow the group, and applies
  nothing after the gap (`GapLost`, 7.4, 7.5); the server ends only a
  mailbox created more than a retention period ago (`EndAfterUse`,
  7.5); and a commit whose POST went unanswered is posted again as it
  was, not made anew (`SameCommit`, 7.6). Three wordings: FETCH repeats
  after the page's last seq (7.4), FOLLOW's head counts expired posts
  (7.1), and late posts after a move are judged by the old mailbox's
  order (12.9). Also: messages do not wait for a move (7.8); a device
  that leaves locally first removes its own other leaves (6.1); a
  device joining by Welcome checks only that each leaf's device is
  current (12.7); `bans` holds at most 10,000 uids (6.4, 12.4); an
  external commit and a new public room's CREATE must fit in a line,
  and the server can link a Welcome blob to its mailbox (2.3, 5.2,
  12.12, Section 14).
- **draft-03, delivery follow-up** (2026-11-10): a device that finds a
  gap asks its own devices at once with RESYNC, and posts that expired
  before it joined, or in a mailbox the group moved from, are not a gap
  (7.4, 7.5, 12.7); a leave keeps trying, a lost leave or one that
  fails its checks leaves locally, removing one's own leaves first
  applies in every kind of group, and the alert for a removed own device
  covers leaves (6.1, 12.7); the ban cap and unique uids are format
  rules that everyone checks (12.4); across a move, every removal made
  in the old mailbox counts there (12.9); a commit too old to win may be
  dropped for a new one (7.6); the server refuses a blob-ref in CREATE
  and in an external commit (5.2, 12.12).
- **draft-03, measured limits and leaving** (2026-11-10): an external
  commit is used only if it fits in a line, since each node of the
  joiner's copath resolution adds 1,188 bytes, and a device joins by
  proposal otherwise (6.1, 12.7, 12.12); a POST with the token `-`
  carries no blob-ref (5.2); the conversation extension is at most
  512 KiB, with its uids in lower case (12.4); LEAVE, by which a device
  that left locally asks its own devices to leave for it, and a device
  that left refuses Welcomes only from its own devices (6.1, 12.9);
  RESYNC and LEAVE match any box the group has had (12.9); the server's
  time on PING (Section 11), by which devices judge a commit's age
  (7.6) and when to delete a past epoch's secrets, so that every device
  decides alike, across a move too, in place of a day's grace there
  (7.8, 12.9, Section 14).
- **draft-03, large public rooms recover** (2026-11-11): a public
  room's resync commit or rejoin too large for a line goes as blobs that
  the device stores on its signed-in connection, where it posts the
  commit anyway, in place of joining by proposal, so that a large room
  whose server took a bad commit can still be resynced; a POST with the
  token `-` may name blobs only there, in a public room (4.1, 5.2, 6.1,
  12.6, 12.7, 12.12, Section 14); a Welcome from another member into a
  group the device left for good is an invitation that the user answers
  (6.1); own devices act on LEAVE after a random wait, as on RESYNC,
  and tell their users that the identity left from the device that
  asked (12.9); a RESYNC after every post up to the head expired names
  the head (7.5, 12.9); and devices tell their users when a public room
  cannot be resynced (12.7).

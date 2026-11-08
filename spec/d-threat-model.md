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
  first post (Section 14).
- Cannot: read any message, file, private display name or topic. Learn
  who sent a post, or who is in a direct conversation or a private room,
  except by the links above. Keep those links in what it stores, if it
  follows 4.2, so that a database seized or handed over later does not
  hold them. Add anyone to a conversation, change the
  roles or settings of a room for its members' devices, change or forge
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
  in rooms, remove its leaves from rooms that are not public until the
  file is back, and warn their users (12.14). Show someone meeting the
  identity for the first time a chain of its own in a log on another
  host, which only safety numbers catch (Section 14). Sign in as the
  identity on servers that have not seen it before, and use its account
  there. Stop the identity from signing in to servers that have no
  cached key file.
- Cannot: change the keys of an identity that a device already knows
  unseen: a new chain is a new master key, a fork or a rollback, and
  devices stop trusting it until their users act (4.5, 12.14). Add a
  device unseen by the identity's own devices. Make anyone remove the
  identity from a conversation for good, which takes a `retire` record
  (4.9). Sign a record of an existing chain without its keys.

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
  every device resync, after which it can be banned (12.7). Remove a
  leaf by claiming that a key check fails for it, or by repairing it as
  an impostor, which devices undo and attribute (12.7). Hold a leaf of
  a device it adds, in that device's name, until devices confirm the
  leaf or find it out, about an hour after it first uses a role.
  Within its role, invite, kick, ban, delete and change settings. Remove others' stale leaves,
  within the limits of 12.7. Commit in up to 3 epochs in a row, then
  about once every 10 minutes. Make a transcript that proves nothing to
  others, since members can forge each other's messages for third
  parties. In an epochal group, prove a message to others until its
  period key is published, or later if it timestamped the message's
  hash in public beforehand. Post abuse and report it to operators as
  someone else's. Once removed, watch the old mailbox and post junk
  there, until the group moves (7.8), which it does right after the
  removal. Fork its own chain, or take its key file down, which stops
  only its own direct conversations, and has its leaves hidden in rooms
  and removed from rooms that are not public (12.14).
- Cannot: post as another member to the other members, make another
  member's leaf look confirmed, give a moderator control of an owner's
  leaf by an invitation, read anything sent after it is removed,
  post or act on a role it has lost after the commit that removed or
  demoted it, or add new identities to a room without a role that
  allows it. Get anyone banned by operators on a report alone. Learn a
  member's network address by sharing a file from a host of its own,
  unless that member chooses to fetch it.

**A guest,** or anyone who opens anonymous connections.

- Can: join public rooms that allow guests, and post where `guests` is
  `write`. Join a public room under a credential that names someone
  else's device, which devices then treat as a guest's leaf. Open a report conversation with an owner or moderator of such
  a room, if they accept it, to send reports (5.8). Use up server
  resources within rate limits and quotas, and, once it is specified,
  proof of work (4.1).
- Cannot: take part in private rooms or in other direct conversations,
  send anything but reports in a report conversation, or appear as
  anything but an unverified guest. Commit in a public room, or force
  its devices to join again.

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
  message is deniable only once its period key is out, up to a day and
  an hour later, and a member who timestamps a message in public before
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
  and size, roughly which devices were added to a group together.
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
  group checks and key checks with their repairs, impostor repairs,
  RESYNC and resync commits (12.7), chained period seeds (12.10), and
  `next`, TOKEN and mailbox moves (7.2, 7.8).
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
  first use of a role, removed and undone within about an hour, 12.7).
  A member who adds a device can hold its leaf until devices confirm
  it, and any member can remove a leaf as an impostor, which devices
  that confirmed it attribute.
- **Resyncs in public rooms** (Mitigated: only identities commit, from
  their signed-in connections, and recovery is one commit and batches,
  12.7). A member's invalid commit makes every device of a public room
  recover.
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

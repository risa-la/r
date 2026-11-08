## 14. Security Considerations

This section lists what risala protects, what the server and others can
still do, and the risks it accepts. Appendix D sums it up by adversary.

- **Zero trust in the server.** Devices take nothing that matters from
  the server: not membership, roles or settings (12.4, 12.7), not whose
  keys are whose (4.5, 12.14), and not who wrote a message (12.9,
  12.10). What the server can still do is listed below, and devices can
  see most of it.

- **What is encrypted end to end.** Every conversation, public rooms
  included (Section 12). The server cannot read messages, files, display
  names in private conversations, topics, typing, read markers, blocks
  or reports to moderators. Anyone can join a public room, so a server
  that wants to read one can join it under an identity of its own, like
  anyone else. Its leaf then shows in the room's membership, which is
  public. Encryption still keeps a public room's messages from an
  operator who does not join, or who is compelled to hand over what it
  stores, and keeps the server from changing them.

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
  devices delete a past epoch's secrets once 2 more epochs have started
  or an hour has passed since it ended (12.9). So a device stolen
  today does not decrypt what the server stored earlier. Commits give
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

- **Deniability.** Nothing an identity publishes signs a message or a
  leaf key (4.3, 12.3), and members confirm leaves in ways that convince
  only themselves (12.10). So a message that leaks does not prove to a
  third party who wrote it. The limits:
  - In groups whose `confirm` is `epochal`, a message is deniable only
    once its period key is published, up to a day and an hour after it
    was sent. Until then, a member who captures a message and its
    attestation can prove it. A member who publishes a message's hash
    somewhere public before the key comes out, such as in a public log,
    can prove later that it existed while only its sender could have
    signed it.
  - A device binding (12.3) shows that a device's KeyPackage was used,
    and a member can show that its key is in a group's tree. So being in
    a group is not deniable to someone who has the group's tree, even
    though what was said is.
  - Sign-in signatures (4.6) give the server proof that a device
    connected at a given time.
  - Pairwise confirmation is deniable only if X-Wing's ciphertexts do
    not show who made them, which rests on the KEM's
    plaintext-awareness.
  - Franking (5.8) proves what a message said, but not who sent it.
  - Pairwise confirmation, epochal confirmation, send tokens with "the
    first valid commit wins" (7.2), and pseudonyms (7.3) are risala's
    own constructions. They need a formal model and an outside review
    before they are relied on.

- **What the server learns.** Devices post on anonymous connections
  (4.2), so the server does not learn who sends a message. In direct
  conversations and private rooms, commits are encrypted, so it does not
  learn who is in them. It still learns:
  - every connection's network address and timing. There is no support
    for Tor in this version. An anonymous connection from the same
    address as a signed-in one, or opened at the same time, is easy to
    link to it, so on a server with few users sealed sending hides
    little from an operator who looks.
  - which connections follow which mailboxes, which mailboxes one
    connection follows, and each post's pseudonym, size within its
    padding, and time;
  - which push subscriptions follow which mailbox (9.1), and, through
    their URLs and timing, which subscriptions may belong to one device;
  - that a device of an identity was added to some group, when a Welcome
    arrives for one of its KeyPackages (12.8), and roughly which, from
    timing;
  - whose KeyPackages someone asked for (12.5), and whose presence
    someone watches (8.3);
  - that an identity has an account on the server: sign-ins, KeyPackages,
    backups and its records in the key log;
  - in a public room, its members and their display names, the leaf of
    each light client (12.6), and its topic;
  - whether an identity is online, unless it has turned that off (8.3);
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
  - In a public room it can accept a commit that members' devices
    reject. Devices that were in the room warn their users, and do not
    take the room's new roles silently (12.7). Devices that join the
    room afterwards cannot tell, so a server can set the roles and
    settings that newcomers to a public room see.
  - It is the authority for public room names, and can make up a room,
    hide one, or put a different group under a name. Devices that know
    the room, or follow a link that carries its group id, notice the
    change (6.1). Until a device has joined a public room, the topic and
    member count that LIST shows are the server's word.
  - It can send a false GONE that makes members' devices remove a
    guest's leaf, or hold one back, so that a reused guest name appears
    twice (6.1).
  - Within a generation, it can serve an older backup (above).

- **Insiders.** A member can read the conversation, and can leak it. A
  member can post invalid commits, which cost every device some work
  and which devices ignore (7.2); send tokens, limits per pseudonym and
  proof of work bound how many. A member can take part in confirming
  leaves only for itself: it cannot make another member's leaf look
  confirmed. Any member can remove others' leaves that are stale, more
  than 35 days behind the group's median (12.7), at most a tenth of the
  group in one commit, and must add those devices again if they have
  KeyPackages. A member can commit in at most 3 epochs in a row before
  it has to wait about 10 minutes (12.7). A removed or demoted member
  loses its role from the commit that removes or demotes it (12.9).
  A compromised device of an identity can, until it is removed, send
  that identity's other devices made-up history for the gaps they ask
  it to fill. They show it as copied from that device, and never let it
  replace what they hold (12.13).

- **Who can add a device.** Any device of an identity holds the
  device-signing key, and so can add a device. That shows in the key
  log, where the identity's own devices look for it and warn (4.5).
  Whoever controls the identity's domain can publish a key file with a
  new chain, but every device that knows the identity sees a new master
  key or a fork, and stops sending to it until the user acknowledges it
  (12.14). A server that hosts an identity holds none of its keys, and
  can do no more than the domain's controller. No operator can reset an
  identity.

- **The key log.** A log could show different trees to different
  people. Witnesses refuse to cosign a checkpoint that is not consistent
  with the last one they saw, so this needs k witnesses to collude. A
  log that withholds a record leaves it pending (4.5), which devices
  see. A log lists every uid whose records it holds, so anyone can list
  the identities a server hosts. A log that is unreachable stops devices
  from accepting new records of its identities, but not from using the
  ones they already accepted.

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

- **Server secrets.** Guest tokens (4.2), send tokens (7.2), `put`,
  `get` and `del` URLs (5.6, 12.12), pairing ids (4.8) and push URLs
  (Section 9) work for whoever holds them. Servers SHOULD store only a
  hash of each, look it up by a part that is not secret, and compare the
  secret part in constant time. Franking tags are compared in constant
  time too (5.8, 12.9).

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

- **Spam and abuse.** The server cannot see who posts, so it limits
  load per connection, per network address and per pseudonym, and can
  require proof of work to open anonymous connections, to become a
  guest, to register and to join public rooms (4.1). Room moderators
  remove spammers with commits, and ask the server to mute a pseudonym
  in the meantime (6.4). Operators can ban network addresses for
  anonymous and guest connections (10.2).

- **Display names** can be used to imitate other people (8.2).
  Bidirectional text controls can make one name look like another, or
  make the text after a name look like part of it. So clients compare
  names without them, and show the uid apart from the name.

- **Reports.** Moderators of a room see who wrote a reported message,
  from their own copy. Operators see what it said, proven by franking,
  but only the reporter's claim of who wrote it. A member can report its
  own post as someone else's, so operators act on pseudonyms, mailboxes
  and rooms, and never ban an identity on reports alone (5.8). The
  reporter is told who will see the report. Operators learn who reported
  only if the reporter was signed in.

- **Blocks** are kept by devices, and the server never sees them (5.7).
  Someone who is blocked can still add the person who blocked them to a
  group, which their devices then ignore.

- **Push.** Push bodies are encrypted to the device (9.3). The push
  service, and any gateway in between, still see when pushes happen and
  for which subscription.

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
  which dominates traffic in large rooms.

- **Operators** see what the server sees, and can refuse service: drop
  rooms and mailboxes, mute pseudonyms and ban identities and addresses
  (Section 10). They cannot read any conversation, act as a room's
  moderator, or change anyone's keys. ADMIN WHO shows them every
  connection's network address (10.3).

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
  pseudonym of each post, sign-ins, KeyPackage fetches, watched
  presence, and which device got a Welcome. See the members, display
  names and topic of public rooms. Join a public room under an identity
  of its own and read it from then on, in view of its members. Withhold,
  delay and reorder posts, refuse service, drop mailboxes and rooms,
  and mute pseudonyms. Link anonymous connections to signed-in ones by
  address and timing (Section 14).
- Cannot: read any message, file, private display name or topic. Learn
  who sent a post, or who is in a direct conversation or a private room,
  except by the links above. Add anyone to a conversation, change a
  room's roles or settings, change or forge a message, replay one
  unnoticed, or hide a gap in one member's messages. Reset an identity
  or add a device to one. Read history, since it keeps none beyond
  retention.

**The controller of an identity's domain**, which includes the server
that hosts an identity.

- Can: publish a key file with a new chain, or no key file at all.
  Stop the identity from signing in to servers that have no cached key
  file.
- Cannot: do any of that unseen. A new chain is a new master key or a
  fork to everyone who knows the identity, and their devices stop
  sending to it until their users act (4.5, 12.14). Sign a record of an
  existing chain without its keys.

**A key log and its witnesses.**

- Can: refuse or delay records, which then stay pending (4.5). A log
  and k colluding witnesses can show different trees to different
  people.
- Cannot: change a record, which the identity's keys sign. Show two
  trees while fewer than k of a client's witnesses collude.

**A member of a conversation,** including a moderator or owner.

- Can: read and leak the conversation from when it joined. Post invalid
  commits, which cost others some work (7.2). Within its role, invite,
  kick, ban, delete and change settings. Make a transcript that proves
  nothing to others, since members can forge each other's messages for
  third parties. In an epochal group, prove a message to others until
  its period key is published, or later if it timestamped the message's
  hash in public beforehand.
- Cannot: post as another member to the other members, make another
  member's leaf look confirmed, read anything sent after it is removed,
  or add new identities to a room without a role that allows it.

**A guest,** or anyone who opens anonymous connections.

- Can: join public rooms that allow guests, and post where `guests` is
  `write`. Use up server resources within proof of work and rate limits.
- Cannot: take part in direct conversations or private rooms, or appear
  as anything but an unverified guest.

**Someone who steals a device,** or compromises one for a while.

- Can: read the history stored on it, and everything sent to its groups
  until its leaves are removed. Use its device-signing key to add a
  device, which the key log shows. Read the backup made with the backup
  key it holds, until the next generation.
- Cannot: read messages whose keys the device had already deleted, or
  messages sent after the device's leaves are removed, or after the
  device itself commits fresh keys, once the attacker has lost access
  (post-compromise security). Remove the identity's other devices, which
  needs the recovery key.

**Someone who gets the recovery key.**

- Can: control the identity: replace its devices, and read its newest
  backup.
- Cannot: read conversations without joining them as a new device, which
  the identity's contacts see.

**Push services and gateways.**

- Can: see when each subscription gets a push.
- Cannot: read push bodies, which are encrypted to the device (9.3), or
  tell which identity a subscription belongs to from the push itself.

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

- **No Tor in this version.** The server sees every connection's network
  address and timing, and can link anonymous connections to signed-in
  ones by them. On small servers, sealed sending hides little from an
  operator who looks.
- **Presence stays on the server.** It knows when each identity is
  online. Presence is off by default; an identity that turns it on is
  shown to anyone on the server who asks (8.3).
- **Public rooms show their membership** to the server and to anyone who
  joins, so that the server can check commits and serve light clients.
  A light client also tells the server its leaf.
- **Delayed deniability in large rooms.** In epochal groups, a message is
  deniable only once its period key is out, up to a day and an hour
  later, and a member who timestamps a message in public before then
  can prove it later.
- **Few post-quantum witnesses.** Clients count only ML-DSA-44
  cosignatures (4.5), and few public witnesses may offer them at first.
  Until enough do, a client's witness list is short, and k colluding
  witnesses are easier to find.
- **Classical parts.** TLS certificates and push encryption still use
  classical algorithms.
- **Metadata from KeyPackages, Welcomes and watch lists.** The server
  sees whose KeyPackages are fetched, which device gets a Welcome, and
  whose presence is watched.
- **The key log lists identities.** Anyone can list the uids whose
  records a log holds.
- **Backups are not forward secret.**
- **New constructions.** Pairwise and epochal confirmation, send tokens
  with "the first valid commit wins", and pseudonyms are this document's
  own, and have not yet been reviewed or formally modelled.
- **Sizes are not yet measured.** The room limits may change once ML-DSA
  and X-Wing have been measured on phones.

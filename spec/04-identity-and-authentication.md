## 4. Identity and Authentication

### 4.1. The Greeting

As soon as TLS is set up, the server sends:

```
RISALA <version> <host> <nonce> [<message...>]
```

- `<version>` is `1` for this document.
- `<host>` is the hostname from SNI, in lower case. If the client sent
  no SNI, it is the server's own main hostname.
- `<nonce>` is 16 to 64 bytes from a cryptographically secure random
  source, written in lower-case hex. It is unique to this connection.
- `<message...>` is an optional welcome text, at most 512 bytes.

A new connection then becomes one of three kinds, once, and stays that
kind until it closes:

- **Signed in**, with AUTH (4.6) or REGISTER (4.7). The connection acts
  for an identity and one of its devices. It is used for what belongs to
  the account: KeyPackages, Welcomes, key files, backups, presence and
  push for the account (Sections 8, 9 and 12).
- **Anonymous**, with ANON (4.2). The connection says nothing about who
  uses it. It is used for everything to do with conversations: posting,
  following mailboxes and fetching (Section 7). A device posts only on
  anonymous connections, so that the server does not learn who sends.
- **Guest**, with GUEST (4.2). Like an anonymous connection, with a
  guest name for public rooms.

Until it becomes one of them, the server accepts only INFO without a
room, ANON, GUEST, AUTH, REGISTER, KEYS PUT, PAIR, PING, PONG and QUIT,
and replies `ERR not-authenticated` to anything else. Once it is one of
them, a command that needs another kind of connection gets
`ERR wrong-connection` (Section 13).

A device keeps one signed-in connection and at least one anonymous
connection open while it is online. Section 14 says what the server can
still link between them.

**Keeping connections apart.** An anonymous connection is anonymous only
as long as nothing sent on it names the device. So:

- A device MUST send each command that names or proves its identity,
  device, leaf or KeyPackage either on its signed-in connection, where
  Section 13 allows it there, or on a connection of its own, which it
  opens for that command, uses for nothing else and closes afterwards,
  never on an anonymous connection that it uses for anything else. These
  are KEYS PUT (4.7), PAIR PUT and PAIR GET (4.8), WELCOME GET (12.8),
  FETCH with `leaf` (12.6), and every PublicMessage it posts: in a
  public room, every commit, external commit and proposal, whose sender
  the server can read (12.6). A light client keeps one such connection
  open for its fetches with `leaf`, and uses it for nothing else.
- A device MUST store the blobs and files that a post or a Welcome
  refers to over an anonymous connection (5.6, 12.12), never over its
  signed-in one, which would tie the post to the identity.
- A device SHOULD use a fresh anonymous connection for each CREATE,
  each KEYPKG GET (12.5) and each WELCOME PUT (12.8), and a separate
  anonymous connection for WATCH (8.3), since each says something about
  whom the device talks to.

Section 14 says what a device's anonymous connections can still reveal
about each other.

**Proof of work.** A server MAY require a client to solve a
proof-of-work puzzle before ANON, GUEST or REGISTER succeeds, before
CREATE, before KEYPKG GET on an anonymous or guest connection (12.5),
and before an anonymous or guest connection joins a public room (6.1).
The puzzle, and how it is bound to the connection, are specified
separately: this paragraph holds the place of that specification, which
will make proof of work on by default.

Servers SHOULD allow at least 120 seconds to sign in or become
anonymous.

### 4.2. Anonymous Connections and Guests

```
ANON
```

→ `OK`

The connection becomes anonymous. It can then use the commands of
Sections 5 to 7 that the summary in Section 13 marks for anonymous
connections. The server MAY limit how many anonymous connections one
network address keeps open, and MUST limit how much each connection and
each network address posts and stores (5.2, 7.5).

**What the server keeps.** Without Tor (Section 14), a server that
watches in real time can often link an anonymous connection to a
signed-in one by its network address. What anonymous connections can
still protect is data the server stores, against anyone who later reads
it: a database that is seized, or that the operator is compelled to hand
over. So:

- A server MUST NOT keep, beyond the life of the connection (or of a
  guest's session, below), the network address of an anonymous or guest
  connection, or any link between such a connection and a signed-in
  connection, a post, a follow, a mailbox, a token, a blob, an upload, a
  Welcome, a report or a push subscription.
- A post is stored with its box, seq, time and message only (5.2). A
  mailbox, blob, upload, Welcome or mailbox push subscription is stored
  without the connection or address that made it.
- State kept per network address for rate limits and quotas is kept in
  memory only, or for no longer than the limit's window. Address bans
  (10.2) hold the banned address, and nothing about the connections that
  led to them.
- Operators' logs follow the same rules. Implementations MUST NOT log
  the addresses of anonymous and guest connections by default.
- ADMIN WHO (10.3) shows open connections only.

```
GUEST <name> [token=<token>]
```

→ `OK uid=~<name> token=<token> [resumed=yes]`

A guest is an anonymous connection with a name, so that it can take part
in public rooms that allow guests (6.2). Guests join public rooms only.
The one other conversation a guest may start is a direct conversation
with an owner or moderator of a room it is in, to report a message
(5.8). For that, a guest connection may also fetch the moderator's
KeyPackages, create the conversation's mailbox and send its Welcomes
(Section 13).
A guest has a name for as long as its **session** lasts. The session
starts with GUEST and ends a while after its connection closes, unless
the guest resumes it (see below). Once it ends, another guest may take
the same name, so a guest uid says nothing about who someone is over
time. For this reason guests:

- cannot take part in private rooms, or in direct conversations other
  than the report conversations above, in which they may only send
  REPORT lines (5.8, 12.7)
- cannot create rooms, hold roles, upload files or register for push
- join a public room's group with a throwaway leaf key, whose credential
  names the guest uid (12.3). Devices show guests as unverified.
- leave their rooms' groups when their session ends. Members' devices
  remove guest leaves whose session has ended (6.1).

**Resuming.** The token in GUEST's `OK` lets a guest come back after its
connection closes, for example after a network drop:

- The token is an id (3.5) with at least 128 bits of randomness. It is a
  secret: anyone who has it can take over the guest's name.
- When a guest's connection closes for any reason, QUIT included, the
  server keeps its session and name for a resume period of its choosing,
  at least 2 minutes. Only then does the session end.
- `GUEST <name> token=<token>` with the session's current token resumes
  it. If another connection still has the session, the server closes
  that one with BYE and reads no more commands from it. The `OK` carries
  `resumed=yes` and a new token, and the old token stops working.
  Without `resumed=yes`, a new session has started.
- A token that matches no current session for that name is ignored, and
  GUEST works as it does without one.
- ADMIN DISCONNECT (10.3) and server bans (10.2) end a guest's session
  at once.

The server replies `ERR name-taken` while a session holds the name,
whether its connection is open or it is waiting to be resumed. A client
that cannot resume SHOULD then try another name. The server MAY reserve
names, for example the names of identities it hosts. It MAY refuse
guests entirely with `ERR forbidden`.

When a guest's session ends, the server tells the public rooms it was in
with a GONE line (6.1), so that members' devices remove its leaves.

### 4.3. Identities

An identity looks like an email address, for example
`alice@example.org`. Whoever controls the key file at this URL controls
the identity:

```
https://example.org/.well-known/risala/alice
```

The key file is a chain of signed records (4.4). Every record is also
published in a witnessed key log (4.5), which the chain itself names. So
once a device knows an identity, the controller of the domain cannot
change the identity's keys for that device, or add a device to it,
without that device or the identity's own devices noticing. The first
time a device meets an identity, it cannot tell whether the chain it is
shown is the one that the identity's owner watches: safety numbers
(12.14) protect that first contact, and Section 14 says what remains. No
chat server is in charge of any identity, and a server never asks
another chat server about a user.

An identity's domain and the chat server are independent of each other.
`alice@example.org` can use `chat.example.org`, `chat.example.net` or
any other server.

An identity has these keys:

| Key | Algorithm | Held by | Signs |
|---|---|---|---|
| **Recovery key** | 32 random bytes | the person, written down | nothing itself. The master key and the backup keys are derived from it (4.8, 12.13) |
| **Master key** | ML-DSA-44 | derived from the recovery key when needed | `master`, `signing`, `log` and `retire` records (4.4) |
| **Device-signing key** | ML-DSA-44 | every device of the identity | `device` records (4.4) |
| **Device key** | ML-DSA-44, one per device | that device | sign-in (4.6), its own pairing message (4.8), KeyPackage bindings (12.5) and period-key certificates (12.10) |
| **Attestation key** | X-Wing, one per device | that device | nothing. It answers leaf challenges (12.10) |
| **Leaf keys** | ML-DSA-44, one per device and group | that device | MLS messages and commits in that one group (12.3) |

The keys listed in the key log never sign anything that names a
message, a group or a leaf's signature key. That is what keeps messages
deniable (12.10).

Every private key in this document is the 32-byte seed of its key pair
[FIPS204] [XWING], and the seed alone is the key:

- Implementations store only the seed, and derive the expanded private
  key from it when they need it.
- An implementation that imports a private key, for example from a PEM
  file in PKCS#8, MUST derive the key from the seed. If the file also
  holds an expanded private key, it MUST check that it equals the one
  derived from the seed, and reject the file if not. A file with only an
  expanded private key is rejected.

**Signing with a label.** Except for sign-in (4.6), every signature this
document defines is made with **RisalaSign**:

```
struct {
    opaque label<V>;
    opaque content<V>;
} RisalaSignContent;
```

RisalaSign(key, Label, Content) is ML-DSA.Sign [FIPS204] over the
encoded RisalaSignContent whose `label` is `risala/1 ` followed by
Label, in ASCII, and whose `content` is Content. It uses an empty
context string and no prehash. RisalaVerify checks it the same way.
Signers SHOULD use the hedged (randomised) variant of ML-DSA, which
resists fault attacks better than the deterministic one. Verifiers
cannot tell them apart.

### 4.4. Key Files

A key file is UTF-8 text, served as described in 4.3. It names the logs
that hold the identity's records, and lists the records by their place
in those logs:

```
risala-keys/1
log <vkey> <url>
<index> <hash>
<index> <hash>
…
- <record>
```

- Every line ends with LF, the last one included. No line contains a CR
  or a TAB, starts or ends with a space, or has two spaces in a row.
  Empty lines and lines that start with `#` are ignored. Any other line
  that is not one of those below makes the file invalid.
- The first line is exactly `risala-keys/1`. A file with any other first
  line is not a key file of this version, and its identity's keys are
  missing (below).
- A **`log` line** names a key log (4.5): `<vkey>` is the log's
  signed-note verifier key [SIGNED-NOTE], and `<url>` its `https` URL
  prefix [TLOG-TILES], without a `/` at the end. The verifier key is
  the log's origin, a `+`, the key ID as 8 lower-case hex digits, a `+`,
  and the base64 with padding of the byte `0x06` followed by the log's
  1312-byte ML-DSA-44 public key. The key ID is the first 4 bytes of the
  SHA-256 hash of the origin, an LF, the byte `0x06` and the public key.
  For example, shortened:
  `log chat.example.org/risala-log/1+4d1e07a2+BhO3…Zw== https://chat.example.org/risala-log/1`.
- The second line is a `log` line. Each `log` line names the log that
  holds the records listed after it, up to the next `log` line. There is
  another one before the first record that the chain puts in another log
  (4.5), after a `log` record or at a hand-off. After a `log` record, it
  may also end the file, to name the log that the next records go into.
  No `log` line follows another.
- A **record line** is `<index> <hash>` for a record that is in the log:
  `<index>` is its position in the log as a number (3.3), and `<hash>`
  its SHA-384 hash as a blob-ref (3.5). Indices increase within each
  log. A record that is not logged yet is listed as `- <record>`, the
  encoded Record (below) in base64 with padding [RFC4648]. Only the
  newest records may be unlogged: no `<index>` line follows a `-` line.
- Records come in chain order, oldest first.
- Base64 here is strict: with padding, with no line breaks, and with
  zero padding bits.

A reader gets the record of each `<index> <hash>` line from the log's
entry bundles [TLOG-TILES], and checks that the entry at that index is
that record (4.5). It fetches them under the same rules as the key file
(below).

```
enum {
    reserved(0),
    master(1),
    signing(2),
    device(3),
    log(4),
    retire(5),
    (255)
} RecordType;

struct {
    opaque origin<V>;            // the log's origin (4.5), in ASCII
    opaque key<V>;               // 0x06, then the log's 1312-byte ML-DSA-44 public key
} LogKey;

struct {
    opaque device_key<V>;        // ML-DSA-44 public key, 1312 bytes
    opaque attestation_key<V>;   // X-Wing public key, 1216 bytes
    opaque label<V>;             // UTF-8, at most 64 bytes
} DeviceKeys;

struct {
    uint8 version;               // 1
    RecordType type;
    opaque uid<V>;               // the identity, in lower case
    opaque previous<V>;          // SHA-384 of the previous Record; empty in the first
    uint64 time;                 // milliseconds since 1970-01-01T00:00:00Z
    select (RecordContent.type) {
        case master:
            opaque master_key<V>;      // ML-DSA-44 public key
            opaque signing_key<V>;     // ML-DSA-44 public key
            LogKey log;
        case signing:
            opaque signing_key<V>;     // ML-DSA-44 public key
            opaque removed<V>;         // device ids, 48 bytes each, sorted
        case device:
            DeviceKeys keys;
        case log:
            LogKey log;
        case retire:
            struct {};
    };
} RecordContent;

struct {
    RecordContent content;
    opaque signature<V>;
} Record;
```

A device's **device id** is the SHA-384 hash of its raw device key. The
records do this:

- **`master`** names a master key, a device-signing key and the key log
  of the chain. The first record of every chain is a `master` record,
  and its `signature` is RisalaSign(its own master key, "record",
  content). A later `master` record replaces the master key (4.8): its
  `signature` is two signatures, one after the other, RisalaSign(key,
  "record", content) by the master key it replaces and then by the new
  one. It also names a new device-signing key, and the same log as
  before. The devices stay.
- **`signing`** replaces the device-signing key, and removes the devices
  in `removed`. It is signed by the current master key. Removing a
  device always takes a new device-signing key, since the removed device
  holds the old one (4.8).
- **`device`** adds a device, with its device key, its attestation key
  and a label for people, usually the device's name. It is signed by the
  current device-signing key.
- **`log`** moves the chain to another key log (4.8). It is signed by the
  current master key, and is the last record that goes into the old log.
  The records after it go into the log it names.
- **`retire`** ends the identity (4.9): after it no device is current,
  and no record may follow it. It is signed by the current master key.

A chain's **generation** is the number of its `signing` records plus the
number of its `master` records after the first. It numbers the backup
keys (12.13), so that the generation in use never depends on what a
server says.

**Valid key files.** A key file is **valid** if it parses, and its chain
replays, as below. Anything that reads a key file, server or device,
MUST check all of it, and MUST treat a file that fails as invalid.

Parsing:

1. The text follows the rules above.
2. Every Record decodes exactly, with vector lengths in their shortest
   form as [RFC9420] requires, and nothing after its last field. Its
   `version` is 1, and its `type` one of those above. An encoded Record
   is at most 16 KiB (16384 bytes).
3. The chain has at most 4,096 records. That is far above normal use,
   but chains only grow, so a device tells its user once its identity's
   chain passes 3,072 records, while there is room to move to a new
   identity.

Replaying, record by record, in order:

1. The `uid` is an identity (3.5), in lower case, and the same in every
   record. It is the identity whose URL the file came from.
2. The first record is a `master` record with an empty `previous`. Every
   other record's `previous` is the SHA-384 hash of the encoded Record
   before it, and it is not a `master` record with an empty `previous`.
3. Each record's `time` is later than the time of the record before it.
4. The `signature` is 2420 bytes, or 4840 in a later `master` record,
   and verifies as described above, under the keys that are current
   after replaying every earlier record.
5. Every ML-DSA-44 key is 1312 bytes, and every X-Wing key passes the
   checks of 12.2. A LogKey's `key` is 1313 bytes and starts with
   `0x06`, and its `origin` has the form of 4.5. No public key appears
   twice in the chain, in any role: master keys, device-signing keys,
   device keys and attestation keys are all different from each other.
6. A later `master` record names the chain's current log.
7. A `signing` record's `removed` is not empty, its length is a multiple
   of 48, its ids are sorted in increasing byte order without repeats,
   and each one is a current device.
8. A `device` record adds a device whose id the chain has never added
   before, current or removed. Its label is valid UTF-8 of at most 64
   bytes. After it, at most 64 devices are current.
9. A `log` record names another log than the current one.
10. A `retire` record is the last record.
11. Each record is listed under a `log` line that names the record's
    log: the log of the chain's newest `master` or `log` record before
    it (a first `master` record is in the log it names), or a later log
    of the same host that this one handed off to (4.5).

A record whose `time` is more than 10 minutes ahead of the reader's
clock makes the fetch an outage (below) rather than the file invalid,
since the reader's clock may be the one that is wrong.

Replaying the chain gives the identity's **current** master key,
device-signing key, log, devices and generation. Only current devices
may sign in, and only their leaves are accepted in groups (12.7).

**Fetching.** A key line is about 110 bytes, and a Record about 5 KiB,
so a key file of 4,096 records is under 0.5 MiB. When a server or device
fetches a key file:

- It MUST use HTTPS with TLS 1.3, and validate the certificate against
  public certificate authorities.
- It MUST NOT follow redirects.
- It MUST stop after 10 seconds or 2 MiB. It fetches the log's
  checkpoint, tiles and entry bundles (4.5) under the same rules, with
  a limit of 8 MiB each.
- A server MUST NOT connect to loopback, private, link-local or other
  special-purpose addresses [RFC6890] unless its operator has configured
  it to. Users choose the domain, so without this rule they could make
  the server probe its own internal network.
- It MAY cache the file for up to one hour, and SHOULD use HTTP
  validators (`ETag` and `If-None-Match`) when it fetches it again. If a
  signature does not verify against a cached file, it SHOULD fetch the
  file again once before failing, so that a newly added device works
  straight away.

**Three states.** After a fetch, a reader's view of the identity is in
one of three states:

- **Keys.** A 200 response, within the limits, whose body is a valid key
  file that extends the chain the reader holds (below). The identity's
  keys are the current ones of the chain. A device that a record
  removes, and every device of an identity whose chain ends with a
  `retire` record, has been **removed by record**, once the reader has
  accepted that record (for a device, 4.5; a server takes it from a
  valid key file that extends its pin, 4.6).
- **Keys missing.** A 404 or 410 response, a body larger than 2 MiB, a
  file whose first line is not `risala-keys/1`, a file that is not
  valid, or one whose `<index> <hash>` lines do not match the log. None
  of these is signed, so none of them removes anything. While an
  identity's keys are missing, nobody signs in with them, and devices
  send nothing to the identity and warn their users (12.14), but keep
  its leaves.
- **Outage.** Anything else: no response, a DNS or TLS error, a timeout,
  a 5xx response, any other status, including a redirect, a failed fetch
  from the log, or a record time in the future. This says nothing about
  the identity's keys, and changes nothing.

A valid key file replaces a cached copy only if it **extends** it: the
newest record that the reader holds for the identity is in its chain.
For a device, that is its head (4.5). A valid key file that does not
extend it is a **rollback**: a device treats it as a fork (4.5), and a
server as keys missing (4.6). A device id that a reader has once seen
removed by record stays removed for that reader, whatever a later key
file says. Keys missing and outages replace nothing: the reader keeps
the chain it holds, and a cached copy stays usable until its hour is up.

A server that sees a device removed by record, or an identity's keys
missing, SHOULD close the connections that signed in with that device's
key, or with the identity's keys. An outage is not a reason to close
anything, however long it lasts.

A server checks that a key file is valid and extends its pin (4.6).
Devices also check every record against the key log before they act on
it (4.5).

### 4.5. The Key Log

Every server that hosts identities (4.7) keeps a **key log**: an
append-only Merkle tree [RFC6962] of the records of the identities it
hosts. It MAY also log the records of other identities whose chains
name it (4.7, KEYS PUT). A key log uses the C2SP formats:

- **Entries.** Each entry is an encoded LogEntry:

```
enum { reserved(0), record(1), handoff(2), (255) } LogEntryType;

struct {
    uint8 version;               // 1
    LogEntryType type;
    select (LogEntry.type) {
        case record:  Record record;   // 4.4
        case handoff: LogKey next;     // the log that takes over
    };
} LogEntry;
```

  The tree is the tree of [RFC6962] with SHA-256, as [TLOG-TILES]
  requires. The entry at a key file's `<index>` is the record entry
  whose Record has the SHA-384 hash `<hash>`.
- **Serving.** The log serves its checkpoint, hash tiles and entry
  bundles under its URL prefix as [TLOG-TILES] describes, over HTTPS.
  It also serves two hints:
  - `<url>/risala/uid/<hash>`, where `<hash>` is the SHA-256 hash of a
    uid in lower-case hex: the indices of that uid's entries, as
    numbers, one per line, in increasing order, each ending with LF; or
    a 404 response if it has none.
  - `<url>/risala/next`: the index of the log's hand-off entry, as a
    number and an LF, once it has one; a 404 response before.
  Readers check every index they use with an inclusion proof. A log
  that leaves an entry out of a hint is caught by its identities' own
  devices (Watching, below).
- **Checkpoints** follow [TLOG-CHECKPOINT]. A log's origin is its
  hostname in lower case, `/risala-log/` and a number, for example
  `chat.example.org/risala-log/1`. A host's first log is number 1, and
  each later one the next number, after a hand-off (below).
- **The log's signature.** The log signs each checkpoint with ML-DSA-44,
  as a timestamped ML-DSA-44 checkpoint signature (signed-note signature
  type `0x06`) [SIGNED-NOTE] [TLOG-COSIGNATURE] over the whole tree,
  under a key whose name is the log's origin, with a timestamp that is
  not zero. Its verifier key is the `<vkey>` of the `log` lines that
  name the log, and its public key the one in the LogKeys that name it.
- **Witnesses.** The log sends each new checkpoint to witnesses with the
  `add-checkpoint` request of [TLOG-WITNESS], and serves the checkpoint
  with the cosignatures it got back. Witnesses check that each
  checkpoint is consistent with the last one they cosigned, so a log
  cannot show different trees to different people without a witness
  refusing. Witness cosignatures MUST be ML-DSA-44 (type `0x06`)
  [TLOG-COSIGNATURE], with a timestamp that is not zero. Clients ignore
  cosignatures of any other type, such as Ed25519, and with a zero
  timestamp, so they do not count towards k. Section 4.10 says how a
  log gets witnesses.
- **Timing.** A log SHOULD get a witnessed checkpoint that includes a new
  record within one minute of adding it, and MUST within one hour. It
  gets a new witnessed checkpoint at least once a day even when nothing
  is added, until it hands off.

**Appending.** A log appends a record only if all of these hold:

- The uid's chain, as far as the log holds it, stays valid with the
  record (4.4). For a uid that it does not hold yet, the log gets the
  whole chain (4.7), and checks all of it.
- The record follows the newest record of the uid that the log holds, or
  is the first record the log holds of it. A record whose `previous` is
  already followed by another record is refused, even if their contents
  are equal.
- The chain puts the record in this log (4.4, replaying step 11).
- It is not a first `master` record of a uid of which this log, or an
  earlier log of the same host, already holds one.
- The chain stays within 4,096 records, and the encoded Record within
  16 KiB.

A log never removes an entry.

**Hand-offs.** A host starts a new log, for example to replace its log's
key, by appending to its current log `n` a hand-off entry whose `next`
names log `n`+1 (`<host>/risala-log/<n+1>`) and its key. After that
entry, log `n` appends nothing more, and every chain whose records were
going into log `n` continues in log `n`+1: its next record goes there,
with no record of its own for the move. Log `n`+1 holds the records of
log `n` as the start of those chains, for KEYS PUT (4.7) and for the
appending rules above, without appending them again. A reader follows a
hand-off only when the hand-off entry is the last entry of a witnessed
checkpoint of log `n`, with an inclusion proof. A log `n` > 1 without a
hand-off from log `n`-1 is not valid: readers ignore it, and witnesses do
not enrol it (4.10). A host that loses its log's key cannot hand off, and the chains
in that log can grow no more, so operators MUST keep the key safe and
backed up (Section 14).

**Witness policy.** Each client has a list of witnesses it trusts, as
signed-note verifier keys, and a number k, which is more than half the
length of the list. A checkpoint is **witnessed** when its log's
signature verifies, under the key that the chain or the hand-off names,
and at least k different witnesses of the list have cosigned it. A
cosignature counts for a witness of the list only if both its key name
and its key match, not just its 4-byte key ID, and each witness counts
once. The log's own signature never counts towards k. Apps ship a
default list (4.10), and update it with their releases. Users MAY change
it. A client that finds no checkpoint of a log with k cosignatures from
its list, even an old one, shows the user that its witness list does not
fit that log, rather than showing the records as pending.

**Accepting a record.** A device acts on a record of an identity, for
example by accepting a leaf of a device the record adds (12.7), only
once all of these hold:

1. The record is part of the identity's valid key file (4.4), which
   extends the device's head for that identity (Pinning, below).
2. The key file gives the record's index, and the entry at that index of
   the record's log is the record.
3. An inclusion proof of that entry verifies against a witnessed
   checkpoint of the log.
4. That checkpoint is consistent with the newest witnessed checkpoint of
   the same log that the device has seen, which it then keeps.
5. If the record's log is a later log of the host than the one the chain
   names, the device has accepted each hand-off in between, the same
   way.

The device computes the proofs of steps 3 and 4 from the log's tiles
[TLOG-TILES]. A record that does not yet pass is **pending**. A device
does not act on pending records, and tries again from time to time.

**Pinning.** The first time a device accepts an identity's records, it
pins the identity's master key and log, and its **head**: the hash and
index of the newest record of the identity that the device has
accepted. The head only moves forward, to a record of a key file that
extends it, and the pinned log only with an accepted `log` record or
hand-off.

- A valid key file whose chain does not hold the head is a rollback
  (4.4), which the device treats as a fork (below).
- A key file whose chain starts with another master key is a **new
  master key**: the device stops sending to the identity until the user
  acknowledges it (12.14). A `master` record that replaces the master
  key within the same chain is a new master key too.

**Freshness.** Each time a device fetches an identity's key file again
(12.14), it also:

1. fetches the newest checkpoint of the identity's current log,
   following its hand-off (`risala/next`) if it has one, and checks that
   it is witnessed, consistent with the newest one the device has seen,
   and that k of its cosignatures are less than 24 hours old;
2. reads the uid's hint (`risala/uid/`), and checks every entry of the
   uid after its head that the key file does not hold. A logged record
   of the uid that the key file leaves out makes the key file a fork, if
   it conflicts with the chain, and a rollback otherwise.

An identity whose view a device has not refreshed this way for 7 days
is **stale**. The device shows that it is, and adds none of its devices
to groups (12.7) until it is fresh again, but keeps sending to it.

**Forks.** A device has found a **fork** when it sees:

- two records of one uid with the same `previous` whose RecordContents
  differ, whether in a log, in key files, or one in each. Two records
  whose contents are equal and whose signatures both verify, for
  example because a device signed the same record twice with hedged
  signing, are the same record, and the device uses the one in the log.
- two `master` records of one uid with an empty `previous`, both in logs
  of the host whose log the identity's key file names, or both in key
  files fetched from the identity's URL. A chain in another log, which
  the identity's key file does not name, is not the identity's.
- two witnessed checkpoints of one log that are not consistent with each
  other
- a rollback (4.4)

A fork means that someone has shown two different histories of an
identity, or a log two different trees. For every identity in a fork,
including every identity in a log that forked, the device stops sending
in each conversation where that identity has a leaf, and tells the user,
until the user resolves it, for example by checking the safety number
with the person (12.14) and choosing which keys to trust.

**Watching your own records.** At least one device of each identity MUST
do the following at least once a day, and every device that comes back
after more than a day offline MUST do it before it sends anything:

1. fetch the newest checkpoint of its identity's current log, following
   its hand-off if it has one, and check that it is witnessed,
   consistent with the last one it saw, and that its cosignatures are
   less than 24 hours old;
2. read its uid's hint (`risala/uid/`), and fetch every entry it lists
   that the device has not seen;
3. check those records against its own chain.

The hint costs a few bytes a day. To catch a log that leaves entries out
of it, each device SHOULD also read every entry bundle added to the log
since it last did so, at least once a week, or a random sample of them
every day (Section 14).

A device announces each record it makes to the identity's other devices,
with RECORD in the conversation with itself (12.9). A record of its uid
that no device announced within 24 hours after the first witnessed
checkpoint that included it, or a fork, means that someone else may
control the identity. The device tells the user, and sends `ALERT`
(12.9) in the conversation with itself, so that every device of the
identity tells the user too. A device that comes back after more than a
day offline may have missed RECORD lines, so it first asks its own
devices with RECORDS (12.9), and alerts only for records that none of
them knows.

The log lists every uid whose records it holds. Section 14 says what
that reveals.

### 4.6. Signing In

```
AUTH <identity> <signature>
```

→ `OK uid=<identity>`

Guests do not sign in, so a guest uid gets `ERR bad-syntax`.

The client signs these bytes with its device key:

```
"risala-auth-1" LF host LF nonce LF uid LF
```

- `host` is the hostname the client connected to, exactly as it sent it
  in SNI, in lower case. The client MUST use its own value, not the one
  in the greeting.
- `nonce` is the nonce from the greeting.
- `uid` is the identity, in lower case.

`<signature>` is the 2420-byte ML-DSA-44 signature [FIPS204], in base64
with padding, which is 3228 characters long. It is plain ML-DSA.Sign,
with an empty context string and no prehash, over these bytes, not
RisalaSign (4.3). Signers SHOULD use the hedged variant. Appendix B's
worked example uses the deterministic variant so that it can be checked.

The server checks the signature as follows:

1. It checks that the connection's SNI hostname is a name it serves:
   its configured hostname, or a name on one of its certificates. If it
   is not, or the client sent no SNI, the server MUST refuse AUTH and
   REGISTER with `ERR auth-failed`. Its message SHOULD say that the host
   name is wrong, so that a client does not tell the user their key was
   removed.
2. It builds the same bytes, using this connection's SNI hostname and
   nonce.
3. It gets the identity's current device keys. If it hosts the identity
   itself (4.7), it uses its own records. Otherwise it fetches the key
   file (4.4), or uses a cached copy, and the records from the log.
4. It accepts if the signature verifies under any of those device keys.
   The master key and the device-signing key never sign in.

On success the server replies `OK uid=<uid>`, and adds `op=yes` if the
identity is a server operator (Section 10). The key that verified becomes
the connection's **device key**. On failure the server replies:

- `ERR auth-failed` if step 1 fails, or if the signature does not verify
  under the keys the server got. A key file that does not list the key,
  and an identity whose keys are missing (4.4, and Pins below), count as
  keys the server got: the identity has none that verify.
- `ERR unavailable` if the fetch failed (4.4) and the server has no
  cached copy, so it could not check the signature at all. This
  includes the case where a cached copy did not verify and fetching
  again failed. It MAY add a `retry` tag.

A client that gets `unavailable` SHOULD reconnect and try again later,
waiting longer after each failure, and at least as long as `retry`
says. A client that gets `auth-failed` SHOULD NOT try again on its own,
since the same key will fail the same way. It tells the user instead.

**Pins.** A server pins, for each identity it does not host, the master
key of the first chain it accepts for it, and the newest record of it
that the server holds (its head). From then on it accepts only key files
that extend the head (4.4). A chain that starts with another master key,
or does not hold the head, means that the identity's keys are missing
for this server, so nobody signs in as it, until an operator clears the
pin with ADMIN UNREGISTER (10.5). A server SHOULD also check each record
against the key log, as devices do (4.5). Section 14 says what remains.

Each part of the signed bytes has a job:

- **The first line** keeps the signature from meaning anything in
  another protocol, or as a RisalaSign or MLS signature.
- **The host** stops a server from using a signature it received to sign
  in somewhere else. Without it, a malicious server could pass another
  server's nonce to the client, then use the client's answer to sign in
  there as that user. The host alone is not enough, since the malicious
  server could connect to the other server with its own name in SNI.
  Step 1 closes that gap: the other server refuses a name it does not
  serve.
- **The nonce** stops replay.
- **The uid** ties the signature to one identity.

Any AUTH or REGISTER command that parses uses up the connection's nonce,
whether it succeeds or not. To try again, reconnect.

A sign-in signature gives the server a transferable proof that a device
of the identity connected at that time. It says nothing about any
message, since devices post on anonymous connections (Section 14).

### 4.7. Registration and Hosted Key Files

A server MAY host identities under a domain it controls, called its
**identity domain**. For example, `chat.example.org` might host
`<name>@example.org`. A server that does this MUST publish each
identity's key file at the URL given in Section 4.3, and log its records
(4.5). It can serve the files itself or place them on a web server. To
every other server, these are ordinary identities.

INFO reports a server's identity domain and its log (8.5).

```
REGISTER <name> <keyfile> <signature>
```

→ `OK uid=<name>@<identity domain>`

This creates the identity `<name>@<identity domain>`:

- `<keyfile>` is the identity's first records, in base64 with padding:
  a one-byte `version` (1) followed by the vector `Record records<V>`.
  They are a `master` record, which names the server's current log (its
  `log` and `log-key` in INFO), and one `device` record, for the uid
  `<name>@<identity domain>`, and must form a valid chain (4.4).
- `<signature>` is computed as in Section 4.6 with that uid, using the
  device key of the `device` record. This proves that the client holds
  it.

If both check, the server logs the records, publishes the key file, and
the connection is signed in as the new identity with that device key.
The client learns the identity domain and the log from INFO (8.5) first.
REGISTER may be a long line before sign-in (2.3).

Errors:

- `not-supported`: this server does not offer registration.
- `name-taken`: the name is already registered, or was once and has been
  retired (4.9).
- `invalid`: the records are not a valid chain for that uid, or do not
  name the server's current log.
- `auth-failed`: the signature did not verify, or the connection's SNI
  is not a name the server serves (4.6).
- `forbidden`: for example, registration is closed.
- `rate-limited`: too many registrations from the client's network
  address (Section 14). The `retry` tag says when to try again. The
  limit counts registrations that have succeeded or are still in
  progress, so that sending REGISTER on several connections at once
  does not get around it.

A client whose REGISTER got no answer, because the connection dropped,
cannot tell whether the identity was created. It SHOULD reconnect and
try AUTH as the new identity with the same key before it treats the
registration as failed. It MUST NOT throw the keys or the signed records
away before then, and if it registers again, it sends the same records.

```
KEYS PUT <after> <records>
```

→ one `RECORD <index> <hash>` line for each record the server added to
its log, then `OK`

Adds records to an identity's chain on this server. `<records>` is one
or more records that continue the chain, oldest first, encoded as for
REGISTER, or a blob-ref (3.5) naming a blob that holds the same bytes
without base64 (12.12). `<after>` is the blob-ref of the record that the
first of them follows, which the server must already hold, or `-` when
they start with the chain's first record. A device sends only what the
server does not have: the records after the newest one it holds, or the
whole chain to a log that holds none of it yet (4.8). Records are
signed, so KEYS PUT needs no sign-in, and works on new and anonymous
connections as well as signed-in ones. The server checks that:

- it holds the record `<after>` names (`ERR not-found`)
- the chain, made of the records it holds up to `<after>` and then
  `<records>`, is valid (4.4) (`ERR invalid`)
- it extends what the server already has for that uid: records it
  already holds are skipped, and a different record in the place of one
  it holds is refused (`ERR forbidden`)
- the newest of `<records>` is one that the chain puts in this server's
  log (4.4, replaying step 11), and the server either hosts the identity
  or logs other identities (`ERR not-supported`)
- for an identity it does not host, the identity's key file (4.4), which
  it fetches, names this log in its last `log` line and lists the new
  records, as `-` lines or by hash (`ERR forbidden`). So nobody can put
  an identity's records into a log that the identity does not name.
- the chain stays within the limits of 4.4 (`ERR too-long`)

It then appends to its log (4.5) each record that it did not hold and
that the chain puts in this log. It keeps the records that belong to
earlier logs of the chain only to check the chain. For an identity it
hosts, it also publishes the new key file. `<index>` is a record's
position in the log, and `<hash>` its SHA-384 hash as a blob-ref (3.5).
Sending records the server already has again gets `OK` and no lines.

A device keeps each record it signs, exactly as encoded, until the log
holds it, and resends those same bytes after a lost answer. It never
signs a second record with the same `previous`, since another signature
over the same content gives another record, which the log refuses.

So nobody can change an identity's records without one of its keys. In
particular, an operator cannot reset an identity: a chain that does not
extend the old one would be a fork in the log (4.5), and a new master
key to everyone who knows the identity (12.14).

Someone who publishes their own key file first publishes it with the new
records as `-` lines, then sends KEYS PUT to the server whose log the
chain names, and then replaces those lines with the indices and hashes
it returns.

### 4.8. Devices

**Creating an identity.** The first device:

1. Makes a recovery key, 32 random bytes, and derives the master key
   from it: its seed is HKDF-Expand(HKDF-Extract("", recovery key),
   info, 32) [RFC5869] with SHA-384, where `info` is `risala/1
   identity ` followed by the uid.
2. Makes a device-signing key, its own device key and its attestation
   key, from new random seeds.
3. Builds the chain: a `master` record that names the log it will use
   (4.5), then a `device` record for itself.
4. Registers (4.7), or publishes the key file and logs it with KEYS PUT
   for an identity it hosts itself.
5. Shows the recovery key to the user once, and SHOULD ask the user to
   type it back, then forgets it and the master key. It keeps only the
   current backup key derived from it (12.13).

Clients show a recovery key as 52 characters of lower-case base32
[RFC4648], without padding, in groups of four separated by spaces. When
reading one that a user typed, they ignore case, spaces and `-`. 52
characters carry 260 bits, so the last 4 bits are zero, and a reader
rejects a key in which they are not.

A device that reads a recovery key derives the master key, and checks
that its public key is the current master key of the identity's chain
(4.4) before it uses it for anything. If it is not, the device tells the
user that the recovery key is wrong.

**Pairing a new device.** A new device joins an identity by pairing with
a device that already has it. The new device shows a QR code, and the
user scans it with the other device. The QR code carries a one-time
secret that never reaches the server:

```
struct {
    uint8 version;           // 1
    opaque host<V>;          // the server used for pairing, lower case
    opaque secret[32];       // the one-time pairing secret
    opaque keys_hash[48];    // SHA-384 of the encoded NewDevice
} PairingCode;

struct {
    DeviceKeys keys;         // as in a device record (4.4)
    opaque pairing_key<V>;   // X-Wing public key, 1216 bytes, for this pairing only
} NewDeviceContent;

struct {
    uint8 version;           // 1
    NewDeviceContent content;
    opaque signature<V>;     // RisalaSign(the new device key, "pair", content)
} NewDevice;

opaque Host<V>;              // a server's hostname, in lower case

struct {
    uint8 version;           // 1
    opaque uid<V>;
    opaque master_key<V>;    // the current master public key, 1312 bytes
    opaque signing_seed[32]; // the current device-signing key
    uint32 backup_generation;// the chain's generation (4.4)
    opaque backup_key[32];   // that generation's backup key (12.13)
    opaque record_hash[48];  // SHA-384 of the new device's device record
    Host hosts<V>;           // the servers the identity uses, its home first (12.13)
    opaque transfer<V>;      // a TransferRef (12.13), or empty
} IdentityBundle;

struct {
    uint8 version;           // 1
    opaque enc[1120];        // the X-Wing encapsulated key
    opaque ciphertext<V>;    // the sealed IdentityBundle
} SealedBundle;
```

The QR code holds the text `RISALA-PAIR:` followed by the encoded
PairingCode in upper-case base32 [RFC4648] without padding, which QR
codes store compactly. From the secret, both devices derive, with
HKDF-SHA384 [RFC5869] and PRK = HKDF-Extract("", secret):

- `new_id` = HKDF-Expand(PRK, "risala/1 pair new id", 16) and `new_key`
  = HKDF-Expand(PRK, "risala/1 pair new key", 32), for the message from
  the new device;
- `old_id` and `old_key` the same way with `old` in place of `new`, for
  the reply.

The two messages are protected like this:

- **The NewDevice** is encrypted with ChaCha20-Poly1305 [RFC8439] under
  `new_key`, with a nonce of 12 zero bytes and the ASCII bytes
  `risala/1 pair` as associated data. The key encrypts this one message
  only: a device that sends `PAIR PUT new_id` again, for example after a
  lost answer, sends the same ciphertext, and to send anything else it
  starts again with a new secret.
- **The IdentityBundle** is sealed to the new device's `pairing_key`
  with HPKE [RFC9180] in mode_psk, with the KEM, KDF and AEAD of 12.2
  (`0x647a`, `0x0002` and `0x0003`): SealPSK(pkR = `pairing_key`, info =
  `risala/1 pair`, aad = empty, pt = the encoded IdentityBundle, psk =
  `old_key`, psk_id = `risala/1 pair`). The SealedBundle holds `enc` and
  the ciphertext. Opening it takes both the secret and the new device's
  private pairing key, which never leaves the new device, so seeing the
  QR code is not enough. The new device deletes the pairing key once it
  has opened the bundle.

In commands, an id is written as a box (3.5): 16 bytes in lower-case
base32.

```
PAIR PUT <id> <data>
PAIR GET <id>
```

- **`PAIR PUT`** stores `<data>`, base64 with padding, under `<id>` for
  10 minutes, and replies `OK`. An id that already holds the same data
  gets `OK` again, and one that holds other data gets `ERR name-taken`.
  A device whose PAIR PUT gets `name-taken` starts the pairing again
  with a new secret.
- **`PAIR GET`** sends `PAIR <id> <data>` and `OK`, or `ERR not-found`
  if nothing is stored under `<id>` yet.
- Both work on new, anonymous and signed-in connections, since their
  data is opaque and their ids are secret.

The pairing then goes:

1. The new device makes its device key, attestation key and pairing key,
   and a new secret. It sends `PAIR PUT new_id` with the encrypted
   NewDevice, and shows the QR code.
2. The other device scans it, connects to `host`, and sends
   `PAIR GET new_id`. It decrypts the NewDevice, checks that its SHA-384
   hash is `keys_hash`, that its signature verifies under the device key
   in it, and that its keys pass the checks of 4.4. It shows the new
   device's label and asks the user to confirm that it is theirs.
3. It makes a `device` record for the new device, and publishes it: with
   KEYS PUT for an identity the server hosts, or by giving the user the
   new key file to publish, then KEYS PUT to the log.
4. It sends `PAIR PUT old_id` with the SealedBundle, and announces the
   new record to the identity's other devices (4.5).
5. The new device polls `PAIR GET old_id` and opens the bundle. It
   fetches its identity's key file, and checks that its chain's current
   master key is `master_key`, that it holds the record whose hash is
   `record_hash`, with the keys the device made, and that
   `backup_generation` is the chain's generation. Its identity's log is
   the one the chain names, which the master key signed, so the server
   cannot point it at another. It shows that it is waiting until its
   record is accepted (4.5). It then signs in, uploads KeyPackages
   (12.5) to each server in `hosts`, and is added to the identity's
   conversations by its other devices (12.7). It fetches the history
   transfer, if there is one (12.13).

The server sees only random ids and ciphertext. A server that changes
either message makes decryption or the hash check fail.

**Removing a device.** Removing a device needs the recovery key, since
the removed device holds the device-signing key. On a remaining device,
the user enters the recovery key, and the device:

1. derives the master key, checks it (above), makes a new device-signing
   key, and publishes a `signing` record that names it and removes the
   device;
2. waits until it has accepted that record itself (4.5), which a log
   SHOULD witness within a minute, then removes the device's leaves from
   every group it is in (12.7), starting with the conversation with
   itself. Until the record is accepted, the removed device is still
   current, and can remove the identity's other leaves from groups.
   Devices of the identity show such removals by a leaf of their own
   identity as an alert (12.7);
3. sends the new device-signing key and the backup key of the new
   generation (4.4) to the identity's other devices, in the conversation
   with itself, with SIGNINGKEY and BACKUPKEY lines (12.9);
4. MUST replace the current backup at once with one under the new
   generation (12.13), since the removed device can read the old one;
5. forgets the recovery key and the master key again.

**Losing every device.** The recovery key is the only way back. On a new
device, the user enters it, and the device derives the master key and
checks it, then publishes a `signing` record that removes every current
device and names a new device-signing key, then a `device` record for
itself. It uses KEYS PUT, which needs no sign-in. The chain is now at the
next generation (4.4). The device restores history from the backup of
the generation before, if there is one (12.13), and makes a new backup
in the new generation; the backup also names the servers its
conversations live on. Without a backup, the
user names them. Once its records are accepted, it signs in to each,
uploads KeyPackages, and the members of the identity's conversations add
it (12.7).

**Changing the recovery key.** A user who thinks the recovery key may
have leaked enters it on a device, which makes a new recovery key and
derives the new master key from it. It publishes a later `master` record
(4.4), signed by both master keys, that names the new master key, a new
device-signing key, and the chain's current log. The chain moves to the
next generation, whose backup key is derived from the new recovery key
(12.13). The device then proceeds as in steps 3 to 5 of removing a
device, and shows the new recovery key once, as at creation. Every
contact sees a new master key (4.5), which clears "verified" and stops
sending until each user acknowledges it (12.14).

**Moving to another log.** An identity whose key file names a log
outside its host, for example a self-hosted one, can move its records
to another log. With the recovery key, a device publishes a `log` record
that names the new log, with KEYS PUT to the old log, then sends the
whole chain to the new log with `KEYS PUT -`, and publishes the key file
with the new `log` line. Every device that knows the identity follows
the move once it accepts the `log` record. A log that its host hands off
needs no such record (4.5).

**No resets.** No operator can do any of this for someone. A server that
hosts an identity holds none of its private keys, and the domain's
controller can replace a key file only with a chain that every device
that knows the identity sees as a fork, a rollback or a new master key
(4.5).

### 4.9. Deleting an Identity

```
UNREGISTER <uid>
```

→ `OK`, then the server closes all of the identity's connections

Deletes everything the server keeps about the identity the connection
is signed in as. `<uid>` MUST be that identity (`ERR forbidden`
otherwise). Having to type it out guards against sending UNREGISTER by
mistake. Any identity may do this on any server.

The server deletes the identity's KeyPackages, pending Welcomes, push
registrations, backups and presence setting. It cannot delete what the
identity posted, since it does not know which posts are its. Those
expire with retention (7.5). A client SHOULD leave every group the
identity is in first (6.1), with each of its devices.

**Ending an identity for everyone.** Only a `retire` record (4.4) makes
other people's devices remove an identity from their conversations
(12.7). A device publishes one with KEYS PUT, which needs the recovery
key, before UNREGISTER. A key file that is gone is only an identity's
keys missing (4.4): contacts stop sending to it and warn, but remove
nothing.

- **Hosted identities (4.7):** the server also stops serving the
  identity. If its chain ends with a `retire` record, the server keeps
  publishing the key file, so that contacts learn of it. Otherwise it
  answers 410 for the key file from then on. Its records stay in the
  log, which never removes entries. The log refuses a second first
  `master` record for the uid (4.5), so the name can never be
  registered again on this host: the server answers `name-taken`.
  Reusing it would take a log that does not descend from this one,
  which every contact would see as a new master key.
- **Other identities** are only forgotten by this server, their pin
  included (4.6). If the same identity signs in again later, the server
  treats it as new.

Guests have nothing to delete.

### 4.10. Witnessing Key Logs

A key log needs witnesses that cosign its checkpoints (4.5). Witnesses
for risala key logs follow [TLOG-WITNESS], with the rules below. Anyone
MAY run one, and a risala server MAY also act as a witness for other
servers' logs.

**Enrolment** is open: a log enrols with a witness by sending it its
first checkpoint, with an `add-checkpoint` request whose old size is 0.
The witness enrols the log only if all of these hold, and otherwise
refuses the request with 403:

1. The origin has the form `<host>/risala-log/<n>` (4.5), and the
   checkpoint is signed as 4.5 says, under an ML-DSA-44 key named after
   the origin.
2. For n = 1: the witness has never enrolled a log of `<host>`.
3. For n > 1: the witness has enrolled log `n`-1 of the same host, and
   has accepted a hand-off from it to this origin and key (below).
4. The witness has never enrolled another key for the origin.

To hand off, the host sends each witness of log `n`-1, before the first
checkpoint of log `n`, a request:

```
POST <witness URL prefix>/risala/handoff
```

whose body is, in lines that each end with LF: `index ` and the index of
the hand-off entry; the encoded LogEntry in base64 with padding; the
hashes of its inclusion proof, each in base64 with padding; an empty
line; and the checkpoint of log `n`-1 that includes it, as a signed
note. The witness accepts it, with 200, if the checkpoint is the newest
one of log `n`-1 that it cosigned, the entry is a hand-off entry naming
`<host>/risala-log/<n>`, it is the checkpoint's last entry, and the
proof verifies. From then on it cosigns no larger tree of log `n`-1.

**Limits.** A witness rate-limits by host: it MAY limit how many new
hosts under one registered domain it enrols, and how fast, and MAY
refuse checkpoints of one log that come more often than every 10
seconds. It SHOULD NOT otherwise refuse a log that follows these rules.

**Cosignatures** are ML-DSA-44 (type `0x06`) [TLOG-COSIGNATURE], with
the time the witness made them as their timestamp, which is never zero.
Since every log gets a new witnessed checkpoint at least once a day
(4.5), a device that finds no cosignature less than 24 hours old knows
that the log or its witnesses are not keeping up. It then treats the
log's new records as pending, and does not count the identity's view as
refreshed (4.5).

**The apps' default list.** Apps ship a list of at least three
witnesses, run by independent organisations in more than one country,
with k more than half the list (2 of 3). Each witness on it publishes
its verifier key, its enrolment policy and a contact, and has committed
to run for years. The list changes only with app releases, and each
release says which list it carries. A witness is added once it has
cosigned the logs the app's users rely on for some weeks. A witness is
retired by removing it from the list in a release, and its operator
keeps running it until that release is widely installed. A log SHOULD
send its checkpoints to every witness of the common apps' lists.

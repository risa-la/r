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
room, ANON, GUEST, AUTH, REGISTER, PING, PONG and QUIT. It replies
`ERR not-authenticated` to anything else, and to a command that needs a
kind of connection this one is not (Section 13).

A device keeps one signed-in connection and at least one anonymous
connection open while it is online. Section 14 says what the server can
still link between them.

**Proof of work.** A server MAY require a client to solve a
proof-of-work puzzle before ANON, GUEST or REGISTER succeeds, and before
an anonymous or guest connection joins a public room (6.1). The puzzle,
and how it is bound to the connection, are specified separately.

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
network address keeps open, and how much each one posts (Section 14).

```
GUEST <name> [token=<token>]
```

→ `OK uid=~<name> token=<token> [resumed=yes]`

A guest is an anonymous connection with a name, so that it can take part
in public rooms that allow guests (6.2). Guests join public rooms only.
The one other conversation a guest may start is a direct conversation
with an owner or moderator of a room it is in, to report a message
(5.8).
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

The key file is a chain of signed records (4.4), and every record is
also published in a witnessed key log (4.5), so that the controller of
the domain cannot show different keys to different people without it
being noticed. No chat server is in charge of any identity, and a server
never asks another chat server about a user.

An identity's domain and the chat server are independent of each other.
`alice@example.org` can use `chat.example.org`, `chat.example.net` or
any other server.

An identity has these keys:

| Key | Algorithm | Held by | Signs |
|---|---|---|---|
| **Recovery key** | 32 random bytes | the person, written down | nothing itself. The master key and the backup keys are derived from it (4.8, 12.13) |
| **Master key** | ML-DSA-44 | derived from the recovery key when needed | `master` and `signing` records (4.4) |
| **Device-signing key** | ML-DSA-44 | every device of the identity | `device` records (4.4) |
| **Device key** | ML-DSA-44, one per device | that device | sign-in (4.6), KeyPackage bindings (12.5) and period-key certificates (12.10) |
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

A key file is UTF-8 text, served as described in 4.3:

```
risala-keys/1
log <vkey> <url>
<index> <record>
<index> <record>
…
```

- The first line is exactly `risala-keys/1`. A file with any other first
  line is not a key file of this version, and holds no keys.
- The `log` line names the key log that holds the identity's records
  (4.5): `<vkey>` is the log's signed-note verifier key [SIGNED-NOTE],
  whose name is the log's origin, and `<url>` is the log's `https` URL
  prefix [TLOG-TILES]. There is exactly one `log` line.
- Each record line holds `<index>`, the record's position in the log as
  a number, or `-` while it is not logged yet, and `<record>`, the
  encoded Record (below) in base64 with padding [RFC4648].
- Records come in chain order, oldest first.
- Blank lines and lines starting with `#` are ignored.

```
enum {
    reserved(0),
    master(1),
    signing(2),
    device(3),
    (255)
} RecordType;

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
        case signing:
            opaque signing_key<V>;     // ML-DSA-44 public key
            opaque removed<V>;         // device ids, 48 bytes each
        case device:
            DeviceKeys keys;
    };
} RecordContent;

struct {
    RecordContent content;
    opaque signature<V>;
} Record;
```

A device's **device id** is the SHA-384 hash of its raw device key. The
records do this:

- **`master`** names a master key and a first device-signing key. The
  first record of every chain is a `master` record, signed with
  RisalaSign(its own master key, "record", content). A later `master`
  record replaces the master key: it is signed by the master key it
  replaces, and also names a new device-signing key.
- **`signing`** replaces the device-signing key, and removes the devices
  in `removed`. It is signed by the current master key. Removing a
  device always takes a new device-signing key, since the removed device
  holds the old one (4.8).
- **`device`** adds a device, with its device key, its attestation key
  and a label for people, usually the device's name. It is signed by the
  current device-signing key.

A key file is **valid** if all of these hold. Anything that checks a key
file, server or device, MUST reject one that is not:

1. The first record is a `master` record with an empty `previous`, signed
   by its own master key.
2. Every other record's `previous` is the SHA-384 hash of the encoded
   Record before it, and its `uid` is the same. Times never go
   backwards.
3. Every record is signed as above by the key that was current when it
   was made.
4. No device is added twice, and no removed device is added again.
5. At most 64 devices are current at any point.
6. Every key passes its algorithm's checks: ML-DSA-44 keys are 1312
   bytes, and X-Wing keys pass the checks of 12.2.

Replaying the chain gives the identity's **current** master key,
device-signing key and devices. Only current devices may sign in, and
only their leaves are accepted in groups (12.7). A key file that is not
valid, or whose `uid` is not the identity at its URL, lists no keys.

Records are about 5 KiB each, so a key file of 200 records is about
1.3 MiB in base64. When a server or device fetches a key file:

- It MUST use HTTPS with TLS 1.3, and validate the certificate against
  public certificate authorities.
- It MUST NOT follow redirects.
- It MUST stop after 10 seconds or 2 MiB.
- A server MUST NOT connect to loopback, private, link-local or other
  special-purpose addresses [RFC6890] unless its operator has configured
  it to. Users choose the domain, so without this rule they could make
  the server probe its own internal network.
- It MAY cache the file for up to one hour. If a signature does not
  verify against a cached file, it SHOULD fetch the file again once
  before failing, so that a newly added device works straight away.

A fetch has one of three outcomes:

- **A key file.** A 200 response whose body arrives within the limits.
  The identity's keys are the current ones of the chain, if it is valid.
  A 200 response whose body is larger than 2 MiB counts as a key file
  that lists no keys.
- **Gone.** A 404 or 410 response. The identity has no keys.
- **Failed.** Anything else: no response, a DNS or TLS error, a timeout,
  a 5xx response, or any other status, including a redirect. This is an
  outage, and says nothing about the identity's keys.

A key file or a gone answer replaces a cached copy. A failed fetch does
not, and a cached copy stays valid until its hour is up.

A device has been **removed** when a fetch returns a valid key file
whose chain removes it, or a gone answer. A server that notices this
SHOULD close the connections that signed in with that device's key. A
failed fetch is not a reason to close anything, however long it lasts.

A server checks only that a key file is valid. Devices also check every
record against the key log before they act on it (4.5).

### 4.5. The Key Log

Every server that hosts identities (4.7) keeps a **key log**: an
append-only Merkle tree [RFC6962] of the records of the identities it
hosts. It MAY also log the records of other identities, whose key files
name it in their `log` line. A key log uses the C2SP formats:

- **Entries.** Each entry is one encoded Record (4.4). The tree is the
  tree of [RFC6962] with SHA-256, as [TLOG-TILES] requires.
- **Serving.** The log serves its checkpoint, hash tiles and entry
  bundles under its URL prefix as [TLOG-TILES] describes, over HTTPS.
- **Checkpoints** follow [TLOG-CHECKPOINT]. A log's origin is its
  hostname, `/risala-log/` and a number that the operator chooses,
  starting at 1, for example `chat.example.org/risala-log/1`. An
  operator that starts a new log, for example after losing the old one,
  gives it a new number.
- **The log's signature.** The log signs each checkpoint with ML-DSA-44,
  as a timestamped ML-DSA-44 checkpoint signature (signed-note signature
  type `0x06`) [SIGNED-NOTE] [TLOG-COSIGNATURE] over the whole tree,
  under a key whose name is the log's origin. Its verifier key is the
  `<vkey>` of the key files that name the log.
- **Witnesses.** The log sends each new checkpoint to public witnesses
  with the `add-checkpoint` request of [TLOG-WITNESS], and serves the
  checkpoint with the cosignatures it got back. Witnesses check that each
  checkpoint is consistent with the last one they cosigned, so a log
  cannot show different trees to different people without a witness
  refusing. Witness cosignatures MUST be ML-DSA-44 (type `0x06`)
  [TLOG-COSIGNATURE]. Clients ignore cosignatures of any other type,
  such as Ed25519, so they do not count towards k.
- **Timing.** A log adds a record and gets a witnessed checkpoint that
  includes it within one hour, and gets a new witnessed checkpoint at
  least once a day even when nothing is added.

A log appends a record only if the identity's chain in the log is valid
with it (4.4): the first record of a uid must be a `master` record with
an empty `previous`, and every later one must follow the newest record
the log holds for that uid. A log never removes an entry.

**Witness policy.** Each client has a list of witnesses it trusts, as
signed-note verifier keys, and a number k. A checkpoint is **witnessed**
when its log's signature verifies, and at least k witnesses of the list
have cosigned it. Apps ship a default list with at least three
witnesses, run by independent organisations, and k = 2, and update it
with their releases. Users MAY change it. A log SHOULD use the witnesses
that the common apps trust.

**Accepting a record.** A device acts on a record of an identity, for
example by accepting a leaf of a device the record adds (12.7), only
once all of these hold:

1. The record is part of the identity's valid key file (4.4).
2. The key file gives the record's index, and the entry at that index of
   the log the key file names is the record.
3. An inclusion proof of that entry verifies against a witnessed
   checkpoint of the log.
4. That checkpoint is consistent with the newest witnessed checkpoint of
   the same log that the device has seen, which it then keeps.

The device computes the proofs of steps 3 and 4 from the log's tiles
[TLOG-TILES]. It fetches them under the rules for key files (4.4). A
record that does not yet pass is **pending**. A device does not act on
pending records, and tries again from time to time.

**Pinning.** The first time a device accepts an identity's records, it
records the identity's master key and log. A key file that later names
another log, or whose chain starts with another master key, is a **new
master key**: the device stops sending to the identity until the user
acknowledges it (12.14). A `master` record that replaces the master key
within the same chain is a new master key too.

**Forks.** A device has found a **fork** when it sees:

- two different records of one uid with the same `previous`, whether in
  the log, in key files, or one in each
- two `master` records of one uid with an empty `previous`
- two witnessed checkpoints of one log that are not consistent with each
  other

A fork means that someone has shown two different histories of an
identity, or a log two different trees. For every identity in a fork,
including every identity in a log that forked, the device stops sending
in each conversation where that identity has a leaf, and tells the user,
until the user resolves it, for example by checking the safety number
with the person (12.14) and choosing which keys to trust.

**Watching your own records.** Each device of an identity SHOULD, at
least once a day:

1. fetch the newest checkpoint of its identity's log, check that it is
   witnessed and consistent with the last one it saw, and that its
   cosignatures are less than 24 hours old;
2. read the entries added since then, from the log's entry bundles;
3. look for records of its own uid.

A device announces each record it makes to the identity's other devices,
in the conversation with itself (12.13). A record of its uid that no
device announced, or a fork, means that someone else may control the
identity. The device tells the user, and sends `ALERT` (12.9) in the
conversation with itself, so that every device of the identity tells
the user too.

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
   file (4.4), or uses a cached copy.
4. It accepts if the signature verifies under any of those device keys.
   The master key and the device-signing key never sign in.

On success the server replies `OK uid=<uid>`, and adds `op=yes` if the
identity is a server operator (Section 10). The key that verified becomes
the connection's **device key**. On failure the server replies:

- `ERR auth-failed` if step 1 fails, or if the signature does not verify
  under the keys the server got. A key file that does not list the key,
  and a gone answer (4.4), count as keys the server got: the identity
  has none that verify.
- `ERR unavailable` if the fetch failed (4.4) and the server has no
  cached copy, so it could not check the signature at all. This
  includes the case where a cached copy did not verify and fetching
  again failed. It MAY add a `retry` tag.

A client that gets `unavailable` SHOULD reconnect and try again later,
waiting longer after each failure, and at least as long as `retry`
says. A client that gets `auth-failed` SHOULD NOT try again on its own,
since the same key will fail the same way. It tells the user instead.

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
  They are a `master` record and one `device` record, for the uid
  `<name>@<identity domain>`, and must form a valid key file (4.4).
- `<signature>` is computed as in Section 4.6 with that uid, using the
  device key of the `device` record. This proves that the client holds
  it.

If both check, the server logs the records, publishes the key file, and
the connection is signed in as the new identity with that device key.
The client learns the identity domain from INFO (8.5) first. REGISTER
may be a long line before sign-in (2.3).

Errors:

- `not-supported`: this server does not offer registration.
- `name-taken`: the name is already registered, or was once and has been
  retired (4.9).
- `invalid`: the records are not a valid key file for that uid.
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
registration as failed. It MUST NOT throw the keys away before then.

```
KEYS PUT <keyfile>
```

→ one `RECORD <index> <hash>` line for each record the server added to
its log, then `OK`

Updates an identity's records on this server. `<keyfile>` is the
identity's whole chain, encoded as for REGISTER. Records are signed, so
KEYS PUT needs no sign-in, and works on anonymous connections as well as
signed-in ones. The
server checks that:

- the chain is a valid key file (4.4) (`ERR invalid`)
- it extends what the server already has for that uid: the records the
  server has are the first records of the chain (`ERR forbidden`)
- the server hosts the identity, or logs records for identities whose
  key file names its log, as this one's must (`ERR not-supported`)

It then appends the new records to its log (4.5). For an identity it
hosts, it also publishes the new key file. `<index>` is a record's
position in the log, and `<hash>` its SHA-384 hash as a blob-ref (3.5).
Sending records the server already has again gets `OK` and no lines.

So nobody can change an identity's records without one of its keys. In
particular, an operator cannot reset an identity: a chain that does not
extend the old one would be a fork in the log (4.5), and a new master
key to everyone who knows the identity (12.14).

Someone who publishes their own key file sends KEYS PUT to the server
whose log they name, then adds the indices it returns to their key file.

### 4.8. Devices

**Creating an identity.** The first device:

1. Makes a recovery key, 32 random bytes, and derives the master key
   from it: its seed is HKDF-Expand(HKDF-Extract("", recovery key),
   info, 32) [RFC5869] with SHA-384, where `info` is `risala/1
   identity ` followed by the uid.
2. Makes a device-signing key, its own device key and its attestation
   key, from new random seeds.
3. Builds the chain: a `master` record, then a `device` record for
   itself.
4. Registers (4.7), or publishes the key file and logs it with KEYS PUT
   for an identity it hosts itself.
5. Shows the recovery key to the user once, then forgets it and the
   master key. It keeps only the current backup key derived from it
   (12.13).

Clients show a recovery key as 52 characters of lower-case base32
[RFC4648], without padding, in groups of four separated by spaces. When
reading one that a user typed, they ignore case, spaces and `-`.

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
    uint8 version;           // 1
    DeviceKeys keys;         // as in a device record (4.4)
} NewDevice;

struct {
    uint8 version;           // 1
    opaque uid<V>;
    opaque master_key<V>;    // the current master public key
    opaque signing_seed[32]; // the current device-signing key
    uint32 backup_generation;
    opaque backup_key[32];   // that generation's backup key (12.13)
    opaque record_hash[48];  // SHA-384 of the new device's device record
    opaque transfer<V>;      // a TransferRef (12.13), or empty
} IdentityBundle;
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

Each message is encrypted once with ChaCha20-Poly1305 [RFC8439] under
its key, with a nonce of 12 zero bytes and the ASCII bytes
`risala/1 pair` as associated data. In commands, an id is written as a
box (3.5): 16 bytes in lower-case base32.

```
PAIR PUT <id> <data>
PAIR GET <id>
```

- **`PAIR PUT`** stores `<data>`, base64 with padding, under `<id>` for
  10 minutes, and replies `OK`. An id that already holds data gets
  `ERR name-taken`.
- **`PAIR GET`** sends `PAIR <id> <data>` and `OK`, or `ERR not-found`
  if nothing is stored under `<id>` yet.
- Both work on anonymous and signed-in connections.

The pairing then goes:

1. The new device makes its device key and attestation key, and a new
   secret. It sends `PAIR PUT new_id` with the encrypted NewDevice, and
   shows the QR code.
2. The other device scans it, connects to `host`, and sends
   `PAIR GET new_id`. It decrypts the NewDevice, and checks that its
   SHA-384 hash is `keys_hash`. It shows the new device's label and asks
   the user to confirm that it is theirs.
3. It makes a `device` record for the new device, and publishes it: with
   KEYS PUT for an identity the server hosts, or by giving the user the
   new key file to publish, then KEYS PUT to the log.
4. It sends `PAIR PUT old_id` with the encrypted IdentityBundle, and
   announces the new record to the identity's other devices (4.5).
5. The new device polls `PAIR GET old_id`, decrypts the bundle, and
   checks that the identity's key file holds the record whose hash is
   `record_hash`, with the keys it made. It then signs in, uploads
   KeyPackages (12.5), and is added to the identity's conversations by
   its other devices (12.7). It fetches the history transfer, if there
   is one (12.13).

The server sees only random ids and ciphertext. A server that changes
either message makes decryption or the hash check fail.

**Removing a device.** Removing a device needs the recovery key, since
the removed device holds the device-signing key. On a remaining device,
the user enters the recovery key, and the device:

1. derives the master key, makes a new device-signing key, and publishes
   a `signing` record that names it and removes the device;
2. removes the device's leaves from every group it is in (12.7),
   starting with the conversation with itself;
3. sends the new device-signing key and the next backup key to the
   identity's other devices, in the conversation with itself, with
   SIGNINGKEY and BACKUPKEY lines (12.9);
4. forgets the recovery key and the master key again.

**Losing every device.** The recovery key is the only way back. On a new
device, the user enters it, and the device derives the master key,
publishes a `signing` record that removes every device and names a new
device-signing key, then a `device` record for itself. For an identity
that a server hosts, it uses KEYS PUT, which needs no sign-in. It then
signs in, and the members of the identity's conversations add the new
device (12.7). The new `signing` record moves backups to the next
generation (12.13). The device restores history from the backup of the
generation before, if there is one, and makes a new backup in the new
generation.

**No resets.** No operator can do any of this for someone. A server that
hosts an identity holds none of its private keys, and the domain's
controller can replace a key file only with a chain that every device
that knows the identity sees as a fork or a new master key (4.5).

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

- **Hosted identities (4.7):** the server also stops publishing the key
  file, and answers 410 for it from then on, so that the identity has no
  keys (4.4). Its records stay in the log, which never removes entries.
  The server SHOULD NOT let anyone register the name again, since other
  servers and devices would take the new owner for the old one.
- **Other identities** are only forgotten by this server. If the same
  identity signs in again later, the server treats it as new.

Guests have nothing to delete.

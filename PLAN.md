# Implementation plan

The high-level plan for building risala: a Rust server, a Rust client
library (librisala), and native apps for GNOME, Apple platforms and
Android. [SPEC.md](SPEC.md) is the source of truth for the protocol.
This file covers how we build it.

## 1. Principles

- **The spec comes first.** If the code and the spec disagree, fix one of
  them on purpose. Don't let them drift. Spec changes are made in
  SPEC.md first.
- **One protocol implementation.** Parsing, grammar and signing live in
  a single crate (`risala-proto`). The server and librisala both use it.
- **Apps are thin.** Everything apps share lives in librisala:
  connections, trust on first use, keys, sign-in, sync, the history
  cache, timelines, rooms, moderation and admin. An app only draws the
  UI and supplies a few platform services (secure key storage, push
  tokens, notifications).
- **`openssl s_client` stays a first-class client.** The server is tested
  with scripted line transcripts. Every example in the spec becomes a
  test.

## 2. Repository layout

```
risala/
├── SPEC.md                the protocol (CC BY 4.0)
├── README.md
├── PLAN.md
├── LICENSE                Apache-2.0, for the code
├── LICENSES/              full license texts (REUSE)
├── REUSE.toml             license and copyright for every file
├── flake.nix              dev shell, packages, checks, later a NixOS module
├── Cargo.toml             Cargo workspace
├── crates/
│   ├── risala-proto/      lines, tags, names, escaping, auth bytes; no I/O
│   ├── risala-server/     the server binary, `risalad`
│   ├── librisala/         the client library
│   ├── librisala-ffi/     UniFFI bindings for Kotlin and Swift
│   ├── risala-cli/        small terminal client and key tool built on librisala
│   └── risala-conformance/  black-box tests that can run against any server
├── clients/
│   ├── gnome/             Rust, gtk4-rs, libadwaita
│   ├── apple/             Swift, SwiftUI (macOS and iOS)
│   └── android/           Kotlin, Jetpack Compose
└── push-gateway/          later: forwards NOTIFY to APNs and FCM (Appendix C)
```

## 3. Components

### 3.1. risala-proto

A pure library with no networking or async code, so it is easy to test
and fuzz.

- Parse and serialise lines (Section 3): tags, verbs, tokens, options,
  text, and per-verb arity tables.
- Typed names: `Uid`, `Room`, `Conv`, `Seq`, `Timestamp`, with
  validation and case folding (3.5).
- Text escaping (3.4) and mention extraction (5.5).
- Typed commands (client → server) and server lines (events, snapshots,
  responses, notices), with conversions both ways.
- The auth challenge bytes and ML-DSA-44 sign/verify (4.5), key file
  parsing (4.4).
- Tests: the Appendix B vectors, every example line in the spec, property
  tests (parsing what we serialise gives back the same value) and a
  cargo-fuzz target for the parser.

### 3.2. risala-server (`risalad`)

- **Runtime:** tokio, with tokio-rustls for TLS 1.3. It picks
  certificates by SNI and reloads them when they are renewed, without
  dropping connections.
- **Connections:** one task per connection. Commands run in order, and a
  bounded output queue per connection disconnects clients that read too
  slowly. Idle PING/PONG timers as in Section 11.
- **Core:** an in-memory hub that tracks who is connected and who is in
  each conversation, and sends each event to them. Each event's seq is
  assigned and the event is stored before it is sent, so sequence numbers
  never have gaps.
- **Storage:** SQLite in WAL mode with a single writer, which is enough
  for one server and keeps running a server simple. Keep storage behind a
  trait so Postgres can be added later if needed.
- **Outbound HTTPS:** key file fetches (4.4) and pushes (9.3), with no
  redirects, size and time limits, and a DNS resolver that refuses
  private and special-purpose addresses. Key files are cached for an
  hour.
- **HTTPS server** (optional, separate listener): serves
  `/.well-known/risala/<name>` for hosted identities and the upload
  `put`/`get` URLs.
- **Background jobs:** retention, cleanup of unattached uploads, push
  batching and retries.
- **Configuration:** a TOML file. The first operators, the identity
  domain, limits and policies all live there. A NixOS module comes later.

### 3.3. librisala

A Rust library, async inside (tokio), with a synchronous-looking API
across the FFI boundary.

- **Transport and trust:** rustls with the verifier from Section 2.2.
  The CA check uses `rustls-platform-verifier`, so each OS's own trust
  store is used. On top of that sits a per-server trust record
  (nothing, CA, or a pinned fingerprint).
- **Session:** connect, read the greeting, sign in, and keep commands
  matched to their responses (responses come back in order, and `ref` is
  used where it helps). Reconnects with backoff, and keepalive.
- **Accounts and identity:**
  - Accounts are guests, identities this server hosts (REGISTER), or
    self-hosted identities on your own domain.
  - Each device generates its own ML-DSA-44 key. It is also the
    device's MLS signature key (Section 12).
  - For self-hosted identities, the library helps produce the key file
    line to publish.
  - KEY management, and adding a new device by showing its public key.
  - Keys are stored through a platform trait: Keychain on Apple
    platforms, an Android Keystore-wrapped key on Android, and libsecret
    on Linux. The Secure Enclave cannot hold ML-DSA keys, so keys are
    software keys that are encrypted or protected at rest. History keys
    and the recovery key (12.9, 12.10) are stored the same way.
- **Sync engine:** SYNC, then fill gaps with HISTORY, dropping duplicates
  by seq. The cache is keyed by conversation id, so a dropped and
  recreated room starts afresh. Lazy paging backwards, with RELATED for
  each older page to get its edits and reactions. An outbox with `cid` so that resends are
  safe across reconnects. Read markers.
- **Store:** SQLite holding servers, trust records, accounts,
  conversations, events, read markers and the outbox. Derived tables
  (current edit text, reaction counts, membership, settings) keep the UI
  fast. The cache can be downloaded completely for offline reading.
- **Model and API:** `Client` (many servers and accounts), `Account`,
  `Conversation`, and a `Timeline` that sends the UI diffs (insert,
  update, remove), plus room settings, members, roles, presence,
  moderation, blocks, reports and ADMIN. The matrix-rust-sdk timeline and UniFFI setup is a good
  reference for this shape.
- **Files:** UPLOAD, then HTTPS PUT and GET, with a download cache.
- **Push:** register a gateway URL and tag per account. An entry point,
  `handle_push(tag)`, connects, syncs and returns what to show in the
  notification, quickly enough for the iOS Notification Service
  Extension. That extension runs as a separate process, so the store must
  be safe to open from two processes at once (a shared app group
  container, WAL, short transactions).

### 3.4. Bindings and apps

- **librisala-ffi:** UniFFI. It produces Kotlin with JNI `.so` files for
  each Android ABI, and Swift with an XCFramework for macOS and iOS.
  Async functions and callback interfaces carry timeline diffs and
  platform services.
- **GNOME:** gtk4-rs and libadwaita, using librisala directly with no
  FFI. This is the first GUI client because it gives the fastest feedback
  loop.
- **Apple:** a SwiftUI app shared between macOS and iOS, with a
  Notification Service Extension for push.
- **Android:** Kotlin with Jetpack Compose. Push through FCM, and through
  UnifiedPush where available.

### 3.5. Tooling

- **Nix flake** (flake-parts): the dev shell now; later packages for
  `risalad` and `risala-cli`, `nix flake check` running the tests, and a
  NixOS module for the server.
- **Cross-compiling:** Android and iOS targets need extra Rust standard
  libraries. When we get there, pin a toolchain with `rust-toolchain.toml`
  and switch the flake to rust-overlay or fenix. Xcode builds stay
  outside Nix.
- **CI:** `nix flake check` (fmt, clippy, tests), plus a smoke test that
  starts `risalad` and talks to it through `openssl s_client`.

## 4. Milestones

Each milestone ends with something that runs.

| # | Milestone | Done when |
|---|---|---|
| M0 | Scaffold | Cargo workspace, CI, license chosen, spec issues in Section 5 decided |
| M1 | `risala-proto` | Every spec example line parses and serialises again unchanged. Appendix B passes. Fuzzer runs clean |
| M2 | Server: guests and rooms | Two `s_client` sessions chat as guests: GUEST, JOIN, PART, LIST, MSG, HISTORY, SYNC, INFO, PING, QUIT, stored in SQLite |
| M3 | Server: identities | AUTH with key files, REGISTER, KEY, hosted `.well-known`, direct conversations, BLOCK, UNREGISTER, READ, `cid`, TYPING, NAME, MEMBERS, WHOIS, PRESENCE |
| M4 | Server: rich messages and moderation | reply, edit, react, DELETE, RELATED; roles, ROLES, SET, INVITE, KICK, BAN; REPORT and RESOLVE; retention; all ADMIN commands |
| M5 | librisala core and `risala-cli` | The CLI signs in, syncs, works offline from its cache and recovers from dropped connections without losing or duplicating messages |
| M5a | End-to-end encryption | Post-quantum TLS and ML-DSA keys everywhere. KEYPKG, INIT, COMMIT, GROUPINFO, WELCOME, ENC and BACKUP in `risalad` and librisala. Two CLI devices talk in an encrypted direct conversation and room; a new device of the same identity reads the whole history offline; a restore from a recovery key works; reports of encrypted messages verify |
| M6 | GNOME app | Day-to-day usable on Linux against a real server |
| M7 | FFI, Apple and Android apps | macOS first, then iOS, then Android, all on the same librisala |
| M8 | Files and push | UPLOAD over HTTPS, PUSH, the gateway, the iOS extension, FCM and UnifiedPush |
| M9 | Hardening and launch | Rate limits, load testing, fuzzing, the NixOS module, a public server and a docs site on risa.la |

M5 can start once M1 is done, alongside M2–M4. Its tests use the real
server.

## 5. Spec issues to settle

These came out of reviewing draft-01 against what the clients need.
Settle them in SPEC.md before or during the matching milestone.

Settled (now in SPEC.md):

1. **Edits and reactions of older messages.** Added RELATED (7.3), which
   returns the edits and reactions for a range of messages, so that a
   page loaded from older history shows current text and reactions.
2. **Dropped and empty rooms.** Every conversation has an id that is
   never reused (5.1), and SYNC, JOIN and INFO report it. ADMIN DROP
   removes everyone as if kicked. A room created again under the same
   name gets a new id and starts again at seq 1, and clients reset their
   cache when the id changes (7.1). An empty room goes on existing.
   Owners and moderators keep their roles when they leave, so they can
   come back. KICK and BAN take roles away. Added ROLES (6.3).
3. **Presence.** Added the PRESENCE line (8.3). One line covers many
   users, the server batches changes, and it waits about 30 seconds
   before reporting someone offline.
4. **Reporting and blocking.**
   - REPORT, REPORTS, ADMIN REPORTS and RESOLVE (5.8). Reports go to room
     owners and moderators (who don't see who reported) and to
     operators. The server keeps a copy of the reported message until the
     report is resolved.
   - BLOCK, UNBLOCK and BLOCKS (5.7). A block stops direct messages
     between the two people, and stops the blocked person's mentions and
     replies from causing pushes. Hiding a blocked person in rooms is up
     to the client.
   - Self-service `UNREGISTER <uid> [purge=yes]` (4.8). Any identity can
     delete everything a server keeps about it, and optionally its
     messages. For a hosted identity, this also deletes its keys and key
     file. Section 13 now covers trusting the host and the spam risk of
     open registration.
5. **Pushes held back by dead connections** (9.2). Before pushing to a
   device that still looks connected, the server PINGs its idle
   connections. If nothing answers within 10 seconds, it pushes anyway.
   Clients MUST answer PING right away, and mobile apps SHOULD send QUIT
   when they go to the background.
6. **Direct conversation naming** (5.2). `<conv>` is now always the
   other participant, as seen by whoever receives the line, which is
   also what they would type to reply. This works whoever `from` is, so
   ADMIN PURGE in direct conversations is no longer a problem.

7. **Grammar details found while writing risala-proto** (3.1-3.7, 4.1,
   4.4, 5.5, 10.6).
   - Lines may not contain C1 control characters (U+0080 to U+009F).
   - A lone `@` with no tags is allowed.
   - Option keys and values now have a grammar, and options may not
     repeat.
   - Spaces after the last token of a verb with no text are ignored.
   - Names and rooms cannot end with `.`. A domain's last label cannot
     be all digits, so IP addresses are not domains.
   - A value that is only too long gets `too-long`, not `bad-syntax`.
   - Key files over 64 KiB mean no keys. The 64-key limit counts only
     different, valid keys.
   - The welcome text is at most 512 bytes.
   - HISTORY and RELATED accept `after=0` (7.2).
8. **Smaller gaps** (3.6, 4.1, 5.2-5.6, 6.2, 6.4, 7.4, 9.1, 10.3).
   - The `ERR` for a line that cannot be parsed carries its `ref`, if a
     valid one can be read.
   - Without SNI, the greeting's `<host>` is the server's main hostname.
   - Only SET, BAN and ROLE are used as snapshots.
   - MSG text made only of spaces and TABs counts as empty.
   - Deleting an already deleted message gets `ERR not-found`. Deleted
     placeholders lose their file tags.
   - UPLOAD's `<type>` is `type/subtype` (RFC 6838), with no parameters.
   - SET and ADMIN SET values may be empty, as for a topic.
   - INVITE, KICK and BAN events that reach non-members are
     notifications, not room history.
   - READ beyond the head sets the marker to the head.
   - PUSH URLs are at most 512 bytes.
   - CONNECTION's `<address>` is an IP address with an optional port.

9. **Decided later** (6.1, 6.2, 9.3, 10.4).
   - Room retention stays at least 1 day.
   - LIST and ADMIN ROOMS page by room name with `after=` and `limit=`,
     and reply `OK more=<0 or 1>`.
   - A NOTIFY with an unknown reason counts as new activity.

10. **Found in the M1 review** (2.3, 3.1-3.8, 4.1, 4.5, 5.3, 6.2, 7.3,
    9.3, 10.6).
    - C1 controls are excluded from the ABNF too. The ABNF describes
      names, option keys and keywords after folding.
    - Numbers have a grammar: decimal, no leading zeros, at most 2^63-1.
    - `too-long` covers names, ids, text, URLs and tag values; a number,
      key or signature of the wrong length is `bad-syntax`.
    - Unknown subcommands get `unknown-command`.
    - An `OK` or `ERR` a client cannot parse still ends its command.
    - Timestamps use upper-case `T` and `Z`, and no leap seconds.
    - Nonces are 16 to 64 bytes. AUTH takes an identity, and only an AUTH
      or REGISTER that parses uses up the nonce.
    - Blank MSG text is checked after unescaping, so line breaks count.
    - Keyword and number setting values ignore trailing spaces.
    - RELATED accepts `after=0`, and `<first>` > `<last>` returns nothing.
    - NOTIFY reasons are 1 to 32 characters of `a-z 0-9 -`.

11. **Found by the TLA+ sync model** in `proofs/sync` (6.1, 7.1-7.3, 7.6).
    - Clients catch up from a sync point, the seq up to which they have
      every event, not from the newest seq stored, which can lie past a
      gap after a dropped connection.
    - HISTORY and RELATED reply `OK id=<id> more=<0 or 1>`, so a page
      from a room that was dropped and created again is noticed.
    - JOIN events carry the room id in the `id` tag, so a device that
      still has an older room's history notices the new room.
    - Clients store no live events for a conversation until they have
      learned its id on the connection.
    - A cid only matches within the conversation, by id, it was first
      sent to.

12. **Decided while building M2** (2.1, 6.2, 11).
    - INFO reports `head=0` for a room with no events yet, such as one
      the server creates from its configuration.
    - A client that offers ALPN without `risala/1` is refused with
      `no_application_protocol`.
    - Only complete lines reset the idle timer, including empty and
      unparseable ones.
    - QUIT is the last command a connection runs. Later lines are
      ignored.

13. **Found while building librisala's connections** (2.2, 3.6, 4.2,
    4.6).
    - A client records "CA" or a pin only after the TLS handshake has
      completed.
    - A final response whose `ref` does not belong to the oldest open
      command means the client SHOULD close the connection and reconnect.
    - A guest that reconnects and gets `name-taken` for its own name
      SHOULD try another name. librisala tries `<name>2`, `<name>3` and
      so on.
    - REGISTER: the client learns the identity domain from INFO first.

14. **Found while building the server core** (5.3, 6.1, 7.2, 7.6, 12).
    - HISTORY with `after` and `before`: `more=1` counts only events
      below `before`.
    - A room you cannot see gets `ERR not-found`. A room you can see but
      may not join or read, such as a guest in a `guests none` room,
      gets `ERR forbidden`.
    - MSG to a room you are not a member of, and guests sending commands
      only identities may use, get `ERR forbidden`.
    - A resent cid is checked before anything else, so it always gets
      the original seq.
    - A guest's LIST leaves out rooms closed to guests.

15. **Found by librisala's sync simulation** (3.6, 7.1, 7.5, 7.6).
    - A CONV line, and the `OK` of JOIN and `INFO <room>`, agree with the
      live events around them: earlier events of the conversation are
      covered, later ones are newer. `risalad` queues them under the
      room's lock.
    - A live event for a conversation the client has no id for on this
      connection makes it send SYNC again.
    - Servers expire events oldest seq first.
    - Guests cannot resend safely after reconnecting. Clients show such
      messages as possibly not sent.

16. **Found by the server review** (2.3, 4.2, 5.3, 6.1, 6.2, 7.2, 7.5,
    10.4, 11).
    - Changing `guests` applies at once: `read` mutes the guests in the
      room, and `none` removes them with a PART each.
    - Guest PARTs missed in a crash are recorded when the server starts
      again.
    - Owners and moderators who left may still read a private room.
    - MSG to a room you cannot see gets `not-found`, and PART when not a
      member gets `not-found`.
    - Open reports survive ADMIN DROP.
    - `ERR too-long` may come before the LF, but the line resets the idle
      timer only once its LF arrives.
    - Expiry stops at the first event that is not old enough.

17. **Guest sessions and resuming** (4.2, 7.6, 13). Guests that
    reconnected filled rooms with JOIN and PART pairs, and came back as
    `~sam2`. Now GUEST's `OK` carries a secret `token`. After a guest's
    connection closes, QUIT included, the server keeps its name and rooms
    for at least 2 minutes. `GUEST <name> token=<token>` resumes the
    session without recording anything, and gets a new token. cids carry
    over to the resumed session.

18. **Found while fixing the server review** (3.6, 4.2, 7.1).
    - A server may stop reading commands while their responses go
      unread, so a client that pipelines MUST keep reading as it writes.
    - Guest PARTs recovered after a crash carry the restart time.
    - SYNC stays one reply. `risalad` streams its CONV lines, waiting for
      queue room between rooms, so a large SYNC cannot overflow a
      connection.

19. **Added end-to-end encryption to v1** (draft-02: 1, 2.1, 2.3, 3.2,
    3.7, 4.4, 4.5, 4.7, 4.8, 5, 6, 7, 9.2, 10, 12, 14, 15, App. A, B).
    - MLS [RFC9420] for direct conversations (always) and private rooms
      (opt-in at creation, with INIT). Public rooms are never encrypted.
    - One cipher suite, `0x0052`: X-Wing (ML-KEM-768 + X25519),
      ChaCha20-Poly1305, SHA-384, ML-DSA-44. It is the provisional value
      that OpenMLS 0.9 uses for these algorithms (feature
      `draft-ietf-mls-pq-ciphersuites`), so no fork is needed. The spec
      fixes the value for risala.
    - Device keys are ML-DSA-44 (`mldsa44` key file lines). The same key
      signs in and signs in MLS.
    - TLS requires X25519MLKEM768. rustls has it only in the aws-lc-rs
      provider, so the server and librisala move off ring.
    - Messages are encrypted under per-epoch history keys from the MLS
      exporter, not MLS application messages, so devices can keep them
      and decrypt HISTORY later and offline. New devices get keys from
      the identity's other devices, and there is an optional recovery
      key backup. Rooms choose `history shared` or `joined`.
    - The server tracks each group's public state (OpenMLS
      `PublicGroup`), checks commits against membership, and stores
      KeyPackages, Welcomes, GroupInfo and backups.
    - Lines that carry MLS data may be up to 8 MiB. Groups have at most
      512 devices.
    - Reports of encrypted messages use message franking.
    - Each group carries a conversation extension (`0xF2A1`) that ties
      it to its conversation and holds the room's `history` setting, so
      the server cannot swap groups or flip the setting.
    - A device keeps sending blocked while any leaf's key cannot be
      confirmed against its key file, instead of dropping the group.
    - New devices get earlier history keys only after the user confirms
      them on an existing device.
    - Confirmed with the user on 2026-11-07: ML-DSA-44 (not 65), suite
      value `0x0052` (not a private-use value), direct conversations
      always encrypted, and servers refuse TLS without X25519MLKEM768.

Open:

- The spec example tests, which now include the new verbs, and the
  Appendix B tests, which now use ML-DSA. Both fail until risala-proto
  catches up.
- The size limits, and whether OpenMLS can remove the joiner's earlier
  leaf and take the tree out of band, were settled by the spike (22).

20. **Found by the librisala review** (2.1, 3.2, 6.4, 7.1, 10.4).
    - The 7.1 head check compares with the sync point, not the newest
      seq stored, so a cache shared by two processes is not wiped.
    - Clients lower-case server hostnames and drop a trailing dot
      before SNI, trust records and signing.
    - DROP carries the dropped room's id in an `id` tag, and clients
      ignore a DROP for another id.
    - INVITE for someone already a member records nothing and gets a
      plain `OK`.

21. **Found while building guest resume and post-quantum TLS** (2.1,
    4.2, 6.2, 7.6).
    - GUEST's `OK` carries `resumed=yes` when a token resumed the
      session, so guests can resend unconfirmed messages and skip the
      extra SYNC.
    - The resumed session's old connection gets BYE and nothing more is
      read from it.
    - `guests none` removes guests from that room only.
    - Servers SHOULD refuse a client without X25519MLKEM768 with
      `handshake_failure`.

22. **Settled by the OpenMLS spike** (2.3, 12.2, 12.4-12.9, 14, 15,
    App. B). `spikes/mls` checked OpenMLS 0.9 against Section 12 of
    draft-02. Its report is `spikes/mls/RESULTS.md`, and changes A-Q
    below refer to it.
    - Decided with the user on 2026-11-07:
      - **Crypto provider** (implementation only, not in the spec):
        `openmls_libcrux_crypto`, plus a small wrapper that adds
        ML-DSA-44 from `libcrux-ml-dsa`, as in
        `spikes/mls/src/libcrux_mldsa.rs`. The binaries then carry one
        ML-DSA, and it is formally verified. Drop the wrapper once
        upstream supports ML-DSA.
      - **A leaf's credential and signature key never change** (12.2,
        12.5, 12.6; change C). OpenMLS accepts a path that changes them,
        so the server and devices check this themselves. A new key means
        a new leaf.
      - **Lifetimes** (12.4, 12.6; change G). They are checked on upload
        and when a commit adds a KeyPackage. Nobody checks the lifetimes
        of leaves already in the tree, unlike the SHOULD in RFC 9420
        section 7.3, because one device offline for longer than its
        lifetime would otherwise stop everyone else from joining. Devices
        call `skip_lifetime_validation()` when joining, and risalad keeps
        each group as a stored `PublicGroup` instead of rebuilding it
        from GroupInfo and tree, since `from_external` cannot skip the
        check.
      - **Rejoining** (12.6; change H). A device that could not process
        a commit because MLS rejected it, not because of a risala rule,
        MAY join again by external commit.
      - **Splitting adds** (12.5; change Q). Clients SHOULD add at most
        256 devices per commit. 8 MiB lines and 512 leaves stay: the
        worst case, 511 devices added in one commit, is 80.5% of 8 MiB.
    - Also from the spike:
      - HPKE parameters pinned: KEM `0x647a` (X-Wing), HKDF-SHA384,
        ChaCha20-Poly1305. OpenMLS names its X-Wing KEM `0x004D`
        internally, but both providers pass `0x647a` to HPKE (A).
      - Leaves list `last_resort` in their capabilities, and KEYPKG ADD
        checks the capabilities (B).
      - Remove allows the leaf of a key the same commit adds again (D).
      - The joiner's earlier leaf is the one with its signature key, for
        the server and devices alike (E).
      - The GroupInfo checks are listed, with what the server cannot
        check: the confirmation tag and path secrets. GroupContextExtensions
        keeps the extension list apart from `history` (F).
      - 12.8 is exact about padding, the `MLS 1.0 ` labels, HKDF-SHA384
        with the history key as PRK, tag lengths and what the HMAC
        covers. Devices keep each epoch's leaf keys and COMMIT seq, for
        when retention has removed the COMMIT events. Content is at most
        4 MiB, and the length limits of 2.3 do not apply to it (I-N).
      - A device derives each history key before it applies the next
        commit (O).
      - The server keeps the tree while a commit's Welcomes are pending,
        and a device deletes a Welcome only once it has joined (P).
      - Appendix B has a test vector for the history key and ENC, from
        `cargo run --release -- vectors` in `spikes/mls`. It starts at
        the exporter secret, since a whole group cannot be made
        reproducible.

    - Decided with the user later on 2026-11-07 (see 23):
      - **KeyPackage lifetime** (12.4). At most 12 weeks and one hour.
        RFC 9420 section 7.3 requires a maximum, and this value is
        OpenMLS's default, so default KeyPackages pass.
      - **Restored epochs** (12.8). A device that restored a history
        key from a backup, and so did not see that epoch live, skips
        decryption's step 1, the check of the epoch against the COMMIT
        events before the message.

Open:

- librisala's MLS storage: `openmls_sqlite_storage` 0.3 cannot link next
  to rusqlite 0.41. The spike recommends porting it.
- Run `cargo audit` on the chosen crates.

23. **Found while implementing draft-02 in risala-proto** (2.3, 3.2,
    3.7, 5.4, 5.8, 12.8, 12.10, 12.11, 13, App. A).
    - Decided with the user on 2026-11-07:
      - **Encrypted reports carry their data after the verb** (2.3,
        3.2, 5.8, 12.8, 13). The franking key and content were tags on
        REPORT, so a decoder had to allow 8 MiB of tags on every line
        before it saw the verb. Now a separate verb,
        `REPORTENC <conv> <seq> <frank-key> <content> [<reason...>]`,
        reports an ENC event, and reviewers receive it with the same
        parameters, followed by the ENC event with an empty payload and
        its `frank` tag. REPORT of an ENC event, and REPORTENC of a MSG
        event, get `ERR invalid`. The `frank-key` and `content` tags are
        gone. Everything up to the end of the verb must fit the normal
        limit, tags included, so a receiver knows from the first 8192 or
        16384 bytes whether a line may be long.
      - **BACKUP GET pages oldest first** (12.10). Without `after` it
        starts at the oldest epoch, so epoch 0 is reachable, and
        `after=<epoch>` continues after that epoch. `limit` counts
        epochs, since an epoch may have one blob per key id and a page
        never splits them. The reply is `OK more=<0 or 1>`.
      - **Deleted ENC placeholders drop `frank`** (5.4, 12.11), like the
        file tags. The copy kept for an open report keeps it.
      - The KeyPackage lifetime and the restored-epoch rule of 22.
    - Slips fixed:
      - 2.3 lists long verbs per direction: servers never send INIT, and
        clients never send long GROUPINFO or WELCOME lines.
      - 3.7: a franking commitment or key of the wrong length, or base64
        that is not valid, gets `bad-syntax`; a required one that is
        missing gets `invalid`.
      - 5.8: the franking check is HMAC-SHA-384 of the decoded content
        bytes, not of the base64 text.
      - 12.8: ENC events may have an empty payload (deleted placeholders
        and reviewers' copies), so the event's syntax is
        `ENC <conv> <epoch> [<payload...>]`. The command still needs one.
      - 12.10: `<blob>` is base64 with padding, 112 characters.
      - Appendix A: `openssl genpkey` writes PKCS#8 with the seed and the
        expanded key, not Appendix B's seed-only form, and readers MUST
        accept both. `-provparam ml-dsa.output_formats=seed-only` writes
        the seed-only form. `pkeyutl -sign` needs `-in` for ML-DSA.
        Checked with OpenSSL 3.5.9 (the dev shell) and 3.6.5.

## 6. Decisions

- **Minimum Rust version:** the newest rustc in the current NixOS stable
  release, now 1.95 (NixOS 26.05). Raise `rust-version` in Cargo.toml
  when a new NixOS release ships a newer one.
- **Minimum OS versions:** the latest release of each platform: iOS and
  macOS 27 (the ones Xcode 27 ships with), the newest Android API level,
  and the newest GNOME platform and libadwaita. Apps may use their
  newest APIs freely, and raise the minimum when a new release comes
  out.
- **Hosted key files** (M3): `risalad` has an optional HTTPS listener
  that serves `/.well-known/risala/<name>`, and later the upload URLs.
  It also writes the key files to a directory, so operators can serve
  them from their own web server instead.
- **The Apple app** keeps its current deployment targets (iOS 18 and
  macOS 15) for now.

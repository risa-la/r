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
- **Tested from transcripts.** The server is tested with scripted line
  transcripts. Every example in the spec becomes a test. Using the
  protocol by hand with `openssl s_client` is no longer a goal: connecting
  will need a client that solves proof of work (item 42).

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
│   ├── risala-keyfetch/   fetches key files over HTTPS (4.4), for the server
│   ├── risala-pow/        HashWX proof of work: interpreter, JIT and puzzles
│   ├── librisala/         the client library
│   ├── librisala-ffi/     planned: UniFFI bindings for Kotlin and Swift
│   ├── risala-cli/        small terminal client and key tool built on librisala
│   └── risala-conformance/  planned: black-box tests that can run against any server
├── clients/
│   ├── gnome/             planned: Rust, gtk4-rs, libadwaita
│   ├── apple/             Swift, SwiftUI (macOS and iOS)
│   └── android/           planned: Kotlin, Jetpack Compose
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

### 3.2. risala-pow

Proof of work against bots (item 42). It implements HashWX, written
clean-room under Apache-2.0: tevador's reference is LGPL-3.0, which an
iOS App Store app cannot ship.

- A `no_std` core makes a function's 32 programs from a seed, hashes
  nonces with a reusable scratchpad, and solves and checks puzzles. Kani
  proofs cover every seed.
- Two backends. A JIT for x86-64 and aarch64 (Linux, Android and macOS)
  keeps strict W^X, or Apple's per-thread `MAP_JIT` on Apple Silicon. Its
  only unsafe code is `jit/exec.rs`. The interpreter runs everywhere
  else, including iOS, and wherever the OS refuses executable memory.
- The JIT is checked against the interpreter: differential tests, a fuzz
  target, every instruction encoding against an independent decoder, a
  static checker of compiled code, and Kani proofs of the emitters. CI
  runs the long comparison on x86-64, ARM and macOS runners.
- On one Threadripper 5995WX core, the interpreter takes about 20 µs a
  hash and the JIT 2.25 µs. tevador's JIT takes 2.35 µs.

### 3.3. risala-server (`risalad`)

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

### 3.4. librisala

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
  - Keys are stored through a platform trait, always under hardware
    (item 45): the Keychain wrapped by the Secure Enclave on Apple
    platforms, the Android Keystore (StrongBox where there is one) on
    Android, and libsecret wrapped by the TPM through `systemd-creds` on
    Linux. A device without that hardware does not start. The Secure
    Enclave cannot hold ML-DSA keys, so keys are software keys that are
    wrapped at rest. History keys, the recovery key (12.9, 12.10) and
    the cache's SQLCipher key are stored the same way.
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

### 3.5. Bindings and apps

- **librisala-ffi:** UniFFI. It produces Kotlin with JNI `.so` files for
  each Android ABI, and Swift with an XCFramework for macOS and iOS.
  Async functions and callback interfaces carry timeline diffs and
  platform services.
- **Theme:** every app follows the terminal design that the Apple app
  and the website already use: the palette roles with light and dark
  values, JetBrains Mono, framed panels and the breadcrumb heading. The
  colors and metrics live in one place and each app uses them (M6), so
  the apps stay native but look like one product.
- **Strings:** the apps share their text through `l10n/` (see
  Decisions), so the same screen says the same thing on every platform.
- **GNOME:** gtk4-rs and libadwaita, using librisala directly with no
  FFI. It comes after the phone apps (item 40). Shipped through Nix and
  native packages, not Flatpak (item 45).
- **Apple:** a SwiftUI app shared between macOS and iOS, with a
  Notification Service Extension for push.
- **Android:** Kotlin with Jetpack Compose. Push through FCM, and through
  UnifiedPush where available.

### 3.6. Tooling

- **Nix flake** (flake-parts): the dev shell now; later packages for
  `risalad` and `risala-cli`, `nix flake check` running the tests, and a
  NixOS module for the server.
- **Cross-compiling:** Android and iOS targets need extra Rust standard
  libraries. When we get there, pin a toolchain with `rust-toolchain.toml`
  and switch the flake to rust-overlay or fenix. On macOS the flake
  builds the Apple app too (`nix build .#apple-macos`, `.#apple-ios`),
  through SweetPad and the host's Xcode. Those builds are not hermetic:
  Xcode itself stays outside the Nix store (see `clients/apple`).
- **CI:** `nix flake check` (fmt, clippy, rustdoc, tests), Kani,
  risala-pow's JIT against its interpreter on x86-64, ARM and macOS
  runners, and a smoke test that starts `risalad` and talks to it through
  `openssl s_client`. Once connecting needs proof of work (item 42), the
  smoke test talks through `risala-cli` instead.

## 4. Milestones

Each milestone ends with something that runs.

| # | Milestone | Done when |
|---|---|---|
| M0 | Scaffold | Cargo workspace, CI, license chosen, spec issues in Section 5 decided |
| M1 | `risala-proto` | Every spec example line parses and serialises again unchanged. Appendix B passes. Fuzzer runs clean |
| M2 | Server: guests and rooms | Two `s_client` sessions chat as guests: GUEST, JOIN, PART, LIST, MSG, HISTORY, SYNC, INFO, PING, QUIT, stored in SQLite |
| M3 | Server: identities | AUTH with key files, REGISTER, KEY, hosted `.well-known`, BLOCK, UNREGISTER, READ, `cid`, TYPING, NAME, MEMBERS, WHOIS, PRESENCE. Direct conversations moved to M5a, since draft-02 makes them always encrypted |
| M4 | Server: rich messages and moderation | reply, edit, react, DELETE, RELATED; roles, ROLES, SET, INVITE, KICK, BAN; REPORT and RESOLVE; retention; all ADMIN commands |
| M5 | librisala core and `risala-cli` | The CLI signs in, syncs, works offline from its cache and recovers from dropped connections without losing or duplicating messages |
| M5a | End-to-end encryption | Post-quantum TLS and ML-DSA keys everywhere. KEYPKG, INIT, COMMIT, GROUPINFO, WELCOME, ENC and BACKUP in `risalad` and librisala, and direct conversations. Two CLI devices talk in an encrypted direct conversation and room; a new device of the same identity reads the whole history offline; a restore from a recovery key works; reports of encrypted messages verify |
| M6 | FFI, shared theme and strings | `librisala-ffi` with UniFFI for Swift and Kotlin, platform key stores, one source for the theme's colors and metrics, and the shared strings in `l10n/`. The Apple app and an Android shell sign in, sync and show a timeline through the bindings |
| M6a | Proof of work | The puzzle is in SPEC.md (item 42). `risalad` hands out puzzles and checks solutions with the interpreter; librisala solves them with the JIT where it can, on every hardware thread. By default a client cannot become a guest or register without solving one. The `openssl` smoke test moves to `risala-cli`. The `risala-pow` crate itself is done (3.2) |
| M7 | iOS and Android apps | Built side by side, with macOS coming along through the shared SwiftUI app. Onboarding (guest, registering with an invite, signing in, pairing a device by QR code, recovery), rooms, direct conversations and encryption. Day-to-day usable on phones against a real server |
| M8 | Push and files | PUSH, the gateway, the iOS extension, FCM and UnifiedPush, then UPLOAD over HTTPS |
| M9 | GNOME app | Day-to-day usable on Linux against a real server |
| M10 | Hardening and launch | Rate limits, load testing, fuzzing, the NixOS module, a public server and a docs site on risa.la |

Phone apps come first (item 40). Push comes straight after them, since a
phone app without notifications is hard to use day to day.

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
   - Key files over 64 KiB mean no keys (256 KiB since draft-02, for ML-DSA keys). The 64-key limit counts only
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
  to rusqlite 0.41. Settled in 43: it is ported.
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

24. **Found while fixing librisala's review** (6.4, 7.1). The head check
    uses the sync point as it was when the command was sent. A live event
    above the head SYNC just reported, and an INVITE for your own
    account, are both reasons to SYNC again. BACKUP GET's `limit` counts
    epochs and never splits one (confirmed with the user).

25. **Found while building key file fetching** (4.4). Key files are
    fetched with TLS 1.3 only. A failed refetch keeps a cached copy.
    Which answers count as failed was settled later, in item 28: only a
    key file (200) or a gone answer (404 or 410) replaces the copy. Lines
    that are not valid UTF-8 are malformed and ignored. The fetcher is
    hand-written (one HTTP/1.1 GET) and trusts Mozilla's roots through
    `webpki-root-certs`, so servers do not depend on their host's CA
    store.

26. **Found while building identities** (4.4, 4.6-4.8, 6.2, 6.3, 8.5).
    - INFO says `register=no` while registration is closed (confirmed
      with the user).
    - UNREGISTER keeps room bans and deletes invitations (confirmed).
    - Operators may join rooms they are banned from (confirmed).
    - Invitees may see a private room's INFO, but not its HISTORY, before
      joining (confirmed).
    - Retired names get `name-taken`. Registration over the limit gets
      `rate-limited`. KEY for an identity the server does not host gets
      `not-supported`. KEY ADD of a known key replaces its label, a label
      with a line break is `bad-syntax`, and a 65th key is `forbidden`.
    - Servers close devices only after fetching a key file that no longer
      lists their key, never because a fetch failed.
    - UNREGISTER `purge=yes` waits for DELETE in M4 and gets
      `not-supported` until then.

27. **Found while building READ, TYPING, NAME and PRESENCE** (5.7,
    7.4, 8.1-8.3), all confirmed with the user. People in the 30-second
    wait before going offline count as online in MEMBERS and WHOIS.
    TYPING needs the right to post, and may be dropped when sent more
    than about once a second. READ works in any room you may read.
    Nobody gets PRESENCE about themselves. NAME also goes to your own
    devices. Servers may cap blocks, with `forbidden` beyond the cap.

28. **Found by the M3 review** (2.1, 3.2, 3.6, 3.7, 4.2, 4.4-4.8, 5.7,
    6.1, 7.1, 7.4, 8.2, 8.3, 8.5, 12.12, 13, 14).
    - Confirmed with the user on 2026-11-07:
      - **SNI must name the server** (4.5, 14). AUTH and REGISTER get
        `auth-failed` unless the connection's SNI is the server's
        configured hostname or a name on one of its certificates.
        Otherwise a malicious server could connect to another with its
        own name in SNI and relay that server's nonce, so binding the
        host into the signature stopped nothing.
      - **New error code `unavailable`** (3.2, 3.7, 4.5). AUTH gets it
        when the server could not get the key file at all, and may add
        `retry`. `auth-failed` now means only that the signature did not
        verify against the keys the server got, which includes a file
        without the key and a 404. Clients retry `unavailable` with
        backoff and do not retry `auth-failed`.
      - **BLOCK and UNBLOCK reach the account's other connections** (5.7,
        13), as READ does. Not events. Clients apply them one at a time.
        `UNBLOCK <target>` is a new server line.
      - **Display names** (8.2, 14). Clients compare names without bidi
        controls, ignoring case and collapsing whitespace, show the uid as
        a separate element, and always show it for a name with `@` or
        one that looks like a uid. Servers may refuse names with bidi
        controls.
      - **Key labels are at most 64 bytes** (4.4, 4.7, 10.5). KEY ADD and
        ADMIN ADDKEY get `too-long`, and a key file line with a longer
        label is malformed. A key line is then at most 1827 bytes with
        CRLF, so 64 keys take 116,928 bytes, under half of 256 KiB.
      - **Which answers remove a key** (4.4, 12.12). A fetch now has
        three outcomes: a key file (200), gone (404 or 410), or failed
        (no response, DNS, TLS, timeout, 5xx, any other status). A key
        file without the key, or gone, removes the key and closes its
        connections. A failed fetch keeps the cached copy and closes
        nothing. This replaces item 25's "any non-200 answer revokes
        it".
      - **Room creation is rate-limited** (6.1, 14): `rate-limited` with
        `retry`, since anyone can mint identities on their own domain.
      - **Guests naming a uid get `not-found`** (4.2, 13), since they
        have no direct conversations.
    - Clarifications:
      - The `<read>` on a CONV line covers the READ lines sent before
        it, as heads cover events (3.6, 7.1, 7.4). BLOCKS covers the
        BLOCK and UNBLOCK lines sent before it in the same way (5.7).
      - A client whose REGISTER got no answer tries AUTH with the same
        key before giving up, and keeps the key until then (4.6).
      - KEY LIST tells a client whether the server hosts its identity
        (`not-supported` if not). INFO's `register=` does not, since it
        says `no` while registration is closed (4.7, 4.8, 8.5).
      - Clients that show presence send MEMBERS and WHOIS again after
        reconnecting, since PRESENCE only reports changes (8.3).
      - The registration rate limit counts registrations that succeeded
        or are in progress, so parallel connections cannot get around
        it (4.6, 14).
    - Chosen while writing it up, and confirmed with the user on
      2026-11-07:
      - A 200 file over 256 KiB counts as a file with no keys (removed),
        while a redirect, 401, 403, 429 or other non-404/410 status
        counts as a failed fetch (outage).
      - A cached copy that does not verify, followed by a failed
        refetch, gets `unavailable`, not `auth-failed`.
      - Display names are also trimmed before comparing, and a server
        refuses a name with bidi controls with `forbidden`.
      - Guests still get `forbidden` for commands closed to them (READ,
        ENC and so on), even when they name a uid.

29. **Found while fixing the M3 reviews** (4.5, 5.7, 6.1, 8.2),
    confirmed with the user on 2026-11-07:
    - Display names are also compared without zero-width characters, and
      look-alike `@` signs make the uid show.
    - A sign-in refused for a wrong host name keeps `auth-failed`, with a
      message that says so.
    - BLOCK and UNBLOCK that change nothing are not sent to other devices.
    - The room-creation limit may exempt operators.

    Implementation choices recorded without a spec change:
    - A device has one key per identity, used on every server and in
      MLS. librisala's platform key store is keyed by identity only.
    - A REGISTER with no answer gets one AUTH attempt with the same key,
      then `Unconfirmed`, and the key is kept.
    - librisala refreshes MEMBERS and WHOIS after a reconnect only for
      what the app watches, at most 64 at a time.
    - UNREGISTER replies `OK` once the identity is deleted, even if the
      key file could not be removed. The removal is retried, logged, and
      redone at startup. A second UNREGISTER at the same time gets
      `forbidden`.
    - Certificate names for the SNI check are taken at handshake time.

30. **Decided before building M4** (5.4, 6.4, 10.2, 10.6), confirmed
    with the user on 2026-11-08:
    - Authors may DELETE their own messages in a room they can no longer
      read, for example after leaving a private room or being kicked.
    - KICK of someone who is not a member gets `not-found`, even if they
      hold a role. ROLE or BAN takes a departed person's role.
    - Room BAN of a guest bans the uid only. ADMIN BAN of a connected
      guest bans its IPv4 address, or the IPv6 `/64` it is in.
    - `ADMIN SET guests no` ends the sessions of guests already
      connected, with BYE.

31. **Found while building M4's moderation and ADMIN** (6.2-6.4,
    10.1-10.3, 10.6), confirmed with the user on 2026-11-08:
    - A BAN event reaches a non-member only if they could see the room
      before, so a ban made in advance does not reveal a private room.
    - INVITE of a banned identity gets `forbidden`: unban first.
    - The only owner cannot KICK or BAN themselves (`last-owner`).
    - A new address ban ends the sessions of guests connected from
      inside it.
    - Operators count as owners, so moderators cannot kick or ban them.
    - AUTH and REGISTER check server bans after the signature, so only
      the key's holder learns of a ban.
    - SET to the current value, ROLE to the current role, and BAN of
      someone already banned (and gone) record nothing and get a plain
      `OK`. BAN again replaces the reason.
    - Smaller ones: UNBAN, ADMIN UNBAN, ADMIN DEOP and ADMIN DISCONNECT
      of nothing get `not-found`. ADMIN UNBAN takes the address a guest
      ban is listed under. `ADMIN SET guests no` also ends sessions
      waiting to be resumed. Role-holders who left keep their rights.
      ROLE of a guest is `forbidden`. `SET retention 0` is `bad-syntax`.
      Section 10.5 commands get `not-supported` on a server that hosts
      no identities.

32. **Found while building M4's client** (3.2, 5.4, 5.8), confirmed with
    the user on 2026-11-08:
    - DELETE of a message that is already deleted gets `OK` with the seq
      of the DELETE event that deleted it, so DELETE is safe to resend.
    - DELETE may carry an `id` tag with the conversation's id. A
      different id gets `not-found`. Clients send it when deleting in a
      room they can no longer read.
    - RESOLVED goes to every reviewer connection except the sender's,
      including the resolver's other devices.

33. **Found while building M4's messages and reports** (5.3, 5.4, 5.8,
    10.4), confirmed with the user on 2026-11-08:
    - A guest is the author only of what it sent in its current session,
      so someone reusing a guest name cannot edit or delete an earlier
      guest's messages.
    - ADMIN DROP also reaches owners and moderators who are not members.
    - Smaller ones: editing someone else's message is `forbidden`.
      `deleted=` counts DELETE events recorded. Repeated reactions are
      compared as escaped bytes. RESOLVE by a non-reviewer is
      `not-found`. A repeated REPORT gets its id before the message is
      checked. A guest reusing a name may get the earlier guest's report
      id back; this is accepted.

    Implementation choice: the report rate limit is
    `limits.reports_per_hour` in the configuration, 30 by default.
    Identities count by uid. Guests count by their session's address,
    IPv6 by its /64, since a guest can take a new name at will.

34. **Found while testing M4's client** (librisala only, no spec change),
    confirmed with the user on 2026-11-08: an identity's messages for a
    room it has left, or was kicked or banned from, fail with
    `NotInRoom` instead of waiting until it joins again, and `send` to
    such a room gets `NotJoined`. DELETEs still go out (5.4). A guest's
    messages still wait, since a guest rejoins its rooms by itself after
    a reconnect.

35. **Found by M4's end-to-end tests** (5.8, 10.2), confirmed with the
    user on 2026-11-08:
    - The author of a reported message is never one of its reviewers:
      no lines, left out of REPORTS, and RESOLVE gets `not-found`.
    - ADMIN BAN of a target that covers an operator, the sender
      included, gets `forbidden`. DEOP first.

36. **Found by the M4 server review** (3.6, 5.4, 5.8, 6.4, 10.1, 10.2),
    confirmed with the user on 2026-11-08:
    - ADMIN OP of an identity covered by a server ban is `forbidden`.
      Operators from the configuration are exempt from server bans at
      sign-in, and the server warns at start if a ban covers one.
    - Both lines of a report carry `id` with the conversation's id.
    - INVITE of someone already invited records nothing: plain `OK`.
    - An address ban also ends guest sessions waiting to be resumed
      whose last connection came from inside it (4.2 over 10.2).
    - ROLES and BANS snapshot lines follow the 3.6 consistency rule.
    - A resent REPORT gets its id before every check but the
      conversation existing.
    - DELETE of an event that is not a message is `not-found`.

37. **Found by the M4 client review** (librisala and the CLI only),
    confirmed with the user on 2026-11-08:
    - Item 34 applies to guests too after KICK, BAN, their own PART or
      DROP. A guest's messages wait only when its room went missing
      because its session ended, since the client then rejoins.
    - librisala exposes `Account::is_operator()` from `op=yes`, and the
      account's own role in each cached conversation. Roles are an enum
      across the API.
    - `risala admin drop` takes the room twice, like `admin unregister`.

38. **Announcement-only rooms** (3.2, 6.2, 6.3, 8.1, 12.2, 12.5, 12.8,
    12.11), asked for by the user and confirmed on 2026-11-08:
    - A new owner-only room setting `send`, `all` (default) or `mods`.
      Under `mods`, only owners, moderators and operators may send
      messages.
    - Plain members and guests may still react, and delete their own
      messages and reactions (5.4 as everywhere). Replies, edits and
      TYPING get `forbidden`.
    - Encrypted rooms: `send` lives in the conversation extension next
      to `history`, changed by an owner's COMMIT. The server lets plain
      members send ENC, and devices drop members' non-reactions.
      Operators without a role count as plain members there.
    - Milestone: M4 for unencrypted rooms (server, librisala, CLI). The
      encrypted part is specified now and built in M5a.

    Implementation choices recorded without a spec change: librisala
    leaves refusing a member's message in an announcement room to the
    server, since it cannot always know offline whether the account is an
    operator. The `id` tag of report lines is optional when parsing, so
    older servers' lines still parse.

39. **Follow-ups from the M4 client fixes** (3.2, 5.3, 6.1), confirmed
    with the user on 2026-11-08:
    - JOIN's OK carries `role=`, as INFO's does, so a room's creator
      learns at once that it owns the room.
    - MSG may carry `id` with the conversation's id, as DELETE may. A
      different id gets `not-found`. The cid is checked first (7.6).
    - Done on a short branch, `m4-followups`, before M5a.

40. **Onboarding and identity review** (4.4, 4.6, 4.7, 10.5, 10.6,
    12.10, 14), decided with the user on 2026-11-08. Spec text still to
    write, before M7:
    - **Phone apps first.** After M5a: FFI and the shared theme (M6),
      iOS and Android side by side (M7), push and files (M8), then GNOME
      (M9) and launch (M10).
    - **Pairing devices by QR code.** The new device shows a QR code
      holding the identity, its public key and a label. A signed-in
      device scans it and adds the key (KEY ADD, or shows the key file
      line for a self-hosted identity). The format goes in a spec
      appendix, so every app can pair with every other.
    - **The recovery key also restores the identity.** An ML-DSA-44 key
      is derived from the same 32-byte recovery secret and listed in the
      key file with the label `recovery`. It never uploads KeyPackages,
      so it never joins a conversation. With it, a person who lost every
      device signs in on a new one, adds the new device's key and
      removes the lost ones, then restores history from the backup. A
      new recovery key replaces the old key file line. Section 14 says
      that whoever holds the recovery key controls the identity.
    - **Invite codes for registration.** Operators create and revoke
      codes with ADMIN, REGISTER takes `invite=<code>`, and INFO says
      when registration needs an invite. An invite link can carry the
      server and the code.

    Open:

    - The QR payload, and whether it is a URI that invite links share.
    - Invite codes: single-use or counted, expiry, the ADMIN verbs (room
      INVITE already exists), and the error for a bad code.

    App-level, no spec change:

    - Apps are identity-first: a person picks an identity, such as
      `alice@example.org`, and then the servers they use it on. The first
      identity on a device is the default for new servers. librisala's
      accounts stay (server, identity) pairs underneath.
    - Key management goes to the server that hosts the identity. Other
      servers answer `not-supported`, so librisala should remember the
      host from REGISTER, or find it with KEY LIST.
    - Device keys never leave the device: Keychain items are
      `ThisDeviceOnly` and not synchronised, and Android keeps them out of
      backups. A restored phone is a new device and pairs again.
    - Onboarding says that direct conversations need both people on the
      same server, since there is no federation (5.1).

41. **Follow-ups from the review of main** (7.6, 4.4), decided with the
    user on 2026-11-08. No spec change:
    - **One message in flight per conversation.** The outbox sends the
      next message to a conversation only after the previous one's OK
      or ERR, and holds everything after `rate-limited` until the retry
      time. Order is always kept; a burst to one room takes a round trip
      per message.
    - **Stable message ids.** A message sent through the outbox keeps
      the id `o<outbox id>` once it is stored; every other item is
      `e<seq>`. While an entry is sending, an own event with the same
      text and reply target waits for the OK rather than showing twice.
      A server that changed the text would show the message twice until
      the OK, which is accepted.
    - **Key-file cache sites** stay as they are: the per-site share can
      be split with subdomains of short domains under two-letter TLDs.
      Revisit in hardening.
    - The Apple app's adapter contract follows librisala's timeline
      (diffs by index, paging through the timeline, start of history).
      It lands once it builds on a Mac.

42. **Proof of work, and no more hand use** (1.1, 2.1, 4.1, 4.2, 4.6,
    14, Appendix A), decided with the user on 2026-11-08. Spec change
    still to write (M6a):
    - **Proof of work is on by default**, to keep bots out. The
      algorithm is HashWX 1.0.0, through our `risala-pow` (3.2, and
      Section 6).
    - **Hand use is dropped as a goal.** `openssl s_client` can no
      longer connect on its own, since it cannot solve the puzzle. This
      frees the spec to require ALPN `risala/1` (2.1) and shorten the
      120-second sign-in window (4.1). Appendix A goes, and so does the
      README's `s_client` session.

    Still to settle, as questions to the user:

    - Which commands need a solution: GUEST and REGISTER, and perhaps
      AUTH for an identity whose key file the server has not cached,
      since fetching it costs the server.
    - How a solution is bound to the connection so it cannot be reused,
      for example by deriving the puzzle's challenge from the greeting's
      nonce.
    - How the server announces the puzzle and its difficulty (a greeting
      tag, or an `ERR` with the parameters), and the new error code.
    - The pass rule: a hash at most the target with the block number as
      8 little-endian bytes, as Cap does, or strictly below it, as
      tevador's sketch has it.
    - Nonces per function: 463, tevador's recommendation for native
      code, or 65536, his choice for browsers.
    - The default difficulty, an `ADMIN SET` key for it, and whether it
      rises under load. It has to be set from the slowest supported
      client, an iPhone using the interpreter.

43. **Decided before building M5a** (4.4, 12.10, 14), with the user on
    2026-11-08:
    - **The recovery signing key** (from 40). Its ML-DSA-44 seed is
      HKDF-Expand(HKDF-Extract("", recovery key), info, 32), where
      `info` is `risala identity ` followed by the uid, the same shape
      as the backup key's.
    - **Only clients treat the `recovery` key differently.** A client
      MUST NOT upload KeyPackages with it, so it never joins a group.
      Servers and devices ignore the label, which stays a hint for apps,
      as labels are for people (4.4).
      Apps may show a `recovery` key as the recovery key rather than as
      a device only while no group has a leaf with it (12.12), so that
      whoever controls a key file cannot hide a new device by its label.
    - **Built in M5a.** The spec text for the recovery key restoring the
      identity is written now, and librisala and the CLI build it, so
      M5a's recovery test starts from losing every device.
    - **MLS storage** (implementation only, from 22).
      `openmls_sqlite_storage` is ported to rusqlite 0.41 inside the
      workspace, with a binary codec, as the spike recommended.
    - **At rest** (implementation only). librisala's whole database,
      the MLS state, history keys and the message cache, is encrypted
      with SQLCipher. The apps keep its key in the platform key store
      (M6): the Keychain, under a Secure Enclave key where there is one,
      the Android Keystore, under StrongBox where there is one, and
      libsecret on GNOME. The device key's seed and the recovery key are
      kept the same way (Linux and the CLI changed by 45). The Secure
      Enclave and StrongBox cannot hold ML-DSA keys themselves, so they
      only wrap the stored secrets. The
      CLI keeps the database key in its private state directory (changed
      by 45).
    - **How the storage and SQLCipher were built** (implementation only,
      no spec change):
      - The port of `openmls_sqlite_storage` is tested with real groups:
        two devices on their own files, two connections on one file,
        rollback of a merged commit and of a Welcome, and each kind of
        row written and deleted. It needed no fixes.
      - **Crypto under SQLCipher.** On Apple platforms rusqlite's
        `bundled-sqlcipher` uses CommonCrypto, so the apps ship no
        OpenSSL. Elsewhere it needs OpenSSL's libcrypto, and librisala
        uses `bundled-sqlcipher-vendored-openssl`, which builds OpenSSL
        from source and links it statically: Android has no libcrypto
        for apps, and plain cargo builds then need no OpenSSL headers.
        Nix builds set `OPENSSL_NO_VENDOR` and link nixpkgs' OpenSSL;
        distributions packaging the GNOME app can do the same. The
        `libtomcrypt` that `sqlcipher-src` carries is not usable through
        libsqlite3-sys yet.
      - **The server.** Cargo builds one SQLite per build, so when the
        server is built together with librisala, as in the workspace's
        tests, it gets SQLCipher's SQLite (now 3.53.4, against 3.54.1).
        That is accepted: without a key SQLCipher reads and writes
        ordinary SQLite files, and the server's tests pass on it.
        `risalad` built alone (`-p risala-server`, as the Nix package
        is) keeps plain SQLite.
      - **The key.** A raw 256-bit key (`PRAGMA key = "x'...'"`), so
        SQLCipher skips its passphrase KDF and opening a connection stays
        cheap for the iOS notification extension. Every connection is
        keyed before anything reads it, and a key that does not open the
        file is its own error, not a corrupt cache. A build without
        SQLCipher is refused, rather than writing in the clear.
      - **Caches from before encryption** are encrypted when opened,
        with `sqlcipher_export` into a new file that then replaces the
        old one, so the outbox's unsent messages are kept. A write lock
        on the old file keeps a second process from doing the same at
        once. The old file's blocks are freed, not overwritten.
      - The CLI keeps the key as 32 bytes in `cache.key`, made on first
        use, mode 0600; one that others can read is refused, as for
        device keys. Losing it loses the cache. (Replaced by 45: the CLI
        keeps it under the TPM or the Secure Enclave.)
      - The MLS tables are schema version 12 of the cache. MLS operations
        run in the cache's own write transaction (`BEGIN IMMEDIATE`), on
        a provider whose storage is that transaction, so the MLS state
        and the cache's rows commit or roll back together.
      - For M6: an encrypted WAL database in an iOS app group container
        may need SQLCipher's plain-text header
        (`cipher_plaintext_header_size`), so that iOS does not end the
        app for holding its lock while suspended. Check this when the
        app shares the cache with its notification extension.

44. **Found while building M5a's foundation and server storage** (3.7,
    12.2, 12.4, 12.7, 12.10), decided with the user on 2026-11-08:
    - **`required_capabilities`** lists exactly the conversation
      extension `0xF2A1`, no proposal types and the `basic` credential
      type, as the spike did. The group context has exactly that and
      the conversation extension, in that order, since the server
      compares the list exactly.
    - **KEYPKG GET without a key file** replies `ERR unavailable`
      rather than hand out KeyPackages of keys that may have been
      removed. `unavailable` now covers that too.
    - **Backups per epoch.** A server MAY limit how many key ids it
      keeps blobs for in one epoch (`ERR forbidden`), since a BACKUP GET
      page holds whole epochs. It must allow at least 4. risalad allows
      8.
    - **WELCOME DEL** of an id that is not pending replies `OK`, so a
      device whose `OK` was lost can retry.

    Implementation choices recorded without a spec change: risalad
    keeps an identity's backups after it leaves a conversation or the
    room is dropped, until BACKUP DEL or UNREGISTER. It allows 100
    KeyPackages per device and 600 KEYPKG GETs per identity an hour, and
    deletes ended KeyPackages hourly. Uploading a KeyPackage it already
    has stores nothing and replies `OK`.

45. **Keys at rest need hardware** (3.3, 43), decided with the user on
    2026-11-08. Implementation only, no spec change. It covers the
    cache's SQLCipher key, the device key's seed, history keys and the
    recovery key.
    - **No downgrade.** Every build keeps these secrets under hardware,
      and a device without it refuses to start rather than fall back to
      a weaker store such as a plain key file. Each install records how
      its secrets are protected and refuses to open them with anything
      weaker later. If the hardware key is lost (a cleared or replaced
      TPM, a lost Keystore key), the device starts afresh as a new device
      and recovers through its backups (12.9, 12.10).
    - **Apple platforms (apps and the CLI on macOS).** A P-256 key in the
      Secure Enclave wraps each secret (ECIES), and the wrapped value is
      kept in the Keychain, `AfterFirstUnlockThisDeviceOnly`, with no
      biometric check, so the notification extension can open the cache.
      Keeping it in the Keychain means P-256, which is not post-quantum,
      is never the only layer. Macs without a Secure Enclave (Intel
      without a T2) are refused.
    - **Android.** A non-exportable AES-256-GCM Keystore key, in StrongBox
      where there is one and the TEE otherwise, wraps each secret. The
      wrapped values are kept in the app's private files, out of backups.
      The key does not require user authentication, so push works while
      the phone is locked.
    - **Linux (the GNOME app and the CLI).** Each secret is wrapped with
      `systemd-creds --user` bound to the TPM (systemd 256 or newer), and
      the wrapped value is kept through libsecret's Secret Service
      (gnome-keyring, KeePassXC, KWallet). A machine without a TPM,
      without systemd 256 or without a Secret Service refuses to start;
      the app says what is missing. The host key alone is not enough.
      The Secret Service cannot say whether it is hardware-backed, so the
      TPM is what provides that.
    - **No Flatpak.** The Secret portal is software only and the sandbox
      cannot reach the TPM or `systemd-creds`, so the GNOME app ships
      through Nix and native packages instead.
    - **Tests and CI.** The CLI's tests run against a software TPM
      (swtpm) and `systemd-creds`, in CI and locally, so the real path
      is tested. The 0600 `cache.key` and PEM key files of 43 go away;
      there is no test-only file store.

46. **Found while building M5a's server groups** (6.2, 6.3, 7.1, 12.5),
    decided with the user on 2026-11-08:
    - **CONV allows head `0`**, for a direct conversation that INIT
      started, before its first COMMIT. Otherwise a crash between INIT
      and COMMIT leaves it out of SYNC.
    - **Only the owner role counts in encrypted rooms**, for INIT and for
      changing `history` and `send`, since devices check the role from
      the room's events and cannot always know who is an operator (as
      item 38 says for `send`). An operator gives itself the role first.
    - **SET of `send` or `history` in an encrypted room** gets
      `forbidden` without the owner role, and `encrypted` with it.

47. **Found while building librisala's engine** (12.6, 12.9, 12.10),
    decided with the user on 2026-11-08:
    - **The conversation with yourself** is created by any device that
      cannot see it. One that loses the race gets `stale` and joins.
    - **A confirmed new device gets the recovery key** as well as the
      history keys, so that it backs up what it gets later.
    - **A removal that needs an unreachable key file** waits and retries.
      It is neither applied nor rejected, since a failed fetch says
      nothing about the keys (4.4).

48. **Found while testing M5a end to end** (5.8, 12.6, 12.12), on
    2026-11-08. Item 47's decisions are built and tested, and the last
    point below changed 12.6:
    - librisala's encryption is tested end to end against `risalad`, with
      key files fetched over HTTPS from the test server's key file host.
      That found: the list of an identity's devices failed on every call;
      a message to a new direct conversation queued before WELCOME LIST
      was answered never started it; and an invitation to an encrypted
      room was lost when its commit got `stale`. The device now keeps the
      invitees' KeyPackages until the server accepts the commit.
    - **The CLI finishes encryption work before exiting.** Each command
      waits, for up to 30 seconds, until its accounts' connections have
      nothing in flight, so that KeyPackage uploads, joins and key
      sharing are not cut short; `register` signs in once, so that others
      can add the new device at once. Debug builds take
      `RISALA_TEST_CONNECT` and `RISALA_TEST_KEY_HOST` (with
      `RISALA_TEST_KEY_CA`), so that its tests reach a test server under
      a made-up name.
    - **Reviewers check REPORTENC.** librisala checks the revealed content
      against the copy's `frank` tag (5.8), and shows its text only if it
      matches; the CLI says which.
    - **Key files on demand.** `Account::refresh_devices` fetches a key
      file now, and the CLI's `devices` uses it, so that a key just added,
      such as a new recovery key, is listed.
    - **A direct conversation whose other side has no KeyPackages**
      (12.6), decided with the user on 2026-11-08: the device sends INIT
      but holds its messages until a device of the other participant
      has a leaf, retrying KEYPKG GET from time to time and on
      reconnect, or until that device joins by external commit.
      Messages sent before then could never be read by the other side.
      Built as: the rule holds whenever the group's current epoch has no
      leaf of the other participant, including after all of theirs were
      removed. The entries stay queued, in order, and show as
      `OutboxStatus::Held` once KEYPKG GET on the connection found
      nothing. It is asked again every five minutes
      (`SyncConfig::peer_retry`) and at once on each connection. A device
      of theirs that signs in usually joins first, by external commit,
      since SYNC lists the conversation with head 0. The CLI's `send`
      says the message is held, and `log` shows it.
    - **Key files count as work in flight.** `wait_synced` also waits for
      key files being fetched, so that a CLI command does not end between
      applying a commit and sending what waited for its leaves to be
      confirmed.
    - **The flaky typing test** was another program on the machine
      probing new ports on 127.0.0.1 with HTTP, which the scripted test
      server counted as the client connecting again. It now ignores
      connections that do not start with TLS. The client was right: it
      never reconnected after `disconnect`.

49. **Server follow-ups for M5a** (4.8, 10.4, 12.5, 12.6), on 2026-11-08.
    Implementation choices, no spec change:
    - **Purges reach every conversation.** ADMIN PURGE and UNREGISTER
      `purge=yes` delete ENC events as well as MSG, in direct
      conversations as well as rooms, each with a DELETE event as in 5.4:
      the placeholder loses its payload and `frank`. Rooms come first, in
      name order, then direct conversations in the order they started.
      An identity that unregisters has left its conversations by then, so
      only the other participant gets the DELETE events, as in rooms.
    - **COMMIT fetches key files without the conversation's lock.** It
      checks what it can under the lock and notes the key files it lacks.
      It then lets go of the lock, fetches them, takes the lock again,
      checks the conversation again and that the group is still in the
      commit's epoch, and runs the checks again. Another commit that came
      first gets `stale`, before `unavailable` or a refusal that needs a
      key file, as rule 1 comes first. If membership changed meanwhile
      so that other key files are needed, it goes round again, at most
      three times, then replies `unavailable`. A slow key host no longer
      holds up the conversation.
    - **Key files fetched afresh for COMMIT** close the connections of
      keys they no longer list, and mark those keys' leaves for removal,
      as at AUTH and KEYPKG GET. That is safe now that no conversation's
      lock is held while fetching.
    - **A proposal by reference gets `forbidden`** (rule 4), not
      `invalid`. The server never has the proposal it names, so OpenMLS
      fails the commit as missing a proposal, and risalad answers with
      rule 4's refusal, which says what is wrong. An Update by value
      cannot be made with OpenMLS, and is not valid MLS (`invalid`).
    - **Tests of 12.5's refusals.** A proposal by reference (an Update),
      a PSK proposal by value, and a confirmation tag that differs from
      the GroupInfo's and nothing else, are tested end to end. OpenMLS
      cannot build an external commit that removes another device's
      leaf, or more than one leaf, so rule 4 is a function of its own,
      tested on crafted proposals. Rule 5's limit is a parameter of the
      commit check, tested with a limit of 2 rather than 513 leaves.

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
  It builds each file from its own records, so it can only ever serve
  hosted key files. It also writes the key files to a directory, so
  operators can serve them from their own web server instead.
- **Rooms from the configuration** (M4): ADMIN DROP of a room named in
  `rooms` creates it again at once, empty and with a new id, so the
  configuration stays true.
- **Shared strings** (M6), decided with the user on 2026-11-08: the
  apps' text lives in Fluent files, `l10n/<locale>/*.ftl`, keyed by id
  (`pair-device-title`), with a comment for translators on each message.
  English is the source, and Arabic comes along from the start, as in
  the Apple app now. A generator in the workspace writes each platform's
  own files from them: a String Catalog for Apple, `strings.xml` for
  Android and `.po` for GNOME. CI checks that the generated files match.
  - Messages use only plain text, named variables and plural selectors
    on numbers, which every platform format can express. The generator
    refuses anything else.
  - Text that only one platform shows, such as macOS menus, may stay in
    that app's own files.
  - librisala returns structured values, such as error kinds and event
    types, never English text, so that apps word everything themselves.
  - The Apple app moves from English text keys to the shared ids, through
    generated Swift constants. Its AGENTS.md changes with it in M6.
- **The Apple app** keeps its current deployment targets (iOS 18 and
  macOS 15) for now.
- **risala-pow** (item 42), decided with the user on 2026-11-08:
  - **Clean room.** One agent described HashWX from tevador's documents
    and code, and another wrote the crate from that description alone.
    Neither the description nor tevador's code is in the repository. The
    test seeds are our own; their expected values come from tevador's
    reference build, so the tests still check against it.
  - **Unsafe code.** risala-pow has its own lints, with `unsafe_code` at
    `deny` rather than the workspace's `forbid`, and only `jit/exec.rs`
    allows it. Every other crate still forbids it.
  - **Clients solve with the JIT** on x86-64 and aarch64. iOS never has
    a JIT, since Apple forbids it, and uses the interpreter.
  - **Servers verify with the interpreter.** Strict W^X costs two
    `mprotect` calls per function, and those stall every thread of the
    process: a JIT check takes 10.9 µs on one thread but 73 µs each
    with 16 threads checking, while the interpreter takes about 25 µs at
    any thread count. Memory protection keys would avoid the stall but
    weaken W^X, so we did not use them.
  - **No two-nonce JIT.** Running two nonces interleaved on one core was
    23–32% slower on x86-64. A hash is held back by mispredicted loop
    exits, which stall both nonces at once, and hyperthreading already
    gives 1.44× per core. Solvers use every hardware thread instead.

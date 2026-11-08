# Implementation plan

The high-level plan for building risala: a Rust server, a Rust client
library (librisala), and native apps for GNOME, Apple platforms and
Android. The spec ([`spec/`](spec/)) is the source of truth for the
protocol. This file covers how we build it.

## 1. Principles

- **The spec comes first.** If the code and the spec disagree, fix one of
  them on purpose. Don't let them drift. Spec changes are made in
  the spec (`spec/`) first.
- **One protocol implementation.** Parsing, grammar and signing live in
  a single crate (`risala-proto`). The server and librisala both use it.
- **Apps are thin.** Everything apps share lives in librisala:
  connections, trust on first use, keys, sign-in, sync, the history
  cache, timelines, rooms, moderation and admin. An app only draws the
  UI and supplies a few platform services (secure key storage, push
  tokens, notifications).
- **Zero trust in the server** (2026-11-08). Devices never take the
  server's word for anything they show or act on in an encrypted
  conversation, or for whose keys are whose. Whatever the server can
  still do, it can only do visibly, and Section 14 lists it.
- **Tested from transcripts.** The server is tested with scripted line
  transcripts. Every example in the spec becomes a test. Using the
  protocol by hand with `openssl s_client` is no longer a goal: connecting
  will need a client that solves proof of work (item 42).

## 2. Repository layout

```
risala/
├── spec/                  the protocol (CC BY 4.0), one file per section
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
- **Packages:** the flake exports the packages, an overlay and a NixOS
  module for `risalad`. For Debian, Ubuntu and Fedora we host our own
  apt and dnf repositories (see Decisions), built in CI with a pinned
  toolchain inside each release's container, by `cargo-deb` and
  `cargo-generate-rpm`, and published as signed static files.
- **CI:** `nix flake check` (fmt, clippy, rustdoc, tests), Kani,
  risala-pow's JIT against its interpreter on x86-64, ARM and macOS
  runners, and a smoke test that starts `risalad` and talks to it through
  `openssl s_client`. Once connecting needs proof of work (item 42), the
  smoke test talks through `risala-cli` instead. A separate Verification
  workflow, on pushes to main and nightly, collects test coverage, the
  fuzz corpora's coverage, Kani and TLC results for the site's
  verification page (`verification/`); the nightly run also fuzzes each
  target for 10 minutes.

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
| M5b | Zero-trust redesign | The spec is rewritten as draft-03 in `spec/` for items 51-58, the code follows, and a fresh security review of the spec finds nothing above Low (item 59 has the order) |
| M6 | FFI, shared theme and strings | `librisala-ffi` with UniFFI for Swift and Kotlin, platform key stores, one source for the theme's colors and metrics, and the shared strings in `l10n/`. The Apple app and an Android shell sign in, sync and show a timeline through the bindings |
| M6a | Proof of work | The puzzle is in the spec (`spec/`, item 42). `risalad` hands out puzzles and checks solutions with the interpreter; librisala solves them with the JIT where it can, on every hardware thread. By default a client cannot become a guest or register without solving one. The `openssl` smoke test moves to `risala-cli`. The `risala-pow` crate itself is done (3.2) |
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
Settle them in the spec (`spec/`) before or during the matching
milestone.

Settled (now in the spec, `spec/`):

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
      - The MLS tables are schema version 13 of the cache. MLS operations
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

50. **Found by the review of M5a** (4.8, 6.2, 6.3, 12.4, 12.6, 12.9,
    12.10), decided with the user on 2026-11-08:
    - **Joining a room checks its members.** Every leaf must belong to a
      member or an invitee, by the room's events, also when a device
      joins again after it could not process a commit. Otherwise a
      server could make a device rejoin a group that holds an outsider.
    - **Keys only to and from confirmed devices.** No KEY or RECOVERY
      lines in the conversation with yourself while a leaf of your
      identity is unconfirmed or declined, since every leaf there reads
      them. Declining a device removes its leaves. KEY and RECOVERY
      lines count only from confirmed devices, a recovery key only while
      the key file lists its signing key, and replacing a recovery key
      the device already holds asks the user.
    - **Recovery order.** Add the new device's key, sign in with it and
      join everything, and only then remove the lost keys. Removing them
      first loses the encrypted rooms. A client that does not hold the
      old recovery key offers to remove every other `recovery` line.
    - **The recovery key never joins a group**: no KEYPKG ADD, INIT,
      COMMIT or ENC on its connection.
    - **A removal waits at most 24 hours** for a key file that cannot be
      fetched, then is applied with a warning (changes item 47's
      decision), so that a key host that stays down cannot hold up a
      conversation.
    - **A returning identity** that the server does not host is a
      participant of its direct conversations again, which belong to the
      pair. Its devices join by external commit, without the history.
    - **Server limits now**: a KeyPackage size limit (at least 16 KiB;
      risalad 64 KiB, `too-long`), and BACKUP ADD only for conversations
      the identity is or was in, up to the group's current epoch. Byte
      budgets for ENC and COMMIT stay for M10's rate limits.
    - **Keys at rest under hardware** (item 45) comes right after M5a,
      before M6. Until then the CLI keeps its secrets in files, a known
      gap.

    Implementation only: devices refuse X-Wing public keys that are not
    1216 bytes before encrypting to them, since libcrux-kem 0.0.9 panics
    on short ones (RUSTSEC-2026-0331), and KEYPKG ADD refuses
    KeyPackages that carry such keys. Move to libcrux-kem 0.0.10 or later
    once hpke-rs-libcrux allows it. The provider never signs with ML-DSA
    itself; only the device signer does.

    Built in risalad as follows, with no spec change:
    - **Removed keys.** A key file fetched afresh takes the keys it lists
      off the list of removed keys, as KEY ADD and REGISTER do for hosted
      identities; otherwise a key that left and came back held up ENC for
      good in a direct conversation. UNREGISTER marks leaves only for
      hosted identities: another identity's key file still lists its keys,
      and its room leaves go because it is no longer a member.
    - **Direct conversations' participants** are the identities of the
      pair that the server knows (it has a row for them). The start
      counts only those; a sign-in that makes an identity known again puts
      it back in its direct conversations before AUTH's `OK`; and every
      command on a direct conversation checks that the sender is a
      participant, in one place. A hosted identity that unregistered gets
      no registry entry at start.
    - **Limits.** `limits.max_key_package_bytes`, 64 KiB by default, at
      least 16 KiB, measured decoded. BACKUP ADD counts an identity as
      having been in a room if it is a member or invited, has a leaf or
      blobs there, or the room's events show it joined or was invited.
      Events that expired under retention no longer show it, a known gap;
      a dropped room, or one without a group, takes no blobs.
    - **HPKE keys.** INIT and COMMIT check every leaf's and parent node's
      key in the tree (the parent's read from its encoding, as OpenMLS
      keeps it private), `external_pub`, and the init and encryption keys
      of added KeyPackages. A COMMIT's Welcome must be addressed to
      exactly the KeyPackage refs it adds.
    - **Smaller fixes.** KEY DEL and ADMIN DELKEY forget the device in the
      transaction that removes the key. Guests keep the normal line
      limits once signed in.

    How librisala builds these (implementation only):
    - **Keys belong to an identity.** The cache keeps device keys by
      identity and key id (cache version 16), and every key is checked
      again after the upgrade. A key counts as listed only in its own
      identity's key file.
    - **Joining a room.** INVITE events are kept with the members (version
      16). A leaf passes if its identity is a member or invitee now, or its
      membership changed after the seq the device joins at, since a later
      commit, which the device checks, then removes it. An invitee's
      Welcome waits on the server until the room is joined and caught up,
      as only then are its events here; a room is joined by external
      commit only once caught up too.
    - **Commits.** The checks of 12.6 run on the commit as the group's
      public part stages it, before MLS processes it with the secrets. A
      commit that skips an epoch makes the group broken only if events
      between are missing (expired); otherwise the server left a commit
      out, and the group is rejected (the narrowest reading of "do not
      rejoin"). A rejected group stays rejected when the conversation is
      discarded for a new id, refuses Welcomes and INIT, and only
      `Conversation::reset_encryption`, on the user's word, forgets it.
    - **Every leaf of a group joined by external commit** gets the key
      check, as a Welcome's do.
    - **Own devices.** "Already there when the device joined" is the
      devices of the conversation with yourself the first time the device
      notes its leaves, right after it joins. Declining a device makes
      each conversation's duties remove its leaves; `confirm_device`
      returns its key file line (`DeclinedDevice`) to offer removing it.
      A recovery key to send, and one another device offered, are kept in
      the cache (version 18). "The key file lists it now" is the last
      fetch, which must be newer than the offer; otherwise the key file is
      fetched first. The user's answer is
      `Account::accept_recovery_key` (CLI `recovery accept`).
    - **24 hours.** The commit that waits, and since when, is kept in the
      cache (version 19), by the engine's clock. Key files a commit waits
      for are asked for again every five minutes on the same connection.
    - **The recovery key's connection.** `SyncEngine::issue`, through which
      every command goes, drops KEYPKG ADD, INIT, COMMIT and ENC on it;
      `recover_identity` uses a connection type that sends only KEY.
    - **A new recovery key in two steps.** `create_recovery_key` only adds
      the new key and returns it; the app shows it, then
      `finish_recovery_key` keeps it, backs up every history key under it,
      and only then sends BACKUP DEL, backs up again and removes the
      previous recovery key. BACKUP DEL cannot spare one key id's blobs,
      hence backing up twice. The other devices get the new key last, so
      the BACKUP DEL does not take theirs.
    - **Recovery.** `recover_identity` waits for the new device to join
      every encrypted conversation SYNC lists (up to five times for the
      connection to settle), restores the backups, then removes the lost
      keys, and keeps them if a conversation could not be joined
      (`Recovered::not_joined`). The CLI's `recover` then makes a new
      recovery key. The end-to-end test cannot force the old order to
      fail: another member removes the old leaf only when it next fetches
      the key file.
    - **Edits and reactions** count toward a verified message only if
      they are verified too.

51. **Zero trust in the server** (1.1, 14), decided with the user on
    2026-11-08 after a security review of the spec. Replaces parts of
    items 19 and 22, as the items below say:
    - Devices never take the server's word for anything they show or act
      on, or for whose keys are whose. Whatever the server can still do,
      it can only do visibly, and Section 14 lists it.
    - Every conversation is end-to-end encrypted, public rooms too. There
      are no plaintext rooms.
    - The server learns as little metadata as v1 can manage: not who
      sends, and not who is in a private conversation.
    - Messages are deniable: a leaked message does not prove to anyone
      else who wrote it.
    - At least Signal's protections: per-message forward secrecy,
      post-compromise security, post-quantum keys, sealed sending and key
      transparency.
    - Rooms of thousands of members.
    - Operators cannot reset identities.

52. **MLS for everything, with no history on the server** (2.3, 5, 7,
    12, 15), decided with the user on 2026-11-08:
    - **MLS for every conversation.** A Triple Ratchet (Signal's Double
      Ratchet with its post-quantum SPQR) was weighed and dropped:
      libsignal and SPQR are AGPL-3.0 and not on crates.io, it would be a
      second protocol, and it does not reach thousands of members.
    - **Per-message keys.** Messages are MLS application messages, with
      a key per message that is deleted after use. History keys, KEY
      lines and key backups (items 19 and 22) go.
    - **No history on the server.** It keeps encrypted messages only
      until devices fetch them, within retention. Newcomers to a room see
      only what is sent after they join.
    - **History moves between your own devices**: by transfer at
      pairing, end to end, and optionally through an encrypted backup of
      message history under the recovery key, kept on the server.
    - **Large MLS objects** (trees, Welcomes, big commits) travel as
      content-addressed blobs over HTTPS. Lines carry their hashes.
    - **The weekly fresh-leaf commit** is a MUST.
    - **Cipher suite `0x0020`**, the value
      draft-ietf-mls-pq-ciphersuites-07 (2026-11-01) requests for X-Wing
      (HPKE KEM `0x647a`), HKDF-SHA384, ChaCha20-Poly1305, SHA-384 and
      ML-DSA-44. `0x0052` was OpenMLS's placeholder, and openmls_traits
      0.6.0, the newest release, still uses it, so `crates/openmls-traits`
      patches that one value until a release has `0x0020`. Builds check
      the suite's value and algorithms, and devices reject MLS objects
      with any other suite or version. Written in the spec (`spec/`) and
      built.

53. **Deniability** (5.8, 12), decided with the user on 2026-11-08:
    - **Per-group leaf keys.** A device signs in MLS with a fresh key for
      each group. Device and identity keys never sign anything that names
      a message or a leaf key: the device key signs sign-ins, KeyPackage
      device bindings and period-key certificates (item 60). This
      replaces item 19's "the same key signs in and signs in MLS".
    - **Direct conversations and private rooms up to about 256 members.**
      Each pair of devices confirms the other's leaf key with a
      post-quantum KEM challenge and a MAC, at the cost of one extra
      flight.
    - **Larger rooms** use epochal signatures (Hülsing and Weber, S&P
      2021): daily keys whose private halves are published after the day.
      Messages are deniable once the key is out. The construction needs
      an outside review.
    - **Reports.** Room moderators, who are members, can trust who wrote
      a reported message. Operators get its content, proven by franking,
      but not provable authorship. The reporter is told exactly who will
      see it, and may add up to 10 earlier messages as franked context,
      with the number left out between them.

54. **Metadata** (4, 9, 12, 14), decided with the user on 2026-11-08:
    - **Hidden membership.** Direct conversations and private rooms
      encrypt their commits, so the server keeps no member lists. Devices
      check commits themselves, and the first valid commit of an epoch
      wins.
    - **Public rooms show their membership**, so the server can check
      their commits, hold the tree and serve light clients
      (draft-ietf-mls-partial). Anyone can join them anyway.
    - **Sealed sending.** Devices post over connections that do not sign
      in, proving membership with a per-epoch send token from the group,
      and carry a per-member pseudonym that the server can rate-limit or
      mute without knowing who it is.
    - **Push** goes through mailboxes: each device subscribes to each
      conversation's mailbox with a tag that cannot be linked to its
      identity. Bodies are encrypted to the device (Web Push encryption,
      RFC 8291).
    - **Spam.** Proof of work to connect anonymously and to join, limits
      per pseudonym, and devices enforce room rules from the group's
      moderators.
    - **Sizes.** Private rooms up to 1,000 members (about 3,000
      devices); public rooms up to 10,000, with light clients. Revisit
      once ML-DSA and X-Wing are measured on phones.
    - **No Tor in v1.** Section 14 says the server sees IP addresses and
      timing.

55. **Rooms** (5, 6, 8, 12), decided with the user on 2026-11-08:
    - **No INVITE command.** Owners and moderators invite with a commit
      that adds the invitee's devices.
    - **Roles live in the group.** The owner and moderator lists are in
      the conversation extension, changed only by an owner's commit.
      Devices act on the group, not on KICK, PART or ROLE events, and
      PART is a commit by the leaving device.
    - **Gaps and deletes.** Each message carries a counter per sending
      device and the id of that device's previous message, so devices
      notice messages they did not get. Deleting is a signed, encrypted
      instruction from the author or a moderator.
    - **What devices show comes from inside the encryption**: the
      sender's timestamp (large gaps from the server's time are
      flagged), display names from a signed profile in the group, topics
      from moderators, and typing and read markers as encrypted
      messages. Presence stays with the server, and Section 14 says so.
    - **Guests** join public rooms only, as members with throwaway keys,
      shown as unverified, with proof of work to join.

56. **Identity and keys** (4.4-4.7, 10.5, 12.12, 14), decided with the
    user on 2026-11-08:
    - **A master key** signs a device-signing key that every device
      holds. The master key is the recovery key's signing key (items 40
      and 43), and every identity gets a recovery key when it is made.
    - **The key file is a chain of records**: a new device-signing key,
      a device added or removed. Each is signed and holds the hash of the
      one before. New contacts read it from the first record.
    - **A witnessed log.** Every server keeps a Merkle log of the records
      of the identities it hosts, and a self-hosted identity names the
      log it uses. Clients accept records only with an inclusion proof
      and a checkpoint cosigned by k of n public witnesses, and check that
      checkpoints are consistent. It uses the C2SP formats
      (tlog-checkpoint, signed-note, tlog-witness, tlog-tiles). Witnesses
      and the log sign with ML-DSA-44 (signed-note type `0x06`); Ed25519
      cosignatures are not accepted (item 60).
    - **Own devices watch the log**, and alert every device of the
      identity to a record they do not know. **A fork** (two records with
      the same parent, or checkpoints that do not agree) stops sending to
      that identity until the user resolves it.
    - **Pairing.** The new device's QR code carries a one-time secret
      that never reaches the server. The device that scans it sends the
      master public key and the device-signing key, encrypted and
      authenticated with that secret.
    - **Hosted identities upload the whole signed key file.** The server
      checks the signature and that the file extends what it has.
    - **Removing a device** makes a new device-signing key, which needs
      the recovery key.
    - **No operator resets.** ADMIN ADDKEY goes. The recovery key is the
      only way back after losing every device.
    - **One safety number per identity**, over the master key and the uid
      (`risala-fp-1`), as digits and a QR code. A new master key clears
      "verified" and stops sending until the user acknowledges it. A new
      device under the same master key is a notice.
    - **The seed is the private key.** Imports derive the key from the
      seed and reject a file whose expanded key does not match it.
      Written in the spec (`spec/`, 4.3).

    Open: the record and log formats, the checkpoint origins, the
    witness list and k, how a self-hosted key file names its log, and how
    devices fetch proofs.

57. **Files** (5.6, 12.11), decided with the user on 2026-11-08:
    - **`file-hash`**: the message carries the SHA-384 hash of the exact
      bytes uploaded, so a swapped file fails, and so does framing
      someone through a report. Reviewers' clients fetch a reported file
      only when asked.
    - **Chunks.** Files are encrypted in 64 KiB chunks with
      ChaCha20-Poly1305, a counter nonce and a last-chunk flag. Devices
      check `file-hash` first, then decrypt chunk by chunk.
    - **Padding.** Files are padded with Padmé before encryption, so the
      server sees only the padded size.

    Open: where the real size goes.

58. **Hygiene** (2.2, 4.2, 4.5, 9, 12, 14, 15), decided with the user
    on 2026-11-08:
    - Clients SHOULD sign with hedged ML-DSA.
    - Implementations MUST run the X-Wing and FIPS 203 key checks before
      encrypting to a key.
    - Servers store only hashes of bearer secrets (guest tokens, upload
      and push URLs) and compare them in constant time. Franking tags are
      compared in constant time too, and never skipped, since they make
      messages key-committing.
    - **Everything is versioned**: labels carry `risala/1`, formats a
      version byte, devices reject unknown versions, and clients accept
      at most the current and the previous version, upgrading in order
      (read, write, re-encrypt, then turn the old one off).
    - **Server pins.** A pinned server whose certificate changes to
      another that a CA vouches for gets a one-time notice. Users can turn
      on a strict pin, after which any change needs their approval.

59. **Order of the work (M5b)**, 2026-11-08:
    1. **First sweep.** This set of items, cipher suite `0x0020` with the
       openmls_traits patch, and the spec changes that stand on their own
       today. The rest of the spec still describes M5a's design.
    2. **The redesign as draft-03**, one area at a time: identity and the
       key log (56); MLS application messages, transfer and backup (52);
       deniability (53); metadata, sealed sending and push (54); rooms
       and guests (55); files (57); hygiene and versions (58); then
       Section 14 and a threat model.
    3. **Measure** ML-DSA and X-Wing on phones before fixing the caps,
       and have the epochal-signature construction reviewed.
    4. **Code follows the spec**, starting with `risala-mls`.

    How much of M5a's code carries over, decided with the user on
    2026-11-08: the protocol layers are rewritten to draft-03 (the line
    types, the server's core and store, librisala's engine, store and
    API), keeping the crypto, OpenMLS's storage, the network code,
    `risala-keyfetch` and `risala-pow`. The schemas start again at
    version 1, with no migrations from M5a. The working plan is
    [docs/plans/M5b.md](docs/plans/M5b.md).

60. **Choices made while writing draft-03, to confirm with the user**
    (2026-11-08). Draft-03 is in `spec/`, one file per section. These
    fill in what items 51-58 left open; the questions at the end would
    change a decision rather than fill one in, and are not in the spec
    as decided.
    - **Connections** (4.1, 4.2): three kinds, signed in (AUTH,
      REGISTER), anonymous (a new `ANON` command) and guest. Account
      things go on the signed-in one; posting, following and fetching
      only on anonymous or guest ones.
    - **Proof of work** (4.1): one placeholder paragraph naming ANON,
      GUEST, REGISTER and joining public rooms. The rest is item 42's.
    - **Mailboxes** (3.5, 5.2): a box is 16 random bytes in lower-case
      base32 (26 characters), picked by the client at CREATE. CREATE has
      a private form (anonymous) and a public-room form (signed in, so
      room creation is limited per identity).
    - **One POST command** for messages, commits and proposals (5.2).
      The server reads group id, epoch, content type and authenticated
      data from the MLS framing. Posts are `@seq;t POST <box> <message>`,
      with no `from`.
    - **RisalaAAD** in MLS `authenticated_data` (12.9): version,
      pseudonym (16 bytes), `frank` (48 bytes on application messages)
      and `next_token_hash` (48 bytes on commits).
    - **Send tokens** (7.2): MLS-Exporter("risala/1 send", "", 32). The
      server keeps SHA-384 hashes in a set per epoch, for the newest 16
      epochs. Each commit adds its next hash. Outside public rooms it
      accepts every commit with a valid token, and a committer fetches
      after its `OK` to see whether it won. Public-room joins use `-`.
    - **Pseudonyms** (7.3): 16 random bytes per leaf, picked by its
      device, in the RisalaAAD. Devices pin the first one per leaf.
      `MUTE`/`UNMUTE` (24 hours by default) for a public room's owners
      and moderators on a signed-in connection, checked against the
      extension; `ADMIN MUTE` for any mailbox. Private rooms have no
      server mute, since the server knows no roles there.
    - **Delivery** (7.1): FOLLOW, UNFOLLOW and FETCH (`after` only)
      replace SYNC, HISTORY and RELATED. At least 1,000 followed
      mailboxes per connection. A box is enough to read ciphertext; no
      token is needed to read. `live=yes` posts (typing) are neither kept
      nor pushed. `cid` is per mailbox, for 24 hours.
    - **Retention** (7.5): at least 7 days, SHOULD be 30, no `forever`,
      and no per-room retention setting.
    - **Line limits** (2.3): long lines shrink from 8 MiB to 1 MiB, and
      anything larger is a blob. REGISTER may be 64 KiB before sign-in.
    - **Key file** (4.4): text, first line `risala-keys/1`, one
      `log <vkey> <url>` line, then `<index> <record>` lines (`-` until
      logged). Records are `master`, `signing` (new device-signing key,
      plus removed device ids) and `device` (ML-DSA-44 device key, X-Wing
      attestation key, label). Each has version, uid, `previous`
      (SHA-384 of the previous Record) and a time in ms. Device id =
      SHA-384 of the device key. Fetches may read 2 MiB (was 256 KiB).
    - **RisalaSign** (4.3): MLS's SignWithLabel shape with a `risala/1 `
      prefix; labels `record`, `keypackage`, `period` and `attest`.
    - **Key log** (4.5): origin `<host>/risala-log/<n>`; entries are
      encoded Records; tlog-tiles over HTTPS. C2SP assigns ML-DSA-44
      only to timestamped cosignatures (signed-note type `0x06`), so the
      log signs its checkpoints that way, under its origin's name.
      Witnesses may cosign with Ed25519 (`0x04`) or ML-DSA-44 (`0x06`).
      New records are in a witnessed checkpoint within an hour, and
      there is at least one checkpoint a day.
    - **Witness policy** (4.5): a list each client holds; the default is
      at least three independent witnesses with k = 2, shipped with the
      apps and editable.
    - **Proofs** (4.5): devices compute them from the log's tiles. The
      server has no proof command.
    - **Self-hosted identities** (4.7): the key file names a log;
      `KEYS PUT` to that server returns `RECORD <index> <hash>` lines,
      and the user adds the indices. A server may refuse to log outside
      identities.
    - **KEYS PUT** (4.7) takes the whole chain and needs no sign-in,
      since the records are signed; recovery uses this.
      `REGISTER <name> <keyfile> <signature>`.
    - **Forks and pins** (4.5): two records with the same `previous`,
      two first `master` records, or inconsistent witnessed checkpoints.
      A log fork marks every identity in it. A device pins each
      identity's log as well as its master key; a new log counts as a new
      master key.
    - **Watching** (4.5): daily. Devices announce their own records with
      `RECORD` in the conversation with themselves, and warn the others
      with `ALERT`.
    - **Master key derivation** (4.8): the HKDF info changes from
      `risala identity ` (item 43) to `risala/1 identity `, for
      versioned labels. AUTH keeps `risala-auth-1`, so Appendix B's
      vector stays valid.
    - **Pairing** (4.8): the QR text is `RISALA-PAIR:` plus base32 of
      PairingCode (version, host, 32-byte secret, SHA-384 of the
      NewDevice). The relay is `PAIR PUT/GET`, with ids and keys derived
      by HKDF; data lasts 10 minutes. The existing device writes the new
      device's record. The IdentityBundle carries the master public key,
      the device-signing seed, the backup key and the transfer.
    - **Removing a device** (4.8) also moves backups to the next
      generation. The new device-signing key and backup key travel as
      `SIGNINGKEY` and `BACKUPKEY` lines in the conversation with
      yourself.
    - **Recovery** (4.8, 12.7): a member's device adds a recovered
      identity's new device if that identity's own devices have not,
      after a random wait of up to an hour. A commit that removes an
      identity's removed devices also adds its current ones.
    - **Removed commands**: `UNREGISTER purge=yes`, `ADMIN KEYS`,
      `ADDKEY`, `DELKEY` and `PURGE`. Hosted key files answer 410 after
      unregistering, and their records stay in the log. `ADMIN DROP`
      takes a room or a box. `ADMIN SET anon` is new.
    - **Credential** (12.3): basic, holding a RisalaIdentity (version,
      uid, device id). Guests have an empty device id.
    - **Device binding** (12.3), extension `0xF2A2`: the device key signs
      the uid and the KeyPackage's init and encryption keys. It goes in
      KeyPackages, and in the leaf nodes of external commits.
    - **Profile** (12.3, 8.2), leaf extension `0xF2A3`: display name, and
      `updated` in ms. Names change by the member's own commit. NAME is
      gone.
    - **Conversation extension** (12.4): version, kind (direct, private
      room, public room), host, box, name, topic, confirm, guests, send,
      owners, mods and bans. The topic lives here and changes by commit
      (owners and moderators); LIST shows it as read by the server.
      Private room names are free text of up to 128 bytes, not unique.
    - **Leaf caps** (6.1): 4,096 leaves in private rooms and 32,768 in
      public rooms, alongside the 1,000 and 10,000 members.
    - **Commits** (12.6) always have a path. Proposals are by value,
      except SelfRemove and public-room external Add proposals, which go
      by reference.
    - **PART** (6.1): a commit that removes the identity's other leaves,
      then a SelfRemove (draft-ietf-mls-extensions) for the device's own
      leaf, which another member commits. See the questions below.
    - **Public rooms** (6.1, 12.6): full clients join by external commit,
      and light clients by external Add proposal. Full clients batch
      pending proposals after a random wait of up to 10 minutes. Public
      commits carry `groupinfo=`.
    - **Light clients** (12.6), from draft-ietf-mls-partial-02:
      `FETCH … leaf=<n>` returns AnnotatedCommits and `WELCOME GET …
      light=yes` an AnnotatedWelcome. They rejoin weekly instead of
      committing, and use a separate connection for fetching with
      `leaf`.
    - **Guests** (4.2, 6.1): a server `GONE <box> <uid>` line when a
      session ends, and any member may remove a guest leaf.
    - **Stale leaves** (12.7): a member may remove a leaf whose profile
      `updated` is more than 35 days older than its own, and re-add the
      device from a new KeyPackage. A device that fell behind retention
      gets back this way.
    - **Last-resort KeyPackage** (12.5): a device that joins with one
      commits a new signature key before it sends.
    - **Welcomes** (12.8): `WELCOME PUT <ref>` on any connection, only
      for refs handed out by KEYPKG GET or in external proposals. A
      random delay of up to a minute after the commit. `WELCOME GET`
      for joins by proposal. Private groups' Welcomes carry the tree.
      `KEYPKG GET` works on any connection.
    - **RisalaMessage** (12.9): version, message_id, counter, previous,
      time (ms), frank_key and content. Padding uses MLS's own, to
      multiples of 256 bytes. Live messages have counter 0. The frank
      still covers `content` only, but now travels in the RisalaAAD
      rather than a tag. Times more than 10 minutes from the server's are
      flagged. Past epochs' secrets are kept for "a few epochs".
    - **Content lines** (12.9): TEXT, DELETE, TYPING, REPORT,
      CHALLENGE/ANSWER, ATTEST/REVEAL, READ, BLOCK/UNBLOCK, RECORD/ALERT
      and SIGNINGKEY/BACKUPKEY. Messages are referenced by `message_id`
      only. Moderators may delete anyone's messages, as before.
    - **Pairwise confirmation** (12.10): `CHALLENGE <leaf> <ct>` and
      `ANSWER <leaf> <mac>`, with an HMAC-SHA-384 under
      HKDF("risala/1 confirm") of the X-Wing secret, over the group id,
      the hash of `ct` and both leaf keys' hashes. Newcomers challenge at
      once; answers come within a minute, in the next message when
      possible.
    - **Threshold** (6.2, 12.10): pairwise up to 256 members. A private
      room moves to epochal by an owner's commit at or before 256, one
      way only. Public rooms are always epochal.
    - **Epochal** (12.10): a period is a UTC day. The device key
      certifies a fresh period key (PeriodCert). The leaf signature key
      is rotated by a commit before the first message of each period.
      ATTEST is sent in that message, and REVEAL after the period plus a
      grace hour, within a day. Attestations are accepted only until the
      grace hour ends, by the device's own clock. There is no
      attestation chain, since there are no late readers.
    - **Typing** (8.1): not sent in rooms of more than 100 members.
    - **Presence** (8.3): `PRESENCE ON|OFF` (ON by default), a
      per-connection `WATCH` list of at least 1,000 uids, WHOIS, and
      MEMBERS for public rooms only. USER and MEMBER lose display names.
    - **Blocks** (5.7): kept on devices, synced with BLOCK/UNBLOCK in the
      conversation with yourself. Devices ignore Welcomes to groups that
      hold someone blocked.
    - **Reports** (5.8): to a room's moderators as REPORT lines in a
      direct conversation with each owner and moderator. To operators as
      `REPORT <box> <report>`, a RisalaReport with seq, frank key and
      content for the target and up to 10 context posts, the claimed
      author and a reason, on any connection. REPORTENC and
      `REPORTS <room>` go; only operators review on the server.
    - **Files** (5.6, 12.11): `UPLOAD <box> <token> <size>` adds a `del`
      URL and drops type and name. The real size goes in a `file-size`
      tag (and stays inside the plain text), which settles item 57's open
      question. Files expire with retention, counted from upload.
    - **Blobs** (12.12): `BLOB <hash> <size> [box= token=]`. A blob-ref is
      `sha384:` plus 96 hex digits, fetched from INFO's `blobs=` prefix.
      Servers allow at least 256 MiB, and keep a public room's current
      tree.
    - **History transfer** (12.13): a HistoryArchive (per conversation,
      messages with sender, verified flag, both times, seq and content),
      encrypted with the 12.11 file format and stored as a blob, with a
      TransferRef in the IdentityBundle. `more` chains large ones.
    - **Backups** (12.13): one current backup per identity, at most
      daily, as a HistoryArchive blob whose key is wrapped under the
      backup key of generation g (HKDF info `risala/1 backup <uid> <g>`).
      `BACKUP PUT/GET/DEL`. The blob outlives retention.
    - **Push** (9): `PUSH ADD <url> <tag> <key> <auth> [box=]`. Mailbox
      subscriptions go on anonymous connections and account ones
      (Welcomes) on signed-in ones, with a different URL for each.
      Bodies are RFC 8291 `aes128gcm`, holding `NOTIFY <tag> <reason>`
      with the reasons `message` and `welcome`. `FOLLOW quiet=<tag>`
      holds pushes back. TTL is a day. Unread counts move to devices.
    - **Safety numbers** (12.14): SHA-384 over the label `risala-fp-1`,
      the uid and the master key, shown as 40 digits (eight 5-byte
      chunks mod 100000) and as QR text `RISALA-FP:` plus base32.
    - **New master key** (12.14): it stops sending in direct
      conversations and private rooms, and only warns in public rooms.
    - **INFO** (8.5) gains `anon`, `log` and `blobs`, and loses
      `retention=forever`. The URI scheme drops `/<seq>` and covers
      public rooms only.
    - **Operators** have no rights in rooms. `ADMIN ROOMS` lists public
      rooms only. Address bans now cover anonymous connections too.
    - **Appendix A** is cut to checking a server and its fingerprint,
      and Appendix D is now the threat model (the IRC appendix is gone).

    Confirmed with the user on 2026-11-08, as written above, except for
    the answers below to the questions the draft left open:

    - **The device key** signs sign-ins, KeyPackage device bindings and
      period-key certificates, never a message or a leaf key. This is
      what item 53's "only signs in" means.
    - **Epochal rooms rotate the leaf key every period**, so every active
      sender commits once a day in each large room.
    - **SelfRemove travels as a PrivateMessage** outside public rooms, a
      deviation from draft-ietf-mls-extensions that keeps membership
      hidden.
    - **Pairwise confirmation covers senders only**: a device confirms a
      leaf the first time that leaf sends, not when it joins. The
      threshold stays at 256 members.
    - **Witnesses must cosign with ML-DSA-44** (signed-note type `0x06`).
      Ed25519 cosignatures are not accepted, which replaces that part of
      item 56. The log signs its checkpoints with type `0x06` too.
    - **Presence is off by default.**
    - **Forks and new master keys** behave as written: a fork stops
      sending in every conversation with that identity, rooms included;
      a new master key stops sending outside public rooms and warns in
      them.
    - **A device that falls behind retention** gets the missed history
      from the identity's other devices, as at pairing, besides the
      35-day leaf replacement.
    - **No 24-hour wait for key files.** A device applies a removal
      without holding it back and flags the key as unconfirmed, so it
      cannot fork from the group. This replaces item 50's wait.
    - **Guests may open a direct conversation with a room's owners and
      moderators**, only to report, with their throwaway key.
    - **`last_resort` is the KeyPackage component `0x0004`**
      (draft-ietf-mls-extensions-11), not the extension `0x000A`.
      OpenMLS still uses the extension, so it needs a patch like the
      cipher suite's.
    - Kept as written: retention of at least 7 days (30 suggested), with
      no per-room setting; operators with no rights inside rooms; no
      typing above 100 members; 1 MiB lines, with blobs for anything
      larger.

    Notes, not decisions: draft-ietf-mls-partial-02 expires on
    2026-11-08, so the light-client text may change with its next
    revision; and item 42's proof-of-work text must also cover ANON and
    joining public rooms.

61. **What risala is called, and where the spec lives**, decided with the
    user on 2026-11-08:
    - risala is "a modern chat protocol". It is no longer described as
      line-based or IRC-like, and the spec's appendix of differences from
      IRC is gone. Lines remain the wire framing (2.3).
    - The spec is a folder, `spec/`: `spec/README.md` holds the title,
      abstract, conventions and contents, and each section and appendix
      is a file of its own, with section numbers running across them.
      The site stitches them into one page and serves the same text as
      one file at `/spec.md`. The spec tests read the whole folder.

62. **Choices made during M5b's run, to confirm with the user**
    (2026-11-08 onwards). M5b ran overnight while the user was away, so
    where the spec was silent or could not be built as written, the
    agents chose the option that trusts the server least and is easiest
    to change, and listed it here. None of these is settled until the
    user confirms it.

    The full findings, with every option the reviewers gave, are kept
    outside the repository in `/home/humaid/repos/risala-m5b/`: the
    reviews (`review-*.md`), the fixers' and coders' choices
    (`choices-*.md`), the code reviews (`code-review-*.md`), the gaps
    the coders found in the spec (`spec-problems.md`) and the run's
    notes (`STATE.md`). Draft-03 had three reviews: round 1 by area,
    round 2 for security and consistency, round 3 a final one. The codes
    in parentheses (S-H6, D-M3 and so on) are the reviewers' finding
    numbers; C1 to C5, SV0 to SV6, M1 to M4 and the like name the coding
    task that made a choice, and R2 the fixes after the code reviews
    (whose findings are LR-, SR- and so on).

    **Choices that change something the user decided.** Each of these
    goes back on, or narrows, an earlier item. They are in the spec now,
    and each needs a yes or a no.

    - **Forks no longer stop rooms** (4.4, 4.5, 12.7, 12.14; round 2,
      S-H6). This changes item 60's answer "a fork stops sending in
      every conversation with that identity, rooms included", and item
      56's fork bullet. Why: a fork needs only the identity's own keys,
      so anyone could fork their own chain, join every public room and
      freeze them all, and any member could freeze a private room the
      same way, or by taking its key file down. Now, for an identity
      that is forked or whose keys are missing:
      - in a direct conversation, sending stops, as before;
      - in rooms, its leaves are shown as unverified, what they send is
        hidden, and devices keep sending;
      - in rooms that are not public, its leaves are also removed at
        once, and come back once its keys are back and no fork is known
        (but see R-M1 below: they do not come back by themselves);
      - in public rooms, an owner's or moderator's device SHOULD ban a
        forked identity, and MAY kick one whose keys are missing.
    - **A missing key file now takes an identity out of private rooms**
      (same fix). This partly reverses round 1's choice (I-M11) that
      missing keys only stop sending and remove nothing. Devices are
      still never removed *by record* for it, but whoever hosts a key
      file can push its identity out of private rooms for as long as the
      file is gone. Section 14 says so.
    - **Owners and moderators are removed "for a check" only by their
      own kind** (12.7, 6.3; round 3, R-H2). This narrows the first
      bullet. In a room, the leaves of an identity listed in `owners`
      may be removed for a check (fork, missing keys, failed key check,
      impostor, RESYNC) only by that identity or an owner; those of one
      in `mods` only by that identity, an owner or a moderator. Other
      members' devices only hide what it sends, warn, and keep sending.
      "A room whose owners are gone" (6.3) now looks at the group before
      the commit, so a moderator cannot remove the owners and take their
      place in one commit. Why: otherwise any member could remove a
      private room's only owner on a claim nobody can check, and only
      owners can add owners back. What it costs:
      - a forked, compromised or keys-missing owner or moderator stays
        in the room, and its leaves go on reading it, until its own
        devices or an owner remove it;
      - **a room's only owner who loses every device never gets back
        in.** Recovery removes the old devices by record, but only an
        owner may remove an owner's leaves, so the old leaves stay for
        good (a thief holding one still reads), the new device can never
        be added, and moderators cannot help (4.8, 12.7, 14, D.3).

      The alternative is round 2's rule as written, accepting that any
      member can leave a private room without owners and any moderator
      can take one over.
    - **No rate limits per pseudonym** (5.2, 7.3, 14; round 1, D-M3).
      This changes item 54's "limits per pseudonym". The server cannot
      tell whose pseudonym a post carries, so anyone in a room could use
      up a moderator's limit with junk under their pseudonym, and a
      spammer could use a new pseudonym for every post. Servers now
      limit posts per connection and per network address only. Mutes
      stay.
    - **In public rooms the server sees who commits** (4.1, 5.2, 12.6,
      14; round 1, M-M1 and D-C1). Every commit, external commit and
      Update proposal by an identity's leaf in a public room goes on the
      signed-in connection of the device its credential names, and a
      guest's join on its guest connection. This changes item 54's
      sealed sending, and item 60's "posting only on anonymous or guest
      connections", for public-room commits. Why: public-room joins no
      longer carry a device binding (next bullet), so this is what stops
      anyone committing under someone else's name and lets the server
      refuse banned identities. It proves nothing to third parties. What
      it costs: the server learns who commits in a public room, which is
      roughly who sent the day before (senders rotate their leaves
      daily), and in quiet rooms may tie a pseudonym to a commit by
      timing. Messages are still posted anonymously.
    - **Public rooms' roles rest on the server** (12.3, 12.6, 14, D.1,
      D.3; round 1, M-H7, and round 3, R-H3). Public-room joins carry no
      device binding, which drops item 60's binding in external commits.
      Why: chained through the room's public commits to every later leaf
      key, the binding proved who wrote any message there, which undid
      the epochal signatures. The cost, found in round 3: a malicious
      server can commit in any identity's name in a public room, and so
      change its roles, bans and settings. Devices find that leaf
      unconfirmed within an hour, warn, and SHOULD keep showing the
      roles from before. This narrows item 51: "the server cannot change
      a room's roles" now holds outside public rooms only. A real fix is
      a larger redesign, left for later.
    - **Proof of work is off until it is specified** (4.1; round 2,
      B-M11). Item 42 decided it is on by default. Servers now MUST NOT
      require it until a later draft specifies the puzzle; 4.1 says what
      that draft will cover. Until then, joins of public rooms are
      bounded only by rate limits.
    - **Pseudonyms change every epoch, outside public rooms** (7.3,
      12.9; round 2, S-M8). Item 60 had a random pseudonym per leaf,
      pinned by devices, which let the server count a group's senders
      and follow each one's rhythm for months. Now it is derived from
      the epoch and the leaf, and checked by devices. Public rooms keep
      a random pseudonym per day. An operator's ADMIN MUTE outside
      public rooms now lasts only until the next commit.
    - **Large rooms rotate leaves by Update proposals** (12.3, 12.10;
      round 1, M-M7). This changes item 60's answer "every active sender
      commits once a day in each large room". A device posts an Update
      at a random time in the first 12 hours of the day, and full
      clients commit pending Updates in batches; after 30 minutes
      without, it commits its own. Light clients rotate by Update too,
      instead of rejoining weekly.
    - **Every device joins a public room by external proposal** (6.1,
      12.6; M-M1, S-C1). Item 60 had full clients join by external
      commit. External commits are now only for a resync, after a commit
      the server accepted but devices reject, and for owners and
      moderators whose proposal waits over 30 minutes.
    - **Confirmation covers more than senders** (12.7, 12.10; round 1,
      M-H5, and round 2, S-H1). This extends item 60's "senders only". A
      device also challenges at once every new leaf of its own identity,
      and any unconfirmed leaf that uses authority (a commit that needs
      a role, removes another identity's leaf, and so on). No good
      answer within an hour makes the leaf an impostor, which any member
      may remove; undoing what it did takes ordinary commits. Owners and
      moderators are invited by owners only.
    - **Welcomes wait up to 10 minutes each** (12.8; round 1, D-H1).
      Item 60 had up to a minute, all together. Each Welcome is now
      sealed to its device and sent after its own random wait, so a new
      direct conversation can take up to 10 minutes to reach the other
      side.
    - **A server with a key log logs outside identities whose chains
      name it** (4.7; code, SV1, R2). SV1 left no switch to refuse,
      against item 60; R2 added one (`limits.log_outside_identities`, on
      by default; off, such a KEYS PUT gets `ERR not-supported`), so
      item 60's choice is back. It also caps new outside identities at
      100 a day per registered domain.

    The client and review work (C2b to C5, R2) added these, which are
    in the code, not the spec:

    - **Daily leaf rotation is by commit in librisala** (12.10; C3).
      The spec rotates leaves in large rooms by Update proposals (the
      bullet above). librisala's epochal groups instead make the day's
      new leaf key with a commit of their own, at a planned time or
      before the period's first message. The Update path, with others
      batching and the 30-minute fallback, is not built, so a large room
      gets a commit per active sender per day, as item 60 had.
    - **With no witnesses set, nobody is added** (4.5, 4.10; C1, C5).
      The apps ship with an empty witness list (below), so no record is
      ever accepted, and devices add only accepted devices. Until a
      witness policy is set, an app can add nobody to any conversation.
      This keeps the rule but makes the 2-of-3 default unusable out of
      the box until independent witnesses run. Development setups and
      risala-cli set one (`--witness`, `--witness-k`).
    - **Only an identity's own devices add its new devices** (12.14;
      C5). 12.14 says any member's device adds an identity's devices
      that have no leaf, where the Adds checks let it. librisala lets
      only the identity's own devices do so, and, in a direct
      conversation, the other participant once the identity has no leaf
      left (after a recovery). Why: so that members do not race to add
      the same device. Cost: in a private room nobody re-adds an
      identity with no leaf left, which R-M1's options below assume an
      owner or moderator does. Alternative: every member adds, after a
      random wait.
    - **risalad keeps times to the hour** (7.5, 14; R2, SR-M2, SR-L5).
      Mailbox creation and last activity, token-hash use, KeyPackage
      handouts and Welcome receipt are kept to the hour, and push
      expiry to the day, so a seized store says less about when people
      were active. Retention may then run up to an hour late. Posts'
      times and cids stay exact, since devices are sent them.
    - **A resent message's ATTEST is remade** (12.9, 12.10; M1d, C3).
      12.9 says a message's fields are fixed once written, and a message
      sent again after `ERR stale` keeps its `frank`. But an ATTEST must
      carry the pseudonym of the epoch it is posted in, so risala-mls
      remakes it, which changes the content and the `frank`; the message
      id, counter, `previous`, time and frank key stay. Alternative:
      drop the ATTEST and attest in the next message.
    - **File downloads accept classical key exchange** (2.1, 5.6; C4).
      librisala's HTTPS client for files and blobs uses rustls's default
      groups, X25519MLKEM768 first but classical ones too, since `get`
      URLs may be on object stores or CDNs; key-file fetches
      (risala-keyfetch) already did the same, since a key file may be on
      any web server. Only chat connections are post-quantum only (2.1).
      Files and key files are encrypted or signed, so what a later
      quantum attacker could learn is which ones a device fetched.
      Alternative: post-quantum only for all HTTPS too.
    - **M5a's seeded scenarios and bots are gone** (C5). They spoke
      M5a's plain-text lines (JOIN, MSG), which librisala no longer
      does. risala-dev is now a library and binary that serves risalad
      as `chat.test`, with its key log, a witness, HTTPS and a test CA,
      for librisala's and the CLI's end-to-end tests. Alternative:
      rebuild seeding on librisala.

    **Open decisions.** Round 3 left two findings that need the user.
    The spec now states each risk plainly, but the design is unchanged
    until the user decides.

    - **R-M1: getting back into a private room** (4.8, 4.9, 10.5, 12.7,
      12.14, 14, D.3). Since round 2, only an owner's or moderator's Add
      brings back an identity that has no leaf left in a private room
      (an owner's, for an owner). Ordinary events take all of an
      identity's leaves out: recovering after losing every device, a key
      file that goes missing (a web move, an ADMIN UNREGISTER), a fork
      the user later resolves, and a RESYNC by a
      device with no other leaf there. The identity comes back only
      where an owner's or moderator's device is online and its user
      agrees, and a room's only owner never comes back (R-H2 above). The
      options:
      - A: keep the design, and add client SHOULDs: warn a sole owner
        with no moderator and suggest adding one, and before recovery
        say which rooms the user owns alone and will lose;
      - B: for missing keys only (not forks or removal by record),
        devices in rooms hide the identity's leaves and keep sending,
        but remove them only once the keys have been missing for, say, 7
        days, so a short outage costs nothing;
      - C, later: a list of member uids in a private room's extension,
        kept by invitations, kicks, bans and leaves, so that any member
        may add a listed identity's devices (owners still need an
        owner).

      The reviewer recommends A and B now.
    - **R-M2: a new master key freezes private rooms** (12.14, 14, D.1,
      D.3). Item 60 is kept: a new master key stops sending in direct
      conversations and private rooms until the user acknowledges it.
      But it is as easy to cause as the fork freeze round 2 removed: any
      member can do it with its own recovery key, and whoever controls a
      member's domain can do it as often as it likes, with an unlogged
      key file. In a room, stopping protects nothing, and acknowledging
      is risky: once one member acknowledges, its device adds the new
      key's devices to every room where the identity still has a leaf,
      for everyone. In a room of 500, the domain's controller needs one
      member to click through. The options:
      - the reviewer's fix, which changes item 60's answer for rooms: in
        rooms a new master key behaves like missing keys (warn, hide the
        new key's leaves, keep sending), and only the identity's own
        devices, or an owner or moderator whose user acknowledged, add
        devices under the new key; direct conversations still stop until
        acknowledged;
      - keep item 60 as it is, with the risk stated (the spec now).

      The reviewer recommends the fix.

    **Design choices, by area.** These fill in what the spec left open,
    or fix what could not be built. Section numbers are draft-03's.

    *Identity and the key log.*
    - **Moving logs** (4.3, 4.5; I-C1). The first `master` record names
      its log's key. A `log` record moves a chain to another host's log.
      A host replaces its own log by a hand-off entry, which carries
      every chain over with nothing for users to do; a host that loses
      its log key can never hand off, so its identities' chains stop
      growing. First contact through another host's log is protected
      only by safety numbers.
    - **Key files list hashes** (4.4, 4.7; I-H2), and readers fetch the
      records from the log. A chain holds at most 4,096 records.
    - **Witnessing** (new 4.10; I-H3, B-H4, S-H5). A witness takes on a
      log by fetching its key from the host over HTTPS, which proves
      control of the host. "Fresh" means k cosignatures under 24 hours
      old. k must be more than half the list; the default stays 2 of 3.
      **The apps ship with an empty witness list** (C1), since no
      independent witnesses run yet, so every log shows "witness list
      does not fit", and no record is accepted, until one is set (see
      above). Accepting a record needs no fresh checkpoint (R2a).
    - **Stale identities** (4.5; I-M14). After 7 days without a fresh
      checkpoint, an identity is shown as stale: no new devices of it
      are added, and sending goes on.
    - **A `retire` record** (4.4, 4.9; I-M11), signed by the master key,
      ends an identity for good, so a thief holding only a device
      cannot. Only accepted records remove devices.
    - **Servers pin outside identities** (4.6, 10.5; I-M12), and accept
      only key files that extend the pinned chain.
    - **Rollback or new master key** (4.4, 4.5; C1). A key file that
      does not extend the pinned chain is a fork if its chain holds the
      pinned master key, and otherwise a new master key, which waits for
      the user's acknowledgment.
    - **Backup generation comes from the chain** (12.13; K-H4), so
      recovery moves it too, and a device that moves it makes a new
      backup at once.
    - **Pairing** (4.8; I-M13, S-L1, C1). The IdentityBundle travels
      sealed under the QR code's secret. The new device shows the uid
      and the identity's current devices and asks the user to confirm,
      within 10 minutes of opening the bundle (LR-H4), and finishes only
      once its record is witnessed (up to 10 minutes). A relay named by
      an IP address is refused (C1b). The history sent at pairing covers
      only conversations on the home server, where its blobs are (C4).
    - **New lines in the conversation with yourself** (12.9): RECORDS
      (which records each device knows), SERVERS (the identity's
      servers; the first is home) and PIN (server pins, shared across
      devices).

    *Groups, MLS and confirmation.*
    - **Group checks look only at the group's current state** (7.2,
      12.7; S-H2). A commit's validity depends on the group in its
      epoch, the commit and its posts' times, never on history, so every
      device judges it the same way, even one that joined a minute ago.
      Rules that looked back 16 epochs or 24 hours went with it.
    - **Group checks and key checks** (12.7; M-H2, S-H3). Key checks,
      against key files, never make a commit invalid; they lead to
      repair commits. Outside public rooms any member may remove one
      identity's leaves per commit "for a check". A device that sees no
      reason warns and names the remover; only the removed identity's
      own devices can call it false and re-add.
    - **Who may add whom** (12.7; S-H2, R-H1). Any member may add
      devices of an identity that still has a leaf after the commit;
      others only by invitation. An owner's devices are added only by
      that identity or an owner.
    - **Commit streaks** (12.3, 12.7; K-L6, S-M3), a new construction:
      one identity starts at most 3 epochs in a row, unless 10 minutes
      have passed, so one member cannot flood a group with commits.
    - **Stale leaves** (12.7; K-H2, S-M1) are judged against the group's
      median rather than the remover's own leaf, at most a tenth per
      commit, and the device is added back from a new KeyPackage.
    - **Moving a mailbox** (new 7.8; D-H3, S-M5). After someone is
      removed from a direct conversation or private room, the group
      moves to a new mailbox, so the removed member cannot keep watching
      its traffic. Blocking does not move it (D-M5).
    - **Send tokens** (7.2; M-C1, D-H4). The next epoch's token hash
      could not sit inside its own commit, so it goes as `next=` on the
      commit's POST, and every device checks it. A new TOKEN command
      repairs a token set someone filled with junk.
    - **Public rooms** (6.1, 12.7; S-C1, S-M2, K-H1). Older copies of a
      credential and never-used leaves may be removed; a plain member's
      commit removes at most a tenth of the leaves that way. A device
      that sees the server accept a commit it holds invalid tells the
      user, and rejoins only if they choose.
    - **Public rooms in librisala** (6.1, 12.7; C2b). A joiner learns
      that its proposal was committed by asking GROUPINFO after each
      commit it sees, and every 5 minutes, then fetches its Welcome. A
      resync commit removes only the GroupInfo's signer, since OpenMLS
      takes no external commit with two Removes; the device's earlier
      leaf goes in its next commit. A device stuck on a commit tells the
      user, waits up to 10 minutes, then resyncs if the server is one
      epoch ahead and otherwise joins again by proposal; it stops only
      on a change of roles or settings it cannot explain, until the user
      accepts it. Every full-client commit also clears the device's own
      earlier leaves, copies, and joins never used for 8 days. Guests
      never commit or propose Updates.
    - **A Welcome to a group the device already has** (12.7, 12.8;
      C2b, LR-C1) is taken only if it continues that group: a later
      epoch, the same kind and participants, and a signer that was a
      leaf the device knew. Otherwise it is refused and the old group
      stays. Cost: a re-add by a member who joined, or rotated its leaf
      key, while this device was away is refused.
    - **Sending waits for key checks** (12.7; LR-C2, C5). A device sends
      no messages in a group while a leaf added there is unchecked
      against its key file, or a failed check's removal is not yet
      queued (repairs and other commits still go); a check pending for 2
      hours counts as failed. A device that is pending or missing from
      the key file as last read is "unknown", not failed, since the copy
      may be old; the key file is read again at once when a group's
      members change. While a key file has never been readable (an
      outage), a fetched KeyPackage is added unchecked and its leaf
      stays unconfirmed, which trusts the server more than refusing
      would.
    - **Repairs by key file** (12.14; C5). Any member removes the leaves
      of devices removed by record, and in a private room those of an
      identity it cannot check, within the owners' and moderators' rule,
      one identity per commit, on a 5-minute upkeep timer.
    - **RESYNC** (12.7; M-M5). A device that cannot process a commit
      asks, with a RESYNC line, to be replaced. librisala asks only once
      it sees a post of the next epoch it cannot read, so a junk commit
      does not make every member ask (C2). A RESYNC is answered by the
      leaf's own identity, or, if it has no other leaf, by the other
      participant of a direct conversation or an owner or moderator of a
      private room; the request moves to the conversation with yourself
      after an hour (C2b).
    - **Splits** (7.7; M-M9). READ carries a short check of the epoch,
      which an identity's own devices compare.
    - **Epochal signatures** (12.10; M-M6). REVEAL comes no earlier than
      3 hours after the day ends, so a message becomes deniable within
      about two days.
    - **Past epochs** (12.9; K-H3, S-M6). Their messages are read for at
      most an hour after the commit that ended them, and their secrets
      are deleted 2 hours after it.
    - **Confirmation in code** (M3, C3, R2a). A sender that never
      answers stays unconfirmed; a wrong answer makes it an impostor,
      but an answer to a challenge already replaced is ignored.
      CHALLENGE, ANSWER, ATTEST and REVEAL lines are added to a message
      just before it is encrypted, so they are bound to the key it is
      posted with. An Add of an owner's or moderator's device by someone
      else counts as using authority, and so does a moderator's DELETE.
      Any member removes an impostor after a random wait, within the
      owners' and moderators' rule, never in a public room. Not built:
      the impostor rule for a new own leaf that sends without ATTEST,
      and offering to undo an impostor's changes.
    - **OpenMLS is vendored** (`crates/openmls`, 0.9.2) with marked
      patches, so SelfRemove travels as a PrivateMessage, a resync may
      remove another leaf, and commits and proposals are padded to a
      Padmé length (R2a). `last_resort` needed no patch.

    *Metadata, mailboxes and push.*
    - **Sealed Welcomes** (12.8; D-H1, S-H4). Outside public rooms each
      Welcome is sealed to its device, so the server cannot read the
      group's members from it. Only the device that fetched the
      KeyPackage may put its Welcome.
    - **Which connection for what** (4.1, 7.4; D-M1, D-M2, C0). Key
      uploads, pairing and public-room commits go on the signed-in
      connection or a one-shot one; new mailboxes, KeyPackage fetches
      and Welcomes SHOULD each take a fresh anonymous one. Otherwise
      librisala keeps one anonymous connection, since spreading out
      helps little without Tor. Devices follow and fetch in ways that
      are hard to link (random order and waits), and never resume TLS
      sessions. In public rooms (C2b), an identity's join proposal and
      its WELCOME GET each take a connection of their own, GROUPINFO
      goes on the anonymous connection that follows the room, and
      commits and Updates on the signed-in one.
    - **Key files of public-room members** (12.10, 12.14; C5). A device
      reads each member's key file once, when the member appears, so it
      can check their ATTEST. 12.14 asks only for senders it has
      confirmed. Cost: a device's address reaches the domain of everyone
      in the rooms it joins.
    - **What the server keeps** (4.2; D-H5, SV0): no address for an
      anonymous or guest connection beyond the connection, posts with
      mailbox, seq, time and message only, and mailboxes and group ids
      only as hashes. Logs leave addresses out by default.
    - **Quotas** (5.2, 7.5; D-H6, SV3, SV6, R2). Over a mailbox's quota
      the server expires the oldest posts early rather than refusing new
      ones, so one member cannot block a group. One quota now counts
      posts, files and blobs together; files and blobs never expire
      early, and one that does not fit is refused. R2 spared commits and
      proposals too, since devices need them to follow: once they alone
      fill a mailbox, it takes nothing new until retention frees room,
      so one member can still block a mailbox for a retention period,
      within the commit rate limit.
    - **Push** (9; D-M4, D-M8, R-L12). Each push waits a random time of
      up to 10 seconds, and notices are padded. Subscriptions last one
      retention period, devices renew them weekly, and subscribing to a
      mailbox needs one of its send tokens, from any set the mailbox
      still keeps, so a member removed recently can renew for a while
      (P1f). The limit per mailbox is never below 4,096 (32,768 in a
      public room), since the server cannot tell a private room from a
      direct conversation. The app hands librisala its push gateway
      URLs, and `quiet=` is off by default (C4).

    *Content, files, transfer and backups.*
    - **Files in transfers and backups** (12.13; K-M9) are encrypted
      again as blobs of their own, which backups keep and reuse.
    - **WANT** (12.13; K-M1). A device that fell behind asks its other
      devices for a range; what comes back fills only the gaps, shown as
      copied.
    - **Transfers in librisala** (12.13; C4, LR-H3). WANT, TRANSFER
      and their blobs go through the home server, so only gaps in
      conversations there are filled. A device asks only once FETCH
      shows posts expired, not yet after being added to a group again.
      A copied message keeps the sender's `verified` only as "vouched
      for by" the device that sent it. A transfer's edit, reaction or
      DELETE applies only to copied messages, and a newer edit less
      trusted than its message is shown apart.
    - **Backups are per device** (12.13; C4). The user turns them on
      for a device, which then makes one at most daily; several devices
      with backups on each replace the backup. A device that moves the
      generation, or sees it move, makes one at once. Restored
      conversations wait until the device is added to them again.
    - **Downloads** (5.6, 12.11; C4, LR-M3) are saved, only once every
      check passes, in a private directory under the client's cache,
      and deleted with their message or conversation. A moderator's
      DELETE erases the message on the uploader's device too, which then
      deletes the file with its `del` URL, although 5.6 says a
      moderator's DELETE cannot remove a file.
    - **No forward secrecy between backups** (K-M6): whoever gets the
      recovery key reads every backup the server kept.
    - **Download origins** (8.5; K-M4). Devices download files without
      asking only from the origins the conversation's server lists.
    - **Reports** (5.8; K-M7, R-L9). The operators' copy carries the
      post's pseudonym, so they can mute it. Operators MUST NOT ban on
      reports alone, and SHOULD NOT mute on a single one. librisala
      sends a report to operators on the anonymous connection that
      follows the room, so they do not learn who reported (C4). A device
      takes a guest's report conversation only if its identity owns or
      moderates a public room on that server that allows guests, and
      joins only once the user accepts (C2b). A REPORT uses its rate
      limit slot whatever the outcome (R2).
    - **Roles** (6.3; K-M2, K-L2). A ban takes the identity off `owners`
      and `mods`. When no owner has a leaf, moderators may do what
      owners may.
    - **Room links** (15; K-L9) may carry the group id, and devices ask
      before joining a different group under a room's name.

    *Server operation.*
    - **Settings** (SV0). Retention is in days, 30 by default and at
      least 7. Anonymous connections are on by default. `room_creation`
      now covers public rooms only.
    - **risalad runs the key log and can be a witness** (SV2), with the
      hand-off to a new log set in its configuration. The witness
      fetches each log's key from the host's own log
      (`/risala-log/1/risala/key`), so the `[witness] logs` setting is
      gone (P1d).
    - **Default limits** (SV3, SV4, SV6): 4 GiB per mailbox, counting
      posts, files and blobs; 8 GiB stored per address an hour; 100 MiB
      uploads; and, per connection and per address, 600 posts a minute
      and 120 new mailboxes an hour.
    - **R2's limits** (SR-H1 to SR-M11). The server review added about
      fifteen limits against floods and running out of memory or disk,
      each in risalad's configuration: 256 GiB stored in all, 1 GiB of
      blobs in memory, 64 connections and 16 guests per address (IPv6
      /64), KEYS PUTs and sign-ins that fetch a key file per hour, 100
      new outside identities a day per domain, 30 join proposals an hour
      and 8 pending per room epoch per address, and push subscriptions
      and sending rates. The table, with the constants, is in
      `choices-code.md`, section R2.
    - **Public-room trees** (6.1, 12.6; SV4b, C2b) are inline only up
      to 8 KiB, so the tree of any room with two or more leaves comes as
      a blob, and joining needs an HTTPS fetch. Trees and room Welcomes
      are dropped 24 hours after their commit.
    - **No conversations on IP-address servers** (6.1; M1d). The room
      extension names the server, so an account on a server named by an
      IP address cannot create conversations.
    - **KEYPKG GET** answers only for uids that uploaded KeyPackages
      within retention, so it never fetches key files from a domain a
      client names (SV4).

    *Clients and tools* (C5).
    - **risala-cli** runs one command per call: it connects, acts, and
      stays until what it queued is sent. `pair accept` needs no prompt
      (running it is the user's confirmation) and sends the history
      unless `--no-history`; `pair new` shows the identity and its
      devices and asks before joining, unless `--yes`. Not built yet:
      guests, reports, push, blocks, edits, reactions, deletes, roles.
    - **A new device does not start a conversation with yourself**
      (5.1, 4.8) while another device of its identity is current; it
      waits to be added, so a paired device does not make a second one.

    Still to check: the C2SP tag that has ML-DSA-44 cosignatures; which
    X-Wing draft draft-ietf-mls-pq-ciphersuites cites (Section 16 still
    names -06); and the light-client structures copied from
    draft-ietf-mls-partial-02, byte for byte.

    **Spec gaps found while building, not yet settled.** The coders
    listed these in `spec-problems.md`; the spec still leaves each open.
    The code's answer is in parentheses.

    - 12.7: a resync commit removes the bad committer's leaf and the
      device's earlier one, but OpenMLS takes no external commit with
      two Removes, and removing another's leaf in an external commit
      departs from RFC 9420 (12.4.3.2) without saying so (earlier leaf
      in the next commit; OpenMLS patched for the other).
    - 12.9 vs 12.10: a resent message's fields are fixed, yet its ATTEST
      must carry the new epoch's pseudonym (ATTEST remade, above).
    - 12.7 vs 12.9: a leaf that does not answer within an hour is an
      impostor, so a device offline when added is removed, while the
      conversation with yourself allows 24 hours.
    - 12.10: a new challenge replaces the old, and a wrong answer makes
      an impostor, so an honest late answer to the old one reads as
      wrong (ignored).
    - 6.1, 12.8: how a joiner learns its join proposal was committed
      (GROUPINFO after each commit).
    - 12.8: "fetched" is undefined for a device's Welcome, also sent
      live, and for a room's Welcome taken by WELCOME GET (a device's
      WELCOME DEL; a WELCOME GET does not freeze a room's Welcome).
    - 12.7, 12.8: what a device does with a Welcome for a group id it
      already has (only one that continues the group, above).
    - 7.5: early expiry should spare commits and proposals, and say what
      happens once they fill the quota (refused until retention frees
      room).
    - 12.13: archives keep edits and DELETEs to apply "as on receipt",
      while a transfer "never replaces or changes a message it holds"
      (never changes a message the device received itself).
    - 12.13, 4.8: which server holds a TransferRef's blobs (the home
      server).
    - 4.8, 12.13: the IdentityBundle names no sending device, yet copied
      messages are shown by that device's label.
    - 12.13: how the "one device of the identity" that makes backups is
      chosen (each device with backups on).
    - 12.13, 7.8: how a device archives messages of a mailbox it forgot
      after a move (left out).
    - 5.6 vs 5.4: whether the uploader's device deletes its file after a
      moderator's DELETE (it does).
    - 12.2: the X-Wing key check does not list a GroupInfo's
      `external_pub`.
    - 9.1: the per-mailbox push limit depends on a group's size, which
      the server cannot know outside public rooms (at least 4,096).
    - 12.9: no limit on the number of content lines (16,384).

63. **Found by the review of M5b before merging** (5.1, 6.1, 7.1, 7.5,
    9.1, 12.5, 12.7, 12.12, 12.14, 14), decided with the user on
    2026-11-09. The review's High findings are already fixed on `m5b`
    (a leaving device re-adding its own devices, CLI text printed raw,
    the blob-memory deadlock, FETCH reading past its budget, `nix run
    .#dev`). The Medium findings, to fix:
    - **Key-file outages** (12.5, 12.14). A device never adds an
      identity whose key file it has never read: the invitation or
      direct conversation fails with "key file unavailable, try later"
      and the upkeep retries. Devices cached from an earlier good read
      still work during an outage. A known log fork refuses too.
    - **An outage never fails a check** (12.7). Only a pending record
      times out after 2 hours. While a key file cannot be read, the
      check stays pending: sending stays held for added leaves,
      committers count as checked as far as records are accepted, the
      user is warned after 2 hours, and nothing is removed for it.
    - **Joining checks the tree** (12.7, Joining). A device that joins
      by Welcome runs the Adds key check on every leaf already there,
      and holds sending until each passes. The spec says so.
    - **Removals go first** (12.7). Repairs and removals by record or by
      check go before any other queued commit and are never held;
      held commits are rebuilt after them.
    - **Deletes from a less trusted leaf** (5.4, 12.10): as for edits, a
      DELETE removes a message only when its leaf is at least as
      trusted as the message's. Otherwise the message shows as deleted
      but unconfirmed, the DELETE applies once its leaf is confirmed, and
      it is dropped if the leaf is an impostor.
    - **Large commits as blobs** (12.12): librisala sends any commit,
      GroupInfo or tree too long for a line as a blob over an anonymous
      connection, now, tested against risalad past the limit.
    - **Own commits are checked** (12.5, 12.7): a device runs the group
      checks on its own commit before posting it, with lifetimes
      against the time it posts and the hour's margin taken inward, and
      fetches again any KeyPackage that fails.
    - **One Remove per external commit** (12.7). The spec follows
      OpenMLS (RFC 9420 12.4.3.2): a resync commit removes only the
      GroupInfo's signer, and the device's own earlier leaf goes in its
      next commit. `risala_mls::group::external_commit` refuses a second
      removal; RISALA.md and the docs say so. No new OpenMLS patch.
    - **Storage cap** (7.5, 10): `max_stored_bytes` applies to BLOB and
      UPLOAD only, with a reserve so inline posts and commits always
      fit; the per-address window is lowered (about 1 GiB an hour); blobs
      kept for reports count separately, with their own bound.
    - **GROUPINFO** (6.1, 12.12): the server stores a public room's tree
      blob once per epoch, when it applies the commit; GROUPINFO returns
      it with no writes, and its reads count against blob memory.
    - **KEYS PUT** (4.7): its rate-limit slot is used as soon as a blob is
      read, whatever follows.
    - **Shared addresses** (2.1, 4.2, 10, 14): per-address limits stay as
      the free tier; past them a client may go on by proof of work
      (item 42), wired in with risala-pow in M6a. Until then the
      defaults go up about four times, and 10 and 14 say what one Tor
      exit or carrier NAT shares.
    - **HTTPS transfers and push hosts** (9.1, 12.12): transfers keep a
      running minimum rate (about 16 KiB/s over 30 seconds) besides the
      overall deadline; push URLs are parsed (host lower-cased, default
      port, trailing dot dropped) and those with userinfo refused, so the
      per-host limit holds. Tested over a real connection.
    - **CLI addressing**: a uid only ever means the direct conversation
      with that identity; rooms are named by number or `#name`.
    - **CLI exit codes**: `Client::is_settled` also waits for pending
      KEYS PUT, KeyPackage uploads and an outgoing transfer, and a
      command fails with a clear message when they have not landed by
      its timeout. The goal test's retries go.
    - **CLI witness policy**: `risala witness show|set|clear`; a saved
      policy changes only through it; `--witness-k` alone is an error;
      `--ca`, `--resolve` and `--short-waits` print a warning, and so
      does a policy naming risala-dev's fixed-seed witness.
    - **No commits while leaving** (6.1): a leaving device makes no
      commit but its own leave commit; repairs and the weekly fresh-leaf
      commit skip conversations it is leaving.
    - **A lone device leaves locally** (6.1): when no other identity has a
      leaf, a device leaving forgets the group (UNFOLLOW, its keys and
      the conversation deleted) and makes no commit.
    - **A direct peer who left** (5.1, 6.1, 12.7) is never added back by
      itself. When the peer leaves, the remaining side leaves too,
      locally, and shows the conversation as left by the peer, so one
      direct conversation per pair shows; talking again starts a new
      one. A peer removed for a check or after a recovery is still added
      back. The spec says so.

## 6. Decisions

- **Minimum Rust version:** the newest rustc in the current NixOS stable
  release, now 1.95 (NixOS 26.05). Raise `rust-version` in Cargo.toml
  when a new NixOS release ships a newer one.
- **Minimum OS versions:** the latest release of each platform: iOS and
  macOS 27 (the ones Xcode 27 ships with), the newest Android API level,
  and the newest GNOME platform and libadwaita. Apps may use their
  newest APIs freely, and raise the minimum when a new release comes
  out.
  The GNOME app is the exception once it ships in our apt and dnf
  repositories: it then targets the libadwaita of the oldest release we
  ship it on (see Linux packages).
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
- **Linux packages**, decided with the user on 2026-11-09:
  - **Nix:** the flake is the way in for Nix users, with packages, an
    overlay and a NixOS module.
  - **Our own apt and dnf repositories**, signed static files that we
    host, not a Launchpad PPA or COPR. Launchpad builds with Ubuntu's
    own rustc, which is older than our minimum.
  - **Releases:** the two current Fedora releases, the two newest Debian
    stable releases, and Ubuntu's two newest LTS releases plus its newest
    non-LTS release. Debian 12 and Ubuntu 24.04 are left out for now:
    their systemd is older than 256, which the clients need (item 45).
    That leaves Debian 13 and Ubuntu 26.04 and 26.10 today; Debian 14
    and Ubuntu 28.04 fill the gaps when they ship.
  - **Architectures:** x86_64 and aarch64 from the first release.
  - **What ships:** `risalad` and `risala-cli` first; the GNOME app goes
    into the same repositories once it exists.
  - **OpenSSL:** the packages link the distribution's libcrypto
    (`OPENSSL_NO_VENDOR`, as Nix does), so OpenSSL fixes reach users
    from the distribution without a rebuild of ours.
  - **Signing:** the repositories' primary key stays offline. Packages
    and metadata are signed with a subkey, kept encrypted in this
    repository with sops. A keyring package (`risala-archive-keyring`,
    `risala-release`) installs the public key, so the key can be rotated.
    Whatever decrypts the subkey can sign packages, so only the release
    job gets that key. To revisit later.
  - **The server package** brings a systemd unit, a system user, a
    config file in `/etc` that upgrades leave alone, and a restart on
    upgrade.
  - **Tested in CI on every release and architecture we target:** install
    from the published repository into a clean system, upgrade from the
    previous published version, and run the smoke test after each.
  - **The GNOME app** targets the libadwaita of the oldest release we
    ship it on, not the newest (see Minimum OS versions).
  - **Later:** a version scheme under which pre-releases sort correctly
    for apt and dnf, and a Nix binary cache.
  - **No AppImage.** It would still need systemd 256 and a TPM, so it
    reaches few more machines, and it has no signed update path.
- **Verification page**, decided with the user on 2026-11-08: the site
  gets a source listing that shows, on each line, every kind of
  evidence at once: tests, fuzzing, Kani, and TLA+ where a line is tied
  to a spec section the model covers.
  - **How a line shows it:** one narrow coloured column per kind of
    evidence beside the line number, so they read side by side, and the
    line's background tinted by the strongest one. Lines nothing reaches
    are tinted red. Hovering a line names the tests' hit count, the fuzz
    targets and the Kani proofs that reach it.
  - **Where the results come from:** a `verification` workflow runs on
    pushes to main and nightly, and uploads the results as JSON. The
    site build downloads the latest copy; it never runs the tools
    itself.
  - **What it covers:** every Rust crate except the vendored
    `openmls-traits`, and the Swift client through xccov on a macOS
    runner.
  - **Fuzz corpus:** kept out of git, in the CI cache, and grown by the
    nightly run. The page states how long each target has been fuzzed.
  - **Rendering:** a client-side React app at `/verification`, with the
    file listings under `/verification/src/<path>`. The site build
    copies the sources and the results JSON into the output as static
    files. The app fetches them and highlights the code in the browser,
    so the site gains `@astrojs/react` and a browser build of a
    highlighter. Without JavaScript, the page shows nothing.
  - **Kani column:** Kani's unstable source-coverage mode gives the
    exact lines each proof reaches. Where that mode fails, on our Kani
    version or in the JIT crates, a proof marks the whole of each
    function it calls, and the page labels those marks function-level.
  - **TLA+ column:** a line is marked when it lies in a function whose
    comments cite a spec section the model covers, such as (7.1). The
    mark says the model checks the spec, not this code.
  - **More choices**, decided with the user on 2026-11-08:
    - Shiki highlights in the browser, with the JavaScript regex engine
      and only the grammars and themes the listing uses, loaded on
      demand.
    - Tests are two columns: unit tests (in `src/`, property tests
      included) and integration tests (`tests/`, the spec example and
      transcript tests included).
    - Kani was to join the dev shell, but nixpkgs does not package it,
      so it is installed with cargo, pinned to 0.68.0, locally and in
      CI (`verification/README.md`). cargo-llvm-cov joins the dev
      shell, but coverage builds use a rustup toolchain: nixpkgs' rustc
      ships a coverage runtime from a newer LLVM than its own, and the
      instrumented test binaries crash on exit.
    - The Swift client's coverage comes from a macOS CI job. Its
      converter is tested against a small hand-made xccov sample.
    - With no results for a commit, the site still builds, and the page
      says so in a banner.
    - The nightly run fuzzes each target for 10 minutes.
    - A spec view at `/verification/spec` lists each section with the
      evidence for it: tested example lines, the TLA+ model, Kani
      proofs that restate its rules, and the code that cites it.
    - Test code (`tests/`, `#[cfg(test)]` modules, fuzz targets, Kani
      proofs) is listed but left out of the percentages.
    - The site's navigation links the page, and the front page shows a
      summary of its numbers.
    - Made while building it: the code still cites draft-02's section
      numbers, so the spec view has a tab per draft. Draft-02's text
      comes from git (`4634b6ff:SPEC.md`), and code citations, Kani
      proofs and the TLA+ model are matched against it. Draft-03's
      tab counts the example lines the spec tests read. When the code
      moves to draft-03, change `verification/config.json`.
    - Kani 0.68.0's coverage mode gives line coverage for all 40
      proofs, so no proof falls back to function-level marks today.

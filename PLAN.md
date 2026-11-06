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
├── apps/
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
- The auth challenge bytes and Ed25519 sign/verify (4.5), key file
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
  - Each device generates its own Ed25519 key.
  - For self-hosted identities, the library helps produce the key file
    line to publish.
  - KEY management, and adding a new device by showing its public key.
  - Keys are stored through a platform trait: Keychain on Apple
    platforms, an Android Keystore-wrapped key on Android, and libsecret
    on Linux. The Secure Enclave cannot hold Ed25519 keys, so keys are
    software keys that are encrypted or protected at rest.
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

Nothing is open right now.

## 6. Open decisions

- Minimum Rust version, and minimum OS versions (iOS, macOS, Android API
  level, GNOME platform).
- Whether `risalad` serves the `.well-known` files itself by default, or
  expects a separate web server.

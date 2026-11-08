# The chat list, and data for developing the apps

The working plan for the Apple app's chat list, the library support it
needs, and the developer data the apps are built against.
The spec ([`spec/`](../../spec/README.md)) is the source of truth; this plan was written against draft-02.
[M2-M5.md](M2-M5.md)'s "Conventions" still apply to the Rust parts.

Decided with the user on 2026-11-08:

- **Developer data comes from a real server.** A local `risalad`, filled
  by named scenarios, is what the apps run against. Nothing fake ships
  in an app.
- **Previews use fixed data kept out of Release builds**, in the Apple
  app's development assets, behind `#if DEBUG`.
- **A thin slice of M6 comes forward:** the UniFFI bindings for Swift,
  only as far as the chat list and a timeline need. The rest of M6
  (Kotlin, platform key stores, shared theme and strings) stays where
  it is.

## Goal

At the end of this plan:

- The Apple app's first screen is the chat list described in the design
  notes: one feed of every conversation on every account, newest
  activity first, with the toggles unread, favourites and rooms, and a
  group per server.
- It runs in the simulator against a local server with a few hundred
  realistic conversations, and keeps up as bots post into them.
- Every state of the screen can be seen in Xcode previews without a
  server.

**Not in this plan:** direct conversations on a real server (they need
M5a; until then only preview data has them), mentions and typing on
rows, rooms not joined yet ("N more rooms in …"), Android, Keychain.

## 1. The library's chat list (`crates/librisala`)

### What a row holds

```rust
/// One conversation in the chat list.
pub struct ChatSummary {
    /// Opaque, stable, unique across accounts. Compare it, do not parse it.
    pub id: String,
    /// The account it belongs to: its server and uid.
    pub account: AccountRef,
    /// A room such as `#general`, or the other person's uid (5.1).
    pub conversation: String,
    pub kind: ChatKind, // Room | Direct
    /// A room's name, or the other person's label (8.2).
    pub name: Label,
    /// For a direct conversation, whether the other person is a guest (4.2).
    pub guest: bool,
    /// A room's topic (6.2), unescaped; empty if none.
    pub topic: String,
    /// The server the conversation lives on, and whether it is the
    /// account's home server. Apps show the server only when it is not.
    pub server: String,
    pub home_server: bool,
    /// The sort key, in ms since the Unix epoch: see "Order".
    pub activity_ms: u64,
    /// The newest message, if any.
    pub last: Option<ChatPreview>,
    /// As `ConversationInfo::unread`.
    pub unread: u64,
    pub favourite: bool,
    /// Whether the account is in it, as far as the client knows.
    pub joined: bool,
}

pub struct ChatPreview {
    pub from: Label,
    pub own: bool,
    /// Current text after edits, unescaped; empty when deleted.
    pub text: String,
    pub deleted: bool,
    pub time_ms: u64,
    /// For the account's own messages: sent, sending or failed (7.6).
    pub delivery: Delivery,
}
```

- **The preview is the newest message only**: MSG events and the
  account's outbox messages. Joins, parts and settings never become the
  preview, so a busy room does not show "~sam joined". Messages from
  blocked people (5.7) are skipped. With no message, `last` is `None`
  and the app hides the line.
- **Favourites are local** to the cache: the spec has nowhere to keep
  them. `Conversation::set_favourite(bool)`.
- **`home_server`:** the cache does not record which server hosts an
  identity, so a conversation is at home when its server's host is the
  identity's domain or under it (`alice@example.org` on
  `chat.example.org`). Guests are always at home. An identity that
  publishes its own key file at `example.org` also counts as at home on
  `chat.example.org`.
- **`guest`** is false on a real server: direct conversations are only
  between identities (5.1), so the mockups' `~sam guest` row cannot
  happen. Drop the field, and the row's guest marker, unless the design
  finds a use for them.
- **Server state is not on the row.** The app reads each account's
  `ConnectionState` (already in `AccountEvent::State`) and marks rows of
  an account that is not online. One account changing state does not
  update every one of its rows.

### Order

Newest `activity_ms` first, ties broken by the cache row. Activity is the
newest of: the last message's time (not edits or reactions), the newest
unsent outbox message's queue time, and when the conversation entered the
cache. It only moves forward, so deleting a message does not move a row
down. A `convs.activity` column (schema 12), indexed, is kept up to date
in the same transaction as the writes that change it, so the list is one
indexed query across all accounts. Conversations from caches older than
schema 12 with no messages get 0.

### The list as a view

```rust
impl Client {
    /// Every account's conversations, newest activity first.
    pub fn chat_list(&self, filter: ChatFilter, limit: u32) -> Result<ChatList, ClientError>;
}

pub struct ChatFilter {
    /// Only this server's conversations: a group tab.
    pub server: Option<String>,
    pub unread: bool,
    pub favourites: bool,
    pub rooms: bool,
}

impl ChatList {
    pub fn items(&self) -> Vec<ChatSummary>;
    pub fn counts(&self) -> ChatCounts;  // unread_chats for the toggle, total for paging
    pub async fn next(&self) -> Option<ChatListBatch>;
    pub async fn load_more(&self, count: u32) -> Result<(), ClientError>;
    pub async fn set_filter(&self, filter: ChatFilter) -> Result<(), ClientError>;
}

pub struct ChatListBatch {
    pub diffs: Vec<ChatListDiff>, // Reset | Insert | Update | Remove, as TimelineDiff
    pub counts: ChatCounts,
}
```

- It works like `Timeline`: read `items()`, then `next()` in a loop.
  It subscribes before it reads, so nothing falls between them.
- **The window** is the first `limit` rows (default and maximum as
  `DEFAULT_PAGE` and `MAX_PAGE`). `load_more` widens it. When a row
  moves up into the window, the row pushed past the end is removed, so
  the window keeps its size.
- **A row that moves** is a `Remove` and an `Insert`. A row whose
  contents change in place is an `Update`. The `id` never changes.
- `set_filter`, a missed batch (`Lagged`) and a discarded history all
  come as one `Reset`.
- No connection is needed. The first read is one query.

### Tests

The sync simulator (`sync/sim.rs`) drives a list alongside its
timelines and checks, after every step, that applying the diffs gives
the same rows as a fresh `chat_list` with the same filter and window.

## 2. The development server (`crates/risala-dev`)

A binary for development only (`publish = false`), built on
`risala_server::testing`:

```sh
nix run .#dev -- busy             # or: cargo run -p risala-dev -- busy
nix run .#dev -- busy --live      # bots keep posting
nix run .#dev -- huge --reset     # start again from nothing
```

- **State lives in `.dev/`** (ignored by git): the server's database,
  its certificate, and what a client needs to sign in, `.dev/me.json`
  (address, fingerprint, identity) and `.dev/me.pem` (the device key).
  The same state is used across runs, so an app's cache stays valid;
  `--reset` starts again, and the app is told to clear its cache.
- **The account is a hosted identity**, `me@risala.test`, registered by
  the scenario with the key in `.dev/me.pem`. Other people are hosted
  identities and guests.
- **Seeding goes through the protocol**, with the server's manual clock
  set back in time and moved forward per event, so history has real
  dates ("yesterday", "march") and every line is one a real client sent.
  The clock follows the system again before the server opens to the
  apps. `TestServerBuilder` gains a fixed state directory and port for
  this.
- **Scenarios are code**, with a fixed random seed, so a run looks the
  same each time:

  | Scenario | What it has |
  |---|---|
  | `empty` | The account, in no conversation |
  | `busy` | About 40 rooms: Arabic, English and mixed names and text, very long names, 1 to 1,200 unread, edits, reactions, deleted messages, an announcements room, a room the account was kicked from |
  | `huge` | 3,000 rooms, for paging and the speed of the first read |

  `--live` adds bots that post, edit, react and join at a steady,
  configurable rate.
- The server runs on port 7473, one above risala's, with the hostname
  `localhost` and the identity domain `risala.test` (a domain needs a
  dot, 3.5). No DNS is needed: librisala fetches no key files to sign in.
  The simulator reaches the Mac's `127.0.0.1`. For a phone, pass
  `--listen 0.0.0.0 --hostname <mac>.local`; the fingerprint stays.
- **What the protocol rules out:** room names are ASCII (3.5), so Arabic
  and mixed-direction text is in topics, display names and messages. A
  room the account was kicked from cannot be seeded, since SYNC lists
  only rooms the account is in (7.1): its owner waits on the server and
  kicks the account 5 s after it first comes online.
- `risala-cli` can sign in with `.dev/me.json`, so the library's side
  can be checked before the app's.

## 3. The bindings slice (`crates/librisala-ffi`)

UniFFI, with proc macros and its tokio async support, wrapping only:
`Client::open`, `import_device_key`, `add_identity`,
`accept_fingerprint`, `Account::start` and `subscribe`, `chat_list`,
`Conversation::timeline`, `send`, `mark_read`, `set_favourite`, and
`Account::remove_outbox`.

- **Retrying a failed message** has no library call yet: the outbox can
  only remove one. `Account::retry_outbox(id)` puts a failed entry back
  in the queue in its place, keeping its id, as the Swift `retry`
  already promises. It belongs to part A.

- **Build:** an XCFramework for iOS, the iOS simulator and macOS, with
  the generated Swift, as a local Swift package in
  `clients/apple/Librisala`. A Nix package builds every slice; for a
  quick edit loop, a command rebuilds only the host's slice.
- **Keys:** a key store in a file, for development. Keychain is M6.

## 4. The Apple app (`clients/apple`)

### The contract

`ChatClient.rooms()` becomes:

```swift
func chats(_ filter: ChatFilter, limit: Int) async throws -> ChatListSubscription
func servers() async throws -> ServerListSubscription
func setFavourite(_ isFavourite: Bool, for chatID: Chat.ID) async throws
```

`Room` becomes `Chat`, with the row fields above as Swift values (`Date`
for times, `Int` for counts, the label's name and uid as `name` and
`uid`), and `ChatListSubscription` mirrors `TimelineSubscription`:
`initial`, `counts` (`unreadChats` and `total`), `batches` and
`loadMore`. A new filter is a new subscription, so the adapter need not
expose `set_filter`. Timeline and chat list changes share one
`ListChange<Element>`. `timeline(in:)` takes a `Chat.ID`. The Rooms
feature becomes Chats.

`servers()` lists the accounts' servers and whether each is reachable:
the group switcher offers them, and rows on an unreachable one show the
offline glyph. The adapter builds it from `Client::accounts` and each
account's `ConnectionState`.

### Running against the development server

Only in Debug builds. A second scheme, "Risala Dev", sets
`RISALA_DEV=$(SRCROOT)/../../.dev/me.json`. When it is set, the app
opens a librisala cache in its own directory, imports the key, adds the
identity, accepts the fingerprint from the file and starts. The launch
argument `-ResetCache` clears that cache first.

### Previews

`clients/apple/Development/`, listed in `DEVELOPMENT_ASSET_PATHS`, holds
`PreviewChatClient`, behind `#if DEBUG`. It is an in-memory library
that filters, pages and reports changes as the library does, with the
scenarios `busy` and `worstCase` (the Paper mockups, row for row),
`arabic`, `many`, `empty`, `loading` and `failed`. They include direct
conversations, which the server cannot have before M5a. It stays apart
from `Tests/Support/TestClients.swift`, whose clients hold calls until
a test finishes them, which previews cannot use.

A Debug build launched with `-RisalaPreview <scenario>` runs on it, to
check a screen in the simulator without a server.

`AGENTS.md`'s "No demo data" becomes: no demo data in Release builds;
preview data lives in `Development/`.

## How the work is split

1. **In parallel:**
   - A. The library's chat list (section 1).
   - B. The development server and scenarios (section 2).
   - C. The Swift contract, the preview client and the chat list screen
     (section 4, without the development server).
2. **After A:** the bindings slice (section 3) and the Swift adapter
   over it, then the "Risala Dev" scheme.
3. **Then:** record the decisions in PLAN.md (section 5 item, and M6's
   row saying which part came forward).

## Later

- **Favourites** are local to each device. Syncing them between a
  person's devices would need the spec.
- **Several servers:** groups are servers, so `busy` should have two or
  three. That needs the library to reach names like `hackspace.test` at
  `127.0.0.1`: a development-only address override in `ClientOptions`.
- **Mentions** on rows (5.5): a count, or a flag, when the design asks
  for it.
- **The bindings stay UniFFI** for now (confirmed with the user on
  2026-11-08). A message bridge over a small C ABI was considered; switch
  if UniFFI's generated Swift fights the app's Swift 6 rules.

## The final design (2026-11-08)

The Apple app follows the Paper page "Exploration · Chat list v2" (F1, N1, N2, F2,
F3, K1, M3, and the typing indicator). It needs more from the library than section 1
gives, all through the chat list and a spaces subscription:

- **Identities:** each of the person's identities with a short label and a tint
  chosen on this device, which one is the main identity, and the person's guest
  names together as one. Every row and space names its identity.
- **Spaces:** each server an identity is on, with whether it is reachable, its count
  of unread chats and unread mentions, and whether it is a favourite. Favourite
  spaces have an order, set on this device.
- **Rows:** the count of unread mentions (5.5), who is typing (8.1), and for a
  direct conversation whether the other person is connected (8.3).
- **Filter:** mentions only, across every space.

Until then the Swift contract has these fields and `PreviewChatClient` fills them.

## Large screens (2026-11-08)

The iPad and the Mac follow the Paper boards L1 (iPad) and L2 (Mac). Decided with
the user:

- **Always panes:** the chat list pane beside a chat pane, under one bar across the
  window. Never a single full-window page, and no spaces sidebar, rail, or inspector.
- **The bar** holds the identity chips, then the same space tabs as the phone. On
  the Mac it shares the title bar with the window buttons.
- **Focus:** one pane has it and shows the mode: the list while its command line is
  open or no chat is, otherwise the chat. ⌘K opens the list's command line from
  anywhere; Escape leaves it.
- **No chat open** is one quiet line in the chat pane. Hudhud stays for having no
  chats at all, in the list pane.
- **Compact widths** (iPhone, Slide Over, a narrow split) keep the phone's layout.
  The Mac window never gets narrower than both panes.
- **Not yet:** splitting a pane, a mic, and attaching files. They stay out rather
  than show buttons that do nothing.

The timeline needs more from the library, through the timeline subscription and
the chat list. Until then the Swift contract has these fields and
`PreviewChatClient` fills them:

- **Messages:** the message a reply answers (its author and text), a thread's reply
  count and the time of its last reply, and an attachment's name, size, whether it
  is an image, and a thumbnail.
- **Timelines:** the first unread message when the timeline opens, for the "new"
  line.
- **Rooms:** how many people are connected now ("48 here").

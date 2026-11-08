//! The client API apps use (PLAN.md 3.3): [`Client`], [`Account`],
//! [`Conversation`], [`Timeline`] and [`ChatList`].
//!
//! # Shape
//!
//! - A [`Client`] owns the cache ([`Store`]) and knows every account, on
//!   any number of servers. It also handles trust (2.2):
//!   [`Client::probe`], [`Client::accept_fingerprint`] and
//!   [`Client::forget_trust`].
//! - An [`Account`] is a uid on a server: a guest (4.2) or an identity
//!   (4.3). [`Account::start`] runs it in the background:
//!   one task per account that keeps a connection up (the
//!   [`Supervisor`](crate::conn::Supervisor)), feeds every server line, in
//!   order, to a [`SyncEngine`](crate::sync::SyncEngine), and sends what
//!   the engine asks for. [`Account::subscribe`] reports what happens.
//! - A [`Conversation`] is a room or a direct conversation of an account.
//!   Reads ([`Conversation::messages`], [`Conversation::info`],
//!   [`Conversation::export`]) come straight from the cache and work with
//!   no connection. Sends go through the outbox (7.6), so a message
//!   written offline is sent once the account is back in the room.
//! - A [`Timeline`] is a window on a conversation's messages that tells
//!   the UI what changed, as [`TimelineDiff`]s: insert, update, remove,
//!   or reset.
//! - A [`ChatList`], from [`Client::chat_list`], is the same for the
//!   conversations of every account, newest activity first, as
//!   [`ChatSummary`] rows with their newest message, and
//!   [`ChatListDiff`]s. A [`ChatFilter`] picks a server and the toggles
//!   unread, favourites and rooms. Favourites are kept on this device
//!   only ([`Conversation::set_favourite`]).
//!
//! The API is made to cross an FFI boundary (UniFFI): handles are cheap
//! to clone and are used through `&self`, values are owned plain data
//! ([`types`]), names and addresses are strings, and changes arrive
//! through async `next()` calls rather than borrowed iterators.
//!
//! # Identities
//!
//! An identity account (4.3) signs in with this device's ML-DSA-44 key,
//! kept in [`ClientOptions::keys`] under the identity:
//!
//! - **Keys.** [`Client::create_device_key`] or
//!   [`Client::import_device_key`] (PEM, App. A), then
//!   [`Client::key_line`] for the line a self-hosted identity publishes
//!   in its key file at [`Client::key_file_url`] (4.4).
//! - **Signing in.** [`Client::add_identity`], then [`Account::connect`]
//!   (AUTH, 4.5). `auth-failed` is final: [`RefusedKind::AuthFailed`], or
//!   [`RefusedKind::KeyRemoved`] for a key the server accepted before.
//!   `unavailable`, when the server could not get the key file, is tried
//!   again with backoff: [`RefusedKind::Unavailable`].
//! - **Registering.** [`Client::register`] (4.6).
//! - **Hosted identities' keys.** [`Account::keys`], [`Account::add_key`]
//!   and [`Account::remove_key`] (4.7).
//! - **Deleting.** [`Account::unregister`] (4.8).
//!
//! The server's refusals are [`ClientError::Refused`] with a
//! [`RefusedKind`], and key store failures [`ClientError::Keys`].
//!
//! # People
//!
//! Read markers (7.4) move with [`Conversation::mark_read`] and
//! [`Conversation::mark_all_read`], and follow the account's other devices.
//! Display names, members, presence, typing and blocks (5.7, 8.1-8.3) are
//! methods of [`Account`] and [`Conversation`], with change events: see
//! `people.rs`, from [`Account::set_display_name`] on.
//!
//! # Rooms, reports and administration
//!
//! Room settings, roles, moderation, deleting and reports (5.4, 5.8,
//! 6.2-6.4) are methods of [`Conversation`] and [`Account`]: see
//! `rooms.rs`, from [`Conversation::set_setting`] on. An operator's ADMIN
//! commands (Section 10) are methods of [`Admin`], from [`Account::admin`].
//! NOTICE lines (8.4) arrive as [`Notice::Server`].
//!
//! # Order
//!
//! The sync engine needs every server line in the order it arrived, with
//! each reply at the point its final `OK` or `ERR` arrived (3.6,
//! "Consistent with live events"). The account task sends the engine's
//! commands with [`Session::send`](crate::conn::Session::send), and reads
//! lines and replies from one queue, so that order is kept.
//!
//! # Guests after a reconnect
//!
//! A guest's session outlives its connection for a while (4.2). The cache
//! keeps the name and token of the session the account last signed in to
//! ([`Store::guest_session`]), and each new connection, even from a later
//! run of the app, sends `GUEST <name> token=<token>` to resume it. A
//! resumed session is still in its rooms, and nothing is recorded. If the
//! session has ended and someone else has the name, the guest signs in as
//! `<name>2`, `<name>3` and so on, and that session's token is kept
//! instead. The account keeps its original uid either way. Events are
//! marked as the account's own when they are stored, by the uid of the
//! connection, so messages sent as `~sam2` do not count as unread for the
//! account `~sam`.
//!
//! GUEST's `OK` says whether the session was resumed (`resumed=yes`) or
//! is new.
//!
//! - **Rooms.** A session that ended has left its rooms. So for a guest
//!   account the client layer keeps the rooms the user joined (in the
//!   cache, [`Store::rejoin_rooms`]). After a new session it joins them all
//!   again, before the sync engine's SYNC, so that SYNC lists them. After a
//!   resumed session it joins none, since the session is still in them,
//!   and nothing is recorded. A room that can no longer be joined
//!   (`not-found` or `forbidden`) is taken off the list and reported as
//!   [`Notice::RejoinFailed`]. Parting a room, or being kicked or banned
//!   from it, or its being dropped, takes it off too. Turn this off with
//!   [`ClientOptions::rejoin_guest_rooms`]. Identities stay members across
//!   connections (6.1), so nothing is joined again for them.
//! - **Messages for its rooms.** Messages queued for a room on the list
//!   wait for it to be joined again. Messages for a room the guest left
//!   otherwise, by its own PART, a KICK, BAN or DROP, or while a resumed
//!   session was away, fail with [`FailKind::NotInRoom`], as an
//!   identity's do, and such a room comes off the list (PLAN.md 5, item
//!   37).
//! - **Messages without an answer.** After a resumed session, a guest's
//!   messages that were sent but not answered when the connection dropped
//!   are sent again with their cids, which carry over to the resumed
//!   session, so the server posts each at most once (7.6). After a new
//!   session the server no longer knows those cids, so a resend could
//!   post a message twice: they end as [`OutboxStatus::Failed`] with
//!   `maybe_sent` set.
//!
//! # Threads and the runtime
//!
//! A [`Client`] runs everything it does in the background on a tokio
//! runtime it holds: the one in [`ClientOptions::runtime`], or else the
//! one current when the client was made, or else a runtime of its own,
//! with a few worker threads, that lives as long as the client. So an app
//! may make a client, and call any method, from its main thread (Swift's
//! main actor, GTK's main loop) with no runtime around.
//!
//! - **Synchronous methods** ([`Account::start`],
//!   [`Account::conversations`], [`Conversation::messages`] and the like)
//!   may be called from any thread. Those that read the cache block for as
//!   long as one SQLite read takes. Reads use their own connection, so they
//!   never wait for a write (see [`Store`]). Still, call them off a UI
//!   thread when the cache may be large.
//! - **Async methods** may be awaited on any executor, not only tokio:
//!   their work runs on the client's runtime, and their futures only wait
//!   for it. SQLite work runs on the runtime's blocking threads.
//! - **Handles** ([`Client`], [`Account`], [`Conversation`]) are `Send`
//!   and `Sync`, and cheap to clone. [`Timeline`] and [`ChatList`] are
//!   `Send` and `Sync`; share one behind an `Arc`, since each change is
//!   returned by one [`next`](ChatList::next) call.
//!
//! Dropping the last handle to a client that made its own runtime stops
//! that runtime, without waiting for its tasks.
//!
//! # Other processes
//!
//! Another process may write to the same cache, such as an iOS
//! notification extension that syncs while the app sleeps. Subscribers
//! and timelines hear only of this process's writes. To pick up the
//! others', call [`Client::check_for_external_changes`] when it matters,
//! for example when the app comes to the foreground. It is cheap, and if
//! anything changed it resets every [`Timeline`] and [`ChatList`] and sends
//! [`AccountEvent::CacheChanged`] to subscribers, so the app reads its
//! conversation list again. [`Timeline::refresh`] resets one timeline
//! by hand.

mod account;
mod admin;
pub(crate) mod chats;
mod driver;
mod identity;
mod people;
mod rooms;
mod timeline;
pub mod types;
mod typing;

#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod people_tests;
#[cfg(test)]
mod rooms_tests;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use risala_proto::names::{Identity, Uid};

use crate::addr::{ServerAddr, TrustStore};
use crate::conn::keys::KeyStore;
use crate::conn::{Backoff, Session, SessionOptions};
use crate::store::{AccountId, Store};
use crate::sync::SyncConfig;

pub use account::{Account, AccountEvents, Conversation};
pub use admin::Admin;
pub use chats::{ChatList, ChatListBatch, ChatListDiff};
pub use people::PresenceWatch;
pub use timeline::{Timeline, TimelineDiff};
pub use types::{
    AccountEvent, AccountRef, BanInfo, ChatCounts, ChatFilter, ChatKind, ChatPreview, ChatSummary,
    ClientError, ConnectionErrorKind, ConnectionInfo, ConnectionState, ConversationInfo,
    ConversationPage, DEFAULT_PAGE, Delivery, DeviceKey, DisconnectKind, EventKind, FailKind,
    KeyErrorKind, KeyInfo, Label, MAX_PAGE, MemberInfo, Message, MessagePage, Notice, OutboxEntry,
    OutboxStatus, Presence, ReactionCount, RefusedKind, ReportInfo, ReportedMessage, Role,
    RoleInfo, RoomInfo, RoomList, RoomListing, ServerBanInfo, ServerHello, ServerInfo, Setting,
    TrustInfo, Unregistered, UserInfo,
};

use account::AccountShared;

/// How many batches of changes the client keeps for slow chat lists
/// before they miss some, and read everything again.
const CHAT_CAPACITY: usize = 4096;

/// Settings for a [`Client`].
#[derive(Clone)]
pub struct ClientOptions {
    /// Connection settings: the CA check, timeouts and keepalive. A
    /// `connect_to` address here applies to every server, which only tests
    /// want.
    pub session: SessionOptions,
    /// How long to wait between reconnects.
    pub backoff: Backoff,
    /// Sync settings: page sizes, when to fetch only the newest page, the
    /// resend window and the clock.
    pub sync: SyncConfig,
    /// Join a guest's rooms again after a reconnect, when its session was
    /// not resumed (4.2). See the [module docs](self). On by default.
    pub rejoin_guest_rooms: bool,
    /// Where identities' device keys are, for signing in (4.5). An app
    /// implements [`PlatformKeyStore`](crate::conn::keys::PlatformKeyStore)
    /// over its platform's store and passes it wrapped in
    /// [`PlatformKeys`](crate::conn::keys::PlatformKeys).
    pub keys: Option<Arc<dyn KeyStore>>,
    /// The tokio runtime to run on. `None`: the runtime current when the
    /// client is made, or else one of the client's own. See the [module
    /// docs](self).
    pub runtime: Option<tokio::runtime::Handle>,
}

impl Default for ClientOptions {
    fn default() -> ClientOptions {
        ClientOptions {
            session: SessionOptions::default(),
            backoff: Backoff::default(),
            sync: SyncConfig::default(),
            rejoin_guest_rooms: true,
            keys: None,
            runtime: None,
        }
    }
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("session", &self.session)
            .field("backoff", &self.backoff)
            .field("sync", &self.sync)
            .field("rejoin_guest_rooms", &self.rejoin_guest_rooms)
            .field("keys", &self.keys.as_ref().map(|_| ".."))
            .field("runtime", &self.runtime.as_ref().map(|_| ".."))
            .finish()
    }
}

/// The client: the cache, and every account on every server. See the
/// [module docs](self).
///
/// Cloning it is cheap; clones share everything.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

pub(crate) struct ClientInner {
    store: Store,
    options: ClientOptions,
    accounts: Mutex<HashMap<AccountId, Arc<AccountShared>>>,
    /// Every account's batches with changes to the cache, for chat lists.
    chats: tokio::sync::broadcast::Sender<Arc<account::Batch>>,
    /// Where the client's tasks run.
    rt: tokio::runtime::Handle,
    /// The cache's data version when last checked, for
    /// [`Client::check_for_external_changes`].
    data_version: Mutex<Option<u64>>,
    /// The runtime, if the client made its own. Declared last, so that it
    /// stops after everything else is dropped.
    _owned: Option<OwnedRuntime>,
}

/// A runtime the client made, stopped without waiting when the client goes,
/// so that dropping a client is fine even inside async code.
struct OwnedRuntime(Option<tokio::runtime::Runtime>);

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

impl Client {
    /// Opens the cache at `path`, creating it if needed.
    ///
    /// For M7 (bindings): this takes a `Path`; the FFI surface will want a
    /// string.
    pub fn open(path: &Path, options: ClientOptions) -> Result<Client, ClientError> {
        Client::with_store(Store::open(path)?, options)
    }

    /// A client with its cache in memory, for tests and short-lived tools.
    pub fn open_in_memory(options: ClientOptions) -> Result<Client, ClientError> {
        Client::with_store(Store::open_in_memory()?, options)
    }

    /// A client on a cache that is already open. Fails only if it needs a
    /// runtime of its own and cannot start one.
    pub fn with_store(store: Store, options: ClientOptions) -> Result<Client, ClientError> {
        let (rt, owned) = match options
            .runtime
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
        {
            Some(handle) => (handle, None),
            None => {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("librisala")
                    .enable_all()
                    .build()
                    .map_err(|e| ClientError::Connection {
                        kind: ConnectionErrorKind::Runtime,
                        message: format!("cannot start a runtime: {e}"),
                        permanent: true,
                    })?;
                (runtime.handle().clone(), Some(OwnedRuntime(Some(runtime))))
            }
        };
        let data_version = store.data_version()?;
        Ok(Client {
            inner: Arc::new(ClientInner {
                store,
                options,
                accounts: Mutex::new(HashMap::new()),
                chats: tokio::sync::broadcast::channel(CHAT_CAPACITY).0,
                rt,
                data_version: Mutex::new(data_version),
                _owned: owned,
            }),
        })
    }

    /// The runtime the client's tasks run on.
    pub(crate) fn runtime(&self) -> &tokio::runtime::Handle {
        &self.inner.rt
    }

    /// Checks whether another process wrote to the cache since the last
    /// check (or since the client was made), using SQLite's
    /// `PRAGMA data_version`. If so, every [`Timeline`] and [`ChatList`]
    /// resets, every account's subscribers get
    /// [`AccountEvent::CacheChanged`], each running account sends what its
    /// outbox holds that can go now, such as a message the other process
    /// queued, and this returns `true`.
    /// Writes by this client do not count. It never waits; while this
    /// client is writing, it returns `false` and the next call tells.
    pub fn check_for_external_changes(&self) -> Result<bool, ClientError> {
        let Some(now) = self.inner.store.data_version()? else {
            return Ok(false);
        };
        let changed = {
            let mut last = self.inner.data_version.lock().expect("poisoned");
            let changed = last.is_some_and(|v| v != now);
            *last = Some(now);
            changed
        };
        if changed {
            // Not through the accounts: a process may have a chat list
            // before it has a handle to any of them.
            self.reload_chat_lists();
            let accounts: Vec<Arc<AccountShared>> = self
                .inner
                .accounts
                .lock()
                .expect("poisoned")
                .values()
                .cloned()
                .collect();
            for shared in accounts {
                shared.publish(account::Batch {
                    changes: Vec::new(),
                    events: vec![AccountEvent::CacheChanged],
                    reload: true,
                });
                shared.resume_outbox();
            }
        }
        Ok(changed)
    }

    /// The cache.
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The settings.
    pub fn options(&self) -> &ClientOptions {
        &self.inner.options
    }

    /// Every account in the cache.
    pub fn accounts(&self) -> Result<Vec<Account>, ClientError> {
        let mut out = Vec::new();
        for (id, server, uid) in self.inner.store.accounts()? {
            out.push(self.handle(id, server, uid));
        }
        Ok(out)
    }

    /// The account for `uid` on `server`, if it is in the cache.
    pub fn account(&self, server: &str, uid: &str) -> Result<Option<Account>, ClientError> {
        let server = parse_server(server)?;
        let uid: Uid = uid
            .parse()
            .map_err(|_| ClientError::Invalid(format!("uid {uid:?}")))?;
        Ok(self
            .accounts()?
            .into_iter()
            .find(|a| a.shared().server == server && a.shared().uid == uid))
    }

    /// The guest account `~<name>` on `server` (4.2), added to the cache
    /// if new. It does not connect: call [`Account::start`] or
    /// [`Account::connect`].
    pub fn add_guest(&self, server: &str, name: &str) -> Result<Account, ClientError> {
        let name: risala_proto::names::Name = name
            .parse()
            .map_err(|_| ClientError::Invalid(format!("name {name:?}")))?;
        self.add_uid(server, Uid::guest(&name))
    }

    /// The account for the identity `identity` on `server` (4.3), added to
    /// the cache if new. It does not connect.
    ///
    /// Signing in needs this device's key for the identity in
    /// [`ClientOptions::keys`], stored under the identity, such as
    /// `alice@example.org`: see [`create_device_key`](Self::create_device_key)
    /// and [`import_device_key`](Self::import_device_key). The identity's
    /// key file must list it (4.4), or for an identity the server hosts,
    /// one of its signed-in devices must have added it
    /// ([`Account::add_key`], 4.7). A server given as an IP address cannot
    /// be signed in to as an identity (2.1); connecting then fails with
    /// [`RefusedKind::NoHostname`].
    pub fn add_identity(&self, server: &str, identity: &str) -> Result<Account, ClientError> {
        let identity: Identity = identity
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("identity {identity:?}")))?;
        self.add_uid(server, identity.to_uid())
    }

    pub(crate) fn add_uid(&self, server: &str, uid: Uid) -> Result<Account, ClientError> {
        let server = parse_server(server)?;
        let id = self.inner.store.account(&server, &uid)?;
        Ok(self.handle(id, server, uid))
    }

    /// The one handle per account, so that every [`Account`] for it shares
    /// its connection.
    fn handle(&self, id: AccountId, server: ServerAddr, uid: Uid) -> Account {
        let mut accounts = self.inner.accounts.lock().expect("poisoned");
        let shared = accounts
            .entry(id)
            .or_insert_with(|| {
                AccountShared::new(
                    id,
                    server,
                    uid,
                    self.inner.store.clone(),
                    self.inner.options.clone(),
                    self.inner.rt.clone(),
                    self.inner.chats.clone(),
                )
            })
            .clone();
        Account::new(self.clone(), shared)
    }

    /// Stops an account and removes it from the cache, with its
    /// conversations, history and outbox.
    pub async fn remove_account(&self, account: &Account) -> Result<(), ClientError> {
        account.disconnect().await;
        let id = account.id();
        self.inner.accounts.lock().expect("poisoned").remove(&id);
        let store = self.inner.store.clone();
        blocking(self.runtime(), move || {
            store.remove_account(id).map_err(ClientError::from)
        })
        .await?;
        // Its conversations leave every chat list.
        self.reload_chat_lists();
        Ok(())
    }

    /// Has every chat list read the cache again.
    fn reload_chat_lists(&self) {
        let reload = account::Batch {
            reload: true,
            ..account::Batch::default()
        };
        let _ = self.inner.chats.send(Arc::new(reload));
    }

    /// Connects to `server`, reads its greeting and closes again, to show
    /// the user who it is.
    ///
    /// A certificate that is not CA-valid and not yet trusted gives
    /// [`ClientError::UnknownCertificate`] with its fingerprint (2.2).
    /// Accepting it is [`accept_fingerprint`](Self::accept_fingerprint).
    pub async fn probe(&self, server: &str) -> Result<ServerHello, ClientError> {
        let addr = parse_server(server)?;
        let trust: Arc<dyn TrustStore> = Arc::new(self.inner.store.clone());
        let options = self.inner.options.session.clone();
        let connected = {
            let addr = addr.clone();
            self.runtime().spawn(async move {
                let session = Session::connect(&addr, trust, options).await?;
                let info = session.info().clone();
                let quit = session.quit("");
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), quit).await;
                Ok(info)
            })
        };
        let info = match connected.await {
            Ok(r) => r.map_err(|e| ClientError::from_conn(&addr.to_string(), &e))?,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(_) => return Err(ClientError::NotConnected),
        };
        Ok(ServerHello {
            server: addr.to_string(),
            host: info.greeting.host.to_string(),
            welcome: risala_proto::text::unescape(&info.greeting.message).into_owned(),
            fingerprint: info.verified.fingerprint.to_string(),
            trust: TrustInfo::from(&info.verified.record),
        })
    }

    /// How `server`'s certificate is trusted, if it is (2.2).
    pub fn trust(&self, server: &str) -> Result<Option<TrustInfo>, ClientError> {
        let addr = parse_server(server)?;
        let record = TrustStore::get(&self.inner.store, &addr)
            .map_err(|e| ClientError::Store(e.to_string()))?;
        Ok(record.as_ref().map(TrustInfo::from))
    }

    /// Records the fingerprint the user accepted for `server`, after
    /// [`ClientError::UnknownCertificate`] (2.2). It refuses to replace a
    /// different record, with [`ClientError::AlreadyTrusted`]: remove that
    /// first with [`forget_trust`](Self::forget_trust).
    pub fn accept_fingerprint(&self, server: &str, fingerprint: &str) -> Result<(), ClientError> {
        let addr = parse_server(server)?;
        let fp = fingerprint
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("fingerprint {fingerprint:?}")))?;
        match crate::conn::accept_fingerprint(&self.inner.store, &addr, fp) {
            Ok(()) => Ok(()),
            Err(crate::conn::Error::Trust(crate::conn::TrustError::Mismatch {
                recorded, ..
            })) => Err(ClientError::AlreadyTrusted {
                server: addr.to_string(),
                recorded: types::show_record(&recorded),
            }),
            Err(e) => Err(ClientError::from_conn(&addr.to_string(), &e)),
        }
    }

    /// Removes the trust record for `server`, as the user must do
    /// explicitly after [`ClientError::CertificateMismatch`] (2.2).
    pub fn forget_trust(&self, server: &str) -> Result<(), ClientError> {
        let addr = parse_server(server)?;
        TrustStore::forget(&self.inner.store, &addr).map_err(|e| ClientError::Store(e.to_string()))
    }

    /// Stops every running account, closing their connections.
    pub async fn shutdown(&self) {
        let accounts: Vec<Arc<AccountShared>> = self
            .inner
            .accounts
            .lock()
            .expect("poisoned")
            .values()
            .cloned()
            .collect();
        for shared in accounts {
            Account::new(self.clone(), shared).disconnect().await;
        }
    }
}

/// Parses a server address such as `chat.example.org` or `host:7000`.
pub(crate) fn parse_server(server: &str) -> Result<ServerAddr, ClientError> {
    server
        .trim()
        .parse()
        .map_err(|_| ClientError::Invalid(format!("server address {server:?}")))
}

/// Runs blocking work (SQLite) on the runtime's blocking threads. The
/// future may be awaited on any executor.
///
/// If the runtime has shut down, the work runs on the calling thread.
pub(crate) async fn blocking<T: Send + 'static>(
    rt: &tokio::runtime::Handle,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let f = Arc::new(Mutex::new(Some(f)));
    let task = {
        let f = f.clone();
        rt.spawn_blocking(move || f.lock().expect("poisoned").take().map(|f| f()))
    };
    match task.await {
        Ok(Some(t)) => t,
        Ok(None) => unreachable!("the work runs once"),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Cancelled: the runtime shut down before it ran.
        Err(_) => {
            let f = f.lock().expect("poisoned").take().expect("not run");
            f()
        }
    }
}

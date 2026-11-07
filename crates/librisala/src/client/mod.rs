//! The client API apps use (PLAN.md 3.3): [`Client`], [`Account`],
//! [`Conversation`] and [`Timeline`].
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
//!
//! The API is made to cross an FFI boundary (UniFFI): handles are cheap
//! to clone and are used through `&self`, values are owned plain data
//! ([`types`]), names and addresses are strings, and changes arrive
//! through async `next()` calls rather than borrowed iterators.
//!
//! # Order
//!
//! The sync engine needs every server line in the order it arrived, with
//! each reply at the point its final `OK` or `ERR` arrived (3.6,
//! "Consistent with live events"). The account task sends the engine's
//! commands with [`Session::send`](crate::conn::Session::send), and reads
//! lines and replies from one queue, so that order is kept.
//!
//! # Guests and rooms after a reconnect
//!
//! Guests leave all their rooms when they disconnect (4.2). So for a
//! guest account the client layer keeps the rooms the user joined (in the
//! cache, [`Store::rejoin_rooms`]) and joins them again on every new
//! connection, before SYNC, so that SYNC already lists them. A room that
//! can no longer be joined (`not-found` or `forbidden`) is taken off the
//! list and reported as [`Notice::RejoinFailed`]. Parting a room, or
//! being kicked or banned from it, or its being dropped, takes it off
//! too. Turn this off with [`ClientOptions::rejoin_guest_rooms`].
//! Identities stay members across connections (6.1), so nothing is
//! joined again for them.
//!
//! A guest's messages that were sent but not answered when the
//! connection dropped are not sent again: the server checks a guest's
//! cids only within one connection (7.6). They end as
//! [`OutboxStatus::Failed`] with `maybe_sent` set.
//!
//! # Blocking
//!
//! The cache is SQLite. The synchronous reads ([`Account::conversations`],
//! [`Conversation::messages`] and so on) block briefly; call them off a
//! UI thread. The async methods do their SQLite work on tokio's blocking
//! threads.

mod account;
mod driver;
mod timeline;
pub mod types;

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
pub use timeline::{Timeline, TimelineDiff};
pub use types::{
    AccountEvent, ClientError, ConnectionState, ConversationInfo, EventKind, Message, Notice,
    OutboxEntry, OutboxStatus, ReactionCount, RoomList, RoomListing, ServerHello, TrustInfo,
};

use account::AccountShared;

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
    /// Join a guest's rooms again after each reconnect (4.2). See the
    /// [module docs](self). On by default.
    pub rejoin_guest_rooms: bool,
    /// Where identities' device keys are, for signing in (4.5).
    pub keys: Option<Arc<dyn KeyStore>>,
}

impl Default for ClientOptions {
    fn default() -> ClientOptions {
        ClientOptions {
            session: SessionOptions::default(),
            backoff: Backoff::default(),
            sync: SyncConfig::default(),
            rejoin_guest_rooms: true,
            keys: None,
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
}

impl Client {
    /// Opens the cache at `path`, creating it if needed.
    pub fn open(path: impl AsRef<Path>, options: ClientOptions) -> Result<Client, ClientError> {
        Ok(Client::with_store(Store::open(path)?, options))
    }

    /// A client with its cache in memory, for tests and short-lived tools.
    pub fn open_in_memory(options: ClientOptions) -> Result<Client, ClientError> {
        Ok(Client::with_store(Store::open_in_memory()?, options))
    }

    /// A client on a cache that is already open.
    pub fn with_store(store: Store, options: ClientOptions) -> Client {
        Client {
            inner: Arc::new(ClientInner {
                store,
                options,
                accounts: Mutex::new(HashMap::new()),
            }),
        }
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
        self.add(server, Uid::guest(&name))
    }

    /// The account for the identity `identity` on `server` (4.3), added to
    /// the cache if new. Signing in needs its device key in
    /// [`ClientOptions::keys`], stored under the identity, such as
    /// `alice@example.org`.
    pub fn add_identity(&self, server: &str, identity: &str) -> Result<Account, ClientError> {
        let identity: Identity = identity
            .parse()
            .map_err(|_| ClientError::Invalid(format!("identity {identity:?}")))?;
        self.add(server, identity.to_uid())
    }

    fn add(&self, server: &str, uid: Uid) -> Result<Account, ClientError> {
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
        blocking(move || store.remove_account(id).map_err(ClientError::from)).await
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
        let session = Session::connect(&addr, trust, self.inner.options.session.clone())
            .await
            .map_err(|e| ClientError::from_conn(&addr.to_string(), &e))?;
        let info = session.info().clone();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), session.quit("")).await;
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
    /// different record: remove that first with
    /// [`forget_trust`](Self::forget_trust).
    pub fn accept_fingerprint(&self, server: &str, fingerprint: &str) -> Result<(), ClientError> {
        let addr = parse_server(server)?;
        let fp = fingerprint
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("fingerprint {fingerprint:?}")))?;
        crate::conn::accept_fingerprint(&self.inner.store, &addr, fp)
            .map_err(|e| ClientError::from_conn(&addr.to_string(), &e))
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

/// Runs blocking work (SQLite) on tokio's blocking threads.
pub(crate) async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(t) => t,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

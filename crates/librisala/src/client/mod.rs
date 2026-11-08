//! The client API apps use (PLAN.md 3.4): [`Client`] and the values it
//! hands out.
//!
//! # Shape
//!
//! A [`Client`] owns the cache ([`Store`]), the platform key store
//! ([`ClientOptions::keys`]) and the accounts' connections. It is cheap to
//! clone and used through `&self`. Values are owned plain data, and
//! changes arrive as [`Event`]s from [`Client::subscribe`], so that the
//! API can cross an FFI boundary (UniFFI). Reads come from the cache and
//! work offline; operations that need the server are `async`.
//!
//! Each area of the API is an `impl Client` block in a module of its own,
//! with its value types, so that the area tasks of docs/plans/M5b.md can
//! fill them in at the same time. Until they do, their methods return
//! [`Error::NotImplemented`].
//!
//! | Module | Task | What |
//! |---|---|---|
//! | [`servers`] | C0 | trust records and pins (2.2), server information (8.5) |
//! | [`accounts`] | C0 | identity and guest accounts on servers (4.1, 4.2) |
//! | [`driver`] | C2 | running an account's connections and engines |
//! | [`identity`] | C1 | identities, devices, pairing, recovery, safety numbers, key logs (4.3-4.9, 12.14) |
//! | [`conversations`] | C2 | conversations, rooms, members, roles, profiles, blocks, presence (5, 6, 8) |
//! | [`messages`] | C2 | messages, deletes, typing, read markers (5.3, 5.4, 7.7, 8.1) |
//! | [`confirm`] | C3 | which leaves are confirmed (12.10) |
//! | [`files`] | C4 | files (5.6, 12.11) |
//! | [`backups`] | C4 | history transfer and backups (12.13) |
//! | [`push`] | C4 | push notifications (Section 9) |
//! | [`reports`] | C4 | reports (5.8) |
//!
//! Shared values are in [`types`], errors in [`Error`] (with one variant
//! per area for the area's own errors), and events in [`Event`].
//!
//! # Accounts and connections
//!
//! An identity this device holds has an account on each server it uses:
//! one signed-in connection there for what belongs to the account, and
//! anonymous connections for its conversations (4.1). A guest has an
//! account with one guest connection (4.2). Connections are never shared
//! between accounts, so the server cannot link two identities of one
//! device by them. See [`crate::conn::ServerConnections`].

pub mod accounts;
pub mod backups;
pub mod confirm;
pub mod conversations;
pub mod driver;
mod error;
mod event;
pub mod files;
pub mod identity;
pub mod messages;
pub mod push;
pub mod reports;
pub mod servers;
pub mod types;

use std::path::Path;
use std::sync::Arc;

use tokio::sync::broadcast;

use crate::clock::{Clock, SystemClock};
use crate::conn::{Backoff, CaVerifier, SessionOptions};
use crate::keys::{KeyStore, MemoryKeyStore};
use crate::store::{DatabaseKey, Store};

pub use error::{Error, Result};
pub use event::{ConnectionEvent, ConnectionState, Event};

/// Settings for a [`Client`].
#[derive(Clone)]
pub struct ClientOptions {
    /// Where this device's secret keys are kept (PLAN.md 3.4).
    pub keys: Arc<dyn KeyStore>,
    /// The CA check for rule 1 of 2.2. `None` uses the platform's,
    /// loaded once when the first connection opens.
    pub ca_verifier: Option<CaVerifier>,
    /// Settings for each connection. Its `ca_verifier` is replaced by the
    /// one above.
    pub session: SessionOptions,
    /// How to wait between reconnects.
    pub backoff: Backoff,
    /// How many anonymous connections an identity keeps to each server it
    /// uses, at least one (4.1).
    pub anonymous_connections: usize,
    /// The time.
    pub clock: Arc<dyn Clock>,
    /// HTTPS fetches of key files and key logs (4.4, 4.5). `None` uses
    /// `risala-keyfetch` with `ca_verifier`, or the platform's CA check.
    pub https: Option<Arc<dyn identity::Https>>,
}

impl Default for ClientOptions {
    /// Keys in memory, the platform's CA check, one anonymous connection
    /// per server and the system clock.
    fn default() -> Self {
        ClientOptions {
            keys: Arc::new(MemoryKeyStore::default()),
            ca_verifier: None,
            session: SessionOptions::default(),
            backoff: Backoff::default(),
            anonymous_connections: 1,
            clock: Arc::new(SystemClock),
            https: None,
        }
    }
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("session", &self.session)
            .field("backoff", &self.backoff)
            .field("anonymous_connections", &self.anonymous_connections)
            .finish_non_exhaustive()
    }
}

/// How many events may wait for a slow subscriber before it misses some
/// ([`broadcast::error::RecvError::Lagged`]); it then reads the state
/// again from the cache.
const EVENT_CAPACITY: usize = 1024;

/// The client. See the [module docs](self).
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    options: ClientOptions,
    events: broadcast::Sender<Event>,
    /// The accounts' running connections and engines (task C2).
    running: driver::Running,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("options", &self.inner.options)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Opens the client with its cache at `path`, encrypted with `key`
    /// (see [`Store::open`]).
    pub fn open(
        path: impl AsRef<Path>,
        key: &DatabaseKey,
        options: ClientOptions,
    ) -> Result<Client> {
        Ok(Client::with_store(Store::open(path, key)?, options))
    }

    /// A client with its cache in memory, for tests and short-lived
    /// tools.
    pub fn open_in_memory(options: ClientOptions) -> Result<Client> {
        Ok(Client::with_store(Store::open_in_memory()?, options))
    }

    /// A client on a cache already open.
    pub fn with_store(store: Store, options: ClientOptions) -> Client {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Client {
            inner: Arc::new(Inner {
                store,
                options,
                events,
                running: driver::Running::default(),
            }),
        }
    }

    /// The cache.
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The options the client was opened with.
    pub fn options(&self) -> &ClientOptions {
        &self.inner.options
    }

    /// Events from now on, for the UI. A subscriber that falls more than
    /// 1024 events behind misses some, and should read what it shows again
    /// from the cache.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Sends an event to every subscriber. Having none is fine.
    pub(crate) fn emit(&self, event: Event) {
        let _ = self.inner.events.send(event);
    }

    /// The accounts' running connections, for the driver.
    pub(crate) fn running(&self) -> &driver::Running {
        &self.inner.running
    }

    /// Runs a blocking call, such as one on the cache or the key store,
    /// off the async runtime's workers.
    pub(crate) async fn blocking<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Client) -> Result<T> + Send + 'static,
    {
        let client = self.clone();
        tokio::task::spawn_blocking(move || f(&client))
            .await
            .map_err(|e| Error::Internal(format!("a blocking task failed: {e}")))?
    }
}

#[cfg(test)]
mod tests;

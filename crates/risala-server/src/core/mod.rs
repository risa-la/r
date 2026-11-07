//! The hub: everything that happens after a line has been parsed.
//!
//! Implements [`crate::handler::Handler`]. Owned by task A in
//! docs/plans/M2-M5.md.
//!
//! The [`Hub`] owns all state, makes every check and does all fan-out.
//! Persistent state lives in a [`Store`]; what lasts only as long as a
//! connection (guests, their memberships and cids) lives in memory.
//!
//! # Ordering
//!
//! Each room has an async lock. Appending an event to a room happens under
//! it: the seq is assigned and the event stored in one store transaction,
//! and then, still under the lock, the event is queued for every
//! connection of every member. So every connection receives a room's
//! events in seq order (5.2), and an event is sent only once it is stored,
//! so seqs never have gaps (5.2, PLAN.md 3.2). A command queues its own
//! final response after the events it caused, so its sender gets them
//! first (3.6).
//!
//! Each command runs in its own task, holding its connection's gate. The
//! clean-up after a connection closes takes the gate too, so it waits for
//! a command in progress, and a command finishes even if the network layer
//! stops waiting for it.

mod commands;
mod state;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;

use risala_proto::auth::Nonce;
use risala_proto::names::Room;
use risala_proto::server::{Greeting, Host, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::{MAX_WELCOME, ServerRetention};

use crate::config::Config;
use crate::handler::{ConnHandle, ConnId, ConnInfo, Handler};
use crate::store::{self, ServerSettings, SqliteStore, Store, StoreError};

use state::{ConnEntry, Registry, RoomEntry};

/// The number of random bytes in a greeting's nonce (4.1).
pub const NONCE_BYTES: usize = 32;

/// Where the hub gets the time from. Replace it in tests where timing
/// matters.
pub trait Clock: Send + Sync + 'static {
    /// The current time, as stamped on events (3.2).
    fn now(&self) -> Timestamp;
}

/// The system clock, through [`Timestamp::now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// A clock that moves only when told to, for tests.
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock stopped at `t`.
    pub fn new(t: Timestamp) -> ManualClock {
        ManualClock(AtomicU64::new(t.unix_millis()))
    }

    /// Sets the time.
    pub fn set(&self, t: Timestamp) {
        self.0.store(t.unix_millis(), Ordering::SeqCst);
    }

    /// Moves the time forward.
    pub fn advance(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.load(Ordering::SeqCst)).unwrap_or(Timestamp::MAX)
    }
}

impl<C: Clock> Clock for Arc<C> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

/// An error starting the hub.
#[derive(Debug, thiserror::Error)]
pub enum HubError {
    /// The store could not be opened or read.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The state directory could not be created.
    #[error("creating {path}: {source}")]
    Io {
        /// The directory.
        path: std::path::PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// A value in the configuration is not valid.
    #[error("configuration: {0}")]
    Config(String),
}

/// The core of the server. Implements [`Handler`].
///
/// Cheap to clone: clones share the same state.
#[derive(Clone)]
pub struct Hub {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("hostname", &self.inner.config.hostname)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Inner {
    config: Config,
    store: Arc<dyn Store>,
    clock: Arc<dyn Clock>,
    settings: RwLock<ServerSettings>,
    rooms: RwLock<BTreeMap<Room, Arc<RoomEntry>>>,
    reg: Mutex<Registry>,
    sign_in_timeout: Duration,
}

impl Hub {
    /// Opens the SQLite database at [`Config::database_path`], creating the
    /// state directory if needed, and starts the hub on it.
    ///
    /// This blocks while the database opens. In async code, call it from
    /// `spawn_blocking`.
    pub fn open(config: Config) -> Result<Hub, HubError> {
        std::fs::create_dir_all(&config.state_dir).map_err(|source| HubError::Io {
            path: config.state_dir.clone(),
            source,
        })?;
        let store = SqliteStore::open(&config.database_path())?;
        Hub::new(config, store)
    }

    /// Starts the hub on `store`.
    ///
    /// - The server settings (10.6) come from the store. Settings it does
    ///   not have yet come from `config.server`.
    /// - The rooms in `config.rooms` are created if missing, with no owner
    ///   and no events.
    ///
    /// This blocks while it reads the store. In async code, call it from
    /// `spawn_blocking`.
    pub fn new(config: Config, store: impl Store) -> Result<Hub, HubError> {
        Hub::with_clock(config, store, SystemClock)
    }

    /// [`Hub::new`] with a clock of your choosing.
    pub fn with_clock(
        config: Config,
        store: impl Store,
        clock: impl Clock,
    ) -> Result<Hub, HubError> {
        let timeout = Duration::from_secs(config.limits.sign_in_secs);
        Hub::build(config, Arc::new(store), Arc::new(clock), timeout)
    }

    pub(crate) fn build(
        config: Config,
        store: Arc<dyn Store>,
        clock: Arc<dyn Clock>,
        sign_in_timeout: Duration,
    ) -> Result<Hub, HubError> {
        let retention: ServerRetention = config.server.retention.parse().map_err(|e| {
            HubError::Config(format!(
                "server.retention {:?}: {e}",
                config.server.retention
            ))
        })?;
        if !valid_welcome(&config.server.welcome) {
            return Err(HubError::Config(format!(
                "server.welcome must be escaped text of at most {MAX_WELCOME} bytes"
            )));
        }
        if config.hostname.parse::<Host>().is_err() {
            return Err(HubError::Config(format!(
                "hostname {:?} is not a hostname",
                config.hostname
            )));
        }
        let defaults = ServerSettings {
            guests: config.server.guests,
            registration: false,
            retention,
            welcome: config.server.welcome.clone(),
        };
        let mut settings = store.load_server_settings(&defaults)?;
        if !valid_welcome(&settings.welcome) {
            tracing::error!("the stored welcome text is not valid; sending none");
            settings.welcome.clear();
        }

        let now = clock.now();
        for name in &config.rooms {
            let room: Room = name
                .parse()
                .map_err(|e| HubError::Config(format!("room {name:?}: {e}")))?;
            store.ensure_room(&room, now)?;
        }
        if let Some(before) = now.checked_sub(Duration::from_millis(store::CID_WINDOW_MS)) {
            store.prune_cids(before)?;
        }

        let mut reg = Registry::default();
        let mut rooms = BTreeMap::new();
        for record in store.rooms()? {
            for uid in &record.members {
                reg.add_member(&record.room, uid);
            }
            rooms.insert(record.room.clone(), Arc::new(RoomEntry::new(record)));
        }
        tracing::info!(rooms = rooms.len(), "hub started");

        Ok(Hub {
            inner: Arc::new(Inner {
                config,
                store,
                clock,
                settings: RwLock::new(settings),
                rooms: RwLock::new(rooms),
                reg: Mutex::new(reg),
                sign_in_timeout,
            }),
        })
    }

    /// The configuration the hub was started with.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }
}

/// Whether `welcome` fits in a greeting (4.1).
fn valid_welcome(welcome: &str) -> bool {
    let greeting = Greeting {
        version: risala_proto::PROTOCOL_VERSION,
        host: "localhost".parse().expect("a valid host"),
        nonce: Nonce::from_bytes(&[0; NONCE_BYTES]).expect("a valid nonce"),
        message: welcome.to_owned(),
    };
    ServerMessage::new(greeting).try_to_line().is_ok()
}

impl Inner {
    fn reg(&self) -> MutexGuard<'_, Registry> {
        // Nothing that panics while holding the lock leaves the registry
        // half-changed in a way that matters more than stopping the server.
        self.reg.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn settings(&self) -> ServerSettings {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn room_entry(&self, room: &Room) -> Option<Arc<RoomEntry>> {
        self.rooms
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(room)
            .cloned()
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Runs a store call on the blocking pool.
    async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn Store) -> store::Result<T> + Send + 'static,
    ) -> store::Result<T> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || f(&*store))
            .await
            .map_err(|e| StoreError::Task(e.to_string()))?
    }

    /// Sends the greeting (4.1), registers the connection and starts its
    /// sign-in timer.
    fn open(self: &Arc<Self>, info: ConnInfo, handle: ConnHandle) {
        let id = handle.id();
        let mut bytes = [0u8; NONCE_BYTES];
        if let Err(e) = getrandom::fill(&mut bytes) {
            tracing::error!(conn = id.0, "no random nonce: {e}");
            handle.close(Some("internal error".into()));
            return;
        }
        let nonce = Nonce::from_bytes(&bytes).expect("32 bytes make a nonce");
        let host = info
            .sni
            .as_deref()
            .and_then(|sni| sni.parse::<Host>().ok())
            .unwrap_or_else(|| {
                self.config
                    .hostname
                    .parse()
                    .expect("hostname checked at start")
            });
        handle.send(ServerMessage::new(Greeting {
            version: risala_proto::PROTOCOL_VERSION,
            host: host.clone(),
            nonce: nonce.clone(),
            message: self.settings().welcome,
        }));
        tracing::debug!(conn = id.0, peer = %info.peer, "connection opened");

        let timer = tokio::runtime::Handle::try_current().ok().map(|rt| {
            let weak: Weak<Inner> = Arc::downgrade(self);
            let timeout = self.sign_in_timeout;
            rt.spawn(async move {
                tokio::time::sleep(timeout).await;
                if let Some(inner) = weak.upgrade() {
                    inner.sign_in_expired(id);
                }
            })
            .abort_handle()
        });
        let mut reg = self.reg();
        reg.conns.insert(
            id,
            ConnEntry {
                handle,
                info,
                host: host.to_string(),
                nonce,
                uid: None,
                gate: Arc::default(),
                guest_cids: Default::default(),
                sign_in_timer: timer,
            },
        );
    }

    /// Closes a connection that has not signed in in time (4.1).
    fn sign_in_expired(&self, id: ConnId) {
        let reg = self.reg();
        if let Some(conn) = reg.conns.get(&id)
            && conn.uid.is_none()
        {
            tracing::debug!(conn = id.0, "sign-in timeout");
            conn.handle.close(Some("sign-in timeout".into()));
        }
    }

    /// Cleans up after a connection: a guest leaves its rooms (4.2) and
    /// gives up its name.
    async fn closed(self: Arc<Self>, id: ConnId) {
        let Some(gate) = self.reg().conns.get(&id).map(|c| c.gate.clone()) else {
            return;
        };
        let _gate = gate.lock().await;
        let Some(conn) = self.reg().conns.remove(&id) else {
            return;
        };
        if let Some(timer) = conn.sign_in_timer {
            timer.abort();
        }
        tracing::debug!(conn = id.0, "connection closed");
        let Some(uid) = conn.uid else {
            return;
        };
        if uid.is_guest() {
            let rooms: Vec<Room> = self
                .reg()
                .rooms_of
                .get(&uid)
                .map(|r| r.iter().cloned().collect())
                .unwrap_or_default();
            for room in rooms {
                self.guest_part(&room, &uid).await;
            }
        }
        let mut reg = self.reg();
        if let Some(conns) = reg.users.get_mut(&uid) {
            conns.retain(|c| *c != id);
            if conns.is_empty() {
                reg.users.remove(&uid);
            }
        }
    }
}

impl Handler for Hub {
    fn open(&self, info: ConnInfo, conn: ConnHandle) {
        self.inner.open(info, conn);
    }

    fn command(
        &self,
        conn: ConnId,
        req: risala_proto::command::Request,
    ) -> impl Future<Output = ()> + Send {
        let inner = self.inner.clone();
        async move {
            let Some(gate) = inner.reg().conns.get(&conn).map(|c| c.gate.clone()) else {
                return;
            };
            // In its own task, so that it runs to the end even if the caller
            // stops waiting.
            let task = tokio::spawn(async move {
                let _gate = gate.lock().await;
                inner.command(conn, req).await;
            });
            if let Err(e) = task.await {
                tracing::error!(conn = conn.0, "command task failed: {e}");
            }
        }
    }

    fn closed(&self, conn: ConnId) -> impl Future<Output = ()> + Send {
        let inner = self.inner.clone();
        async move {
            let task = tokio::spawn(inner.closed(conn));
            if let Err(e) = task.await {
                tracing::error!(conn = conn.0, "clean-up task failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests;

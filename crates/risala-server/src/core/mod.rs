//! The hub: everything that happens after a line has been parsed
//! (draft-03).
//!
//! Implements [`crate::handler::Handler`]. The [`Hub`] holds the store,
//! the registry of connections and every area's state, checks each
//! command's kind of connection, and routes it to its area.
//!
//! # Layout
//!
//! - [`command`](self::command): [`Cx`](command::Cx), what a handler
//!   gets, and the routing table from commands to areas.
//! - `state`: the registry of connections, their kinds (4.1) and guest
//!   sessions, and the per-connection state of every area.
//! - `session`: the greeting, ANON and GUEST, guest sessions and GONE
//!   (4.1, 4.2), PING, PONG and QUIT (11), and clean-up after a
//!   connection closes.
//! - One module per area, each with its commands' handlers, its own
//!   state ([`State`](identity::State), loaded at start), its own
//!   per-connection state ([`ConnState`](identity::ConnState)), a hook for
//!   closed connections and a background task (`maintain`):
//!   - [`identity`]: AUTH, REGISTER, KEYS PUT, PAIR, UNREGISTER, ADMIN
//!     UNREGISTER, hosted key files (4.6-4.9, 10.5).
//!   - [`keylog`]: the key log (4.5), which has no commands.
//!   - [`mailbox`]: CREATE, POST, GROUPINFO, MUTE, UNMUTE, FOLLOW,
//!     UNFOLLOW, FETCH, TOKEN, GONE and DROP lines, moves, retention
//!     (5.2, 6.1, 6.4, 7).
//!   - [`keys`]: KEYPKG, WELCOME, BLOB, BACKUP, UPLOAD (5.6, 12.5, 12.8,
//!     12.12, 12.13).
//!   - [`misc`]: INFO, LIST, PRESENCE, WATCH, WHOIS, MEMBERS, PUSH,
//!     REPORT, RESOLVE (5.8, 6.1, 8, 9).
//!   - [`admin`]: the ADMIN commands but ADMIN UNREGISTER (Section 10),
//!     operators and bans.
//! - `rate`: limits over a sliding window, for any area.
//!
//! # Concurrency
//!
//! Each command runs in its own task, holding its connection's gate, so a
//! connection's commands run one at a time and in order (3.6), and a
//! command finishes even if the network layer stops waiting for it. The
//! clean-up after a connection closes takes the gate too. The registry is
//! behind a plain mutex, never held across an `await` (see `state`).
//! Store calls run on the blocking pool ([`Inner::db`]).

pub(crate) mod admin;
pub(crate) mod command;
pub(crate) mod identity;
pub(crate) mod keylog;
pub(crate) mod keys;
pub(crate) mod mailbox;
pub(crate) mod misc;
pub(crate) mod rate;
mod session;
pub(crate) mod state;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use risala_proto::auth::Nonce;
use risala_proto::names::{Domain, Name, Uid};
use risala_proto::server::{Greeting, Host, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::Retention;

use crate::config::{Config, ConfigError};
use crate::handler::{ConnHandle, ConnId, ConnInfo, Handler};
use crate::keyfiles::KeyServices;
use crate::store::{self, ServerSettings, SqliteStore, Store, StoreError};
use state::Registry;

pub use identity::{BYE_KEYS_CHANGED, BYE_UNREGISTERED, HostedKeyFile, PAIR_LIFETIME};
pub use session::{BYE_RESUMED, BYE_SHUTDOWN, BYE_SIGN_IN_TIMEOUT, NONCE_BYTES, TOKEN_LEN};

/// Where the hub gets the time from. Replace it in tests where timing
/// matters.
pub trait Clock: Send + Sync + 'static {
    /// The current time, as stamped on posts (3.2).
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

/// A clock that moves only when told to, for tests, until
/// [`follow_system`](Self::follow_system) lets it run.
#[derive(Debug)]
pub struct ManualClock {
    /// The time it is stopped at, in ms since the Unix epoch.
    ms: AtomicU64,
    /// Whether it follows the system clock.
    follows: AtomicBool,
}

impl ManualClock {
    /// A clock stopped at `t`.
    pub fn new(t: Timestamp) -> ManualClock {
        ManualClock {
            ms: AtomicU64::new(t.unix_millis()),
            follows: AtomicBool::new(false),
        }
    }

    /// Sets the time.
    pub fn set(&self, t: Timestamp) {
        self.ms.store(t.unix_millis(), Ordering::SeqCst);
    }

    /// Moves the time forward.
    pub fn advance(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        self.ms.fetch_add(ms, Ordering::SeqCst);
    }

    /// From now on, the time is the system clock's, but never earlier than
    /// the time the clock was stopped at, so it does not go back.
    pub fn follow_system(&self) {
        self.follows.store(true, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        let stopped =
            Timestamp::from_unix_millis(self.ms.load(Ordering::SeqCst)).unwrap_or(Timestamp::MAX);
        if self.follows.load(Ordering::SeqCst) {
            stopped.max(Timestamp::now())
        } else {
            stopped
        }
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

/// The hub's timers, which tests may shorten below what the configuration
/// allows.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timers {
    /// How long a new connection has to choose a kind (4.1).
    pub(crate) sign_in: Duration,
    /// How long a guest session waits to be resumed (4.2).
    pub(crate) guest_resume: Duration,
    /// How long after an identity's last connection closes it is reported
    /// offline (8.3).
    pub(crate) presence_offline: Duration,
    /// How long presence changes are collected before they are sent (8.3).
    pub(crate) presence_batch: Duration,
}

impl Timers {
    pub(crate) fn from_config(config: &Config) -> Timers {
        let l = &config.limits;
        Timers {
            sign_in: Duration::from_secs(l.sign_in_secs),
            guest_resume: Duration::from_secs(l.guest_resume_secs),
            presence_offline: Duration::from_secs(l.presence_offline_secs),
            presence_batch: Duration::from_millis(l.presence_batch_ms),
        }
    }
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

/// Everything the hub holds. Areas reach it through
/// [`Cx::inner`](command::Cx::inner).
#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
pub(crate) struct Inner {
    /// The configuration the hub started with.
    pub(crate) config: Config,
    /// The store.
    pub(crate) store: Arc<dyn Store>,
    /// The time.
    pub(crate) clock: Arc<dyn Clock>,
    /// The timers.
    pub(crate) timers: Timers,
    /// Fetching key files, and publishing hosted ones (4.4, 4.7).
    pub(crate) key_files: KeyServices,
    /// The identity domain (4.7), if the server hosts identities.
    pub(crate) identity_domain: Option<Domain>,
    /// The server settings (10.6).
    settings: RwLock<ServerSettings>,
    /// Connections and guest sessions.
    reg: Mutex<Registry>,
    /// Each area's own state.
    pub(crate) identity: identity::State,
    pub(crate) keylog: keylog::State,
    pub(crate) mailbox: mailbox::State,
    pub(crate) keys: keys::State,
    pub(crate) misc: misc::State,
    pub(crate) admin: admin::State,
}

impl Hub {
    /// Opens the SQLite database at [`Config::database_path`], creating the
    /// state directory if needed, and starts the hub on it.
    ///
    /// This blocks while the database opens. In async code, call it from
    /// `spawn_blocking`.
    pub fn open(config: Config) -> Result<Hub, HubError> {
        let timers = Timers::from_config(&config);
        Hub::open_with(
            config,
            timers,
            KeyServices::default(),
            Arc::new(SystemClock),
        )
    }

    /// [`Hub::open`] with timers that need not follow the configuration,
    /// key files fetched and published with `key_files`, and a clock of
    /// your choosing.
    pub(crate) fn open_with(
        config: Config,
        timers: Timers,
        key_files: KeyServices,
        clock: Arc<dyn Clock>,
    ) -> Result<Hub, HubError> {
        create_state_dir(&config.state_dir).map_err(|source| HubError::Io {
            path: config.state_dir.clone(),
            source,
        })?;
        let store = SqliteStore::open(&config.database_path())?;
        Hub::build(config, Arc::new(store), clock, timers, key_files)
    }

    /// Starts the hub on `store`, with the system clock.
    ///
    /// This blocks while it reads the store. In async code, call it from
    /// `spawn_blocking`.
    pub fn new(config: Config, store: impl Store) -> Result<Hub, HubError> {
        let timers = Timers::from_config(&config);
        Hub::build(
            config,
            Arc::new(store),
            Arc::new(SystemClock),
            timers,
            KeyServices::default(),
        )
    }

    /// Starts the hub. The server settings (10.6) come from the store, and
    /// those it does not have from `config.server`. Each area loads its
    /// state.
    pub(crate) fn build(
        config: Config,
        store: Arc<dyn Store>,
        clock: Arc<dyn Clock>,
        timers: Timers,
        key_files: KeyServices,
    ) -> Result<Hub, HubError> {
        match config.validate() {
            Ok(warnings) => {
                for warning in warnings {
                    tracing::warn!("{warning}");
                }
            }
            Err(ConfigError::Invalid(message)) => return Err(HubError::Config(message)),
            Err(e) => return Err(HubError::Config(e.to_string())),
        }
        if config.hostname.parse::<Host>().is_err() {
            return Err(HubError::Config(format!(
                "hostname {:?} is not a hostname",
                config.hostname
            )));
        }
        let retention = Retention::new(config.server.retention).ok_or_else(|| {
            HubError::Config(format!(
                "server.retention is {} days, but must be at least {} (7.5)",
                config.server.retention,
                Retention::MIN.days()
            ))
        })?;
        if !valid_welcome(&config.server.welcome) {
            return Err(HubError::Config(format!(
                "server.welcome must be escaped text of at most {} bytes (4.1)",
                risala_proto::types::MAX_WELCOME
            )));
        }
        let defaults = ServerSettings {
            anon: config.server.anon,
            guests: config.server.guests,
            registration: config.server.registration,
            retention,
            welcome: config.server.welcome.clone(),
        };
        let mut settings = store.settings(&defaults)?;
        if !valid_welcome(&settings.welcome) {
            tracing::error!("the stored welcome text is not valid; sending none");
            settings.welcome.clear();
        }
        let identity_domain = config.identity_domain();
        let inner = Inner {
            identity: identity::State::load(&config, &*store)?,
            keylog: keylog::State::load(&config, &store, &*clock)?,
            mailbox: mailbox::State::load(&config, &*store)?,
            keys: keys::State::load(&config, &*store)?,
            misc: misc::State::load(&config, &*store)?,
            admin: admin::State::load(&config, &*store)?,
            config,
            store,
            clock,
            timers,
            key_files,
            identity_domain,
            settings: RwLock::new(settings),
            reg: Mutex::new(Registry::default()),
        };
        tracing::info!("hub started");
        Ok(Hub {
            inner: Arc::new(inner),
        })
    }

    /// The configuration the hub was started with.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// Ends the session of the guest `uid` now (4.2), whether it is
    /// connected or waiting to be resumed: its connection, if it has one,
    /// is closed with `BYE <bye>`, the public rooms it had a leaf in get
    /// GONE (6.1), and then its name is free. Returns `false` if there was
    /// no such session, or it was already ending.
    ///
    /// ADMIN DISCONNECT (10.3), server bans (10.2) and `ADMIN SET guests
    /// no` (10.6) end sessions through this. A clean shutdown does too.
    pub async fn end_guest_session(&self, uid: &Uid, bye: &str) -> bool {
        self.inner.end_guest_session(uid, bye).await
    }

    /// Ends every guest session, as
    /// [`end_guest_session`](Self::end_guest_session) does. `risalad`
    /// calls this as it shuts down, once every connection has closed.
    pub async fn end_guest_sessions(&self, bye: &str) {
        let uids: Vec<Uid> = self.inner.reg().sessions.keys().cloned().collect();
        for uid in uids {
            self.inner.end_guest_session(&uid, bye).await;
        }
    }

    /// The guests that have a session, connected or waiting, in order.
    pub fn guest_sessions(&self) -> Vec<Uid> {
        let mut uids: Vec<Uid> = self.inner.reg().sessions.keys().cloned().collect();
        uids.sort();
        uids
    }

    /// The key file of the hosted identity `<name>@<identity domain>`, as
    /// served at its URL (4.3, 4.7): the file, gone once the identity was
    /// unregistered without a `retire` record (4.9), or not found. This
    /// blocks while it reads the store.
    pub fn hosted_key_file(&self, name: &Name) -> std::io::Result<HostedKeyFile> {
        identity::hosted_key_file(&self.inner, name)
    }

    /// The server's current key log (4.5), as a key file's `log` line
    /// names it, if it keeps one: the log that REGISTER's `master` record
    /// names (4.7).
    pub fn key_log(&self) -> Option<risala_proto::keyfile::LogLine> {
        identity::current_log(&self.inner)
    }

    /// Runs every area's background work (retention, expiry, checkpoints,
    /// pushes) until the future is dropped. `risalad` runs it next to the
    /// listeners.
    pub async fn maintain(self) {
        let inner = &self.inner;
        tokio::join!(
            identity::maintain(inner.clone()),
            keylog::maintain(inner.clone()),
            mailbox::maintain(inner.clone()),
            keys::maintain(inner.clone()),
            misc::maintain(inner.clone()),
            admin::maintain(inner.clone()),
        );
    }
}

#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
impl Inner {
    /// The registry of connections and guest sessions.
    pub(crate) fn reg(&self) -> MutexGuard<'_, Registry> {
        // Nothing that panics while holding the lock leaves the registry
        // half-changed in a way that matters more than stopping the server.
        self.reg.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The server settings now (10.6).
    pub(crate) fn settings(&self) -> ServerSettings {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Changes the server settings in memory, as ADMIN SET does once it
    /// has stored the change (10.6).
    pub(crate) fn update_settings(&self, f: impl FnOnce(&mut ServerSettings)) {
        f(&mut self.settings.write().unwrap_or_else(|e| e.into_inner()));
    }

    /// The time now.
    pub(crate) fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Runs a store call on the blocking pool.
    pub(crate) async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn Store) -> store::Result<T> + Send + 'static,
    ) -> store::Result<T> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || f(&*store))
            .await
            .map_err(|e| StoreError::Task(e.to_string()))?
    }
}

/// Creates the state directory, and any missing parents, with mode 0700,
/// and warns if it is open to others: it holds the database and the
/// generated certificate's private key.
fn create_state_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                dir = %dir.display(),
                mode = format!("{:o}", mode & 0o777),
                "the state directory is open to other users; consider chmod 700"
            );
        }
        Ok(())
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
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
                command::route(&inner, conn, req).await;
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

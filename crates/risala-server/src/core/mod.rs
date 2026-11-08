//! The hub: everything that happens after a line has been parsed.
//!
//! Implements [`crate::handler::Handler`]. Owned by task A in
//! docs/plans/M2-M5.md.
//!
//! The [`Hub`] owns all state, makes every check and does all fan-out.
//! Persistent state lives in a [`Store`]; what lasts only as long as a
//! guest session (its name, token and cids) lives in memory.
//!
//! # Guest sessions
//!
//! A guest's session (4.2) starts with GUEST and outlives its connection:
//! when the connection closes, QUIT included, the session waits
//! `limits.guest_resume_secs` for `GUEST <name> token=<token>` before it
//! ends. While it waits, the guest stays a member of its rooms, and its
//! name stays taken. A session ends in one place,
//! [`Hub::end_guest_session`], which records a PART in each of its rooms
//! and only then frees the name, so a new guest of the same name never
//! meets the old one's memberships. Sessions do not survive a restart: a
//! clean shutdown ends them all, and the PARTs of any a crash cut off are
//! recorded at the next start.
//!
//! # Identities
//!
//! An identity signs in with AUTH (4.5). The hub checks the signature over
//! this connection's SNI hostname and nonce, against the server's own
//! records for an identity it hosts, or else against the key file it gets
//! through a [`KeyFetcher`], with no lock held while it waits. REGISTER
//! (4.6), KEY (4.7) and UNREGISTER (4.8) keep hosted identities' keys in
//! the store and publish their key files through a [`KeyFilePublisher`].
//! An identity stays a member of its rooms across connections and
//! restarts: every connection signed in as it gets their live events.
//!
//! # Lines that are not events
//!
//! Read markers (7.4), typing (8.1), display names (8.2), MEMBERS and
//! WHOIS (8.3) and blocks (5.7) are in `social`. Presence (8.3) is in
//! `presence`: the registry notes when an identity's first connection
//! opens and its last one closes, and changes go out in batches, with a
//! delay before `offline`.
//!
//! # Conversations and ordering
//!
//! Every conversation, a room now and a direct conversation from M5a, has
//! an entry with an async lock ([`state::ConvEntry`]). Its members are kept
//! there, by conversation id (5.1), so a room that is dropped and created
//! again starts with nobody in it. Appending an event happens under the
//! lock: the seq is assigned and the event stored in one store
//! transaction, and then, still under the lock, the event is queued for
//! every connection of every member. So every connection receives a
//! conversation's events in seq order (5.2), and an event is sent only
//! once it is stored, so seqs never have gaps (5.2, PLAN.md 3.2). A
//! command queues its own final response after the events it caused, so
//! its sender gets them first (3.6).
//!
//! Fan-out does not take the registry's lock: each member's entry
//! ([`state::UserEntry`]) holds its connections. See [`state`] for the
//! order the locks are taken in.
//!
//! Each command runs in its own task, holding its connection's gate. The
//! clean-up after a connection closes takes the gate too, so it waits for
//! a command in progress, and a command finishes even if the network layer
//! stops waiting for it.

mod admin;
mod commands;
mod identity;
pub mod keys;
mod messages;
mod moderation;
mod presence;
mod rate;
mod reports;
mod social;
mod state;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;

use risala_proto::auth::Nonce;
use risala_proto::names::Room;
use risala_proto::server::{Greeting, Host, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::{MAX_WELCOME, ServerRetention};

use crate::config::{Config, ConfigError};
use crate::handler::{ConnHandle, ConnId, ConnInfo, Handler};
use crate::store::{self, ServerSettings, SqliteStore, Store, StoreError};

use risala_proto::names::{Domain, Id, Uid};

pub use keys::{
    FetchError, FetchedKeys, KeyFetcher, KeyFilePublisher, KeyServices, MemoryFetcher,
    MemoryPublisher, NoFetcher, NoPublisher,
};
use presence::PresenceBook;
use state::{ConnEntry, ConvEntry, ConvState, GuestSession, Registry};

/// The number of random bytes in a greeting's nonce (4.1).
pub const NONCE_BYTES: usize = 32;

/// The number of random `a-z 0-9` characters in a guest's token (4.2): 32
/// of them carry about 165 bits.
pub const TOKEN_LEN: usize = 32;

/// How long AUTH waits for an identity's key file (4.4) before it gives
/// up with `ERR unavailable`. A fetch stops after 10 seconds itself, but
/// may first wait as long again for its turn; this is a backstop.
pub const KEY_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The `retry` on AUTH's `ERR unavailable` (4.5): how long a client
/// should wait before it tries again after a key file could not be
/// fetched. A fetcher does not try a file again sooner anyway (14).
pub const UNAVAILABLE_RETRY: Duration = Duration::from_secs(10);

/// The BYE text for a connection whose guest session was resumed on
/// another connection (4.2).
pub const BYE_RESUMED: &str = "resumed on another connection";

/// The BYE text for guest sessions ended by a shutdown. Their connections
/// have closed by then, so nobody reads it.
pub const BYE_SHUTDOWN: &str = "server shutting down";

/// How often [`Hub::prune_cids_every`] runs in `risalad`.
pub const CID_PRUNE_PERIOD: Duration = Duration::from_secs(60 * 60);

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
    /// Every room, by name. A room is added at run time only while
    /// `create_lock` is held, so two JOINs cannot both create it.
    rooms: RwLock<BTreeMap<Room, Arc<ConvEntry>>>,
    create_lock: tokio::sync::Mutex<()>,
    reg: Mutex<Registry>,
    sign_in_timeout: Duration,
    guest_resume: Duration,
    /// Key files: fetched for AUTH, published for hosted identities (4.4,
    /// 4.6).
    keys: KeyServices,
    /// The identity domain (4.6), if the server hosts identities.
    identity_domain: Option<Domain>,
    /// The operators (10.1): from the configuration, and from the store.
    operators: RwLock<BTreeSet<Uid>>,
    /// Server bans (10.2), and the lock the ADMIN commands change things
    /// under.
    admin_state: admin::AdminState,
    /// Held while the keys of a hosted identity change and its key file is
    /// published, so that the files are published in the order of the
    /// changes.
    keys_lock: tokio::sync::Mutex<()>,
    /// The identities each network address registered in the last hour,
    /// or is registering now (4.6, 14), for
    /// `limits.registrations_per_hour`.
    registrations: rate::WindowLimit<IpAddr>,
    /// The rooms each identity created in the last day, or is creating
    /// now (6.1, 14), for `limits.rooms_per_day`.
    room_creations: rate::WindowLimit<Uid>,
    /// Held while presence changes are sent (8.3), so that one flush ends
    /// before the next begins.
    presence_lock: tokio::sync::Mutex<()>,
    /// Held while a display name is stored and sent (8.2), so that every
    /// connection gets a user's changes in the order they were stored.
    names_lock: tokio::sync::Mutex<()>,
    /// `limits.typing_interval_ms` (8.1).
    typing_interval: Duration,
    /// Counts the read markers that moved (7.4), so that SYNC can tell
    /// which conversations' markers moved since it read them all
    /// ([`ConvState::marker_moved`]).
    markers_moved: AtomicU64,
}

impl Hub {
    /// Opens the SQLite database at [`Config::database_path`], creating the
    /// state directory if needed, and starts the hub on it.
    ///
    /// This blocks while the database opens. In async code, call it from
    /// `spawn_blocking`.
    ///
    /// A new state directory gets mode 0700, and a warning is logged if an
    /// existing one can be read by others (13).
    pub fn open(config: Config) -> Result<Hub, HubError> {
        Hub::open_with_keys(config, KeyServices::default())
    }

    /// [`Hub::open`], fetching and publishing key files with `keys` (4.4,
    /// 4.6).
    pub fn open_with_keys(config: Config, keys: KeyServices) -> Result<Hub, HubError> {
        let timers = Timers::from_config(&config);
        Hub::open_with(config, timers, keys)
    }

    /// [`Hub::open`] with timers that need not follow the configuration.
    pub(crate) fn open_with(
        config: Config,
        timers: Timers,
        keys: KeyServices,
    ) -> Result<Hub, HubError> {
        create_state_dir(&config.state_dir).map_err(|source| HubError::Io {
            path: config.state_dir.clone(),
            source,
        })?;
        let store = SqliteStore::open(&config.database_path())?;
        Hub::build(config, Arc::new(store), Arc::new(SystemClock), timers, keys)
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
        Hub::with_services(config, store, clock, KeyServices::default())
    }

    /// [`Hub::new`] with a clock, and fetching and publishing key files
    /// with `keys` (4.4, 4.6).
    pub fn with_services(
        config: Config,
        store: impl Store,
        clock: impl Clock,
        keys: KeyServices,
    ) -> Result<Hub, HubError> {
        let timers = Timers::from_config(&config);
        Hub::build(config, Arc::new(store), Arc::new(clock), timers, keys)
    }

    pub(crate) fn build(
        config: Config,
        store: Arc<dyn Store>,
        clock: Arc<dyn Clock>,
        timers: Timers,
        keys: KeyServices,
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
            registration: config.server.registration,
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
        part_leftover_guests(&*store, now)?;

        let mut reg = Registry::default();
        let mut rooms = BTreeMap::new();
        for mut record in store.rooms()? {
            let members = std::mem::take(&mut record.members);
            let room = record.room.clone();
            let entry = Arc::new(ConvEntry::new(ConvState::room(record)));
            {
                let mut st = entry.try_lock().expect("a new room is not locked");
                for uid in &members {
                    let user = reg.user(uid);
                    st.add_member(&entry, &user);
                }
            }
            rooms.insert(room, entry);
        }
        tracing::info!(rooms = rooms.len(), "hub started");

        let operators: BTreeSet<Uid> = config
            .operators()
            .iter()
            .map(|op| op.to_uid())
            .chain(store.operators()?)
            .collect();
        let identity_domain = config.identity_domain();
        let admin_state = admin::AdminState::load(&*store)?;
        // The key files of hosted identities, again, in case they were
        // lost or the publisher keeps them in memory (4.6), and none of
        // the names no longer hosted, in case removing one failed (4.8).
        let mut names = Vec::new();
        for (uid, hosted) in store.hosted_identities()? {
            // A failure is logged, and the next change publishes again.
            let _ = identity::publish(&*keys.publisher, &uid, &hosted);
            names.extend(uid.name().parse::<risala_proto::names::Name>().ok());
        }
        if let Err(e) = keys.publisher.retain(&names) {
            tracing::error!("removing the key files of names no longer hosted failed: {e}");
        }

        Ok(Hub {
            inner: Arc::new_cyclic(|weak| {
                reg.presence =
                    PresenceBook::new(weak.clone(), timers.presence_offline, timers.presence_batch);
                Inner {
                    config,
                    store,
                    clock,
                    settings: RwLock::new(settings),
                    rooms: RwLock::new(rooms),
                    create_lock: tokio::sync::Mutex::new(()),
                    reg: Mutex::new(reg),
                    sign_in_timeout: timers.sign_in,
                    guest_resume: timers.guest_resume,
                    keys,
                    identity_domain,
                    operators: RwLock::new(operators),
                    admin_state,
                    keys_lock: tokio::sync::Mutex::new(()),
                    registrations: rate::WindowLimit::new(identity::REGISTRATION_WINDOW),
                    room_creations: rate::WindowLimit::new(commands::ROOM_CREATION_WINDOW),
                    presence_lock: tokio::sync::Mutex::new(()),
                    names_lock: tokio::sync::Mutex::new(()),
                    typing_interval: timers.typing_interval,
                    markers_moved: AtomicU64::new(0),
                }
            }),
        })
    }

    /// The configuration the hub was started with.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// Ends the session of the guest `uid` now (4.2), whether it is
    /// connected or waiting to be resumed: its connection, if it has one,
    /// is closed with `BYE <bye>`, a PART is recorded in each of its rooms,
    /// and then its name is free. Returns `false` if there was no such
    /// session, or it was already ending.
    ///
    /// ADMIN DISCONNECT (10.3) and server bans (10.2) end guest sessions
    /// through this, once they exist (M4). A clean shutdown uses it too.
    pub async fn end_guest_session(&self, uid: &Uid, bye: &str) -> bool {
        self.inner.end_guest_session(uid, bye).await
    }

    /// Ends every guest session, as [`end_guest_session`](Self::end_guest_session)
    /// does. `risalad` calls this as it shuts down, once every connection
    /// has closed, so that the PARTs carry the time of the shutdown.
    pub async fn end_guest_sessions(&self, bye: &str) {
        let uids: Vec<Uid> = self.inner.reg().sessions.keys().cloned().collect();
        for uid in uids {
            self.inner.end_guest_session(&uid, bye).await;
        }
    }

    /// Whether the identity `by` has blocked `uid` (5.7), by identity or by
    /// domain. Guests never block and are never blocked.
    ///
    /// Blocks have no effect in rooms on the server. This is the hook for
    /// what they do: in direct conversations (M5a), and for push (M8, 9.2).
    pub async fn is_blocked(&self, by: &Uid, uid: &Uid) -> Result<bool, StoreError> {
        self.inner.is_blocked(by, uid).await
    }

    /// The key file of the hosted identity `<name>@<identity domain>`, from
    /// the hub's records (4.6), or `None` if the server hosts no such
    /// identity. This blocks while it reads the store.
    pub fn hosted_key_file(
        &self,
        name: &risala_proto::names::Name,
    ) -> Result<Option<Vec<risala_proto::keyfile::KeyEntry>>, StoreError> {
        let Some(domain) = &self.inner.identity_domain else {
            return Ok(None);
        };
        let uid = risala_proto::names::Identity::new(name, domain).to_uid();
        let keys = self.inner.store.hosted_keys(&uid)?;
        Ok(keys.map(|keys| keys.iter().map(identity::key_entry).collect()))
    }

    /// The names of the guests that have a session, connected or waiting,
    /// in order.
    pub fn guest_sessions(&self) -> Vec<Uid> {
        let mut uids: Vec<Uid> = self.inner.reg().sessions.keys().cloned().collect();
        uids.sort();
        uids
    }

    /// Forgets the cids of messages sent more than 24 hours ago (7.6), and
    /// returns how many. The hub does this when it starts, and `risalad`
    /// every [`CID_PRUNE_PERIOD`] after that.
    pub async fn prune_cids(&self) -> Result<u64, StoreError> {
        let window = Duration::from_millis(store::CID_WINDOW_MS);
        let Some(before) = self.inner.now().checked_sub(window) else {
            return Ok(0);
        };
        self.inner.db(move |s| s.prune_cids(before)).await
    }

    /// Runs [`prune_cids`](Self::prune_cids) every `period`, starting one
    /// period from now, until the future is dropped. Failures are logged.
    pub async fn prune_cids_every(self, period: Duration) {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is now; the hub pruned when it started.
        tick.tick().await;
        loop {
            tick.tick().await;
            match self.prune_cids().await {
                Ok(n) => tracing::debug!(cids = n, "forgot old cids"),
                Err(e) => tracing::error!("forgetting old cids failed: {e}"),
            }
        }
    }
}

/// The hub's timers, which tests may shorten below what the configuration
/// allows.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timers {
    /// How long a new connection has to sign in (4.1).
    pub(crate) sign_in: Duration,
    /// How long a guest session waits to be resumed (4.2).
    pub(crate) guest_resume: Duration,
    /// How long after an identity's last connection closes it is reported
    /// offline (8.3).
    pub(crate) presence_offline: Duration,
    /// How long presence changes are collected before they are sent (8.3).
    pub(crate) presence_batch: Duration,
    /// The least time between two TYPING one connection passes on to a
    /// conversation (8.1).
    pub(crate) typing_interval: Duration,
}

impl Timers {
    pub(crate) fn from_config(config: &Config) -> Timers {
        let l = &config.limits;
        Timers {
            sign_in: Duration::from_secs(l.sign_in_secs),
            guest_resume: Duration::from_secs(l.guest_resume_secs),
            presence_offline: Duration::from_secs(l.presence_offline_secs),
            presence_batch: Duration::from_millis(l.presence_batch_ms),
            typing_interval: Duration::from_millis(l.typing_interval_ms),
        }
    }
}

/// Creates the state directory, and any missing parents, with mode 0700,
/// and warns if it is open to others (13): it holds the database and the
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

/// Records a PART, with no reason, for every guest still in a room when
/// the server starts (4.2). Sessions do not survive a restart, so these
/// are guests whose sessions a crash cut off before their PARTs were
/// stored, whether they were connected or waiting to be resumed (PLAN.md
/// 5, items 16 and 17). The PARTs carry the time of the restart.
/// Each PART also removes the stored membership, so it is recorded once.
fn part_leftover_guests(store: &dyn Store, now: Timestamp) -> Result<(), StoreError> {
    let leftover = store.guest_members()?;
    if !leftover.is_empty() {
        tracing::info!(
            guests = leftover.len(),
            "recording the PARTs of guests cut off by a crash"
        );
    }
    for (conv, uid) in leftover {
        let event = store::NewEvent {
            t: now,
            from: uid,
            kind: store::EventKind::Part {
                reason: String::new(),
            },
            cid: None,
        };
        store.append(conv, &event)?;
    }
    Ok(())
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

    fn room_entry(&self, room: &Room) -> Option<Arc<ConvEntry>> {
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
                nonce: Some(nonce),
                uid: None,
                detached: false,
                gate: Arc::default(),
                sign_in_timer: timer,
                typing: HashMap::new(),
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

    /// Cleans up after a connection. A guest's session starts waiting to
    /// be resumed (4.2), unless it has moved to another connection.
    async fn closed(self: Arc<Self>, id: ConnId) {
        let Some(gate) = self.reg().conns.get(&id).map(|c| c.gate.clone()) else {
            return;
        };
        let _gate = gate.lock().await;
        let mut reg = self.reg();
        let Some(conn) = reg.remove_conn(id) else {
            return;
        };
        if let Some(timer) = conn.sign_in_timer {
            timer.abort();
        }
        tracing::debug!(conn = id.0, "connection closed");
        let Some(uid) = conn.uid else {
            return;
        };
        if let Some(session) = reg.sessions.get_mut(&uid)
            && session.conn == Some(id)
            && !session.ending
        {
            session.conn = None;
            session.epoch += 1;
            let epoch = session.epoch;
            let weak: Weak<Inner> = Arc::downgrade(&self);
            let wait = self.guest_resume;
            let expired_uid = uid.clone();
            session.expiry = Some(
                tokio::spawn(async move {
                    tokio::time::sleep(wait).await;
                    if let Some(inner) = weak.upgrade() {
                        inner.resume_expired(&expired_uid, epoch).await;
                    }
                })
                .abort_handle(),
            );
            tracing::debug!(conn = id.0, "guest session waits to be resumed");
        }
    }

    /// Ends a guest session whose resume period is over (4.2), unless it
    /// was resumed meanwhile.
    async fn resume_expired(&self, uid: &Uid, epoch: u64) {
        {
            let mut reg = self.reg();
            let Some(session) = reg.sessions.get_mut(uid) else {
                return;
            };
            if session.conn.is_some() || session.epoch != epoch || session.ending {
                return;
            }
            // This task is the expiry: it must not abort itself.
            session.expiry = None;
        }
        tracing::debug!("guest session not resumed in time");
        self.end_guest_session(uid, "session ended").await;
    }

    /// See [`Hub::end_guest_session`].
    async fn end_guest_session(&self, uid: &Uid, bye: &str) -> bool {
        {
            let mut reg = self.reg();
            let Some(session) = reg.sessions.get_mut(uid) else {
                return false;
            };
            if session.ending {
                return false;
            }
            session.ending = true;
            if let Some(expiry) = session.expiry.take() {
                expiry.abort();
            }
            if let Some(conn) = session.conn.take() {
                reg.detach(conn, bye);
            }
        }
        // A JOIN that was under way when the session began to end may add
        // a room after the first pass, but none can start after it, since
        // `may_join` is now false. So this ends.
        loop {
            let convs = self
                .reg()
                .users
                .get(uid)
                .map(|user| user.convs())
                .unwrap_or_default();
            if convs.is_empty() {
                break;
            }
            for conv in convs {
                self.auto_part(conv, uid).await;
            }
        }
        let mut reg = self.reg();
        reg.sessions.remove(uid);
        reg.release(uid);
        drop(reg);
        tracing::debug!("guest session ended");
        true
    }

    /// Starts a guest session for connection `id`, or moves the session of
    /// `uid` to it when `token` is the session's current token (4.2).
    /// The session's token becomes `new_token`.
    fn sign_in_guest(
        &self,
        id: ConnId,
        uid: &Uid,
        token: Option<&Id>,
        new_token: Id,
    ) -> Result<SignIn, SignInRefused> {
        let mut reg = self.reg();
        let Some(conn) = reg.conns.get(&id) else {
            return Err(SignInRefused::Gone);
        };
        // Under the registry's lock: see `admin`.
        if let Some(why) = self.guest_refused(conn.info.peer.ip()) {
            return Err(SignInRefused::Forbidden(why));
        }
        let resumed = match reg.sessions.get_mut(uid) {
            Some(session) if !session.ending && token.is_some_and(|t| session.token_is(t)) => {
                session.token = new_token.clone();
                session.epoch += 1;
                if let Some(expiry) = session.expiry.take() {
                    expiry.abort();
                }
                Some(session.conn.replace(id))
            }
            Some(_) => return Err(SignInRefused::NameTaken),
            None => None,
        };
        match resumed {
            Some(old) => {
                if let Some(old) = old {
                    reg.detach(old, BYE_RESUMED);
                }
                reg.attach(id, uid, None);
                Ok(SignIn::Resumed)
            }
            None => {
                reg.attach(id, uid, None);
                reg.sessions.insert(
                    uid.clone(),
                    GuestSession {
                        token: new_token,
                        conn: Some(id),
                        cids: Default::default(),
                        epoch: 0,
                        expiry: None,
                        ending: false,
                        display_name: String::new(),
                    },
                );
                Ok(SignIn::New)
            }
        }
    }
}

/// How GUEST signed a connection in (4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignIn {
    /// A new session.
    New,
    /// An existing session moved to the connection.
    Resumed,
}

/// Why GUEST could not sign a connection in (4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignInRefused {
    /// Another session holds the name.
    NameTaken,
    /// The connection has closed.
    Gone,
    /// Guests are not allowed, or not from this address (10.2, 10.6).
    Forbidden(&'static str),
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

#[cfg(test)]
mod identity_tests;

#[cfg(test)]
mod social_tests;

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

use crate::config::{Config, ConfigError};
use crate::handler::{ConnHandle, ConnId, ConnInfo, Handler};
use crate::store::{self, ServerSettings, SqliteStore, Store, StoreError};

use risala_proto::names::{Id, Uid};

use state::{ConnEntry, GuestSession, Registry, RoomEntry};

/// The number of random bytes in a greeting's nonce (4.1).
pub const NONCE_BYTES: usize = 32;

/// The number of random `a-z 0-9` characters in a guest's token (4.2): 32
/// of them carry about 165 bits.
pub const TOKEN_LEN: usize = 32;

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
    rooms: RwLock<BTreeMap<Room, Arc<RoomEntry>>>,
    reg: Mutex<Registry>,
    sign_in_timeout: Duration,
    guest_resume: Duration,
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
        let timers = Timers::from_config(&config);
        Hub::open_with(config, timers)
    }

    /// [`Hub::open`] with timers that need not follow the configuration.
    pub(crate) fn open_with(config: Config, timers: Timers) -> Result<Hub, HubError> {
        create_state_dir(&config.state_dir).map_err(|source| HubError::Io {
            path: config.state_dir.clone(),
            source,
        })?;
        let store = SqliteStore::open(&config.database_path())?;
        Hub::build(config, Arc::new(store), Arc::new(SystemClock), timers)
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
        let timers = Timers::from_config(&config);
        Hub::build(config, Arc::new(store), Arc::new(clock), timers)
    }

    pub(crate) fn build(
        config: Config,
        store: Arc<dyn Store>,
        clock: Arc<dyn Clock>,
        timers: Timers,
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
        part_leftover_guests(&*store, now)?;

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
                sign_in_timeout: timers.sign_in,
                guest_resume: timers.guest_resume,
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
}

impl Timers {
    pub(crate) fn from_config(config: &Config) -> Timers {
        Timers {
            sign_in: Duration::from_secs(config.limits.sign_in_secs),
            guest_resume: Duration::from_secs(config.limits.guest_resume_secs),
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
                detached: false,
                gate: Arc::default(),
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

    /// Cleans up after a connection. A guest's session starts waiting to
    /// be resumed (4.2), unless it has moved to another connection.
    async fn closed(self: Arc<Self>, id: ConnId) {
        let Some(gate) = self.reg().conns.get(&id).map(|c| c.gate.clone()) else {
            return;
        };
        let _gate = gate.lock().await;
        let mut reg = self.reg();
        let Some(conn) = reg.conns.remove(&id) else {
            return;
        };
        if let Some(timer) = conn.sign_in_timer {
            timer.abort();
        }
        tracing::debug!(conn = id.0, "connection closed");
        let Some(uid) = conn.uid else {
            return;
        };
        if let Some(conns) = reg.users.get_mut(&uid) {
            conns.retain(|c| *c != id);
            if conns.is_empty() {
                reg.users.remove(&uid);
            }
        }
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
            let rooms: Vec<Room> = self
                .reg()
                .rooms_of
                .get(uid)
                .map(|r| r.iter().cloned().collect())
                .unwrap_or_default();
            if rooms.is_empty() {
                break;
            }
            for room in rooms {
                self.guest_part(&room, uid).await;
            }
        }
        self.reg().sessions.remove(uid);
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
        if !reg.conns.contains_key(&id) {
            return Err(SignInRefused::Gone);
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
        if let Some(conn) = reg.conns.get_mut(&id) {
            conn.uid = Some(uid.clone());
            if let Some(timer) = conn.sign_in_timer.take() {
                timer.abort();
            }
        }
        match resumed {
            Some(old) => {
                if let Some(old) = old {
                    reg.detach(old, BYE_RESUMED);
                }
                reg.users.insert(uid.clone(), vec![id]);
                Ok(SignIn::Resumed)
            }
            None => {
                reg.users.insert(uid.clone(), vec![id]);
                reg.sessions.insert(
                    uid.clone(),
                    GuestSession {
                        token: new_token,
                        conn: Some(id),
                        cids: Default::default(),
                        epoch: 0,
                        expiry: None,
                        ending: false,
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

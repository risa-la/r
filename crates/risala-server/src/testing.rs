//! A whole server for tests, here and in other crates.
//!
//! **For tests only.** [`TestServer`] runs a real `risalad` (the
//! [`Hub`](crate::core::Hub) behind the [network layer](crate::net)) in
//! the current tokio runtime, on `127.0.0.1` with a port the system
//! chooses, with its database and a generated self-signed certificate in a
//! temporary directory. [`TestClient`] talks to it line by line over TLS,
//! accepting any certificate.
//!
//! ```no_run
//! # async fn f() {
//! use risala_server::testing::TestServer;
//!
//! let server = TestServer::builder().room("#general").start().await;
//! let mut sam = server.guest("sam").await;
//! sam.send("join #general").await.unwrap();
//! let join = sam.expect_line().await.unwrap();
//! assert!(join.ends_with(" JOIN #general"));
//! server.stop().await;
//! # }
//! ```
//!
//! Every method panics when something fails, since it runs in a test.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use risala_proto::fingerprint::Fingerprint;
use risala_proto::names::Room;
use risala_proto::time::Timestamp;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, Limits};
use crate::daemon::{Daemon, RunError};
use crate::store::{SqliteStore, Store as _};

pub use crate::net::testing::{ClientOptions, RECV_TIMEOUT, TestClient};

/// How long [`TestServer::stop`] waits for the server to finish.
const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// A preparation step, run on the database before the server starts.
type Prepare = Box<dyn FnOnce(&SqliteStore) + Send>;

/// Builds a [`TestServer`]. Get one from [`TestServer::builder`].
///
/// Unless changed, the server:
///
/// - is called `localhost`
/// - has no rooms (guests cannot create any, so add some with
///   [`room`](Self::room))
/// - allows guests, has no welcome text, and uses the default
///   [`Limits`]
#[must_use]
pub struct TestServerBuilder {
    config: Config,
    prepare: Vec<Prepare>,
}

impl fmt::Debug for TestServerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestServerBuilder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TestServerBuilder {
    /// The server's main hostname (`hostname` in the configuration). It is
    /// in the greeting of a client that sends no SNI (4.1), and names the
    /// self-signed certificate.
    pub fn hostname(mut self, hostname: &str) -> Self {
        self.config.hostname = hostname.to_owned();
        self
    }

    /// Adds a room that exists from the start (`rooms` in the
    /// configuration), with default settings and no events.
    pub fn room(mut self, room: &str) -> Self {
        self.config.rooms.push(room.to_owned());
        self
    }

    /// Whether guests may connect (`server.guests`).
    pub fn guests(mut self, allowed: bool) -> Self {
        self.config.server.guests = allowed;
        self
    }

    /// The greeting's welcome text, already escaped (`server.welcome`).
    pub fn welcome(mut self, text: &str) -> Self {
        self.config.server.welcome = text.to_owned();
        self
    }

    /// Limits and timers, for example short keepalive timers:
    ///
    /// ```
    /// # use risala_server::{config::Limits, testing::TestServer};
    /// let builder = TestServer::builder().limits(Limits {
    ///     idle_ping_secs: 1,
    ///     ping_timeout_secs: 1,
    ///     ..Limits::default()
    /// });
    /// ```
    pub fn limits(mut self, limits: Limits) -> Self {
        self.config.limits = limits;
        self
    }

    /// Changes anything else in the configuration. `listen` and
    /// `state_dir` are replaced when the server starts.
    pub fn configure(mut self, f: impl FnOnce(&mut Config)) -> Self {
        f(&mut self.config);
        self
    }

    /// Runs `f` on the database before the server opens it, for state that
    /// guests cannot make: events by identities, or room settings such as
    /// `public no` or `guests none`. The rooms added with
    /// [`room`](Self::room) already exist when `f` runs. Steps run in the
    /// order they were added.
    pub fn prepare(mut self, f: impl FnOnce(&SqliteStore) + Send + 'static) -> Self {
        self.prepare.push(Box::new(f));
        self
    }

    /// Starts the server and returns once it accepts connections.
    pub async fn start(self) -> TestServer {
        let dir = TempDir::new();
        let mut config = self.config;
        config.state_dir = dir.path().to_owned();
        config.listen = vec![SocketAddr::from(([127, 0, 0, 1], 0))];
        if !self.prepare.is_empty() {
            let config = config.clone();
            let prepare = self.prepare;
            tokio::task::spawn_blocking(move || prepare_store(&config, prepare))
                .await
                .expect("preparing the database");
        }
        let mut server = TestServer {
            config,
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            fingerprint: None,
            running: None,
            dir: Some(dir),
        };
        server.launch().await;
        server
    }
}

fn prepare_store(config: &Config, prepare: Vec<Prepare>) {
    std::fs::create_dir_all(&config.state_dir).expect("creating the state directory");
    let store = SqliteStore::open(&config.database_path()).expect("opening the database");
    for name in &config.rooms {
        let room: Room = name.parse().expect("a valid room name");
        store
            .ensure_room(&room, Timestamp::now())
            .expect("creating a room");
    }
    for f in prepare {
        f(&store);
    }
}

/// A running server, for tests. See the [module documentation](self).
///
/// Dropping it stops the server in the background and then deletes its
/// directory. [`stop`](Self::stop) does the same and waits for it.
#[derive(Debug)]
pub struct TestServer {
    config: Config,
    addr: SocketAddr,
    fingerprint: Option<Fingerprint>,
    running: Option<Running>,
    dir: Option<TempDir>,
}

#[derive(Debug)]
struct Running {
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), RunError>>,
}

impl TestServer {
    /// A server with the [defaults](TestServerBuilder).
    pub async fn start() -> TestServer {
        TestServer::builder().start().await
    }

    /// A builder, to change the defaults.
    pub fn builder() -> TestServerBuilder {
        TestServerBuilder {
            config: Config {
                hostname: "localhost".into(),
                ..Config::default()
            },
            prepare: Vec::new(),
        }
    }

    /// The address the server listens on, on `127.0.0.1`. It stays the
    /// same across [`restart`](Self::restart).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The server's main hostname.
    pub fn hostname(&self) -> &str {
        &self.config.hostname
    }

    /// The fingerprint of the server's self-signed certificate (2.2). It
    /// stays the same across [`restart`](Self::restart).
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint.expect("the server has started")
    }

    /// The configuration the server runs with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The directory holding the database and the certificate. It is
    /// deleted when the server is dropped or stopped.
    pub fn state_dir(&self) -> &Path {
        &self.config.state_dir
    }

    /// Connects over TLS, sending the server's hostname in SNI and
    /// offering ALPN. The greeting (4.1) is the first line to read.
    pub async fn connect(&self) -> TestClient {
        self.connect_with(ClientOptions::sni(&self.config.hostname))
            .await
    }

    /// Connects over TLS with the given options. The greeting (4.1) is the
    /// first line to read.
    pub async fn connect_with(&self, options: ClientOptions) -> TestClient {
        TestClient::connect_with(self.addr, options)
            .await
            .expect("connecting to the test server")
    }

    /// Connects, reads the greeting and signs in as the guest `~<name>`
    /// (4.2). The next line to read is whatever comes after `OK`.
    pub async fn guest(&self, name: &str) -> TestClient {
        let mut client = self.connect().await;
        let greeting = client.expect_line().await.expect("a greeting");
        assert!(greeting.starts_with("RISALA 1 "), "greeting: {greeting}");
        client
            .send(&format!("GUEST {name}"))
            .await
            .expect("sending");
        let ok = client.expect_line().await.expect("an answer to GUEST");
        assert_eq!(ok, format!("OK uid=~{name}"), "answer to GUEST {name}");
        client
    }

    /// Stops the server and starts it again on the same directory and
    /// address, as after a restart of `risalad`. Connections are closed
    /// with `BYE server shutting down` (11), and connected guests leave
    /// their rooms (4.2).
    pub async fn restart(&mut self) {
        self.shut_down().await;
        self.launch().await;
    }

    /// Stops the server, waits until it has finished, and deletes its
    /// directory. Connections are closed with `BYE server shutting down`
    /// (11).
    pub async fn stop(mut self) {
        self.shut_down().await;
    }

    async fn launch(&mut self) {
        assert!(self.running.is_none(), "the server is already running");
        let mut config = self.config.clone();
        // After a restart, listen on the same port again.
        config.listen = vec![self.addr];
        let daemon = Daemon::bind(config)
            .await
            .expect("starting the test server");
        self.addr = daemon.local_addrs()[0];
        let fingerprint = daemon.fingerprint();
        if let Some(old) = self.fingerprint {
            assert_eq!(old, fingerprint, "the fingerprint changed on restart");
        }
        self.fingerprint = Some(fingerprint);
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(daemon.run(async {
            let _ = stopped.await;
        }));
        self.running = Some(Running { stop, task });
    }

    async fn shut_down(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        let _ = running.stop.send(());
        tokio::time::timeout(STOP_TIMEOUT, running.task)
            .await
            .expect("the test server stops in time")
            .expect("the test server's task")
            .expect("the test server");
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let dir = self.dir.take();
        let Some(running) = self.running.take() else {
            return;
        };
        let _ = running.stop.send(());
        // Delete the directory only once the server has let go of it. If
        // the runtime is going away, the task is dropped with it, and so
        // is the directory.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = tokio::time::timeout(STOP_TIMEOUT, running.task).await;
                drop(dir);
            });
        }
    }
}

/// A directory under the system's temporary directory, deleted on drop.
#[derive(Debug)]
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("random bytes");
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("risala-test-{name}"));
        std::fs::create_dir(&path).expect("creating a temporary directory");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

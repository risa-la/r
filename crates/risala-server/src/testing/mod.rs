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
//!
//! # Identities
//!
//! A test server can have identities of two kinds (4.3):
//!
//! - **Hosted ones**, under its own identity domain, made with REGISTER
//!   (4.6). Set the domain with
//!   [`identity_domain`](TestServerBuilder::identity_domain), which also
//!   opens registration, then call [`TestServer::register`].
//! - **Others**, whose key files a [`TestKeyServer`] serves over HTTPS
//!   (4.4). Name their domains with
//!   [`key_domains`](TestServerBuilder::key_domains), then make them with
//!   [`TestServer::identity`]. The server fetches their key files for real:
//!   it trusts the key server's test CA through `[keys] extra_roots`, may
//!   fetch from `127.0.0.1` through `[keys] allow_private`, and sends each
//!   domain to its listener with a test resolver. It fetches a file again
//!   whenever a signature fails against the cached copy, without the usual
//!   rate limit, so a key added during a test works at once.
//!
//! The key server also serves the hosted identities' key files, from the
//! server's `key_dir`, so devices can fetch every key file (12.12) with
//! [`TestKeyServer::fetch_options`].
//!
//! Each identity is handled through a [`TestIdentity`]: one device, with
//! its own key. [`TestServer::sign_in`] connects and signs in with AUTH
//! (4.5); [`TestServer::new_device`] adds another key to the identity
//! (with KEY ADD for a hosted one) and returns the new device.
//!
//! ```no_run
//! # async fn f() {
//! use risala_server::testing::TestServer;
//!
//! let server = TestServer::builder()
//!     .identity_domain("example.org")
//!     .key_domains(&["example.net"])
//!     .start()
//!     .await;
//! // Hosted: registered, and signed in on that connection.
//! let (alice, mut laptop) = server.register("alice").await;
//! // A second device of alice, signed in with its own key.
//! let phone = server.new_device(&alice).await;
//! let mut phone_conn = server.sign_in(&phone).await;
//! // Someone from elsewhere, whose key file the server fetches.
//! let bob = server.identity("bob@example.net");
//! let mut bob_conn = server.sign_in(&bob).await;
//! laptop.send("join #general").await.unwrap();
//! # }
//! ```
//!
//! Presence (8.3) is on, with the spec's timings unless
//! [`presence`](TestServerBuilder::presence) changes them: a client signed
//! in as an identity gets `PRESENCE` lines a second after people who share
//! a room with it come online, and 30 seconds after they go.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use risala_proto::fingerprint::Fingerprint;
use risala_proto::names::Room;
use risala_proto::time::Timestamp;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, Limits};
use crate::core::{KeyServices, Timers};
use crate::daemon::{Daemon, RunError};
use crate::http::{HttpsKeyFetcher, KeyDir};
use crate::store::{SqliteStore, Store as _};

mod identities;

pub use crate::net::testing::{ClientOptions, RECV_TIMEOUT, TestClient};
pub use identities::{TestIdentity, TestKeyServer};

/// How long [`TestServer::stop`] waits for the server to finish.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

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
/// - hosts no identities, and fetches no key files
#[must_use]
pub struct TestServerBuilder {
    config: Config,
    prepare: Vec<Prepare>,
    guest_resume: Option<Duration>,
    presence: Option<(Duration, Duration)>,
    key_domains: Vec<String>,
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

    /// How long a guest session waits to be resumed after its connection
    /// closes (4.2). Unlike `limits.guest_resume_secs`, this may be shorter
    /// than the 2 minutes the spec requires, so that tests can watch
    /// sessions end. Without it, the configuration's value is used.
    pub fn guest_resume(mut self, wait: Duration) -> Self {
        self.guest_resume = Some(wait);
        self
    }

    /// Hosts identities under `domain` (`identity_domain`, 4.6), with
    /// registration open (`server.registration`). Register them with
    /// [`TestServer::register`]. Their key files are written to the
    /// server's `key_dir`, and the [`TestKeyServer`] serves them.
    pub fn identity_domain(mut self, domain: &str) -> Self {
        self.config.identity_domain = Some(domain.to_owned());
        self.config.server.registration = true;
        self
    }

    /// Identities at `domains` may sign in: a [`TestKeyServer`] serves
    /// their key files, and the server fetches them from it (4.4). Make
    /// them with [`TestServer::identity`].
    pub fn key_domains(mut self, domains: &[&str]) -> Self {
        self.key_domains
            .extend(domains.iter().map(|d| (*d).to_owned()));
        self
    }

    /// How long after an identity's last connection closes it is reported
    /// offline, and how long presence changes are collected before they
    /// are sent (8.3). Unlike `limits.presence_offline_secs` and
    /// `limits.presence_batch_ms`, these may be any length, so that tests
    /// can watch presence change. Without it, the configuration's values
    /// are used: 30 seconds and 1 second.
    pub fn presence(mut self, offline: Duration, batch: Duration) -> Self {
        self.presence = Some((offline, batch));
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
        let mut timers = Timers::from_config(&config);
        if let Some(wait) = self.guest_resume {
            timers.guest_resume = wait;
        }
        if let Some((offline, batch)) = self.presence {
            timers.presence_offline = offline;
            timers.presence_batch = batch;
        }
        let hosted = config.identity_domain.clone();
        let keys = if self.key_domains.is_empty() && hosted.is_none() {
            None
        } else {
            let domains: Vec<&str> = self.key_domains.iter().map(String::as_str).collect();
            let keys = TestKeyServer::start_with(
                &domains,
                hosted.as_deref().map(|d| (d, config.key_dir())),
            )
            .await;
            config.keys.extra_roots.push(keys.ca_path().to_owned());
            config.keys.allow_private = true;
            Some(keys)
        };
        let mut server = TestServer {
            config,
            timers,
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            fingerprint: None,
            running: None,
            keys,
            dir: Some(dir),
        };
        server.launch().await;
        server
    }
}

/// Key file fetching from `keys` for a server with `config`, and
/// publishing into its `key_dir`: `[keys]` as configured, with the key
/// server's resolver, and no limit on refetching (see the [module
/// documentation](self)).
async fn key_services(config: &Config, keys: &TestKeyServer) -> KeyServices {
    let keys_config = config.keys.clone();
    let mut options =
        tokio::task::spawn_blocking(move || crate::http::fetch::fetch_options(&keys_config))
            .await
            .expect("reading [keys]")
            .expect("reading the test CA");
    options.resolver = std::sync::Arc::new(keys.resolver());
    options.min_refetch = Duration::ZERO;
    let fetcher = HttpsKeyFetcher(risala_keyfetch::KeyFetcher::new(options));
    KeyServices::shared(
        std::sync::Arc::new(fetcher),
        std::sync::Arc::new(KeyDir::new(config.key_dir())),
    )
}

fn prepare_store(config: &Config, prepare: Vec<Prepare>) {
    std::fs::create_dir_all(&config.state_dir).expect("creating the state directory");
    let store = SqliteStore::open(&config.database_path()).expect("opening the database");
    store.set_durable(false).expect("speeding up the database");
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
    timers: Timers,
    addr: SocketAddr,
    fingerprint: Option<Fingerprint>,
    running: Option<Running>,
    keys: Option<TestKeyServer>,
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
            guest_resume: None,
            presence: None,
            key_domains: Vec::new(),
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
        self.guest_session(name, None).await.0
    }

    /// Connects, reads the greeting and sends `GUEST <name>`, with
    /// `token=<token>` if there is one, to start or resume a guest session
    /// (4.2). Returns the client and the token from the `OK`. The next line
    /// to read is whatever comes after `OK`.
    pub async fn guest_session(&self, name: &str, token: Option<&str>) -> (TestClient, String) {
        let mut client = self.connect().await;
        let greeting = client.expect_line().await.expect("a greeting");
        assert!(greeting.starts_with("RISALA 1 "), "greeting: {greeting}");
        let command = match token {
            Some(token) => format!("GUEST {name} token={token}"),
            None => format!("GUEST {name}"),
        };
        client.send(&command).await.expect("sending");
        let ok = client.expect_line().await.expect("an answer to GUEST");
        let prefix = format!("OK uid=~{name} token=");
        let rest = ok
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("answer to GUEST {name}: {ok}"));
        // A resumed session's OK carries resumed=yes too (4.2).
        let new_token = rest.strip_suffix(" resumed=yes").unwrap_or(rest);
        assert!(!new_token.contains(' '), "answer to GUEST {name}: {ok}");
        (client, new_token.to_owned())
    }

    /// The key server, which serves the key files of identities that are
    /// not hosted here, and of hosted ones. Panics if the server has
    /// neither [`identity_domain`](TestServerBuilder::identity_domain) nor
    /// [`key_domains`](TestServerBuilder::key_domains).
    pub fn key_server(&self) -> &TestKeyServer {
        self.keys
            .as_ref()
            .expect("the test server has no identities: use identity_domain or key_domains")
    }

    /// A new identity at one of the [`key_domains`](TestServerBuilder::key_domains),
    /// with one device, whose key file the key server now serves (4.4).
    /// Sign in with [`sign_in`](Self::sign_in).
    pub fn identity(&self, identity: &str) -> TestIdentity {
        self.key_server().new_identity(identity)
    }

    /// A new device of `of`'s identity, with its own key: added to its key
    /// file on the key server, or for a hosted identity with `KEY ADD`
    /// (4.7) from a connection signed in as `of`, which then quits.
    pub async fn new_device(&self, of: &TestIdentity) -> TestIdentity {
        if !self.hosts(of) {
            return self.key_server().new_device(of);
        }
        let device = of.new_key();
        let mut conn = self.sign_in(of).await;
        let command = format!("@ref=testkey KEY ADD {} device", device.public_key());
        conn.send(&command).await.expect("sending");
        loop {
            let line = conn.expect_line().await.expect("an answer to KEY ADD");
            if line.starts_with("@ref=testkey ") {
                assert_eq!(line, "@ref=testkey OK", "answer to KEY ADD");
                break;
            }
        }
        conn.send("QUIT").await.expect("sending");
        device
    }

    /// Whether `who` is hosted here (4.6).
    fn hosts(&self, who: &TestIdentity) -> bool {
        self.config
            .identity_domain()
            .is_some_and(|d| d.as_str() == who.identity().domain())
    }

    /// Connects, reads the greeting and sends `AUTH` for `who` (4.5),
    /// signing for the server's hostname, which it sends in SNI. Returns
    /// the client and the answer: `OK uid=<uid>` (with ` op=yes` for an
    /// operator) or an `ERR`.
    pub async fn auth(&self, who: &TestIdentity) -> (TestClient, String) {
        let (mut client, nonce) = self.connect_for_sign_in().await;
        client
            .send(&who.auth_line(&self.config.hostname, &nonce))
            .await
            .expect("sending");
        let answer = client.expect_line().await.expect("an answer to AUTH");
        (client, answer)
    }

    /// Connects and signs in as `who` (4.5). Panics unless AUTH succeeds.
    /// The next line to read is whatever comes after `OK`: live events of
    /// the identity's rooms start at once (7.1).
    pub async fn sign_in(&self, who: &TestIdentity) -> TestClient {
        let (client, answer) = self.auth(who).await;
        let ok = format!("OK uid={}", who.identity());
        assert!(
            answer == ok || answer == format!("{ok} op=yes"),
            "answer to AUTH {}: {answer}",
            who.identity()
        );
        client
    }

    /// Connects and registers `<name>@<identity domain>` (4.6) with a new
    /// key. Returns the new identity's device and the connection, signed
    /// in. Panics unless REGISTER succeeds; the server needs an
    /// [`identity_domain`](TestServerBuilder::identity_domain).
    pub async fn register(&self, name: &str) -> (TestIdentity, TestClient) {
        let domain = self
            .config
            .identity_domain
            .clone()
            .expect("the test server has no identity_domain");
        let who = TestIdentity::new(&format!("{name}@{domain}"));
        let (mut client, nonce) = self.connect_for_sign_in().await;
        client
            .send(&who.register_line(&self.config.hostname, &nonce))
            .await
            .expect("sending");
        let answer = client.expect_line().await.expect("an answer to REGISTER");
        assert_eq!(
            answer,
            format!("OK uid={}", who.identity()),
            "answer to REGISTER {name}"
        );
        (who, client)
    }

    /// Connects and reads the greeting. Returns the client and the
    /// greeting's nonce (4.1).
    async fn connect_for_sign_in(&self) -> (TestClient, risala_proto::auth::Nonce) {
        let mut client = self.connect().await;
        let greeting = client.expect_line().await.expect("a greeting");
        let nonce = greeting
            .strip_prefix("RISALA 1 ")
            .and_then(|rest| rest.split(' ').nth(1))
            .unwrap_or_else(|| panic!("greeting: {greeting}"))
            .parse()
            .unwrap_or_else(|e| panic!("the greeting's nonce: {e}: {greeting}"));
        (client, nonce)
    }

    /// Stops the server and starts it again on the same directory and
    /// address, as after a restart of `risalad`. Connections are closed
    /// with `BYE server shutting down` (11), and guest sessions end, so
    /// their guests leave their rooms (4.2).
    pub async fn restart(&mut self) {
        self.shut_down().await;
        self.launch().await;
    }

    /// Stops the server, runs `f` while it is stopped, then starts it again
    /// as [`restart`](Self::restart) does. `f` gets the configuration, to
    /// change the files under [`state_dir`](Self::state_dir), for example
    /// to remove a room from the database with SQL so that it is created
    /// again with a new id, as after ADMIN DROP (10.4). Rooms from
    /// [`room`](TestServerBuilder::room) that are missing are created
    /// again when the server starts.
    pub async fn restart_with(&mut self, f: impl FnOnce(&Config) + Send + 'static) {
        self.shut_down().await;
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || f(&config))
            .await
            .expect("changing the stopped server");
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
        let daemon = match &self.keys {
            None => Daemon::bind_with(config, self.timers).await,
            Some(keys) => {
                let services = key_services(&config, keys).await;
                Daemon::bind_full(config, self.timers, Some(services)).await
            }
        }
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
        let mut dir = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
        dir.create(&path).expect("creating a temporary directory");
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

/// A TCP proxy in front of a server, which cuts its connections on
/// command, for tests of dropped connections.
///
/// **For tests only.** It forwards bytes unchanged, so TLS runs end to end
/// between the client and the server behind it. Cutting a connection
/// closes both of its sockets at once, with no TLS `close_notify` and no
/// BYE, as when a network goes away: the client sees the connection end,
/// and the server notices and records a guest's PARTs (4.2).
///
/// ```no_run
/// # async fn f() {
/// use risala_server::testing::{Proxy, TestServer};
///
/// let server = TestServer::builder().room("#general").start().await;
/// let proxy = Proxy::start(server.addr()).await;
/// // Connect clients to proxy.addr() instead of server.addr().
/// proxy.cut_after(Some(5000)); // Each new connection ends after 5000 bytes from the server.
/// proxy.cut(); // Every open connection ends now.
/// # }
/// ```
#[derive(Debug)]
pub struct Proxy {
    addr: SocketAddr,
    shared: std::sync::Arc<ProxyShared>,
    task: JoinHandle<()>,
}

#[derive(Debug)]
struct ProxyShared {
    target: SocketAddr,
    /// Bumped by [`Proxy::cut`]; a link ends when it changes.
    generation: tokio::sync::watch::Sender<u64>,
    /// Bytes from the server after which a new link ends.
    budget: std::sync::Mutex<Option<u64>>,
    /// Links accepted so far.
    accepted: std::sync::atomic::AtomicU64,
    /// While true, bytes from the server are held back.
    held: tokio::sync::watch::Sender<bool>,
}

impl Proxy {
    /// Starts a proxy on `127.0.0.1` with a port the system chooses,
    /// forwarding to `target`.
    pub async fn start(target: SocketAddr) -> Proxy {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("binding the proxy");
        let addr = listener.local_addr().expect("the proxy's address");
        let shared = std::sync::Arc::new(ProxyShared {
            target,
            generation: tokio::sync::watch::channel(0).0,
            budget: std::sync::Mutex::new(None),
            accepted: std::sync::atomic::AtomicU64::new(0),
            held: tokio::sync::watch::channel(false).0,
        });
        let task = tokio::spawn(proxy_accept(listener, shared.clone()));
        Proxy { addr, shared, task }
    }

    /// The address to connect to instead of the server's.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Cuts every connection open now. Later connections go through.
    pub fn cut(&self) {
        self.shared.generation.send_modify(|g| *g += 1);
    }

    /// Makes each connection opened from now on end after the server has
    /// sent `bytes` bytes through it, counting the TLS handshake. `None`
    /// lets them run.
    pub fn cut_after(&self, bytes: Option<u64>) {
        *self.shared.budget.lock().expect("poisoned") = bytes;
    }

    /// Holds back what the server sends on every connection, open or new,
    /// without closing them, or lets it through again. Bytes from the
    /// client still reach the server. A [`cut`](Self::cut) while holding
    /// drops what was held, so a test can let a command reach the server
    /// and then cut the connection before its answer arrives.
    pub fn hold(&self, on: bool) {
        self.shared.held.send_replace(on);
    }

    /// How many connections the proxy has accepted.
    pub fn connections(&self) -> u64 {
        self.shared
            .accepted
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.cut();
        self.task.abort();
    }
}

async fn proxy_accept(listener: tokio::net::TcpListener, shared: std::sync::Arc<ProxyShared>) {
    while let Ok((client, _)) = listener.accept().await {
        shared
            .accepted
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let budget = *shared.budget.lock().expect("poisoned");
        let cut = shared.generation.subscribe();
        let held = shared.held.subscribe();
        let target = shared.target;
        tokio::spawn(async move {
            if let Ok(server) = tokio::net::TcpStream::connect(target).await {
                proxy_link(client, server, budget, cut, held).await;
            }
        });
    }
}

/// Copies bytes both ways until either side closes, the budget of bytes
/// from the server runs out, or the proxy cuts. Bytes from the server wait
/// while `held` is true. Dropping the sockets closes them.
async fn proxy_link(
    client: tokio::net::TcpStream,
    server: tokio::net::TcpStream,
    mut budget: Option<u64>,
    mut cut: tokio::sync::watch::Receiver<u64>,
    mut held: tokio::sync::watch::Receiver<bool>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut server_rd, mut server_wr) = server.into_split();
    let up = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match client_rd.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if server_wr.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    };
    let down = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match server_rd.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let n = match &mut budget {
                Some(left) => {
                    let n = n.min(usize::try_from(*left).unwrap_or(usize::MAX));
                    *left -= n as u64;
                    n
                }
                None => n,
            };
            if held.wait_for(|h| !*h).await.is_err() {
                return;
            }
            if client_wr.write_all(&buf[..n]).await.is_err() {
                return;
            }
            if budget == Some(0) {
                return;
            }
        }
    };
    tokio::select! {
        () = up => {}
        () = down => {}
        _ = cut.changed() => {}
    }
}

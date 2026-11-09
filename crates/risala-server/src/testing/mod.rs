//! A whole server for tests, here and in other crates.
//!
//! **For tests only.** [`TestServer`] runs a real `risalad` (the
//! [`Hub`] behind the [network layer](crate::net)) in
//! the current tokio runtime, on `127.0.0.1` with a port the system
//! chooses, with its database and a generated self-signed certificate in a
//! temporary directory. [`TestClient`] talks to it line by line over TLS,
//! accepting any certificate.
//!
//! ```no_run
//! # async fn f() {
//! use risala_server::testing::TestServer;
//!
//! let server = TestServer::start().await;
//! let mut sam = server.guest("sam").await;
//! sam.send("ping").await.unwrap();
//! assert_eq!(sam.expect_line().await.unwrap(), "OK");
//! let mut anon = server.anon().await;
//! anon.send("quit").await.unwrap();
//! server.stop().await;
//! # }
//! ```
//!
//! Every method panics when something fails, since it runs in a test.
//!
//! # Identities
//!
//! Identities whose key files a [`TestKeyServer`] serves over HTTPS (4.4)
//! can be made with [`TestServer::identity`] once their domains are named
//! with [`key_domains`](TestServerBuilder::key_domains). The server
//! fetches their key files for real: it trusts the key server's test CA
//! through `[keys] extra_roots`, may fetch from `127.0.0.1` through
//! `[keys] allow_private`, and sends each domain to its listener with a
//! test resolver. [`TestServer::auth`] sends AUTH (4.6) for one. The
//! resolver also sends the server's own hostname to its own HTTPS
//! listener, when `http.listen` names a port, so that a witness can fetch
//! its own log's key (4.10).
//!
//! Their chains name a log of their own domain, which nothing serves, so
//! their key files list every record unlogged (4.4).
//!
//! With [`identity_domain`](TestServerBuilder::identity_domain), the
//! server hosts identities (4.7): [`TestServer::register`] registers one,
//! with a [`TestChain`] that names the server's key log.
//!
//! # Time
//!
//! [`manual_clock`](TestServerBuilder::manual_clock) stops the server's
//! clock, which stamps posts (3.2) and decides what has expired (7.5):
//! move it with [`TestServer::advance`].
//!
//! # Development servers
//!
//! `risala-dev` runs a server from this module for the apps to develop
//! against, which needs a few options that tests do not. Each is off
//! unless asked for, so a test server stays as described above.
//!
//! - [`state_dir`](TestServerBuilder::state_dir) keeps the database, the
//!   self-signed certificate and the hosted identities' key files in a
//!   directory of your choosing, which is not deleted. A server started
//!   again on it carries on, with the same certificate fingerprint, so a
//!   client's pinned fingerprint stays valid.
//! - [`listen`](TestServerBuilder::listen) chooses the address and port.
//! - [`manual_clock_at`](TestServerBuilder::manual_clock_at) stops the
//!   clock at a time in the past, [`TestServer::set_time`] moves it, and
//!   [`TestServer::follow_system_clock`] lets it run on the system clock.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use risala_proto::fingerprint::Fingerprint;
use risala_proto::time::Timestamp;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, Limits};
use crate::core::{Clock, Hub, ManualClock, SystemClock, Timers};
use crate::daemon::{Daemon, RunError};
use crate::http::{HttpsKeyFetcher, KeyDir};
use crate::keyfiles::KeyServices;
use crate::store::SqliteStore;

mod identities;

pub use crate::net::testing::{ClientOptions, RECV_TIMEOUT, TestClient};
pub use identities::{TestChain, TestIdentity, TestKeyServer, test_log_key};

/// How long [`TestServer::stop`] waits for the server to finish.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// A preparation step, run on the database before the server starts.
type Prepare = Box<dyn FnOnce(&SqliteStore) + Send>;

/// Builds a [`TestServer`]. Get one from [`TestServer::builder`].
///
/// Unless changed, the server:
///
/// - is called `localhost`
/// - allows anonymous connections and guests, has no welcome text, and
///   uses the default [`Limits`]
/// - hosts no identities, and fetches no key files
#[must_use]
pub struct TestServerBuilder {
    config: Config,
    prepare: Vec<Prepare>,
    guest_resume: Option<Duration>,
    presence: Option<(Duration, Duration)>,
    key_domains: Vec<String>,
    clock: Option<std::sync::Arc<ManualClock>>,
    state_dir: Option<PathBuf>,
    listen: Option<SocketAddr>,
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

    /// Whether anonymous connections may be opened (`server.anon`).
    pub fn anon(mut self, allowed: bool) -> Self {
        self.config.server.anon = allowed;
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

    /// Hosts identities under `domain` (`identity_domain`, 4.7), with
    /// registration open (`server.registration`). Their key files are
    /// written to the server's `key_dir`, and the [`TestKeyServer`] serves
    /// them.
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

    /// Makes `identity` one of the server's operators, in the
    /// configuration (`operators`, 10.1), so that ADMIN DEOP cannot remove
    /// it. It still has to sign in.
    pub fn operator(mut self, identity: &str) -> Self {
        self.config.operators.push(identity.to_owned());
        self
    }

    /// Stops the server's clock at the current time. It moves only with
    /// [`TestServer::advance`], and stays where it is across
    /// [`restart`](TestServer::restart). Posts are stamped with it (3.2),
    /// and retention (7.5) and the rate limits that count per hour or per
    /// day measure time by it. Timers for connections, guest sessions and
    /// presence still run on real time.
    pub fn manual_clock(self) -> Self {
        self.manual_clock_at(Timestamp::now())
    }

    /// Like [`manual_clock`](Self::manual_clock), with the clock stopped at
    /// `t` instead of now, for history with past dates. Move it with
    /// [`TestServer::set_time`] or [`TestServer::advance`], and let it run
    /// with [`TestServer::follow_system_clock`].
    pub fn manual_clock_at(mut self, t: Timestamp) -> Self {
        self.clock = Some(std::sync::Arc::new(ManualClock::new(t)));
        self
    }

    /// Keeps the server's state in `dir`, created if missing, instead of a
    /// temporary directory: the database, the self-signed certificate and
    /// its key, and the hosted identities' key files. The directory is not
    /// deleted when the server stops, and a server started on it again
    /// carries on with what is there, with the same certificate
    /// fingerprint. For development servers (see the [module
    /// documentation](self)); tests should leave it out.
    pub fn state_dir(mut self, dir: &Path) -> Self {
        self.state_dir = Some(dir.to_owned());
        self
    }

    /// Listens on `addr` instead of `127.0.0.1` with a port the system
    /// chooses. Port 0 still lets the system choose.
    pub fn listen(mut self, addr: SocketAddr) -> Self {
        self.listen = Some(addr);
        self
    }

    /// Changes anything else in the configuration. `listen` and
    /// `state_dir` are replaced when the server starts.
    pub fn configure(mut self, f: impl FnOnce(&mut Config)) -> Self {
        f(&mut self.config);
        self
    }

    /// Runs `f` on the database before the server opens it, for state that
    /// commands cannot make yet. Steps run in the order they were added.
    pub fn prepare(mut self, f: impl FnOnce(&SqliteStore) + Send + 'static) -> Self {
        self.prepare.push(Box::new(f));
        self
    }

    /// Starts the server and returns once it accepts connections.
    pub async fn start(self) -> TestServer {
        let mut config = self.config;
        let dir = match self.state_dir {
            Some(path) => {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
                builder.create(&path).expect("creating the state directory");
                config.state_dir = path;
                None
            }
            None => {
                let dir = TempDir::new();
                config.state_dir = dir.path().to_owned();
                Some(dir)
            }
        };
        let addr = self
            .listen
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
        config.listen = vec![addr];
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
            clock: self.clock,
            timers,
            addr,
            fingerprint: None,
            running: None,
            keys,
            dir,
        };
        server.launch().await;
        server
    }
}

/// Key file fetching from `keys` for a server with `config`, and
/// publishing into its `key_dir`: `[keys]` as configured, with the key
/// server's resolver, and no limit on refetching (see the [module
/// documentation](self)).
///
/// The resolver also sends the server's own hostname to its own HTTPS
/// listener, when `http.listen` names a port, so that its witness can
/// fetch the key of its own log as it would another host's (4.10).
async fn key_services(config: &Config, keys: &TestKeyServer) -> KeyServices {
    let keys_config = config.keys.clone();
    let mut options =
        tokio::task::spawn_blocking(move || crate::http::fetch::fetch_options(&keys_config))
            .await
            .expect("reading [keys]")
            .expect("reading the test CA");
    let mut resolver = keys.resolver();
    if let Some(listen) = config.http.listen.first().filter(|a| a.port() != 0)
        && !keys.serves(&config.hostname)
    {
        let mut own = *listen;
        if own.ip().is_unspecified() {
            own.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
        }
        resolver.insert(&config.hostname, [own]);
    }
    options.resolver = std::sync::Arc::new(resolver);
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
    clock: Option<std::sync::Arc<ManualClock>>,
    timers: Timers,
    addr: SocketAddr,
    fingerprint: Option<Fingerprint>,
    running: Option<Running>,
    keys: Option<TestKeyServer>,
    dir: Option<TempDir>,
}

#[derive(Debug)]
struct Running {
    hub: Hub,
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
            clock: None,
            state_dir: None,
            listen: None,
        }
    }

    /// The address the server listens on: on `127.0.0.1` unless
    /// [`listen`](TestServerBuilder::listen) chose another. It stays the
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
    /// deleted when the server is dropped or stopped, unless it was given
    /// with [`state_dir`](TestServerBuilder::state_dir).
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

    /// Connects, reads the greeting and sends ANON (4.2). The next line to
    /// read is whatever comes after `OK`.
    pub async fn anon(&self) -> TestClient {
        let mut client = self.connect().await;
        let greeting = client.expect_line().await.expect("a greeting");
        assert!(greeting.starts_with("RISALA 1 "), "greeting: {greeting}");
        client.send("ANON").await.expect("sending");
        let ok = client.expect_line().await.expect("an answer to ANON");
        assert_eq!(ok, "OK", "answer to ANON");
        client
    }

    /// Connects, reads the greeting and becomes the guest `~<name>` (4.2).
    /// The next line to read is whatever comes after `OK`.
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

    /// Connects, reads the greeting and sends `AUTH` for `who` (4.6),
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

    /// Connects and signs in as `who` (4.6). Panics unless AUTH succeeds.
    /// The next line to read is whatever comes after `OK`.
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

    /// Registers `<name>@<identity domain>` (4.7) with a new chain that
    /// names the server's key log, and its first device. Panics unless
    /// REGISTER succeeds. Returns the client, signed in as the new
    /// identity, the chain, and the device.
    pub async fn register(&self, name: &str) -> (TestClient, TestChain, TestIdentity) {
        let domain = self
            .config
            .identity_domain
            .as_deref()
            .expect("the test server has no identity_domain");
        let log = self
            .hub()
            .key_log()
            .expect("a server with an identity domain has a log");
        let (chain, device) = TestChain::new(&format!("{name}@{domain}"), &log.log);
        let (mut client, nonce) = self.connect_for_sign_in().await;
        client
            .send(&chain.register_line(&device, &self.config.hostname, &nonce))
            .await
            .expect("sending");
        let answer = client.expect_line().await.expect("an answer to REGISTER");
        let ok = format!("OK uid={}", chain.identity());
        assert!(
            answer == ok || answer == format!("{ok} op=yes"),
            "answer to REGISTER {name}: {answer}"
        );
        (client, chain, device)
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

    /// Moves the server's clock forward by `by`. Needs
    /// [`manual_clock`](TestServerBuilder::manual_clock).
    pub fn advance(&self, by: Duration) {
        self.clock
            .as_ref()
            .expect("the test server has no manual_clock")
            .advance(by);
    }

    /// Sets the server's clock to `t`, which posts from now on are stamped
    /// with. Needs [`manual_clock`](TestServerBuilder::manual_clock) or
    /// [`manual_clock_at`](TestServerBuilder::manual_clock_at). Panics if
    /// `t` is earlier than the clock's time, since posts are stamped in
    /// order.
    pub fn set_time(&self, t: Timestamp) {
        let clock = self
            .clock
            .as_ref()
            .expect("the test server has no manual_clock");
        assert!(t >= clock.now(), "the clock does not go back");
        clock.set(t);
    }

    /// Lets the [manual clock](TestServerBuilder::manual_clock) run on the
    /// system clock from now on, never going back: when it is ahead of the
    /// system clock, it waits there until the system clock passes it.
    /// [`set_time`](Self::set_time) and [`advance`](Self::advance) can
    /// still move it forward.
    pub fn follow_system_clock(&self) {
        self.clock
            .as_ref()
            .expect("the test server has no manual_clock")
            .follow_system();
    }

    /// The server's time now: the [manual clock](TestServerBuilder::manual_clock)'s
    /// if it has one.
    pub fn now(&self) -> Timestamp {
        self.clock.as_ref().map_or_else(Timestamp::now, |c| c.now())
    }

    /// The running server's hub, for tests that act on it directly, such
    /// as ending a guest session at once (4.2).
    pub fn hub(&self) -> &Hub {
        &self
            .running
            .as_ref()
            .expect("the test server is running")
            .hub
    }

    /// Stops the server and starts it again on the same directory and
    /// address, as after a restart of `risalad`. Connections are closed
    /// with `BYE server shutting down` (11), and guest sessions end
    /// (4.2).
    pub async fn restart(&mut self) {
        self.shut_down().await;
        self.launch().await;
    }

    /// Stops the server, runs `f` while it is stopped, then starts it again
    /// as [`restart`](Self::restart) does. `f` gets the configuration, to
    /// change the files under [`state_dir`](Self::state_dir).
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
        let services = match &self.keys {
            None => None,
            Some(keys) => Some(key_services(&config, keys).await),
        };
        let clock: std::sync::Arc<dyn Clock> = match &self.clock {
            Some(clock) => clock.clone(),
            None => std::sync::Arc::new(SystemClock),
        };
        let daemon = Daemon::bind_clock(config, self.timers, services, clock)
            .await
            .expect("starting the test server");
        let hub = daemon.hub().clone();
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
        self.running = Some(Running { hub, stop, task });
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
/// and the server notices, and starts a guest's resume period (4.2).
///
/// ```no_run
/// # async fn f() {
/// use risala_server::testing::{Proxy, TestServer};
///
/// let server = TestServer::start().await;
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

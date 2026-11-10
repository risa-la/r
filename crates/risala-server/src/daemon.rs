//! The whole server: the [`Hub`] behind the network layer
//! ([`net::Server`]), as `risalad` runs it.
//!
//! [`run`] starts a server from a [`Config`] and runs it until a shutdown
//! future resolves. [`Daemon`] splits that in two, binding first, so the
//! caller can read the addresses and the fingerprint before it runs:
//!
//! ```no_run
//! # async fn f() -> Result<(), risala_server::RunError> {
//! use risala_server::{Daemon, config::Config};
//!
//! let daemon = Daemon::bind(Config::default()).await?;
//! println!("listening on {:?}", daemon.local_addrs());
//! println!("fingerprint {}", daemon.fingerprint());
//! daemon
//!     .run(async {
//!         let _ = tokio::signal::ctrl_c().await;
//!     })
//!     .await
//! # }
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use risala_proto::fingerprint::Fingerprint;

use crate::config::Config;
use crate::core::{BYE_SHUTDOWN, Clock, Hub, HubError, SystemClock, Timers};
use crate::http::{self, HttpServer, KeyDir};
use crate::keyfiles::KeyServices;
use crate::net;

/// An error starting or running the server.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The hub could not start: the database could not be opened, or the
    /// configuration has a bad value.
    #[error(transparent)]
    Hub(#[from] HubError),
    /// A listener could not be bound, or a certificate could not be loaded
    /// or generated.
    #[error("{0}")]
    Net(#[from] std::io::Error),
}

/// A server that has opened its database, loaded its certificates and
/// bound its listeners, but does not accept connections yet.
pub struct Daemon {
    server: net::Server<Hub>,
    hub: Hub,
    http: Option<HttpServer>,
    key_dir: Arc<KeyDir>,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("server", &self.server)
            .field("http", &self.http)
            .field("key_dir", &self.key_dir)
            .finish_non_exhaustive()
    }
}

impl Daemon {
    /// Opens the database at [`Config::database_path`] (creating the state
    /// directory if needed), loads or generates the certificates (2.2),
    /// sets up key file fetching (4.4)
    /// and binds every address in `config.listen`, and in `http.listen`
    /// for the HTTPS listener.
    ///
    /// Port 0 lets the system choose; [`local_addrs`](Self::local_addrs)
    /// says what it chose.
    pub async fn bind(config: Config) -> Result<Daemon, RunError> {
        let timers = Timers::from_config(&config);
        Daemon::bind_with(config, timers).await
    }

    /// [`Daemon::bind`] with timers that need not follow the
    /// configuration, for tests.
    pub(crate) async fn bind_with(config: Config, timers: Timers) -> Result<Daemon, RunError> {
        Daemon::bind_full(config, timers, None).await
    }

    /// [`Daemon::bind`], fetching and publishing key files with `keys`
    /// (4.4, 4.7) instead of over HTTPS and into `key_dir`, for tests.
    pub async fn bind_with_keys(config: Config, keys: KeyServices) -> Result<Daemon, RunError> {
        let timers = Timers::from_config(&config);
        Daemon::bind_full(config, timers, Some(keys)).await
    }

    /// Binds with `keys`, or else with key files fetched over HTTPS as
    /// `[keys]` says (4.4) and hosted ones written to `key_dir` (4.6).
    pub(crate) async fn bind_full(
        config: Config,
        timers: Timers,
        keys: Option<KeyServices>,
    ) -> Result<Daemon, RunError> {
        Daemon::bind_clock(config, timers, keys, Arc::new(SystemClock)).await
    }

    /// [`Daemon::bind_full`] with a clock of your choosing, for tests.
    pub(crate) async fn bind_clock(
        config: Config,
        timers: Timers,
        keys: Option<KeyServices>,
        clock: Arc<dyn Clock>,
    ) -> Result<Daemon, RunError> {
        // Opening SQLite, reading certificates and generating a key all
        // block, so keep them off the runtime's worker threads.
        tokio::task::spawn_blocking(move || {
            let key_dir = Arc::new(KeyDir::new(config.key_dir()));
            let keys = match keys {
                Some(keys) => keys,
                None => {
                    KeyServices::shared(http::fetch::from_config(&config.keys)?, key_dir.clone())
                }
            };
            let hub = Hub::open_with(config, timers, keys, clock)?;
            let server = net::Server::bind(hub.config(), Arc::new(hub.clone()))?;
            let config = hub.config();
            let http = if config.http.listen.is_empty() {
                None
            } else if config.http.certs.is_empty() {
                // The risala listener's certificates, which it reloads.
                let certs = server.certificates().clone();
                Some(HttpServer::bind(
                    &config.http.listen,
                    certs,
                    false,
                    Arc::new(hub.clone()),
                )?)
            } else {
                let certs = net::Certificates::from_pairs(config.http.certs.clone())?;
                Some(HttpServer::bind(
                    &config.http.listen,
                    certs,
                    true,
                    Arc::new(hub.clone()),
                )?)
            };
            // Blobs and files go through the HTTPS listener (5.6, 12.12),
            // at the origin `files.url` names, or else at the hostname and
            // the listener's port.
            let http = http.map(|http| {
                let http = http.with_per_address(config.limits.https_connections_per_address);
                let port = http.local_addrs().first().map_or(443, SocketAddr::port);
                let url = match port {
                    443 => format!("https://{}", hub.config().hostname),
                    port => format!("https://{}:{port}", hub.config().hostname),
                };
                hub.set_files_url(&url);
                http.with_files(&hub)
            });
            Ok(Daemon {
                server,
                hub,
                http,
                key_dir,
            })
        })
        .await
        .map_err(|e| RunError::Net(std::io::Error::other(e)))?
    }

    /// The addresses the server listens on, in the order of
    /// `config.listen`, with the ports the system chose.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        self.server.local_addrs()
    }

    /// The fingerprint of the certificate a client gets without SNI (2.2),
    /// as Appendix A's openssl pipeline prints it.
    pub fn fingerprint(&self) -> Fingerprint {
        self.server.fingerprint()
    }

    /// The fingerprints of every certificate, in configuration order.
    pub fn fingerprints(&self) -> Vec<Fingerprint> {
        self.server.certificates().fingerprints()
    }

    /// The configuration the server runs with.
    pub fn config(&self) -> &Config {
        self.hub.config()
    }

    /// The hub, for tests that act on it directly.
    pub(crate) fn hub(&self) -> &Hub {
        &self.hub
    }

    /// The addresses the HTTPS listener listens on, in the order of
    /// `http.listen`, with the ports the system chose. Empty when it is
    /// off.
    pub fn http_addrs(&self) -> &[SocketAddr] {
        self.http.as_ref().map_or(&[], HttpServer::local_addrs)
    }

    /// The key file directory, where hosted identities' key files are
    /// published (4.6) for another web server to serve. The HTTPS
    /// listener serves them from the hub's records instead.
    pub fn key_dir(&self) -> &Arc<KeyDir> {
        &self.key_dir
    }

    /// Accepts connections until `shutdown` resolves, then says BYE to
    /// every connection (11) and returns once they have closed, or after a
    /// grace period (see [`net::Server::run`]). Then every guest session
    /// ends, connected or waiting to be resumed, and its public rooms get
    /// GONE (4.2) before this returns.
    ///
    /// Meanwhile, every area does its background work
    /// ([`Hub::maintain`]), and the HTTPS listener, if there is one, serves
    /// key files. Both stop when this returns.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
        let _maintain = AbortOnDrop(tokio::spawn(self.hub.clone().maintain()));
        let _http = self.http.map(|http| {
            AbortOnDrop(tokio::spawn(async move {
                if let Err(e) = http.run(std::future::pending()).await {
                    tracing::error!(error = %e, "the HTTPS listener stopped");
                }
            }))
        });
        let result = self.server.run(shutdown).await;
        // Sessions do not survive a restart (4.2): those waiting to be
        // resumed, and those whose connections just closed, end now.
        self.hub.end_guest_sessions(BYE_SHUTDOWN).await;
        result?;
        Ok(())
    }
}

/// Stops a background task when the daemon stops, however it stops.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs a server with `config` until `shutdown` resolves: [`Daemon::bind`],
/// then [`Daemon::run`].
pub async fn run(config: Config, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
    Daemon::bind(config).await?.run(shutdown).await
}

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
use crate::core::{Hub, HubError};
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
#[derive(Debug)]
pub struct Daemon {
    server: net::Server<Hub>,
    hub: Hub,
}

impl Daemon {
    /// Opens the database at [`Config::database_path`] (creating the state
    /// directory if needed), creates the rooms in `config.rooms`, loads or
    /// generates the certificates (2.2) and binds every address in
    /// `config.listen`.
    ///
    /// Port 0 lets the system choose; [`local_addrs`](Self::local_addrs)
    /// says what it chose.
    pub async fn bind(config: Config) -> Result<Daemon, RunError> {
        // Opening SQLite, reading certificates and generating a key all
        // block, so keep them off the runtime's worker threads.
        tokio::task::spawn_blocking(move || {
            let hub = Hub::open(config)?;
            let server = net::Server::bind(hub.config(), Arc::new(hub.clone()))?;
            Ok(Daemon { server, hub })
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

    /// Accepts connections until `shutdown` resolves, then says BYE to
    /// every connection (11) and returns once they have closed, or after a
    /// grace period (see [`net::Server::run`]). Guests still connected at
    /// shutdown leave their rooms (4.2) before this returns.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
        self.server.run(shutdown).await?;
        Ok(())
    }
}

/// Runs a server with `config` until `shutdown` resolves: [`Daemon::bind`],
/// then [`Daemon::run`].
pub async fn run(config: Config, shutdown: impl Future<Output = ()>) -> Result<(), RunError> {
    Daemon::bind(config).await?.run(shutdown).await
}

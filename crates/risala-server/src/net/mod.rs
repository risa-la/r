//! TLS listeners, connection tasks, line framing and keepalive.
//!
//! [`Server`] accepts TCP on every address in `config.listen`, runs TLS
//! 1.3 (2.1), splits each connection into lines (2.3) and drives a
//! [`Handler`] with the commands that parse. It answers lines that do not
//! parse itself (2.3, 3.6), keeps connections alive with PING (11), and
//! sends BYE to everyone when it shuts down.
//!
//! - [`tls`]: certificates chosen by SNI, reloading, and the generated
//!   self-signed certificate (2.1, 2.2).
//! - [`testing`]: a TLS client for tests, here and in other crates.
//!
//! Owned by task B in docs/plans/M2-M5.md.

mod conn;
pub mod testing;
pub mod tls;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_proto::fingerprint::Fingerprint;
use risala_proto::time::Timestamp;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::handler::{ConnHandle, ConnId, ConnInfo, Handler, conn_channel};
use conn::{CommandRoom, Timers};
pub use tls::Certificates;

/// The most connections open at once, counting those still in their TLS
/// handshake. Connections over the limit are closed as soon as they are
/// accepted. Each network address also has its own cap,
/// `limits.connections_per_address` (4.2).
pub const MAX_CONNECTIONS: usize = 10_000;

/// How long a client has to finish the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long shutdown waits for connections to send what is queued for
/// them, BYE last, before dropping them.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How often certificate files are checked for changes (2.2). SIGHUP
/// reloads them at once.
pub const CERT_POLL: Duration = Duration::from_secs(60);

/// The text of the BYE sent to every connection at shutdown (11).
pub const SHUTDOWN_BYE: &str = "server shutting down";

/// The network side of the server: listeners, TLS and connection tasks,
/// driving a [`Handler`].
///
/// ```no_run
/// # async fn f<H: risala_server::handler::Handler>(handler: std::sync::Arc<H>) -> std::io::Result<()> {
/// use risala_server::{config::Config, net::Server};
///
/// let server = Server::bind(&Config::default(), handler)?;
/// println!("listening on {:?}", server.local_addrs());
/// server
///     .run(async {
///         let _ = tokio::signal::ctrl_c().await;
///     })
///     .await?;
/// # Ok(()) }
/// ```
pub struct Server<H> {
    listeners: Vec<std::net::TcpListener>,
    addrs: Vec<SocketAddr>,
    handler: Arc<H>,
    certs: Certificates,
    acceptor: TlsAcceptor,
    timers: Timers,
    out_queue: usize,
    out_queue_bytes: usize,
    room: CommandRoom,
    handshake_timeout: Duration,
    max_connections: usize,
    /// The most connections one network address may have open; 0 for no
    /// limit.
    pub(crate) per_address: usize,
}

impl<H> std::fmt::Debug for Server<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("addrs", &self.addrs)
            .field("certs", &self.certs)
            .finish_non_exhaustive()
    }
}

impl<H: Handler> Server<H> {
    /// Binds every address in `config.listen` and loads the certificates
    /// (2.1, 2.2). Use port 0 to let the system choose, and
    /// [`local_addrs`](Self::local_addrs) to see what it chose.
    ///
    /// With no certificates configured, this generates a self-signed one,
    /// or reuses the one generated before (see [`Certificates::load`]).
    ///
    /// Fails with [`io::ErrorKind::InvalidInput`] if the limits cannot work
    /// (see [`Config::validate`]).
    pub fn bind(config: &Config, handler: Arc<H>) -> io::Result<Server<H>> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let certs = Certificates::load(config)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls::server_config(&certs)?));
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        for addr in &config.listen {
            let listener = std::net::TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            addrs.push(listener.local_addr()?);
            listeners.push(listener);
        }
        Ok(Server {
            listeners,
            addrs,
            handler,
            certs,
            acceptor,
            timers: Timers {
                idle_ping: Duration::from_secs(config.limits.idle_ping_secs),
                ping_timeout: Duration::from_secs(config.limits.ping_timeout_secs),
            },
            out_queue: config.limits.out_queue,
            out_queue_bytes: config.limits.out_queue_bytes,
            room: CommandRoom {
                lines: config.limits.command_room(),
                bytes: config.limits.command_room_bytes(),
            },
            handshake_timeout: HANDSHAKE_TIMEOUT,
            max_connections: MAX_CONNECTIONS,
            per_address: config.limits.connections_per_address,
        })
    }

    /// The addresses the server listens on, in the order of
    /// `config.listen`, with the ports the system chose.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// The server's certificates. Use this to reload them by hand, or to
    /// read the fingerprint a client will see (2.2).
    pub fn certificates(&self) -> &Certificates {
        &self.certs
    }

    /// The fingerprint of the certificate a client gets without SNI, or
    /// with a name no certificate covers (2.2).
    pub fn fingerprint(&self) -> Fingerprint {
        self.certs.fingerprint()
    }

    /// Accepts connections until `shutdown` resolves.
    ///
    /// Meanwhile, it checks the certificate files for changes every
    /// [`CERT_POLL`] and reloads them on SIGHUP (2.2). At shutdown it stops
    /// accepting, sends `BYE server shutting down` to every connection
    /// (11), waits up to [`SHUTDOWN_GRACE`] for their queues to drain, drops
    /// whatever is left, and returns.
    ///
    /// Fails only if a listener cannot be registered with the runtime.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let listeners = self
            .listeners
            .into_iter()
            .map(TcpListener::from_std)
            .collect::<io::Result<Vec<_>>>()?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let shared = Arc::new(Shared {
            handler: self.handler,
            acceptor: self.acceptor,
            certs: self.certs.clone(),
            timers: self.timers,
            out_queue: self.out_queue,
            out_queue_bytes: self.out_queue_bytes,
            room: self.room,
            handshake_timeout: self.handshake_timeout,
            permits: Arc::new(Semaphore::new(self.max_connections)),
            max_connections: self.max_connections,
            per_address: self.per_address,
            addresses: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            registry: Mutex::new(Registry::default()),
            stop: stop_rx,
        });
        tracing::info!(addrs = ?self.addrs, "listening");

        let mut background = JoinSet::new();
        for listener in listeners {
            background.spawn(accept_loop(listener, shared.clone()));
        }
        background.spawn(watch_certificates(self.certs));

        shutdown.await;
        tracing::info!("shutting down");

        // Stop accepting, and wait until the listeners are closed.
        background.abort_all();
        while background.join_next().await.is_some() {}

        let open = {
            let mut registry = shared.registry();
            registry.shutting_down = true;
            for conn in registry.conns.values() {
                conn.close(Some(SHUTDOWN_BYE.into()));
            }
            registry.conns.len()
        };
        let _ = stop_tx.send(true);
        tracing::debug!(open, "sent BYE to every connection");

        let all = u32::try_from(shared.max_connections).unwrap_or(u32::MAX);
        let drained = tokio::time::timeout(SHUTDOWN_GRACE, shared.permits.acquire_many(all)).await;
        if drained.is_err() {
            let conns: Vec<ConnHandle> = shared.registry().conns.values().cloned().collect();
            tracing::warn!(
                left = conns.len(),
                "dropping connections that did not drain"
            );
            for conn in &conns {
                conn.kill();
            }
            // Killed connections end at once, unless the handler is stuck.
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, shared.permits.acquire_many(all)).await;
        }
        tracing::info!("stopped");
        Ok(())
    }
}

/// What every connection task shares.
struct Shared<H> {
    handler: Arc<H>,
    acceptor: TlsAcceptor,
    /// The certificates, to tell whether a connection's SNI names one.
    certs: Certificates,
    timers: Timers,
    out_queue: usize,
    out_queue_bytes: usize,
    room: CommandRoom,
    handshake_timeout: Duration,
    permits: Arc<Semaphore>,
    max_connections: usize,
    /// The most connections per network address, and how many each has.
    per_address: usize,
    addresses: Mutex<HashMap<IpAddr, usize>>,
    next_id: AtomicU64,
    registry: Mutex<Registry>,
    stop: watch::Receiver<bool>,
}

/// The open connections, so shutdown can reach them.
#[derive(Default)]
struct Registry {
    conns: HashMap<ConnId, ConnHandle>,
    shutting_down: bool,
}

impl<H> Shared<H> {
    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }
}

async fn accept_loop<H: Handler>(listener: TcpListener, shared: Arc<Shared<H>>) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Usually out of file descriptors. Wait rather than spin.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = shared.permits.clone().try_acquire_owned() else {
            // No address at the default levels: it may be an anonymous
            // connection's (4.2).
            tracing::warn!("too many connections, closing a new one");
            continue;
        };
        let Some(slot) = AddressSlot::take(&shared, peer.ip()) else {
            tracing::debug!(
                target: ADDRESSES,
                %peer,
                "too many connections from one address"
            );
            continue;
        };
        let _ = tcp.set_nodelay(true);
        tokio::spawn(connection(shared.clone(), tcp, peer, (permit, slot)));
    }
}

/// The `tracing` target of events that name a network address, so that
/// they can be turned on apart from the rest (4.2: addresses are not
/// logged by default).
pub const ADDRESSES: &str = "risala_server::addresses";

/// One of a network address's connections, counted until dropped.
struct AddressSlot<H> {
    shared: Arc<Shared<H>>,
    key: IpAddr,
}

impl<H> AddressSlot<H> {
    /// Counts a connection from `peer`, unless its network has its fill
    /// (4.2). IPv6 addresses count by their /64. Limits per network
    /// address are the free tier: past them a client will go on by proof of
    /// work, from M6a (PLAN items 42 and 63).
    fn take(shared: &Arc<Shared<H>>, peer: IpAddr) -> Option<AddressSlot<H>> {
        let key = crate::core::rate::network(peer);
        let mut counts = shared.addresses.lock().unwrap_or_else(|e| e.into_inner());
        let n = counts.entry(key).or_default();
        if shared.per_address > 0 && *n >= shared.per_address {
            if *n == 0 {
                counts.remove(&key);
            }
            return None;
        }
        *n += 1;
        Some(AddressSlot {
            shared: shared.clone(),
            key,
        })
    }
}

impl<H> Drop for AddressSlot<H> {
    fn drop(&mut self) {
        let mut counts = self
            .shared
            .addresses
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// One connection, from TCP accept to close. Holds its permit and its
/// address's slot until the end.
async fn connection<H: Handler>(
    shared: Arc<Shared<H>>,
    tcp: TcpStream,
    peer: SocketAddr,
    _held: (OwnedSemaphorePermit, AddressSlot<H>),
) {
    let mut stop = shared.stop.clone();
    let handshake = tokio::time::timeout(shared.handshake_timeout, shared.acceptor.accept(tcp));
    let tls = tokio::select! {
        result = handshake => match result {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                match tls::handshake_failure(&e) {
                    Some(reason) => tracing::info!(reason, "TLS handshake refused"),
                    None => tracing::debug!(target: ADDRESSES, %peer, error = %e, "TLS handshake failed"),
                }
                return;
            }
            Err(_) => {
                tracing::debug!(target: ADDRESSES, %peer, "TLS handshake timed out");
                return;
            }
        },
        _ = stop.wait_for(|stopping| *stopping) => return,
    };

    let session = tls.get_ref().1;
    let sni = session.server_name().map(|s| s.to_ascii_lowercase());
    let alpn = session
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let id = ConnId(shared.next_id.fetch_add(1, Ordering::Relaxed));
    let (handle, receiver) = conn_channel(id, shared.out_queue, shared.out_queue_bytes);
    {
        let mut registry = shared.registry();
        if registry.shutting_down {
            return;
        }
        registry.conns.insert(id, handle.clone());
    }
    tracing::debug!(target: ADDRESSES, conn = id.0, %peer, "connected");
    tracing::debug!(conn = id.0, ?sni, ?alpn, "connected");

    let sni_certified = sni.as_deref().is_some_and(|name| shared.certs.serves(name));
    let info = ConnInfo {
        peer,
        sni,
        sni_certified,
        since: Timestamp::now(),
    };
    conn::serve(
        tls,
        info,
        handle,
        receiver,
        shared.handler.clone(),
        shared.timers,
        shared.room,
        stop,
    )
    .await;
    shared.registry().conns.remove(&id);
}

/// Reloads certificates whose files changed, every [`CERT_POLL`], and all
/// of them on SIGHUP (2.2).
pub(crate) async fn watch_certificates(certs: Certificates) {
    let mut poll = tokio::time::interval(CERT_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll.tick().await;
    let mut hangup = Hangup::new();
    loop {
        let certs = certs.clone();
        tokio::select! {
            _ = poll.tick() => {
                let _ = tokio::task::spawn_blocking(move || certs.reload_if_changed()).await;
            }
            () = hangup.recv() => {
                tracing::info!("SIGHUP: reloading certificates");
                let _ = tokio::task::spawn_blocking(move || certs.reload()).await;
            }
        }
    }
}

/// SIGHUP, where there is such a thing.
struct Hangup {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
}

impl Hangup {
    fn new() -> Hangup {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let signal = signal(SignalKind::hangup())
                .inspect_err(|e| tracing::warn!(error = %e, "cannot listen for SIGHUP"))
                .ok();
            Hangup { signal }
        }
        #[cfg(not(unix))]
        Hangup {}
    }

    /// Resolves at each SIGHUP; never, if there is none.
    async fn recv(&mut self) {
        #[cfg(unix)]
        if let Some(signal) = &mut self.signal
            && signal.recv().await.is_some()
        {
            return;
        }
        std::future::pending::<()>().await;
    }
}

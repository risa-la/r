//! `risalad`'s HTTPS listener (4.6, PLAN.md section 6): it serves hosted
//! identities' key files at `/.well-known/risala/<name>`, from wherever
//! its [`KeyFiles`] gets them. In `risalad` that is the hub's own records
//! of the identities it hosts, so the listener serves those names and
//! nothing else, whatever else is in `key_dir`.
//!
//! It speaks just enough HTTP/1.1 for that: one request per connection,
//! answered and then closed. `GET` and `HEAD` of a key file get it, with
//! `Content-Type: text/plain; charset=utf-8`. Other paths get 404 and
//! other methods 405. Requests have a size limit and a time limit, and
//! nothing lists the directory. `route` is where the upload URLs of 5.6
//! will go.
//!
//! TLS is 1.3 only. Browsers and curl fetch these files too, so the key
//! exchange groups are the usual ones (X25519MLKEM768 first, then X25519,
//! P-256 and P-384), not the risala listener's X25519MLKEM768 alone (2.1).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_proto::names::Name;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use super::KeyDir;
use crate::core::Hub;
use crate::net::{self, Certificates};

/// Where the HTTPS listener gets the key files it serves.
pub trait KeyFiles: Send + Sync + 'static {
    /// The key file of `<name>@<identity domain>`, or `None` if there is
    /// none to serve (404). Called on the blocking pool.
    fn key_file(&self, name: &Name) -> io::Result<Option<Vec<u8>>>;
}

/// The key files of the identities the hub hosts, made from its records
/// (4.7): the names it hosts, and nothing else.
impl KeyFiles for Hub {
    fn key_file(&self, name: &Name) -> io::Result<Option<Vec<u8>>> {
        self.hosted_key_file(name)
    }
}

/// The files in a directory that another program writes, as a web server
/// serving `key_dir` would. Tests use it for key servers of their own.
impl KeyFiles for KeyDir {
    fn key_file(&self, name: &Name) -> io::Result<Option<Vec<u8>>> {
        self.read(name)
    }
}

/// The path under which key files are served (4.3).
pub const KEY_FILE_PREFIX: &str = "/.well-known/risala/";

/// The most HTTPS connections open at once. Others are closed as soon as
/// they are accepted.
pub const MAX_HTTP_CONNECTIONS: usize = 1024;

/// The most HTTPS connections open at once from one network address (an
/// IPv6 address counts by its /64), so that one client that opens
/// connections and sends nothing cannot take them all. Others are closed
/// as soon as they are accepted.
pub const MAX_HTTP_PER_ADDRESS: usize = 16;

/// The most bytes of request head (request line and headers).
pub const MAX_REQUEST_HEAD: usize = 8 * 1024;

/// How long a client has for its TLS handshake, and then again for the
/// head of its request. A key file request is a few hundred bytes.
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the server has to send its response.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The HTTPS listener, bound but not yet accepting.
pub struct HttpServer {
    listeners: Vec<std::net::TcpListener>,
    addrs: Vec<SocketAddr>,
    acceptor: TlsAcceptor,
    certs: Certificates,
    reload: bool,
    keys: Arc<dyn KeyFiles>,
}

impl std::fmt::Debug for HttpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpServer")
            .field("addrs", &self.addrs)
            .finish_non_exhaustive()
    }
}

impl HttpServer {
    /// Binds every address in `listen`, to serve the key files `keys`
    /// has with `certs`, chosen by SNI. Port 0 lets the system choose.
    ///
    /// With `reload`, [`run`](Self::run) re-reads the certificates when
    /// their files change and on SIGHUP, as the risala listener does with
    /// its own. Pass `false` when sharing the risala listener's
    /// certificates, which it already reloads.
    pub fn bind(
        listen: &[SocketAddr],
        certs: Certificates,
        reload: bool,
        keys: Arc<dyn KeyFiles>,
    ) -> io::Result<HttpServer> {
        let mut config = rustls::ServerConfig::builder_with_provider(risala_keyfetch::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_cert_resolver(certs.resolver());
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut listeners = Vec::new();
        let mut addrs = Vec::new();
        for addr in listen {
            let listener = std::net::TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            addrs.push(listener.local_addr()?);
            listeners.push(listener);
        }
        Ok(HttpServer {
            listeners,
            addrs,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            certs,
            reload,
            keys,
        })
    }

    /// The addresses it listens on, with the ports the system chose.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Serves until `shutdown` resolves, then drops every connection.
    ///
    /// Fails only if a listener cannot be registered with the runtime.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let listeners = self
            .listeners
            .into_iter()
            .map(TcpListener::from_std)
            .collect::<io::Result<Vec<_>>>()?;
        tracing::info!(addrs = ?self.addrs, "HTTPS listening");
        let shared = Arc::new(Shared {
            acceptor: self.acceptor,
            keys: self.keys,
            permits: Arc::new(Semaphore::new(MAX_HTTP_CONNECTIONS)),
            per_address: Mutex::new(HashMap::new()),
        });
        let mut background = JoinSet::new();
        for listener in listeners {
            background.spawn(accept_loop(listener, shared.clone()));
        }
        if self.reload {
            background.spawn(net::watch_certificates(self.certs));
        }
        shutdown.await;
        // Dropping the set aborts the accept loops, and with them every
        // connection they started.
        background.shutdown().await;
        Ok(())
    }
}

struct Shared {
    acceptor: TlsAcceptor,
    keys: Arc<dyn KeyFiles>,
    permits: Arc<Semaphore>,
    /// How many connections each network address has open.
    per_address: Mutex<HashMap<IpAddr, usize>>,
}

/// The network a connection counts against: the address, or the /64 of
/// an IPv6 address, since one host usually has a whole /64.
fn address_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        v4 => v4,
    }
}

/// One of an address's connections, counted until it is dropped.
struct AddressSlot {
    shared: Arc<Shared>,
    key: IpAddr,
}

impl AddressSlot {
    /// Counts a connection from `peer`, unless it has its fill.
    fn take(shared: &Arc<Shared>, peer: IpAddr) -> Option<AddressSlot> {
        let key = address_key(peer);
        let mut counts = shared.per_address.lock().unwrap_or_else(|e| e.into_inner());
        let n = counts.entry(key).or_default();
        if *n >= MAX_HTTP_PER_ADDRESS {
            return None;
        }
        *n += 1;
        Some(AddressSlot {
            shared: shared.clone(),
            key,
        })
    }
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut counts = self
            .shared
            .per_address
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

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        tracing::warn!(error = %e, "HTTPS accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = shared.permits.clone().try_acquire_owned() else {
                    // No address at the default levels: anonymous devices
                    // store blobs and files here (4.2).
                    tracing::warn!("too many HTTPS connections, closing a new one");
                    continue;
                };
                let Some(slot) = AddressSlot::take(&shared, peer.ip()) else {
                    tracing::debug!(%peer, "too many HTTPS connections from one address");
                    continue;
                };
                conns.spawn(connection(shared.clone(), tcp, peer, (permit, slot)));
            }
            // Reap finished connections, so the set does not grow.
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

async fn connection(
    shared: Arc<Shared>,
    tcp: TcpStream,
    peer: SocketAddr,
    _held: (OwnedSemaphorePermit, AddressSlot),
) {
    let handshake = shared.acceptor.accept(tcp);
    let mut tls = match tokio::time::timeout(HTTP_REQUEST_TIMEOUT, handshake).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            tracing::debug!(%peer, error = %e, "HTTPS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "HTTPS handshake timed out");
            return;
        }
    };
    let response = match tokio::time::timeout(HTTP_REQUEST_TIMEOUT, read_request(&mut tls)).await {
        Ok(Ok(request)) => route(&request, &shared.keys).await,
        Ok(Err(response)) => response,
        Err(_) => Response::error(408, "Request Timeout"),
    };
    tracing::debug!(%peer, status = response.status, "HTTPS request");
    let _ = tokio::time::timeout(HTTP_TIMEOUT, async {
        tls.write_all(&response.to_bytes()).await?;
        tls.shutdown().await
    })
    .await;
}

/// The parts of a request the listener uses.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) method: String,
    /// The path, without any query.
    pub(crate) path: String,
}

/// Reads a request head and parses its request line. A request that
/// cannot be served gets its error response.
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Request, Response> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(end) = head_end(&head) {
            break end;
        }
        if head.len() > MAX_REQUEST_HEAD {
            return Err(Response::error(431, "Request Header Fields Too Large"));
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(Response::error(400, "Bad Request")),
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    };
    if end > MAX_REQUEST_HEAD {
        return Err(Response::error(431, "Request Header Fields Too Large"));
    }
    parse_request_line(&head[..end]).ok_or_else(|| Response::error(400, "Bad Request"))
}

/// Where the head ends: the index of the LF that ends its last line, if
/// the blank line after it has arrived.
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.iter()
        .enumerate()
        .filter(|&(_, &b)| b == b'\n')
        .find(|&(i, _)| {
            matches!(
                (buf.get(i + 1), buf.get(i + 2)),
                (Some(b'\n'), _) | (Some(b'\r'), Some(b'\n'))
            )
        })
        .map(|(i, _)| i)
}

/// Parses `METHOD SP target SP HTTP/1.x` (RFC 9112 3). Only origin-form
/// targets (a path, then an optional query) are accepted.
fn parse_request_line(head: &[u8]) -> Option<Request> {
    let head = std::str::from_utf8(head).ok()?;
    let line = head.split('\n').next()?.trim_end_matches('\r');
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_alphabetic())
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !target.starts_with('/')
    {
        return None;
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    Some(Request {
        method: method.to_owned(),
        path: path.to_owned(),
    })
}

/// A response, always sent with `Connection: close`.
#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    reason: &'static str,
    content_type: &'static str,
    extra: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
    /// For HEAD: the headers of the body, but not the body.
    head_only: bool,
}

impl Response {
    fn error(status: u16, reason: &'static str) -> Response {
        Response {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            extra: Vec::new(),
            body: format!("{status} {reason}\n").into_bytes(),
            head_only: false,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
             X-Content-Type-Options: nosniff\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        for (name, value) in &self.extra {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        if !self.head_only {
            bytes.extend_from_slice(&self.body);
        }
        bytes
    }
}

/// What a request asks for, by path.
enum Route {
    /// `/.well-known/risala/<name>` (4.3).
    KeyFile(Name),
    NotFound,
}

impl Route {
    fn of(path: &str) -> Route {
        match path.strip_prefix(KEY_FILE_PREFIX).map(str::parse::<Name>) {
            Some(Ok(name)) => Route::KeyFile(name),
            _ => Route::NotFound,
        }
    }
}

/// Answers a request.
async fn route(request: &Request, keys: &Arc<dyn KeyFiles>) -> Response {
    let head_only = match request.method.as_str() {
        "GET" => false,
        "HEAD" => true,
        _ => {
            let mut response = Response::error(405, "Method Not Allowed");
            response.extra.push(("Allow", "GET, HEAD"));
            return response;
        }
    };
    let mut response = match Route::of(&request.path) {
        Route::KeyFile(name) => key_file(name, keys).await,
        Route::NotFound => Response::error(404, "Not Found"),
    };
    response.head_only = head_only;
    response
}

/// A hosted identity's key file, or 404.
async fn key_file(name: Name, keys: &Arc<dyn KeyFiles>) -> Response {
    let keys = keys.clone();
    let read = tokio::task::spawn_blocking(move || keys.key_file(&name)).await;
    match read {
        Ok(Ok(Some(body))) => Response {
            status: 200,
            reason: "OK",
            content_type: "text/plain; charset=utf-8",
            extra: Vec::new(),
            body,
            head_only: false,
        },
        Ok(Ok(None)) => Response::error(404, "Not Found"),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "reading a key file");
            Response::error(500, "Internal Server Error")
        }
        Err(e) => {
            tracing::error!(error = %e, "reading a key file");
            Response::error(500, "Internal Server Error")
        }
    }
}

/// Lets tests drive the request handling without TLS.
#[cfg(test)]
pub(crate) async fn handle<S: AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    keys: &Arc<dyn KeyFiles>,
) {
    let response = match read_request(stream).await {
        Ok(request) => route(&request, keys).await,
        Err(response) => response,
    };
    let _ = stream.write_all(&response.to_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_count_by_network() {
        let key = |s: &str| address_key(s.parse().unwrap()).to_string();
        assert_eq!(key("203.0.113.7"), "203.0.113.7");
        assert_eq!(key("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(key("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::");
    }

    #[test]
    fn request_lines() {
        let parse = |s: &str| parse_request_line(s.as_bytes());
        assert_eq!(
            parse("GET /.well-known/risala/alice?x=1 HTTP/1.1\r\nHost: a\r"),
            Some(Request {
                method: "GET".into(),
                path: "/.well-known/risala/alice".into()
            })
        );
        assert!(parse("GET / HTTP/1.0").is_some());
        assert!(parse("GET https://a/ HTTP/1.1").is_none());
        assert!(parse("GET / HTTP/2").is_none());
        assert!(parse("GET  / HTTP/1.1").is_none());
        assert!(parse("GET / HTTP/1.1 x").is_none());
        assert!(parse("G3T / HTTP/1.1").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn routes() {
        let key_file = |p: &str| matches!(Route::of(p), Route::KeyFile(n) if n.as_str() == "alice");
        assert!(key_file("/.well-known/risala/alice"));
        assert!(key_file("/.well-known/risala/Alice"));
        for path in [
            "/",
            "/.well-known/risala/",
            "/.well-known/risala",
            "/.well-known/risala/alice/",
            "/.well-known/risala/../alice",
            "/.well-known/risala/.alice.tmp",
            "/.well-known/risala/%61lice",
            "/.well-known/risala/a/b",
            "/.well-known/other/alice",
        ] {
            assert!(matches!(Route::of(path), Route::NotFound), "{path}");
        }
    }
}

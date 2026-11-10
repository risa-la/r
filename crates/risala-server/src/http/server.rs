//! `risalad`'s HTTPS listener (4.6, PLAN.md section 6): it serves hosted
//! identities' key files at `/.well-known/risala/<name>`, from wherever
//! its [`KeyFiles`] gets them. In `risalad` that is the hub's own records
//! of the identities it hosts, so the listener serves those names and
//! nothing else, whatever else is in `key_dir`. The key file of a name
//! that was unregistered gets 410 (4.9).
//!
//! It speaks just enough HTTP/1.1 for that: one request per connection,
//! answered and then closed. `GET` and `HEAD` of a key file get it, with
//! `Content-Type: text/plain; charset=utf-8`. Other paths get 404 and
//! other methods 405. Requests have a size limit and a time limit, and
//! nothing lists the directory.
//!
//! With [`with_files`](HttpServer::with_files), it also stores and serves
//! blobs (12.12) and uploaded files (5.6): see [`super::files`].
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
use crate::core::keys::disk::Files;
use crate::core::{HostedKeyFile, Hub};
use crate::net::{self, Certificates};

/// Where the HTTPS listener gets the key files it serves.
pub trait KeyFiles: Send + Sync + 'static {
    /// The key file of `<name>@<identity domain>`, or why there is none
    /// to serve. Called on the blocking pool.
    fn key_file(&self, name: &Name) -> io::Result<HostedKeyFile>;

    /// The hub, whose key log and witness the listener also serves (4.5,
    /// 4.10); `None` for key files from elsewhere.
    fn hub(&self) -> Option<&Hub> {
        None
    }
}

/// The key files of the identities the hub hosts, made from its records
/// (4.7): the names it hosts, and nothing else.
impl KeyFiles for Hub {
    fn key_file(&self, name: &Name) -> io::Result<HostedKeyFile> {
        self.hosted_key_file(name)
    }

    fn hub(&self) -> Option<&Hub> {
        Some(self)
    }
}

/// The files in a directory that another program writes, as a web server
/// serving `key_dir` would. Tests use it for key servers of their own.
impl KeyFiles for KeyDir {
    fn key_file(&self, name: &Name) -> io::Result<HostedKeyFile> {
        Ok(self
            .read(name)?
            .map_or(HostedKeyFile::NotFound, HostedKeyFile::File))
    }
}

/// The path under which key files are served (4.3).
pub const KEY_FILE_PREFIX: &str = "/.well-known/risala/";

/// The most HTTPS connections open at once. Others are closed as soon as
/// they are accepted.
pub const MAX_HTTP_CONNECTIONS: usize = 1024;

/// The default of `limits.https_connections_per_address`: the most HTTPS
/// connections open at once from one network address (an IPv6 address
/// counts by its /64), so that one client that opens connections and
/// sends nothing cannot take them all. Others are closed as soon as they
/// are accepted.
pub const DEFAULT_HTTP_PER_ADDRESS: usize = 16;

/// The default of `limits.https_connections_per_prefix`: the most HTTPS
/// connections open at once from one IPv6 /48, since a /48 holds 65,536
/// /64s, each of which counts as an address.
pub const DEFAULT_HTTP_PER_PREFIX: usize = 64;

/// The most connections that may be sending or receiving blobs and files
/// at once (5.6, 12.12), and the default of `files.max_transfers`: the
/// rest of [`MAX_HTTP_CONNECTIONS`] stays for key files, log tiles and the
/// witness (4.3, 4.5, 4.10), so that slow transfers cannot keep devices
/// from checking keys. Further blob and file requests get 503.
pub const MAX_HTTP_TRANSFERS: usize = MAX_HTTP_CONNECTIONS * 3 / 4;

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
    files: Option<Files>,
    per_address: usize,
    per_prefix: usize,
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
            files: None,
            per_address: DEFAULT_HTTP_PER_ADDRESS,
            per_prefix: DEFAULT_HTTP_PER_PREFIX,
        })
    }

    /// Allows at most `max` HTTPS connections open at once from one
    /// network address, an IPv6 address counting by its /64
    /// (`limits.https_connections_per_address`); 0 means no limit. The
    /// default is [`DEFAULT_HTTP_PER_ADDRESS`].
    pub fn with_per_address(mut self, max: usize) -> HttpServer {
        self.per_address = max;
        self
    }

    /// Allows at most `max` HTTPS connections open at once from one IPv6
    /// /48, whatever each of its addresses has
    /// (`limits.https_connections_per_prefix`); 0 means no limit. The
    /// default is [`DEFAULT_HTTP_PER_PREFIX`].
    pub fn with_per_prefix(mut self, max: usize) -> HttpServer {
        self.per_prefix = max;
        self
    }

    /// Also stores and serves the hub's blobs and files (5.6, 12.12).
    pub fn with_files(mut self, hub: &Hub) -> HttpServer {
        self.files = Some(hub.files());
        self
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
            transfers: Arc::new(Semaphore::new(
                self.files
                    .as_ref()
                    .map_or(MAX_HTTP_TRANSFERS, Files::max_transfers)
                    .min(MAX_HTTP_TRANSFERS),
            )),
            files: self.files,
            counts: Arc::new(ConnectionCounts::new(self.per_address, self.per_prefix)),
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
    files: Option<Files>,
    permits: Arc<Semaphore>,
    /// Connections sending or receiving blobs and files.
    transfers: Arc<Semaphore>,
    /// The connections open from each network address and IPv6 /48.
    counts: Arc<ConnectionCounts>,
}

/// The network a connection counts against: the address, or the /64 of
/// an IPv6 address, since one host usually has a whole /64.
fn address_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        v4 => v4,
    }
}

/// The IPv6 /48 an address is in, for the wider count; none for IPv4.
fn wide_key(ip: IpAddr) -> Option<IpAddr> {
    match ip.to_canonical() {
        IpAddr::V6(v6) => Some(IpAddr::V6((u128::from(v6) & !((1u128 << 80) - 1)).into())),
        IpAddr::V4(_) => None,
    }
}

/// A network a connection counts against: an address or prefix, with
/// its length in bits, since the /48 of an address and the /64 at its
/// start are written alike.
type NetworkKey = (IpAddr, u8);

/// How many HTTPS connections each network address (an IPv6 /64), and
/// each IPv6 /48, has open, and the most each may have.
struct ConnectionCounts {
    /// The most for one address; 0 means no limit.
    per_address: usize,
    /// The most for one IPv6 /48; 0 means no limit.
    per_prefix: usize,
    counts: Mutex<HashMap<NetworkKey, usize>>,
}

impl ConnectionCounts {
    fn new(per_address: usize, per_prefix: usize) -> ConnectionCounts {
        ConnectionCounts {
            per_address,
            per_prefix,
            counts: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<NetworkKey, usize>> {
        self.counts.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One of an address's connections, counted until it is dropped.
struct AddressSlot {
    counts: Arc<ConnectionCounts>,
    keys: Vec<NetworkKey>,
}

impl AddressSlot {
    /// Counts a connection from `peer`, unless its address or its /48 has
    /// its fill.
    fn take(counts: &Arc<ConnectionCounts>, peer: IpAddr) -> Option<AddressSlot> {
        let mut keys = Vec::new();
        if counts.per_address > 0 {
            let key = address_key(peer);
            let bits = if key.is_ipv6() { 64 } else { 32 };
            keys.push(((key, bits), counts.per_address));
        }
        if counts.per_prefix > 0
            && let Some(wide) = wide_key(peer)
        {
            keys.push(((wide, 48), counts.per_prefix));
        }
        let mut open = counts.lock();
        if keys
            .iter()
            .any(|(key, max)| open.get(key).copied().unwrap_or(0) >= *max)
        {
            return None;
        }
        for (key, _) in &keys {
            *open.entry(*key).or_default() += 1;
        }
        Some(AddressSlot {
            counts: counts.clone(),
            keys: keys.into_iter().map(|(key, _)| key).collect(),
        })
    }
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut open = self.counts.lock();
        for key in &self.keys {
            if let Some(n) = open.get_mut(key) {
                *n -= 1;
                if *n == 0 {
                    open.remove(key);
                }
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
                let Some(slot) = AddressSlot::take(&shared.counts, peer.ip()) else {
                    tracing::debug!(target: crate::net::ADDRESSES, %peer, "too many HTTPS connections from one address");
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
            tracing::debug!(target: crate::net::ADDRESSES, %peer, error = %e, "HTTPS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(target: crate::net::ADDRESSES, %peer, "HTTPS handshake timed out");
            return;
        }
    };
    let response = match tokio::time::timeout(HTTP_REQUEST_TIMEOUT, read_request(&mut tls)).await {
        Ok(Ok((request, body))) => match &shared.files {
            // Blobs and files: their bodies and downloads are streamed, so
            // they write their own responses (12.12, 5.6).
            Some(files) if super::files::claims(&request.path) => {
                match shared.transfers.clone().try_acquire_owned() {
                    Ok(_transfer) => {
                        super::files::serve(&mut tls, &request, body, files, peer).await;
                        return;
                    }
                    // The other connections are kept for key files, log
                    // tiles and the witness.
                    Err(_) => Response::error(503, "Service Unavailable"),
                }
            }
            _ => route(&request, &shared.keys).await,
        },
        Ok(Err(response)) => response,
        Err(_) => Response::error(408, "Request Timeout"),
    };
    tracing::debug!(target: crate::net::ADDRESSES, %peer, status = response.status, "HTTPS request");
    let _ = tokio::time::timeout(HTTP_TIMEOUT, async {
        tls.write_all(&response.to_bytes()).await?;
        tls.shutdown().await
    })
    .await;
}

/// The parts of a request the listener uses.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) method: String,
    /// The path, without any query.
    pub(crate) path: String,
    /// The body of a `POST` to the witness (4.10); empty otherwise.
    pub(crate) body: Vec<u8>,
    /// `Content-Length`, if it was sent.
    pub(crate) content_length: Option<u64>,
    /// A `Transfer-Encoding` was sent.
    pub(crate) transfer_encoding: bool,
    /// `Expect: 100-continue` was sent.
    pub(crate) expect_continue: bool,
}

/// Reads a request head and parses it. Returns the request and whatever
/// of its body arrived with the head. A request that cannot be served
/// gets its error response.
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(Request, Vec<u8>), Response> {
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
    let mut request =
        parse_request_line(&head[..end]).ok_or_else(|| Response::error(400, "Bad Request"))?;
    parse_headers(&head[..end], &mut request).ok_or_else(|| Response::error(400, "Bad Request"))?;
    // The body starts after the blank line: LF LF, or LF CR LF.
    let body_start = match head.get(end + 1) {
        Some(b'\r') => end + 3,
        _ => end + 2,
    };
    if request.method == "POST" && super::keylog::is_witness_path(&request.path) {
        // The witness reads its whole body here (4.10); nothing is left.
        request.body = read_body(stream, &head, end).await?;
        return Ok((request, Vec::new()));
    }
    let body = head.get(body_start..).unwrap_or_default().to_vec();
    Ok((request, body))
}

/// Reads the body of a request whose head ends at `end` in `head`, by its
/// `Content-Length`, up to [`MAX_WITNESS_REQUEST`](super::keylog::MAX_WITNESS_REQUEST).
async fn read_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    head: &[u8],
    end: usize,
) -> Result<Vec<u8>, Response> {
    let text =
        std::str::from_utf8(&head[..end]).map_err(|_| Response::error(400, "Bad Request"))?;
    let mut length = None;
    for line in text.split('\n').skip(1) {
        let line = line.trim_end_matches('\r');
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(Response::error(411, "Length Required"));
            }
            if name.eq_ignore_ascii_case("content-length") {
                let n = value.trim().parse::<usize>();
                length = Some(n.map_err(|_| Response::error(400, "Bad Request"))?);
            }
        }
    }
    let length = length.ok_or_else(|| Response::error(411, "Length Required"))?;
    if length > super::keylog::MAX_WITNESS_REQUEST {
        return Err(Response::error(413, "Content Too Large"));
    }
    // The blank line after the head is LF or CRLF.
    let crlf = head.get(end + 1) == Some(&b'\r');
    let start = end + 2 + usize::from(crlf);
    let mut body = head.get(start..).unwrap_or_default().to_vec();
    body.truncate(length);
    let mut chunk = [0u8; 4096];
    while body.len() < length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(Response::error(400, "Bad Request")),
            Ok(n) => body.extend_from_slice(&chunk[..n.min(length - body.len())]),
        }
    }
    Ok(body)
}

/// Reads the headers the listener uses (RFC 9112 5, 6): `Content-Length`,
/// which must be one number, given once or the same each time;
/// `Transfer-Encoding`, which bodies here may not use; and `Expect`.
/// `None` for a head that is not valid.
fn parse_headers(head: &[u8], request: &mut Request) -> Option<()> {
    let head = std::str::from_utf8(head).ok()?;
    for line in head.split('\n').skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.ends_with([' ', '\t']) {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n: u64 = value.parse().ok()?;
            if request.content_length.is_some_and(|m| m != n) {
                return None;
            }
            request.content_length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            request.transfer_encoding = true;
        } else if name.eq_ignore_ascii_case("expect") {
            request.expect_continue |= value.eq_ignore_ascii_case("100-continue");
        }
    }
    Some(())
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
        ..Request::default()
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
    if let Some(hub) = keys.hub()
        && let Some(answer) =
            super::keylog::route(hub, &request.method, &request.path, request.body.clone()).await
    {
        return Response {
            status: answer.status,
            reason: super::keylog::reason(answer.status),
            content_type: answer.content_type,
            extra: if answer.immutable {
                vec![("Cache-Control", "public, max-age=31536000, immutable")]
            } else {
                vec![("Cache-Control", "no-cache")]
            },
            body: answer.body,
            head_only: request.method == "HEAD",
        };
    }
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

/// A hosted identity's key file, 410 for one unregistered (4.9), or 404.
async fn key_file(name: Name, keys: &Arc<dyn KeyFiles>) -> Response {
    let keys = keys.clone();
    let read = tokio::task::spawn_blocking(move || keys.key_file(&name)).await;
    match read {
        Ok(Ok(HostedKeyFile::File(body))) => Response {
            status: 200,
            reason: "OK",
            content_type: "text/plain; charset=utf-8",
            extra: Vec::new(),
            body,
            head_only: false,
        },
        Ok(Ok(HostedKeyFile::Gone)) => Response::error(410, "Gone"),
        Ok(Ok(HostedKeyFile::NotFound)) => Response::error(404, "Not Found"),
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
        Ok((request, _)) => route(&request, keys).await,
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
        let wide = |s: &str| wide_key(s.parse().unwrap()).map(|k| k.to_string());
        assert_eq!(wide("2001:db8:1:2:3:4:5:6").unwrap(), "2001:db8:1::");
        assert_eq!(wide("203.0.113.7"), None);
        assert_eq!(wide("::ffff:203.0.113.7"), None);
    }

    /// Each address (an IPv6 /64) and each IPv6 /48 has its own count and
    /// limit, 0 being none, and a slot counts again once dropped. The /64
    /// at the start of a /48 is written as the /48 is, and is counted apart
    /// from it.
    #[test]
    fn connections_count_by_address_and_prefix() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let counts = Arc::new(ConnectionCounts::new(2, 3));
        let take = |s: &str| AddressSlot::take(&counts, ip(s));
        // Two from the /64 at the start of 2001:db8:1::/48, and no third.
        let first = [
            take("2001:db8:1::1").unwrap(),
            take("2001:db8:1::2").unwrap(),
        ];
        assert!(take("2001:db8:1::3").is_none());
        // One more from another /64 of the /48, then the /48 is full.
        let other = take("2001:db8:1:2::1").unwrap();
        assert!(take("2001:db8:1:3::1").is_none());
        // Another /48 is not, nor IPv4, which has no /48.
        let elsewhere = take("2001:db8:2::1").unwrap();
        let v4 = [take("203.0.113.7").unwrap(), take("203.0.113.7").unwrap()];
        assert!(take("::ffff:203.0.113.7").is_none());
        drop(other);
        let again = take("2001:db8:1:3::1").unwrap();
        drop((first, again, elsewhere, v4));
        assert!(counts.lock().is_empty());

        // 0: no limit on the /48, then on the address.
        let counts = Arc::new(ConnectionCounts::new(1, 0));
        let held: Vec<_> = (0..100)
            .map(|i| AddressSlot::take(&counts, ip(&format!("2001:db8:1:{i:x}::1"))).unwrap())
            .collect();
        assert!(AddressSlot::take(&counts, ip("2001:db8:1::2")).is_none());
        drop(held);
        let counts = Arc::new(ConnectionCounts::new(0, 2));
        let held = [
            AddressSlot::take(&counts, ip("2001:db8:1::1")).unwrap(),
            AddressSlot::take(&counts, ip("2001:db8:1::1")).unwrap(),
        ];
        assert!(AddressSlot::take(&counts, ip("2001:db8:1:5::1")).is_none());
        let v4: Vec<_> = (0..100)
            .map(|_| AddressSlot::take(&counts, ip("203.0.113.7")).unwrap())
            .collect();
        drop((held, v4));
    }

    #[test]
    fn transfers_keep_a_minimum_rate() {
        use super::super::files::{MIN_RATE, TRANSFER_GRACE, transfer_deadline};
        assert_eq!(transfer_deadline(0), TRANSFER_GRACE);
        // A 256 MiB blob: about 68 minutes, not 33 hours.
        let big = transfer_deadline(256 * 1024 * 1024);
        assert_eq!(big, TRANSFER_GRACE + Duration::from_secs(4096));
        assert_eq!(MIN_RATE, 64 * 1024);
    }

    #[test]
    fn request_lines() {
        let parse = |s: &str| parse_request_line(s.as_bytes());
        assert_eq!(
            parse("GET /.well-known/risala/alice?x=1 HTTP/1.1\r\nHost: a\r"),
            Some(Request {
                method: "GET".into(),
                path: "/.well-known/risala/alice".into(),
                ..Request::default()
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

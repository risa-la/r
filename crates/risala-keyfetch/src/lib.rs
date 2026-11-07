//! Fetching risala key files over HTTPS (SPEC 4.4).
//!
//! `alice@example.org` is controlled by whoever controls
//! `https://example.org/.well-known/risala/alice` (4.3). Servers fetch that
//! file to check sign-ins (4.5), and devices to check the members of
//! encrypted conversations (12.12). [`KeyFetcher`] does it under the rules
//! of 4.4:
//!
//! - HTTPS, with TLS 1.3 and certificates checked against public CAs
//!   ([`Roots`]);
//! - no redirects: only a 200 response counts;
//! - at most 10 seconds and 256 KiB, or else no keys;
//! - at most 64 distinct valid keys ([`risala_proto::keyfile`]);
//! - an optional guard against special-purpose addresses ([`guard`]),
//!   checked on every address it connects to, which servers must use;
//! - a cache of up to an hour, with an explicit refetch for "fetch again
//!   once before failing";
//! - a limit on how often any one key file is fetched (14, "Abuse").
//!
//! ```no_run
//! # async fn f() -> Result<(), risala_keyfetch::FetchError> {
//! use risala_keyfetch::{FetchOptions, KeyFetcher};
//!
//! let fetcher = KeyFetcher::new(FetchOptions::default());
//! let alice = "alice@example.org".parse().unwrap();
//! let keys = fetcher.fetch(&alice, false).await?;
//! # Ok(()) }
//! ```
//!
//! The HTTP client is a small one written here, rather than hyper: it
//! sends one GET and reads one response, which is all 4.4 needs, and
//! keeps every limit under our control.

pub mod guard;
mod http;
pub mod resolve;
mod tls;

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use risala_proto::auth::PublicKey;
use risala_proto::keyfile::{KeyEntry, KeyFile, MAX_KEY_FILE_BYTES};
use risala_proto::names::Identity;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;

pub use resolve::{BoxFuture, Resolve, StaticResolver, SystemResolver};
pub use rustls::pki_types::CertificateDer;
pub use tls::{Roots, provider};

/// The longest a fetch may take (4.4).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest a key file may be cached (4.4).
pub const MAX_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// The default number of key files kept in the cache.
pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;

/// The default shortest time between two fetches of one key file (14).
pub const DEFAULT_MIN_REFETCH: Duration = Duration::from_secs(10);

/// The default number of fetches that may run at once.
pub const DEFAULT_MAX_CONCURRENT: usize = 64;

/// Why a fetch gave no keys. Every error means the identity has no keys
/// (4.4); the kinds are there for logs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The domain did not resolve, or resolved to no address.
    #[error("resolving the domain: {0}")]
    Resolve(String),
    /// Every address of the domain is a special-purpose one, which the
    /// address guard refuses (4.4). This is the first of them.
    #[error("refused to connect to the special-purpose address {0}")]
    Refused(IpAddr),
    /// No address accepted a TCP connection.
    #[error("connecting: {0}")]
    Connect(String),
    /// The TLS handshake failed, for example because the certificate is
    /// not valid for the domain.
    #[error("TLS: {0}")]
    Tls(String),
    /// The response was not a 200 (4.4). Redirects end here too, without
    /// being followed.
    #[error("HTTP status {0}")]
    Status(u16),
    /// The file is over 256 KiB (4.4).
    #[error("the key file is over 256 KiB")]
    TooLarge,
    /// The file did not arrive within the time limit (4.4).
    #[error("the key file did not arrive in time")]
    Timeout,
    /// The response was not valid HTTP/1.
    #[error("bad HTTP response: {0}")]
    BadResponse(&'static str),
    /// Reading or writing the connection failed.
    #[error("reading the response: {0}")]
    Io(String),
}

/// Where a [`KeyFetcher`] gets the time from, for its cache and rate
/// limit. Replace it in tests.
pub trait Clock: Send + Sync + 'static {
    /// The current time.
    fn now(&self) -> Instant;
}

/// The system's monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// How a [`KeyFetcher`] works. [`Default`] gives what a server needs: the
/// public CAs, the address guard on, and the limits of 4.4.
#[derive(Clone)]
pub struct FetchOptions {
    /// The CAs certificates are checked against.
    pub roots: Roots,
    /// Turns the address guard off, so that loopback, private, link-local
    /// and other special-purpose addresses may be connected to (4.4). A
    /// server may do this only when its operator says so; devices are not
    /// bound by the rule.
    pub allow_private: bool,
    /// The longest a fetch may take, from resolving to the end of the
    /// body. At most [`FETCH_TIMEOUT`]; longer values are cut to it.
    pub timeout: Duration,
    /// How long a fetched file is used before it is fetched again. At most
    /// [`MAX_CACHE_TTL`]; longer values are cut to it.
    pub cache_ttl: Duration,
    /// The most key files kept in the cache. When it is full, expired
    /// entries go first, then the oldest. At least 1.
    pub cache_capacity: usize,
    /// The shortest time between two fetches of one key file, refetches
    /// included (14). A failed fetch is also remembered this long, so that
    /// repeated sign-ins do not fetch again and again.
    pub min_refetch: Duration,
    /// The most fetches that run at once. Others wait, within their
    /// timeout. At least 1.
    pub max_concurrent: usize,
    /// Turns domains into addresses.
    pub resolver: Arc<dyn Resolve>,
    /// The time, for the cache and the rate limit.
    pub clock: Arc<dyn Clock>,
}

impl Default for FetchOptions {
    fn default() -> Self {
        FetchOptions {
            roots: Roots::default(),
            allow_private: false,
            timeout: FETCH_TIMEOUT,
            cache_ttl: MAX_CACHE_TTL,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
            min_refetch: DEFAULT_MIN_REFETCH,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            resolver: Arc::new(SystemResolver),
            clock: Arc::new(SystemClock),
        }
    }
}

impl fmt::Debug for FetchOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchOptions")
            .field("roots", &self.roots)
            .field("allow_private", &self.allow_private)
            .field("timeout", &self.timeout)
            .field("cache_ttl", &self.cache_ttl)
            .field("cache_capacity", &self.cache_capacity)
            .field("min_refetch", &self.min_refetch)
            .field("max_concurrent", &self.max_concurrent)
            .finish_non_exhaustive()
    }
}

/// Fetches and caches key files (4.4). Cloning gives another handle to the
/// same cache.
#[derive(Clone)]
pub struct KeyFetcher {
    inner: Arc<Inner>,
}

struct Inner {
    connector: TlsConnector,
    allow_private: bool,
    timeout: Duration,
    cache_ttl: Duration,
    cache_capacity: usize,
    min_refetch: Duration,
    resolver: Arc<dyn Resolve>,
    clock: Arc<dyn Clock>,
    permits: Semaphore,
    cache: Mutex<HashMap<Identity, Arc<Slot>>>,
}

/// One key file's place in the cache. Its lock is held while it is
/// fetched, so concurrent fetches of one file become one.
#[derive(Default)]
struct Slot {
    last: tokio::sync::Mutex<Option<Fetched>>,
}

/// What is known of a key file: the outcome of its last fetch.
#[derive(Clone)]
struct Fetched {
    /// When `result` was fetched.
    at: Instant,
    /// When a fetch was last tried. Later than `at` when a refetch failed
    /// to reach the server and the file fetched at `at` was kept.
    tried: Instant,
    result: Result<Arc<[KeyEntry]>, FetchError>,
}

impl Fetched {
    /// Whether this may still be used without fetching again: a file for
    /// the cache's lifetime, a failure only for the rate limit's.
    fn fresh(&self, now: Instant, inner: &Inner) -> bool {
        match self.result {
            Ok(_) => now.saturating_duration_since(self.at) < inner.cache_ttl,
            Err(_) => !self.may_retry(now, inner),
        }
    }

    /// Whether the rate limit lets the file be fetched again (14).
    fn may_retry(&self, now: Instant, inner: &Inner) -> bool {
        now.saturating_duration_since(self.tried) >= inner.min_refetch
    }
}

impl FetchError {
    /// Whether the key file's server answered: with a status other than
    /// 200, a file over the size limit, or a response that is not HTTP.
    /// Other errors mean it could not be reached in time.
    pub fn is_answer(&self) -> bool {
        matches!(
            self,
            FetchError::Status(_) | FetchError::TooLarge | FetchError::BadResponse(_)
        )
    }
}

impl fmt::Debug for KeyFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFetcher")
            .field("allow_private", &self.inner.allow_private)
            .field("cached", &self.cached())
            .finish_non_exhaustive()
    }
}

impl KeyFetcher {
    /// A fetcher with `options`. Loading the built-in roots takes a few
    /// milliseconds, so make one and share it.
    pub fn new(options: FetchOptions) -> KeyFetcher {
        KeyFetcher {
            inner: Arc::new(Inner {
                connector: tls::connector(&options.roots),
                allow_private: options.allow_private,
                timeout: options.timeout.min(FETCH_TIMEOUT),
                cache_ttl: options.cache_ttl.min(MAX_CACHE_TTL),
                cache_capacity: options.cache_capacity.max(1),
                min_refetch: options.min_refetch,
                resolver: options.resolver,
                clock: options.clock,
                permits: Semaphore::new(options.max_concurrent.max(1)),
                cache: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The public keys of `identity`'s key file, in file order (4.4).
    ///
    /// A cached file is used if it is younger than the cache's lifetime.
    /// With `refresh`, the file is fetched again instead, as 4.4 asks
    /// after a signature fails against a cached file, unless it was
    /// fetched less than [`FetchOptions::min_refetch`] ago: then the last
    /// result stands. A failure is remembered for that long too.
    ///
    /// If a refetch cannot reach the server (any error but
    /// [`is_answer`](FetchError::is_answer)), a cached file still within
    /// the cache's lifetime is kept and returned: the cache is there so
    /// that people can sign in while their key file's host is down (14).
    /// An answer, such as a 404 for a deleted file, replaces it.
    ///
    /// Any error means the identity has no keys (4.4). An empty list means
    /// the file was fetched but has no valid key.
    pub async fn fetch(
        &self,
        identity: &Identity,
        refresh: bool,
    ) -> Result<Vec<PublicKey>, FetchError> {
        let entries = self.fetch_entries(identity, refresh).await?;
        Ok(entries.iter().map(|e| e.key().clone()).collect())
    }

    /// [`fetch`](Self::fetch), with each key's label, for clients that
    /// show an identity's devices (12.12).
    pub async fn fetch_entries(
        &self,
        identity: &Identity,
        refresh: bool,
    ) -> Result<Arc<[KeyEntry]>, FetchError> {
        let inner = &*self.inner;
        let slot = self.slot(identity);
        let mut last = slot.last.lock().await;
        let now = inner.clock.now();
        if let Some(fetched) = &*last
            && (!fetched.may_retry(now, inner) || (!refresh && fetched.fresh(now, inner)))
        {
            return fetched.result.clone();
        }
        let result = self.get(identity).await;
        let tried = inner.clock.now();
        match &result {
            Ok(keys) => tracing::debug!(%identity, keys = keys.len(), "fetched key file"),
            Err(error) => tracing::info!(%identity, %error, "key file fetch failed"),
        }
        if let (Err(error), Some(fetched)) = (&result, &mut *last)
            && !error.is_answer()
            && fetched.result.is_ok()
            && fetched.fresh(tried, inner)
        {
            tracing::info!(%identity, "keeping the cached key file");
            fetched.tried = tried;
            return fetched.result.clone();
        }
        *last = Some(Fetched {
            at: tried,
            tried,
            result: result.clone(),
        });
        result
    }

    /// Forgets the cached key file of `identity`, so that the next fetch
    /// gets it again. This forgets when it was last fetched too, so the
    /// next fetch is not rate-limited.
    pub fn invalidate(&self, identity: &Identity) {
        self.cache().remove(identity);
    }

    /// The number of key files in the cache, fetched or being fetched.
    pub fn cached(&self) -> usize {
        self.cache().len()
    }

    fn cache(&self) -> MutexGuard<'_, HashMap<Identity, Arc<Slot>>> {
        self.inner.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cache slot of `identity`, made if there is none. When the cache
    /// is full, it drops expired entries, then the oldest. If every entry
    /// is being fetched, the new slot is used without being cached.
    fn slot(&self, identity: &Identity) -> Arc<Slot> {
        let inner = &*self.inner;
        let mut cache = self.cache();
        if let Some(slot) = cache.get(identity) {
            return slot.clone();
        }
        if cache.len() >= inner.cache_capacity {
            let now = inner.clock.now();
            // Entries being fetched are locked, and skipped.
            let mut oldest: Option<(Instant, Identity)> = None;
            cache.retain(|id, slot| {
                let Ok(last) = slot.last.try_lock() else {
                    return true;
                };
                let Some(fetched) = &*last else {
                    return false;
                };
                let expired = !fetched.fresh(now, inner) && fetched.may_retry(now, inner);
                if !expired && oldest.as_ref().is_none_or(|(at, _)| fetched.tried < *at) {
                    oldest = Some((fetched.tried, id.clone()));
                }
                !expired
            });
            if cache.len() >= inner.cache_capacity
                && let Some((_, id)) = oldest
            {
                cache.remove(&id);
            }
            if cache.len() >= inner.cache_capacity {
                return Arc::default();
            }
        }
        cache.entry(identity.clone()).or_default().clone()
    }

    /// Fetches the key file of `identity` now, within the time limit.
    async fn get(&self, identity: &Identity) -> Result<Arc<[KeyEntry]>, FetchError> {
        let inner = &*self.inner;
        let work = async {
            let _permit = inner
                .permits
                .acquire()
                .await
                .map_err(|_| FetchError::Timeout)?;
            let domain = identity.domain();
            let path = format!("/.well-known/risala/{}", identity.name());
            let addrs = inner
                .resolver
                .resolve(domain)
                .await
                .map_err(|e| FetchError::Resolve(e.to_string()))?;
            let tcp = self.connect(&addrs).await?;
            let name = ServerName::try_from(domain.to_owned())
                .map_err(|e| FetchError::Tls(e.to_string()))?;
            let mut stream = inner
                .connector
                .connect(name, tcp)
                .await
                .map_err(|e| FetchError::Tls(e.to_string()))?;
            let body = http::get(&mut stream, domain, &path, MAX_KEY_FILE_BYTES).await?;
            // Labels and comments are for people: a stray byte that is not
            // UTF-8 should not lose every key in the file.
            let text = String::from_utf8_lossy(&body);
            let file = KeyFile::parse(&text).map_err(|_| FetchError::TooLarge)?;
            Ok(Arc::from(file.into_keys()))
        };
        tokio::time::timeout(inner.timeout, work)
            .await
            .unwrap_or(Err(FetchError::Timeout))
    }

    /// Connects to the first address that accepts, skipping those the
    /// address guard refuses (4.4). The guard checks the address the
    /// socket is actually connected to, which is one this function chose
    /// from the resolved list: nothing is resolved again later, so DNS
    /// rebinding cannot slip a different address in.
    async fn connect(&self, addrs: &[SocketAddr]) -> Result<TcpStream, FetchError> {
        let guarded = !self.inner.allow_private;
        let mut refused = None;
        let mut error = None;
        for &addr in addrs {
            if guarded && guard::is_special(addr.ip()) {
                refused.get_or_insert(addr.ip());
                continue;
            }
            let tcp = match TcpStream::connect(addr).await {
                Ok(tcp) => tcp,
                Err(e) => {
                    error = Some(e.to_string());
                    continue;
                }
            };
            match tcp.peer_addr() {
                Ok(peer) if guarded && guard::is_special(peer.ip()) => {
                    refused.get_or_insert(peer.ip());
                }
                Ok(_) => return Ok(tcp),
                Err(e) => error = Some(e.to_string()),
            }
        }
        Err(match (error, refused) {
            (Some(e), _) => FetchError::Connect(e),
            (None, Some(ip)) => FetchError::Refused(ip),
            (None, None) => FetchError::Resolve("no addresses".into()),
        })
    }
}

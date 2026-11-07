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
//! - no redirects;
//! - at most 10 seconds and 256 KiB;
//! - at most 64 distinct valid keys ([`risala_proto::keyfile`]);
//! - an optional guard against special-purpose addresses ([`guard`]),
//!   checked on every address it connects to, which servers must use;
//! - a cache of up to an hour, with an explicit refetch for "fetch again
//!   once before failing";
//! - a limit on how often any one key file is fetched (14, "Abuse").
//!
//! A fetch has one of three outcomes (4.4):
//!
//! - **a key file**: a 200 response, whose keys may be none. One over 256
//!   KiB counts as a file with no keys.
//! - **gone**: a 404 or 410 response. The identity has no keys.
//! - **failed**: anything else, a [`FetchError`]. This is an outage, and
//!   says nothing about the identity's keys.
//!
//! A key file or a gone answer replaces the cached copy. A failed fetch
//! does not: the cached copy stays valid until its hour is up.
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

/// What a fetch found (4.4): a key file, or a gone answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The identity's keys, in file order, with their labels: those the
    /// key file lists, which may be none. None for a gone answer, or for a
    /// file over 256 KiB.
    pub entries: Arc<[KeyEntry]>,
    /// The answer was a 404 or 410, not a key file.
    pub gone: bool,
    /// It came from the cache, and the rate limit would let it be fetched
    /// again now, so a fetch with `refresh` may find a newer file. `false`
    /// when it was fetched for this call, or so recently that it would
    /// not be fetched again yet.
    pub cached: bool,
}

/// Why a fetch failed: an outage, which says nothing about the identity's
/// keys (4.4). The kinds are there for logs.
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
    /// The response was not a 200, 404 or 410 (4.4). Redirects end here
    /// too, without being followed.
    #[error("HTTP status {0}")]
    Status(u16),
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
    cache: Mutex<Cache>,
}

/// The cache: a slot per identity.
#[derive(Default)]
struct Cache {
    slots: HashMap<Identity, Arc<Slot>>,
}

impl Cache {
    fn insert(&mut self, identity: &Identity) -> Arc<Slot> {
        let slot = Arc::<Slot>::default();
        self.slots.insert(identity.clone(), slot.clone());
        slot
    }

    fn remove(&mut self, identity: &Identity) {
        self.slots.remove(identity);
    }
}

/// One key file's place in the cache. Its lock is held while it is
/// fetched, so concurrent fetches of one file become one.
#[derive(Default)]
struct Slot {
    last: tokio::sync::Mutex<Option<Last>>,
}

/// What is known of a key file.
#[derive(Clone)]
struct Last {
    /// The last answer the host gave about the file, a key file or gone,
    /// and when it came. `None` if every fetch so far failed.
    answer: Option<(Instant, Answer)>,
    /// When a fetch was last tried.
    tried: Instant,
    /// Why the last try failed, if it did. An answer from before it is
    /// kept, and stays valid for the cache's lifetime (4.4).
    failure: Option<FetchError>,
}

/// A key file or a gone answer (4.4).
#[derive(Clone)]
struct Answer {
    entries: Arc<[KeyEntry]>,
    gone: bool,
}

impl Answer {
    fn found(&self, cached: bool) -> Found {
        Found {
            entries: self.entries.clone(),
            gone: self.gone,
            cached,
        }
    }
}

impl Last {
    /// The answer, if it may still be used: younger than the cache's
    /// lifetime.
    fn fresh(&self, now: Instant, inner: &Inner) -> Option<&Answer> {
        self.answer
            .as_ref()
            .filter(|(at, _)| now.saturating_duration_since(*at) < inner.cache_ttl)
            .map(|(_, answer)| answer)
    }

    /// Whether the rate limit lets the file be fetched again (14).
    fn may_retry(&self, now: Instant, inner: &Inner) -> bool {
        now.saturating_duration_since(self.tried) >= inner.min_refetch
    }

    /// Whether nothing in it is of use any more, so that the cache may
    /// drop it first.
    fn expired(&self, now: Instant, inner: &Inner) -> bool {
        self.fresh(now, inner).is_none() && self.may_retry(now, inner)
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
        let cache_capacity = options.cache_capacity.max(1);
        KeyFetcher {
            inner: Arc::new(Inner {
                connector: tls::connector(&options.roots),
                allow_private: options.allow_private,
                timeout: options.timeout.min(FETCH_TIMEOUT),
                cache_ttl: options.cache_ttl.min(MAX_CACHE_TTL),
                cache_capacity,
                min_refetch: options.min_refetch,
                resolver: options.resolver,
                clock: options.clock,
                permits: Semaphore::new(options.max_concurrent.max(1)),
                cache: Mutex::new(Cache::default()),
            }),
        }
    }

    /// The public keys of `identity`, in file order (4.4): those its key
    /// file lists, or none if it is gone. See [`lookup`](Self::lookup).
    pub async fn fetch(
        &self,
        identity: &Identity,
        refresh: bool,
    ) -> Result<Vec<PublicKey>, FetchError> {
        let found = self.lookup(identity, refresh).await?;
        Ok(found.entries.iter().map(|e| e.key().clone()).collect())
    }

    /// [`fetch`](Self::fetch), with each key's label, for clients that
    /// show an identity's devices (12.12).
    pub async fn fetch_entries(
        &self,
        identity: &Identity,
        refresh: bool,
    ) -> Result<Arc<[KeyEntry]>, FetchError> {
        Ok(self.lookup(identity, refresh).await?.entries)
    }

    /// What `identity`'s key file says (4.4): a key file, which may list
    /// no keys, or gone. An error means the fetch failed, and says nothing
    /// about the identity's keys.
    ///
    /// - A cached answer is used if it is younger than the cache's
    ///   lifetime.
    /// - With `refresh`, the file is fetched again instead, as 4.4 asks
    ///   after a signature fails against a cached file, unless it was
    ///   tried less than [`FetchOptions::min_refetch`] ago: then the last
    ///   outcome stands, failure included.
    /// - A key file or a gone answer replaces the cached one. A failed
    ///   fetch does not, but is returned: the cached answer stays, and is
    ///   used without `refresh` until its hour is up, so that people can
    ///   sign in while their key file's host is down (14).
    pub async fn lookup(&self, identity: &Identity, refresh: bool) -> Result<Found, FetchError> {
        let inner = &*self.inner;
        let slot = self.slot(identity);
        let mut last = slot.last.lock().await;
        let now = inner.clock.now();
        if let Some(known) = &*last {
            if !known.may_retry(now, inner) {
                // Tried too recently to try again: the last outcome stands.
                return match (&known.failure, known.fresh(now, inner)) {
                    (Some(failure), _) if refresh => Err(failure.clone()),
                    (_, Some(answer)) => Ok(answer.found(false)),
                    (Some(failure), None) => Err(failure.clone()),
                    (None, None) => Err(FetchError::Timeout),
                };
            }
            if !refresh && let Some(answer) = known.fresh(now, inner) {
                return Ok(answer.found(true));
            }
        }
        let result = self.get(identity).await;
        let tried = inner.clock.now();
        match result {
            Ok(answer) => {
                tracing::debug!(
                    %identity,
                    keys = answer.entries.len(),
                    gone = answer.gone,
                    "fetched key file"
                );
                let found = answer.found(false);
                *last = Some(Last {
                    answer: Some((tried, answer)),
                    tried,
                    failure: None,
                });
                Ok(found)
            }
            Err(error) => {
                tracing::info!(%identity, %error, "key file fetch failed");
                let answer = last.take().and_then(|known| known.answer);
                *last = Some(Last {
                    answer,
                    tried,
                    failure: Some(error.clone()),
                });
                Err(error)
            }
        }
    }

    /// Forgets the cached key file of `identity`, so that the next fetch
    /// gets it again. This forgets when it was last fetched too, so the
    /// next fetch is not rate-limited.
    pub fn invalidate(&self, identity: &Identity) {
        self.cache().remove(identity);
    }

    /// The number of key files in the cache, fetched or being fetched.
    pub fn cached(&self) -> usize {
        self.cache().slots.len()
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.inner.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cache slot of `identity`, made if there is none. When the cache
    /// is full, expired entries go, then the oldest. Entries being fetched
    /// are locked, and skipped. If no entry can go, the new slot is used
    /// without being cached.
    fn slot(&self, identity: &Identity) -> Arc<Slot> {
        let inner = &*self.inner;
        let mut cache = self.cache();
        if let Some(slot) = cache.slots.get(identity) {
            return slot.clone();
        }
        let now = inner.clock.now();
        if cache.slots.len() >= inner.cache_capacity && !self.make_room(&mut cache, now, |_| true) {
            return Arc::default();
        }
        cache.insert(identity)
    }

    /// Drops the expired entries of those for which `which` is true, or
    /// else the oldest of them. Returns whether any went.
    fn make_room(
        &self,
        cache: &mut Cache,
        now: Instant,
        which: impl Fn(&Identity) -> bool,
    ) -> bool {
        let inner = &*self.inner;
        let mut expired = Vec::new();
        let mut oldest: Option<(Instant, Identity)> = None;
        for (id, slot) in &cache.slots {
            if !which(id) {
                continue;
            }
            // Entries being fetched are locked, and skipped.
            let Ok(last) = slot.last.try_lock() else {
                continue;
            };
            let Some(known) = &*last else {
                expired.push(id.clone());
                continue;
            };
            if known.expired(now, inner) {
                expired.push(id.clone());
            } else if oldest.as_ref().is_none_or(|(at, _)| known.tried < *at) {
                oldest = Some((known.tried, id.clone()));
            }
        }
        if expired.is_empty() {
            match oldest {
                Some((_, id)) => expired.push(id),
                None => return false,
            }
        }
        for id in &expired {
            cache.remove(id);
        }
        true
    }

    /// Fetches the key file of `identity` now, within the time limit.
    async fn get(&self, identity: &Identity) -> Result<Answer, FetchError> {
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
            let none = || Answer {
                entries: Arc::from(Vec::new()),
                gone: false,
            };
            match http::get(&mut stream, domain, &path, MAX_KEY_FILE_BYTES).await? {
                http::Got::Body(body) => {
                    let text = valid_lines(&body);
                    // Parsing fails only for a file over the limit.
                    Ok(KeyFile::parse(&text).map_or_else(
                        |_| none(),
                        |file| Answer {
                            entries: Arc::from(file.into_keys()),
                            gone: false,
                        },
                    ))
                }
                // A file over 256 KiB lists no keys (4.4).
                http::Got::TooLarge => Ok(none()),
                http::Got::Gone => Ok(Answer {
                    entries: Arc::from(Vec::new()),
                    gone: true,
                }),
            }
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

/// The lines of a key file that are valid UTF-8, joined with LF. A line
/// that is not valid UTF-8 counts as malformed and is skipped, like any
/// other malformed line, so a stray byte does not lose the other keys
/// (4.4). The result is never longer than `body`.
fn valid_lines(body: &[u8]) -> String {
    body.split(|&b| b == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod utf8_tests {
    use super::valid_lines;

    #[test]
    fn lines_that_are_not_utf8_are_skipped() {
        let body = b"# keys\nmldsa44 AAAA laptop\nmldsa44 BBBB \xff\xfe phone\r\nmldsa44 CCCC\n";
        assert_eq!(
            valid_lines(body),
            "# keys\nmldsa44 AAAA laptop\nmldsa44 CCCC\n"
        );
    }
}

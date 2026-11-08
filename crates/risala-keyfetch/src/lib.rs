//! Fetching risala key files over HTTPS (SPEC 4.4), and the files of key
//! logs that readers check them against (4.5).
//!
//! `alice@example.org` is controlled by whoever controls
//! `https://example.org/.well-known/risala/alice` (4.3). Servers fetch that
//! file to check sign-ins (4.6), and devices to check the members of
//! encrypted conversations (12.7). [`KeyFetcher`] does it under the rules
//! of 4.4:
//!
//! - HTTPS, with TLS 1.3 and certificates checked against public CAs
//!   ([`Roots`]);
//! - no redirects;
//! - at most 10 seconds and 2 MiB
//!   ([`MAX_KEY_FILE_BYTES`](risala_proto::keyfile::MAX_KEY_FILE_BYTES));
//! - an optional guard against special-purpose addresses ([`guard`]),
//!   checked on every address it connects to, which servers must use;
//! - a cache of up to an hour, with an explicit refetch for "fetch again
//!   once before failing";
//! - a limit on how often any one key file is fetched (14, "Abuse"), on
//!   how many fetches run at once, overall and per domain, and on how much
//!   of the cache one domain may take.
//!
//! It does not read the file: what a body means, keys, keys missing or an
//! outage, is for [`risala_proto::keyfile::read_key_file`], which needs
//! the log's entries too. A fetch has one of these outcomes:
//!
//! - **a body** ([`Body::File`]): a 200 response within 2 MiB;
//! - **too large** ([`Body::TooLarge`]): a 200 response over 2 MiB, which
//!   makes the keys missing;
//! - **gone** ([`Body::Gone`]): a 404 or 410 response, which makes the
//!   keys missing;
//! - **failed**: anything else, a [`FetchError`]. This is an outage, and
//!   says nothing about the identity's keys.
//!
//! An answer replaces the cached copy. A failed fetch does not: the
//! cached copy stays valid until its hour is up.
//!
//! [`KeyFetcher::fetch_url`] fetches a key log's checkpoint, tiles and
//! entry bundles (4.5) under the same rules, with a limit of 8 MiB, and
//! without the cache.
//!
//! ```no_run
//! # async fn f() -> Result<(), risala_keyfetch::FetchError> {
//! use risala_keyfetch::{FetchOptions, KeyFetcher};
//!
//! let fetcher = KeyFetcher::new(FetchOptions::default());
//! let alice = "alice@example.org".parse().unwrap();
//! let found = fetcher.lookup(&alice, false).await?;
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

use risala_proto::keyfile::MAX_KEY_FILE_BYTES;
use risala_proto::names::Identity;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};
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

/// The default number of fetches from one domain that may run at once.
pub const DEFAULT_MAX_PER_DOMAIN: usize = 4;

/// The default share of the cache one site may take, as a fraction: an
/// eighth.
pub const DEFAULT_CACHE_SHARE: usize = 8;

/// The most failed fetches logged at info level per minute. The rest are
/// logged at debug level, and counted in the next one.
const FAILURE_LOGS_PER_MINUTE: u32 = 10;

/// What a key file fetch got (4.4), when it was an answer about the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// A 200 response within 2 MiB, with its body, unread.
    File(Arc<[u8]>),
    /// A 200 response over 2 MiB, which was not read to the end: the
    /// identity's keys are missing.
    TooLarge,
    /// A 404 or 410 response, with its status: the identity's keys are
    /// missing.
    Gone(u16),
}

/// What a fetch found (4.4): an answer about the key file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The answer.
    pub body: Body,
    /// It came from the cache, and the rate limit would let it be fetched
    /// again now, so a fetch with `refresh` may find a newer file. `false`
    /// when it was fetched for this call, or so recently that it would
    /// not be fetched again yet.
    pub cached: bool,
}

/// What a fetch of a key log's file got ([`KeyFetcher::fetch_url`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlBody {
    /// A 200 response within the limit, with its body.
    Ok(Vec<u8>),
    /// A 200 response over the limit.
    TooLarge,
    /// A 404 or 410 response, with its status.
    Gone(u16),
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
    /// Too many fetches were running, overall or from the domain, for this
    /// one to start in time. Nothing was fetched.
    #[error("too many key file fetches at once")]
    Busy,
    /// The URL is not an `https` URL this fetcher can use.
    #[error("not an https URL: {0}")]
    Url(String),
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
    /// The most fetches that run at once. Others wait, for up to
    /// `timeout`, before their own `timeout` starts. At least 1.
    pub max_concurrent: usize,
    /// The most fetches from one domain that run at once, so that one slow
    /// domain cannot hold up every fetch. Others wait as above. At least
    /// 1.
    pub max_per_domain: usize,
    /// The most cache entries one site may have, so that someone who makes
    /// up identities at their own domain cannot push everyone else's key
    /// files out of the cache. When a site has this many, its own oldest
    /// entry makes way. A site is a domain's last two labels, or three
    /// when the second-to-last is a short label under a two-letter
    /// country code, as in `example.co.uk`. At least 1, and at most
    /// `cache_capacity`.
    pub cache_per_site: usize,
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
            max_per_domain: DEFAULT_MAX_PER_DOMAIN,
            cache_per_site: DEFAULT_CACHE_CAPACITY / DEFAULT_CACHE_SHARE,
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
            .field("max_per_domain", &self.max_per_domain)
            .field("cache_per_site", &self.cache_per_site)
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
    cache_per_site: usize,
    min_refetch: Duration,
    resolver: Arc<dyn Resolve>,
    clock: Arc<dyn Clock>,
    permits: Semaphore,
    max_per_domain: usize,
    /// The permits of each domain that has fetches running or waiting.
    domains: Mutex<HashMap<String, Arc<Semaphore>>>,
    cache: Mutex<Cache>,
    failure_log: Mutex<LogLimit>,
}

/// The cache: a slot per identity, and how many each site has.
#[derive(Default)]
struct Cache {
    slots: HashMap<Identity, Arc<Slot>>,
    per_site: HashMap<String, usize>,
}

impl Cache {
    fn insert(&mut self, identity: &Identity) -> Arc<Slot> {
        let slot = Arc::<Slot>::default();
        if self.slots.insert(identity.clone(), slot.clone()).is_none() {
            *self.per_site.entry(site(identity.domain())).or_default() += 1;
        }
        slot
    }

    fn remove(&mut self, identity: &Identity) {
        if self.slots.remove(identity).is_some() {
            let site = site(identity.domain());
            if let Some(n) = self.per_site.get_mut(&site) {
                *n -= 1;
                if *n == 0 {
                    self.per_site.remove(&site);
                }
            }
        }
    }
}

/// The site a domain belongs to, for its share of the cache: its last two
/// labels, or three when the second-to-last is a label of at most three
/// letters under a two-letter country code (`example.co.uk`). This only
/// shares the cache out; nothing else depends on it.
fn site(domain: &str) -> String {
    let labels: Vec<&str> = domain.rsplit('.').collect();
    let keep = match labels.as_slice() {
        [tld, second, _, ..] if tld.len() == 2 && second.len() <= 3 => 3,
        _ => 2,
    };
    let mut site: Vec<&str> = labels.into_iter().take(keep).collect();
    site.reverse();
    site.join(".").to_ascii_lowercase()
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

/// An answer about a key file (4.4).
#[derive(Clone)]
struct Answer {
    body: Body,
}

impl Answer {
    fn found(&self, cached: bool) -> Found {
        Found {
            body: self.body.clone(),
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

/// Holds failed fetches to [`FAILURE_LOGS_PER_MINUTE`] info-level log
/// lines a minute, since anyone can make the server fetch from a host that
/// fails.
struct LogLimit {
    since: Option<Instant>,
    logged: u32,
    held: u64,
}

impl LogLimit {
    /// Whether to log one more at info level now, and how many were held
    /// back since the last one that was.
    fn take(&mut self, now: Instant) -> Option<u64> {
        if self
            .since
            .is_none_or(|since| now.saturating_duration_since(since) >= Duration::from_secs(60))
        {
            self.since = Some(now);
            self.logged = 0;
        }
        if self.logged < FAILURE_LOGS_PER_MINUTE {
            self.logged += 1;
            Some(std::mem::take(&mut self.held))
        } else {
            self.held += 1;
            None
        }
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
                cache_per_site: options.cache_per_site.clamp(1, cache_capacity),
                min_refetch: options.min_refetch,
                resolver: options.resolver,
                clock: options.clock,
                permits: Semaphore::new(options.max_concurrent.max(1)),
                max_per_domain: options.max_per_domain.max(1),
                domains: Mutex::new(HashMap::new()),
                cache: Mutex::new(Cache::default()),
                failure_log: Mutex::new(LogLimit {
                    since: None,
                    logged: 0,
                    held: 0,
                }),
            }),
        }
    }

    /// What `identity`'s key file is (4.4): a body, one too large, or
    /// gone. An error means the fetch failed, and says nothing about the
    /// identity's keys.
    ///
    /// - A cached answer is used if it is younger than the cache's
    ///   lifetime.
    /// - With `refresh`, the file is fetched again instead, as 4.4 asks
    ///   after a signature fails against a cached file, unless it was
    ///   tried less than [`FetchOptions::min_refetch`] ago: then the last
    ///   outcome stands, failure included.
    /// - An answer replaces the cached one. A failed
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
                tracing::debug!(%identity, body = ?answer.body.summary(), "fetched key file");
                let found = answer.found(false);
                *last = Some(Last {
                    answer: Some((tried, answer)),
                    tried,
                    failure: None,
                });
                Ok(found)
            }
            // Nothing was fetched, so nothing is learnt or rate-limited.
            Err(FetchError::Busy) => Err(FetchError::Busy),
            Err(error) => {
                self.log_failure(identity, &error, tried);
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

    /// Logs a failed fetch, at info level unless too many have been
    /// lately.
    fn log_failure(&self, identity: &Identity, error: &FetchError, now: Instant) {
        let held = self
            .inner
            .failure_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take(now);
        match held {
            Some(0) => tracing::info!(%identity, %error, "key file fetch failed"),
            Some(held) => tracing::info!(
                %identity,
                %error,
                "key file fetch failed ({held} more failures not logged)"
            ),
            None => tracing::debug!(%identity, %error, "key file fetch failed"),
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

    /// The cache slot of `identity`, made if there is none.
    ///
    /// A site that has its share of the cache makes room among its own
    /// entries. When the whole cache is full, expired entries go, then the
    /// oldest. Entries being fetched are locked, and skipped. If no entry
    /// can go, the new slot is used without being cached.
    fn slot(&self, identity: &Identity) -> Arc<Slot> {
        let inner = &*self.inner;
        let mut cache = self.cache();
        if let Some(slot) = cache.slots.get(identity) {
            return slot.clone();
        }
        let now = inner.clock.now();
        let site = site(identity.domain());
        if cache.per_site.get(&site).copied().unwrap_or(0) >= inner.cache_per_site {
            let own = |id: &Identity| self::site(id.domain()) == site;
            if !self.make_room(&mut cache, now, own) {
                return Arc::default();
            }
        }
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

    /// Waits for a permit to fetch from `domain`, and then for one of the
    /// overall permits, for up to the fetch timeout. The fetch's own
    /// timeout starts after this.
    async fn permits(&self, domain: &str) -> Result<Permits<'_>, FetchError> {
        let inner = &*self.inner;
        let ours = {
            let mut domains = inner.domains.lock().unwrap_or_else(|e| e.into_inner());
            domains
                .entry(domain.to_ascii_lowercase())
                .or_insert_with(|| Arc::new(Semaphore::new(inner.max_per_domain)))
                .clone()
        };
        let wait = async {
            let domain_permit = ours.clone().acquire_owned().await.ok()?;
            let permit = inner.permits.acquire().await.ok()?;
            Some((domain_permit, permit))
        };
        let permits = tokio::time::timeout(inner.timeout, wait).await;
        let permits = Permits {
            fetcher: self,
            domain: domain.to_ascii_lowercase(),
            semaphore: ours,
            held: permits.ok().flatten(),
        };
        if permits.held.is_none() {
            return Err(FetchError::Busy);
        }
        Ok(permits)
    }

    /// Fetches the key file of `identity` now, within the time limit,
    /// once it has its permits.
    async fn get(&self, identity: &Identity) -> Result<Answer, FetchError> {
        let inner = &*self.inner;
        let _permits = self.permits(identity.domain()).await?;
        let deadline = tokio::time::Instant::now() + inner.timeout;
        let work = async {
            let domain = identity.domain();
            let path = format!("/.well-known/risala/{}", identity.name());
            let addrs = inner
                .resolver
                .resolve(domain)
                .await
                .map_err(|e| FetchError::Resolve(e.to_string()))?;
            let tcp = self.connect(&addrs, deadline).await?;
            let name = ServerName::try_from(domain.to_owned())
                .map_err(|e| FetchError::Tls(e.to_string()))?;
            let mut stream = inner
                .connector
                .connect(name, tcp)
                .await
                .map_err(|e| FetchError::Tls(e.to_string()))?;
            let body = match http::get(&mut stream, domain, &path, MAX_KEY_FILE_BYTES).await? {
                http::Got::Body(body) => Body::File(Arc::from(body)),
                http::Got::TooLarge => Body::TooLarge,
                http::Got::Gone(status) => Body::Gone(status),
            };
            Ok(Answer { body })
        };
        tokio::time::timeout(inner.timeout, work)
            .await
            .unwrap_or(Err(FetchError::Timeout))
    }

    /// Fetches `url`, an `https` URL such as a key log's checkpoint, tile
    /// or entry bundle (4.5), under the rules of 4.4: no redirects, the
    /// address guard, the time limit, and at most `max_body` bytes. Nothing
    /// is cached.
    pub async fn fetch_url(&self, url: &str, max_body: usize) -> Result<UrlBody, FetchError> {
        let (host, port, path) = split_url(url).ok_or_else(|| FetchError::Url(url.to_owned()))?;
        let inner = &*self.inner;
        let _permits = self.permits(host).await?;
        let deadline = tokio::time::Instant::now() + inner.timeout;
        let work = async {
            let addrs: Vec<SocketAddr> = inner
                .resolver
                .resolve(host)
                .await
                .map_err(|e| FetchError::Resolve(e.to_string()))?
                .into_iter()
                .map(|a| SocketAddr::new(a.ip(), port.unwrap_or(a.port())))
                .collect();
            let tcp = self.connect(&addrs, deadline).await?;
            let name = ServerName::try_from(host.to_owned())
                .map_err(|e| FetchError::Tls(e.to_string()))?;
            let mut stream = inner
                .connector
                .connect(name, tcp)
                .await
                .map_err(|e| FetchError::Tls(e.to_string()))?;
            let host_header = match port {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            };
            Ok(
                match http::get(&mut stream, &host_header, path, max_body).await? {
                    http::Got::Body(body) => UrlBody::Ok(body),
                    http::Got::TooLarge => UrlBody::TooLarge,
                    http::Got::Gone(status) => UrlBody::Gone(status),
                },
            )
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
    ///
    /// Each attempt gets an equal share of the time left before
    /// `deadline`, so that an address that never answers, often an IPv6
    /// one, does not use up the whole fetch.
    async fn connect(
        &self,
        addrs: &[SocketAddr],
        deadline: tokio::time::Instant,
    ) -> Result<TcpStream, FetchError> {
        let guarded = !self.inner.allow_private;
        let mut refused = None;
        let mut error = None;
        let mut candidates = Vec::with_capacity(addrs.len());
        for &addr in addrs {
            if guarded && guard::is_special(addr.ip()) {
                refused.get_or_insert(addr.ip());
            } else {
                candidates.push(addr);
            }
        }
        for (i, &addr) in candidates.iter().enumerate() {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let share = left / u32::try_from(candidates.len() - i).unwrap_or(u32::MAX);
            let tcp = match tokio::time::timeout(share, TcpStream::connect(addr)).await {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(e)) => {
                    error = Some(e.to_string());
                    continue;
                }
                Err(_) => {
                    error = Some(format!("{addr}: timed out"));
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

/// The permits a fetch holds: one for its domain and one of the overall
/// ones. Dropping them forgets the domain's permits once nobody else holds
/// or waits for them.
struct Permits<'a> {
    fetcher: &'a KeyFetcher,
    domain: String,
    semaphore: Arc<Semaphore>,
    held: Option<(OwnedSemaphorePermit, SemaphorePermit<'a>)>,
}

impl Drop for Permits<'_> {
    fn drop(&mut self) {
        self.held = None;
        let mut domains = self
            .fetcher
            .inner
            .domains
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The map's and this one's: nobody else holds or waits.
        if Arc::strong_count(&self.semaphore) == 2
            && domains
                .get(&self.domain)
                .is_some_and(|s| Arc::ptr_eq(s, &self.semaphore))
        {
            domains.remove(&self.domain);
        }
    }
}

impl Body {
    /// A short description, for logs: never the body itself.
    fn summary(&self) -> String {
        match self {
            Body::File(body) => format!("{} bytes", body.len()),
            Body::TooLarge => "too large".into(),
            Body::Gone(status) => format!("gone ({status})"),
        }
    }
}

/// Splits an `https` URL into its host, its port if it names one, and its
/// path (`/` if it has none). The host is a domain name: no user info, no
/// IP literal, no query or fragment.
fn split_url(url: &str) -> Option<(&str, Option<u16>, &str)> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if path.contains(['?', '#', ' ', '\r', '\n']) || authority.contains(['@', '[']) {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse().ok()?)),
        None => (authority, None),
    };
    let valid = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    valid.then_some((host, port, path))
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn sites() {
        assert_eq!(site("example.org"), "example.org");
        assert_eq!(site("chat.example.org"), "example.org");
        assert_eq!(site("a.b.Example.ORG"), "example.org");
        assert_eq!(site("example.co.uk"), "example.co.uk");
        assert_eq!(site("x.example.co.uk"), "example.co.uk");
        assert_eq!(site("x.example.de"), "example.de");
        assert_eq!(site("x.example.com.au"), "example.com.au");
    }

    #[test]
    fn failure_logs_are_limited() {
        let mut limit = LogLimit {
            since: None,
            logged: 0,
            held: 0,
        };
        let t0 = Instant::now();
        for _ in 0..FAILURE_LOGS_PER_MINUTE {
            assert_eq!(limit.take(t0), Some(0));
        }
        assert_eq!(limit.take(t0), None);
        assert_eq!(limit.take(t0 + Duration::from_secs(59)), None);
        assert_eq!(limit.take(t0 + Duration::from_secs(60)), Some(2));
        assert_eq!(limit.take(t0 + Duration::from_secs(61)), Some(0));
    }
}

#[cfg(test)]
mod url_tests {
    use super::split_url;

    #[test]
    fn urls() {
        assert_eq!(
            split_url("https://chat.example.org/risala-log/1/checkpoint"),
            Some(("chat.example.org", None, "/risala-log/1/checkpoint"))
        );
        assert_eq!(
            split_url("https://example.org:8443/a"),
            Some(("example.org", Some(8443), "/a"))
        );
        assert_eq!(
            split_url("https://example.org"),
            Some(("example.org", None, "/"))
        );
        for bad in [
            "http://example.org/a",
            "https:///a",
            "https://user@example.org/a",
            "https://[::1]/a",
            "https://example.org:x/a",
            "https://example.org/a?b",
            "https://example.org/a b",
        ] {
            assert_eq!(split_url(bad), None, "{bad}");
        }
    }
}

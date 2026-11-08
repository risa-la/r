//! Where the hub gets identities' key files and the key log entries they
//! list, and where it publishes the key files of the identities it hosts
//! (4.4-4.7).
//!
//! The hub checks AUTH against the identity's key file (4.6), which it
//! gets through a [`KeyFetcher`]: over HTTPS in `risalad`, from memory in
//! tests ([`MemoryFetcher`]). A fetch gives the file as it came, or an
//! outage; the hub reads it ([`risala_proto::keyfile`]), fetching the
//! records that it lists by index from their logs through the same
//! fetcher. The identities it hosts it checks against its own records,
//! and it publishes their key files through a [`KeyFilePublisher`]
//! whenever their chains change.
//!
//! [`KeyServices`] bundles the two for the [`Hub`](crate::core::Hub).
//! Without them, the hub fetches nothing ([`NoFetcher`]), so only hosted
//! identities can sign in, and publishes nothing ([`NoPublisher`]).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use risala_proto::names::{Identity, Name};

pub use risala_keyfetch::{Body, UrlBody};

/// How long AUTH waits for an identity's key file (4.4) before it gives
/// up with `ERR unavailable`. A fetch stops after 10 seconds itself, but
/// may first wait as long again for its turn; this is a backstop.
pub const KEY_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why an identity's key file, or a file of a key log, could not be had:
/// an outage (4.4), which says nothing about the identity's keys. AUTH
/// gets `ERR unavailable` (4.6), and no connection is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The fetch failed (4.4): the address is not allowed, DNS, the
    /// connection or TLS failed, it took too long, or the response was a
    /// status other than 200, 404 and 410.
    #[error("fetching failed: {0}")]
    Failed(String),
    /// This server fetches no key files.
    #[error("this server does not fetch key files")]
    Unavailable,
}

/// What a key file fetch got (4.4), not yet read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedFile {
    /// The answer: a body, one too large, or gone.
    pub body: Body,
    /// It came from a cache, and fetching the file again with `refresh`
    /// may find a newer one. `false` when it was fetched just now, or so
    /// recently that a refetch would give the same.
    pub cached: bool,
}

/// Gets the key files of identities the server does not host (4.3, 4.4),
/// and the files of the key logs they name (4.5).
///
/// Implementations follow 4.4: HTTPS with certificates checked, no
/// redirects, at most 10 seconds, 2 MiB for a key file and 8 MiB for a
/// log's file, and no special-purpose addresses unless configured. They
/// may cache a key file for up to an hour, and a failed fetch does not
/// replace the cached copy.
///
/// The hub calls this without holding any lock, and gives up after
/// [`KEY_FETCH_TIMEOUT`], so a slow key host holds up only the AUTH that
/// waits for it.
pub trait KeyFetcher: Send + Sync + 'static {
    /// `identity`'s key file.
    ///
    /// - `Ok` is an answer about the file, fetched or cached: a body, which
    ///   the hub reads, or a body too large or gone, which make the keys
    ///   missing (4.4).
    /// - `Err` means the fetch failed, and there is no cached copy to go
    ///   by: an outage.
    ///
    /// With `refresh`, a cached copy must not be used: the hub asks again
    /// with `refresh` once when a signature does not verify against a
    /// cached answer, so that a newly added device works straight away
    /// (4.4). If that fetch fails, it is an `Err`, even though the cached
    /// copy stays for later fetches without `refresh`.
    fn fetch(
        &self,
        identity: &Identity,
        refresh: bool,
    ) -> impl Future<Output = Result<FetchedFile, FetchError>> + Send;

    /// A file of a key log at `url`: its checkpoint or an entry bundle
    /// (4.5), at most 8 MiB. Not cached.
    fn fetch_log(&self, url: &str) -> impl Future<Output = Result<UrlBody, FetchError>> + Send;
}

/// Publishes the key files of the identities the server hosts (4.7): to a
/// directory, which another web server may serve. `risalad`'s own HTTPS
/// listener serves them from the hub's records instead.
///
/// Calls may block: the hub makes them on the blocking pool. For each
/// identity they come one at a time and in order, so the last call is the
/// current state.
pub trait KeyFilePublisher: Send + Sync + 'static {
    /// Publishes `file`, the key file of the hosted identity
    /// `<name>@<identity domain>`, replacing any earlier one. It is served
    /// at `https://<identity domain>/.well-known/risala/<name>` (4.3). The
    /// hub calls this on REGISTER and on every change to the identity's
    /// chain, and for every hosted identity when it starts.
    fn publish(&self, name: &Name, file: &[u8]) -> std::io::Result<()>;

    /// Removes the key file of `<name>@<identity domain>`, after
    /// UNREGISTER (4.9). Removing a file that does not exist is not an
    /// error.
    fn remove(&self, name: &Name) -> std::io::Result<()>;

    /// Removes every key file but those of `hosted`, the names the server
    /// publishes. The hub calls this when it starts, after publishing
    /// theirs, so that a removal that failed earlier is made up for (4.9).
    fn retain(&self, hosted: &[Name]) -> std::io::Result<()> {
        let _ = hosted;
        Ok(())
    }
}

/// A [`KeyFetcher`] that has nothing for anyone: [`FetchError::Unavailable`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFetcher;

impl KeyFetcher for NoFetcher {
    async fn fetch(&self, _: &Identity, _: bool) -> Result<FetchedFile, FetchError> {
        Err(FetchError::Unavailable)
    }

    async fn fetch_log(&self, _: &str) -> Result<UrlBody, FetchError> {
        Err(FetchError::Unavailable)
    }
}

/// A [`KeyFilePublisher`] that publishes nothing, for a server whose
/// operator publishes the key files some other way.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPublisher;

impl KeyFilePublisher for NoPublisher {
    fn publish(&self, _: &Name, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn remove(&self, _: &Name) -> std::io::Result<()> {
        Ok(())
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The boxed form of [`KeyFetcher`], so that the hub can hold any.
pub(crate) trait DynKeyFetcher: Send + Sync + 'static {
    fn fetch_boxed<'a>(
        &'a self,
        identity: &'a Identity,
        refresh: bool,
    ) -> BoxFuture<'a, Result<FetchedFile, FetchError>>;

    fn fetch_log_boxed<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<UrlBody, FetchError>>;
}

impl<T: KeyFetcher> DynKeyFetcher for T {
    fn fetch_boxed<'a>(
        &'a self,
        identity: &'a Identity,
        refresh: bool,
    ) -> BoxFuture<'a, Result<FetchedFile, FetchError>> {
        Box::pin(self.fetch(identity, refresh))
    }

    fn fetch_log_boxed<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<UrlBody, FetchError>> {
        Box::pin(self.fetch_log(url))
    }
}

/// The hub's [`KeyFetcher`] and [`KeyFilePublisher`].
#[derive(Clone)]
pub struct KeyServices {
    pub(crate) fetcher: Arc<dyn DynKeyFetcher>,
    pub(crate) publisher: Arc<dyn KeyFilePublisher>,
}

impl KeyServices {
    /// Uses `fetcher` and `publisher`.
    pub fn new(fetcher: impl KeyFetcher, publisher: impl KeyFilePublisher) -> KeyServices {
        KeyServices {
            fetcher: Arc::new(fetcher),
            publisher: Arc::new(publisher),
        }
    }

    /// Uses shared ones, which the caller can still look at, as tests do.
    pub fn shared(
        fetcher: Arc<impl KeyFetcher>,
        publisher: Arc<impl KeyFilePublisher>,
    ) -> KeyServices {
        KeyServices { fetcher, publisher }
    }
}

impl Default for KeyServices {
    /// [`NoFetcher`] and [`NoPublisher`].
    fn default() -> KeyServices {
        KeyServices::new(NoFetcher, NoPublisher)
    }
}

impl fmt::Debug for KeyServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyServices").finish_non_exhaustive()
    }
}

/// What a [`MemoryFetcher`] has for one identity.
#[derive(Debug, Clone)]
enum Answer {
    /// This answer, or this failure.
    Body(Result<Body, FetchError>),
    /// Never answers, like a key host that does not respond.
    Hang,
    /// Answers with this body once notified.
    Held(Arc<tokio::sync::Notify>, Body),
}

/// What a key log serves at a path under its URL prefix: `None` for a
/// 404.
type LogServer = Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

#[derive(Default)]
struct MemoryState {
    /// What a fetch with `refresh` gets: the key file as it is now.
    current: HashMap<Identity, Answer>,
    /// What a fetch without `refresh` gets instead, until the next fetch
    /// with it: an older copy in the cache.
    cached: HashMap<Identity, Body>,
    /// Every key file fetch, in order, with its `refresh`.
    calls: Vec<(Identity, bool)>,
    /// Key logs, by URL prefix.
    logs: HashMap<String, LogServer>,
    /// Key logs whose fetches fail, by URL prefix.
    failing_logs: Vec<String>,
}

/// A [`KeyFetcher`] with key files and key logs in memory, for tests. It
/// can model a cache that is out of date ([`set_cached`](Self::set_cached)),
/// a file that is gone, a fetch that fails, and a key host that never
/// answers.
///
/// An identity it knows nothing about is gone, as for a 404.
#[derive(Default)]
pub struct MemoryFetcher {
    state: Mutex<MemoryState>,
}

impl fmt::Debug for MemoryFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryFetcher").finish_non_exhaustive()
    }
}

impl MemoryFetcher {
    /// An empty one.
    pub fn new() -> MemoryFetcher {
        MemoryFetcher::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `identity`'s key file is `file` from now on, as a 200 response.
    pub fn set(&self, identity: &Identity, file: impl Into<Vec<u8>>) {
        let body = Body::File(Arc::from(file.into()));
        self.state()
            .current
            .insert(identity.clone(), Answer::Body(Ok(body)));
    }

    /// Fetching `identity`'s key file gets `body` from now on.
    pub fn set_body(&self, identity: &Identity, body: Body) {
        self.state()
            .current
            .insert(identity.clone(), Answer::Body(Ok(body)));
    }

    /// Fetching `identity`'s key file fails from now on, as when its host
    /// cannot be reached (4.4). A cached copy from
    /// [`set_cached`](Self::set_cached) is still returned without
    /// `refresh`.
    pub fn fail(&self, identity: &Identity) {
        self.state().current.insert(
            identity.clone(),
            Answer::Body(Err(FetchError::Failed("unreachable".into()))),
        );
    }

    /// `identity`'s key file is gone from now on, as for a 404 (4.4).
    pub fn gone(&self, identity: &Identity) {
        self.set_body(identity, Body::Gone(404));
    }

    /// Fetching `identity`'s key file never finishes from now on.
    pub fn hang(&self, identity: &Identity) {
        self.state().current.insert(identity.clone(), Answer::Hang);
    }

    /// Fetching `identity`'s key file waits, from now on, until the
    /// returned [`Notify`](tokio::sync::Notify) is notified once for each
    /// fetch, and then gets `file`. For tests that need something to
    /// happen while AUTH waits for a key file.
    pub fn hold(&self, identity: &Identity, file: impl Into<Vec<u8>>) -> Arc<tokio::sync::Notify> {
        let notify = Arc::new(tokio::sync::Notify::new());
        let body = Body::File(Arc::from(file.into()));
        self.state()
            .current
            .insert(identity.clone(), Answer::Held(notify.clone(), body));
        notify
    }

    /// Fetches of `identity` without `refresh` get `file`, as if an older
    /// copy were cached, until a fetch with `refresh`.
    pub fn set_cached(&self, identity: &Identity, file: impl Into<Vec<u8>>) {
        self.state()
            .cached
            .insert(identity.clone(), Body::File(Arc::from(file.into())));
    }

    /// Every key file fetch so far, in order, with its `refresh`.
    pub fn calls(&self) -> Vec<(Identity, bool)> {
        self.state().calls.clone()
    }

    /// The key log at the URL prefix `url` serves what `serve` gives for
    /// each path under it (`checkpoint`, `tile/entries/...`), and 404 for
    /// `None`.
    pub fn serve_log(
        &self,
        url: &str,
        serve: impl Fn(&str) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) {
        self.state().logs.insert(url.to_owned(), Arc::new(serve));
    }

    /// Fetches from the key log at the URL prefix `url` fail from now on.
    pub fn fail_log(&self, url: &str) {
        self.state().failing_logs.push(url.to_owned());
    }
}

impl KeyFetcher for MemoryFetcher {
    async fn fetch(&self, identity: &Identity, refresh: bool) -> Result<FetchedFile, FetchError> {
        let (answer, cached) = {
            let mut state = self.state();
            state.calls.push((identity.clone(), refresh));
            let current = state
                .current
                .get(identity)
                .cloned()
                .unwrap_or(Answer::Body(Ok(Body::Gone(404))));
            match (refresh, state.cached.get(identity).cloned()) {
                (false, Some(body)) => (Answer::Body(Ok(body)), true),
                (_, cached) => {
                    // A failed fetch keeps the cached copy (4.4); anything
                    // else replaces it.
                    let failed = matches!(current, Answer::Body(Err(_)));
                    if cached.is_some() && !failed {
                        state.cached.remove(identity);
                    }
                    (current, false)
                }
            }
        };
        let body = match answer {
            Answer::Body(result) => result?,
            Answer::Hang => std::future::pending().await,
            Answer::Held(notify, body) => {
                notify.notified().await;
                body
            }
        };
        Ok(FetchedFile { body, cached })
    }

    async fn fetch_log(&self, url: &str) -> Result<UrlBody, FetchError> {
        let state = self.state();
        let found = state.logs.iter().find_map(|(prefix, serve)| {
            Some((
                prefix,
                serve,
                url.strip_prefix(prefix.as_str())?.strip_prefix('/')?,
            ))
        });
        let Some((prefix, serve, path)) = found else {
            return Err(FetchError::Failed(format!("no log at {url}")));
        };
        if state.failing_logs.contains(prefix) {
            return Err(FetchError::Failed("unreachable".into()));
        }
        Ok(serve(path).map_or(UrlBody::Gone(404), UrlBody::Ok))
    }
}

/// A [`KeyFilePublisher`] that keeps the key files in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryPublisher {
    files: Mutex<HashMap<Name, Vec<u8>>>,
    /// How many of the next removals fail.
    failing_removals: std::sync::atomic::AtomicUsize,
}

impl MemoryPublisher {
    /// An empty one.
    pub fn new() -> MemoryPublisher {
        MemoryPublisher::default()
    }

    /// The next `n` removals fail, as if the file could not be deleted.
    pub fn fail_removals(&self, n: usize) {
        self.failing_removals
            .store(n, std::sync::atomic::Ordering::SeqCst);
    }

    /// The published key file of `name`, if there is one.
    pub fn get(&self, name: &str) -> Option<Vec<u8>> {
        let name: Name = name.parse().ok()?;
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&name)
            .cloned()
    }
}

impl KeyFilePublisher for MemoryPublisher {
    fn publish(&self, name: &Name, file: &[u8]) -> std::io::Result<()> {
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.clone(), file.to_vec());
        Ok(())
    }

    fn remove(&self, name: &Name) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;
        let failing = self
            .failing_removals
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        if failing.is_ok() {
            return Err(std::io::Error::other("removal failed on purpose"));
        }
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name);
        Ok(())
    }

    fn retain(&self, hosted: &[Name]) -> std::io::Result<()> {
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|name, _| hosted.contains(name));
        Ok(())
    }
}

//! Where the hub gets identities' keys, and where it publishes the key
//! files of the identities it hosts (4.4, 4.6).
//!
//! The hub checks AUTH against the identity's key file, which it gets
//! through a [`KeyFetcher`]: over HTTPS in `risalad`, from memory in tests
//! ([`MemoryFetcher`]). The identities it hosts itself it checks against
//! its own records, and it publishes their key files through a
//! [`KeyFilePublisher`] whenever their keys change.
//!
//! [`KeyServices`] bundles the two for [`Hub`](super::Hub). Without them,
//! the hub fetches nothing ([`NoFetcher`]), so only hosted identities can
//! sign in, and publishes nothing ([`NoPublisher`]).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use risala_proto::auth::PublicKey;
use risala_proto::keyfile::KeyEntry;
use risala_proto::names::{Identity, Name};

/// Why an identity's key file could not be had (4.4). For signing in, any
/// of these means the identity has no keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Fetching failed: the address is not allowed, the connection or TLS
    /// failed, the response was not 200, or it was too large or too slow
    /// (4.4).
    #[error("fetching the key file failed: {0}")]
    Failed(String),
    /// This server fetches no key files.
    #[error("this server does not fetch key files")]
    Unavailable,
}

/// Gets the keys of identities the server does not host, from their key
/// files (4.3, 4.4).
///
/// Implementations follow 4.4: HTTPS with certificates checked, no
/// redirects, only a 200 response, at most 10 seconds and 256 KiB, the
/// first 64 different `mldsa44` keys, and no special-purpose addresses
/// unless configured. They may cache a file for up to an hour.
///
/// The hub calls this without holding any lock, and gives up after
/// [`KEY_FETCH_TIMEOUT`](super::KEY_FETCH_TIMEOUT), so a slow key host
/// holds up only the AUTH that waits for it.
pub trait KeyFetcher: Send + Sync + 'static {
    /// The keys in `identity`'s key file.
    ///
    /// - `Ok` means a key file was fetched (or is cached) and parsed: its
    ///   keys, which may be none. The hub closes the identity's connections
    ///   whose device key is no longer listed (4.4).
    /// - `Err` means there is no file to go by: the identity has no keys
    ///   for this sign-in, but its signed-in devices stay.
    ///
    /// With `refresh`, a cached copy must not be used: the hub asks again
    /// with `refresh` once when a signature does not verify against what
    /// it got first, so that a newly added device works straight away
    /// (4.4). After a fetch with `refresh`, later fetches without it
    /// return that file or a newer one.
    fn fetch(
        &self,
        identity: &Identity,
        refresh: bool,
    ) -> impl Future<Output = Result<Vec<PublicKey>, FetchError>> + Send;
}

/// Publishes the key files of the identities the server hosts (4.6): to a
/// directory, to `risalad`'s own HTTPS listener, or both.
///
/// Calls may block: the hub makes them on the blocking pool. For each
/// identity they come one at a time and in order, so the last call is the
/// current state.
pub trait KeyFilePublisher: Send + Sync + 'static {
    /// Publishes the key file of the hosted identity
    /// `<name>@<identity domain>`, with these keys, replacing any earlier
    /// one. It is served at `https://<identity domain>/.well-known/risala/<name>`
    /// (4.3). The hub calls this on REGISTER and on every change to the
    /// identity's keys, and for every hosted identity when it starts.
    fn publish(&self, name: &Name, keys: &[KeyEntry]) -> std::io::Result<()>;

    /// Removes the key file of `<name>@<identity domain>`, after UNREGISTER
    /// (4.8). Removing a file that does not exist is not an error.
    fn remove(&self, name: &Name) -> std::io::Result<()>;

    /// Removes every key file but those of `hosted`, the names the server
    /// hosts. The hub calls this when it starts, after publishing theirs,
    /// so that a removal that failed earlier is made up for (4.8).
    fn retain(&self, hosted: &[Name]) -> std::io::Result<()> {
        let _ = hosted;
        Ok(())
    }
}

/// A [`KeyFetcher`] that has no keys for anyone: [`FetchError::Unavailable`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFetcher;

impl KeyFetcher for NoFetcher {
    async fn fetch(&self, _: &Identity, _: bool) -> Result<Vec<PublicKey>, FetchError> {
        Err(FetchError::Unavailable)
    }
}

/// A [`KeyFilePublisher`] that publishes nothing, for a server whose
/// operator publishes the key files some other way.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPublisher;

impl KeyFilePublisher for NoPublisher {
    fn publish(&self, _: &Name, _: &[KeyEntry]) -> std::io::Result<()> {
        Ok(())
    }

    fn remove(&self, _: &Name) -> std::io::Result<()> {
        Ok(())
    }
}

/// The boxed form of [`KeyFetcher`], so that the hub can hold any.
pub(crate) trait DynKeyFetcher: Send + Sync + 'static {
    fn fetch_boxed<'a>(
        &'a self,
        identity: &'a Identity,
        refresh: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<PublicKey>, FetchError>> + Send + 'a>>;
}

impl<T: KeyFetcher> DynKeyFetcher for T {
    fn fetch_boxed<'a>(
        &'a self,
        identity: &'a Identity,
        refresh: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<PublicKey>, FetchError>> + Send + 'a>> {
        Box::pin(self.fetch(identity, refresh))
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
    /// These keys, or this error.
    Keys(Result<Vec<PublicKey>, FetchError>),
    /// Never answers, like a key host that does not respond.
    Hang,
    /// Answers with these keys once notified.
    Held(Arc<tokio::sync::Notify>, Vec<PublicKey>),
}

#[derive(Debug, Default)]
struct MemoryState {
    /// What a fetch with `refresh` gets: the key file as it is now.
    current: HashMap<Identity, Answer>,
    /// What a fetch without `refresh` gets instead, until the next fetch
    /// with it: an older copy in the cache.
    cached: HashMap<Identity, Vec<PublicKey>>,
    /// Every fetch, in order, with its `refresh`.
    calls: Vec<(Identity, bool)>,
}

/// A [`KeyFetcher`] with key files in memory, for tests. It can model a
/// cache that is out of date ([`set_cached`](Self::set_cached)), a fetch
/// that fails, and a key host that never answers.
///
/// An identity it knows nothing about gets [`FetchError::Failed`], as for
/// a 404.
#[derive(Debug, Default)]
pub struct MemoryFetcher {
    state: Mutex<MemoryState>,
}

impl MemoryFetcher {
    /// An empty one.
    pub fn new() -> MemoryFetcher {
        MemoryFetcher::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `identity`'s key file lists `keys` from now on.
    pub fn set(&self, identity: &Identity, keys: Vec<PublicKey>) {
        self.state()
            .current
            .insert(identity.clone(), Answer::Keys(Ok(keys)));
    }

    /// Fetching `identity`'s key file fails from now on.
    pub fn fail(&self, identity: &Identity) {
        self.state().current.insert(
            identity.clone(),
            Answer::Keys(Err(FetchError::Failed("404".into()))),
        );
    }

    /// Fetching `identity`'s key file never finishes from now on.
    pub fn hang(&self, identity: &Identity) {
        self.state().current.insert(identity.clone(), Answer::Hang);
    }

    /// Fetching `identity`'s key file waits, from now on, until the
    /// returned [`Notify`](tokio::sync::Notify) is notified once for each
    /// fetch, and then lists `keys`. For tests that need something to
    /// happen while AUTH waits for a key file.
    pub fn hold(&self, identity: &Identity, keys: Vec<PublicKey>) -> Arc<tokio::sync::Notify> {
        let notify = Arc::new(tokio::sync::Notify::new());
        self.state()
            .current
            .insert(identity.clone(), Answer::Held(notify.clone(), keys));
        notify
    }

    /// Fetches of `identity` without `refresh` get `keys`, as if an older
    /// copy were cached, until a fetch with `refresh`.
    pub fn set_cached(&self, identity: &Identity, keys: Vec<PublicKey>) {
        self.state().cached.insert(identity.clone(), keys);
    }

    /// Every fetch so far, in order, with its `refresh`.
    pub fn calls(&self) -> Vec<(Identity, bool)> {
        self.state().calls.clone()
    }
}

impl KeyFetcher for MemoryFetcher {
    async fn fetch(
        &self,
        identity: &Identity,
        refresh: bool,
    ) -> Result<Vec<PublicKey>, FetchError> {
        let answer = {
            let mut state = self.state();
            state.calls.push((identity.clone(), refresh));
            let cached = if refresh {
                state.cached.remove(identity);
                None
            } else {
                state.cached.get(identity).cloned()
            };
            match cached {
                Some(keys) => Answer::Keys(Ok(keys)),
                None => state
                    .current
                    .get(identity)
                    .cloned()
                    .unwrap_or(Answer::Keys(Err(FetchError::Failed("404".into())))),
            }
        };
        match answer {
            Answer::Keys(result) => result,
            Answer::Hang => std::future::pending().await,
            Answer::Held(notify, keys) => {
                notify.notified().await;
                Ok(keys)
            }
        }
    }
}

/// A [`KeyFilePublisher`] that keeps the key files in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryPublisher {
    files: Mutex<HashMap<Name, Vec<KeyEntry>>>,
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
    pub fn get(&self, name: &str) -> Option<Vec<KeyEntry>> {
        let name: Name = name.parse().ok()?;
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&name)
            .cloned()
    }
}

impl KeyFilePublisher for MemoryPublisher {
    fn publish(&self, name: &Name, keys: &[KeyEntry]) -> std::io::Result<()> {
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.clone(), keys.to_vec());
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

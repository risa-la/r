//! Keeping a connection up: reconnects with exponential backoff and
//! jitter, signing in again each time, and reporting what happens.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::SecretKey;
use risala_proto::error::ErrorCode;
use risala_proto::names::{Id, Identity, MAX_NAME_LEN, Name, Uid};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::error::{CloseReason, CommandError, Error};
use super::session::{Incoming, Session, SessionInfo, SessionOptions};
use super::tls;
use crate::addr::{ServerAddr, TrustStore};

/// A boxed future, for [`SignIn`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How a [`Supervisor`] signs in on each new connection.
pub trait SignIn: Send + Sync {
    /// Signs `session` in and returns the uid. An error that
    /// [`is_permanent`](Error::is_permanent), such as `auth-failed`,
    /// stops the supervisor.
    fn sign_in<'a>(&'a self, session: &'a Session) -> BoxFuture<'a, Result<Uid, Error>>;
}

/// The guest session (4.2) a [`GuestSignIn`] resumes: the name it got and
/// the token from the last `OK`. Shared, so that the app can load it from
/// its cache before connecting and save it after each sign-in.
///
/// The token is a secret: [`Debug`](std::fmt::Debug) leaves it out.
#[derive(Default)]
pub struct GuestToken {
    session: std::sync::Mutex<Option<(Name, Id)>>,
}

impl std::fmt::Debug for GuestToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestToken")
            .field("name", &self.get().map(|(name, _)| name))
            .finish_non_exhaustive()
    }
}

impl GuestToken {
    /// A holder with `session` in it, as [`set`](Self::set) leaves it.
    pub fn new(session: Option<(Name, Id)>) -> GuestToken {
        GuestToken {
            session: std::sync::Mutex::new(session),
        }
    }

    /// The name and token of the session to resume, if any.
    pub fn get(&self) -> Option<(Name, Id)> {
        self.session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Records the session signed in to, or forgets it.
    pub fn set(&self, session: Option<(Name, Id)>) {
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = session;
    }
}

/// Signs in as the guest `~<name>` (4.2), resuming the last session when
/// it can.
///
/// - If [`session`](Self::session) holds a session, it sends
///   `GUEST <that name> token=<token>` first. The server resumes the
///   session if it is still waiting, and otherwise ignores the token.
/// - If that name is taken, the session has ended and someone else has
///   the name, so it tries `<name>`, then `<name>2`, `<name>3` and so on,
///   on the same connection, up to [`GuestSignIn::MAX_NAMES`] names in
///   all. Each new connection starts again from the stored session.
///
/// Either way, the name and the new token from the `OK` go into
/// [`session`](Self::session), and the uid is in
/// [`SupervisorEvent::SignedIn`].
#[derive(Debug, Clone)]
pub struct GuestSignIn {
    /// The name the user chose, without `~`.
    pub name: Name,
    /// The session to resume, updated by each sign-in.
    pub session: Arc<GuestToken>,
}

impl GuestSignIn {
    /// How many names one sign-in tries before giving up until the next
    /// connection.
    pub const MAX_NAMES: u32 = 9;

    /// Signs in as `~<name>`, with no session to resume yet.
    pub fn new(name: Name) -> GuestSignIn {
        GuestSignIn::resuming(name, Arc::default())
    }

    /// Signs in as `~<name>`, resuming the session in `session` if there
    /// is one.
    pub fn resuming(name: Name, session: Arc<GuestToken>) -> GuestSignIn {
        GuestSignIn { name, session }
    }

    /// The `n`th name to try, counting from 1: `<name>` itself, then
    /// `<name>2`, `<name>3` and so on, shortened to fit 32 characters.
    pub fn numbered(&self, n: u32) -> Name {
        if n <= 1 {
            return self.name.clone();
        }
        let suffix = n.to_string();
        let base = self.name.as_str();
        let keep = base.len().min(MAX_NAME_LEN - suffix.len());
        // Names are ASCII. A shortened name may not end with '.' (3.5),
        // but it can end with a digit, '_' or '-' before the suffix.
        let base = base[..keep].trim_end_matches('.');
        format!("{base}{suffix}")
            .parse()
            .expect("a shortened name plus digits is a name")
    }

    /// Records the session `GUEST <name>` signed in to.
    fn signed_in(&self, name: &Name, token: Option<Id>) {
        self.session.set(token.map(|t| (name.clone(), t)));
    }
}

fn name_taken(e: &Error) -> bool {
    matches!(e, Error::Rejected(CommandError::Server(e)) if e.code == ErrorCode::NameTaken)
}

impl SignIn for GuestSignIn {
    fn sign_in<'a>(&'a self, session: &'a Session) -> BoxFuture<'a, Result<Uid, Error>> {
        Box::pin(async move {
            let resumed = self.session.get();
            if let Some((name, token)) = &resumed {
                match session.guest_session(name, Some(token)).await {
                    Ok((uid, token)) => {
                        self.signed_in(name, token);
                        return Ok(uid);
                    }
                    Err(e) if name_taken(&e) => {}
                    Err(e) => return Err(e),
                }
            }
            let tried = resumed.map(|(name, _)| name);
            let mut n = 1;
            loop {
                let name = self.numbered(n);
                if tried.as_ref() == Some(&name) && n < Self::MAX_NAMES {
                    // Just refused.
                    n += 1;
                    continue;
                }
                match session.guest_session(&name, None).await {
                    Err(e) if name_taken(&e) && n < Self::MAX_NAMES => n += 1,
                    Ok((uid, token)) => {
                        self.signed_in(&name, token);
                        return Ok(uid);
                    }
                    Err(e) => return Err(e),
                }
            }
        })
    }
}

/// Signs in as an identity with a device key (4.5).
#[derive(Debug, Clone)]
pub struct IdentitySignIn {
    /// The identity.
    pub identity: Identity,
    /// The device key, listed in the identity's key file.
    pub key: SecretKey,
}

impl SignIn for IdentitySignIn {
    fn sign_in<'a>(&'a self, session: &'a Session) -> BoxFuture<'a, Result<Uid, Error>> {
        Box::pin(session.auth(&self.identity, &self.key))
    }
}

/// How long to wait between attempts.
///
/// After the `n`th failure in a row the wait is about `initial * 2^(n-1)`,
/// capped at `max`, with "equal jitter": a random point in its upper half,
/// so that many clients do not reconnect in step. A connection that stayed
/// signed in for `stable_after` resets the count, and the first attempt
/// after it is immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The first wait.
    pub initial: Duration,
    /// The longest wait.
    pub max: Duration,
    /// How long a connection must last to reset the count.
    pub stable_after: Duration,
}

impl Default for Backoff {
    /// One second, doubling up to five minutes; reset after a minute.
    fn default() -> Self {
        Backoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(300),
            stable_after: Duration::from_secs(60),
        }
    }
}

impl Backoff {
    /// The wait before the next attempt, after `failures` failures in a
    /// row. Zero for none.
    pub fn delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let factor = 1u32 << failures.saturating_sub(1).min(20);
        let full = self.initial.saturating_mul(factor).min(self.max);
        let half = full / 2;
        let jitter = getrandom::u64().unwrap_or(0) % (half.as_millis() as u64 + 1);
        half + Duration::from_millis(jitter)
    }
}

/// What a [`Supervisor`] reports, in order.
#[derive(Debug)]
pub enum SupervisorEvent {
    /// Connecting, for the `attempt`th time since the last stable
    /// connection (0 for the first).
    Connecting {
        /// Failures in a row so far.
        attempt: u32,
    },
    /// TLS is up and the greeting has arrived; signing in.
    Connected {
        /// The new connection.
        info: SessionInfo,
    },
    /// Signed in. The session is ready for commands, and its incoming
    /// lines arrive on `incoming`. Catch up with SYNC (7.1) now.
    SignedIn {
        /// The uid signed in as.
        uid: Uid,
        /// The session. The supervisor keeps a handle to close it.
        session: Arc<Session>,
        /// The session's incoming queue: lines, and the replies to
        /// commands sent with [`Session::send`], in arrival order.
        incoming: mpsc::Receiver<Incoming>,
    },
    /// The signed-in connection closed.
    Disconnected {
        /// Why.
        reason: CloseReason,
    },
    /// Waiting before the next attempt.
    Waiting {
        /// How long.
        delay: Duration,
        /// The error that ended the last attempt, if it failed before
        /// signing in.
        error: Option<Error>,
    },
    /// Gave up: the error cannot pass without the user (a trust error,
    /// `auth-failed` and so on; see [`Error::is_permanent`]). The
    /// supervisor has stopped.
    Failed {
        /// The error.
        error: Error,
    },
    /// [`Supervisor::stop`] was called. The supervisor has stopped.
    Stopped,
}

/// Keeps one connection to one server up, signing in each time.
///
/// It runs as a task. Events arrive on the receiver returned by
/// [`spawn`](Self::spawn); the supervisor waits for the app to read
/// them, and stops if the receiver is dropped.
#[derive(Debug)]
pub struct Supervisor {
    stop: watch::Sender<bool>,
    retry: watch::Sender<u64>,
    task: tokio::task::JoinHandle<()>,
}

impl Supervisor {
    /// Starts keeping a connection to `addr` up.
    ///
    /// If `options` has no CA verifier, the platform's is loaded once
    /// here and reused.
    pub fn spawn(
        addr: ServerAddr,
        trust: Arc<dyn TrustStore>,
        options: SessionOptions,
        sign_in: Arc<dyn SignIn>,
        backoff: Backoff,
    ) -> (Supervisor, mpsc::Receiver<SupervisorEvent>) {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (retry, retry_rx) = watch::channel(0u64);
        let run = Run {
            addr,
            trust,
            options,
            sign_in,
            backoff,
            events: events_tx,
            stop: stop_rx,
            retry: retry_rx,
        };
        let task = tokio::spawn(run.run());
        (
            Supervisor {
                stop: stop_tx,
                retry,
                task,
            },
            events_rx,
        )
    }

    /// Skips the current wait and tries again now, for example when the
    /// network comes back. Closes the current connection if there is
    /// one, so that a stale connection is replaced. A call while
    /// connecting does nothing.
    pub fn reconnect_now(&self) {
        self.retry.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Closes the connection and stops. Reports
    /// [`SupervisorEvent::Stopped`] unless it had already stopped.
    pub async fn stop(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.task).await;
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

struct Run {
    addr: ServerAddr,
    trust: Arc<dyn TrustStore>,
    options: SessionOptions,
    sign_in: Arc<dyn SignIn>,
    backoff: Backoff,
    events: mpsc::Sender<SupervisorEvent>,
    stop: watch::Receiver<bool>,
    retry: watch::Receiver<u64>,
}

/// The supervisor was told to stop, or the app went away.
struct Stop;

impl Run {
    async fn run(mut self) {
        let _: Result<(), Stop> = self.run_inner().await;
    }

    async fn emit(&self, event: SupervisorEvent) -> Result<(), Stop> {
        self.events.send(event).await.map_err(|_| Stop)
    }

    async fn stopped(stop: &mut watch::Receiver<bool>) {
        let _ = stop.wait_for(|s| *s).await;
    }

    async fn run_inner(&mut self) -> Result<(), Stop> {
        if self.options.ca_verifier.is_none() {
            self.options.ca_verifier = Some(tls::platform_ca_verifier());
        }
        let mut failures: u32 = 0;
        loop {
            self.emit(SupervisorEvent::Connecting { attempt: failures })
                .await?;
            let mut stop = self.stop.clone();
            let attempt = tokio::select! {
                r = self.attempt() => r,
                () = Run::stopped(&mut stop) => return self.emit(SupervisorEvent::Stopped).await,
            };
            // A request to reconnect made while connecting is already met.
            self.retry.borrow_and_update();
            let mut error = None;
            let mut hint = Duration::ZERO;
            match attempt {
                Ok((session, uid)) => {
                    let session = Arc::new(session);
                    let incoming = session.take_incoming().expect("a new session");
                    let started = Instant::now();
                    self.emit(SupervisorEvent::SignedIn {
                        uid,
                        session: session.clone(),
                        incoming,
                    })
                    .await?;
                    let mut stop = self.stop.clone();
                    let reason = tokio::select! {
                        r = session.closed() => r,
                        Ok(()) = self.retry.changed() => {
                            session.close();
                            session.closed().await
                        }
                        () = Run::stopped(&mut stop) => {
                            session.close();
                            return self.emit(SupervisorEvent::Stopped).await;
                        }
                    };
                    self.emit(SupervisorEvent::Disconnected { reason }).await?;
                    if started.elapsed() >= self.backoff.stable_after {
                        failures = 0;
                    } else {
                        failures = failures.saturating_add(1);
                    }
                }
                Err(e) if e.is_permanent() => {
                    return self.emit(SupervisorEvent::Failed { error: e }).await;
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    hint = Duration::from_secs(e.retry_after().unwrap_or(0));
                    error = Some(e);
                }
            }
            let delay = self.backoff.delay(failures).max(hint);
            if delay.is_zero() {
                continue;
            }
            self.emit(SupervisorEvent::Waiting { delay, error }).await?;
            let mut stop = self.stop.clone();
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                Ok(()) = self.retry.changed() => {}
                () = Run::stopped(&mut stop) => return self.emit(SupervisorEvent::Stopped).await,
            }
        }
    }

    /// Connects and signs in once.
    async fn attempt(&self) -> Result<(Session, Uid), Error> {
        let session =
            Session::connect(&self.addr, self.trust.clone(), self.options.clone()).await?;
        self.emit(SupervisorEvent::Connected {
            info: session.info().clone(),
        })
        .await
        .map_err(|_| Error::Closed(CloseReason::Local))?;
        let uid = self.sign_in.sign_in(&session).await?;
        Ok((session, uid))
    }
}

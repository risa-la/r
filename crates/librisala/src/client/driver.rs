//! Running an account: its connections ([`ServerConnections`]) and its
//! engines ([`crate::sync`]).
//!
//! Owned by task C2, which builds the group engine that needs most of
//! this. What C0 left here is real but thin: [`Client::connect`] starts
//! the account's connections and reports their state as
//! [`Event::Connection`](super::Event), and every line that arrives goes
//! to [`Engines::line`], whose engines are still empty. Carrying out the
//! engines' [`Action`](crate::sync::Action)s (sending on the right
//! connection, matching replies to tokens, FOLLOW after each reconnect)
//! is C2's.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use risala_proto::server::ServerLine;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use super::{Client, ConnectionEvent, ConnectionState, Event, Result};
use crate::conn::{
    ConnectionPlan, GuestSession, GuestSignIn, Incoming, PoolEvent, ServerConnections, Slot,
    SupervisorEvent,
};
use crate::store::{AccountId, AccountKind, Store};
use crate::sync::{Context, Engines};

/// The accounts that are running.
#[derive(Default)]
pub(crate) struct Running(Mutex<HashMap<AccountId, RunningAccount>>);

struct RunningAccount {
    connections: ServerConnections,
    task: JoinHandle<()>,
}

impl Running {
    fn take(&self, account: AccountId) -> Option<RunningAccount> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&account)
    }

    fn is_running(&self, account: AccountId) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&account)
    }
}

impl Client {
    /// Starts an account's connections (4.1): for an identity, one signed
    /// in and [`anonymous_connections`](super::ClientOptions) anonymous
    /// ones; for a guest, one guest connection that resumes its last
    /// session if it can (4.2). They reconnect on their own until
    /// [`disconnect`](Self::disconnect). Does nothing if it is running.
    pub async fn connect(&self, account: AccountId) -> Result<()> {
        if self.running().is_running(account) {
            return Ok(());
        }
        let a = self.account(account)?;
        let mut guest = None;
        let plan = match a.kind {
            AccountKind::Identity => ConnectionPlan::identity(
                self.identity_sign_in(account).await?,
                self.options().anonymous_connections,
            ),
            AccountKind::Guest => {
                let stored = self
                    .blocking(move |c| Ok(c.store().guest_session(account)?))
                    .await?;
                let session = Arc::new(GuestSession::new(stored));
                guest = Some(session.clone());
                let name = a
                    .uid
                    .as_str()
                    .trim_start_matches('~')
                    .parse()
                    .map_err(|_| super::Error::invalid("guest name", a.uid.as_str()))?;
                ConnectionPlan::guest(Arc::new(GuestSignIn::resuming(name, session)))
            }
        };
        let (connections, events) = ServerConnections::spawn(
            a.server.clone(),
            self.trust(),
            self.session_options(),
            &plan,
            self.options().backoff,
        )
        .await;
        let run = Run {
            store: self.store().clone(),
            account,
            events: self.inner.events.clone(),
            guest,
        };
        let task = tokio::spawn(run.run(events));
        let this = RunningAccount { connections, task };
        let raced = {
            let mut running = self.running().0.lock().unwrap_or_else(|e| e.into_inner());
            match running.entry(account) {
                std::collections::hash_map::Entry::Occupied(_) => Some(this),
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(this);
                    None
                }
            }
        };
        // Another call won the race; stop this one.
        if let Some(raced) = raced {
            raced.task.abort();
            raced.connections.stop().await;
        }
        Ok(())
    }

    /// Stops an account's connections. Does nothing if it is not running.
    pub async fn disconnect(&self, account: AccountId) -> Result<()> {
        if let Some(running) = self.running().take(account) {
            running.connections.stop().await;
            let _ = running.task.await;
        }
        Ok(())
    }
}

/// The task that reads an account's connection events.
struct Run {
    store: Store,
    account: AccountId,
    events: broadcast::Sender<Event>,
    guest: Option<Arc<GuestSession>>,
}

impl Run {
    fn emit(&self, slot: Slot, state: ConnectionState) {
        let _ = self.events.send(Event::Connection(ConnectionEvent {
            account: self.account,
            slot,
            state,
        }));
    }

    async fn run(self, mut events: mpsc::Receiver<PoolEvent>) {
        let engines = Arc::new(tokio::sync::Mutex::new(Engines::default()));
        let cx = Context {
            store: self.store.clone(),
            account: self.account,
        };
        while let Some(PoolEvent { slot, event }) = events.recv().await {
            match event {
                SupervisorEvent::Connecting { attempt } => {
                    self.emit(slot, ConnectionState::Connecting { attempt });
                }
                SupervisorEvent::Connected { info } => {
                    if let Some(change) = info.verified.pin_change {
                        let _ = self.events.send(Event::PinReplaced {
                            server: info.addr,
                            change,
                        });
                    }
                }
                SupervisorEvent::Ready {
                    kind,
                    session: _,
                    incoming,
                    ..
                } => {
                    self.save_guest_session().await;
                    self.emit(slot, ConnectionState::Ready);
                    {
                        let mut engines = engines.lock().await;
                        let _actions =
                            engines.broadcast(&cx, &crate::sync::Input::Ready { slot, kind });
                    }
                    tokio::spawn(read(cx.clone(), engines.clone(), slot, incoming));
                }
                SupervisorEvent::Disconnected { reason } => {
                    let mut engines = engines.lock().await;
                    let _ = engines.broadcast(&cx, &crate::sync::Input::Closed { slot });
                    self.emit(
                        slot,
                        ConnectionState::Waiting {
                            error: Some(reason.to_string()),
                            delay_ms: 0,
                        },
                    );
                }
                SupervisorEvent::Waiting { delay, error } => self.emit(
                    slot,
                    ConnectionState::Waiting {
                        error: error.map(|e| e.to_string()),
                        delay_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    },
                ),
                SupervisorEvent::Failed { error } => {
                    self.emit(slot, ConnectionState::Failed(error.to_string()));
                }
                SupervisorEvent::Stopped => self.emit(slot, ConnectionState::Stopped),
            }
        }
    }

    /// Keeps the guest session a sign-in got, so that the next run of the
    /// app resumes it (4.2).
    async fn save_guest_session(&self) {
        let Some(guest) = &self.guest else {
            return;
        };
        let (store, account, session) = (self.store.clone(), self.account, guest.get());
        let saved = tokio::task::spawn_blocking(move || {
            let session = session.as_ref().map(|(n, t)| (n, t));
            store.set_guest_session(account, session)
        })
        .await;
        match saved {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "could not keep the guest session"),
            Err(e) => tracing::warn!(error = %e, "could not keep the guest session"),
        }
    }
}

/// Reads one connection's lines, and hands each to its engine (task C2:
/// and carries out the engines' actions).
async fn read(
    cx: Context,
    engines: Arc<tokio::sync::Mutex<Engines>>,
    slot: Slot,
    mut incoming: mpsc::Receiver<Incoming>,
) {
    while let Some(item) = incoming.recv().await {
        match item {
            Incoming::Line(message) => {
                if let ServerLine::Notice { message } = &message.line {
                    tracing::info!(?slot, notice = %message, "server notice");
                }
                let _actions = engines.lock().await.line(&cx, slot, &message);
            }
            // Only engines send with Session::send, and none does yet.
            Incoming::Reply { ref_, .. } => {
                tracing::debug!(?slot, %ref_, "a reply no engine asked for");
            }
        }
    }
}

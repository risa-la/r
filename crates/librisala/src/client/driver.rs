//! Running an account: its connections ([`ServerConnections`]) and its
//! engines ([`crate::sync`]).
//!
//! Owned by task C2. [`Client::connect`] starts the account's
//! connections, and a task that hands what they bring to the engines and
//! carries out what the engines ask:
//!
//! - **Lines** go to the engine of their area ([`crate::sync::route`]).
//! - **Commands** an engine sends go on the connection its [`Target`]
//!   names: the signed-in one, the anonymous one that follows a mailbox
//!   ([`MailboxSlots`], or the guest's only connection), the WATCH one, or
//!   a connection of its own for one command ([`single_use`], 4.1). They
//!   are sent with [`Session::send`], so that their replies arrive in
//!   their place among the live lines (3.6, 7.1), and each reply goes back
//!   to the engine that sent the command, with its [`Token`].
//! - A command whose connection is down, or closes before its reply, gets
//!   a reply whose end is [`End::Unparseable`], so the engine can try
//!   again.
//! - **Time**: every engine gets an [`Input::Tick`] each second.
//! - **Events** engines emit go to [`Client::subscribe`].
//!
//! The API reaches a running account's engines through `Exec`, to start
//! jobs and to make the engines send at once what an API call queued.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_proto::command::Command;
use risala_proto::connection::ConnectionKind;
use risala_proto::server::ServerMessage;
use risala_proto::types::Ref;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use super::{Client, ConnectionEvent, ConnectionState, Error, Event, Result};
use crate::addr::{ServerAddr, TrustStore};
use crate::conn::{
    ConnectionPlan, End, GuestSession, GuestSignIn, Incoming, MailboxSlots, PoolEvent, Response,
    ServerConnections, Session, SessionOptions, Slot, SupervisorEvent, single_use,
};
use crate::store::{AccountId, AccountKind, Store};
use crate::sync::conversations::{Config, ConversationEngine, Hooks, SINGLE_USE_SLOT};
use crate::sync::{Action, Area, Context, Engine, Engines, Input, Target, Token, route};

/// How often engines get a tick.
const TICK: Duration = Duration::from_secs(1);

/// How many mailboxes one anonymous connection follows at most (7.1: a
/// server allows at least 1,000).
const PER_CONNECTION: usize = MailboxSlots::MIN_SERVER_LIMIT;

/// The accounts that are running.
#[derive(Default)]
pub(crate) struct Running(Mutex<HashMap<AccountId, RunningAccount>>);

struct RunningAccount {
    connections: ServerConnections,
    exec: Arc<Exec>,
    tasks: Vec<JoinHandle<()>>,
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

    /// A running account's executor.
    pub(crate) fn exec(&self, account: AccountId) -> Option<Arc<Exec>> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&account)
            .map(|r| r.exec.clone())
    }
}

/// Which engine a command came from, to give its reply back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EngineId {
    Identity,
    KeyLog,
    Conversations,
    Confirm,
    Transfer,
    Push,
}

const ALL: [EngineId; 6] = [
    EngineId::Identity,
    EngineId::KeyLog,
    EngineId::Conversations,
    EngineId::Confirm,
    EngineId::Transfer,
    EngineId::Push,
];

fn engine(engines: &mut Engines, id: EngineId) -> &mut dyn Engine {
    match id {
        EngineId::Identity => &mut engines.identity,
        EngineId::KeyLog => &mut engines.keylog,
        EngineId::Conversations => &mut engines.conversations,
        EngineId::Confirm => &mut engines.confirm,
        EngineId::Transfer => &mut engines.transfer,
        EngineId::Push => &mut engines.push,
    }
}

/// An account's engines, its live sessions and the commands in flight.
pub(crate) struct Exec {
    cx: Context,
    engines: tokio::sync::Mutex<Engines>,
    sessions: Mutex<HashMap<Slot, (Arc<Session>, ConnectionKind)>>,
    pending: Mutex<HashMap<(Slot, Ref), (EngineId, Token)>>,
    mailboxes: Mutex<MailboxSlots>,
    events: broadcast::Sender<Event>,
    addr: ServerAddr,
    trust: Arc<dyn TrustStore>,
    options: SessionOptions,
    guest: bool,
    /// Replies that do not come from a session's queue: single-use
    /// connections, and commands that could not be sent.
    replies: mpsc::UnboundedSender<(EngineId, Slot, Token, Response)>,
}

fn failed(why: impl Into<String>) -> Response {
    Response {
        lines: Vec::new(),
        end: End::Unparseable(why.into()),
    }
}

impl Exec {
    /// Runs `f` on the engines, and carries out the actions it returns as
    /// the conversation engine's.
    pub(crate) async fn with_conversations<T>(
        &self,
        f: impl FnOnce(&mut ConversationEngine, &Context) -> (T, Vec<Action>),
    ) -> T {
        let mut engines = self.engines.lock().await;
        let (value, actions) = f(&mut engines.conversations, &self.cx);
        self.carry_out(EngineId::Conversations, actions);
        value
    }

    /// Reads the conversation engine, if no one holds it now.
    pub(crate) fn try_conversations<T>(
        &self,
        f: impl FnOnce(&ConversationEngine) -> T,
    ) -> Option<T> {
        let engines = self.engines.try_lock().ok()?;
        Some(f(&engines.conversations))
    }

    /// Gives every engine a tick now, so that what an API call queued is
    /// sent at once.
    pub(crate) async fn kick(&self) {
        let now = crate::clock::Clock::now(&crate::clock::SystemClock);
        self.broadcast(&Input::Tick { now }).await;
    }

    async fn broadcast(&self, input: &Input<'_>) {
        let mut engines = self.engines.lock().await;
        for id in ALL {
            let actions = engine(&mut engines, id).handle(&self.cx, input);
            self.carry_out(id, actions);
        }
    }

    async fn line(&self, slot: Slot, message: &ServerMessage) {
        let id = match route(&message.line) {
            Area::Identity => EngineId::Identity,
            Area::Conversations => EngineId::Conversations,
            Area::Transfer => EngineId::Transfer,
            Area::Push => EngineId::Push,
            Area::Connection | Area::Admin => return,
        };
        let mut engines = self.engines.lock().await;
        let actions = engine(&mut engines, id).handle(&self.cx, &Input::Line { slot, message });
        self.carry_out(id, actions);
    }

    async fn reply(&self, id: EngineId, slot: Slot, token: Token, response: &Response) {
        match &response.end {
            End::Err(e) => {
                tracing::debug!(engine = ?id, ?slot, code = %e.code, msg = %e.message, "a command was refused")
            }
            End::Unparseable(why) => {
                tracing::debug!(engine = ?id, ?slot, why, "a command got no reply")
            }
            End::Ok(_) => {}
        }
        let mut engines = self.engines.lock().await;
        let actions = engine(&mut engines, id).handle(
            &self.cx,
            &Input::Reply {
                slot,
                token,
                response,
            },
        );
        self.carry_out(id, actions);
    }

    /// Carries out an engine's actions.
    fn carry_out(&self, id: EngineId, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Emit(event) => {
                    let _ = self.events.send(event);
                }
                Action::Send {
                    target,
                    command,
                    token,
                } => self.send(id, target, command, token),
            }
        }
    }

    /// The slot a command for `target` goes on, if it has one.
    fn slot_for(&self, target: &Target) -> Option<Slot> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match target {
            Target::SignedIn => Some(Slot::SignedIn),
            Target::Watch => Some(Slot::Watch),
            Target::Mailbox(mailbox) => {
                if self.guest {
                    return Some(Slot::Guest);
                }
                let mut slots = self.mailboxes.lock().unwrap_or_else(|e| e.into_inner());
                slots.assign(mailbox).map(Slot::Anonymous)
            }
            Target::Conversing => {
                if self.guest {
                    return Some(Slot::Guest);
                }
                sessions
                    .iter()
                    .filter(|(s, (_, k))| {
                        matches!(s, Slot::Anonymous(_)) && *k == ConnectionKind::Anonymous
                    })
                    .map(|(s, _)| *s)
                    .min()
            }
            Target::Own(_) => None,
        }
    }

    fn send(&self, id: EngineId, target: Target, command: Command, token: Token) {
        tracing::trace!(engine = ?id, verb = command.verb(), "sending a command");
        if let Target::Own(kind) = target {
            let (addr, trust, options, replies) = (
                self.addr.clone(),
                self.trust.clone(),
                self.options.clone(),
                self.replies.clone(),
            );
            tokio::spawn(async move {
                let response = match single_use(&addr, trust, options, kind, command).await {
                    Ok(r) => r,
                    Err(e) => failed(e.to_string()),
                };
                let _ = replies.send((id, SINGLE_USE_SLOT, token, response));
            });
            return;
        }
        let Some(slot) = self.slot_for(&target) else {
            let _ = self
                .replies
                .send((id, Slot::Anonymous(0), token, failed("no connection")));
            return;
        };
        let session = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&slot)
            .map(|(s, _)| s.clone());
        let Some(session) = session else {
            let _ = self
                .replies
                .send((id, slot, token, failed("not connected")));
            return;
        };
        // Held while sending, so that a fast reply finds its entry.
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        match session.send(command) {
            Ok(ref_) => {
                pending.insert((slot, ref_), (id, token));
            }
            Err(e) => {
                drop(pending);
                let _ = self.replies.send((id, slot, token, failed(e.to_string())));
            }
        }
    }

    /// A connection closed: the commands in flight on it get no reply.
    fn closed(&self, slot: Slot) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&slot);
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let lost: Vec<(Slot, Ref)> = pending
            .keys()
            .filter(|(s, _)| *s == slot)
            .cloned()
            .collect();
        for key in lost {
            if let Some((id, token)) = pending.remove(&key) {
                let _ = self
                    .replies
                    .send((id, slot, token, failed("connection closed")));
            }
        }
    }

    /// Sends a command on the connection `target` names and waits for its
    /// response, for API calls and task C4's worker: a connection of its
    /// own for [`Target::Own`].
    pub(crate) async fn request_on(&self, target: Target, command: Command) -> Result<Response> {
        if let Target::Own(kind) = target {
            return single_use(
                &self.addr,
                self.trust.clone(),
                self.options.clone(),
                kind,
                command,
            )
            .await
            .map_err(Error::from);
        }
        let slot = self
            .slot_for(&target)
            .ok_or(Error::Internal("no connection for that command".into()))?;
        self.request(slot, command).await
    }

    /// Sends a command on a slot and waits for its response, for API
    /// calls that are not an engine's (PRESENCE, WATCH).
    pub(crate) async fn request(&self, slot: Slot, command: Command) -> Result<Response> {
        let session = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&slot)
            .map(|(s, _)| s.clone())
            .ok_or(Error::Internal("that connection is not up".into()))?;
        Ok(session.request(command).await?)
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
        self.connect_with(account, plan, guest, self.options().conversations.clone())
            .await
    }

    /// [`connect`](Self::connect) with a plan of its own, and the group
    /// engine's settings: for tests, and until the identity area (C1)
    /// signs identities in.
    pub(crate) async fn connect_with(
        &self,
        account: AccountId,
        plan: ConnectionPlan,
        guest: Option<Arc<GuestSession>>,
        config: Config,
    ) -> Result<()> {
        let a = self.account(account)?;
        let (connections, events) = ServerConnections::spawn(
            a.server.clone(),
            self.trust(),
            self.session_options(),
            &plan,
            self.options().backoff,
        )
        .await;
        let mut engines = Engines::default();
        let hooks: Arc<dyn Hooks> = self.conversation_hooks();
        engines.conversations =
            ConversationEngine::new(config, hooks, self.options().clock.clone());
        engines.confirm = crate::sync::confirm::ConfirmEngine::new(self.confirm_service());
        let (replies, replies_rx) = mpsc::unbounded_channel();
        let exec = Arc::new(Exec {
            cx: Context {
                store: self.store().clone(),
                account,
            },
            engines: tokio::sync::Mutex::new(engines),
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            mailboxes: Mutex::new(MailboxSlots::new(plan.anonymous.max(1), PER_CONNECTION)),
            events: self.inner.events.clone(),
            addr: a.server.clone(),
            trust: self.trust(),
            options: self.session_options(),
            guest: a.kind == AccountKind::Guest,
            replies,
        });
        let run = Run {
            store: self.store().clone(),
            account,
            events: self.inner.events.clone(),
            guest,
            exec: exec.clone(),
        };
        let mut tasks = vec![
            tokio::spawn(run.run(events)),
            tokio::spawn(replies_task(exec.clone(), replies_rx)),
            tokio::spawn(ticker(exec.clone(), self.options().clock.clone())),
        ];
        // Task C4: files, transfers and backups.
        tasks.extend(self.spawn_transfer_worker(account, exec.clone()));
        // Task C5: the identity area's upkeep, and groups' devices by key
        // files (4.5, 12.14).
        tasks.push(self.spawn_maintenance(account));
        let this = RunningAccount {
            connections,
            exec,
            tasks,
        };
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
            for task in raced.tasks {
                task.abort();
            }
            raced.connections.stop().await;
        }
        Ok(())
    }

    /// Stops an account's connections. Does nothing if it is not running.
    pub async fn disconnect(&self, account: AccountId) -> Result<()> {
        if let Some(running) = self.running().take(account) {
            running.connections.stop().await;
            for task in running.tasks {
                task.abort();
                let _ = task.await;
            }
        }
        Ok(())
    }

    /// A running account's executor, or [`Error::Internal`] if it is not
    /// connected.
    pub(crate) fn exec(&self, account: AccountId) -> Result<Arc<Exec>> {
        self.running()
            .exec(account)
            .ok_or(Error::Internal("the account is not connected".into()))
    }

    /// Makes a running account's engines send what was just queued. Does
    /// nothing if the account is not running: it is sent once it is.
    pub(crate) async fn kick(&self, account: AccountId) {
        if let Some(exec) = self.running().exec(account) {
            exec.kick().await;
        }
    }
}

/// Gives the engines a tick every second.
async fn ticker(exec: Arc<Exec>, clock: Arc<dyn crate::clock::Clock>) {
    let mut interval = tokio::time::interval(TICK);
    loop {
        interval.tick().await;
        exec.broadcast(&Input::Tick { now: clock.now() }).await;
    }
}

/// Hands replies that did not come from a session's queue to their
/// engines.
async fn replies_task(
    exec: Arc<Exec>,
    mut rx: mpsc::UnboundedReceiver<(EngineId, Slot, Token, Response)>,
) {
    while let Some((id, slot, token, response)) = rx.recv().await {
        exec.reply(id, slot, token, &response).await;
    }
}

/// The task that reads an account's connection events.
struct Run {
    store: Store,
    account: AccountId,
    events: broadcast::Sender<Event>,
    guest: Option<Arc<GuestSession>>,
    exec: Arc<Exec>,
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
                    session,
                    incoming,
                    ..
                } => {
                    self.save_guest_session().await;
                    self.emit(slot, ConnectionState::Ready);
                    self.exec
                        .sessions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(slot, (session, kind));
                    self.exec.broadcast(&Input::Ready { slot, kind }).await;
                    tokio::spawn(read(self.exec.clone(), slot, incoming));
                }
                SupervisorEvent::Disconnected { reason } => {
                    self.exec.closed(slot);
                    self.exec.broadcast(&Input::Closed { slot }).await;
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

/// Reads one connection's lines and replies, in order, and hands each to
/// its engine.
async fn read(exec: Arc<Exec>, slot: Slot, mut incoming: mpsc::Receiver<Incoming>) {
    while let Some(item) = incoming.recv().await {
        match item {
            Incoming::Line(message) => {
                if let risala_proto::server::ServerLine::Notice { message } = &message.line {
                    tracing::info!(?slot, notice = %message, "server notice");
                }
                exec.line(slot, &message).await;
            }
            Incoming::Reply { ref_, response } => {
                let entry = exec
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&(slot, ref_.clone()));
                match entry {
                    Some((id, token)) => exec.reply(id, slot, token, &response).await,
                    None => tracing::debug!(?slot, %ref_, "a reply no engine asked for"),
                }
            }
        }
    }
    // The queue ended: the connection closed.
    exec.closed(slot);
}

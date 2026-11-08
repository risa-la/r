//! [`Account`] and [`Conversation`] handles, and the commands they send to
//! the account's task.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use risala_proto::command::{Command, Request, RoomPage};
use risala_proto::names::{BlockTarget, Conv, Room, Seq, Uid};
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use risala_proto::text::{escape, unescape};
use risala_proto::types::{Presence as WirePresence, Relation};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::driver;
use super::timeline::Timeline;
use super::types::{
    AccountEvent, ClientError, ConnectionState, ConversationInfo, ConversationPage, Message,
    MessagePage, OutboxEntry, RoomList, RoomListing, page_size,
};
use super::typing::Typists;
use super::{Client, ClientOptions, blocking};
use crate::addr::ServerAddr;
use crate::conn::Session;
use crate::store::{AccountId, Change, Draft, OutboxId, Store};

/// How many batches of events an account keeps for slow subscribers
/// before they miss some ([`AccountEvent::Lagged`]).
const EVENT_CAPACITY: usize = 1024;

/// What an account's task produced in one step: the cache's changes, for
/// timelines, and the events for subscribers.
#[derive(Debug, Default)]
pub(crate) struct Batch {
    pub changes: Vec<Change>,
    pub events: Vec<AccountEvent>,
    /// Another process changed the cache: re-read everything shown.
    pub reload: bool,
}

/// Whether the current connection has caught up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Synced {
    /// Counts connections; 0 before the first.
    pub connection: u64,
    /// Signed in, and the sync engine has nothing in flight.
    pub idle: bool,
}

/// What every handle to one account shares.
pub(crate) struct AccountShared {
    pub id: AccountId,
    pub server: ServerAddr,
    pub uid: Uid,
    pub store: Store,
    pub options: ClientOptions,
    pub state: watch::Sender<ConnectionState>,
    pub synced: watch::Sender<Synced>,
    pub events: broadcast::Sender<Arc<Batch>>,
    /// The client's channel for chat lists, which hear of every account.
    pub chats: broadcast::Sender<Arc<Batch>>,
    pub driver: Mutex<Option<DriverHandle>>,
    /// The signed-in session, for commands outside the sync engine.
    pub session: Mutex<Option<Arc<Session>>>,
    /// The client's runtime, where the account's tasks run.
    pub rt: tokio::runtime::Handle,
    /// Who is typing where (8.1), while connected.
    pub typing: Mutex<Typists>,
    /// People's presence as last heard on this connection (8.3).
    pub presence: Mutex<HashMap<Uid, WirePresence>>,
    /// Rooms and users whose presence the app shows, to ask about again
    /// after each reconnect (8.3).
    pub watching: Mutex<Watching>,
    /// Whether the account was running before an UNREGISTER whose answer
    /// was lost (4.8), to start it again if a later try is refused.
    pub ran_before_unregister: Mutex<Option<bool>>,
    /// A [`Client::register`](super::Client::register) for the account's
    /// identity is under way in this client (4.6).
    pub registering: AtomicBool,
    /// The last sign-in said the identity is an operator (`op=yes`).
    pub operator: AtomicBool,
    next_driver: AtomicU64,
}

/// What the app watches the presence of, with how many
/// [`PresenceWatch`](super::people::PresenceWatch)es hold each (8.3).
#[derive(Debug, Default)]
pub(crate) struct Watching {
    pub rooms: HashMap<Room, usize>,
    pub users: HashMap<Uid, usize>,
}

/// An account task, running or stopping.
pub(crate) struct DriverHandle {
    pub generation: u64,
    pub cmds: mpsc::UnboundedSender<Cmd>,
    /// Closes when the task ends: its sender lives in the task.
    pub done: watch::Receiver<()>,
    /// [`Account::disconnect`] asked it to stop. It stays here until it
    /// ends, or until [`Account::start`] puts in its place a task that
    /// waits for it to end.
    pub stopping: bool,
}

impl DriverHandle {
    fn is_finished(&self) -> bool {
        self.done.has_changed().is_err()
    }
}

/// Waits until the task whose `done` this is has ended.
pub(crate) async fn finished(mut done: watch::Receiver<()>) {
    while done.changed().await.is_ok() {}
}

type Reply<T> = oneshot::Sender<Result<T, ClientError>>;

/// A request to an account's task.
pub(crate) enum Cmd {
    Join {
        room: Room,
        reply: Reply<()>,
    },
    Part {
        room: Room,
        reason: String,
        reply: Reply<()>,
    },
    Send {
        conv: Conv,
        draft: Draft,
        reply: Reply<OutboxId>,
    },
    Delete {
        conv: Conv,
        seq: Seq,
        reply: Reply<OutboxId>,
    },
    MarkRead {
        conv: Conv,
        seq: Seq,
        reply: Reply<()>,
    },
    LoadOlder {
        conv: Conv,
        reply: Reply<()>,
    },
    Download {
        conv: Conv,
        reply: Reply<()>,
    },
    Fetch {
        conv: Conv,
        seq: Seq,
        reply: Reply<()>,
    },
    /// The user is typing, or stopped (8.1). Nothing to answer.
    Typing {
        conv: Conv,
        active: bool,
    },
    /// A command about people (5.7, 8.2, 8.3), answered with its response
    /// lines once it succeeds.
    People {
        op: PeopleOp,
        reply: Reply<Vec<ServerMessage>>,
    },
    /// Any other command, answered with its response lines and its OK
    /// once it succeeds.
    Request {
        op: RequestOp,
        reply: Reply<Answer>,
    },
    Reconnect,
    /// Send what the outbox holds that can go now, such as entries another
    /// process sharing the cache queued. Nothing to answer.
    ResumeOutbox,
    /// An encryption operation (12), answered once the engine has taken
    /// it.
    E2ee {
        op: E2eeOp,
        reply: Reply<()>,
    },
    Stop {
        reply: oneshot::Sender<()>,
    },
}

/// An encryption operation of the sync engine (12).
#[derive(Debug, Clone)]
pub(crate) enum E2eeOp {
    /// Make a room encrypted (12.3, 12.5).
    EncryptRoom {
        room: Room,
        history: risala_proto::types::HistoryMode,
        send: risala_proto::types::SendMode,
    },
    /// Invite to a room: by commit if it is encrypted (6.4, 12.6).
    Invite { room: Room, uid: Uid },
    /// The user confirmed, or not, a new device of the identity (12.9).
    ConfirmDevice {
        key: risala_proto::auth::PublicKey,
        confirmed: bool,
    },
    /// The identity's recovery key, to back up under (12.10).
    SetRecovery(Option<risala_mls::RecoveryKey>),
    /// Send the recovery key to the identity's other devices (12.10).
    ShareRecovery(risala_mls::RecoveryKey),
    /// An identity's key file, fetched now (12.12): `None` if the fetch
    /// failed.
    KeyFile(Uid, Option<Vec<super::e2ee::KeyFileEntry>>),
}

/// A command about people, sent through the sync engine so that its reply
/// is handled in order with the lines around it.
#[derive(Debug, Clone)]
pub(crate) enum PeopleOp {
    Name(String),
    Members(Room),
    Whois(Uid),
    Block(BlockTarget),
    Unblock(BlockTarget),
    Blocks,
}

/// A command sent through the sync engine for the app, so that the events
/// it causes are handled before its answer (5.2, 3.6).
#[derive(Debug, Clone)]
pub(crate) enum RequestOp {
    /// INFO of a room (6.2), which the engine also checks the id of.
    Info(Room),
    /// A command the engine keeps nothing from.
    Plain(Command),
}

/// A command's response lines and its OK (3.6).
#[derive(Debug, Clone)]
pub(crate) struct Answer {
    pub lines: Vec<ServerMessage>,
    pub ok: OkResponse,
}

impl AccountShared {
    pub fn new(
        id: AccountId,
        server: ServerAddr,
        uid: Uid,
        store: Store,
        options: ClientOptions,
        rt: tokio::runtime::Handle,
        chats: broadcast::Sender<Arc<Batch>>,
    ) -> Arc<AccountShared> {
        Arc::new(AccountShared {
            id,
            server,
            uid,
            store,
            options,
            state: watch::channel(ConnectionState::Offline).0,
            synced: watch::channel(Synced::default()).0,
            events: broadcast::channel(EVENT_CAPACITY).0,
            chats,
            driver: Mutex::new(None),
            session: Mutex::new(None),
            rt,
            typing: Mutex::new(Typists::default()),
            presence: Mutex::new(HashMap::new()),
            watching: Mutex::new(Watching::default()),
            ran_before_unregister: Mutex::new(None),
            registering: AtomicBool::new(false),
            operator: AtomicBool::new(false),
            next_driver: AtomicU64::new(1),
        })
    }

    /// Changes the state, and tells subscribers.
    pub fn set_state(&self, state: ConnectionState) {
        let changed = self.state.send_if_modified(|s| {
            if *s == state {
                false
            } else {
                *s = state.clone();
                true
            }
        });
        if changed {
            self.publish(Batch {
                reload: false,
                changes: Vec::new(),
                events: vec![AccountEvent::State { state }],
            });
        }
    }

    pub fn publish(&self, batch: Batch) {
        if !batch.changes.is_empty() || !batch.events.is_empty() || batch.reload {
            let batch = Arc::new(batch);
            // No receivers is fine. A reload reaches chat lists from the
            // client instead, once for every account: chat lists are not
            // tied to the accounts it has handles for.
            if !batch.changes.is_empty() {
                let _ = self.chats.send(batch.clone());
            }
            let _ = self.events.send(batch);
        }
    }

    pub fn is_guest(&self) -> bool {
        self.uid.is_guest()
    }

    /// Whether the account's task is running, and not stopping.
    pub fn is_running(&self) -> bool {
        self.driver_queue().is_some()
    }

    /// The running task's command queue, if a task is running and not
    /// stopping.
    fn driver_queue(&self) -> Option<mpsc::UnboundedSender<Cmd>> {
        let driver = self.driver.lock().expect("poisoned");
        driver
            .as_ref()
            .filter(|d| !d.stopping && !d.is_finished())
            .map(|d| d.cmds.clone())
    }

    /// Asks the running task, if any, to send what the outbox holds that
    /// can go now.
    pub(crate) fn resume_outbox(&self) {
        if let Some(queue) = self.driver_queue() {
            let _ = queue.send(Cmd::ResumeOutbox);
        }
    }

    /// Runs `f` if the task of `generation` is the account's current one,
    /// and says whether it was. The slot stays locked meanwhile, so that
    /// [`Account::start`] cannot put a new task in between: a task that
    /// was replaced never touches the session, the state or `synced`.
    /// `f` must not lock the slot.
    pub(crate) fn if_current(&self, generation: u64, f: impl FnOnce()) -> bool {
        let driver = self.driver.lock().expect("poisoned");
        let current = driver.as_ref().is_some_and(|d| d.generation == generation);
        if current {
            f();
        }
        current
    }

    /// Changes the state, if the task of `generation` is the current one.
    pub(crate) fn set_state_for(&self, generation: u64, state: ConnectionState) {
        self.if_current(generation, || self.set_state(state));
    }

    /// Whether the task of `generation` is the current one, and was asked
    /// to stop.
    pub(crate) fn is_stopping(&self, generation: u64) -> bool {
        let driver = self.driver.lock().expect("poisoned");
        driver
            .as_ref()
            .is_some_and(|d| d.generation == generation && d.stopping)
    }

    /// Ends the turn of the task of `generation`, if it is the current
    /// one: it leaves the slot, and the session goes. If it was asked to
    /// stop, or `stopped`, the account goes offline. Returns whether it
    /// was current.
    pub(crate) fn retire(&self, generation: u64, stopped: bool) -> bool {
        let mut driver = self.driver.lock().expect("poisoned");
        let Some(d) = driver.as_ref().filter(|d| d.generation == generation) else {
            return false;
        };
        let stopped = stopped || d.stopping;
        *driver = None;
        *self.session.lock().expect("poisoned") = None;
        self.synced.send_modify(|s| s.idle = false);
        if stopped {
            self.set_state(ConnectionState::Offline);
        }
        true
    }

    /// Hands a command to the task, or handles it offline if none runs.
    pub(crate) fn command(self: &Arc<Self>, cmd: Cmd) {
        let cmd = match self.driver_queue() {
            Some(queue) => match queue.send(cmd) {
                Ok(()) => return,
                Err(mpsc::error::SendError(cmd)) => cmd,
            },
            None => cmd,
        };
        let shared = self.clone();
        self.rt
            .spawn(async move { driver::offline(&shared, cmd).await });
    }
}

/// An account: a uid on a server (4.2, 4.3). See the [module
/// docs](super).
///
/// Cloning it is cheap; every handle to the same account shares one
/// connection.
#[derive(Clone)]
pub struct Account {
    client: Client,
    shared: Arc<AccountShared>,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("server", &self.shared.server)
            .field("uid", &self.shared.uid)
            .finish_non_exhaustive()
    }
}

impl Account {
    pub(crate) fn new(client: Client, shared: Arc<AccountShared>) -> Account {
        Account { client, shared }
    }

    pub(crate) fn shared(&self) -> &Arc<AccountShared> {
        &self.shared
    }

    /// The account's row in the cache.
    pub fn id(&self) -> AccountId {
        self.shared.id
    }

    /// The server address.
    pub fn server(&self) -> String {
        self.shared.server.to_string()
    }

    /// The account's uid, such as `~sam` or `alice@example.org`. A guest
    /// may sign in under a numbered name; see [`ConnectionState::Online`].
    pub fn uid(&self) -> String {
        self.shared.uid.to_string()
    }

    /// Whether the identity is an operator of the server (10.1), as the
    /// last sign-in said with `op=yes` (4.5): one that may use
    /// [`Account::admin`]. `false` before the first sign-in, and for
    /// guests. Operators added or removed while signed in show at the next
    /// sign-in.
    pub fn is_operator(&self) -> bool {
        self.shared.operator.load(Ordering::SeqCst)
    }

    /// Whether this is a guest account (4.2).
    pub fn is_guest(&self) -> bool {
        self.shared.is_guest()
    }

    /// The client it belongs to.
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Where the connection is.
    pub fn state(&self) -> ConnectionState {
        self.shared.state.borrow().clone()
    }

    /// Whether the account is running: started, and not stopped or
    /// failed for good.
    pub(crate) fn is_running(&self) -> bool {
        self.shared.is_running()
    }

    /// The signed-in session, for commands outside the sync engine.
    pub(crate) fn session(&self) -> Result<Arc<Session>, ClientError> {
        self.shared
            .session
            .lock()
            .expect("poisoned")
            .clone()
            .ok_or(ClientError::NotConnected)
    }

    /// Starts keeping a connection up in the background, signing in and
    /// syncing on each one. Does nothing if it is already running. It runs
    /// on the client's runtime, so this may be called from any thread.
    ///
    /// Called while a [`disconnect`](Self::disconnect) is under way, it
    /// starts a new task that waits for the old one to end before it
    /// connects, so that the two never overlap.
    pub fn start(&self) {
        let mut driver = self.shared.driver.lock().expect("poisoned");
        let previous = match driver.as_ref() {
            Some(d) if d.is_finished() => None,
            Some(d) if d.stopping => Some(d.done.clone()),
            Some(_) => return,
            None => None,
        };
        if previous.is_some() {
            // The stopping task's session is going; it no longer touches
            // these once replaced.
            *self.shared.session.lock().expect("poisoned") = None;
            self.shared.synced.send_modify(|s| s.idle = false);
        }
        let generation = self.shared.next_driver.fetch_add(1, Ordering::SeqCst);
        let (cmds, rx) = mpsc::unbounded_channel();
        let (done_tx, done) = watch::channel(());
        // Before the task runs, so that a stale Failed is not read as the
        // outcome of this start.
        self.shared
            .set_state(ConnectionState::Connecting { attempt: 0 });
        self.shared.rt.spawn(driver::run(
            self.shared.clone(),
            generation,
            rx,
            previous,
            done_tx,
        ));
        *driver = Some(DriverHandle {
            generation,
            cmds,
            done,
            stopping: false,
        });
    }

    /// Starts the account if needed, and waits until it has signed in.
    /// Returns the uid it signed in as.
    ///
    /// It fails with the error of the first attempt that fails, such as
    /// [`ClientError::UnknownCertificate`] (2.2), `auth-failed` (4.5) or
    /// a refused connection. What happens next follows from
    /// [`ClientError::is_permanent`], and from nothing else:
    ///
    /// - **Permanent:** the account has stopped, in
    ///   [`ConnectionState::Failed`] with this error. Show it, let the user
    ///   act (accept a certificate, publish a key), then call `connect` or
    ///   [`start`](Self::start) again.
    /// - **Not permanent**, such as a network failure, `unavailable` or
    ///   `rate-limited`: the account is in [`ConnectionState::Waiting`],
    ///   and tries again in the background on its own. Show the error as
    ///   passing, and follow [`state`](Self::state) or
    ///   [`subscribe`](Self::subscribe) for what comes next, or call
    ///   [`wait_synced`](Self::wait_synced). [`disconnect`](Self::disconnect)
    ///   stops it.
    ///
    /// [`ClientError::NotConnected`] means the account was stopped while
    /// this waited.
    pub async fn connect(&self) -> Result<String, ClientError> {
        let mut state = self.shared.state.subscribe();
        self.start();
        loop {
            match &*state.borrow_and_update() {
                ConnectionState::Online { uid } => return Ok(uid.clone()),
                ConnectionState::Failed { error } => return Err(error.clone()),
                ConnectionState::Waiting {
                    error: Some(error), ..
                } => return Err(error.clone()),
                ConnectionState::Offline => return Err(ClientError::NotConnected),
                _ => {}
            }
            if state.changed().await.is_err() {
                return Err(ClientError::NotConnected);
            }
        }
    }

    /// Asks the server to close the connection (QUIT, 11), and stops.
    /// The account goes offline; reads still work from the cache.
    ///
    /// The task is marked as stopping until it has ended. A
    /// [`start`](Self::start) or [`connect`](Self::connect) meanwhile
    /// starts a new task, which connects once the old one has ended; the
    /// account then stays with the new task, and does not go offline.
    pub async fn disconnect(&self) {
        let (generation, done) = {
            let mut driver = self.shared.driver.lock().expect("poisoned");
            let Some(d) = driver.as_mut() else {
                return;
            };
            if !d.stopping {
                d.stopping = true;
                // What counts is that the task ends, so its answer is not
                // awaited.
                let (reply, _) = oneshot::channel();
                let _ = d.cmds.send(Cmd::Stop { reply });
            }
            (d.generation, d.done.clone())
        };
        finished(done).await;
        // The task leaves its slot and goes offline as it ends, unless a
        // newer one took its place. This covers one that ended otherwise,
        // such as by a panic.
        self.shared.retire(generation, true);
    }

    /// Skips the wait before the next attempt, or replaces the current
    /// connection, for example when the network comes back.
    pub fn reconnect_now(&self) {
        if let Some(queue) = self.shared.driver_queue() {
            let _ = queue.send(Cmd::Reconnect);
        }
    }

    /// Reports what happens to the account from now on.
    pub fn subscribe(&self) -> AccountEvents {
        AccountEvents {
            rx: tokio::sync::Mutex::new((self.shared.events.subscribe(), VecDeque::new())),
        }
    }

    /// Whether the account is signed in and has caught up: the sync engine
    /// has nothing in flight, commands or key files being fetched. See
    /// [`wait_synced`](Self::wait_synced).
    pub fn is_synced(&self) -> bool {
        self.state().is_online() && self.shared.synced.borrow().idle
    }

    /// Waits until the account is signed in and has caught up: the sync
    /// engine has nothing in flight, commands or key files being fetched
    /// (12.12). Fails if the account stops, or fails
    /// for good.
    pub async fn wait_synced(&self) -> Result<(), ClientError> {
        let mut synced = self.shared.synced.subscribe();
        let mut state = self.shared.state.subscribe();
        loop {
            match &*state.borrow_and_update() {
                ConnectionState::Failed { error } => return Err(error.clone()),
                ConnectionState::Offline => return Err(ClientError::NotConnected),
                _ => {}
            }
            if synced.borrow_and_update().idle {
                return Ok(());
            }
            tokio::select! {
                r = synced.changed() => r.map_err(|_| ClientError::NotConnected)?,
                r = state.changed() => r.map_err(|_| ClientError::NotConnected)?,
            }
        }
    }

    /// Sends `command` in order with the sync engine's, and waits for its
    /// answer. The command is checked first: one that cannot be sent as
    /// it is fails with [`ClientError::Invalid`]. Needs a connection.
    pub(crate) async fn request(&self, command: Command) -> Result<Answer, ClientError> {
        Request::new(command.clone())
            .validate()
            .map_err(|e| ClientError::Invalid(format!("{}: {e}", command.verb())))?;
        self.request_op(RequestOp::Plain(command)).await
    }

    pub(crate) async fn request_op(&self, op: RequestOp) -> Result<Answer, ClientError> {
        let (reply, rx) = oneshot::channel();
        self.shared.command(Cmd::Request { op, reply });
        wait(rx).await
    }

    /// One page of the account's conversations from the cache, in byte
    /// order of name. Pass `None` for the first page, then the page's
    /// [`next`](ConversationPage::next) cursor. `limit` is capped at
    /// [`MAX_PAGE`](super::types::MAX_PAGE); 0 asks for
    /// [`DEFAULT_PAGE`](super::types::DEFAULT_PAGE). It needs no
    /// connection.
    pub fn conversations(
        &self,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<ConversationPage, ClientError> {
        let after = match cursor.as_deref() {
            None => None,
            Some(c) => Some(
                c.strip_prefix("c:")
                    .and_then(|name| name.parse::<Conv>().ok())
                    .ok_or_else(|| ClientError::Invalid(format!("cursor {c:?}")))?,
            ),
        };
        let limit = page_size(limit) as usize;
        let mut page =
            self.shared
                .store
                .conversations_page(self.shared.id, after.as_ref(), limit + 1)?;
        let more = page.len() > limit;
        page.truncate(limit);
        let next = more
            .then(|| page.last().map(|c| format!("c:{}", c.name)))
            .flatten();
        Ok(ConversationPage {
            conversations: page.into_iter().map(ConversationInfo::from).collect(),
            next,
        })
    }

    /// A conversation by name: a room such as `#general`, or the other
    /// person's uid (5.1). It need not be in the cache yet.
    pub fn conversation(&self, name: &str) -> Result<Conversation, ClientError> {
        let conv: Conv = name
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("conversation {name:?}")))?;
        Ok(Conversation {
            account: self.clone(),
            conv,
        })
    }

    /// Joins a room (6.1), and returns it once the server has answered.
    /// Its history then catches up in the background. For a guest, the
    /// room is joined again after each reconnect (see the [module
    /// docs](super)).
    pub async fn join(&self, room: &str) -> Result<Conversation, ClientError> {
        let room = parse_room(room)?;
        let (reply, rx) = oneshot::channel();
        self.shared.command(Cmd::Join {
            room: room.clone(),
            reply,
        });
        wait(rx).await?;
        Ok(Conversation {
            account: self.clone(),
            conv: Conv::Room(room),
        })
    }

    /// Leaves a room (6.1). Its history stays in the cache. A guest that
    /// is offline is in no room, so for one this only stops the room
    /// being joined again.
    pub async fn part(&self, room: &str, reason: &str) -> Result<(), ClientError> {
        let room = parse_room(room)?;
        let (reply, rx) = oneshot::channel();
        self.shared.command(Cmd::Part {
            room,
            reason: escape(reason),
            reply,
        });
        wait(rx).await
    }

    /// One page of the server's public rooms (6.1), in byte order of name,
    /// after the room `after` if given. Needs a connection.
    pub async fn list_rooms(
        &self,
        after: Option<String>,
        limit: Option<u64>,
    ) -> Result<RoomList, ClientError> {
        let after = after.map(|a| parse_room(&a)).transpose()?;
        let session = self.session()?;
        let command = Command::List(RoomPage {
            after,
            limit: limit.and_then(NonZeroU64::new),
        });
        let server = self.server();
        let response = session
            .request(command)
            .await
            .map_err(|e| ClientError::from_conn(&server, &e))?;
        let (lines, ok) = response
            .into_result()
            .map_err(|e| ClientError::from_conn(&server, &e.into()))?;
        let rooms = lines
            .into_iter()
            .filter_map(|m| match m.line {
                ServerLine::Room {
                    room,
                    members,
                    topic,
                } => Some(RoomListing {
                    room: room.to_string(),
                    members,
                    topic: unescape(&topic).into_owned(),
                }),
                _ => None,
            })
            .collect();
        Ok(RoomList {
            rooms,
            more: ok.more().ok().flatten().unwrap_or(false),
        })
    }

    /// Every outbox entry of the account, oldest first.
    pub fn outbox(&self) -> Result<Vec<OutboxEntry>, ClientError> {
        Ok(self
            .shared
            .store
            .outbox(self.shared.id)?
            .into_iter()
            .map(OutboxEntry::from)
            .collect())
    }

    /// Removes an outbox entry, for example a failed one the user
    /// dismissed.
    pub fn remove_outbox(&self, id: i64) -> Result<(), ClientError> {
        let entry = self.outbox_entry(id)?;
        let changes = self.shared.store.remove_outbox(OutboxId(entry.id))?;
        driver::publish_changes(&self.shared, changes);
        Ok(())
    }

    /// Sends a failed outbox entry again, for example when the user taps
    /// "retry" (7.6). It goes back in the queue in its place, with its id
    /// and its cid, so a [`Timeline`] shows it as queued again where it
    /// was, and it goes out as soon as it can, after the conversation's
    /// messages before it: one message is in flight per conversation at a
    /// time (PLAN.md 5, item 41). A message that failed as
    /// [`FailKind::Unconfirmed`](super::FailKind::Unconfirmed) may have
    /// been posted already: within 24 hours of its first sending, an
    /// identity's server sees the same cid and does not post it twice;
    /// after that, or for a guest whose session ended, it may (7.6). If
    /// what made it fail still holds, such as the account having left the
    /// room, it fails again. Fails with [`ClientError::Invalid`] for an
    /// entry of another account, or one that has not failed.
    pub fn retry_outbox(&self, id: i64) -> Result<(), ClientError> {
        let entry = self.outbox_entry(id)?;
        let (retried, changes) = self.shared.store.retry_outbox(OutboxId(entry.id))?;
        if !retried {
            return Err(ClientError::Invalid(format!(
                "outbox entry {id} has not failed"
            )));
        }
        driver::publish_changes(&self.shared, changes);
        self.shared.resume_outbox();
        Ok(())
    }

    fn outbox_entry(&self, id: i64) -> Result<OutboxEntry, ClientError> {
        match self.shared.store.outbox_item(OutboxId(id))? {
            Some(item) if item.account == self.shared.id => Ok(item.into()),
            _ => Err(ClientError::Invalid(format!("outbox entry {id}"))),
        }
    }

    /// Waits until an outbox entry is sent or has failed, and returns it.
    /// An identity's message that was sending when the connection dropped
    /// is sent again after reconnecting (7.6), so this can take a while;
    /// add a timeout.
    pub async fn wait_outbox(&self, id: i64) -> Result<OutboxEntry, ClientError> {
        let events = self.subscribe();
        loop {
            let account = self.clone();
            let rt = account.shared.rt.clone();
            let entry = blocking(&rt, move || account.outbox_entry(id)).await?;
            if entry.status.is_final() {
                return Ok(entry);
            }
            loop {
                match events.next().await {
                    Some(AccountEvent::Outbox { entry }) if entry.id == id => break,
                    Some(AccountEvent::OutboxRemoved { id: gone }) if gone == id => break,
                    Some(AccountEvent::Lagged | AccountEvent::CacheChanged) => break,
                    Some(_) => {}
                    None => return Err(ClientError::NotConnected),
                }
            }
        }
    }
}

/// The events of one account, from [`Account::subscribe`].
pub struct AccountEvents {
    rx: tokio::sync::Mutex<(broadcast::Receiver<Arc<Batch>>, VecDeque<AccountEvent>)>,
}

impl std::fmt::Debug for AccountEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountEvents").finish_non_exhaustive()
    }
}

impl AccountEvents {
    /// The next event. `None` once the account has been removed.
    pub async fn next(&self) -> Option<AccountEvent> {
        let mut guard = self.rx.lock().await;
        let (rx, queue) = &mut *guard;
        loop {
            if let Some(event) = queue.pop_front() {
                return Some(event);
            }
            match rx.recv().await {
                Ok(batch) => queue.extend(batch.events.iter().cloned()),
                Err(broadcast::error::RecvError::Lagged(_)) => return Some(AccountEvent::Lagged),
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// A conversation of an account: a room or a direct conversation (5.1).
///
/// Reads come from the cache and work offline. Sends go through the
/// outbox (7.6).
#[derive(Clone)]
pub struct Conversation {
    account: Account,
    conv: Conv,
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("account", &self.account)
            .field("conv", &self.conv)
            .finish()
    }
}

impl Conversation {
    /// Its name: a room, or the other person.
    pub fn name(&self) -> String {
        self.conv.to_string()
    }

    /// The account it belongs to.
    pub fn account(&self) -> Account {
        self.account.clone()
    }

    pub(crate) fn conv(&self) -> &Conv {
        &self.conv
    }

    fn store(&self) -> &Store {
        &self.account.shared.store
    }

    /// Marks it as a favourite, or not, for the chat list's favourites
    /// toggle ([`ChatFilter::favourites`](super::ChatFilter::favourites)).
    /// Favourites are kept on this device only: the spec has nowhere to
    /// keep them. Fails with [`ClientError::NotJoined`] for a conversation
    /// that is not in the cache.
    pub fn set_favourite(&self, favourite: bool) -> Result<(), ClientError> {
        let shared = self.account.shared();
        let Some(conv) = shared.store.conversation_id(shared.id, &self.conv)? else {
            return Err(ClientError::NotJoined(self.conv.to_string()));
        };
        let changes = shared.store.set_favourite(conv, favourite)?;
        driver::publish_changes(shared, changes);
        Ok(())
    }

    /// Its summary from the cache, if it is there.
    pub fn info(&self) -> Result<Option<ConversationInfo>, ClientError> {
        Ok(self
            .store()
            .conversation(self.account.shared.id, &self.conv)?
            .map(ConversationInfo::from))
    }

    /// One page of messages from the cache, oldest first: the newest for
    /// `None`, then older ones for the page's
    /// [`older`](MessagePage::older) cursor. `limit` is capped at
    /// [`MAX_PAGE`](super::types::MAX_PAGE); 0 asks for
    /// [`DEFAULT_PAGE`](super::types::DEFAULT_PAGE). It needs no
    /// connection; for older history from the server, see
    /// [`load_older`](Self::load_older).
    pub fn messages(&self, cursor: Option<String>, limit: u32) -> Result<MessagePage, ClientError> {
        let before = match cursor.as_deref() {
            None => None,
            Some(c) => Some(
                c.strip_prefix("m:")
                    .and_then(|n| n.parse::<u64>().ok())
                    .and_then(Seq::new)
                    .ok_or_else(|| ClientError::Invalid(format!("cursor {c:?}")))?,
            ),
        };
        let Some(summary) = self
            .store()
            .conversation(self.account.shared.id, &self.conv)?
        else {
            return Ok(MessagePage {
                messages: Vec::new(),
                older: None,
            });
        };
        let limit = page_size(limit) as usize;
        let mut items = self.store().timeline(summary.id, before, limit + 1)?;
        let more = items.len() > limit;
        if more {
            items.remove(0);
        }
        let older = more
            .then(|| items.first().map(|i| format!("m:{}", i.seq)))
            .flatten();
        Ok(MessagePage {
            messages: items.into_iter().map(Message::from).collect(),
            older,
        })
    }

    /// Every stored event, oldest first, as lines in canonical form: a
    /// copy for reading offline (7.1). Call [`download`](Self::download)
    /// first to make it complete.
    pub fn export(&self) -> Result<Vec<String>, ClientError> {
        let Some(summary) = self
            .store()
            .conversation(self.account.shared.id, &self.conv)?
        else {
            return Ok(Vec::new());
        };
        Ok(self.store().export(summary.id)?)
    }

    /// The conversation's outbox entries, oldest first.
    pub fn outbox(&self) -> Result<Vec<OutboxEntry>, ClientError> {
        Ok(self
            .store()
            .outbox_for(self.account.shared.id, &self.conv)?
            .into_iter()
            .map(OutboxEntry::from)
            .collect())
    }

    /// A timeline of the newest `limit` messages in the cache, which then
    /// follows every change. See [`Timeline`]. `limit` is bounded as for
    /// [`messages`](Self::messages).
    pub fn timeline(&self, limit: u32) -> Result<Timeline, ClientError> {
        Timeline::new(self.clone(), limit)
    }

    /// Sends a message (5.3), through the outbox (7.6). It goes out as soon
    /// as the account is in the room on a connection, perhaps at once.
    /// Follow it with [`Account::wait_outbox`] or [`Account::subscribe`].
    ///
    /// `text` is plain; it is escaped here (3.4). Fails with
    /// [`ClientError::NotJoined`] for a room that has never been joined, or
    /// that the account has left, or was kicked or banned from. A message
    /// still queued when the account learns it has left fails with
    /// [`FailKind::NotInRoom`](super::FailKind::NotInRoom). The exception
    /// is a guest's room that went missing because its session ended:
    /// messages wait, since the client joins it again after a reconnect
    /// (4.2).
    pub async fn send(&self, text: &str) -> Result<OutboxEntry, ClientError> {
        self.send_draft(Draft::text(escape(text))).await
    }

    /// Sends a reply to message `to` (5.3).
    pub async fn reply(&self, to: u64, text: &str) -> Result<OutboxEntry, ClientError> {
        self.send_related(Relation::Reply, to, text).await
    }

    /// Replaces the text of the account's message `seq` (5.3).
    pub async fn edit(&self, seq: u64, text: &str) -> Result<OutboxEntry, ClientError> {
        self.send_related(Relation::Edit, seq, text).await
    }

    /// Reacts to message `to`, usually with an emoji (5.3).
    pub async fn react(&self, to: u64, reaction: &str) -> Result<OutboxEntry, ClientError> {
        self.send_related(Relation::React, to, reaction).await
    }

    async fn send_related(
        &self,
        relation: fn(Seq) -> Relation,
        seq: u64,
        text: &str,
    ) -> Result<OutboxEntry, ClientError> {
        let seq = Seq::new(seq).ok_or_else(|| ClientError::Invalid("seq 0".into()))?;
        self.send_draft(Draft {
            text: escape(text),
            relation: Some(relation(seq)),
            file: None,
        })
        .await
    }

    async fn send_draft(&self, draft: Draft) -> Result<OutboxEntry, ClientError> {
        let (reply, rx) = oneshot::channel();
        self.account.shared.command(Cmd::Send {
            conv: self.conv.clone(),
            draft,
            reply,
        });
        self.queued(rx).await
    }

    /// Deletes message `seq` (5.4), through the outbox like a message
    /// (7.6), so that a deletion asked for offline goes out on the next
    /// connection. Follow it with [`Account::wait_outbox`]; the entry has
    /// [`OutboxEntry::deletes`] set, and timelines do not show it. Once the
    /// server records the DELETE event, the message shows as deleted.
    ///
    /// The author may delete their own messages, and in rooms moderators
    /// and owners anyone's. An author may delete their own messages in a
    /// room they have left, too. The entry carries the room's id, so that
    /// nothing is deleted in a room created again under the same name.
    /// Fails with [`ClientError::NotJoined`] for a
    /// conversation the cache has no id for, since there is no message to
    /// name. A message deleted already, by this DELETE sent before a
    /// dropped connection or by someone else, ends the entry as
    /// [`OutboxStatus::Sent`](super::types::OutboxStatus::Sent) with the
    /// seq of the DELETE that deleted it (5.4).
    pub async fn delete(&self, seq: u64) -> Result<OutboxEntry, ClientError> {
        let seq = Seq::new(seq).ok_or_else(|| ClientError::Invalid("seq 0".into()))?;
        let (reply, rx) = oneshot::channel();
        self.account.shared.command(Cmd::Delete {
            conv: self.conv.clone(),
            seq,
            reply,
        });
        self.queued(rx).await
    }

    /// The outbox entry a send queued, once it is queued.
    async fn queued(
        &self,
        rx: oneshot::Receiver<Result<OutboxId, ClientError>>,
    ) -> Result<OutboxEntry, ClientError> {
        let id = wait(rx).await?;
        let account = self.account.clone();
        let rt = account.shared.rt.clone();
        blocking(&rt, move || account.outbox_entry(id.get())).await
    }

    /// Moves the read marker forward to `seq` (7.4): in the cache, and on
    /// the server for an identity that is online.
    pub async fn mark_read(&self, seq: u64) -> Result<(), ClientError> {
        let seq = Seq::new(seq).ok_or_else(|| ClientError::Invalid("seq 0".into()))?;
        let (reply, rx) = oneshot::channel();
        self.account.shared.command(Cmd::MarkRead {
            conv: self.conv.clone(),
            seq,
            reply,
        });
        wait(rx).await
    }

    /// Asks the server for the page of history below the newest stored
    /// run of messages, when the cache has a gap there (7.1 step 4, 7.3).
    /// What arrives shows up in timelines. Needs a connection.
    pub async fn load_older(&self) -> Result<(), ClientError> {
        let (reply, rx) = oneshot::channel();
        self.account.shared.command(Cmd::LoadOlder {
            conv: self.conv.clone(),
            reply,
        });
        wait(rx).await
    }

    /// Fetches one message the cache does not have, such as the target of
    /// a reply, with its edits and reactions (7.3). Needs a connection.
    pub async fn fetch(&self, seq: u64) -> Result<(), ClientError> {
        let seq = Seq::new(seq).ok_or_else(|| ClientError::Invalid("seq 0".into()))?;
        let (reply, rx) = oneshot::channel();
        self.account.shared.command(Cmd::Fetch {
            conv: self.conv.clone(),
            seq,
            reply,
        });
        wait(rx).await
    }

    /// Downloads the whole history the server keeps, across any gap, for
    /// reading offline (7.1). It runs in the background; when
    /// [`Account::wait_synced`] returns, it is done. Needs a connection.
    pub async fn download(&self) -> Result<(), ClientError> {
        let (reply, rx) = oneshot::channel();
        self.account.shared.command(Cmd::Download {
            conv: self.conv.clone(),
            reply,
        });
        wait(rx).await
    }
}

pub(crate) async fn wait<T>(
    rx: oneshot::Receiver<Result<T, ClientError>>,
) -> Result<T, ClientError> {
    rx.await.unwrap_or(Err(ClientError::NotConnected))
}

pub(crate) fn parse_room(room: &str) -> Result<Room, ClientError> {
    room.trim()
        .parse()
        .map_err(|_| ClientError::Invalid(format!("room {room:?}")))
}

/// Checks that a message can be sent (5.3), as the sync engine does.
pub(crate) fn check_draft(conv: &Conv, draft: &Draft) -> Result<(), ClientError> {
    Request::new(Command::Msg {
        conv: conv.clone(),
        text: draft.text.clone(),
        relation: draft.relation,
        file: draft.file.clone(),
        cid: None,
        id: None,
    })
    .validate()
    .map_err(|e| ClientError::Invalid(format!("message: {e}")))
}

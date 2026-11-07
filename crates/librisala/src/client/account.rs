//! [`Account`] and [`Conversation`] handles, and the commands they send to
//! the account's task.

use std::collections::VecDeque;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use risala_proto::command::{Command, Request, RoomPage};
use risala_proto::names::{Conv, Room, Seq, Uid};
use risala_proto::server::ServerLine;
use risala_proto::text::{escape, unescape};
use risala_proto::types::Relation;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::driver;
use super::timeline::Timeline;
use super::types::{
    AccountEvent, ClientError, ConnectionState, ConversationInfo, Message, OutboxEntry, RoomList,
    RoomListing,
};
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
    pub driver: Mutex<Option<DriverHandle>>,
    /// The signed-in session, for commands outside the sync engine.
    pub session: Mutex<Option<Arc<Session>>>,
    next_driver: AtomicU64,
}

/// A running account task.
pub(crate) struct DriverHandle {
    pub generation: u64,
    pub cmds: mpsc::UnboundedSender<Cmd>,
    pub task: tokio::task::JoinHandle<()>,
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
    Reconnect,
    Stop {
        reply: oneshot::Sender<()>,
    },
}

impl AccountShared {
    pub fn new(
        id: AccountId,
        server: ServerAddr,
        uid: Uid,
        store: Store,
        options: ClientOptions,
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
            driver: Mutex::new(None),
            session: Mutex::new(None),
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
                changes: Vec::new(),
                events: vec![AccountEvent::State { state }],
            });
        }
    }

    pub fn publish(&self, batch: Batch) {
        if !batch.changes.is_empty() || !batch.events.is_empty() {
            // No receivers is fine.
            let _ = self.events.send(Arc::new(batch));
        }
    }

    pub fn is_guest(&self) -> bool {
        self.uid.is_guest()
    }

    /// The running task's command queue, if a task is running.
    fn driver_queue(&self) -> Option<mpsc::UnboundedSender<Cmd>> {
        let driver = self.driver.lock().expect("poisoned");
        driver
            .as_ref()
            .filter(|d| !d.task.is_finished())
            .map(|d| d.cmds.clone())
    }

    /// Hands a command to the task, or handles it offline if none runs.
    fn command(self: &Arc<Self>, cmd: Cmd) {
        let cmd = match self.driver_queue() {
            Some(queue) => match queue.send(cmd) {
                Ok(()) => return,
                Err(mpsc::error::SendError(cmd)) => cmd,
            },
            None => cmd,
        };
        let shared = self.clone();
        tokio::spawn(async move { driver::offline(&shared, cmd).await });
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

    /// Starts keeping a connection up in the background, signing in and
    /// syncing on each one. Does nothing if it is already running. Needs a
    /// tokio runtime.
    pub fn start(&self) {
        let mut driver = self.shared.driver.lock().expect("poisoned");
        if driver.as_ref().is_some_and(|d| !d.task.is_finished()) {
            return;
        }
        let generation = self.shared.next_driver.fetch_add(1, Ordering::SeqCst);
        let (cmds, rx) = mpsc::unbounded_channel();
        // Before the task runs, so that a stale Failed is not read as the
        // outcome of this start.
        self.shared
            .set_state(ConnectionState::Connecting { attempt: 0 });
        let task = tokio::spawn(driver::run(self.shared.clone(), generation, rx));
        *driver = Some(DriverHandle {
            generation,
            cmds,
            task,
        });
    }

    /// Starts the account if needed, and waits until it has signed in.
    /// Returns the uid it signed in as.
    ///
    /// It fails with the error of the first attempt that fails, such as
    /// [`ClientError::UnknownCertificate`] (2.2) or a refused connection.
    /// The account goes on trying in the background unless the error is
    /// permanent; [`disconnect`](Self::disconnect) stops it.
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
    pub async fn disconnect(&self) {
        let driver = self.shared.driver.lock().expect("poisoned").take();
        let Some(driver) = driver else {
            return;
        };
        let (tx, rx) = oneshot::channel();
        if driver.cmds.send(Cmd::Stop { reply: tx }).is_ok() {
            let _ = rx.await;
        }
        let _ = driver.task.await;
        self.shared.set_state(ConnectionState::Offline);
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
    /// has nothing in flight. See [`wait_synced`](Self::wait_synced).
    pub fn is_synced(&self) -> bool {
        self.state().is_online() && self.shared.synced.borrow().idle
    }

    /// Waits until the account is signed in and has caught up: the sync
    /// engine has nothing in flight. Fails if the account stops, or fails
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

    /// The account's conversations, from the cache.
    pub fn conversations(&self) -> Result<Vec<ConversationInfo>, ClientError> {
        Ok(self
            .shared
            .store
            .conversations(self.shared.id)?
            .into_iter()
            .map(ConversationInfo::from)
            .collect())
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
        let session = self
            .shared
            .session
            .lock()
            .expect("poisoned")
            .clone()
            .ok_or(ClientError::NotConnected)?;
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
        self.shared.store.remove_outbox(OutboxId(entry.id))?;
        self.shared.publish(Batch {
            changes: vec![Change::Outbox { id: OutboxId(id) }],
            events: vec![AccountEvent::OutboxRemoved { id }],
        });
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
            let entry = blocking(move || account.outbox_entry(id)).await?;
            if entry.status.is_final() {
                return Ok(entry);
            }
            loop {
                match events.next().await {
                    Some(AccountEvent::Outbox { entry }) if entry.id == id => break,
                    Some(AccountEvent::OutboxRemoved { id: gone }) if gone == id => break,
                    Some(AccountEvent::Lagged) => break,
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

    /// Its summary from the cache, if it is there.
    pub fn info(&self) -> Result<Option<ConversationInfo>, ClientError> {
        Ok(self
            .store()
            .conversation(self.account.shared.id, &self.conv)?
            .map(ConversationInfo::from))
    }

    /// Up to `limit` messages from the cache before seq `before`, or the
    /// newest if `None`, oldest first. Page back by passing the first
    /// one's seq.
    pub fn messages(&self, before: Option<u64>, limit: u32) -> Result<Vec<Message>, ClientError> {
        let Some(summary) = self
            .store()
            .conversation(self.account.shared.id, &self.conv)?
        else {
            return Ok(Vec::new());
        };
        let items = self
            .store()
            .timeline(summary.id, before.and_then(Seq::new), limit as usize)?;
        Ok(items.into_iter().map(Message::from).collect())
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
    /// follows every change. See [`Timeline`].
    pub fn timeline(&self, limit: u32) -> Result<Timeline, ClientError> {
        Timeline::new(self.clone(), limit)
    }

    /// Sends a message (5.3), through the outbox (7.6). It goes out as soon
    /// as the account is in the room on a connection, perhaps at once.
    /// Follow it with [`Account::wait_outbox`] or [`Account::subscribe`].
    ///
    /// `text` is plain; it is escaped here (3.4). Fails with
    /// [`ClientError::NotJoined`] for a room that has never been joined.
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
        let id = wait(rx).await?;
        let account = self.account.clone();
        blocking(move || account.outbox_entry(id.get())).await
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

async fn wait<T>(rx: oneshot::Receiver<Result<T, ClientError>>) -> Result<T, ClientError> {
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
    })
    .validate()
    .map_err(|e| ClientError::Invalid(format!("message: {e}")))
}

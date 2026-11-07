//! The task that runs one account: it keeps a connection up with the
//! [`Supervisor`], and on each signed-in connection feeds every server
//! line, in arrival order, to a fresh [`SyncEngine`], and sends what the
//! engine asks for (7.1-7.3, 7.6).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use risala_proto::command::Command;
use risala_proto::names::{Conv, Id, Name, Room, Seq, Uid};
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::text::unescape;
use risala_proto::types::Ref;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, warn};

use super::account::{AccountShared, Batch, Cmd, Synced, check_draft};
use super::blocking;
use super::types::{
    AccountEvent, ClientError, ConnectionState, Notice, OutboxEntry, is_lasting_refusal,
};
use crate::addr::TrustStore;
use crate::conn::{
    self, End, GuestSignIn, GuestToken, IdentitySignIn, Incoming, Response, Session, SignIn,
    Supervisor, SupervisorEvent,
};
use crate::store::{AccountId, Change, Draft, OutboxId, Store, StoreError};
use crate::sync::{self, Notification, Outcome, Output, ReqId, SyncEngine, SyncError};

/// The most incoming items handled in one blocking step.
const BATCH: usize = 256;

/// How long QUIT may take when stopping.
const QUIT_TIMEOUT: Duration = Duration::from_secs(3);

type Reply<T> = oneshot::Sender<Result<T, ClientError>>;

/// Runs the account until it is stopped or fails for good.
pub(crate) async fn run(
    shared: Arc<AccountShared>,
    generation: u64,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
) {
    let stop_reply = drive(&shared, &mut cmds).await;
    // Whatever is still queued is handled offline; later commands find
    // the queue closed and are handled offline too.
    cmds.close();
    while let Ok(cmd) = cmds.try_recv() {
        offline(&shared, cmd).await;
    }
    *shared.session.lock().expect("poisoned") = None;
    shared.synced.send_modify(|s| s.idle = false);
    {
        let mut driver = shared.driver.lock().expect("poisoned");
        if driver.as_ref().is_some_and(|d| d.generation == generation) {
            *driver = None;
        }
    }
    if let Some(reply) = stop_reply {
        shared.set_state(ConnectionState::Offline);
        let _ = reply.send(());
    }
}

/// How a signed-in connection ended.
enum Flow {
    /// The connection closed, or must be replaced.
    Disconnected,
    /// The app asked to reconnect now.
    Reconnect,
    /// The app asked to stop.
    Stop(oneshot::Sender<()>),
}

/// The main loop. Returns the reply to send once stopped, if the app
/// asked to stop.
async fn drive(
    shared: &Arc<AccountShared>,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
) -> Option<oneshot::Sender<()>> {
    let server = shared.server.to_string();
    // A guest resumes the session it last signed in to (4.2).
    let guest_token = if shared.is_guest() {
        let store = shared.store.clone();
        let account = shared.id;
        match blocking(&shared.rt, move || store.guest_session(account)).await {
            Ok(session) => Some(Arc::new(GuestToken::new(session))),
            Err(e) => {
                warn!(error = %e, "reading the guest session");
                Some(Arc::default())
            }
        }
    } else {
        None
    };
    let sign_in = match sign_in_for(shared, guest_token.clone()) {
        Ok(s) => s,
        Err(error) => {
            shared.set_state(ConnectionState::Failed { error });
            return None;
        }
    };
    let trust: Arc<dyn TrustStore> = Arc::new(shared.store.clone());
    let (supervisor, mut events) = Supervisor::spawn(
        shared.server.clone(),
        trust,
        shared.options.session.clone(),
        sign_in,
        shared.options.backoff,
    );
    loop {
        tokio::select! {
            event = events.recv() => {
                let event = event?;
                match event {
                    SupervisorEvent::Connecting { attempt } => {
                        shared.set_state(ConnectionState::Connecting { attempt });
                    }
                    SupervisorEvent::Connected { .. } => shared.set_state(ConnectionState::SigningIn),
                    SupervisorEvent::SignedIn { uid, session, incoming } => {
                        if let Some(token) = &guest_token {
                            save_guest_session(shared, token.get()).await;
                        }
                        match online(shared, uid, session.clone(), incoming, cmds).await {
                            Flow::Disconnected => session.close(),
                            Flow::Reconnect => supervisor.reconnect_now(),
                            Flow::Stop(reply) => {
                                let _ = tokio::time::timeout(QUIT_TIMEOUT, session.quit("")).await;
                                supervisor.stop().await;
                                return Some(reply);
                            }
                        }
                    }
                    SupervisorEvent::Disconnected { reason } => {
                        shared.set_state(ConnectionState::Disconnected { reason: reason.to_string() });
                    }
                    SupervisorEvent::Waiting { delay, error } => {
                        shared.set_state(ConnectionState::Waiting {
                            retry_in_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                            error: error.map(|e| ClientError::from_conn(&server, &e)),
                        });
                    }
                    SupervisorEvent::Failed { error } => {
                        shared.set_state(ConnectionState::Failed {
                            error: ClientError::from_conn(&server, &error),
                        });
                        return None;
                    }
                    SupervisorEvent::Stopped => return None,
                }
            }
            cmd = cmds.recv() => match cmd {
                None => {
                    supervisor.stop().await;
                    return None;
                }
                Some(Cmd::Stop { reply }) => {
                    supervisor.stop().await;
                    return Some(reply);
                }
                Some(Cmd::Reconnect) => supervisor.reconnect_now(),
                Some(cmd) => offline(shared, cmd).await,
            },
        }
    }
}

/// Saves the guest session the account signed in to, so that the next
/// connection, even from a later run of the app, can resume it (4.2).
async fn save_guest_session(shared: &AccountShared, session: Option<(Name, Id)>) {
    let store = shared.store.clone();
    let account = shared.id;
    let saved = blocking(&shared.rt, move || {
        store.set_guest_session(account, session.as_ref().map(|(name, token)| (name, token)))
    })
    .await;
    if let Err(e) = saved {
        warn!(error = %e, "saving the guest session");
    }
}

/// How the account signs in: a guest by name, resuming the session in
/// `guest_token`, or an identity with its key.
fn sign_in_for(
    shared: &AccountShared,
    guest_token: Option<Arc<GuestToken>>,
) -> Result<Arc<dyn SignIn>, ClientError> {
    let uid = &shared.uid;
    if uid.is_guest() {
        let name = uid
            .name()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("guest name {:?}", uid.name())))?;
        return Ok(Arc::new(GuestSignIn::resuming(
            name,
            guest_token.unwrap_or_default(),
        )));
    }
    let identity = uid
        .to_identity()
        .ok_or_else(|| ClientError::Invalid(format!("uid {uid}")))?;
    let keys = shared
        .options
        .keys
        .as_ref()
        .ok_or_else(|| ClientError::Keys("no key store".into()))?;
    let key = keys
        .load(identity.as_str())
        .map_err(|e| ClientError::Keys(e.to_string()))?
        .ok_or_else(|| ClientError::Keys(format!("no key for {identity}")))?;
    Ok(Arc::new(IdentitySignIn { identity, key }))
}

// ---------------------------------------------------------------------------
// Online

/// Something for the engine to do, in a blocking step.
enum Input {
    Line(ServerMessage),
    Reply(ReqId, sync::Reply),
    Start,
    Join(Room),
    Part(Room, String),
    Send(Conv, Draft),
    MarkRead(Conv, Seq),
    LoadOlder(Conv),
    Download(Conv),
    Fetch(Conv, Seq),
    Resume,
}

/// What to do with an input's result, on the async side.
enum Ctx {
    None,
    /// A JOIN the app asked for.
    Join(Room, Reply<()>),
    /// A JOIN after reconnecting (4.2).
    Rejoin(Room),
    /// A PART the app asked for.
    Part(Reply<()>),
    Send(Reply<OutboxId>),
    Done(Reply<()>),
}

/// One signed-in connection.
struct Online<'a> {
    shared: &'a Arc<AccountShared>,
    session: Arc<Session>,
    engine: Option<SyncEngine>,
    /// The engine's requests in flight, by the `ref` they were sent with.
    refs: HashMap<Ref, ReqId>,
    /// JOIN and PART requests the app waits on.
    waiters: HashMap<ReqId, (Option<Room>, Reply<()>)>,
    /// JOINs sent after reconnecting.
    rejoining: HashMap<ReqId, Room>,
    /// Replies the session could not send a command for.
    synthetic: Vec<(Input, Ctx)>,
    /// When to call [`SyncEngine::resume_outbox`] after `rate-limited`.
    resume_at: Option<Instant>,
}

async fn online(
    shared: &Arc<AccountShared>,
    uid: Uid,
    session: Arc<Session>,
    mut incoming: mpsc::Receiver<Incoming>,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
) -> Flow {
    debug!(server = %shared.server, %uid, "signed in");
    *shared.session.lock().expect("poisoned") = Some(session.clone());
    shared.synced.send_modify(|s| {
        *s = Synced {
            connection: s.connection + 1,
            idle: false,
        }
    });
    shared.set_state(ConnectionState::Online {
        uid: uid.to_string(),
    });
    let engine = SyncEngine::signed_in_as(
        shared.store.clone(),
        shared.id,
        uid.clone(),
        shared.options.sync.clone(),
    );
    let mut on = Online {
        shared,
        session,
        engine: Some(engine),
        refs: HashMap::new(),
        waiters: HashMap::new(),
        rejoining: HashMap::new(),
        synthetic: Vec::new(),
        resume_at: None,
    };
    let flow = on.run(&mut incoming, cmds).await;
    *shared.session.lock().expect("poisoned") = None;
    shared.synced.send_modify(|s| s.idle = false);
    // Waiters still open get NotConnected when dropped.
    flow
}

impl Online<'_> {
    async fn run(
        &mut self,
        incoming: &mut mpsc::Receiver<Incoming>,
        cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    ) -> Flow {
        // Guests rejoin the rooms their session lost first, so that SYNC
        // lists them (4.2).
        let mut first = Vec::new();
        if self.shared.is_guest() && self.shared.options.rejoin_guest_rooms {
            match self.rooms_to_rejoin().await {
                Ok(rooms) => {
                    for room in rooms {
                        first.push((Input::Join(room.clone()), Ctx::Rejoin(room)));
                    }
                }
                Err(e) => warn!(error = %e, "reading the rooms to rejoin"),
            }
        }
        first.push((Input::Start, Ctx::None));
        if let Err(e) = self.feed(first).await {
            warn!(error = %e, "sync failed; reconnecting");
            return Flow::Disconnected;
        }
        loop {
            let resume_at = self.resume_at;
            let resume = async move {
                match resume_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            let inputs = tokio::select! {
                biased;
                item = incoming.recv() => {
                    let Some(item) = item else { return Flow::Disconnected };
                    let mut inputs = Vec::new();
                    self.take(item, &mut inputs);
                    while inputs.len() < BATCH {
                        match incoming.try_recv() {
                            Ok(item) => self.take(item, &mut inputs),
                            Err(_) => break,
                        }
                    }
                    inputs
                }
                cmd = cmds.recv() => match cmd {
                    None => return Flow::Disconnected,
                    Some(Cmd::Stop { reply }) => return Flow::Stop(reply),
                    Some(Cmd::Reconnect) => return Flow::Reconnect,
                    Some(cmd) => match self.command(cmd).await {
                        Some(input) => vec![input],
                        None => continue,
                    },
                },
                () = resume => {
                    self.resume_at = None;
                    vec![(Input::Resume, Ctx::None)]
                }
            };
            if let Err(e) = self.feed(inputs).await {
                warn!(error = %e, "sync failed; reconnecting");
                return Flow::Disconnected;
            }
        }
    }

    /// The rooms a guest joins again on this connection: those it should
    /// be in, by [`Store::rejoin_rooms`], that a SYNC sent before anything
    /// else does not list. After a resumed session, that is none (4.2), so
    /// no JOIN is recorded; after a new session, it is all of them.
    ///
    /// If the SYNC fails, it is all of them too. That is safe: JOIN of a
    /// room the guest is still in records nothing (6.1).
    async fn rooms_to_rejoin(&self) -> Result<Vec<Room>, StoreError> {
        let store = self.shared.store.clone();
        let account = self.shared.id;
        let mut rooms = blocking(&self.shared.rt, move || store.rejoin_rooms(account)).await?;
        if rooms.is_empty() {
            return Ok(rooms);
        }
        match self.session.request(Command::Sync).await {
            Ok(response) if response.is_ok() => {
                let listed: HashSet<Conv> = response
                    .lines
                    .iter()
                    .filter_map(|msg| match &msg.line {
                        ServerLine::Conv { conv, .. } => Some(conv.clone()),
                        _ => None,
                    })
                    .collect();
                rooms.retain(|room| !listed.contains(&Conv::Room(room.clone())));
            }
            Ok(response) => debug!(end = ?response.end, "SYNC before rejoining failed"),
            Err(e) => debug!(error = %e, "SYNC before rejoining failed"),
        }
        Ok(rooms)
    }

    /// Turns an incoming item into engine input.
    fn take(&mut self, item: Incoming, inputs: &mut Vec<(Input, Ctx)>) {
        match item {
            Incoming::Line(msg) => {
                if let ServerLine::Notice { message } = &msg.line {
                    self.shared.publish(Batch {
                        reload: false,
                        changes: Vec::new(),
                        events: vec![AccountEvent::Notice {
                            notice: Notice::Server {
                                text: unescape(message).into_owned(),
                            },
                        }],
                    });
                }
                inputs.push((Input::Line(msg), Ctx::None));
            }
            Incoming::Reply { ref_, response } => match self.refs.remove(&ref_) {
                Some(req) => inputs.push((Input::Reply(req, to_reply(response)), Ctx::None)),
                None => debug!(%ref_, "reply to no request of the engine"),
            },
        }
    }

    /// Turns an app command into engine input, or answers it at once.
    async fn command(&mut self, cmd: Cmd) -> Option<(Input, Ctx)> {
        Some(match cmd {
            Cmd::Join { room, reply } => (Input::Join(room.clone()), Ctx::Join(room, reply)),
            Cmd::Part {
                room,
                reason,
                reply,
            } => {
                // The user left: do not join it again (4.2).
                let store = self.shared.store.clone();
                let (account, r) = (self.shared.id, room.clone());
                if let Err(e) = blocking(&self.shared.rt, move || {
                    store.set_rejoin(account, &r, false)
                })
                .await
                {
                    let _ = reply.send(Err(e.into()));
                    return None;
                }
                (Input::Part(room, reason), Ctx::Part(reply))
            }
            Cmd::Send { conv, draft, reply } => (Input::Send(conv, draft), Ctx::Send(reply)),
            Cmd::MarkRead { conv, seq, reply } => (Input::MarkRead(conv, seq), Ctx::Done(reply)),
            Cmd::LoadOlder { conv, reply } => (Input::LoadOlder(conv), Ctx::Done(reply)),
            Cmd::Download { conv, reply } => (Input::Download(conv), Ctx::Done(reply)),
            Cmd::Fetch { conv, seq, reply } => (Input::Fetch(conv, seq), Ctx::Done(reply)),
            Cmd::Reconnect | Cmd::Stop { .. } => return None,
        })
    }

    /// Runs inputs through the engine in one blocking step, then sends its
    /// commands and reports its changes, in order.
    async fn feed(&mut self, mut inputs: Vec<(Input, Ctx)>) -> Result<(), SyncError> {
        while !inputs.is_empty() {
            let (inputs_only, ctxs): (Vec<Input>, Vec<Ctx>) = inputs.into_iter().unzip();
            let mut engine = self.engine.take().expect("the engine is here");
            let store = self.shared.store.clone();
            let account = self.shared.id;
            let (engine, results) = blocking(&self.shared.rt, move || {
                let mut results = Vec::new();
                for input in inputs_only {
                    let result = step(&mut engine, input).map(|(out, sent)| {
                        let events = describe(&store, account, &out);
                        (out, sent, events)
                    });
                    let failed = result.is_err();
                    results.push(result);
                    if failed {
                        break;
                    }
                }
                (engine, results)
            })
            .await;
            self.engine = Some(engine);
            for (result, ctx) in results.into_iter().zip(ctxs) {
                match result {
                    Ok((out, sent, events)) => self.dispatch(out, sent, events, ctx).await,
                    Err(SyncError::Store(e)) => return Err(SyncError::Store(e)),
                    Err(e) => answer_err(ctx, e.into()),
                }
            }
            inputs = std::mem::take(&mut self.synthetic);
        }
        let idle = self.refs.is_empty() && !self.engine.as_ref().is_some_and(SyncEngine::is_busy);
        self.shared.synced.send_modify(|s| s.idle = idle);
        Ok(())
    }

    /// Sends the engine's commands, reports its changes and answers the
    /// app.
    async fn dispatch(
        &mut self,
        out: Output,
        sent: Option<OutboxId>,
        events: Vec<AccountEvent>,
        ctx: Ctx,
    ) {
        let first_req = out.send.first().map(|o| o.req);
        for o in out.send {
            match self.session.send(o.command) {
                Ok(ref_) => {
                    self.refs.insert(ref_, o.req);
                }
                Err(conn::Error::Closed(_)) => {
                    // The connection is ending; the incoming queue ends too.
                }
                Err(e) => {
                    // The engine must still hear how the command ended.
                    warn!(error = %e, "cannot send a command");
                    let reply = sync::Reply {
                        lines: Vec::new(),
                        outcome: Outcome::Failed,
                    };
                    self.synthetic.push((Input::Reply(o.req, reply), Ctx::None));
                }
            }
        }
        if let Some(wait) = out.retry_after {
            self.resume_at = Some(Instant::now() + wait);
        }

        // Rooms to stop joining again.
        let mut not_again: Vec<Room> = Vec::new();
        let mut join_again: Vec<Room> = Vec::new();
        let mut events = events;
        for n in &out.notifications {
            match n {
                Notification::Kicked { room, .. }
                | Notification::Banned { room, .. }
                | Notification::Dropped { room, .. } => not_again.push(room.clone()),
                _ => {}
            }
        }
        let mut answers: Vec<(Reply<()>, Result<(), ClientError>)> = Vec::new();
        for done in out.completed {
            let result = match &done.outcome {
                Outcome::Ok(_) => Ok(()),
                Outcome::Err(err) => Err(ClientError::server(err)),
                Outcome::Failed => Err(ClientError::Connection {
                    message: "the server's answer could not be read".into(),
                    permanent: false,
                }),
            };
            if let Some(room) = self.rejoining.remove(&done.req)
                && let Outcome::Err(err) = &done.outcome
                && is_lasting_refusal(&err.code)
            {
                events.push(AccountEvent::Notice {
                    notice: Notice::RejoinFailed {
                        room: room.to_string(),
                        error: ClientError::server(err),
                    },
                });
                not_again.push(room);
            }
            if let Some((room, reply)) = self.waiters.remove(&done.req) {
                if let (Some(room), Ok(())) = (room, &result)
                    && self.shared.is_guest()
                    && self.shared.options.rejoin_guest_rooms
                {
                    join_again.push(room);
                }
                answers.push((reply, result));
            }
        }
        if !not_again.is_empty() || !join_again.is_empty() {
            let store = self.shared.store.clone();
            let account = self.shared.id;
            let written = blocking(&self.shared.rt, move || -> Result<(), StoreError> {
                for room in &not_again {
                    store.set_rejoin(account, room, false)?;
                }
                for room in &join_again {
                    store.set_rejoin(account, room, true)?;
                }
                Ok(())
            })
            .await;
            if let Err(e) = written {
                warn!(error = %e, "updating the rooms to rejoin");
            }
        }

        self.shared.publish(Batch {
            reload: false,
            changes: out.changes,
            events,
        });
        // The app learns the result after the changes it caused.
        let idle = self.refs.is_empty() && !self.engine.as_ref().is_some_and(SyncEngine::is_busy);
        if !idle {
            self.shared.synced.send_modify(|s| s.idle = false);
        }
        match ctx {
            Ctx::None => {}
            Ctx::Join(room, reply) => match first_req {
                Some(req) => {
                    self.waiters.insert(req, (Some(room), reply));
                }
                None => {
                    let _ = reply.send(Err(ClientError::NotConnected));
                }
            },
            Ctx::Rejoin(room) => {
                if let Some(req) = first_req {
                    self.rejoining.insert(req, room);
                }
            }
            Ctx::Part(reply) => match first_req {
                Some(req) => {
                    self.waiters.insert(req, (None, reply));
                }
                None => {
                    let _ = reply.send(Err(ClientError::NotConnected));
                }
            },
            Ctx::Send(reply) => {
                let _ = reply.send(sent.ok_or(ClientError::NotConnected));
            }
            Ctx::Done(reply) => {
                let _ = reply.send(Ok(()));
            }
        }
        for (reply, result) in answers {
            let _ = reply.send(result);
        }
    }
}

/// Runs one input through the engine. Returns its output, and the outbox
/// entry a send queued.
fn step(engine: &mut SyncEngine, input: Input) -> Result<(Output, Option<OutboxId>), SyncError> {
    let out = match input {
        Input::Line(msg) => engine.handle_line(&msg)?,
        Input::Reply(req, reply) => engine.handle_reply(req, reply)?,
        Input::Start => engine.start()?,
        Input::Join(room) => engine.join(&room),
        Input::Part(room, reason) => engine.part(&room, &reason),
        Input::Send(conv, draft) => {
            let (id, out) = engine.send(&conv, &draft)?;
            return Ok((out, Some(id)));
        }
        Input::MarkRead(conv, seq) => engine.mark_read(&conv, seq)?,
        Input::LoadOlder(conv) => engine.load_older(&conv)?,
        Input::Download(conv) => engine.download(&conv)?,
        Input::Fetch(conv, seq) => engine.fetch(&conv, seq)?,
        Input::Resume => engine.resume_outbox()?,
    };
    Ok((out, None))
}

fn answer_err(ctx: Ctx, e: ClientError) {
    match ctx {
        Ctx::Join(_, reply) | Ctx::Part(reply) | Ctx::Done(reply) => {
            let _ = reply.send(Err(e));
        }
        Ctx::Send(reply) => {
            let _ = reply.send(Err(e));
        }
        Ctx::None | Ctx::Rejoin(_) => {}
    }
}

fn to_reply(response: Response) -> sync::Reply {
    sync::Reply {
        lines: response.lines,
        outcome: match response.end {
            End::Ok(ok) => Outcome::Ok(ok),
            End::Err(err) => Outcome::Err(err),
            End::Unparseable(_) => Outcome::Failed,
        },
    }
}

/// The subscriber events for an output: its changes, named, and its
/// notifications. Reads the cache, so it runs on a blocking thread.
pub(crate) fn describe(store: &Store, account: AccountId, out: &Output) -> Vec<AccountEvent> {
    let mut events = describe_changes(store, account, &out.changes);
    events.extend(out.notifications.iter().map(|n| AccountEvent::Notice {
        notice: Notice::from_sync(n),
    }));
    events
}

fn describe_changes(store: &Store, _account: AccountId, changes: &[Change]) -> Vec<AccountEvent> {
    let mut names = HashMap::new();
    let mut name = |conv: crate::store::ConvId| -> Option<String> {
        names
            .entry(conv)
            .or_insert_with(|| {
                store
                    .conversation_by_id(conv)
                    .ok()
                    .flatten()
                    .map(|c| c.name.to_string())
            })
            .clone()
    };
    let mut events = Vec::new();
    let mut messages = HashSet::new();
    let mut convs = HashSet::new();
    for change in changes {
        match change {
            Change::Inserted { conv, .. }
            | Change::Updated { conv, .. }
            | Change::Cleared { conv } => {
                if let Some(n) = name(*conv)
                    && messages.insert(n.clone())
                {
                    events.push(AccountEvent::MessagesChanged { conversation: n });
                }
            }
            Change::Conversation { conv } => {
                if let Some(n) = name(*conv)
                    && convs.insert(n.clone())
                {
                    events.push(AccountEvent::ConversationChanged { conversation: n });
                }
            }
            Change::ConversationRemoved { name, .. } => {
                events.push(AccountEvent::ConversationRemoved {
                    conversation: name.to_string(),
                });
            }
            Change::Outbox { id } => match store.outbox_item(*id) {
                Ok(Some(item)) => events.push(AccountEvent::Outbox {
                    entry: OutboxEntry::from(item),
                }),
                Ok(None) => events.push(AccountEvent::OutboxRemoved { id: id.get() }),
                Err(e) => warn!(error = %e, "reading an outbox entry"),
            },
        }
    }
    events
}

// ---------------------------------------------------------------------------
// Offline

/// Handles a command with no connection: sends are queued in the outbox,
/// read markers move in the cache, and a guest's PART stops the room being
/// joined again. Anything else needs a connection.
pub(crate) async fn offline(shared: &Arc<AccountShared>, cmd: Cmd) {
    match cmd {
        Cmd::Send { conv, draft, reply } => {
            let s = shared.clone();
            let result = blocking(&shared.rt, move || queue_offline(&s, &conv, &draft)).await;
            let _ = reply.send(result);
        }
        Cmd::MarkRead { conv, seq, reply } => {
            let s = shared.clone();
            let result = blocking(&shared.rt, move || {
                let account = s.id;
                let (_, changes) = s.store.write(|tx| {
                    if let Some(mut row) = tx.conv_by_name(account, &conv)? {
                        tx.set_read(&mut row, seq.get())?;
                    }
                    Ok(())
                })?;
                publish_changes(&s, changes);
                Ok(())
            })
            .await;
            let _ = reply.send(result);
        }
        Cmd::Part { room, reply, .. } if shared.is_guest() => {
            let s = shared.clone();
            let result = blocking(&shared.rt, move || {
                s.store.set_rejoin(s.id, &room, false)?;
                let account = s.id;
                let (_, changes) = s.store.write(|tx| {
                    if let Some(mut row) = tx.conv_by_name(account, &Conv::Room(room))? {
                        tx.set_joined(&mut row, false)?;
                    }
                    Ok(())
                })?;
                publish_changes(&s, changes);
                Ok(())
            })
            .await;
            let _ = reply.send(result);
        }
        Cmd::Join { reply, .. }
        | Cmd::Part { reply, .. }
        | Cmd::LoadOlder { reply, .. }
        | Cmd::Download { reply, .. }
        | Cmd::Fetch { reply, .. } => {
            let _ = reply.send(Err(ClientError::NotConnected));
        }
        Cmd::Reconnect => {}
        Cmd::Stop { reply } => {
            let _ = reply.send(());
        }
    }
}

/// Queues a message with no connection, bound to the stored id (7.6), as
/// [`SyncEngine::send`] does.
fn queue_offline(
    shared: &AccountShared,
    conv: &Conv,
    draft: &Draft,
) -> Result<OutboxId, ClientError> {
    check_draft(conv, draft)?;
    let account = shared.id;
    let now = shared.options.sync.clock.now();
    let (id, changes) = shared.store.write(|tx| {
        let bound = tx.conv_by_name(account, conv)?.and_then(|r| r.conv_id);
        if bound.is_none() && conv.is_room() {
            return Ok(None);
        }
        tx.queue(account, conv, bound.as_ref(), draft, now)
            .map(Some)
    })?;
    publish_changes(shared, changes);
    id.ok_or_else(|| ClientError::NotJoined(conv.to_string()))
}

fn publish_changes(shared: &AccountShared, changes: Vec<Change>) {
    let events = describe_changes(&shared.store, shared.id, &changes);
    shared.publish(Batch {
        reload: false,
        changes,
        events,
    });
}

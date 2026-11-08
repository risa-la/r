//! People on the server: a connection per person, opened when needed,
//! that sends typed commands and waits for their final response, as a
//! client does.
//!
//! A connection that has been quiet while others talk fills up with live
//! events it has not read, and the server drops a connection whose queue
//! is full. So an identity's connection is closed after a while unused,
//! and opened again when needed. A guest's session must live on (4.2), so
//! a guest's quiet connection is read to the end with a PING instead.

use std::collections::{BTreeSet, HashMap, VecDeque};

use risala_proto::command::{Command, GuestToken, Request};
use risala_proto::names::{Conv, Name, Room, Seq, Uid};
use risala_proto::server::{EventBody, OkResponse, ServerLine, ServerMessage};
use risala_proto::types::{Ref, Relation};
use risala_server::testing::{TestClient, TestIdentity, TestServer};

/// Leaves `room`, giving no reason.
pub fn part(room: &Room) -> Command {
    Command::Part {
        room: room.clone(),
        reason: String::new(),
    }
}

/// Sets someone's display name (8.2).
fn set_name(display: &str) -> Command {
    Command::Name {
        display_name: risala_proto::text::escape(display),
    }
}

use crate::rng::Rng;

/// Commands after which a connection that has not been used is closed or
/// read. Each command adds at most a couple of lines to every other
/// connection, so this stays well inside a connection's queue (1,024
/// lines by default).
const IDLE: u64 = 250;

/// How often, in commands, quiet connections are looked at.
const SWEEP: u64 = 50;

/// Who someone is on the server.
#[derive(Debug)]
pub enum Who {
    Identity(TestIdentity),
    Guest {
        name: Name,
        /// The token of the guest's session, once it has one (4.2).
        token: Option<String>,
    },
}

/// One person, and their connection if it is open.
#[derive(Debug)]
pub struct Actor {
    pub who: Who,
    /// Their display name (8.2), set when a guest's session starts.
    pub display: String,
    conn: Option<TestClient>,
    /// The command count when the connection was last read to the end.
    used: u64,
    /// The rooms a guest is in, to join again if its session ended.
    rooms: BTreeSet<Room>,
}

impl Actor {
    pub fn new(who: Who, display: &str) -> Actor {
        Actor {
            who,
            display: display.to_owned(),
            conn: None,
            used: 0,
            rooms: BTreeSet::new(),
        }
    }

    /// Their uid.
    pub fn uid(&self) -> Uid {
        match &self.who {
            Who::Identity(i) => i.uid(),
            Who::Guest { name, .. } => Uid::guest(name),
        }
    }

    pub fn is_guest(&self) -> bool {
        matches!(self.who, Who::Guest { .. })
    }
}

/// A message seen on any connection, for bots to answer.
#[derive(Debug, Clone)]
pub struct Seen {
    pub seq: Seq,
    pub from: Uid,
}

/// The server's refusal of a command.
#[derive(Debug, Clone)]
pub struct Refused {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ERR {} {}", self.code, self.message)
    }
}

/// Everyone, with their connections to one server.
pub struct Pool<'a> {
    server: &'a TestServer,
    pub actors: Vec<Actor>,
    /// Commands run so far.
    commands: u64,
    rng: Rng,
    /// When set, the newest plain messages seen in each room.
    pub seen: Option<HashMap<Room, VecDeque<Seen>>>,
}

/// How many seen messages are kept per room.
const SEEN_PER_ROOM: usize = 30;

impl<'a> Pool<'a> {
    pub fn new(server: &'a TestServer, actors: Vec<Actor>, rng: Rng) -> Pool<'a> {
        Pool {
            server,
            actors,
            commands: 0,
            rng,
            seen: None,
        }
    }

    /// A MSG with a cid (7.6), so that a message sent again after a lost
    /// connection is not stored twice.
    pub fn msg(&mut self, conv: Conv, text: &str, relation: Option<Relation>) -> Command {
        let hex: String = (0..3)
            .map(|_| format!("{:016x}", self.rng.next_u64()))
            .collect();
        Command::Msg {
            conv,
            text: risala_proto::text::escape(text),
            relation,
            file: None,
            cid: Some(hex.parse().expect("hex digits are a cid")),
            id: None,
        }
    }

    /// Runs `command` as actor `a` and returns the server's OK, or its
    /// ERR as [`Refused`]. Connects first if needed. A connection lost on
    /// the way is opened again and the command sent once more, which is
    /// safe for what scenarios send: messages carry a cid, and the rest
    /// end up the same when repeated.
    pub async fn call(&mut self, a: usize, command: Command) -> Result<OkResponse, Refused> {
        self.commands += 1;
        if self.commands.is_multiple_of(SWEEP) {
            self.sweep(a).await;
        }
        let mut last_error = None;
        for _ in 0..2 {
            if self.actors[a].conn.is_none() {
                self.open(a).await;
            }
            match self.exchange(a, &command).await {
                Ok(result) => {
                    let actor = &mut self.actors[a];
                    actor.used = self.commands;
                    match (&result, &command) {
                        (Ok(_), Command::Join { room }) => _ = actor.rooms.insert(room.clone()),
                        (Ok(_), Command::Part { room, .. }) => _ = actor.rooms.remove(room),
                        _ => {}
                    }
                    return result;
                }
                Err(e) => {
                    self.actors[a].conn = None;
                    last_error = Some(e);
                }
            }
        }
        panic!(
            "{}: the connection keeps failing: {}",
            self.actors[a].uid(),
            last_error.expect("an error")
        );
    }

    /// Sends `command` and reads until its final response, answering the
    /// server's PINGs and noting messages on the way. Fails if the
    /// connection does.
    async fn exchange(
        &mut self,
        a: usize,
        command: &Command,
    ) -> std::io::Result<Result<OkResponse, Refused>> {
        let r: Ref = "d".parse().expect("a ref");
        let line = Request {
            ref_: Some(r.clone()),
            command: command.clone(),
        }
        .to_string();
        let seen = &mut self.seen;
        let conn = self.actors[a].conn.as_mut().expect("connected");
        conn.send(&line).await?;
        loop {
            let Some(line) = conn.recv().await? else {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            };
            let Ok(msg) = line.parse::<ServerMessage>() else {
                continue;
            };
            match msg.line {
                ServerLine::Ok(ok) if msg.ref_.as_ref() == Some(&r) => return Ok(Ok(ok)),
                ServerLine::Err(err) if msg.ref_.as_ref() == Some(&r) => {
                    return Ok(Err(Refused {
                        code: err.code.to_string(),
                        message: err.message,
                    }));
                }
                ServerLine::Ping { token } => {
                    let pong = Request::new(Command::Pong { token }).to_string();
                    conn.send(&pong).await?;
                }
                ServerLine::Bye { .. } => {
                    return Err(std::io::ErrorKind::ConnectionAborted.into());
                }
                ServerLine::Event(event) => {
                    if let (Some(seen), Some(meta), EventBody::Msg(m)) =
                        (seen.as_mut(), event.meta, event.body)
                        && m.relation.is_none()
                        && !m.deleted
                        && let Conv::Room(room) = m.conv
                    {
                        let list = seen.entry(room).or_default();
                        list.push_back(Seen {
                            seq: meta.seq,
                            from: meta.from,
                        });
                        if list.len() > SEEN_PER_ROOM {
                            list.pop_front();
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Opens actor `a`'s connection and signs in: AUTH for an identity,
    /// GUEST for a guest, resuming its session if it has one. A guest
    /// whose session ended joins its rooms again.
    async fn open(&mut self, a: usize) {
        let server = self.server;
        let actor = &mut self.actors[a];
        let (name, token) = match &actor.who {
            Who::Identity(identity) => {
                actor.conn = Some(server.sign_in(identity).await);
                actor.used = self.commands;
                return;
            }
            Who::Guest { name, token } => (name.clone(), token.clone()),
        };
        let mut conn = server.connect().await;
        let greeting = conn.expect_line().await.expect("a greeting");
        assert!(greeting.starts_with("RISALA "), "greeting: {greeting}");
        let command = Command::Guest {
            name: name.clone(),
            token: token
                .as_deref()
                .map(|t| GuestToken(t.parse().expect("a token we were given"))),
        };
        conn.send(&Request::new(command).to_string())
            .await
            .expect("sending GUEST");
        let answer = conn.expect_line().await.expect("an answer to GUEST");
        let ok = match answer.parse::<ServerMessage>().map(|m| m.line) {
            Ok(ServerLine::Ok(ok)) => ok,
            _ => panic!("~{name} could not start a session: {answer}"),
        };
        if let Who::Guest { token: t, .. } = &mut actor.who {
            *t = ok.value("token").map(str::to_owned);
        }
        actor.conn = Some(conn);
        actor.used = self.commands;
        if ok.value("resumed") == Some("yes") {
            return;
        }
        let display = actor.display.clone();
        let rooms: Vec<Room> = actor.rooms.iter().cloned().collect();
        if !display.is_empty() {
            let _ = self.exchange(a, &set_name(&display)).await;
        }
        if token.is_some() {
            // The session ended while the connection was closed: back
            // into the rooms it was in.
            for room in rooms {
                let _ = self.exchange(a, &Command::Join { room }).await;
            }
        }
    }

    /// Registers actor `a`, a hosted identity, with its key (4.6), keeps
    /// the connection, and sets its display name (8.2).
    pub async fn register(&mut self, a: usize) {
        let Who::Identity(identity) = &self.actors[a].who else {
            panic!("guests do not register");
        };
        let conn = self.server.register_as(identity).await;
        self.actors[a].conn = Some(conn);
        self.actors[a].used = self.commands;
        let display = self.actors[a].display.clone();
        if !display.is_empty()
            && let Err(e) = self.call(a, set_name(&display)).await
        {
            panic!("{}: NAME: {e}", self.actors[a].uid());
        }
    }

    /// Closes identities' connections that have been quiet for a while,
    /// and reads guests' to the end, so that no queue fills up. Leaves
    /// actor `keep`, about to be used, alone.
    async fn sweep(&mut self, keep: usize) {
        for a in 0..self.actors.len() {
            let actor = &self.actors[a];
            if a == keep || actor.conn.is_none() || self.commands - actor.used < IDLE {
                continue;
            }
            if actor.is_guest() {
                if self
                    .exchange(a, &Command::Ping { token: None })
                    .await
                    .is_err()
                {
                    self.actors[a].conn = None;
                } else {
                    self.actors[a].used = self.commands;
                }
            } else {
                self.quit(a).await;
            }
        }
    }

    /// Closes actor `a`'s connection, if open, with QUIT.
    pub async fn quit(&mut self, a: usize) {
        if let Some(mut conn) = self.actors[a].conn.take() {
            let quit = Request::new(Command::Quit {
                message: String::new(),
            });
            let _ = conn.send(&quit.to_string()).await;
            let _ = conn.close().await;
        }
    }

    /// Closes every connection.
    pub async fn quit_all(&mut self) {
        for a in 0..self.actors.len() {
            self.quit(a).await;
        }
    }
}

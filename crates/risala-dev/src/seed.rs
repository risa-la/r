//! Carries out a [`Plan`] on a server, step by step, through the protocol,
//! with the server's clock set to each step's time first.

use std::io::Write as _;
use std::time::{Duration, Instant};

use risala_proto::auth::SecretKey;
use risala_proto::command::Command;
use risala_proto::names::{Conv, Room, Seq, Uid};
use risala_proto::server::OkResponse;
use risala_proto::text::escape;
use risala_proto::time::Timestamp;
use risala_proto::types::{Relation, Role, RoomSetting, SendMode};
use risala_server::testing::{TestIdentity, TestServer};

use crate::actors::{Actor, Pool, Refused};
use crate::plan::{Act, ME, Plan};
use crate::rng::Rng;

/// The identity domain of the development server (4.6). It need not
/// resolve: clients never fetch a hosted identity's key file to sign in.
pub const IDENTITY_DOMAIN: &str = "risala.test";

/// The device key of person `who` in a scenario seeded with `seed`. The
/// same every time, so that bots can sign in again on later runs, and the
/// account's key survives `--reset`.
pub fn key_for(seed: u64, who: usize) -> SecretKey {
    SecretKey::from_seed(Rng::stream(seed, 7_000_000 + who as u64).seed32())
}

/// Everyone in `plan`, as actors with their keys.
pub fn actors(plan: &Plan, seed: u64) -> Vec<Actor> {
    plan.people
        .iter()
        .enumerate()
        .map(|(who, p)| {
            if p.guest {
                Actor::guest(p.name.parse().expect("a guest name"), &p.display)
            } else {
                let identity = format!("{}@{IDENTITY_DOMAIN}", p.name)
                    .parse()
                    .expect("an identity");
                let mut actor =
                    Actor::identity(TestIdentity::with_key(identity, key_for(seed, who)));
                actor.display = p.display.clone();
                actor
            }
        })
        .collect()
}

/// How seeding went.
#[derive(Debug)]
pub struct Outcome {
    pub elapsed: Duration,
    pub steps: usize,
    /// Steps the server refused. Each is reported on standard error.
    pub refused: usize,
}

/// What the seeder remembers of a room.
#[derive(Default)]
struct RoomState {
    /// The seq of each planned message, once sent.
    messages: Vec<Option<Seq>>,
    /// The newest seq seen.
    head: Option<Seq>,
    /// The account's JOIN.
    me_joined: Option<Seq>,
    /// Messages from others that count as unread, oldest first, with
    /// whether they are still there (not deleted).
    counted: Vec<(Seq, usize, bool)>,
}

/// Seeds `plan` on `server`, whose manual clock must stand at or before
/// the plan's first step. Its last steps are at `end`.
pub async fn seed(server: &TestServer, plan: &Plan, seed: u64, end: Timestamp) -> Outcome {
    let started = Instant::now();
    let mut pool = Pool::new(server, actors(plan, seed), Rng::stream(seed, 3));
    let mut rooms: Vec<RoomState> = plan.rooms.iter().map(|_| RoomState::default()).collect();
    let uids: Vec<Uid> = pool.actors.iter().map(Actor::uid).collect();
    let room_names: Vec<Room> = plan
        .rooms
        .iter()
        .map(|r| r.name.parse().expect("a room"))
        .collect();
    let mut refused = 0usize;
    let mut last_report = Instant::now();
    let mut reported = false;
    let total = plan.items.len();

    for (step, item) in plan.items.iter().enumerate() {
        let t = end
            .checked_sub(Duration::from_millis(item.ago))
            .expect("a time after 1970");
        if t > server.now() {
            server.set_time(t);
        }
        if last_report.elapsed() > Duration::from_secs(1) {
            eprint!("\rrisala-dev: seeding, step {step} of {total}   ");
            let _ = std::io::stderr().flush();
            last_report = Instant::now();
            reported = true;
        }
        let a = item.who;
        if let Act::Register = item.act {
            pool.register(a).await;
            continue;
        }
        let room = room_names[item.room].clone();
        let conv = Conv::Room(room.clone());
        let state = &mut rooms[item.room];
        let mut new_message: Option<usize> = None;
        let command = match &item.act {
            Act::Register => unreachable!("handled above"),
            Act::Create | Act::Join => Command::Join { room: room.clone() },
            Act::Part => Command::Part {
                room: room.clone(),
                reason: String::new(),
            },
            Act::Topic(topic) => Command::Set {
                room: room.clone(),
                setting: RoomSetting::Topic(escape(topic)),
            },
            Act::SendMods => Command::Set {
                room: room.clone(),
                setting: RoomSetting::Send(SendMode::Mods),
            },
            Act::Mod(p) => Command::Role {
                room: room.clone(),
                uid: uids[*p].clone(),
                role: Role::Mod,
            },
            Act::Msg { n, text, reply } => {
                new_message = Some(*n);
                Command::Msg {
                    conv: conv.clone(),
                    text: escape(text),
                    relation: reply
                        .and_then(|r| message_seq(state, r))
                        .map(Relation::Reply),
                    file: None,
                    cid: Some(pool.cid()),
                    id: None,
                }
            }
            Act::Edit { target, text } => {
                let Some(seq) = message_seq(state, *target) else {
                    continue;
                };
                Command::Msg {
                    conv: conv.clone(),
                    text: escape(text),
                    relation: Some(Relation::Edit(seq)),
                    file: None,
                    cid: Some(pool.cid()),
                    id: None,
                }
            }
            Act::React { target, emoji } => {
                let Some(seq) = message_seq(state, *target) else {
                    continue;
                };
                Command::Msg {
                    conv: conv.clone(),
                    text: escape(emoji),
                    relation: Some(Relation::React(seq)),
                    file: None,
                    cid: Some(pool.cid()),
                    id: None,
                }
            }
            Act::Delete { target } => {
                let Some(seq) = message_seq(state, *target) else {
                    continue;
                };
                for c in &mut state.counted {
                    if c.0 == seq {
                        c.2 = false;
                    }
                }
                Command::Delete {
                    conv: conv.clone(),
                    seq,
                    id: None,
                }
            }
            Act::Read => {
                let want = plan.rooms[item.room].unread;
                let alive: Vec<Seq> = state.counted.iter().filter(|c| c.2).map(|c| c.0).collect();
                let marker = if want == 0 {
                    state.head
                } else if want < alive.len() {
                    Some(alive[alive.len() - want - 1])
                } else {
                    state.me_joined
                };
                let Some(seq) = marker else { continue };
                Command::Read {
                    conv: conv.clone(),
                    seq,
                }
            }
        };
        let verb = verb(&item.act);
        match pool.call(a, command).await {
            Ok(ok) => {
                let seq = seq_in(&ok);
                if let Some(seq) = seq {
                    state.head = state.head.max(Some(seq));
                }
                if a == ME && matches!(item.act, Act::Join) {
                    state.me_joined = seq;
                }
                if let (Some(n), Some(seq)) = (new_message, seq) {
                    if state.messages.len() <= n {
                        state.messages.resize(n + 1, None);
                    }
                    state.messages[n] = Some(seq);
                    if a != ME {
                        state.counted.push((seq, n, true));
                    }
                }
            }
            Err(e) => {
                refused += 1;
                report_refusal(&uids[a], verb, &room, &e);
            }
        }
    }
    pool.quit_all().await;
    if reported {
        eprint!("\r{:60}\r", "");
    }
    Outcome {
        elapsed: started.elapsed(),
        steps: total,
        refused,
    }
}

/// The seq of the room's message `n`, once it was sent.
fn message_seq(state: &RoomState, n: usize) -> Option<Seq> {
    state.messages.get(n).copied().flatten()
}

/// The seq an OK names: `seq=` for events (5.3), or `head=` for JOIN
/// (6.1), which is the JOIN itself when it was recorded.
fn seq_in(ok: &OkResponse) -> Option<Seq> {
    match ok.seq() {
        Ok(Some(seq)) => Some(seq),
        _ => ok.value("head").and_then(|h| h.parse().ok()),
    }
}

fn verb(act: &Act) -> &'static str {
    match act {
        Act::Register => "REGISTER",
        Act::Create | Act::Join => "JOIN",
        Act::Part => "PART",
        Act::Topic(_) | Act::SendMods => "SET",
        Act::Mod(_) => "ROLE",
        Act::Msg { .. } => "MSG",
        Act::Edit { .. } => "MSG edit",
        Act::React { .. } => "MSG react",
        Act::Delete { .. } => "DELETE",
        Act::Read => "READ",
    }
}

/// Reports a refused step, without its text.
fn report_refusal(who: &Uid, verb: &str, room: &Room, e: &Refused) {
    eprintln!("\rrisala-dev: {who}: {verb} {room}: {e}");
}

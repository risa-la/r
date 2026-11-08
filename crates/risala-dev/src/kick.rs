//! The kick of the account from a room, held back until a client has
//! seen the room.
//!
//! A client learns its rooms from SYNC, which lists only the rooms the
//! account is in (7.1). A room the account was kicked from before a
//! client first signed in is never seen by that client. So the kick is
//! not seeded: the room's owner waits on the server until the account
//! comes online (PRESENCE, 8.3), gives its client a few seconds to catch
//! up, and kicks it then. After that, every run finds the account out of
//! the room and does nothing; `--reset` sets it up again.

use std::time::Duration;

use risala_proto::command::{Command, Request};
use risala_proto::names::{Room, Uid};
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::text::escape;
use risala_proto::types::{Presence, Ref};
use risala_server::testing::{TestClient, TestServer};
use tokio::task::JoinHandle;

use crate::actors::Who;
use crate::plan::{ME, Plan};

/// The reason the owner gives.
const REASON: &str = "Keep it civil, please";

/// How long the account's client gets to catch up before the kick.
const GRACE: Duration = Duration::from_secs(5);

/// How long the owner waits for the reply to a command, across as many
/// of [`TestClient::recv`]'s shorter timeouts as it takes: a server busy
/// with a client's first sync may be slow to answer.
const REPLY_DEADLINE: Duration = Duration::from_secs(60);

/// For each room the account is to be kicked from and is still in,
/// starts the owner waiting for the account to come online. Returns the
/// waiting tasks and the rooms they are for.
pub async fn arm(server: &TestServer, plan: &Plan, seed: u64) -> (Vec<JoinHandle<()>>, Vec<Room>) {
    let actors = crate::seed::actors(plan, seed);
    let me = actors[ME].uid();
    let mut tasks = Vec::new();
    let mut rooms = Vec::new();
    for room_plan in plan.rooms.iter().filter(|r| r.kicked) {
        let room: Room = room_plan.name.parse().expect("a room");
        let Who::Identity(owner) = &actors[room_plan.members[0]].who else {
            continue;
        };
        let mut conn = server.sign_in(owner).await;
        let members = Command::Members { room: room.clone() };
        let Ok(lines) = exchange(&mut conn, members).await else {
            continue;
        };
        let presence = lines.iter().find_map(|l| match l {
            ServerLine::Member { uid, presence, .. } if *uid == me => Some(presence.clone()),
            _ => None,
        });
        let Some(presence) = presence else {
            let _ = conn.close().await;
            continue;
        };
        rooms.push(room.clone());
        let online = presence == Presence::Online;
        tasks.push(tokio::spawn(wait_and_kick(conn, room, me.clone(), online)));
    }
    (tasks, rooms)
}

/// Reads `conn` until `me` comes online, then kicks it from `room`. If
/// it is `online` already, from a connection that may not be a client's,
/// waits for it to go offline first.
async fn wait_and_kick(mut conn: TestClient, room: Room, me: Uid, mut online: bool) {
    loop {
        let line = match conn.recv().await {
            Ok(Some(line)) => line,
            Ok(None) => return,
            // Nothing for a while: keep waiting.
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => return,
        };
        let Ok(msg) = line.parse::<ServerMessage>() else {
            continue;
        };
        match msg.line {
            ServerLine::Ping { token } => {
                let pong = Request::new(Command::Pong { token }).to_string();
                if conn.send(&pong).await.is_err() {
                    return;
                }
            }
            ServerLine::Presence { presence, uids } if uids.contains(&me) => {
                if presence == Presence::Online && !online {
                    break;
                }
                online = presence == Presence::Online;
            }
            _ => {}
        }
    }
    tokio::time::sleep(GRACE).await;
    let kick = Command::Kick {
        room: room.clone(),
        uid: me.clone(),
        reason: escape(REASON),
    };
    match exchange(&mut conn, kick).await {
        Ok(_) => println!("risala-dev: {me} came online, and was kicked from {room}"),
        Err(e) => eprintln!("risala-dev: kicking {me} from {room}: {e}"),
    }
    let _ = conn.close().await;
}

/// Sends `command` and returns the lines of its response, up to its OK,
/// or the ERR, connection failure or missing reply as text. It answers
/// PINGs while it waits, as [`wait_and_kick`] does.
async fn exchange(conn: &mut TestClient, command: Command) -> Result<Vec<ServerLine>, String> {
    let deadline = tokio::time::Instant::now() + REPLY_DEADLINE;
    let r: Ref = "k".parse().expect("a ref");
    let line = Request {
        ref_: Some(r.clone()),
        command,
    }
    .to_string();
    conn.send(&line).await.map_err(|e| e.to_string())?;
    let mut lines = Vec::new();
    loop {
        let line = match conn.recv().await {
            Ok(Some(line)) => line,
            Ok(None) => return Err("the server closed the connection".into()),
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    && tokio::time::Instant::now() < deadline =>
            {
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        let Ok(msg) = line.parse::<ServerMessage>() else {
            continue;
        };
        if let ServerLine::Ping { token } = msg.line {
            let pong = Request::new(Command::Pong { token }).to_string();
            conn.send(&pong).await.map_err(|e| e.to_string())?;
            continue;
        }
        if msg.ref_.as_ref() != Some(&r) {
            continue;
        }
        match msg.line {
            ServerLine::Ok(_) => return Ok(lines),
            ServerLine::Err(e) => return Err(format!("ERR {} {}", e.code, e.message)),
            other => lines.push(other),
        }
    }
}

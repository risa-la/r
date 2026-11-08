//! `--live`: bots that keep the server busy after seeding, posting,
//! editing, reacting and joining at a steady rate, on the system clock.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use risala_proto::command::Command;
use risala_proto::names::{Conv, Room, Seq};
use risala_proto::text::escape;
use risala_proto::types::Relation;
use risala_server::testing::TestServer;

use crate::actors::Pool;
use crate::corpus;
use crate::plan::{ME, Pid, Plan};
use crate::rng::Rng;

/// Rooms most of the activity goes to: the most recently active, so that
/// it shows near the top of the list instead of spreading thin over
/// thousands of rooms.
const HOT_ROOMS: usize = 15;

/// Rooms quiet for longer than this stay quiet, as do rooms with no
/// messages at all: scenarios have them on purpose.
const STALE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A bot's own message, which it may edit.
struct Posted {
    who: Pid,
    room: usize,
    seq: Seq,
    text: String,
}

/// What happened in the last minute, for the summary line.
#[derive(Default)]
struct Counts {
    posts: u32,
    replies: u32,
    edits: u32,
    reactions: u32,
    joins: u32,
    parts: u32,
    refused: u32,
}

/// Runs the bots until `stop` resolves. `rate` is steps per minute.
pub async fn run(
    server: &TestServer,
    plan: &Plan,
    seed: u64,
    rate: u32,
    stop: impl std::future::Future<Output = ()>,
) {
    if plan.rooms.is_empty() {
        eprintln!("risala-dev: this scenario has no rooms, so --live has nobody to post");
        stop.await;
        return;
    }
    let mut pool = Pool::new(
        server,
        crate::seed::actors(plan, seed),
        Rng::stream(seed, 5),
    );
    pool.seen = Some(Default::default());
    // A different stream each run, so that live activity is not the same
    // every time.
    let mut rng = Rng::new(seed ^ risala_proto::time::Timestamp::now().unix_millis());
    let rooms: Vec<Room> = plan
        .rooms
        .iter()
        .map(|r| r.name.parse().expect("a room"))
        .collect();
    let mut members: Vec<Vec<Pid>> = plan.rooms.iter().map(|r| r.members.clone()).collect();
    let hosted: Vec<Pid> = (1..plan.people.len())
        .filter(|&p| !plan.people[p].guest)
        .collect();
    let guests: Vec<Pid> = (1..plan.people.len())
        .filter(|&p| plan.people[p].guest)
        .collect();
    // Rooms the bots are active in, the most recent first.
    let stale = u64::try_from(STALE.as_millis()).expect("fits");
    let mut active: Vec<usize> = (0..plan.rooms.len())
        .filter(|&r| plan.rooms[r].messages > 0 && plan.rooms[r].last <= stale)
        .collect();
    active.sort_by_key(|&r| plan.rooms[r].last);
    if active.is_empty() {
        eprintln!(
            "risala-dev: no room in this scenario was active lately, so --live has nothing to do"
        );
        stop.await;
        return;
    }
    let mut posted: VecDeque<Posted> = VecDeque::new();
    // Guests visiting a room, and how many more steps they stay.
    let mut visits: Vec<(Pid, usize, u32)> = Vec::new();
    let mut counts = Counts::default();
    let mut summary = Instant::now();

    let period = Duration::from_secs_f64(60.0 / f64::from(rate.max(1)));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => break,
            _ = ticker.tick() => {}
        }
        if summary.elapsed() >= Duration::from_secs(60) {
            let c = std::mem::take(&mut counts);
            eprintln!(
                "risala-dev: live, last minute: {} posts, {} replies, {} edits, {} reactions, \
                 {} joins, {} parts, {} refused",
                c.posts, c.replies, c.edits, c.reactions, c.joins, c.parts, c.refused
            );
            summary = Instant::now();
        }

        // Guests whose visit is over leave.
        let mut leaving = Vec::new();
        visits.retain_mut(|(g, r, left)| {
            if *left == 0 {
                leaving.push((*g, *r));
                false
            } else {
                *left -= 1;
                true
            }
        });
        for (g, r) in leaving {
            let part = Command::Part {
                room: rooms[r].clone(),
                reason: String::new(),
            };
            match pool.call(g, part).await {
                Ok(_) => counts.parts += 1,
                Err(_) => counts.refused += 1,
            }
            pool.quit(g).await;
        }

        let r = if rng.chance(0.85) {
            *rng.pick(&active[..active.len().min(HOT_ROOMS)])
        } else {
            *rng.pick(&active)
        };
        let room = &rooms[r];
        let conv = Conv::Room(room.clone());
        let lang = plan.rooms[r].lang;
        let bots: Vec<Pid> = if plan.rooms[r].announcements {
            members[r].iter().copied().take(1).collect()
        } else {
            members[r].iter().copied().filter(|&p| p != ME).collect()
        };
        let roll = rng.below(100);

        if roll < 10 && !plan.rooms[r].announcements {
            // Someone new joins: an identity to stay, or a guest who says
            // something and leaves a few steps later.
            if rng.chance(0.5) && !guests.is_empty() {
                let g = *rng.pick(&guests);
                if visits.iter().any(|v| v.0 == g) {
                    continue;
                }
                if pool
                    .call(g, Command::Join { room: room.clone() })
                    .await
                    .is_ok()
                {
                    counts.joins += 1;
                    let msg = message(&mut pool, conv, corpus::line(&mut rng, lang), None);
                    if pool.call(g, msg).await.is_ok() {
                        counts.posts += 1;
                    }
                    visits.push((g, r, rng.range(2, 8) as u32));
                } else {
                    counts.refused += 1;
                }
            } else {
                let outside: Vec<Pid> = hosted
                    .iter()
                    .copied()
                    .filter(|p| !members[r].contains(p))
                    .collect();
                if outside.is_empty() {
                    continue;
                }
                let p = *rng.pick(&outside);
                match pool.call(p, Command::Join { room: room.clone() }).await {
                    Ok(_) => {
                        counts.joins += 1;
                        members[r].push(p);
                    }
                    Err(_) => counts.refused += 1,
                }
            }
            continue;
        }
        if bots.is_empty() {
            continue;
        }

        if roll < 20 && !posted.is_empty() {
            // A bot fixes one of its recent messages.
            let i = rng.below(posted.len());
            let p = &posted[i];
            let text = corpus::edited(&mut rng, plan.rooms[p.room].lang, &p.text);
            let conv = Conv::Room(rooms[p.room].clone());
            let msg = message(&mut pool, conv, text, Some(Relation::Edit(p.seq)));
            let who = p.who;
            posted.remove(i);
            match pool.call(who, msg).await {
                Ok(_) => counts.edits += 1,
                Err(_) => counts.refused += 1,
            }
            continue;
        }

        let seen: Vec<_> = pool
            .seen
            .as_ref()
            .and_then(|s| s.get(room))
            .map(|l| l.iter().cloned().collect())
            .unwrap_or_default();
        if roll < 45 && !seen.is_empty() {
            // A reaction to something recent, the account's messages
            // included.
            let target = rng.pick(&seen).clone();
            let others: Vec<Pid> = members[r]
                .iter()
                .copied()
                .filter(|&p| p != ME && pool.actors[p].uid() != target.from)
                .collect();
            if others.is_empty() {
                continue;
            }
            let who = *rng.pick(&others);
            let emoji = (*rng.pick(corpus::REACTIONS)).to_owned();
            let msg = message(&mut pool, conv, emoji, Some(Relation::React(target.seq)));
            match pool.call(who, msg).await {
                Ok(_) => counts.reactions += 1,
                Err(_) => counts.refused += 1,
            }
            continue;
        }

        // A message, sometimes a reply: to the account's own messages
        // more often than to others'.
        let who = *rng.pick(&bots);
        let me = pool.actors[ME].uid();
        let reply = seen
            .iter()
            .rev()
            .find(|s| s.from == me && rng.chance(0.5))
            .or_else(|| (rng.chance(0.15)).then(|| seen.last()).flatten())
            .map(|s| s.seq);
        let text = if rng.chance(0.03) {
            let paragraphs = rng.range(2, 5) as usize;
            corpus::long_message(&mut rng, lang, paragraphs)
        } else {
            corpus::line(&mut rng, lang)
        };
        let msg = message(&mut pool, conv, text.clone(), reply.map(Relation::Reply));
        match pool.call(who, msg).await {
            Ok(ok) => {
                if reply.is_some() {
                    counts.replies += 1;
                } else {
                    counts.posts += 1;
                }
                if let Ok(Some(seq)) = ok.seq() {
                    posted.push_back(Posted {
                        who,
                        room: r,
                        seq,
                        text,
                    });
                    if posted.len() > 20 {
                        posted.pop_front();
                    }
                }
            }
            Err(_) => counts.refused += 1,
        }
    }
    for (g, r, _) in visits {
        let part = Command::Part {
            room: rooms[r].clone(),
            reason: String::new(),
        };
        let _ = pool.call(g, part).await;
    }
    pool.quit_all().await;
}

fn message(pool: &mut Pool<'_>, conv: Conv, text: String, relation: Option<Relation>) -> Command {
    Command::Msg {
        conv,
        text: escape(&text),
        relation,
        file: None,
        cid: Some(pool.cid()),
        id: None,
    }
}

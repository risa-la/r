//! Scenarios as plans: who exists, which rooms, and a schedule of what
//! each person does when, worked out from a seed before anything is sent.
//!
//! Times in a plan are `ago`: milliseconds before the end of seeding. The
//! seeder turns them into real times by subtracting them from the moment
//! seeding is meant to end, a little before it starts.

use std::fmt;

use crate::corpus::{self, Lang};
use crate::rng::Rng;

/// The scenarios.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Scenario {
    /// The account, in no conversation.
    Empty,
    /// About 40 rooms of every kind the chat list has to show.
    Busy,
    /// 3,000 rooms, for paging and the speed of the first read.
    Huge,
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Scenario::Empty => "empty",
            Scenario::Busy => "busy",
            Scenario::Huge => "huge",
        })
    }
}

/// A person, by index into [`Plan::people`]. The account is always 0.
pub type Pid = usize;

/// The account the apps sign in as.
pub const ME: Pid = 0;

/// The account's name, under the identity domain.
pub const ME_NAME: &str = "me";

/// The account's display name.
pub const ME_DISPLAY: &str = "Noor";

/// One person in a scenario.
#[derive(Debug, Clone)]
pub struct Person {
    /// The name: the part before the `@` of an identity, or a guest's
    /// name without the `~`.
    pub name: String,
    /// The display name (8.2); empty for none.
    pub display: String,
    /// Whether it is a guest (4.2) rather than a hosted identity (4.6).
    pub guest: bool,
}

/// One room in a scenario.
#[derive(Debug, Clone)]
pub struct RoomPlan {
    /// The room, with its `#`.
    pub name: String,
    pub lang: Lang,
    /// Identities in the room at the end, the account included unless it
    /// was kicked. The owner is first.
    pub members: Vec<Pid>,
    /// Messages from others the account has not read, when seeding ends.
    pub unread: usize,
    /// Only owners and moderators post (6.2 `send mods`).
    pub announcements: bool,
    /// The owner kicks the account once a client has seen the room: see
    /// [`crate::kick`]. Not part of the schedule.
    pub kicked: bool,
    /// How many messages it has, edits and reactions not counted.
    pub messages: usize,
    /// When its last message was, in ms before the end of seeding.
    pub last: u64,
}

/// What someone does.
#[derive(Debug, Clone)]
pub enum Act {
    /// Registers (4.6) and sets a display name. Before anything else.
    Register,
    /// Creates the room by joining it (6.1).
    Create,
    Topic(String),
    /// `SET send mods` (6.2).
    SendMods,
    /// Makes someone a moderator (6.3).
    Mod(Pid),
    Join,
    Part,
    /// Message number `n` of the room, maybe a reply to message `reply`.
    Msg {
        n: usize,
        text: String,
        reply: Option<usize>,
    },
    Edit {
        target: usize,
        text: String,
    },
    React {
        target: usize,
        emoji: String,
    },
    Delete {
        target: usize,
    },
    /// The account's read marker (7.4), set so that the room has
    /// [`RoomPlan::unread`] unread messages.
    Read,
}

/// One step of the schedule.
#[derive(Debug, Clone)]
pub struct Item {
    /// Milliseconds before the end of seeding.
    pub ago: u64,
    /// Who does it.
    pub who: Pid,
    /// The room, by index into [`Plan::rooms`]; unused for
    /// [`Act::Register`].
    pub room: usize,
    pub act: Act,
}

/// A whole scenario.
#[derive(Debug, Clone)]
pub struct Plan {
    pub people: Vec<Person>,
    pub rooms: Vec<RoomPlan>,
    /// The schedule, earliest first.
    pub items: Vec<Item>,
}

impl Plan {
    /// How many messages the plan sends, edits and reactions included.
    pub fn messages(&self) -> usize {
        self.items
            .iter()
            .filter(|i| {
                matches!(
                    i.act,
                    Act::Msg { .. } | Act::Edit { .. } | Act::React { .. }
                )
            })
            .count()
    }
}

const SEC: u64 = 1000;
const MIN: u64 = 60 * SEC;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;

/// Builds the plan of `scenario` from `seed`. The same seed always gives
/// the same plan.
pub fn build(scenario: Scenario, seed: u64) -> Plan {
    let mut plan = Plan {
        people: vec![Person {
            name: ME_NAME.to_owned(),
            display: ME_DISPLAY.to_owned(),
            guest: false,
        }],
        rooms: Vec::new(),
        items: Vec::new(),
    };
    match scenario {
        Scenario::Empty => {}
        Scenario::Busy => busy(&mut plan, seed),
        Scenario::Huge => huge(&mut plan, seed),
    }
    // Everyone registers first, a day before anything else happens.
    let first = plan.items.iter().map(|i| i.ago).max().unwrap_or(0) + DAY;
    let registrations = plan
        .people
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.guest)
        .map(|(who, _)| Item {
            ago: first,
            who,
            room: 0,
            act: Act::Register,
        })
        .collect::<Vec<_>>();
    plan.items.splice(0..0, registrations);
    // Earliest first; items of the same time keep the order they were
    // planned in, which puts a room's steps in the order they depend on.
    plan.items.sort_by_key(|i| std::cmp::Reverse(i.ago));
    plan
}

/// What a room in `busy` is like.
struct Spec {
    name: &'static str,
    lang: Lang,
    /// Messages, edits and reactions not counted.
    messages: usize,
    unread: usize,
    /// When its last message was, in minutes before the end.
    last_min: u64,
    /// Over how many days its messages are spread.
    span_days: u64,
    /// Identities in it besides the owner and the account.
    members: usize,
    guests: usize,
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    Announcements,
    Kicked,
    /// Very long messages.
    Long,
    /// Edited and reacted to a lot.
    Lively,
    /// Many deleted messages.
    Deletions,
    /// A long name and a long topic.
    LongTopic,
}

// A row of the table below, so its fields are its arguments.
#[allow(clippy::too_many_arguments)]
const fn spec(
    name: &'static str,
    lang: Lang,
    messages: usize,
    unread: usize,
    last_min: u64,
    span_days: u64,
    members: usize,
    guests: usize,
    kind: Kind,
) -> Spec {
    Spec {
        name,
        lang,
        messages,
        unread,
        last_min,
        span_days,
        members,
        guests,
        kind,
    }
}

const H: u64 = 60;
const D: u64 = 24 * H;

#[rustfmt::skip]
const BUSY: &[Spec] = &[
    spec("#general", Lang::En, 180, 3, 4, 30, 14, 2, Kind::Plain),
    spec("#majlis", Lang::Ar, 400, 27, 9, 35, 12, 2, Kind::Plain),
    spec("#announcements", Lang::Mix, 24, 2, 5 * H, 40, 18, 0, Kind::Announcements),
    spec("#random", Lang::En, 1300, 1200, 1, 21, 10, 3, Kind::Plain),
    spec("#qahwa", Lang::Ar, 1080, 1000, 16, 20, 9, 2, Kind::Plain),
    spec("#bugs", Lang::En, 1040, 999, 45, 25, 8, 1, Kind::Plain),
    spec("#thursday-football", Lang::Mix, 290, 250, 2 * H, 18, 11, 1, Kind::Plain),
    spec("#design-critique", Lang::En, 140, 100, 3 * H, 15, 7, 0, Kind::Plain),
    spec("#release-train", Lang::En, 160, 101, 5 * H, 20, 6, 0, Kind::Plain),
    spec("#arabic-typography", Lang::Mix, 120, 99, 8 * H, 30, 8, 1, Kind::Plain),
    spec("#hackspace", Lang::En, 90, 48, 20 * H, 30, 9, 2, Kind::Plain),
    spec("#iftar-planning", Lang::Ar, 60, 12, 26 * H, 10, 7, 1, Kind::Plain),
    spec("#book-club", Lang::Mix, 70, 9, 30 * H, 25, 6, 0, Kind::Plain),
    spec("#rust", Lang::En, 220, 5, 36 * H, 40, 10, 1, Kind::Plain),
    spec("#family", Lang::Ar, 150, 1, 2 * H, 30, 5, 0, Kind::Plain),
    spec("#a-room-whose-name-is-long-enough-to-need-truncating-everywhere", Lang::En, 15, 4, 50 * H, 5, 4, 0, Kind::LongTopic),
    spec("#photography", Lang::En, 40, 0, 60 * H, 30, 6, 0, Kind::Plain),
    spec("#dubai-meetup", Lang::Mix, 35, 0, 3 * D, 20, 8, 1, Kind::Plain),
    spec("#quran-study", Lang::Ar, 50, 0, 4 * D, 30, 6, 0, Kind::Plain),
    spec("#kitchen", Lang::En, 25, 0, 5 * D, 20, 4, 0, Kind::Plain),
    spec("#travel", Lang::Mix, 30, 0, 6 * D, 25, 5, 1, Kind::Plain),
    spec("#old-project", Lang::En, 20, 0, 41 * D, 10, 4, 0, Kind::Plain),
    spec("#off-topic-heated", Lang::En, 60, 7, 2 * D, 6, 6, 1, Kind::Kicked),
    spec("#new-room", Lang::En, 0, 0, 5 * H, 0, 3, 0, Kind::Plain),
    spec("#quiet-corner", Lang::Ar, 0, 0, 9 * D, 0, 2, 0, Kind::Plain),
    spec("#just-created", Lang::Mix, 0, 0, 20, 0, 1, 0, Kind::Plain),
    spec("#long-reads", Lang::Mix, 12, 2, 7 * H, 6, 4, 0, Kind::Long),
    spec("#edits-and-reactions", Lang::En, 50, 6, 4 * H, 2, 6, 0, Kind::Lively),
    spec("#moderation-log", Lang::En, 40, 3, 11 * H, 5, 5, 1, Kind::Deletions),
    spec("#gaming", Lang::En, 80, 15, 13 * H, 10, 6, 1, Kind::Plain),
    spec("#music", Lang::Mix, 45, 0, 7 * D, 20, 5, 0, Kind::Plain),
    spec("#ops-oncall", Lang::En, 200, 64, 30, 7, 5, 0, Kind::Plain),
    spec("#translations", Lang::Mix, 90, 33, 6 * H, 15, 6, 1, Kind::Plain),
    spec("#parents", Lang::Ar, 40, 2, 28 * H, 10, 5, 0, Kind::Plain),
    spec("#climbing", Lang::En, 30, 0, 12 * D, 30, 4, 0, Kind::Plain),
    spec("#garden", Lang::En, 18, 0, 15 * D, 25, 3, 0, Kind::Plain),
    spec("#movies", Lang::Mix, 55, 11, 40 * H, 15, 6, 1, Kind::Plain),
    spec("#jobs", Lang::En, 20, 0, 20 * D, 30, 5, 1, Kind::Plain),
    spec("#neighbours", Lang::Ar, 75, 0, 2 * D, 30, 7, 0, Kind::Plain),
    spec("#maktab", Lang::Ar, 110, 18, H, 10, 6, 0, Kind::Plain),
];

fn busy(plan: &mut Plan, seed: u64) {
    let hosted: Vec<Pid> = corpus::HOSTED
        .iter()
        .map(|(name, display)| add_person(plan, name, display, false))
        .collect();
    let guests: Vec<Pid> = corpus::GUESTS
        .iter()
        .map(|(name, display)| add_person(plan, name, display, true))
        .collect();
    for (i, s) in BUSY.iter().enumerate() {
        let mut rng = Rng::stream(seed, 1000 + i as u64);
        let mut pool = hosted.clone();
        rng.shuffle(&mut pool);
        let owner = pool[0];
        let mut members = vec![owner, ME];
        members.extend(pool[1..].iter().take(s.members));
        let mut gs = guests.clone();
        rng.shuffle(&mut gs);
        gs.truncate(s.guests);
        let room = RoomShape {
            name: s.name.to_owned(),
            lang: s.lang,
            members,
            guests: gs,
            messages: s.messages,
            unread: s.unread,
            last: s.last_min * MIN + 2 * MIN,
            span: (s.span_days * DAY).max(HOUR),
            announcements: s.kind == Kind::Announcements,
            kicked: s.kind == Kind::Kicked,
            long: s.kind == Kind::Long,
            long_topic: s.kind == Kind::LongTopic,
            edit_rate: if s.kind == Kind::Lively { 0.25 } else { 0.04 },
            react_rate: if s.kind == Kind::Lively { 0.7 } else { 0.12 },
            delete_rate: if s.kind == Kind::Deletions { 0.3 } else { 0.02 },
            topic: true,
        };
        add_room(plan, &mut rng, room);
    }
}

/// How many people `huge` has besides the account.
const HUGE_PEOPLE: usize = 150;
const HUGE_GUESTS: usize = 20;
const HUGE_ROOMS: usize = 3000;

fn huge(plan: &mut Plan, seed: u64) {
    let mut hosted = Vec::new();
    for i in 0..HUGE_PEOPLE {
        let (first, display) = corpus::FIRST_NAMES[i % corpus::FIRST_NAMES.len()];
        let n = i / corpus::FIRST_NAMES.len();
        let name = if n == 0 {
            first.to_owned()
        } else {
            format!("{first}{n}")
        };
        hosted.push(add_person(plan, &name, display, false));
    }
    let mut guests = Vec::new();
    for i in 0..HUGE_GUESTS {
        guests.push(add_person(plan, &format!("guest{i}"), "", true));
    }
    let mut names = std::collections::HashSet::new();
    for i in 0..HUGE_ROOMS {
        let mut room_rng = Rng::stream(seed, 100_000 + i as u64);
        let r = &mut room_rng;
        let mut name = format!(
            "#{}-{}",
            r.pick(corpus::ROOM_WORDS),
            r.pick(corpus::ROOM_KINDS)
        );
        if !names.insert(name.clone()) {
            name = format!("{name}-{i}");
            names.insert(name.clone());
        }
        let owner = *r.pick(&hosted);
        let mut members = vec![owner, ME];
        for _ in 0..r.range(0, 5) {
            let p = *r.pick(&hosted);
            if !members.contains(&p) {
                members.push(p);
            }
        }
        let guests_in = if r.chance(0.05) {
            vec![*r.pick(&guests)]
        } else {
            Vec::new()
        };
        // Most rooms are small and quiet; a few are busy.
        let messages = match r.below(100) {
            0..15 => 0,
            15..85 => r.range(1, 7) as usize,
            85..98 => r.range(7, 25) as usize,
            _ => r.range(25, 80) as usize,
        };
        let unread = if messages > 3 && r.chance(0.3) {
            r.range(1, messages as u64 - 1) as usize
        } else {
            0
        };
        // Recent activity is likelier than old.
        let last = (r.unit().powi(3) * 120.0 * DAY as f64) as u64 + 2 * MIN;
        let shape = RoomShape {
            name,
            lang: *r.pick(&[Lang::En, Lang::Ar, Lang::Mix]),
            members,
            guests: guests_in,
            messages,
            unread,
            last,
            span: r.range(HOUR, 20 * DAY),
            announcements: r.chance(0.01),
            kicked: r.chance(0.003),
            long: false,
            long_topic: false,
            edit_rate: 0.02,
            react_rate: 0.05,
            delete_rate: 0.01,
            topic: r.chance(0.5),
        };
        add_room(plan, r, shape);
    }
}

fn add_person(plan: &mut Plan, name: &str, display: &str, guest: bool) -> Pid {
    plan.people.push(Person {
        name: name.to_owned(),
        display: display.to_owned(),
        guest,
    });
    plan.people.len() - 1
}

/// Everything about a room that its schedule is made from.
struct RoomShape {
    name: String,
    lang: Lang,
    /// Identities: the owner first, then the account, then the rest.
    members: Vec<Pid>,
    guests: Vec<Pid>,
    messages: usize,
    unread: usize,
    /// When its last message is, before the end.
    last: u64,
    /// How long its messages are spread over.
    span: u64,
    announcements: bool,
    kicked: bool,
    long: bool,
    long_topic: bool,
    edit_rate: f64,
    react_rate: f64,
    delete_rate: f64,
    topic: bool,
}

/// Plans one room: its creation, members, messages, edits, reactions,
/// deletions, guests coming and going, and the account's read marker.
fn add_room(plan: &mut Plan, rng: &mut Rng, s: RoomShape) {
    let room = plan.rooms.len();
    let owner = s.members[0];
    let n = s.messages;
    let mut items: Vec<Item> = Vec::new();
    let mut push = |ago: u64, who: Pid, act: Act| {
        items.push(Item {
            ago,
            who,
            room,
            act,
        })
    };

    // When each message is sent: gaps of seconds, minutes and hours,
    // scaled to fill the room's span, the newest at `last`.
    let mut times = vec![0u64; n];
    if n > 0 {
        let gaps: Vec<f64> = (1..n)
            .map(|_| match rng.below(100) {
                0..70 => rng.range(5, 120) as f64,
                70..95 => rng.range(120, 3600) as f64,
                _ => rng.range(3600, 86_400) as f64,
            })
            .collect();
        let total: f64 = gaps.iter().sum::<f64>().max(1.0) * SEC as f64;
        let scale = (s.span as f64 / total).min(1.0);
        times[n - 1] = s.last;
        for k in (0..n - 1).rev() {
            let gap = ((gaps[k] * SEC as f64 * scale) as u64).max(2 * SEC);
            times[k] = times[k + 1] + gap;
        }
    }
    let first = times.first().copied().unwrap_or(s.last);
    let created = first + rng.range(HOUR, 2 * DAY);

    push(created, owner, Act::Create);
    if s.long_topic {
        push(created - SEC, owner, Act::Topic(corpus::long_topic()));
    } else if s.topic {
        push(created - SEC, owner, Act::Topic(corpus::topic(rng, s.lang)));
    }
    let mut posters = vec![owner];
    if s.announcements {
        push(created - 2 * SEC, owner, Act::SendMods);
        if let Some(&m) = s.members.get(2) {
            // After everyone has joined (below), before the first message.
            push(created - 55 * MIN, owner, Act::Mod(m));
            posters.push(m);
        }
    }
    for &m in &s.members[1..] {
        push(created - rng.range(10 * SEC, 50 * MIN), m, Act::Join);
    }
    if !s.announcements {
        posters = s.members.clone();
    }

    // Guests are around for a stretch of messages each.
    let windows: Vec<(Pid, usize, usize)> = s
        .guests
        .iter()
        .filter(|_| n > 2)
        .map(|&g| {
            let a = rng.below(n);
            let b = (a + rng.range(3, 40) as usize).min(n - 1);
            (g, a, b)
        })
        .collect();

    // The account does not post among the messages it has not read.
    let tail = n.saturating_sub(s.unread);
    // In some rooms with nothing unread, the account had the last word.
    let me_last = s.unread == 0 && !s.announcements && !s.kicked && n > 0 && rng.chance(0.35);
    let mut authors = vec![0usize; n];
    let mut texts = vec![String::new(); n];
    let mut deleted = vec![false; n];
    for k in 0..n {
        let mut candidates: Vec<Pid> = posters
            .iter()
            .copied()
            .filter(|&p| p != ME || k < tail)
            .collect();
        for &(g, a, b) in &windows {
            if (a..=b).contains(&k) && !s.announcements {
                candidates.push(g);
            }
        }
        let me_now = me_last && k == n - 1;
        let who = if me_now || (k < tail && posters.contains(&ME) && rng.chance(0.08)) {
            ME
        } else {
            let others: Vec<Pid> = candidates.iter().copied().filter(|&p| p != ME).collect();
            if others.is_empty() {
                // A room of the owner and the account only.
                if k < tail { ME } else { owner }
            } else {
                *rng.pick(&others)
            }
        };
        let text = if s.long && rng.chance(0.6) {
            let paragraphs = rng.range(2, 12) as usize;
            corpus::long_message(rng, s.lang, paragraphs)
        } else if rng.chance(0.01) {
            let paragraphs = rng.range(2, 5) as usize;
            corpus::long_message(rng, s.lang, paragraphs)
        } else {
            corpus::line(rng, s.lang)
        };
        let reply = if k > 0 && rng.chance(0.1) {
            let back = rng.range(1, 10.min(k as u64) + 1) as usize;
            let t = k - back;
            (!deleted[t]).then_some(t)
        } else {
            None
        };
        authors[k] = who;
        texts[k] = text.clone();
        push(times[k], who, Act::Msg { n: k, text, reply });
        // Deleted soon after, unless among the unread, so that the
        // count of unread stays as planned. The account is not around to
        // tidy up in a room it is kicked from.
        if k < tail && k + 1 < n && !(s.kicked && who == ME) && rng.chance(s.delete_rate) {
            deleted[k] = true;
            push(
                times[k]
                    .saturating_sub(rng.range(20 * SEC, 5 * MIN))
                    .max(SEC),
                who,
                Act::Delete { target: k },
            );
        }
    }
    // Replies planned before a deletion was decided keep their target;
    // edits and reactions only go to messages that stay.
    for k in 0..n {
        if deleted[k] {
            continue;
        }
        if !(s.kicked && authors[k] == ME) && rng.chance(s.edit_rate) {
            let text = corpus::edited(rng, s.lang, &texts[k]);
            push(
                times[k]
                    .saturating_sub(rng.range(30 * SEC, 10 * MIN))
                    .max(SEC),
                authors[k],
                Act::Edit { target: k, text },
            );
        }
        if rng.chance(s.react_rate) {
            for _ in 0..rng.range(1, 4) {
                let who = *rng.pick(&s.members);
                if who == authors[k] || (who == ME && (k >= tail || s.kicked)) {
                    continue;
                }
                push(
                    times[k]
                        .saturating_sub(rng.range(10 * SEC, 30 * MIN))
                        .max(SEC),
                    who,
                    Act::React {
                        target: k,
                        emoji: (*rng.pick(corpus::REACTIONS)).to_owned(),
                    },
                );
            }
        }
    }

    // Guests join before their first message and leave after their last
    // step in the room.
    for &(g, _, _) in &windows {
        let steps: Vec<u64> = items
            .iter()
            .filter(|i| i.who == g && i.room == room)
            .map(|i| i.ago)
            .collect();
        if steps.is_empty() {
            continue;
        }
        let first = *steps.iter().max().expect("not empty");
        let last = *steps.iter().min().expect("not empty");
        // After the room exists, before the guest's first step.
        let join = (first + rng.range(30 * SEC, 10 * MIN)).min(created - SEC);
        items.push(Item {
            ago: join,
            who: g,
            room,
            act: Act::Join,
        });
        items.push(Item {
            ago: last.saturating_sub(rng.range(MIN, 2 * HOUR)).max(SEC / 2),
            who: g,
            room,
            act: Act::Part,
        });
    }

    items.push(Item {
        ago: 0,
        who: ME,
        room,
        act: Act::Read,
    });

    plan.rooms.push(RoomPlan {
        name: s.name,
        lang: s.lang,
        members: s.members,
        unread: s.unread,
        announcements: s.announcements,
        kicked: s.kicked,
        messages: n,
        last: s.last,
    });
    plan.items.extend(items);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn plans_are_the_same_for_a_seed() {
        let a = build(Scenario::Busy, 1);
        let b = build(Scenario::Busy, 1);
        assert_eq!(a.items.len(), b.items.len());
        let c = build(Scenario::Busy, 2);
        assert_ne!(
            a.items.iter().map(|i| i.ago).collect::<Vec<_>>(),
            c.items.iter().map(|i| i.ago).collect::<Vec<_>>()
        );
    }

    #[test]
    fn room_names_are_valid_and_distinct() {
        for scenario in [Scenario::Busy, Scenario::Huge] {
            let plan = build(scenario, 1);
            let mut seen = HashSet::new();
            for r in &plan.rooms {
                assert!(
                    r.name.parse::<risala_proto::names::Room>().is_ok(),
                    "{}",
                    r.name
                );
                assert!(seen.insert(r.name.clone()), "{}", r.name);
            }
        }
        assert_eq!(build(Scenario::Busy, 1).rooms.len(), BUSY.len());
        assert_eq!(build(Scenario::Huge, 1).rooms.len(), HUGE_ROOMS);
        assert!(build(Scenario::Empty, 1).rooms.is_empty());
    }

    /// Every step comes after what it needs: rooms exist before anyone
    /// joins, people join before they post, and messages exist before
    /// they are edited, reacted to or deleted, by their authors.
    #[test]
    fn steps_come_in_an_order_that_works() {
        for scenario in [Scenario::Busy, Scenario::Huge] {
            let plan = build(scenario, 7);
            assert!(
                plan.items.windows(2).all(|w| w[0].ago >= w[1].ago),
                "not in order"
            );
            let mut registered = HashSet::new();
            let mut created = HashSet::new();
            let mut joined: HashSet<(usize, Pid)> = HashSet::new();
            let mut authors: HashMap<(usize, usize), Pid> = HashMap::new();
            let mut gone: HashSet<(usize, usize)> = HashSet::new();
            for i in &plan.items {
                let p = &plan.people[i.who];
                match &i.act {
                    Act::Register => {
                        registered.insert(i.who);
                    }
                    Act::Create => {
                        assert!(registered.contains(&i.who) && !p.guest);
                        assert!(created.insert(i.room));
                        joined.insert((i.room, i.who));
                    }
                    Act::Join => {
                        assert!(created.contains(&i.room));
                        assert!(p.guest || registered.contains(&i.who));
                        joined.insert((i.room, i.who));
                    }
                    Act::Part => {
                        assert!(joined.remove(&(i.room, i.who)));
                    }
                    Act::Msg { n, reply, .. } => {
                        assert!(
                            joined.contains(&(i.room, i.who)),
                            "{} not in {}",
                            p.name,
                            plan.rooms[i.room].name
                        );
                        if let Some(t) = reply {
                            assert!(authors.contains_key(&(i.room, *t)));
                        }
                        authors.insert((i.room, *n), i.who);
                    }
                    Act::Edit { target, .. } | Act::Delete { target } => {
                        assert!(joined.contains(&(i.room, i.who)));
                        assert_eq!(authors.get(&(i.room, *target)), Some(&i.who));
                        assert!(!gone.contains(&(i.room, *target)));
                        if matches!(i.act, Act::Delete { .. }) {
                            gone.insert((i.room, *target));
                        }
                    }
                    Act::React { target, .. } => {
                        assert!(joined.contains(&(i.room, i.who)));
                        assert!(authors.contains_key(&(i.room, *target)));
                        assert!(!gone.contains(&(i.room, *target)));
                    }
                    Act::Topic(_) | Act::SendMods => {
                        assert!(created.contains(&i.room));
                    }
                    Act::Mod(m) => {
                        assert!(joined.contains(&(i.room, *m)));
                    }
                    Act::Read => {
                        assert!(joined.contains(&(i.room, ME)));
                    }
                }
            }
            // Guests have left every room by the end.
            assert!(joined.iter().all(|&(_, p)| !plan.people[p].guest));
        }
    }

    #[test]
    fn busy_has_what_the_chat_list_needs() {
        let plan = build(Scenario::Busy, 1);
        let unread: Vec<usize> = plan.rooms.iter().map(|r| r.unread).collect();
        assert_eq!(unread.iter().max(), Some(&1200));
        assert!(unread.contains(&0) && unread.contains(&999) && unread.contains(&1000));
        assert!(plan.rooms.iter().any(|r| r.announcements));
        assert!(plan.rooms.iter().any(|r| r.kicked));
        let with_messages: HashSet<usize> = plan
            .items
            .iter()
            .filter(|i| matches!(i.act, Act::Msg { .. }))
            .map(|i| i.room)
            .collect();
        assert!(
            with_messages.len() < plan.rooms.len(),
            "no room without messages"
        );
        assert!(plan.items.iter().any(|i| matches!(i.act, Act::Edit { .. })));
        assert!(
            plan.items
                .iter()
                .any(|i| matches!(i.act, Act::Delete { .. }))
        );
        assert!(
            plan.items
                .iter()
                .any(|i| matches!(i.act, Act::React { .. }))
        );
        assert!(plan.people.iter().any(|p| p.guest));
    }
}

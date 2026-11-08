//! Server information, presence, push and reports (5.8, 6.1, 8, 9): INFO,
//! LIST, PRESENCE, WATCH, WHOIS, MEMBERS, PUSH, REPORT and RESOLVE.
//!
//! - INFO, LIST and MEMBERS are here; they read public rooms from the
//!   mailbox area's tables ([`MailboxStore`](crate::store::MailboxStore)).
//! - [`presence`]: PRESENCE, WATCH and WHOIS, and the PRESENCE lines (8.3).
//! - [`push`]: PUSH, and sending pushes (9).
//! - [`report`]: REPORT, RESOLVE and the operators' report lines (5.8).
//!
//! # Hooks for other areas
//!
//! - [`signed_in`]: a connection has signed in (`command::route` calls it
//!   after AUTH and REGISTER), for presence.
//! - [`heard`]: a line arrived on a connection (`command::route`), for
//!   the liveness check before a push (9.2).
//! - [`post_kept`]: a mailbox got a kept post (the mailbox area's POST),
//!   for mailbox pushes (9.2).
//! - [`welcome_arrived`]: a device got a Welcome (the keys area's WELCOME
//!   PUT), for account pushes (9.2).
//! - [`follow_quiet`] and [`unfollow`]: a connection follows a mailbox
//!   with `quiet=<tag>`, or stops (the mailbox area's FOLLOW and UNFOLLOW,
//!   7.1, 9.2).
//! - [`device_removed`] and [`identity_removed`]: a device or identity is
//!   gone (the identity area), so its account subscriptions go too (9.1).
//! - [`mailbox_dropped`]: a mailbox was deleted, so its subscriptions go
//!   too (10.4).

pub(crate) mod presence;
pub(crate) mod push;
pub(crate) mod report;

use std::num::NonZeroU64;
use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use risala_proto::names::Room;
use risala_proto::server::{OkResponse, Register, ServerLine};
use risala_proto::types::{GuestAccess, Presence};

use super::command::{Cx, Reply, err, misrouted};
use super::state::{ConnEntry, Who};
use super::{Inner, keys, mailbox};
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::{PublicRoomRecord, Store, StoreError};

pub(crate) use presence::signed_in;
#[allow(
    unused_imports,
    reason = "hooks the other areas call as they are built (docs/plans/M5b.md, SV1-SV4)"
)]
pub(crate) use push::{
    device_removed, follow_quiet, heard, identity_removed, mailbox_dropped, post_kept, unfollow,
    welcome_arrived,
};

/// The default page of LIST and ADMIN ROOMS (6.1).
pub(crate) const DEFAULT_LIST: u64 = 100;

/// What the misc area keeps in memory.
pub(crate) struct State {
    /// Who is online, and who watches whom (8.3).
    pub(crate) presence: presence::State,
    /// Push subscriptions' timing, and the pusher (9).
    pub(crate) push: push::State,
    /// Reports' rate limit (5.8).
    pub(crate) reports: report::State,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("misc::State").finish_non_exhaustive()
    }
}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {
            presence: presence::State::default(),
            push: push::State::new(config),
            reports: report::State::default(),
        })
    }
}

/// What the misc area keeps about one connection. Watch lists and quiet
/// follows live in the area's own state, by connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles INFO, LIST, PRESENCE, WATCH, WHOIS, MEMBERS, PUSH, REPORT and
/// RESOLVE.
pub(super) async fn handle(cx: &Cx, command: Command) -> Reply {
    match command {
        Command::Info { room: None } => info(cx).await,
        Command::Info { room: Some(room) } => room_info(cx, room).await,
        Command::List { after, limit } => {
            list(cx, after, limit, matches!(cx.who, Who::Guest(_))).await
        }
        Command::Presence { on } => presence::set(cx, on).await,
        Command::Watch { uids } => presence::watch(cx, uids).await,
        Command::Whois { uid } => presence::whois(cx, uid).await,
        Command::Members { room } => members(cx, room).await,
        Command::Push(push) => push::handle(cx, push).await,
        Command::Report { mailbox, report } => report::report(cx, mailbox, report).await,
        Command::Resolve { id } => report::resolve(cx, id).await,
        other => misrouted("misc", &other),
    }
}

/// `INFO` (8.5): the server's values, in the order of 8.5's table.
async fn info(cx: &Cx) -> Reply {
    let inner = &cx.inner;
    let settings = inner.settings();
    let register = match &inner.identity_domain {
        Some(domain) if settings.registration => Register::Domain(domain.clone()),
        _ => Register::No,
    };
    let mut ok = OkResponse::new()
        .with_version(risala_proto::PROTOCOL_VERSION)
        .with_anon(settings.anon)
        .with_guests(settings.guests)
        .with_register(&register);
    match (inner.keylog.url(), inner.keylog.current_log()) {
        (Some(url), Some(key)) => {
            ok = ok
                .with_log(&risala_proto::server::Log::Url(url))
                .with_log_key(&key);
        }
        _ => ok = ok.with_log(&risala_proto::server::Log::No),
    }
    ok = ok.with_retention(settings.retention);
    if let Some(quota) = mailbox::quota(inner) {
        ok = ok.with_quota(quota);
    }
    ok = ok.with_push(inner.config.push.enabled);
    let files = keys::info(inner);
    ok = ok.with_upload(files.upload);
    if let Some(blobs) = &files.blobs {
        ok = ok.with_blobs(blobs).map_err(|e| {
            tracing::error!("blobs= is not a token: {e}");
            err(ErrorCode::Internal)
        })?;
    }
    if !files.files.is_empty() {
        ok = ok.with_files(&files.files).map_err(|e| {
            tracing::error!("files= does not fit: {e}");
            err(ErrorCode::Internal)
        })?;
    }
    Ok(ok)
}

/// The public room `room`, as a connection of kind `who` may see it: a
/// guest does not see rooms whose `guests` setting is `none`, as in LIST
/// (6.1).
async fn visible_room(cx: &Cx, room: Room) -> Result<PublicRoomRecord, risala_proto::server::ErrResponse> {
    let found = cx.db(move |store| store.public_room(&room)).await?;
    match found {
        // 6.1 says only that a guest's LIST leaves such rooms out; INFO and
        // MEMBERS do the same, so that they show a guest nothing LIST
        // hides.
        Some(r) if matches!(cx.who, Who::Guest(_)) && r.guests == GuestAccess::None => {
            Err(err(ErrorCode::NotFound))
        }
        Some(r) => Ok(r),
        None => Err(err(ErrorCode::NotFound)),
    }
}

/// `INFO <room>` (6.1): one public room's box, members and epoch.
async fn room_info(cx: &Cx, room: Room) -> Reply {
    let r = visible_room(cx, room).await?;
    Ok(OkResponse::new()
        .with_mailbox(&r.mailbox)
        .with_members(r.members)
        .with_epoch(r.epoch))
}

/// `LIST` (6.1) and `ADMIN ROOMS` (10.4): a page of public rooms, as ROOM
/// lines, then `OK more=`. A guest's list leaves out rooms whose `guests`
/// setting is `none`.
pub(crate) async fn list(
    cx: &Cx,
    after: Option<Room>,
    limit: Option<NonZeroU64>,
    for_guest: bool,
) -> Reply {
    let limit = limit
        .map_or(DEFAULT_LIST, NonZeroU64::get)
        .min(cx.inner.config.limits.max_list);
    let (rooms, more) = cx
        .db(move |store| store.public_rooms(after.as_ref(), limit, for_guest))
        .await?;
    for r in rooms {
        cx.send(ServerLine::Room {
            room: r.room,
            mailbox: r.mailbox,
            members: r.members,
            topic: r.topic,
        });
    }
    Ok(OkResponse::new().with_more(more))
}

/// `MEMBERS <room>` (8.3): one MEMBER line for each identity and guest
/// with a leaf in a public room's group.
async fn members(cx: &Cx, room: Room) -> Reply {
    let r = visible_room(cx, room).await?;
    let mailbox = r.mailbox;
    let members = cx.db(move |store| store.room_members(&mailbox)).await?;
    for (i, (uid, role)) in members.into_iter().enumerate() {
        if i > 0 && i % 64 == 0 {
            cx.wait_for_room().await;
        }
        let presence = presence::presence_of(&cx.inner, &uid);
        cx.send(ServerLine::Member {
            room: r.room.clone(),
            uid,
            role,
            presence,
        });
    }
    Ok(OkResponse::new())
}

/// Sends `line` to every connection of every operator (5.8), except
/// connection `except`.
pub(crate) fn to_operators(inner: &Inner, line: &ServerLine, except: Option<ConnId>) {
    let out = crate::handler::OutLine::new(risala_proto::server::ServerMessage::new(line.clone()));
    let reg = inner.reg();
    for conn in reg.conns.iter().filter_map(|(id, conn)| {
        (Some(*id) != except && !conn.detached).then_some(conn)
    }) {
        if let Who::SignedIn(device) = &conn.who
            && super::admin::is_operator(inner, &device.uid)
        {
            conn.handle.send_line(out.clone());
        }
    }
}

/// Connection `id` has closed: it watches nothing, follows nothing
/// quietly, and its identity may have gone offline (8.3).
pub(super) fn conn_closed(inner: &Arc<Inner>, id: ConnId, conn: &ConnEntry) {
    presence::conn_closed(inner, id, conn);
    push::conn_closed(inner, id);
}

/// The area's background work: expiring mailbox subscriptions (9.1), and
/// forgetting push timing that no longer matters (9.2).
pub(super) async fn maintain(inner: Arc<Inner>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tick.tick().await;
        push::maintain_once(&inner).await;
    }
}

/// The presence that MEMBER, USER and PRESENCE lines show for `uid` (8.3):
/// a guest has none, and so shows `offline`.
pub(crate) fn shown_presence(online: bool) -> Presence {
    if online {
        Presence::Online
    } else {
        Presence::Offline
    }
}

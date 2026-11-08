//! Server administration (Section 10): the ADMIN commands but ADMIN
//! UNREGISTER (which is `identity`'s), operators and server bans.
//!
//! The routing in [`command`](super::command) lets only operators send
//! ADMIN commands: anyone else gets `ERR forbidden` (Section 10).
//! Operators are those in the configuration and those added with
//! ADMIN OP, which the store keeps ([`AdminStore`](crate::store::AdminStore)).
//!
//! Server bans (10.2) are kept in the store and in memory:
//!
//! - identity and domain bans stop identities from signing in
//!   ([`banned`], which AUTH and REGISTER ask after checking the
//!   signature) and their devices from joining public rooms (the mailbox
//!   area asks the same), except operators named in the configuration;
//! - address bans stop anonymous and guest connections from inside them
//!   ([`refuses_address`]). Signed-in connections are not affected.
//!
//! # Hooks for other areas
//!
//! - [`banned`]: AUTH and REGISTER (identity), and joins of public rooms
//!   (mailbox).
//! - [`refuses_address`]: ANON and GUEST (session).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use risala_proto::command::{AdminCommand, DropTarget};
use risala_proto::error::ErrorCode;
use risala_proto::mls::Pseudonym;
use risala_proto::names::{BoxName, IpPrefix, ServerBanTarget, Uid};
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::ServerSetting;

use super::Inner;
use super::command::{Cx, Reply, err, misrouted};
use super::state::{ConnEntry, Who};
use super::{mailbox, misc};
use crate::config::Config;
use crate::handler::{ConnId, OutLine};
use crate::store::{Store, StoreError};

/// The BYE text for connections closed by a server ban without a reason
/// (10.2).
pub const BYE_BANNED: &str = "banned from this server";

/// The BYE text for connections closed by ADMIN DISCONNECT without a
/// reason (10.3).
pub const BYE_DISCONNECTED: &str = "disconnected by an operator";

/// The BYE text for guests when `ADMIN SET guests no` (10.6).
pub const BYE_NO_GUESTS: &str = "guests are not allowed";

/// The BYE text for anonymous connections when `ADMIN SET anon no` (10.6).
pub const BYE_NO_ANON: &str = "anonymous connections are off";

/// How long a MUTE lasts by default, in hours (6.4).
const DEFAULT_MUTE_HOURS: u64 = 24;

/// One day, the length of a period (12.10).
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// What the admin area keeps in memory.
#[derive(Debug)]
pub(crate) struct State {
    /// The operators named in the configuration, who cannot be removed
    /// with ADMIN DEOP or banned (10.1, 10.2).
    configured: BTreeSet<Uid>,
    /// Every operator: those configured, and those added with ADMIN OP.
    operators: RwLock<BTreeSet<Uid>>,
    /// Every server ban, as the store has them (10.2).
    bans: RwLock<Vec<ServerBanTarget>>,
}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(config: &Config, store: &dyn Store) -> Result<State, StoreError> {
        let configured: BTreeSet<Uid> = config.operators().iter().map(|op| op.to_uid()).collect();
        let mut operators = configured.clone();
        operators.extend(store.operators()?);
        let bans = store
            .server_bans()?
            .into_iter()
            .map(|(target, _)| target)
            .collect();
        Ok(State {
            configured,
            operators: RwLock::new(operators),
            bans: RwLock::new(bans),
        })
    }

    fn operators(&self) -> BTreeSet<Uid> {
        self.operators
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn bans(&self) -> std::sync::RwLockReadGuard<'_, Vec<ServerBanTarget>> {
        self.bans.read().unwrap_or_else(|e| e.into_inner())
    }

    fn bans_mut(&self) -> std::sync::RwLockWriteGuard<'_, Vec<ServerBanTarget>> {
        self.bans.write().unwrap_or_else(|e| e.into_inner())
    }

    fn operators_mut(&self) -> std::sync::RwLockWriteGuard<'_, BTreeSet<Uid>> {
        self.operators.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// What the admin area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Whether `uid` is an operator (10.1).
pub(crate) fn is_operator(inner: &Inner, uid: &Uid) -> bool {
    inner
        .admin
        .operators
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains(uid)
}

/// Whether `uid` is an operator named in the configuration (10.1).
pub(crate) fn is_configured_operator(inner: &Inner, uid: &Uid) -> bool {
    inner.admin.configured.contains(uid)
}

/// Whether an identity or domain ban covers `uid` (10.2): it cannot sign
/// in, and its devices cannot join public rooms. Server bans never apply
/// to operators named in the configuration. AUTH and REGISTER ask this
/// only once the signature verifies (10.2).
pub(crate) fn banned(inner: &Inner, uid: &Uid) -> bool {
    !is_configured_operator(inner, uid) && inner.admin.bans().iter().any(|b| b.covers_uid(uid))
}

/// Why anonymous and guest connections from `ip` are refused, if they
/// are: an address ban (10.2).
pub(crate) fn refuses_address(inner: &Inner, ip: IpAddr) -> Option<&'static str> {
    inner
        .admin
        .bans()
        .iter()
        .any(|b| b.covers_address(ip))
        .then_some("this network is banned")
}

/// Handles the ADMIN commands but ADMIN UNREGISTER, from an operator.
pub(super) async fn handle(cx: &Cx, command: AdminCommand) -> Reply {
    match command {
        AdminCommand::Ops => ops(cx),
        AdminCommand::Op { uid } => op(cx, uid).await,
        AdminCommand::Deop { uid } => deop(cx, uid).await,
        AdminCommand::Ban { target, reason } => ban(cx, target, reason).await,
        AdminCommand::Unban { target } => unban(cx, target).await,
        AdminCommand::Bans => bans(cx).await,
        AdminCommand::Who => who(cx),
        AdminCommand::Disconnect { uid, reason } => disconnect(cx, uid, reason).await,
        AdminCommand::Notice { message } => notice(cx, message),
        AdminCommand::Rooms { after, limit } => misc::list(cx, after, limit, false).await,
        AdminCommand::Drop { target, reason } => drop_target(cx, target, reason).await,
        AdminCommand::Mute {
            mailbox,
            pseudonym,
            hours,
        } => mute(cx, mailbox, pseudonym, hours).await,
        AdminCommand::Unmute { mailbox, pseudonym } => unmute(cx, mailbox, pseudonym).await,
        AdminCommand::Reports => misc::report::admin_reports(cx).await,
        AdminCommand::Set(setting) => set(cx, setting).await,
        AdminCommand::Unregister { .. } => {
            misrouted("admin", &risala_proto::command::Command::Admin(command))
        }
    }
}

// ---------------------------------------------------------------------------
// 10.1 Operators

/// `ADMIN OPS`: one OP line per operator.
fn ops(cx: &Cx) -> Reply {
    for uid in cx.inner.admin.operators() {
        cx.send(ServerLine::Op { uid });
    }
    Ok(OkResponse::new())
}

/// `ADMIN OP <uid>`: makes an identity an operator. Guests cannot be
/// operators, nor can identities a server ban covers (`ERR forbidden`).
async fn op(cx: &Cx, uid: Uid) -> Reply {
    if uid.is_guest() {
        return Err(err(ErrorCode::Forbidden).with_message("guests cannot be operators"));
    }
    if banned(&cx.inner, &uid) {
        return Err(err(ErrorCode::Forbidden).with_message("lift the ban first"));
    }
    if is_operator(&cx.inner, &uid) {
        return Ok(OkResponse::new());
    }
    let now = cx.inner.now();
    let who = uid.clone();
    cx.db(move |store| store.add_operator(&who, now)).await?;
    cx.inner.admin.operators_mut().insert(uid);
    tracing::info!("operator added");
    Ok(OkResponse::new())
}

/// `ADMIN DEOP <uid>`: removes an operator added with ADMIN OP.
async fn deop(cx: &Cx, uid: Uid) -> Reply {
    if is_configured_operator(&cx.inner, &uid) {
        return Err(err(ErrorCode::Forbidden).with_message("named in the configuration"));
    }
    if !is_operator(&cx.inner, &uid) {
        return Err(err(ErrorCode::NotFound));
    }
    let who = uid.clone();
    cx.db(move |store| store.remove_operator(&who)).await?;
    cx.inner.admin.operators_mut().remove(&uid);
    tracing::info!("operator removed");
    Ok(OkResponse::new())
}

// ---------------------------------------------------------------------------
// 10.2 Bans

/// The network a guest's ban covers (10.2): its IPv4 address, or the IPv6
/// /64 that holds its address.
fn guest_ban(ip: IpAddr) -> ServerBanTarget {
    match ip.to_canonical() {
        IpAddr::V4(v4) => ServerBanTarget::Address(IpAddr::V4(v4)),
        v6 => ServerBanTarget::Prefix(IpPrefix::new(v6, 64).expect("64 fits an IPv6 address")),
    }
}

/// `ADMIN BAN <target> [<reason...>]` (10.2).
async fn ban(cx: &Cx, target: ServerBanTarget, reason: String) -> Reply {
    let inner = &cx.inner;
    let target = match target {
        ServerBanTarget::Guest(name) => {
            let uid = Uid::guest(&name);
            let address = inner.reg().sessions.get(&uid).map(|s| s.address);
            match address {
                Some(ip) => guest_ban(ip),
                None => return Err(err(ErrorCode::NotFound)),
            }
        }
        other => other,
    };
    // Operators cannot be banned: lift them first (10.2).
    if inner
        .admin
        .operators()
        .iter()
        .any(|op| target.covers_uid(op))
    {
        return Err(err(ErrorCode::Forbidden).with_message("the ban covers an operator"));
    }
    let now = inner.now();
    let (stored, why) = (target.clone(), reason.clone());
    let added = cx
        .db(move |store| store.add_server_ban(&stored, &why, now))
        .await?;
    if added {
        inner.admin.bans_mut().push(target.clone());
    }
    tracing::info!("server ban");
    let bye = if reason.is_empty() {
        BYE_BANNED.to_owned()
    } else {
        reason
    };
    match &target {
        ServerBanTarget::Identity(_) | ServerBanTarget::Domain(_) => {
            // A banned identity's signed-in connections close (10.2).
            let mut reg = inner.reg();
            let ids: Vec<ConnId> = reg
                .conns
                .iter()
                .filter(|(_, c)| {
                    !c.detached
                        && matches!(&c.who, Who::SignedIn(d)
                            if target.covers_uid(&d.uid) && !is_configured_operator(inner, &d.uid))
                })
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                reg.detach(id, &bye);
            }
        }
        _ => close_from(inner, &target, &bye).await,
    }
    Ok(OkResponse::new())
}

/// A new address ban (10.2): closes the anonymous and guest connections
/// from inside it, and ends the guest sessions whose last connection came
/// from inside it.
async fn close_from(inner: &Arc<Inner>, target: &ServerBanTarget, bye: &str) {
    let guests: Vec<Uid> = {
        let mut reg = inner.reg();
        let ids: Vec<ConnId> = reg
            .conns
            .iter()
            .filter(|(_, c)| {
                !c.detached && c.who == Who::Anonymous && target.covers_address(c.info.peer.ip())
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            reg.detach(id, bye);
        }
        // A guest's connection closes with its session, which ends below:
        // its address is that of the session's last connection.
        reg.sessions
            .iter()
            .filter(|(_, s)| target.covers_address(s.address))
            .map(|(uid, _)| uid.clone())
            .collect()
    };
    for uid in guests {
        inner.end_guest_session(&uid, bye).await;
    }
}

/// `ADMIN UNBAN <target>` (10.2). A guest's ban is lifted by its address,
/// so `~name` is never banned.
async fn unban(cx: &Cx, target: ServerBanTarget) -> Reply {
    if matches!(target, ServerBanTarget::Guest(_)) {
        return Err(err(ErrorCode::NotFound).with_message("unban the guest's address"));
    }
    let stored = target.clone();
    if !cx.db(move |store| store.remove_server_ban(&stored)).await? {
        return Err(err(ErrorCode::NotFound));
    }
    cx.inner.admin.bans_mut().retain(|b| *b != target);
    tracing::info!("server ban lifted");
    Ok(OkResponse::new())
}

/// `ADMIN BANS` (10.2): one SERVERBAN line per ban.
async fn bans(cx: &Cx) -> Reply {
    let bans = cx.db(|store| store.server_bans()).await?;
    for (target, reason) in bans {
        cx.send(ServerLine::ServerBan { target, reason });
    }
    Ok(OkResponse::new())
}

// ---------------------------------------------------------------------------
// 10.3 Connections

/// `ADMIN WHO` (10.3): one CONNECTION line per open connection.
fn who(cx: &Cx) -> Reply {
    let mut lines: Vec<(ConnId, ServerLine)> = {
        let reg = cx.inner.reg();
        reg.conns
            .iter()
            .filter(|(_, c)| !c.detached)
            .map(|(id, c)| {
                let line = ServerLine::Connection {
                    uid: c.who.uid().cloned(),
                    address: c.info.peer.ip(),
                    port: Some(c.info.peer.port()),
                    since: c.info.since,
                };
                (*id, line)
            })
            .collect()
    };
    lines.sort_by_key(|(id, _)| *id);
    for (_, line) in lines {
        cx.send(line);
    }
    Ok(OkResponse::new())
}

/// `ADMIN DISCONNECT <uid> [<reason...>]` (10.3): closes every connection
/// of `uid` with BYE, and ends a guest's session.
async fn disconnect(cx: &Cx, uid: Uid, reason: String) -> Reply {
    let bye = if reason.is_empty() {
        BYE_DISCONNECTED.to_owned()
    } else {
        reason
    };
    // A guest's connection closes with its session (4.2).
    let ended = uid.is_guest() && cx.inner.end_guest_session(&uid, &bye).await;
    let closed = {
        let mut reg = cx.inner.reg();
        let ids: Vec<ConnId> = reg
            .by_uid
            .get(&uid)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default();
        for id in &ids {
            reg.detach(*id, &bye);
        }
        !ids.is_empty()
    };
    if !closed && !ended {
        return Err(err(ErrorCode::NotFound));
    }
    tracing::info!("disconnected by an operator");
    Ok(OkResponse::new())
}

/// `ADMIN NOTICE <message...>` (10.3): a NOTICE to every open connection.
fn notice(cx: &Cx, message: String) -> Reply {
    let line = OutLine::new(ServerMessage::new(ServerLine::Notice { message }));
    let reg = cx.inner.reg();
    for conn in reg.conns.values().filter(|c| !c.detached) {
        conn.handle.send_line(line.clone());
    }
    Ok(OkResponse::new())
}

// ---------------------------------------------------------------------------
// 10.4 Rooms and mailboxes

/// `ADMIN DROP <target> [<reason...>]` (10.4): deletes a public room or any
/// mailbox, with its posts. Its followers get DROP, and its push
/// subscriptions go.
async fn drop_target(cx: &Cx, target: DropTarget, reason: String) -> Reply {
    let mailbox = match target {
        DropTarget::Mailbox(mailbox) => mailbox,
        DropTarget::Room(room) => match cx.db(move |store| store.public_room(&room)).await? {
            Some(room) => room.mailbox,
            None => return Err(err(ErrorCode::NotFound)),
        },
    };
    if !cx.db(move |store| store.drop_mailbox(&mailbox)).await? {
        return Err(err(ErrorCode::NotFound));
    }
    misc::mailbox_dropped(&cx.inner, mailbox).await;
    let line = OutLine::new(ServerMessage::new(ServerLine::Drop { mailbox, reason }));
    let followers = cx.inner.mailbox.followers(&mailbox);
    {
        let reg = cx.inner.reg();
        for conn in followers.iter().filter_map(|id| reg.conns.get(id)) {
            conn.handle.send_line(line.clone());
        }
    }
    for conn in followers {
        misc::unfollow(&cx.inner, conn, &mailbox);
    }
    mailbox::dropped(&cx.inner, &mailbox);
    tracing::info!("mailbox dropped");
    Ok(OkResponse::new())
}

/// The end of the period (12.10) that `now` is in: the next UTC midnight.
fn end_of_period(now: Timestamp) -> Timestamp {
    let ms = now.unix_millis();
    Timestamp::from_unix_millis((ms / DAY_MS + 1) * DAY_MS).unwrap_or(Timestamp::MAX)
}

/// When a mute made at `now` for `hours` ends (6.4, 10.4): after the
/// hours, 24 by default, and in an epochal group at the end of the current
/// period at the latest.
pub(crate) fn mute_until(now: Timestamp, hours: Option<NonZeroU64>, epochal: bool) -> Timestamp {
    let hours = hours.map_or(DEFAULT_MUTE_HOURS, NonZeroU64::get);
    let after = now
        .checked_add(Duration::from_secs(hours.saturating_mul(3600)))
        .unwrap_or(Timestamp::MAX);
    if epochal {
        after.min(end_of_period(now))
    } else {
        after
    }
}

/// `ADMIN MUTE <box> <pseudonym> [hours=<n>]` (10.4): MUTE (6.4) for any
/// mailbox.
async fn mute(cx: &Cx, mailbox: BoxName, pseudonym: Pseudonym, hours: Option<NonZeroU64>) -> Reply {
    let Some(record) = cx.db(move |store| store.mailbox(&mailbox)).await? else {
        return Err(err(ErrorCode::NotFound));
    };
    // A mute ends with the period only in a group whose `confirm` is
    // `epochal` (10.4). The server can read `confirm` only in public
    // rooms, which are always epochal (6.1); in any other mailbox the mute
    // lasts its hours.
    let until = mute_until(cx.inner.now(), hours, record.room.is_some());
    if !cx
        .db(move |store| store.set_mute(&mailbox, &pseudonym, until))
        .await?
    {
        return Err(err(ErrorCode::NotFound));
    }
    tracing::info!("pseudonym muted by an operator");
    Ok(OkResponse::new())
}

/// `ADMIN UNMUTE <box> <pseudonym>` (10.4). A pseudonym that is not muted
/// there gets `ERR not-found`, as ADMIN UNBAN does (10.2).
async fn unmute(cx: &Cx, mailbox: BoxName, pseudonym: Pseudonym) -> Reply {
    if !cx
        .db(move |store| store.remove_mute(&mailbox, &pseudonym))
        .await?
    {
        return Err(err(ErrorCode::NotFound));
    }
    Ok(OkResponse::new())
}

// ---------------------------------------------------------------------------
// 10.6 Settings

/// `ADMIN SET <key> [<value...>]` (10.6). A key this server does not know
/// gets `ERR not-supported`, since settings not listed in 10.6 are left to
/// the configuration.
async fn set(cx: &Cx, setting: ServerSetting) -> Reply {
    if !setting.is_known() {
        return Err(err(ErrorCode::NotSupported));
    }
    let stored = setting.clone();
    if !cx.db(move |store| store.save_setting(&stored)).await? {
        return Err(err(ErrorCode::NotSupported));
    }
    let inner = &cx.inner;
    inner.update_settings(|settings| {
        settings.apply(&setting);
    });
    tracing::info!(key = setting.key(), "server setting changed");
    match setting {
        // Every guest session ends, connected or waiting (10.6).
        ServerSetting::Guests(false) => {
            let uids: Vec<Uid> = inner.reg().sessions.keys().cloned().collect();
            for uid in uids {
                inner.end_guest_session(&uid, BYE_NO_GUESTS).await;
            }
        }
        // Every anonymous connection closes (10.6).
        ServerSetting::Anon(false) => {
            let mut reg = inner.reg();
            let ids: Vec<ConnId> = reg
                .conns
                .iter()
                .filter(|(_, c)| !c.detached && c.who == Who::Anonymous)
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                reg.detach(id, BYE_NO_ANON);
            }
        }
        // A shorter retention applies to posts already stored (10.6): the
        // mailbox area's retention reads the setting each time it runs.
        _ => {}
    }
    Ok(OkResponse::new())
}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work.
pub(super) async fn maintain(_inner: Arc<Inner>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn mutes_end_with_the_period_in_epochal_groups() {
        let now = t("2026-11-09T12:00:00.000Z");
        assert_eq!(mute_until(now, None, true), t("2026-11-10T00:00:00.000Z"));
        assert_eq!(mute_until(now, None, false), t("2026-11-10T12:00:00.000Z"));
        assert_eq!(
            mute_until(now, NonZeroU64::new(3), true),
            t("2026-11-09T15:00:00.000Z")
        );
        let late = t("2026-11-09T23:59:59.999Z");
        assert_eq!(
            mute_until(late, NonZeroU64::new(1), true),
            t("2026-11-10T00:00:00.000Z")
        );
        assert_eq!(
            mute_until(now, NonZeroU64::new(u64::MAX), true),
            t("2026-11-10T00:00:00.000Z")
        );
        assert_eq!(
            mute_until(now, NonZeroU64::new(u64::MAX), false),
            Timestamp::MAX
        );
    }

    #[test]
    fn guest_bans_cover_the_address_or_its_64() {
        assert_eq!(
            guest_ban("203.0.113.7".parse().unwrap()).to_string(),
            "203.0.113.7"
        );
        assert_eq!(
            guest_ban("::ffff:203.0.113.7".parse().unwrap()).to_string(),
            "203.0.113.7"
        );
        assert_eq!(
            guest_ban("2001:db8:1:2:3:4:5:6".parse().unwrap()).to_string(),
            "2001:db8:1:2::/64"
        );
    }
}

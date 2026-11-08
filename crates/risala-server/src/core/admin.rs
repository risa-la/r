//! Server administration (Section 10): the ADMIN commands, except
//! `ADMIN PURGE`, which is in [`super::messages`], and `ADMIN REPORTS`,
//! `ROOMS` and `DROP`, which are in [`super::reports`].
//!
//! # Bans and sign-ins
//!
//! Server bans (10.2) are stored, and kept in memory too
//! ([`AdminState`]), so that AUTH, REGISTER and GUEST can check them while
//! they hold the registry's lock, just before they sign a connection in.
//! ADMIN BAN changes the bans in memory first and only then, under the
//! registry's lock, looks for the connections to close. So a sign-in
//! either comes first, and its connection is closed, or comes after, and
//! is refused. `ADMIN SET guests no` works the same way, with the server
//! settings.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use risala_proto::command::{AdminCommand, KeyCommand};
use risala_proto::error::ErrorCode;
use risala_proto::names::{IpPrefix, ServerBanTarget, Uid};
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use risala_proto::types::ServerSetting;

use super::commands::{Fail, Outcome, Reply, fail, not_supported, respond};
use super::{Inner, valid_welcome};
use crate::handler::{ConnId, OutLine};
use crate::store::{KeyChange, ServerBan, Store, StoreError};

/// The BYE text for connections closed by a server ban without a reason
/// (10.2). With a reason, the BYE carries the reason.
pub const BYE_BANNED: &str = "banned from this server";

/// The BYE text for ADMIN DISCONNECT without a reason (10.3).
pub const BYE_DISCONNECTED: &str = "disconnected by an operator";

/// The BYE text for guests whose sessions `ADMIN SET guests no` ended
/// (10.6).
pub const BYE_GUESTS_OFF: &str = "guests are no longer allowed";

/// The prefix length a ban of an IPv6 guest covers (10.2): one IPv6 user
/// usually holds a whole `/64`.
pub const GUEST_BAN_PREFIX_V6: u8 = 64;

/// What the hub keeps in memory for the ADMIN commands.
#[derive(Debug)]
pub(crate) struct AdminState {
    /// The server bans (10.2), by target, with their reasons: the same as
    /// the store's. Read by sign-ins under the registry's lock.
    bans: RwLock<BTreeMap<ServerBanTarget, String>>,
    /// Held while an ADMIN command changes operators, bans or server
    /// settings, so that memory and the store change in the same order.
    lock: tokio::sync::Mutex<()>,
}

impl AdminState {
    /// Reads the server bans from the store. Blocks.
    pub(crate) fn load(store: &dyn Store) -> Result<AdminState, StoreError> {
        let bans = store
            .server_bans()?
            .into_iter()
            .map(|ban| (ban.target, ban.reason))
            .collect();
        Ok(AdminState {
            bans: RwLock::new(bans),
            lock: tokio::sync::Mutex::new(()),
        })
    }

    fn bans(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<ServerBanTarget, String>> {
        self.bans.read().unwrap_or_else(|e| e.into_inner())
    }

    fn bans_mut(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<ServerBanTarget, String>> {
        self.bans.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// What a ban of a guest connected from `ip` bans (10.2): the IPv4
/// address itself, or the IPv6 `/64` that holds the address. An
/// IPv4-mapped IPv6 address counts as the IPv4 address.
pub fn guest_ban_target(ip: IpAddr) -> ServerBanTarget {
    match ip.to_canonical() {
        IpAddr::V4(v4) => ServerBanTarget::Address(IpAddr::V4(v4)),
        v6 => ServerBanTarget::Prefix(
            IpPrefix::new(v6, GUEST_BAN_PREFIX_V6).expect("an IPv6 address has 64 bits"),
        ),
    }
}

fn forbidden(message: &str) -> Fail {
    fail(ErrorCode::Forbidden, message)
}

/// The BYE text for a ban or disconnection: the reason, or `default`.
fn bye_text(reason: &str, default: &str) -> String {
    if reason.is_empty() {
        default.to_owned()
    } else {
        reason.to_owned()
    }
}

impl Inner {
    /// Handles the ADMIN commands about operators, bans, connections,
    /// hosted identities and server settings (10.1-10.3, 10.5, 10.6).
    /// Anyone who is not an operator gets `ERR forbidden` (Section 10).
    pub(super) async fn admin(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: AdminCommand,
    ) -> Outcome {
        if !uid.is_identity() || !self.is_operator(uid) {
            return Err(forbidden("only operators may use ADMIN"));
        }
        match command {
            AdminCommand::Ops => self.admin_ops(reply).await,
            AdminCommand::Op { uid: target } => self.admin_op(&target).await,
            AdminCommand::Deop { uid: target } => self.admin_deop(&target).await,
            AdminCommand::Ban { target, reason } => self.admin_ban(reply, target, reason).await,
            AdminCommand::Unban { target } => self.admin_unban(target).await,
            AdminCommand::Bans => self.admin_bans(reply).await,
            AdminCommand::Who => self.admin_who(reply).await,
            AdminCommand::Disconnect {
                uid: target,
                reason,
            } => self.admin_disconnect(reply, &target, &reason).await,
            AdminCommand::Notice { message } => Ok(self.admin_notice(message)),
            AdminCommand::Keys { uid: target } => self.admin_keys(reply, &target).await,
            AdminCommand::AddKey {
                uid: target,
                key,
                label,
            } => self.admin_add_key(reply, &target, key, label).await,
            AdminCommand::DelKey { uid: target, key } => {
                self.admin_del_key(reply, &target, key).await
            }
            AdminCommand::Unregister { uid: target } => self.admin_unregister(reply, &target).await,
            AdminCommand::Set(setting) => self.admin_set(setting).await,
            // Routed to their own areas in `commands`.
            AdminCommand::Purge { .. }
            | AdminCommand::Reports
            | AdminCommand::Rooms(_)
            | AdminCommand::Drop { .. } => Err(not_supported()),
        }
    }

    // ---- Sign-in checks (4.2, 4.5, 4.6, 10.2, 10.6) ----

    /// Whether a server ban covers the identity `uid` (10.2), by identity
    /// or by domain. Guests are never covered: their bans go by address.
    pub(super) fn uid_banned(&self, uid: &Uid) -> bool {
        uid.is_identity() && self.admin_state.bans().keys().any(|t| t.covers_uid(uid))
    }

    /// `ERR forbidden` if a server ban covers the identity `uid` (10.2),
    /// for AUTH and REGISTER.
    pub(super) fn check_not_banned(&self, uid: &Uid) -> Result<(), Fail> {
        if self.uid_banned(uid) {
            return Err(forbidden("this identity is banned from this server"));
        }
        Ok(())
    }

    /// Why GUEST from `peer` is refused, if it is: guests are not allowed
    /// (10.6), or a server ban covers the address (10.2). GUEST calls this
    /// under the registry's lock, just before it signs the connection in.
    pub(super) fn guest_refused(&self, peer: IpAddr) -> Option<&'static str> {
        if !self.settings().guests {
            return Some("guests are not allowed");
        }
        if self
            .admin_state
            .bans()
            .keys()
            .any(|t| t.covers_address(peer))
        {
            return Some("guests may not connect from this address");
        }
        None
    }

    // ---- Operators (10.1) ----

    /// Whether `uid` is an operator from the configuration, which ADMIN
    /// DEOP cannot remove (10.1).
    fn configured_operator(&self, uid: &Uid) -> bool {
        self.config.operators().iter().any(|op| op.to_uid() == *uid)
    }

    /// ADMIN OPS (10.1): one `OP <uid>` line per operator, in order.
    async fn admin_ops(&self, reply: &Reply) -> Outcome {
        let lines: Vec<ServerLine> = self
            .operators
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|uid| ServerLine::Op { uid: uid.clone() })
            .collect();
        if !self.reply_all(reply, lines).await {
            return Ok(None);
        }
        Ok(Some(OkResponse::new()))
    }

    /// ADMIN OP (10.1). Making an operator of one already is not an error.
    /// The identity learns it at its next sign-in (4.5).
    async fn admin_op(&self, target: &Uid) -> Outcome {
        if !target.is_identity() {
            return Err(forbidden("guests cannot be operators"));
        }
        let _admin = self.admin_state.lock.lock().await;
        if !self.configured_operator(target) {
            let (who, now) = (target.clone(), self.now());
            self.db(move |s| s.add_operator(&who, now)).await?;
        }
        self.operators
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target.clone());
        tracing::info!(operator = %target, "operator added");
        Ok(Some(OkResponse::new()))
    }

    /// ADMIN DEOP (10.1). Operators from the configuration cannot be
    /// removed (`forbidden`). Someone who is not an operator is
    /// `not-found`.
    async fn admin_deop(&self, target: &Uid) -> Outcome {
        if self.configured_operator(target) {
            return Err(forbidden(
                "operators from the configuration cannot be removed",
            ));
        }
        let _admin = self.admin_state.lock.lock().await;
        let who = target.clone();
        let stored = self.db(move |s| s.remove_operator(&who)).await?;
        let held = self
            .operators
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(target);
        if !stored && !held {
            return Err(fail(ErrorCode::NotFound, "not an operator"));
        }
        tracing::info!(operator = %target, "operator removed");
        Ok(Some(OkResponse::new()))
    }

    // ---- Bans (10.2) ----

    /// ADMIN BAN (10.2).
    ///
    /// - An identity or domain ban closes the open connections of every
    ///   identity it covers, with BYE.
    /// - A guest's ban bans its address ([`guest_ban_target`]), and is
    ///   stored and listed under it.
    /// - An address or prefix ban, the guest's included, ends the sessions
    ///   of the guests connected from inside it, with BYE and their PARTs
    ///   (4.2), and of those waiting to be resumed whose last connection
    ///   came from inside it.
    ///
    /// Banning again replaces the reason. The guests' PARTs come before
    /// the `OK`, since this command caused them (3.6); the BYE to any
    /// identity's connections comes after it, in case the operator banned
    /// itself.
    async fn admin_ban(&self, reply: &Reply, target: ServerBanTarget, reason: String) -> Outcome {
        let target = match target {
            ServerBanTarget::Guest(name) => {
                let guest = Uid::guest(&name);
                let peer = self
                    .guest_address(&guest)
                    .ok_or_else(|| fail(ErrorCode::NotFound, "no such guest is connected"))?;
                guest_ban_target(peer)
            }
            ServerBanTarget::Address(ip) => ServerBanTarget::Address(ip.to_canonical()),
            target => target,
        };
        let bye = bye_text(&reason, BYE_BANNED);
        let _admin = self.admin_state.lock.lock().await;
        // Operators cannot be banned, so that nobody locks the server's
        // operators out, themselves included: DEOP first. Configured
        // operators cannot be removed, so never (PLAN.md 5, item 35).
        let covers_operator = {
            let operators = self.operators.read().unwrap_or_else(|e| e.into_inner());
            operators.iter().any(|op| target.covers_uid(op))
        };
        if covers_operator {
            return Err(fail(
                ErrorCode::Forbidden,
                "that would ban an operator; remove the operator first",
            ));
        }
        let ban = ServerBan {
            target: target.clone(),
            reason: reason.clone(),
            t: self.now(),
        };
        self.db(move |s| s.add_server_ban(&ban)).await?;
        // In memory before anything is closed: see the module docs.
        self.admin_state.bans_mut().insert(target.clone(), reason);
        tracing::info!(%target, "server ban added");
        for guest in self.guests_covered(&target) {
            self.end_guest_session(&guest, &bye).await;
        }
        respond(reply, "ADMIN", Ok(Some(OkResponse::new())));
        self.detach_identities(|uid| target.covers_uid(uid), &bye);
        Ok(None)
    }

    /// The address of the connection that has the guest `uid`'s session,
    /// if it has one (10.2).
    fn guest_address(&self, uid: &Uid) -> Option<IpAddr> {
        let reg = self.reg();
        let conn = reg.sessions.get(uid)?.conn?;
        reg.conns.get(&conn).map(|c| c.info.peer.ip())
    }

    /// The guests whose sessions have a connection from an address that
    /// `target` covers, or wait to be resumed and had their last one from
    /// such an address (10.2).
    fn guests_covered(&self, target: &ServerBanTarget) -> Vec<Uid> {
        let reg = self.reg();
        let mut guests: Vec<Uid> = reg
            .sessions
            .iter()
            .filter(|(_, session)| target.covers_address(session.address))
            .map(|(uid, _)| uid.clone())
            .collect();
        guests.sort();
        guests
    }

    /// Closes every connection of the identities for which `covered` is
    /// true, with `BYE <bye>`. They run no more commands (10.2, 10.3).
    fn detach_identities(&self, covered: impl Fn(&Uid) -> bool, bye: &str) {
        let mut reg = self.reg();
        let conns: Vec<ConnId> = reg
            .users
            .iter()
            .filter(|(uid, _)| uid.is_identity() && covered(uid))
            .flat_map(|(_, user)| {
                user.lock()
                    .conns
                    .iter()
                    .map(|c| c.handle.id())
                    .collect::<Vec<_>>()
            })
            .collect();
        for id in conns {
            tracing::debug!(conn = id.0, "closing a connection for an operator");
            reg.detach(id, bye);
        }
    }

    /// ADMIN UNBAN (10.2). A ban that does not exist is `not-found`. A
    /// guest's ban is listed under its address, and is lifted by that
    /// address: `~name` is `not-found`.
    async fn admin_unban(&self, target: ServerBanTarget) -> Outcome {
        let target = match target {
            ServerBanTarget::Guest(_) => {
                return Err(fail(
                    ErrorCode::NotFound,
                    "a guest's ban is listed under its address; unban that",
                ));
            }
            ServerBanTarget::Address(ip) => ServerBanTarget::Address(ip.to_canonical()),
            target => target,
        };
        let _admin = self.admin_state.lock.lock().await;
        let stored = target.clone();
        let removed = self.db(move |s| s.remove_server_ban(&stored)).await?;
        self.admin_state.bans_mut().remove(&target);
        if !removed {
            return Err(fail(ErrorCode::NotFound, "no such ban"));
        }
        tracing::info!(%target, "server ban lifted");
        Ok(Some(OkResponse::new()))
    }

    /// ADMIN BANS (10.2): one `SERVERBAN <target> [<reason...>]` line per
    /// ban, in the byte order of the targets.
    async fn admin_bans(&self, reply: &Reply) -> Outcome {
        let bans = self.db(|s| s.server_bans()).await?;
        let lines = bans
            .into_iter()
            .map(|ban| ServerLine::ServerBan {
                target: ban.target,
                reason: ban.reason,
            })
            .collect();
        if !self.reply_all(reply, lines).await {
            return Ok(None);
        }
        Ok(Some(OkResponse::new()))
    }

    // ---- Connections (10.3) ----

    /// ADMIN WHO (10.3): one `CONNECTION` line per open connection, in the
    /// order they opened. Connections that have been told BYE are left out.
    async fn admin_who(&self, reply: &Reply) -> Outcome {
        let lines: Vec<ServerLine> = {
            let reg = self.reg();
            let mut conns: Vec<_> = reg.conns.iter().filter(|(_, c)| !c.detached).collect();
            conns.sort_by_key(|(id, _)| id.0);
            conns
                .into_iter()
                .map(|(_, c)| ServerLine::Connection {
                    uid: c.uid.clone(),
                    address: c.info.peer.ip().to_canonical(),
                    port: Some(c.info.peer.port()),
                    since: c.info.since,
                })
                .collect()
        };
        if !self.reply_all(reply, lines).await {
            return Ok(None);
        }
        Ok(Some(OkResponse::new()))
    }

    /// ADMIN DISCONNECT (10.3): closes every connection of `target` with
    /// BYE. A guest's session ends at once, with its PARTs (4.2), whether
    /// or not it has a connection. Someone with no connection and no
    /// session is `not-found`.
    async fn admin_disconnect(&self, reply: &Reply, target: &Uid, reason: &str) -> Outcome {
        let bye = bye_text(reason, BYE_DISCONNECTED);
        if target.is_guest() {
            if !self.end_guest_session(target, &bye).await {
                return Err(fail(ErrorCode::NotFound, "no such guest"));
            }
            tracing::info!(%target, "guest disconnected by an operator");
            return Ok(Some(OkResponse::new()));
        }
        let connected = self
            .reg()
            .users
            .get(target)
            .is_some_and(|user| !user.lock().conns.is_empty());
        if !connected {
            return Err(fail(ErrorCode::NotFound, "not connected"));
        }
        // The OK first, in case the operator disconnected itself.
        respond(reply, "ADMIN", Ok(Some(OkResponse::new())));
        self.detach_identities(|uid| uid == target, &bye);
        tracing::info!(%target, "identity disconnected by an operator");
        Ok(None)
    }

    /// ADMIN NOTICE (10.3): `NOTICE <message...>` to every open connection,
    /// signed in or not, the operator's own included, before its `OK`.
    fn admin_notice(&self, message: String) -> Option<OkResponse> {
        let line = OutLine::new(ServerMessage::new(ServerLine::Notice { message }));
        let reg = self.reg();
        for conn in reg.conns.values().filter(|c| !c.detached) {
            conn.handle.send_line(line.clone());
        }
        Some(OkResponse::new())
    }

    // ---- Hosted identities (10.5) ----

    /// Checks that `target` is an identity this server hosts (4.6): one
    /// that is not is `not-found`. A server with no identity domain hosts
    /// none, and offers none of these commands (`not-supported`).
    async fn check_hosted(&self, target: &Uid) -> Result<(), Fail> {
        if self.identity_domain.is_none() {
            return Err(fail(
                ErrorCode::NotSupported,
                "this server hosts no identities",
            ));
        }
        let not_hosted = || {
            fail(
                ErrorCode::NotFound,
                "this server does not host that identity",
            )
        };
        if !self.hosts_uid(target) {
            return Err(not_hosted());
        }
        let who = target.clone();
        match self.db(move |s| s.hosted_keys(&who)).await? {
            Some(_) => Ok(()),
            None => Err(not_hosted()),
        }
    }

    /// ADMIN KEYS (10.5): the identity's keys as KEY LIST lists them (4.7).
    async fn admin_keys(&self, reply: &Reply, target: &Uid) -> Outcome {
        self.check_hosted(target).await?;
        self.key(target, reply, KeyCommand::List)
            .await
            .map_err(not_hosted_is_not_found)
    }

    /// ADMIN ADDKEY (10.5): KEY ADD (4.7) for any hosted identity.
    async fn admin_add_key(
        &self,
        reply: &Reply,
        target: &Uid,
        key: risala_proto::auth::PublicKey,
        label: String,
    ) -> Outcome {
        self.check_hosted(target).await?;
        let result = self
            .key(target, reply, KeyCommand::Add { key, label })
            .await
            .map_err(not_hosted_is_not_found);
        if result.is_ok() {
            tracing::info!(%target, "key added by an operator");
        }
        result
    }

    /// ADMIN DELKEY (10.5): KEY DEL (4.7) for any hosted identity, except
    /// that it may remove the last key, which locks the identity. The
    /// connections that use the key are closed, after the `OK`.
    async fn admin_del_key(
        &self,
        reply: &Reply,
        target: &Uid,
        key: risala_proto::auth::PublicKey,
    ) -> Outcome {
        self.check_hosted(target).await?;
        let _keys = self.keys_lock.lock().await;
        let (who, gone) = (target.clone(), key.clone());
        match self
            .db(move |s| s.remove_any_hosted_key(&who, &gone))
            .await?
        {
            KeyChange::Done(keys) => {
                let result = self.republish(target, keys).await;
                respond(reply, "ADMIN", result);
                self.close_keys(target, |k| *k == key);
                tracing::info!(%target, "key removed by an operator");
                // M5a: delete the key's KeyPackages and pending Welcomes
                // (4.7).
                Ok(None)
            }
            KeyChange::NotFound => Err(fail(ErrorCode::NotFound, "no such key")),
            KeyChange::NotHosted | KeyChange::LastKey | KeyChange::TooMany => Err(fail(
                ErrorCode::NotFound,
                "this server does not host that identity",
            )),
        }
    }

    /// ADMIN UNREGISTER (10.5): UNREGISTER (4.8) without `purge=yes`, of
    /// any hosted identity. Its name is never registered again.
    async fn admin_unregister(self: &Arc<Self>, reply: &Reply, target: &Uid) -> Outcome {
        self.check_hosted(target).await?;
        tracing::info!(%target, "identity deleted by an operator");
        self.unregister(target, reply, target, false).await
    }

    // ---- Server settings (10.6) ----

    /// ADMIN SET (10.6). Unknown keys are `not-supported`: they are left to
    /// the configuration. The change shows in INFO (8.5) and the next
    /// greeting (4.1) at once.
    ///
    /// - `guests no` ends the session of every guest, with BYE and its
    ///   PARTs (4.2): those connected, and those waiting to be resumed,
    ///   which no GUEST can resume any more.
    /// - Shortening `retention` applies to stored events too (7.5).
    async fn admin_set(&self, setting: ServerSetting) -> Outcome {
        match &setting {
            ServerSetting::Other { .. } => {
                return Err(fail(
                    ErrorCode::NotSupported,
                    "that setting is left to the configuration",
                ));
            }
            ServerSetting::Welcome(text) if !valid_welcome(text) => {
                return Err(fail(ErrorCode::TooLong, "the welcome text is too long"));
            }
            _ => {}
        }
        let _admin = self.admin_state.lock.lock().await;
        let stored = setting.clone();
        self.db(move |s| s.set_server_setting(&stored)).await?;
        // In memory before any guest is looked for: see the module docs.
        self.settings
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .apply(&setting);
        tracing::info!(key = setting.key(), "server setting changed");
        match setting {
            ServerSetting::Guests(false) => {
                let mut guests: Vec<Uid> = self.reg().sessions.keys().cloned().collect();
                guests.sort();
                for guest in guests {
                    self.end_guest_session(&guest, BYE_GUESTS_OFF).await;
                }
            }
            // A shorter period applies to stored events at once (7.5,
            // 10.6). The setting stands even if this fails; the hourly
            // run catches up.
            ServerSetting::Retention(_) => {
                if let Err(e) = self.expire_all().await {
                    tracing::error!("expiring events failed: {e}");
                }
            }
            _ => {}
        }
        Ok(Some(OkResponse::new()))
    }
}

/// KEY's `not-supported` for an identity the server does not host (4.7)
/// is `not-found` for ADMIN (10.5). The hosting was checked first, so this
/// is only an identity deleted meanwhile.
fn not_hosted_is_not_found(e: Fail) -> Fail {
    match e {
        Fail::Err(err) if err.code == ErrorCode::NotSupported => fail(
            ErrorCode::NotFound,
            "this server does not host that identity",
        ),
        other => other,
    }
}

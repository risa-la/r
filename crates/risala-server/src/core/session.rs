//! A connection's life before and around its kind (4.1, 4.2, 11): the
//! greeting, the time to choose a kind, ANON, GUEST and guest sessions,
//! and the clean-up after a connection closes.
//!
//! # Guest sessions
//!
//! A guest's session (4.2) starts with GUEST and outlives its connection:
//! when the connection closes, QUIT included, the session waits
//! `limits.guest_resume_secs` (at least 2 minutes) for
//! `GUEST <name> token=<token>` before it ends. Resuming moves the session
//! to the new connection, closes the old one with BYE, and gives a new
//! token. A session ends in one place, [`Inner::end_guest_session`], which
//! sends GONE to the public rooms the guest had a leaf in (6.1) and only
//! then frees the name. Sessions live in memory: they do not survive a
//! restart.
//!
//! The server keeps only the hash of a session's token, and compares it in
//! constant time (Section 14).

use std::sync::{Arc, Weak};

use risala_proto::auth::Nonce;
use risala_proto::command::GuestToken;
use risala_proto::error::ErrorCode;
use risala_proto::names::{Id, Name, Uid};
use risala_proto::server::{Greeting, Host, OkResponse, ServerMessage};

use super::command::{Cx, Reply, err};
use super::rate::network;
use super::state::{ConnEntry, GuestSession, Who};
use super::{Inner, admin, identity, keylog, keys, mailbox, misc};
use crate::handler::{ConnHandle, ConnId, ConnInfo};
use crate::secret::{SecretHash, random_token};

/// The number of random bytes in a greeting's nonce (4.1: 16 to 64).
pub const NONCE_BYTES: usize = 32;

/// The number of random `a-z 0-9` characters in a guest's token (4.2): 32
/// of them carry about 165 bits, more than the 128 the spec asks for.
pub const TOKEN_LEN: usize = 32;

/// The BYE text for a connection whose guest session was resumed on
/// another connection (4.2).
pub const BYE_RESUMED: &str = "resumed on another connection";

/// The BYE text for a connection that did not choose a kind in time (4.1).
pub const BYE_SIGN_IN_TIMEOUT: &str = "sign-in timeout";

/// The BYE text for guest sessions ended by a shutdown. Their connections
/// have closed by then, so nobody reads it.
pub const BYE_SHUTDOWN: &str = "server shutting down";

impl Inner {
    /// Sends the greeting (4.1), registers the connection and starts its
    /// time to choose a kind. The greeting is queued under the registry's
    /// lock, as the connection is registered, so that nothing reaches the
    /// connection before it.
    pub(super) fn open(self: &Arc<Self>, info: ConnInfo, handle: ConnHandle) {
        let id = handle.id();
        let nonce = match crate::secret::random_bytes::<NONCE_BYTES>() {
            Ok(bytes) => Nonce::from_bytes(&bytes).expect("32 bytes make a nonce"),
            Err(e) => {
                tracing::error!(conn = id.0, "no random nonce: {e}");
                handle.close(Some("internal error".into()));
                return;
            }
        };
        // The SNI hostname, or the server's own if the client sent none
        // (4.1). The network layer gives SNI in lower case.
        let host = info
            .sni
            .as_deref()
            .and_then(|sni| sni.parse::<Host>().ok())
            .unwrap_or_else(|| {
                self.config
                    .hostname
                    .parse()
                    .expect("the hostname was checked at start")
            });
        let greeting = ServerMessage::new(Greeting {
            version: risala_proto::PROTOCOL_VERSION,
            host,
            nonce: nonce.clone(),
            message: self.settings().welcome,
        });
        tracing::debug!(conn = id.0, "connection opened");

        let timer = tokio::runtime::Handle::try_current().ok().map(|rt| {
            let weak: Weak<Inner> = Arc::downgrade(self);
            let wait = self.timers.sign_in;
            rt.spawn(async move {
                tokio::time::sleep(wait).await;
                if let Some(inner) = weak.upgrade() {
                    inner.sign_in_expired(id);
                }
            })
            .abort_handle()
        });
        let mut reg = self.reg();
        handle.send(greeting);
        reg.conns.insert(
            id,
            ConnEntry {
                handle,
                info,
                who: Who::New,
                nonce: Some(nonce),
                gate: Arc::default(),
                sign_in_timer: timer,
                detached: false,
                areas: Default::default(),
            },
        );
    }

    /// Closes a connection that is still new when its time to choose a
    /// kind is up (4.1).
    fn sign_in_expired(&self, id: ConnId) {
        let mut reg = self.reg();
        if reg.conns.get(&id).is_some_and(|c| c.who == Who::New) {
            tracing::debug!(conn = id.0, "sign-in timeout");
            reg.detach(id, BYE_SIGN_IN_TIMEOUT);
        }
    }

    /// Cleans up after a connection: every area forgets it, and a guest's
    /// session starts waiting to be resumed (4.2), unless it has moved to
    /// another connection.
    pub(super) async fn closed(self: Arc<Self>, id: ConnId) {
        let Some(gate) = self.reg().conns.get(&id).map(|c| c.gate.clone()) else {
            return;
        };
        let _gate = gate.lock().await;
        let Some(conn) = self.reg().remove(id) else {
            return;
        };
        if let Some(timer) = &conn.sign_in_timer {
            timer.abort();
        }
        identity::conn_closed(&self, id, &conn);
        keylog::conn_closed(&self, id, &conn);
        mailbox::conn_closed(&self, id, &conn);
        keys::conn_closed(&self, id, &conn);
        misc::conn_closed(&self, id, &conn);
        admin::conn_closed(&self, id, &conn);
        tracing::debug!(conn = id.0, "connection closed");
        if let Who::Guest(uid) = &conn.who {
            self.wait_for_resume(id, uid);
        }
    }

    /// Starts the resume period of the session of `uid`, if connection `id`
    /// still has it (4.2).
    fn wait_for_resume(self: &Arc<Self>, id: ConnId, uid: &Uid) {
        let mut reg = self.reg();
        let Some(session) = reg.sessions.get_mut(uid) else {
            return;
        };
        if session.conn != Some(id) || session.ending {
            return;
        }
        session.conn = None;
        session.epoch += 1;
        let epoch = session.epoch;
        let weak: Weak<Inner> = Arc::downgrade(self);
        let wait = self.timers.guest_resume;
        let expired = uid.clone();
        session.expiry = Some(
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                if let Some(inner) = weak.upgrade() {
                    inner.resume_expired(&expired, epoch).await;
                }
            })
            .abort_handle(),
        );
        tracing::debug!(conn = id.0, "guest session waits to be resumed");
    }

    /// Ends a guest session whose resume period is over (4.2), unless it
    /// was resumed meanwhile.
    async fn resume_expired(&self, uid: &Uid, epoch: u64) {
        {
            let mut reg = self.reg();
            let Some(session) = reg.sessions.get_mut(uid) else {
                return;
            };
            if session.conn.is_some() || session.epoch != epoch || session.ending {
                return;
            }
            // This task is the expiry: it must not abort itself.
            session.expiry = None;
        }
        tracing::debug!("guest session not resumed in time");
        self.end_guest_session(uid, "session ended").await;
    }

    /// Ends the session of the guest `uid` now (4.2), whether it is
    /// connected or waiting to be resumed: its connection, if it has one,
    /// is closed with `BYE <bye>`, the public rooms it had a leaf in get
    /// GONE (6.1), and then its name is free. Returns `false` if there was
    /// no such session, or it was already ending.
    pub(super) async fn end_guest_session(&self, uid: &Uid, bye: &str) -> bool {
        {
            let mut reg = self.reg();
            let Some(session) = reg.sessions.get_mut(uid) else {
                return false;
            };
            if session.ending {
                return false;
            }
            session.ending = true;
            if let Some(expiry) = session.expiry.take() {
                expiry.abort();
            }
            if let Some(conn) = session.conn.take() {
                reg.detach(conn, bye);
            }
        }
        mailbox::guest_session_ended(self, uid).await;
        self.reg().sessions.remove(uid);
        tracing::debug!("guest session ended");
        true
    }
}

/// `ANON` (4.2): the connection becomes anonymous.
///
/// Refused with `ERR forbidden` while the server allows no anonymous
/// connections (10.6), or from a banned address (10.2).
pub(super) async fn anon(cx: &Cx) -> Reply {
    if !cx.inner.settings().anon {
        return Err(err(ErrorCode::Forbidden).with_message("anonymous connections are off"));
    }
    if let Some(why) = admin::refuses_address(&cx.inner, cx.peer.ip()) {
        return Err(err(ErrorCode::Forbidden).with_message(why));
    }
    if !cx.inner.reg().set_who(cx.conn, Who::Anonymous) {
        return Err(err(ErrorCode::Internal));
    }
    Ok(OkResponse::new())
}

/// `GUEST <name> [token=<token>]` (4.2): the connection becomes a guest,
/// in a new session or the one its token resumes.
pub(super) async fn guest(cx: &Cx, name: &Name, token: Option<&GuestToken>) -> Reply {
    if !cx.inner.settings().guests {
        return Err(err(ErrorCode::Forbidden).with_message("guests are not allowed"));
    }
    let ip = cx.peer.ip();
    if let Some(why) = admin::refuses_address(&cx.inner, ip) {
        return Err(err(ErrorCode::Forbidden).with_message(why));
    }
    let new_token = match random_token(TOKEN_LEN) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(conn = cx.conn.0, "no random token: {e}");
            return Err(err(ErrorCode::Internal));
        }
    };
    let new_token: Id = new_token.parse().expect("a random token is an id");
    let new_hash = SecretHash::of(new_token.as_str().as_bytes());
    let uid = Uid::guest(name);

    let mut reg = cx.inner.reg();
    if !reg.conns.contains_key(&cx.conn) {
        return Err(err(ErrorCode::Internal));
    }
    let resumed = match reg.sessions.get_mut(&uid) {
        // A token for the session resumes it, compared in constant time
        // (Section 14).
        Some(session)
            if !session.ending
                && token.is_some_and(|t| session.token.matches(t.0.as_str().as_bytes())) =>
        {
            session.token = new_hash;
            session.epoch += 1;
            session.address = ip;
            if let Some(expiry) = session.expiry.take() {
                expiry.abort();
            }
            if let Some(old) = session.conn.replace(cx.conn) {
                reg.detach(old, BYE_RESUMED);
            }
            true
        }
        // Held by a session, connected or waiting, or ending.
        Some(_) => return Err(err(ErrorCode::NameTaken)),
        // A token that matches no session is ignored (4.2).
        None => {
            // So many sessions per network address, those waiting to be
            // resumed included, since each holds a name and outlives its
            // connection (4.2). Limits per network address are the free
            // tier: past them a client will go on by proof of work, from
            // M6a (PLAN items 42 and 63).
            let max = cx.inner.config.limits.guests_per_address;
            let net = network(ip);
            if max > 0
                && reg
                    .sessions
                    .values()
                    .filter(|s| network(s.address) == net)
                    .count()
                    >= max
            {
                return Err(err(ErrorCode::RateLimited).with_retry(60));
            }
            reg.sessions.insert(
                uid.clone(),
                GuestSession {
                    token: new_hash,
                    conn: Some(cx.conn),
                    address: ip,
                    epoch: 0,
                    expiry: None,
                    ending: false,
                },
            );
            false
        }
    };
    reg.set_who(cx.conn, Who::Guest(uid.clone()));
    drop(reg);
    tracing::debug!(conn = cx.conn.0, resumed, "guest");
    Ok(OkResponse::new()
        .with_uid(&uid)
        .with_token(&GuestToken(new_token))
        .with_resumed(resumed))
}

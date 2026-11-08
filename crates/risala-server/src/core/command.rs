//! Routing each command to its area, and what a command's handler gets to
//! work with ([`Cx`]).
//!
//! [`route`] checks that the connection's kind may send the command
//! ([`Command::check_kind`], Section 13), and that whoever sends an ADMIN
//! command is an operator (Section 10), then hands it to its area:
//!
//! | Commands | Area |
//! |---|---|
//! | ANON, GUEST (4.2), PING, PONG, QUIT (11) | `session` |
//! | AUTH, REGISTER, KEYS PUT, PAIR, UNREGISTER, ADMIN UNREGISTER (4.6-4.9, 10.5) | `identity` |
//! | CREATE, POST, GROUPINFO, MUTE, UNMUTE, FOLLOW, UNFOLLOW, FETCH, TOKEN (5.2, 6.1, 6.4, 7.1, 7.2) | `mailbox` |
//! | KEYPKG, WELCOME, BLOB, BACKUP, UPLOAD (12.5, 12.8, 12.12, 12.13, 5.6) | `keys` |
//! | INFO, LIST, PRESENCE, WATCH, WHOIS, MEMBERS, PUSH, REPORT, RESOLVE (8, 6.1, 9, 5.8) | `misc` |
//! | ADMIN, except ADMIN UNREGISTER (Section 10) | `admin` |
//!
//! The key log (`keylog`, 4.5) has no commands of its own.
//!
//! A handler returns its final response as a [`Reply`]; `route` sends it,
//! with the command's `ref` (3.6), after any lines the handler sent.

use std::net::SocketAddr;
use std::sync::Arc;

use risala_proto::command::{AdminCommand, Command, Request};
use risala_proto::error::ErrorCode;
use risala_proto::server::{ErrResponse, OkResponse, ServerLine, ServerMessage};
use risala_proto::types::Ref;

use super::state::{Device, Who};
use super::{Inner, admin, identity, keys, mailbox, misc, session};
use crate::handler::{ConnHandle, ConnId};
use crate::store::{self, Store};

/// A command's final response: `OK` or `ERR` (3.6).
pub(crate) type Reply = Result<OkResponse, ErrResponse>;

/// `ERR <code>`, with no message.
pub(crate) fn err(code: ErrorCode) -> ErrResponse {
    ErrResponse::new(code)
}

/// `ERR not-supported`: what every command of an area not built yet gets.
pub(crate) fn not_supported() -> Reply {
    Err(err(ErrorCode::NotSupported))
}

/// The reply of an area to a command that is not its own: a bug in
/// [`route`], logged, and `ERR internal` to the client.
pub(crate) fn misrouted(area: &str, command: &Command) -> Reply {
    tracing::error!(
        area,
        verb = command.verb(),
        "a command was routed to the wrong area"
    );
    Err(err(ErrorCode::Internal))
}

/// One command being handled: the hub, and the connection that sent it.
pub(crate) struct Cx {
    /// The hub.
    pub(crate) inner: Arc<Inner>,
    /// The connection.
    pub(crate) conn: ConnId,
    /// Its queue.
    pub(crate) handle: ConnHandle,
    /// The command's `ref`, copied onto its response lines (3.6).
    pub(crate) ref_: Option<Ref>,
    /// The client's address and port.
    pub(crate) peer: SocketAddr,
    /// Who the connection acts for, as the command began.
    pub(crate) who: Who,
    /// A BYE text to close the connection with once the final response
    /// has been sent ([`close_after`](Self::close_after)).
    close_after: std::sync::Mutex<Option<String>>,
}

#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
impl Cx {
    /// Sends a response line, with the command's `ref` (3.6). Returns
    /// `false` if the connection is gone or was too slow.
    pub(crate) fn send(&self, line: impl Into<ServerLine>) -> bool {
        self.handle
            .send(ServerMessage::new(line).with_ref_opt(self.ref_.clone()))
    }

    /// Waits until the connection's queue has room for a whole response
    /// (see [`Limits::command_room`](crate::config::Limits::command_room)),
    /// before each long line after the first of a response that has
    /// several, such as KEYPKG GET or WELCOME LIST (12.5, 12.8).
    pub(crate) async fn wait_for_room(&self) {
        let limits = &self.inner.config.limits;
        self.handle
            .wait_for_room(limits.command_room(), limits.command_room_bytes())
            .await;
    }

    /// The signed-in identity and device, if the connection is signed in.
    pub(crate) fn device(&self) -> Option<&Device> {
        match &self.who {
            Who::SignedIn(device) => Some(device),
            _ => None,
        }
    }

    /// Closes the connection with `BYE <bye>` once the command's final
    /// response has been sent, as UNREGISTER does (4.9).
    pub(crate) fn close_after(&self, bye: &str) {
        *self.close_after.lock().unwrap_or_else(|e| e.into_inner()) = Some(bye.to_owned());
    }

    /// Runs a store call on the blocking pool. A failure is logged, and
    /// becomes `ERR internal`.
    pub(crate) async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn Store) -> store::Result<T> + Send + 'static,
    ) -> Result<T, ErrResponse> {
        self.inner.db(f).await.map_err(|e| {
            tracing::error!(conn = self.conn.0, "store: {e}");
            err(ErrorCode::Internal)
        })
    }
}

/// Handles one command from connection `id`, and sends its final
/// response, unless it is PONG, which gets none (3.6).
pub(super) async fn route(inner: &Arc<Inner>, id: ConnId, req: Request) {
    let Request { ref_, command } = req;
    let cx = {
        let reg = inner.reg();
        let Some(conn) = reg.conns.get(&id) else {
            return;
        };
        if conn.detached {
            return;
        }
        Cx {
            inner: inner.clone(),
            conn: id,
            handle: conn.handle.clone(),
            ref_,
            peer: conn.info.peer,
            who: conn.who.clone(),
            close_after: std::sync::Mutex::new(None),
        }
    };
    if let Err(code) = command.check_kind(cx.who.kind()) {
        finish(&cx, Err(err(code)));
        return;
    }
    let reply = match command {
        Command::Pong { .. } => return,
        Command::Quit { .. } => {
            finish(&cx, Ok(OkResponse::new()));
            cx.handle.close(None);
            return;
        }
        Command::Ping { .. } => Ok(OkResponse::new()),
        Command::Anon => session::anon(&cx).await,
        Command::Guest { name, token } => session::guest(&cx, &name, token.as_ref()).await,
        Command::Admin(admin) => route_admin(&cx, admin).await,
        command @ (Command::Auth { .. }
        | Command::Register { .. }
        | Command::KeysPut { .. }
        | Command::Pair(_)
        | Command::Unregister { .. }) => identity::handle(&cx, command).await,
        command @ (Command::Create { .. }
        | Command::Post { .. }
        | Command::GroupInfo { .. }
        | Command::Mute { .. }
        | Command::Unmute { .. }
        | Command::Follow { .. }
        | Command::Unfollow { .. }
        | Command::Fetch { .. }
        | Command::Token { .. }) => mailbox::handle(&cx, command).await,
        command @ (Command::KeyPkg(_)
        | Command::Welcome(_)
        | Command::Blob { .. }
        | Command::Backup(_)
        | Command::Upload { .. }) => keys::handle(&cx, command).await,
        command @ (Command::Info { .. }
        | Command::List { .. }
        | Command::Presence { .. }
        | Command::Watch { .. }
        | Command::Whois { .. }
        | Command::Members { .. }
        | Command::Push(_)
        | Command::Report { .. }
        | Command::Resolve { .. }) => misc::handle(&cx, command).await,
    };
    finish(&cx, reply);
    let close = cx
        .close_after
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(bye) = close {
        cx.handle.close(Some(bye));
    }
}

/// ADMIN commands are for operators only: anyone else gets `ERR forbidden`
/// for every one of them (Section 10).
async fn route_admin(cx: &Cx, command: AdminCommand) -> Reply {
    let operator = cx
        .device()
        .is_some_and(|device| admin::is_operator(&cx.inner, &device.uid));
    if !operator {
        return Err(err(ErrorCode::Forbidden));
    }
    match command {
        AdminCommand::Unregister { uid } => identity::admin_unregister(cx, &uid).await,
        command => admin::handle(cx, command).await,
    }
}

/// Sends a command's final response, with its `ref` (3.6).
fn finish(cx: &Cx, reply: Reply) {
    let line = match reply {
        Ok(ok) => ServerLine::Ok(ok),
        Err(err) => ServerLine::Err(err),
    };
    cx.send(line);
}

//! The engines: sans-I/O state machines, one per area, that turn what
//! arrives from the server into changes to the cache, and decide what to
//! send. [`client::driver`](crate::client::driver) runs them on an
//! account's connections.
//!
//! Each area has an [`Engine`] in a module of its own, so that the area
//! tasks of docs/plans/M5b.md can build them at the same time:
//!
//! | Module | Task | What |
//! |---|---|---|
//! | [`identity`] | C1 | key files, daily checks, RECORD lines, pairing relay (4.4-4.8, 12.14) |
//! | [`keylog`] | C1 | checkpoints, tiles, proofs, forks, watching (4.5) |
//! | [`conversations`] | C2 | the group engine: FOLLOW, FETCH, posts, commits, Welcomes, KeyPackages (5-8, 12.5-12.9) |
//! | [`confirm`] | C3 | confirming leaves (12.10) |
//! | [`transfer`] | C4 | blobs, files, transfers, backups, reports (5.6, 5.8, 12.11-12.13) |
//! | [`push`] | C4 | push subscriptions (Section 9) |
//!
//! # Shape
//!
//! An engine gets [`Input`]s, in the order they happened, and returns
//! [`Action`]s for the driver to carry out. It reads and writes the cache
//! itself, in short transactions, and keeps nothing persistent in memory
//! between calls, since another process may change the cache (PLAN.md
//! 3.4). Commands it sends carry a [`Token`] of its own; the reply comes
//! back to the same engine as [`Input::Reply`] with that token.
//!
//! Live lines go to the engine of their area, as [`route`] says. Replies
//! go to the engine that sent the command. [`Input::Ready`] and
//! [`Input::Tick`] go to every engine.

pub mod confirm;
pub mod conversations;
pub mod identity;
pub mod keylog;
pub mod push;
pub mod transfer;

use risala_proto::command::Command;
use risala_proto::connection::ConnectionKind;
use risala_proto::names::BoxName;
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::time::Timestamp;

use crate::client::Event;
use crate::conn::{Response, Slot};
use crate::store::{AccountId, Store};

/// The area a line belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Area {
    /// The connection itself: the greeting, final responses, PING, BYE,
    /// NOTICE and unknown lines. The driver handles them.
    Connection,
    /// RECORD and PAIR (4.7, 4.8).
    Identity,
    /// Posts, rooms, members, presence, Welcomes and KeyPackages (5-8,
    /// 12.5, 12.8).
    Conversations,
    /// BACKUP and REPORT (5.8, 12.13).
    Transfer,
    /// PUSH (9.1).
    Push,
    /// The operator's lines: OP, SERVERBAN, CONNECTION and RESOLVED
    /// (Section 10, 5.8).
    Admin,
}

/// The area of a server line.
pub fn route(line: &ServerLine) -> Area {
    match line {
        ServerLine::Greeting(_)
        | ServerLine::Ok(_)
        | ServerLine::Err(_)
        | ServerLine::Ping { .. }
        | ServerLine::Bye { .. }
        | ServerLine::Notice { .. }
        | ServerLine::Unknown(_) => Area::Connection,
        ServerLine::Record { .. } | ServerLine::Pair { .. } => Area::Identity,
        ServerLine::Post(_)
        | ServerLine::Room { .. }
        | ServerLine::GroupInfo { .. }
        | ServerLine::Gone { .. }
        | ServerLine::Drop { .. }
        | ServerLine::User { .. }
        | ServerLine::Member { .. }
        | ServerLine::Presence { .. }
        | ServerLine::KeyPkg { .. }
        | ServerLine::Welcome { .. } => Area::Conversations,
        ServerLine::Backup { .. } | ServerLine::Report(_) => Area::Transfer,
        ServerLine::Push { .. } => Area::Push,
        ServerLine::Op { .. }
        | ServerLine::ServerBan { .. }
        | ServerLine::Connection { .. }
        | ServerLine::Resolved { .. } => Area::Admin,
    }
}

/// An engine's own number for a command it sent, to match the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Token(pub u64);

/// Which connection a command goes on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// The signed-in connection: what belongs to the account (4.1).
    SignedIn,
    /// The anonymous or guest connection that follows this mailbox, or
    /// will (7.1).
    Mailbox(BoxName),
    /// Any anonymous or guest connection, for commands about no mailbox
    /// that say nothing about the device, such as LIST.
    Conversing,
    /// The anonymous connection kept apart for WATCH (4.1, 8.3).
    Watch,
    /// A connection of its own, opened for this command and closed after
    /// it (4.1, "Keeping connections apart"): for KEYS PUT, PAIR, WELCOME
    /// GET, FETCH with `leaf` and a public room's PublicMessages, and
    /// fresh for each CREATE, KEYPKG GET and WELCOME PUT. See
    /// [`single_use`](crate::conn::single_use).
    Own(crate::conn::SingleUse),
}

/// What happened, for an engine.
#[derive(Debug)]
pub enum Input<'a> {
    /// A connection is ready: anonymous, a guest or signed in.
    Ready {
        /// Which.
        slot: Slot,
        /// Its kind.
        kind: ConnectionKind,
    },
    /// A connection closed. Commands sent on it get no reply.
    Closed {
        /// Which.
        slot: Slot,
    },
    /// A live line, of this engine's area.
    Line {
        /// The connection it came on.
        slot: Slot,
        /// The line.
        message: &'a ServerMessage,
    },
    /// The reply to a command this engine sent.
    Reply {
        /// The connection it came on.
        slot: Slot,
        /// The engine's token for the command.
        token: Token,
        /// The response.
        response: &'a Response,
    },
    /// Time passed: for retries, daily checks and timeouts.
    Tick {
        /// The time now.
        now: Timestamp,
    },
}

/// What an engine asks the driver to do.
#[derive(Debug)]
pub enum Action {
    /// Send a command, and give the reply back with `token`.
    Send {
        /// On which connection.
        target: Target,
        /// The command.
        command: Command,
        /// The engine's token for the reply.
        token: Token,
    },
    /// Tell the UI.
    Emit(Event),
}

/// What every engine is given besides its input.
#[derive(Debug, Clone)]
pub struct Context {
    /// The cache.
    pub store: Store,
    /// The account the engine runs for.
    pub account: AccountId,
}

/// One area's engine. Every method has a default that does nothing, so a
/// new engine starts empty.
pub trait Engine: Send {
    /// Handles one input, and returns what to do.
    fn handle(&mut self, cx: &Context, input: &Input<'_>) -> Vec<Action> {
        let _ = (cx, input);
        Vec::new()
    }
}

/// Every area's engine, for one account.
#[derive(Default)]
pub struct Engines {
    /// Task C1.
    pub identity: identity::IdentityEngine,
    /// Task C1.
    pub keylog: keylog::KeyLogEngine,
    /// Task C2.
    pub conversations: conversations::ConversationEngine,
    /// Task C3.
    pub confirm: confirm::ConfirmEngine,
    /// Task C4.
    pub transfer: transfer::TransferEngine,
    /// Task C4.
    pub push: push::PushEngine,
}

impl std::fmt::Debug for Engines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engines").finish_non_exhaustive()
    }
}

impl Engines {
    /// Every engine, in a fixed order.
    fn all(&mut self) -> [&mut dyn Engine; 6] {
        [
            &mut self.identity,
            &mut self.keylog,
            &mut self.conversations,
            &mut self.confirm,
            &mut self.transfer,
            &mut self.push,
        ]
    }

    /// Hands a live line to the engine of its area. Lines of the
    /// connection's own area and the operator's are the driver's, and give
    /// nothing here.
    pub fn line(&mut self, cx: &Context, slot: Slot, message: &ServerMessage) -> Vec<Action> {
        let input = Input::Line { slot, message };
        match route(&message.line) {
            Area::Identity => self.identity.handle(cx, &input),
            Area::Conversations => self.conversations.handle(cx, &input),
            Area::Transfer => self.transfer.handle(cx, &input),
            Area::Push => self.push.handle(cx, &input),
            Area::Connection | Area::Admin => Vec::new(),
        }
    }

    /// Hands an input to every engine, in order: [`Input::Ready`],
    /// [`Input::Closed`] and [`Input::Tick`].
    pub fn broadcast(&mut self, cx: &Context, input: &Input<'_>) -> Vec<Action> {
        self.all()
            .into_iter()
            .flat_map(|engine| engine.handle(cx, input))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(line: &str) -> Area {
        route(&line.parse::<ServerMessage>().unwrap().line)
    }

    #[test]
    fn lines_go_to_their_area() {
        let blob = format!("sha384:{}", "0".repeat(96));
        for (line, expected) in [
            (
                "RISALA 1 chat.test 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e",
                Area::Connection,
            ),
            ("OK", Area::Connection),
            ("ERR internal", Area::Connection),
            ("NOTICE hi", Area::Connection),
            ("PING x", Area::Connection),
            ("BYE", Area::Connection),
            ("FROB x", Area::Connection),
            (
                "@seq=1;t=2026-11-08T15:41:02.377Z POST ujzdegxdncf32epf3dhodzdoci AAEAAg==",
                Area::Conversations,
            ),
            ("GONE ujzdegxdncf32epf3dhodzdoci ~sam", Area::Conversations),
            ("DROP ujzdegxdncf32epf3dhodzdoci", Area::Conversations),
            ("PRESENCE online alice@example.org", Area::Conversations),
            (&format!("RECORD 7 {blob}"), Area::Identity),
            ("OP alice@example.org", Area::Admin),
        ] {
            assert_eq!(area(line), expected, "{line}");
        }
    }

    #[test]
    fn empty_engines_do_nothing() {
        let cx = Context {
            store: Store::open_in_memory().unwrap(),
            account: crate::store::AccountId(1),
        };
        let mut engines = Engines::default();
        let tick = Input::Tick {
            now: Timestamp::MIN,
        };
        assert!(engines.broadcast(&cx, &tick).is_empty());
        let post: ServerMessage =
            "@seq=1;t=2026-11-08T15:41:02.377Z POST ujzdegxdncf32epf3dhodzdoci AAEAAg=="
                .parse()
                .unwrap();
        assert!(engines.line(&cx, Slot::Anonymous(0), &post).is_empty());
    }
}

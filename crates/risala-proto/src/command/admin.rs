//! The commands of Section 10, `ADMIN <subcommand> ...`, and RESOLVE
//! (5.8). They are for operators, on signed-in connections; the server
//! replies `ERR forbidden` to anyone else (Section 10).

use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use super::Command;
use crate::error::ParseError;
use crate::line::{LineBuilder, Params};
use crate::mls::Pseudonym;
use crate::names::{BoxName, Room, ServerBanTarget, Uid};
use crate::parse::{
    last, opt, options, positive_opt, required_text, subcommand, tok, unknown_subcommand,
};
use crate::types::ServerSetting;

/// The subcommands of `ADMIN` (Section 10). The subcommand word is
/// case-insensitive.
///
/// Commands that name a user take any [`Uid`]: whether a guest makes
/// sense (it does for DISCONNECT, not for OP) is for the server to
/// answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommand {
    /// `ADMIN OPS` (10.1): list operators.
    Ops,
    /// `ADMIN OP <uid>` (10.1): make an identity an operator.
    Op {
        /// The new operator.
        uid: Uid,
    },
    /// `ADMIN DEOP <uid>` (10.1): remove an operator.
    Deop {
        /// The operator to remove.
        uid: Uid,
    },
    /// `ADMIN BAN <target> [<reason...>]` (10.2): a server-wide ban.
    Ban {
        /// An identity, domain, guest, address or prefix.
        target: ServerBanTarget,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `ADMIN UNBAN <target>` (10.2).
    Unban {
        /// The ban to lift.
        target: ServerBanTarget,
    },
    /// `ADMIN BANS` (10.2): list server bans.
    Bans,
    /// `ADMIN WHO` (10.3): list open connections.
    Who,
    /// `ADMIN DISCONNECT <uid> [<reason...>]` (10.3).
    Disconnect {
        /// Whose connections to close.
        uid: Uid,
        /// The reason sent with BYE, escaped. May be empty.
        reason: String,
    },
    /// `ADMIN NOTICE <message...>` (10.3): a notice to every connection.
    Notice {
        /// The message, escaped, never empty.
        message: String,
    },
    /// `ADMIN ROOMS [after=<room>] [limit=<n>]` (10.4): list every public
    /// room, a page at a time.
    Rooms {
        /// Only rooms whose names sort after this one.
        after: Option<Room>,
        /// At most this many rooms; at least 1, default 100.
        limit: Option<NonZeroU64>,
    },
    /// `ADMIN DROP <target> [<reason...>]` (10.4): delete a public room or
    /// any mailbox, with all of its posts.
    Drop {
        /// The room or mailbox.
        target: DropTarget,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `ADMIN MUTE <box> <pseudonym> [hours=<n>]` (10.4): MUTE (6.4) for
    /// any mailbox.
    Mute {
        /// The mailbox.
        mailbox: BoxName,
        /// The pseudonym to mute.
        pseudonym: Pseudonym,
        /// For how many hours; at least 1, default 24.
        hours: Option<NonZeroU64>,
    },
    /// `ADMIN UNMUTE <box> <pseudonym>` (10.4).
    Unmute {
        /// The mailbox.
        mailbox: BoxName,
        /// The pseudonym to unmute.
        pseudonym: Pseudonym,
    },
    /// `ADMIN REPORTS` (5.8, 10.4): list every open report.
    Reports,
    /// `ADMIN UNREGISTER <uid>` (10.5): delete a hosted identity.
    Unregister {
        /// The identity.
        uid: Uid,
    },
    /// `ADMIN SET <key> [<value...>]` (10.6): change a server setting.
    ///
    /// Unknown keys are kept in [`ServerSetting::Other`]; a known key with
    /// a bad value is `BadSyntax`.
    Set(ServerSetting),
}

impl AdminCommand {
    /// The subcommand, in upper case.
    pub fn word(&self) -> &'static str {
        match self {
            AdminCommand::Ops => "OPS",
            AdminCommand::Op { .. } => "OP",
            AdminCommand::Deop { .. } => "DEOP",
            AdminCommand::Ban { .. } => "BAN",
            AdminCommand::Unban { .. } => "UNBAN",
            AdminCommand::Bans => "BANS",
            AdminCommand::Who => "WHO",
            AdminCommand::Disconnect { .. } => "DISCONNECT",
            AdminCommand::Notice { .. } => "NOTICE",
            AdminCommand::Rooms { .. } => "ROOMS",
            AdminCommand::Drop { .. } => "DROP",
            AdminCommand::Mute { .. } => "MUTE",
            AdminCommand::Unmute { .. } => "UNMUTE",
            AdminCommand::Reports => "REPORTS",
            AdminCommand::Unregister { .. } => "UNREGISTER",
            AdminCommand::Set(_) => "SET",
        }
    }

    fn parse(mut p: Params<'_>) -> Result<AdminCommand, ParseError> {
        let word = subcommand(&mut p)?;
        let end = |p: Params<'_>, command| p.end().map(|()| command);
        Ok(match word.as_str() {
            // 10.1
            "OPS" => end(p, AdminCommand::Ops)?,
            "OP" => AdminCommand::Op { uid: last(p)? },
            "DEOP" => AdminCommand::Deop { uid: last(p)? },
            // 10.2
            "BAN" => AdminCommand::Ban {
                target: tok(&mut p)?,
                reason: p.text().to_owned(),
            },
            "UNBAN" => AdminCommand::Unban { target: last(p)? },
            "BANS" => end(p, AdminCommand::Bans)?,
            // 10.3
            "WHO" => end(p, AdminCommand::Who)?,
            "DISCONNECT" => AdminCommand::Disconnect {
                uid: tok(&mut p)?,
                reason: p.text().to_owned(),
            },
            "NOTICE" => AdminCommand::Notice {
                message: required_text(p, "ADMIN NOTICE needs a message")?,
            },
            // 10.4
            "ROOMS" => {
                let options = options(p, &["after", "limit"])?;
                AdminCommand::Rooms {
                    after: opt(&options, "after")?,
                    limit: positive_opt(&options, "limit")?,
                }
            }
            "DROP" => AdminCommand::Drop {
                target: tok(&mut p)?,
                reason: p.text().to_owned(),
            },
            "MUTE" => {
                let mailbox = tok(&mut p)?;
                let pseudonym = tok(&mut p)?;
                let options = options(p, &["hours"])?;
                AdminCommand::Mute {
                    mailbox,
                    pseudonym,
                    hours: positive_opt(&options, "hours")?,
                }
            }
            "UNMUTE" => {
                let mailbox = tok(&mut p)?;
                let pseudonym = last(p)?;
                AdminCommand::Unmute { mailbox, pseudonym }
            }
            "REPORTS" => end(p, AdminCommand::Reports)?,
            // 10.5
            "UNREGISTER" => AdminCommand::Unregister { uid: last(p)? },
            // 10.6
            "SET" => {
                let key = p.token()?;
                AdminCommand::Set(ServerSetting::parse(key, p.text())?)
            }
            _ => return Err(unknown_subcommand("ADMIN", &word)),
        })
    }

    /// Adds the subcommand word and its parameters.
    fn write(&self, b: &mut LineBuilder) {
        b.token(self.word());
        match self {
            AdminCommand::Ops | AdminCommand::Bans | AdminCommand::Who | AdminCommand::Reports => {}
            AdminCommand::Op { uid }
            | AdminCommand::Deop { uid }
            | AdminCommand::Unregister { uid } => {
                b.token(uid);
            }
            AdminCommand::Ban { target, reason } => {
                b.token(target).text(reason);
            }
            AdminCommand::Unban { target } => {
                b.token(target);
            }
            AdminCommand::Disconnect { uid, reason } => {
                b.token(uid).text(reason);
            }
            AdminCommand::Notice { message } => {
                b.text(message);
            }
            AdminCommand::Rooms { after, limit } => {
                if let Some(after) = after {
                    b.option("after", after);
                }
                if let Some(limit) = limit {
                    b.option("limit", limit);
                }
            }
            AdminCommand::Drop { target, reason } => {
                b.token(target).text(reason);
            }
            AdminCommand::Mute {
                mailbox,
                pseudonym,
                hours,
            } => {
                b.token(mailbox).token(pseudonym);
                if let Some(hours) = hours {
                    b.option("hours", hours);
                }
            }
            AdminCommand::Unmute { mailbox, pseudonym } => {
                b.token(mailbox).token(pseudonym);
            }
            AdminCommand::Set(setting) => {
                b.token(setting.key()).text(&setting.value());
            }
        }
    }
}

/// The `<target>` of ADMIN DROP (10.4): a public room, named by its name,
/// or any mailbox, named by its box. A target that starts with `#` is a
/// room.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DropTarget {
    /// A public room.
    Room(Room),
    /// A mailbox.
    Mailbox(BoxName),
}

impl fmt::Display for DropTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropTarget::Room(room) => fmt::Display::fmt(room, f),
            DropTarget::Mailbox(mailbox) => fmt::Display::fmt(mailbox, f),
        }
    }
}

impl FromStr for DropTarget {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<DropTarget, ParseError> {
        if s.starts_with('#') {
            s.parse().map(DropTarget::Room)
        } else {
            s.parse().map(DropTarget::Mailbox)
        }
    }
}

/// Parses the commands of this module; `None` for any other verb.
pub(super) fn parse(verb: &str, p: Params<'_>) -> Option<Result<Command, ParseError>> {
    match verb {
        "ADMIN" => Some(AdminCommand::parse(p).map(Command::Admin)),
        "RESOLVE" => Some(last(p).map(|id| Command::Resolve { id })),
        _ => None,
    }
}

/// Writes the commands of this module; `false` for any other command.
pub(super) fn write(command: &Command, b: &mut LineBuilder) -> bool {
    match command {
        Command::Admin(admin) => admin.write(b),
        Command::Resolve { id } => {
            b.token(id);
        }
        _ => return false,
    }
    true
}

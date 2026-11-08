//! The commands of Sections 5 to 7: CREATE and POST (5.2, 7.8), UPLOAD
//! (5.6), REPORT (5.8), LIST, INFO and GROUPINFO (6.1, 8.5), MUTE and
//! UNMUTE (6.4), FOLLOW, UNFOLLOW and FETCH (7.1), and TOKEN (7.2).

use std::num::NonZeroU64;

use super::Command;
use crate::error::ParseError;
use crate::line::{LineBuilder, Params, Tags};
use crate::mls::{GroupInfo, OrBlob, RatchetTree};
use crate::names::{Room, Seq};
use crate::parse::{
    bad, flag_opt, last, number, opt, opt_tok, options, parse_tag, positive_opt, tok,
};

/// The two forms of CREATE (5.2), after `<box> <group-id> <token-hash>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateForm {
    /// `[epoch=<epoch>]`: the mailbox of a direct conversation or a
    /// private room, on an anonymous or guest connection.
    Private {
        /// `epoch=`: the first epoch of the new mailbox of a group that is
        /// moving (7.8), greater than 0. `None` for a new group, which
        /// starts at epoch 0.
        epoch: Option<NonZeroU64>,
    },
    /// `<room> <groupinfo> <tree>`: a public room, on a signed-in
    /// connection (6.1).
    Public(PublicRoom),
}

impl CreateForm {
    /// The first form without `epoch=`: a new group's mailbox.
    pub const NEW: CreateForm = CreateForm::Private { epoch: None };

    /// The epoch the mailbox starts at: 0, or `epoch=` (5.2, 7.8).
    pub fn first_epoch(&self) -> u64 {
        match self {
            CreateForm::Private { epoch: Some(e) } => e.get(),
            _ => 0,
        }
    }
}

/// What the second form of CREATE adds: the public room it creates
/// (5.2, 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRoom {
    /// The room's name.
    pub room: Room,
    /// The group's GroupInfo in epoch 0 (12.6).
    pub groupinfo: OrBlob<GroupInfo>,
    /// The group's ratchet tree in epoch 0: one leaf (12.6).
    pub tree: OrBlob<RatchetTree>,
}

/// Parses the commands of this module; `None` for any other verb.
pub(super) fn parse(verb: &str, tags: &Tags, p: Params<'_>) -> Option<Result<Command, ParseError>> {
    let parse: fn(&Tags, Params<'_>) -> Result<Command, ParseError> = match verb {
        "INFO" => |_, mut p| {
            let room = opt_tok(&mut p)?;
            p.end()?;
            Ok(Command::Info { room })
        },
        "CREATE" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let group_id = tok(&mut p)?;
            let token_hash = tok(&mut p)?;
            // The second form's room starts with `#`, which an option key
            // never does (3.3, 3.5). Anything else is the first form's
            // options.
            let mut peek = p;
            let form = match peek.opt_token()? {
                Some(room) if room.starts_with('#') => {
                    let public = PublicRoom {
                        room: room.parse()?,
                        groupinfo: tok(&mut peek)?,
                        tree: tok(&mut peek)?,
                    };
                    peek.end()?;
                    CreateForm::Public(public)
                }
                _ => {
                    let options = options(p, &["epoch"])?;
                    // `epoch` is "a number greater than 0" (5.2).
                    CreateForm::Private {
                        epoch: positive_opt(&options, "epoch")?,
                    }
                }
            };
            Ok(Command::Create {
                mailbox,
                group_id,
                token_hash,
                form,
            })
        },
        "POST" => |tags, mut p| {
            let cid = parse_tag(tags, "cid")?;
            let mailbox = tok(&mut p)?;
            let token = tok(&mut p)?;
            let message = tok(&mut p)?;
            let options = options(p, &["live", "groupinfo"])?;
            Ok(Command::Post {
                mailbox,
                token,
                message,
                live: flag_opt(&options, "live")?,
                groupinfo: opt(&options, "groupinfo")?,
                cid,
            })
        },
        "UPLOAD" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let token = tok(&mut p)?;
            let size = number(&mut p)?;
            p.end()?;
            Ok(Command::Upload {
                mailbox,
                token,
                size,
            })
        },
        "REPORT" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let report = last(p)?;
            Ok(Command::Report { mailbox, report })
        },
        "LIST" => |_, p| {
            let options = options(p, &["after", "limit"])?;
            Ok(Command::List {
                after: opt(&options, "after")?,
                limit: positive_opt(&options, "limit")?,
            })
        },
        "GROUPINFO" => |_, p| Ok(Command::GroupInfo { mailbox: last(p)? }),
        "MUTE" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let pseudonym = tok(&mut p)?;
            let options = options(p, &["hours"])?;
            Ok(Command::Mute {
                mailbox,
                pseudonym,
                hours: positive_opt(&options, "hours")?,
            })
        },
        "UNMUTE" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let pseudonym = last(p)?;
            Ok(Command::Unmute { mailbox, pseudonym })
        },
        "FOLLOW" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let options = options(p, &["quiet"])?;
            Ok(Command::Follow {
                mailbox,
                quiet: opt(&options, "quiet")?,
            })
        },
        "UNFOLLOW" => |_, p| Ok(Command::Unfollow { mailbox: last(p)? }),
        "TOKEN" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let epoch = number(&mut p)?;
            let token = tok(&mut p)?;
            let hash = last(p)?;
            Ok(Command::Token {
                mailbox,
                epoch,
                token,
                hash,
            })
        },
        "FETCH" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let options = options(p, &["after", "limit", "leaf"])?;
            // `after` is required, and may be 0 (7.1).
            let after = options.get("after").ok_or(bad("FETCH needs after="))?;
            let after = Seq::parse_or_zero(after)?.map_or(0, Seq::get);
            let leaf = options
                .get("leaf")
                .map(|v| {
                    crate::types::parse_u64(v)
                        .and_then(|n| u32::try_from(n).map_err(|_| bad("leaf is out of range")))
                })
                .transpose()?;
            Ok(Command::Fetch {
                mailbox,
                after,
                limit: positive_opt(&options, "limit")?,
                leaf,
            })
        },
        _ => return None,
    };
    Some(parse(tags, p))
}

/// Writes the commands of this module; `false` for any other command.
pub(super) fn write(command: &Command, b: &mut LineBuilder) -> bool {
    match command {
        Command::Info { room } => {
            if let Some(room) = room {
                b.token(room);
            }
        }
        Command::Create {
            mailbox,
            group_id,
            token_hash,
            form,
        } => {
            b.token(mailbox).token(group_id).token(token_hash);
            match form {
                CreateForm::Private { epoch: None } => {}
                CreateForm::Private { epoch: Some(epoch) } => {
                    b.option("epoch", epoch);
                }
                CreateForm::Public(public) => {
                    b.token(&public.room)
                        .token(&public.groupinfo)
                        .token(&public.tree);
                }
            }
        }
        Command::Post {
            mailbox,
            token,
            message,
            live,
            groupinfo,
            cid,
        } => {
            if let Some(cid) = cid {
                b.tag("cid", cid);
            }
            b.token(mailbox).token(token).token(message);
            if *live {
                b.option("live", "yes");
            }
            if let Some(groupinfo) = groupinfo {
                b.option("groupinfo", groupinfo);
            }
        }
        Command::Upload {
            mailbox,
            token,
            size,
        } => {
            b.token(mailbox).token(token).token(size);
        }
        Command::Report { mailbox, report } => {
            b.token(mailbox).token(report);
        }
        Command::List { after, limit } => {
            if let Some(after) = after {
                b.option("after", after);
            }
            if let Some(limit) = limit {
                b.option("limit", limit);
            }
        }
        Command::GroupInfo { mailbox } | Command::Unfollow { mailbox } => {
            b.token(mailbox);
        }
        Command::Token {
            mailbox,
            epoch,
            token,
            hash,
        } => {
            b.token(mailbox).token(epoch).token(token).token(hash);
        }
        Command::Mute {
            mailbox,
            pseudonym,
            hours,
        } => {
            b.token(mailbox).token(pseudonym);
            if let Some(hours) = hours {
                b.option("hours", hours);
            }
        }
        Command::Unmute { mailbox, pseudonym } => {
            b.token(mailbox).token(pseudonym);
        }
        Command::Follow { mailbox, quiet } => {
            b.token(mailbox);
            if let Some(quiet) = quiet {
                b.option("quiet", quiet);
            }
        }
        Command::Fetch {
            mailbox,
            after,
            limit,
            leaf,
        } => {
            b.token(mailbox).option("after", after);
            if let Some(limit) = limit {
                b.option("limit", limit);
            }
            if let Some(leaf) = leaf {
                b.option("leaf", leaf);
            }
        }
        _ => return false,
    }
    true
}

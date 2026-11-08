//! The lines of Sections 4, 8, 9 and 12: RECORD (4.7), PAIR (4.8), USER,
//! MEMBER and PRESENCE (8.3), PUSH (9.1), KEYPKG (12.5), WELCOME (12.8)
//! and BACKUP (12.13).

use std::str::FromStr;

use super::ServerLine;
use crate::error::ParseError;
use crate::line::{LineBuilder, Params};
use crate::names::Uid;
use crate::parse::{last, number, number_u32, opt, options, tok};

/// Parses the lines of this module; `None` for any other verb.
pub(super) fn parse(verb: &str, p: Params<'_>) -> Option<Result<ServerLine, ParseError>> {
    let parse: fn(Params<'_>) -> Result<ServerLine, ParseError> = match verb {
        "RECORD" => |mut p| {
            let index = number(&mut p)?;
            let hash = last(p)?;
            Ok(ServerLine::Record { index, hash })
        },
        "PAIR" => |mut p| {
            let id = tok(&mut p)?;
            let data = last(p)?;
            Ok(ServerLine::Pair { id, data })
        },
        "USER" => |mut p| {
            let uid = tok(&mut p)?;
            let presence = last(p)?;
            Ok(ServerLine::User { uid, presence })
        },
        "MEMBER" => |mut p| {
            let room = tok(&mut p)?;
            let uid = tok(&mut p)?;
            let role = tok(&mut p)?;
            let presence = last(p)?;
            Ok(ServerLine::Member {
                room,
                uid,
                role,
                presence,
            })
        },
        "PRESENCE" => |mut p| {
            let presence = tok(&mut p)?;
            let uids = p
                .token()?
                .split(',')
                .map(Uid::from_str)
                .collect::<Result<Vec<_>, _>>()?;
            p.end()?;
            Ok(ServerLine::Presence { presence, uids })
        },
        "PUSH" => |mut p| {
            let url = tok(&mut p)?;
            let tag = last(p)?;
            Ok(ServerLine::Push { url, tag })
        },
        "KEYPKG" => |mut p| {
            let uid = tok(&mut p)?;
            let key_package = last(p)?;
            Ok(ServerLine::KeyPkg { uid, key_package })
        },
        "WELCOME" => |mut p| {
            let id = tok(&mut p)?;
            let welcome = last(p)?;
            Ok(ServerLine::Welcome { id, welcome })
        },
        "BACKUP" => |mut p| {
            let generation = number_u32(&mut p)?;
            let hash = tok(&mut p)?;
            let key = tok(&mut p)?;
            let options = options(p, &["files"])?;
            Ok(ServerLine::Backup {
                generation,
                hash,
                key,
                files: opt(&options, "files")?,
            })
        },
        _ => return None,
    };
    Some(parse(p))
}

/// Writes the lines of this module; `false` for any other line.
pub(super) fn write(line: &ServerLine, b: &mut LineBuilder) -> bool {
    match line {
        ServerLine::Record { index, hash } => {
            b.token(index).token(hash);
        }
        ServerLine::Pair { id, data } => {
            b.token(id).token(data);
        }
        ServerLine::User { uid, presence } => {
            b.token(uid).token(presence);
        }
        ServerLine::Member {
            room,
            uid,
            role,
            presence,
        } => {
            b.token(room).token(uid).token(role).token(presence);
        }
        ServerLine::Presence { presence, uids } => {
            let list: Vec<&str> = uids.iter().map(Uid::as_str).collect();
            b.token(presence).token(list.join(","));
        }
        ServerLine::Push { url, tag } => {
            b.token(url).token(tag);
        }
        ServerLine::KeyPkg { uid, key_package } => {
            b.token(uid).token(key_package);
        }
        ServerLine::Welcome { id, welcome } => {
            b.token(id).token(welcome);
        }
        ServerLine::Backup {
            generation,
            hash,
            key,
            files,
        } => {
            b.token(generation).token(hash).token(key);
            if let Some(files) = files {
                b.option("files", files);
            }
        }
        _ => return false,
    }
    true
}

//! The lines of Section 10: OP (10.1), SERVERBAN (10.2) and CONNECTION
//! (10.3). ROOM lines for ADMIN ROOMS and REPORT lines for ADMIN REPORTS
//! are in [`mailbox`](super::mailbox).

use std::net::{IpAddr, SocketAddr};

use super::ServerLine;
use crate::error::ParseError;
use crate::line::{LineBuilder, Params};
use crate::parse::{bad, last, tok};

/// Reads an IP address, with or without a port (10.3): `203.0.113.7`,
/// `203.0.113.7:51000`, `2001:db8::1` or `[2001:db8::1]:51000`.
fn parse_address(s: &str) -> Result<(IpAddr, Option<u16>), ParseError> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, None));
    }
    s.parse::<SocketAddr>()
        .map(|addr| (addr.ip(), Some(addr.port())))
        .map_err(|_| bad("an address is an IP address, with or without a port"))
}

/// Parses the lines of this module; `None` for any other verb.
pub(super) fn parse(verb: &str, p: Params<'_>) -> Option<Result<ServerLine, ParseError>> {
    let parse: fn(Params<'_>) -> Result<ServerLine, ParseError> = match verb {
        "OP" => |p| Ok(ServerLine::Op { uid: last(p)? }),
        "SERVERBAN" => |mut p| {
            let target = tok(&mut p)?;
            Ok(ServerLine::ServerBan {
                target,
                reason: p.text().to_owned(),
            })
        },
        "CONNECTION" => |mut p| {
            let uid = match p.token()? {
                "-" => None,
                uid => Some(uid.parse()?),
            };
            let (address, port) = parse_address(p.token()?)?;
            let since = last(p)?;
            Ok(ServerLine::Connection {
                uid,
                address,
                port,
                since,
            })
        },
        _ => return None,
    };
    Some(parse(p))
}

/// Writes the lines of this module; `false` for any other line.
pub(super) fn write(line: &ServerLine, b: &mut LineBuilder) -> bool {
    match line {
        ServerLine::Op { uid } => {
            b.token(uid);
        }
        ServerLine::ServerBan { target, reason } => {
            b.token(target).text(reason);
        }
        ServerLine::Connection {
            uid,
            address,
            port,
            since,
        } => {
            match uid {
                Some(uid) => b.token(uid),
                None => b.token("-"),
            };
            match port {
                Some(port) => b.token(SocketAddr::new(*address, *port)),
                None => b.token(address),
            };
            b.token(since);
        }
        _ => return false,
    }
    true
}

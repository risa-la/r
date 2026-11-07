//! Typed server lines, server to client (SPEC 3.6, 4.1, 5-11), and the
//! NOTIFY push body (9.3).
//!
//! Every line in the second table of Section 12 parses into a
//! [`ServerMessage`]: an envelope with the `ref` (3.6) and `report` (5.8)
//! tags, around a [`ServerLine`]. Events and snapshots (5.2) share one
//! type, [`Event`], whose [`meta`](Event::meta) is `None` for a snapshot.
//!
//! ```
//! use risala_proto::server::{ServerLine, ServerMessage};
//!
//! let msg: ServerMessage =
//!     "@seq=8811;t=2026-11-06T15:31:40.950Z;from=bob@example.net MSG #general yep".parse()?;
//! let ServerLine::Event(event) = &msg.line else { panic!() };
//! assert_eq!(event.meta.as_ref().unwrap().seq.get(), 8811);
//! assert_eq!(msg.to_line().to_string(),
//!     "@seq=8811;t=2026-11-06T15:31:40.950Z;from=bob@example.net MSG #general yep");
//! # Ok::<(), risala_proto::error::ParseError>(())
//! ```
//!
//! A server builds lines from values:
//!
//! ```
//! use risala_proto::names::Seq;
//! use risala_proto::server::{OkResponse, ServerMessage};
//!
//! let seq = Seq::new(8813).unwrap();
//! let ok = ServerMessage::new(OkResponse::new().with("seq", seq));
//! assert_eq!(ok.to_line().to_string(), "OK seq=8813");
//! ```
//!
//! Decisions where the spec leaves room:
//!
//! - **Unknown verbs** parse as [`ServerLine::Unknown`], not as an error,
//!   since clients ignore lines with unknown verbs (3.8). A known verb with
//!   the wrong parameters is an error, and a client ignores it (2.3).
//! - **Unknown and inapplicable tags are ignored** (3.2). That includes
//!   `seq`, `t` and `from` on lines that are not events, REPORT, TYPING or
//!   NAME (a `seq` on a PRESENCE line, say), and `reply`, `file` or
//!   `deleted` on events other than MSG. A client gains nothing from
//!   dropping such a line, and the tags are not read, so their values are
//!   not checked either. Serialising leaves them out.
//! - **Tags that are read are checked.** A bad `ref`, `report`, `seq`,
//!   `t`, `from`, relation, `file`, `file-size` or `retry` value is an
//!   error, as is one of these tags without a value. `deleted` is a flag;
//!   a value on it is ignored.
//! - **Events and snapshots (5.2).** `seq`, `t` and `from` must be all
//!   present (an event) or all absent (a snapshot); anything in between is
//!   `BadSyntax`. Only SET, BAN and ROLE may be snapshots (Section 12), so a
//!   MSG, DELETE, JOIN, PART, INVITE, KICK or UNBAN without them is
//!   `BadSyntax`.
//! - **Messages (5.3, 5.4, 5.6).** At most one of `reply`, `edit` and
//!   `react`, and no `file` with `edit` or `react`, as for commands. A
//!   `deleted` message has empty text; any other message has text. A
//!   `file` must be an `https` URL of at most 512 bytes. `file-type` and
//!   `file-size` are optional, so a client still shows a file whose
//!   metadata a server left out; without `file` they are ignored.
//! - **Length limits** stated by the spec are applied as on commands, so a
//!   correct server never trips them: a topic (ROOM, SET) or a report
//!   reason of 512 bytes, a display name (MEMBER, USER, NAME) of 128 and a
//!   reaction of 64. Longer values are `TooLong`. Other text has no limit
//!   beyond the line's.
//! - **Uids.** INVITE, KICK, BAN, UNBAN, ROLE and OP take any [`Uid`], as
//!   the commands do, even where the spec says the target is always an
//!   identity. Whether that holds is the server's business, and a client
//!   need not drop the line to find out.
//! - **Optional text** (`[<reason...>]`, `[<name...>]` and so on) is a
//!   `String`, empty when absent: on the wire the two are the same (3.3).
//!   Required text (`<message...>` of NOTICE, `<text...>` of MSG) must not
//!   be empty.
//! - **Text stays escaped** (3.4). Unescape it with
//!   [`text::unescape`](crate::text::unescape) to display it.
//! - **Case.** Verbs and keywords are case-insensitive and names are
//!   folded (3.5). Serialising writes the canonical form, so a parsed line
//!   in canonical form serialises back byte for byte.
//!
//! Tags are written in this order: `ref`, `report`, then `seq`, `t`,
//! `from`, the relation (`reply`, `edit` or `react`), `file`, `file-type`,
//! `file-size` and `deleted`, or `retry` on ERR. This reproduces every
//! example in the spec.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use crate::auth::{Nonce, PublicKey};
use crate::error::{ErrorCode, ParseError};
use crate::line::{Line, LineBuilder, Params, Tags, is_token};
use crate::names::{BlockTarget, Conv, Domain, Id, Room, Seq, ServerBanTarget, Uid};
use crate::time::Timestamp;
use crate::types::{
    FileUrl, InfoRole, MAX_DISPLAY_NAME, MAX_REACTION, MAX_REPORT_REASON, MAX_TOPIC, MAX_WELCOME,
    MediaType, NotifyReason, Presence, PushTag, PushUrl, Ref, Relation, Role, RoomSetting,
    ServerRetention, parse_u64, parse_yes_no, yes_no,
};

const fn bad(what: &'static str) -> ParseError {
    ParseError::BadSyntax(what)
}

// ---------------------------------------------------------------------------
// The envelope

/// A line from the server (Section 12, second table), with the tags that
/// any line may carry (3.6, 5.8).
///
/// - `ref_` is the client's `ref` tag, copied onto every response line and
///   the final OK or ERR of the command that had it (3.6). Live events
///   never carry it.
/// - `report` is the `report` tag (5.8). It is on [`ServerLine::Report`]
///   lines and on [`ServerLine::ReportCopy`], the reported event sent with
///   them, and both need it. On any other line it is kept but means
///   nothing.
///
/// For [`ServerLine::Unknown`], these two tags are taken out of the line
/// and kept here, so that a client can still match a `ref` (3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerMessage {
    /// The `ref` tag (3.6).
    pub ref_: Option<Ref>,
    /// The `report` tag: the id of the report the line belongs to (5.8).
    pub report: Option<Id>,
    /// The line itself.
    pub line: ServerLine,
}

impl ServerMessage {
    /// A message with no `ref` and no `report` tag.
    pub fn new(line: impl Into<ServerLine>) -> ServerMessage {
        ServerMessage {
            ref_: None,
            report: None,
            line: line.into(),
        }
    }

    /// Sets the `ref` tag (3.6), for a response line or a final response.
    pub fn with_ref(mut self, ref_: Ref) -> ServerMessage {
        self.ref_ = Some(ref_);
        self
    }

    /// Sets the `ref` tag (3.6) if there is one, as when answering a
    /// command that may have had one.
    pub fn with_ref_opt(mut self, ref_: Option<Ref>) -> ServerMessage {
        self.ref_ = ref_;
        self
    }

    /// The REPORT line of report `id` (5.8).
    pub fn report_line(id: Id, report: Report) -> ServerMessage {
        ServerMessage {
            ref_: None,
            report: Some(id),
            line: ServerLine::Report(report),
        }
    }

    /// The copy of the reported event that follows the REPORT line of
    /// report `id` (5.8). The event needs its `seq`, `t` and `from`.
    pub fn report_copy(id: Id, event: Event) -> ServerMessage {
        ServerMessage {
            ref_: None,
            report: Some(id),
            line: ServerLine::ReportCopy(event),
        }
    }

    /// Parses a line from the server (Section 12).
    ///
    /// An unknown verb gives [`ServerLine::Unknown`] (3.8). A known verb
    /// with bad parameters or bad tags fails with `BadSyntax`, or `TooLong`
    /// for a value over a protocol limit. See the [module](self) docs for
    /// what is checked and what is ignored.
    pub fn parse(line: &Line) -> Result<ServerMessage, ParseError> {
        let tags = line.tags();
        let ref_ = parse_tag::<Ref>(tags, "ref")?;
        let report = parse_tag::<Id>(tags, "report")?;
        let verb = line.verb_upper();
        let params = line.params();
        let line = match &*verb {
            "RISALA" => ServerLine::Greeting(Greeting::parse(params)?),
            "OK" => ServerLine::Ok(OkResponse::parse(params)?),
            "ERR" => ServerLine::Err(ErrResponse::parse(tags, params)?),
            "MSG" | "DELETE" | "JOIN" | "PART" | "INVITE" | "KICK" | "BAN" | "UNBAN" | "SET"
            | "ROLE" => {
                let event = Event::parse(&verb, tags, params)?;
                if report.is_some() {
                    if event.meta.is_none() {
                        return Err(bad("a reported event has seq, t and from"));
                    }
                    ServerLine::ReportCopy(event)
                } else {
                    ServerLine::Event(event)
                }
            }
            "REPORT" => {
                if report.is_none() {
                    return Err(bad("a REPORT line has a report tag"));
                }
                ServerLine::Report(Report::parse(tags, params)?)
            }
            _ => parse_response(&verb, tags, params)?.unwrap_or_else(|| {
                let mut rest = line.clone();
                rest.tags_mut().remove("ref");
                rest.tags_mut().remove("report");
                ServerLine::Unknown(rest)
            }),
        };
        Ok(ServerMessage { ref_, report, line })
    }

    /// Serialises the message, in canonical form.
    ///
    /// # Panics
    ///
    /// If the message is not valid, for example text with a line break,
    /// an empty PRESENCE list or a REPORT line without `report`. Every
    /// parsed message is valid. Use [`try_to_line`](Self::try_to_line) for
    /// messages built from values that were not checked.
    pub fn to_line(&self) -> Line {
        match self.try_to_line() {
            Ok(line) => line,
            Err(e) => panic!("invalid ServerMessage ({e}): {self:?}"),
        }
    }

    /// Serialises the message, in canonical form, or says why it is not
    /// valid: what [`parse`](Self::parse) would reject, such as a bad
    /// token, a control character in text, a missing tag or a value over a
    /// limit.
    ///
    /// The line it returns always parses back to an equal message. It is
    /// written, then parsed again from its string form and compared, so
    /// values that are valid but not canonical, such as
    /// `RoomSetting::Other` with the key `topic` or `ErrorCode::Other`
    /// holding a known code, fail too.
    pub fn try_to_line(&self) -> Result<Line, ParseError> {
        let line = self.write_line()?;
        let reparsed = ServerMessage::parse(&Line::parse(&line.to_string())?)?;
        if reparsed == *self {
            Ok(line)
        } else {
            Err(bad("the message is not in canonical form"))
        }
    }

    /// Writes the line without checking that it parses back.
    fn write_line(&self) -> Result<Line, ParseError> {
        if let ServerLine::Unknown(line) = &self.line {
            let mut tags = Tags::new();
            if let Some(ref_) = &self.ref_ {
                tags.insert("ref", Some(ref_.as_str()))?;
            }
            if let Some(report) = &self.report {
                tags.insert("report", Some(report.as_str()))?;
            }
            for (key, value) in line.tags().iter() {
                tags.insert(key, value)?;
            }
            let mut line = line.clone();
            *line.tags_mut() = tags;
            return Ok(line);
        }
        let mut b = Line::builder(self.line.verb());
        if let Some(ref_) = &self.ref_ {
            b.tag("ref", ref_);
        }
        if let Some(report) = &self.report {
            b.tag("report", report);
        }
        match &self.line {
            ServerLine::Report(_) | ServerLine::ReportCopy(_) if self.report.is_none() => {
                return Err(bad("a report line needs the report tag"));
            }
            _ => {}
        }
        self.line.write(&mut b)?;
        b.build()
    }

    /// Whether this is a copy of a reported event, which clients must not
    /// treat as a new event (5.8).
    pub fn is_report_copy(&self) -> bool {
        matches!(self.line, ServerLine::ReportCopy(_))
    }
}

impl FromStr for ServerMessage {
    type Err = ParseError;

    /// Parses a line without its line ending, then the message.
    fn from_str(s: &str) -> Result<ServerMessage, ParseError> {
        ServerMessage::parse(&Line::parse(s)?)
    }
}

impl From<ServerLine> for ServerMessage {
    fn from(line: ServerLine) -> ServerMessage {
        ServerMessage::new(line)
    }
}

// ---------------------------------------------------------------------------
// Lines

/// One line a server can send (Section 12, second table), without the
/// `ref` and `report` tags, which are in [`ServerMessage`].
///
/// Text fields hold escaped text (3.4) without control characters other
/// than TAB. Where the syntax has optional text, the field is empty when
/// the text is absent.
///
/// `Conv` fields follow 5.2: in a direct conversation, the conv is the
/// other participant as seen by the receiver of the line, which is the uid
/// to send to in order to reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerLine {
    /// `RISALA <version> <host> <nonce> [<message...>]`, the greeting
    /// (4.1).
    Greeting(Greeting),
    /// `OK [<key>=<value> ...]`, a final response (3.6).
    Ok(OkResponse),
    /// `ERR <code> [<message...>]`, a final response (3.6, 3.7).
    Err(ErrResponse),
    /// An event or a snapshot (5.2): MSG, DELETE, JOIN, PART, INVITE,
    /// KICK, BAN, UNBAN, SET or ROLE.
    Event(Event),
    /// The copy of a reported event that follows a [`Report`](Self::Report)
    /// line, with the same `report` tag (5.8). It always has its `seq`, `t`
    /// and `from`. Clients must not treat it as a new event in the
    /// conversation.
    ReportCopy(Event),
    /// `REPORT <conv> <seq> [<reason...>]`, a report sent to its reviewers
    /// (5.8). The [`ServerMessage::report`] tag is required.
    Report(Report),
    /// `RESOLVED <id>`: another reviewer resolved report `id` (5.8).
    Resolved {
        /// The report's id.
        id: Id,
    },
    /// `ROOM <room> <members> [<topic...>]`, a response to LIST (6.1) or
    /// ADMIN ROOMS (10.4).
    Room {
        /// The room.
        room: Room,
        /// The number of members.
        members: u64,
        /// The topic, escaped, at most 512 bytes; empty if none.
        topic: String,
    },
    /// `CONV <conv> <id> <head> <read>`, a response to SYNC (7.1).
    Conv {
        /// The conversation, named as in 5.2.
        conv: Conv,
        /// The conversation's id (5.1).
        id: Id,
        /// The newest seq.
        head: Seq,
        /// The account's read marker, or `None` for `0`: no marker, or a
        /// guest (7.1, 7.4).
        read: Option<Seq>,
    },
    /// `MEMBER <room> <uid> <role> <presence> [<name...>]`, a response to
    /// MEMBERS (8.3).
    Member {
        /// The room.
        room: Room,
        /// The member.
        uid: Uid,
        /// The member's role (6.3).
        role: Role,
        /// Their presence.
        presence: Presence,
        /// Their display name, escaped, at most 128 bytes; empty if none.
        name: String,
    },
    /// `USER <uid> <presence> [<name...>]`, a response to WHOIS (8.3).
    User {
        /// The user.
        uid: Uid,
        /// Their presence.
        presence: Presence,
        /// Their display name, escaped, at most 128 bytes; empty if none.
        name: String,
    },
    /// `PRESENCE <presence> <uids>`: users came online or went offline
    /// (8.3).
    Presence {
        /// The new presence of every listed user.
        presence: Presence,
        /// The users, at least one. Written separated by commas.
        uids: Vec<Uid>,
    },
    /// `BLOCK <target>`, a response to BLOCKS (5.7).
    Block {
        /// The blocked identity or domain.
        target: BlockTarget,
    },
    /// `KEY <key> [<label...>]`, a response to KEY LIST (4.7) or ADMIN
    /// KEYS (10.5).
    Key {
        /// The public key.
        key: PublicKey,
        /// The key's label, escaped; empty if none.
        label: String,
    },
    /// `PUSH <url> <tag>`, a response to PUSH LIST (9.1).
    Push {
        /// The push URL, an `https` URL in one token.
        url: PushUrl,
        /// The registration's tag.
        tag: PushTag,
    },
    /// `READ <conv> <seq>`: the read marker moved on another of the
    /// account's connections (7.4). Not an event.
    Read {
        /// The conversation, named as in 5.2.
        conv: Conv,
        /// The new marker.
        seq: Seq,
    },
    /// `@from=<uid> TYPING <conv>`: someone is typing (8.1). Not stored.
    Typing {
        /// Who is typing, from the required `from` tag.
        from: Uid,
        /// The conversation, named as in 5.2.
        conv: Conv,
    },
    /// `@from=<uid> NAME [<name...>]`: someone set their display name
    /// (8.2).
    Name {
        /// Whose name it is, from the required `from` tag.
        from: Uid,
        /// The display name, escaped, at most 128 bytes; empty if cleared.
        name: String,
    },
    /// `NOTICE <message...>`: information for people (8.4, 10.3).
    Notice {
        /// The message, escaped, not empty.
        message: String,
    },
    /// `DROP <room> [<reason...>]`: an operator deleted the room (10.4).
    Drop {
        /// The room.
        room: Room,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// `OP <uid>`, a response to ADMIN OPS (10.1).
    Op {
        /// The operator.
        uid: Uid,
    },
    /// `SERVERBAN <target> [<reason...>]`, a response to ADMIN BANS
    /// (10.2).
    ServerBan {
        /// What is banned.
        target: ServerBanTarget,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// `CONNECTION <uid> <address> <since>`, a response to ADMIN WHO
    /// (10.3).
    ///
    /// The spec does not say how `<address>` is written. This crate reads
    /// an IP address, or an IP address with a port in the usual
    /// `203.0.113.7:51000` or `[2001:db8::1]:51000` form, and writes it the
    /// same way.
    Connection {
        /// The connection's uid, or `None` for `-`: not signed in yet.
        uid: Option<Uid>,
        /// The client's IP address.
        address: IpAddr,
        /// The client's port, if the server sent one.
        port: Option<u16>,
        /// When the connection was opened.
        since: Timestamp,
    },
    /// `PING <token>`: the server checks the connection (11). The client
    /// answers `PONG <token>`.
    Ping {
        /// The token, required from a server.
        token: String,
    },
    /// `BYE [<message...>]`: the server is about to close the connection
    /// (11).
    Bye {
        /// The message, escaped; empty if none.
        message: String,
    },
    /// A line with a verb this crate does not know (3.8). Clients ignore
    /// it. The `ref` and `report` tags are moved to the
    /// [`ServerMessage`]; every other tag stays in the line.
    Unknown(Line),
}

impl ServerLine {
    /// The verb, in upper case (3.1). For [`Unknown`](Self::Unknown), the
    /// verb as written.
    pub fn verb(&self) -> &str {
        match self {
            ServerLine::Greeting(_) => "RISALA",
            ServerLine::Ok(_) => "OK",
            ServerLine::Err(_) => "ERR",
            ServerLine::Event(e) | ServerLine::ReportCopy(e) => e.body.verb(),
            ServerLine::Report(_) => "REPORT",
            ServerLine::Resolved { .. } => "RESOLVED",
            ServerLine::Room { .. } => "ROOM",
            ServerLine::Conv { .. } => "CONV",
            ServerLine::Member { .. } => "MEMBER",
            ServerLine::User { .. } => "USER",
            ServerLine::Presence { .. } => "PRESENCE",
            ServerLine::Block { .. } => "BLOCK",
            ServerLine::Key { .. } => "KEY",
            ServerLine::Push { .. } => "PUSH",
            ServerLine::Read { .. } => "READ",
            ServerLine::Typing { .. } => "TYPING",
            ServerLine::Name { .. } => "NAME",
            ServerLine::Notice { .. } => "NOTICE",
            ServerLine::Drop { .. } => "DROP",
            ServerLine::Op { .. } => "OP",
            ServerLine::ServerBan { .. } => "SERVERBAN",
            ServerLine::Connection { .. } => "CONNECTION",
            ServerLine::Ping { .. } => "PING",
            ServerLine::Bye { .. } => "BYE",
            ServerLine::Unknown(line) => line.verb(),
        }
    }

    /// Whether this is a final response, OK or ERR (3.6).
    pub fn is_final(&self) -> bool {
        matches!(self, ServerLine::Ok(_) | ServerLine::Err(_))
    }

    /// Adds this line's tags and parameters to `b`, which has the verb and
    /// the envelope tags. Not for `Unknown`.
    fn write(&self, b: &mut LineBuilder) -> Result<(), ParseError> {
        match self {
            ServerLine::Greeting(g) => g.write(b),
            ServerLine::Ok(ok) => ok.write(b),
            ServerLine::Err(err) => err.write(b),
            ServerLine::Event(e) => e.write(b)?,
            ServerLine::ReportCopy(e) => {
                if e.meta.is_none() {
                    return Err(bad("a reported event has seq, t and from"));
                }
                e.write(b)?;
            }
            ServerLine::Report(r) => r.write(b)?,
            ServerLine::Resolved { id } => {
                b.token(id);
            }
            ServerLine::Room {
                room,
                members,
                topic,
            } => {
                limit(topic, MAX_TOPIC)?;
                b.token(room).token(members).text(topic);
            }
            ServerLine::Conv {
                conv,
                id,
                head,
                read,
            } => {
                b.token(conv).token(id).token(head);
                match read {
                    Some(read) => b.token(read),
                    None => b.token(0),
                };
            }
            ServerLine::Member {
                room,
                uid,
                role,
                presence,
                name,
            } => {
                limit(name, MAX_DISPLAY_NAME)?;
                b.token(room)
                    .token(uid)
                    .token(role)
                    .token(presence)
                    .text(name);
            }
            ServerLine::User {
                uid,
                presence,
                name,
            } => {
                limit(name, MAX_DISPLAY_NAME)?;
                b.token(uid).token(presence).text(name);
            }
            ServerLine::Presence { presence, uids } => {
                if uids.is_empty() {
                    return Err(bad("PRESENCE lists at least one uid"));
                }
                let list: Vec<&str> = uids.iter().map(Uid::as_str).collect();
                b.token(presence).token(list.join(","));
            }
            ServerLine::Block { target } => {
                b.token(target);
            }
            ServerLine::Key { key, label } => {
                b.token(key).text(label);
            }
            ServerLine::Push { url, tag } => {
                b.token(url).token(tag);
            }
            ServerLine::Read { conv, seq } => {
                b.token(conv).token(seq);
            }
            ServerLine::Typing { from, conv } => {
                b.tag("from", from).token(conv);
            }
            ServerLine::Name { from, name } => {
                limit(name, MAX_DISPLAY_NAME)?;
                b.tag("from", from).text(name);
            }
            ServerLine::Notice { message } => {
                if message.is_empty() {
                    return Err(bad("NOTICE has a message"));
                }
                b.text(message);
            }
            ServerLine::Drop { room, reason } => {
                b.token(room).text(reason);
            }
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
            ServerLine::Ping { token } => {
                b.token(token);
            }
            ServerLine::Bye { message } => {
                b.text(message);
            }
            ServerLine::Unknown(_) => unreachable!("unknown lines are copied, not built"),
        }
        Ok(())
    }
}

impl From<Greeting> for ServerLine {
    fn from(g: Greeting) -> ServerLine {
        ServerLine::Greeting(g)
    }
}

impl From<OkResponse> for ServerLine {
    fn from(ok: OkResponse) -> ServerLine {
        ServerLine::Ok(ok)
    }
}

impl From<ErrResponse> for ServerLine {
    fn from(err: ErrResponse) -> ServerLine {
        ServerLine::Err(err)
    }
}

impl From<Event> for ServerLine {
    /// A live event or snapshot. For a report copy, use
    /// [`ServerMessage::report_copy`].
    fn from(event: Event) -> ServerLine {
        ServerLine::Event(event)
    }
}

/// Parses the response lines and other lines that are not greetings, final
/// responses, events or reports. `None` for an unknown verb.
fn parse_response(
    verb: &str,
    tags: &Tags,
    mut p: Params<'_>,
) -> Result<Option<ServerLine>, ParseError> {
    let line = match verb {
        "RESOLVED" => {
            let id = token(&mut p)?;
            p.end()?;
            ServerLine::Resolved { id }
        }
        "ROOM" => {
            let room = token(&mut p)?;
            let members = parse_u64(p.token()?)?;
            let topic = text(p, MAX_TOPIC)?;
            ServerLine::Room {
                room,
                members,
                topic,
            }
        }
        "CONV" => {
            let conv = token(&mut p)?;
            let id = token(&mut p)?;
            let head = token(&mut p)?;
            let read = Seq::parse_or_zero(p.token()?)?;
            p.end()?;
            ServerLine::Conv {
                conv,
                id,
                head,
                read,
            }
        }
        "MEMBER" => {
            let room = token(&mut p)?;
            let uid = token(&mut p)?;
            let role = token(&mut p)?;
            let presence = token(&mut p)?;
            let name = text(p, MAX_DISPLAY_NAME)?;
            ServerLine::Member {
                room,
                uid,
                role,
                presence,
                name,
            }
        }
        "USER" => {
            let uid = token(&mut p)?;
            let presence = token(&mut p)?;
            let name = text(p, MAX_DISPLAY_NAME)?;
            ServerLine::User {
                uid,
                presence,
                name,
            }
        }
        "PRESENCE" => {
            let presence = token(&mut p)?;
            let uids = p
                .token()?
                .split(',')
                .map(Uid::from_str)
                .collect::<Result<Vec<_>, _>>()?;
            p.end()?;
            ServerLine::Presence { presence, uids }
        }
        "BLOCK" => {
            let target = token(&mut p)?;
            p.end()?;
            ServerLine::Block { target }
        }
        "KEY" => {
            let key = token(&mut p)?;
            let label = p.text().to_owned();
            ServerLine::Key { key, label }
        }
        "PUSH" => {
            let url = token(&mut p)?;
            let tag = token(&mut p)?;
            p.end()?;
            ServerLine::Push { url, tag }
        }
        "READ" => {
            let conv = token(&mut p)?;
            let seq = token(&mut p)?;
            p.end()?;
            ServerLine::Read { conv, seq }
        }
        "TYPING" => {
            let from = required_tag(tags, "from")?;
            let conv = token(&mut p)?;
            p.end()?;
            ServerLine::Typing { from, conv }
        }
        "NAME" => {
            let from = required_tag(tags, "from")?;
            let name = text(p, MAX_DISPLAY_NAME)?;
            ServerLine::Name { from, name }
        }
        "NOTICE" => {
            let message = p.text();
            if message.is_empty() {
                return Err(bad("NOTICE has a message"));
            }
            ServerLine::Notice {
                message: message.to_owned(),
            }
        }
        "DROP" => {
            let room = token(&mut p)?;
            let reason = p.text().to_owned();
            ServerLine::Drop { room, reason }
        }
        "OP" => {
            let uid = token(&mut p)?;
            p.end()?;
            ServerLine::Op { uid }
        }
        "SERVERBAN" => {
            let target = token(&mut p)?;
            let reason = p.text().to_owned();
            ServerLine::ServerBan { target, reason }
        }
        "CONNECTION" => {
            let uid = match p.token()? {
                "-" => None,
                uid => Some(uid.parse()?),
            };
            let (address, port) = parse_address(p.token()?)?;
            let since = token(&mut p)?;
            p.end()?;
            ServerLine::Connection {
                uid,
                address,
                port,
                since,
            }
        }
        "PING" => {
            let token = p.token()?.to_owned();
            p.end()?;
            ServerLine::Ping { token }
        }
        "BYE" => ServerLine::Bye {
            message: p.text().to_owned(),
        },
        _ => return Ok(None),
    };
    Ok(Some(line))
}

/// Reads an IP address, with or without a port (10.3).
fn parse_address(s: &str) -> Result<(IpAddr, Option<u16>), ParseError> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, None));
    }
    s.parse::<SocketAddr>()
        .map(|addr| (addr.ip(), Some(addr.port())))
        .map_err(|_| bad("an address is an IP address, with or without a port"))
}

// ---------------------------------------------------------------------------
// Small parse helpers

/// The value of tag `key`, or `None` if absent. A tag that must have a
/// value but has none is `BadSyntax`.
fn tag_value<'a>(tags: &'a Tags, key: &str) -> Result<Option<&'a str>, ParseError> {
    match tags.entry(key) {
        None => Ok(None),
        Some(None) => Err(bad("tag needs a value")),
        Some(Some(value)) => Ok(Some(value)),
    }
}

/// Parses the value of tag `key`, if present.
fn parse_tag<T: FromStr<Err = ParseError>>(
    tags: &Tags,
    key: &str,
) -> Result<Option<T>, ParseError> {
    tag_value(tags, key)?.map(str::parse).transpose()
}

/// Parses the value of tag `key`, which must be present.
fn required_tag<T: FromStr<Err = ParseError>>(tags: &Tags, key: &str) -> Result<T, ParseError> {
    parse_tag(tags, key)?.ok_or(bad("missing a required tag"))
}

/// Reads and parses the next token.
fn token<T: FromStr<Err = ParseError>>(p: &mut Params<'_>) -> Result<T, ParseError> {
    p.token()?.parse()
}

/// Reads the text, checking a length limit in bytes.
fn text(p: Params<'_>, max: usize) -> Result<String, ParseError> {
    let text = p.text();
    limit(text, max)?;
    Ok(text.to_owned())
}

/// `TooLong` if `text` is longer than `max` bytes.
fn limit(text: &str, max: usize) -> Result<(), ParseError> {
    if text.len() > max {
        Err(ParseError::TooLong)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Greeting

/// The greeting, `RISALA <version> <host> <nonce> [<message...>]` (4.1).
///
/// A client that does not support `version` must close the connection
/// (3.8); the version is kept whatever it is, so that the caller decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// The protocol version, `1` for this spec
    /// ([`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION)).
    pub version: u32,
    /// The hostname from SNI, in lower case. A client signs with the
    /// hostname it sent, not this one (4.5).
    pub host: Host,
    /// The connection's nonce, signed when signing in (4.5).
    pub nonce: Nonce,
    /// The welcome message, escaped; empty if none.
    pub message: String,
}

impl Greeting {
    fn parse(mut p: Params<'_>) -> Result<Greeting, ParseError> {
        let version = u32::try_from(parse_u64(p.token()?)?)
            .map_err(|_| bad("protocol version is out of range"))?;
        let host = token(&mut p)?;
        let nonce = token(&mut p)?;
        let message = p.text().to_owned();
        limit(&message, MAX_WELCOME)?;
        Ok(Greeting {
            version,
            host,
            nonce,
            message,
        })
    }

    fn write(&self, b: &mut LineBuilder) {
        b.token(self.version)
            .token(&self.host)
            .token(&self.nonce)
            .text(&self.message);
    }
}

/// The `<host>` of the greeting (4.1): the hostname the client sent in SNI
/// (2.1), in lower case.
///
/// This is a light check, not a [`Domain`]: a host may be a single label
/// such as `localhost`. It is 1 to 253 characters of labels separated by
/// `.`, each 1 to 63 characters of `a-z 0-9 -`. An IP address is accepted
/// too, for a server that was reached without SNI and names itself by
/// address. Parsing folds ASCII upper case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Host(String);

impl Host {
    /// The host as written, in lower case (4.1).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Host {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Host, ParseError> {
        let host = s.to_ascii_lowercase();
        if host.parse::<IpAddr>().is_ok() {
            return Ok(Host(host));
        }
        if host.len() > 253 {
            return Err(ParseError::TooLong);
        }
        let label_ok = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if host.split('.').all(label_ok) {
            Ok(Host(host))
        } else {
            Err(bad("a host is a hostname"))
        }
    }
}

impl AsRef<str> for Host {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// OK

/// `OK [<key>=<value> ...]`, a successful final response (3.6).
///
/// The result values are kept in order, as strings, with keys in lower
/// case. Unknown values are kept, since clients must ignore them rather
/// than fail (3.6). The typed accessors read the values the spec defines;
/// each returns `Ok(None)` if the value is absent and an error if it is
/// malformed.
///
/// ```
/// use risala_proto::names::Seq;
/// use risala_proto::server::OkResponse;
///
/// let ok = OkResponse::new().with("id", "k3f9q2").with("head", 8812);
/// assert_eq!(ok.head()?, Some(8812));
/// assert_eq!(ok.value("id"), Some("k3f9q2"));
/// assert_eq!(ok.more()?, None);
/// # Ok::<(), risala_proto::error::ParseError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OkResponse {
    values: Vec<(String, String)>,
}

impl OkResponse {
    /// An `OK` with no values.
    pub fn new() -> OkResponse {
        OkResponse::default()
    }

    /// Adds the value `key=value`, replacing an earlier value with the same
    /// key, and returns the response for chaining.
    ///
    /// # Panics
    ///
    /// If `key` or `value` is not a valid option (see
    /// [`try_with`](Self::try_with)). Values from this crate's types always
    /// are.
    pub fn with(self, key: &str, value: impl fmt::Display) -> OkResponse {
        let value = value.to_string();
        match self.try_with(key, &value) {
            Ok(ok) => ok,
            Err(e) => panic!("bad OK value {key}={value}: {e}"),
        }
    }

    /// Adds the value `key=value`, replacing an earlier value with the same
    /// key. Fails with `BadSyntax` if `key`, folded, is not `a-z 0-9 -`, or
    /// if `value` is not a non-empty token (3.3).
    pub fn try_with(
        mut self,
        key: &str,
        value: impl fmt::Display,
    ) -> Result<OkResponse, ParseError> {
        self.insert(key, value)?;
        Ok(self)
    }

    /// Sets the value `key=value` in place, as [`try_with`](Self::try_with)
    /// does. The key is folded to lower case and must then be `a-z 0-9 -`;
    /// the value must be a non-empty token (3.3).
    pub fn insert(&mut self, key: &str, value: impl fmt::Display) -> Result<(), ParseError> {
        let value = value.to_string();
        let key = key.to_ascii_lowercase();
        if !crate::line::is_option_key(&key) {
            return Err(bad("bad result key"));
        }
        if !is_token(&value) {
            return Err(bad("bad result value"));
        }
        match self.values.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.values.push((key, value)),
        }
        Ok(())
    }

    /// Removes the value `key`. Returns whether it was there.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.values.len();
        self.values.retain(|(k, _)| k != key);
        self.values.len() != before
    }

    /// The raw value of `key`, which must be given in lower case.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The values in order, as `(key, value)`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The number of values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether there are no values.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn parse(p: Params<'_>) -> Result<OkResponse, ParseError> {
        let values = p
            .options()?
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        Ok(OkResponse { values })
    }

    fn write(&self, b: &mut LineBuilder) {
        for (key, value) in &self.values {
            b.option(key, value);
        }
    }

    fn typed<T>(
        &self,
        key: &str,
        parse: impl FnOnce(&str) -> Result<T, ParseError>,
    ) -> Result<Option<T>, ParseError> {
        self.value(key).map(parse).transpose()
    }

    /// `seq=`: the seq of the event a command created (5.3, 5.4, 6.2-6.4),
    /// or of an existing message (5.3, 7.6).
    pub fn seq(&self) -> Result<Option<Seq>, ParseError> {
        self.typed("seq", str::parse)
    }

    /// `id=`: a conversation's id from JOIN or `INFO <room>` (6.1, 6.2), or
    /// a report's id from REPORT (5.8).
    pub fn id(&self) -> Result<Option<Id>, ParseError> {
        self.typed("id", str::parse)
    }

    /// `head=`: a room's newest seq, from JOIN or `INFO <room>` (6.1, 6.2).
    /// It is `0` for a room with no events yet, which only INFO can report.
    pub fn head(&self) -> Result<Option<u64>, ParseError> {
        self.typed("head", parse_u64)
    }

    /// `more=`: whether HISTORY or RELATED has more events, from `0` or `1`
    /// (7.2, 7.3).
    pub fn more(&self) -> Result<Option<bool>, ParseError> {
        self.typed("more", |v| match v {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(bad("more is 0 or 1")),
        })
    }

    /// `uid=`: who the connection signed in as, from GUEST, AUTH or
    /// REGISTER (4.2, 4.5, 4.6).
    pub fn uid(&self) -> Result<Option<Uid>, ParseError> {
        self.typed("uid", str::parse)
    }

    /// `op=`: whether the identity is a server operator, from AUTH (4.5,
    /// 10.1).
    pub fn op(&self) -> Result<Option<bool>, ParseError> {
        self.typed("op", parse_yes_no)
    }

    /// `members=`: the number of members, from `INFO <room>` (6.2).
    pub fn members(&self) -> Result<Option<u64>, ParseError> {
        self.typed("members", parse_u64)
    }

    /// `role=`: your role in the room, from `INFO <room>` (6.2).
    pub fn role(&self) -> Result<Option<InfoRole>, ParseError> {
        self.typed("role", str::parse)
    }

    /// `joined=`: whether you are a member now, from `INFO <room>` (6.2).
    pub fn joined(&self) -> Result<Option<bool>, ParseError> {
        self.typed("joined", parse_yes_no)
    }

    /// `put=`: the URL to upload to, from UPLOAD (5.6). Not checked
    /// further.
    pub fn put_url(&self) -> Option<&str> {
        self.value("put")
    }

    /// `get=`: the URL to download from and attach with `file`, from UPLOAD
    /// (5.6). Not checked further.
    pub fn get_url(&self) -> Option<&str> {
        self.value("get")
    }

    /// `deleted=`: the number of messages ADMIN PURGE deleted (10.4).
    pub fn deleted(&self) -> Result<Option<u64>, ParseError> {
        self.typed("deleted", parse_u64)
    }

    /// `version=`: the protocol version, from INFO (8.5).
    pub fn version(&self) -> Result<Option<u32>, ParseError> {
        self.typed("version", |v| {
            u32::try_from(parse_u64(v)?).map_err(|_| bad("protocol version is out of range"))
        })
    }

    /// `guests=`: whether guests are allowed, from INFO (8.5).
    pub fn guests(&self) -> Result<Option<bool>, ParseError> {
        self.typed("guests", parse_yes_no)
    }

    /// `register=`: the identity domain for REGISTER, or `no`, from INFO
    /// (4.6, 8.5).
    pub fn register(&self) -> Result<Option<Register>, ParseError> {
        self.typed("register", str::parse)
    }

    /// `retention=`: how long the server keeps events, from INFO (7.5,
    /// 8.5).
    pub fn retention(&self) -> Result<Option<ServerRetention>, ParseError> {
        self.typed("retention", str::parse)
    }

    /// `push=`: whether PUSH is supported, from INFO (8.5).
    pub fn push(&self) -> Result<Option<bool>, ParseError> {
        self.typed("push", parse_yes_no)
    }

    /// `upload=`: the largest file UPLOAD accepts, or `no`, from INFO (5.6,
    /// 8.5).
    pub fn upload(&self) -> Result<Option<Upload>, ParseError> {
        self.typed("upload", str::parse)
    }

    /// `get=` as a [`FileUrl`], ready for MSG's `file` tag (5.6).
    pub fn get_file_url(&self) -> Result<Option<FileUrl>, ParseError> {
        self.typed("get", str::parse)
    }

    // Typed setters, one per result value, so the server writes each in
    // its spec form (`more=1`, `joined=yes`). They cannot fail: every
    // value is a valid token.

    /// Adds `seq=` (5.3).
    pub fn with_seq(self, seq: Seq) -> OkResponse {
        self.with("seq", seq)
    }

    /// Adds `id=` (5.1, 5.8).
    pub fn with_id(self, id: &Id) -> OkResponse {
        self.with("id", id)
    }

    /// Adds `head=` (6.1, 6.2): a seq, or `0` for a room with no events.
    pub fn with_head(self, head: impl Into<u64>) -> OkResponse {
        self.with("head", head.into())
    }

    /// Adds `more=0` or `more=1` (6.1, 7.2, 7.3).
    pub fn with_more(self, more: bool) -> OkResponse {
        self.with("more", if more { "1" } else { "0" })
    }

    /// Adds `uid=` (4.2, 4.5, 4.6).
    pub fn with_uid(self, uid: &Uid) -> OkResponse {
        self.with("uid", uid)
    }

    /// Adds `op=yes` or `op=no` (4.5).
    pub fn with_op(self, op: bool) -> OkResponse {
        self.with("op", yes_no(op))
    }

    /// Adds `members=` (6.2).
    pub fn with_members(self, members: u64) -> OkResponse {
        self.with("members", members)
    }

    /// Adds `role=` (6.2).
    pub fn with_role(self, role: InfoRole) -> OkResponse {
        self.with("role", role)
    }

    /// Adds `joined=yes` or `joined=no` (6.2).
    pub fn with_joined(self, joined: bool) -> OkResponse {
        self.with("joined", yes_no(joined))
    }

    /// Adds `put=` and `get=` (5.6). `put` must be one token.
    pub fn with_upload_urls(self, put: &str, get: &FileUrl) -> Result<OkResponse, ParseError> {
        Ok(self.try_with("put", put)?.with("get", get))
    }

    /// Adds `deleted=` (10.4).
    pub fn with_deleted(self, deleted: u64) -> OkResponse {
        self.with("deleted", deleted)
    }

    /// Adds `version=` (8.5).
    pub fn with_version(self, version: u32) -> OkResponse {
        self.with("version", version)
    }

    /// Adds `guests=yes` or `guests=no` (8.5).
    pub fn with_guests(self, guests: bool) -> OkResponse {
        self.with("guests", yes_no(guests))
    }

    /// Adds `register=` (8.5).
    pub fn with_register(self, register: &Register) -> OkResponse {
        self.with("register", register)
    }

    /// Adds `retention=` (8.5).
    pub fn with_retention(self, retention: ServerRetention) -> OkResponse {
        self.with("retention", retention)
    }

    /// Adds `push=yes` or `push=no` (8.5).
    pub fn with_push(self, push: bool) -> OkResponse {
        self.with("push", yes_no(push))
    }

    /// Adds `upload=` (5.6, 8.5).
    pub fn with_upload(self, upload: Upload) -> OkResponse {
        self.with("upload", upload)
    }
}

/// The `register=` value of INFO (8.5): the server's identity domain
/// (4.6), or `no`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Register {
    /// `no`: the server offers no registration.
    No,
    /// REGISTER creates identities under this domain.
    Domain(Domain),
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Register::No => f.write_str("no"),
            Register::Domain(domain) => f.write_str(domain.as_str()),
        }
    }
}

impl FromStr for Register {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Register, ParseError> {
        if s.eq_ignore_ascii_case("no") {
            Ok(Register::No)
        } else {
            s.parse().map(Register::Domain)
        }
    }
}

/// The `upload=` value of INFO (5.6, 8.5): the largest file in bytes, or
/// `no`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Upload {
    /// `no`: the server offers no uploads.
    No,
    /// The largest file UPLOAD accepts, in bytes.
    MaxBytes(u64),
}

impl fmt::Display for Upload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upload::No => f.write_str("no"),
            Upload::MaxBytes(n) => write!(f, "{n}"),
        }
    }
}

impl FromStr for Upload {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Upload, ParseError> {
        if s.eq_ignore_ascii_case("no") {
            Ok(Upload::No)
        } else {
            parse_u64(s).map(Upload::MaxBytes)
        }
    }
}

// ---------------------------------------------------------------------------
// ERR

/// `ERR <code> [<message...>]`, a failed final response (3.6, 3.7), with
/// the `retry` tag of `ERR rate-limited` (3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrResponse {
    /// The error code. Clients treat an unknown code as a general failure
    /// (3.7).
    pub code: ErrorCode,
    /// The `retry` tag: seconds to wait before trying again (3.2). Read on
    /// any ERR, though the spec sends it with `rate-limited`.
    pub retry: Option<u64>,
    /// The message for people, escaped; empty if none.
    pub message: String,
}

impl ErrResponse {
    /// An ERR with this code, no `retry` and no message.
    pub fn new(code: ErrorCode) -> ErrResponse {
        ErrResponse {
            code,
            retry: None,
            message: String::new(),
        }
    }

    /// Sets the message, escaped text (3.4).
    pub fn with_message(mut self, message: impl Into<String>) -> ErrResponse {
        self.message = message.into();
        self
    }

    /// Sets the `retry` tag, in seconds (3.2).
    pub fn with_retry(mut self, seconds: u64) -> ErrResponse {
        self.retry = Some(seconds);
        self
    }

    fn parse(tags: &Tags, mut p: Params<'_>) -> Result<ErrResponse, ParseError> {
        let retry = tag_value(tags, "retry")?.map(parse_u64).transpose()?;
        let code = token(&mut p)?;
        let message = p.text().to_owned();
        Ok(ErrResponse {
            code,
            retry,
            message,
        })
    }

    fn write(&self, b: &mut LineBuilder) {
        if let Some(retry) = self.retry {
            b.tag("retry", retry);
        }
        b.token(&self.code).text(&self.message);
    }
}

impl From<ParseError> for ErrResponse {
    /// The ERR a server replies with to a command that did not parse: the
    /// error's code (3.7) with its description as the message.
    fn from(e: ParseError) -> ErrResponse {
        ErrResponse::new(e.code()).with_message(crate::text::escape(&e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Events

/// An event or a snapshot line (5.2).
///
/// An event has [`meta`](Self::meta): its `seq`, `t` and `from`. A
/// snapshot has none, and describes current state rather than a change;
/// it is otherwise the same line, so a client can apply both with the same
/// code. Only SET, BAN and ROLE are sent as snapshots (6.1-6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// `seq`, `t` and `from`, or `None` for a snapshot.
    pub meta: Option<EventMeta>,
    /// The verb and its parameters.
    pub body: EventBody,
}

/// The `seq`, `t` and `from` tags of an event (5.2), which come together.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventMeta {
    /// The event's position in its conversation.
    pub seq: Seq,
    /// When the server accepted the event.
    pub t: Timestamp,
    /// Who caused the event.
    pub from: Uid,
}

impl Event {
    /// An event with `seq`, `t` and `from`.
    pub fn new(meta: EventMeta, body: EventBody) -> Event {
        Event {
            meta: Some(meta),
            body,
        }
    }

    /// A snapshot line: SET, BAN or ROLE without metadata (5.2).
    pub fn snapshot(body: EventBody) -> Event {
        Event { meta: None, body }
    }

    /// Whether this is a snapshot rather than an event (5.2).
    pub fn is_snapshot(&self) -> bool {
        self.meta.is_none()
    }

    fn parse(verb: &str, tags: &Tags, p: Params<'_>) -> Result<Event, ParseError> {
        let meta = parse_meta(tags)?;
        let body = EventBody::parse(verb, tags, p)?;
        if meta.is_none() && !body.can_be_snapshot() {
            return Err(bad("an event has seq, t and from"));
        }
        Ok(Event { meta, body })
    }

    fn write(&self, b: &mut LineBuilder) -> Result<(), ParseError> {
        if let Some(meta) = &self.meta {
            b.tag("seq", meta.seq)
                .tag("t", meta.t)
                .tag("from", &meta.from);
        } else if !self.body.can_be_snapshot() {
            return Err(bad("an event has seq, t and from"));
        }
        self.body.write(b)
    }
}

fn parse_meta(tags: &Tags) -> Result<Option<EventMeta>, ParseError> {
    match (
        tag_value(tags, "seq")?,
        tag_value(tags, "t")?,
        tag_value(tags, "from")?,
    ) {
        (Some(seq), Some(t), Some(from)) => Ok(Some(EventMeta {
            seq: seq.parse()?,
            t: t.parse()?,
            from: from.parse()?,
        })),
        (None, None, None) => Ok(None),
        _ => Err(bad("an event has all of seq, t and from, or none of them")),
    }
}

/// The verb and parameters of an event (5.2): the same as those of the
/// command that caused it.
///
/// For MSG and DELETE the conversation follows 5.2: in a direct
/// conversation it is the other participant as seen by the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBody {
    /// `MSG <conv> <text...>`, a message (5.3).
    Msg(Message),
    /// `DELETE <conv> <seq>`: message `seq` was deleted (5.4).
    Delete {
        /// The conversation.
        conv: Conv,
        /// The deleted message.
        seq: Seq,
    },
    /// `JOIN <room>`: `from` joined (6.1).
    Join {
        /// The room.
        room: Room,
        /// The room's id, from the `id` tag (6.1). A device whose stored
        /// id for the room differs discards what it has stored first.
        id: Id,
    },
    /// `PART <room> [<reason...>]`: `from` left (6.1). A guest's automatic
    /// PART has no reason (5.2).
    Part {
        /// The room.
        room: Room,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// `INVITE <room> <uid>`: `uid` was invited (6.4).
    Invite {
        /// The room.
        room: Room,
        /// The invitee.
        uid: Uid,
    },
    /// `KICK <room> <uid> [<reason...>]`: `uid` was removed (6.4).
    Kick {
        /// The room.
        room: Room,
        /// Who was kicked.
        uid: Uid,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// `BAN <room> <uid> [<reason...>]`: `uid` was banned (6.4). Also a
    /// snapshot, in response to BANS.
    Ban {
        /// The room.
        room: Room,
        /// Who is banned.
        uid: Uid,
        /// The reason, escaped; empty if none.
        reason: String,
    },
    /// `UNBAN <room> <uid>`: a ban was lifted (6.4).
    Unban {
        /// The room.
        room: Room,
        /// Who was unbanned.
        uid: Uid,
    },
    /// `SET <room> <key> [<value...>]`: a setting changed (6.2). Also a
    /// snapshot, after JOIN and in response to `INFO <room>`.
    Set {
        /// The room.
        room: Room,
        /// The setting and its value.
        setting: RoomSetting,
    },
    /// `ROLE <room> <uid> <role>`: a role changed (6.3). Also a snapshot,
    /// in response to ROLES.
    Role {
        /// The room.
        room: Room,
        /// Whose role it is.
        uid: Uid,
        /// The role.
        role: Role,
    },
}

impl EventBody {
    /// The verb, in upper case.
    pub fn verb(&self) -> &'static str {
        match self {
            EventBody::Msg(_) => "MSG",
            EventBody::Delete { .. } => "DELETE",
            EventBody::Join { .. } => "JOIN",
            EventBody::Part { .. } => "PART",
            EventBody::Invite { .. } => "INVITE",
            EventBody::Kick { .. } => "KICK",
            EventBody::Ban { .. } => "BAN",
            EventBody::Unban { .. } => "UNBAN",
            EventBody::Set { .. } => "SET",
            EventBody::Role { .. } => "ROLE",
        }
    }

    /// The conversation the event belongs to (5.2).
    pub fn conv(&self) -> Conv {
        match self {
            EventBody::Msg(msg) => msg.conv.clone(),
            EventBody::Delete { conv, .. } => conv.clone(),
            EventBody::Join { room, .. }
            | EventBody::Part { room, .. }
            | EventBody::Invite { room, .. }
            | EventBody::Kick { room, .. }
            | EventBody::Ban { room, .. }
            | EventBody::Unban { room, .. }
            | EventBody::Set { room, .. }
            | EventBody::Role { room, .. } => Conv::Room(room.clone()),
        }
    }

    /// Whether this verb is also sent as a snapshot: SET, BAN and ROLE
    /// (Section 12).
    pub fn can_be_snapshot(&self) -> bool {
        matches!(
            self,
            EventBody::Set { .. } | EventBody::Ban { .. } | EventBody::Role { .. }
        )
    }

    fn parse(verb: &str, tags: &Tags, mut p: Params<'_>) -> Result<EventBody, ParseError> {
        Ok(match verb {
            "MSG" => EventBody::Msg(Message::parse(tags, p)?),
            "DELETE" => {
                let conv = token(&mut p)?;
                let seq = token(&mut p)?;
                p.end()?;
                EventBody::Delete { conv, seq }
            }
            "JOIN" => {
                let room = token(&mut p)?;
                p.end()?;
                let id = parse_tag::<Id>(tags, "id")?.ok_or(bad("a JOIN event has the id tag"))?;
                EventBody::Join { room, id }
            }
            "PART" => {
                let room = token(&mut p)?;
                EventBody::Part {
                    room,
                    reason: p.text().to_owned(),
                }
            }
            "INVITE" => {
                let room = token(&mut p)?;
                let uid = token(&mut p)?;
                p.end()?;
                EventBody::Invite { room, uid }
            }
            "KICK" => {
                let room = token(&mut p)?;
                let uid = token(&mut p)?;
                EventBody::Kick {
                    room,
                    uid,
                    reason: p.text().to_owned(),
                }
            }
            "BAN" => {
                let room = token(&mut p)?;
                let uid = token(&mut p)?;
                EventBody::Ban {
                    room,
                    uid,
                    reason: p.text().to_owned(),
                }
            }
            "UNBAN" => {
                let room = token(&mut p)?;
                let uid = token(&mut p)?;
                p.end()?;
                EventBody::Unban { room, uid }
            }
            "SET" => {
                let room = token(&mut p)?;
                let key = p.token()?;
                let setting = RoomSetting::parse(key, p.text())?;
                EventBody::Set { room, setting }
            }
            "ROLE" => {
                let room = token(&mut p)?;
                let uid = token(&mut p)?;
                let role = token(&mut p)?;
                p.end()?;
                EventBody::Role { room, uid, role }
            }
            _ => unreachable!("only event verbs are passed in"),
        })
    }

    fn write(&self, b: &mut LineBuilder) -> Result<(), ParseError> {
        match self {
            EventBody::Msg(msg) => msg.write(b)?,
            EventBody::Delete { conv, seq } => {
                b.token(conv).token(seq);
            }
            EventBody::Join { room, id } => {
                b.tag("id", id).token(room);
            }
            EventBody::Part { room, reason } => {
                b.token(room).text(reason);
            }
            EventBody::Invite { room, uid } | EventBody::Unban { room, uid } => {
                b.token(room).token(uid);
            }
            EventBody::Kick { room, uid, reason } | EventBody::Ban { room, uid, reason } => {
                b.token(room).token(uid).text(reason);
            }
            EventBody::Set { room, setting } => {
                if let RoomSetting::Topic(topic) = setting {
                    limit(topic, MAX_TOPIC)?;
                }
                b.token(room).token(setting.key()).text(&setting.value());
            }
            EventBody::Role { room, uid, role } => {
                b.token(room).token(uid).token(role);
            }
        }
        Ok(())
    }
}

impl From<Message> for EventBody {
    fn from(msg: Message) -> EventBody {
        EventBody::Msg(msg)
    }
}

/// A MSG event (5.3), with its relation (5.3), attached file (5.6) and
/// `deleted` flag (5.4).
///
/// Invariants, checked when parsing and serialising:
///
/// - A deleted message is a placeholder (5.4): `text` is empty. It keeps
///   its relation.
/// - Any other message has non-empty `text`; a reaction's is at most 64
///   bytes.
/// - A `file` goes only with no relation or with `reply` (5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The conversation, named as in 5.2.
    pub conv: Conv,
    /// The `reply`, `edit` or `react` tag, if any (5.3).
    pub relation: Option<Relation>,
    /// The attached file, if any (5.6).
    pub file: Option<Attachment>,
    /// The `deleted` tag: the content was removed (5.4).
    pub deleted: bool,
    /// The text, escaped (3.4). Empty exactly when `deleted`.
    pub text: String,
}

impl Message {
    /// A plain message with this text, with no relation or file.
    pub fn new(conv: impl Into<Conv>, text: impl Into<String>) -> Message {
        Message {
            conv: conv.into(),
            relation: None,
            file: None,
            deleted: false,
            text: text.into(),
        }
    }

    fn parse(tags: &Tags, mut p: Params<'_>) -> Result<Message, ParseError> {
        let mut relation = None;
        for key in Relation::KEYS {
            if tags.has(key) {
                if relation.is_some() {
                    return Err(bad("a message has at most one of reply, edit and react"));
                }
                relation = Relation::from_tag(key, tags.get(key))?;
            }
        }
        let file = match tag_value(tags, "file")? {
            None => None,
            Some(url) => Some(Attachment {
                url: url.parse()?,
                media_type: tag_value(tags, "file-type")?.map(str::parse).transpose()?,
                size: tag_value(tags, "file-size")?.map(parse_u64).transpose()?,
            }),
        };
        let conv = token(&mut p)?;
        let msg = Message {
            conv,
            relation,
            file,
            deleted: tags.has("deleted"),
            text: p.text().to_owned(),
        };
        msg.check()?;
        Ok(msg)
    }

    fn check(&self) -> Result<(), ParseError> {
        if self.file.is_some()
            && matches!(self.relation, Some(Relation::Edit(_) | Relation::React(_)))
        {
            return Err(bad("a file goes only with reply"));
        }
        if self.deleted {
            if !self.text.is_empty() {
                return Err(bad("a deleted message has empty text"));
            }
            if self.file.is_some() {
                return Err(bad("a deleted message has no file"));
            }
        } else if crate::text::is_blank(&self.text) {
            return Err(bad("a message has text"));
        } else if matches!(self.relation, Some(Relation::React(_))) {
            limit(&self.text, MAX_REACTION)?;
        }
        Ok(())
    }

    fn write(&self, b: &mut LineBuilder) -> Result<(), ParseError> {
        self.check()?;
        if let Some(relation) = self.relation {
            b.tag(relation.key(), relation.seq());
        }
        if let Some(file) = &self.file {
            b.tag("file", &file.url);
            if let Some(media_type) = &file.media_type {
                b.tag("file-type", media_type);
            }
            if let Some(size) = file.size {
                b.tag("file-size", size);
            }
        }
        if self.deleted {
            b.flag("deleted");
        }
        b.token(&self.conv).text(&self.text);
        Ok(())
    }
}

/// A file attached to a message, from the `file`, `file-type` and
/// `file-size` tags (5.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Attachment {
    /// The `get` URL: `https`, at most 512 bytes, no `;` or spaces.
    pub url: FileUrl,
    /// The media type the server stored, from `file-type`, if sent.
    pub media_type: Option<MediaType>,
    /// The size in bytes the server stored, from `file-size`, if sent.
    pub size: Option<u64>,
}

// ---------------------------------------------------------------------------
// Reports

/// A REPORT line, `REPORT <conv> <seq> [<reason...>]` (5.8), as sent to a
/// report's reviewers. The report's id is the [`ServerMessage::report`]
/// tag, and the reported event follows as a [`ServerLine::ReportCopy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// When the report was made, from the required `t` tag.
    pub t: Timestamp,
    /// The reporter, from the `from` tag. Only operators see it; room
    /// owners and moderators get `None`.
    pub from: Option<Uid>,
    /// The conversation, named as the reporter sees it (5.8).
    pub conv: Conv,
    /// The reported message.
    pub seq: Seq,
    /// The reason, escaped, at most 512 bytes; empty if none.
    pub reason: String,
}

impl Report {
    fn parse(tags: &Tags, mut p: Params<'_>) -> Result<Report, ParseError> {
        let t = required_tag(tags, "t")?;
        let from = parse_tag(tags, "from")?;
        let conv = token(&mut p)?;
        let seq = token(&mut p)?;
        let reason = text(p, MAX_REPORT_REASON)?;
        Ok(Report {
            t,
            from,
            conv,
            seq,
            reason,
        })
    }

    fn write(&self, b: &mut LineBuilder) -> Result<(), ParseError> {
        limit(&self.reason, MAX_REPORT_REASON)?;
        b.tag("t", self.t);
        if let Some(from) = &self.from {
            b.tag("from", from);
        }
        b.token(&self.conv).token(self.seq).text(&self.reason);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Push

/// The body of a push request, `NOTIFY <tag> <reason> <unread>` (9.3).
///
/// It is one line in the format of Section 3, and the request body ends
/// with LF. Tags on the line are ignored.
///
/// ```
/// use risala_proto::server::Notify;
/// use risala_proto::types::{NotifyReason, PushReason};
///
/// let notify: Notify = "NOTIFY x7Hq2 mention 3\n".parse()?;
/// assert_eq!(notify.reason, NotifyReason::Known(PushReason::Mention));
/// assert_eq!(notify.to_body(), "NOTIFY x7Hq2 mention 3\n");
/// # Ok::<(), risala_proto::error::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Notify {
    /// The registration's tag, chosen by the client (9.1).
    pub tag: PushTag,
    /// Why the push was sent (9.2). A reason from a later version is kept
    /// as [`NotifyReason::Other`]; apps treat it as new activity (9.3).
    pub reason: NotifyReason,
    /// The account's unread count (9.2).
    pub unread: u64,
}

impl Notify {
    /// Parses a NOTIFY line (9.3). A verb other than NOTIFY is
    /// `UnknownVerb`.
    pub fn parse(line: &Line) -> Result<Notify, ParseError> {
        if !line.verb_is("NOTIFY") {
            return Err(ParseError::UnknownVerb(line.verb().to_owned()));
        }
        let mut p = line.params();
        let tag = token(&mut p)?;
        let reason = token(&mut p)?;
        let unread = parse_u64(p.token()?)?;
        p.end()?;
        Ok(Notify {
            tag,
            reason,
            unread,
        })
    }

    /// The line, without its LF (9.3).
    pub fn to_line(&self) -> Line {
        Line::builder("NOTIFY")
            .token(&self.tag)
            .token(&self.reason)
            .token(self.unread)
            .build()
            .expect("a push tag, reason and count are tokens")
    }

    /// The request body: the line followed by LF (9.3).
    pub fn to_body(&self) -> String {
        format!("{}\n", self.to_line())
    }
}

impl fmt::Display for Notify {
    /// Writes the line without its LF.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_line())
    }
}

impl FromStr for Notify {
    type Err = ParseError;

    /// Parses a request body or a bare line: one trailing LF, and a CR
    /// before it, are removed first.
    fn from_str(s: &str) -> Result<Notify, ParseError> {
        let s = s.strip_suffix('\n').unwrap_or(s);
        let s = s.strip_suffix('\r').unwrap_or(s);
        Notify::parse(&Line::parse(s)?)
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PushReason;

    #[test]
    fn deleted_message_has_no_file_and_blank_text_is_empty() {
        let url = "https://files.example.org/f/k3JxR8vN2qYd6hWaP0tZcE/cat.png";
        let line = format!("@seq=5;t={T};from=~sam;file={url};deleted MSG #general");
        assert!(line.parse::<ServerMessage>().is_err());
        let line = format!("@seq=5;t={T};from=~sam MSG #general  \t");
        assert!(line.parse::<ServerMessage>().is_err());
    }

    const T: &str = "2026-11-06T15:40:58.120Z";

    fn parse(s: &str) -> ServerMessage {
        s.parse()
            .unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    /// Parses, checks that serialising gives back `s` and that parsing
    /// that gives the same value.
    fn round_trip(s: &str) -> ServerMessage {
        let msg = parse(s);
        let out = msg.to_line().to_string();
        assert_eq!(out, s, "{msg:?}");
        assert_eq!(parse(&out), msg);
        msg
    }

    /// Parses, then checks that the canonical form is `canonical`.
    fn canonical(s: &str, canonical: &str) -> ServerMessage {
        let msg = parse(s);
        assert_eq!(msg.to_line().to_string(), canonical);
        assert_eq!(parse(canonical), msg);
        msg
    }

    fn err(s: &str) -> ParseError {
        match s.parse::<ServerMessage>() {
            Ok(msg) => panic!("{s:?} should not parse, got {msg:?}"),
            Err(e) => e,
        }
    }

    fn syntax(s: &str) {
        assert!(matches!(err(s), ParseError::BadSyntax(_)), "{s:?}");
    }

    fn event(s: &str) -> Event {
        match round_trip(s).line {
            ServerLine::Event(e) => e,
            other => panic!("{s:?} is not an event: {other:?}"),
        }
    }

    fn msg_of(e: &Event) -> &Message {
        match &e.body {
            EventBody::Msg(m) => m,
            other => panic!("not a MSG: {other:?}"),
        }
    }

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    fn room(s: &str) -> Room {
        s.parse().unwrap()
    }

    fn seq(n: u64) -> Seq {
        Seq::new(n).unwrap()
    }

    // ---- envelope ----

    #[test]
    fn ref_on_events_and_final_responses() {
        let m = round_trip(&format!(
            "@ref=7;seq=8812;t={T};from=~sam;id=k3f9q2 JOIN #general"
        ));
        assert_eq!(m.ref_.as_ref().map(Ref::as_str), Some("7"));
        assert!(matches!(m.line, ServerLine::Event(_)));
        let m = round_trip("@ref=7 OK more=1");
        assert_eq!(m.ref_.as_ref().map(Ref::as_str), Some("7"));
        let m = round_trip("@ref=abc ERR not-found no such room");
        assert_eq!(m.ref_.as_ref().map(Ref::as_str), Some("abc"));
        round_trip("@ref=x ROOM #general 12 General chat");
        round_trip("@ref=x SET #general public yes");
    }

    #[test]
    fn tag_order_is_canonical() {
        canonical(
            &format!("@from=~sam;t={T};seq=8812;id=k3f9q2;ref=7 JOIN #general"),
            &format!("@ref=7;seq=8812;t={T};from=~sam;id=k3f9q2 JOIN #general"),
        );
        canonical(
            &format!("@deleted;reply=8810;from=~sam;t={T};seq=8813 MSG #general"),
            &format!("@seq=8813;t={T};from=~sam;reply=8810;deleted MSG #general"),
        );
        canonical(
            "@retry=30;ref=1 ERR rate-limited",
            "@ref=1;retry=30 ERR rate-limited",
        );
    }

    #[test]
    fn bad_envelope_tags() {
        syntax("@ref OK");
        assert_eq!(
            err(&format!("@ref={} OK", "a".repeat(65))),
            ParseError::TooLong
        );
        syntax("@report=Bad! OK");
    }

    #[test]
    fn with_ref_and_constructors() {
        let r: Ref = "q".parse().unwrap();
        let m = ServerMessage::new(OkResponse::new()).with_ref(r.clone());
        assert_eq!(m.to_line().to_string(), "@ref=q OK");
        let m = ServerMessage::new(ErrResponse::new(ErrorCode::NotFound)).with_ref_opt(None);
        assert_eq!(m.to_line().to_string(), "ERR not-found");
        let e = ErrResponse::new(ErrorCode::RateLimited)
            .with_retry(5)
            .with_message("slow down");
        let m = ServerMessage::new(e).with_ref(r);
        assert_eq!(
            m.to_line().to_string(),
            "@ref=q;retry=5 ERR rate-limited slow down"
        );
    }

    #[test]
    fn lower_case_verbs_are_accepted() {
        canonical("ok uid=~sam", "OK uid=~sam");
        canonical("Ping abc", "PING abc");
    }

    #[test]
    fn unknown_verbs() {
        let m = round_trip("FROBNICATE a b c");
        assert!(matches!(&m.line, ServerLine::Unknown(l) if l.verb() == "FROBNICATE"));
        let m = round_trip("@ref=7;report=r1;x-foo=1 FUTURE stuff");
        assert_eq!(m.ref_.as_ref().map(Ref::as_str), Some("7"));
        assert_eq!(m.report.as_ref().map(Id::as_str), Some("r1"));
        let ServerLine::Unknown(line) = &m.line else {
            panic!()
        };
        assert!(!line.tags().has("ref"));
        assert_eq!(line.tags().get("x-foo"), Some("1"));
        // NOTIFY is a push body, not a chat line.
        assert!(matches!(
            parse("NOTIFY a dm 1").line,
            ServerLine::Unknown(_)
        ));
        // The verb is kept as written.
        let m = round_trip("future stuff");
        assert_eq!(m.line.verb(), "future");
    }

    #[test]
    fn unknown_tags_are_ignored() {
        canonical(
            "@x-foo=1;seq=5 PRESENCE online ~sam",
            "PRESENCE online ~sam",
        );
        canonical(&format!("@seq=1;t={T};from=~sam;x-a OK"), "OK");
        // Meaningless MSG tags on other events.
        canonical(
            &format!("@seq=1;t={T};from=~sam;reply=3;id=a1;file=x;deleted JOIN #a"),
            &format!("@seq=1;t={T};from=~sam;id=a1 JOIN #a"),
        );
        // Unread tag values are not checked.
        canonical("@seq=zzz NOTICE hi", "NOTICE hi");
    }

    // ---- greeting ----

    #[test]
    fn greeting() {
        let m = round_trip("RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e Welcome!");
        let ServerLine::Greeting(g) = m.line else {
            panic!()
        };
        assert_eq!(g.version, 1);
        assert_eq!(g.host.as_str(), "chat.example.org");
        assert_eq!(g.nonce.as_str(), "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e");
        assert_eq!(g.message, "Welcome!");
        round_trip("RISALA 2 localhost 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e");
        round_trip("RISALA 1 192.0.2.1 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e hello there");
        canonical(
            "RISALA 1 Chat.Example.ORG 6F1C0A9E4B2D4C8F9A7E3B5D1C2F4A6E",
            "RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e",
        );
        syntax("RISALA 1 chat.example.org");
        syntax("RISALA one chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e");
        syntax("RISALA 01 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e");
        syntax("RISALA 99999999999 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e");
        syntax("RISALA 1 chat..example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e");
        syntax("RISALA 1 chat_example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e");
        syntax("RISALA 1 chat.example.org 6f1c");
    }

    #[test]
    fn hosts() {
        for good in [
            "localhost",
            "a",
            "chat.example.org",
            "xn--bcher-kva.example",
            "::1",
        ] {
            assert_eq!(good.parse::<Host>().unwrap().as_str(), good);
        }
        for b in ["", ".", "a.", ".a", "a b", "a_b.org", "ä.org"] {
            assert!(b.parse::<Host>().is_err(), "{b:?}");
        }
        assert!(format!("{}.org", "a".repeat(64)).parse::<Host>().is_err());
        assert_eq!(
            format!("{}.a", "a".repeat(252)).parse::<Host>(),
            Err(ParseError::TooLong)
        );
    }

    // ---- OK and ERR ----

    #[test]
    fn ok_values_in_order_with_unknown_kept() {
        let m = round_trip("OK id=k3f9q2 head=8812 future=thing");
        let ServerLine::Ok(ok) = m.line else { panic!() };
        let keys: Vec<_> = ok.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["id", "head", "future"]);
        assert_eq!(ok.value("future"), Some("thing"));
        assert_eq!(ok.id().unwrap().unwrap().as_str(), "k3f9q2");
        assert_eq!(ok.head().unwrap(), Some(8812));
        round_trip("OK");
        canonical("OK  SEQ=1 ", "OK seq=1");
        syntax("OK yes");
        syntax("OK seq=1 seq=2");
    }

    #[test]
    fn ok_head_zero_is_an_empty_room() {
        let ok = round_trip("OK id=k3f9q2 members=0 head=0 role=none joined=no");
        let ServerLine::Ok(ok) = ok.line else {
            panic!("not OK")
        };
        assert_eq!(ok.head().unwrap(), Some(0));
        let line = |ok: OkResponse| ServerMessage::new(ServerLine::Ok(ok)).to_line().to_string();
        assert_eq!(line(OkResponse::new().with_head(0u64)), "OK head=0");
        assert_eq!(line(OkResponse::new().with_head(seq(7))), "OK head=7");
        assert!(OkResponse::new().with("head", "007").head().is_err());
    }

    #[test]
    fn ok_accessors() {
        let ok = OkResponse::new()
            .with("seq", 8813)
            .with("id", "p4x8n2")
            .with("head", 9)
            .with("more", 1)
            .with("uid", "alice@example.org")
            .with("op", yes_no(true))
            .with("members", 12)
            .with("role", InfoRole(None))
            .with("joined", "no")
            .with("put", "https://f.example/u/1")
            .with("get", "https://f.example/f/1/cat.png")
            .with("deleted", 0)
            .with("version", 1)
            .with("guests", "yes")
            .with("register", "example.org")
            .with("retention", ServerRetention::Forever)
            .with("push", "no")
            .with("upload", Upload::MaxBytes(10_000_000));
        assert_eq!(ok.seq().unwrap(), Some(seq(8813)));
        assert_eq!(ok.id().unwrap().unwrap().as_str(), "p4x8n2");
        assert_eq!(ok.head().unwrap(), Some(9));
        assert_eq!(ok.more().unwrap(), Some(true));
        assert_eq!(ok.uid().unwrap(), Some(uid("alice@example.org")));
        assert_eq!(ok.op().unwrap(), Some(true));
        assert_eq!(ok.members().unwrap(), Some(12));
        assert_eq!(ok.role().unwrap(), Some(InfoRole(None)));
        assert_eq!(ok.joined().unwrap(), Some(false));
        assert_eq!(ok.put_url(), Some("https://f.example/u/1"));
        assert_eq!(ok.get_url(), Some("https://f.example/f/1/cat.png"));
        assert_eq!(ok.deleted().unwrap(), Some(0));
        assert_eq!(ok.version().unwrap(), Some(1));
        assert_eq!(ok.guests().unwrap(), Some(true));
        assert_eq!(
            ok.register().unwrap(),
            Some(Register::Domain("example.org".parse().unwrap()))
        );
        assert_eq!(ok.retention().unwrap(), Some(ServerRetention::Forever));
        assert_eq!(ok.push().unwrap(), Some(false));
        assert_eq!(ok.upload().unwrap(), Some(Upload::MaxBytes(10_000_000)));
        let line = ServerMessage::new(ok.clone()).to_line().to_string();
        assert!(
            line.starts_with("OK seq=8813 id=p4x8n2 head=9 more=1 "),
            "{line}"
        );
        assert_eq!(parse(&line).line, ServerLine::Ok(ok));

        let ok = OkResponse::new()
            .with("register", Register::No)
            .with("upload", "no")
            .with("retention", 30)
            .with("role", Role::Mod);
        assert_eq!(ok.register().unwrap(), Some(Register::No));
        assert_eq!(ok.upload().unwrap(), Some(Upload::No));
        assert_eq!(
            ok.retention()
                .unwrap()
                .and_then(ServerRetention::days)
                .map(|d| d.get()),
            Some(30)
        );
        assert_eq!(ok.role().unwrap(), Some(InfoRole(Some(Role::Mod))));
        assert_eq!(ok.seq().unwrap(), None);
        assert_eq!(ok.more().unwrap(), None);
    }

    #[test]
    fn ok_bad_values() {
        assert!("OK seq2=".parse::<ServerMessage>().is_err());
        let ok = match parse("OK seq=0 more=2 op=maybe members=-1 uid=x upload=big seq2=x").line {
            ServerLine::Ok(ok) => ok,
            _ => panic!(),
        };
        assert!(ok.seq().is_err());
        assert!(ok.more().is_err());
        assert!(ok.op().is_err());
        assert!(ok.members().is_err());
        assert!(ok.uid().is_err());
        assert!(ok.upload().is_err());
        assert_eq!(ok.value("seq2"), Some("x"));
    }

    #[test]
    fn ok_typed_setters_match_getters() {
        let ok = OkResponse::new()
            .with_more(true)
            .with_joined(false)
            .with_op(true)
            .with_seq(Seq::new(5).unwrap())
            .with_role(InfoRole(None))
            .with_upload(Upload::MaxBytes(10));
        assert_eq!(
            ServerMessage::new(ok.clone()).to_line().to_string(),
            "OK more=1 joined=no op=yes seq=5 role=none upload=10"
        );
        assert_eq!(ok.more(), Ok(Some(true)));
        assert_eq!(ok.joined(), Ok(Some(false)));
        assert_eq!(ok.op(), Ok(Some(true)));
        let get: FileUrl = "https://f.example/f/x".parse().unwrap();
        let ok = OkResponse::new()
            .with_upload_urls("https://f.example/u/y", &get)
            .unwrap();
        assert_eq!(ok.get_file_url(), Ok(Some(get)));
        assert!(
            OkResponse::new()
                .with_upload_urls("a b", &ok.get_file_url().unwrap().unwrap())
                .is_err()
        );
    }

    #[test]
    fn hand_built_lines_must_be_canonical() {
        let set = |setting| {
            ServerMessage::new(Event {
                meta: None,
                body: EventBody::Set {
                    room: "#a".parse().unwrap(),
                    setting,
                },
            })
        };
        assert!(
            set(RoomSetting::Other {
                key: "topic".into(),
                value: "x".repeat(600)
            })
            .try_to_line()
            .is_err()
        );
        assert!(
            set(RoomSetting::Other {
                key: "public".into(),
                value: "maybe".into()
            })
            .try_to_line()
            .is_err()
        );
        assert!(
            set(RoomSetting::Other {
                key: "x-new".into(),
                value: "1".into()
            })
            .try_to_line()
            .is_ok()
        );
        let err = |code| {
            ServerMessage::new(ServerLine::Err(ErrResponse {
                code,
                retry: None,
                message: String::new(),
            }))
        };
        assert!(
            err(ErrorCode::Other("bad-syntax".into()))
                .try_to_line()
                .is_err()
        );
        assert!(
            err(ErrorCode::Other("slow-down".into()))
                .try_to_line()
                .is_ok()
        );
    }

    #[test]
    fn ok_builder() {
        let mut ok = OkResponse::new().with("Seq", 1).with("seq", 2);
        assert_eq!(ok.len(), 1);
        assert_eq!(ok.value("seq"), Some("2"));
        assert!(ok.clone().try_with("a b", 1).is_err());
        assert!(ok.clone().try_with("a=b", 1).is_err());
        assert!(ok.clone().try_with("", 1).is_err());
        assert!(ok.clone().try_with("a", "b c").is_err());
        assert!(ok.clone().try_with("a_b", 1).is_err());
        assert!(ok.insert("empty", "").is_err());
        assert!(ok.insert("x-new", "v").is_ok());
        assert_eq!(
            ServerMessage::new(ok.clone()).to_line().to_string(),
            "OK seq=2 x-new=v"
        );
        assert!(ok.remove("seq"));
        assert!(!ok.remove("seq"));
        assert!(!ok.is_empty());
    }

    #[test]
    fn err_lines() {
        let m = round_trip("ERR not-found");
        let ServerLine::Err(e) = &m.line else {
            panic!()
        };
        assert_eq!(e.code, ErrorCode::NotFound);
        assert_eq!(e.message, "");
        assert_eq!(e.retry, None);
        let m = round_trip("@retry=30 ERR rate-limited slow down, please");
        let ServerLine::Err(e) = &m.line else {
            panic!()
        };
        assert_eq!(e.retry, Some(30));
        assert_eq!(e.message, "slow down, please");
        let m = round_trip("ERR x-new-code something");
        let ServerLine::Err(e) = &m.line else {
            panic!()
        };
        assert_eq!(e.code, ErrorCode::Other("x-new-code".into()));
        canonical("ERR Not-Found", "ERR not-found");
        syntax("ERR");
        syntax("@retry=soon ERR rate-limited");
        syntax("@retry ERR rate-limited");
        assert!(matches!(m.line, ServerLine::Err(_)) && m.line.is_final());
    }

    #[test]
    fn err_from_parse_error() {
        let e = ErrResponse::from(ParseError::BadSyntax("missing parameter"));
        assert_eq!(
            ServerMessage::new(e).to_line().to_string(),
            "ERR bad-syntax bad syntax: missing parameter"
        );
    }

    // ---- events ----

    #[test]
    fn events_round_trip() {
        let e = event(&format!(
            "@seq=8812;t={T};from=~sam;id=k3f9q2 JOIN #general"
        ));
        let meta = e.meta.as_ref().unwrap();
        assert_eq!(meta.seq, seq(8812));
        assert_eq!(meta.t.to_string(), T);
        assert_eq!(meta.from, uid("~sam"));
        assert_eq!(
            e.body,
            EventBody::Join {
                room: room("#general"),
                id: "k3f9q2".parse().unwrap(),
            }
        );
        // The room id is required on JOIN events (6.1).
        assert!(
            format!("@seq=1;t={T};from=~sam JOIN #general")
                .parse::<ServerMessage>()
                .is_err()
        );
        assert_eq!(e.body.conv(), Conv::Room(room("#general")));

        let e = event(&format!(
            "@seq=2;t={T};from=a@b.org DELETE bob@example.net 1"
        ));
        assert_eq!(
            e.body,
            EventBody::Delete {
                conv: Conv::Uid(uid("bob@example.net")),
                seq: seq(1)
            }
        );
        event(&format!("@seq=3;t={T};from=~sam PART #general"));
        let e = event(&format!("@seq=3;t={T};from=~sam PART #general  bye now"));
        assert!(matches!(&e.body, EventBody::Part { reason, .. } if reason == " bye now"));
        event(&format!("@seq=4;t={T};from=a@b.org INVITE #priv c@d.org"));
        event(&format!("@seq=5;t={T};from=a@b.org KICK #priv ~spam"));
        event(&format!(
            "@seq=6;t={T};from=a@b.org KICK #priv ~spam go away"
        ));
        event(&format!("@seq=7;t={T};from=a@b.org BAN #priv ~spam spam"));
        event(&format!("@seq=8;t={T};from=a@b.org UNBAN #priv ~spam"));
        let e = event(&format!(
            "@seq=9;t={T};from=a@b.org SET #priv topic New topic"
        ));
        assert_eq!(
            e.body,
            EventBody::Set {
                room: room("#priv"),
                setting: RoomSetting::Topic("New topic".into())
            }
        );
        event(&format!("@seq=10;t={T};from=a@b.org SET #priv topic"));
        event(&format!(
            "@seq=11;t={T};from=a@b.org SET #priv x-color blue"
        ));
        let e = event(&format!(
            "@seq=12;t={T};from=a@b.org ROLE #priv c@d.org mod"
        ));
        assert!(matches!(
            e.body,
            EventBody::Role {
                role: Role::Mod,
                ..
            }
        ));
        assert!(!e.is_snapshot());
    }

    #[test]
    fn events_canonical_form() {
        canonical(
            &format!("@seq=1;t={T};from=Alice@Example.ORG MSG #General  hi"),
            &format!("@seq=1;t={T};from=alice@example.org MSG #general  hi"),
        );
        canonical(
            &format!("@seq=1;t={T};from=~sam SET #a PUBLIC YES"),
            &format!("@seq=1;t={T};from=~sam SET #a public yes"),
        );
    }

    #[test]
    fn bad_events() {
        // Wrong arity.
        syntax(&format!("@seq=1;t={T};from=~sam JOIN"));
        syntax(&format!("@seq=1;t={T};from=~sam;id=a1 JOIN #a #b"));
        syntax(&format!("@seq=1;t={T};from=~sam DELETE #a"));
        syntax(&format!("@seq=1;t={T};from=~sam DELETE #a 0"));
        syntax(&format!("@seq=1;t={T};from=~sam INVITE #a"));
        syntax(&format!("@seq=1;t={T};from=~sam UNBAN #a ~b c"));
        syntax(&format!("@seq=1;t={T};from=~sam ROLE #a ~b boss"));
        syntax(&format!("@seq=1;t={T};from=~sam SET #a public maybe"));
        syntax(&format!("@seq=1;t={T};from=~sam SET #a"));
        syntax(&format!("@seq=1;t={T};from=~sam JOIN general"));
        // Bad metadata values.
        syntax(&format!("@seq=0;t={T};from=~sam;id=a1 JOIN #a"));
        syntax("@seq=1;t=yesterday;from=~sam;id=a1 JOIN #a");
        syntax(&format!("@seq=1;t={T};from=sam;id=a1 JOIN #a"));
        syntax(&format!("@seq;t={T};from=~sam;id=a1 JOIN #a"));
        assert_eq!(
            err(&format!(
                "@seq=1;t={T};from=~sam SET #a topic {}",
                "x".repeat(513)
            )),
            ParseError::TooLong
        );
    }

    #[test]
    fn metadata_is_all_or_nothing() {
        for tags in [
            "seq=1".to_owned(),
            format!("t={T}"),
            "from=~sam".to_owned(),
            format!("seq=1;t={T}"),
            "seq=1;from=~sam".to_owned(),
            format!("t={T};from=~sam"),
        ] {
            for line in [
                "SET #a public yes",
                "BAN #a ~b",
                "ROLE #a b@c.org mod",
                "JOIN #a",
            ] {
                syntax(&format!("@{tags} {line}"));
            }
        }
    }

    #[test]
    fn snapshots() {
        for s in [
            "SET #general topic General chat. Be kind.",
            "SET #general public yes",
            "SET #general guests write",
            "SET #general retention server",
            "SET #general retention 30",
            "BAN #general ~spam",
            "BAN #general ~spam flooding",
            "ROLE #general alice@example.org owner",
        ] {
            let m = round_trip(s);
            let ServerLine::Event(e) = &m.line else {
                panic!("{s}")
            };
            assert!(e.is_snapshot(), "{s}");
            assert!(e.body.can_be_snapshot());
        }
        // Other event verbs are never snapshots.
        for s in [
            "MSG #general hi",
            "DELETE #general 5",
            "JOIN #general",
            "PART #general",
            "INVITE #general a@b.org",
            "KICK #general ~sam",
            "UNBAN #general ~sam",
        ] {
            syntax(s);
        }
        let snap = Event::snapshot(EventBody::Role {
            room: room("#a"),
            uid: uid("a@b.org"),
            role: Role::Owner,
        });
        assert_eq!(
            ServerMessage::new(snap).to_line().to_string(),
            "ROLE #a a@b.org owner"
        );
        let bad = ServerMessage::new(Event::snapshot(EventBody::Join {
            room: room("#a"),
            id: "x1".parse().unwrap(),
        }));
        assert!(bad.try_to_line().is_err());
    }

    // ---- messages ----

    #[test]
    fn messages() {
        let e = event(&format!("@seq=1;t={T};from=~sam MSG #general hello!"));
        let m = msg_of(&e);
        assert_eq!(m.text, "hello!");
        assert_eq!(m.relation, None);
        assert!(!m.deleted);
        let e = event(&format!(
            "@seq=8813;t={T};from=~sam;reply=8810 MSG #general hi alice, I'm new here"
        ));
        assert_eq!(msg_of(&e).relation, Some(Relation::Reply(seq(8810))));
        let e = event(&format!(
            "@seq=4003;t={T};from=b@c.org;edit=4000 MSG #general sure"
        ));
        assert_eq!(msg_of(&e).relation, Some(Relation::Edit(seq(4000))));
        let e = event(&format!(
            "@seq=8790;t={T};from=~sam;react=3999 MSG #general 🍕"
        ));
        assert_eq!(msg_of(&e).relation, Some(Relation::React(seq(3999))));
        // Text keeps leading spaces and escapes.
        let e = event(&format!(
            r"@seq=1;t={T};from=~sam MSG a@b.org   two\nlines \\ ok"
        ));
        assert_eq!(msg_of(&e).text, r"  two\nlines \\ ok");
        assert_eq!(msg_of(&e).conv, Conv::Uid(uid("a@b.org")));
    }

    #[test]
    fn bad_messages() {
        syntax(&format!("@seq=1;t={T};from=~sam MSG #general"));
        syntax(&format!("@seq=1;t={T};from=~sam MSG #general "));
        syntax(&format!("@seq=1;t={T};from=~sam MSG"));
        syntax(&format!("@seq=1;t={T};from=~sam;reply=1;edit=2 MSG #a x"));
        syntax(&format!("@seq=1;t={T};from=~sam;react=1;reply=2 MSG #a x"));
        syntax(&format!("@seq=1;t={T};from=~sam;reply=x MSG #a x"));
        syntax(&format!("@seq=1;t={T};from=~sam;reply MSG #a x"));
        assert_eq!(
            err(&format!(
                "@seq=1;t={T};from=~sam;react=1 MSG #a {}",
                "x".repeat(65)
            )),
            ParseError::TooLong
        );
        event(&format!(
            "@seq=1;t={T};from=~sam;react=1 MSG #a {}",
            "x".repeat(64)
        ));
    }

    #[test]
    fn deleted_placeholders() {
        let e = event(&format!(
            "@seq=8813;t={T};from=~sam;reply=8810;deleted MSG #general"
        ));
        let m = msg_of(&e);
        assert!(m.deleted);
        assert_eq!(m.text, "");
        assert_eq!(m.relation, Some(Relation::Reply(seq(8810))));
        event(&format!("@seq=9;t={T};from=~sam;deleted MSG #general"));
        // A value on the flag is ignored.
        canonical(
            &format!("@seq=9;t={T};from=~sam;deleted=1 MSG #general"),
            &format!("@seq=9;t={T};from=~sam;deleted MSG #general"),
        );
        syntax(&format!(
            "@seq=9;t={T};from=~sam;deleted MSG #general leftover"
        ));
        // Building one by hand.
        let mut msg = Message::new(room("#general"), "");
        msg.deleted = true;
        let meta = EventMeta {
            seq: seq(5),
            t: T.parse().unwrap(),
            from: uid("~sam"),
        };
        let line = ServerMessage::new(Event::new(meta.clone(), msg.into())).to_line();
        assert_eq!(
            line.to_string(),
            format!("@seq=5;t={T};from=~sam;deleted MSG #general")
        );
        // Invalid by hand: deleted with text, or not deleted and empty.
        let mut msg = Message::new(room("#general"), "x");
        msg.deleted = true;
        let bad = ServerMessage::new(Event::new(meta.clone(), msg.into()));
        assert!(bad.try_to_line().is_err());
        let bad = ServerMessage::new(Event::new(meta, Message::new(room("#a"), "").into()));
        assert!(bad.try_to_line().is_err());
    }

    #[test]
    fn files() {
        let url = "https://files.example.org/f/k3JxR8vN2qYd6hWaP0tZcE/cat.png";
        let e = event(&format!(
            "@seq=8815;t={T};from=alice@example.org;file={url};file-type=image/png;file-size=48213 MSG #general look at this"
        ));
        let file = msg_of(&e).file.as_ref().unwrap();
        assert_eq!(file.url.as_str(), url);
        assert_eq!(
            file.media_type.as_ref().map(MediaType::as_str),
            Some("image/png")
        );
        assert_eq!(file.size, Some(48213));
        // Metadata is optional; reply is allowed.
        let e = event(&format!(
            "@seq=1;t={T};from=~sam;reply=3;file={url} MSG #a cap"
        ));
        let m = msg_of(&e);
        assert_eq!(m.file.as_ref().unwrap().size, None);
        assert_eq!(m.relation, Some(Relation::Reply(seq(3))));
        // Without file, file-type and file-size are ignored.
        canonical(
            &format!("@seq=1;t={T};from=~sam;file-size=3 MSG #a x"),
            &format!("@seq=1;t={T};from=~sam MSG #a x"),
        );
        syntax(&format!(
            "@seq=1;t={T};from=~sam;edit=3;file={url} MSG #a x"
        ));
        syntax(&format!(
            "@seq=1;t={T};from=~sam;react=3;file={url} MSG #a x"
        ));
        syntax(&format!(
            "@seq=1;t={T};from=~sam;file=http://x.org/f MSG #a x"
        ));
        syntax(&format!("@seq=1;t={T};from=~sam;file=ftp MSG #a x"));
        syntax(&format!(
            "@seq=1;t={T};from=~sam;file={url};file-size=big MSG #a x"
        ));
        syntax(&format!("@seq=1;t={T};from=~sam;file MSG #a x"));
        let long = format!("https://x.org/{}", "a".repeat(500));
        assert_eq!(
            err(&format!("@seq=1;t={T};from=~sam;file={long} MSG #a x")),
            ParseError::TooLong
        );
    }

    // ---- reports ----

    #[test]
    fn reports() {
        let m = round_trip(
            "@report=p4x8n2;t=2026-11-06T15:44:10.230Z;from=bob@example.net REPORT #general 8816 spam",
        );
        assert_eq!(m.report.as_ref().map(Id::as_str), Some("p4x8n2"));
        assert!(!m.is_report_copy());
        let ServerLine::Report(r) = &m.line else {
            panic!()
        };
        assert_eq!(r.from, Some(uid("bob@example.net")));
        assert_eq!(r.seq, seq(8816));
        assert_eq!(r.reason, "spam");
        // Moderators get it without from, and the reason may be empty.
        let m = round_trip(&format!("@report=p4x8n2;t={T} REPORT ~spammer 3"));
        let ServerLine::Report(r) = &m.line else {
            panic!()
        };
        assert_eq!(r.from, None);
        assert_eq!(r.conv, Conv::Uid(uid("~spammer")));

        let m = round_trip(
            "@report=p4x8n2;seq=8816;t=2026-11-06T15:43:58.019Z;from=~spammer MSG #general cheap pills at …",
        );
        assert!(m.is_report_copy());
        let ServerLine::ReportCopy(e) = &m.line else {
            panic!()
        };
        assert_eq!(e.meta.as_ref().unwrap().seq, seq(8816));

        // A REPORT line needs report and t; a copy needs its metadata.
        syntax(&format!("@t={T} REPORT #general 1 spam"));
        syntax("@report=p4 REPORT #general 1 spam");
        syntax(&format!("@report=p4;t={T} REPORT #general"));
        syntax(&format!("@report=p4;t={T};from=nobody REPORT #general 1"));
        syntax("@report=p4 MSG #general hi");
        assert_eq!(
            err(&format!("@report=p4;t={T} REPORT #a 1 {}", "x".repeat(513))),
            ParseError::TooLong
        );

        // Constructors set the tag.
        let id: Id = "r1".parse().unwrap();
        let report = Report {
            t: T.parse().unwrap(),
            from: None,
            conv: Conv::Room(room("#a")),
            seq: seq(2),
            reason: String::new(),
        };
        let m = ServerMessage::report_line(id.clone(), report.clone());
        assert_eq!(
            m.to_line().to_string(),
            format!("@report=r1;t={T} REPORT #a 2")
        );
        assert!(
            ServerMessage::new(ServerLine::Report(report))
                .try_to_line()
                .is_err()
        );
        let ev = Event::new(
            EventMeta {
                seq: seq(2),
                t: T.parse().unwrap(),
                from: uid("~x"),
            },
            Message::new(room("#a"), "bad").into(),
        );
        let m = ServerMessage::report_copy(id, ev.clone());
        assert_eq!(
            m.to_line().to_string(),
            format!("@report=r1;seq=2;t={T};from=~x MSG #a bad")
        );
        assert!(
            ServerMessage::new(ServerLine::ReportCopy(ev))
                .try_to_line()
                .is_err()
        );
    }

    #[test]
    fn resolved() {
        let m = round_trip("RESOLVED p4x8n2");
        assert_eq!(
            m.line,
            ServerLine::Resolved {
                id: "p4x8n2".parse().unwrap()
            }
        );
        syntax("RESOLVED");
        syntax("RESOLVED a b");
        syntax("RESOLVED a!");
    }

    // ---- response lines ----

    #[test]
    fn room_lines() {
        let m = round_trip("ROOM #general 42 General chat. Be kind.");
        assert_eq!(
            m.line,
            ServerLine::Room {
                room: room("#general"),
                members: 42,
                topic: "General chat. Be kind.".into()
            }
        );
        round_trip("ROOM #quiet 0");
        syntax("ROOM #general");
        syntax("ROOM #general many");
        syntax("ROOM general 1");
        assert_eq!(
            err(&format!("ROOM #a 1 {}", "x".repeat(513))),
            ParseError::TooLong
        );
    }

    #[test]
    fn conv_lines() {
        let m = round_trip("CONV #general k3f9q2 8814 8813");
        assert_eq!(
            m.line,
            ServerLine::Conv {
                conv: Conv::Room(room("#general")),
                id: "k3f9q2".parse().unwrap(),
                head: seq(8814),
                read: Some(seq(8813)),
            }
        );
        let m = round_trip("CONV bob@example.net d1 3 0");
        assert!(matches!(m.line, ServerLine::Conv { read: None, .. }));
        syntax("CONV #general k3f9q2 0 0");
        syntax("CONV #general k3f9q2 1");
        syntax("CONV #general k3f9q2 1 1 1");
        syntax("CONV #general k3f9q2 1 01");
    }

    #[test]
    fn member_and_user_lines() {
        let m = round_trip("MEMBER #general alice@example.org owner online Alice Martin");
        assert_eq!(
            m.line,
            ServerLine::Member {
                room: room("#general"),
                uid: uid("alice@example.org"),
                role: Role::Owner,
                presence: Presence::Online,
                name: "Alice Martin".into(),
            }
        );
        round_trip("MEMBER #general ~sam member offline");
        round_trip("MEMBER #general ~sam member away");
        syntax("MEMBER #general ~sam none online");
        syntax("MEMBER #general ~sam member");
        let m = round_trip("USER bob@example.net offline عائشة");
        assert!(matches!(&m.line, ServerLine::User { name, .. } if name == "عائشة"));
        round_trip("USER ~sam online");
        syntax("USER ~sam");
        assert_eq!(
            err(&format!("USER ~sam online {}", "x".repeat(129))),
            ParseError::TooLong
        );
    }

    #[test]
    fn presence_lines() {
        let m = round_trip("PRESENCE online alice@example.org,bob@example.net");
        assert_eq!(
            m.line,
            ServerLine::Presence {
                presence: Presence::Online,
                uids: vec![uid("alice@example.org"), uid("bob@example.net")],
            }
        );
        round_trip("PRESENCE offline carol@example.com");
        round_trip("PRESENCE busy carol@example.com");
        syntax("PRESENCE online");
        syntax("PRESENCE online a@b.org,");
        syntax("PRESENCE online ,a@b.org");
        syntax("PRESENCE online a@b.org,,c@d.org");
        syntax("PRESENCE online a@b.org c@d.org");
        let empty = ServerMessage::new(ServerLine::Presence {
            presence: Presence::Online,
            uids: vec![],
        });
        assert!(empty.try_to_line().is_err());
    }

    #[test]
    fn block_key_push_lines() {
        round_trip("BLOCK spam@example.net");
        round_trip("BLOCK *@example.net");
        syntax("BLOCK ~sam");
        syntax("BLOCK");
        let m = round_trip("KEY J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY= laptop");
        assert!(matches!(&m.line, ServerLine::Key { label, .. } if label == "laptop"));
        round_trip("KEY J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY=");
        syntax("KEY J/Kmupu");
        let m = round_trip("PUSH https://push.app.example/n/3f9c x7Hq2");
        assert!(
            matches!(&m.line, ServerLine::Push { url, .. } if url.as_str() == "https://push.app.example/n/3f9c")
        );
        syntax("PUSH https://push.app.example/n/3f9c");
        syntax("PUSH https://push.app.example/n/3f9c a b");
    }

    #[test]
    fn read_typing_name_lines() {
        round_trip("READ #general 8813");
        round_trip("READ alice@example.org 2");
        syntax("READ #general");
        syntax("READ #general 0");
        let m = round_trip("@from=alice@example.org TYPING #general");
        assert_eq!(
            m.line,
            ServerLine::Typing {
                from: uid("alice@example.org"),
                conv: Conv::Room(room("#general")),
            }
        );
        syntax("TYPING #general");
        syntax("@from=nobody TYPING #general");
        syntax("@from=~sam TYPING");
        // A stray seq is ignored.
        canonical("@seq=4;from=~sam TYPING #a", "@from=~sam TYPING #a");
        let m = round_trip("@from=~sam NAME Sam the Guest");
        assert!(matches!(&m.line, ServerLine::Name { name, .. } if name == "Sam the Guest"));
        round_trip("@from=~sam NAME");
        syntax("NAME Sam");
        assert_eq!(
            err(&format!("@from=~sam NAME {}", "x".repeat(129))),
            ParseError::TooLong
        );
    }

    #[test]
    fn notice_drop_op_serverban() {
        let m = round_trip("NOTICE Downtime at 22:00 UTC");
        assert!(
            matches!(&m.line, ServerLine::Notice { message } if message == "Downtime at 22:00 UTC")
        );
        round_trip("NOTICE  leading space");
        syntax("NOTICE");
        assert!(
            ServerMessage::new(ServerLine::Notice {
                message: String::new()
            })
            .try_to_line()
            .is_err()
        );
        round_trip("DROP #general");
        round_trip("DROP #general spam haven");
        syntax("DROP");
        round_trip("OP alice@example.org");
        syntax("OP");
        syntax("OP a@b.org c@d.org");
        for target in [
            "spam@example.net",
            "*@example.net",
            "~sam",
            "203.0.113.7",
            "2001:db8::/32",
        ] {
            round_trip(&format!("SERVERBAN {target}"));
            round_trip(&format!("SERVERBAN {target} spam"));
        }
        syntax("SERVERBAN");
        syntax("SERVERBAN 300.1.1.1");
    }

    #[test]
    fn connection_lines() {
        let m = round_trip(&format!("CONNECTION alice@example.org 203.0.113.7 {T}"));
        assert_eq!(
            m.line,
            ServerLine::Connection {
                uid: Some(uid("alice@example.org")),
                address: "203.0.113.7".parse().unwrap(),
                port: None,
                since: T.parse().unwrap(),
            }
        );
        let m = round_trip(&format!("CONNECTION - 203.0.113.7:51000 {T}"));
        assert!(matches!(
            m.line,
            ServerLine::Connection {
                uid: None,
                port: Some(51000),
                ..
            }
        ));
        round_trip(&format!("CONNECTION ~sam 2001:db8::1 {T}"));
        round_trip(&format!("CONNECTION ~sam [2001:db8::1]:7472 {T}"));
        canonical(
            &format!("CONNECTION ~sam 2001:DB8:0::1 {T}"),
            &format!("CONNECTION ~sam 2001:db8::1 {T}"),
        );
        syntax(&format!("CONNECTION ~sam example.org {T}"));
        syntax(&format!("CONNECTION ~sam 203.0.113.7:99999 {T}"));
        syntax("CONNECTION ~sam 203.0.113.7 now");
        syntax("CONNECTION ~sam 203.0.113.7");
        syntax(&format!("CONNECTION sam 203.0.113.7 {T}"));
    }

    #[test]
    fn ping_and_bye() {
        let m = round_trip("PING abc123");
        assert_eq!(
            m.line,
            ServerLine::Ping {
                token: "abc123".into()
            }
        );
        syntax("PING");
        syntax("PING a b");
        round_trip("BYE");
        let m = round_trip("BYE server shutting down");
        assert!(
            matches!(&m.line, ServerLine::Bye { message } if message == "server shutting down")
        );
    }

    #[test]
    fn invalid_values_do_not_serialise() {
        let bad = ServerMessage::new(ServerLine::Bye {
            message: "two\nlines".into(),
        });
        assert!(bad.try_to_line().is_err());
        let bad = ServerMessage::new(ServerLine::Ping {
            token: "a b".into(),
        });
        assert!(bad.try_to_line().is_err());
        let bad = ServerMessage::new(ServerLine::Room {
            room: room("#a"),
            members: 1,
            topic: "x".repeat(513),
        });
        assert_eq!(bad.try_to_line(), Err(ParseError::TooLong));
    }

    #[test]
    #[should_panic(expected = "invalid ServerMessage")]
    fn to_line_panics_on_invalid_values() {
        ServerMessage::new(ServerLine::Ping {
            token: String::new(),
        })
        .to_line();
    }

    // ---- NOTIFY ----

    #[test]
    fn notify() {
        for reason in PushReason::ALL {
            let s = format!("NOTIFY x7Hq2 {reason} 3");
            let n: Notify = s.parse().unwrap();
            assert_eq!(n.reason, NotifyReason::Known(*reason));
            assert_eq!(n.to_string(), s);
            assert_eq!(n.to_body(), format!("{s}\n"));
            assert_eq!(Notify::parse(&n.to_line()), Ok(n));
        }
        let n: Notify = "notify Tag-1 DM 0\r\n".parse().unwrap();
        assert_eq!(n.tag.as_str(), "Tag-1");
        assert_eq!(n.reason, NotifyReason::Known(PushReason::Dm));
        assert_eq!(n.unread, 0);
        // A reason from a later version is kept (9.3).
        let later: Notify = "NOTIFY t Invite 2".parse().unwrap();
        assert_eq!(later.reason, NotifyReason::Other("invite".into()));
        assert_eq!(later.to_string(), "NOTIFY t invite 2");
        assert_eq!(n.to_body(), "NOTIFY Tag-1 dm 0\n");
        let n: Notify = "@x=1 NOTIFY t read 12".parse().unwrap();
        assert_eq!(n.unread, 12);
        assert_eq!(
            "OK x".parse::<Notify>(),
            Err(ParseError::UnknownVerb("OK".into()))
        );
        for b in [
            "NOTIFY t dm",
            "NOTIFY t dm 1 2",
            "NOTIFY t dm -1",
            "NOTIFY t dm 01",
            "NOTIFY t dm 1\n\n",
        ] {
            assert!(b.parse::<Notify>().is_err(), "{b:?}");
        }
        assert_eq!(
            format!("NOTIFY {} dm 1", "a".repeat(65)).parse::<Notify>(),
            Err(ParseError::TooLong)
        );
    }
}

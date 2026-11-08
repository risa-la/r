//! Typed server lines, server to client (SPEC 3.6, 4-12, the second table
//! of Section 13), and the NOTIFY push body (9.3).
//!
//! Every line in the second table of Section 13 parses into a
//! [`ServerMessage`]: an envelope with the `ref` tag (3.6) around a
//! [`ServerLine`]. Tags that belong to one kind of line, such as a post's
//! `seq` and `t` (5.2) or a report's `report`, `t` and `from` (5.8), live
//! in that line's type.
//!
//! ```
//! use risala_proto::server::{ServerLine, ServerMessage};
//!
//! let msg: ServerMessage =
//!     "@seq=9122;t=2026-11-08T15:41:02.377Z POST ujzdegxdncf32epf3dhodzdoci AAEAAg==".parse()?;
//! let ServerLine::Post(post) = &msg.line else { panic!() };
//! assert_eq!(post.seq.map(|s| s.get()), Some(9122));
//! assert_eq!(msg.to_line().to_string(),
//!     "@seq=9122;t=2026-11-08T15:41:02.377Z POST ujzdegxdncf32epf3dhodzdoci AAEAAg==");
//! # Ok::<(), risala_proto::error::ParseError>(())
//! ```
//!
//! A server builds lines from values:
//!
//! ```
//! use risala_proto::names::Seq;
//! use risala_proto::server::{OkResponse, ServerMessage};
//!
//! let seq = Seq::new(9121).unwrap();
//! let ok = ServerMessage::new(OkResponse::new().with_seq(seq));
//! assert_eq!(ok.to_line().to_string(), "OK seq=9121");
//! ```
//!
//! The code is split like [`command`](crate::command): [`response`]
//! (the greeting, OK and ERR), [`mailbox`] (POST, ROOM, GROUPINFO, GONE,
//! DROP, REPORT and RESOLVED), [`account`] (USER, MEMBER, PRESENCE,
//! RECORD, PAIR, PUSH, KEYPKG, WELCOME and BACKUP), [`admin`] (OP,
//! SERVERBAN and CONNECTION) and [`notify`] (the NOTIFY push body). NOTICE,
//! PING and BYE are here.
//!
//! Decisions where the spec leaves room:
//!
//! - **Unknown verbs** parse as [`ServerLine::Unknown`], not as an error,
//!   since clients ignore lines with unknown verbs (3.8). A known verb with
//!   the wrong parameters is an error, and a client ignores it (2.3).
//! - **Unknown and inapplicable tags are ignored** (3.2), such as `seq` on
//!   a PRESENCE line. They are not read, so their values are not checked
//!   either. Serialising leaves them out.
//! - **Tags that are read are checked.** A bad `ref`, `seq`, `t`,
//!   `report`, `from` or `retry` value is an error, as is one of these
//!   tags without a value.
//! - **Posts (5.2).** A kept post has `seq` and `t`. A live post
//!   (`live=yes`) has no `seq`; whether it has `t` the spec does not say,
//!   so `t` is optional without `seq` and required with it.
//! - **Reports (5.8)** need `report` and `t`; `from` is optional.
//! - **MLS data and other binary values** are opaque: they only have to
//!   be strict base64 of the right length, or a blob-ref where the spec
//!   allows one ([`OrBlob`]).
//! - **Length limits** stated by the spec are applied as on commands, so a
//!   correct server never trips them: a room's topic of 512 bytes, and a
//!   greeting's welcome text of 512. Longer values are `TooLong`. Other
//!   text has no limit beyond the line's.
//! - **Optional text** (`[<reason...>]`, `[<message...>]`) is a `String`,
//!   empty when absent: on the wire the two are the same (3.3). Required
//!   text (`<message...>` of NOTICE) must not be empty.
//! - **Text stays escaped** (3.4). Unescape it with
//!   [`text::unescape`](crate::text::unescape) to display it.
//! - **Case.** Verbs and keywords are case-insensitive and names are
//!   folded (3.5). Serialising writes the canonical form, so a parsed line
//!   in canonical form serialises back byte for byte.
//!
//! Tags are written in this order: `ref`, then `report`, `seq`, `t` and
//! `from`, or `retry` on ERR. This reproduces every example in the spec.

use std::net::IpAddr;
use std::str::FromStr;

use crate::binary::{PairData, WrappedKey};
use crate::error::ParseError;
use crate::line::{Line, LineBuilder, Params, Tags};
use crate::mls::{GroupInfo, KeyPackage, OrBlob, RatchetTree, Welcome};
use crate::names::{BlobRef, BoxName, Id, PairId, Room, Seq, ServerBanTarget, Uid};
use crate::parse::{bad, parse_tag, required_text};
use crate::time::Timestamp;
use crate::types::{Presence, PushTag, PushUrl, Ref, Role};

pub mod account;
pub mod admin;
pub mod mailbox;
pub mod notify;
pub mod response;

pub use mailbox::{Post, Report};
pub use notify::Notify;
pub use response::{ErrResponse, Greeting, Host, Log, OkResponse, Register, Upload};

// ---------------------------------------------------------------------------
// The envelope

/// A line from the server (Section 13, second table), with its `ref` tag
/// (3.6).
///
/// `ref_` is the client's `ref` tag, copied onto every response line and
/// the final OK or ERR of the command that had it (3.6). Live posts and
/// other lines a command did not ask for never carry it.
///
/// For [`ServerLine::Unknown`], `ref` is taken out of the line and kept
/// here, so that a client can still match it (3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerMessage {
    /// The `ref` tag (3.6).
    pub ref_: Option<Ref>,
    /// The line itself.
    pub line: ServerLine,
}

impl ServerMessage {
    /// A message with no `ref` tag.
    pub fn new(line: impl Into<ServerLine>) -> ServerMessage {
        ServerMessage {
            ref_: None,
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

    /// Parses a line from the server (Section 13).
    ///
    /// An unknown verb gives [`ServerLine::Unknown`] (3.8). A known verb
    /// with bad parameters or bad tags fails with `BadSyntax`, or `TooLong`
    /// for a value over a protocol limit. See the [module](self) docs for
    /// what is checked and what is ignored.
    pub fn parse(line: &Line) -> Result<ServerMessage, ParseError> {
        let tags = line.tags();
        let ref_ = parse_tag::<Ref>(tags, "ref")?;
        let verb = line.verb_upper();
        let p = line.params();
        let parsed = response::parse(&verb, tags, p)
            .or_else(|| mailbox::parse(&verb, tags, p))
            .or_else(|| account::parse(&verb, p))
            .or_else(|| admin::parse(&verb, p))
            .or_else(|| parse_other(&verb, p));
        let line = match parsed {
            Some(line) => line?,
            None => {
                let mut rest = line.clone();
                rest.tags_mut().remove("ref");
                ServerLine::Unknown(rest)
            }
        };
        Ok(ServerMessage { ref_, line })
    }

    /// Serialises the message, in canonical form.
    ///
    /// # Panics
    ///
    /// If the message is not valid, for example text with a line break or
    /// an empty PRESENCE list. Every parsed message is valid. Use
    /// [`try_to_line`](Self::try_to_line) for messages built from values
    /// that were not checked.
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
    /// `ErrorCode::Other` holding a known code, fail too.
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
        let written = response::write(&self.line, &mut b)
            || mailbox::write(&self.line, &mut b)
            || account::write(&self.line, &mut b)
            || admin::write(&self.line, &mut b)
            || write_other(&self.line, &mut b);
        debug_assert!(written, "every server line is written by its area");
        b.build()
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

/// One line a server can send (Section 13, second table), without the
/// `ref` tag, which is in [`ServerMessage`].
///
/// Text fields hold escaped text (3.4) without control characters other
/// than TAB. Where the syntax has optional text, the field is empty when
/// the text is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerLine {
    /// `RISALA <version> <host> <nonce> [<message...>]`, the greeting
    /// (4.1).
    Greeting(Greeting),
    /// `OK [<key>=<value> ...]`, a successful final response (3.6).
    Ok(OkResponse),
    /// `ERR <code> [<message...>]`, a failed final response (3.6, 3.7).
    Err(ErrResponse),
    /// `POST <box> <message>`: a post, live or in response to FETCH (5.2,
    /// 7.1).
    Post(Post),
    /// `ROOM <room> <box> <members> [<topic...>]`: a public room, in
    /// response to LIST and ADMIN ROOMS (6.1, 10.4).
    Room {
        /// The room's name.
        room: Room,
        /// Its mailbox.
        mailbox: BoxName,
        /// The number of identities and guests with a leaf in its group.
        members: u64,
        /// Its topic, escaped; empty if none. At most 512 bytes.
        topic: String,
    },
    /// `GROUPINFO <box> <epoch> <seq> <groupinfo> <tree>`: a public room's
    /// current GroupInfo and ratchet tree, in response to GROUPINFO (6.1).
    GroupInfo {
        /// The public room's mailbox.
        mailbox: BoxName,
        /// The group's current epoch.
        epoch: u64,
        /// The seq of the commit that started the epoch, or `None` (`0`)
        /// in epoch 0.
        seq: Option<Seq>,
        /// The GroupInfo, or a blob that holds it.
        groupinfo: OrBlob<GroupInfo>,
        /// The ratchet tree, or a blob that holds it.
        tree: OrBlob<RatchetTree>,
    },
    /// `GONE <box> <uid>`: a guest's session ended, so members' devices
    /// remove its leaves (6.1).
    Gone {
        /// A public room's mailbox the guest had a leaf in.
        mailbox: BoxName,
        /// The guest.
        uid: Uid,
    },
    /// `DROP <box> [<reason...>]`: an operator deleted the mailbox (6.1,
    /// 10.4).
    Drop {
        /// The mailbox.
        mailbox: BoxName,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `USER <uid> <presence>`: in response to WATCH and WHOIS (8.3).
    User {
        /// The identity.
        uid: Uid,
        /// Whether it is online.
        presence: Presence,
    },
    /// `MEMBER <room> <uid> <role> <presence>`: in response to MEMBERS
    /// (8.3).
    Member {
        /// The public room.
        room: Room,
        /// The identity or guest with a leaf in its group.
        uid: Uid,
        /// The role, from the room's conversation extension.
        role: Role,
        /// Whether it is online.
        presence: Presence,
    },
    /// `PRESENCE <presence> <uids>`: watched identities came online or
    /// went offline (8.3).
    Presence {
        /// The new presence of each of them.
        presence: Presence,
        /// The identities, at least one, separated by commas on the wire.
        uids: Vec<Uid>,
    },
    /// `REPORT <box> <report>`: a report, live or in response to ADMIN
    /// REPORTS (5.8).
    Report(Report),
    /// `RESOLVED <id>`: a report was resolved (5.8).
    Resolved {
        /// The report's id.
        id: Id,
    },
    /// `RECORD <index> <hash>`: a record the server added to its log, in
    /// response to KEYS PUT (4.7).
    Record {
        /// The record's position in the log.
        index: u64,
        /// The record's SHA-384 hash.
        hash: BlobRef,
    },
    /// `PAIR <id> <data>`: in response to PAIR GET (4.8).
    Pair {
        /// The id.
        id: PairId,
        /// The encrypted pairing message stored under it.
        data: PairData,
    },
    /// `PUSH <url> <tag>`: an account subscription, in response to PUSH
    /// LIST (9.1).
    Push {
        /// The subscription's URL.
        url: PushUrl,
        /// Its tag.
        tag: PushTag,
    },
    /// `KEYPKG <uid> <keypackage>`: a KeyPackage of one of the identity's
    /// current devices, in response to KEYPKG GET (12.5).
    KeyPkg {
        /// The identity.
        uid: Uid,
        /// The KeyPackage.
        key_package: KeyPackage,
    },
    /// `WELCOME <id> <welcome>`: a Welcome, live or in response to
    /// WELCOME LIST or WELCOME GET (12.8).
    Welcome {
        /// The id the server gave it, for WELCOME DEL.
        id: Id,
        /// The Welcome, AnnotatedWelcome or a blob that holds it.
        welcome: OrBlob<Welcome>,
    },
    /// `BACKUP <generation> <hash> <key>`: in response to BACKUP GET
    /// (12.13).
    Backup {
        /// The generation of the backup key that wraps `key`.
        generation: u32,
        /// The blob-ref of the encrypted archive.
        hash: BlobRef,
        /// The archive's key, wrapped.
        key: WrappedKey,
    },
    /// `NOTICE <message...>`: information for people (8.4).
    Notice {
        /// The message, escaped, never empty.
        message: String,
    },
    /// `OP <uid>`: an operator, in response to ADMIN OPS (10.1).
    Op {
        /// The operator.
        uid: Uid,
    },
    /// `SERVERBAN <target> [<reason...>]`: a ban, in response to ADMIN
    /// BANS (10.2).
    ServerBan {
        /// What is banned.
        target: ServerBanTarget,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `CONNECTION <uid> <address> <since>`: an open connection, in
    /// response to ADMIN WHO (10.3).
    Connection {
        /// The identity or guest, or `None` (`-`) for an anonymous or new
        /// connection.
        uid: Option<Uid>,
        /// The client's IP address.
        address: IpAddr,
        /// The client's port, if given.
        port: Option<u16>,
        /// When the connection was opened.
        since: Timestamp,
    },
    /// `PING <token>`: the server checks that the connection is alive
    /// (11). The client answers PONG with the same token.
    Ping {
        /// The token.
        token: String,
    },
    /// `BYE [<message...>]`: the server is closing the connection (11).
    Bye {
        /// Why, escaped. May be empty.
        message: String,
    },
    /// A line with a verb this crate does not know (3.8), without its
    /// `ref` tag. Clients ignore it.
    Unknown(Line),
}

impl ServerLine {
    /// The verb, in upper case.
    pub fn verb(&self) -> &str {
        match self {
            ServerLine::Greeting(_) => "RISALA",
            ServerLine::Ok(_) => "OK",
            ServerLine::Err(_) => "ERR",
            ServerLine::Post(_) => "POST",
            ServerLine::Room { .. } => "ROOM",
            ServerLine::GroupInfo { .. } => "GROUPINFO",
            ServerLine::Gone { .. } => "GONE",
            ServerLine::Drop { .. } => "DROP",
            ServerLine::User { .. } => "USER",
            ServerLine::Member { .. } => "MEMBER",
            ServerLine::Presence { .. } => "PRESENCE",
            ServerLine::Report(_) => "REPORT",
            ServerLine::Resolved { .. } => "RESOLVED",
            ServerLine::Record { .. } => "RECORD",
            ServerLine::Pair { .. } => "PAIR",
            ServerLine::Push { .. } => "PUSH",
            ServerLine::KeyPkg { .. } => "KEYPKG",
            ServerLine::Welcome { .. } => "WELCOME",
            ServerLine::Backup { .. } => "BACKUP",
            ServerLine::Notice { .. } => "NOTICE",
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
}

impl From<Greeting> for ServerLine {
    fn from(greeting: Greeting) -> ServerLine {
        ServerLine::Greeting(greeting)
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

impl From<Post> for ServerLine {
    fn from(post: Post) -> ServerLine {
        ServerLine::Post(post)
    }
}

impl From<Report> for ServerLine {
    fn from(report: Report) -> ServerLine {
        ServerLine::Report(report)
    }
}

// ---------------------------------------------------------------------------
// NOTICE (8.4), PING and BYE (11)

fn parse_other(verb: &str, mut p: Params<'_>) -> Option<Result<ServerLine, ParseError>> {
    let mut parse = || -> Result<ServerLine, ParseError> {
        Ok(match verb {
            "NOTICE" => ServerLine::Notice {
                message: required_text(p, "NOTICE has a message")?,
            },
            "PING" => {
                let token = p.token()?.to_owned();
                p.end()?;
                ServerLine::Ping { token }
            }
            "BYE" => ServerLine::Bye {
                message: p.text().to_owned(),
            },
            _ => unreachable!(),
        })
    };
    matches!(verb, "NOTICE" | "PING" | "BYE").then(&mut parse)
}

fn write_other(line: &ServerLine, b: &mut LineBuilder) -> bool {
    match line {
        ServerLine::Notice { message } => {
            b.text(message);
        }
        ServerLine::Ping { token } => {
            b.token(token);
        }
        ServerLine::Bye { message } => {
            b.text(message);
        }
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests;

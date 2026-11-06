//! Typed client commands (SPEC 4-11, the first table of Section 12).
//!
//! A [`Request`] is one line a client sends: its optional `ref` tag (3.6)
//! and a [`Command`]. Parse one from a [`Line`] with [`Request::parse`],
//! or from a string with [`str::parse`]; turn it back into a line with
//! [`Request::to_line`].
//!
//! ```
//! use risala_proto::command::{Command, Request};
//! use risala_proto::types::Relation;
//!
//! let request: Request = "@ref=7;reply=8810 msg #General hi".parse()?;
//! let Command::Msg { conv, text, relation, .. } = &request.command else {
//!     panic!("not a MSG");
//! };
//! assert_eq!(conv.as_str(), "#general");
//! assert_eq!(text, "hi");
//! assert!(matches!(relation, Some(Relation::Reply(_))));
//! assert_eq!(
//!     request.to_line().to_string(),
//!     "@ref=7;reply=8810 MSG #general hi"
//! );
//! # Ok::<(), risala_proto::error::ParseError>(())
//! ```
//!
//! # Rules
//!
//! - **Arity (3.3).** Too few or too many tokens, an unknown option or a
//!   repeated option is `BadSyntax`. An unknown verb is
//!   [`ParseError::UnknownVerb`], carrying the verb in upper case. An
//!   unknown or missing subcommand of a known verb (`KEY FOO`, `ADMIN`) is
//!   `BadSyntax`, since the verb itself is known and only its parameters
//!   are wrong.
//! - **Tags (3.2).** `ref` applies to every command. MSG also reads
//!   `reply`, `edit`, `react`, `file` and `cid` (5.3, 5.6, 7.6). Every
//!   other tag is ignored, including those MSG tags on other commands. A
//!   tag this module reads must have a valid value: a `ref` or `cid` over
//!   64 bytes is `TooLong`, a missing or malformed value is `BadSyntax`.
//! - **Text stays escaped (3.4).** Text parameters are kept exactly as
//!   received. Length limits apply to that escaped form and are
//!   `TooLong`.
//! - **Optional text** (`[<reason...>]`, `[<label...>]`, `[<name...>]`,
//!   `[<message...>]`) is a `String` that is empty when absent, so
//!   `PART #r` and `PART #r ` parse equal. Required text (`<text...>`,
//!   `<name...>`, `<message...>`) must not be empty (`BadSyntax`), except
//!   for the value of SET and ADMIN SET, which may be empty because a
//!   topic or welcome message may be (6.2, 10.6). Only the empty string
//!   counts as empty: `MSG #r  ` has the text `" "`.
//! - **Names fold (3.5).** Rooms, uids, roles, subcommands, option keys
//!   and keyword values are case-insensitive and are written back in
//!   lower case. Verbs and subcommands are written in upper case.
//!
//! # Serialising
//!
//! [`Request::to_line`] writes the canonical form: the verb (and
//! subcommand) in upper case, single spaces, tags in the order `ref`,
//! then the relation, then `file`, then `cid`, and options in the order
//! the spec's syntax line lists them. Optional options are left out when
//! they are absent, and so is `purge=` when it is false.
//!
//! The fields of [`Command`] are public, so a request built by hand can
//! hold values that a parsed one never does. [`Request::validate`] checks
//! a hand-built request against every rule above.

use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use crate::auth::{PublicKey, Signature};
use crate::error::ParseError;
use crate::line::{Line, LineBuilder, Options, Params, Tags};
use crate::names::{BlockTarget, Conv, Id, Identity, Name, Room, Seq, ServerBanTarget, Uid};
use crate::types::{
    Cid, MAX_DISPLAY_NAME, MAX_REACTION, MAX_REPORT_REASON, PushTag, Ref, Relation, Role,
    RoomSetting, ServerSetting, parse_u64, parse_yes_no,
};
pub use crate::types::{FileUrl, MAX_MEDIA_TYPE_PART, MediaType, PushUrl};

// ---------------------------------------------------------------------------
// Request

/// One command from a client, with its `ref` tag (3.6).
///
/// Every other tag the command needs, such as MSG's `reply`, lives in the
/// [`Command`]. Tags this crate does not use are dropped (3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The `ref` tag, which the server copies onto the command's response
    /// lines and final response (3.6). Named `ref_` because `ref` is a
    /// Rust keyword.
    pub ref_: Option<Ref>,
    /// The command.
    pub command: Command,
}

impl Request {
    /// A request without a `ref` tag.
    pub fn new(command: Command) -> Request {
        Request {
            ref_: None,
            command,
        }
    }

    /// Parses a client line into a typed request (3.3, Section 12).
    ///
    /// Errors: [`ParseError::UnknownVerb`] for a verb that is not a client
    /// command, `TooLong` for a value over a protocol limit, and
    /// `BadSyntax` for everything else, as described in the [module
    /// documentation](self).
    pub fn parse(line: &Line) -> Result<Request, ParseError> {
        let ref_ = Request::parse_ref(line.tags())?;
        let command = Command::parse(line)?;
        Ok(Request { ref_, command })
    }

    /// The valid `ref` of `line`, if it has one (3.6).
    ///
    /// A server copies the `ref` onto its final response, including an
    /// `ERR` for a line that [`Request::parse`] rejected. This reads it
    /// on its own, so a server can do that. A `ref` without a value or
    /// over 64 bytes gives `None`.
    pub fn ref_of(line: &Line) -> Option<Ref> {
        Request::parse_ref(line.tags()).ok().flatten()
    }

    fn parse_ref(tags: &Tags) -> Result<Option<Ref>, ParseError> {
        match tags.entry("ref") {
            None => Ok(None),
            Some(None) => Err(ParseError::BadSyntax("ref needs a value")),
            Some(Some(value)) => value.parse().map(Some),
        }
    }

    /// Writes the request as a line in canonical form (see the [module
    /// documentation](self)).
    ///
    /// # Panics
    ///
    /// Never for a request from [`Request::parse`]: every value in it was
    /// read from a valid line, and every token and tag comes from a type
    /// that checks itself. A request built by hand can hold a string that
    /// no line can carry, and then this panics. That is a text field
    /// (including a [`RoomSetting`] or [`ServerSetting`] value) with a
    /// control character other than TAB, a setting key or PING/PONG token
    /// that is not one token, or a PING/PONG token that is empty. Make
    /// text with [`text::escape`](crate::text::escape), or use
    /// [`try_to_line`](Self::try_to_line) or
    /// [`validate`](Self::validate) for such requests.
    pub fn to_line(&self) -> Line {
        self.try_to_line()
            .expect("a parsed request's values all fit in a line")
    }

    /// Writes the request as a line, like [`to_line`](Self::to_line), but
    /// returns an error instead of panicking when a hand-built request
    /// holds a string that no line can carry.
    pub fn try_to_line(&self) -> Result<Line, ParseError> {
        let mut b = Line::builder(self.command.verb());
        if let Some(r) = &self.ref_ {
            b.tag("ref", r);
        }
        self.command.write(&mut b);
        b.build()
    }

    /// Checks a request built by hand: it serialises, and parsing the
    /// result gives back the same request. So every rule of
    /// [`Request::parse`] holds, including length limits and the MSG tag
    /// rules, and the values are in canonical form (for example, a
    /// [`RoomSetting::Other`] whose key is a known one fails).
    pub fn validate(&self) -> Result<(), ParseError> {
        let line = self.try_to_line()?;
        if Request::parse(&line)? == *self {
            Ok(())
        } else {
            Err(ParseError::BadSyntax("request is not in canonical form"))
        }
    }
}

impl From<Command> for Request {
    fn from(command: Command) -> Request {
        Request::new(command)
    }
}

impl FromStr for Request {
    type Err = ParseError;

    /// Parses a whole line, without its line ending: [`Line::parse`], then
    /// [`Request::parse`].
    fn from_str(s: &str) -> Result<Request, ParseError> {
        Request::parse(&Line::parse(s)?)
    }
}

impl fmt::Display for Request {
    /// Writes the canonical line, as [`Request::to_line`] does (and with
    /// the same panics).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_line(), f)
    }
}

// ---------------------------------------------------------------------------
// Command

/// A client command: one variant per row of the first table in Section 12.
///
/// Optional text is an empty `String` when absent. Text is escaped, as on
/// the wire (3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // ---- 4. Identity and authentication ----
    /// `INFO [<room>]` (8.5, 6.2): server information, or a room's.
    Info {
        /// The room, for `INFO <room>` (6.2). Without one, the server's
        /// information (8.5), which is allowed before sign-in.
        room: Option<Room>,
    },
    /// `GUEST <name>` (4.2): become the guest `~<name>`.
    Guest {
        /// The guest name, without `~`.
        name: Name,
    },
    /// `AUTH <uid> <signature>` (4.5): sign in as an identity.
    ///
    /// The uid is an [`Identity`]: a guest cannot sign in with a key, and
    /// the signed bytes name an identity (4.5), so `AUTH ~sam ...` is
    /// `BadSyntax`.
    Auth {
        /// The identity to sign in as.
        identity: Identity,
        /// The signature over the challenge bytes (4.5).
        signature: Signature,
    },
    /// `REGISTER <name> <key> <signature>` (4.6): create a hosted identity.
    Register {
        /// The name, the local part of the new identity.
        name: Name,
        /// The identity's first key.
        key: PublicKey,
        /// The signature over the challenge bytes for the new uid (4.5).
        signature: Signature,
    },
    /// `KEY LIST`, `KEY ADD` or `KEY DEL` (4.7): manage a hosted
    /// identity's keys.
    Key(KeyCommand),
    /// `UNREGISTER <uid> [purge=yes]` (4.8): delete your identity.
    Unregister {
        /// The identity, typed out as a guard. Any uid parses, so that a
        /// server can answer a mismatch, including a guest uid, with
        /// `ERR forbidden` (4.8).
        uid: Uid,
        /// `purge=yes`: also delete every message sent. `purge=no` is
        /// accepted and means the same as leaving the option out.
        purge: bool,
    },

    // ---- 5. Conversations ----
    /// `MSG <conv> <text...>` (5.3), with its tags (5.3, 5.6, 7.6).
    Msg {
        /// The conversation.
        conv: Conv,
        /// The text, escaped, never empty. At most 64 bytes for a
        /// reaction ([`MAX_REACTION`]).
        text: String,
        /// The `reply`, `edit` or `react` tag: at most one (5.3).
        relation: Option<Relation>,
        /// The `file` tag (5.6). It may go with a reply, but not with an
        /// edit or a reaction.
        file: Option<FileUrl>,
        /// The `cid` tag, for safe resending (7.6).
        cid: Option<Cid>,
    },
    /// `DELETE <conv> <seq>` (5.4): delete a message.
    Delete {
        /// The conversation.
        conv: Conv,
        /// The message to delete.
        seq: Seq,
    },
    /// `UPLOAD <size> <type> <name...>` (5.6): ask to upload a file.
    Upload {
        /// The file's size in bytes. Zero is allowed.
        size: u64,
        /// The file's media type.
        media_type: MediaType,
        /// The file name, escaped text, never empty.
        name: String,
    },
    /// `BLOCK <target>` (5.7).
    Block {
        /// An identity or a domain.
        target: BlockTarget,
    },
    /// `UNBLOCK <target>` (5.7).
    Unblock {
        /// An identity or a domain.
        target: BlockTarget,
    },
    /// `BLOCKS` (5.7): list your blocks.
    Blocks,
    /// `REPORT <conv> <seq> [<reason...>]` (5.8): report a message.
    Report {
        /// The conversation.
        conv: Conv,
        /// The reported message.
        seq: Seq,
        /// Why, escaped, at most 512 bytes ([`MAX_REPORT_REASON`]). May be
        /// empty.
        reason: String,
    },
    /// `REPORTS <room>` (5.8): list a room's open reports.
    Reports {
        /// The room.
        room: Room,
    },
    /// `RESOLVE <id>` (5.8): close a report.
    Resolve {
        /// The report's id.
        id: Id,
    },

    // ---- 6. Rooms ----
    /// `LIST` (6.1): list public rooms.
    List,
    /// `JOIN <room>` (6.1).
    Join {
        /// The room.
        room: Room,
    },
    /// `PART <room> [<reason...>]` (6.1).
    Part {
        /// The room.
        room: Room,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `SET <room> <key> <value...>` (6.2): change a room setting.
    ///
    /// Unknown keys are kept in [`RoomSetting::Other`], so that a server
    /// can reply `ERR not-supported`. A known key with a bad value is
    /// `BadSyntax`, and a topic over 512 bytes is `TooLong`.
    Set {
        /// The room.
        room: Room,
        /// The setting and its new value.
        setting: RoomSetting,
    },
    /// `ROLE <room> <uid> <role>` (6.3): set someone's role.
    Role {
        /// The room.
        room: Room,
        /// Whose role. Any uid parses; the server checks that it is an
        /// identity.
        uid: Uid,
        /// The new role.
        role: Role,
    },
    /// `ROLES <room>` (6.3): list owners and moderators.
    Roles {
        /// The room.
        room: Room,
    },
    /// `INVITE <room> <uid>` (6.4).
    Invite {
        /// The room.
        room: Room,
        /// Who to invite. Any uid parses; guests cannot be invited, which
        /// the server checks.
        uid: Uid,
    },
    /// `KICK <room> <uid> [<reason...>]` (6.4).
    Kick {
        /// The room.
        room: Room,
        /// Who to kick.
        uid: Uid,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `BAN <room> <uid> [<reason...>]` (6.4).
    Ban {
        /// The room.
        room: Room,
        /// Who to ban.
        uid: Uid,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `UNBAN <room> <uid>` (6.4).
    Unban {
        /// The room.
        room: Room,
        /// Whose ban to lift.
        uid: Uid,
    },
    /// `BANS <room>` (6.4): list a room's bans.
    Bans {
        /// The room.
        room: Room,
    },

    // ---- 7. History and sync ----
    /// `SYNC` (7.1): list every conversation with its head.
    Sync,
    /// `HISTORY <conv> [after=<seq>] [before=<seq>] [limit=<n>]` (7.2).
    History {
        /// The conversation.
        conv: Conv,
        /// `after=`: return events after this seq. `0` is accepted, as
        /// 7.1 has a client with nothing stored send `after=0`; it means
        /// "from the first event". So this is a plain number from 0 to
        /// 2^63-1 rather than a [`Seq`]. `Some(0)` and `None` differ: with
        /// `after` the server returns the earliest events, without it the
        /// latest.
        after: Option<u64>,
        /// `before=`: return events before this seq.
        before: Option<Seq>,
        /// `limit=`: the most events to return, at least 1. The server's
        /// default is 50 ([`DEFAULT_LIMIT`](crate::types::DEFAULT_LIMIT)).
        /// `limit=0` is `BadSyntax`.
        limit: Option<NonZeroU64>,
    },
    /// `RELATED <conv> <first> <last> [after=<seq>] [limit=<n>]` (7.3):
    /// the edits and reactions of messages `<first>` to `<last>`.
    ///
    /// `first > last` parses; it names an empty range.
    Related {
        /// The conversation.
        conv: Conv,
        /// The first target seq, inclusive.
        first: Seq,
        /// The last target seq, inclusive.
        last: Seq,
        /// `after=`, as in [`Command::History`]; `0` is accepted.
        after: Option<u64>,
        /// `limit=`, as in [`Command::History`]; at least 1.
        limit: Option<NonZeroU64>,
    },
    /// `READ <conv> <seq>` (7.4): move your read marker.
    Read {
        /// The conversation.
        conv: Conv,
        /// The newest seq read.
        seq: Seq,
    },

    // ---- 8. Other lines ----
    /// `TYPING <conv>` (8.1).
    Typing {
        /// The conversation.
        conv: Conv,
    },
    /// `NAME [<name...>]` (8.2): set or clear your display name.
    Name {
        /// The display name, escaped, at most 128 bytes
        /// ([`MAX_DISPLAY_NAME`]). Empty clears it.
        display_name: String,
    },
    /// `MEMBERS <room>` (8.3).
    Members {
        /// The room.
        room: Room,
    },
    /// `WHOIS <uid>` (8.3).
    Whois {
        /// The user.
        uid: Uid,
    },

    // ---- 9. Push ----
    /// `PUSH ADD`, `PUSH DEL` or `PUSH LIST` (9.1).
    Push(PushCommand),

    // ---- 10. Administration ----
    /// `ADMIN ...` (10, 5.8): operator commands.
    Admin(AdminCommand),

    // ---- 11. Keepalive and closing ----
    /// `PING [<token>]` (11).
    Ping {
        /// The token, if any. Any token is accepted.
        token: Option<String>,
    },
    /// `PONG <token>` (11): the answer to a server's PING. It gets no
    /// response (3.6).
    Pong {
        /// The token from the server's PING.
        token: String,
    },
    /// `QUIT [<message...>]` (11).
    Quit {
        /// A parting message, escaped. May be empty.
        message: String,
    },
}

/// The subcommands of `KEY` (4.7). The subcommand word is case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCommand {
    /// `KEY LIST`: list your keys.
    List,
    /// `KEY ADD <key> [<label...>]`: add a key.
    Add {
        /// The key to add.
        key: PublicKey,
        /// A note for people, escaped. May be empty.
        label: String,
    },
    /// `KEY DEL <key>`: remove a key.
    Del {
        /// The key to remove.
        key: PublicKey,
    },
}

/// The subcommands of `PUSH` (9.1). The subcommand word is
/// case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushCommand {
    /// `PUSH ADD <url> <tag>`: register for pushes.
    Add {
        /// Where to send pushes.
        url: PushUrl,
        /// The opaque tag sent in every push, at most 64 bytes.
        tag: PushTag,
    },
    /// `PUSH DEL <url>`: remove a registration.
    Del {
        /// The registration's URL.
        url: PushUrl,
    },
    /// `PUSH LIST`: list this device's registrations.
    List,
}

/// The subcommands of `ADMIN` (Section 10, 5.8). The subcommand word is
/// case-insensitive.
///
/// Commands that name a user take any [`Uid`]: whether a guest makes
/// sense (it does for DISCONNECT and PURGE, not for OP or KEYS) is for
/// the server to answer.
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
    /// `ADMIN ROOMS` (10.4): list every room.
    Rooms,
    /// `ADMIN DROP <room> [<reason...>]` (10.4): delete a room.
    Drop {
        /// The room.
        room: Room,
        /// Why, escaped. May be empty.
        reason: String,
    },
    /// `ADMIN PURGE <uid> [hours=<n>]` (10.4): delete what a user sent.
    Purge {
        /// Whose messages.
        uid: Uid,
        /// `hours=`: only the last `n` hours, at least 1. `hours=0` is
        /// `BadSyntax`.
        hours: Option<NonZeroU64>,
    },
    /// `ADMIN REPORTS` (5.8, 10.4): list every open report.
    Reports,
    /// `ADMIN KEYS <uid>` (10.5): list a hosted identity's keys.
    Keys {
        /// The identity.
        uid: Uid,
    },
    /// `ADMIN ADDKEY <uid> <key> [<label...>]` (10.5).
    AddKey {
        /// The identity.
        uid: Uid,
        /// The key to add.
        key: PublicKey,
        /// A note for people, escaped. May be empty.
        label: String,
    },
    /// `ADMIN DELKEY <uid> <key>` (10.5).
    DelKey {
        /// The identity.
        uid: Uid,
        /// The key to remove.
        key: PublicKey,
    },
    /// `ADMIN UNREGISTER <uid>` (10.5): delete a hosted identity.
    Unregister {
        /// The identity.
        uid: Uid,
    },
    /// `ADMIN SET <key> <value...>` (10.6): change a server setting.
    ///
    /// Unknown keys are kept in [`ServerSetting::Other`]; a known key with
    /// a bad value is `BadSyntax`.
    Set(ServerSetting),
}

// ---------------------------------------------------------------------------
// Tables (Section 12)

impl Command {
    /// The verb, in upper case (3.1). Subcommands share their verb:
    /// `KEY`, `PUSH` or `ADMIN`.
    pub fn verb(&self) -> &'static str {
        match self {
            Command::Info { .. } => "INFO",
            Command::Guest { .. } => "GUEST",
            Command::Auth { .. } => "AUTH",
            Command::Register { .. } => "REGISTER",
            Command::Key(_) => "KEY",
            Command::Unregister { .. } => "UNREGISTER",
            Command::Msg { .. } => "MSG",
            Command::Delete { .. } => "DELETE",
            Command::Upload { .. } => "UPLOAD",
            Command::Block { .. } => "BLOCK",
            Command::Unblock { .. } => "UNBLOCK",
            Command::Blocks => "BLOCKS",
            Command::Report { .. } => "REPORT",
            Command::Reports { .. } => "REPORTS",
            Command::Resolve { .. } => "RESOLVE",
            Command::List => "LIST",
            Command::Join { .. } => "JOIN",
            Command::Part { .. } => "PART",
            Command::Set { .. } => "SET",
            Command::Role { .. } => "ROLE",
            Command::Roles { .. } => "ROLES",
            Command::Invite { .. } => "INVITE",
            Command::Kick { .. } => "KICK",
            Command::Ban { .. } => "BAN",
            Command::Unban { .. } => "UNBAN",
            Command::Bans { .. } => "BANS",
            Command::Sync => "SYNC",
            Command::History { .. } => "HISTORY",
            Command::Related { .. } => "RELATED",
            Command::Read { .. } => "READ",
            Command::Typing { .. } => "TYPING",
            Command::Name { .. } => "NAME",
            Command::Members { .. } => "MEMBERS",
            Command::Whois { .. } => "WHOIS",
            Command::Push(_) => "PUSH",
            Command::Admin(_) => "ADMIN",
            Command::Ping { .. } => "PING",
            Command::Pong { .. } => "PONG",
            Command::Quit { .. } => "QUIT",
        }
    }

    /// Whether the server accepts this command before the connection has
    /// signed in (4.1, the "Before sign-in" column of Section 12): INFO
    /// without a room, GUEST, AUTH, REGISTER, PING, PONG and QUIT. The
    /// server replies `ERR not-authenticated` to anything else.
    pub fn allowed_before_sign_in(&self) -> bool {
        matches!(
            self,
            Command::Info { room: None }
                | Command::Guest { .. }
                | Command::Auth { .. }
                | Command::Register { .. }
                | Command::Ping { .. }
                | Command::Pong { .. }
                | Command::Quit { .. }
        )
    }

    /// Whether this command signs a connection in: GUEST, AUTH or REGISTER
    /// (4.1-4.6). A connection signs in once; after that the server
    /// replies `ERR already-authenticated` to these (3.7, 4.1).
    pub fn signs_in(&self) -> bool {
        matches!(
            self,
            Command::Guest { .. } | Command::Auth { .. } | Command::Register { .. }
        )
    }

    /// Whether a guest may use this command (the "Guests" column of Section
    /// 12). MSG is allowed to rooms only. The sign-in commands
    /// ([`signs_in`](Self::signs_in)) give `false`, since a guest has
    /// already signed in. Permissions within a room (6.3) are checked
    /// separately.
    pub fn allowed_for_guests(&self) -> bool {
        match self {
            Command::Msg { conv, .. } => conv.is_room(),
            Command::Info { .. }
            | Command::Delete { .. }
            | Command::List
            | Command::Join { .. }
            | Command::Part { .. }
            | Command::Roles { .. }
            | Command::Sync
            | Command::History { .. }
            | Command::Related { .. }
            | Command::Typing { .. }
            | Command::Name { .. }
            | Command::Members { .. }
            | Command::Whois { .. }
            | Command::Report { .. }
            | Command::Ping { .. }
            | Command::Pong { .. }
            | Command::Quit { .. } => true,
            Command::Guest { .. }
            | Command::Auth { .. }
            | Command::Register { .. }
            | Command::Key(_)
            | Command::Unregister { .. }
            | Command::Upload { .. }
            | Command::Block { .. }
            | Command::Unblock { .. }
            | Command::Blocks
            | Command::Reports { .. }
            | Command::Resolve { .. }
            | Command::Set { .. }
            | Command::Role { .. }
            | Command::Invite { .. }
            | Command::Kick { .. }
            | Command::Ban { .. }
            | Command::Unban { .. }
            | Command::Bans { .. }
            | Command::Read { .. }
            | Command::Push(_)
            | Command::Admin(_) => false,
        }
    }

    /// Whether the server answers this command with a final `OK` or `ERR`
    /// (3.6). Every command does, except PONG.
    pub fn gets_response(&self) -> bool {
        !matches!(self, Command::Pong { .. })
    }
}

impl KeyCommand {
    /// The subcommand word, in upper case (4.7).
    pub fn word(&self) -> &'static str {
        match self {
            KeyCommand::List => "LIST",
            KeyCommand::Add { .. } => "ADD",
            KeyCommand::Del { .. } => "DEL",
        }
    }
}

impl PushCommand {
    /// The subcommand word, in upper case (9.1).
    pub fn word(&self) -> &'static str {
        match self {
            PushCommand::Add { .. } => "ADD",
            PushCommand::Del { .. } => "DEL",
            PushCommand::List => "LIST",
        }
    }
}

impl AdminCommand {
    /// The subcommand word, in upper case (Section 10).
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
            AdminCommand::Rooms => "ROOMS",
            AdminCommand::Drop { .. } => "DROP",
            AdminCommand::Purge { .. } => "PURGE",
            AdminCommand::Reports => "REPORTS",
            AdminCommand::Keys { .. } => "KEYS",
            AdminCommand::AddKey { .. } => "ADDKEY",
            AdminCommand::DelKey { .. } => "DELKEY",
            AdminCommand::Unregister { .. } => "UNREGISTER",
            AdminCommand::Set(_) => "SET",
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers

/// Reads the next token as a `T`.
fn tok<T: FromStr<Err = ParseError>>(p: &mut Params<'_>) -> Result<T, ParseError> {
    p.token()?.parse()
}

/// Reads the next token as a `T` and checks that nothing follows.
fn last<T: FromStr<Err = ParseError>>(mut p: Params<'_>) -> Result<T, ParseError> {
    let value = tok(&mut p)?;
    p.end()?;
    Ok(value)
}

/// Text that may be empty, with a length limit in bytes (escaped, 3.4).
fn text_max(p: Params<'_>, max: usize) -> Result<String, ParseError> {
    let text = p.text();
    if text.len() > max {
        return Err(ParseError::TooLong);
    }
    Ok(text.to_owned())
}

/// Text that must not be empty (`<name...>` in a syntax line, 3.3).
fn required_text(p: Params<'_>, what: &'static str) -> Result<String, ParseError> {
    match p.text() {
        text if crate::text::is_blank(text) => Err(ParseError::BadSyntax(what)),
        text => Ok(text.to_owned()),
    }
}

/// Reads options, rejecting any not in `known` (3.3).
fn options(p: Params<'_>, known: &[&str]) -> Result<Options, ParseError> {
    let options = p.options()?;
    options.reject_unknown(known)?;
    Ok(options)
}

/// `after=`: a seq, or `0` (7.1, 7.2).
fn after_opt(options: &Options) -> Result<Option<u64>, ParseError> {
    options
        .get("after")
        .map(|v| Ok(Seq::parse_or_zero(v)?.map_or(0, Seq::get)))
        .transpose()
}

/// A positive integer option such as `limit=` or `hours=`.
fn positive_opt(options: &Options, key: &str) -> Result<Option<NonZeroU64>, ParseError> {
    options
        .get(key)
        .map(|v| NonZeroU64::new(parse_u64(v)?).ok_or(ParseError::BadSyntax("must be at least 1")))
        .transpose()
}

/// Reads a tag that must have a value, if present.
fn tag_value<T: FromStr<Err = ParseError>>(
    tags: &Tags,
    key: &str,
    missing: &'static str,
) -> Result<Option<T>, ParseError> {
    match tags.entry(key) {
        None => Ok(None),
        Some(None) => Err(ParseError::BadSyntax(missing)),
        Some(Some(value)) => value.parse().map(Some),
    }
}

// ---------------------------------------------------------------------------
// Parsing (one arm per command, in the order of Section 12)

impl Command {
    /// Parses the command of a line, ignoring its `ref` (Section 12). Use
    /// [`Request::parse`] to keep the `ref`.
    pub fn parse(line: &Line) -> Result<Command, ParseError> {
        let mut p = line.params();
        let verb = line.verb_upper();
        Ok(match &*verb {
            // 8.5, 6.2
            "INFO" => {
                let room = p.opt_token()?.map(str::parse).transpose()?;
                p.end()?;
                Command::Info { room }
            }
            // 4.2
            "GUEST" => Command::Guest { name: last(p)? },
            // 4.5
            "AUTH" => {
                let identity = tok(&mut p)?;
                let signature = last(p)?;
                Command::Auth {
                    identity,
                    signature,
                }
            }
            // 4.6
            "REGISTER" => {
                let name = tok(&mut p)?;
                let key = tok(&mut p)?;
                let signature = last(p)?;
                Command::Register {
                    name,
                    key,
                    signature,
                }
            }
            // 4.7
            "KEY" => Command::Key(KeyCommand::parse(p)?),
            // 4.8
            "UNREGISTER" => {
                let uid = tok(&mut p)?;
                let options = options(p, &["purge"])?;
                let purge = options.get("purge").map(parse_yes_no).transpose()?;
                Command::Unregister {
                    uid,
                    purge: purge.unwrap_or(false),
                }
            }
            // 5.3
            "MSG" => parse_msg(line.tags(), p)?,
            // 5.4
            "DELETE" => {
                let conv = tok(&mut p)?;
                let seq = last(p)?;
                Command::Delete { conv, seq }
            }
            // 6.1
            "LIST" => {
                p.end()?;
                Command::List
            }
            "JOIN" => Command::Join { room: last(p)? },
            "PART" => {
                let room = tok(&mut p)?;
                Command::Part {
                    room,
                    reason: p.text().to_owned(),
                }
            }
            // 6.2
            "SET" => {
                let room = tok(&mut p)?;
                let key = p.token()?;
                let setting = RoomSetting::parse(key, p.text())?;
                Command::Set { room, setting }
            }
            // 6.3
            "ROLE" => {
                let room = tok(&mut p)?;
                let uid = tok(&mut p)?;
                let role = last(p)?;
                Command::Role { room, uid, role }
            }
            "ROLES" => Command::Roles { room: last(p)? },
            // 6.4
            "INVITE" => {
                let room = tok(&mut p)?;
                let uid = last(p)?;
                Command::Invite { room, uid }
            }
            "KICK" => {
                let room = tok(&mut p)?;
                let uid = tok(&mut p)?;
                Command::Kick {
                    room,
                    uid,
                    reason: p.text().to_owned(),
                }
            }
            "BAN" => {
                let room = tok(&mut p)?;
                let uid = tok(&mut p)?;
                Command::Ban {
                    room,
                    uid,
                    reason: p.text().to_owned(),
                }
            }
            "UNBAN" => {
                let room = tok(&mut p)?;
                let uid = last(p)?;
                Command::Unban { room, uid }
            }
            "BANS" => Command::Bans { room: last(p)? },
            // 7.1
            "SYNC" => {
                p.end()?;
                Command::Sync
            }
            // 7.2
            "HISTORY" => {
                let conv = tok(&mut p)?;
                let options = options(p, &["after", "before", "limit"])?;
                Command::History {
                    conv,
                    after: after_opt(&options)?,
                    before: options.get("before").map(str::parse).transpose()?,
                    limit: positive_opt(&options, "limit")?,
                }
            }
            // 7.3
            "RELATED" => {
                let conv = tok(&mut p)?;
                let first = tok(&mut p)?;
                let last_seq = tok(&mut p)?;
                let options = options(p, &["after", "limit"])?;
                Command::Related {
                    conv,
                    first,
                    last: last_seq,
                    after: after_opt(&options)?,
                    limit: positive_opt(&options, "limit")?,
                }
            }
            // 7.4
            "READ" => {
                let conv = tok(&mut p)?;
                let seq = last(p)?;
                Command::Read { conv, seq }
            }
            // 8.1
            "TYPING" => Command::Typing { conv: last(p)? },
            // 8.2
            "NAME" => Command::Name {
                display_name: text_max(p, MAX_DISPLAY_NAME)?,
            },
            // 8.3
            "MEMBERS" => Command::Members { room: last(p)? },
            "WHOIS" => Command::Whois { uid: last(p)? },
            // 5.6
            "UPLOAD" => {
                let size = parse_u64(p.token()?)?;
                let media_type = tok(&mut p)?;
                let name = required_text(p, "UPLOAD needs a file name")?;
                Command::Upload {
                    size,
                    media_type,
                    name,
                }
            }
            // 5.7
            "BLOCK" => Command::Block { target: last(p)? },
            "UNBLOCK" => Command::Unblock { target: last(p)? },
            "BLOCKS" => {
                p.end()?;
                Command::Blocks
            }
            // 5.8
            "REPORT" => {
                let conv = tok(&mut p)?;
                let seq = tok(&mut p)?;
                Command::Report {
                    conv,
                    seq,
                    reason: text_max(p, MAX_REPORT_REASON)?,
                }
            }
            "REPORTS" => Command::Reports { room: last(p)? },
            "RESOLVE" => Command::Resolve { id: last(p)? },
            // 9.1
            "PUSH" => Command::Push(PushCommand::parse(p)?),
            // 10
            "ADMIN" => Command::Admin(AdminCommand::parse(p)?),
            // 11
            "PING" => {
                let token = p.opt_token()?.map(str::to_owned);
                p.end()?;
                Command::Ping { token }
            }
            "PONG" => {
                let token = p.token()?.to_owned();
                p.end()?;
                Command::Pong { token }
            }
            "QUIT" => Command::Quit {
                message: p.text().to_owned(),
            },
            _ => return Err(ParseError::UnknownVerb(verb.into_owned())),
        })
    }
}

/// `MSG <conv> <text...>` and its tags (5.3, 5.6, 7.6).
fn parse_msg(tags: &Tags, mut p: Params<'_>) -> Result<Command, ParseError> {
    let conv = tok(&mut p)?;
    let text = required_text(p, "MSG text must not be empty")?;

    let mut relation = None;
    for key in Relation::KEYS {
        if let Some(value) = tags.entry(key) {
            if relation.is_some() {
                return Err(ParseError::BadSyntax(
                    "a message has at most one of reply, edit and react",
                ));
            }
            relation = Relation::from_tag(key, value)?;
        }
    }
    let file: Option<FileUrl> = tag_value(tags, "file", "file needs a URL")?;
    let cid = tag_value(tags, "cid", "cid needs a value")?;

    if file.is_some() && matches!(relation, Some(Relation::Edit(_) | Relation::React(_))) {
        return Err(ParseError::BadSyntax("file cannot go with edit or react"));
    }
    if matches!(relation, Some(Relation::React(_))) && text.len() > MAX_REACTION {
        return Err(ParseError::TooLong);
    }
    Ok(Command::Msg {
        conv,
        text,
        relation,
        file,
        cid,
    })
}

/// Reads a subcommand word, upper case.
fn subcommand(p: &mut Params<'_>) -> Result<String, ParseError> {
    Ok(p.token()?.to_ascii_uppercase())
}

const UNKNOWN_SUBCOMMAND: ParseError = ParseError::BadSyntax("unknown subcommand");

impl KeyCommand {
    /// Parses the parameters after `KEY` (4.7).
    fn parse(mut p: Params<'_>) -> Result<KeyCommand, ParseError> {
        Ok(match subcommand(&mut p)?.as_str() {
            "LIST" => {
                p.end()?;
                KeyCommand::List
            }
            "ADD" => {
                let key = tok(&mut p)?;
                KeyCommand::Add {
                    key,
                    label: p.text().to_owned(),
                }
            }
            "DEL" => KeyCommand::Del { key: last(p)? },
            _ => return Err(UNKNOWN_SUBCOMMAND),
        })
    }
}

impl PushCommand {
    /// Parses the parameters after `PUSH` (9.1).
    fn parse(mut p: Params<'_>) -> Result<PushCommand, ParseError> {
        Ok(match subcommand(&mut p)?.as_str() {
            "ADD" => {
                let url = tok(&mut p)?;
                let tag = last(p)?;
                PushCommand::Add { url, tag }
            }
            "DEL" => PushCommand::Del { url: last(p)? },
            "LIST" => {
                p.end()?;
                PushCommand::List
            }
            _ => return Err(UNKNOWN_SUBCOMMAND),
        })
    }
}

impl AdminCommand {
    /// Parses the parameters after `ADMIN` (Section 10).
    fn parse(mut p: Params<'_>) -> Result<AdminCommand, ParseError> {
        Ok(match subcommand(&mut p)?.as_str() {
            // 10.1
            "OPS" => {
                p.end()?;
                AdminCommand::Ops
            }
            "OP" => AdminCommand::Op { uid: last(p)? },
            "DEOP" => AdminCommand::Deop { uid: last(p)? },
            // 10.2
            "BAN" => {
                let target = tok(&mut p)?;
                AdminCommand::Ban {
                    target,
                    reason: p.text().to_owned(),
                }
            }
            "UNBAN" => AdminCommand::Unban { target: last(p)? },
            "BANS" => {
                p.end()?;
                AdminCommand::Bans
            }
            // 10.3
            "WHO" => {
                p.end()?;
                AdminCommand::Who
            }
            "DISCONNECT" => {
                let uid = tok(&mut p)?;
                AdminCommand::Disconnect {
                    uid,
                    reason: p.text().to_owned(),
                }
            }
            "NOTICE" => AdminCommand::Notice {
                message: required_text(p, "ADMIN NOTICE needs a message")?,
            },
            // 10.4
            "ROOMS" => {
                p.end()?;
                AdminCommand::Rooms
            }
            "DROP" => {
                let room = tok(&mut p)?;
                AdminCommand::Drop {
                    room,
                    reason: p.text().to_owned(),
                }
            }
            "PURGE" => {
                let uid = tok(&mut p)?;
                let options = options(p, &["hours"])?;
                AdminCommand::Purge {
                    uid,
                    hours: positive_opt(&options, "hours")?,
                }
            }
            "REPORTS" => {
                p.end()?;
                AdminCommand::Reports
            }
            // 10.5
            "KEYS" => AdminCommand::Keys { uid: last(p)? },
            "ADDKEY" => {
                let uid = tok(&mut p)?;
                let key = tok(&mut p)?;
                AdminCommand::AddKey {
                    uid,
                    key,
                    label: p.text().to_owned(),
                }
            }
            "DELKEY" => {
                let uid = tok(&mut p)?;
                let key = last(p)?;
                AdminCommand::DelKey { uid, key }
            }
            "UNREGISTER" => AdminCommand::Unregister { uid: last(p)? },
            // 10.6
            "SET" => {
                let key = p.token()?;
                AdminCommand::Set(ServerSetting::parse(key, p.text())?)
            }
            _ => return Err(UNKNOWN_SUBCOMMAND),
        })
    }
}

// ---------------------------------------------------------------------------
// Serialising

impl Command {
    /// Adds this command's tags and parameters to `b`, whose verb is
    /// already [`verb`](Self::verb).
    fn write(&self, b: &mut LineBuilder) {
        match self {
            Command::Info { room } => {
                if let Some(room) = room {
                    b.token(room);
                }
            }
            Command::Guest { name } => {
                b.token(name);
            }
            Command::Auth {
                identity,
                signature,
            } => {
                b.token(identity).token(signature);
            }
            Command::Register {
                name,
                key,
                signature,
            } => {
                b.token(name).token(key).token(signature);
            }
            Command::Key(sub) => {
                b.token(sub.word());
                match sub {
                    KeyCommand::List => {}
                    KeyCommand::Add { key, label } => {
                        b.token(key).text(label);
                    }
                    KeyCommand::Del { key } => {
                        b.token(key);
                    }
                }
            }
            Command::Unregister { uid, purge } => {
                b.token(uid);
                if *purge {
                    b.option("purge", "yes");
                }
            }
            Command::Msg {
                conv,
                text,
                relation,
                file,
                cid,
            } => {
                if let Some(relation) = relation {
                    b.tag(relation.key(), relation.seq());
                }
                if let Some(file) = file {
                    b.tag("file", file);
                }
                if let Some(cid) = cid {
                    b.tag("cid", cid);
                }
                b.token(conv).text(text);
            }
            Command::Delete { conv, seq } | Command::Read { conv, seq } => {
                b.token(conv).token(seq);
            }
            Command::Report { conv, seq, reason } => {
                b.token(conv).token(seq).text(reason);
            }
            Command::Upload {
                size,
                media_type,
                name,
            } => {
                b.token(size).token(media_type).text(name);
            }
            Command::Block { target } | Command::Unblock { target } => {
                b.token(target);
            }
            Command::Blocks | Command::List | Command::Sync => {}
            Command::Reports { room }
            | Command::Join { room }
            | Command::Roles { room }
            | Command::Bans { room }
            | Command::Members { room } => {
                b.token(room);
            }
            Command::Resolve { id } => {
                b.token(id);
            }
            Command::Part { room, reason } => {
                b.token(room).text(reason);
            }
            Command::Set { room, setting } => {
                b.token(room).token(setting.key()).text(&setting.value());
            }
            Command::Role { room, uid, role } => {
                b.token(room).token(uid).token(role);
            }
            Command::Invite { room, uid } | Command::Unban { room, uid } => {
                b.token(room).token(uid);
            }
            Command::Kick { room, uid, reason } | Command::Ban { room, uid, reason } => {
                b.token(room).token(uid).text(reason);
            }
            Command::History {
                conv,
                after,
                before,
                limit,
            } => {
                b.token(conv);
                write_after_limit(b, *after, *before, *limit);
            }
            Command::Related {
                conv,
                first,
                last,
                after,
                limit,
            } => {
                b.token(conv).token(first).token(last);
                write_after_limit(b, *after, None, *limit);
            }
            Command::Typing { conv } => {
                b.token(conv);
            }
            Command::Name { display_name } => {
                b.text(display_name);
            }
            Command::Whois { uid } => {
                b.token(uid);
            }
            Command::Push(sub) => {
                b.token(sub.word());
                match sub {
                    PushCommand::Add { url, tag } => {
                        b.token(url).token(tag);
                    }
                    PushCommand::Del { url } => {
                        b.token(url);
                    }
                    PushCommand::List => {}
                }
            }
            Command::Admin(sub) => {
                b.token(sub.word());
                sub.write(b);
            }
            Command::Ping { token } => {
                if let Some(token) = token {
                    b.token(token);
                }
            }
            Command::Pong { token } => {
                b.token(token);
            }
            Command::Quit { message } => {
                b.text(message);
            }
        }
    }
}

/// Writes `after=`, `before=` and `limit=` in that order (7.2, 7.3).
fn write_after_limit(
    b: &mut LineBuilder,
    after: Option<u64>,
    before: Option<Seq>,
    limit: Option<NonZeroU64>,
) {
    if let Some(after) = after {
        b.option("after", after);
    }
    if let Some(before) = before {
        b.option("before", before);
    }
    if let Some(limit) = limit {
        b.option("limit", limit);
    }
}

impl AdminCommand {
    /// Adds the parameters after the subcommand word.
    fn write(&self, b: &mut LineBuilder) {
        match self {
            AdminCommand::Ops
            | AdminCommand::Bans
            | AdminCommand::Who
            | AdminCommand::Rooms
            | AdminCommand::Reports => {}
            AdminCommand::Op { uid }
            | AdminCommand::Deop { uid }
            | AdminCommand::Keys { uid }
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
            AdminCommand::Drop { room, reason } => {
                b.token(room).text(reason);
            }
            AdminCommand::Purge { uid, hours } => {
                b.token(uid);
                if let Some(hours) = hours {
                    b.option("hours", hours);
                }
            }
            AdminCommand::AddKey { uid, key, label } => {
                b.token(uid).token(key).text(label);
            }
            AdminCommand::DelKey { uid, key } => {
                b.token(uid).token(key);
            }
            AdminCommand::Set(setting) => {
                b.token(setting.key()).text(&setting.value());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GuestAccess, MAX_FILE_URL, RoomRetention, ServerRetention};

    const KEY: &str = "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY=";
    const SIG: &str =
        "Hk+S5Vd7ciW57dRNS3AhcvZkYNLmj+kkgJUxOYvCrbEQSBk0UDdH+cSBXF6YvCSU85FRVPaURwsQdbV/SAK0CQ==";
    const URL: &str = "https://files.example.org/f/k3JxR8vN2qYd6hWaP0tZcE/cat.png";

    fn req(s: &str) -> Request {
        s.parse()
            .unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    fn cmd(s: &str) -> Command {
        req(s).command
    }

    fn err(s: &str) -> ParseError {
        match s.parse::<Request>() {
            Ok(r) => panic!("{s:?} should not parse, got {r:?}"),
            Err(e) => e,
        }
    }

    fn is_syntax(s: &str) {
        assert!(
            matches!(err(s), ParseError::BadSyntax(_)),
            "{s:?}: {:?}",
            err(s)
        );
    }

    fn is_too_long(s: &str) {
        assert_eq!(err(s), ParseError::TooLong, "{s:?}");
    }

    /// `s` parses, writes back as `canonical`, and that parses equal.
    fn canon(s: &str, canonical: &str) -> Request {
        let r = req(s);
        let line = r.to_line();
        assert_eq!(line.to_string(), canonical, "from {s:?}");
        assert_eq!(Request::parse(&line), Ok(r.clone()), "{canonical:?}");
        assert_eq!(r.validate(), Ok(()), "{canonical:?}");
        r
    }

    /// `s` is canonical: it round-trips unchanged.
    fn rt(s: &str) -> Request {
        canon(s, s)
    }

    fn room(s: &str) -> Room {
        s.parse().unwrap()
    }

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    fn seq(n: u64) -> Seq {
        Seq::new(n).unwrap()
    }

    fn nz(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).unwrap()
    }

    fn key() -> PublicKey {
        KEY.parse().unwrap()
    }

    // ---- requests, ref and verbs ----

    #[test]
    fn ref_tag() {
        let r = rt("@ref=7 SYNC");
        assert_eq!(r.ref_, Some("7".parse().unwrap()));
        assert_eq!(r.command, Command::Sync);
        assert_eq!(req("SYNC").ref_, None);
        is_syntax("@ref SYNC");
        let r64 = "r".repeat(64);
        rt(&format!("@ref={r64} SYNC"));
        is_too_long(&format!("@ref={r64}x SYNC"));
    }

    #[test]
    fn ref_of_reads_ref_from_bad_lines() {
        let line = Line::parse("@ref=9 JOIN").unwrap();
        assert!(Request::parse(&line).is_err());
        assert_eq!(Request::ref_of(&line), Some("9".parse().unwrap()));
        assert_eq!(Request::ref_of(&Line::parse("@ref JOIN").unwrap()), None);
        assert_eq!(Request::ref_of(&Line::parse("JOIN").unwrap()), None);
    }

    #[test]
    fn unknown_tags_are_ignored() {
        canon("@x-foo=1;ref=2;zzz SYNC", "@ref=2 SYNC");
        // MSG's tags mean nothing on other commands, even malformed ones.
        canon("@reply=1;edit=2;file=nope;cid=x JOIN #a", "JOIN #a");
    }

    #[test]
    fn unknown_verb() {
        assert_eq!(err("frob #a"), ParseError::UnknownVerb("FROB".into()));
        // Server-only lines are not client commands.
        assert_eq!(err("OK"), ParseError::UnknownVerb("OK".into()));
        assert_eq!(err("ROOM #a 1"), ParseError::UnknownVerb("ROOM".into()));
    }

    #[test]
    fn verbs_fold_and_write_upper_case() {
        let r = canon("msg #General hi", "MSG #general hi");
        assert_eq!(r.command.verb(), "MSG");
        canon("JoIn #A", "JOIN #a");
        canon("key list", "KEY LIST");
        canon("admin ops", "ADMIN OPS");
        canon("Push List", "PUSH LIST");
    }

    #[test]
    fn runs_of_spaces_are_accepted() {
        canon(
            "ROLE  #a   bob@example.net  mod ",
            "ROLE #a bob@example.net mod",
        );
        canon(
            "HISTORY #a  after=1   limit=2 ",
            "HISTORY #a after=1 limit=2",
        );
    }

    #[test]
    fn display_and_from() {
        let r: Request = Command::List.into();
        assert_eq!(r.to_string(), "LIST");
        assert_eq!(Request::new(Command::Sync).ref_, None);
    }

    // ---- tables ----

    #[test]
    fn before_sign_in() {
        for s in [
            "INFO",
            "GUEST sam",
            &format!("AUTH alice@example.org {SIG}"),
            &format!("REGISTER alice {KEY} {SIG}"),
            "PING",
            "PING x",
            "PONG x",
            "QUIT",
        ] {
            assert!(cmd(s).allowed_before_sign_in(), "{s}");
        }
        for s in [
            "INFO #a",
            "JOIN #a",
            "SYNC",
            "MSG #a hi",
            "LIST",
            "ADMIN OPS",
        ] {
            assert!(!cmd(s).allowed_before_sign_in(), "{s}");
        }
    }

    #[test]
    fn guests_and_sign_in() {
        assert!(cmd("GUEST sam").signs_in());
        assert!(!cmd("JOIN #a").signs_in());
        assert!(cmd("MSG #a hi").allowed_for_guests());
        assert!(!cmd("MSG bob@example.net hi").allowed_for_guests());
        assert!(cmd("HISTORY #a").allowed_for_guests());
        assert!(cmd("REPORT #a 1").allowed_for_guests());
        assert!(!cmd("READ #a 1").allowed_for_guests());
        assert!(!cmd("UPLOAD 1 a/b c").allowed_for_guests());
        assert!(!cmd("GUEST sam").allowed_for_guests());
        assert!(!cmd("ADMIN OPS").allowed_for_guests());
    }

    #[test]
    fn responses() {
        assert!(!cmd("PONG x").gets_response());
        assert!(cmd("PING x").gets_response());
    }

    // ---- 4. Identity and authentication ----

    #[test]
    fn info() {
        assert_eq!(rt("INFO").command, Command::Info { room: None });
        assert_eq!(
            canon("INFO #General", "INFO #general").command,
            Command::Info {
                room: Some(room("#general"))
            }
        );
        is_syntax("INFO general");
        is_syntax("INFO #a #b");
    }

    #[test]
    fn guest() {
        let c = canon("GUEST Sam", "GUEST sam").command;
        assert_eq!(
            c,
            Command::Guest {
                name: "sam".parse().unwrap()
            }
        );
        is_syntax("GUEST");
        is_syntax("GUEST sam extra");
        is_syntax("GUEST ~sam");
        is_too_long(&format!("GUEST {}", "a".repeat(33)));
    }

    #[test]
    fn auth() {
        let c = canon(
            &format!("auth Alice@Example.org {SIG}"),
            &format!("AUTH alice@example.org {SIG}"),
        )
        .command;
        let Command::Auth {
            identity,
            signature,
        } = c
        else {
            panic!()
        };
        assert_eq!(identity.as_str(), "alice@example.org");
        assert_eq!(signature.to_string(), SIG);
        is_syntax(&format!("AUTH ~sam {SIG}"));
        is_syntax("AUTH alice@example.org");
        is_syntax("AUTH alice@example.org abc");
        is_syntax(&format!("AUTH alice@example.org {SIG} x"));
    }

    #[test]
    fn register() {
        let c = rt(&format!("REGISTER alice {KEY} {SIG}")).command;
        assert!(matches!(c, Command::Register { ref name, .. } if name.as_str() == "alice"));
        is_syntax(&format!("REGISTER alice {KEY}"));
        is_syntax(&format!("REGISTER alice@example.org {KEY} {SIG}"));
        is_syntax(&format!("REGISTER alice {SIG} {KEY}"));
        is_syntax(&format!("REGISTER alice {KEY} {SIG} x"));
    }

    #[test]
    fn key_commands() {
        assert_eq!(rt("KEY LIST").command, Command::Key(KeyCommand::List));
        assert_eq!(
            rt(&format!("KEY ADD {KEY} my laptop")).command,
            Command::Key(KeyCommand::Add {
                key: key(),
                label: "my laptop".into()
            })
        );
        assert_eq!(
            canon(&format!("key add {KEY} "), &format!("KEY ADD {KEY}")).command,
            Command::Key(KeyCommand::Add {
                key: key(),
                label: String::new()
            })
        );
        assert_eq!(
            canon(&format!("key Del {KEY}"), &format!("KEY DEL {KEY}")).command,
            Command::Key(KeyCommand::Del { key: key() })
        );
        is_syntax("KEY");
        is_syntax("KEY FOO");
        is_syntax("KEY LIST x");
        is_syntax("KEY ADD");
        is_syntax("KEY DEL");
        is_syntax(&format!("KEY DEL {KEY} x"));
    }

    #[test]
    fn unregister() {
        assert_eq!(
            rt("UNREGISTER alice@example.org").command,
            Command::Unregister {
                uid: uid("alice@example.org"),
                purge: false
            }
        );
        assert_eq!(
            canon(
                "UNREGISTER alice@example.org PURGE=YES",
                "UNREGISTER alice@example.org purge=yes"
            )
            .command,
            Command::Unregister {
                uid: uid("alice@example.org"),
                purge: true
            }
        );
        canon(
            "UNREGISTER alice@example.org purge=no",
            "UNREGISTER alice@example.org",
        );
        // A guest uid parses; the server answers forbidden (4.8).
        rt("UNREGISTER ~sam");
        is_syntax("UNREGISTER");
        is_syntax("UNREGISTER alice@example.org purge=maybe");
        is_syntax("UNREGISTER alice@example.org force=yes");
        is_syntax("UNREGISTER alice@example.org purge=yes purge=yes");
        is_syntax("UNREGISTER alice@example.org yes");
    }

    // ---- 5. Conversations ----

    #[test]
    fn msg() {
        let c = canon("msg #General hi  there ", "MSG #general hi  there ").command;
        assert_eq!(
            c,
            Command::Msg {
                conv: Conv::Room(room("#general")),
                text: "hi  there ".into(),
                relation: None,
                file: None,
                cid: None
            }
        );
        let c = rt("MSG bob@example.net one\\ntwo").command;
        assert!(matches!(c, Command::Msg { ref text, .. } if text == "one\\ntwo"));
        // Text keeps leading spaces after the one separator.
        assert!(matches!(cmd("MSG #a  x"), Command::Msg { ref text, .. } if text == " x"));
        // Text of only spaces and TABs counts as empty (5.3).
        is_syntax("MSG #a  ");
        is_syntax("MSG #a  \t ");
        is_syntax("MSG #a");
        is_syntax("MSG #a ");
        is_syntax("MSG");
        is_syntax("MSG general hi");
    }

    #[test]
    fn msg_relations() {
        for (tag, rel) in [
            ("reply", Relation::Reply(seq(5))),
            ("edit", Relation::Edit(seq(5))),
            ("react", Relation::React(seq(5))),
        ] {
            let c = rt(&format!("@{tag}=5 MSG #a x")).command;
            assert!(matches!(c, Command::Msg { relation: Some(r), .. } if r == rel));
        }
        is_syntax("@reply=1;edit=2 MSG #a x");
        is_syntax("@react=1;reply=2 MSG #a x");
        is_syntax("@reply MSG #a x");
        is_syntax("@reply=0 MSG #a x");
        is_syntax("@edit=abc MSG #a x");
    }

    #[test]
    fn msg_reaction_limit() {
        let ok = "x".repeat(MAX_REACTION);
        rt(&format!("@react=1 MSG #a {ok}"));
        is_too_long(&format!("@react=1 MSG #a {ok}x"));
        // The limit is on the escaped form, in bytes: 16 four-byte emoji fit.
        rt(&format!("@react=1 MSG #a {}", "👋".repeat(16)));
        is_too_long(&format!("@react=1 MSG #a {}\\n", "👋".repeat(16)));
        // Only reactions have the limit.
        rt(&format!("@reply=1 MSG #a {ok}x"));
    }

    #[test]
    fn msg_file() {
        let c = rt(&format!("@file={URL} MSG #a look")).command;
        assert!(matches!(c, Command::Msg { file: Some(ref f), .. } if f.as_str() == URL));
        rt(&format!("@reply=3;file={URL} MSG #a look"));
        canon(
            &format!("@file={URL};reply=3 MSG #a look"),
            &format!("@reply=3;file={URL} MSG #a look"),
        );
        is_syntax(&format!("@edit=3;file={URL} MSG #a look"));
        is_syntax(&format!("@react=3;file={URL} MSG #a look"));
        is_syntax("@file MSG #a look");
        is_syntax("@file=http://x.example/a MSG #a look");
        is_syntax("@file=https:// MSG #a look");
        is_syntax(&format!("@file={URL} MSG #a"));
        canon(
            "@file=HTTPS://x.example/a MSG #a x",
            "@file=HTTPS://x.example/a MSG #a x",
        );
        let base = "https://x.example/";
        let fit = format!("{base}{}", "a".repeat(MAX_FILE_URL - base.len()));
        rt(&format!("@file={fit} MSG #a x"));
        is_too_long(&format!("@file={fit}a MSG #a x"));
    }

    #[test]
    fn msg_cid_and_tag_order() {
        let cid = "0123456789abcdef";
        let c = rt(&format!("@cid={cid} MSG #a x")).command;
        assert!(matches!(c, Command::Msg { cid: Some(ref c), .. } if c.as_str() == cid));
        canon(
            &format!("@cid={cid};file={URL};zz;reply=9;ref=r1 MSG #a x"),
            &format!("@ref=r1;reply=9;file={URL};cid={cid} MSG #a x"),
        );
        is_syntax("@cid MSG #a x");
        is_syntax("@cid=short MSG #a x");
        rt(&format!("@cid={} MSG #a x", "c".repeat(64)));
        is_too_long(&format!("@cid={} MSG #a x", "c".repeat(65)));
    }

    #[test]
    fn delete() {
        assert_eq!(
            canon("delete #A 12", "DELETE #a 12").command,
            Command::Delete {
                conv: Conv::Room(room("#a")),
                seq: seq(12)
            }
        );
        is_syntax("DELETE #a");
        is_syntax("DELETE #a 0");
        is_syntax("DELETE #a 012");
        is_syntax("DELETE #a 1 2");
    }

    #[test]
    fn upload() {
        let c = canon(
            "upload 48213 Image/PNG cat.png",
            "UPLOAD 48213 image/png cat.png",
        )
        .command;
        assert_eq!(
            c,
            Command::Upload {
                size: 48213,
                media_type: "image/png".parse().unwrap(),
                name: "cat.png".into()
            }
        );
        let Command::Upload { media_type, .. } = c else {
            panic!()
        };
        assert_eq!(media_type.top_level(), "image");
        assert_eq!(media_type.subtype(), "png");
        rt("UPLOAD 0 application/vnd.foo+json my file.json");
        is_syntax("UPLOAD 10 image/png");
        is_syntax("UPLOAD 10 image/png ");
        is_syntax("UPLOAD x image/png a");
        is_syntax("UPLOAD 010 image/png a");
        is_syntax("UPLOAD 10 image a");
        is_syntax("UPLOAD 10 image/ a");
        is_syntax("UPLOAD 10 /png a");
        is_syntax("UPLOAD 10 text/plain;charset=utf-8 a");
        is_syntax("UPLOAD 10 a/b/c a");
        let part = "a".repeat(MAX_MEDIA_TYPE_PART);
        rt(&format!("UPLOAD 1 {part}/{part} a"));
        is_too_long(&format!("UPLOAD 1 {part}a/b a"));
    }

    #[test]
    fn blocks() {
        assert_eq!(
            rt("BLOCK *@example.net").command,
            Command::Block {
                target: "*@example.net".parse().unwrap()
            }
        );
        canon("unblock Spam@Example.net", "UNBLOCK spam@example.net");
        rt("BLOCKS");
        is_syntax("BLOCK");
        is_syntax("BLOCK ~sam");
        is_syntax("BLOCK a@example.net b@example.net");
        is_syntax("BLOCKS x");
    }

    #[test]
    fn report() {
        assert_eq!(
            rt("REPORT #a 8816 spam").command,
            Command::Report {
                conv: Conv::Room(room("#a")),
                seq: seq(8816),
                reason: "spam".into()
            }
        );
        canon("REPORT #a 8816 ", "REPORT #a 8816");
        assert_eq!(cmd("REPORT #a 8816"), cmd("REPORT #a 8816 "));
        let ok = "r".repeat(MAX_REPORT_REASON);
        rt(&format!("REPORT #a 1 {ok}"));
        is_too_long(&format!("REPORT #a 1 {ok}r"));
        is_syntax("REPORT #a");
        is_syntax("REPORT #a x");
    }

    #[test]
    fn reports_and_resolve() {
        rt("REPORTS #a");
        assert_eq!(
            canon("RESOLVE P4x8n2", "RESOLVE p4x8n2").command,
            Command::Resolve {
                id: "p4x8n2".parse().unwrap()
            }
        );
        is_syntax("REPORTS");
        is_syntax("REPORTS #a #b");
        is_syntax("RESOLVE");
        is_syntax("RESOLVE a.b");
    }

    // ---- 6. Rooms ----

    #[test]
    fn list_join_part() {
        rt("LIST");
        is_syntax("LIST x");
        assert_eq!(
            rt("JOIN #general").command,
            Command::Join {
                room: room("#general")
            }
        );
        is_syntax("JOIN");
        is_syntax("JOIN #a #b");
        is_syntax("JOIN general");
        is_too_long(&format!("JOIN #{}", "a".repeat(65)));
        assert_eq!(
            rt("PART #a bye now").command,
            Command::Part {
                room: room("#a"),
                reason: "bye now".into()
            }
        );
        assert_eq!(cmd("PART #a"), cmd("PART #a "));
        canon("PART #a ", "PART #a");
        is_syntax("PART");
    }

    #[test]
    fn set() {
        assert_eq!(
            rt("SET #a topic General chat. Be kind.").command,
            Command::Set {
                room: room("#a"),
                setting: RoomSetting::Topic("General chat. Be kind.".into())
            }
        );
        assert_eq!(
            canon("SET #a topic", "SET #a topic").command,
            Command::Set {
                room: room("#a"),
                setting: RoomSetting::Topic(String::new())
            }
        );
        canon("SET #a topic ", "SET #a topic");
        canon("set #A Public YES", "SET #a public yes");
        assert!(matches!(
            cmd("SET #a guests read"),
            Command::Set {
                setting: RoomSetting::Guests(GuestAccess::Read),
                ..
            }
        ));
        assert!(matches!(
            cmd("SET #a retention server"),
            Command::Set {
                setting: RoomSetting::Retention(RoomRetention::Server),
                ..
            }
        ));
        rt("SET #a retention 30");
        // Unknown keys are kept, for ERR not-supported.
        let c = canon("SET #a Color dark blue", "SET #a color dark blue").command;
        assert!(matches!(
            c,
            Command::Set { setting: RoomSetting::Other { ref key, ref value }, .. }
                if key == "color" && value == "dark blue"
        ));
        is_syntax("SET #a public maybe");
        is_syntax("SET #a public");
        is_syntax("SET #a retention 0");
        is_syntax("SET #a");
        is_syntax("SET");
        let ok = "t".repeat(512);
        rt(&format!("SET #a topic {ok}"));
        is_too_long(&format!("SET #a topic {ok}t"));
    }

    #[test]
    fn role_and_roles() {
        assert_eq!(
            canon("ROLE #a Bob@Example.net MOD", "ROLE #a bob@example.net mod").command,
            Command::Role {
                room: room("#a"),
                uid: uid("bob@example.net"),
                role: Role::Mod
            }
        );
        is_syntax("ROLE #a bob@example.net");
        is_syntax("ROLE #a bob@example.net none");
        is_syntax("ROLE #a bob@example.net mod x");
        rt("ROLES #a");
        is_syntax("ROLES");
    }

    #[test]
    fn moderation() {
        rt("INVITE #a bob@example.net");
        is_syntax("INVITE #a");
        is_syntax("INVITE #a bob@example.net x");
        assert_eq!(
            rt("KICK #a ~sam be nice").command,
            Command::Kick {
                room: room("#a"),
                uid: uid("~sam"),
                reason: "be nice".into()
            }
        );
        canon("KICK #a ~sam ", "KICK #a ~sam");
        is_syntax("KICK #a");
        assert_eq!(
            rt("BAN #a ~sam").command,
            Command::Ban {
                room: room("#a"),
                uid: uid("~sam"),
                reason: String::new()
            }
        );
        rt("BAN #a ~sam spam");
        is_syntax("BAN #a");
        rt("UNBAN #a ~sam");
        is_syntax("UNBAN #a ~sam x");
        rt("BANS #a");
        is_syntax("BANS");
    }

    // ---- 7. History and sync ----

    #[test]
    fn sync() {
        rt("SYNC");
        is_syntax("SYNC x");
    }

    #[test]
    fn history() {
        assert_eq!(
            rt("HISTORY #general before=8812 limit=2").command,
            Command::History {
                conv: Conv::Room(room("#general")),
                after: None,
                before: Some(seq(8812)),
                limit: Some(nz(2))
            }
        );
        assert_eq!(
            rt("HISTORY #a").command,
            Command::History {
                conv: Conv::Room(room("#a")),
                after: None,
                before: None,
                limit: None
            }
        );
        // after=0: a client with nothing stored (7.1).
        assert!(matches!(
            rt("HISTORY bob@example.net after=0").command,
            Command::History { after: Some(0), .. }
        ));
        // Options in any order, keys folded; written in spec order.
        canon(
            "HISTORY #a LIMIT=5 before=9 After=3",
            "HISTORY #a after=3 before=9 limit=5",
        );
        rt(&format!("HISTORY #a after={}", Seq::MAX));
        is_syntax(&format!("HISTORY #a after={}", Seq::MAX.get() + 1));
        is_syntax("HISTORY #a after=00");
        is_syntax("HISTORY #a after=01");
        is_syntax("HISTORY #a after=-1");
        is_syntax("HISTORY #a before=0");
        is_syntax("HISTORY #a limit=0");
        is_syntax("HISTORY #a limit=x");
        is_syntax("HISTORY #a after=1 after=2");
        is_syntax("HISTORY #a around=5");
        is_syntax("HISTORY #a 5");
        is_syntax("HISTORY");
    }

    #[test]
    fn related() {
        assert_eq!(
            rt("RELATED #general 3999 4000").command,
            Command::Related {
                conv: Conv::Room(room("#general")),
                first: seq(3999),
                last: seq(4000),
                after: None,
                limit: None
            }
        );
        canon(
            "RELATED #a 1 9 limit=3 after=0",
            "RELATED #a 1 9 after=0 limit=3",
        );
        // An empty range parses.
        rt("RELATED #a 9 1");
        is_syntax("RELATED #a 1");
        is_syntax("RELATED #a 1 2 3");
        is_syntax("RELATED #a 1 2 before=3");
        is_syntax("RELATED #a 1 2 limit=0");
    }

    #[test]
    fn read() {
        rt("READ #a 5");
        rt("READ alice@example.org 5");
        is_syntax("READ #a");
        is_syntax("READ #a 0");
        is_syntax("READ #a 5 6");
    }

    // ---- 8. Other lines ----

    #[test]
    fn typing_members_whois() {
        rt("TYPING #a");
        rt("TYPING bob@example.net");
        is_syntax("TYPING");
        is_syntax("TYPING #a x");
        rt("MEMBERS #a");
        is_syntax("MEMBERS bob@example.net");
        canon("WHOIS ~Sam", "WHOIS ~sam");
        is_syntax("WHOIS");
        is_syntax("WHOIS sam");
    }

    #[test]
    fn name() {
        assert_eq!(
            rt("NAME Alice Martin").command,
            Command::Name {
                display_name: "Alice Martin".into()
            }
        );
        rt("NAME عائشة");
        assert_eq!(
            rt("NAME").command,
            Command::Name {
                display_name: String::new()
            }
        );
        canon("NAME ", "NAME");
        // Leading spaces belong to the text.
        rt("NAME  x");
        let ok = "n".repeat(MAX_DISPLAY_NAME);
        rt(&format!("NAME {ok}"));
        is_too_long(&format!("NAME {ok}n"));
    }

    // ---- 9. Push ----

    #[test]
    fn push() {
        let url = "https://push.app.example/n/3f9c";
        assert_eq!(
            canon(
                &format!("push add {url} Tag1"),
                &format!("PUSH ADD {url} Tag1")
            )
            .command,
            Command::Push(PushCommand::Add {
                url: url.parse().unwrap(),
                tag: "Tag1".parse().unwrap()
            })
        );
        rt(&format!("PUSH DEL {url}"));
        rt("PUSH LIST");
        rt(&format!("PUSH ADD {url} {}", "t".repeat(64)));
        is_too_long(&format!("PUSH ADD {url} {}", "t".repeat(65)));
        is_syntax(&format!("PUSH ADD {url}"));
        is_syntax(&format!("PUSH ADD {url} a b"));
        is_syntax("PUSH ADD http://push.example/x t");
        is_syntax("PUSH DEL");
        is_syntax("PUSH LIST x");
        is_syntax("PUSH");
        is_syntax("PUSH FOO");
    }

    // ---- 10. Administration ----

    #[test]
    fn admin_ops() {
        rt("ADMIN OPS");
        assert_eq!(
            canon("admin op Alice@example.org", "ADMIN OP alice@example.org").command,
            Command::Admin(AdminCommand::Op {
                uid: uid("alice@example.org")
            })
        );
        rt("ADMIN DEOP alice@example.org");
        is_syntax("ADMIN OPS x");
        is_syntax("ADMIN OP");
        is_syntax("ADMIN DEOP a@example.org b@example.org");
        is_syntax("ADMIN");
        is_syntax("ADMIN FOO");
    }

    #[test]
    fn admin_bans() {
        for target in [
            "spam@example.net",
            "*@example.net",
            "~sam",
            "203.0.113.7",
            "2001:db8::/32",
        ] {
            rt(&format!("ADMIN BAN {target} go away"));
            rt(&format!("ADMIN BAN {target}"));
            rt(&format!("ADMIN UNBAN {target}"));
        }
        assert_eq!(
            cmd("ADMIN BAN ~sam "),
            Command::Admin(AdminCommand::Ban {
                target: "~sam".parse().unwrap(),
                reason: String::new()
            })
        );
        rt("ADMIN BANS");
        is_syntax("ADMIN BAN");
        is_syntax("ADMIN BAN sam");
        is_syntax("ADMIN UNBAN ~sam x");
        is_syntax("ADMIN BANS x");
    }

    #[test]
    fn admin_connections() {
        rt("ADMIN WHO");
        is_syntax("ADMIN WHO x");
        rt("ADMIN DISCONNECT ~sam bye");
        canon("ADMIN DISCONNECT ~sam ", "ADMIN DISCONNECT ~sam");
        is_syntax("ADMIN DISCONNECT");
        assert_eq!(
            rt("ADMIN NOTICE Down at 22:00 UTC").command,
            Command::Admin(AdminCommand::Notice {
                message: "Down at 22:00 UTC".into()
            })
        );
        is_syntax("ADMIN NOTICE");
        is_syntax("ADMIN NOTICE ");
    }

    #[test]
    fn admin_rooms_and_content() {
        rt("ADMIN ROOMS");
        rt("ADMIN DROP #a");
        rt("ADMIN DROP #a spam room");
        is_syntax("ADMIN DROP");
        assert_eq!(
            rt("ADMIN PURGE ~spammer hours=24").command,
            Command::Admin(AdminCommand::Purge {
                uid: uid("~spammer"),
                hours: Some(nz(24))
            })
        );
        canon("ADMIN PURGE ~x HOURS=1", "ADMIN PURGE ~x hours=1");
        rt("ADMIN PURGE spam@example.net");
        is_syntax("ADMIN PURGE ~x hours=0");
        is_syntax("ADMIN PURGE ~x hours=");
        is_syntax("ADMIN PURGE ~x days=1");
        is_syntax("ADMIN PURGE ~x 5");
        is_syntax("ADMIN PURGE");
        rt("ADMIN REPORTS");
        is_syntax("ADMIN REPORTS #a");
    }

    #[test]
    fn admin_hosted_identities() {
        rt("ADMIN KEYS alice@example.org");
        rt(&format!("ADMIN ADDKEY alice@example.org {KEY} new phone"));
        assert_eq!(
            canon(
                &format!("ADMIN ADDKEY alice@example.org {KEY} "),
                &format!("ADMIN ADDKEY alice@example.org {KEY}")
            )
            .command,
            Command::Admin(AdminCommand::AddKey {
                uid: uid("alice@example.org"),
                key: key(),
                label: String::new()
            })
        );
        rt(&format!("ADMIN DELKEY alice@example.org {KEY}"));
        rt("ADMIN UNREGISTER alice@example.org");
        is_syntax("ADMIN KEYS");
        is_syntax("ADMIN ADDKEY alice@example.org");
        is_syntax(&format!("ADMIN DELKEY alice@example.org {KEY} x"));
        is_syntax("ADMIN UNREGISTER alice@example.org purge=yes");
    }

    #[test]
    fn admin_set() {
        assert_eq!(
            canon("ADMIN SET Guests NO", "ADMIN SET guests no").command,
            Command::Admin(AdminCommand::Set(ServerSetting::Guests(false)))
        );
        rt("ADMIN SET registration open");
        assert!(matches!(
            cmd("ADMIN SET retention forever"),
            Command::Admin(AdminCommand::Set(ServerSetting::Retention(
                ServerRetention::Forever
            )))
        ));
        rt("ADMIN SET welcome Hello, and welcome!");
        rt("ADMIN SET welcome");
        rt("ADMIN SET motd hi");
        is_syntax("ADMIN SET registration maybe");
        is_syntax("ADMIN SET guests");
        is_syntax("ADMIN SET");
    }

    // ---- 11. Keepalive and closing ----

    #[test]
    fn ping_pong_quit() {
        assert_eq!(rt("PING").command, Command::Ping { token: None });
        assert_eq!(
            rt("PING abc").command,
            Command::Ping {
                token: Some("abc".into())
            }
        );
        canon("PING abc ", "PING abc");
        is_syntax("PING a b");
        assert_eq!(
            rt("PONG Xy1").command,
            Command::Pong {
                token: "Xy1".into()
            }
        );
        is_syntax("PONG");
        is_syntax("PONG a b");
        assert_eq!(
            rt("QUIT").command,
            Command::Quit {
                message: String::new()
            }
        );
        rt("QUIT going home");
        canon("QUIT ", "QUIT");
    }

    // ---- hand-built requests ----

    #[test]
    fn hand_built_requests() {
        let bad_text = Request::new(Command::Quit {
            message: "a\nb".into(),
        });
        assert!(bad_text.try_to_line().is_err());
        assert!(bad_text.validate().is_err());

        let empty_msg = Request::new(Command::Msg {
            conv: Conv::Room(room("#a")),
            text: String::new(),
            relation: None,
            file: None,
            cid: None,
        });
        assert_eq!(empty_msg.to_line().to_string(), "MSG #a");
        assert!(matches!(
            empty_msg.validate(),
            Err(ParseError::BadSyntax(_))
        ));

        let not_canonical = Request::new(Command::Set {
            room: room("#a"),
            setting: RoomSetting::Other {
                key: "public".into(),
                value: "yes".into(),
            },
        });
        assert!(not_canonical.validate().is_err());

        let good = Request {
            ref_: Some("1".parse().unwrap()),
            command: Command::Msg {
                conv: Conv::Uid(uid("bob@example.net")),
                text: crate::text::escape("hello\nthere"),
                relation: Some(Relation::Reply(seq(4))),
                file: Some(URL.parse().unwrap()),
                cid: None,
            },
        };
        assert_eq!(good.validate(), Ok(()));
        assert_eq!(
            good.to_string(),
            format!("@ref=1;reply=4;file={URL} MSG bob@example.net hello\\nthere")
        );
    }
}

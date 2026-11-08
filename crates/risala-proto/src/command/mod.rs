//! Typed client commands (SPEC 4-12, the first table of Section 13).
//!
//! A [`Request`] is one line a client sends: its optional `ref` tag (3.6)
//! and a [`Command`]. Parse one from a [`Line`] with [`Request::parse`],
//! or from a string with [`str::parse`]; turn it back into a line with
//! [`Request::to_line`].
//!
//! ```
//! use risala_proto::command::{Command, Request};
//! use risala_proto::mls::PostToken;
//!
//! let request: Request = "@ref=7 fetch ujzdegxdncf32epf3dhodzdoci after=9120 limit=2".parse()?;
//! let Command::Fetch { mailbox, after, limit, .. } = &request.command else {
//!     panic!("not a FETCH");
//! };
//! assert_eq!(mailbox.to_string(), "ujzdegxdncf32epf3dhodzdoci");
//! assert_eq!((*after, limit.map(|l| l.get())), (9120, Some(2)));
//! assert_eq!(
//!     request.to_line().to_string(),
//!     "@ref=7 FETCH ujzdegxdncf32epf3dhodzdoci after=9120 limit=2"
//! );
//! # Ok::<(), risala_proto::error::ParseError>(())
//! ```
//!
//! The code is split by area, each with the commands of a few sections:
//! [`identity`] (4: ANON, GUEST, AUTH, REGISTER, KEYS, PAIR, UNREGISTER),
//! [`mailbox`] (5-7: CREATE, POST, UPLOAD, REPORT, LIST, INFO, GROUPINFO,
//! MUTE, FOLLOW, FETCH), [`account`] (8, 9, 12: PRESENCE, WATCH, WHOIS,
//! MEMBERS, PUSH, KEYPKG, WELCOME, BLOB, BACKUP) and [`admin`] (10, 5.8:
//! ADMIN, RESOLVE). This module holds the [`Command`] type, which kinds of
//! connection may send each command, and the keepalive commands of
//! Section 11.
//!
//! # Rules
//!
//! - **Arity (3.3).** Too few or too many tokens, an unknown option or a
//!   repeated option is `BadSyntax`. An unknown verb is
//!   [`ParseError::UnknownVerb`], carrying the verb in upper case. So is
//!   an unknown subcommand of a known verb (`KEYPKG FOO`), carried as
//!   `"KEYPKG FOO"`, so the server replies `ERR unknown-command` (3.8). A
//!   missing subcommand (`ADMIN` alone) is `BadSyntax`. ON and OFF of
//!   PRESENCE are subcommands too.
//! - **Tags (3.2).** `ref` applies to every command, and POST also reads
//!   `cid` (7.6). Every other tag is ignored (3.2). A tag this module
//!   reads must have a valid value: a `ref` or `cid` over 64 bytes is
//!   `TooLong`, a missing or malformed value is `BadSyntax`.
//! - **Binary values** are opaque here: MLS objects ([`mls`](crate::mls))
//!   and key files, pairing data and reports ([`binary`](crate::binary))
//!   only have to be strict base64, of the right length where the spec
//!   fixes one (`BadSyntax` otherwise, 3.7). Whether they verify is for
//!   the server, which answers `ERR invalid`. MLS objects that may be too
//!   large for a line may be a blob-ref instead ([`OrBlob`]).
//! - **Text stays escaped (3.4).** Text parameters are kept exactly as
//!   received. Length limits apply to that escaped form and are `TooLong`.
//! - **Optional text** (`[<reason...>]`, `[<message...>]`) is a `String`
//!   that is empty when absent. Required text (`<message...>` of ADMIN
//!   NOTICE) must not be empty (`BadSyntax`).
//! - **Names fold (3.5).** Rooms, uids, boxes, blob-refs, subcommands,
//!   option keys and keyword values are case-insensitive and are written
//!   back in lower case. Verbs and subcommands are written in upper case.
//!
//! # Serialising
//!
//! [`Request::to_line`] writes the canonical form: the verb (and
//! subcommand) in upper case, single spaces, the `ref` tag then `cid`,
//! and options in the order the spec's syntax line lists them. Optional
//! options are left out when they are absent, and so are `live=` and
//! `light=` when they are false.
//!
//! The fields of [`Command`] are public, so a request built by hand can
//! hold values that a parsed one never does. [`Request::validate`] checks
//! a hand-built request against every rule above.
//!
//! # Kinds of connection
//!
//! [`Command::kinds`] gives the kinds of connection that may send a
//! command (Section 13), and [`Command::check_kind`] the error a server
//! replies with when this one may not.

use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use crate::auth::Signature;
use crate::binary::{EncodedRecords, ReportData};
use crate::connection::{ConnectionKind, Kinds};
use crate::error::{ErrorCode, ParseError};
use crate::line::{Line, LineBuilder, Params, Tags};
use crate::mls::{
    GroupId, GroupInfo, MlsMessage, OrBlob, PostToken, Pseudonym, SendToken, TokenHash,
};
use crate::names::{BlobRef, BoxName, Id, Identity, Name, Room, Uid};
use crate::parse::bad;
use crate::types::{Cid, PushTag, Ref};

pub mod account;
pub mod admin;
pub mod identity;
pub mod mailbox;

pub use account::{BackupCommand, BlobPermit, KeyPkgCommand, PushCommand, WelcomeCommand};
pub use admin::{AdminCommand, DropTarget};
pub use identity::{GuestToken, KeysPutRecords, PairCommand};
pub use mailbox::{CreateForm, PublicRoom};

// ---------------------------------------------------------------------------
// Request

/// One command from a client, with its `ref` tag (3.6).
///
/// The one other tag a command reads, POST's `cid`, lives in the
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

    /// Parses a client line into a typed request (3.3, Section 13).
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
            Some(None) => Err(bad("ref needs a value")),
            Some(Some(value)) => value.parse().map(Some),
        }
    }

    /// Writes the request as a line in canonical form (see the [module
    /// documentation](self)).
    ///
    /// # Panics
    ///
    /// Never for a request from [`Request::parse`]. A request built by
    /// hand panics if [`try_to_line`](Self::try_to_line) would fail: for
    /// example text with a control character other than TAB, a value over
    /// a limit, or a setting that is not in canonical form. Use
    /// [`try_to_line`](Self::try_to_line) for requests whose values were
    /// not checked.
    pub fn to_line(&self) -> Line {
        self.try_to_line()
            .expect("a parsed request's values all fit in a line")
    }

    /// Writes the request as a line, like [`to_line`](Self::to_line), but
    /// returns an error instead of panicking when a hand-built request
    /// cannot be sent as it is.
    ///
    /// The line it returns always parses back to an equal request: it is
    /// written, then parsed again from its string form and compared. So
    /// every rule of [`Request::parse`] holds, and the values are in
    /// canonical form (for example, a
    /// [`ServerSetting::Other`](crate::types::ServerSetting::Other) whose
    /// key is a known one fails).
    pub fn try_to_line(&self) -> Result<Line, ParseError> {
        let mut b = Line::builder(self.command.verb());
        if let Some(r) = &self.ref_ {
            b.tag("ref", r);
        }
        self.command.write(&mut b);
        let line = b.build()?;
        if Request::parse(&Line::parse(&line.to_string())?)? == *self {
            Ok(line)
        } else {
            Err(bad("request is not in canonical form"))
        }
    }

    /// Checks a request built by hand, as
    /// [`try_to_line`](Self::try_to_line) does.
    pub fn validate(&self) -> Result<(), ParseError> {
        self.try_to_line().map(drop)
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

/// A client command: one variant per row of the first table in Section 13,
/// or per verb where a row lists several.
///
/// Optional text is an empty `String` when absent. Text is escaped, as on
/// the wire (3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // ---- 8.5, 6.1
    /// `INFO [<room>]`: the server's values (8.5), or one public room's
    /// (6.1). A new connection may send it only without a room.
    Info {
        /// The public room to look up, if any.
        room: Option<Room>,
    },

    // ---- 4.2
    /// `ANON`: the connection becomes anonymous (4.2).
    Anon,
    /// `GUEST <name> [token=<token>]`: the connection becomes a guest, or
    /// resumes a guest session (4.2).
    Guest {
        /// The guest name, without `~`.
        name: Name,
        /// The token of the session to resume.
        token: Option<GuestToken>,
    },

    // ---- 4.6, 4.7
    /// `AUTH <identity> <signature>`: signs in (4.6). A guest uid is
    /// `BadSyntax`.
    Auth {
        /// The identity, in lower case.
        identity: Identity,
        /// The ML-DSA-44 signature over the sign-in bytes.
        signature: Signature,
    },
    /// `REGISTER <name> <keyfile> <signature>`: creates and signs in as
    /// `<name>@<identity domain>` (4.7). It may be up to 64 KiB on a new
    /// connection (2.3).
    Register {
        /// The name of the new identity.
        name: Name,
        /// Its first records: a `master` and a `device` record.
        records: EncodedRecords,
        /// The sign-in signature, made with the `device` record's key.
        signature: Signature,
    },
    /// `KEYS PUT <after> <records>`: adds records to an identity's chain
    /// on this server (4.7). Replies with RECORD lines. Allowed on new,
    /// anonymous and signed-in connections, since records are signed.
    KeysPut {
        /// `<after>`: the hash of the record the first of `records`
        /// follows, or `None` for `-`, when they start with the chain's
        /// first record.
        after: Option<BlobRef>,
        /// `<records>`: the records, inline or as a blob.
        records: KeysPutRecords,
    },

    // ---- 4.8
    /// `PAIR PUT <id> <data>` and `PAIR GET <id>` (4.8).
    Pair(PairCommand),

    // ---- 4.9
    /// `UNREGISTER <uid>`: deletes everything the server keeps about the
    /// identity the connection is signed in as, which `<uid>` must be.
    Unregister {
        /// The connection's own identity, typed out.
        uid: Uid,
    },

    // ---- 5.2
    /// `CREATE <box> <group-id> <token-hash> [epoch=<epoch>]` or
    /// `CREATE <box> <group-id> <token-hash> <room> <groupinfo> <tree>`:
    /// creates a mailbox for a group in epoch 0 (5.2), or in epoch
    /// `epoch` for a group that moves (7.8). The second form creates a
    /// public room (6.1).
    Create {
        /// The new mailbox, from 16 new random bytes.
        mailbox: BoxName,
        /// The group's id.
        group_id: GroupId,
        /// The SHA-384 hash of the group's send token for the mailbox's
        /// first epoch: 0, or `epoch`.
        token_hash: TokenHash,
        /// The second form's public room, or the first form's `epoch=`.
        form: CreateForm,
    },
    /// `POST <box> <token> <message> [live=yes] [groupinfo=<groupinfo>]
    /// [next=<hash>]`: posts an MLS message to a mailbox (5.2).
    Post {
        /// The mailbox.
        mailbox: BoxName,
        /// The send token of the message's epoch, or `-` for a join of a
        /// public room (6.1).
        token: PostToken,
        /// The MLSMessage, or a blob-ref if it is too large for a line.
        message: OrBlob<MlsMessage>,
        /// `live=yes`: the post is not kept, numbered or pushed (5.2).
        live: bool,
        /// `groupinfo=`: the new GroupInfo of a commit in a public room
        /// (12.6).
        groupinfo: Option<OrBlob<GroupInfo>>,
        /// `next=`: the SHA-384 hash of the send token of the epoch that a
        /// commit creates (5.2, 7.2). Required on commits and refused on
        /// anything else, which only the server can tell from the
        /// message's framing (`ERR invalid`), so the parser just carries
        /// it.
        next: Option<TokenHash>,
        /// The `cid` tag, for safe resending (7.6).
        cid: Option<Cid>,
    },

    // ---- 5.6
    /// `UPLOAD <box> <token> <size>`: asks to upload an encrypted file
    /// (5.6).
    Upload {
        /// The conversation's mailbox.
        mailbox: BoxName,
        /// A send token of the group, checked as for POST.
        token: SendToken,
        /// The size of the encrypted file, in bytes.
        size: u64,
    },

    // ---- 5.8
    /// `REPORT <box> <report>`: reports posts to the server's operators
    /// (5.8).
    Report {
        /// The mailbox the posts are in.
        mailbox: BoxName,
        /// The RisalaReport.
        report: ReportData,
    },

    // ---- 6.1
    /// `LIST [after=<room>] [limit=<n>]`: lists public rooms (6.1).
    List {
        /// Only rooms whose names sort after this one.
        after: Option<Room>,
        /// At most this many rooms; at least 1, default 100.
        limit: Option<NonZeroU64>,
    },
    /// `GROUPINFO <box>`: a public room's current GroupInfo and ratchet
    /// tree (6.1).
    GroupInfo {
        /// The public room's mailbox.
        mailbox: BoxName,
    },

    // ---- 6.4
    /// `MUTE <box> <pseudonym> [hours=<n>]`: asks the server to refuse a
    /// pseudonym's posts in a public room (6.4).
    Mute {
        /// The public room's mailbox.
        mailbox: BoxName,
        /// The pseudonym to mute.
        pseudonym: Pseudonym,
        /// For how many hours; at least 1, default 24.
        hours: Option<NonZeroU64>,
    },
    /// `UNMUTE <box> <pseudonym>` (6.4).
    Unmute {
        /// The public room's mailbox.
        mailbox: BoxName,
        /// The pseudonym to unmute.
        pseudonym: Pseudonym,
    },

    // ---- 7.1
    /// `FOLLOW <box> [quiet=<tag>]`: sends the connection every new post
    /// of a mailbox (7.1).
    Follow {
        /// The mailbox.
        mailbox: BoxName,
        /// A push subscription to hold back while this connection follows
        /// (9.2).
        quiet: Option<PushTag>,
    },
    /// `UNFOLLOW <box>` (7.1).
    Unfollow {
        /// The mailbox.
        mailbox: BoxName,
    },
    /// `FETCH <box> after=<position> [limit=<n>] [leaf=<n>]`: the earliest
    /// posts after a seq (7.1).
    Fetch {
        /// The mailbox.
        mailbox: BoxName,
        /// Posts after this position (3.5): a seq, or 0 for the place
        /// before the first post. Required.
        after: u64,
        /// At most this many posts; at least 1, default 50. A server may
        /// cap it, but not below [`MIN_FETCH_LIMIT_CAP`](crate::types::MIN_FETCH_LIMIT_CAP)
        /// (7.1).
        limit: Option<NonZeroU64>,
        /// A light client's leaf index in a public room (12.6).
        leaf: Option<u32>,
    },

    // ---- 7.2
    /// `TOKEN <box> <epoch> <token> <hash>`: adds `hash` to the token set
    /// of epoch `epoch + 1`, for a holder of a send token of `epoch`
    /// (7.2).
    Token {
        /// The mailbox.
        mailbox: BoxName,
        /// The epoch of `token`.
        epoch: u64,
        /// A send token of `epoch`, checked as for POST (5.2).
        token: SendToken,
        /// The SHA-384 hash of a send token of `epoch + 1`.
        hash: TokenHash,
    },

    // ---- 8.3
    /// `PRESENCE ON` (true) or `PRESENCE OFF` (false): whether the server
    /// reports the identity's presence (8.3).
    Presence {
        /// `ON`.
        on: bool,
    },
    /// `WATCH [<uids>]`: sets the identities to report presence for, or
    /// clears them (8.3).
    Watch {
        /// The uids, separated by commas on the wire. Empty clears the
        /// list.
        uids: Vec<Uid>,
    },
    /// `WHOIS <uid>` (8.3).
    Whois {
        /// The identity.
        uid: Uid,
    },
    /// `MEMBERS <room>`: the members of a public room (8.3).
    Members {
        /// The public room.
        room: Room,
    },

    // ---- 9.1
    /// `PUSH ADD`, `PUSH DEL` and `PUSH LIST` (9.1).
    Push(PushCommand),

    // ---- 12.5
    /// `KEYPKG ADD`, `KEYPKG COUNT` and `KEYPKG GET` (12.5).
    KeyPkg(KeyPkgCommand),

    // ---- 12.8
    /// `WELCOME PUT`, `WELCOME LIST`, `WELCOME DEL` and `WELCOME GET`
    /// (12.8).
    Welcome(WelcomeCommand),

    // ---- 12.12
    /// `BLOB <hash> <size> [box=<box> token=<token>]`: asks to store a
    /// blob (12.12).
    Blob {
        /// The blob's blob-ref.
        hash: BlobRef,
        /// Its size in bytes.
        size: u64,
        /// `box=` and `token=`, which anonymous and guest connections need.
        permit: Option<BlobPermit>,
    },

    // ---- 12.13
    /// `BACKUP PUT`, `BACKUP GET` and `BACKUP DEL` (12.13).
    Backup(BackupCommand),

    // ---- 10
    /// `ADMIN <subcommand> ...` (Section 10).
    Admin(AdminCommand),

    // ---- 5.8
    /// `RESOLVE <id>`: closes a report (5.8). For operators.
    Resolve {
        /// The report's id.
        id: Id,
    },

    // ---- 11
    /// `PING [<token>]` (11).
    Ping {
        /// The token, if any: one token of any characters but space and
        /// TAB.
        token: Option<String>,
    },
    /// `PONG <token>`: the answer to a server's PING. It gets no response
    /// (3.6, 11).
    Pong {
        /// The token from the server's PING.
        token: String,
    },
    /// `QUIT [<message...>]` (11).
    Quit {
        /// The message, escaped; empty if none.
        message: String,
    },
}

/// The kinds that may send each command (Section 13).
const NEW: Kinds = Kinds::NEW;
const ANON: Kinds = Kinds::ANONYMOUS;
const GUEST: Kinds = Kinds::GUEST;
const SIGNED: Kinds = Kinds::SIGNED_IN;
const CONVERSING: Kinds = ANON.or(GUEST);
const HAVING_A_KIND: Kinds = ANON.or(GUEST).or(SIGNED);

impl Command {
    /// The verb, in upper case.
    pub fn verb(&self) -> &'static str {
        match self {
            Command::Info { .. } => "INFO",
            Command::Anon => "ANON",
            Command::Guest { .. } => "GUEST",
            Command::Auth { .. } => "AUTH",
            Command::Register { .. } => "REGISTER",
            Command::KeysPut { .. } => "KEYS",
            Command::Pair(_) => "PAIR",
            Command::Unregister { .. } => "UNREGISTER",
            Command::Create { .. } => "CREATE",
            Command::Post { .. } => "POST",
            Command::Upload { .. } => "UPLOAD",
            Command::Report { .. } => "REPORT",
            Command::List { .. } => "LIST",
            Command::GroupInfo { .. } => "GROUPINFO",
            Command::Mute { .. } => "MUTE",
            Command::Unmute { .. } => "UNMUTE",
            Command::Follow { .. } => "FOLLOW",
            Command::Unfollow { .. } => "UNFOLLOW",
            Command::Fetch { .. } => "FETCH",
            Command::Token { .. } => "TOKEN",
            Command::Presence { .. } => "PRESENCE",
            Command::Watch { .. } => "WATCH",
            Command::Whois { .. } => "WHOIS",
            Command::Members { .. } => "MEMBERS",
            Command::Push(_) => "PUSH",
            Command::KeyPkg(_) => "KEYPKG",
            Command::Welcome(_) => "WELCOME",
            Command::Blob { .. } => "BLOB",
            Command::Backup(_) => "BACKUP",
            Command::Admin(_) => "ADMIN",
            Command::Resolve { .. } => "RESOLVE",
            Command::Ping { .. } => "PING",
            Command::Pong { .. } => "PONG",
            Command::Quit { .. } => "QUIT",
        }
    }

    /// The subcommand, in upper case, for verbs that have one (3.8):
    /// `PUT` of `KEYS PUT`, `ON` of `PRESENCE ON`, `BAN` of `ADMIN BAN`.
    pub fn subcommand(&self) -> Option<&'static str> {
        Some(match self {
            Command::KeysPut { .. } => "PUT",
            Command::Pair(c) => c.word(),
            Command::Presence { on: true } => "ON",
            Command::Presence { on: false } => "OFF",
            Command::Push(c) => c.word(),
            Command::KeyPkg(c) => c.word(),
            Command::Welcome(c) => c.word(),
            Command::Backup(c) => c.word(),
            Command::Admin(c) => c.word(),
            _ => return None,
        })
    }

    /// The kinds of connection that may send this command: its row in the
    /// table of Section 13.
    ///
    /// Where a row depends on the command's parameters, so does the
    /// answer: INFO with a room, the two forms of CREATE, and PUSH with
    /// and without `box=`.
    ///
    /// Section 13 is followed where other sections say "any kind of
    /// connection" more loosely: KEYPKG GET (12.5), WELCOME PUT and GET
    /// (12.8), and WATCH, WHOIS and MEMBERS (8.3) are not for new
    /// connections, the narrower reading.
    pub fn kinds(&self) -> Kinds {
        match self {
            Command::Info { room: None } => Kinds::ALL,
            Command::Info { room: Some(_) } => HAVING_A_KIND,
            Command::Anon
            | Command::Guest { .. }
            | Command::Auth { .. }
            | Command::Register { .. } => NEW,
            Command::KeysPut { .. } | Command::Pair(_) => NEW | ANON | SIGNED,
            Command::Unregister { .. } => SIGNED,
            Command::Create {
                form: CreateForm::Private { .. },
                ..
            } => CONVERSING,
            Command::Create {
                form: CreateForm::Public(_),
                ..
            } => SIGNED,
            // A signed-in connection may post a public room's
            // PublicMessages, and MUST post commits and Update proposals
            // by an identity's leaf there; every other post needs an
            // anonymous or guest connection (5.2 point 5, 12.6, 13). Only
            // the server can tell, from the message's framing and the
            // mailbox, so all three kinds pass here.
            Command::Post { .. } => HAVING_A_KIND,
            Command::Upload { .. } => ANON,
            Command::Report { .. } | Command::List { .. } => HAVING_A_KIND,
            Command::GroupInfo { .. } => CONVERSING,
            Command::Mute { .. } | Command::Unmute { .. } => SIGNED,
            Command::Follow { .. }
            | Command::Unfollow { .. }
            | Command::Fetch { .. }
            | Command::Token { .. } => CONVERSING,
            Command::Presence { .. } => SIGNED,
            Command::Watch { .. } | Command::Whois { .. } | Command::Members { .. } => {
                HAVING_A_KIND
            }
            Command::Push(c) => c.kinds(),
            Command::KeyPkg(c) => c.kinds(),
            Command::Welcome(c) => c.kinds(),
            Command::Blob { .. } => HAVING_A_KIND,
            Command::Backup(_) | Command::Admin(_) | Command::Resolve { .. } => SIGNED,
            Command::Ping { .. } | Command::Pong { .. } | Command::Quit { .. } => Kinds::ALL,
        }
    }

    /// Whether a connection of `kind` may send this command, and if not,
    /// the error a server replies with (Section 13, 3.7):
    ///
    /// - `already-authenticated` for ANON, GUEST, AUTH and REGISTER on a
    ///   connection that is already anonymous, a guest or signed in;
    /// - `not-authenticated` for anything else a new connection may not
    ///   send (4.1);
    /// - `wrong-connection` for anything else an anonymous, guest or
    ///   signed-in connection may not send (3.7, 4.1, 13);
    /// - `bad-syntax` for a BLOB without `box=` and `token=` from an
    ///   anonymous or guest connection, which needs them (12.12).
    ///
    /// Permissions that depend on more than the kind, such as being an
    /// operator (Section 10) or a room's moderator (6.4), are the
    /// server's to check afterwards.
    pub fn check_kind(&self, kind: ConnectionKind) -> Result<(), ErrorCode> {
        if !self.kinds().contains(kind) {
            return Err(if self.kinds() == NEW {
                ErrorCode::AlreadyAuthenticated
            } else {
                kind.refusal()
            });
        }
        match self {
            Command::Blob { permit: None, .. }
                if matches!(kind, ConnectionKind::Anonymous | ConnectionKind::Guest) =>
            {
                Err(ErrorCode::BadSyntax)
            }
            _ => Ok(()),
        }
    }

    /// Whether the command makes a new connection anonymous, a guest or
    /// signed in when it succeeds: ANON, GUEST, AUTH and REGISTER (4.1).
    pub fn sets_kind(&self) -> bool {
        matches!(
            self,
            Command::Anon | Command::Guest { .. } | Command::Auth { .. } | Command::Register { .. }
        )
    }

    /// Whether the command gets a final response. Every command does,
    /// except PONG (3.6).
    pub fn gets_response(&self) -> bool {
        !matches!(self, Command::Pong { .. })
    }

    /// Parses the command of a line, ignoring its `ref` (Section 13). Use
    /// [`Request::parse`] to keep the `ref`.
    pub fn parse(line: &Line) -> Result<Command, ParseError> {
        let verb = line.verb_upper();
        let tags = line.tags();
        let p = line.params();
        let parsed = identity::parse(&verb, p)
            .or_else(|| mailbox::parse(&verb, tags, p))
            .or_else(|| account::parse(&verb, p))
            .or_else(|| admin::parse(&verb, p))
            .or_else(|| parse_keepalive(&verb, p));
        parsed.unwrap_or_else(|| Err(ParseError::UnknownVerb(verb.into_owned())))
    }

    /// Writes the command's tags and parameters after the verb.
    fn write(&self, b: &mut LineBuilder) {
        let written = identity::write(self, b)
            || mailbox::write(self, b)
            || account::write(self, b)
            || admin::write(self, b)
            || write_keepalive(self, b);
        debug_assert!(written, "every command is written by its area");
    }
}

// ---------------------------------------------------------------------------
// Keepalive and closing (11)

fn parse_keepalive(verb: &str, mut p: Params<'_>) -> Option<Result<Command, ParseError>> {
    let parsed = || -> Result<Command, ParseError> {
        Ok(match verb {
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
            _ => unreachable!(),
        })
    };
    matches!(verb, "PING" | "PONG" | "QUIT").then(parsed)
}

fn write_keepalive(command: &Command, b: &mut LineBuilder) -> bool {
    match command {
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
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests;

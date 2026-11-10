//! The lines inside encrypted messages (SPEC 12.9): the `content` of a
//! RisalaMessage.
//!
//! A [`Content`] is one or more lines in the format of Section 3, each
//! ending in LF, that only the conversation's members can read: TEXT
//! (5.3), DELETE (5.4), TYPING (8.1), REPORT (5.8), CHALLENGE and ANSWER,
//! ATTEST and REVEAL (12.10), RESYNC (12.7), REFETCH (4.5, 12.14), and the lines of the
//! conversation with yourself: READ (7.7), RESYNC with a box (12.7), BLOCK and UNBLOCK (5.7), RECORD, ALERT and
//! RECORDS (4.5), SIGNINGKEY and BACKUPKEY (4.8, 12.13), WANT, TRANSFER
//! and SERVERS (12.13), and PIN (4.5, 12.14).
//!
//! ```
//! use risala_proto::content::{Content, ContentLine, Target};
//!
//! let content: Content = "@reply=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n".parse()?;
//! let [ContentLine::Text(text)] = content.lines() else {
//!     panic!("not one TEXT line");
//! };
//! assert!(matches!(text.target, Some(Target::Reply(_))));
//! assert_eq!(text.text, "see you at 12");
//! assert_eq!(content.as_str(), "@reply=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n");
//! # Ok::<(), risala_proto::error::ParseError>(())
//! ```
//!
//! # Parsing
//!
//! [`Content::parse`] reads the bytes of `content`. It fails only if they
//! are not lines at all: not UTF-8, empty, longer than 4 MiB, not ending
//! in LF, or holding a control character other than TAB (2.3), CR
//! included. Otherwise each line becomes a [`ContentLine`]. A line with a
//! verb this crate does not know, or a known verb whose line does not
//! follow its syntax, becomes [`ContentLine::Ignored`]: devices ignore
//! such lines (12.9), and the rest of the message still counts.
//!
//! A [`Content`] keeps its bytes exactly as received, since the franking
//! tag (12.9), reports (5.8) and history archives (12.13) all need the
//! very same bytes. [`Content::as_str`] gives them back unchanged.
//!
//! The rules of each line follow Section 3 and the line's own section:
//!
//! - **Verbs** are case-insensitive, and written in upper case.
//! - **Tags (3.2)** that a line does not use are ignored, `x-` tags too.
//!   A tag the line uses must have a valid value.
//! - **Text stays escaped (3.4).** Length limits apply to the escaped
//!   form (`TooLong`).
//! - **TEXT (5.3)**: the text must not be blank, and is at most 8192
//!   bytes, or 64 for a reaction. It has at most one of `reply`, `edit`
//!   and `react`. It has a file only if `file`, `file-key` and
//!   `file-hash` are all present and valid (12.9), and is not an edit or
//!   a reaction (5.3). Otherwise it is a message with no file, not an
//!   ignored line.
//! - **Names fold (3.5)**: boxes, uids, blob-refs, domains and media
//!   types are written back in lower case. Log origins do not fold.
//!
//! # Writing
//!
//! [`Content::new`] writes lines in canonical form: the verb in upper
//! case, single spaces, and tags in the order the spec lists them. It
//! checks each line by parsing it back, so a hand-built line that breaks
//! a rule above, or that would not parse back to the same value, is an
//! error. [`ContentLine::Ignored`] lines are written back as they were
//! received.
//!
//! # Where lines are allowed
//!
//! [`ContentLine::allowed_in`] says whether a line counts in a
//! conversation, from the table of 12.9 and the rules of 8.1 (TYPING is
//! live) and 4.2 and 5.8 (guests). Devices ignore lines in a
//! conversation where they are not allowed.

use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::auth::{PublicKey, Signature};
use crate::error::ParseError;
use crate::frame::is_forbidden_control;
use crate::line::{Line, LineBuilder, Params, Tags};
use crate::mls::Pseudonym;
use crate::names::{BlobRef, BlockTarget, BoxName, Identity, Seq, ServerAddr};
use crate::parse::{
    bad, last, limit, number, number_u32, opt_tok, parse_tag, required_tag, tag_value, text_max,
    tok,
};
use crate::text;
use crate::types::{ConfirmMode, parse_yes_no, yes_no};

mod values;

pub use values::{
    BACKUP_KEY_LEN, BackupKey, CHALLENGE_LEN, CONFIRM_MAC_LEN, ChallengeCiphertext, ConfirmMac,
    EPOCH_CHECK_LEN, EpochCheck, FILE_HASH_LEN, FILE_KEY_LEN, FileHash, FileKey, FileRef, FileUrl,
    LogOrigin, MAX_FILE_URL_LEN, MAX_MEDIA_NAME_LEN, MAX_ORIGIN_LEN, MESSAGE_ID_LEN, MediaType,
    MessageId, ORIGIN_PATH, PeriodSeed, SEED_LEN, SigningSeed, TRANSFER_REF_LEN, TransferRef,
};

/// The most bytes a message's content may have (12.9).
pub const MAX_CONTENT_LEN: usize = 4 * 1024 * 1024;

/// The most lines a content may have. 12.9 sets no such limit, only 4 MiB
/// in all; this one keeps a message of short lines from taking about a
/// hundred times its size in memory on every device that reads it. No
/// message comes near it: the most lines a device sends at once are a
/// CHALLENGE and an ANSWER for each leaf of a private room (4,096 at most,
/// 6.1), and a few more. (A choice to confirm: the spec is silent.)
pub const MAX_CONTENT_LINES: usize = 16_384;

/// The most bytes of escaped text a TEXT line may have (5.3).
pub const MAX_TEXT_LEN: usize = 8192;

/// The most bytes of escaped text a reaction may have (5.3).
pub const MAX_REACTION_LEN: usize = 64;

/// The most bytes of escaped text a REPORT's reason may have (5.8).
pub const MAX_REASON_LEN: usize = 512;

/// The most messages a REPORT's `context` may list (5.8).
pub const MAX_REPORT_CONTEXT: usize = 10;

/// The members above which devices SHOULD NOT send typing notifications
/// (8.1).
pub const MAX_TYPING_MEMBERS: usize = 100;

// ---------------------------------------------------------------------------
// Content

/// The content of an encrypted message (12.9): its exact bytes, and the
/// lines they hold.
///
/// It is made by [`Content::parse`] from received bytes, or by
/// [`Content::new`] from lines, so its bytes are always valid content.
/// The bytes are wiped from memory when it is dropped, since lines such
/// as SIGNINGKEY carry secrets, and `Debug` shows only the lines, whose
/// secrets show only their type.
#[derive(Clone, PartialEq, Eq)]
pub struct Content {
    bytes: Zeroizing<String>,
    lines: Vec<ContentLine>,
}

impl Content {
    /// Parses the bytes of a RisalaMessage's `content` (12.9).
    ///
    /// Errors, for bytes that are not lines at all: `InvalidUtf8`;
    /// `TooLong` beyond 4 MiB or [`MAX_CONTENT_LINES`] lines; `ControlChar`
    /// for a control character
    /// other than TAB, CR included; and `BadSyntax` for empty content or
    /// content that does not end in LF. Lines that do not parse are kept
    /// as [`ContentLine::Ignored`].
    pub fn parse(bytes: &[u8]) -> Result<Content, ParseError> {
        if bytes.len() > MAX_CONTENT_LEN {
            return Err(ParseError::TooLong);
        }
        let s = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8)?;
        if s.is_empty() {
            return Err(bad("content has at least one line"));
        }
        let body = s.strip_suffix('\n').ok_or(bad("content ends with LF"))?;
        // Counted before any line is parsed, so that the memory it takes
        // stays bounded.
        if body.bytes().filter(|&b| b == b'\n').count() >= MAX_CONTENT_LINES {
            return Err(ParseError::TooLong);
        }
        let lines = body
            .split('\n')
            .map(|raw| {
                if raw.chars().any(is_forbidden_control) {
                    Err(ParseError::ControlChar)
                } else {
                    Ok(ContentLine::parse_or_ignore(raw))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Content {
            bytes: Zeroizing::new(s.to_owned()),
            lines,
        })
    }

    /// Writes `lines` as content, each in canonical form and ending in LF
    /// (see the [module documentation](self)).
    ///
    /// Errors: `BadSyntax` for no lines; `TooLong` if the content would
    /// be longer than 4 MiB or [`MAX_CONTENT_LINES`] lines; and the error
    /// of the first line that cannot
    /// be written as it is, as [`ContentLine::to_line`] gives it.
    pub fn new(lines: Vec<ContentLine>) -> Result<Content, ParseError> {
        if lines.is_empty() {
            return Err(bad("content has at least one line"));
        }
        if lines.len() > MAX_CONTENT_LINES {
            return Err(ParseError::TooLong);
        }
        let mut bytes = Zeroizing::new(String::new());
        for line in &lines {
            bytes.push_str(&line.to_line()?);
            bytes.push('\n');
            if bytes.len() > MAX_CONTENT_LEN {
                return Err(ParseError::TooLong);
            }
        }
        Ok(Content { bytes, lines })
    }

    /// Content of one line, as [`Content::new`] writes it.
    pub fn single(line: ContentLine) -> Result<Content, ParseError> {
        Content::new(vec![line])
    }

    /// The lines, in order.
    pub fn lines(&self) -> &[ContentLine] {
        &self.lines
    }

    /// The content's bytes, exactly as received or written: the bytes the
    /// franking tag covers (12.9).
    pub fn as_str(&self) -> &str {
        &self.bytes
    }

    /// The content's bytes, as [`as_str`](Self::as_str).
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }

    /// The lines that count in `place`: those [`ContentLine::allowed_in`]
    /// allows. Devices ignore the others (12.9).
    pub fn allowed(&self, place: Place) -> impl Iterator<Item = &ContentLine> {
        self.lines.iter().filter(move |l| l.allowed_in(place))
    }

    /// Whether the content has a line with something to show (a TEXT,
    /// DELETE or REPORT line), which makes a device challenge an
    /// unconfirmed sender in a pairwise group (12.10).
    pub fn shows_something(&self) -> bool {
        self.lines.iter().any(ContentLine::is_shown)
    }
}

impl FromStr for Content {
    type Err = ParseError;

    /// Same as [`Content::parse`].
    fn from_str(s: &str) -> Result<Content, ParseError> {
        Content::parse(s.as_bytes())
    }
}

impl fmt::Display for Content {
    /// Writes the bytes exactly, with every line ending.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.bytes)
    }
}

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Content").field(&self.lines).finish()
    }
}

// ---------------------------------------------------------------------------
// ContentLine

/// One line inside an encrypted message: one variant per verb of the
/// table in 12.9, and [`Ignored`](Self::Ignored) for every line that
/// devices ignore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentLine {
    /// `[@<tags>] TEXT <text...>`: a message that people see (5.3).
    Text(Text),
    /// `DELETE <id>`: asks every device to delete message `<id>` (5.4).
    Delete {
        /// The message to delete.
        id: MessageId,
    },
    /// `TYPING`: the sender's user is typing, in a live message (8.1).
    Typing,
    /// `@box=<box>;target=<id>[;context=<ids>] REPORT [<reason...>]`: a
    /// report to a room's owner or moderator (5.8).
    Report(Report),
    /// `CHALLENGE <leaf> <ciphertext>`: a challenge to the device of leaf
    /// `<leaf>` (12.10).
    Challenge {
        /// The challenged leaf's index.
        leaf: u32,
        /// The X-Wing ciphertext.
        ciphertext: ChallengeCiphertext,
    },
    /// `ANSWER <leaf> <mac>`: the answer to a challenge from leaf `<leaf>`
    /// (12.10).
    Answer {
        /// The challenger's leaf index.
        leaf: u32,
        /// The MAC over the ConfirmContent.
        mac: ConfirmMac,
    },
    /// `ATTEST <period> <period-key> <certificate> <attestation>
    /// <pseudonym>`: binds the sender's leaf to its device for one period,
    /// and announces the leaf's pseudonym for it (12.10, 7.3).
    Attest {
        /// The period: a UTC day, numbered from 1970-01-01 as 0.
        period: u32,
        /// The period key, ML-DSA-44.
        period_key: PublicKey,
        /// The PeriodCert's signature by the device key.
        certificate: Signature,
        /// The AttestContent's signature by the period key.
        attestation: Signature,
        /// The leaf's pseudonym for the period. Devices check that it is
        /// the one in the RisalaAAD of the message that carries the line
        /// (12.10).
        pseudonym: Pseudonym,
    },
    /// `REVEAL <period> <seed>`: publishes a period key once its period is
    /// over (12.10).
    Reveal {
        /// The period.
        period: u32,
        /// The period key's seed.
        seed: PeriodSeed,
    },
    /// `RESYNC <seq>` in a direct conversation or a private room, or
    /// `RESYNC <box> <seq>` in the conversation with yourself: the sending
    /// device could not process the commit at `<seq>`, and asks for its
    /// leaf to be replaced (12.7, 12.9).
    Resync {
        /// The mailbox of the group, in the conversation with yourself
        /// only; `None` in the group itself.
        mailbox: Option<BoxName>,
        /// The seq of the commit the device could not process.
        seq: Seq,
    },
    /// `LEAVE <box>` in the conversation with yourself: the sending device
    /// left the group of that box locally, its leaf perhaps still there,
    /// and asks the identity's other devices to leave it for the whole
    /// identity with the usual leave commit (6.1, 12.7).
    Leave {
        /// The mailbox of the group, now or before a move.
        mailbox: BoxName,
    },
    /// `REFETCH <hash>`: the sender's identity has a new record, so members
    /// fetch its key file soon rather than at their daily fetch (4.5,
    /// 12.14).
    Refetch(BlobRef),
    /// `READ <box> <seq> <check>`: the sending device has shown mailbox
    /// `<box>` up to `<seq>` (7.7).
    Read {
        /// The conversation's mailbox.
        mailbox: BoxName,
        /// The last post shown.
        seq: Seq,
        /// A check of the epoch the device had applied at `<seq>` (12.9).
        check: EpochCheck,
    },
    /// `BLOCK <target>`: the user blocked an identity or a domain (5.7).
    Block(BlockTarget),
    /// `UNBLOCK <target>`: the user lifted a block (5.7).
    Unblock(BlockTarget),
    /// `RECORD <hash>`: the sending device made a key file record (4.5).
    Record(BlobRef),
    /// `ALERT <hash>`: a record of the identity that no device announced,
    /// or a fork (4.5).
    Alert(BlobRef),
    /// `RECORDS [<hashes...>]`: `None` (no hashes) asks which records
    /// were announced; `Some` answers, with the hashes of the records the
    /// device knows were announced, written `RECORDS -` when it knows of
    /// none (4.5, 12.9).
    Records(Option<Vec<BlobRef>>),
    /// `SIGNINGKEY <seed>`: the identity's new device-signing key (4.8).
    SigningKey(SigningSeed),
    /// `BACKUPKEY <generation> <key>`: the backup key of a generation
    /// (12.13).
    BackupKey {
        /// The generation (4.4).
        generation: u32,
        /// The backup key.
        key: BackupKey,
    },
    /// `WANT <box> <after> <before>`: the sending device lacks the posts
    /// of `<box>` after `<after>` and before `<before>` (12.13).
    Want {
        /// The conversation's mailbox.
        mailbox: BoxName,
        /// The gap starts after this seq; 0 for the start.
        after: u64,
        /// The gap ends before this seq; `None` (`-`) if the device does
        /// not know where it ends.
        before: Option<Seq>,
    },
    /// `TRANSFER <ref>`: history for a WANT, as archives (12.13).
    Transfer(TransferRef),
    /// `SERVERS <hosts...>`: the servers the identity uses, its home first
    /// (12.13).
    Servers(Vec<ServerAddr>),
    /// `PIN <uid> <master> <origin> <head> <verified>`: another identity's
    /// pin and verified mark (4.5, 12.14).
    Pin(Pin),
    /// A line that devices ignore (12.9): its verb is not one this crate
    /// knows, or it does not follow its verb's syntax.
    Ignored(IgnoredLine),
}

/// A TEXT line (5.3, 12.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Text {
    /// The text, escaped as on the wire (3.4): not blank, at most 8192
    /// bytes, or 64 for a reaction.
    pub text: String,
    /// What the message refers to: `reply`, `edit` or `react`.
    pub target: Option<Target>,
    /// The file it shares (5.6, 12.11). Only a plain message or a reply
    /// has one.
    pub file: Option<FileRef>,
}

impl Text {
    /// A plain message with this escaped text.
    pub fn new(text: impl Into<String>) -> Text {
        Text {
            text: text.into(),
            target: None,
            file: None,
        }
    }

    /// The text for display, unescaped (3.4).
    pub fn unescaped(&self) -> std::borrow::Cow<'_, str> {
        text::unescape(&self.text)
    }

    /// The uids the text mentions (5.5).
    pub fn mentions(&self) -> Vec<crate::names::Uid> {
        text::mentions(&self.text)
    }
}

/// The message a TEXT line refers to (5.3). A line has at most one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// `reply=<id>`: a reply to message `<id>`.
    Reply(MessageId),
    /// `edit=<id>`: replaces the text of message `<id>`.
    Edit(MessageId),
    /// `react=<id>`: a reaction to message `<id>`.
    React(MessageId),
}

impl Target {
    /// The tag key: `reply`, `edit` or `react`.
    pub fn key(&self) -> &'static str {
        match self {
            Target::Reply(_) => "reply",
            Target::Edit(_) => "edit",
            Target::React(_) => "react",
        }
    }

    /// The message it refers to.
    pub fn id(&self) -> MessageId {
        match self {
            Target::Reply(id) | Target::Edit(id) | Target::React(id) => *id,
        }
    }
}

/// A REPORT line, to a room's owner or moderator (5.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// `box`: the room's mailbox.
    pub mailbox: BoxName,
    /// `target`: the reported message.
    pub target: MessageId,
    /// `context`: up to 10 earlier messages of the room.
    pub context: Vec<MessageId>,
    /// The reason, escaped (3.4), at most 512 bytes; empty if none.
    pub reason: String,
}

/// A PIN line (4.5, 12.14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The pinned identity.
    pub uid: Identity,
    /// The SHA-384 hash of the pinned master key.
    pub master: BlobRef,
    /// The pinned log's origin.
    pub origin: LogOrigin,
    /// The hash of the head record.
    pub head: BlobRef,
    /// The verified mark (12.14).
    pub verified: bool,
}

/// A line that devices ignore (12.9), kept exactly as received so that
/// content can be written back unchanged.
///
/// `Debug` shows the verb and the reason only, since the line may hold a
/// secret.
#[derive(Clone, PartialEq, Eq)]
pub struct IgnoredLine {
    raw: Zeroizing<String>,
    reason: ParseError,
}

impl IgnoredLine {
    /// The line as received, without its LF.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Why it is ignored: [`ParseError::UnknownVerb`] for a verb this
    /// crate does not know, otherwise what is wrong with the line.
    pub fn reason(&self) -> &ParseError {
        &self.reason
    }

    /// The line's verb in upper case, if it has one.
    pub fn verb(&self) -> Option<String> {
        Line::parse(&self.raw)
            .ok()
            .map(|l| l.verb_upper().into_owned())
    }
}

impl fmt::Debug for IgnoredLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IgnoredLine")
            .field("verb", &self.verb())
            .field("reason", &self.reason)
            .finish()
    }
}

/// Every verb of 12.9's table, in upper case.
pub const VERBS: &[&str] = &[
    "TEXT",
    "DELETE",
    "TYPING",
    "REPORT",
    "CHALLENGE",
    "ANSWER",
    "ATTEST",
    "REVEAL",
    "RESYNC",
    "REFETCH",
    "READ",
    "BLOCK",
    "UNBLOCK",
    "RECORD",
    "ALERT",
    "RECORDS",
    "SIGNINGKEY",
    "BACKUPKEY",
    "WANT",
    "TRANSFER",
    "SERVERS",
    "PIN",
];

impl ContentLine {
    /// Parses one line, without its LF, strictly: a line that devices
    /// would ignore is an error. [`Content::parse`] keeps such lines as
    /// [`ContentLine::Ignored`] instead.
    ///
    /// Errors: [`ParseError::UnknownVerb`] for a verb not in 12.9's
    /// table; `TooLong` for a value over a limit; `ControlChar` for a
    /// control character other than TAB; `BadSyntax` for anything else.
    pub fn parse(raw: &str) -> Result<ContentLine, ParseError> {
        let line = Line::parse(raw)?;
        let verb = line.verb_upper();
        let tags = line.tags();
        let p = line.params();
        Ok(match &*verb {
            "TEXT" => ContentLine::Text(parse_text(tags, p)?),
            "DELETE" => ContentLine::Delete { id: last(p)? },
            "TYPING" => {
                p.end()?;
                ContentLine::Typing
            }
            "REPORT" => ContentLine::Report(parse_report(tags, p)?),
            "CHALLENGE" => {
                let mut p = p;
                let leaf = number_u32(&mut p)?;
                ContentLine::Challenge {
                    leaf,
                    ciphertext: last(p)?,
                }
            }
            "ANSWER" => {
                let mut p = p;
                let leaf = number_u32(&mut p)?;
                ContentLine::Answer {
                    leaf,
                    mac: last(p)?,
                }
            }
            "ATTEST" => {
                let mut p = p;
                let period = number_u32(&mut p)?;
                let period_key = tok(&mut p)?;
                let certificate = tok(&mut p)?;
                let attestation = tok(&mut p)?;
                ContentLine::Attest {
                    period,
                    period_key,
                    certificate,
                    attestation,
                    pseudonym: last(p)?,
                }
            }
            "REVEAL" => {
                let mut p = p;
                let period = number_u32(&mut p)?;
                ContentLine::Reveal {
                    period,
                    seed: last(p)?,
                }
            }
            "RESYNC" => {
                let mut p = p;
                let first = p.token()?;
                match p.opt_token()? {
                    None => ContentLine::Resync {
                        mailbox: None,
                        seq: first.parse()?,
                    },
                    Some(seq) => {
                        p.end()?;
                        ContentLine::Resync {
                            mailbox: Some(first.parse()?),
                            seq: seq.parse()?,
                        }
                    }
                }
            }
            "LEAVE" => ContentLine::Leave { mailbox: last(p)? },
            "REFETCH" => ContentLine::Refetch(last(p)?),
            "READ" => {
                let mut p = p;
                let mailbox = tok(&mut p)?;
                let seq = tok(&mut p)?;
                ContentLine::Read {
                    mailbox,
                    seq,
                    check: last(p)?,
                }
            }
            "BLOCK" => ContentLine::Block(last(p)?),
            "UNBLOCK" => ContentLine::Unblock(last(p)?),
            "RECORD" => ContentLine::Record(last(p)?),
            "ALERT" => ContentLine::Alert(last(p)?),
            "RECORDS" => {
                let mut first = p;
                match first.opt_token()? {
                    None => ContentLine::Records(None),
                    Some("-") => {
                        first.end()?;
                        ContentLine::Records(Some(Vec::new()))
                    }
                    Some(_) => ContentLine::Records(Some(rest(p)?)),
                }
            }
            "SIGNINGKEY" => ContentLine::SigningKey(last(p)?),
            "BACKUPKEY" => {
                let mut p = p;
                let generation = number_u32(&mut p)?;
                ContentLine::BackupKey {
                    generation,
                    key: last(p)?,
                }
            }
            "WANT" => parse_want(p)?,
            "TRANSFER" => ContentLine::Transfer(last(p)?),
            "SERVERS" => {
                let hosts: Vec<ServerAddr> = rest(p)?;
                if hosts.is_empty() {
                    return Err(bad("SERVERS lists at least one server"));
                }
                if hosts
                    .iter()
                    .enumerate()
                    .any(|(i, h)| hosts[..i].contains(h))
                {
                    return Err(bad("SERVERS lists each server once"));
                }
                ContentLine::Servers(hosts)
            }
            "PIN" => {
                let mut p = p;
                let uid = tok(&mut p)?;
                let master = tok(&mut p)?;
                let origin = tok(&mut p)?;
                let head = tok(&mut p)?;
                let verified = parse_yes_no(p.token()?)?;
                p.end()?;
                ContentLine::Pin(Pin {
                    uid,
                    master,
                    origin,
                    head,
                    verified,
                })
            }
            _ => return Err(ParseError::UnknownVerb(verb.into_owned())),
        })
    }

    /// Parses one line as [`Content::parse`] does: a line that does not
    /// parse becomes [`ContentLine::Ignored`].
    fn parse_or_ignore(raw: &str) -> ContentLine {
        ContentLine::parse(raw).unwrap_or_else(|reason| {
            ContentLine::Ignored(IgnoredLine {
                raw: Zeroizing::new(raw.to_owned()),
                reason,
            })
        })
    }

    /// The verb, in upper case, or `None` for an ignored line.
    pub fn verb(&self) -> Option<&'static str> {
        Some(match self {
            ContentLine::Text(_) => "TEXT",
            ContentLine::Delete { .. } => "DELETE",
            ContentLine::Typing => "TYPING",
            ContentLine::Report(_) => "REPORT",
            ContentLine::Challenge { .. } => "CHALLENGE",
            ContentLine::Answer { .. } => "ANSWER",
            ContentLine::Attest { .. } => "ATTEST",
            ContentLine::Reveal { .. } => "REVEAL",
            ContentLine::Resync { .. } => "RESYNC",
            ContentLine::Leave { .. } => "LEAVE",
            ContentLine::Refetch(_) => "REFETCH",
            ContentLine::Read { .. } => "READ",
            ContentLine::Block(_) => "BLOCK",
            ContentLine::Unblock(_) => "UNBLOCK",
            ContentLine::Record(_) => "RECORD",
            ContentLine::Alert(_) => "ALERT",
            ContentLine::Records(_) => "RECORDS",
            ContentLine::SigningKey(_) => "SIGNINGKEY",
            ContentLine::BackupKey { .. } => "BACKUPKEY",
            ContentLine::Want { .. } => "WANT",
            ContentLine::Transfer(_) => "TRANSFER",
            ContentLine::Servers(_) => "SERVERS",
            ContentLine::Pin(_) => "PIN",
            ContentLine::Ignored(_) => return None,
        })
    }

    /// Writes the line, without its LF, in canonical form. An ignored line
    /// is written as it was received.
    ///
    /// The line is checked by parsing it back: it fails with that parse's
    /// error, or `BadSyntax` if it parses to a different value, as for a
    /// TEXT line with a file and an `edit` tag, or a name not in lower
    /// case. A parsed line never fails.
    pub fn to_line(&self) -> Result<String, ParseError> {
        let ContentLine::Ignored(ignored) = self else {
            let mut b = Line::builder(self.verb().unwrap_or_default());
            self.write(&mut b);
            let line = b.build()?.to_string();
            return if ContentLine::parse(&line)? == *self {
                Ok(line)
            } else {
                Err(bad("line is not in canonical form"))
            };
        };
        Ok(ignored.raw.to_string())
    }

    /// Writes the tags and parameters after the verb.
    fn write(&self, b: &mut LineBuilder) {
        match self {
            ContentLine::Text(text) => write_text(text, b),
            ContentLine::Delete { id } => {
                b.token(id);
            }
            ContentLine::Typing | ContentLine::Ignored(_) => {}
            ContentLine::Report(report) => {
                b.tag("box", report.mailbox).tag("target", report.target);
                if !report.context.is_empty() {
                    b.tag("context", join(&report.context, ","));
                }
                b.text(&report.reason);
            }
            ContentLine::Challenge { leaf, ciphertext } => {
                b.token(leaf).token(ciphertext);
            }
            ContentLine::Answer { leaf, mac } => {
                b.token(leaf).token(mac);
            }
            ContentLine::Attest {
                period,
                period_key,
                certificate,
                attestation,
                pseudonym,
            } => {
                b.token(period)
                    .token(period_key)
                    .token(certificate)
                    .token(attestation)
                    .token(pseudonym);
            }
            ContentLine::Reveal { period, seed } => {
                b.token(period).token(seed);
            }
            ContentLine::Resync { mailbox, seq } => {
                if let Some(mailbox) = mailbox {
                    b.token(mailbox);
                }
                b.token(seq);
            }
            ContentLine::Leave { mailbox } => {
                b.token(mailbox);
            }
            ContentLine::Read {
                mailbox,
                seq,
                check,
            } => {
                b.token(mailbox).token(seq).token(check);
            }
            ContentLine::Block(target) | ContentLine::Unblock(target) => {
                b.token(target);
            }
            ContentLine::Refetch(hash) | ContentLine::Record(hash) | ContentLine::Alert(hash) => {
                b.token(hash);
            }
            ContentLine::Records(None) => {}
            ContentLine::Records(Some(hashes)) if hashes.is_empty() => {
                b.token("-");
            }
            ContentLine::Records(Some(hashes)) => {
                for hash in hashes {
                    b.token(hash);
                }
            }
            ContentLine::SigningKey(seed) => {
                b.token(seed);
            }
            ContentLine::BackupKey { generation, key } => {
                b.token(generation).token(key);
            }
            ContentLine::Want {
                mailbox,
                after,
                before,
            } => {
                b.token(mailbox).token(after);
                match before {
                    Some(before) => b.token(before),
                    None => b.token("-"),
                };
            }
            ContentLine::Transfer(transfer) => {
                b.token(transfer);
            }
            ContentLine::Servers(hosts) => {
                for host in hosts {
                    b.token(host);
                }
            }
            ContentLine::Pin(pin) => {
                b.token(&pin.uid)
                    .token(pin.master)
                    .token(&pin.origin)
                    .token(pin.head)
                    .token(yes_no(pin.verified));
            }
        }
    }

    /// Whether the line has something to show (a TEXT, DELETE or REPORT
    /// line), which makes a device challenge an unconfirmed sender in a
    /// pairwise group (12.10).
    pub fn is_shown(&self) -> bool {
        matches!(
            self,
            ContentLine::Text(_) | ContentLine::Delete { .. } | ContentLine::Report(_)
        )
    }

    /// Whether the line counts in `place` (12.9's table, 8.1, 4.2, 5.8).
    /// Devices ignore it otherwise.
    ///
    /// - Ignored lines never count.
    /// - A live message counts only for TYPING, and TYPING only in a live
    ///   message (5.2, 8.1).
    /// - TEXT, DELETE and TYPING count in any conversation.
    /// - REPORT counts only in a direct conversation with another
    ///   identity.
    /// - CHALLENGE and ANSWER count only where `confirm` is `pairwise`,
    ///   and ATTEST and REVEAL only where it is `epochal`.
    /// - `RESYNC <seq>` counts only in direct conversations and private
    ///   rooms, and `RESYNC <box> <seq>` only in the conversation with
    ///   yourself (12.7). Public rooms resync by external commit instead.
    /// - LEAVE counts only in the conversation with yourself (6.1).
    /// - REFETCH counts only in direct conversations and private rooms
    ///   (12.14). Public rooms have no key checks.
    /// - READ, BLOCK, UNBLOCK, RECORD, ALERT, RECORDS, SIGNINGKEY,
    ///   BACKUPKEY, WANT, TRANSFER, SERVERS and PIN count only in the
    ///   conversation with yourself.
    /// - From a guest's leaf, only REPORT counts in a direct conversation
    ///   (4.2, 5.8). Guests have no attestation key and no logged device,
    ///   so their CHALLENGE, ANSWER, ATTEST and REVEAL lines never count
    ///   (12.10).
    ///
    /// The rest is up to the device: roles and room settings (6.2, 6.3),
    /// and that the lines of the conversation with yourself come from a
    /// confirmed leaf of its own identity (12.9).
    pub fn allowed_in(&self, place: Place) -> bool {
        use Conversation::*;
        if matches!(self, ContentLine::Ignored(_))
            || place.live != matches!(self, ContentLine::Typing)
        {
            return false;
        }
        if place.guest {
            // Guests send REPORT lines in report conversations, and
            // TEXT, DELETE and TYPING in public rooms (4.2, 5.8, 6.2).
            return match place.conversation {
                Direct => matches!(self, ContentLine::Report(_)),
                PublicRoom => matches!(
                    self,
                    ContentLine::Text(_) | ContentLine::Delete { .. } | ContentLine::Typing
                ),
                WithYourself | PrivateRoom(_) => false,
            };
        }
        match self {
            ContentLine::Text(_) | ContentLine::Delete { .. } | ContentLine::Typing => true,
            ContentLine::Report(_) => place.conversation == Direct,
            ContentLine::Challenge { .. } | ContentLine::Answer { .. } => {
                place.conversation.confirm() == ConfirmMode::Pairwise
            }
            ContentLine::Attest { .. } | ContentLine::Reveal { .. } => {
                place.conversation.confirm() == ConfirmMode::Epochal
            }
            ContentLine::Resync { mailbox: None, .. } | ContentLine::Refetch(_) => {
                matches!(place.conversation, Direct | PrivateRoom(_))
            }
            ContentLine::Resync {
                mailbox: Some(_), ..
            }
            | ContentLine::Leave { .. }
            | ContentLine::Read { .. }
            | ContentLine::Block(_)
            | ContentLine::Unblock(_)
            | ContentLine::Record(_)
            | ContentLine::Alert(_)
            | ContentLine::Records(_)
            | ContentLine::SigningKey(_)
            | ContentLine::BackupKey { .. }
            | ContentLine::Want { .. }
            | ContentLine::Transfer(_)
            | ContentLine::Servers(_)
            | ContentLine::Pin(_) => place.conversation == WithYourself,
            ContentLine::Ignored(_) => false,
        }
    }
}

impl FromStr for ContentLine {
    type Err = ParseError;

    /// Same as [`ContentLine::parse`].
    fn from_str(s: &str) -> Result<ContentLine, ParseError> {
        ContentLine::parse(s)
    }
}

impl From<Text> for ContentLine {
    fn from(text: Text) -> ContentLine {
        ContentLine::Text(text)
    }
}

impl From<Report> for ContentLine {
    fn from(report: Report) -> ContentLine {
        ContentLine::Report(report)
    }
}

impl From<Pin> for ContentLine {
    fn from(pin: Pin) -> ContentLine {
        ContentLine::Pin(pin)
    }
}

fn join<T: fmt::Display>(items: &[T], sep: &str) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(sep)
}

/// Reads every remaining token as a `T`.
fn rest<T: FromStr<Err = ParseError>>(mut p: Params<'_>) -> Result<Vec<T>, ParseError> {
    let mut out = Vec::new();
    while let Some(value) = opt_tok(&mut p)? {
        out.push(value);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// TEXT (5.3, 5.6, 12.9)

fn parse_text(tags: &Tags, p: Params<'_>) -> Result<Text, ParseError> {
    let mut target = None;
    for (key, make) in [
        ("reply", Target::Reply as fn(MessageId) -> Target),
        ("edit", Target::Edit),
        ("react", Target::React),
    ] {
        if let Some(id) = parse_tag(tags, key)? {
            if target.is_some() {
                return Err(bad("TEXT has at most one of reply, edit and react"));
            }
            target = Some(make(id));
        }
    }
    let text = p.text();
    if text::is_blank(text) {
        return Err(bad("TEXT must not be empty"));
    }
    let max = match target {
        Some(Target::React(_)) => MAX_REACTION_LEN,
        _ => MAX_TEXT_LEN,
    };
    limit(text, max)?;
    // Only a plain message or a reply shares a file (5.3).
    let file = match target {
        None | Some(Target::Reply(_)) => parse_file(tags),
        Some(Target::Edit(_) | Target::React(_)) => None,
    };
    Ok(Text {
        text: text.to_owned(),
        target,
        file,
    })
}

/// The file of a TEXT line's tags, if `file`, `file-key` and `file-hash`
/// are all present and valid (12.9). An invalid `file-type` or
/// `file-size` is left out: they are only shown before the download, and
/// a device never trusts them (12.11).
fn parse_file(tags: &Tags) -> Option<FileRef> {
    let get = |key| tags.get(key);
    Some(FileRef {
        url: get("file")?.parse().ok()?,
        key: get("file-key")?.parse().ok()?,
        hash: get("file-hash")?.parse().ok()?,
        media_type: get("file-type").and_then(|t| t.parse().ok()),
        size: get("file-size").and_then(|s| crate::types::parse_u64(s).ok()),
    })
}

fn write_text(text: &Text, b: &mut LineBuilder) {
    if let Some(target) = &text.target {
        b.tag(target.key(), target.id());
    }
    if let Some(file) = &text.file {
        b.tag("file", &file.url).tag("file-key", &file.key);
        if let Some(media_type) = &file.media_type {
            b.tag("file-type", media_type);
        }
        if let Some(size) = file.size {
            b.tag("file-size", size);
        }
        b.tag("file-hash", file.hash);
    }
    b.text(&text.text);
}

// ---------------------------------------------------------------------------
// REPORT (5.8)

fn parse_report(tags: &Tags, p: Params<'_>) -> Result<Report, ParseError> {
    let mailbox = required_tag(tags, "box")?;
    let target = required_tag(tags, "target")?;
    let context = match tag_value(tags, "context")? {
        None => Vec::new(),
        Some(ids) => {
            let ids = ids
                .split(',')
                .map(str::parse)
                .collect::<Result<Vec<MessageId>, _>>()?;
            if ids.len() > MAX_REPORT_CONTEXT {
                return Err(ParseError::TooLong);
            }
            ids
        }
    };
    Ok(Report {
        mailbox,
        target,
        context,
        reason: text_max(p, MAX_REASON_LEN)?,
    })
}

// ---------------------------------------------------------------------------
// WANT (12.13)

fn parse_want(mut p: Params<'_>) -> Result<ContentLine, ParseError> {
    let mailbox = tok(&mut p)?;
    let after = number(&mut p)?;
    let before = match p.token()? {
        "-" => None,
        seq => Some(seq.parse::<Seq>()?),
    };
    p.end()?;
    // The posts wanted are those after `after` and before `before`
    // (12.13). A range with none in it asks for nothing, so it is not a
    // valid WANT.
    if before.is_some_and(|b| b.get() <= after.saturating_add(1)) {
        return Err(bad("WANT asks for an empty range"));
    }
    Ok(ContentLine::Want {
        mailbox,
        after,
        before,
    })
}

// ---------------------------------------------------------------------------
// Where lines are allowed (12.9)

/// A kind of conversation, as its conversation extension says (5.1,
/// 12.4), with the `confirm` mode its lines depend on (12.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Conversation {
    /// The conversation with yourself: a direct conversation of one
    /// identity (5.1, 12.13). `confirm` is `pairwise`.
    WithYourself,
    /// A direct conversation between two identities, or a guest's report
    /// conversation (5.1, 5.8). `confirm` is `pairwise`.
    Direct,
    /// A private room, with its `confirm` mode (6.2).
    PrivateRoom(ConfirmMode),
    /// A public room. `confirm` is `epochal`.
    PublicRoom,
}

impl Conversation {
    /// The conversation's `confirm` mode (12.4).
    pub fn confirm(self) -> ConfirmMode {
        match self {
            Conversation::WithYourself | Conversation::Direct => ConfirmMode::Pairwise,
            Conversation::PrivateRoom(confirm) => confirm,
            Conversation::PublicRoom => ConfirmMode::Epochal,
        }
    }
}

/// Where a message's lines arrive, for [`ContentLine::allowed_in`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Place {
    /// The conversation.
    pub conversation: Conversation,
    /// Whether the message was posted with `live=yes` (5.2).
    pub live: bool,
    /// Whether the sender's leaf is a guest's: its credential names a
    /// guest uid (4.2, 12.3).
    pub guest: bool,
}

impl Place {
    /// A stored message from a member who is not a guest.
    pub fn new(conversation: Conversation) -> Place {
        Place {
            conversation,
            live: false,
            guest: false,
        }
    }
}

#[cfg(test)]
mod tests;

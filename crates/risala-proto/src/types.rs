//! Small values shared by commands and server lines: roles (6.3), presence
//! (8.3), guest access and retention (6.2, 10.6), relations (5.3), the
//! `ref` and `cid` tags (3.2, 7.6), settings (6.2, 10.6), push reasons
//! (9.3) and the protocol's length limits.
//!
//! Keywords are case-insensitive (3.5): parsing folds ASCII upper case, and
//! `Display` writes lower case.

use std::borrow::Cow;
use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use crate::error::ParseError;
use crate::line::{is_tag_value, is_token};
use crate::names::Seq;

// ---------------------------------------------------------------------------
// Limits

/// The longest `ref` or `cid` tag value, in bytes (3.2).
pub const MAX_TAG_TOKEN: usize = 64;
/// The fewest characters in a `cid` (7.6).
pub const MIN_CID_CHARS: usize = 16;
/// The longest reaction text, in bytes, escaped (5.3).
pub const MAX_REACTION: usize = 64;
/// The longest room topic, in bytes, escaped (6.2).
pub const MAX_TOPIC: usize = 512;
/// The longest REPORT reason, in bytes, escaped (5.8).
pub const MAX_REPORT_REASON: usize = 512;
/// The longest display name, in bytes, escaped (8.2).
pub const MAX_DISPLAY_NAME: usize = 128;
/// The longest file `get` URL, in bytes (5.6).
pub const MAX_FILE_URL: usize = 512;
/// The longest PUSH ADD `<tag>`, in bytes (9.1).
pub const MAX_PUSH_TAG: usize = 64;
/// The longest PUSH ADD `<url>`, in bytes (9.1).
pub const MAX_PUSH_URL: usize = 512;
/// The longest welcome text, in bytes (4.1, 10.6).
pub const MAX_WELCOME: usize = 512;
/// The number of events HISTORY and RELATED return when `limit` is not
/// given (7.2, 7.3).
pub const DEFAULT_LIMIT: u64 = 50;

// ---------------------------------------------------------------------------
// Numbers and yes/no

/// Parses a non-negative decimal number in canonical form, as used by
/// options and results such as `limit=`, `members`, `hours=` and `size`
/// (3.3). Only ASCII digits, and no leading zeros except for `0` itself.
pub fn parse_u64(s: &str) -> Result<u64, ParseError> {
    let b = s.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::BadSyntax("expected a decimal number"));
    }
    if b.len() > 1 && b[0] == b'0' {
        return Err(ParseError::BadSyntax("a number has no leading zeros"));
    }
    s.parse()
        .map_err(|_| ParseError::BadSyntax("number is out of range"))
}

/// Parses a number of days, at least 1, for the `retention` settings (6.2,
/// 10.6).
fn parse_days(s: &str) -> Result<NonZeroU32, ParseError> {
    let n = parse_u64(s)?;
    let n = u32::try_from(n).map_err(|_| ParseError::BadSyntax("too many days"))?;
    NonZeroU32::new(n).ok_or(ParseError::BadSyntax("retention must be at least 1 day"))
}

/// Parses `yes` or `no`, in any case, as used by `public` (6.2), `guests`
/// (10.6), `purge=` (4.8) and results such as `op=` and `joined=`.
pub fn parse_yes_no(s: &str) -> Result<bool, ParseError> {
    if s.eq_ignore_ascii_case("yes") {
        Ok(true)
    } else if s.eq_ignore_ascii_case("no") {
        Ok(false)
    } else {
        Err(ParseError::BadSyntax("expected yes or no"))
    }
}

/// Writes a flag as `yes` or `no` (6.2, 8.5, 10.6).
pub fn yes_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

/// Checks a free-form keyword token: not empty, no space or TAB, no control
/// characters. Folds it to lower case.
fn keyword_token(s: &str, what: &'static str) -> Result<String, ParseError> {
    if s.is_empty() || s.chars().any(|c| c == ' ' || c.is_control()) {
        Err(ParseError::BadSyntax(what))
    } else {
        Ok(s.to_ascii_lowercase())
    }
}

// ---------------------------------------------------------------------------
// Keyword enums

/// Defines a `Copy` enum of fixed, case-insensitive keywords.
macro_rules! keywords {
    (
        $(#[$meta:meta])*
        pub enum $ty:ident {
            $( $(#[$vmeta:meta])* $var:ident = $word:literal, )+
        }
        error = $err:literal;
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $ty {
            $( $(#[$vmeta])* $var, )+
        }

        impl $ty {
            /// Every value, in the order listed above.
            pub const ALL: &'static [$ty] = &[$($ty::$var),+];

            /// The keyword as written on the wire (3.5: keywords are lower case).
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $ty::$var => $word, )+
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<$ty, ParseError> {
                $( if s.eq_ignore_ascii_case($word) {
                    return Ok($ty::$var);
                } )+
                Err(ParseError::BadSyntax($err))
            }
        }
    };
}

keywords! {
    /// A role in a room (6.3). The order is by rank: `Member < Mod < Owner`.
    pub enum Role {
        /// `member`: can send messages and manage their own.
        Member = "member",
        /// `mod`: can also delete messages, set the topic and moderate.
        Mod = "mod",
        /// `owner`: can do everything, including changing roles.
        Owner = "owner",
    }
    error = "a role is owner, mod or member";
}

impl Role {
    /// Whether this role may moderate: delete others' messages, set the
    /// topic, INVITE, KICK, BAN, UNBAN and BANS (6.3).
    pub fn can_moderate(self) -> bool {
        self >= Role::Mod
    }
}

keywords! {
    /// The `guests` setting of a room (6.2). The order is by access:
    /// `None < Read < Write`.
    pub enum GuestAccess {
        /// `none`: guests cannot join or read.
        None = "none",
        /// `read`: guests may join and read, but not send.
        Read = "read",
        /// `write`: guests may also send. The default.
        Write = "write",
    }
    error = "guests is none, read or write";
}

impl GuestAccess {
    /// Whether guests may join and read the room (6.2, 7.2).
    pub fn allows_read(self) -> bool {
        self >= GuestAccess::Read
    }

    /// Whether guests may send messages, reactions and typing
    /// notifications (6.2, 6.3).
    pub fn allows_write(self) -> bool {
        self == GuestAccess::Write
    }
}

impl Default for GuestAccess {
    /// `write`, the default for new rooms (6.2).
    fn default() -> GuestAccess {
        GuestAccess::Write
    }
}

keywords! {
    /// The `<reason>` of a NOTIFY push (9.2, 9.3).
    pub enum PushReason {
        /// `dm`: a message in a direct conversation.
        Dm = "dm",
        /// `mention`: a mention in a room.
        Mention = "mention",
        /// `reply`: a reply to one of the user's messages.
        Reply = "reply",
        /// `read`: the unread count went down.
        Read = "read",
    }
    error = "a push reason is dm, mention, reply or read";
}

/// The `<reason>` of a NOTIFY line as received (9.3): a [`PushReason`],
/// or a reason from a later version of the protocol. Gateways forward a
/// NOTIFY with an unknown reason unchanged, and apps treat it as new
/// activity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NotifyReason {
    /// A reason this crate knows.
    Known(PushReason),
    /// Any other reason: one token, folded to lower case.
    Other(String),
}

impl NotifyReason {
    /// The reason as written on the wire (9.3).
    pub fn as_str(&self) -> &str {
        match self {
            NotifyReason::Known(reason) => reason.as_str(),
            NotifyReason::Other(reason) => reason,
        }
    }

    /// The known reason, if it is one.
    pub fn known(&self) -> Option<PushReason> {
        match self {
            NotifyReason::Known(reason) => Some(*reason),
            NotifyReason::Other(_) => None,
        }
    }
}

impl From<PushReason> for NotifyReason {
    fn from(reason: PushReason) -> NotifyReason {
        NotifyReason::Known(reason)
    }
}

impl fmt::Display for NotifyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NotifyReason {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<NotifyReason, ParseError> {
        if let Ok(reason) = s.parse::<PushReason>() {
            return Ok(NotifyReason::Known(reason));
        }
        if !is_token(s) {
            return Err(ParseError::BadSyntax("a push reason is one token"));
        }
        if s.len() > MAX_TAG_TOKEN {
            return Err(ParseError::TooLong);
        }
        Ok(NotifyReason::Other(s.to_ascii_lowercase()))
    }
}

/// The `role=` result of `INFO <room>` (6.2): a [`Role`], or `none` for
/// someone who is neither a member nor holds a role. `InfoRole(None)` is
/// `none`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InfoRole(pub Option<Role>);

impl InfoRole {
    /// The keyword as written on the wire (6.2).
    pub const fn as_str(self) -> &'static str {
        match self.0 {
            Some(role) => role.as_str(),
            None => "none",
        }
    }
}

impl fmt::Display for InfoRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InfoRole {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<InfoRole, ParseError> {
        if s.eq_ignore_ascii_case("none") {
            Ok(InfoRole(None))
        } else {
            s.parse()
                .map(|role| InfoRole(Some(role)))
                .map_err(|_| ParseError::BadSyntax("a role is owner, mod, member or none"))
        }
    }
}

impl From<Option<Role>> for InfoRole {
    fn from(role: Option<Role>) -> InfoRole {
        InfoRole(role)
    }
}

impl From<Role> for InfoRole {
    fn from(role: Role) -> InfoRole {
        InfoRole(Some(role))
    }
}

// ---------------------------------------------------------------------------
// Presence

/// A presence value (8.3). Future versions may add values, so unknown ones
/// are kept in [`Presence::Other`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Presence {
    /// `online`: the user has at least one open connection.
    Online,
    /// `offline`: the user has no open connection.
    Offline,
    /// A value this crate does not know. Always lower case, never empty,
    /// and never contains spaces.
    Other(String),
}

impl Presence {
    /// The value as written on the wire (8.3).
    pub fn as_str(&self) -> &str {
        match self {
            Presence::Online => "online",
            Presence::Offline => "offline",
            Presence::Other(value) => value,
        }
    }

    /// Whether a client should show the user as online. Clients show an
    /// unknown value as online (8.3).
    pub fn shows_online(&self) -> bool {
        !matches!(self, Presence::Offline)
    }
}

impl fmt::Display for Presence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Presence {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Presence, ParseError> {
        let value = keyword_token(s, "presence must be one token")?;
        Ok(match value.as_str() {
            "online" => Presence::Online,
            "offline" => Presence::Offline,
            _ => Presence::Other(value),
        })
    }
}

// ---------------------------------------------------------------------------
// Retention

/// A room's `retention` setting (6.2): `server`, or a number of days.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum RoomRetention {
    /// `server`: follow the server's retention period. The default.
    #[default]
    Server,
    /// Delete events older than this many days. At least 1.
    Days(NonZeroU32),
}

impl RoomRetention {
    /// The period that applies to the room, given the server's: whichever
    /// is shorter (7.5). `None` means events are kept forever.
    pub fn effective(self, server: ServerRetention) -> Option<NonZeroU32> {
        match (self, server.days()) {
            (RoomRetention::Days(room), Some(server)) => Some(room.min(server)),
            (RoomRetention::Days(room), None) => Some(room),
            (RoomRetention::Server, server) => server,
        }
    }
}

impl fmt::Display for RoomRetention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoomRetention::Server => f.write_str("server"),
            RoomRetention::Days(days) => write!(f, "{days}"),
        }
    }
}

impl FromStr for RoomRetention {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<RoomRetention, ParseError> {
        if s.eq_ignore_ascii_case("server") {
            Ok(RoomRetention::Server)
        } else {
            parse_days(s).map(RoomRetention::Days)
        }
    }
}

/// The server's retention period (8.5, 10.6): `forever`, or a number of
/// days.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServerRetention {
    /// `forever`: events are never deleted for age.
    Forever,
    /// Delete events older than this many days. At least 1.
    Days(NonZeroU32),
}

impl ServerRetention {
    /// The number of days, or `None` for `forever` (10.6).
    pub fn days(self) -> Option<NonZeroU32> {
        match self {
            ServerRetention::Forever => None,
            ServerRetention::Days(days) => Some(days),
        }
    }
}

impl fmt::Display for ServerRetention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerRetention::Forever => f.write_str("forever"),
            ServerRetention::Days(days) => write!(f, "{days}"),
        }
    }
}

impl FromStr for ServerRetention {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<ServerRetention, ParseError> {
        if s.eq_ignore_ascii_case("forever") {
            Ok(ServerRetention::Forever)
        } else {
            parse_days(s).map(ServerRetention::Days)
        }
    }
}

// ---------------------------------------------------------------------------
// Relations

/// The relation a message has to an earlier one, from its `reply`, `edit`
/// or `react` tag (5.3). A message carries at most one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Relation {
    /// `reply=<seq>`: a reply to message `<seq>`.
    Reply(Seq),
    /// `edit=<seq>`: replaces the text of message `<seq>`.
    Edit(Seq),
    /// `react=<seq>`: a reaction to message `<seq>`.
    React(Seq),
}

impl Relation {
    /// The tag keys that carry a relation (3.2, 5.3).
    pub const KEYS: [&'static str; 3] = ["reply", "edit", "react"];

    /// The relation for tag `key` with target `seq`, or `None` if `key` is
    /// not a relation tag. Tag keys are lower case (3.1).
    pub fn new(key: &str, seq: Seq) -> Option<Relation> {
        match key {
            "reply" => Some(Relation::Reply(seq)),
            "edit" => Some(Relation::Edit(seq)),
            "react" => Some(Relation::React(seq)),
            _ => None,
        }
    }

    /// Parses the tag `key=value`. `Ok(None)` if `key` is not a relation
    /// tag; an error if it is one but `value` is not a seq (5.3).
    pub fn from_tag(key: &str, value: Option<&str>) -> Result<Option<Relation>, ParseError> {
        if !Relation::KEYS.contains(&key) {
            return Ok(None);
        }
        let seq = value
            .ok_or(ParseError::BadSyntax("a relation tag needs a seq"))?
            .parse()?;
        Ok(Relation::new(key, seq))
    }

    /// The tag key: `reply`, `edit` or `react` (5.3).
    pub fn key(self) -> &'static str {
        match self {
            Relation::Reply(_) => "reply",
            Relation::Edit(_) => "edit",
            Relation::React(_) => "react",
        }
    }

    /// The target message (5.3).
    pub fn seq(self) -> Seq {
        match self {
            Relation::Reply(seq) | Relation::Edit(seq) | Relation::React(seq) => seq,
        }
    }
}

impl fmt::Display for Relation {
    /// Writes the tag, `key=seq`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key(), self.seq())
    }
}

impl FromStr for Relation {
    type Err = ParseError;

    /// Parses the tag, `key=seq`.
    fn from_str(s: &str) -> Result<Relation, ParseError> {
        let (key, value) = s
            .split_once('=')
            .ok_or(ParseError::BadSyntax("a relation is key=seq"))?;
        Relation::from_tag(key, Some(value))?
            .ok_or(ParseError::BadSyntax("a relation is reply, edit or react"))
    }
}

// ---------------------------------------------------------------------------
// Tokens

/// `%x21-3A / %x3C-7E / UTF8-nonascii`, a character of a tag value (3.1).
fn is_tag_value_char(c: char) -> bool {
    !c.is_ascii() || (('\x21'..='\x7e').contains(&c) && c != ';')
}

/// Checks a tag value of at most `MAX_TAG_TOKEN` bytes.
fn tag_token(s: &str) -> Result<(), ParseError> {
    if s.is_empty() || !s.chars().all(is_tag_value_char) {
        Err(ParseError::BadSyntax(
            "a tag value has no space, ';' or control characters",
        ))
    } else if s.len() > MAX_TAG_TOKEN {
        Err(ParseError::TooLong)
    } else {
        Ok(())
    }
}

/// Defines a case-sensitive token newtype over a `String`.
macro_rules! token_type {
    ($(#[$meta:meta])* $ty:ident, $check:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty(String);

        impl $ty {
            /// The token as written on the wire (3.1).
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<$ty, ParseError> {
                let check: fn(&str) -> Result<(), ParseError> = $check;
                check(s)?;
                Ok($ty(s.to_owned()))
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

token_type!(
    /// The value of a `ref` tag (3.2, 3.6): 1 to 64 bytes of tag-value
    /// characters, so no space, `;` or control characters. Case-sensitive
    /// and opaque.
    Ref,
    tag_token
);

token_type!(
    /// The value of a `cid` tag (7.6): a random token of at least 16
    /// characters and at most 64 bytes of tag-value characters.
    /// Case-sensitive and opaque.
    ///
    /// A cid shorter than 16 characters is rejected as `BadSyntax`, since
    /// 7.6 defines the token as at least that long.
    Cid,
    |s| {
        tag_token(s)?;
        if s.chars().count() < MIN_CID_CHARS {
            return Err(ParseError::BadSyntax("a cid has at least 16 characters"));
        }
        Ok(())
    }
);

token_type!(
    /// The `<tag>` of PUSH ADD, PUSH lines and NOTIFY (9.1, 9.3): an opaque
    /// token of 1 to 64 bytes, without spaces or control characters.
    /// Case-sensitive.
    PushTag,
    |s| {
        if s.is_empty() || s.chars().any(|c| c == ' ' || c.is_control()) {
            Err(ParseError::BadSyntax("a push tag is one token"))
        } else if s.len() > MAX_PUSH_TAG {
            Err(ParseError::TooLong)
        } else {
            Ok(())
        }
    }
);

// ---------------------------------------------------------------------------
// Settings

/// Splits `key value...` at the first space. The value may be empty.
fn split_setting(s: &str) -> (&str, &str) {
    s.split_once(' ').unwrap_or((s, ""))
}

/// Writes `key` and, if it is not empty, a space and `value`.
fn write_setting(f: &mut fmt::Formatter<'_>, key: &str, value: &str) -> fmt::Result {
    if value.is_empty() {
        f.write_str(key)
    } else {
        write!(f, "{key} {value}")
    }
}

/// A room setting, as in `SET <room> <key> <value...>` (6.2).
///
/// Unknown keys are kept in [`RoomSetting::Other`], so that a server can
/// reply `ERR not-supported` rather than `ERR bad-syntax`. A known key with
/// a bad value is a syntax error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RoomSetting {
    /// `topic`: escaped text (3.4) of up to 512 bytes, possibly empty.
    Topic(String),
    /// `public`: `yes` or `no`.
    Public(bool),
    /// `guests`: `none`, `read` or `write`.
    Guests(GuestAccess),
    /// `retention`: `server` or a number of days.
    Retention(RoomRetention),
    /// A key this crate does not know, folded to lower case, with its value
    /// kept as escaped text.
    Other {
        /// The key: one token, lower case.
        key: String,
        /// The value, exactly as received.
        value: String,
    },
}

impl RoomSetting {
    /// Parses a setting from its key token and its value text (6.2). The
    /// key is case-insensitive. The value is the text parameter, still
    /// escaped; keyword values are case-insensitive, and a topic is kept
    /// exactly as given.
    pub fn parse(key: &str, value: &str) -> Result<RoomSetting, ParseError> {
        let key = keyword_token(key, "a setting key is one token")?;
        Ok(match key.as_str() {
            "topic" if value.len() > MAX_TOPIC => return Err(ParseError::TooLong),
            "topic" => RoomSetting::Topic(value.to_owned()),
            "public" => RoomSetting::Public(parse_yes_no(value)?),
            "guests" => RoomSetting::Guests(value.parse()?),
            "retention" => RoomSetting::Retention(value.parse()?),
            _ => RoomSetting::Other {
                key,
                value: value.to_owned(),
            },
        })
    }

    /// The key, in lower case (6.2).
    pub fn key(&self) -> &str {
        match self {
            RoomSetting::Topic(_) => "topic",
            RoomSetting::Public(_) => "public",
            RoomSetting::Guests(_) => "guests",
            RoomSetting::Retention(_) => "retention",
            RoomSetting::Other { key, .. } => key,
        }
    }

    /// The value as written on the wire (6.2).
    pub fn value(&self) -> Cow<'_, str> {
        match self {
            RoomSetting::Topic(topic) => Cow::Borrowed(topic),
            RoomSetting::Public(public) => Cow::Borrowed(yes_no(*public)),
            RoomSetting::Guests(guests) => Cow::Borrowed(guests.as_str()),
            RoomSetting::Retention(retention) => Cow::Owned(retention.to_string()),
            RoomSetting::Other { value, .. } => Cow::Borrowed(value),
        }
    }

    /// Whether this crate knows the key (6.2).
    pub fn is_known(&self) -> bool {
        !matches!(self, RoomSetting::Other { .. })
    }
}

impl fmt::Display for RoomSetting {
    /// Writes `key value`, or just `key` when the value is empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_setting(f, self.key(), &self.value())
    }
}

impl FromStr for RoomSetting {
    type Err = ParseError;

    /// Parses `key value...`, splitting at the first space.
    fn from_str(s: &str) -> Result<RoomSetting, ParseError> {
        let (key, value) = split_setting(s);
        RoomSetting::parse(key, value)
    }
}

/// A server setting, as in `ADMIN SET <key> <value...>` (10.6).
///
/// Unknown keys are kept in [`ServerSetting::Other`], so that a server can
/// reply `ERR not-supported`. A known key with a bad value is a syntax
/// error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ServerSetting {
    /// `guests`: `yes` or `no`, whether guests may connect.
    Guests(bool),
    /// `registration`: `open` (true) or `closed` (false), whether REGISTER
    /// is accepted.
    Registration(bool),
    /// `retention`: `forever` or a number of days.
    Retention(ServerRetention),
    /// `welcome`: escaped text (3.4) for the greeting (4.1), possibly empty.
    Welcome(String),
    /// A key this crate does not know, folded to lower case, with its value
    /// kept as escaped text.
    Other {
        /// The key: one token, lower case.
        key: String,
        /// The value, exactly as received.
        value: String,
    },
}

impl ServerSetting {
    /// Parses a setting from its key token and its value text (10.6). The
    /// key is case-insensitive. The value is the text parameter, still
    /// escaped; keyword values are case-insensitive, and a welcome message
    /// is kept exactly as given.
    pub fn parse(key: &str, value: &str) -> Result<ServerSetting, ParseError> {
        let key = keyword_token(key, "a setting key is one token")?;
        Ok(match key.as_str() {
            "guests" => ServerSetting::Guests(parse_yes_no(value)?),
            "registration" if value.eq_ignore_ascii_case("open") => {
                ServerSetting::Registration(true)
            }
            "registration" if value.eq_ignore_ascii_case("closed") => {
                ServerSetting::Registration(false)
            }
            "registration" => {
                return Err(ParseError::BadSyntax("registration is open or closed"));
            }
            "retention" => ServerSetting::Retention(value.parse()?),
            "welcome" if value.len() > MAX_WELCOME => return Err(ParseError::TooLong),
            "welcome" => ServerSetting::Welcome(value.to_owned()),
            _ => ServerSetting::Other {
                key,
                value: value.to_owned(),
            },
        })
    }

    /// The key, in lower case (10.6).
    pub fn key(&self) -> &str {
        match self {
            ServerSetting::Guests(_) => "guests",
            ServerSetting::Registration(_) => "registration",
            ServerSetting::Retention(_) => "retention",
            ServerSetting::Welcome(_) => "welcome",
            ServerSetting::Other { key, .. } => key,
        }
    }

    /// The value as written on the wire (10.6).
    pub fn value(&self) -> Cow<'_, str> {
        match self {
            ServerSetting::Guests(guests) => Cow::Borrowed(yes_no(*guests)),
            ServerSetting::Registration(true) => Cow::Borrowed("open"),
            ServerSetting::Registration(false) => Cow::Borrowed("closed"),
            ServerSetting::Retention(retention) => Cow::Owned(retention.to_string()),
            ServerSetting::Welcome(welcome) => Cow::Borrowed(welcome),
            ServerSetting::Other { value, .. } => Cow::Borrowed(value),
        }
    }

    /// Whether this crate knows the key (10.6).
    pub fn is_known(&self) -> bool {
        !matches!(self, ServerSetting::Other { .. })
    }
}

impl fmt::Display for ServerSetting {
    /// Writes `key value`, or just `key` when the value is empty.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_setting(f, self.key(), &self.value())
    }
}

impl FromStr for ServerSetting {
    type Err = ParseError;

    /// Parses `key value...`, splitting at the first space.
    fn from_str(s: &str) -> Result<ServerSetting, ParseError> {
        let (key, value) = split_setting(s);
        ServerSetting::parse(key, value)
    }
}

// ---------------------------------------------------------------------------
// URLs and media types (5.6, 9.1)

/// The value of a MSG's `file` tag: a `get` URL from UPLOAD (5.6).
///
/// It uses `https`, contains no `;` and is at most 512 bytes
/// ([`MAX_FILE_URL`]), so that it fits in a tag. The scheme is matched
/// without regard to case; the URL is otherwise kept exactly as given,
/// since only its server can interpret it. A URL over 512 bytes is
/// `TooLong`; anything else that breaks these rules is `BadSyntax`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileUrl(String);

impl FileUrl {
    /// The URL as written on the wire (5.6).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FileUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for FileUrl {
    type Err = ParseError;

    /// Checks the rules for `get` URLs (5.6).
    fn from_str(s: &str) -> Result<FileUrl, ParseError> {
        check_https(s, "a file URL is an https URL")?;
        if !is_tag_value(s) {
            return Err(ParseError::BadSyntax(
                "a file URL has no space, ';' or control characters",
            ));
        }
        if s.len() > MAX_FILE_URL {
            return Err(ParseError::TooLong);
        }
        Ok(FileUrl(s.to_owned()))
    }
}

impl AsRef<str> for FileUrl {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The `<url>` of PUSH ADD and PUSH DEL (9.1): an `https` URL, one token,
/// at most 512 bytes ([`MAX_PUSH_URL`]).
///
/// The scheme is matched without regard to case; the URL is otherwise
/// kept exactly as given. A URL over 512 bytes is `TooLong`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PushUrl(String);

impl PushUrl {
    /// The URL as written on the wire (9.1).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PushUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PushUrl {
    type Err = ParseError;

    /// Checks that `s` is one token starting with `https://` (9.1).
    fn from_str(s: &str) -> Result<PushUrl, ParseError> {
        check_https(s, "a push URL is an https URL")?;
        if !is_token(s) {
            return Err(ParseError::BadSyntax("a push URL is one token"));
        }
        if s.len() > MAX_PUSH_URL {
            return Err(ParseError::TooLong);
        }
        Ok(PushUrl(s.to_owned()))
    }
}

impl AsRef<str> for PushUrl {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Checks that `s` starts with `https://`, in any case, and has something
/// after it.
fn check_https(s: &str, what: &'static str) -> Result<(), ParseError> {
    match s.get(..8) {
        Some(scheme) if scheme.eq_ignore_ascii_case("https://") && s.len() > 8 => Ok(()),
        _ => Err(ParseError::BadSyntax(what)),
    }
}

/// The longest type or subtype of a [`MediaType`], in bytes (RFC 6838,
/// 4.2).
pub const MAX_MEDIA_TYPE_PART: usize = 127;

/// The `<type>` of UPLOAD (5.6): a media type such as `image/png`.
///
/// It is checked loosely, following the `restricted-name` of RFC 6838:
/// `type/subtype`, where each part is 1 to 127 characters of
/// `a-z 0-9 ! # $ & - ^ _ . +` starting with a letter or digit. Media
/// types are case-insensitive, so parsing folds to lower case. Parameters
/// such as `;charset=utf-8` are not allowed: the server echoes the type in
/// the `file-type` tag (5.6), and a tag value cannot contain `;` (3.1).
/// Whether the type is acceptable is up to the server (`ERR forbidden`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MediaType(String);

impl MediaType {
    /// The media type as written on the wire, in lower case (5.6).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The top-level type, the part before the `/`, such as `image` (5.6).
    pub fn top_level(&self) -> &str {
        self.0.split_once('/').map_or("", |(t, _)| t)
    }

    /// The part after the `/`, such as `png` (5.6).
    pub fn subtype(&self) -> &str {
        self.0.split_once('/').map_or("", |(_, s)| s)
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MediaType {
    type Err = ParseError;

    /// Checks `type/subtype` as described on [`MediaType`].
    fn from_str(s: &str) -> Result<MediaType, ParseError> {
        fn part(p: &str) -> Result<bool, ParseError> {
            let b = p.as_bytes();
            let ok = b.first().is_some_and(u8::is_ascii_alphanumeric)
                && b.iter()
                    .all(|&c| c.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&c));
            if !ok {
                return Err(ParseError::BadSyntax("a media type is type/subtype"));
            }
            Ok(b.len() <= MAX_MEDIA_TYPE_PART)
        }
        let (t, sub) = s
            .split_once('/')
            .ok_or(ParseError::BadSyntax("a media type is type/subtype"))?;
        if !(part(t)? & part(sub)?) {
            return Err(ParseError::TooLong);
        }
        Ok(MediaType(s.to_ascii_lowercase()))
    }
}

impl AsRef<str> for MediaType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_reasons() {
        assert_eq!(
            "Mention".parse::<NotifyReason>(),
            Ok(NotifyReason::Known(PushReason::Mention))
        );
        let other: NotifyReason = "Invite".parse().unwrap();
        assert_eq!(other, NotifyReason::Other("invite".into()));
        assert_eq!(other.to_string(), "invite");
        assert_eq!(other.known(), None);
        assert!("a b".parse::<NotifyReason>().is_err());
        assert!("".parse::<NotifyReason>().is_err());
    }

    #[test]
    fn push_url_limit() {
        let base = "https://push.example/n/";
        let fit = format!("{base}{}", "a".repeat(MAX_PUSH_URL - base.len()));
        assert_eq!(fit.parse::<PushUrl>().unwrap().as_str(), fit);
        assert_eq!(
            format!("{fit}a").parse::<PushUrl>(),
            Err(ParseError::TooLong)
        );
        assert!("http://push.example/n/x".parse::<PushUrl>().is_err());
    }

    fn days(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn seq(n: u64) -> Seq {
        Seq::new(n).unwrap()
    }

    fn is_syntax<T: fmt::Debug>(r: Result<T, ParseError>) -> bool {
        matches!(r, Err(ParseError::BadSyntax(_)))
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_u64("0"), Ok(0));
        assert_eq!(parse_u64("50"), Ok(50));
        assert_eq!(parse_u64("18446744073709551615"), Ok(u64::MAX));
        for s in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1.5",
            "18446744073709551616",
            "١",
        ] {
            assert!(is_syntax(parse_u64(s)), "{s:?}");
        }
        assert_eq!(parse_yes_no("yes"), Ok(true));
        assert_eq!(parse_yes_no("No"), Ok(false));
        assert_eq!(parse_yes_no("YES"), Ok(true));
        assert!(is_syntax(parse_yes_no("y")));
        assert!(is_syntax(parse_yes_no("")));
        assert!(is_syntax(parse_yes_no("yes ")));
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn roles() {
        for &role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
            assert_eq!(role.to_string().to_uppercase().parse::<Role>(), Ok(role));
        }
        assert_eq!("Owner".parse::<Role>(), Ok(Role::Owner));
        assert!(is_syntax("none".parse::<Role>()));
        assert!(is_syntax("moderator".parse::<Role>()));
        assert!(is_syntax("".parse::<Role>()));
        assert!(Role::Member < Role::Mod && Role::Mod < Role::Owner);
        assert!(!Role::Member.can_moderate());
        assert!(Role::Mod.can_moderate());
        assert!(Role::Owner.can_moderate());

        assert_eq!("none".parse::<InfoRole>(), Ok(InfoRole(None)));
        assert_eq!("NONE".parse::<InfoRole>(), Ok(InfoRole(None)));
        assert_eq!("mod".parse::<InfoRole>(), Ok(InfoRole(Some(Role::Mod))));
        assert_eq!(InfoRole(None).to_string(), "none");
        assert_eq!(InfoRole::from(Role::Owner).to_string(), "owner");
        assert_eq!(InfoRole::from(None), InfoRole(None));
        assert!(is_syntax("admin".parse::<InfoRole>()));
    }

    #[test]
    fn guest_access() {
        for &g in GuestAccess::ALL {
            assert_eq!(g.to_string().parse::<GuestAccess>(), Ok(g));
        }
        assert_eq!("Read".parse::<GuestAccess>(), Ok(GuestAccess::Read));
        assert!(is_syntax("yes".parse::<GuestAccess>()));
        assert_eq!(GuestAccess::default(), GuestAccess::Write);
        assert!(!GuestAccess::None.allows_read());
        assert!(GuestAccess::Read.allows_read() && !GuestAccess::Read.allows_write());
        assert!(GuestAccess::Write.allows_read() && GuestAccess::Write.allows_write());
    }

    #[test]
    fn push_reasons() {
        for &r in PushReason::ALL {
            assert_eq!(r.to_string().parse::<PushReason>(), Ok(r));
        }
        assert_eq!(PushReason::ALL.len(), 4);
        assert_eq!("DM".parse::<PushReason>(), Ok(PushReason::Dm));
        assert!(is_syntax("edit".parse::<PushReason>()));
    }

    #[test]
    fn presence() {
        assert_eq!("online".parse::<Presence>(), Ok(Presence::Online));
        assert_eq!("Offline".parse::<Presence>(), Ok(Presence::Offline));
        let away: Presence = "Away".parse().unwrap();
        assert_eq!(away, Presence::Other("away".into()));
        assert_eq!(away.to_string(), "away");
        assert!(away.shows_online());
        assert!(Presence::Online.shows_online());
        assert!(!Presence::Offline.shows_online());
        assert!(is_syntax("".parse::<Presence>()));
        assert!(is_syntax("on line".parse::<Presence>()));
        assert!(is_syntax("on\tline".parse::<Presence>()));
    }

    #[test]
    fn retention() {
        assert_eq!("server".parse(), Ok(RoomRetention::Server));
        assert_eq!("SERVER".parse(), Ok(RoomRetention::Server));
        assert_eq!("30".parse(), Ok(RoomRetention::Days(days(30))));
        assert_eq!("1".parse(), Ok(RoomRetention::Days(days(1))));
        assert_eq!(
            "4294967295".parse(),
            Ok(RoomRetention::Days(days(u32::MAX)))
        );
        for s in [
            "0",
            "00",
            "030",
            "-1",
            "4294967296",
            "forever",
            "",
            " 30",
            "30 ",
        ] {
            assert!(is_syntax(s.parse::<RoomRetention>()), "{s:?}");
        }
        assert_eq!(RoomRetention::Days(days(7)).to_string(), "7");
        assert_eq!(RoomRetention::Server.to_string(), "server");
        assert_eq!(RoomRetention::default(), RoomRetention::Server);

        assert_eq!("forever".parse(), Ok(ServerRetention::Forever));
        assert_eq!("Forever".parse(), Ok(ServerRetention::Forever));
        assert_eq!("365".parse(), Ok(ServerRetention::Days(days(365))));
        for s in ["0", "server", "", "07"] {
            assert!(is_syntax(s.parse::<ServerRetention>()), "{s:?}");
        }
        assert_eq!(ServerRetention::Forever.to_string(), "forever");
        assert_eq!(ServerRetention::Days(days(365)).to_string(), "365");

        let forever = ServerRetention::Forever;
        let year = ServerRetention::Days(days(365));
        assert_eq!(RoomRetention::Server.effective(forever), None);
        assert_eq!(RoomRetention::Server.effective(year), Some(days(365)));
        assert_eq!(
            RoomRetention::Days(days(30)).effective(forever),
            Some(days(30))
        );
        assert_eq!(
            RoomRetention::Days(days(30)).effective(year),
            Some(days(30))
        );
        assert_eq!(
            RoomRetention::Days(days(900)).effective(year),
            Some(days(365))
        );
    }

    #[test]
    fn relations() {
        assert_eq!(
            Relation::from_tag("reply", Some("8810")),
            Ok(Some(Relation::Reply(seq(8810))))
        );
        assert_eq!(
            Relation::from_tag("edit", Some("4000")),
            Ok(Some(Relation::Edit(seq(4000))))
        );
        assert_eq!(
            Relation::from_tag("react", Some("1")),
            Ok(Some(Relation::React(seq(1))))
        );
        assert_eq!(Relation::from_tag("file", Some("x")), Ok(None));
        assert_eq!(Relation::from_tag("ref", None), Ok(None));
        assert!(Relation::from_tag("reply", None).is_err());
        assert!(Relation::from_tag("reply", Some("0")).is_err());
        assert!(Relation::from_tag("reply", Some("x")).is_err());
        // Tag keys are lower case by grammar (3.1).
        assert_eq!(Relation::from_tag("Reply", Some("1")), Ok(None));

        let r: Relation = "react=8813".parse().unwrap();
        assert_eq!(r, Relation::React(seq(8813)));
        assert_eq!(r.key(), "react");
        assert_eq!(r.seq(), seq(8813));
        assert_eq!(r.to_string(), "react=8813");
        for s in ["react", "react=", "seq=1", "=1", "reply=01"] {
            assert!(is_syntax(s.parse::<Relation>()), "{s:?}");
        }
        for key in Relation::KEYS {
            assert_eq!(Relation::new(key, seq(5)).unwrap().key(), key);
        }
        assert_eq!(Relation::new("x", seq(5)), None);
    }

    #[test]
    fn refs() {
        for s in ["7", "a", "abc-123", "Mixed:Case", "x=y", "日本", "!~"] {
            assert_eq!(s.parse::<Ref>().unwrap().as_str(), s);
        }
        let max = "r".repeat(64);
        assert_eq!(max.parse::<Ref>().unwrap().to_string(), max);
        assert_eq!("r".repeat(65).parse::<Ref>(), Err(ParseError::TooLong));
        // 64 bytes is the limit, not 64 characters.
        assert_eq!("é".repeat(33).parse::<Ref>(), Err(ParseError::TooLong));
        assert!("é".repeat(32).parse::<Ref>().is_ok());
        for s in ["", "a b", "a;b", "a\tb", "a\x7f", "a\x01", ";"] {
            assert!(is_syntax(s.parse::<Ref>()), "{s:?}");
        }
        // Bad characters win over the length.
        assert!(is_syntax(format!("{} ", "r".repeat(70)).parse::<Ref>()));
    }

    #[test]
    fn cids() {
        let min = "0123456789abcdef";
        assert_eq!(min.parse::<Cid>().unwrap().as_str(), min);
        assert!(is_syntax(min[..15].parse::<Cid>()));
        assert!("ééééééééééééééééé"[..32].parse::<Cid>().is_ok()); // 16 chars, 32 bytes
        let max = "c".repeat(64);
        assert!(max.parse::<Cid>().is_ok());
        assert_eq!("c".repeat(65).parse::<Cid>(), Err(ParseError::TooLong));
        assert!(is_syntax("0123456789abcdef;".parse::<Cid>()));
        assert!(is_syntax("0123456789 abcdef".parse::<Cid>()));
        assert!(is_syntax("".parse::<Cid>()));
    }

    #[test]
    fn push_tags() {
        for s in ["t", "a;b", "Q2xpZW50=", "x".repeat(64).as_str()] {
            assert_eq!(s.parse::<PushTag>().unwrap().as_str(), s);
        }
        assert_eq!("x".repeat(65).parse::<PushTag>(), Err(ParseError::TooLong));
        for s in ["", "a b", "a\tb", "a\x00"] {
            assert!(is_syntax(s.parse::<PushTag>()), "{s:?}");
        }
    }

    #[test]
    fn room_settings() {
        // The SET lines of 1.4.
        let cases = [
            (
                "topic",
                "General chat. Be kind.",
                RoomSetting::Topic("General chat. Be kind.".into()),
            ),
            ("public", "yes", RoomSetting::Public(true)),
            ("guests", "write", RoomSetting::Guests(GuestAccess::Write)),
            (
                "retention",
                "server",
                RoomSetting::Retention(RoomRetention::Server),
            ),
            (
                "retention",
                "30",
                RoomSetting::Retention(RoomRetention::Days(days(30))),
            ),
            ("public", "no", RoomSetting::Public(false)),
        ];
        for (key, value, setting) in cases {
            assert_eq!(RoomSetting::parse(key, value), Ok(setting.clone()));
            assert_eq!(setting.key(), key);
            assert_eq!(setting.value(), value);
            assert!(setting.is_known());
            let line = format!("{key} {value}");
            assert_eq!(setting.to_string(), line);
            assert_eq!(line.parse::<RoomSetting>(), Ok(setting));
        }

        // Keys and keyword values fold; topics are kept exactly.
        assert_eq!(
            RoomSetting::parse("PUBLIC", "Yes"),
            Ok(RoomSetting::Public(true))
        );
        assert_eq!(
            RoomSetting::parse("Topic", "  Two  Spaces\\n"),
            Ok(RoomSetting::Topic("  Two  Spaces\\n".into()))
        );
        assert_eq!(
            RoomSetting::parse("guests", "NONE"),
            Ok(RoomSetting::Guests(GuestAccess::None))
        );

        // An empty topic clears it.
        let empty = RoomSetting::parse("topic", "").unwrap();
        assert_eq!(empty, RoomSetting::Topic(String::new()));
        assert_eq!(empty.to_string(), "topic");
        assert_eq!("topic".parse::<RoomSetting>(), Ok(empty));

        // Topic length.
        assert!(RoomSetting::parse("topic", &"t".repeat(512)).is_ok());
        assert_eq!(
            RoomSetting::parse("topic", &"t".repeat(513)),
            Err(ParseError::TooLong)
        );

        // Known keys with bad values are syntax errors.
        for (key, value) in [
            ("public", "maybe"),
            ("public", ""),
            ("public", "yes "),
            ("guests", "all"),
            ("retention", "0"),
            ("retention", "forever"),
            ("retention", "30 days"),
        ] {
            assert!(is_syntax(RoomSetting::parse(key, value)), "{key} {value}");
        }
        assert!(is_syntax(RoomSetting::parse("", "x")));
        assert!(is_syntax(RoomSetting::parse("a b", "x")));

        // Unknown keys are kept.
        let other = RoomSetting::parse("Slowmode", "10 Seconds").unwrap();
        assert_eq!(
            other,
            RoomSetting::Other {
                key: "slowmode".into(),
                value: "10 Seconds".into()
            }
        );
        assert!(!other.is_known());
        assert_eq!(other.to_string(), "slowmode 10 Seconds");
        assert_eq!("slowmode 10 Seconds".parse::<RoomSetting>(), Ok(other));
    }

    #[test]
    fn server_settings() {
        let cases = [
            ("guests", "yes", ServerSetting::Guests(true)),
            ("guests", "no", ServerSetting::Guests(false)),
            ("registration", "open", ServerSetting::Registration(true)),
            ("registration", "closed", ServerSetting::Registration(false)),
            (
                "retention",
                "forever",
                ServerSetting::Retention(ServerRetention::Forever),
            ),
            (
                "retention",
                "90",
                ServerSetting::Retention(ServerRetention::Days(days(90))),
            ),
            (
                "welcome",
                "Welcome! Be kind.",
                ServerSetting::Welcome("Welcome! Be kind.".into()),
            ),
        ];
        for (key, value, setting) in cases {
            assert_eq!(ServerSetting::parse(key, value), Ok(setting.clone()));
            assert_eq!(setting.key(), key);
            assert_eq!(setting.value(), value);
            assert!(setting.is_known());
            let line = format!("{key} {value}");
            assert_eq!(setting.to_string(), line);
            assert_eq!(line.parse::<ServerSetting>(), Ok(setting));
        }
        assert_eq!(
            ServerSetting::parse("REGISTRATION", "Open"),
            Ok(ServerSetting::Registration(true))
        );
        assert_eq!(
            ServerSetting::parse("welcome", ""),
            Ok(ServerSetting::Welcome(String::new()))
        );
        for (key, value) in [
            ("guests", "write"),
            ("registration", "yes"),
            ("registration", ""),
            ("retention", "server"),
            ("retention", "0"),
        ] {
            assert!(is_syntax(ServerSetting::parse(key, value)), "{key} {value}");
        }
        let other = ServerSetting::parse("motd", "hi").unwrap();
        assert_eq!(
            other,
            ServerSetting::Other {
                key: "motd".into(),
                value: "hi".into()
            }
        );
        assert!(!other.is_known());
    }
}

//! One line as tags, verb and parameters (SPEC 3.1-3.3).
//!
//! This layer works on raw strings. It knows the grammar of 3.1, the tag
//! rules of 3.2 and how 3.3 splits parameters into tokens, options and
//! text, but not what any verb means. The typed layers in
//! [`command`](crate::command) and [`server`](crate::server) build on it.
//!
//! Parsing:
//!
//! ```
//! use risala_proto::line::Line;
//!
//! let line = Line::parse("@ref=7 history #general after=8811 limit=2")?;
//! assert!(line.verb_is("HISTORY"));
//! assert_eq!(line.tags().get("ref"), Some("7"));
//! let mut params = line.params();
//! assert_eq!(params.token()?, "#general");
//! let options = params.options()?;
//! assert_eq!(options.get("limit"), Some("2"));
//! # Ok::<(), risala_proto::error::ParseError>(())
//! ```
//!
//! Serialising:
//!
//! ```
//! use risala_proto::line::Line;
//!
//! let line = Line::builder("MSG")
//!     .tag("reply", 8810)
//!     .token("#general")
//!     .text("hi there")
//!     .build()?;
//! assert_eq!(line.to_string(), "@reply=8810 MSG #general hi there");
//! # Ok::<(), risala_proto::error::ParseError>(())
//! ```
//!
//! Decisions where the spec leaves room:
//!
//! - **Tag keys** must be lower case, as the grammar says (`a-z 0-9 -`).
//!   Upper-case tag keys are rejected, not folded. Tags are metadata
//!   written by programs, and 3.5's case-insensitivity covers names and
//!   verbs, not tag keys. Rejecting keeps `@ref=1;REF=2` from being
//!   ambiguous.
//! - **TAB** is allowed only in text. A TAB where a token is read, either
//!   inside a token or between tokens, is a syntax error: 3.3 says tokens
//!   are characters other than space and TAB, and only spaces separate
//!   them.
//! - **Runs of spaces** are accepted between the tags and the verb, and
//!   between tokens (3.3). Spaces at the end of the token part are
//!   accepted too. Text starts after exactly one space following the
//!   last token read, and the verb counts as a token, so `NOTICE  hi` has
//!   the text ` hi`. A line must not start with a space.
//! - **Option keys** are folded to lower case. They may contain any token
//!   character except `=`; their values may contain `=` and may be empty.
//!   The typed layers decide which keys and values they accept.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use crate::error::ParseError;
use crate::frame::{check_line, is_forbidden_control};

/// Whether `key` is a valid tag key: `1*( a-z / DIGIT / "-" )` (3.1).
pub fn is_tag_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `value` is a valid tag value (3.1): one or more characters
/// from %x21-3A, %x3C-7E or non-ASCII. So no space, no `;`, no control
/// characters, but `=` is allowed.
pub fn is_tag_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| matches!(c, '\u{21}'..='\u{3A}' | '\u{3C}'..='\u{7E}') || !c.is_ascii())
}

/// Whether `verb` is a valid verb: `1*ALPHA` (3.1).
pub fn is_verb(verb: &str) -> bool {
    !verb.is_empty() && verb.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Whether `token` is a valid token (3.3): one or more characters other
/// than space, TAB and the control characters of 2.3.
pub fn is_token(token: &str) -> bool {
    !token.is_empty()
        && !token
            .chars()
            .any(|c| c == ' ' || c == '\t' || is_forbidden_control(c))
}

/// The tags of a line (3.2): ordered, with unique keys, each with an
/// optional value.
///
/// Order is kept so that a parsed line displays back as it was, but it
/// carries no meaning (3.2). Equality compares order too.
///
/// [`Display`](fmt::Display) writes the tags without the leading `@`, so
/// an empty `Tags` displays as the empty string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Tags {
    entries: Vec<(String, Option<String>)>,
}

impl Tags {
    /// No tags.
    pub fn new() -> Self {
        Tags::default()
    }

    /// Parses `tag *( ";" tag )` (3.1), without the leading `@`.
    ///
    /// Fails with `BadSyntax` on an empty tag, a bad key (including upper
    /// case), an empty or bad value, or a repeated key.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let mut tags = Tags::new();
        for tag in s.split(';') {
            let (key, value) = match tag.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (tag, None),
            };
            check_tag(key, value)?;
            if tags.has(key) {
                return Err(ParseError::BadSyntax("repeated tag"));
            }
            tags.entries
                .push((key.to_owned(), value.map(str::to_owned)));
        }
        Ok(tags)
    }

    /// The value of tag `key`. `None` if the tag is absent or has no
    /// value; use [`has`](Self::has) or [`entry`](Self::entry) to tell
    /// these apart.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entry(key).flatten()
    }

    /// `None` if tag `key` is absent, `Some(None)` if it is present
    /// without a value (such as `deleted`, 5.4), and `Some(Some(value))`
    /// otherwise.
    pub fn entry(&self, key: &str) -> Option<Option<&str>> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_deref())
    }

    /// Whether tag `key` is present, with or without a value.
    pub fn has(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// Sets tag `key`, checking the grammar of 3.1. An existing tag with
    /// the same key is replaced in place; a new one goes at the end.
    pub fn insert(&mut self, key: &str, value: Option<&str>) -> Result<(), ParseError> {
        check_tag(key, value)?;
        let value = value.map(str::to_owned);
        match self.entries.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key.to_owned(), value)),
        }
        Ok(())
    }

    /// Removes tag `key`. Returns whether it was present.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(k, _)| k != key);
        self.entries.len() != before
    }

    /// Keeps only the tags for which `keep(key, value)` is true. For
    /// example, a server keeps only `reply`, `edit`, `react` and `file`
    /// from a client command (3.2).
    pub fn retain(&mut self, mut keep: impl FnMut(&str, Option<&str>) -> bool) {
        self.entries.retain(|(k, v)| keep(k, v.as_deref()));
    }

    /// The tags in order, as `(key, value)`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_deref()))
    }

    /// The number of tags.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no tags.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn check_tag(key: &str, value: Option<&str>) -> Result<(), ParseError> {
    if !is_tag_key(key) {
        return Err(ParseError::BadSyntax("bad tag key"));
    }
    if let Some(value) = value {
        if !is_tag_value(value) {
            return Err(ParseError::BadSyntax("bad tag value"));
        }
    }
    Ok(())
}

impl fmt::Display for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (key, value)) in self.entries.iter().enumerate() {
            if i > 0 {
                f.write_str(";")?;
            }
            f.write_str(key)?;
            if let Some(value) = value {
                write!(f, "={value}")?;
            }
        }
        Ok(())
    }
}

impl FromStr for Tags {
    type Err = ParseError;

    /// Same as [`Tags::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Tags::parse(s)
    }
}

/// One line: tags, verb and raw parameters (3.1).
///
/// A `Line` is always valid: it comes from [`Line::parse`] or
/// [`LineBuilder::build`], and its tags check themselves.
///
/// [`Display`](fmt::Display) writes the line without a line ending. For
/// any line in canonical form (single spaces, no trailing space after a
/// verb without parameters), parsing and displaying gives back the same
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Line {
    tags: Tags,
    verb: String,
    params: String,
}

impl Line {
    /// Parses one line, without its line ending (3.1).
    ///
    /// Checks the characters of 2.3 too, so it is safe on any `&str`.
    /// Errors: `ControlChar` for control characters (including CR and
    /// LF), `BadSyntax` for an empty line, a line starting with a space,
    /// bad tags, a missing verb or a verb that is not `1*ALPHA`.
    ///
    /// The verb is kept as written. The parameters are everything after
    /// the single space that follows the verb, unchanged; read them with
    /// [`params`](Self::params).
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        check_line(s)?;
        if s.is_empty() {
            return Err(ParseError::BadSyntax("empty line"));
        }
        let mut rest = s;
        let mut tags = Tags::new();
        if let Some(after_at) = rest.strip_prefix('@') {
            let (raw_tags, after) = after_at
                .split_once(' ')
                .ok_or(ParseError::BadSyntax("missing verb"))?;
            tags = Tags::parse(raw_tags)?;
            rest = after.trim_start_matches(' ');
            if rest.is_empty() {
                return Err(ParseError::BadSyntax("missing verb"));
            }
        }
        let (verb, params) = match rest.find(|c: char| !c.is_ascii_alphabetic()) {
            None => (rest, ""),
            Some(0) if rest.starts_with(' ') => {
                return Err(ParseError::BadSyntax("line starts with a space"));
            }
            Some(0) => return Err(ParseError::BadSyntax("bad verb")),
            Some(i) => match rest[i..].strip_prefix(' ') {
                Some(params) => (&rest[..i], params),
                None => return Err(ParseError::BadSyntax("bad verb")),
            },
        };
        Ok(Line {
            tags,
            verb: verb.to_owned(),
            params: params.to_owned(),
        })
    }

    /// Starts building a line with this verb (3.1). The verb is written in
    /// upper case. A verb that is not `1*ALPHA` makes
    /// [`build`](LineBuilder::build) fail.
    pub fn builder(verb: &str) -> LineBuilder {
        LineBuilder::new(verb)
    }

    /// The tags.
    pub fn tags(&self) -> &Tags {
        &self.tags
    }

    /// The tags, for changing them. [`Tags`] checks what is inserted, so
    /// the line stays valid.
    pub fn tags_mut(&mut self) -> &mut Tags {
        &mut self.tags
    }

    /// The verb, exactly as written. Compare with
    /// [`verb_is`](Self::verb_is), since verbs are case-insensitive (3.1).
    pub fn verb(&self) -> &str {
        &self.verb
    }

    /// The verb in upper case, for matching. Borrows when the verb is
    /// already upper case, as it is on every line a server sends.
    pub fn verb_upper(&self) -> Cow<'_, str> {
        if self.verb.bytes().any(|b| b.is_ascii_lowercase()) {
            Cow::Owned(self.verb.to_ascii_uppercase())
        } else {
            Cow::Borrowed(&self.verb)
        }
    }

    /// Whether the verb is `verb`, ignoring ASCII case (3.1).
    pub fn verb_is(&self, verb: &str) -> bool {
        self.verb.eq_ignore_ascii_case(verb)
    }

    /// A cursor over the parameters, which splits them as in 3.3.
    pub fn params(&self) -> Params<'_> {
        Params::new(&self.params)
    }

    /// The parameters, raw: everything after the single space that
    /// follows the verb.
    pub fn raw_params(&self) -> &str {
        &self.params
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.tags.is_empty() {
            write!(f, "@{} ", self.tags)?;
        }
        f.write_str(&self.verb)?;
        if !self.params.is_empty() {
            write!(f, " {}", self.params)?;
        }
        Ok(())
    }
}

impl FromStr for Line {
    type Err = ParseError;

    /// Same as [`Line::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Line::parse(s)
    }
}

/// A cursor that splits a line's parameters into tokens, options and text
/// (3.3).
///
/// Read the verb's tokens with [`token`](Self::token) and
/// [`opt_token`](Self::opt_token), then finish with exactly one of
/// [`text`](Self::text), [`options`](Self::options) or
/// [`end`](Self::end). Those three take the cursor by value, since each
/// reads to the end of the line.
///
/// ```
/// use risala_proto::line::Line;
///
/// let line = Line::parse("MSG #general  hi there")?;
/// let mut params = line.params();
/// assert_eq!(params.token()?, "#general");
/// assert_eq!(params.text(), " hi there");
/// # Ok::<(), risala_proto::error::ParseError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params<'a> {
    rest: &'a str,
    /// Whether a token has been read, so that text starts after one space.
    after_token: bool,
}

impl<'a> Params<'a> {
    /// A cursor over `params`, which starts right after the space that
    /// follows the verb. Usually made with [`Line::params`].
    pub fn new(params: &'a str) -> Self {
        Params {
            rest: params,
            after_token: false,
        }
    }

    /// Reads the next token, skipping spaces before it. Fails with
    /// `BadSyntax` if there is none, or if it runs into a TAB.
    pub fn token(&mut self) -> Result<&'a str, ParseError> {
        self.opt_token()?
            .ok_or(ParseError::BadSyntax("missing parameter"))
    }

    /// Reads the next token if there is one, skipping spaces before it.
    /// Returns `Ok(None)`, and reads nothing, if only spaces are left.
    /// Fails with `BadSyntax` if it runs into a TAB.
    pub fn opt_token(&mut self) -> Result<Option<&'a str>, ParseError> {
        let start = self.rest.trim_start_matches(' ');
        if start.is_empty() {
            return Ok(None);
        }
        let end = start.find([' ', '\t']).unwrap_or(start.len());
        if end == 0 || start[end..].starts_with('\t') {
            return Err(ParseError::BadSyntax("TAB between tokens"));
        }
        self.rest = &start[end..];
        self.after_token = true;
        Ok(Some(&start[..end]))
    }

    /// The text: the rest of the line after exactly one space following
    /// the last token read (3.3), or all of it if no token was read.
    /// Further leading spaces belong to the text. It may be empty.
    pub fn text(self) -> &'a str {
        if self.after_token {
            self.rest.strip_prefix(' ').unwrap_or(self.rest)
        } else {
            // The space after the verb is already gone.
            self.rest
        }
    }

    /// Reads the remaining tokens as options (3.3), each `key=value`.
    /// Keys are folded to lower case. Fails with `BadSyntax` on a token
    /// without `=`, an empty key, a repeated key or a TAB.
    pub fn options(mut self) -> Result<Options, ParseError> {
        let mut options = Options::default();
        while let Some(token) = self.opt_token()? {
            let (key, value) = token
                .split_once('=')
                .ok_or(ParseError::BadSyntax("expected an option"))?;
            if key.is_empty() {
                return Err(ParseError::BadSyntax("empty option key"));
            }
            let key = key.to_ascii_lowercase();
            if options.get(&key).is_some() {
                return Err(ParseError::BadSyntax("repeated option"));
            }
            options.entries.push((key, value.to_owned()));
        }
        Ok(options)
    }

    /// Checks that nothing but spaces is left. Fails with `BadSyntax`
    /// otherwise, which is how a command with too many tokens is
    /// rejected (3.3).
    pub fn end(self) -> Result<(), ParseError> {
        if self.rest.bytes().all(|b| b == b' ') {
            Ok(())
        } else {
            Err(ParseError::BadSyntax("too many parameters"))
        }
    }

    /// What is left to read, unchanged.
    pub fn remaining(&self) -> &'a str {
        self.rest
    }
}

/// The options of a line, from [`Params::options`] (3.3): `key=value`
/// pairs in order, with unique keys folded to lower case.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Options {
    entries: Vec<(String, String)>,
}

impl Options {
    /// The value of option `key`, which must be given in lower case.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Fails with `BadSyntax` if any option is not in `known`. Servers
    /// reject unknown options on a command (3.3); clients ignore unknown
    /// result values on OK (3.6) and should not call this.
    pub fn reject_unknown(&self, known: &[&str]) -> Result<(), ParseError> {
        if self
            .entries
            .iter()
            .all(|(k, _)| known.contains(&k.as_str()))
        {
            Ok(())
        } else {
            Err(ParseError::BadSyntax("unknown option"))
        }
    }

    /// The options in order, as `(key, value)`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The number of options.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no options.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Builds a [`Line`] for sending (3.1-3.3). Made with [`Line::builder`].
///
/// Add tags at any point, then the tokens, then either options or text.
/// Methods take `&mut self` so that both chaining and conditional
/// additions work:
///
/// ```
/// use risala_proto::line::Line;
///
/// let reference: Option<&str> = Some("7");
/// let mut b = Line::builder("OK");
/// if let Some(r) = reference {
///     b.tag("ref", r);
/// }
/// b.option("more", 1);
/// assert_eq!(b.build()?.to_string(), "@ref=7 OK more=1");
/// # Ok::<(), risala_proto::error::ParseError>(())
/// ```
///
/// Each value is checked as it is added. The first problem is kept and
/// returned by [`build`](Self::build), so a builder never produces an
/// invalid line. Values from this crate's validated types never fail.
#[derive(Debug, Clone)]
pub struct LineBuilder {
    tags: Tags,
    verb: String,
    params: String,
    stage: Stage,
    error: Option<ParseError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Tokens,
    Options,
    Text,
}

impl LineBuilder {
    fn new(verb: &str) -> Self {
        let error = (!is_verb(verb)).then_some(ParseError::BadSyntax("bad verb"));
        LineBuilder {
            tags: Tags::new(),
            verb: verb.to_ascii_uppercase(),
            params: String::new(),
            stage: Stage::Tokens,
            error,
        }
    }

    fn fail(&mut self, error: ParseError) -> &mut Self {
        self.error.get_or_insert(error);
        self
    }

    fn push_param(&mut self, s: &str) {
        if !self.params.is_empty() {
            self.params.push(' ');
        }
        self.params.push_str(s);
    }

    /// Adds tag `key=value`, replacing an earlier tag with the same key.
    pub fn tag(&mut self, key: &str, value: impl fmt::Display) -> &mut Self {
        let value = value.to_string();
        if let Err(e) = self.tags.insert(key, Some(&value)) {
            return self.fail(e);
        }
        self
    }

    /// Adds tag `key` without a value, such as `deleted` (5.4).
    pub fn flag(&mut self, key: &str) -> &mut Self {
        if let Err(e) = self.tags.insert(key, None) {
            return self.fail(e);
        }
        self
    }

    /// Adds a token (3.3). It must be non-empty and contain no space,
    /// TAB or control character, and must come before options and text.
    pub fn token(&mut self, token: impl fmt::Display) -> &mut Self {
        let token = token.to_string();
        if self.stage > Stage::Tokens {
            return self.fail(ParseError::BadSyntax("token after options or text"));
        }
        if !is_token(&token) {
            return self.fail(ParseError::BadSyntax("bad token"));
        }
        self.push_param(&token);
        self
    }

    /// Adds option `key=value` (3.3). The key must be non-empty, without
    /// `=`, and is written in lower case. Both must be token characters;
    /// the value may be empty. Options cannot be mixed with text.
    pub fn option(&mut self, key: &str, value: impl fmt::Display) -> &mut Self {
        let value = value.to_string();
        if self.stage > Stage::Options {
            return self.fail(ParseError::BadSyntax("option after text"));
        }
        if !is_token(key) || key.contains('=') {
            return self.fail(ParseError::BadSyntax("bad option key"));
        }
        if !value.is_empty() && !is_token(&value) {
            return self.fail(ParseError::BadSyntax("bad option value"));
        }
        self.stage = Stage::Options;
        let option = format!("{}={value}", key.to_ascii_lowercase());
        self.push_param(&option);
        self
    }

    /// Sets the text, which ends the line (3.3). It must contain no
    /// control characters other than TAB; spaces, including leading ones,
    /// are kept. Empty text leaves out the space before it. Text cannot be
    /// combined with options or set twice.
    pub fn text(&mut self, text: &str) -> &mut Self {
        if self.stage != Stage::Tokens {
            return self.fail(ParseError::BadSyntax("text set twice or after options"));
        }
        if let Err(e) = check_line(text) {
            return self.fail(e);
        }
        self.stage = Stage::Text;
        if !text.is_empty() {
            if self.params.is_empty() {
                // Right after the verb's space: keep leading spaces as is.
                self.params.push_str(text);
            } else {
                self.params.push(' ');
                self.params.push_str(text);
            }
        }
        self
    }

    /// Returns the line, or the first problem found while building it.
    /// Line length is not checked; use
    /// [`check_line_len`](crate::frame::check_line_len) on the result.
    pub fn build(&self) -> Result<Line, ParseError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        Ok(Line {
            tags: self.tags.clone(),
            verb: self.verb.clone(),
            params: self.params.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bad(s: &'static str) -> ParseError {
        ParseError::BadSyntax(s)
    }

    fn round_trip(s: &str) -> Line {
        let line = Line::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"));
        assert_eq!(line.to_string(), s);
        line
    }

    // ---- predicates ----

    #[test]
    fn tag_key_grammar() {
        for good in ["ref", "t", "file-type", "x-foo", "a1", "-", "0"] {
            assert!(is_tag_key(good), "{good}");
        }
        for b in ["", "Ref", "REF", "a_b", "a.b", "a=b", "a b", "ä"] {
            assert!(!is_tag_key(b), "{b}");
        }
    }

    #[test]
    fn tag_value_grammar() {
        for good in [
            "7",
            "a=b",
            "https://x.org/f?a=b&c=d",
            "~sam",
            "👋",
            "!",
            "~",
            ":",
            "<",
        ] {
            assert!(is_tag_value(good), "{good}");
        }
        for b in ["", " ", "a;b", "a b", "a\tb", "\u{7f}", "\u{1}"] {
            assert!(!is_tag_value(b), "{b:?}");
        }
    }

    #[test]
    fn verb_grammar() {
        assert!(is_verb("MSG"));
        assert!(is_verb("msg"));
        assert!(is_verb("Msg"));
        for b in ["", "MSG1", "MS-G", "ÄB", "M G"] {
            assert!(!is_verb(b), "{b}");
        }
    }

    #[test]
    fn token_grammar() {
        assert!(is_token("#general"));
        assert!(is_token("a=b"));
        assert!(is_token("👋"));
        for b in ["", " ", "a b", "a\tb", "a\nb", "\u{7f}"] {
            assert!(!is_token(b), "{b:?}");
        }
    }

    // ---- Tags ----

    #[test]
    fn tags_parse() {
        let tags = Tags::parse("seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;deleted").unwrap();
        assert_eq!(tags.len(), 4);
        assert_eq!(tags.get("seq"), Some("8813"));
        assert_eq!(tags.get("t"), Some("2026-11-06T15:41:02.377Z"));
        assert_eq!(tags.get("deleted"), None);
        assert!(tags.has("deleted"));
        assert_eq!(tags.entry("deleted"), Some(None));
        assert_eq!(tags.entry("seq"), Some(Some("8813")));
        assert_eq!(tags.entry("nope"), None);
        assert!(!tags.has("nope"));
        assert_eq!(
            tags.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            ["seq", "t", "from", "deleted"]
        );
        assert_eq!(
            tags.to_string(),
            "seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;deleted"
        );
    }

    #[test]
    fn tag_value_may_contain_equals() {
        let tags: Tags = "file=https://f.example.org/x?a=b".parse().unwrap();
        assert_eq!(tags.get("file"), Some("https://f.example.org/x?a=b"));
    }

    #[test]
    fn tags_parse_errors() {
        let cases = [
            ("", "bad tag key"),
            (";", "bad tag key"),
            ("a;", "bad tag key"),
            (";a", "bad tag key"),
            ("a;;b", "bad tag key"),
            ("=1", "bad tag key"),
            ("REF=7", "bad tag key"),
            ("Ref", "bad tag key"),
            ("a_b=1", "bad tag key"),
            ("ref=", "bad tag value"),
            ("ref=a\tb", "bad tag value"),
            ("ref=a b", "bad tag value"),
            ("ref=\u{7f}", "bad tag value"),
            ("ref=1;ref=2", "repeated tag"),
            ("deleted;deleted", "repeated tag"),
            ("ref=1;ref", "repeated tag"),
        ];
        for (input, why) in cases {
            assert_eq!(Tags::parse(input), Err(bad(why)), "{input:?}");
        }
    }

    #[test]
    fn tags_insert_remove_retain() {
        let mut tags = Tags::new();
        assert!(tags.is_empty());
        assert_eq!(tags.to_string(), "");
        tags.insert("seq", Some("1")).unwrap();
        tags.insert("deleted", None).unwrap();
        tags.insert("from", Some("~sam")).unwrap();
        // Replacing keeps the position.
        tags.insert("seq", Some("2")).unwrap();
        assert_eq!(tags.to_string(), "seq=2;deleted;from=~sam");
        tags.insert("deleted", Some("x")).unwrap();
        assert_eq!(tags.to_string(), "seq=2;deleted=x;from=~sam");

        assert_eq!(tags.insert("Seq", Some("1")), Err(bad("bad tag key")));
        assert_eq!(tags.insert("", None), Err(bad("bad tag key")));
        assert_eq!(tags.insert("a", Some("")), Err(bad("bad tag value")));
        assert_eq!(tags.insert("a", Some("x;y")), Err(bad("bad tag value")));
        assert_eq!(tags.len(), 3);

        assert!(tags.remove("deleted"));
        assert!(!tags.remove("deleted"));
        assert_eq!(tags.to_string(), "seq=2;from=~sam");

        let mut client: Tags = "ref=7;reply=8810;cid=abc;file=https://x".parse().unwrap();
        client.retain(|k, _| matches!(k, "reply" | "edit" | "react" | "file"));
        assert_eq!(client.to_string(), "reply=8810;file=https://x");
        client.retain(|_, v| v == Some("8810"));
        assert_eq!(client.to_string(), "reply=8810");
    }

    // ---- Line::parse ----

    #[test]
    fn parse_simple() {
        let line = round_trip("LIST");
        assert!(line.tags().is_empty());
        assert_eq!(line.verb(), "LIST");
        assert_eq!(line.raw_params(), "");

        let line = round_trip("MSG #general hi there");
        assert_eq!(line.verb(), "MSG");
        assert_eq!(line.raw_params(), "#general hi there");
    }

    #[test]
    fn parse_tags() {
        let line = round_trip("@ref=7 history #general after=8811 limit=2");
        assert_eq!(line.tags().get("ref"), Some("7"));
        assert_eq!(line.verb(), "history");
        assert_eq!(line.raw_params(), "#general after=8811 limit=2");

        let line = round_trip(
            "@seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;reply=8810;deleted MSG #general",
        );
        assert!(line.tags().has("deleted"));
        assert_eq!(line.raw_params(), "#general");

        let line = round_trip("@ref=7 OK");
        assert_eq!(line.raw_params(), "");
    }

    #[test]
    fn verb_case() {
        let line = round_trip("msg #a hi");
        assert_eq!(line.verb(), "msg");
        assert_eq!(line.verb_upper(), "MSG");
        assert!(matches!(line.verb_upper(), Cow::Owned(_)));
        assert!(line.verb_is("MSG"));
        assert!(line.verb_is("msg"));
        assert!(line.verb_is("mSg"));
        assert!(!line.verb_is("MS"));
        assert!(!line.verb_is("MSGS"));

        let line = round_trip("MSG #a hi");
        assert!(matches!(line.verb_upper(), Cow::Borrowed("MSG")));
        assert_ne!(Line::parse("msg").unwrap(), Line::parse("MSG").unwrap());
    }

    #[test]
    fn parse_lenient_spacing() {
        // Runs of spaces between tags and verb.
        let line = Line::parse("@ref=7   OK").unwrap();
        assert_eq!(line.verb(), "OK");
        assert_eq!(line.to_string(), "@ref=7 OK");

        // Extra spaces after the verb belong to the params, and so to
        // the text of a verb that takes only text.
        let line = Line::parse("NOTICE  hi").unwrap();
        assert_eq!(line.raw_params(), " hi");
        assert_eq!(line.params().text(), " hi");
        assert_eq!(line.to_string(), "NOTICE  hi");

        // A trailing space after a bare verb is dropped on display.
        let line = Line::parse("LIST ").unwrap();
        assert_eq!(line.raw_params(), "");
        assert_eq!(line.to_string(), "LIST");
        assert_eq!(line, Line::parse("LIST").unwrap());
    }

    #[test]
    fn parse_errors() {
        let cases: &[(&str, ParseError)] = &[
            ("", bad("empty line")),
            (" ", bad("line starts with a space")),
            (" MSG #a hi", bad("line starts with a space")),
            ("\tMSG", bad("bad verb")),
            ("@", bad("missing verb")),
            ("@ref=7", bad("missing verb")),
            ("@ref=7 ", bad("missing verb")),
            ("@ref=7   ", bad("missing verb")),
            ("@ MSG", bad("bad tag key")),
            ("@ref= MSG", bad("bad tag value")),
            ("@REF=7 MSG", bad("bad tag key")),
            ("@ref=1;ref=2 MSG", bad("repeated tag")),
            ("@ref=7;  MSG", bad("bad tag key")),
            ("@ref=a\tb MSG", bad("bad tag value")),
            ("@ref=7 @x=1 MSG", bad("bad verb")),
            ("@ref=7 1MSG", bad("bad verb")),
            ("MSG1 #a", bad("bad verb")),
            ("MS-G", bad("bad verb")),
            ("MSG\t#a", bad("bad verb")),
            ("MSG:", bad("bad verb")),
            ("ÄMSG", bad("bad verb")),
            ("MSGÄ", bad("bad verb")),
            ("#general hi", bad("bad verb")),
            ("123", bad("bad verb")),
            ("MSG #a hi\r", ParseError::ControlChar),
            ("MSG #a hi\nPING", ParseError::ControlChar),
            ("MSG #a \u{0}", ParseError::ControlChar),
            ("@ref=\u{1b} MSG", ParseError::ControlChar),
            ("\u{7f}", ParseError::ControlChar),
        ];
        for (input, want) in cases {
            assert_eq!(Line::parse(input).as_ref(), Err(want), "{input:?}");
        }
    }

    #[test]
    fn parse_allows_tab_and_unicode_in_params() {
        let line = round_trip("MSG #a col1\tcol2 👋 مرحبا");
        let mut p = line.params();
        assert_eq!(p.token().unwrap(), "#a");
        assert_eq!(p.text(), "col1\tcol2 👋 مرحبا");
    }

    #[test]
    fn from_str_matches_parse() {
        let a: Line = "PING abc".parse().unwrap();
        assert_eq!(a, Line::parse("PING abc").unwrap());
        assert!("".parse::<Line>().is_err());
    }

    #[test]
    fn tags_mut_keeps_line_valid() {
        let mut line = Line::parse("@reply=8810;ref=7 msg #general hi").unwrap();
        line.tags_mut().retain(|k, _| k == "reply");
        line.tags_mut().insert("seq", Some("8813")).unwrap();
        assert!(line.tags_mut().insert("bad key", None).is_err());
        assert_eq!(line.to_string(), "@reply=8810;seq=8813 msg #general hi");
        line.tags_mut().retain(|_, _| false);
        assert_eq!(line.to_string(), "msg #general hi");
    }

    // ---- Params ----

    #[test]
    fn params_tokens_and_text() {
        let line = Line::parse("MSG #general hi there").unwrap();
        let mut p = line.params();
        assert_eq!(p.token(), Ok("#general"));
        assert_eq!(p.remaining(), " hi there");
        assert_eq!(p.text(), "hi there");
    }

    #[test]
    fn params_text_keeps_extra_leading_spaces() {
        let line = Line::parse("MSG #general   hi  there ").unwrap();
        let mut p = line.params();
        assert_eq!(p.token(), Ok("#general"));
        assert_eq!(p.text(), "  hi  there ");
    }

    #[test]
    fn params_runs_of_spaces_between_tokens() {
        let line = Line::parse("ROLE  #general   bob@example.net  mod  ").unwrap();
        let mut p = line.params();
        assert_eq!(p.token(), Ok("#general"));
        assert_eq!(p.token(), Ok("bob@example.net"));
        assert_eq!(p.token(), Ok("mod"));
        assert_eq!(p.opt_token(), Ok(None));
        assert_eq!(p.end(), Ok(()));
    }

    #[test]
    fn params_empty_text() {
        // Text may be empty, with or without its space.
        for s in ["PART #general", "PART #general "] {
            let line = Line::parse(s).unwrap();
            let mut p = line.params();
            assert_eq!(p.token(), Ok("#general"));
            assert_eq!(p.text(), "", "{s:?}");
        }
        let line = Line::parse("QUIT").unwrap();
        assert_eq!(line.params().text(), "");
        let line = Line::parse("QUIT bye now").unwrap();
        assert_eq!(line.params().text(), "bye now");
    }

    #[test]
    fn params_missing_token() {
        let line = Line::parse("JOIN").unwrap();
        let mut p = line.params();
        assert_eq!(p.token(), Err(bad("missing parameter")));
        let line = Line::parse("JOIN   ").unwrap();
        let mut p = line.params();
        assert_eq!(p.token(), Err(bad("missing parameter")));
        assert_eq!(p.opt_token(), Ok(None));
    }

    #[test]
    fn params_opt_token() {
        let line = Line::parse("PING abc").unwrap();
        let mut p = line.params();
        assert_eq!(p.opt_token(), Ok(Some("abc")));
        assert_eq!(p.opt_token(), Ok(None));
        assert_eq!(p.end(), Ok(()));

        let line = Line::parse("PING").unwrap();
        let mut p = line.params();
        assert_eq!(p.opt_token(), Ok(None));
        assert_eq!(p.end(), Ok(()));
    }

    #[test]
    fn params_tab_in_token_part() {
        for s in ["JOIN #a\tb", "JOIN \t#a", "JOIN #a \t", "JOIN #a\t"] {
            let line = Line::parse(s).unwrap();
            let mut p = line.params();
            let r = p.token().and_then(|_| p.token());
            assert_eq!(r, Err(bad("TAB between tokens")), "{s:?}");
        }
        // end() also refuses a TAB.
        let line = Line::parse("JOIN #a \t").unwrap();
        let mut p = line.params();
        p.token().unwrap();
        assert_eq!(p.end(), Err(bad("too many parameters")));
        // A TAB in text is fine.
        let line = Line::parse("PART #a \tbye").unwrap();
        let mut p = line.params();
        p.token().unwrap();
        assert_eq!(p.text(), "\tbye");
    }

    #[test]
    fn params_end() {
        let line = Line::parse("JOIN #general extra").unwrap();
        let mut p = line.params();
        p.token().unwrap();
        assert_eq!(p.end(), Err(bad("too many parameters")));
        assert_eq!(Line::parse("LIST").unwrap().params().end(), Ok(()));
        assert_eq!(
            Line::parse("LIST x").unwrap().params().end(),
            Err(bad("too many parameters"))
        );
    }

    #[test]
    fn params_options() {
        let line = Line::parse("@ref=7 history #general after=8811 limit=2").unwrap();
        let mut p = line.params();
        assert_eq!(p.token(), Ok("#general"));
        let o = p.options().unwrap();
        assert_eq!(o.len(), 2);
        assert!(!o.is_empty());
        assert_eq!(o.get("after"), Some("8811"));
        assert_eq!(o.get("limit"), Some("2"));
        assert_eq!(o.get("before"), None);
        assert_eq!(
            o.iter().collect::<Vec<_>>(),
            [("after", "8811"), ("limit", "2")]
        );
        assert_eq!(o.reject_unknown(&["after", "before", "limit"]), Ok(()));
        assert_eq!(o.reject_unknown(&["after"]), Err(bad("unknown option")));
    }

    #[test]
    fn options_fold_keys_and_keep_values() {
        let line =
            Line::parse("OK PUT=https://f.example.org/u?a=b Get=X  head=8812 note=").unwrap();
        let o = line.params().options().unwrap();
        assert_eq!(o.get("put"), Some("https://f.example.org/u?a=b"));
        assert_eq!(o.get("get"), Some("X"));
        assert_eq!(o.get("head"), Some("8812"));
        assert_eq!(o.get("note"), Some(""));
        assert_eq!(o.get("PUT"), None);
    }

    #[test]
    fn options_empty() {
        for s in ["OK", "OK ", "OK   "] {
            let o = Line::parse(s).unwrap().params().options().unwrap();
            assert!(o.is_empty(), "{s:?}");
            assert_eq!(o.reject_unknown(&[]), Ok(()));
        }
    }

    #[test]
    fn options_errors() {
        let cases = [
            ("OK seq", "expected an option"),
            ("OK seq=1 more", "expected an option"),
            ("OK =1", "empty option key"),
            ("OK seq=1 seq=2", "repeated option"),
            ("OK seq=1 SEQ=2", "repeated option"),
            ("OK seq=1\tmore=1", "TAB between tokens"),
        ];
        for (input, why) in cases {
            let line = Line::parse(input).unwrap();
            assert_eq!(line.params().options(), Err(bad(why)), "{input:?}");
        }
    }

    // ---- LineBuilder ----

    #[test]
    fn builder_basic() {
        let line = Line::builder("msg")
            .tag("reply", 8810)
            .token("#general")
            .text("hi there")
            .build()
            .unwrap();
        assert_eq!(line.verb(), "MSG");
        assert_eq!(line.to_string(), "@reply=8810 MSG #general hi there");
        assert_eq!(Line::parse(&line.to_string()).unwrap(), line);
    }

    #[test]
    fn builder_deleted_event_has_no_trailing_space() {
        let line = Line::builder("MSG")
            .tag("seq", 8813)
            .tag("t", "2026-11-06T15:41:02.377Z")
            .tag("from", "~sam")
            .tag("reply", 8810)
            .flag("deleted")
            .token("#general")
            .text("")
            .build()
            .unwrap();
        assert_eq!(
            line.to_string(),
            "@seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;reply=8810;deleted MSG #general"
        );
    }

    #[test]
    fn builder_options() {
        let line = Line::builder("OK")
            .tag("ref", 7)
            .option("more", 1)
            .build()
            .unwrap();
        assert_eq!(line.to_string(), "@ref=7 OK more=1");
        let line = Line::builder("HISTORY")
            .token("#general")
            .option("AFTER", 8811)
            .option("limit", 2)
            .option("x", "")
            .build()
            .unwrap();
        assert_eq!(line.to_string(), "HISTORY #general after=8811 limit=2 x=");
        let line = Line::builder("OK")
            .option("put", "https://x/?a=b")
            .build()
            .unwrap();
        assert_eq!(line.to_string(), "OK put=https://x/?a=b");
    }

    #[test]
    fn builder_text_only() {
        let line = Line::builder("NOTICE")
            .text("Server restarts at 22:00")
            .build()
            .unwrap();
        assert_eq!(line.to_string(), "NOTICE Server restarts at 22:00");
        let line = Line::builder("NAME").text("").build().unwrap();
        assert_eq!(line.to_string(), "NAME");
        let line = Line::builder("QUIT").build().unwrap();
        assert_eq!(line.to_string(), "QUIT");
    }

    #[test]
    fn builder_text_leading_spaces_round_trip() {
        for text in [" hi", "  hi ", "\thi", " "] {
            let line = Line::builder("MSG").token("#a").text(text).build().unwrap();
            let parsed = Line::parse(&line.to_string()).unwrap();
            let mut p = parsed.params();
            p.token().unwrap();
            assert_eq!(p.text(), text, "{text:?}");

            let line = Line::builder("NOTICE").text(text).build().unwrap();
            let parsed = Line::parse(&line.to_string()).unwrap();
            assert_eq!(parsed.params().text(), text, "{text:?}");
        }
    }

    #[test]
    fn builder_conditional_use() {
        let mut b = Line::builder("PING");
        let token: Option<&str> = None;
        if let Some(t) = token {
            b.token(t);
        }
        assert_eq!(b.build().unwrap().to_string(), "PING");
        b.token("abc");
        assert_eq!(b.build().unwrap().to_string(), "PING abc");
    }

    #[test]
    fn builder_replaces_repeated_tag() {
        let line = Line::builder("OK")
            .tag("ref", 1)
            .tag("ref", 2)
            .build()
            .unwrap();
        assert_eq!(line.to_string(), "@ref=2 OK");
    }

    #[test]
    fn builder_errors() {
        let check = |b: &LineBuilder, want: ParseError| assert_eq!(b.build(), Err(want));
        check(&Line::builder(""), bad("bad verb"));
        check(&Line::builder("M SG"), bad("bad verb"));
        check(&Line::builder("MSG2"), bad("bad verb"));
        check(Line::builder("OK").tag("REF", 1), bad("bad tag key"));
        check(Line::builder("OK").tag("ref", ""), bad("bad tag value"));
        check(Line::builder("OK").tag("ref", "a;b"), bad("bad tag value"));
        check(Line::builder("OK").flag("x y"), bad("bad tag key"));
        check(Line::builder("JOIN").token(""), bad("bad token"));
        check(Line::builder("JOIN").token("a b"), bad("bad token"));
        check(Line::builder("JOIN").token("a\tb"), bad("bad token"));
        check(Line::builder("JOIN").token("a\nb"), bad("bad token"));
        check(Line::builder("OK").option("", 1), bad("bad option key"));
        check(Line::builder("OK").option("a=b", 1), bad("bad option key"));
        check(Line::builder("OK").option("a b", 1), bad("bad option key"));
        check(
            Line::builder("OK").option("a", "x y"),
            bad("bad option value"),
        );
        check(
            Line::builder("OK").option("a", "x\u{7f}"),
            bad("bad option value"),
        );
        check(
            Line::builder("H").option("a", 1).token("t"),
            bad("token after options or text"),
        );
        check(
            Line::builder("M").text("x").token("t"),
            bad("token after options or text"),
        );
        check(
            Line::builder("M").text("x").option("a", 1),
            bad("option after text"),
        );
        check(
            Line::builder("M").option("a", 1).text("x"),
            bad("text set twice or after options"),
        );
        check(
            Line::builder("M").text("x").text("y"),
            bad("text set twice or after options"),
        );
        check(Line::builder("M").text("a\nb"), ParseError::ControlChar);
        check(Line::builder("M").text("a\rb"), ParseError::ControlChar);
        // The first problem wins.
        check(Line::builder("1").tag("REF", 1).token(""), bad("bad verb"));
        check(
            Line::builder("OK").token("").tag("REF", 1),
            bad("bad token"),
        );
    }
}

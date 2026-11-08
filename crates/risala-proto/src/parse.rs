//! Helpers shared by the typed line layers: client commands
//! ([`command`](crate::command)), server lines ([`server`](crate::server))
//! and the lines inside encrypted messages (12.9), which use the same
//! format (Section 3).
//!
//! Each reads one part of a [`Line`](crate::line::Line) as a typed value
//! and reports problems as the spec's error codes expect: a value over a
//! length limit is `TooLong`, anything else `BadSyntax` (3.7).

use std::num::NonZeroU64;
use std::str::FromStr;

use crate::error::ParseError;
use crate::line::{Options, Params, Tags};
use crate::types::{parse_u64, parse_yes_no};

/// `BadSyntax` with a description.
pub(crate) const fn bad(what: &'static str) -> ParseError {
    ParseError::BadSyntax(what)
}

/// Reads the next token as a `T`.
pub(crate) fn tok<T: FromStr<Err = ParseError>>(p: &mut Params<'_>) -> Result<T, ParseError> {
    p.token()?.parse()
}

/// Reads the next token, if there is one, as a `T`.
pub(crate) fn opt_tok<T: FromStr<Err = ParseError>>(
    p: &mut Params<'_>,
) -> Result<Option<T>, ParseError> {
    p.opt_token()?.map(str::parse).transpose()
}

/// Reads the next token as a `T` and checks that nothing follows.
pub(crate) fn last<T: FromStr<Err = ParseError>>(mut p: Params<'_>) -> Result<T, ParseError> {
    let value = tok(&mut p)?;
    p.end()?;
    Ok(value)
}

/// Reads the next token as a number (3.3).
pub(crate) fn number(p: &mut Params<'_>) -> Result<u64, ParseError> {
    parse_u64(p.token()?)
}

/// Reads the next token as a number that fits a `u32`, such as a backup
/// generation (12.13). A larger number is `BadSyntax`.
pub(crate) fn number_u32(p: &mut Params<'_>) -> Result<u32, ParseError> {
    u32::try_from(number(p)?).map_err(|_| bad("number is out of range"))
}

/// Text that may be empty, with a length limit in bytes (escaped, 3.4).
pub(crate) fn text_max(p: Params<'_>, max: usize) -> Result<String, ParseError> {
    let text = p.text();
    limit(text, max)?;
    Ok(text.to_owned())
}

/// Text that must not be empty (`<name...>` in a syntax line, 3.3).
pub(crate) fn required_text(p: Params<'_>, what: &'static str) -> Result<String, ParseError> {
    match p.text() {
        "" => Err(bad(what)),
        text => Ok(text.to_owned()),
    }
}

/// `TooLong` if `text` is longer than `max` bytes.
pub(crate) fn limit(text: &str, max: usize) -> Result<(), ParseError> {
    if text.len() > max {
        Err(ParseError::TooLong)
    } else {
        Ok(())
    }
}

/// Reads options, rejecting any not in `known` (3.3).
pub(crate) fn options(p: Params<'_>, known: &[&str]) -> Result<Options, ParseError> {
    let options = p.options()?;
    options.reject_unknown(known)?;
    Ok(options)
}

/// Parses option `key`, if present.
pub(crate) fn opt<T: FromStr<Err = ParseError>>(
    options: &Options,
    key: &str,
) -> Result<Option<T>, ParseError> {
    options.get(key).map(str::parse).transpose()
}

/// A number option of at least 1, such as `limit=` or `hours=`.
pub(crate) fn positive_opt(options: &Options, key: &str) -> Result<Option<NonZeroU64>, ParseError> {
    options
        .get(key)
        .map(|v| NonZeroU64::new(parse_u64(v)?).ok_or(bad("must be at least 1")))
        .transpose()
}

/// A `yes`/`no` option such as `live=` or `light=`, false when absent.
pub(crate) fn flag_opt(options: &Options, key: &str) -> Result<bool, ParseError> {
    options.get(key).map_or(Ok(false), parse_yes_no)
}

/// The value of tag `key`, or `None` if absent. A tag that must have a
/// value but has none is `BadSyntax`.
pub(crate) fn tag_value<'a>(tags: &'a Tags, key: &str) -> Result<Option<&'a str>, ParseError> {
    match tags.entry(key) {
        None => Ok(None),
        Some(None) => Err(bad("tag needs a value")),
        Some(Some(value)) => Ok(Some(value)),
    }
}

/// Parses the value of tag `key`, if present.
pub(crate) fn parse_tag<T: FromStr<Err = ParseError>>(
    tags: &Tags,
    key: &str,
) -> Result<Option<T>, ParseError> {
    tag_value(tags, key)?.map(str::parse).transpose()
}

/// Parses the value of tag `key`, which must be present.
pub(crate) fn required_tag<T: FromStr<Err = ParseError>>(
    tags: &Tags,
    key: &str,
) -> Result<T, ParseError> {
    parse_tag(tags, key)?.ok_or(bad("missing a required tag"))
}

/// Reads a subcommand, such as `PUT` in `KEYS PUT` (3.8), in upper case.
/// A missing one is `BadSyntax`.
pub(crate) fn subcommand<'a>(p: &mut Params<'a>) -> Result<String, ParseError> {
    p.opt_token()?
        .map(str::to_ascii_uppercase)
        .ok_or(bad("missing subcommand"))
}

/// The error for an unknown subcommand of a known verb: `UnknownVerb`
/// with both words, so that a server replies `ERR unknown-command` (3.8).
pub(crate) fn unknown_subcommand(verb: &str, word: &str) -> ParseError {
    ParseError::UnknownVerb(format!("{verb} {word}"))
}

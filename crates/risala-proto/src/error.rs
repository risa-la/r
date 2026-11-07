//! Error codes (SPEC 3.7) and the crate's parse error.

use std::fmt;
use std::str::FromStr;

/// An error code, as sent in `ERR <code> [<message...>]` (3.7).
///
/// Clients must treat an unknown code as a general failure, so unknown
/// codes are kept in [`ErrorCode::Other`] rather than rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `bad-syntax`
    BadSyntax,
    /// `unknown-command`
    UnknownCommand,
    /// `too-long`
    TooLong,
    /// `not-authenticated`
    NotAuthenticated,
    /// `already-authenticated`
    AlreadyAuthenticated,
    /// `auth-failed`
    AuthFailed,
    /// `name-taken`
    NameTaken,
    /// `not-found`
    NotFound,
    /// `forbidden`
    Forbidden,
    /// `last-owner`
    LastOwner,
    /// `not-supported`
    NotSupported,
    /// `encrypted`: the conversation is encrypted, so the command cannot be
    /// used in it (12.3).
    Encrypted,
    /// `stale`: the conversation's group is not in the state the command
    /// needs (12.5, 12.6).
    Stale,
    /// `invalid`: MLS data or a franking commitment did not verify
    /// (Section 12).
    Invalid,
    /// `rate-limited`
    RateLimited,
    /// `internal`
    Internal,
    /// A code this crate does not know. Always lower case, never empty,
    /// never contains spaces.
    Other(String),
}

impl ErrorCode {
    /// The code as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::BadSyntax => "bad-syntax",
            ErrorCode::UnknownCommand => "unknown-command",
            ErrorCode::TooLong => "too-long",
            ErrorCode::NotAuthenticated => "not-authenticated",
            ErrorCode::AlreadyAuthenticated => "already-authenticated",
            ErrorCode::AuthFailed => "auth-failed",
            ErrorCode::NameTaken => "name-taken",
            ErrorCode::NotFound => "not-found",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::LastOwner => "last-owner",
            ErrorCode::NotSupported => "not-supported",
            ErrorCode::Encrypted => "encrypted",
            ErrorCode::Stale => "stale",
            ErrorCode::Invalid => "invalid",
            ErrorCode::RateLimited => "rate-limited",
            ErrorCode::Internal => "internal",
            ErrorCode::Other(code) => code,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ErrorCode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.contains([' ', '\t']) {
            return Err(ParseError::BadSyntax("error code must be one token"));
        }
        let lower = s.to_ascii_lowercase();
        Ok(match lower.as_str() {
            "bad-syntax" => ErrorCode::BadSyntax,
            "unknown-command" => ErrorCode::UnknownCommand,
            "too-long" => ErrorCode::TooLong,
            "not-authenticated" => ErrorCode::NotAuthenticated,
            "already-authenticated" => ErrorCode::AlreadyAuthenticated,
            "auth-failed" => ErrorCode::AuthFailed,
            "name-taken" => ErrorCode::NameTaken,
            "not-found" => ErrorCode::NotFound,
            "forbidden" => ErrorCode::Forbidden,
            "last-owner" => ErrorCode::LastOwner,
            "not-supported" => ErrorCode::NotSupported,
            "encrypted" => ErrorCode::Encrypted,
            "stale" => ErrorCode::Stale,
            "invalid" => ErrorCode::Invalid,
            "rate-limited" => ErrorCode::RateLimited,
            "internal" => ErrorCode::Internal,
            _ => ErrorCode::Other(lower),
        })
    }
}

/// Why a line, or a value inside it, could not be parsed.
///
/// Every variant maps to the error code a server replies with, through
/// [`ParseError::code`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The line, or one of its values, is longer than allowed.
    #[error("too long")]
    TooLong,
    /// The line is not valid UTF-8 (2.3).
    #[error("line is not valid UTF-8")]
    InvalidUtf8,
    /// The line contains a forbidden control character (2.3).
    #[error("line contains a control character")]
    ControlChar,
    /// The verb is not one this crate knows (3.8).
    #[error("unknown command {0}")]
    UnknownVerb(String),
    /// Anything else that does not follow the grammar. The text says what,
    /// for logs and for the human-readable part of `ERR bad-syntax`.
    #[error("bad syntax: {0}")]
    BadSyntax(&'static str),
}

impl ParseError {
    /// The error code a server replies with for this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            ParseError::TooLong => ErrorCode::TooLong,
            ParseError::UnknownVerb(_) => ErrorCode::UnknownCommand,
            ParseError::InvalidUtf8 | ParseError::ControlChar | ParseError::BadSyntax(_) => {
                ErrorCode::BadSyntax
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_round_trip() {
        for code in [
            "bad-syntax",
            "unknown-command",
            "too-long",
            "not-authenticated",
            "already-authenticated",
            "auth-failed",
            "name-taken",
            "not-found",
            "forbidden",
            "last-owner",
            "not-supported",
            "encrypted",
            "stale",
            "invalid",
            "rate-limited",
            "internal",
        ] {
            let parsed: ErrorCode = code.parse().unwrap();
            assert!(!matches!(parsed, ErrorCode::Other(_)), "{code}");
            assert_eq!(parsed.to_string(), code);
        }
    }

    #[test]
    fn unknown_code_is_kept() {
        let parsed: ErrorCode = "Slow-Down".parse().unwrap();
        assert_eq!(parsed, ErrorCode::Other("slow-down".into()));
        assert!("".parse::<ErrorCode>().is_err());
        assert!("a b".parse::<ErrorCode>().is_err());
    }

    #[test]
    fn parse_error_codes() {
        assert_eq!(ParseError::TooLong.code(), ErrorCode::TooLong);
        assert_eq!(
            ParseError::UnknownVerb("FOO".into()).code(),
            ErrorCode::UnknownCommand
        );
        assert_eq!(ParseError::ControlChar.code(), ErrorCode::BadSyntax);
    }
}

//! Error codes (SPEC 3.7) and the crate's parse error.

use std::fmt;
use std::str::FromStr;

/// An error code, as sent in `ERR <code> [<message...>]` (3.7), in the
/// order of the table there.
///
/// Clients must treat an unknown code as a general failure, so unknown
/// codes are kept in [`ErrorCode::Other`] rather than rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `bad-syntax`: the line could not be parsed, or has the wrong
    /// parameters.
    BadSyntax,
    /// `unknown-command`: the verb, or a verb's subcommand, is not known
    /// (3.8).
    UnknownCommand,
    /// `too-long`: the line or one of its parameters is too long, or a
    /// file, blob or KeyPackage is too large.
    TooLong,
    /// `not-authenticated`: the connection is new, and the command needs
    /// ANON, GUEST, AUTH or REGISTER first (4.1).
    NotAuthenticated,
    /// `wrong-connection`: the command needs another kind of connection
    /// than this one, which is anonymous, a guest or signed in (4.1,
    /// Section 13).
    WrongConnection,
    /// `already-authenticated`: the connection is already anonymous, a
    /// guest or signed in.
    AlreadyAuthenticated,
    /// `auth-failed`: the signature did not verify against the identity's
    /// keys, or the connection's SNI does not name this server (4.6).
    /// Clients do not retry it.
    AuthFailed,
    /// `name-taken`: the guest name, identity name, room name or mailbox
    /// is already in use.
    NameTaken,
    /// `not-found`: the room, mailbox, user, post or blob does not exist,
    /// or is not visible to you.
    NotFound,
    /// `forbidden`: not allowed because of permissions, a ban, a mute or
    /// server policy.
    Forbidden,
    /// `not-supported`: the server does not offer this feature.
    NotSupported,
    /// `stale`: the send token is not valid for that epoch, or the epoch
    /// is too old (7.2, 12.6).
    Stale,
    /// `invalid`: MLS data, a key file, a signature or a franking
    /// commitment did not verify, or something required is missing
    /// (Sections 4, 5.8 and 12).
    Invalid,
    /// `rate-limited`: too many requests; the `retry` tag says when to try
    /// again.
    RateLimited,
    /// `unavailable`: the server could not get an identity's key file
    /// (4.6, 12.5). Clients retry it with backoff.
    Unavailable,
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
            ErrorCode::WrongConnection => "wrong-connection",
            ErrorCode::AlreadyAuthenticated => "already-authenticated",
            ErrorCode::AuthFailed => "auth-failed",
            ErrorCode::NameTaken => "name-taken",
            ErrorCode::NotFound => "not-found",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotSupported => "not-supported",
            ErrorCode::Stale => "stale",
            ErrorCode::Invalid => "invalid",
            ErrorCode::RateLimited => "rate-limited",
            ErrorCode::Unavailable => "unavailable",
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
            "wrong-connection" => ErrorCode::WrongConnection,
            "already-authenticated" => ErrorCode::AlreadyAuthenticated,
            "auth-failed" => ErrorCode::AuthFailed,
            "name-taken" => ErrorCode::NameTaken,
            "not-found" => ErrorCode::NotFound,
            "forbidden" => ErrorCode::Forbidden,
            "not-supported" => ErrorCode::NotSupported,
            "stale" => ErrorCode::Stale,
            "invalid" => ErrorCode::Invalid,
            "rate-limited" => ErrorCode::RateLimited,
            "unavailable" => ErrorCode::Unavailable,
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
            "wrong-connection",
            "already-authenticated",
            "auth-failed",
            "name-taken",
            "not-found",
            "forbidden",
            "not-supported",
            "stale",
            "invalid",
            "rate-limited",
            "unavailable",
            "internal",
        ] {
            let parsed: ErrorCode = code.parse().unwrap();
            assert!(!matches!(parsed, ErrorCode::Other(_)), "{code}");
            assert_eq!(parsed.to_string(), code);
        }
    }

    #[test]
    fn dropped_codes_are_unknown() {
        // draft-02's codes that draft-03 drops (3.7).
        for code in ["last-owner", "encrypted"] {
            let parsed: ErrorCode = code.parse().unwrap();
            assert_eq!(parsed, ErrorCode::Other(code.into()));
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

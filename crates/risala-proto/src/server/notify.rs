//! The body of a push, once decrypted: `NOTIFY <tag> <reason>` (9.3).

use std::fmt;
use std::str::FromStr;

use crate::error::ParseError;
use crate::line::Line;
use crate::parse::tok;
use crate::types::{MAX_PUSH_REASON, MAX_PUSH_TAG, NotifyReason, PushReason, PushTag};

/// The size a server pads every push body to, with the record padding of
/// RFC 8188, before it encrypts it (9.3). Every body fits: see
/// [`MAX_NOTIFY_BODY`].
pub const NOTIFY_PADDED_LEN: usize = 128;

/// The longest push body, `NOTIFY <tag> <reason>` and its LF, with the
/// longest tag and reason (9.1, 9.3). It leaves room in
/// [`NOTIFY_PADDED_LEN`] for RFC 8188's padding delimiter.
pub const MAX_NOTIFY_BODY: usize = "NOTIFY  \n".len() + MAX_PUSH_TAG + MAX_PUSH_REASON;

const _: () = assert!(MAX_NOTIFY_BODY < NOTIFY_PADDED_LEN);

/// A push body (9.3): one line, `NOTIFY <tag> <reason>`, ending with LF.
///
/// ```
/// use risala_proto::server::Notify;
/// use risala_proto::types::{NotifyReason, PushReason};
///
/// let notify: Notify = "NOTIFY x7Hq2 message\n".parse()?;
/// assert_eq!(notify.reason, NotifyReason::Known(PushReason::Message));
/// assert_eq!(notify.to_body(), "NOTIFY x7Hq2 message\n");
/// # Ok::<(), risala_proto::error::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Notify {
    /// The subscription's tag, chosen by the client (9.1).
    pub tag: PushTag,
    /// Why the push was sent: `message` for a mailbox subscription,
    /// `welcome` for an account subscription. A reason from a later
    /// version is kept as [`NotifyReason::Other`]; apps treat it as new
    /// activity (9.3).
    pub reason: NotifyReason,
}

impl Notify {
    /// Parses a NOTIFY line (9.3). A verb other than NOTIFY is
    /// `UnknownVerb`.
    pub fn parse(line: &Line) -> Result<Notify, ParseError> {
        if !line.verb_is("NOTIFY") {
            return Err(ParseError::UnknownVerb(line.verb().to_owned()));
        }
        let mut p = line.params();
        let tag = tok(&mut p)?;
        let reason = tok(&mut p)?;
        p.end()?;
        Ok(Notify { tag, reason })
    }

    /// The line, without its LF (9.3).
    pub fn to_line(&self) -> Line {
        Line::builder("NOTIFY")
            .token(&self.tag)
            .token(&self.reason)
            .build()
            .expect("a push tag and a reason are tokens")
    }

    /// The request body: the line followed by LF (9.3).
    pub fn to_body(&self) -> String {
        format!("{}\n", self.to_line())
    }

    /// The push's `Urgency` header (RFC 8030, 9.3): `high` for a
    /// `welcome` push, `normal` for a `message` push, and `normal` for a
    /// reason of a later version, which this version does not send.
    pub fn urgency(&self) -> &'static str {
        match self.reason {
            NotifyReason::Known(PushReason::Welcome) => "high",
            _ => "normal",
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PushReason;

    #[test]
    fn notify_round_trips() {
        for (body, reason) in [
            (
                "NOTIFY t message\n",
                NotifyReason::Known(PushReason::Message),
            ),
            (
                "NOTIFY t welcome\n",
                NotifyReason::Known(PushReason::Welcome),
            ),
            ("NOTIFY t mention\n", NotifyReason::Other("mention".into())),
        ] {
            let notify: Notify = body.parse().unwrap();
            let urgency = if body.contains("welcome") {
                "high"
            } else {
                "normal"
            };
            assert_eq!(notify.urgency(), urgency);
            assert_eq!(notify.reason, reason);
            assert_eq!(notify.to_body(), body);
        }
        let crlf: Notify = "notify a;b Message\r\n".parse().unwrap();
        assert_eq!(crlf.to_body(), "NOTIFY a;b message\n");
        // draft-02's unread count is gone (9.3).
        assert!("NOTIFY t message 3\n".parse::<Notify>().is_err());
        assert!("NOTIFY t\n".parse::<Notify>().is_err());
        // The longest body fits the padded size (9.3).
        let longest = Notify {
            tag: "x".repeat(MAX_PUSH_TAG).parse().unwrap(),
            reason: NotifyReason::Other("r".repeat(MAX_PUSH_REASON)),
        };
        assert_eq!(longest.to_body().len(), MAX_NOTIFY_BODY);
        assert!(longest.to_body().len() < NOTIFY_PADDED_LEN);
        assert_eq!(longest.urgency(), "normal");
        assert!(matches!(
            "PUSH t message".parse::<Notify>(),
            Err(ParseError::UnknownVerb(_))
        ));
    }
}

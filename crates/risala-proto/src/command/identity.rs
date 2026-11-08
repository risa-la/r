//! The commands of Section 4: ANON and GUEST (4.2), AUTH (4.6),
//! REGISTER and KEYS PUT (4.7), PAIR (4.8) and UNREGISTER (4.9).

use std::fmt;
use std::str::FromStr;

use super::Command;
use crate::binary::{EncodedRecords, PairData};
use crate::error::ParseError;
use crate::line::{LineBuilder, Params};
use crate::names::{BlobRef, Id, PairId};
use crate::parse::{last, options, subcommand, tok, unknown_subcommand};
use crate::record::{Record, RecordError, decode_records};

/// The token that resumes a guest session (4.2), as GUEST carries it: an
/// [`Id`] that is a secret. Its `Debug` output leaves the token out, so
/// that a command written to a log does not give the session away.
/// `Display` writes it, for the line.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GuestToken(pub Id);

impl fmt::Debug for GuestToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuestToken(..)")
    }
}

impl fmt::Display for GuestToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for GuestToken {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<GuestToken, ParseError> {
        s.parse().map(GuestToken)
    }
}

impl From<Id> for GuestToken {
    fn from(id: Id) -> GuestToken {
        GuestToken(id)
    }
}

/// The `<records>` of KEYS PUT (4.7): the records, encoded as for
/// REGISTER (a version byte and `Record records<V>`) in base64, or a
/// blob-ref naming a blob that holds the same bytes without base64
/// (12.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysPutRecords {
    /// The records in base64.
    Inline(EncodedRecords),
    /// A blob that holds them.
    Blob(BlobRef),
}

impl KeysPutRecords {
    /// The records of [`Inline`](KeysPutRecords::Inline), decoded; `None`
    /// for a blob, whose bytes the server fetches and decodes with
    /// [`decode_records`].
    pub fn inline_records(&self) -> Option<Result<Vec<Record>, RecordError>> {
        match self {
            KeysPutRecords::Inline(records) => Some(decode_records(&records.decode())),
            KeysPutRecords::Blob(_) => None,
        }
    }
}

impl FromStr for KeysPutRecords {
    type Err = ParseError;

    /// A blob-ref if it starts with `sha384:` in any case, which base64
    /// never does, and base64 otherwise.
    fn from_str(s: &str) -> Result<KeysPutRecords, ParseError> {
        let blob = s
            .get(..BlobRef::PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(BlobRef::PREFIX));
        if blob {
            s.parse().map(KeysPutRecords::Blob)
        } else {
            s.parse().map(KeysPutRecords::Inline)
        }
    }
}

impl fmt::Display for KeysPutRecords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeysPutRecords::Inline(records) => fmt::Display::fmt(records, f),
            KeysPutRecords::Blob(blob) => fmt::Display::fmt(blob, f),
        }
    }
}

/// Reads KEYS PUT's `<after>`: `-`, or a blob-ref.
fn parse_after(s: &str) -> Result<Option<BlobRef>, ParseError> {
    if s == "-" {
        Ok(None)
    } else {
        s.parse().map(Some)
    }
}

/// `PAIR PUT` and `PAIR GET` (4.8): pairing messages, stored for 10
/// minutes under ids that only the two devices know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairCommand {
    /// `PAIR PUT <id> <data>`: stores an encrypted pairing message.
    Put {
        /// The id, derived from the pairing secret.
        id: PairId,
        /// The encrypted NewDevice or IdentityBundle.
        data: PairData,
    },
    /// `PAIR GET <id>`: replies with a PAIR line, or `ERR not-found`.
    Get {
        /// The id, derived from the pairing secret.
        id: PairId,
    },
}

impl PairCommand {
    /// The subcommand, in upper case.
    pub fn word(&self) -> &'static str {
        match self {
            PairCommand::Put { .. } => "PUT",
            PairCommand::Get { .. } => "GET",
        }
    }
}

/// Parses the commands of this module; `None` for any other verb.
pub(super) fn parse(verb: &str, p: Params<'_>) -> Option<Result<Command, ParseError>> {
    let parse: fn(Params<'_>) -> Result<Command, ParseError> = match verb {
        "ANON" => |p: Params<'_>| {
            p.end()?;
            Ok(Command::Anon)
        },
        "GUEST" => |mut p: Params<'_>| {
            let name = tok(&mut p)?;
            let options = options(p, &["token"])?;
            let token = options.get("token").map(str::parse).transpose()?;
            Ok(Command::Guest { name, token })
        },
        "AUTH" => |mut p: Params<'_>| {
            let identity = tok(&mut p)?;
            let signature = last(p)?;
            Ok(Command::Auth {
                identity,
                signature,
            })
        },
        "REGISTER" => |mut p: Params<'_>| {
            let name = tok(&mut p)?;
            let records = tok(&mut p)?;
            let signature = last(p)?;
            Ok(Command::Register {
                name,
                records,
                signature,
            })
        },
        "KEYS" => |mut p: Params<'_>| match subcommand(&mut p)?.as_str() {
            "PUT" => {
                let after = parse_after(p.token()?)?;
                let records = last(p)?;
                Ok(Command::KeysPut { after, records })
            }
            word => Err(unknown_subcommand("KEYS", word)),
        },
        "PAIR" => |mut p: Params<'_>| {
            Ok(Command::Pair(match subcommand(&mut p)?.as_str() {
                "PUT" => {
                    let id = tok(&mut p)?;
                    let data = last(p)?;
                    PairCommand::Put { id, data }
                }
                "GET" => PairCommand::Get { id: last(p)? },
                word => return Err(unknown_subcommand("PAIR", word)),
            }))
        },
        "UNREGISTER" => |p: Params<'_>| Ok(Command::Unregister { uid: last(p)? }),
        _ => return None,
    };
    Some(parse(p))
}

/// Writes the commands of this module; `false` for any other command.
pub(super) fn write(command: &Command, b: &mut LineBuilder) -> bool {
    match command {
        Command::Anon => {}
        Command::Guest { name, token } => {
            b.token(name);
            if let Some(token) = token {
                b.option("token", token);
            }
        }
        Command::Auth {
            identity,
            signature,
        } => {
            b.token(identity).token(signature);
        }
        Command::Register {
            name,
            records,
            signature,
        } => {
            b.token(name).token(records).token(signature);
        }
        Command::KeysPut { after, records } => {
            b.token("PUT");
            match after {
                Some(after) => b.token(after),
                None => b.token("-"),
            };
            b.token(records);
        }
        Command::Pair(PairCommand::Put { id, data }) => {
            b.token("PUT").token(id).token(data);
        }
        Command::Pair(PairCommand::Get { id }) => {
            b.token("GET").token(id);
        }
        Command::Unregister { uid } => {
            b.token(uid);
        }
        _ => return false,
    }
    true
}

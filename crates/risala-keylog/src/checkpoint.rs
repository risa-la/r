//! Checkpoints [TLOG-CHECKPOINT], and the origins of risala's key logs
//! (SPEC 4.5).

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::merkle::Hash;
use crate::note::{Note, NoteError};

/// The longest cosigner name or log origin [TLOG-COSIGNATURE].
pub const MAX_NAME_LEN: usize = 255;

/// The path in a key log's origin, before its number (SPEC 4.5, 15).
pub const ORIGIN_PATH: &str = "/risala-log/";

/// Why a checkpoint or an origin did not parse.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// The note text is not a checkpoint.
    #[error("malformed checkpoint: {0}")]
    Malformed(&'static str),
    /// The origin is not a valid cosigner name, or not a risala log's.
    #[error("invalid origin")]
    BadOrigin,
    /// The signed note around it is malformed.
    #[error(transparent)]
    Note(#[from] NoteError),
}

/// Whether a string is a valid cosigner name or log origin
/// [TLOG-COSIGNATURE]: 1 to 255 bytes of UTF-8 with no Unicode space, no
/// plus and no control character.
pub fn is_valid_name(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c == '+' || c.is_control())
}

/// The body of a checkpoint: origin, tree size, root hash and any
/// extension lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    origin: String,
    size: u64,
    root: Hash,
    extensions: Vec<String>,
}

impl Checkpoint {
    /// A checkpoint with no extension lines.
    pub fn new(origin: &str, size: u64, root: Hash) -> Result<Checkpoint, CheckpointError> {
        if !is_valid_name(origin) {
            return Err(CheckpointError::BadOrigin);
        }
        Ok(Checkpoint {
            origin: origin.to_owned(),
            size,
            root,
            extensions: Vec::new(),
        })
    }

    /// Parses a checkpoint from a note's text, which ends in a newline.
    pub fn from_text(text: &str) -> Result<Checkpoint, CheckpointError> {
        let body = text
            .strip_suffix('\n')
            .ok_or(CheckpointError::Malformed("text must end in a newline"))?;
        let mut lines = body.split('\n');
        let origin = lines.next().unwrap_or_default();
        let size = lines
            .next()
            .ok_or(CheckpointError::Malformed("no tree size"))?;
        let root = lines
            .next()
            .ok_or(CheckpointError::Malformed("no root hash"))?;
        if !is_valid_name(origin) {
            return Err(CheckpointError::BadOrigin);
        }
        let size = parse_decimal(size).ok_or(CheckpointError::Malformed("bad tree size"))?;
        let root = Hash::from_base64(root).ok_or(CheckpointError::Malformed("bad root hash"))?;
        let extensions: Vec<String> = lines.map(str::to_owned).collect();
        if extensions
            .iter()
            .any(|l| l.is_empty() || l.chars().any(char::is_control))
        {
            return Err(CheckpointError::Malformed("empty extension line"));
        }
        Ok(Checkpoint {
            origin: origin.to_owned(),
            size,
            root,
            extensions,
        })
    }

    /// The note text: the lines, each ending in a newline.
    pub fn to_text(&self) -> String {
        let mut s = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            self.root.to_base64()
        );
        for e in &self.extensions {
            s.push_str(e);
            s.push('\n');
        }
        s
    }

    /// The log's origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The tree size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The root hash.
    pub fn root(&self) -> &Hash {
        &self.root
    }

    /// The extension lines, which ML-DSA-44 signatures do not cover.
    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }
}

/// A decimal number with no leading zeros; zero is `0`.
pub(crate) fn parse_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// A checkpoint and the signed note it came in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    checkpoint: Checkpoint,
    note: Note,
}

impl SignedCheckpoint {
    /// Parses a signed checkpoint, as served at `<prefix>/checkpoint`.
    pub fn parse(bytes: &[u8]) -> Result<SignedCheckpoint, CheckpointError> {
        let note = Note::parse(bytes)?;
        let checkpoint = Checkpoint::from_text(note.text())?;
        Ok(SignedCheckpoint { checkpoint, note })
    }

    /// A checkpoint with no signatures yet.
    pub fn unsigned(checkpoint: Checkpoint) -> SignedCheckpoint {
        let note =
            Note::new(checkpoint.to_text()).expect("a checkpoint's text is a valid note text");
        SignedCheckpoint { checkpoint, note }
    }

    /// The checkpoint.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// The signed note.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// Adds a signature line.
    pub fn push_signature(
        &mut self,
        sig: crate::note::NoteSignature,
    ) -> Result<(), CheckpointError> {
        Ok(self.note.push_signature(sig)?)
    }

    /// The signed note's bytes.
    pub fn to_text(&self) -> String {
        self.note.to_text()
    }
}

/// A key log's origin: `<host>/risala-log/<n>`, where `<n>` is a number
/// from 1 that the operator picks (SPEC 4.5).
///
/// The host must be a DNS name in lower case: letters, digits and hyphens
/// in labels of 1 to 63 characters, separated by dots, with no port. The
/// spec says only "its hostname"; insisting on one spelling keeps two
/// origins from naming one log. (SPEC 4.5; a choice to confirm.)
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogOrigin {
    host: String,
    number: u64,
}

impl LogOrigin {
    /// The origin for log `number` on `host`.
    pub fn new(host: &str, number: u64) -> Result<LogOrigin, CheckpointError> {
        if number == 0 || !is_hostname(host) {
            return Err(CheckpointError::BadOrigin);
        }
        let o = LogOrigin {
            host: host.to_owned(),
            number,
        };
        if o.to_string().len() > MAX_NAME_LEN {
            return Err(CheckpointError::BadOrigin);
        }
        Ok(o)
    }

    /// The log's host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The log's number.
    pub fn number(&self) -> u64 {
        self.number
    }
}

impl FromStr for LogOrigin {
    type Err = CheckpointError;

    fn from_str(s: &str) -> Result<LogOrigin, CheckpointError> {
        let (host, n) = s
            .split_once(ORIGIN_PATH)
            .ok_or(CheckpointError::BadOrigin)?;
        let n = parse_decimal(n).ok_or(CheckpointError::BadOrigin)?;
        LogOrigin::new(host, n)
    }
}

impl fmt::Display for LogOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{ORIGIN_PATH}{}", self.host, self.number)
    }
}

fn is_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example of [TLOG-CHECKPOINT].
    const SPEC_CHECKPOINT: &str = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n\u{2014} example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n";

    #[test]
    fn spec_example() {
        let sc = SignedCheckpoint::parse(SPEC_CHECKPOINT.as_bytes()).unwrap();
        let c = sc.checkpoint();
        assert_eq!(c.origin(), "example.com/behind-the-sofa");
        assert_eq!(c.size(), 20852163);
        assert_eq!(
            c.root().to_base64(),
            "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="
        );
        assert!(c.extensions().is_empty());
        assert_eq!(sc.to_text(), SPEC_CHECKPOINT);
        assert_eq!(sc.note().signatures().len(), 1);
    }

    #[test]
    fn extension_lines() {
        let text = "o\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\nfoo\nbar baz\n";
        let c = Checkpoint::from_text(text).unwrap();
        assert_eq!(c.extensions(), ["foo", "bar baz"]);
        assert_eq!(c.to_text(), text);
    }

    #[test]
    fn rejects_malformed_checkpoints() {
        let root = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        for bad in [
            format!("o\n0\n{root}"),
            "o\n0\n".to_owned(),
            "o\n".to_owned(),
            format!("\n0\n{root}\n"),
            format!("o p\n0\n{root}\n"),
            format!("o+p\n0\n{root}\n"),
            format!("o\n00\n{root}\n"),
            format!("o\n01\n{root}\n"),
            format!("o\n-1\n{root}\n"),
            format!("o\n+1\n{root}\n"),
            format!("o\n18446744073709551616\n{root}\n"),
            "o\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\n".to_owned(),
            "o\n0\nAAAA\n".to_owned(),
            format!("o\n0\n{root}\n\n"),
            format!("o\n0\n{root}\nx\n\ny\n"),
            format!("{}\n0\n{root}\n", "a".repeat(256)),
        ] {
            assert!(Checkpoint::from_text(&bad).is_err(), "{bad:?}");
        }
        assert!(
            Checkpoint::from_text(&format!(
                "{}\n18446744073709551615\n{root}\n",
                "a".repeat(255)
            ))
            .is_ok()
        );
    }

    #[test]
    fn origins() {
        let o: LogOrigin = "chat.example.org/risala-log/1".parse().unwrap();
        assert_eq!((o.host(), o.number()), ("chat.example.org", 1));
        assert_eq!(o.to_string(), "chat.example.org/risala-log/1");
        assert!(is_valid_name(&o.to_string()));
        assert_eq!(
            LogOrigin::new("localhost", 42).unwrap().to_string(),
            "localhost/risala-log/42"
        );
        for bad in [
            "chat.example.org/risala-log/0",
            "chat.example.org/risala-log/01",
            "chat.example.org/risala-log/",
            "chat.example.org/risala-log/1/",
            "Chat.example.org/risala-log/1",
            "chat.example.org:7472/risala-log/1",
            "chat..example.org/risala-log/1",
            "-chat.example.org/risala-log/1",
            "chat.example.org/risala-logs/1",
            "/risala-log/1",
            "https://chat.example.org/risala-log/1",
            "chat.example.org/risala-log/1/risala-log/1",
        ] {
            assert!(bad.parse::<LogOrigin>().is_err(), "{bad:?}");
        }
    }
}

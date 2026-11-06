//! Key files (SPEC 4.3, 4.4).
//!
//! A key file lists an identity's public keys, one per line:
//!
//! ```text
//! # alice@example.org
//! ed25519 J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY= laptop
//! ```
//!
//! Parsing is lenient, as a server must be: anything it cannot use is
//! left out, and [`KeyFile::skipped`] says what was left out and why, so
//! that a key tool can lint a file.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use crate::auth::PublicKey;
use crate::error::ParseError;

/// The only key type this version of the protocol defines (4.4).
pub const KEY_TYPE: &str = "ed25519";

/// The most keys a server uses from one key file (4.4).
pub const MAX_KEYS: usize = 64;

/// The most bytes a server reads of a key file, 64 KiB (4.4).
pub const MAX_KEY_FILE_BYTES: usize = 65536;

/// The URL of the key file for the identity `name@domain` (4.3).
///
/// Both parts are folded to lower case. They are not otherwise checked:
/// pass a validated name and domain.
pub fn well_known_url(name: &str, domain: &str) -> String {
    format!(
        "https://{}/.well-known/risala/{}",
        domain.to_ascii_lowercase(),
        name.to_ascii_lowercase()
    )
}

/// One key in a key file: `ed25519 <key> [<label...>]` (4.4).
///
/// The label is free text for people, usually a device name. It never
/// starts or ends with whitespace, is never empty (no label is `None`)
/// and holds no control characters, so `Display` always writes one valid
/// key file line, without its LF. Parsing that line gives back the same
/// entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyEntry {
    key: PublicKey,
    label: Option<String>,
}

impl KeyEntry {
    /// Makes an entry for `key` with an optional label (4.4).
    ///
    /// Spaces and tabs around the label are trimmed, and a label that is
    /// then empty becomes `None`. A label with a control character other
    /// than tab inside it, such as a line break, fails with `BadSyntax`.
    /// The spec sets no length limit; the line limits (2.3) and
    /// [`MAX_KEY_FILE_BYTES`] bound it in practice.
    pub fn new(key: PublicKey, label: Option<&str>) -> Result<KeyEntry, ParseError> {
        let label = match label.map(|l| l.trim_matches([' ', '\t'])) {
            None | Some("") => None,
            Some(l) if l.chars().any(|c| c.is_control() && c != '\t') => {
                return Err(ParseError::BadSyntax("label contains a control character"));
            }
            Some(l) => Some(l.to_owned()),
        };
        Ok(KeyEntry { key, label })
    }

    /// The public key (4.4).
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The label, if there is one (4.4).
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

impl FromStr for KeyEntry {
    type Err = ParseError;

    /// Parses one `ed25519 <key> [<label...>]` line, without its line
    /// ending (4.4).
    ///
    /// Spaces and tabs may separate the fields and surround the line. The
    /// key type is matched without regard to case. Unlike
    /// [`KeyFile::parse`], this fails on comments, blank lines and other
    /// key types.
    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let line = line.trim_matches([' ', '\t']);
        let (key_type, rest) = split_field(line);
        if key_type.is_empty() {
            return Err(ParseError::BadSyntax("empty key file line"));
        }
        if !key_type.eq_ignore_ascii_case(KEY_TYPE) {
            return Err(ParseError::BadSyntax("not an ed25519 key"));
        }
        let (key, label) = split_field(rest);
        if key.is_empty() {
            return Err(ParseError::BadSyntax("missing key"));
        }
        KeyEntry::new(key.parse()?, Some(label))
    }
}

impl fmt::Display for KeyEntry {
    /// Writes the key file line without its LF, the same line as the
    /// `printf` in Appendix A prints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{KEY_TYPE} {}", self.key)?;
        if let Some(label) = &self.label {
            write!(f, " {label}")?;
        }
        Ok(())
    }
}

/// Why [`KeyFile::parse`] left out a line (4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// The line has a key type other than `ed25519`. The spec says to
    /// ignore these quietly; they are listed so a key tool can mention
    /// them.
    OtherKeyType(String),
    /// The line starts with `ed25519` but is not a valid key line: the
    /// key is missing, is not 44 characters of strict base64, is not a
    /// curve point, or the label holds a control character.
    Malformed(ParseError),
    /// The key already appeared on an earlier line. The first line's
    /// label is kept.
    Duplicate,
    /// The file already had [`MAX_KEYS`] keys.
    TooMany,
}

/// A line [`KeyFile::parse`] left out (4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// The line number, counting from 1.
    pub line: usize,
    /// Why it was left out.
    pub reason: SkipReason,
}

/// A parsed key file: the keys a server accepts for an identity (4.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyFile {
    keys: Vec<KeyEntry>,
    skipped: Vec<Skipped>,
}

impl KeyFile {
    /// Parses a key file (4.4).
    ///
    /// - Lines end in LF or CRLF. A UTF-8 byte order mark at the start is
    ///   ignored.
    /// - Blank lines and lines whose first non-blank character is `#` are
    ///   ignored.
    /// - Lines with another key type are ignored.
    /// - Malformed `ed25519` lines are ignored too, so that one bad line
    ///   does not lock someone out of every other device.
    /// - A key that appears again is ignored; the first line wins.
    /// - Only the first [`MAX_KEYS`] distinct keys are kept.
    ///
    /// Every ignored line except blanks and comments is listed in
    /// [`skipped`](KeyFile::skipped).
    ///
    /// Fails with `TooLong` if the text is over [`MAX_KEY_FILE_BYTES`],
    /// which a server must treat as a file with no keys. This is the only
    /// error.
    pub fn parse(text: &str) -> Result<KeyFile, ParseError> {
        if text.len() > MAX_KEY_FILE_BYTES {
            return Err(ParseError::TooLong);
        }
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut file = KeyFile::default();
        let mut seen = HashSet::new();
        for (index, line) in text.split('\n').enumerate() {
            let line_no = index + 1;
            let line = line.strip_suffix('\r').unwrap_or(line);
            let line = line.trim_matches([' ', '\t']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut skip = |reason| {
                file.skipped.push(Skipped {
                    line: line_no,
                    reason,
                })
            };
            let (key_type, _) = split_field(line);
            if !key_type.eq_ignore_ascii_case(KEY_TYPE) {
                skip(SkipReason::OtherKeyType(key_type.to_owned()));
                continue;
            }
            match line.parse::<KeyEntry>() {
                Err(e) => skip(SkipReason::Malformed(e)),
                Ok(entry) if seen.contains(entry.key()) => skip(SkipReason::Duplicate),
                Ok(_) if file.keys.len() == MAX_KEYS => skip(SkipReason::TooMany),
                Ok(entry) => {
                    seen.insert(*entry.key());
                    file.keys.push(entry);
                }
            }
        }
        Ok(file)
    }

    /// The keys, in file order (4.4).
    pub fn keys(&self) -> &[KeyEntry] {
        &self.keys
    }

    /// The lines that were left out, other than blanks and comments (4.4).
    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }

    /// Whether the file lists `key` (4.4, 4.5).
    pub fn contains(&self, key: &PublicKey) -> bool {
        self.keys.iter().any(|e| e.key() == key)
    }

    /// The public keys, in file order (4.5).
    pub fn public_keys(&self) -> impl Iterator<Item = &PublicKey> {
        self.keys.iter().map(KeyEntry::key)
    }

    /// Takes the keys out of the file (4.4).
    pub fn into_keys(self) -> Vec<KeyEntry> {
        self.keys
    }
}

/// Splits off the first field of a line: everything up to the first space
/// or tab, and the rest after any run of spaces and tabs.
fn split_field(s: &str) -> (&str, &str) {
    match s.find([' ', '\t']) {
        Some(i) => (&s[..i], s[i..].trim_start_matches([' ', '\t'])),
        None => (s, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SecretKey;

    const LAPTOP: &str = "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY=";
    const PHONE: &str = "xOANpWbIg5OCt//dfeEit/1AngQtJJdLe4ks1mxhd5M=";

    fn key(s: &str) -> PublicKey {
        s.parse().unwrap()
    }

    #[test]
    fn spec_example() {
        let text = "# alice@example.org\n\
            ed25519 J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY= laptop\n\
            ed25519 xOANpWbIg5OCt//dfeEit/1AngQtJJdLe4ks1mxhd5M= phone\n";
        let file = KeyFile::parse(text).unwrap();
        assert_eq!(file.keys().len(), 2);
        assert_eq!(file.keys()[0].key(), &key(LAPTOP));
        assert_eq!(file.keys()[0].label(), Some("laptop"));
        assert_eq!(file.keys()[1].key(), &key(PHONE));
        assert_eq!(file.keys()[1].label(), Some("phone"));
        assert!(file.skipped().is_empty());
        assert!(file.contains(&key(PHONE)));
        assert_eq!(file.public_keys().count(), 2);
    }

    #[test]
    fn appendix_b_line() {
        let seed = [
            0xc1, 0x1f, 0xae, 0x5c, 0x59, 0x2e, 0x13, 0xbe, 0x67, 0xdc, 0x96, 0xf6, 0xe8, 0x50,
            0x04, 0xd3, 0x2e, 0x92, 0x86, 0x15, 0xf7, 0xaf, 0x1f, 0xd3, 0xa6, 0xc5, 0xd9, 0xea,
            0x0a, 0xb6, 0xcb, 0xa8,
        ];
        let public = SecretKey::from_seed(seed).public_key();
        let entry = KeyEntry::new(public, Some("laptop")).unwrap();
        let line = "ed25519 J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY= laptop";
        assert_eq!(entry.to_string(), line);
        assert_eq!(line.parse::<KeyEntry>().unwrap(), entry);
    }

    #[test]
    fn labels() {
        let e: KeyEntry = format!("ed25519 {LAPTOP}").parse().unwrap();
        assert_eq!(e.label(), None);
        assert_eq!(e.to_string(), format!("ed25519 {LAPTOP}"));

        let e: KeyEntry = format!("ed25519\t{LAPTOP}  my  old\tlaptop  ")
            .parse()
            .unwrap();
        assert_eq!(e.label(), Some("my  old\tlaptop"));
        assert_eq!(e.to_string().parse::<KeyEntry>().unwrap(), e);

        let e: KeyEntry = format!("ed25519 {LAPTOP} téléphone 📱").parse().unwrap();
        assert_eq!(e.label(), Some("téléphone 📱"));

        assert_eq!(
            KeyEntry::new(key(LAPTOP), Some("  ")).unwrap().label(),
            None
        );
        assert!(KeyEntry::new(key(LAPTOP), Some("a\nb")).is_err());
        assert!(KeyEntry::new(key(LAPTOP), Some("a\rb")).is_err());
    }

    #[test]
    fn single_line_errors() {
        assert!("".parse::<KeyEntry>().is_err());
        assert!("# comment".parse::<KeyEntry>().is_err());
        assert!("ed25519".parse::<KeyEntry>().is_err());
        assert!(format!("ssh-ed25519 {LAPTOP}").parse::<KeyEntry>().is_err());
        assert!(format!("ED25519 {LAPTOP}").parse::<KeyEntry>().is_ok());
    }

    #[test]
    fn lenient_parsing() {
        let text = format!(
            "\u{feff}# keys\r\n\
             \r\n\
             \x20  \t\r\n\
             \x20 # indented comment\n\
             ed448 AAAA future\n\
             ed25519 notbase64 broken\n\
             ed25519\n\
             ed25519 {LAPTOP} laptop\r\n\
             ed25519 {LAPTOP} laptop again\n\
             \tED25519   {PHONE}\t\n\
             ed25519 {}\n",
            &LAPTOP[..43]
        );
        let file = KeyFile::parse(&text).unwrap();
        assert_eq!(file.keys().len(), 2);
        assert_eq!(file.keys()[0].label(), Some("laptop"));
        assert_eq!(file.keys()[1].key(), &key(PHONE));
        assert_eq!(file.keys()[1].label(), None);

        let reasons: Vec<_> = file
            .skipped()
            .iter()
            .map(|s| (s.line, s.reason.clone()))
            .collect();
        assert_eq!(
            reasons,
            vec![
                (5, SkipReason::OtherKeyType("ed448".into())),
                (
                    6,
                    SkipReason::Malformed(ParseError::BadSyntax("bad public key"))
                ),
                (
                    7,
                    SkipReason::Malformed(ParseError::BadSyntax("missing key"))
                ),
                (9, SkipReason::Duplicate),
                (
                    11,
                    SkipReason::Malformed(ParseError::BadSyntax("bad public key"))
                ),
            ]
        );
    }

    #[test]
    fn empty_file() {
        let file = KeyFile::parse("").unwrap();
        assert!(file.keys().is_empty());
        assert!(file.skipped().is_empty());
        assert!(KeyFile::parse("\n\n# nothing\n").unwrap().keys().is_empty());
    }

    #[test]
    fn at_most_64_keys() {
        let mut text = String::new();
        for i in 0..70u8 {
            let public = SecretKey::from_seed([i; 32]).public_key();
            text.push_str(
                &KeyEntry::new(public, Some(&format!("d{i}")))
                    .unwrap()
                    .to_string(),
            );
            text.push('\n');
            // A duplicate does not use up one of the 64.
            if i == 0 {
                text.push_str(&format!("ed25519 {public}\n"));
            }
        }
        let file = KeyFile::parse(&text).unwrap();
        assert_eq!(file.keys().len(), MAX_KEYS);
        assert_eq!(file.keys()[63].label(), Some("d63"));
        assert_eq!(file.skipped()[0].reason, SkipReason::Duplicate);
        assert_eq!(file.skipped().len(), 1 + 6);
        assert!(
            file.skipped()[1..]
                .iter()
                .all(|s| s.reason == SkipReason::TooMany)
        );
        assert_eq!(file.skipped()[1].line, 66);
    }

    #[test]
    fn size_limit() {
        let ok = "#".repeat(MAX_KEY_FILE_BYTES);
        assert!(KeyFile::parse(&ok).is_ok());
        let big = "#".repeat(MAX_KEY_FILE_BYTES + 1);
        assert_eq!(KeyFile::parse(&big), Err(ParseError::TooLong));
    }

    #[test]
    fn url() {
        assert_eq!(
            well_known_url("alice", "example.org"),
            "https://example.org/.well-known/risala/alice"
        );
        assert_eq!(
            well_known_url("Alice", "Example.ORG"),
            "https://example.org/.well-known/risala/alice"
        );
    }
}

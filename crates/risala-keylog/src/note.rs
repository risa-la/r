//! Signed notes [SIGNED-NOTE]: text followed by signature lines, and the
//! verifier keys (`vkey`s) that name the keys that sign them.
//!
//! This module only reads and writes the format. Which signatures count,
//! and how they verify, is up to the checkpoint and witness code: the only
//! signature type risala uses, `0x06`, signs a structure built from the
//! checkpoint rather than the note's text (see [`crate::cosig`]).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The most signature lines a note may have. [SIGNED-NOTE] asks verifiers
/// to accept at least 16.
pub const MAX_SIGNATURES: usize = 100;

/// The largest note this crate reads, in bytes. A hundred ML-DSA-44
/// signature lines are about 330 KB.
pub const MAX_NOTE_LEN: usize = 1 << 20;

/// The start of a signature line: an em dash and a space.
const SIG_PREFIX: &str = "\u{2014} ";

/// Why a note or a verifier key did not parse.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NoteError {
    /// The note is not a well-formed signed note.
    #[error("malformed note: {0}")]
    Malformed(&'static str),
    /// The note has more than [`MAX_SIGNATURES`] signatures or is longer
    /// than [`MAX_NOTE_LEN`].
    #[error("note too large")]
    TooLarge,
    /// A key name is empty or holds a space or a plus.
    #[error("invalid key name")]
    BadKeyName,
    /// A verifier key is malformed.
    #[error("malformed verifier key: {0}")]
    BadVerifierKey(&'static str),
}

/// One signature line: the key's name, its 32-bit id and the signature
/// bytes after the id.
#[derive(Clone, PartialEq, Eq)]
pub struct NoteSignature {
    /// The key's name.
    pub name: String,
    /// The key's id.
    pub key_id: u32,
    /// The signature, without the key id in front.
    pub signature: Vec<u8>,
}

impl NoteSignature {
    /// Parses a signature line, without its newline.
    pub fn parse_line(line: &str) -> Result<NoteSignature, NoteError> {
        let rest = line
            .strip_prefix(SIG_PREFIX)
            .ok_or(NoteError::Malformed("not a signature line"))?;
        let (name, b64) = rest
            .split_once(' ')
            .ok_or(NoteError::Malformed("signature line without a signature"))?;
        if !is_valid_key_name(name) {
            return Err(NoteError::BadKeyName);
        }
        let bytes = BASE64
            .decode(b64)
            .map_err(|_| NoteError::Malformed("signature is not canonical base64"))?;
        // A key id and at least one byte of signature.
        if bytes.len() < 5 {
            return Err(NoteError::Malformed("signature too short"));
        }
        let (id, sig) = bytes.split_at(4);
        Ok(NoteSignature {
            name: name.to_owned(),
            key_id: u32::from_be_bytes(id.try_into().expect("4 bytes")),
            signature: sig.to_vec(),
        })
    }

    /// The signature line, ending in a newline.
    pub fn to_line(&self) -> String {
        let mut bytes = Vec::with_capacity(4 + self.signature.len());
        bytes.extend_from_slice(&self.key_id.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        format!("{SIG_PREFIX}{} {}\n", self.name, BASE64.encode(bytes))
    }

    /// Parses signature lines, each ending in a newline, as a witness's
    /// `add-checkpoint` response holds them [TLOG-WITNESS].
    pub fn parse_lines(text: &str) -> Result<Vec<NoteSignature>, NoteError> {
        let body = text.strip_suffix('\n').ok_or(NoteError::Malformed(
            "signature lines must end in a newline",
        ))?;
        if body.is_empty() {
            return Err(NoteError::Malformed("no signature lines"));
        }
        let lines: Vec<&str> = body.split('\n').collect();
        if lines.len() > MAX_SIGNATURES {
            return Err(NoteError::TooLarge);
        }
        lines.into_iter().map(NoteSignature::parse_line).collect()
    }
}

impl fmt::Debug for NoteSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteSignature")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .field("len", &self.signature.len())
            .finish()
    }
}

/// A signed note: its text, which ends in a newline, and its signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    text: String,
    signatures: Vec<NoteSignature>,
}

impl Note {
    /// A note with this text and no signatures yet. The text must end in
    /// a newline and hold no control characters other than newlines.
    pub fn new(text: impl Into<String>) -> Result<Note, NoteError> {
        let text = text.into();
        check_text(&text)?;
        Ok(Note {
            text,
            signatures: Vec::new(),
        })
    }

    /// Parses a signed note. It must be UTF-8 with no control characters
    /// other than newlines, its text must end in a newline, and a blank
    /// line must separate it from one or more signature lines, each ending
    /// in a newline. Nothing may follow them.
    pub fn parse(bytes: &[u8]) -> Result<Note, NoteError> {
        if bytes.len() > MAX_NOTE_LEN {
            return Err(NoteError::TooLarge);
        }
        let s = std::str::from_utf8(bytes).map_err(|_| NoteError::Malformed("not UTF-8"))?;
        if s.chars().any(|c| c < ' ' && c != '\n') {
            return Err(NoteError::Malformed("control character"));
        }
        // The text is separated from the signatures by the last blank line.
        let split = s
            .rfind("\n\n")
            .ok_or(NoteError::Malformed("no blank line before the signatures"))?;
        let text = &s[..=split];
        let sigs = &s[split + 2..];
        let signatures = NoteSignature::parse_lines(sigs)?;
        Ok(Note {
            text: text.to_owned(),
            signatures,
        })
    }

    /// The note's text, with its final newline.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The note's signatures, in order.
    pub fn signatures(&self) -> &[NoteSignature] {
        &self.signatures
    }

    /// Adds a signature line at the end.
    pub fn push_signature(&mut self, signature: NoteSignature) -> Result<(), NoteError> {
        if !is_valid_key_name(&signature.name) {
            return Err(NoteError::BadKeyName);
        }
        if signature.signature.is_empty() {
            return Err(NoteError::Malformed("signature too short"));
        }
        if self.signatures.len() == MAX_SIGNATURES {
            return Err(NoteError::TooLarge);
        }
        self.signatures.push(signature);
        Ok(())
    }

    /// The signed note: the text, a blank line and the signature lines.
    /// A note with no signatures is not a signed note; this writes the
    /// text and the blank line only.
    pub fn to_text(&self) -> String {
        let mut s = self.text.clone();
        s.push('\n');
        for sig in &self.signatures {
            s.push_str(&sig.to_line());
        }
        s
    }
}

fn check_text(text: &str) -> Result<(), NoteError> {
    if !text.ends_with('\n') {
        return Err(NoteError::Malformed("text must end in a newline"));
    }
    if text.chars().any(|c| c < ' ' && c != '\n') {
        return Err(NoteError::Malformed("control character"));
    }
    Ok(())
}

/// Whether a key name is valid [SIGNED-NOTE]: not empty, and holding no
/// Unicode space and no plus.
pub fn is_valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c == '+' || c.is_control())
}

/// The recommended key id of [SIGNED-NOTE]: the first four bytes of
/// `SHA-256(name || 0x0A || type || public key)`, big-endian.
pub fn key_id(name: &str, sig_type: u8, public_key: &[u8]) -> u32 {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([b'\n', sig_type]);
    h.update(public_key);
    let d = h.finalize();
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// A verifier key, `<name>+<hex key id>+<base64(type || public key)>`
/// [SIGNED-NOTE].
///
/// Parsing checks the format and, for the types whose key id is the
/// recommended hash (`0x01`, `0x04` and `0x06`), that the id matches.
/// Whether a type is accepted is up to the user of the key.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifierKey {
    name: String,
    key_id: u32,
    sig_type: u8,
    public_key: Vec<u8>,
}

impl VerifierKey {
    /// A verifier key whose id is the recommended hash.
    pub fn new(name: &str, sig_type: u8, public_key: &[u8]) -> Result<VerifierKey, NoteError> {
        if !is_valid_key_name(name) {
            return Err(NoteError::BadKeyName);
        }
        Ok(VerifierKey {
            name: name.to_owned(),
            key_id: key_id(name, sig_type, public_key),
            sig_type,
            public_key: public_key.to_vec(),
        })
    }

    /// The key's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key's id.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The signature type.
    pub fn sig_type(&self) -> u8 {
        self.sig_type
    }

    /// The public key, without the type.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl FromStr for VerifierKey {
    type Err = NoteError;

    fn from_str(s: &str) -> Result<VerifierKey, NoteError> {
        // The key name and id hold no plus, but the base64 may.
        let mut parts = s.splitn(3, '+');
        let (Some(name), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(NoteError::BadVerifierKey("not three parts"));
        };
        if !is_valid_key_name(name) {
            return Err(NoteError::BadKeyName);
        }
        if id.len() != 8 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(NoteError::BadVerifierKey(
                "key id is not 8 lower-case hex digits",
            ));
        }
        let key_id =
            u32::from_str_radix(id, 16).map_err(|_| NoteError::BadVerifierKey("bad key id"))?;
        let bytes = BASE64
            .decode(key)
            .map_err(|_| NoteError::BadVerifierKey("key is not canonical base64"))?;
        let (&sig_type, public_key) = bytes
            .split_first()
            .ok_or(NoteError::BadVerifierKey("empty key"))?;
        if public_key.is_empty() {
            return Err(NoteError::BadVerifierKey("empty key"));
        }
        if matches!(sig_type, 0x01 | 0x04 | 0x06)
            && key_id != self::key_id(name, sig_type, public_key)
        {
            return Err(NoteError::BadVerifierKey("key id does not match the key"));
        }
        Ok(VerifierKey {
            name: name.to_owned(),
            key_id,
            sig_type,
            public_key: public_key.to_vec(),
        })
    }
}

impl fmt::Display for VerifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(1 + self.public_key.len());
        bytes.push(self.sig_type);
        bytes.extend_from_slice(&self.public_key);
        write!(
            f,
            "{}+{:08x}+{}",
            self.name,
            self.key_id,
            BASE64.encode(bytes)
        )
    }
}

impl fmt::Debug for VerifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierKey")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .field("sig_type", &self.sig_type)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example of [SIGNED-NOTE]'s "Verifier keys" section.
    const SPEC_VKEY: &str = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
    const SPEC_NOTE: &str = "This is an example message.\n\n\u{2014} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";

    /// golang.org/x/mod/sumdb/note's TestOpen.
    const PETER_KEY: &str = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
    const ENOCH_KEY: &str = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop";
    const GO_TEXT: &str = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n";
    const PETER_SIG: &str = "\u{2014} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
    const ENOCH_SIG: &str = "\u{2014} EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n";

    #[test]
    fn spec_example() {
        let vkey: VerifierKey = SPEC_VKEY.parse().unwrap();
        assert_eq!(vkey.name(), "example.com/foo");
        assert_eq!(vkey.key_id(), 0x530d903a);
        assert_eq!(vkey.sig_type(), 0x01);
        assert_eq!(vkey.public_key().len(), 32);
        // The key id is the recommended hash, for type 0x01.
        assert_eq!(
            key_id("example.com/foo", 0x01, vkey.public_key()),
            0x530d903a
        );
        assert_eq!(vkey.to_string(), SPEC_VKEY);
        assert_eq!(
            VerifierKey::new("example.com/foo", 0x01, vkey.public_key()).unwrap(),
            vkey
        );

        let note = Note::parse(SPEC_NOTE.as_bytes()).unwrap();
        assert_eq!(note.text(), "This is an example message.\n");
        assert_eq!(note.signatures().len(), 1);
        let sig = &note.signatures()[0];
        assert_eq!(
            (sig.name.as_str(), sig.key_id),
            ("example.com/foo", 0x530d903a)
        );
        assert_eq!(sig.signature.len(), 64);
        assert_eq!(note.to_text(), SPEC_NOTE);
    }

    #[test]
    fn go_examples() {
        for k in [PETER_KEY, ENOCH_KEY] {
            let v: VerifierKey = k.parse().unwrap();
            assert_eq!(v.to_string(), k);
        }
        let n = Note::parse(format!("{GO_TEXT}\n{PETER_SIG}{ENOCH_SIG}").as_bytes()).unwrap();
        assert_eq!(n.text(), GO_TEXT);
        let ids: Vec<(&str, u32)> = n
            .signatures()
            .iter()
            .map(|s| (s.name.as_str(), s.key_id))
            .collect();
        assert_eq!(
            ids,
            [("PeterNeumann", 0xc74f20a3), ("EnochRoot", 0xaf0cfe78)]
        );

        // golang.org/x/mod/sumdb/note's bad keys: wrong key length with an
        // adjusted hash is a format question for the algorithm, but an
        // unknown type with an id that is not the hash of 0x01 parses as
        // an unknown type.
        let bad: VerifierKey = "PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
            .parse()
            .unwrap();
        assert_eq!(bad.sig_type(), 0x65);
        // A changed id no longer matches the key.
        assert!(
            "PeterNeumann+c74f20a4+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
                .parse::<VerifierKey>()
                .is_err()
        );

        // Its malformed notes.
        let bad_notes = [
            GO_TEXT.to_owned(),
            format!("{GO_TEXT}\n"),
            format!("{GO_TEXT}\n{}", &PETER_SIG[..PETER_SIG.len() - 1]),
            format!("\x01{GO_TEXT}\n{PETER_SIG}"),
            format!(
                "{GO_TEXT}\n\u{2014} Bad Name x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM="
            ),
            format!("{GO_TEXT}\n{PETER_SIG}Unexpected line.\n"),
        ];
        for bad in &bad_notes {
            assert!(Note::parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let mut invalid_utf8 = b"\xff".to_vec();
        invalid_utf8.extend_from_slice(format!("{GO_TEXT}\n{PETER_SIG}").as_bytes());
        assert!(Note::parse(&invalid_utf8).is_err());
        // Too many signatures: the Go test uses 101.
        let many = format!("{GO_TEXT}\n{}", PETER_SIG.repeat(101));
        assert_eq!(Note::parse(many.as_bytes()), Err(NoteError::TooLarge));
        let enough = format!("{GO_TEXT}\n{}", PETER_SIG.repeat(100));
        assert!(Note::parse(enough.as_bytes()).is_ok());
    }

    #[test]
    fn blank_lines_in_the_text() {
        let raw = format!("a\n\nb\n\n{PETER_SIG}");
        let n = Note::parse(raw.as_bytes()).unwrap();
        assert_eq!(n.text(), "a\n\nb\n");
        assert_eq!(n.to_text(), raw);
        let raw = format!("a\n\n\n{PETER_SIG}");
        let n = Note::parse(raw.as_bytes()).unwrap();
        assert_eq!(n.text(), "a\n\n");
        assert_eq!(n.to_text(), raw);
    }

    #[test]
    fn rejects_bad_signatures_and_names() {
        let line = |name: &str, b64: &str| format!("{GO_TEXT}\n\u{2014} {name} {b64}\n");
        // Four bytes of id and nothing more.
        assert!(Note::parse(line("a", "AAAAAA==").as_bytes()).is_err());
        assert!(Note::parse(line("a", "AAAAAAA=").as_bytes()).is_ok());
        // Non-canonical base64: trailing bits set.
        assert!(Note::parse(line("a", "AAAAAAB=").as_bytes()).is_err());
        assert!(Note::parse(line("a", "AAAAAAA").as_bytes()).is_err());
        assert!(Note::parse(line("a+b", "AAAAAAA=").as_bytes()).is_err());
        assert!(Note::parse(line("a\u{a0}b", "AAAAAAA=").as_bytes()).is_err());
        assert!(Note::parse(format!("{GO_TEXT}\n- a AAAAAAA=\n").as_bytes()).is_err());
        assert!(Note::parse(format!("{GO_TEXT}\n\u{2014}  a AAAAAAA=\n").as_bytes()).is_err());
        assert!(Note::parse(format!("{GO_TEXT}\n\u{2014} a AAAAAAA= \n").as_bytes()).is_err());
        assert!(Note::parse(format!("{GO_TEXT}\r\n\u{2014} a AAAAAAA=\n").as_bytes()).is_err());

        assert!(is_valid_key_name("example.com/log"));
        for bad in ["", "a b", "a+b", "a\tb", "a\u{2003}b"] {
            assert!(!is_valid_key_name(bad), "{bad:?}");
        }
        assert!(Note::new("no newline").is_err());
        assert!(Note::new("tab\there\n").is_err());
    }

    #[test]
    fn rejects_bad_verifier_keys() {
        for bad in [
            "",
            "a",
            "a+530d903a",
            "a+530d903a+AQ==+x",
            "example.com/foo+530D903A+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
            "example.com/foo+530d903+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
            "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2",
            "example.com/foo+530d903a+",
            "example.com/foo+530d903a+AQ==",
            "+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
        ] {
            assert!(bad.parse::<VerifierKey>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn signature_lines() {
        let sigs = NoteSignature::parse_lines(&format!("{PETER_SIG}{ENOCH_SIG}")).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].to_line(), PETER_SIG);
        assert!(NoteSignature::parse_lines("").is_err());
        assert!(NoteSignature::parse_lines("\n").is_err());
        assert!(NoteSignature::parse_lines(&PETER_SIG[..PETER_SIG.len() - 1]).is_err());
    }
}

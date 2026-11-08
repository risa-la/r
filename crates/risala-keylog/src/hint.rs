//! The three small text files a key log serves under its URL prefix,
//! which is always `https://` followed by its origin (SPEC 4.5). Each line
//! ends with LF, and each file starts with a line that names its version
//! (SPEC 2.4):
//!
//! - `risala/uid/<hash>`, where `<hash>` is the SHA-256 hash of a uid in
//!   lower-case hex: the line `risala-hint/1`, then the indices of that
//!   uid's entries in this log, one number per line, in increasing order;
//!   or a 404 response if the log holds none;
//! - `risala/next`: the line `risala-hint/1`, then the index of the log's
//!   hand-off entry, once it has one; a 404 response before;
//! - `risala/key`: the line `risala-log-key/1`, then the log's verifier
//!   key, as in a key file's `log` line. Witnesses fetch it to enrol a
//!   host's first log (SPEC 4.10, [`crate::witnessing`]).
//!
//! Hints are not signed. A reader checks every index it uses with an
//! inclusion proof against a witnessed checkpoint, and a log that leaves an
//! entry out of a uid's hint is caught by that identity's own devices,
//! which read the log's entry bundles (SPEC 4.5, "Watching your own
//! records").
//!
//! A device uses them each time it fetches an identity's key file again
//! (SPEC 4.5, "Freshness"): `risala/next` to follow a hand-off to the
//! host's next log ([`crate::client::accept_handoff`]), and the uid's hint
//! to find logged records of the uid after its head that the key file
//! leaves out ([`UidHint::unlisted`]). Each such index is then read from
//! its entry bundle and proved with
//! [`verify_bundle_entry`](crate::client::verify_bundle_entry); a record
//! there that the key file does not hold makes the key file a fork or a
//! rollback, which the caller decides from the records' `previous` fields.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::checkpoint::{LogOrigin, parse_decimal};
use crate::witness::LogKey;

/// The first line of the two hints (SPEC 4.5, 15).
pub const HINT_HEADER: &str = "risala-hint/1";

/// The first line of the log's key file (SPEC 4.5, 15).
pub const LOG_KEY_HEADER: &str = "risala-log-key/1";

/// The path of the hand-off hint, under the log's URL prefix.
pub const NEXT_PATH: &str = "risala/next";

/// The path of the log's key file, under its URL prefix (SPEC 4.5, 15).
pub const KEY_PATH: &str = "risala/key";

/// The most bytes a witness reads of a log's key file, as of a key file
/// (SPEC 4.4, 4.10).
pub const MAX_LOG_KEY_FILE: usize = 64 * 1024;

/// The start of a uid hint's path, under the log's URL prefix.
pub const UID_PATH: &str = "risala/uid/";

/// The most indices a uid hint may list. A log appends at most one record
/// per place in a uid's chain, and a chain has at most 4,096 records (SPEC
/// 4.4, 4.5), so a longer hint is not a valid one. (SPEC 4.5 sets no
/// limit of its own; a choice to confirm.)
pub const MAX_UID_ENTRIES: usize = 4096;

/// The largest number SPEC 3.3 allows, 2^63 - 1.
const MAX_NUMBER: u64 = i64::MAX as u64;

/// Why a hint did not parse.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HintError {
    /// The first line is not the version line, the body lists nothing, a
    /// line is not a number (SPEC 3.3), or a line does not end with LF.
    #[error("malformed hint: {0}")]
    Malformed(&'static str),
    /// The indices are not in strictly increasing order.
    #[error("hint indices are not in increasing order")]
    NotIncreasing,
    /// The hint lists more than [`MAX_UID_ENTRIES`] indices.
    #[error("the hint lists too many indices")]
    TooMany,
}

/// The path of a uid's hint, under the log's URL prefix:
/// `risala/uid/<SHA-256 of the uid, in lower-case hex>`.
///
/// The uid must be in its lower-case form, as key file records hold it
/// (SPEC 4.4); this hashes its bytes as they are.
pub fn uid_hint_path(uid: &str) -> String {
    let mut path = String::with_capacity(UID_PATH.len() + 64);
    path.push_str(UID_PATH);
    for b in Sha256::digest(uid.as_bytes()) {
        write!(path, "{b:02x}").expect("writing to a String");
    }
    path
}

/// The indices of a uid's entries in one log, from its `risala/uid/` hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UidHint {
    indices: Vec<u64>,
}

impl UidHint {
    /// A hint listing these indices, which must be strictly increasing,
    /// not empty, and at most [`MAX_UID_ENTRIES`].
    pub fn new(indices: Vec<u64>) -> Result<UidHint, HintError> {
        if indices.is_empty() {
            return Err(HintError::Malformed("no indices"));
        }
        if indices.len() > MAX_UID_ENTRIES {
            return Err(HintError::TooMany);
        }
        if indices.iter().any(|&i| i > MAX_NUMBER) {
            return Err(HintError::Malformed("index larger than 2^63 - 1"));
        }
        if !indices.windows(2).all(|w| w[0] < w[1]) {
            return Err(HintError::NotIncreasing);
        }
        Ok(UidHint { indices })
    }

    /// Parses the body of a 200 response. A log with no entries of the uid
    /// answers 404 instead, so a body that lists none is malformed.
    pub fn parse(body: &[u8]) -> Result<UidHint, HintError> {
        // The version line, then lines of at most 19 digits and an LF.
        if body.len() > HINT_HEADER.len() + 1 + MAX_UID_ENTRIES * 20 {
            return Err(HintError::TooMany);
        }
        let indices = hint_lines(body)?
            .map(parse_number)
            .collect::<Result<Vec<_>, _>>()?;
        UidHint::new(indices)
    }

    /// The body of the hint.
    pub fn to_body(&self) -> String {
        let mut s = String::with_capacity(HINT_HEADER.len() + 1 + self.indices.len() * 8);
        writeln!(s, "{HINT_HEADER}").expect("writing to a String");
        for i in &self.indices {
            writeln!(s, "{i}").expect("writing to a String");
        }
        s
    }

    /// The indices, in increasing order.
    pub fn indices(&self) -> &[u64] {
        &self.indices
    }

    /// The indices after the device's head that the key file does not list,
    /// which the device must check (SPEC 4.5, "Freshness", step 2).
    ///
    /// `head` is the index of the device's head in this log, or `None` if
    /// its head is in an earlier log of the host, or it has none, so that
    /// every entry of this log counts as after it. `listed` holds the
    /// indices of the key file's `<index> <hash>` lines for this log, in
    /// any order.
    pub fn unlisted(&self, head: Option<u64>, listed: &[u64]) -> Vec<u64> {
        self.indices
            .iter()
            .copied()
            .filter(|&i| head.is_none_or(|h| i > h) && !listed.contains(&i))
            .collect()
    }
}

/// Parses the body of a `risala/next` 200 response: the index of the log's
/// hand-off entry.
pub fn parse_next(body: &[u8]) -> Result<u64, HintError> {
    let mut lines = hint_lines(body)?;
    let index = lines.next().map(parse_number).transpose()?;
    match (index, lines.next()) {
        (Some(index), None) => Ok(index),
        _ => Err(HintError::Malformed("risala/next holds one index")),
    }
}

/// The body of a `risala/next` response.
pub fn next_body(index: u64) -> String {
    format!("{HINT_HEADER}\n{index}\n")
}

/// The lines of a hint after its version line, which must be
/// [`HINT_HEADER`]; every line ends with LF.
fn hint_lines(body: &[u8]) -> Result<std::str::Split<'_, char>, HintError> {
    let text = std::str::from_utf8(body).map_err(|_| HintError::Malformed("not UTF-8"))?;
    let text = text
        .strip_suffix('\n')
        .ok_or(HintError::Malformed("does not end with LF"))?;
    let mut lines = text.split('\n');
    if lines.next() != Some(HINT_HEADER) {
        return Err(HintError::Malformed("does not start with risala-hint/1"));
    }
    Ok(lines)
}

/// The body of a log's `risala/key` file: [`LOG_KEY_HEADER`], then the
/// log's verifier key, each on a line of its own (SPEC 4.5).
pub fn log_key_body(key: &LogKey) -> String {
    format!("{LOG_KEY_HEADER}\n{}\n", key.verifier().vkey())
}

/// Parses a log's `risala/key` file, as a witness does to enrol log 1 of a
/// host (SPEC 4.10): the version line, then a verifier key whose name is
/// `origin` and whose key ID is right, of type `0x06`, and nothing else.
/// At most [`MAX_LOG_KEY_FILE`] bytes.
pub fn parse_log_key(body: &[u8], origin: &LogOrigin) -> Result<LogKey, HintError> {
    if body.len() > MAX_LOG_KEY_FILE {
        return Err(HintError::Malformed("a log's key file is at most 64 KiB"));
    }
    let text = std::str::from_utf8(body).map_err(|_| HintError::Malformed("not UTF-8"))?;
    let text = text
        .strip_suffix('\n')
        .ok_or(HintError::Malformed("does not end with LF"))?;
    let (header, vkey) = text
        .split_once('\n')
        .ok_or(HintError::Malformed("a log's key file has two lines"))?;
    if header != LOG_KEY_HEADER {
        return Err(HintError::Malformed("does not start with risala-log-key/1"));
    }
    if vkey.contains('\n') {
        return Err(HintError::Malformed("a log's key file has two lines"));
    }
    let key = LogKey::from_vkey_str(vkey)
        .map_err(|_| HintError::Malformed("not a log's verifier key"))?;
    if key.origin() != origin {
        return Err(HintError::Malformed("the key names another log"));
    }
    Ok(key)
}

fn parse_number(s: &str) -> Result<u64, HintError> {
    parse_decimal(s)
        .filter(|&n| n <= MAX_NUMBER)
        .ok_or(HintError::Malformed("not a number"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_paths() {
        // SHA-256 of "alice@example.org".
        assert_eq!(
            uid_hint_path("alice@example.org"),
            format!(
                "risala/uid/{}",
                "7a64adf28737ea90719cbdf0b1a87a5effff3753b79c91d717f4f4153ead0498"
            )
        );
        assert_eq!(uid_hint_path("").len(), UID_PATH.len() + 64);
    }

    fn hint(lines: &[u8]) -> Vec<u8> {
        [b"risala-hint/1\n", lines].concat()
    }

    #[test]
    fn uid_hints() {
        let h = UidHint::parse(&hint(b"0\n7\n300\n")).unwrap();
        assert_eq!(h.indices(), [0, 7, 300]);
        assert_eq!(h.to_body(), "risala-hint/1\n0\n7\n300\n");
        assert_eq!(
            UidHint::parse(&hint(b"9223372036854775807\n"))
                .unwrap()
                .indices(),
            [i64::MAX as u64]
        );

        for bad in [
            &b""[..],
            b"\n",
            b"1",
            b"1\n\n",
            b"1\n2",
            b"01\n",
            b"+1\n",
            b"1 \n",
            b"1\r\n",
            b"a\n",
            b"9223372036854775808\n",
            b"\xff\n",
        ] {
            assert!(
                matches!(UidHint::parse(&hint(bad)), Err(HintError::Malformed(_))),
                "{bad:?}"
            );
        }
        // The version line comes first (SPEC 4.5), exactly.
        for bad in [
            &b"1\n"[..],
            b"risala-hint/2\n1\n",
            b"RISALA-HINT/1\n1\n",
            b"risala-hint/1\n",
            b"risala-hint/1",
            b"\nrisala-hint/1\n1\n",
        ] {
            assert!(
                matches!(UidHint::parse(bad), Err(HintError::Malformed(_))),
                "{bad:?}"
            );
        }
        assert_eq!(
            UidHint::parse(&hint(b"2\n1\n")),
            Err(HintError::NotIncreasing)
        );
        assert_eq!(
            UidHint::parse(&hint(b"1\n1\n")),
            Err(HintError::NotIncreasing)
        );

        let many: Vec<u64> = (0..=MAX_UID_ENTRIES as u64).collect();
        assert_eq!(UidHint::new(many.clone()), Err(HintError::TooMany));
        let ok = UidHint::new(many[..MAX_UID_ENTRIES].to_vec()).unwrap();
        assert_eq!(UidHint::parse(ok.to_body().as_bytes()), Ok(ok));
        let body: String = many.iter().map(|i| format!("{i}\n")).collect();
        assert_eq!(
            UidHint::parse(&hint(body.as_bytes())),
            Err(HintError::TooMany)
        );
    }

    #[test]
    fn unlisted_entries() {
        let h = UidHint::new(vec![2, 5, 9, 12]).unwrap();
        assert_eq!(h.unlisted(None, &[]), [2, 5, 9, 12]);
        assert_eq!(h.unlisted(Some(5), &[]), [9, 12]);
        assert_eq!(h.unlisted(Some(5), &[12, 2]), [9]);
        assert_eq!(h.unlisted(None, &[2, 5, 9, 12]), [] as [u64; 0]);
    }

    #[test]
    fn next_hints() {
        assert_eq!(parse_next(b"risala-hint/1\n41\n"), Ok(41));
        assert_eq!(next_body(41), "risala-hint/1\n41\n");
        for bad in [
            &b""[..],
            b"41",
            b"41\n\n",
            b"041\n",
            b"4 1\n",
            b"-1\n",
            b"41\n42\n",
        ] {
            assert!(parse_next(&hint(bad)).is_err(), "{bad:?}");
        }
        for bad in [&b"41\n"[..], b"risala-hint/1\n", b"risala-hint/2\n41\n"] {
            assert!(parse_next(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn log_key_files() {
        let origin: LogOrigin = "chat.example.org/risala-log/1".parse().unwrap();
        let cosigner = crate::cosig::Cosigner::from_seed(&origin.to_string(), &[1; 32]).unwrap();
        let key = LogKey::new(cosigner.verifier()).unwrap();
        let body = log_key_body(&key);
        assert!(body.starts_with("risala-log-key/1\nchat.example.org/risala-log/1+"));
        assert!(body.ends_with("=\n"));
        assert_eq!(parse_log_key(body.as_bytes(), &origin), Ok(key.clone()));

        // Another origin's key, a key of another log of the host.
        let log2 = origin.next().unwrap();
        assert!(parse_log_key(body.as_bytes(), &log2).is_err());
        // A wrong key ID, a wrong version line, extra lines, no LF.
        let vkey = key.verifier().vkey().to_string();
        let (name, rest) = vkey.split_once('+').unwrap();
        let (id, b64) = rest.split_once('+').unwrap();
        let wrong_id = format!(
            "{name}+{}+{b64}",
            if id == "00000000" {
                "00000001"
            } else {
                "00000000"
            }
        );
        for bad in [
            format!("risala-log-key/1\n{wrong_id}\n"),
            format!("risala-log-key/2\n{vkey}\n"),
            format!("risala-hint/1\n{vkey}\n"),
            format!("{vkey}\n"),
            format!("risala-log-key/1\n{vkey}"),
            format!("risala-log-key/1\n{vkey}\n\n"),
            format!("risala-log-key/1\n{vkey}\n{vkey}\n"),
            format!("risala-log-key/1\r\n{vkey}\r\n"),
            "risala-log-key/1\n\n".to_owned(),
        ] {
            assert!(parse_log_key(bad.as_bytes(), &origin).is_err(), "{bad:?}");
        }
        let huge = format!("{body}{}", " ".repeat(MAX_LOG_KEY_FILE));
        assert!(parse_log_key(huge.as_bytes(), &origin).is_err());
    }
}

//! The two hint files a key log serves under its URL prefix (SPEC 4.5):
//!
//! - `risala/uid/<hash>`, where `<hash>` is the SHA-256 hash of a uid in
//!   lower-case hex: the indices of that uid's entries, one number per
//!   line, in increasing order, each line ending with LF; or a 404
//!   response if the log holds none;
//! - `risala/next`: the index of the log's hand-off entry, a number and an
//!   LF, once it has one; a 404 response before.
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

use crate::checkpoint::parse_decimal;

/// The path of the hand-off hint, under the log's URL prefix.
pub const NEXT_PATH: &str = "risala/next";

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
    /// The body is empty, a line is not a number (SPEC 3.3), or a line
    /// does not end with LF.
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
    /// answers 404 instead, so an empty body is malformed.
    pub fn parse(body: &[u8]) -> Result<UidHint, HintError> {
        // Each line is at most 19 digits and an LF.
        if body.len() > MAX_UID_ENTRIES * 20 {
            return Err(HintError::TooMany);
        }
        let text = std::str::from_utf8(body).map_err(|_| HintError::Malformed("not UTF-8"))?;
        let text = text
            .strip_suffix('\n')
            .ok_or(HintError::Malformed("does not end with LF"))?;
        let indices = text
            .split('\n')
            .map(parse_number)
            .collect::<Result<Vec<_>, _>>()?;
        UidHint::new(indices)
    }

    /// The body of the hint.
    pub fn to_body(&self) -> String {
        let mut s = String::with_capacity(self.indices.len() * 8);
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
    let text = std::str::from_utf8(body).map_err(|_| HintError::Malformed("not UTF-8"))?;
    let line = text
        .strip_suffix('\n')
        .ok_or(HintError::Malformed("does not end with LF"))?;
    parse_number(line)
}

/// The body of a `risala/next` response.
pub fn next_body(index: u64) -> String {
    format!("{index}\n")
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

    #[test]
    fn uid_hints() {
        let h = UidHint::parse(b"0\n7\n300\n").unwrap();
        assert_eq!(h.indices(), [0, 7, 300]);
        assert_eq!(h.to_body(), "0\n7\n300\n");
        assert_eq!(
            UidHint::parse(b"9223372036854775807\n").unwrap().indices(),
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
                matches!(UidHint::parse(bad), Err(HintError::Malformed(_))),
                "{bad:?}"
            );
        }
        assert_eq!(UidHint::parse(b"2\n1\n"), Err(HintError::NotIncreasing));
        assert_eq!(UidHint::parse(b"1\n1\n"), Err(HintError::NotIncreasing));

        let many: Vec<u64> = (0..=MAX_UID_ENTRIES as u64).collect();
        assert_eq!(UidHint::new(many.clone()), Err(HintError::TooMany));
        let ok = UidHint::new(many[..MAX_UID_ENTRIES].to_vec()).unwrap();
        assert_eq!(UidHint::parse(ok.to_body().as_bytes()), Ok(ok));
        let body: String = many.iter().map(|i| format!("{i}\n")).collect();
        assert_eq!(UidHint::parse(body.as_bytes()), Err(HintError::TooMany));
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
        assert_eq!(parse_next(b"41\n"), Ok(41));
        assert_eq!(next_body(41), "41\n");
        for bad in [&b""[..], b"41", b"41\n\n", b"041\n", b"4 1\n", b"-1\n"] {
            assert!(parse_next(bad).is_err(), "{bad:?}");
        }
    }
}

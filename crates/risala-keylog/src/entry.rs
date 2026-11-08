//! Key log entries (SPEC 4.5): an encoded `LogEntry`, which holds either a
//! key file Record or a hand-off to the host's next log.
//!
//! ```text
//! enum { reserved(0), record(1), handoff(2), (255) } LogEntryType;
//!
//! struct {
//!     uint8 version;               // 1
//!     LogEntryType type;
//!     select (LogEntry.type) {
//!         case record:  Record record;   // 4.4
//!         case handoff: LogKey next;     // the log that takes over
//!     };
//! } LogEntry;
//!
//! struct {
//!     opaque origin<V>;            // the log's origin, in ASCII
//!     opaque key<V>;               // 0x06, then the 1312-byte ML-DSA-44 public key
//! } LogKey;
//! ```
//!
//! What a Record holds is not this crate's business (it belongs with the
//! key file formats of SPEC 4.4): here a record entry carries the encoded
//! Record as bytes, which run to the end of the entry. A Record is a
//! struct, not a vector, so nothing else marks where it ends.

use sha2::{Digest, Sha384};
use thiserror::Error;

use crate::cosig::{CosignatureVerifier, PUBLIC_KEY_LEN, SIG_TYPE};
use crate::witness::LogKey;

/// The LogEntry version this crate reads and writes.
pub const VERSION: u8 = 1;

/// The largest encoded Record a log appends (SPEC 4.4, 4.5).
pub const MAX_RECORD_LEN: usize = 16 * 1024;

/// The largest encoded LogEntry: a record entry with the largest Record.
/// A hand-off entry is about 1.3 KB.
pub const MAX_ENTRY_LEN: usize = 2 + MAX_RECORD_LEN;

/// The length of a SHA-384 hash, which key files name records by.
pub const RECORD_HASH_LEN: usize = 48;

/// A key log entry's type (SPEC 4.5, 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogEntryType {
    /// A key file Record.
    Record = 1,
    /// A hand-off to the host's next log.
    Handoff = 2,
}

/// A key log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogEntry {
    /// An encoded Record (SPEC 4.4), not decoded here.
    Record(Vec<u8>),
    /// A hand-off: the log that takes over from this one.
    Handoff(LogKey),
}

/// Why bytes are not a LogEntry, or a LogKey.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    /// The entry is shorter than its fields, or has bytes after them.
    #[error("malformed log entry: {0}")]
    Malformed(&'static str),
    /// The version is not 1.
    #[error("unknown log entry version {0}")]
    UnknownVersion(u8),
    /// The type is not `record` or `handoff`.
    #[error("unknown log entry type {0}")]
    UnknownType(u8),
    /// The Record is empty, or longer than 16 KiB.
    #[error("the record is empty or longer than 16 KiB")]
    RecordSize,
    /// A LogKey's origin is not `<host>/risala-log/<n>`, or its key is not
    /// `0x06` and a 1312-byte ML-DSA-44 public key.
    #[error("not a key log's LogKey: {0}")]
    BadLogKey(&'static str),
}

impl LogEntry {
    /// The entry's type.
    pub fn entry_type(&self) -> LogEntryType {
        match self {
            LogEntry::Record(_) => LogEntryType::Record,
            LogEntry::Handoff(_) => LogEntryType::Handoff,
        }
    }

    /// A record entry. The Record must be 1 to 16384 bytes.
    pub fn record(record: &[u8]) -> Result<LogEntry, EntryError> {
        if record.is_empty() || record.len() > MAX_RECORD_LEN {
            return Err(EntryError::RecordSize);
        }
        Ok(LogEntry::Record(record.to_vec()))
    }

    /// The encoded entry.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION, self.entry_type() as u8];
        match self {
            LogEntry::Record(r) => out.extend_from_slice(r),
            LogEntry::Handoff(next) => out.extend_from_slice(&encode_log_key(next)),
        }
        out
    }

    /// Decodes an entry exactly: version 1, a known type, and nothing after
    /// a hand-off's LogKey. A Record is taken as it is, up to 16 KiB; the
    /// reader decodes it under SPEC 4.4's rules.
    pub fn decode(bytes: &[u8]) -> Result<LogEntry, EntryError> {
        let [version, ty, body @ ..] = bytes else {
            return Err(EntryError::Malformed("shorter than its header"));
        };
        if *version != VERSION {
            return Err(EntryError::UnknownVersion(*version));
        }
        match *ty {
            1 => LogEntry::record(body),
            2 => {
                let (key, rest) = decode_log_key(body)?;
                if !rest.is_empty() {
                    return Err(EntryError::Malformed("bytes after the LogKey"));
                }
                Ok(LogEntry::Handoff(key))
            }
            other => Err(EntryError::UnknownType(other)),
        }
    }

    /// The Record, for a record entry.
    pub fn as_record(&self) -> Option<&[u8]> {
        match self {
            LogEntry::Record(r) => Some(r),
            LogEntry::Handoff(_) => None,
        }
    }

    /// The next log, for a hand-off entry.
    pub fn as_handoff(&self) -> Option<&LogKey> {
        match self {
            LogEntry::Record(_) => None,
            LogEntry::Handoff(k) => Some(k),
        }
    }
}

/// The SHA-384 hash of an encoded Record: what a key file's `<hash>` names
/// it by (SPEC 4.4).
pub fn record_hash(record: &[u8]) -> [u8; RECORD_HASH_LEN] {
    Sha384::digest(record).into()
}

/// Encodes a LogKey: the origin, and `0x06` followed by the public key,
/// each as an RFC 9420 vector.
pub fn encode_log_key(key: &LogKey) -> Vec<u8> {
    let origin = key.origin().to_string();
    let mut k = Vec::with_capacity(1 + PUBLIC_KEY_LEN);
    k.push(SIG_TYPE);
    k.extend_from_slice(key.verifier().public_key());
    let mut out = Vec::with_capacity(4 + origin.len() + k.len());
    put_vector(&mut out, origin.as_bytes());
    put_vector(&mut out, &k);
    out
}

/// Decodes a LogKey from the front of `bytes`, and returns it with the
/// bytes after it. Vector lengths must be in their shortest form (RFC
/// 9420), the origin `<host>/risala-log/<n>`, and the key `0x06` and 1312
/// bytes.
pub fn decode_log_key(bytes: &[u8]) -> Result<(LogKey, &[u8]), EntryError> {
    let (origin, rest) = get_vector(bytes)?;
    let (key, rest) = get_vector(rest)?;
    let origin = std::str::from_utf8(origin)
        .ok()
        .filter(|o| o.is_ascii())
        .ok_or(EntryError::BadLogKey("origin is not ASCII"))?;
    let origin_ok = origin.parse::<crate::checkpoint::LogOrigin>().is_ok();
    if !origin_ok {
        return Err(EntryError::BadLogKey("origin is not <host>/risala-log/<n>"));
    }
    let Some((&SIG_TYPE, public_key)) = key.split_first() else {
        return Err(EntryError::BadLogKey("key does not start with 0x06"));
    };
    let public_key: &[u8; PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| EntryError::BadLogKey("key is not 1312 bytes"))?;
    let verifier = CosignatureVerifier::new(origin, public_key)
        .map_err(|_| EntryError::BadLogKey("origin is not a valid name"))?;
    let key = LogKey::new(verifier)
        .map_err(|_| EntryError::BadLogKey("origin is not <host>/risala-log/<n>"))?;
    Ok((key, rest))
}

/// Writes an RFC 9420 variable-length vector: its length in the shortest
/// of the 1, 2 or 4-byte forms, then the bytes.
fn put_vector(out: &mut Vec<u8>, bytes: &[u8]) {
    let n = bytes.len();
    if n < 1 << 6 {
        out.push(n as u8);
    } else if n < 1 << 14 {
        out.extend_from_slice(&(0x4000 | n as u16).to_be_bytes());
    } else {
        assert!(n < 1 << 30, "an RFC 9420 vector is shorter than 2^30");
        out.extend_from_slice(&(0x8000_0000 | n as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// Reads an RFC 9420 variable-length vector, whose length must be in its
/// shortest form.
fn get_vector(bytes: &[u8]) -> Result<(&[u8], &[u8]), EntryError> {
    let short = EntryError::Malformed("vector longer than the entry");
    let first = *bytes.first().ok_or(short)?;
    let (len, used) = match first >> 6 {
        0 => (usize::from(first), 1),
        1 => {
            let b: [u8; 2] = bytes.get(..2).ok_or(short)?.try_into().expect("2 bytes");
            (usize::from(u16::from_be_bytes(b) & 0x3fff), 2)
        }
        2 => {
            let b: [u8; 4] = bytes.get(..4).ok_or(short)?.try_into().expect("4 bytes");
            let n = u32::from_be_bytes(b) & 0x3fff_ffff;
            (usize::try_from(n).map_err(|_| short)?, 4)
        }
        _ => return Err(EntryError::Malformed("vector length prefix 0b11")),
    };
    let shortest: usize = match len {
        0..64 => 1,
        64..16384 => 2,
        _ => 4,
    };
    if used != shortest {
        return Err(EntryError::Malformed(
            "vector length not in its shortest form",
        ));
    }
    let end = used.checked_add(len).ok_or(short)?;
    let body = bytes.get(used..end).ok_or(short)?;
    Ok((body, &bytes[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosig::Cosigner;

    fn log_key(origin: &str) -> LogKey {
        LogKey::new(Cosigner::from_seed(origin, &[3; 32]).unwrap().verifier()).unwrap()
    }

    #[test]
    fn record_entries() {
        let e = LogEntry::record(b"a record").unwrap();
        let bytes = e.encode();
        assert_eq!(bytes, b"\x01\x01a record");
        assert_eq!(LogEntry::decode(&bytes), Ok(e.clone()));
        assert_eq!(e.as_record(), Some(&b"a record"[..]));
        assert_eq!(e.as_handoff(), None);
        assert_eq!(e.entry_type(), LogEntryType::Record);

        let max = vec![7; MAX_RECORD_LEN];
        let e = LogEntry::record(&max).unwrap();
        assert_eq!(e.encode().len(), MAX_ENTRY_LEN);
        assert_eq!(LogEntry::decode(&e.encode()), Ok(e));
        assert_eq!(
            LogEntry::record(&[7; MAX_RECORD_LEN + 1]),
            Err(EntryError::RecordSize)
        );
        assert_eq!(LogEntry::decode(b"\x01\x01"), Err(EntryError::RecordSize));
        let mut long = vec![1, 1];
        long.extend_from_slice(&[0; MAX_RECORD_LEN + 1]);
        assert_eq!(LogEntry::decode(&long), Err(EntryError::RecordSize));
    }

    #[test]
    fn handoff_entries() {
        let next = log_key("chat.example.org/risala-log/2");
        let e = LogEntry::Handoff(next.clone());
        let bytes = e.encode();
        // version, type, origin (1-byte length), key (2-byte length 1313).
        let origin = b"chat.example.org/risala-log/2";
        assert_eq!(&bytes[..3], &[1, 2, origin.len() as u8]);
        assert_eq!(&bytes[3..3 + origin.len()], origin);
        let k = 3 + origin.len();
        assert_eq!(&bytes[k..k + 3], &[0x45, 0x21, 0x06]);
        assert_eq!(&bytes[k + 3..], next.verifier().public_key());
        assert_eq!(bytes.len(), 3 + origin.len() + 2 + 1313);
        assert_eq!(LogEntry::decode(&bytes), Ok(e.clone()));
        assert_eq!(e.as_handoff(), Some(&next));
        assert_eq!(e.as_record(), None);

        // Trailing bytes, a short key, the wrong type byte, a bad origin.
        let mut b = bytes.clone();
        b.push(0);
        assert!(LogEntry::decode(&b).is_err());
        let mut b = bytes.clone();
        b.pop();
        assert!(LogEntry::decode(&b).is_err());
        let mut b = bytes.clone();
        b[k + 2] = 0x04;
        assert!(matches!(
            LogEntry::decode(&b),
            Err(EntryError::BadLogKey(_))
        ));
        let mut b = bytes.clone();
        b[3] = b'C';
        assert!(matches!(
            LogEntry::decode(&b),
            Err(EntryError::BadLogKey(_))
        ));
    }

    #[test]
    fn rejects_bad_headers_and_lengths() {
        assert!(matches!(
            LogEntry::decode(b""),
            Err(EntryError::Malformed(_))
        ));
        assert!(matches!(
            LogEntry::decode(b"\x01"),
            Err(EntryError::Malformed(_))
        ));
        assert_eq!(
            LogEntry::decode(b"\x02\x01x"),
            Err(EntryError::UnknownVersion(2))
        );
        assert_eq!(
            LogEntry::decode(b"\x01\x00x"),
            Err(EntryError::UnknownType(0))
        );
        assert_eq!(
            LogEntry::decode(b"\x01\x03x"),
            Err(EntryError::UnknownType(3))
        );

        // Lengths not in their shortest form.
        assert_eq!(
            get_vector(&[0x40, 0x01, 9]).map(|v| v.0),
            Err(EntryError::Malformed(
                "vector length not in its shortest form"
            ))
        );
        assert!(get_vector(&[0x80, 0, 0, 1, 9]).is_err());
        assert!(get_vector(&[0xc0, 0]).is_err());
        assert_eq!(get_vector(&[1, 9, 8]), Ok((&[9][..], &[8][..])));
        let mut v = Vec::new();
        put_vector(&mut v, &[5; 64]);
        assert_eq!(&v[..2], &[0x40, 64]);
        assert_eq!(get_vector(&v), Ok((&[5; 64][..], &[][..])));
        let mut v = Vec::new();
        put_vector(&mut v, &[5; 16384]);
        assert_eq!(&v[..4], &[0x80, 0, 0x40, 0]);
        assert_eq!(get_vector(&v).unwrap().0.len(), 16384);
    }

    #[test]
    fn record_hashes() {
        // SHA-384 of "abc", FIPS 180-2's example.
        let h = record_hash(b"abc");
        assert_eq!(h[..4], [0xcb, 0x00, 0x75, 0x3f]);
        assert_eq!(h[44..], [0x34, 0xc8, 0x25, 0xa7]);
    }
}

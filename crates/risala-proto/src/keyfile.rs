//! Key files (SPEC 4.3, 4.4): the text format, its parsing, and the
//! whole check that turns a fetch into one of the three states of 4.4.
//!
//! ```text
//! risala-keys/1
//! log chat.example.org/risala-log/1+4d1e07a2+BhO3…Zw== https://chat.example.org/risala-log/1
//! 0 sha384:5f0c…
//! 7 sha384:91aa…
//! - AQMRYWxpY2VAZXhhbXBsZS5vcmcw…
//! ```
//!
//! [`KeyFile::parse`] checks the text rules of 4.4 and decodes each
//! unlogged record. [`KeyFile::check`] then gets the record of each
//! `<index> <hash>` line from the log, replays the chain
//! ([`Chain`]) and gives a [`KeyFileState`]. [`read_key_file`] does both
//! for an HTTP response, under 4.4's rules for what is an outage and what
//! makes the keys missing.

pub mod m5a;

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;

use crate::chain::{Chain, ChainError, Handoffs};
use crate::names::{BlobRef, Identity};
use crate::record::{LogEntry, LogKey, MAX_CHAIN_LEN, Record, RecordBody, RecordError};
use crate::time::Timestamp;

/// The first line of a key file of this version (4.4, 15).
pub const KEY_FILE_HEADER: &str = "risala-keys/1";

/// The most bytes a reader takes of a key file, 2 MiB (4.4). A larger
/// body makes the identity's keys missing.
pub const MAX_KEY_FILE_BYTES: usize = 2 * 1024 * 1024;

/// The most bytes a reader takes of a log's checkpoint, tile or entry
/// bundle when it fetches them for a key file, 8 MiB (4.4).
pub const MAX_LOG_FETCH_BYTES: usize = 8 * 1024 * 1024;

/// The longest a key file fetch may take (4.4).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest a reader may cache a key file (4.4).
pub const MAX_CACHE_AGE: Duration = Duration::from_secs(60 * 60);

/// The URL of an identity's key file (4.3):
/// `https://<domain>/.well-known/risala/<name>`.
pub fn well_known_url(identity: &Identity) -> String {
    format!(
        "https://{}/.well-known/risala/{}",
        identity.domain(),
        identity.name()
    )
}

/// Why a key file did not parse (4.4). Every one of these makes the
/// identity's keys missing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyFileError {
    /// Larger than [`MAX_KEY_FILE_BYTES`].
    #[error("a key file is at most 2 MiB")]
    TooLarge,
    /// The first line is not `risala-keys/1`: not a key file of this
    /// version.
    #[error("not a risala-keys/1 file")]
    NotKeyFile,
    /// The text breaks a rule of 4.4, on this line (from 1).
    #[error("line {line}: {reason}")]
    Invalid {
        /// The line, counting from 1.
        line: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// An unlogged record does not decode (4.4, parsing step 2).
    #[error("line {line}: {error}")]
    Record {
        /// The line, counting from 1.
        line: usize,
        /// Why the record did not decode.
        error: RecordError,
    },
}

/// A `log` line (4.4): a key log, by its verifier key, and its URL
/// prefix.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LogLine {
    /// The log.
    pub log: LogKey,
    /// Its `https` URL prefix [TLOG-TILES], without a `/` at the end.
    pub url: String,
}

impl LogLine {
    /// A `log` line for `log` at `url`, which must be an `https` URL that
    /// does not end with `/` and holds no space.
    pub fn new(log: LogKey, url: &str) -> Option<LogLine> {
        is_log_url(url).then(|| LogLine {
            log,
            url: url.to_owned(),
        })
    }
}

impl fmt::Display for LogLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "log {} {}", self.log.vkey(), self.url)
    }
}

/// Whether `url` can be a `log` line's URL prefix (4.4): `https://`, then
/// at least one character, no `/` at the end, and nothing a line may not
/// hold.
fn is_log_url(url: &str) -> bool {
    url.strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        && !url.ends_with('/')
        && !url.contains([' ', '\t', '\r', '\n'])
}

/// How a key file lists one record (4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listing {
    /// `<index> <hash>`: the record is the entry at `index` of its log.
    Logged {
        /// The entry's index in the log.
        index: u64,
        /// The record's SHA-384 hash.
        hash: BlobRef,
    },
    /// `- <record>`: a record that is not logged yet.
    Unlogged(Record),
}

impl Listing {
    /// The listed record's hash.
    pub fn hash(&self) -> BlobRef {
        match self {
            Listing::Logged { hash, .. } => *hash,
            Listing::Unlogged(record) => record.hash(),
        }
    }
}

impl fmt::Display for Listing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Listing::Logged { index, hash } => write!(f, "{index} {hash}"),
            Listing::Unlogged(record) => write!(f, "- {}", BASE64.encode(record.encoded())),
        }
    }
}

/// A `log` line and the records listed after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// The log that holds these records.
    pub log: LogLine,
    /// The records, in chain order. Empty only in a last section after a
    /// `log` record, which names the log the next records go into (4.4).
    pub records: Vec<Listing>,
}

/// A parsed key file (4.4): its sections, in order. It has passed the
/// text rules, but its chain has not been checked: see
/// [`check`](KeyFile::check).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFile {
    sections: Vec<Section>,
}

impl KeyFile {
    /// Parses a key file's bytes under the text rules of 4.4, and decodes
    /// its unlogged records. Readers MUST check everything; any failure
    /// makes the identity's keys missing.
    pub fn parse(bytes: &[u8]) -> Result<KeyFile, KeyFileError> {
        if bytes.len() > MAX_KEY_FILE_BYTES {
            return Err(KeyFileError::TooLarge);
        }
        let invalid = |line: usize, reason| Err(KeyFileError::Invalid { line, reason });
        // The first line decides whether this is a key file of this
        // version at all.
        let first = bytes.split(|&b| b == b'\n').next().unwrap_or_default();
        if first != KEY_FILE_HEADER.as_bytes() {
            return Err(KeyFileError::NotKeyFile);
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            return invalid(0, "a key file is UTF-8");
        };
        let Some(text) = text.strip_suffix('\n') else {
            return invalid(text.split('\n').count(), "every line ends with LF");
        };

        let mut sections: Vec<Section> = Vec::new();
        let mut last_index: HashMap<LogKey, u64> = HashMap::new();
        let mut unlogged = false;
        let mut previous_was_log = false;
        let mut count = 0usize;
        for (n, line) in text.split('\n').enumerate() {
            let n = n + 1;
            if line.contains(['\r', '\t']) {
                return invalid(n, "a line holds a CR or a TAB");
            }
            if line.starts_with(' ') || line.ends_with(' ') || line.contains("  ") {
                return invalid(n, "a line starts or ends with a space, or has two in a row");
            }
            if n == 1 || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut words = line.split(' ');
            let (Some(a), Some(b)) = (words.next(), words.next()) else {
                return invalid(n, "not a line of a key file");
            };
            let c = words.next();
            if words.next().is_some() {
                return invalid(n, "not a line of a key file");
            }
            match (a, c) {
                ("log", Some(url)) => {
                    if previous_was_log {
                        return invalid(n, "a log line follows another");
                    }
                    let Ok(log) = LogKey::from_vkey(b) else {
                        return invalid(n, "not a key log's verifier key");
                    };
                    let Some(log_line) = LogLine::new(log, url) else {
                        return invalid(n, "a log URL is https, without a / at the end");
                    };
                    // A new log line starts the records of another log
                    // (4.4). The same log twice in a row would be one
                    // log split in two. (4.4 does not say; a choice to
                    // confirm.)
                    if sections.last().is_some_and(|s| s.log.log == log_line.log) {
                        return invalid(n, "a log line names the log before it again");
                    }
                    sections.push(Section {
                        log: log_line,
                        records: Vec::new(),
                    });
                    previous_was_log = true;
                    continue;
                }
                (_, Some(_)) => return invalid(n, "not a line of a key file"),
                (_, None) => {}
            }
            let Some(section) = sections.last_mut() else {
                return invalid(n, "the first line after the header is a log line");
            };
            count += 1;
            if count > MAX_CHAIN_LEN {
                return invalid(n, "a chain has at most 4096 records");
            }
            let listing = if a == "-" {
                let Ok(bytes) = BASE64.decode(b) else {
                    return invalid(n, "a record is in strict base64");
                };
                let record = Record::decode(&bytes)
                    .map_err(|error| KeyFileError::Record { line: n, error })?;
                unlogged = true;
                Listing::Unlogged(record)
            } else {
                let Ok(index) = crate::types::parse_u64(a) else {
                    return invalid(n, "an index is a number");
                };
                let hash = match b.parse::<BlobRef>() {
                    Ok(hash) if hash.to_string() == b => hash,
                    _ => return invalid(n, "a hash is a blob-ref in lower case"),
                };
                if unlogged {
                    return invalid(n, "an index line follows an unlogged record");
                }
                let last = last_index.insert(section.log.log.clone(), index);
                if last.is_some_and(|last| last >= index) {
                    return invalid(n, "indices increase within each log");
                }
                Listing::Logged { index, hash }
            };
            section.records.push(listing);
            previous_was_log = false;
        }
        if count == 0 {
            return invalid(text.split('\n').count(), "a key file lists records");
        }
        Ok(KeyFile { sections })
    }

    /// The key file that lists `chain` (4.4), for the identity's host or
    /// owner to publish. `logged` gives the index of each record that its
    /// log holds, by the record's position in the chain; the others are
    /// listed whole. `url` gives each log's URL prefix. A chain that ends
    /// with a `log` record also gets a last `log` line, naming the log
    /// that the next records go into.
    ///
    /// Fails if a logged record follows one that is not, or if a URL is
    /// not a valid `log` line URL.
    pub fn from_chain(
        chain: &Chain,
        logged: &dyn Fn(usize) -> Option<u64>,
        url: &dyn Fn(&LogKey) -> String,
    ) -> Result<KeyFile, KeyFileError> {
        let mut text = format!("{KEY_FILE_HEADER}\n");
        let mut current: Option<&LogKey> = None;
        for (i, (record, log)) in chain.records().iter().zip(chain.placements()).enumerate() {
            if current != Some(log) {
                text.push_str(&format!("log {} {}\n", log.vkey(), url(log)));
                current = Some(log);
            }
            let listing = match logged(i) {
                Some(index) => Listing::Logged {
                    index,
                    hash: record.hash(),
                },
                None => Listing::Unlogged(record.clone()),
            };
            text.push_str(&format!("{listing}\n"));
        }
        if chain.head().record_type() == crate::record::RecordType::Log {
            let log = chain.log();
            text.push_str(&format!("log {} {}\n", log.vkey(), url(log)));
        }
        KeyFile::parse(text.as_bytes())
    }

    /// The sections, in order.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Every listing with the `log` line it is under, in chain order.
    pub fn listings(&self) -> impl Iterator<Item = (&LogLine, &Listing)> {
        self.sections
            .iter()
            .flat_map(|s| s.records.iter().map(move |r| (&s.log, r)))
    }

    /// The number of records listed.
    pub fn len(&self) -> usize {
        self.sections.iter().map(|s| s.records.len()).sum()
    }

    /// Always false: a key file lists at least one record.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The last `log` line. A server that logs an identity it does not
    /// host checks that it names its own log (4.7).
    pub fn last_log(&self) -> &LogLine {
        &self.sections.last().expect("a key file has a log line").log
    }

    /// Whether the file lists the record with this hash, as a `-` line or
    /// by hash (4.7).
    pub fn lists(&self, hash: &BlobRef) -> bool {
        self.listings().any(|(_, l)| l.hash() == *hash)
    }

    /// The file as text, as [`parse`](KeyFile::parse) reads it.
    pub fn to_text(&self) -> String {
        let mut text = format!("{KEY_FILE_HEADER}\n");
        for section in &self.sections {
            text.push_str(&format!("{}\n", section.log));
            for listing in &section.records {
                text.push_str(&format!("{listing}\n"));
            }
        }
        text
    }

    /// Checks the file for `uid` (4.4): gets the record of each
    /// `<index> <hash>` line from `entries`, replays the chain with each
    /// record in the log it is listed under, and checks the records'
    /// times against `now`.
    ///
    /// `entries` gives the entry at an index of a log, as the log's entry
    /// bundles hold it [TLOG-TILES]. Whether that entry is in a witnessed
    /// checkpoint is for the reader to check before it acts on a record
    /// (4.5); this only checks that the entry is the record listed.
    pub fn check(
        &self,
        uid: &Identity,
        entries: &mut dyn EntrySource,
        handoffs: &dyn Handoffs,
        now: Timestamp,
    ) -> KeyFileState {
        let mut records = Vec::with_capacity(self.len());
        for (position, (log, listing)) in self.listings().enumerate() {
            let record = match listing {
                Listing::Unlogged(record) => record.clone(),
                Listing::Logged { index, hash } => match entries.entry(log, *index) {
                    Err(EntryError::Outage) => return KeyFileState::Outage(Outage::LogFetch),
                    Err(EntryError::Missing) => {
                        return KeyFileState::KeysMissing(Missing::NotInLog(position));
                    }
                    Ok(bytes) => match LogEntry::decode(&bytes) {
                        Ok(LogEntry::Record(record)) if record.hash() == *hash => record,
                        _ => return KeyFileState::KeysMissing(Missing::NotInLog(position)),
                    },
                },
            };
            records.push((record, &log.log));
        }
        let chain = match Chain::replay_placed(
            uid,
            records.iter().map(|(r, log)| (r, Some(*log))),
            handoffs,
        ) {
            Ok(chain) => chain,
            Err(e) => return KeyFileState::KeysMissing(Missing::Chain(e)),
        };
        // A last log line with no records follows a log record and names
        // the log it moves to (4.4).
        let last = self.sections.last().expect("a key file has a log line");
        if last.records.is_empty() {
            let moved = matches!(&chain.head().content().body,
                RecordBody::Log(named) if *named == last.log.log);
            if !moved {
                return KeyFileState::KeysMissing(Missing::TrailingLog);
            }
        }
        if let Some(index) = chain.ahead_of(now) {
            return KeyFileState::Outage(Outage::Ahead(index));
        }
        KeyFileState::Keys(Box::new(chain))
    }
}

/// Why an entry could not be had from a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    /// The fetch from the log failed: an outage (4.4).
    Outage,
    /// The log has no entry at that index: the key file does not match
    /// the log, so the keys are missing (4.4).
    Missing,
}

/// Where [`KeyFile::check`] gets log entries.
pub trait EntrySource {
    /// The encoded LogEntry at `index` of the log of `log`.
    fn entry(&mut self, log: &LogLine, index: u64) -> Result<Vec<u8>, EntryError>;
}

impl<F: FnMut(&LogLine, u64) -> Result<Vec<u8>, EntryError>> EntrySource for F {
    fn entry(&mut self, log: &LogLine, index: u64) -> Result<Vec<u8>, EntryError> {
        self(log, index)
    }
}

/// No log at all: every `<index> <hash>` line is an outage. For files
/// that list only unlogged records, and for tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEntries;

impl EntrySource for NoEntries {
    fn entry(&mut self, _: &LogLine, _: u64) -> Result<Vec<u8>, EntryError> {
        Err(EntryError::Outage)
    }
}

/// A reader's view of an identity after a fetch (4.4).
#[derive(Debug, Clone)]
pub enum KeyFileState {
    /// **Keys**: a valid key file. Whether it extends what the reader
    /// holds is the next check: [`Chain::extends`], [`Chain::check_pin`].
    Keys(Box<Chain>),
    /// **Keys missing**: nobody signs in with the identity's keys, and
    /// devices send nothing to it and warn, but remove nothing.
    KeysMissing(Missing),
    /// **Outage**: says nothing about the identity's keys, and changes
    /// nothing.
    Outage(Outage),
}

/// Why an identity's keys are missing (4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// A 404 or 410 response.
    Gone(u16),
    /// A body larger than 2 MiB.
    TooLarge,
    /// The first line is not `risala-keys/1`.
    NotKeyFile,
    /// The text breaks a rule of 4.4.
    Text(KeyFileError),
    /// The chain does not replay (4.4).
    Chain(ChainError),
    /// A last `log` line without records that does not follow a `log`
    /// record naming that log (4.4).
    TrailingLog,
    /// The `<index> <hash>` line of the record at this position does not
    /// match the log (4.4).
    NotInLog(usize),
}

/// Why a fetch was an outage (4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outage {
    /// No response: a DNS or TLS error, a timeout, a refused connection.
    NoResponse,
    /// A status other than 200, 404 and 410, a redirect included.
    Status(u16),
    /// A fetch from the log failed.
    LogFetch,
    /// The record at this position is more than 10 minutes ahead of the
    /// reader's clock.
    Ahead(usize),
}

/// What a reader got when it fetched a key file (4.4).
#[derive(Debug, Clone, Copy)]
pub enum Response<'a> {
    /// No response: a DNS or TLS error, a timeout, a refused connection.
    Failed,
    /// A response whose body went past [`MAX_KEY_FILE_BYTES`], which the
    /// reader stopped reading.
    TooLarge,
    /// A response within the limits. Redirects are not followed, so they
    /// arrive here.
    Body {
        /// The HTTP status.
        status: u16,
        /// The body.
        body: &'a [u8],
    },
}

/// Reads a key file fetch for `uid` into one of the three states of 4.4.
pub fn read_key_file(
    response: Response<'_>,
    uid: &Identity,
    entries: &mut dyn EntrySource,
    handoffs: &dyn Handoffs,
    now: Timestamp,
) -> KeyFileState {
    match response {
        Response::Failed => KeyFileState::Outage(Outage::NoResponse),
        Response::TooLarge => KeyFileState::KeysMissing(Missing::TooLarge),
        Response::Body {
            status: status @ (404 | 410),
            ..
        } => KeyFileState::KeysMissing(Missing::Gone(status)),
        Response::Body { status: 200, body } => match KeyFile::parse(body) {
            Ok(file) => file.check(uid, entries, handoffs, now),
            Err(KeyFileError::TooLarge) => KeyFileState::KeysMissing(Missing::TooLarge),
            Err(KeyFileError::NotKeyFile) => KeyFileState::KeysMissing(Missing::NotKeyFile),
            Err(e) => KeyFileState::KeysMissing(Missing::Text(e)),
        },
        Response::Body { status, .. } => KeyFileState::Outage(Outage::Status(status)),
    }
}

//! Splitting a byte stream into lines, and line limits (SPEC 2.3).
//!
//! [`LineDecoder`] is sans-I/O: feed it bytes as they arrive with
//! [`LineDecoder::push`] and take lines out with
//! [`LineDecoder::next_line`]. [`check_line`], [`check_line_len`] and
//! [`LineLimits::check`] apply the same rules to lines about to be sent.
//!
//! # Long lines
//!
//! Lines that carry MLS data, key files or reports (Sections 4, 5.8 and
//! 12) may be longer than others. From a client, a line whose verb is one
//! of [`CLIENT_LONG_VERBS`] may be up to [`MAX_LONG_CLIENT_LINE`] bytes,
//! 1 MiB; from a server, one whose verb is one of [`SERVER_LONG_VERBS`]
//! may be up to [`MAX_LONG_SERVER_LINE`]. Every other line keeps the
//! normal limit. [`LineLimits`] holds both limits of one direction and its
//! long verbs.
//!
//! The long data always comes after the verb, so the start of every line,
//! up to the end of its verb, must fit the normal limit, tags included
//! (2.3). The decoder reads the verb as the line arrives: until the verb
//! has ended, the normal limit applies, and once it shows that the line
//! is long, the long limit does.
//!
//! Before a connection has signed in, or become anonymous or a guest, a
//! server applies the normal limit to every line except REGISTER, KEYS
//! and PAIR, which may be up to [`MAX_REGISTER_LINE`] bytes for their
//! records and pairing messages (2.3, 4.7, 4.8):
//! [`LineLimits::NEW_CONNECTION`]. It switches to [`LineLimits::CLIENT`]
//! with [`LineDecoder::set_limits`] once the connection has a kind, as
//! [`ConnectionKind::client_limits`](crate::connection::ConnectionKind::client_limits)
//! says.

use std::collections::VecDeque;

use crate::error::ParseError;
use crate::line::find_ref;
use crate::types::Ref;

/// The longest line a client may send, in bytes, including the LF (2.3).
pub const MAX_CLIENT_LINE: usize = 8192;

/// The longest line a server may send, in bytes, including the LF (2.3).
pub const MAX_SERVER_LINE: usize = 16384;

/// The longest line a client may send whose verb is one of
/// [`CLIENT_LONG_VERBS`]: 1 MiB, including the LF (2.3).
pub const MAX_LONG_CLIENT_LINE: usize = 1024 * 1024;

/// The longest line a server may send whose verb is one of
/// [`SERVER_LONG_VERBS`]: 1 MiB plus 16384 bytes, including the LF (2.3).
/// The difference leaves room for the tags a server adds.
pub const MAX_LONG_SERVER_LINE: usize = MAX_LONG_CLIENT_LINE + MAX_SERVER_LINE;

/// The longest REGISTER, KEYS or PAIR line a new connection may send,
/// including the LF: 64 KiB, for their records and pairing messages
/// (2.3, 4.7, 4.8).
pub const MAX_REGISTER_LINE: usize = 65536;

/// The verbs of client lines that may be long once the connection has a
/// kind (2.3), in upper case: the commands that carry MLS data, records,
/// pairing messages or reports.
pub const CLIENT_LONG_VERBS: [&str; 7] = [
    "CREATE", "KEYPKG", "KEYS", "PAIR", "POST", "REPORT", "WELCOME",
];

/// The verbs of server lines that may be long (2.3), in upper case.
pub const SERVER_LONG_VERBS: [&str; 6] =
    ["GROUPINFO", "KEYPKG", "PAIR", "POST", "REPORT", "WELCOME"];

/// The verbs a new connection may send up to [`MAX_REGISTER_LINE`]
/// bytes long (2.3, 4.7, 4.8).
pub const NEW_CONNECTION_LONG_VERBS: [&str; 3] = ["KEYS", "PAIR", "REGISTER"];

/// The length of the longest verb in [`CLIENT_LONG_VERBS`],
/// [`SERVER_LONG_VERBS`] and [`NEW_CONNECTION_LONG_VERBS`]. A longer verb
/// is never long.
const LONGEST_LONG_VERB: usize = 9;

fn contains_verb(verbs: &[&str], verb: &[u8]) -> bool {
    verbs
        .iter()
        .any(|long| long.as_bytes().eq_ignore_ascii_case(verb))
}

/// The length limits of one direction of a connection (2.3), each in
/// bytes including the LF: `normal` for most lines, `long` for lines whose
/// verb is one of `long_verbs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LineLimits {
    /// The limit for lines whose verb is not in `long_verbs`. Everything
    /// up to the end of a line's verb must fit it, tags included.
    pub normal: usize,
    /// The limit for lines whose verb is in `long_verbs`. Never less
    /// than `normal`.
    pub long: usize,
    /// The verbs of lines that may be long, in upper case, at most
    /// nine letters each, such as [`CLIENT_LONG_VERBS`]. Verbs are
    /// matched case-insensitively.
    pub long_verbs: &'static [&'static str],
}

impl LineLimits {
    /// The limits of lines from a client once its connection is
    /// anonymous, a guest or signed in (2.3): what a server's decoder then
    /// applies, and what a client checks before it sends.
    pub const CLIENT: LineLimits = LineLimits {
        normal: MAX_CLIENT_LINE,
        long: MAX_LONG_CLIENT_LINE,
        long_verbs: &CLIENT_LONG_VERBS,
    };

    /// The limits of lines from a client on a new connection (2.3): the
    /// normal limit for every line, except REGISTER, KEYS and PAIR, which
    /// may be up to [`MAX_REGISTER_LINE`].
    pub const NEW_CONNECTION: LineLimits = LineLimits {
        normal: MAX_CLIENT_LINE,
        long: MAX_REGISTER_LINE,
        long_verbs: &NEW_CONNECTION_LONG_VERBS,
    };

    /// The limits of lines from a server (2.3): what a client's decoder
    /// applies, and what a server checks before it sends.
    pub const SERVER: LineLimits = LineLimits {
        normal: MAX_SERVER_LINE,
        long: MAX_LONG_SERVER_LINE,
        long_verbs: &SERVER_LONG_VERBS,
    };

    /// The same limit for every line, with no long verbs.
    pub const fn uniform(max_len: usize) -> LineLimits {
        LineLimits {
            normal: max_len,
            long: max_len,
            long_verbs: &[],
        }
    }

    /// Whether a line with this verb may be long (2.3). Verbs are
    /// case-insensitive.
    pub fn is_long_verb(&self, verb: &str) -> bool {
        contains_verb(self.long_verbs, verb.as_bytes())
    }

    /// The limit for a line with this verb, if the line's start up to the
    /// end of the verb fits the normal limit.
    pub fn for_verb(&self, verb: &str) -> usize {
        if self.is_long_verb(verb) {
            self.long.max(self.normal)
        } else {
            self.normal
        }
    }

    /// Checks that `line`, without its line ending, fits its limit once
    /// the LF is added, judging by its verb as [`LineDecoder`] does: the
    /// long limit applies only if the verb is long and ends within the
    /// normal limit. Fails with [`ParseError::TooLong`].
    pub fn check(&self, line: &str) -> Result<(), ParseError> {
        let mut scan = VerbScan::default();
        scan.feed(line.as_bytes());
        scan.finish();
        check_line_len(line, self.max_for(&scan))
    }

    /// The limit for a line whose start `scan` has read.
    fn max_for(&self, scan: &VerbScan) -> usize {
        if scan.is_long(self) {
            self.long.max(self.normal)
        } else {
            self.normal
        }
    }
}

/// Whether `c` is a control character forbidden in a line (2.3): %x00-08,
/// %x0A-1F, %x7F and the C1 controls U+0080 to U+009F. TAB (%x09) is
/// allowed.
pub fn is_forbidden_control(c: char) -> bool {
    matches!(
        c,
        '\u{00}'..='\u{08}' | '\u{0A}'..='\u{1F}' | '\u{7F}'..='\u{9F}'
    )
}

/// Checks the characters of one line, without its line ending (2.3).
///
/// Fails with [`ParseError::ControlChar`] if the line contains a control
/// character other than TAB. LF and CR count as control characters here,
/// since `line` is the content between line endings. UTF-8 validity is
/// already guaranteed by `&str`.
///
/// Use it on lines about to be sent; [`LineDecoder`] applies it to every
/// line it yields.
pub fn check_line(line: &str) -> Result<(), ParseError> {
    if line.chars().any(is_forbidden_control) {
        Err(ParseError::ControlChar)
    } else {
        Ok(())
    }
}

/// Checks that `line`, without its line ending, fits in `max_len` bytes
/// once the LF is added (2.3). Pass [`MAX_CLIENT_LINE`] or
/// [`MAX_SERVER_LINE`], or use [`LineLimits::check`] to take long lines
/// into account. Fails with [`ParseError::TooLong`].
pub fn check_line_len(line: &str, max_len: usize) -> Result<(), ParseError> {
    if line.len() < max_len {
        Ok(())
    } else {
        Err(ParseError::TooLong)
    }
}

/// Reads the verb at the start of a line, a few bytes at a time, to tell
/// whether the line may be long (2.3).
///
/// It skips the tags (`@` up to the first space) and any spaces after
/// them, then reads letters. It stops at the first byte after the verb,
/// or once the verb is longer than any long verb. So each byte of a line
/// is looked at most once. It records where the verb ended, since a line
/// is long only if its verb ends within the normal limit, and leaves the
/// verdict to [`is_long`](Self::is_long), so that a change of limits
/// halfway through a line applies to it.
#[derive(Clone, Copy, Debug, Default)]
struct VerbScan {
    phase: Phase,
    verb: [u8; LONGEST_LONG_VERB],
    len: usize,
    /// The number of bytes read so far, until the scan is done.
    pos: usize,
    /// The index of the byte after the verb, once the verb has ended: a
    /// space, any other non-letter, or the end of the line.
    end: Option<usize>,
    /// The verb is longer than any long verb.
    overlong: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Start,
    Tags,
    Gap,
    Verb,
}

impl VerbScan {
    fn done(&self) -> bool {
        self.end.is_some() || self.overlong
    }

    /// Reads more bytes of the line. Does nothing once the verb has ended.
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.done() {
                return;
            }
            match self.phase {
                Phase::Start if b == b'@' => self.phase = Phase::Tags,
                Phase::Tags if b == b' ' => self.phase = Phase::Gap,
                Phase::Tags => {}
                Phase::Gap if b == b' ' => {}
                Phase::Start | Phase::Gap | Phase::Verb => {
                    self.phase = Phase::Verb;
                    self.verb_byte(b);
                }
            }
            self.pos += 1;
        }
    }

    fn verb_byte(&mut self, b: u8) {
        if !b.is_ascii_alphabetic() {
            self.end = Some(self.pos);
        } else if self.len == LONGEST_LONG_VERB {
            self.overlong = true;
        } else {
            self.verb[self.len] = b;
            self.len += 1;
        }
    }

    /// Marks the end of the line: a verb still being read ends here.
    fn finish(&mut self) {
        if self.phase == Phase::Verb && !self.done() {
            self.end = Some(self.pos);
        }
    }

    /// Whether the line may be long under `limits`: its verb has ended,
    /// within the normal limit, and is one of the long verbs. Until the
    /// verb has ended, it may not.
    fn is_long(&self, limits: &LineLimits) -> bool {
        match self.end {
            Some(end) if !self.overlong => {
                end < limits.normal && contains_verb(limits.long_verbs, &self.verb[..self.len])
            }
            _ => false,
        }
    }
}

/// A sans-I/O decoder that splits a byte stream into lines (2.3).
///
/// - A line ends with LF. The LF, and one CR directly before it, are
///   removed. Any other CR is a control character.
/// - Each line is checked to be UTF-8 ([`ParseError::InvalidUtf8`]) and
///   free of control characters other than TAB
///   ([`ParseError::ControlChar`]).
/// - A line longer than its limit ([`LineLimits`]), counting its CR and
///   LF, is reported once as [`ParseError::TooLong`] as soon as it is
///   known to be too long, and the rest of it is discarded up to and
///   including the next LF. The next line starts after that LF. The limit
///   is the long one for a line whose verb is one of the limits' long
///   verbs and ends within the normal limit, and the normal one
///   otherwise. Until the verb has ended, the normal limit applies, so
///   tags can never make a line long (2.3).
/// - Empty lines are yielded as `Ok("")`. Callers ignore them, but they
///   still count as activity for keepalive (11).
/// - Bytes after the last LF are kept until more data arrives. An
///   unfinished line at the end of the stream is not a line.
///
/// Memory: the decoder never holds more than `normal - 1` bytes of an
/// unfinished line until its verb shows that it is long, never more than
/// `long - 1` bytes, and none while it discards a long one. Complete lines
/// found by [`push`](Self::push) are queued until taken with
/// [`next_line`](Self::next_line), so a caller that pushes a bounded
/// buffer and then drains the decoder keeps memory bounded too.
#[derive(Debug, Clone)]
pub struct LineDecoder {
    limits: LineLimits,
    partial: Vec<u8>,
    scan: VerbScan,
    discarding: bool,
    /// Each finished line, and for a bad line the `ref` tag read from it.
    ready: VecDeque<(Result<String, ParseError>, Option<Ref>)>,
}

impl LineDecoder {
    /// Creates a decoder for lines of at most `max_len` bytes including
    /// the LF, whatever their verb: [`LineLimits::uniform`].
    pub fn new(max_len: usize) -> Self {
        LineDecoder::with_limits(LineLimits::uniform(max_len))
    }

    /// Creates a decoder with these limits: [`LineLimits::NEW_CONNECTION`]
    /// on a server until the connection has a kind, then
    /// [`LineLimits::CLIENT`], and [`LineLimits::SERVER`] on a client
    /// (2.3).
    pub fn with_limits(limits: LineLimits) -> Self {
        LineDecoder {
            limits: LineLimits {
                long: limits.long.max(limits.normal),
                ..limits
            },
            partial: Vec::new(),
            scan: VerbScan::default(),
            discarding: false,
            ready: VecDeque::new(),
        }
    }

    /// Changes the limits, for example when a connection becomes
    /// anonymous, a guest or signed in (2.3).
    /// Lines already complete keep the verdict they had. The line in
    /// progress is judged by the new limits from the next byte on; if it
    /// already holds more bytes than they allow, it is reported as too
    /// long at its next byte.
    pub fn set_limits(&mut self, limits: LineLimits) {
        self.limits = LineLimits {
            long: limits.long.max(limits.normal),
            ..limits
        };
    }

    /// The limits this decoder applies.
    pub fn limits(&self) -> LineLimits {
        self.limits
    }

    /// The normal limit this decoder applies, the one for lines whose verb
    /// is not long.
    pub fn max_len(&self) -> usize {
        self.limits.normal
    }

    /// The limit for the line in progress, as far as its verb is known.
    fn current_max(&self) -> usize {
        self.limits.max_for(&self.scan)
    }

    /// Feeds bytes from the stream. Lines they complete become available
    /// from [`next_line`](Self::next_line).
    pub fn push(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let Some(lf) = data.iter().position(|&b| b == b'\n') else {
                // No line ending: the bytes belong to an unfinished line.
                if !self.discarding {
                    self.scan.feed(data);
                    if self.partial.len() + data.len() >= self.current_max() {
                        // Even an LF right after these bytes would be over
                        // the limit.
                        let r = self.prefix_ref(data, false);
                        self.partial = Vec::new();
                        self.scan = VerbScan::default();
                        self.discarding = true;
                        self.ready.push_back((Err(ParseError::TooLong), r));
                    } else {
                        self.partial.extend_from_slice(data);
                    }
                }
                return;
            };
            let segment = &data[..lf];
            data = &data[lf + 1..];
            if self.discarding {
                // The end of a line already reported as too long.
                self.discarding = false;
                continue;
            }
            self.scan.feed(segment);
            self.scan.finish();
            let max = self.limits.max_for(&self.scan);
            self.scan = VerbScan::default();
            if self.partial.len() + segment.len() + 1 > max {
                let r = self.prefix_ref(segment, true);
                self.partial = Vec::new();
                self.ready.push_back((Err(ParseError::TooLong), r));
                continue;
            }
            let entry = if self.partial.is_empty() {
                decode(segment)
            } else {
                self.partial.extend_from_slice(segment);
                let entry = decode(&self.partial);
                // Let go of a long line's buffer rather than keep it.
                if self.partial.capacity() > self.limits.normal {
                    self.partial = Vec::new();
                } else {
                    self.partial.clear();
                }
                entry
            };
            self.ready.push_back(entry);
        }
    }

    /// Takes the next complete line, without its line ending, or the
    /// error for a bad line. Returns `None` when more bytes are needed.
    pub fn next_line(&mut self) -> Option<Result<String, ParseError>> {
        self.ready.pop_front().map(|(line, _)| line)
    }

    /// Like [`next_line`](Self::next_line), but a bad line also comes with
    /// its `ref` tag, if one could be read from its first bytes (3.6). A
    /// server copies it onto the `ERR` it sends. Good lines come with
    /// `None`; read their `ref` from the parsed line.
    pub fn next_line_with_ref(&mut self) -> Option<(Result<String, ParseError>, Option<Ref>)> {
        self.ready.pop_front()
    }

    /// The `ref` of a line that is too long: the bytes held so far
    /// followed by `more`. `complete` says whether `more` ends the line.
    fn prefix_ref(&self, more: &[u8], complete: bool) -> Option<Ref> {
        if self.partial.is_empty() {
            find_ref(more, complete)
        } else if self.partial.first() == Some(&b'@') {
            // The tags end at the first space; only they are searched, so
            // copy at most the normal limit's worth.
            let room = self.limits.normal.saturating_sub(self.partial.len());
            let mut bytes = self.partial.clone();
            bytes.extend_from_slice(&more[..more.len().min(room)]);
            find_ref(&bytes, complete && more.len() <= room)
        } else {
            None
        }
    }

    /// The number of bytes held for the unfinished line. Always less than
    /// the long limit, and zero while a long line is being discarded.
    pub fn pending_bytes(&self) -> usize {
        self.partial.len()
    }

    /// Whether the decoder is discarding the rest of a line that was
    /// already reported as too long.
    pub fn is_discarding(&self) -> bool {
        self.discarding
    }
}

/// Decodes one line's bytes, LF already removed. A bad line comes with
/// the `ref` read from it, if any.
fn decode(bytes: &[u8]) -> (Result<String, ParseError>, Option<Ref>) {
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    let result = std::str::from_utf8(bytes)
        .map_err(|_| ParseError::InvalidUtf8)
        .and_then(|line| check_line(line).map(|()| line.to_owned()));
    match result {
        Ok(line) => (Ok(line), None),
        Err(e) => (Err(e), find_ref(bytes, true)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_lines_keep_their_ref() {
        let mut d = LineDecoder::new(32);
        d.push(b"@ref=7 MSG #a hi\x01\n@ref=8 OK\n@ref=9 \xff\n");
        let (line, r) = d.next_line_with_ref().unwrap();
        assert_eq!(line, Err(ParseError::ControlChar));
        assert_eq!(r.unwrap().as_str(), "7");
        // Good lines carry their ref in the line itself.
        assert_eq!(d.next_line_with_ref(), Some((Ok("@ref=8 OK".into()), None)));
        let (line, r) = d.next_line_with_ref().unwrap();
        assert_eq!(line, Err(ParseError::InvalidUtf8));
        assert_eq!(r.unwrap().as_str(), "9");

        // Too long, in one push and split over several.
        let long = format!("@ref=10 MSG #a {}\n", "x".repeat(40));
        let mut d = LineDecoder::new(32);
        d.push(long.as_bytes());
        let (line, r) = d.next_line_with_ref().unwrap();
        assert_eq!(line, Err(ParseError::TooLong));
        assert_eq!(r.unwrap().as_str(), "10");
        let mut d = LineDecoder::new(32);
        for chunk in long.as_bytes().chunks(5) {
            d.push(chunk);
        }
        let (line, r) = d.next_line_with_ref().unwrap();
        assert_eq!(line, Err(ParseError::TooLong));
        assert_eq!(r.unwrap().as_str(), "10");
    }

    fn drain(d: &mut LineDecoder) -> Vec<Result<String, ParseError>> {
        std::iter::from_fn(|| d.next_line()).collect()
    }

    fn decode_all(max: usize, input: &[u8]) -> Vec<Result<String, ParseError>> {
        let mut d = LineDecoder::new(max);
        d.push(input);
        drain(&mut d)
    }

    /// Feeds the input one byte at a time, draining after every byte.
    fn decode_bytewise(max: usize, input: &[u8]) -> Vec<Result<String, ParseError>> {
        let mut d = LineDecoder::new(max);
        let mut out = Vec::new();
        for b in input {
            d.push(std::slice::from_ref(b));
            assert!(d.pending_bytes() < max.max(1));
            out.extend(drain(&mut d));
        }
        out
    }

    fn ok(s: &str) -> Result<String, ParseError> {
        Ok(s.to_owned())
    }

    #[test]
    fn limits() {
        assert_eq!(MAX_CLIENT_LINE, 8192);
        assert_eq!(MAX_SERVER_LINE, 16384);
    }

    #[test]
    fn splits_lines() {
        let input = b"GUEST sam\nJOIN #general\n";
        let want = vec![ok("GUEST sam"), ok("JOIN #general")];
        assert_eq!(decode_all(100, input), want);
        assert_eq!(decode_bytewise(100, input), want);
    }

    #[test]
    fn strips_one_cr_before_lf() {
        assert_eq!(decode_all(100, b"PING\r\n"), vec![ok("PING")]);
        assert_eq!(
            decode_all(100, b"a\r\r\n"),
            vec![Err(ParseError::ControlChar)]
        );
        assert_eq!(decode_all(100, b"\r\n"), vec![ok("")]);
    }

    #[test]
    fn lone_cr_is_a_control_character() {
        assert_eq!(
            decode_all(100, b"MSG #a hi\rthere\n"),
            vec![Err(ParseError::ControlChar)]
        );
        // A CR at the end of a push, not followed by LF, is kept until the
        // next byte shows what it is.
        let mut d = LineDecoder::new(100);
        d.push(b"PING\r");
        assert_eq!(d.next_line(), None);
        assert_eq!(d.pending_bytes(), 5);
        d.push(b"\n");
        assert_eq!(drain(&mut d), vec![ok("PING")]);
        d.push(b"PING\r");
        d.push(b"x\n");
        assert_eq!(drain(&mut d), vec![Err(ParseError::ControlChar)]);
    }

    #[test]
    fn empty_lines_are_yielded() {
        assert_eq!(
            decode_all(100, b"\n\nPING\n\r\n"),
            vec![ok(""), ok(""), ok("PING"), ok("")]
        );
    }

    #[test]
    fn keeps_unfinished_line() {
        let mut d = LineDecoder::new(100);
        d.push(b"MSG #general he");
        assert_eq!(d.next_line(), None);
        assert_eq!(d.pending_bytes(), 15);
        d.push(b"llo\nPI");
        assert_eq!(d.next_line(), Some(ok("MSG #general hello")));
        assert_eq!(d.next_line(), None);
        assert_eq!(d.pending_bytes(), 2);
        d.push(b"NG\n");
        assert_eq!(d.next_line(), Some(ok("PING")));
        assert_eq!(d.pending_bytes(), 0);
    }

    #[test]
    fn empty_push_does_nothing() {
        let mut d = LineDecoder::new(10);
        d.push(b"");
        assert_eq!(d.next_line(), None);
        assert_eq!(d.pending_bytes(), 0);
        assert!(!d.is_discarding());
        assert_eq!(d.max_len(), 10);
    }

    #[test]
    fn tab_and_unicode_are_allowed() {
        assert_eq!(
            decode_all(100, "MSG #a \tمرحبا 👋\n".as_bytes()),
            vec![ok("MSG #a \tمرحبا 👋")]
        );
        // U+00A0 is the first character after the C1 controls.
        assert_eq!(decode_all(100, "a\u{a0}\n".as_bytes()), vec![ok("a\u{a0}")]);
        // C1 controls are forbidden (2.3).
        assert_eq!(
            decode_all(100, "a\u{85}\n".as_bytes()),
            vec![Err(ParseError::ControlChar)]
        );
    }

    #[test]
    fn rejects_control_characters() {
        // CR is left out: before LF it is part of the line ending.
        for b in (0u8..=0x08)
            .chain(0x0B..=0x0C)
            .chain(0x0E..=0x1F)
            .chain([0x7F])
        {
            let input = [b'a', b, b'\n'];
            assert_eq!(
                decode_all(100, &input),
                vec![Err(ParseError::ControlChar)],
                "byte {b:#04x}"
            );
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(
            decode_all(100, b"MSG #a \xff\nPING\n"),
            vec![Err(ParseError::InvalidUtf8), ok("PING")]
        );
        // Truncated sequence, overlong encoding, surrogate.
        for bad in [&b"\xe2\x82\n"[..], b"\xc0\xaf\n", b"\xed\xa0\x80\n"] {
            assert_eq!(decode_all(100, bad), vec![Err(ParseError::InvalidUtf8)]);
        }
    }

    #[test]
    fn utf8_split_across_pushes() {
        let bytes = "👋\n".as_bytes();
        assert_eq!(decode_bytewise(100, bytes), vec![ok("👋")]);
    }

    #[test]
    fn length_limit_counts_cr_and_lf() {
        // max 5: four bytes plus LF fit, five do not.
        assert_eq!(decode_all(5, b"abcd\n"), vec![ok("abcd")]);
        assert_eq!(decode_all(5, b"abc\r\n"), vec![ok("abc")]);
        assert_eq!(decode_all(5, b"abcde\n"), vec![Err(ParseError::TooLong)]);
        assert_eq!(decode_all(5, b"abcd\r\n"), vec![Err(ParseError::TooLong)]);
        assert_eq!(decode_bytewise(5, b"abcd\n"), vec![ok("abcd")]);
        assert_eq!(
            decode_bytewise(5, b"abcde\n"),
            vec![Err(ParseError::TooLong)]
        );
    }

    #[test]
    fn exact_client_limit() {
        let mut line = vec![b'a'; MAX_CLIENT_LINE - 1];
        line.push(b'\n');
        let out = decode_all(MAX_CLIENT_LINE, &line);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_ref().unwrap().len(), MAX_CLIENT_LINE - 1);

        let mut line = vec![b'a'; MAX_CLIENT_LINE];
        line.push(b'\n');
        assert_eq!(
            decode_all(MAX_CLIENT_LINE, &line),
            vec![Err(ParseError::TooLong)]
        );
    }

    #[test]
    fn too_long_is_reported_once_and_discarded() {
        let mut input = b"PING\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', 50));
        input.extend(b"\nAFTER\n");
        let want = vec![ok("PING"), Err(ParseError::TooLong), ok("AFTER")];
        assert_eq!(decode_all(10, &input), want);
        assert_eq!(decode_bytewise(10, &input), want);
    }

    #[test]
    fn too_long_is_reported_before_the_lf_arrives() {
        let mut d = LineDecoder::new(10);
        d.push(&[b'x'; 9]);
        assert_eq!(d.next_line(), None);
        assert_eq!(d.pending_bytes(), 9);
        assert!(!d.is_discarding());
        d.push(b"x");
        assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
        assert!(d.is_discarding());
        assert_eq!(d.pending_bytes(), 0);
        // Memory stays bounded while discarding.
        for _ in 0..1000 {
            d.push(&[b'y'; 1000]);
            assert_eq!(d.pending_bytes(), 0);
            assert_eq!(d.next_line(), None);
        }
        // Bad bytes in the discarded part do not matter.
        d.push(b"\x00\xff\r");
        assert_eq!(d.next_line(), None);
        d.push(b"tail\nPING\n");
        assert!(!d.is_discarding());
        assert_eq!(drain(&mut d), vec![ok("PING")]);
    }

    #[test]
    fn line_ending_right_at_discard_start() {
        // The line becomes too long and its LF is in the same push.
        let mut d = LineDecoder::new(4);
        d.push(b"abcdefgh\nok\n");
        assert_eq!(drain(&mut d), vec![Err(ParseError::TooLong), ok("ok")]);
        assert!(!d.is_discarding());
    }

    #[test]
    fn consecutive_long_lines_each_reported() {
        let input = b"aaaaaaaa\nbbbbbbbbbb\nc\n";
        let want = vec![Err(ParseError::TooLong), Err(ParseError::TooLong), ok("c")];
        assert_eq!(decode_all(5, input), want);
        assert_eq!(decode_bytewise(5, input), want);
    }

    #[test]
    fn long_line_split_over_partial_and_segment() {
        let mut d = LineDecoder::new(6);
        d.push(b"abc");
        d.push(b"def\nok\n");
        assert_eq!(drain(&mut d), vec![Err(ParseError::TooLong), ok("ok")]);
    }

    #[test]
    fn tiny_limits() {
        // max 1 allows only empty lines.
        assert_eq!(
            decode_all(1, b"\na\n\n"),
            vec![ok(""), Err(ParseError::TooLong), ok("")]
        );
        // max 0 allows nothing.
        assert_eq!(decode_all(0, b"\n"), vec![Err(ParseError::TooLong)]);
        assert_eq!(
            decode_all(0, b"ab\n\n"),
            vec![Err(ParseError::TooLong), Err(ParseError::TooLong)]
        );
    }

    #[test]
    fn long_limits() {
        assert_eq!(MAX_LONG_CLIENT_LINE, 1_048_576);
        assert_eq!(MAX_LONG_SERVER_LINE, 1_048_576 + 16_384);
        assert_eq!(MAX_REGISTER_LINE, 65_536);
        for verb in CLIENT_LONG_VERBS
            .iter()
            .chain(&SERVER_LONG_VERBS)
            .chain(&NEW_CONNECTION_LONG_VERBS)
        {
            assert!(verb.len() <= LONGEST_LONG_VERB);
            assert_eq!(verb.to_ascii_uppercase(), *verb);
        }
        let client = LineLimits::CLIENT;
        let server = LineLimits::SERVER;
        let new = LineLimits::NEW_CONNECTION;
        for verb in ["KEYPKG", "POST", "REPORT", "WELCOME", "post", "Report"] {
            assert!(client.is_long_verb(verb), "{verb}");
            assert!(server.is_long_verb(verb), "{verb}");
            assert!(!new.is_long_verb(verb), "{verb}");
        }
        // PAIR is long both ways, and up to 64 KiB on a new connection,
        // like KEYS (2.3, 4.8).
        for verb in ["PAIR", "pair"] {
            assert!(client.is_long_verb(verb));
            assert!(server.is_long_verb(verb));
            assert_eq!(new.for_verb(verb), MAX_REGISTER_LINE);
        }
        assert_eq!(new.for_verb("KEYS"), MAX_REGISTER_LINE);
        // Clients send CREATE and KEYS; servers send GROUPINFO.
        for verb in ["CREATE", "KEYS"] {
            assert!(client.is_long_verb(verb));
            assert!(!server.is_long_verb(verb));
        }
        assert!(!client.is_long_verb("GROUPINFO"));
        assert!(server.is_long_verb("GROUPINFO"));
        // REGISTER is long only on a new connection (2.3).
        assert!(new.is_long_verb("register"));
        assert!(!client.is_long_verb("REGISTER"));
        for verb in [
            "MSG", "ENC", "COMMIT", "INIT", "POSTS", "BACKUP", "BLOB", "",
        ] {
            assert!(!client.is_long_verb(verb), "{verb}");
            assert!(!server.is_long_verb(verb), "{verb}");
            assert!(!new.is_long_verb(verb), "{verb}");
        }
        assert_eq!(client.for_verb("post"), MAX_LONG_CLIENT_LINE);
        assert_eq!(client.for_verb("LIST"), MAX_CLIENT_LINE);
        assert_eq!(server.for_verb("WELCOME"), MAX_LONG_SERVER_LINE);
        assert_eq!(new.for_verb("REGISTER"), MAX_REGISTER_LINE);
        assert_eq!(new.for_verb("POST"), MAX_CLIENT_LINE);
        assert_eq!(LineLimits::uniform(10).for_verb("POST"), 10);
        assert!(!LineLimits::uniform(10).is_long_verb("POST"));
    }

    /// Small limits that behave like the real ones: normal 16, long 64.
    const SMALL: LineLimits = LineLimits {
        normal: 16,
        long: 64,
        long_verbs: &CLIENT_LONG_VERBS,
    };

    fn decode_small(input: &[u8]) -> Vec<Result<String, ParseError>> {
        let mut d = LineDecoder::with_limits(SMALL);
        d.push(input);
        let all = drain(&mut d);
        // The same, a byte at a time.
        let mut d = LineDecoder::with_limits(SMALL);
        let mut bytewise = Vec::new();
        for b in input {
            d.push(std::slice::from_ref(b));
            assert!(d.pending_bytes() < SMALL.long);
            bytewise.extend(drain(&mut d));
        }
        assert_eq!(bytewise, all);
        all
    }

    #[test]
    fn long_verbs_get_the_long_limit() {
        let post = format!("POST b 1 {}", "A".repeat(40));
        let list = format!("LIST {}", "a".repeat(40));
        let input = format!("{post}\n{list}\nPING\n");
        assert_eq!(
            decode_small(input.as_bytes()),
            vec![ok(&post), Err(ParseError::TooLong), ok("PING")]
        );

        // Case-insensitive, after tags and runs of spaces.
        let post = format!("@ref=1   post b 1 {}", "A".repeat(30));
        assert_eq!(
            decode_small(format!("{post}\n").as_bytes()),
            vec![ok(&post)]
        );
        let report = format!("report b {}", "A".repeat(30));
        assert_eq!(
            decode_small(format!("{report}\n").as_bytes()),
            vec![ok(&report)]
        );

        // A long line over the long limit.
        let post = format!("POST b 1 {}", "A".repeat(60));
        assert_eq!(
            decode_small(format!("{post}\nPING\n").as_bytes()),
            vec![Err(ParseError::TooLong), ok("PING")]
        );

        // Exactly at each limit: 15 and 63 bytes plus the LF fit.
        let list = format!("LIST {}", "a".repeat(10));
        assert_eq!(list.len(), 15);
        assert_eq!(
            decode_small(format!("{list}\n").as_bytes()),
            vec![ok(&list)]
        );
        assert_eq!(
            decode_small(format!("{list}a\n").as_bytes()),
            vec![Err(ParseError::TooLong)]
        );
        let post = format!("POST b 1 {}", "A".repeat(54));
        assert_eq!(post.len(), 63);
        assert_eq!(
            decode_small(format!("{post}\n").as_bytes()),
            vec![ok(&post)]
        );
        assert_eq!(
            decode_small(format!("{post}A\n").as_bytes()),
            vec![Err(ParseError::TooLong)]
        );
    }

    #[test]
    fn the_verb_must_end_within_the_normal_limit() {
        // Up to the end of the verb, the normal limit applies, tags
        // included (2.3): 11 bytes of tags, a space and POST end at index
        // 16, one byte too late.
        let tags = format!("@ref={}", "a".repeat(6));
        assert_eq!(tags.len(), 11);
        let late = format!("{tags} POST b 1 {}", "A".repeat(20));
        assert_eq!(late.find(" b 1"), Some(16));
        assert_eq!(
            decode_small(format!("{late}\nPING\n").as_bytes()),
            vec![Err(ParseError::TooLong), ok("PING")]
        );
        assert_eq!(SMALL.check(&late), Err(ParseError::TooLong));
        // One byte shorter, and the verb ends at index 15.
        let early = format!("@ref=aaaaa POST b 1 {}", "A".repeat(20));
        assert_eq!(
            decode_small(format!("{early}\n").as_bytes()),
            vec![ok(&early)]
        );
        assert_eq!(SMALL.check(&early), Ok(()));
        // The same with runs of spaces before the verb.
        let spaced = format!("@ref=1{}POST b 1 {}", " ".repeat(10), "A".repeat(20));
        assert_eq!(
            decode_small(format!("{spaced}\n").as_bytes()),
            vec![Err(ParseError::TooLong)]
        );

        // Tags longer than the normal limit are too long whatever follows,
        // and the decoder holds no more than the normal limit of them.
        let tags = format!("@x-big={}", "A".repeat(30));
        let input = format!("{tags} REPORT b 1\n{tags} LIST\nPING\n");
        assert_eq!(
            decode_small(input.as_bytes()),
            vec![
                Err(ParseError::TooLong),
                Err(ParseError::TooLong),
                ok("PING")
            ]
        );
        let mut d = LineDecoder::with_limits(SMALL);
        d.push(b"@");
        d.push(&[b'x'; 14]);
        assert_eq!(d.pending_bytes(), 15);
        assert_eq!(d.next_line(), None);
        d.push(b"x");
        assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
        assert_eq!(d.pending_bytes(), 0);

        // A chunk that holds the end of the verb past the normal limit
        // and the rest of a long line is still too long.
        let mut d = LineDecoder::with_limits(SMALL);
        d.push(late.as_bytes());
        assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
    }

    #[test]
    fn verbs_that_only_look_long() {
        // A longer verb that starts with a long one, a verb that is too
        // long to be one, a line with no verb at all, a verb that is long
        // only from the other side, and LIST, which is never long.
        let cases = [
            format!("POSTS {}", "a".repeat(20)),
            format!("WELCOMEXYZ {}", "a".repeat(20)),
            format!("@ref=1 {}", "a".repeat(20)),
            format!(" POST {}", "a".repeat(20)),
            format!("1POST {}", "a".repeat(20)),
            format!("GROUPINFO {}", "a".repeat(20)),
            format!("REGISTER {}", "a".repeat(20)),
            format!("LIST {}", "a".repeat(20)),
        ];
        for line in cases {
            assert_eq!(
                decode_small(format!("{line}\n").as_bytes()),
                vec![Err(ParseError::TooLong)],
                "{line:?}"
            );
            assert_eq!(SMALL.check(&line), Err(ParseError::TooLong), "{line:?}");
        }
        // A verb alone on its line.
        assert_eq!(decode_small(b"POST\n"), vec![ok("POST")]);
        assert_eq!(SMALL.check("POST"), Ok(()));
    }

    #[test]
    fn limits_can_change() {
        // A server: normal limits until the connection has a kind, then
        // long lines.
        let mut d = LineDecoder::new(16);
        let post = format!("POST b 1 {}", "A".repeat(30));
        d.push(format!("{post}\n").as_bytes());
        assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
        d.set_limits(SMALL);
        assert_eq!(d.limits(), SMALL);
        assert_eq!(d.max_len(), 16);
        d.push(format!("{post}\n").as_bytes());
        assert_eq!(d.next_line(), Some(ok(&post)));

        // The line in progress is judged by the new limits.
        let mut d = LineDecoder::new(16);
        d.push(b"POST b 1 ");
        d.set_limits(SMALL);
        d.push(format!("{}\n", "A".repeat(30)).as_bytes());
        assert_eq!(
            d.next_line(),
            Some(Ok(format!("POST b 1 {}", "A".repeat(30))))
        );
    }

    #[test]
    fn new_connections_allow_only_a_long_register() {
        // 2.3: before a connection has a kind, REGISTER may be 64 KiB and
        // every other line has the normal limit.
        let new = LineLimits::NEW_CONNECTION;
        let register = format!("REGISTER alice {} sig", "A".repeat(60_000));
        assert_eq!(new.check(&register), Ok(()));
        assert_eq!(
            LineLimits::CLIENT.check(&register),
            Err(ParseError::TooLong)
        );
        let at_limit = format!("REGISTER {}", "A".repeat(MAX_REGISTER_LINE - 10));
        assert_eq!(at_limit.len(), MAX_REGISTER_LINE - 1);
        assert_eq!(new.check(&at_limit), Ok(()));
        assert_eq!(new.check(&format!("{at_limit}A")), Err(ParseError::TooLong));
        let post = format!("POST b 1 {}", "A".repeat(MAX_CLIENT_LINE));
        assert_eq!(new.check(&post), Err(ParseError::TooLong));
        assert_eq!(LineLimits::CLIENT.check(&post), Ok(()));

        let mut d = LineDecoder::with_limits(new);
        d.push(format!("{register}\n{post}\nPING\n").as_bytes());
        assert_eq!(d.next_line(), Some(Ok(register)));
        assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
        assert_eq!(d.next_line(), Some(ok("PING")));
    }

    #[test]
    fn check_by_verb() {
        let long = format!("POST b 1 {}", "A".repeat(MAX_CLIENT_LINE));
        assert_eq!(LineLimits::CLIENT.check(&long), Ok(()));
        assert_eq!(
            check_line_len(&long, MAX_CLIENT_LINE),
            Err(ParseError::TooLong)
        );
        let list = format!("LIST {}", "a".repeat(MAX_CLIENT_LINE));
        assert_eq!(LineLimits::CLIENT.check(&list), Err(ParseError::TooLong));
        let report = format!("@ref=1 report b {}", "x".repeat(9000));
        assert_eq!(LineLimits::CLIENT.check(&report), Ok(()));
        let backup = format!("@ref=1 backup put {}", "x".repeat(9000));
        assert_eq!(LineLimits::CLIENT.check(&backup), Err(ParseError::TooLong));
        // Long tags before a long verb.
        let tags = format!("@x-big={} POST b 1 AAAA", "A".repeat(MAX_CLIENT_LINE));
        assert_eq!(LineLimits::CLIENT.check(&tags), Err(ParseError::TooLong));
        // GROUPINFO lines are long only from a server.
        let gi = format!("GROUPINFO b 1 0 {}", "A".repeat(MAX_SERVER_LINE));
        assert_eq!(LineLimits::SERVER.check(&gi), Ok(()));
        assert_eq!(LineLimits::CLIENT.check(&gi), Err(ParseError::TooLong));
        // Exactly 1 MiB, LF included, fits; one byte more does not.
        let max = format!("POST {}", "A".repeat(MAX_LONG_CLIENT_LINE - 6));
        assert_eq!(LineLimits::CLIENT.check(&max), Ok(()));
        assert_eq!(
            LineLimits::CLIENT.check(&format!("{max}A")),
            Err(ParseError::TooLong)
        );
    }

    #[test]
    fn check_line_rules() {
        assert_eq!(check_line(""), Ok(()));
        assert_eq!(check_line("MSG #a hi\tthere 👋"), Ok(()));
        assert_eq!(check_line("a\nb"), Err(ParseError::ControlChar));
        assert_eq!(check_line("a\r"), Err(ParseError::ControlChar));
        assert_eq!(check_line("\0"), Err(ParseError::ControlChar));
        assert_eq!(check_line("\u{1b}[31m"), Err(ParseError::ControlChar));
        assert_eq!(check_line("\u{7f}"), Err(ParseError::ControlChar));
        assert!(!is_forbidden_control('\t'));
        assert!(!is_forbidden_control(' '));
        assert!(is_forbidden_control('\u{80}'));
        assert!(is_forbidden_control('\u{9f}'));
        assert!(!is_forbidden_control('\u{a0}'));
    }

    #[test]
    fn check_line_len_rules() {
        assert_eq!(check_line_len("abcd", 5), Ok(()));
        assert_eq!(check_line_len("abcde", 5), Err(ParseError::TooLong));
        assert_eq!(check_line_len("", 1), Ok(()));
        assert_eq!(check_line_len("", 0), Err(ParseError::TooLong));
        let long = "a".repeat(MAX_SERVER_LINE - 1);
        assert_eq!(check_line_len(&long, MAX_SERVER_LINE), Ok(()));
        assert_eq!(
            check_line_len(&long, MAX_CLIENT_LINE),
            Err(ParseError::TooLong)
        );
        // Bytes, not characters.
        assert_eq!(check_line_len("éé", 5), Ok(()));
        assert_eq!(check_line_len("ééé", 5), Err(ParseError::TooLong));
    }
}

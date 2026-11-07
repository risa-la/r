//! Splitting a byte stream into lines, and line limits (SPEC 2.3).
//!
//! [`LineDecoder`] is sans-I/O: feed it bytes as they arrive with
//! [`LineDecoder::push`] and take lines out with
//! [`LineDecoder::next_line`]. [`check_line`], [`check_line_len`] and
//! [`LineLimits::check`] apply the same rules to lines about to be sent.
//!
//! # Long lines
//!
//! Lines that carry MLS data (Section 12) may be much longer than others.
//! A line whose verb is one of [`LONG_VERBS`] may be up to
//! [`MAX_LONG_CLIENT_LINE`] bytes from a client and
//! [`MAX_LONG_SERVER_LINE`] from a server; every other line keeps the
//! normal limit. [`LineLimits`] holds both limits of one direction. The
//! decoder reads the verb as the line arrives: until it has seen the
//! verb, which comes after the tags, a line may grow up to the long
//! limit, and once the verb shows that the line is not long, the normal
//! limit applies. A server applies only the normal limits before a
//! connection signs in (2.3), with [`LineLimits::uniform`], and switches
//! with [`LineDecoder::set_limits`].

use std::collections::VecDeque;

use crate::error::ParseError;
use crate::line::find_ref;
use crate::types::Ref;

/// The longest line a client may send, in bytes, including the LF (2.3).
pub const MAX_CLIENT_LINE: usize = 8192;

/// The longest line a server may send, in bytes, including the LF (2.3).
pub const MAX_SERVER_LINE: usize = 16384;

/// The longest line a client may send whose verb is one of
/// [`LONG_VERBS`]: 8 MiB, including the LF (2.3).
pub const MAX_LONG_CLIENT_LINE: usize = 8 * 1024 * 1024;

/// The longest line a server may send whose verb is one of
/// [`LONG_VERBS`]: 8 MiB plus 16384 bytes, including the LF (2.3). The
/// difference leaves room for the tags a server adds.
pub const MAX_LONG_SERVER_LINE: usize = MAX_LONG_CLIENT_LINE + MAX_SERVER_LINE;

/// The verbs of lines that may carry MLS data and so be long (2.3), in
/// upper case.
pub const LONG_VERBS: [&str; 7] = [
    "COMMIT",
    "ENC",
    "GROUPINFO",
    "INIT",
    "KEYPKG",
    "REPORT",
    "WELCOME",
];

/// The length of the longest verb in [`LONG_VERBS`].
const LONGEST_LONG_VERB: usize = 9;

/// Whether a line with this verb may be long (2.3). Verbs are
/// case-insensitive.
pub fn is_long_verb(verb: &str) -> bool {
    is_long_verb_bytes(verb.as_bytes())
}

fn is_long_verb_bytes(verb: &[u8]) -> bool {
    LONG_VERBS
        .iter()
        .any(|long| long.as_bytes().eq_ignore_ascii_case(verb))
}

/// The length limits of one direction of a connection (2.3), each in
/// bytes including the LF: `normal` for most lines, `long` for lines whose
/// verb is one of [`LONG_VERBS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LineLimits {
    /// The limit for lines whose verb is not in [`LONG_VERBS`].
    pub normal: usize,
    /// The limit for lines whose verb is in [`LONG_VERBS`]. Never less
    /// than `normal`.
    pub long: usize,
}

impl LineLimits {
    /// The limits of lines from a client (2.3): what a server's decoder
    /// applies once the connection has signed in, and what a client
    /// checks before it sends.
    pub const CLIENT: LineLimits = LineLimits {
        normal: MAX_CLIENT_LINE,
        long: MAX_LONG_CLIENT_LINE,
    };

    /// The limits of lines from a server (2.3): what a client's decoder
    /// applies, and what a server checks before it sends.
    pub const SERVER: LineLimits = LineLimits {
        normal: MAX_SERVER_LINE,
        long: MAX_LONG_SERVER_LINE,
    };

    /// The same limit for every line. A server's decoder uses
    /// `uniform(MAX_CLIENT_LINE)` until the connection signs in (2.3).
    pub const fn uniform(max_len: usize) -> LineLimits {
        LineLimits {
            normal: max_len,
            long: max_len,
        }
    }

    /// The limit for a line with this verb.
    pub fn for_verb(&self, verb: &str) -> usize {
        if is_long_verb(verb) {
            self.long.max(self.normal)
        } else {
            self.normal
        }
    }

    /// Checks that `line`, without its line ending, fits its limit once
    /// the LF is added, judging by its verb as [`LineDecoder`] does.
    /// Fails with [`ParseError::TooLong`].
    pub fn check(&self, line: &str) -> Result<(), ParseError> {
        let mut scan = VerbScan::default();
        scan.feed(line.as_bytes());
        let max = if scan.finish() {
            self.long.max(self.normal)
        } else {
            self.normal
        };
        check_line_len(line, max)
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
/// them, then reads letters. It stops as soon as it knows the answer: at
/// the first byte after the verb, or once the verb is longer than any long
/// verb. So each byte of a line is looked at most once.
#[derive(Clone, Copy, Debug, Default)]
struct VerbScan {
    phase: Phase,
    verb: [u8; LONGEST_LONG_VERB],
    len: usize,
    /// `Some(long)` once known.
    known: Option<bool>,
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
    /// Reads more bytes of the line. Does nothing once the answer is
    /// known.
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.known.is_some() {
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
        }
    }

    fn verb_byte(&mut self, b: u8) {
        if !b.is_ascii_alphabetic() {
            self.known = Some(is_long_verb_bytes(&self.verb[..self.len]));
        } else if self.len == LONGEST_LONG_VERB {
            self.known = Some(false);
        } else {
            self.verb[self.len] = b;
            self.len += 1;
        }
    }

    /// Whether the line may be long, so far: until the verb is known, it
    /// may.
    fn may_be_long(&self) -> bool {
        self.known.unwrap_or(true)
    }

    /// Whether the line may be long, once all of it has been fed.
    fn finish(&self) -> bool {
        self.known.unwrap_or_else(|| {
            self.phase == Phase::Verb && is_long_verb_bytes(&self.verb[..self.len])
        })
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
///   is the long one for a line whose verb is in [`LONG_VERBS`], and the
///   normal one otherwise. Until the verb has arrived, the long limit
///   applies, since the line may still turn out to be long.
/// - Empty lines are yielded as `Ok("")`. Callers ignore them, but they
///   still count as activity for keepalive (11).
/// - Bytes after the last LF are kept until more data arrives. An
///   unfinished line at the end of the stream is not a line.
///
/// Memory: the decoder never holds more than `long - 1` bytes of an
/// unfinished line, and none while it discards a long one. Complete lines
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

    /// Creates a decoder with these limits: [`LineLimits::CLIENT`] on a
    /// server once the connection has signed in, [`LineLimits::SERVER`]
    /// on a client (2.3).
    pub fn with_limits(limits: LineLimits) -> Self {
        LineDecoder {
            limits: LineLimits {
                normal: limits.normal,
                long: limits.long.max(limits.normal),
            },
            partial: Vec::new(),
            scan: VerbScan::default(),
            discarding: false,
            ready: VecDeque::new(),
        }
    }

    /// Changes the limits, for example when a connection signs in (2.3).
    /// Lines already complete keep the verdict they had. The line in
    /// progress is judged by the new limits from the next byte on; if it
    /// already holds more bytes than they allow, it is reported as too
    /// long at its next byte.
    pub fn set_limits(&mut self, limits: LineLimits) {
        self.limits = LineLimits {
            normal: limits.normal,
            long: limits.long.max(limits.normal),
        };
    }

    /// The limits this decoder applies.
    pub fn limits(&self) -> LineLimits {
        self.limits
    }

    /// The normal limit this decoder applies, the one for lines whose verb
    /// is not in [`LONG_VERBS`].
    pub fn max_len(&self) -> usize {
        self.limits.normal
    }

    /// The limit for the line in progress, as far as its verb is known.
    fn current_max(&self) -> usize {
        if self.scan.may_be_long() {
            self.limits.long
        } else {
            self.limits.normal
        }
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
            let max = if self.scan.finish() {
                self.limits.long
            } else {
                self.limits.normal
            };
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
        assert_eq!(MAX_LONG_CLIENT_LINE, 8_388_608);
        assert_eq!(MAX_LONG_SERVER_LINE, 8_388_608 + 16_384);
        for verb in LONG_VERBS {
            assert!(is_long_verb(verb));
            assert!(is_long_verb(&verb.to_ascii_lowercase()));
            assert!(verb.len() <= LONGEST_LONG_VERB);
        }
        assert!(!is_long_verb("MSG"));
        assert!(!is_long_verb("ENCX"));
        assert!(!is_long_verb(""));
        assert_eq!(LineLimits::CLIENT.for_verb("enc"), MAX_LONG_CLIENT_LINE);
        assert_eq!(LineLimits::CLIENT.for_verb("MSG"), MAX_CLIENT_LINE);
        assert_eq!(LineLimits::SERVER.for_verb("COMMIT"), MAX_LONG_SERVER_LINE);
        assert_eq!(LineLimits::uniform(10).for_verb("ENC"), 10);
    }

    /// Small limits that behave like the real ones: normal 16, long 64.
    const SMALL: LineLimits = LineLimits {
        normal: 16,
        long: 64,
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
        let enc = format!("ENC #r 1 {}", "A".repeat(40));
        let msg = format!("MSG #r {}", "a".repeat(40));
        let input = format!("{enc}\n{msg}\nPING\n");
        assert_eq!(
            decode_small(input.as_bytes()),
            vec![ok(&enc), Err(ParseError::TooLong), ok("PING")]
        );

        // Case-insensitive, after tags and runs of spaces.
        let enc = format!("@frank=x;ref=1   enc #r 1 {}", "A".repeat(30));
        assert_eq!(decode_small(format!("{enc}\n").as_bytes()), vec![ok(&enc)]);

        // A long line over the long limit.
        let enc = format!("ENC #r 1 {}", "A".repeat(60));
        assert_eq!(
            decode_small(format!("{enc}\nPING\n").as_bytes()),
            vec![Err(ParseError::TooLong), ok("PING")]
        );

        // Exactly at each limit: 15 and 63 bytes plus the LF fit.
        let msg = format!("MSG #r {}", "a".repeat(8));
        assert_eq!(msg.len(), 15);
        assert_eq!(decode_small(format!("{msg}\n").as_bytes()), vec![ok(&msg)]);
        assert_eq!(
            decode_small(format!("{msg}a\n").as_bytes()),
            vec![Err(ParseError::TooLong)]
        );
        let enc = format!("ENC #r 1 {}", "A".repeat(54));
        assert_eq!(enc.len(), 63);
        assert_eq!(decode_small(format!("{enc}\n").as_bytes()), vec![ok(&enc)]);
        assert_eq!(
            decode_small(format!("{enc}A\n").as_bytes()),
            vec![Err(ParseError::TooLong)]
        );
    }

    #[test]
    fn long_tags_wait_for_the_verb() {
        // Tags longer than the normal limit: the verb decides.
        let tags = format!("@content={}", "A".repeat(30));
        let report = format!("{tags} REPORT #r 1");
        let msg = format!("{tags} MSG #r hi");
        let input = format!("{report}\n{msg}\nPING\n");
        assert_eq!(
            decode_small(input.as_bytes()),
            vec![ok(&report), Err(ParseError::TooLong), ok("PING")]
        );
        // Tags that never end are bounded by the long limit.
        let mut d = LineDecoder::with_limits(SMALL);
        d.push(b"@");
        d.push(&[b'x'; 62]);
        assert_eq!(d.pending_bytes(), 63);
        assert_eq!(d.next_line(), None);
        d.push(b"x");
        assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
        assert_eq!(d.pending_bytes(), 0);
    }

    #[test]
    fn verbs_that_only_look_long() {
        // A longer verb that starts with a long one, a verb that is too
        // long to be one, and a line with no verb at all.
        let cases = [
            format!("ENCRYPT {}", "a".repeat(20)),
            format!("GROUPINFOS {}", "a".repeat(20)),
            format!("@ref=1 {}", "a".repeat(20)),
            format!(" ENC {}", "a".repeat(20)),
            format!("1ENC {}", "a".repeat(20)),
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
        assert_eq!(decode_small(b"ENC\n"), vec![ok("ENC")]);
        assert_eq!(SMALL.check("ENC"), Ok(()));
    }

    #[test]
    fn limits_can_change() {
        // A server: normal limits until sign-in, then long lines.
        let mut d = LineDecoder::new(16);
        let enc = format!("ENC #r 1 {}", "A".repeat(30));
        d.push(format!("{enc}\n").as_bytes());
        assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
        d.set_limits(SMALL);
        assert_eq!(d.limits(), SMALL);
        assert_eq!(d.max_len(), 16);
        d.push(format!("{enc}\n").as_bytes());
        assert_eq!(d.next_line(), Some(ok(&enc)));
    }

    #[test]
    fn check_by_verb() {
        let long = format!("ENC #r 1 {}", "A".repeat(MAX_CLIENT_LINE));
        assert_eq!(LineLimits::CLIENT.check(&long), Ok(()));
        assert_eq!(
            check_line_len(&long, MAX_CLIENT_LINE),
            Err(ParseError::TooLong)
        );
        let msg = format!("MSG #r {}", "a".repeat(MAX_CLIENT_LINE));
        assert_eq!(LineLimits::CLIENT.check(&msg), Err(ParseError::TooLong));
        assert_eq!(
            LineLimits::CLIENT.check(&format!("@ref=1 report #r 1 {}", "x".repeat(9000))),
            Ok(())
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

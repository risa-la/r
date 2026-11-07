//! Property tests for lines: framing (SPEC 2.3), the line grammar (3.1),
//! tags (3.2) and parameters (3.3).
//!
//! The generators build values from the grammar, so most cases are valid
//! lines. Other properties feed arbitrary input and check that nothing
//! panics and that whatever parses also round-trips.

use std::collections::HashSet;

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use proptest::sample::Index;
use risala_proto::error::ParseError;
use risala_proto::frame::{
    CLIENT_LONG_VERBS, LineDecoder, LineLimits, MAX_CLIENT_LINE, MAX_LONG_CLIENT_LINE,
    MAX_SERVER_LINE, SERVER_LONG_VERBS, check_line,
};
use risala_proto::line::{Line, Tags};

/// Explicit case counts keep `cargo test` fast in debug builds. Set
/// `PROPTEST_CASES` to run every property with that many cases instead.
/// Failures are not persisted to files; a minimal failing case found here
/// becomes a named test instead.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Generators

/// A character from `UTF8-nonascii` (3.1) that lines allow, so not a C1
/// control (2.3), with a few interesting ones (no-break space, line
/// separator, BOM, RTL, emoji) weighted up.
fn non_ascii() -> impl Strategy<Value = char> {
    prop_oneof![
        Just('é'),
        Just('\u{a0}'),
        Just('\u{2028}'),
        Just('\u{feff}'),
        Just('م'),
        Just('👋'),
        any::<char>().prop_filter("non-ASCII, not C1", |c| !c.is_ascii() && !is_c1(*c)),
    ]
}

/// `tag-key = 1*( %x61-7A / DIGIT / "-" )`.
fn tag_key() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => "[a-z0-9-]{1,8}",
        1 => prop::sample::select(vec!["ref", "seq", "t", "from", "reply", "file-type", "x-a"])
            .prop_map(str::to_owned),
    ]
}

/// `tag-value = 1*( %x21-3A / %x3C-7E / UTF8-nonascii )`.
fn tag_value() -> impl Strategy<Value = String> {
    let c = prop_oneof![
        4 => prop::char::range('!', ':'),
        4 => prop::char::range('<', '~'),
        1 => non_ascii(),
    ];
    vec(c, 1..12).prop_map(String::from_iter)
}

type TagEntries = Vec<(String, Option<String>)>;

/// Tags with unique keys, in order, each with an optional value.
fn tag_entries(len: std::ops::Range<usize>) -> impl Strategy<Value = TagEntries> {
    vec((tag_key(), option::of(tag_value())), len).prop_map(|entries| {
        let mut seen = HashSet::new();
        entries
            .into_iter()
            .filter(|(k, _)| seen.insert(k.clone()))
            .collect()
    })
}

fn tag_string(key: &str, value: Option<&str>) -> String {
    match value {
        Some(value) => format!("{key}={value}"),
        None => key.to_owned(),
    }
}

/// The wire form of tags, without the `@`.
fn tags_string(entries: &TagEntries) -> String {
    entries
        .iter()
        .map(|(k, v)| tag_string(k, v.as_deref()))
        .collect::<Vec<_>>()
        .join(";")
}

fn entries_of(tags: &Tags) -> TagEntries {
    tags.iter()
        .map(|(k, v)| (k.to_owned(), v.map(str::to_owned)))
        .collect()
}

/// `verb = 1*ALPHA`, in any case.
fn verb() -> impl Strategy<Value = String> {
    "[A-Za-z]{1,10}"
}

/// `params = *( HTAB / %x20-7E / UTF8-nonascii )`, with spaces and TABs
/// weighted up so that runs of them appear.
fn params_char() -> impl Strategy<Value = char> {
    prop_oneof![
        3 => Just(' '),
        1 => Just('\t'),
        6 => prop::char::range(' ', '~'),
        1 => non_ascii(),
    ]
}

fn params() -> impl Strategy<Value = String> {
    vec(params_char(), 0..30).prop_map(String::from_iter)
}

/// A token (3.3): no space, TAB or control character.
fn token() -> impl Strategy<Value = String> {
    let c = prop_oneof![8 => prop::char::range('!', '~'), 1 => non_ascii()];
    vec(c, 1..10).prop_map(String::from_iter)
}

/// An option key (3.3) as `LineBuilder::option` takes it: `a-z 0-9 -`
/// once folded, so upper case is allowed too.
fn option_key() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9-]{1,8}"
}

/// An option value (3.3): a non-empty token, `=` allowed.
fn option_value() -> impl Strategy<Value = String> {
    token()
}

/// Text (3.3): anything allowed in a line, often with leading spaces.
fn text() -> impl Strategy<Value = String> {
    (0..4usize, params()).prop_map(|(n, t)| " ".repeat(n) + &t)
}

/// How a built line ends (3.3): nothing, options or text.
#[derive(Debug, Clone)]
enum Tail {
    Nothing,
    Options(Vec<(String, String)>),
    Text(String),
}

fn tail() -> impl Strategy<Value = Tail> {
    prop_oneof![
        Just(Tail::Nothing),
        vec((option_key(), option_value()), 0..4).prop_map(|options| {
            // Keys are folded, so they must be unique after folding.
            let mut seen = HashSet::new();
            Tail::Options(
                options
                    .into_iter()
                    .filter(|(k, _)| seen.insert(k.to_ascii_lowercase()))
                    .collect(),
            )
        }),
        text().prop_map(Tail::Text),
    ]
}

/// Strings that look a bit like lines, to reach more of the parser than
/// arbitrary strings do.
fn line_like() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[@;= \t\r\na-zA-Z0-9#~é\\x00\\x7f-]{0,40}",
        (
            tag_entries(0..3),
            "[ ]{0,3}",
            verb(),
            "[ \t]{0,2}",
            params()
        )
            .prop_map(|(tags, gap, verb, sep, params)| {
                let tags = tags_string(&tags);
                format!("@{tags}{gap}{verb}{sep}{params}")
            }),
    ]
}

// ---------------------------------------------------------------------------
// Line and Tags

proptest! {
    #![proptest_config(config(512))]

    /// A canonical line (single space after the tags and after the verb)
    /// parses into its parts and displays back unchanged (3.1).
    #[test]
    fn canonical_line_round_trips(
        entries in tag_entries(0..5),
        verb in verb(),
        params in params(),
    ) {
        let mut s = String::new();
        if !entries.is_empty() {
            s = format!("@{} ", tags_string(&entries));
        }
        s.push_str(&verb);
        if !params.is_empty() {
            s.push(' ');
            s.push_str(&params);
        }
        let line = Line::parse(&s)
            .map_err(|e| TestCaseError::fail(format!("{s:?}: {e}")))?;
        prop_assert_eq!(line.to_string(), s.as_str());
        prop_assert_eq!(line.verb(), verb.as_str());
        prop_assert!(line.verb_is(&verb.to_ascii_lowercase()));
        prop_assert_eq!(line.verb_upper(), verb.to_ascii_uppercase());
        prop_assert_eq!(line.raw_params(), params.as_str());
        prop_assert_eq!(entries_of(line.tags()), entries);
    }

    /// Any string either fails to parse or parses into a line whose
    /// display parses back to the same line and is itself a valid line.
    #[test]
    fn any_parsed_line_round_trips(s in line_like()) {
        if let Ok(line) = Line::parse(&s) {
            let shown = line.to_string();
            prop_assert_eq!(check_line(&shown), Ok(()));
            let again = Line::parse(&shown)
                .map_err(|e| TestCaseError::fail(format!("{shown:?}: {e}")))?;
            prop_assert_eq!(&again, &line);
            prop_assert_eq!(again.to_string(), shown);
        }
    }

    /// Tokens separated by runs of spaces, with trailing spaces, read
    /// back one by one (3.3: receivers accept runs of spaces).
    #[test]
    fn tokens_with_runs_of_spaces(
        verb in verb(),
        tokens in vec(token(), 0..5),
        gaps in vec(1..4usize, 5),
        trailing in 0..3usize,
    ) {
        let mut s = verb;
        for (token, gap) in tokens.iter().zip(&gaps) {
            s.push_str(&" ".repeat(*gap));
            s.push_str(token);
        }
        s.push_str(&" ".repeat(trailing));
        let line = Line::parse(&s)
            .map_err(|e| TestCaseError::fail(format!("{s:?}: {e}")))?;
        let mut params = line.params();
        for token in &tokens {
            prop_assert_eq!(params.token()?, token.as_str());
        }
        prop_assert_eq!(params.opt_token()?, None);
        prop_assert_eq!(params.end(), Ok(()));
    }

    /// `LineBuilder` output displays, parses and reads back as the tags,
    /// verb, tokens, options or text it was given (3.1-3.3). Text keeps
    /// its leading spaces.
    #[test]
    fn builder_round_trips(
        entries in tag_entries(0..4),
        verb in verb(),
        tokens in vec(token(), 0..4),
        tail in tail(),
    ) {
        let mut b = Line::builder(&verb);
        for (key, value) in &entries {
            match value {
                Some(value) => b.tag(key, value),
                None => b.flag(key),
            };
        }
        for token in &tokens {
            b.token(token);
        }
        match &tail {
            Tail::Nothing => {}
            Tail::Options(options) => {
                for (key, value) in options {
                    b.option(key, value);
                }
            }
            Tail::Text(text) => {
                b.text(text);
            }
        }
        let built = b.build().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let shown = built.to_string();
        let line = Line::parse(&shown)
            .map_err(|e| TestCaseError::fail(format!("{shown:?}: {e}")))?;
        prop_assert_eq!(&line, &built);
        prop_assert_eq!(line.to_string(), shown.as_str());
        prop_assert_eq!(line.verb(), verb.to_ascii_uppercase());
        prop_assert_eq!(entries_of(line.tags()), entries);

        let mut params = line.params();
        for token in &tokens {
            prop_assert_eq!(params.token()?, token.as_str());
        }
        match tail {
            Tail::Nothing => prop_assert_eq!(params.end(), Ok(())),
            Tail::Options(options) => {
                let got: Vec<(String, String)> = params
                    .options()?
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
                let want: Vec<(String, String)> = options
                    .into_iter()
                    .map(|(k, v)| (k.to_ascii_lowercase(), v))
                    .collect();
                prop_assert_eq!(got, want);
            }
            Tail::Text(text) => prop_assert_eq!(params.text(), text.as_str()),
        }
    }

    /// The builder refuses what would make an invalid line, whatever else
    /// it is given.
    #[test]
    fn builder_rejects_bad_parts(
        verb in verb(),
        token in token(),
        bad in 0..6usize,
        at in any::<Index>(),
    ) {
        let mut b = Line::builder(&verb);
        b.token(&token);
        let insert = |s: &str, c: char| {
            let mut s = s.to_owned();
            let i = s.char_indices().map(|(i, _)| i).nth(at.index(s.chars().count())).unwrap();
            s.insert(i, c);
            s
        };
        match bad {
            0 => { b.tag(&insert("key", 'K'), "v"); }
            1 => { b.tag("key", insert("v", ';')); }
            2 => { b.token(insert(&token, ' ')); }
            3 => { b.text(&insert(&token, '\n')); }
            4 => { b.text("t"); b.option("k", "v"); }
            _ => { b.option("k", "v"); b.token(&token); }
        }
        prop_assert!(b.build().is_err());
        let bad_verb = format!("{verb}1");
        prop_assert!(Line::builder(&bad_verb).build().is_err());
    }

    /// Tags display and parse back unchanged, with every entry readable
    /// (3.2), and `insert` builds the same value.
    #[test]
    fn tags_round_trip(entries in tag_entries(1..8)) {
        let s = tags_string(&entries);
        let tags = Tags::parse(&s)
            .map_err(|e| TestCaseError::fail(format!("{s:?}: {e}")))?;
        prop_assert_eq!(tags.to_string(), s.as_str());
        prop_assert_eq!(tags.len(), entries.len());
        for (key, value) in &entries {
            prop_assert!(tags.has(key));
            prop_assert_eq!(tags.entry(key), Some(value.as_deref()));
            prop_assert_eq!(tags.get(key), value.as_deref());
        }
        let mut built = Tags::new();
        for (key, value) in &entries {
            built.insert(key, value.as_deref())?;
        }
        prop_assert_eq!(&built, &tags);

        // Replacing a value keeps the tag in place.
        let (key, _) = &entries[0];
        built.insert(key, Some("x"))?;
        prop_assert_eq!(built.len(), entries.len());
        prop_assert_eq!(built.iter().next(), Some((key.as_str(), Some("x"))));
        prop_assert!(built.remove(key));
        prop_assert!(!built.has(key));
    }

    /// A repeated tag key is rejected, whatever its value and wherever it
    /// is (3.2), both by `Tags::parse` and `Line::parse`.
    #[test]
    fn repeated_tag_key_is_rejected(
        entries in tag_entries(1..6),
        pick in any::<Index>(),
        value in option::of(tag_value()),
        at_front in any::<bool>(),
    ) {
        let key = &entries[pick.index(entries.len())].0;
        let extra = tag_string(key, value.as_deref());
        let tags = tags_string(&entries);
        let s = if at_front { format!("{extra};{tags}") } else { format!("{tags};{extra}") };
        prop_assert!(matches!(Tags::parse(&s), Err(ParseError::BadSyntax(_))), "{:?}", s);
        let line = format!("@{s} PING");
        prop_assert!(Line::parse(&line).is_err());
    }

    /// `Tags::parse` never panics, and what it accepts round-trips.
    #[test]
    fn any_parsed_tags_round_trip(s in prop_oneof![any::<String>(), "[a-zA-Z0-9=; -]{0,20}"]) {
        if let Ok(tags) = Tags::parse(&s) {
            prop_assert_eq!(tags.to_string(), s.as_str());
        }
    }
}

// ---------------------------------------------------------------------------
// LineDecoder

/// The C1 controls, U+0080 to U+009F (2.3).
fn is_c1(c: char) -> bool {
    ('\u{80}'..='\u{9f}').contains(&c)
}

/// The 2.3 control characters: %x00-08, %x0A-1F, %x7F and C1.
fn is_control_char(c: char) -> bool {
    matches!(c, '\u{00}'..='\u{08}' | '\u{0a}'..='\u{1f}' | '\u{7f}') || is_c1(c)
}

/// What `LineDecoder` should yield for a whole stream: the results, the
/// bytes left pending, and whether it ends discarding a long line.
///
/// Split on LF. Each complete line is too long if it has `max_len` bytes
/// or more before its LF. Otherwise strip one CR and check UTF-8 and
/// control characters. An unfinished line at the end that already has
/// `max_len` bytes or more is reported as too long once, and dropped.
fn reference(input: &[u8], max_len: usize) -> (Vec<Result<String, ParseError>>, usize, bool) {
    let mut parts: Vec<&[u8]> = input.split(|&b| b == b'\n').collect();
    let unfinished = parts.pop().expect("split yields at least one part");
    let mut out = Vec::new();
    for line in parts {
        out.push(if line.len() + 1 > max_len {
            Err(ParseError::TooLong)
        } else {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            match std::str::from_utf8(line) {
                Err(_) => Err(ParseError::InvalidUtf8),
                Ok(s) if s.chars().any(is_control_char) => Err(ParseError::ControlChar),
                Ok(s) => Ok(s.to_owned()),
            }
        });
    }
    if !unfinished.is_empty() && unfinished.len() >= max_len {
        out.push(Err(ParseError::TooLong));
        (out, 0, true)
    } else {
        (out, unfinished.len(), false)
    }
}

/// Bytes for a stream: LFs, CRs, letters, spaces, TABs, control bytes,
/// stray high bytes and whole UTF-8 characters.
fn stream() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        4 => Just(vec![b'\n']),
        2 => Just(vec![b'\r']),
        8 => (b'a'..=b'z').prop_map(|b| vec![b]),
        2 => Just(vec![b' ']),
        1 => Just(vec![b'\t']),
        1 => prop::sample::select(vec![0x00u8, 0x1b, 0x7f, 0x0b]).prop_map(|b| vec![b]),
        1 => (0x80u8..=0xff).prop_map(|b| vec![b]),
        2 => non_ascii().prop_map(|c| c.to_string().into_bytes()),
        1 => any::<u8>().prop_map(|b| vec![b]),
    ];
    vec(piece, 0..120).prop_map(|pieces| pieces.concat())
}

fn max_len() -> impl Strategy<Value = usize> {
    prop_oneof![1 => 0..=2usize, 4 => 1..=24usize, 1 => Just(64usize)]
}

/// Pushes `input` into a fresh decoder in the chunks given by `cuts`,
/// checking the memory bound after every push. Drains after every push
/// if `drain_each`, else only at the end.
fn decode_in_chunks(
    input: &[u8],
    max_len: usize,
    cuts: &[Index],
    drain_each: bool,
) -> Result<(Vec<Result<String, ParseError>>, LineDecoder), TestCaseError> {
    let mut cuts: Vec<usize> = cuts.iter().map(|i| i.index(input.len() + 1)).collect();
    cuts.sort_unstable();
    cuts.push(input.len());
    let mut d = LineDecoder::new(max_len);
    let mut got = Vec::new();
    let mut start = 0;
    for cut in cuts {
        d.push(&input[start..cut]);
        start = cut;
        // Documented bound: at most `max_len - 1` bytes pending, and none
        // while discarding.
        prop_assert!(
            d.pending_bytes() <= max_len.saturating_sub(1),
            "{} bytes pending, max_len {}",
            d.pending_bytes(),
            max_len
        );
        if d.is_discarding() {
            prop_assert_eq!(d.pending_bytes(), 0);
        }
        if drain_each {
            got.extend(std::iter::from_fn(|| d.next_line()));
        }
    }
    got.extend(std::iter::from_fn(|| d.next_line()));
    Ok((got, d))
}

proptest! {
    #![proptest_config(config(1024))]

    /// For any bytes pushed in any chunks, the decoder yields what the
    /// reference splitter does, stays within its memory bound and ends
    /// in the same state (2.3).
    #[test]
    fn decoder_matches_reference(
        input in stream(),
        max_len in max_len(),
        cuts in vec(any::<Index>(), 0..8),
        drain_each in any::<bool>(),
    ) {
        let (got, d) = decode_in_chunks(&input, max_len, &cuts, drain_each)?;
        let (want, pending, discarding) = reference(&input, max_len);
        prop_assert_eq!(got, want);
        prop_assert_eq!(d.pending_bytes(), pending);
        prop_assert_eq!(d.is_discarding(), discarding);
        prop_assert_eq!(d.max_len(), max_len);
    }
}

proptest! {
    #![proptest_config(config(24))]

    /// The same at the real client limit, with lines just under, at and
    /// well over 8192 bytes (2.3).
    #[test]
    fn decoder_matches_reference_at_client_limit(
        lens in vec(prop_oneof![0..10usize, 8188..8196usize, 9000..20000usize], 1..4),
        last_unfinished in any::<bool>(),
        cr in any::<bool>(),
        cuts in vec(any::<Index>(), 0..6),
    ) {
        let mut input = Vec::new();
        for len in &lens {
            input.extend(std::iter::repeat_n(b'a', *len));
            if cr {
                input.push(b'\r');
            }
            input.push(b'\n');
        }
        if last_unfinished {
            input.pop();
        }
        let (got, d) = decode_in_chunks(&input, MAX_CLIENT_LINE, &cuts, true)?;
        let (want, pending, discarding) = reference(&input, MAX_CLIENT_LINE);
        prop_assert_eq!(got.len(), want.len());
        prop_assert!(got == want);
        prop_assert_eq!(d.pending_bytes(), pending);
        prop_assert_eq!(d.is_discarding(), discarding);
    }
}

// ---------------------------------------------------------------------------
// Long lines (2.3)

/// Where the verb of a line, or of the start of one, ends, and what it
/// is: `Some((end, verb))` once the verb has ended, where `end` is the
/// index of the byte after it; `None` before, or if there is no verb (tags
/// without a space, or a verb longer than nine letters). The verb comes
/// after the tags (`@` to the first space) and any spaces.
fn verb_end(line: &[u8], complete: bool) -> Option<(usize, &[u8])> {
    let mut start = 0;
    if line.first() == Some(&b'@') {
        start = line.iter().position(|&b| b == b' ')?;
        start += line[start..].iter().take_while(|&&b| b == b' ').count();
    }
    let rest = &line[start..];
    let letters = rest.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if letters > 9 || (letters == rest.len() && !complete) {
        None
    } else {
        Some((start + letters, &rest[..letters]))
    }
}

/// Whether a line, or the start of one, may be long under `limits`: its
/// verb has ended within the normal limit and is a long verb (2.3).
fn is_long(line: &[u8], complete: bool, limits: &LineLimits) -> bool {
    verb_end(line, complete).is_some_and(|(end, verb)| {
        end < limits.normal
            && limits
                .long_verbs
                .iter()
                .any(|v| v.as_bytes().eq_ignore_ascii_case(verb))
    })
}

/// [`reference`] with a long limit for lines whose verb is long and ends
/// within the normal limit. Until then, the normal limit applies.
fn reference_long(
    input: &[u8],
    limits: LineLimits,
) -> (Vec<Result<String, ParseError>>, usize, bool) {
    let limit = |line: &[u8], complete: bool| {
        if is_long(line, complete, &limits) {
            limits.long
        } else {
            limits.normal
        }
    };
    let mut parts: Vec<&[u8]> = input.split(|&b| b == b'\n').collect();
    let unfinished = parts.pop().expect("split yields at least one part");
    let mut out = Vec::new();
    for line in parts {
        out.push(if line.len() + 1 > limit(line, true) {
            Err(ParseError::TooLong)
        } else {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            match std::str::from_utf8(line) {
                Err(_) => Err(ParseError::InvalidUtf8),
                Ok(s) if s.chars().any(is_control_char) => Err(ParseError::ControlChar),
                Ok(s) => Ok(s.to_owned()),
            }
        });
    }
    if !unfinished.is_empty() && unfinished.len() >= limit(unfinished, false) {
        out.push(Err(ParseError::TooLong));
        (out, 0, true)
    } else {
        (out, unfinished.len(), false)
    }
}

/// A stream of lines that start with verbs, long and not, often after
/// tags, with filler of any length.
fn verb_stream() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        3 => Just(b"\n".to_vec()),
        1 => Just(b"\r\n".to_vec()),
        3 => prop::sample::select(vec![
            "ENC ", "enc ", "COMMIT", "groupinfo ", "REPORT ", "WelCome ", "INIT", "KEYPKG ",
            "reportEnc ", "MSG ", "ENCX ", "GROUPINFOS ", "REPORTENCS ", "PING", "@", "@ref=1 ",
            "@x-tag=AAAA  ", " ",
        ])
        .prop_map(|s| s.as_bytes().to_vec()),
        4 => "[a-zA-Z0-9 ;=]{1,12}".prop_map(String::into_bytes),
        1 => any::<u8>().prop_map(|b| vec![b]),
    ];
    vec(piece, 0..60).prop_map(|pieces| pieces.concat())
}

fn limits() -> impl Strategy<Value = LineLimits> {
    (1..=24usize, 0..=40usize, any::<bool>()).prop_map(|(normal, extra, client)| LineLimits {
        normal,
        long: normal + extra,
        long_verbs: if client {
            &CLIENT_LONG_VERBS
        } else {
            &SERVER_LONG_VERBS
        },
    })
}

proptest! {
    #![proptest_config(config(1024))]

    /// With a long limit for MLS verbs, the decoder yields what the
    /// reference splitter does, in any chunks, never holds more than the
    /// long limit, and holds no more than the normal limit until a long
    /// verb has ended (2.3).
    #[test]
    fn long_line_decoder_matches_reference(
        input in verb_stream(),
        limits in limits(),
        cuts in vec(any::<Index>(), 0..8),
        drain_each in any::<bool>(),
    ) {
        let mut cuts: Vec<usize> = cuts.iter().map(|i| i.index(input.len() + 1)).collect();
        cuts.sort_unstable();
        cuts.push(input.len());
        let mut d = LineDecoder::with_limits(limits);
        let mut got = Vec::new();
        let mut start = 0;
        for cut in cuts {
            d.push(&input[start..cut]);
            start = cut;
            prop_assert!(d.pending_bytes() < limits.long, "{} pending", d.pending_bytes());
            let line_start = input[..cut].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            if !is_long(&input[line_start..cut], false, &limits) {
                prop_assert!(d.pending_bytes() < limits.normal.max(1), "{} pending", d.pending_bytes());
            }
            if d.is_discarding() {
                prop_assert_eq!(d.pending_bytes(), 0);
            }
            if drain_each {
                got.extend(std::iter::from_fn(|| d.next_line()));
            }
        }
        got.extend(std::iter::from_fn(|| d.next_line()));
        let (want, pending, discarding) = reference_long(&input, limits);
        prop_assert_eq!(got, want);
        prop_assert_eq!(d.pending_bytes(), pending);
        prop_assert_eq!(d.is_discarding(), discarding);
        prop_assert_eq!(d.limits(), limits);

        // An outgoing line passes LineLimits::check exactly when the
        // decoder would take it.
        for line in input.split(|&b| b == b'\n') {
            if let Ok(line) = std::str::from_utf8(line) {
                let fits = line.len() < limits.for_verb_of(line);
                prop_assert_eq!(limits.check(line).is_ok(), fits, "{:?}", line);
            }
        }
    }
}

trait ForVerbOf {
    fn for_verb_of(&self, line: &str) -> usize;
}

impl ForVerbOf for LineLimits {
    /// The limit for a whole line, by the reference's verb rules.
    fn for_verb_of(&self, line: &str) -> usize {
        if is_long(line.as_bytes(), true, self) {
            self.long
        } else {
            self.normal
        }
    }
}

/// A real ENC line just under, at and over the real long limit, with
/// the normal limit for a MSG of the same length.
#[test]
fn real_long_limit() {
    for (len, ok) in [
        (MAX_LONG_CLIENT_LINE - 1, true),
        (MAX_LONG_CLIENT_LINE, false),
    ] {
        let prefix = "ENC #a 0 ";
        let mut line = prefix.as_bytes().to_vec();
        line.resize(len, b'A');
        line.push(b'\n');
        let mut d = LineDecoder::with_limits(LineLimits::CLIENT);
        for chunk in line.chunks(65536) {
            d.push(chunk);
            assert!(d.pending_bytes() < MAX_LONG_CLIENT_LINE);
        }
        let got = d.next_line().unwrap();
        assert_eq!(got.is_ok(), ok, "{len}");
        if let Ok(got) = got {
            assert_eq!(got.len(), len);
        }
    }
    let mut d = LineDecoder::with_limits(LineLimits::CLIENT);
    let mut msg = b"MSG #a ".to_vec();
    msg.resize(MAX_CLIENT_LINE, b'a');
    d.push(&msg);
    assert_eq!(d.next_line(), Some(Err(ParseError::TooLong)));
}

/// With the real limits, the verb of a long line must end within the
/// normal limit: tags can fill at most the normal limit (2.3).
#[test]
fn real_tags_before_a_long_verb() {
    for (limits, verb) in [
        (LineLimits::CLIENT, "REPORTENC"),
        (LineLimits::SERVER, "REPORTENC"),
        (LineLimits::SERVER, "WELCOME"),
    ] {
        let normal = limits.normal;
        assert!(normal == MAX_CLIENT_LINE || normal == MAX_SERVER_LINE);
        // `@x=` plus filler, a space and the verb, so that the byte after
        // the verb is at index `end`.
        let line_with_end = |end: usize| {
            let filler = end - verb.len() - 1 - 3;
            format!(
                "@x={} {verb} {}\n",
                "a".repeat(filler),
                "A".repeat(normal * 2)
            )
        };
        for (end, ok) in [(normal - 1, true), (normal, false)] {
            let line = line_with_end(end);
            assert_eq!(
                line.find(&format!(" {verb} ")).unwrap() + 1 + verb.len(),
                end
            );
            let mut d = LineDecoder::with_limits(limits);
            for chunk in line.as_bytes().chunks(1000) {
                d.push(chunk);
                // Until the verb has ended, no more than the normal limit.
                if d.pending_bytes() >= normal {
                    assert!(ok);
                }
            }
            assert_eq!(d.next_line().unwrap().is_ok(), ok, "{verb} ending at {end}");
            let line = line.trim_end_matches('\n');
            assert_eq!(limits.check(line).is_ok(), ok, "{verb} ending at {end}");
        }
    }
}

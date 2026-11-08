//! Property tests of the lines inside encrypted messages (SPEC 12.9):
//! content made of random valid lines parses, keeps its bytes, and writes
//! back byte for byte; content of random bytes or random protocol words
//! never panics the parser, and whatever parses writes back to the same
//! lines.

use proptest::collection::vec;
use proptest::prelude::*;
use risala_proto::content::{Content, ContentLine, Conversation, Place};
use risala_proto::names::{BlobRef, BoxName};
use risala_proto::types::ConfirmMode;

/// Explicit case counts keep `cargo test` fast in debug builds. Set
/// `PROPTEST_CASES` to run every property with that many cases instead.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Values, as their canonical wire forms

fn fixed(n: usize) -> impl Strategy<Value = String> {
    use base64::Engine as _;
    vec(any::<u8>(), n).prop_map(|b| base64::engine::general_purpose::STANDARD.encode(b))
}

fn message_id() -> impl Strategy<Value = String> {
    fixed(16)
}

fn boxname() -> impl Strategy<Value = String> {
    any::<[u8; 16]>().prop_map(|b| BoxName::from_bytes(b).to_string())
}

fn blob_ref() -> impl Strategy<Value = String> {
    any::<[u8; 48]>().prop_map(|h| BlobRef::from_hash(h).to_string())
}

fn number() -> impl Strategy<Value = u64> {
    0..=i64::MAX as u64
}

fn domain() -> impl Strategy<Value = String> {
    ("[a-z0-9]{1,8}", "[a-z]{2,4}").prop_map(|(d, t)| format!("{d}.{t}"))
}

fn identity() -> impl Strategy<Value = String> {
    ("[a-z0-9]([a-z0-9._-]{0,6}[a-z0-9_-])?", domain()).prop_map(|(n, d)| format!("{n}@{d}"))
}

/// Escaped text that is not blank: a visible character, with spaces,
/// TABs, escapes and non-ASCII around it.
fn text() -> impl Strategy<Value = String> {
    (
        "[ \t]{0,2}",
        "[a-zA-Z0-9.,!?@éع👍\\\\]",
        "[a-zA-Z0-9 \t.,!?@éع👍\\\\]{0,40}",
    )
        .prop_map(|(a, b, c)| format!("{a}{b}{c}"))
}

/// Escaped text that may be empty, for REPORT's reason.
fn reason() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 \t.,!?éع\\\\]{0,60}"
}

fn file_tags() -> impl Strategy<Value = String> {
    (
        "https://[a-z]{1,8}\\.example\\.org(:[1-9][0-9]{0,3})?/[a-zA-Z0-9=?&/]{1,20}",
        fixed(32),
        proptest::option::of("(text|image|application)/(plain|png|octet-stream|vnd\\.a\\+b)"),
        proptest::option::of(number()),
        fixed(48),
    )
        .prop_map(|(url, key, media_type, size, hash)| {
            let mut tags = format!("file={url};file-key={key}");
            if let Some(t) = media_type {
                tags.push_str(&format!(";file-type={t}"));
            }
            if let Some(s) = size {
                tags.push_str(&format!(";file-size={s}"));
            }
            tags.push_str(&format!(";file-hash={hash}"));
            tags
        })
}

fn text_line() -> impl Strategy<Value = String> {
    let plain = (proptest::option::of(file_tags()), text()).prop_map(|(file, text)| match file {
        Some(file) => format!("@{file} TEXT {text}"),
        None => format!("TEXT {text}"),
    });
    let reply =
        (message_id(), proptest::option::of(file_tags()), text()).prop_map(|(id, file, text)| {
            match file {
                Some(file) => format!("@reply={id};{file} TEXT {text}"),
                None => format!("@reply={id} TEXT {text}"),
            }
        });
    let edit = (message_id(), text()).prop_map(|(id, text)| format!("@edit={id} TEXT {text}"));
    let react =
        (message_id(), "[a-z👍é]{1,12}").prop_map(|(id, text)| format!("@react={id} TEXT {text}"));
    prop_oneof![plain, reply, edit, react]
}

fn report_line() -> impl Strategy<Value = String> {
    (boxname(), message_id(), vec(message_id(), 0..=10), reason()).prop_map(
        |(mailbox, target, context, reason)| {
            let mut line = format!("@box={mailbox};target={target}");
            if !context.is_empty() {
                line.push_str(&format!(";context={}", context.join(",")));
            }
            line.push_str(" REPORT");
            if !reason.is_empty() {
                line.push(' ');
                line.push_str(&reason);
            }
            line
        },
    )
}

fn block_target() -> impl Strategy<Value = String> {
    prop_oneof![identity(), domain().prop_map(|d| format!("*@{d}"))]
}

fn want_line() -> impl Strategy<Value = String> {
    (
        boxname(),
        0..i64::MAX as u64 - 2,
        proptest::option::of(2..1000u64),
    )
        .prop_map(|(mailbox, after, gap)| match gap {
            Some(gap) => {
                let before = after.saturating_add(gap).min(i64::MAX as u64);
                format!("WANT {mailbox} {after} {before}")
            }
            None => format!("WANT {mailbox} {after} -"),
        })
}

fn pin_line() -> impl Strategy<Value = String> {
    (
        identity(),
        blob_ref(),
        domain(),
        1..10_000u64,
        blob_ref(),
        any::<bool>(),
    )
        .prop_map(|(uid, master, host, n, head, verified)| {
            let verified = if verified { "yes" } else { "no" };
            format!("PIN {uid} {master} {host}/risala-log/{n} {head} {verified}")
        })
}

/// One valid content line in canonical form, of any verb.
fn content_line() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => text_line(),
        1 => message_id().prop_map(|id| format!("DELETE {id}")),
        1 => Just("TYPING".to_owned()),
        1 => report_line(),
        1 => (any::<u32>(), fixed(1120)).prop_map(|(l, c)| format!("CHALLENGE {l} {c}")),
        1 => (any::<u32>(), fixed(48)).prop_map(|(l, m)| format!("ANSWER {l} {m}")),
        1 => (any::<u32>(), fixed(1312), fixed(2420), fixed(2420), fixed(16))
            .prop_map(|(p, k, c, a, s)| format!("ATTEST {p} {k} {c} {a} {s}")),
        1 => (any::<u32>(), fixed(32)).prop_map(|(p, s)| format!("REVEAL {p} {s}")),
        1 => (boxname(), 1..=i64::MAX as u64, fixed(8))
            .prop_map(|(b, s, c)| format!("READ {b} {s} {c}")),
        1 => (1..=i64::MAX as u64).prop_map(|s| format!("RESYNC {s}")),
        1 => (boxname(), 1..=i64::MAX as u64).prop_map(|(b, s)| format!("RESYNC {b} {s}")),
        1 => block_target().prop_map(|t| format!("BLOCK {t}")),
        1 => block_target().prop_map(|t| format!("UNBLOCK {t}")),
        1 => blob_ref().prop_map(|h| format!("RECORD {h}")),
        1 => blob_ref().prop_map(|h| format!("ALERT {h}")),
        1 => Just("RECORDS -".to_owned()),
        1 => vec(blob_ref(), 0..4).prop_map(|h| {
            let mut line = "RECORDS".to_owned();
            for h in h {
                line.push(' ');
                line.push_str(&h);
            }
            line
        }),
        1 => fixed(32).prop_map(|s| format!("SIGNINGKEY {s}")),
        1 => (any::<u32>(), fixed(32)).prop_map(|(g, k)| format!("BACKUPKEY {g} {k}")),
        1 => want_line(),
        1 => fixed(81).prop_map(|r| format!("TRANSFER {r}")),
        1 => proptest::collection::btree_set(domain(), 1..4)
            .prop_map(|h| format!("SERVERS {}", h.into_iter().collect::<Vec<_>>().join(" "))),
        1 => pin_line(),
    ]
}

/// A line that devices ignore: an unknown verb, or a known verb with
/// the wrong parameters.
fn ignored_line() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Z]{1,8}( [a-z0-9]{1,8}){0,3}"
            .prop_filter("not a content verb", |l| !risala_proto::content::VERBS
                .contains(&l.split(' ').next().unwrap())),
        Just("TEXT".to_owned()),
        Just("TYPING now".to_owned()),
        Just("DELETE x".to_owned()),
        Just(String::new()),
        Just(" leading space".to_owned()),
        Just("@ x".to_owned()),
    ]
}

/// The raw bytes of content: valid lines, with some ignored ones.
fn content() -> impl Strategy<Value = String> {
    vec(prop_oneof![5 => content_line(), 1 => ignored_line()], 1..6)
        .prop_map(|lines| lines.into_iter().map(|l| l + "\n").collect())
}

// ---------------------------------------------------------------------------
// Properties

proptest! {
    #![proptest_config(config(256))]

    /// Every valid line parses, and writes back byte for byte.
    #[test]
    fn line_round_trips(line in content_line()) {
        let parsed = ContentLine::parse(&line).map_err(|e| TestCaseError::fail(format!("{line}: {e}")))?;
        prop_assert_eq!(parsed.to_line(), Ok(line.clone()));
        prop_assert!(parsed.verb().is_some());
    }

    /// Content keeps its bytes, and writing its lines again gives the
    /// same bytes and the same lines: every line here is canonical, and
    /// ignored lines are written back as received.
    #[test]
    fn content_round_trips(raw in content()) {
        let content = Content::parse(raw.as_bytes()).map_err(|e| TestCaseError::fail(format!("{raw:?}: {e}")))?;
        prop_assert_eq!(content.as_str(), raw.as_str());
        prop_assert_eq!(content.lines().len(), raw.matches('\n').count());
        let again = Content::new(content.lines().to_vec()).unwrap();
        prop_assert_eq!(again.as_str(), raw.as_str());
        prop_assert_eq!(&again, &content);
        prop_assert_eq!(Content::parse(again.as_bytes()).unwrap(), content);
    }

    /// Lines with random case in their verbs, and random unknown tags,
    /// parse to the same values, and write back in canonical form.
    #[test]
    fn non_canonical_lines_normalise(line in content_line(), lower in any::<bool>(), tag in "x-[a-z]{1,5}") {
        let canonical = ContentLine::parse(&line).unwrap();
        let (tags, rest) = match line.strip_prefix('@') {
            Some(after) => {
                let (tags, rest) = after.split_once(' ').unwrap();
                (format!("@{tags};{tag}=1 "), rest.to_owned())
            }
            None => (format!("@{tag} "), line.clone()),
        };
        let (verb, params) = rest.split_once(' ').unwrap_or((&rest, ""));
        let verb = if lower { verb.to_ascii_lowercase() } else { verb.to_owned() };
        let mut messy = format!("{tags}{verb}");
        if !params.is_empty() || rest.contains(' ') {
            messy.push(' ');
            messy.push_str(params);
        }
        let parsed = ContentLine::parse(&messy).map_err(|e| TestCaseError::fail(format!("{messy}: {e}")))?;
        prop_assert_eq!(&parsed, &canonical);
        prop_assert_eq!(parsed.to_line(), Ok(line));
    }

    /// Whatever parses as content can be written again, to the same lines.
    #[test]
    fn random_words_never_panic(words in vec(prop_oneof![
        Just("TEXT"), Just("text"), Just("REPORT"), Just("WANT"), Just("PIN"), Just("SERVERS"),
        Just("RECORDS"), Just("CHALLENGE"), Just("@reply=AAAAAAAAAAAAAAAAAAAAAA=="),
        Just("@box=ujzdegxdncf32epf3dhodzdoci;target=AAAAAAAAAAAAAAAAAAAAAA=="),
        Just("@file=https://a.org/x;file-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;file-hash=x"),
        Just("ujzdegxdncf32epf3dhodzdoci"), Just("1"), Just("0"), Just("-"), Just("yes"),
        Just("a.org"), Just("a.org/risala-log/1"), Just("bob@a.org"), Just("\\n"), Just(" "),
        Just("\n"), Just("\t"), Just("é"), Just("sha384:"), Just("AAAA"),
    ], 0..12)) {
        let raw: String = words.concat();
        if let Ok(content) = Content::parse(raw.as_bytes()) {
            prop_assert_eq!(content.as_str(), raw.as_str());
            let again = Content::new(content.lines().to_vec()).unwrap();
            prop_assert_eq!(again.lines(), content.lines());
            for place in [
                Place::new(Conversation::WithYourself),
                Place::new(Conversation::PrivateRoom(ConfirmMode::Epochal)),
            ] {
                let _ = content.allowed(place).count();
            }
        }
    }

    /// Random bytes never panic the parser.
    #[test]
    fn random_bytes_never_panic(bytes in vec(any::<u8>(), 0..200)) {
        if let Ok(content) = Content::parse(&bytes) {
            prop_assert_eq!(content.as_bytes(), &bytes[..]);
            Content::new(content.lines().to_vec()).unwrap();
        }
    }
}

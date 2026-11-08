//! Every `C:` example in the spec (`spec/`) parses as a typed
//! [`Request`] (Section 13), and serialises back to the same line with
//! only the verb in upper case.
//!
//! Values that the spec shortens with `…` (README) are first made whole
//! with [`common::expand_shortened`].

mod common;

use common::client_examples;
use risala_proto::command::Request;
use risala_proto::line::Line;

/// Verbs that take a subcommand, which is written in upper case too.
const WITH_SUBCOMMAND: [&str; 8] = [
    "ADMIN", "BACKUP", "KEYPKG", "KEYS", "PAIR", "PRESENCE", "PUSH", "WELCOME",
];

/// The example with its verb, and subcommand if any, in upper case. Spec
/// examples use lower-case verbs, as someone typing would, and
/// already-folded names.
fn with_upper_verb(example: &str) -> String {
    let (tags, rest) = match example.strip_prefix('@') {
        Some(_) => {
            let (tags, rest) = example.split_once(' ').expect("tags end with a space");
            (format!("{tags} "), rest)
        }
        None => (String::new(), example),
    };
    let mut words = rest.splitn(3, ' ');
    let verb = words.next().unwrap_or_default().to_ascii_uppercase();
    let mut out = format!("{tags}{verb}");
    if let Some(second) = words.next() {
        out.push(' ');
        if WITH_SUBCOMMAND.contains(&verb.as_str()) {
            out.push_str(&second.to_ascii_uppercase());
        } else {
            out.push_str(second);
        }
    }
    if let Some(rest) = words.next() {
        out.push(' ');
        out.push_str(rest);
    }
    out
}

#[test]
fn every_client_example_parses() {
    let examples = client_examples();
    // The spec has 7 `C:` lines, and Appendix B's AUTH.
    assert!(
        examples.len() >= 8,
        "only {} client examples",
        examples.len()
    );
    for example in examples {
        let expanded = example.expanded();
        let line = Line::parse(&expanded).unwrap_or_else(|e| panic!("{example}: {e}"));
        let request = Request::parse(&line).unwrap_or_else(|e| panic!("{example}: {e}"));
        let written = request.to_line();
        assert_eq!(written.to_string(), with_upper_verb(&expanded), "{example}");
        assert_eq!(Request::parse(&written).as_ref(), Ok(&request), "{example}");
        assert_eq!(request.validate(), Ok(()), "{example}");
    }
}

#[test]
fn every_client_example_may_be_sent_by_some_kind() {
    use risala_proto::connection::ConnectionKind;
    for example in client_examples() {
        let request: Request = example.expanded().parse().unwrap();
        assert!(
            ConnectionKind::ALL
                .iter()
                .any(|&k| request.command.check_kind(k).is_ok()),
            "{example}"
        );
    }
}

#[test]
fn shortened_values_are_expanded() {
    use common::expand_shortened;
    // Base64 becomes 96 bytes; a blob-ref 96 hex digits.
    let b64 = |p: &str| format!("{p}{}", "A".repeat(128 - p.len()));
    let hex = |p: &str| format!("{p}{}", "0".repeat(96 - p.len()));
    assert_eq!(
        expand_shortened("post ujzdegxdncf32epf3dhodzdoci - AAEAAQ… groupinfo=AAEABA…"),
        format!(
            "post ujzdegxdncf32epf3dhodzdoci - {} groupinfo={}",
            b64("AAEAAQ"),
            b64("AAEABA")
        )
    );
    assert_eq!(
        expand_shortened("GROUPINFO b 1 0 AAEABA… sha384:5d0c9a1e…"),
        format!(
            "GROUPINFO b 1 0 {} sha384:{}",
            b64("AAEABA"),
            hex("5d0c9a1e")
        )
    );
    // Not base64: left alone.
    assert_eq!(
        expand_shortened("NOTICE cheap pills at …"),
        "NOTICE cheap pills at …"
    );
}

#[test]
fn upper_case_verb_helper() {
    assert_eq!(with_upper_verb("anon"), "ANON");
    assert_eq!(with_upper_verb("list after=#a"), "LIST after=#a");
    assert_eq!(
        with_upper_verb("@ref=7 fetch b after=1"),
        "@ref=7 FETCH b after=1"
    );
    assert_eq!(with_upper_verb("quit  two  spaces"), "QUIT  two  spaces");
    assert_eq!(
        with_upper_verb("keypkg get bob@example.net"),
        "KEYPKG GET bob@example.net"
    );
    assert_eq!(with_upper_verb("presence on"), "PRESENCE ON");
    assert_eq!(with_upper_verb("welcome list"), "WELCOME LIST");
}

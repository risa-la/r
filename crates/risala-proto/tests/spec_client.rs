//! Every `C:` example in SPEC.md and README.md parses as a typed
//! [`Request`] (Section 13), and serialises back to the same line with
//! only the verb in upper case.

mod common;

use common::client_examples;
use risala_proto::command::Request;
use risala_proto::line::Line;

/// The example with its verb in upper case. Spec examples use lower-case
/// verbs, as someone typing would, and already-folded names.
fn with_upper_verb(example: &str) -> String {
    let (tags, rest) = match example.strip_prefix('@') {
        Some(_) => {
            let (tags, rest) = example.split_once(' ').expect("tags end with a space");
            (format!("{tags} "), rest)
        }
        None => (String::new(), example),
    };
    let (verb, params) = match rest.split_once(' ') {
        Some((verb, params)) => (verb, format!(" {params}")),
        None => (rest, String::new()),
    };
    format!("{tags}{}{params}", verb.to_ascii_uppercase())
}

#[test]
fn every_client_example_parses() {
    let examples = client_examples();
    assert!(
        examples.len() >= 10,
        "only {} client examples",
        examples.len()
    );
    for example in examples {
        let line = Line::parse(&example.line).unwrap_or_else(|e| panic!("{example}: {e}"));
        let request = Request::parse(&line).unwrap_or_else(|e| panic!("{example}: {e}"));
        let written = request.to_line();
        assert_eq!(
            written.to_string(),
            with_upper_verb(&example.line),
            "{example}"
        );
        assert_eq!(Request::parse(&written).as_ref(), Ok(&request), "{example}");
        assert_eq!(request.validate(), Ok(()), "{example}");
    }
}

#[test]
fn upper_case_verb_helper() {
    assert_eq!(with_upper_verb("sync"), "SYNC");
    assert_eq!(with_upper_verb("join #a"), "JOIN #a");
    assert_eq!(with_upper_verb("@ref=7 msg #a hi"), "@ref=7 MSG #a hi");
}

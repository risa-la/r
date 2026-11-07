//! Every `S:` example in SPEC.md and README.md parses as a typed
//! [`ServerMessage`] and serialises back byte for byte (SPEC Section 13).
//!
//! Base64 values that the spec shortens with `…` (12.1) are first made
//! whole with `common::expand_shortened`.

mod common;

use common::server_examples;
use risala_proto::line::Line;
use risala_proto::server::{ServerLine, ServerMessage};

#[test]
fn every_server_example_round_trips() {
    let examples = server_examples();
    assert!(examples.len() >= 30, "only {} examples", examples.len());
    for example in examples {
        let expanded = example.expanded();
        let msg: ServerMessage = expanded
            .parse()
            .unwrap_or_else(|e| panic!("{example}: {e}"));
        let out = msg.to_line().to_string();
        assert_eq!(out, expanded, "{example}");
        let again = ServerMessage::parse(&Line::parse(&out).unwrap());
        assert_eq!(again.as_ref(), Ok(&msg), "{example}");
    }
}

#[test]
fn no_server_example_is_unknown() {
    for example in server_examples() {
        let msg: ServerMessage = example.expanded().parse().unwrap();
        assert!(
            !matches!(msg.line, ServerLine::Unknown(_)),
            "{example}: parsed as an unknown verb"
        );
    }
}

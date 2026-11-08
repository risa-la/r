//! Every `C:` example in the spec (`spec/`) parses as a typed
//! [`Request`] (Section 13), and serialises back to the same line with
//! only the verb in upper case.
//!
//! Base64 values that the spec shortens with `…` (12.1) are first made
//! whole with [`common::expand_shortened`].

mod common;

use common::client_examples;
use risala_proto::command::Request;
use risala_proto::line::Line;

/// Verbs that take a subcommand, which is written in upper case too.
const WITH_SUBCOMMAND: [&str; 6] = ["ADMIN", "BACKUP", "KEY", "KEYPKG", "PUSH", "WELCOME"];

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
    assert!(
        examples.len() >= 10,
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
fn shortened_values_are_expanded() {
    use common::expand_shortened;
    // frank is 48 bytes (12.8); other values 96.
    let frank = format!("hT3m{}", "A".repeat(60));
    let blob = |p: &str| format!("{p}{}", "A".repeat(128 - p.len()));
    assert_eq!(
        expand_shortened("@frank=hT3m…;cid=q2r8sv0alm3nb7xk enc bob@example.net 1 3qG8w…"),
        format!(
            "@frank={frank};cid=q2r8sv0alm3nb7xk enc bob@example.net 1 {}",
            blob("3qG8w")
        )
    );
    // REPORTENC's content, after a franking key written in full.
    let key = "g6310tyvzbFYtF+zfJzNGwhM3CbuWJ83hbt4OL35Zb4=";
    assert_eq!(
        expand_shortened(&format!("reportenc a@b.org 2 {key} VEVYVCBz… spam")),
        format!("reportenc a@b.org 2 {key} {} spam", blob("VEVYVCBz"))
    );
    // Not base64: left alone.
    assert_eq!(
        expand_shortened("MSG #general cheap pills at …"),
        "MSG #general cheap pills at …"
    );
    // A value that looks like a tag's but is in the parameters.
    assert_eq!(
        expand_shortened("@ref=1 X frank=hT3m…"),
        format!("@ref=1 X frank={}", blob("hT3m"))
    );
}

#[test]
fn upper_case_verb_helper() {
    assert_eq!(with_upper_verb("sync"), "SYNC");
    assert_eq!(with_upper_verb("join #a"), "JOIN #a");
    assert_eq!(with_upper_verb("@ref=7 msg #a hi"), "@ref=7 MSG #a hi");
    assert_eq!(
        with_upper_verb("msg #a  two  spaces"),
        "MSG #a  two  spaces"
    );
    assert_eq!(
        with_upper_verb("keypkg get bob@example.net"),
        "KEYPKG GET bob@example.net"
    );
    assert_eq!(with_upper_verb("welcome list"), "WELCOME LIST");
}

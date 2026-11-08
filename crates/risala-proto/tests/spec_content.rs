//! The content lines of the spec (`spec/`) parse as [`ContentLine`]s
//! and write back byte for byte (SPEC 12.9).
//!
//! - Every concrete content line in a code block, such as 12.9's reply
//!   and 8.1's `TYPING`, parses.
//! - 12.9's table lists exactly the verbs this crate knows, and each of
//!   its syntax lines, with sample values for its placeholders, parses.
//! - Every syntax line of a content verb in a code block elsewhere, such
//!   as `DELETE <id>` in 5.4, is the one in the table.

mod common;

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use common::{SPEC, code_blocks, spec_files};
use risala_proto::content::{
    BACKUP_KEY_LEN, CHALLENGE_LEN, CONFIRM_MAC_LEN, Content, ContentLine, MESSAGE_ID_LEN, SEED_LEN,
    TRANSFER_REF_LEN, VERBS,
};

/// Lines in code blocks that have a content verb but are not content
/// lines: the client's REPORT to operators and the server's REPORT line
/// (5.8).
const NOT_CONTENT: &[&str] = &[
    "REPORT <box> <report>",
    "@report=<id>;t=<timestamp>;pseudonym=<pseudonym>[;from=<uid>] REPORT <box> <report>",
];

/// The verb of a line, after any tags, in upper case.
fn verb_of(line: &str) -> &str {
    let rest = match line.strip_prefix('@') {
        Some(after) => after.split_once(' ').map_or("", |(_, rest)| rest),
        None => line,
    };
    rest.split(' ').next().unwrap_or("")
}

fn is_content_verb(verb: &str) -> bool {
    VERBS.contains(&verb)
}

/// Every code block line whose verb is a content verb.
fn code_block_lines() -> Vec<(usize, String)> {
    code_blocks(&SPEC)
        .into_iter()
        .flatten()
        .filter(|l| is_content_verb(verb_of(l.text)))
        .map(|l| (l.number, l.text.to_owned()))
        .collect()
}

/// The syntax lines in the first column of 12.9's table of content lines.
fn table_syntaxes() -> Vec<String> {
    let (_, doc) = spec_files()
        .iter()
        .find(|(name, _)| name.contains("12-end-to-end-encryption"))
        .expect("Section 12");
    let start = doc
        .lines()
        .position(|l| l.starts_with("| Line | Where |"))
        .expect("12.9's table of content lines");
    let mut out = Vec::new();
    for row in doc
        .lines()
        .skip(start + 2)
        .take_while(|l| l.starts_with('|'))
    {
        let cell = row.split('|').nth(1).unwrap();
        out.extend(cell.split('`').skip(1).step_by(2).map(str::to_owned));
    }
    assert!(!out.is_empty(), "12.9's table is empty");
    out
}

fn b64(n: usize) -> String {
    BASE64.encode(vec![7u8; n])
}

/// Replaces the placeholders of a syntax line with sample values, and
/// keeps the insides of optional parts, except optional tags.
fn instantiate(syntax: &str) -> String {
    let hash = format!("sha384:{}", "ab".repeat(48));
    let id = b64(MESSAGE_ID_LEN);
    let values: Vec<(&str, String)> = vec![
        ("<text...>", "hello".into()),
        ("<reason...>", "spam".into()),
        ("<box>", "ujzdegxdncf32epf3dhodzdoci".into()),
        ("<seq>", "9120".into()),
        ("<ids>", format!("{id},{id}")),
        ("<id>", id),
        ("<leaf>", "3".into()),
        ("<ciphertext>", b64(CHALLENGE_LEN)),
        ("<mac>", b64(CONFIRM_MAC_LEN)),
        ("<period>", "20401".into()),
        ("<period-key>", b64(1312)),
        ("<certificate>", b64(2420)),
        ("<attestation>", b64(2420)),
        ("<seed>", b64(SEED_LEN)),
        ("<target>", "*@example.net".into()),
        ("<hashes>", format!("{hash} {hash}")),
        ("<hash>", hash.clone()),
        ("<generation>", "2".into()),
        ("<key>", b64(BACKUP_KEY_LEN)),
        ("<after>", "100".into()),
        ("<before>", "200".into()),
        ("<ref>", b64(TRANSFER_REF_LEN)),
        ("<hosts>", "chat.example.org other.example.net".into()),
        ("<uid>", "bob@example.net".into()),
        ("<master>", hash.clone()),
        ("<origin>", "chat.example.net/risala-log/1".into()),
        ("<head>", hash),
        ("<verified>", "yes".into()),
    ];
    // REPORT's `box` and `target` tags are required (5.8), though the
    // table writes its tags as optional.
    let mut line = syntax
        .replace("[@<tags>] REPORT", "@box=<box>;target=<id> REPORT")
        .replace("[@<tags>] ", "")
        .replace(['[', ']'], "");
    for (placeholder, value) in &values {
        line = line.replace(placeholder, value);
    }
    assert!(
        !line.contains('<'),
        "unknown placeholder in {syntax:?}: {line}"
    );
    line
}

#[test]
fn concrete_examples_parse() {
    let examples: Vec<_> = code_block_lines()
        .into_iter()
        .filter(|(_, l)| !l.contains('<'))
        .collect();
    assert!(
        examples.len() >= 2,
        "only {} content examples: {examples:?}",
        examples.len()
    );
    for (number, line) in examples {
        let parsed =
            ContentLine::parse(&line).unwrap_or_else(|e| panic!("spec line {number}: {line}: {e}"));
        assert_eq!(parsed.to_line().as_deref(), Ok(line.as_str()), "{line}");
        let content = Content::parse(format!("{line}\n").as_bytes()).unwrap();
        assert_eq!(content.lines(), [parsed]);
    }
}

#[test]
fn table_lists_every_verb() {
    let table: BTreeSet<String> = table_syntaxes()
        .iter()
        .map(|s| verb_of(&s.replace("[@<tags>] ", "")).to_owned())
        .collect();
    let known: BTreeSet<String> = VERBS.iter().map(|v| (*v).to_owned()).collect();
    assert_eq!(table, known);
}

#[test]
fn table_syntaxes_parse() {
    for syntax in table_syntaxes() {
        let line = instantiate(&syntax);
        let parsed = ContentLine::parse(&line).unwrap_or_else(|e| panic!("{syntax}: {line}: {e}"));
        assert_eq!(parsed.to_line().as_deref(), Ok(line.as_str()), "{syntax}");
    }
}

#[test]
fn syntax_lines_match_the_table() {
    let table: BTreeSet<String> = table_syntaxes().into_iter().collect();
    for (number, line) in code_block_lines() {
        if !line.contains('<') || NOT_CONTENT.contains(&line.as_str()) {
            continue;
        }
        let in_table = table.contains(&line)
            || table.iter().any(|t| {
                // The table writes optional tags as `[@<tags>]`, and 5.8
                // spells REPORT's tags out.
                t.strip_prefix("[@<tags>] ")
                    .is_some_and(|rest| line.ends_with(rest) && line.starts_with('@'))
            });
        assert!(
            in_table,
            "spec line {number}: {line} is not in 12.9's table"
        );
        // And it parses with sample values.
        let instance = instantiate(&line);
        ContentLine::parse(&instance).unwrap_or_else(|e| panic!("{line}: {instance}: {e}"));
    }
}

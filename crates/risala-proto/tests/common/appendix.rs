//! Appendix B's test vectors, read from `spec/b-test-vectors.md`.
//!
//! The appendix is split into sections by `### ` headings. Each section's
//! code blocks are either *value blocks*, lines of `name: value`, or
//! *text blocks*, anything else, such as the AUTH command or a PEM key.
//! In a value block:
//!
//! - a value longer than one line goes on in the next lines, each
//!   starting with two spaces; the parts are joined with nothing between;
//! - a name that ends in `(file F)` gives the SHA-256 hash of file `F` in
//!   `crates/risala-proto/tests/vectors/`, whose bytes are the value;
//! - the value `rejected` says that the case named MUST fail;
//! - empty lines separate a vector's inputs from its outputs.
//!
//! A test opens a section with [`Checker::open`] and checks every value in
//! it against what the code makes; [`Checker::finish`] fails if any value
//! of the section was left unchecked, so nothing in the appendix goes
//! untested. Run a test with `RISALA_VECTORS=print` to print each section
//! as the code makes it (and to write its files) instead of checking.
//!
//! This file is shared: risala-mls includes it with `#[path]`.

#![allow(dead_code)]

use std::fmt::Write as _;

use sha2::Digest as _;

/// The appendix.
pub const APPENDIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/b-test-vectors.md");

/// The folder of the values given as files.
pub const FILES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../risala-proto/tests/vectors");

/// The value of a case that MUST fail.
pub const REJECTED: &str = "rejected";

/// The widest a value is printed before it goes on in the next line.
const WRAP: usize = 64;

/// The widest a `name: value` line is printed; past it, the value goes
/// on the next line.
const LINE: usize = 92;

/// One `### ` section of the appendix.
#[derive(Debug, Clone)]
pub struct Section {
    /// The heading, without `### `.
    pub title: String,
    /// The `name: value` lines of its value blocks, in order.
    pub values: Vec<(String, String)>,
    /// Its text blocks, each as its lines joined with LF (and no final LF).
    pub texts: Vec<String>,
}

/// The sections of the appendix, in order.
pub fn sections() -> Vec<Section> {
    let doc = std::fs::read_to_string(APPENDIX).expect("spec/b-test-vectors.md");
    parse(&doc)
}

/// Splits `doc` into sections. Panics on anything malformed, so that a
/// change to the appendix cannot drop a vector silently.
pub fn parse(doc: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    let mut block: Option<Vec<&str>> = None;
    for (i, line) in doc.lines().enumerate() {
        let is_fence = line.starts_with("```");
        match &mut block {
            Some(lines) if is_fence => {
                assert_eq!(line, "```", "line {}: a closing fence with text", i + 1);
                let lines = block.take().unwrap();
                let section = sections
                    .last_mut()
                    .unwrap_or_else(|| panic!("line {}: a code block before any ###", i + 1));
                add_block(section, &lines, i + 1);
            }
            Some(lines) => lines.push(line),
            None if is_fence => block = Some(Vec::new()),
            None => {
                if let Some(title) = line.strip_prefix("### ") {
                    sections.push(Section {
                        title: title.to_owned(),
                        values: Vec::new(),
                        texts: Vec::new(),
                    });
                }
            }
        }
    }
    assert!(block.is_none(), "an unclosed code block");
    let mut titles: Vec<&str> = sections.iter().map(|s| s.title.as_str()).collect();
    titles.sort_unstable();
    titles.dedup();
    assert_eq!(titles.len(), sections.len(), "two sections with one title");
    sections
}

/// The name and value of a `name: value` line, or of a `name:` line
/// whose value is on the lines after it. Names hold no `:`.
fn split_value_line(line: &str) -> Option<(&str, &str)> {
    if line.starts_with(' ') {
        return None;
    }
    let (name, value) = match line.split_once(": ") {
        Some((name, value)) => (name, value.trim_start()),
        None => (line.strip_suffix(':')?, ""),
    };
    (!name.is_empty() && !name.contains(':')).then_some((name, value))
}

fn add_block(section: &mut Section, lines: &[&str], end: usize) {
    let first = lines.iter().find(|l| !l.is_empty());
    if !first.is_some_and(|l| split_value_line(l).is_some()) {
        section.texts.push(lines.join("\n"));
        return;
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(more) = line.strip_prefix("  ") {
            assert!(
                !more.starts_with(' ') && !more.is_empty(),
                "before line {end}: a continuation line {line:?}"
            );
            section
                .values
                .last_mut()
                .expect("a value before its continuation")
                .1
                .push_str(more);
        } else {
            let (name, value) = split_value_line(line)
                .unwrap_or_else(|| panic!("before line {end}: not a value line: {line:?}"));
            assert!(
                !section.values.iter().any(|(n, _)| n == name),
                "{}: {name} twice",
                section.title
            );
            section.values.push((name.to_owned(), value.to_owned()));
        }
    }
    for (name, value) in &section.values {
        assert!(!value.is_empty(), "{}: {name} has no value", section.title);
    }
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Hex to bytes. Panics on anything else.
pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// SHA-256, in hex.
pub fn sha256(bytes: &[u8]) -> String {
    hex(&sha2::Sha256::digest(bytes))
}

/// Whether the tests print the vectors rather than check them.
pub fn printing() -> bool {
    std::env::var("RISALA_VECTORS").is_ok_and(|v| v == "print")
}

/// Checks one section of the appendix against the code.
pub struct Checker {
    section: Section,
    used: Vec<bool>,
    texts_used: usize,
    print: bool,
    /// In print mode: the lines so far, with an empty name for a gap.
    out: Vec<(String, String)>,
}

impl Checker {
    /// Opens the section whose title starts with `prefix`, such as
    /// `"B.5 "`. In print mode, a missing section is an empty one.
    pub fn open(prefix: &str) -> Checker {
        let print = printing();
        let found = sections().into_iter().find(|s| s.title.starts_with(prefix));
        let section = match (found, print) {
            (Some(s), _) => s,
            (None, true) => Section {
                title: prefix.to_owned(),
                values: Vec::new(),
                texts: Vec::new(),
            },
            (None, false) => panic!("Appendix B has no section {prefix:?}"),
        };
        Checker {
            used: vec![false; section.values.len()],
            section,
            texts_used: 0,
            print,
            out: Vec::new(),
        }
    }

    fn find(&mut self, name: &str) -> Option<String> {
        let i = self.section.values.iter().position(|(n, _)| n == name)?;
        assert!(
            !self.used[i],
            "{}: {name} checked twice",
            self.section.title
        );
        self.used[i] = true;
        Some(self.section.values[i].1.clone())
    }

    /// The value `name` is `actual`.
    pub fn eq(&mut self, name: &str, actual: impl Into<String>) {
        let actual = actual.into();
        if self.print {
            self.out.push((name.to_owned(), actual));
            return;
        }
        let title = self.section.title.clone();
        let expected = self
            .find(name)
            .unwrap_or_else(|| panic!("{title}: no value {name:?}"));
        assert_eq!(expected, actual, "{title}: {name}");
    }

    /// The value `name` is `bytes` in hex.
    pub fn hex(&mut self, name: &str, bytes: &[u8]) {
        self.eq(name, hex(bytes));
    }

    /// The value `name (file <file>)` is the SHA-256 of `bytes`, which are
    /// file `<file>`'s bytes.
    pub fn file(&mut self, name: &str, file: &str, bytes: &[u8]) {
        let path = format!("{FILES}/{file}");
        if self.print {
            std::fs::create_dir_all(FILES).unwrap();
            std::fs::write(&path, bytes).unwrap();
        } else {
            let on_disk = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(on_disk == bytes, "{}: {file} differs", self.section.title);
        }
        self.eq(&format!("{name} (file {file})"), sha256(bytes));
    }

    /// The case `name` MUST fail, and does when `failed`.
    pub fn rejected(&mut self, name: &str, failed: bool) {
        assert!(failed, "{}: {name} did not fail", self.section.title);
        self.eq(name, REJECTED);
    }

    /// In print mode, an empty line between inputs and outputs.
    pub fn gap(&mut self) {
        if self.print {
            self.out.push((String::new(), String::new()));
        }
    }

    /// The section's next text block.
    pub fn text(&mut self) -> String {
        let text = self
            .section
            .texts
            .get(self.texts_used)
            .unwrap_or_else(|| panic!("{}: too few text blocks", self.section.title))
            .clone();
        self.texts_used += 1;
        text
    }

    /// The section's text blocks are all used, and so are its values; or
    /// in print mode, prints the section's value block.
    pub fn finish(self) {
        if self.print {
            println!(
                "### {}\n\n```\n{}```\n",
                self.section.title,
                format_block(&self.out)
            );
            return;
        }
        let title = &self.section.title;
        assert_eq!(
            self.texts_used,
            self.section.texts.len(),
            "{title}: text blocks left unchecked"
        );
        let left: Vec<&str> = self
            .section
            .values
            .iter()
            .zip(&self.used)
            .filter(|(_, used)| !**used)
            .map(|((n, _), _)| n.as_str())
            .collect();
        assert!(left.is_empty(), "{title}: values left unchecked: {left:?}");
    }
}

/// `name: value` lines. A value longer than [`WRAP`], or that would make
/// the line longer than [`LINE`], goes on the lines after its name,
/// [`WRAP`] characters to a line; the others are lined up, in each group
/// of lines between empty ones. Values with a space stay on the line.
pub fn format_block(lines: &[(String, String)]) -> String {
    let fits = |name: &str, value: &str| {
        value.contains(' ') || (value.len() <= WRAP && name.len() + 2 + value.len() <= LINE)
    };
    let mut out = String::new();
    for group in lines.split(|(name, _)| name.is_empty()) {
        if !out.is_empty() {
            out.push('\n');
        }
        let width = group
            .iter()
            .filter(|(n, v)| fits(n, v))
            .map(|(n, _)| n.len() + 2)
            .max()
            .unwrap_or(0);
        for (name, value) in group {
            let head = format!("{name}:");
            if fits(name, value) {
                let _ = writeln!(out, "{head:<width$}{value}");
                continue;
            }
            let _ = writeln!(out, "{head}");
            let mut rest = value.as_str();
            while !rest.is_empty() {
                let (part, more) = rest.split_at(WRAP.min(rest.len()));
                let _ = writeln!(out, "  {part}");
                rest = more;
            }
        }
    }
    out
}

#[test]
fn format_and_parse_agree() {
    let lines = vec![
        ("a".to_owned(), "x".repeat(150)),
        (String::new(), String::new()),
        ("longer name (file f.bin)".to_owned(), "1 2 3".to_owned()),
        ("QR text".to_owned(), "RISALA-FP:ABC".to_owned()),
    ];
    let doc = format!("### T\n\n```\n{}```\n", format_block(&lines));
    let sections = parse(&doc);
    assert_eq!(sections.len(), 1);
    assert_eq!(
        sections[0].values,
        vec![
            ("a".to_owned(), "x".repeat(150)),
            ("longer name (file f.bin)".to_owned(), "1 2 3".to_owned()),
            ("QR text".to_owned(), "RISALA-FP:ABC".to_owned()),
        ]
    );
}

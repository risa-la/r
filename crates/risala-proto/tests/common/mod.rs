//! Example lines from SPEC.md and README.md, shared by the spec tests.
//!
//! [`spec_examples`] collects:
//!
//! - every `C:` and `S:` line inside a fenced code block in SPEC.md, with
//!   the prefix removed. Other lines in those blocks, such as
//!   "(the client PUTs ...)" or "$ openssl ...", are skipped.
//! - the session in README.md: the lines after `$ openssl s_client` in
//!   its first code block. They have no prefix, so the direction comes
//!   from the verb's case: the person typing uses lower case, and servers
//!   send verbs in upper case (3.1).
//! - the `AUTH` command in Appendix B.
//!
//! The extractor panics on anything it does not understand, such as an
//! unclosed code block, so a change to the documents cannot silently drop
//! examples.

#![allow(dead_code)]

use std::fmt;

/// The text of SPEC.md.
pub const SPEC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SPEC.md"));

/// The text of README.md.
pub const README: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));

/// Who sent an example line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Client to server (`C:`).
    Client,
    /// Server to client (`S:`).
    Server,
}

/// Which document an example comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// SPEC.md.
    Spec,
    /// README.md.
    Readme,
}

impl Source {
    pub fn file_name(self) -> &'static str {
        match self {
            Source::Spec => "SPEC.md",
            Source::Readme => "README.md",
        }
    }
}

/// One example line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Example {
    /// Who sent it.
    pub dir: Dir,
    /// The line, without prefix and without line ending.
    pub line: String,
    /// The 1-based line number in `source`.
    pub spec_line: usize,
    /// The document it comes from.
    pub source: Source,
}

impl fmt::Display for Example {
    /// `SPEC.md:117: S: RISALA 1 ...`, for test failure messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.dir {
            Dir::Client => "C",
            Dir::Server => "S",
        };
        write!(
            f,
            "{}:{}: {prefix}: {}",
            self.source.file_name(),
            self.spec_line,
            self.line
        )
    }
}

/// Every example line, in document order: SPEC.md (including Appendix
/// B's AUTH command, in place), then README.md.
pub fn spec_examples() -> Vec<Example> {
    let mut examples = spec_md_examples(SPEC);
    examples.extend(appendix_b_auth(SPEC));
    examples.sort_by_key(|e| e.spec_line);
    examples.extend(readme_examples(README));
    examples
}

/// Every example sent by the client.
pub fn client_examples() -> Vec<Example> {
    spec_examples()
        .into_iter()
        .filter(|e| e.dir == Dir::Client)
        .collect()
}

/// Every example sent by the server.
pub fn server_examples() -> Vec<Example> {
    spec_examples()
        .into_iter()
        .filter(|e| e.dir == Dir::Server)
        .collect()
}

/// A line inside a fenced code block.
#[derive(Debug, Clone, Copy)]
pub struct BlockLine<'a> {
    /// 1-based line number in the document.
    pub number: usize,
    /// The line, with any CR removed.
    pub text: &'a str,
}

/// The fenced code blocks of a Markdown document, each as its lines
/// (without the fences). Panics on an unclosed block.
pub fn code_blocks(doc: &str) -> Vec<Vec<BlockLine<'_>>> {
    let mut blocks = Vec::new();
    // The fence that opened the current block: its character and length.
    let mut open: Option<(char, usize, usize)> = None;
    let mut current = Vec::new();
    for (i, raw) in doc.split('\n').enumerate() {
        let number = i + 1;
        let text = raw.strip_suffix('\r').unwrap_or(raw);
        let fence = fence(text);
        match (open, fence) {
            (None, Some((c, n, _))) => open = Some((c, n, number)),
            (Some((c, n, _)), Some((fc, fnum, info)))
                if fc == c && fnum >= n && info.is_empty() =>
            {
                open = None;
                blocks.push(std::mem::take(&mut current));
            }
            (Some(_), _) => current.push(BlockLine { number, text }),
            (None, None) => {}
        }
    }
    if let Some((_, _, number)) = open {
        panic!("unclosed code block opened at line {number}");
    }
    blocks
}

/// If `line` is a code fence (up to three spaces, then three or more
/// backticks or tildes), returns its character, length and info string.
fn fence(line: &str) -> Option<(char, usize, &str)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let c = rest.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let n = rest.len() - rest.trim_start_matches(c).len();
    if n < 3 {
        return None;
    }
    Some((c, n, rest[n..].trim()))
}

/// The `C:` and `S:` lines in the code blocks of SPEC.md.
fn spec_md_examples(doc: &str) -> Vec<Example> {
    let mut examples = Vec::new();
    for block in code_blocks(doc) {
        for line in block {
            let trimmed = line.text.trim_start();
            let (dir, rest) = if let Some(rest) = trimmed.strip_prefix("C:") {
                (Dir::Client, rest)
            } else if let Some(rest) = trimmed.strip_prefix("S:") {
                (Dir::Server, rest)
            } else {
                continue;
            };
            let Some(example) = rest.strip_prefix(' ') else {
                // Something like `C:\Users`, not a prefix.
                continue;
            };
            assert!(
                !example.is_empty() && !example.starts_with(' '),
                "SPEC.md:{}: malformed example {:?}",
                line.number,
                line.text
            );
            examples.push(Example {
                dir,
                line: example.to_owned(),
                spec_line: line.number,
                source: Source::Spec,
            });
        }
    }
    examples
}

/// The AUTH command in Appendix B: the code block lines there that start
/// with `AUTH `. Panics unless there is exactly one.
fn appendix_b_auth(doc: &str) -> Vec<Example> {
    let start = doc
        .split('\n')
        .position(|l| l.starts_with("## Appendix B"))
        .expect("SPEC.md has no Appendix B")
        + 1;
    let end = doc
        .split('\n')
        .enumerate()
        .skip(start)
        .find(|(_, l)| l.starts_with("## "))
        .map_or(usize::MAX, |(i, _)| i + 1);
    let examples: Vec<Example> = code_blocks(doc)
        .into_iter()
        .flatten()
        .filter(|l| l.number > start && l.number < end && l.text.starts_with("AUTH "))
        .map(|l| Example {
            dir: Dir::Client,
            line: l.text.to_owned(),
            spec_line: l.number,
            source: Source::Spec,
        })
        .collect();
    assert_eq!(
        examples.len(),
        1,
        "expected one AUTH command in Appendix B, found {examples:?}"
    );
    examples
}

/// The session in README.md: the lines after `$ openssl s_client` in the
/// code block that contains it. Panics if there is no such block, or if a
/// line's direction cannot be told from its verb.
fn readme_examples(doc: &str) -> Vec<Example> {
    let block = code_blocks(doc)
        .into_iter()
        .find(|b| b.iter().any(|l| l.text.starts_with("$ openssl s_client")))
        .expect("README.md has no openssl session");
    let mut lines = block
        .into_iter()
        .skip_while(|l| !l.text.starts_with("$ openssl s_client"));
    lines.next();
    let examples: Vec<Example> = lines
        .filter(|l| !l.text.trim().is_empty())
        .map(|l| Example {
            dir: direction_by_shape(l.text).unwrap_or_else(|| {
                panic!("README.md:{}: cannot tell who sent {:?}", l.number, l.text)
            }),
            line: l.text.to_owned(),
            spec_line: l.number,
            source: Source::Readme,
        })
        .collect();
    assert!(!examples.is_empty(), "README.md's session has no lines");
    examples
}

/// Who sent an unprefixed session line, judged by its verb: all lower
/// case for what the person typed, all upper case for the server.
/// `None` for anything else.
pub fn direction_by_shape(line: &str) -> Option<Dir> {
    let rest = if line.starts_with('@') {
        line.split_once(' ')?.1
    } else {
        line
    };
    let verb = rest.split(' ').next()?;
    if verb.is_empty() || !verb.bytes().all(|b| b.is_ascii_alphabetic()) {
        None
    } else if verb.bytes().all(|b| b.is_ascii_lowercase()) {
        Some(Dir::Client)
    } else if verb.bytes().all(|b| b.is_ascii_uppercase()) {
        Some(Dir::Server)
    } else {
        None
    }
}

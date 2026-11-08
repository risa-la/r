//! Example lines from the spec (`spec/`), shared by the spec tests.
//!
//! The spec is `spec/README.md` followed by the folder's other files in
//! name order, as its contents list them. [`spec_examples`] collects:
//!
//! - every `C:` and `S:` line inside a fenced code block, with the prefix
//!   removed. Other lines in those blocks, such as
//!   "(the client PUTs ...)" or "$ openssl ...", are skipped.
//! - the `AUTH` command in Appendix B.
//!
//! The extractor panics on anything it does not understand, such as an
//! unclosed code block, so a change to the documents cannot silently drop
//! examples.

#![allow(dead_code)]

use std::fmt;
use std::sync::LazyLock;

/// The whole spec: its files joined in reading order (see [`spec_files`]).
pub static SPEC: LazyLock<String> =
    LazyLock::new(|| spec_files().iter().map(|(_, text)| text.as_str()).collect());

/// The files of `spec/`, each with its text: `README.md` first, then the
/// rest in name order (`01-…` to `16-…`, then the appendices `a-…` on).
pub fn spec_files() -> &'static [(String, String)] {
    static FILES: LazyLock<Vec<(String, String)>> = LazyLock::new(|| {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec");
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("the spec folder, spec/")
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".md"))
            .collect();
        names.sort_by_key(|n| (n != "README.md", n.clone()));
        names
            .into_iter()
            .map(|n| {
                let mut text = std::fs::read_to_string(format!("{dir}/{n}")).unwrap();
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                (format!("spec/{n}"), text)
            })
            .collect()
    });
    &FILES
}

/// Where line `n` (1-based) of [`SPEC`] comes from: its file, and its
/// line number in that file.
pub fn spec_location(n: usize) -> (&'static str, usize) {
    let mut start = 0;
    for (name, text) in spec_files() {
        let lines = text.matches('\n').count();
        if n <= start + lines {
            return (name, n - start);
        }
        start += lines;
    }
    ("spec", n)
}

/// Who sent an example line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dir {
    /// Client to server (`C:`).
    Client,
    /// Server to client (`S:`).
    Server,
}

/// Which document an example comes from. Only the spec has examples:
/// README.md's hand-typed session went with item 42 of PLAN.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// The spec (`spec/`).
    Spec,
}

/// One example line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Example {
    /// Who sent it.
    pub dir: Dir,
    /// The line, without prefix and without line ending.
    pub line: String,
    /// The 1-based line number in [`SPEC`]; [`spec_location`] turns it
    /// into a file and a line in it.
    pub spec_line: usize,
    /// The document it comes from.
    pub source: Source,
}

impl Example {
    /// The line with each shortened base64 value made whole, so that it
    /// parses as a typed line. See [`expand_shortened`].
    pub fn expanded(&self) -> String {
        expand_shortened(&self.line)
    }
}

/// How many bytes a shortened base64 value stands for. MLS data, the
/// only base64 the spec's examples shorten, has any length; 96 bytes is
/// enough to look like a real value.
const SHORTENED_BYTES: usize = 96;

/// The spec's examples shorten long values with `…` (README), as in
/// `POST ujzdegxdncf32epf3dhodzdoci AAEAAQ…` or
/// `sha384:5d0c9a1e…`. This replaces each such value, a run of base64
/// characters followed by `…`, so that the line parses as a typed line:
///
/// - after `sha384:`, with the 96 hex digits of a blob-ref (3.5), padded
///   with `0`;
/// - otherwise with valid base64 of 96 bytes that starts with the same
///   characters.
///
/// The same shortened value always becomes the same full one. An `…`
/// that does not follow a base64 character, as in `cheap pills at …`, is
/// left alone.
pub fn expand_shortened(line: &str) -> String {
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find('…') {
        let before = &rest[..at];
        let start = before
            .char_indices()
            .rev()
            .take_while(|&(_, c)| is_b64(c))
            .last()
            .map_or(at, |(i, _)| i);
        let prefix = &before[start..];
        out.push_str(&before[..start]);
        if prefix.is_empty() {
            out.push('…');
        } else if before[..start].ends_with("sha384:") {
            assert!(prefix.len() < 96, "{line}: {prefix} is too long");
            out.push_str(prefix);
            out.extend(std::iter::repeat_n('0', 96 - prefix.len()));
        } else {
            let len = SHORTENED_BYTES.div_ceil(3) * 4;
            let pad = (3 - SHORTENED_BYTES % 3) % 3;
            assert!(prefix.len() < len - pad, "{line}: {prefix} is too long");
            out.push_str(prefix);
            out.extend(std::iter::repeat_n('A', len - pad - prefix.len()));
            out.extend(std::iter::repeat_n('=', pad));
        }
        rest = &rest[at + '…'.len_utf8()..];
    }
    out.push_str(rest);
    out
}

impl fmt::Display for Example {
    /// `spec/01-introduction.md:117: S: RISALA 1 ...`, for test failure
    /// messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.dir {
            Dir::Client => "C",
            Dir::Server => "S",
        };
        let (file, line) = spec_location(self.spec_line);
        write!(f, "{file}:{line}: {prefix}: {}", self.line)
    }
}

/// Every example line, in document order, including Appendix B's AUTH
/// command in place.
pub fn spec_examples() -> Vec<Example> {
    let mut examples = spec_md_examples(&SPEC);
    examples.extend(appendix_b_auth(&SPEC));
    examples.sort_by_key(|e| e.spec_line);
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

/// The `C:` and `S:` lines in the code blocks of the spec.
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
                "{:?}: malformed example {:?}",
                spec_location(line.number),
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
        .expect("the spec has no Appendix B")
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

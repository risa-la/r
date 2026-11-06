//! Text escaping (SPEC 3.4) and mentions (5.5).
//!
//! Text parameters stay escaped everywhere in this crate, exactly as they
//! travel on the wire. [`escape`] turns what a user typed into wire text,
//! [`unescape`] turns wire text into display text, and [`mentions`] finds
//! the uids a message mentions.

use std::borrow::Cow;
use std::collections::HashSet;

use crate::names::{MAX_UID_LEN, Uid, is_valid_uid};

/// Escapes user input for use as a text parameter (3.4).
///
/// - A backslash becomes `\\`.
/// - A line break becomes `\n`. LF, CRLF and a lone CR each count as one
///   line break, so text pasted from any platform keeps its lines.
/// - TAB is kept, since lines may contain it (2.3).
/// - Every other control character (U+0000 to U+001F, U+007F and the C1
///   controls U+0080 to U+009F) is dropped. Lines must not contain them
///   (2.3), and none of them has a meaning in chat text. Dropping them
///   also removes terminal escape sequence introducers from pasted text.
///
/// The result is always valid inside a line.
///
/// For any input without dropped control characters and with LF line
/// breaks, `unescape(&escape(s)) == s`.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => {
                chars.next_if_eq(&'\n');
                out.push_str("\\n");
            }
            '\t' => out.push('\t'),
            c if crate::frame::is_forbidden_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Unescapes a text parameter for display (3.4).
///
/// Escapes are read left to right: `\n` is a line break (LF), `\\` is one
/// backslash, and any other backslash stands for itself. So `\\n` is a
/// backslash followed by `n`, `C:\Users` stays as it is, and a lone
/// backslash at the end stays.
///
/// Borrows the input when it contains no backslash.
pub fn unescape(escaped: &str) -> Cow<'_, str> {
    let Some(first) = escaped.find('\\') else {
        return Cow::Borrowed(escaped);
    };
    let mut out = String::with_capacity(escaped.len());
    out.push_str(&escaped[..first]);
    let mut chars = escaped[first..].chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let rest = chars.as_str();
        if rest.starts_with('n') {
            out.push('\n');
            chars.next();
        } else if rest.starts_with('\\') {
            out.push('\\');
            chars.next();
        } else {
            out.push('\\');
        }
    }
    Cow::Owned(out)
}

/// The characters that can appear in a uid, in either case (3.5).
fn is_uid_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'@')
}

/// The uids that a message's text mentions, in order of first mention,
/// without duplicates (5.5).
///
/// `escaped` is a text parameter as on the wire; it is unescaped first. A
/// mention is `@` at the start of the text or after whitespace (any
/// Unicode white space, including an escaped line break), followed by a
/// uid. The mention is the longest uid that follows the `@`. Uids never
/// end with `.` (3.5), so full stops after a mention are not part of it.
/// Names are folded to lower case.
///
/// - `@alice@example.org.` mentions `alice@example.org`
/// - `@alice@example.org's` mentions `alice@example.org`
/// - `@~sam,` and `@~sam...` mention `~sam`
/// - `@Bob@Example.NET` mentions `bob@example.net`
/// - `@alice`, `@alice@localhost` and `mail@example.org` mention nobody
pub fn mentions(escaped: &str) -> Vec<Uid> {
    let text = unescape(escaped);
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let mut after_space = true;
    for (i, c) in text.char_indices() {
        if c == '@' && after_space {
            if let Some(uid) = mention_at(&text[i + 1..]) {
                if seen.insert(uid.clone()) {
                    found.push(uid);
                }
            }
        }
        after_space = c.is_whitespace();
    }
    found
}

/// The uid mentioned by the text directly after an `@`, if any.
fn mention_at(rest: &str) -> Option<Uid> {
    // The longest uid is a prefix of the run of uid characters. Folding it
    // once lets the grammar check run on each prefix without allocating.
    // Runs are capped at the longest possible uid, which keeps the work per
    // mention bounded.
    let run = rest
        .bytes()
        .take(MAX_UID_LEN)
        .take_while(|&b| is_uid_char(b))
        .map(|b| b.to_ascii_lowercase())
        .collect::<Vec<u8>>();
    let mut end = (1..=run.len()).rev().find(|&n| is_valid_uid(&run[..n]))?;
    // Every valid uid starts with an alphanumeric after `~` or ends with an
    // alphanumeric label, so this never empties the name.
    while run[end - 1] == b'.' {
        end -= 1;
    }
    std::str::from_utf8(&run[..end]).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_rules() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape(""), "");
        assert_eq!(escape("one\ntwo"), "one\\ntwo");
        assert_eq!(escape("one\r\ntwo"), "one\\ntwo");
        assert_eq!(escape("one\rtwo"), "one\\ntwo");
        assert_eq!(escape("one\r\rtwo"), "one\\n\\ntwo");
        assert_eq!(escape("one\n\r\ntwo"), "one\\n\\ntwo");
        assert_eq!(escape("one\n\rtwo"), "one\\n\\ntwo");
        assert_eq!(escape("end\r"), "end\\n");
        assert_eq!(escape("C:\\Users"), "C:\\\\Users");
        assert_eq!(escape("\\n"), "\\\\n");
        assert_eq!(escape("a\tb"), "a\tb");
        assert_eq!(escape("\x1b[31mred\x1b[0m"), "[31mred[0m");
        assert_eq!(escape("nul\0del\x7fbell\x07"), "nuldelbell");
        assert_eq!(escape("عائشة 👋"), "عائشة 👋");
        assert_eq!(escape("c1\u{85}\u{9b}\u{a0}"), "c1\u{a0}");
        assert_eq!(escape("  leading"), "  leading");
    }

    #[test]
    fn escape_output_is_line_safe() {
        let all: String = (0u8..=0x7f).map(char::from).collect();
        let out = escape(&all);
        assert!(
            out.chars().all(|c| c == '\t' || !c.is_ascii_control()),
            "{out:?}"
        );
    }

    #[test]
    fn unescape_rules() {
        assert!(matches!(unescape("plain"), Cow::Borrowed("plain")));
        assert_eq!(unescape("one\\ntwo"), "one\ntwo");
        assert_eq!(unescape("C:\\Users"), "C:\\Users");
        assert_eq!(unescape("\\\\n"), "\\n");
        assert_eq!(unescape("\\\\"), "\\");
        assert_eq!(unescape("\\\\\\n"), "\\\n");
        assert_eq!(unescape("\\n\\n"), "\n\n");
        assert_eq!(unescape("trailing\\"), "trailing\\");
        assert_eq!(unescape("\\"), "\\");
        assert_eq!(unescape("\\\\\\"), "\\\\");
        assert_eq!(unescape("\\N"), "\\N");
        assert_eq!(unescape("\\t"), "\\t");
        assert_eq!(unescape("\\é"), "\\é");
        assert_eq!(unescape("é\\nü"), "é\nü");
    }

    #[test]
    fn round_trip() {
        for s in [
            "",
            "hello",
            "one\ntwo",
            "C:\\Users\\sam",
            "\\n",
            "\\",
            "\\\\n\n\\",
            "tab\there",
            "  spaces  ",
            "日本語\n👋",
        ] {
            assert_eq!(unescape(&escape(s)), s, "{s:?}");
        }
    }

    fn uids(text: &str) -> Vec<String> {
        mentions(text).iter().map(|u| u.to_string()).collect()
    }

    #[test]
    fn mention_basics() {
        assert_eq!(uids("@alice@example.org hi"), ["alice@example.org"]);
        assert_eq!(uids("hi @~sam"), ["~sam"]);
        assert_eq!(uids("@~sam"), ["~sam"]);
        assert_eq!(uids("hi\t@~sam"), ["~sam"]);
        assert_eq!(uids("nobody here"), Vec::<String>::new());
        assert_eq!(uids(""), Vec::<String>::new());
        assert_eq!(uids("@"), Vec::<String>::new());
        assert_eq!(uids("@ alice@example.org"), Vec::<String>::new());
    }

    #[test]
    fn mention_trailing_punctuation() {
        assert_eq!(uids("thanks @alice@example.org."), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org's idea"), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org, hi"), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org: hi"), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org!"), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org?"), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org..."), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org-"), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org_"), ["alice@example.org"]);
        assert_eq!(uids("@alice@example.org)"), ["alice@example.org"]);
        assert_eq!(uids("@~sam,"), ["~sam"]);
        assert_eq!(uids("@~sam."), ["~sam"]);
        assert_eq!(uids("@~sam..."), ["~sam"]);
        assert_eq!(uids("@~sam's"), ["~sam"]);
        assert_eq!(uids("@~sam:"), ["~sam"]);
        assert_eq!(uids("@~sam~"), ["~sam"]);
    }

    #[test]
    fn mention_longest_uid() {
        // Names may contain '.', '_' and '-'.
        assert_eq!(uids("@~sam.smith"), ["~sam.smith"]);
        assert_eq!(uids("@~sam_smith-2"), ["~sam_smith-2"]);
        assert_eq!(
            uids("@bob.smith@mail.example.net"),
            ["bob.smith@mail.example.net"]
        );
        assert_eq!(uids("@alice@example.org.uk."), ["alice@example.org.uk"]);
        // A second '@' cannot belong to the same uid.
        assert_eq!(uids("@alice@example.org@bob@x.y"), ["alice@example.org"]);
        // Without a valid domain, there is no identity.
        assert_eq!(uids("@alice"), Vec::<String>::new());
        assert_eq!(uids("@alice@localhost"), Vec::<String>::new());
        assert_eq!(uids("@alice@-example.org"), Vec::<String>::new());
        assert_eq!(uids("@alice@"), Vec::<String>::new());
        // A non-ASCII character ends the run.
        assert_eq!(uids("@alice@exämple.org"), Vec::<String>::new());
        assert_eq!(uids("@alice@example.orgé"), ["alice@example.org"]);
        // A guest name stops at 32 characters, the longest valid uid.
        let long = "a".repeat(40);
        assert_eq!(uids(&format!("@~{long}")), [format!("~{}", &long[..32])]);
        assert_eq!(uids("@~"), Vec::<String>::new());
        assert_eq!(uids("@~.sam"), Vec::<String>::new());
        assert_eq!(uids("@@alice@example.org"), Vec::<String>::new());
    }

    #[test]
    fn mention_position() {
        // '@' must start the text or follow whitespace.
        assert_eq!(uids("mail alice@example.org"), Vec::<String>::new());
        assert_eq!(uids("(@alice@example.org)"), Vec::<String>::new());
        assert_eq!(uids("x@~sam"), Vec::<String>::new());
        // After unescaping: a line break counts as whitespace...
        assert_eq!(uids("hi\\n@~sam"), ["~sam"]);
        // ...but an escaped backslash does not.
        assert_eq!(uids("\\\\@~sam"), Vec::<String>::new());
        // `\\n` is a backslash and an 'n', not a line break.
        assert_eq!(uids("\\\\n@~sam"), Vec::<String>::new());
        // Unicode white space counts.
        assert_eq!(uids("hi\u{3000}@~sam"), ["~sam"]);
        assert_eq!(uids("hi\u{a0}@~sam"), ["~sam"]);
    }

    #[test]
    fn mention_fold_and_dedupe() {
        assert_eq!(uids("@Bob@Example.NET"), ["bob@example.net"]);
        assert_eq!(uids("@~Sam @~sam @~SAM"), ["~sam"]);
        assert_eq!(
            uids("@~b @alice@example.org @~a @Alice@example.org @~b"),
            ["~b", "alice@example.org", "~a"]
        );
    }

    #[test]
    fn mention_many() {
        // Many mentions in one long text stay fast and correct.
        let text = "@~a ".repeat(2000) + &format!("@{}@{}.org", "b".repeat(32), "c".repeat(63));
        let found = mentions(&text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].as_str(), "~a");
    }
}

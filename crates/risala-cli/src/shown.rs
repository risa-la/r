//! Text from others, made safe to print to a terminal.
//!
//! Labels, display names, room names, topics, message text and the
//! server's error text come from other people and servers. Printed raw,
//! terminal escapes in them can move the cursor, rewrite what was printed
//! before, or hide the question the user answers, as in 4.8 step 5 where
//! whoever saw the QR code answers with an identity of their own. Bidi
//! controls can reorder what is shown. So everything the CLI prints that
//! it did not make itself goes through [`Shown`].

use std::fmt;

/// Prints `.0` with every control character shown as `\u{..}`: C0 (TAB
/// too, since fields are separated by TABs), DEL, C1, and Unicode's format
/// characters and line and paragraph separators, bidi controls among
/// them. Everything else, backslashes too, is printed as it is.
pub struct Shown<'a>(pub &'a str);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.0;
        while let Some(at) = rest.find(escaped) {
            f.write_str(&rest[..at])?;
            let c = rest[at..].chars().next().unwrap_or_default();
            write!(f, "\\u{{{:x}}}", u32::from(c))?;
            rest = &rest[at + c.len_utf8()..];
        }
        f.write_str(rest)
    }
}

/// Whether `c` is shown escaped: a control (Cc), a format character (Cf),
/// or a line or paragraph separator (Zl, Zp), as of Unicode 15.
///
/// ZERO WIDTH NON-JOINER and ZERO WIDTH JOINER (U+200C, U+200D) are kept:
/// Persian and other scripts need the first and emoji sequences the
/// second, and neither moves text.
fn escaped(c: char) -> bool {
    matches!(
        c,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'
            | '\u{200e}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// [`Shown`] for anything printable, such as a uid or a room.
pub fn shown(value: impl fmt::Display) -> String {
    Shown(&value.to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> String {
        Shown(text).to_string()
    }

    #[test]
    fn plain_text_is_unchanged() {
        for text in [
            "",
            "alice@example.org",
            "laptop",
            "C:\\Users and \\n stay",
            "héllo, مرحبا, שלום, 你好, 🌱",
            "می‌خواهم",
            "👨\u{200d}👩\u{200d}👧",
        ] {
            assert_eq!(s(text), text);
        }
    }

    #[test]
    fn c0_del_and_c1_are_escaped() {
        assert_eq!(s("\u{1b}[2J"), "\\u{1b}[2J");
        assert_eq!(s("a\u{0}b"), "a\\u{0}b");
        assert_eq!(s("a\tb\nc\rd"), "a\\u{9}b\\u{a}c\\u{d}d");
        assert_eq!(s("\u{7}\u{8}"), "\\u{7}\\u{8}");
        assert_eq!(s("x\u{7f}"), "x\\u{7f}");
        assert_eq!(s("\u{80}\u{9b}31m\u{9f}"), "\\u{80}\\u{9b}31m\\u{9f}");
        assert_eq!(s("\u{a0}"), "\u{a0}");
    }

    #[test]
    fn bidi_and_format_controls_are_escaped() {
        for c in [
            '\u{61c}',
            '\u{200e}',
            '\u{200f}',
            '\u{202a}',
            '\u{202b}',
            '\u{202c}',
            '\u{202d}',
            '\u{202e}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{200b}',
            '\u{2060}',
            '\u{feff}',
            '\u{ad}',
            '\u{2028}',
            '\u{2029}',
            '\u{e0041}',
        ] {
            let text = format!("a{c}b");
            assert_eq!(s(&text), format!("a\\u{{{:x}}}b", u32::from(c)), "{c:?}");
        }
        assert_eq!(s("evil\u{202e}gpj.exe"), "evil\\u{202e}gpj.exe");
    }

    #[test]
    fn every_control_is_escaped() {
        for c in (0..=0x10ffff).filter_map(char::from_u32) {
            let out = s(&c.to_string());
            if c.is_control() {
                assert_eq!(out, format!("\\u{{{:x}}}", u32::from(c)));
            }
            assert!(!out.chars().any(char::is_control), "{c:?}");
            assert!(!out.contains('\u{1b}'));
        }
    }

    #[test]
    fn shown_takes_anything_printable() {
        assert_eq!(shown(format_args!("x\u{1b}y")), "x\\u{1b}y");
        assert_eq!(shown(42), "42");
    }
}

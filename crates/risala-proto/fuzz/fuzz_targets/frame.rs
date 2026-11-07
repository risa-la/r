//! Bytes into `LineDecoder` (SPEC 2.3), then each line into `Line::parse`
//! (3.1).
//!
//! The first input byte picks the length limits and where to split the
//! rest. Some limits give lines whose verb carries MLS data a longer
//! limit, as 2.3 does, with the long verbs of either direction. The
//! decoder must give the same results whether the bytes arrive at once,
//! in three chunks or one byte at a time, and must stay within its memory
//! bounds: below the long limit always, and below the normal limit until
//! a long verb has ended within it. Every line that parses must display
//! as a line that parses back to the same value, and an outgoing line
//! passes `LineLimits::check` if the decoder took it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use risala_proto::error::ParseError;
use risala_proto::frame::{
    CLIENT_LONG_VERBS, LineDecoder, LineLimits, MAX_CLIENT_LINE, SERVER_LONG_VERBS, check_line,
};
use risala_proto::line::Line;

type Output = (Vec<Result<String, ParseError>>, usize, bool);

/// Whether the start of a line holds a long verb that ends within the
/// normal limit: after the tags (`@` to the first space) and any spaces,
/// letters that make a long verb, then a byte that is not a letter.
fn long_verb_ends(line: &[u8], limits: &LineLimits) -> bool {
    let mut start = 0;
    if line.first() == Some(&b'@') {
        let Some(space) = line.iter().position(|&b| b == b' ') else {
            return false;
        };
        start = space + line[space..].iter().take_while(|&&b| b == b' ').count();
    }
    let letters = line[start..]
        .iter()
        .take_while(|b| b.is_ascii_alphabetic())
        .count();
    let end = start + letters;
    end < line.len()
        && end < limits.normal
        && limits
            .long_verbs
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(&line[start..end]))
}

fn decode(limits: LineLimits, chunks: &[&[u8]]) -> Output {
    let mut d = LineDecoder::with_limits(limits);
    let mut out = Vec::new();
    let mut pushed: Vec<u8> = Vec::new();
    for chunk in chunks {
        d.push(chunk);
        pushed.extend_from_slice(chunk);
        assert!(d.pending_bytes() <= limits.long.saturating_sub(1));
        if d.is_discarding() {
            assert_eq!(d.pending_bytes(), 0);
        }
        // The bytes held are the start of a line: more than the normal
        // limit's worth only once a long verb has ended.
        let pending = &pushed[pushed.len() - d.pending_bytes()..];
        if !pending.is_empty() && pending.len() >= limits.normal {
            assert!(long_verb_ends(pending, &limits), "{pending:?}");
        }
        out.extend(std::iter::from_fn(|| d.next_line()));
    }
    (out, d.pending_bytes(), d.is_discarding())
}

fn check_parsed_line(s: &str) {
    assert_eq!(check_line(s), Ok(()));
    let Ok(line) = Line::parse(s) else {
        return;
    };
    let shown = line.to_string();
    let again = Line::parse(&shown).unwrap_or_else(|e| panic!("{shown:?} from {s:?}: {e}"));
    assert_eq!(again, line);
    assert_eq!(again.to_string(), shown);

    // Read the parameters every way a typed layer might.
    let mut params = line.params();
    while let Ok(Some(_)) = params.opt_token() {}
    let _ = params.end();
    let mut params = line.params();
    let _ = params.token();
    let _ = params.text();
    let _ = line.params().options();
    let _ = line.params().text();
}

fuzz_target!(|data: &[u8]| {
    let Some((&seed, data)) = data.split_first() else {
        return;
    };
    let limits = match seed & 3 {
        0 => LineLimits::uniform(MAX_CLIENT_LINE),
        1 => LineLimits::SERVER,
        2 => LineLimits {
            normal: 16,
            long: 64,
            long_verbs: if seed & 4 == 0 {
                &CLIENT_LONG_VERBS
            } else {
                &SERVER_LONG_VERBS
            },
        },
        _ => LineLimits::uniform(usize::from(seed >> 2)),
    };
    let a = data.len() * usize::from(seed) / 256;
    let b = a + (data.len() - a) / 2;

    let whole = decode(limits, &[data]);
    let split = decode(limits, &[&data[..a], &data[a..b], &data[b..]]);
    assert_eq!(whole, split);
    if data.len() <= 4096 {
        let bytes: Vec<&[u8]> = data.chunks(1).collect();
        assert_eq!(whole, decode(limits, &bytes));
    }

    for line in whole.0.iter().flatten() {
        assert_eq!(limits.check(line), Ok(()), "{line:?}");
        check_parsed_line(line);
    }
});

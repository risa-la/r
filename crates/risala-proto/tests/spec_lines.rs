//! Every example line in SPEC.md and README.md parses as a raw [`Line`]
//! and displays back unchanged (SPEC 3.1-3.3).

mod common;

use common::{Dir, Example, Source, code_blocks, direction_by_shape, spec_examples};
use risala_proto::frame::{LineDecoder, MAX_CLIENT_LINE, MAX_SERVER_LINE, check_line_len};
use risala_proto::line::Line;

#[test]
fn collects_examples() {
    let all = spec_examples();
    let count = |f: &dyn Fn(&Example) -> bool| all.iter().filter(|e| f(e)).count();
    let spec = count(&|e| e.source == Source::Spec);
    let readme = count(&|e| e.source == Source::Readme);
    let client = count(&|e| e.dir == Dir::Client);
    let server = count(&|e| e.dir == Dir::Server);
    eprintln!(
        "{} examples: {spec} from SPEC.md, {readme} from README.md; {client} client, {server} server",
        all.len()
    );
    assert!(spec >= 41, "only {spec} examples in SPEC.md");
    assert!(client >= 10, "only {client} client examples");
    assert!(server >= 30, "only {server} server examples");
}

#[test]
fn every_example_round_trips() {
    for example in spec_examples() {
        let line = Line::parse(&example.line).unwrap_or_else(|e| panic!("{example}: {e}"));
        assert_eq!(line.to_string(), example.line, "{example}");
        assert_eq!(
            Line::parse(&line.to_string()).as_ref(),
            Ok(&line),
            "{example}"
        );
    }
}

#[test]
fn every_example_fits_its_limit() {
    for example in spec_examples() {
        let max = match example.dir {
            Dir::Client => MAX_CLIENT_LINE,
            Dir::Server => MAX_SERVER_LINE,
        };
        assert_eq!(check_line_len(&example.line, max), Ok(()), "{example}");
    }
}

#[test]
fn every_example_splits_into_tokens() {
    for example in spec_examples() {
        let line = Line::parse(&example.line).unwrap();
        let mut params = line.params();
        let mut tokens = 0;
        while let Some(token) = params
            .opt_token()
            .unwrap_or_else(|e| panic!("{example}: {e}"))
        {
            assert!(!token.is_empty());
            tokens += 1;
        }
        assert_eq!(params.end(), Ok(()), "{example}");
        assert_eq!(tokens == 0, line.raw_params().is_empty(), "{example}");
    }
}

#[test]
fn server_examples_use_upper_case_verbs() {
    for example in spec_examples().iter().filter(|e| e.dir == Dir::Server) {
        let line = Line::parse(&example.line).unwrap();
        assert_eq!(line.verb(), line.verb_upper(), "{example}");
    }
}

#[test]
fn examples_survive_the_decoder() {
    for (dir, max) in [
        (Dir::Client, MAX_CLIENT_LINE),
        (Dir::Server, MAX_SERVER_LINE),
    ] {
        let examples: Vec<Example> = spec_examples()
            .into_iter()
            .filter(|e| e.dir == dir)
            .collect();
        for ending in ["\n", "\r\n"] {
            let stream: String = examples
                .iter()
                .map(|e| format!("{}{ending}", e.line))
                .collect();
            // Push in awkward chunks, including splits inside characters.
            let mut decoder = LineDecoder::new(max);
            let mut out = Vec::new();
            for chunk in stream.as_bytes().chunks(7) {
                decoder.push(chunk);
                out.extend(std::iter::from_fn(|| decoder.next_line()));
            }
            let got: Vec<String> = out.into_iter().map(Result::unwrap).collect();
            let want: Vec<&str> = examples.iter().map(|e| e.line.as_str()).collect();
            assert_eq!(got, want);
            assert_eq!(decoder.pending_bytes(), 0);
        }
    }
}

#[test]
fn readme_session_directions() {
    use Dir::{Client as C, Server as S};
    let readme: Vec<Example> = spec_examples()
        .into_iter()
        .filter(|e| e.source == Source::Readme)
        .collect();
    let dirs: Vec<Dir> = readme.iter().map(|e| e.dir).collect();
    // The greeting, `guest sam`, OK, `join #general`, the JOIN event,
    // five SET snapshots, OK, `msg #general hello!`, the MSG event, OK.
    assert_eq!(
        dirs,
        [S, C, S, C, S, S, S, S, S, S, S, C, S, S],
        "{readme:#?}"
    );
    assert!(readme[0].line.starts_with("RISALA 1 "));
}

#[test]
fn readme_agrees_with_spec() {
    // Lines that appear in both documents are sent by the same side.
    let all = spec_examples();
    let mut shared = 0;
    for readme in all.iter().filter(|e| e.source == Source::Readme) {
        for spec in all
            .iter()
            .filter(|e| e.source == Source::Spec && e.line == readme.line)
        {
            assert_eq!(readme.dir, spec.dir, "{readme} vs {spec}");
            shared += 1;
        }
    }
    assert!(shared >= 5, "only {shared} README lines found in SPEC.md");
}

#[test]
fn specific_examples_are_present() {
    let all = spec_examples();
    let find = |needle: &str| {
        all.iter()
            .find(|e| e.line.contains(needle))
            .unwrap_or_else(|| panic!("no example contains {needle:?}"))
    };
    let auth = find("AUTH alice@example.org 0eS7OdclGDTKyqFl");
    assert_eq!(auth.dir, Dir::Client);
    assert_eq!(auth.source, Source::Spec);
    // A 3228-character ML-DSA-44 signature, ending in one `=` (4.5).
    assert_eq!(auth.line.len(), "AUTH alice@example.org ".len() + 3228);
    assert!(auth.line.ends_with("kXJzM="));

    let deleted = find(";deleted MSG #general");
    assert_eq!(deleted.dir, Dir::Server);
    assert!(deleted.line.ends_with("MSG #general"));

    assert_eq!(find("@ref=7 history").dir, Dir::Client);
    assert_eq!(find("upload 48213").dir, Dir::Client);
    assert_eq!(find("PRESENCE offline").dir, Dir::Server);
    assert_eq!(find("SET #general e2ee no").dir, Dir::Server);
    assert_eq!(find("init bob@example.net").dir, Dir::Client);
    assert_eq!(find("COMMIT bob@example.net 1").dir, Dir::Server);
    assert_eq!(find("enc bob@example.net 1").dir, Dir::Client);
    assert_eq!(find("frank-key=").dir, Dir::Server);

    // Prose and shell commands inside example blocks are skipped.
    for e in &all {
        assert!(!e.line.starts_with('('), "{e}");
        assert!(!e.line.starts_with('$'), "{e}");
        assert!(!e.line.starts_with("openssl"), "{e}");
    }
}

#[test]
fn spec_lines_point_at_the_example() {
    let spec_lines: Vec<&str> = common::SPEC.split('\n').collect();
    let readme_lines: Vec<&str> = common::README.split('\n').collect();
    for e in spec_examples() {
        let doc = match e.source {
            Source::Spec => &spec_lines,
            Source::Readme => &readme_lines,
        };
        let text = doc[e.spec_line - 1];
        assert!(text.ends_with(&e.line), "{e} vs {text:?}");
    }
}

// ---- the extractor itself ----

#[test]
fn code_blocks_basic() {
    let doc = "text\n```\nC: a\n```\n\n~~~~ abnf\nx\n```\ny\n~~~~\r\n  ```\nz\r\n  ```\n";
    let blocks = code_blocks(doc);
    let texts: Vec<Vec<(usize, &str)>> = blocks
        .iter()
        .map(|b| b.iter().map(|l| (l.number, l.text)).collect())
        .collect();
    assert_eq!(
        texts,
        [
            vec![(3, "C: a")],
            vec![(7, "x"), (8, "```"), (9, "y")],
            vec![(12, "z")]
        ]
    );
}

#[test]
fn code_blocks_ignore_indented_and_short_fences() {
    let doc = "    ```\n``\n";
    assert!(code_blocks(doc).is_empty());
}

#[test]
#[should_panic(expected = "unclosed code block opened at line 2")]
fn code_blocks_panic_when_unclosed() {
    code_blocks("a\n```\nC: x\n");
}

#[test]
fn shape_rule() {
    assert_eq!(direction_by_shape("guest sam"), Some(Dir::Client));
    assert_eq!(direction_by_shape("@reply=1 msg #a hi"), Some(Dir::Client));
    assert_eq!(direction_by_shape("OK uid=~sam"), Some(Dir::Server));
    assert_eq!(
        direction_by_shape("@seq=1;t=x;from=~sam JOIN #general"),
        Some(Dir::Server)
    );
    assert_eq!(
        direction_by_shape("RISALA 1 host nonce Welcome!"),
        Some(Dir::Server)
    );
    assert_eq!(direction_by_shape("Msg #a"), None);
    assert_eq!(direction_by_shape("$ openssl"), None);
    assert_eq!(direction_by_shape(""), None);
    assert_eq!(direction_by_shape("@ref=7"), None);
}

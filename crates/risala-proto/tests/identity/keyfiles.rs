//! Key files (4.4): the text rules, checking against the log, and the
//! three states.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::chain::{Chain, NoHandoffs, Rule};
use risala_proto::keyfile::{
    EntryError, KeyFile, KeyFileError, KeyFileState, LogLine, Missing, NoEntries, Outage, Response,
    read_key_file, well_known_url,
};
use risala_proto::record::{LogEntry, LogKey, Record};
use risala_proto::time::Timestamp;

use super::*;

const URL: &str = "https://chat.example.org/risala-log/1";

fn now() -> Timestamp {
    Timestamp::from_unix_millis(T0 + 86_400_000).unwrap()
}

/// A key file of the builder's chain, every record unlogged.
fn unlogged(b: &Builder) -> String {
    let chain = Chain::replay(&b.uid, &b.records).unwrap();
    KeyFile::from_chain(&chain, &|_| None).unwrap().to_text()
}

/// A log of entries: the builder's records at indices 10, 20, ...
struct Log(HashMap<u64, Vec<u8>>);

impl Log {
    fn of(records: &[Record]) -> Log {
        Log(records
            .iter()
            .enumerate()
            .map(|(i, r)| (10 * (i as u64 + 1), LogEntry::Record(r.clone()).encode()))
            .collect())
    }

    fn source(&self) -> impl FnMut(&LogLine, u64) -> Result<Vec<u8>, EntryError> + '_ {
        |_, index| self.0.get(&index).cloned().ok_or(EntryError::Missing)
    }
}

fn check(text: &str, entries: &mut dyn risala_proto::keyfile::EntrySource) -> KeyFileState {
    read_key_file(
        Response::Body {
            status: 200,
            body: text.as_bytes(),
        },
        &alice(),
        entries,
        &NoHandoffs,
        now(),
    )
}

fn keys(state: KeyFileState) -> Chain {
    match state {
        KeyFileState::Keys(chain) => *chain,
        other => panic!("not keys: {other:?}"),
    }
}

fn invalid_text(text: &str) -> KeyFileError {
    KeyFile::parse(text.as_bytes()).unwrap_err()
}

#[test]
fn url() {
    assert_eq!(
        well_known_url(&alice()),
        "https://example.org/.well-known/risala/alice"
    );
}

#[test]
fn unlogged_files_round_trip() {
    let mut b = Builder::new(&log1());
    b.device(1, "laptop");
    let text = unlogged(&b);
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("risala-keys/1"));
    assert_eq!(
        lines.next(),
        Some(format!("log {} {URL}", log1().vkey()).as_str())
    );
    assert!(lines.all(|l| l.starts_with("- ")));
    let file = KeyFile::parse(text.as_bytes()).unwrap();
    assert_eq!(file.to_text(), text);
    assert_eq!(file.len(), 2);
    assert_eq!(file.last_log().log, log1());
    assert!(file.lists(&b.records[1].hash()));
    let chain = keys(check(&text, &mut NoEntries));
    assert_eq!(chain.devices().len(), 1);

    // Comments and empty lines are ignored, anywhere after the header.
    let commented = text
        .replacen("\nlog ", "\n# alice\n\nlog ", 1)
        .replace("\n- ", "\n\n- ");
    assert!(KeyFile::parse(commented.as_bytes()).is_ok());
    keys(check(&commented, &mut NoEntries));
}

#[test]
fn logged_files_are_checked_against_the_log() {
    let mut b = Builder::new(&log1());
    b.device(1, "laptop").device(2, "phone");
    let chain = Chain::replay(&b.uid, &b.records).unwrap();
    // The first two are logged, the last not yet.
    let file = KeyFile::from_chain(&chain, &|i| (i < 2).then_some(10 * (i as u64 + 1))).unwrap();
    let text = file.to_text();
    assert!(text.contains(&format!(
        "\n10 {}\n20 {}\n- ",
        b.records[0].hash(),
        b.records[1].hash()
    )));
    let log = Log::of(&b.records);
    keys(check(&text, &mut log.source()));

    // An index whose entry is another record, or no entry at all.
    let swapped = text.replace(
        &format!("10 {}", b.records[0].hash()),
        &format!("20 {}", b.records[0].hash()),
    );
    let swapped = swapped.replace(
        &format!("\n20 {}", b.records[1].hash()),
        &format!("\n30 {}", b.records[1].hash()),
    );
    assert!(matches!(
        check(&swapped, &mut log.source()),
        KeyFileState::KeysMissing(Missing::NotInLog(0))
    ));
    let empty = Log(HashMap::new());
    assert!(matches!(
        check(&text, &mut empty.source()),
        KeyFileState::KeysMissing(Missing::NotInLog(0))
    ));
    // An entry that is a hand-off, or does not decode.
    let mut odd = Log::of(&b.records);
    odd.0.insert(
        20,
        LogEntry::Handoff(log_on("chat.example.org", 2, 201)).encode(),
    );
    assert!(matches!(
        check(&text, &mut odd.source()),
        KeyFileState::KeysMissing(Missing::NotInLog(1))
    ));
    odd.0.insert(20, vec![1, 1, 0]);
    assert!(matches!(
        check(&text, &mut odd.source()),
        KeyFileState::KeysMissing(Missing::NotInLog(1))
    ));
    // A failed fetch from the log is an outage.
    assert!(matches!(
        check(&text, &mut NoEntries),
        KeyFileState::Outage(Outage::LogFetch)
    ));
}

#[test]
fn three_states() {
    let mut b = Builder::new(&log1());
    b.device(1, "laptop");
    let text = unlogged(&b);
    let state = |response| read_key_file(response, &alice(), &mut NoEntries, &NoHandoffs, now());
    assert!(matches!(
        state(Response::Body {
            status: 200,
            body: text.as_bytes()
        }),
        KeyFileState::Keys(_)
    ));
    for status in [404, 410] {
        assert!(matches!(
            state(Response::Body { status, body: b"" }),
            KeyFileState::KeysMissing(Missing::Gone(s)) if s == status
        ));
    }
    for status in [301, 302, 304, 401, 403, 429, 500, 503, 201, 204] {
        assert!(
            matches!(
                state(Response::Body { status, body: text.as_bytes() }),
                KeyFileState::Outage(Outage::Status(s)) if s == status
            ),
            "{status}"
        );
    }
    assert!(matches!(
        state(Response::Failed),
        KeyFileState::Outage(Outage::NoResponse)
    ));
    assert!(matches!(
        state(Response::TooLarge),
        KeyFileState::KeysMissing(Missing::TooLarge)
    ));
    assert!(matches!(
        state(Response::Body {
            status: 200,
            body: b"risala-keys/2\n"
        }),
        KeyFileState::KeysMissing(Missing::NotKeyFile)
    ));
    assert!(matches!(
        state(Response::Body {
            status: 200,
            body: b"mldsa44 AAAA laptop\n"
        }),
        KeyFileState::KeysMissing(Missing::NotKeyFile)
    ));
    let big = vec![b'#'; 2 * 1024 * 1024 + 1];
    assert!(matches!(
        state(Response::Body {
            status: 200,
            body: &big
        }),
        KeyFileState::KeysMissing(Missing::TooLarge)
    ));
    // Another identity's file is not valid for this one.
    let bob = Builder::with_keys(
        "bob@example.org".parse().unwrap(),
        key(103),
        key(153),
        &log1(),
    );
    assert!(matches!(
        state(Response::Body { status: 200, body: unlogged(&bob).as_bytes() }),
        KeyFileState::KeysMissing(Missing::Chain(e)) if e.rule == Rule::Uid
    ));
}

#[test]
fn records_from_the_future_are_an_outage() {
    let mut b = Builder::new(&log1());
    b.time = now().unix_millis() + 10 * 60 * 1000 - 60_000;
    b.device(1, "exactly ten minutes ahead");
    keys(check(&unlogged(&b), &mut NoEntries));
    b.time += 1;
    b.device(2, "one millisecond more");
    assert!(matches!(
        check(&unlogged(&b), &mut NoEntries),
        KeyFileState::Outage(Outage::Ahead(2))
    ));
    // Even beyond the year 9999.
    let mut far = Builder::new(&log1());
    far.time = u64::MAX - 120_000;
    far.device(1, "far");
    assert!(matches!(
        check(&unlogged(&far), &mut NoEntries),
        KeyFileState::Outage(Outage::Ahead(1))
    ));
}

#[test]
fn trailing_log_lines() {
    let other = log_on("keys.example.net", 1, 201);
    let mut b = Builder::new(&log1());
    b.device(1, "x").log(&other);
    let text = unlogged(&b);
    assert!(text.ends_with(&format!(
        "log {} https://keys.example.net/risala-log/1\n",
        other.vkey()
    )));
    let chain = keys(check(&text, &mut NoEntries));
    assert_eq!(chain.log(), &other);
    // Without the trailing line, still valid.
    let cut = text[..text.rfind("log ").unwrap()].to_owned();
    keys(check(&cut, &mut NoEntries));
    // A trailing log line that names another log than the log record.
    let wrong = text.replace(
        &format!("log {} https://keys.example.net", other.vkey()),
        &format!(
            "log {} https://keys.example.net",
            log_on("keys.example.net", 1, 202).vkey()
        ),
    );
    assert!(matches!(
        check(&wrong, &mut NoEntries),
        KeyFileState::KeysMissing(Missing::TrailingLog)
    ));
    // A trailing log line without a log record before it.
    let mut c = Builder::new(&log1());
    c.device(1, "x");
    let text = format!(
        "{}log {} https://keys.example.net/risala-log/1\n",
        unlogged(&c),
        other.vkey()
    );
    assert!(matches!(
        check(&text, &mut NoEntries),
        KeyFileState::KeysMissing(Missing::TrailingLog)
    ));
    // Records listed under the old log after the log record.
    let mut d = Builder::new(&log1());
    d.device(1, "x").log(&other).device(2, "y");
    let text = unlogged(&d);
    keys(check(&text, &mut NoEntries));
    let lines: Vec<&str> = text.lines().collect();
    let mut moved: Vec<&str> = lines.clone();
    moved.remove(5); // the second log line
    let moved = moved.join("\n") + "\n";
    assert!(matches!(
        check(&moved, &mut NoEntries),
        KeyFileState::KeysMissing(Missing::Chain(e)) if e.rule == Rule::WrongLog
    ));
}

#[test]
fn text_rules() {
    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let text = unlogged(&b);
    assert!(KeyFile::parse(text.as_bytes()).is_ok());
    let log_line = format!("log {} {URL}", log1().vkey());
    let invalid = |t: &str| matches!(invalid_text(t), KeyFileError::Invalid { .. });

    // Every line ends with LF, the last one included.
    assert!(invalid(&text[..text.len() - 1]));
    // No CR, TAB, leading or trailing space, or two spaces in a row.
    assert!(invalid(&text.replacen(
        &format!("{URL}\n"),
        &format!("{URL}\r\n"),
        1
    )));
    assert_eq!(
        invalid_text(&text.replacen('\n', "\r\n", 1)),
        KeyFileError::NotKeyFile
    );
    assert!(invalid(&text.replacen("\n- ", "\n-\t", 1)));
    assert!(invalid(&text.replacen("\n- ", "\n - ", 1)));
    assert!(invalid(&text.replacen("\n- ", "\n-  ", 1)));
    assert!(invalid(&format!("{text}# trailing \n")));
    assert!(invalid(&format!("{text} \n")));
    // The first line is exactly risala-keys/1.
    for first in [
        "risala-keys/2",
        "Risala-keys/1",
        "risala-keys/1 ",
        "\u{feff}risala-keys/1",
        "",
    ] {
        let t = text.replacen("risala-keys/1", first, 1);
        assert_eq!(invalid_text(&t), KeyFileError::NotKeyFile, "{first:?}");
    }
    assert_eq!(invalid_text(""), KeyFileError::NotKeyFile);
    assert!(invalid("risala-keys/1"));
    // The first line after the header is a log line.
    let records: String = text.lines().skip(2).map(|l| format!("{l}\n")).collect();
    assert!(invalid(&format!("risala-keys/1\n{records}{log_line}\n")));
    // No log line follows another.
    assert!(invalid(&text.replacen(
        &log_line,
        &format!("{log_line}\n{log_line}"),
        1
    )));
    let other = format!("log {} {URL}", log_on("chat.example.org", 2, 201).vkey());
    assert!(invalid(&text.replacen(
        &log_line,
        &format!("{log_line}\n# between\n{other}"),
        1
    )));
    // A file with no records.
    assert!(invalid(&format!("risala-keys/1\n{log_line}\n")));
    // Unknown lines.
    for line in ["mldsa44 AAAA", "+ AAAA", "1", "- ", "log x y", "1 2 3"] {
        assert!(invalid(&format!("{text}{line}\n")), "{line}");
    }

    // Bad log lines.
    let vkey = log1().vkey();
    // The URL is always `https://` and the log's origin (4.4, 4.5).
    for url in [
        "http://chat.example.org/l",
        "https://chat.example.org/",
        "https://",
        "chat.example.org",
        "http://chat.example.org/risala-log/1",
        "https://chat.example.org/risala-log/1/",
        "https://chat.example.org/risala-log/2",
        "https://Chat.example.org/risala-log/1",
        "https://chat.example.org:443/risala-log/1",
        "https://keys.example.net/risala-log/1",
        "https://chat.example.org/logs/risala-log/1",
    ] {
        let t = text.replacen(URL, url, 1);
        assert!(invalid(&t), "{url}");
    }
    let bad_vkey = vkey.replacen("+", "+0", 1);
    assert!(invalid(&text.replacen(&vkey, &bad_vkey, 1)));
    assert!(invalid(&text.replacen(&vkey, &vkey[..vkey.len() - 4], 1)));

    // Strict base64 in - lines.
    let record_b64 = BASE64.encode(b.records[1].encoded());
    let no_pad = record_b64.trim_end_matches('=').to_owned();
    if no_pad != record_b64 {
        assert!(invalid(&text.replacen(&record_b64, &no_pad, 1)));
    }
    let mut split = record_b64.clone();
    split.insert(100, '\n');
    assert!(KeyFile::parse(text.replacen(&record_b64, &split, 1).as_bytes()).is_err());
    split.insert(102, '\n');
    assert!(KeyFile::parse(text.replacen(&record_b64, &split, 1).as_bytes()).is_err());
    // Non-zero padding bits: the last character before = changes.
    let bytes = b.records[1].encoded();
    let enc = BASE64.encode(bytes);
    if enc.ends_with('=') {
        let pos = enc.trim_end_matches('=').len() - 1;
        let c = enc.as_bytes()[pos];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let v = alphabet.iter().position(|&a| a == c).unwrap();
        let mut sloppy = enc.clone().into_bytes();
        sloppy[pos] = alphabet[v | 1];
        let sloppy = String::from_utf8(sloppy).unwrap();
        if sloppy != enc {
            assert!(invalid(&text.replacen(&enc, &sloppy, 1)));
        }
    }
    // A record that does not decode.
    let t = text.replacen(&record_b64, "AQID", 1);
    assert!(matches!(invalid_text(&t), KeyFileError::Record { .. }));
}

#[test]
fn index_lines() {
    let h0 = Builder::new(&log1()).records[0].hash();
    let log_line = format!("log {} {URL}", log1().vkey());
    let file = |body: &str| format!("risala-keys/1\n{log_line}\n{body}");
    assert!(KeyFile::parse(file(&format!("0 {h0}\n7 {h0}\n")).as_bytes()).is_ok());
    let invalid = |t: String| {
        matches!(
            KeyFile::parse(t.as_bytes()),
            Err(KeyFileError::Invalid { .. })
        )
    };
    // Indices increase within each log.
    assert!(invalid(file(&format!("7 {h0}\n7 {h0}\n"))));
    assert!(invalid(file(&format!("7 {h0}\n3 {h0}\n"))));
    // Numbers without leading zeros or signs; hashes as blob-refs in
    // lower case.
    assert!(invalid(file(&format!("07 {h0}\n"))));
    assert!(invalid(file(&format!("+7 {h0}\n"))));
    assert!(invalid(file(&format!("9223372036854775808 {h0}\n"))));
    let upper = h0.to_string().to_uppercase();
    assert!(invalid(file(&format!("7 {upper}\n"))));
    assert!(invalid(file(&format!("7 {}\n", &h0.to_string()[7..]))));
    // No index line after an unlogged record.
    let b = Builder::new(&log1());
    let rec = BASE64.encode(b.records[0].encoded());
    assert!(invalid(file(&format!("- {rec}\n7 {h0}\n"))));
    assert!(KeyFile::parse(file(&format!("7 {h0}\n- {rec}\n")).as_bytes()).is_ok());
    // Indices increase per log, across log lines.
    let other: LogKey = log_on("keys.example.net", 1, 201);
    let other_line = format!("log {} https://keys.example.net/risala-log/1", other.vkey());
    let t = format!("risala-keys/1\n{log_line}\n7 {h0}\n{other_line}\n3 {h0}\n");
    assert!(KeyFile::parse(t.as_bytes()).is_ok());
    let t =
        format!("risala-keys/1\n{log_line}\n7 {h0}\n{other_line}\n3 {h0}\n{log_line}\n5 {h0}\n");
    assert!(invalid(t));
}

#[test]
fn record_limit() {
    let h0 = Builder::new(&log1()).records[0].hash();
    let log_line = format!("log {} {URL}", log1().vkey());
    let lines = |n: u64| -> String {
        let mut t = format!("risala-keys/1\n{log_line}\n");
        for i in 0..n {
            t.push_str(&format!("{i} {h0}\n"));
        }
        t
    };
    assert_eq!(KeyFile::parse(lines(4096).as_bytes()).unwrap().len(), 4096);
    assert!(matches!(
        KeyFile::parse(lines(4097).as_bytes()),
        Err(KeyFileError::Invalid { line: 4099, .. })
    ));
    // The size limit is checked first.
    let mut big = lines(1);
    big.push_str(&"#".repeat(2 * 1024 * 1024));
    big.push('\n');
    assert_eq!(
        KeyFile::parse(big.as_bytes()).unwrap_err(),
        KeyFileError::TooLarge
    );
}

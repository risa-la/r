use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::*;
use crate::names::Domain;

fn b64(n: usize, byte: u8) -> String {
    BASE64.encode(vec![byte; n])
}

fn id(byte: u8) -> String {
    b64(MESSAGE_ID_LEN, byte)
}

fn hash(c: char) -> String {
    format!("sha384:{}", c.to_string().repeat(96))
}

const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";

/// Parses `line` strictly and checks that it writes back unchanged.
fn round_trip(line: &str) -> ContentLine {
    let parsed = ContentLine::parse(line).unwrap_or_else(|e| panic!("{line:?}: {e}"));
    assert_eq!(parsed.to_line().as_deref(), Ok(line), "{line:?}");
    let content = Content::parse(format!("{line}\n").as_bytes()).unwrap();
    assert_eq!(content.lines(), std::slice::from_ref(&parsed));
    parsed
}

fn err(line: &str) -> ParseError {
    match ContentLine::parse(line) {
        Ok(parsed) => panic!("{line:?} parsed as {parsed:?}"),
        Err(e) => e,
    }
}

fn is_syntax(e: ParseError) -> bool {
    matches!(e, ParseError::BadSyntax(_))
}

// ---- each verb ----

#[test]
fn every_verb_round_trips() {
    let lines = [
        "TEXT hello".to_owned(),
        format!("@reply={} TEXT see you at 12", id(1)),
        format!("@edit={} TEXT fixed", id(2)),
        format!("@react={} TEXT 👍", id(3)),
        format!(
            "@file=https://files.example.org/abc;file-key={};file-type=image/png;file-size=1234;file-hash={} TEXT cat.png",
            b64(32, 4),
            b64(48, 5)
        ),
        format!("DELETE {}", id(6)),
        "TYPING".to_owned(),
        format!("@box={BOX};target={} REPORT", id(7)),
        format!(
            "@box={BOX};target={};context={},{} REPORT spam",
            id(7),
            id(8),
            id(9)
        ),
        format!("CHALLENGE 3 {}", b64(CHALLENGE_LEN, 10)),
        format!("ANSWER 0 {}", b64(CONFIRM_MAC_LEN, 11)),
        format!(
            "ATTEST 20401 {} {} {} {}",
            b64(1312, 12),
            b64(2420, 13),
            b64(2420, 14),
            b64(16, 15)
        ),
        format!("REVEAL 20401 {}", b64(SEED_LEN, 15)),
        format!("READ {BOX} 9120 {}", b64(EPOCH_CHECK_LEN, 19)),
        "RESYNC 9121".to_owned(),
        format!("RESYNC {BOX} 9121"),
        format!("LEAVE {BOX}"),
        format!("REFETCH {}", hash('a')),
        "BLOCK spam@example.net".to_owned(),
        "UNBLOCK *@example.net".to_owned(),
        format!("RECORD {}", hash('a')),
        format!("ALERT {}", hash('b')),
        "RECORDS".to_owned(),
        format!("RECORDS {} {}", hash('c'), hash('d')),
        "RECORDS -".to_owned(),
        format!("SIGNINGKEY {}", b64(SEED_LEN, 16)),
        format!("BACKUPKEY 2 {}", b64(BACKUP_KEY_LEN, 17)),
        format!("WANT {BOX} 0 -"),
        format!("WANT {BOX} 9120 9200"),
        format!("TRANSFER {}", b64(TRANSFER_REF_LEN, 18)),
        "SERVERS chat.example.org other.example.net".to_owned(),
        "SERVERS chat.example.org:7000 localhost:7473".to_owned(),
        format!(
            "PIN bob@example.net {} chat.example.net/risala-log/1 {} yes",
            hash('e'),
            hash('f')
        ),
        format!(
            "PIN bob@example.net {} chat.example.net/risala-log/12 {} no",
            hash('e'),
            hash('f')
        ),
    ];
    let mut seen = std::collections::HashSet::new();
    for line in &lines {
        let parsed = round_trip(line);
        seen.insert(parsed.verb().unwrap());
    }
    // Every verb of 12.9's table has an example above.
    for verb in VERBS {
        assert!(seen.contains(verb), "{verb}");
    }
}

#[test]
fn values_are_read() {
    let ContentLine::Text(text) = round_trip(&format!(
        "@reply={};file=https://Files.Example.org:8443/x?y=1;file-key={};file-hash={} TEXT hi @bob@example.org",
        id(1),
        b64(32, 2),
        b64(48, 3)
    )) else {
        panic!()
    };
    assert_eq!(text.target.unwrap().id().as_bytes(), &[1; 16]);
    let file = text.file.unwrap();
    assert_eq!(file.url.origin(), "https://files.example.org:8443");
    assert_eq!(file.key.as_bytes(), &[2; 32]);
    assert_eq!(file.media_type, None);
    assert_eq!(file.size, None);
    assert_eq!(text.text, "hi @bob@example.org");
    assert_eq!(
        Text::new("hi @bob@example.org").mentions(),
        ["bob@example.org".parse::<crate::names::Uid>().unwrap()]
    );

    let ContentLine::Want { after, before, .. } = round_trip(&format!("WANT {BOX} 5 7")) else {
        panic!()
    };
    assert_eq!((after, before.map(Seq::get)), (5, Some(7)));

    let ContentLine::Pin(pin) = round_trip(&format!(
        "PIN bob@example.net {} chat.example.net/risala-log/3 {} yes",
        hash('e'),
        hash('f')
    )) else {
        panic!()
    };
    assert_eq!(pin.origin.host().as_str(), "chat.example.net");
    assert_eq!(pin.origin.number(), 3);
    assert!(pin.verified);

    let ContentLine::Transfer(transfer) = round_trip(&format!("TRANSFER {}", {
        let mut b = vec![1u8];
        b.extend([7; 48]);
        b.extend([9; 32]);
        BASE64.encode(b)
    })) else {
        panic!()
    };
    assert_eq!(transfer.version(), 1);
    assert_eq!(transfer.blob_hash(), [7; 48]);
    assert_eq!(*transfer.key(), [9; 32]);
}

// ---- TEXT (5.3, 12.9) ----

#[test]
fn text_must_not_be_blank() {
    for line in ["TEXT", "TEXT ", "TEXT  \t", "TEXT \\n \\n"] {
        assert!(is_syntax(err(line)), "{line:?}");
    }
    round_trip("TEXT \\");
    // Leading spaces belong to the text (3.3).
    let ContentLine::Text(text) = round_trip("TEXT  indented") else {
        panic!()
    };
    assert_eq!(text.text, " indented");
}

#[test]
fn text_limits() {
    round_trip(&format!("TEXT {}", "a".repeat(MAX_TEXT_LEN)));
    assert_eq!(
        err(&format!("TEXT {}", "a".repeat(MAX_TEXT_LEN + 1))),
        ParseError::TooLong
    );
    // The limit is on the escaped form (3.4).
    assert_eq!(
        err(&format!("TEXT {}", "\\na".repeat(MAX_TEXT_LEN / 3 + 1))),
        ParseError::TooLong
    );
    let react = |text: &str| format!("@react={} TEXT {text}", id(1));
    round_trip(&react(&"a".repeat(MAX_REACTION_LEN)));
    assert_eq!(
        err(&react(&"a".repeat(MAX_REACTION_LEN + 1))),
        ParseError::TooLong
    );
    // A reply may be as long as any text.
    round_trip(&format!(
        "@reply={} TEXT {}",
        id(1),
        "a".repeat(MAX_TEXT_LEN)
    ));
}

#[test]
fn text_has_at_most_one_target() {
    let line = format!("@reply={};edit={} TEXT hi", id(1), id(2));
    assert!(is_syntax(err(&line)));
    assert!(is_syntax(err(&format!(
        "@react={};edit={} TEXT x",
        id(1),
        id(2)
    ))));
    // A target with a malformed id, or with no value.
    assert!(is_syntax(err("@reply=abc TEXT hi")));
    assert!(is_syntax(err("@reply TEXT hi")));
}

#[test]
fn unknown_tags_are_ignored() {
    let parsed = ContentLine::parse(&format!("@x-foo=1;reply={};zzz TEXT hi", id(1))).unwrap();
    assert_eq!(
        parsed.to_line().unwrap(),
        format!("@reply={} TEXT hi", id(1))
    );
    // Tags on lines that take none are ignored too.
    assert_eq!(
        ContentLine::parse("@x=1 TYPING").unwrap(),
        ContentLine::Typing
    );
}

#[test]
fn verbs_are_case_insensitive() {
    let parsed = ContentLine::parse("text hi").unwrap();
    assert_eq!(parsed.to_line().unwrap(), "TEXT hi");
    assert_eq!(ContentLine::parse("Typing").unwrap(), ContentLine::Typing);
}

fn file_tags(key: &str, hash: &str) -> String {
    format!("file=https://f.example.org/a;file-key={key};file-hash={hash}")
}

fn file_of(line: &str) -> Option<FileRef> {
    match ContentLine::parse(line).unwrap() {
        ContentLine::Text(text) => text.file,
        other => panic!("{other:?}"),
    }
}

#[test]
fn file_needs_url_key_and_hash() {
    let key = b64(32, 1);
    let hash = b64(48, 2);
    assert!(file_of(&format!("@{} TEXT f", file_tags(&key, &hash))).is_some());
    // Without both file-key and file-hash, or with the wrong lengths, the
    // message has no file, but still counts (12.9).
    for tags in [
        format!("file=https://f.example.org/a;file-key={key}"),
        format!("file=https://f.example.org/a;file-hash={hash}"),
        file_tags(&b64(31, 1), &hash),
        file_tags(&key, &b64(32, 2)),
        format!("file-key={key};file-hash={hash}"),
        format!("file=http://f.example.org/a;file-key={key};file-hash={hash}"),
        format!("file=https://;file-key={key};file-hash={hash}"),
        format!("file=https://u@f.example.org/a;file-key={key};file-hash={hash}"),
        format!(
            "file=https://f.example.org/{};file-key={key};file-hash={hash}",
            "a".repeat(MAX_FILE_URL_LEN)
        ),
    ] {
        let line = format!("@{tags} TEXT f");
        assert_eq!(file_of(&line), None, "{line}");
        let parsed = ContentLine::parse(&line).unwrap();
        assert_eq!(parsed.to_line().unwrap(), "TEXT f");
    }
}

#[test]
fn file_hints_are_optional() {
    let tags = file_tags(&b64(32, 1), &b64(48, 2));
    for (extra, media_type, size) in [
        (
            ";file-type=Image/PNG;file-size=10",
            Some("image/png"),
            Some(10),
        ),
        (";file-type=image;file-size=010", None, None),
        (
            ";file-type=image/png;charset;file-size=-1",
            Some("image/png"),
            None,
        ),
        (";file-type=/png;file-size", None, None),
    ] {
        let file = file_of(&format!("@{tags}{extra} TEXT f")).unwrap();
        assert_eq!(file.media_type.as_ref().map(MediaType::as_str), media_type);
        assert_eq!(file.size, size);
    }
    assert_eq!(
        "a/".parse::<MediaType>().map(|_| ()),
        Err(bad("a media type is type/subtype"))
    );
    assert_eq!(
        format!("a/{}", "b".repeat(128)).parse::<MediaType>(),
        Err(ParseError::TooLong)
    );
}

#[test]
fn only_messages_and_replies_share_files() {
    let tags = file_tags(&b64(32, 1), &b64(48, 2));
    assert!(file_of(&format!("@reply={};{tags} TEXT f", id(1))).is_some());
    assert!(file_of(&format!("@edit={};{tags} TEXT f", id(1))).is_none());
    assert!(file_of(&format!("@react={};{tags} TEXT f", id(1))).is_none());

    // A hand-built edit with a file cannot be written as it is.
    let ContentLine::Text(mut text) = ContentLine::parse(&format!("@{tags} TEXT f")).unwrap()
    else {
        panic!()
    };
    text.target = Some(Target::Edit(MessageId::from_bytes([1; 16])));
    assert!(is_syntax(ContentLine::Text(text).to_line().unwrap_err()));
}

#[test]
fn file_tags_are_written_in_order() {
    let line = format!(
        "@file-hash={};file-size=3;file-type=text/plain;file-key={};file=https://f.example.org/a TEXT f",
        b64(48, 2),
        b64(32, 1)
    );
    let parsed = ContentLine::parse(&line).unwrap();
    assert_eq!(
        parsed.to_line().unwrap(),
        format!(
            "@file=https://f.example.org/a;file-key={};file-type=text/plain;file-size=3;file-hash={} TEXT f",
            b64(32, 1),
            b64(48, 2)
        )
    );
}

// ---- REPORT (5.8) ----

#[test]
fn report_rules() {
    let target = id(1);
    assert!(is_syntax(err(&format!("@target={target} REPORT"))));
    assert!(is_syntax(err(&format!("@box={BOX} REPORT"))));
    assert!(is_syntax(err(&format!("@box=nope;target={target} REPORT"))));
    assert!(is_syntax(err(&format!(
        "@box={BOX};target={target};context= REPORT"
    ))));
    assert!(is_syntax(err(&format!(
        "@box={BOX};target={target};context={},,{} REPORT",
        id(2),
        id(3)
    ))));
    let context = |n| (0..n).map(id).collect::<Vec<_>>().join(",");
    round_trip(&format!(
        "@box={BOX};target={target};context={} REPORT",
        context(MAX_REPORT_CONTEXT as u8)
    ));
    assert_eq!(
        err(&format!(
            "@box={BOX};target={target};context={} REPORT",
            context(MAX_REPORT_CONTEXT as u8 + 1)
        )),
        ParseError::TooLong
    );
    round_trip(&format!(
        "@box={BOX};target={target} REPORT {}",
        "r".repeat(MAX_REASON_LEN)
    ));
    assert_eq!(
        err(&format!(
            "@box={BOX};target={target} REPORT {}",
            "r".repeat(MAX_REASON_LEN + 1)
        )),
        ParseError::TooLong
    );
    // The box folds (3.5).
    let parsed = ContentLine::parse(&format!(
        "@box={};target={target} REPORT",
        BOX.to_uppercase()
    ))
    .unwrap();
    assert_eq!(
        parsed.to_line().unwrap(),
        format!("@box={BOX};target={target} REPORT")
    );
}

// ---- the other lines ----

#[test]
fn arity() {
    for line in [
        "TYPING now".to_owned(),
        "DELETE".to_owned(),
        format!("DELETE {} {}", id(1), id(2)),
        format!("CHALLENGE {}", b64(CHALLENGE_LEN, 1)),
        format!("ANSWER 1 {} x", b64(48, 1)),
        format!("READ {BOX}"),
        format!("READ {BOX} 1"),
        format!("READ {BOX} 1 {} x", b64(EPOCH_CHECK_LEN, 1)),
        "RESYNC".to_owned(),
        format!("RESYNC {BOX} 1 2"),
        "LEAVE".to_owned(),
        format!("LEAVE {BOX} 1"),
        "BLOCK".to_owned(),
        "RECORD".to_owned(),
        "REFETCH".to_owned(),
        format!("REFETCH {} {}", hash('a'), hash('b')),
        format!("BACKUPKEY {}", b64(32, 1)),
        format!("WANT {BOX} 1"),
        "SERVERS".to_owned(),
        format!(
            "PIN bob@example.net {} chat.example.net/risala-log/1 {}",
            hash('e'),
            hash('f')
        ),
    ] {
        assert!(is_syntax(err(&line)), "{line}");
    }
}

#[test]
fn value_rules() {
    for line in [
        format!("CHALLENGE 4294967296 {}", b64(CHALLENGE_LEN, 1)),
        format!("CHALLENGE 01 {}", b64(CHALLENGE_LEN, 1)),
        format!("CHALLENGE 1 {}", b64(CHALLENGE_LEN - 1, 1)),
        format!("ANSWER 1 {}", b64(32, 1)),
        format!(
            "ATTEST 1 {} {} {} {}",
            b64(1311, 1),
            b64(2420, 1),
            b64(2420, 1),
            b64(16, 1)
        ),
        // The pseudonym is 16 bytes, and required (12.10).
        format!(
            "ATTEST 1 {} {} {} {}",
            b64(1312, 1),
            b64(2420, 1),
            b64(2420, 1),
            b64(15, 1)
        ),
        format!(
            "ATTEST 1 {} {} {}",
            b64(1312, 1),
            b64(2420, 1),
            b64(2420, 1)
        ),
        format!("REVEAL -1 {}", b64(32, 1)),
        format!("READ {BOX} 0 {}", b64(EPOCH_CHECK_LEN, 1)),
        // The check is 8 bytes (12.9).
        format!("READ {BOX} 1 {}", b64(EPOCH_CHECK_LEN + 1, 1)),
        format!("READ {BOX} 1 {}", b64(EPOCH_CHECK_LEN - 1, 1)),
        "RESYNC 0".to_owned(),
        "RESYNC x".to_owned(),
        format!("RESYNC {BOX} 0"),
        "RESYNC general 1".to_owned(),
        "LEAVE general".to_owned(),
        "BLOCK ~sam".to_owned(),
        format!("SIGNINGKEY {}", b64(33, 1)),
        format!("TRANSFER {}", b64(80, 1)),
        format!("WANT {BOX} 5 6"),
        format!("WANT {BOX} 5 5"),
        format!("WANT {BOX} 5 0"),
        "SERVERS 127.0.0.1".to_owned(),
        // One written form (2.1): lower case, no port 7472, no repeats
        // (12.9).
        "SERVERS Chat.example.org".to_owned(),
        "SERVERS chat.example.org:7472".to_owned(),
        "SERVERS chat.example.org chat.example.org".to_owned(),
        "SERVERS [2001:db8::1]:7000".to_owned(),
        // `-` stands alone (12.9).
        format!("RECORDS - {}", hash('c')),
        format!("RECORDS {} -", hash('c')),
        format!(
            "PIN ~sam {} chat.example.net/risala-log/1 {} yes",
            hash('e'),
            hash('f')
        ),
        format!(
            "PIN bob@example.net {} Chat.example.net/risala-log/1 {} yes",
            hash('e'),
            hash('f')
        ),
        format!(
            "PIN bob@example.net {} chat.example.net/risala-log/0 {} yes",
            hash('e'),
            hash('f')
        ),
        format!(
            "PIN bob@example.net {} chat.example.net/log/1 {} yes",
            hash('e'),
            hash('f')
        ),
        format!(
            "PIN bob@example.net {} chat.example.net/risala-log/1 {} maybe",
            hash('e'),
            hash('f')
        ),
    ] {
        assert!(is_syntax(err(&line)), "{line}");
    }
    round_trip(&format!("WANT {BOX} 5 7"));
    round_trip(&format!("CHALLENGE 4294967295 {}", b64(CHALLENGE_LEN, 1)));
}

#[test]
fn log_origins() {
    let origin: LogOrigin = "chat.example.org/risala-log/1".parse().unwrap();
    assert_eq!(origin.to_string(), "chat.example.org/risala-log/1");
    assert_eq!(
        LogOrigin::new(origin.host().clone(), 1),
        Some(origin.clone())
    );
    assert_eq!(LogOrigin::new(origin.host().clone(), 0), None);
    // A host of 241 characters leaves room for two digits in 255 bytes.
    let a63 = "a".repeat(63);
    let long = format!("{a63}.{a63}.{a63}.{}.org", "a".repeat(45));
    assert_eq!(long.len(), 241);
    let host: Domain = long.parse().unwrap();
    assert!(LogOrigin::new(host.clone(), 10).is_some());
    assert_eq!(LogOrigin::new(host, 100), None);
    assert!(
        format!("{long}{ORIGIN_PATH}10")
            .parse::<LogOrigin>()
            .is_ok()
    );
    assert_eq!(
        format!("{long}{ORIGIN_PATH}100").parse::<LogOrigin>(),
        Err(ParseError::TooLong)
    );
}

#[test]
fn names_fold() {
    let parsed = ContentLine::parse(&format!("RECORDS {}", hash('A'))).unwrap();
    assert_eq!(parsed.to_line().unwrap(), format!("RECORDS {}", hash('a')));
    // Server addresses are compared byte for byte, so they do not fold
    // (2.1).
    assert!(ContentLine::parse("SERVERS Chat.Example.org").is_err());
}

#[test]
fn unknown_verbs() {
    assert_eq!(
        err("FROBNICATE x"),
        ParseError::UnknownVerb("FROBNICATE".into())
    );
    // Commands of the connection are not content lines.
    assert_eq!(err("POST x y z"), ParseError::UnknownVerb("POST".into()));
}

// ---- Content ----

#[test]
fn content_keeps_its_bytes() {
    let raw = format!(
        "text  hi\nFROB x\n@reply={} TEXT \\n\nCHALLENGE 1 short\n\n  x\nTYPING\n",
        id(1)
    );
    let content: Content = raw.parse().unwrap();
    assert_eq!(content.as_str(), raw);
    assert_eq!(content.to_string(), raw);
    let verbs: Vec<_> = content.lines().iter().map(ContentLine::verb).collect();
    assert_eq!(
        verbs,
        [Some("TEXT"), None, None, None, None, None, Some("TYPING")]
    );
    let ContentLine::Ignored(frob) = &content.lines()[1] else {
        panic!()
    };
    assert_eq!(frob.as_str(), "FROB x");
    assert_eq!(frob.verb().as_deref(), Some("FROB"));
    assert_eq!(frob.reason(), &ParseError::UnknownVerb("FROB".into()));
    let ContentLine::Ignored(blank) = &content.lines()[4] else {
        panic!()
    };
    assert_eq!(blank.as_str(), "");
    assert_eq!(blank.verb(), None);

    // Writing the lines again gives canonical known lines, and ignored
    // lines exactly as they were.
    let again = Content::new(content.lines().to_vec()).unwrap();
    assert_eq!(
        again.as_str(),
        format!(
            "TEXT  hi\nFROB x\n@reply={} TEXT \\n\nCHALLENGE 1 short\n\n  x\nTYPING\n",
            id(1)
        )
    );
    assert_eq!(again.lines(), content.lines());
    assert!(content.shows_something());
    assert!(
        !Content::single(ContentLine::Typing)
            .unwrap()
            .shows_something()
    );
}

#[test]
fn content_errors() {
    assert!(is_syntax(Content::parse(b"").unwrap_err()));
    assert!(is_syntax(Content::parse(b"TEXT hi").unwrap_err()));
    assert!(is_syntax(Content::parse(b"TEXT hi\nTYPING").unwrap_err()));
    assert_eq!(Content::parse(b"TEXT hi\r\n"), Err(ParseError::ControlChar));
    assert_eq!(
        Content::parse(b"TEXT a\x01b\n"),
        Err(ParseError::ControlChar)
    );
    assert_eq!(
        Content::parse("TEXT a\u{85}b\n".as_bytes()),
        Err(ParseError::ControlChar)
    );
    assert_eq!(Content::parse(b"TEXT \xff\n"), Err(ParseError::InvalidUtf8));
    // TAB is allowed in text (2.3).
    Content::parse(b"TEXT a\tb\n").unwrap();
    assert!(is_syntax(Content::new(vec![]).unwrap_err()));
}

#[test]
fn content_size_limit() {
    // Lines have no length limit of their own (12.9), but the content as
    // a whole does.
    let line = format!("@box={BOX};target={} REPORT {}\n", id(1), "r".repeat(400));
    let mut raw = line.repeat(MAX_CONTENT_LEN / line.len());
    raw.push_str(&"x".repeat(MAX_CONTENT_LEN - raw.len() - 1));
    raw.push('\n');
    assert_eq!(raw.len(), MAX_CONTENT_LEN);
    let content = Content::parse(raw.as_bytes()).unwrap();
    raw.insert(0, 'x');
    assert_eq!(Content::parse(raw.as_bytes()), Err(ParseError::TooLong));

    let mut lines = content.lines().to_vec();
    lines.push(ContentLine::Typing);
    assert_eq!(Content::new(lines), Err(ParseError::TooLong));
}

/// A content of many short lines would take about a hundred times its
/// size in memory once parsed, so it has at most MAX_CONTENT_LINES lines.
#[test]
fn content_line_limit() {
    let raw = "\n".repeat(MAX_CONTENT_LINES);
    assert_eq!(
        Content::parse(raw.as_bytes()).unwrap().lines().len(),
        MAX_CONTENT_LINES
    );
    let raw = "\n".repeat(MAX_CONTENT_LINES + 1);
    assert_eq!(Content::parse(raw.as_bytes()), Err(ParseError::TooLong));
    let raw = "TYPING\n".repeat(MAX_CONTENT_LINES + 1);
    assert_eq!(Content::parse(raw.as_bytes()), Err(ParseError::TooLong));
    assert_eq!(
        Content::new(vec![ContentLine::Typing; MAX_CONTENT_LINES + 1]),
        Err(ParseError::TooLong)
    );
    assert!(Content::new(vec![ContentLine::Typing; MAX_CONTENT_LINES]).is_ok());
}

#[test]
fn debug_hides_secrets() {
    let seed = b64(SEED_LEN, 0x5a);
    let key = b64(32, 0x6b);
    let content: Content = format!(
        "SIGNINGKEY {seed}\nBACKUPKEY 1 {key}\nSIGNINGKEY {seed} oops\n@file=https://f.example.org/a;file-key={key};file-hash={} TEXT f\n",
        b64(48, 1)
    )
    .parse()
    .unwrap();
    let debug = format!("{content:?}");
    assert!(!debug.contains(&seed), "{debug}");
    assert!(!debug.contains(&key), "{debug}");
    assert!(debug.contains("SigningSeed(..)"), "{debug}");
}

#[test]
fn hand_built_lines_are_checked() {
    let bad_text = ContentLine::Text(Text::new("line\nbreak"));
    assert_eq!(bad_text.to_line(), Err(ParseError::ControlChar));
    assert!(is_syntax(
        ContentLine::Text(Text::new(" ")).to_line().unwrap_err()
    ));
    let report = Report {
        mailbox: BOX.parse().unwrap(),
        target: MessageId::from_bytes([1; 16]),
        context: vec![MessageId::from_bytes([2; 16]); MAX_REPORT_CONTEXT + 1],
        reason: String::new(),
    };
    assert_eq!(
        ContentLine::Report(report).to_line(),
        Err(ParseError::TooLong)
    );
    let want = ContentLine::Want {
        mailbox: BOX.parse().unwrap(),
        after: 3,
        before: Seq::new(4),
    };
    assert!(is_syntax(want.to_line().unwrap_err()));
    assert!(is_syntax(
        ContentLine::Servers(vec![]).to_line().unwrap_err()
    ));
    let good = ContentLine::Text(Text {
        text: "hi".into(),
        target: Some(Target::Reply(MessageId::from_bytes([1; 16]))),
        file: None,
    });
    assert_eq!(
        Content::single(good).unwrap().as_str(),
        format!("@reply={} TEXT hi\n", id(1))
    );
}

// ---- where lines count (12.9) ----

fn sample_lines() -> Vec<ContentLine> {
    let content: Content = format!(
        "TEXT hi\nDELETE {id}\nTYPING\n@box={BOX};target={id} REPORT\nCHALLENGE 1 {ct}\nANSWER 1 {mac}\nATTEST 1 {pk} {sig} {sig} {ps}\nREVEAL 1 {seed}\nRESYNC 1\nRESYNC {BOX} 1\nLEAVE {BOX}\nREFETCH {h}\nREAD {BOX} 1 {check}\nBLOCK a@b.org\nUNBLOCK a@b.org\nRECORD {h}\nALERT {h}\nRECORDS\nSIGNINGKEY {seed}\nBACKUPKEY 0 {seed}\nWANT {BOX} 0 -\nTRANSFER {tr}\nSERVERS b.org\nPIN a@b.org {h} b.org/risala-log/1 {h} no\nFROB\n",
        id = id(1),
        ct = b64(CHALLENGE_LEN, 1),
        mac = b64(48, 1),
        pk = b64(1312, 1),
        sig = b64(2420, 1),
        seed = b64(32, 1),
        h = hash('a'),
        tr = b64(TRANSFER_REF_LEN, 1),
        ps = b64(16, 1),
        check = b64(EPOCH_CHECK_LEN, 1),
    )
    .parse()
    .unwrap();
    content.lines().to_vec()
}

/// The verbs of `sample_lines` that count in `place`.
fn allowed(place: Place) -> Vec<&'static str> {
    sample_lines()
        .iter()
        .filter(|l| l.allowed_in(place))
        .map(|l| l.verb().unwrap())
        .collect()
}

#[test]
fn where_lines_count() {
    use Conversation::*;
    let ourselves = [
        "RESYNC",
        "LEAVE",
        "READ",
        "BLOCK",
        "UNBLOCK",
        "RECORD",
        "ALERT",
        "RECORDS",
        "SIGNINGKEY",
        "BACKUPKEY",
        "WANT",
        "TRANSFER",
        "SERVERS",
        "PIN",
    ];
    let mut with_yourself = vec!["TEXT", "DELETE", "CHALLENGE", "ANSWER"];
    with_yourself.extend(ourselves);
    assert_eq!(allowed(Place::new(WithYourself)), with_yourself);
    assert_eq!(
        allowed(Place::new(Direct)),
        [
            "TEXT",
            "DELETE",
            "REPORT",
            "CHALLENGE",
            "ANSWER",
            "RESYNC",
            "REFETCH"
        ]
    );
    assert_eq!(
        allowed(Place::new(PrivateRoom(ConfirmMode::Pairwise))),
        ["TEXT", "DELETE", "CHALLENGE", "ANSWER", "RESYNC", "REFETCH"]
    );
    assert_eq!(
        allowed(Place::new(PrivateRoom(ConfirmMode::Epochal))),
        ["TEXT", "DELETE", "ATTEST", "REVEAL", "RESYNC", "REFETCH"]
    );
    // Public rooms resync by external commit, not RESYNC (12.7).
    assert_eq!(
        allowed(Place::new(PublicRoom)),
        ["TEXT", "DELETE", "ATTEST", "REVEAL"]
    );
}

#[test]
fn live_messages_hold_typing_only() {
    for conversation in [
        Conversation::WithYourself,
        Conversation::Direct,
        Conversation::PrivateRoom(ConfirmMode::Pairwise),
        Conversation::PublicRoom,
    ] {
        let place = Place {
            conversation,
            live: true,
            guest: false,
        };
        assert_eq!(allowed(place), ["TYPING"]);
    }
}

#[test]
fn guests() {
    let guest = |conversation, live| Place {
        conversation,
        live,
        guest: true,
    };
    assert_eq!(allowed(guest(Conversation::Direct, false)), ["REPORT"]);
    assert!(allowed(guest(Conversation::Direct, true)).is_empty());
    assert_eq!(
        allowed(guest(Conversation::PublicRoom, false)),
        ["TEXT", "DELETE"]
    );
    assert_eq!(allowed(guest(Conversation::PublicRoom, true)), ["TYPING"]);
    assert!(allowed(guest(Conversation::WithYourself, false)).is_empty());
    assert!(
        allowed(guest(
            Conversation::PrivateRoom(ConfirmMode::Epochal),
            false
        ))
        .is_empty()
    );
}

#[test]
fn content_allowed() {
    let content: Content = "TEXT hi\nREAD ujzdegxdncf32epf3dhodzdoci 4 AAAAAAAAAAA=\nFROB\n"
        .parse()
        .unwrap();
    let direct: Vec<_> = content.allowed(Place::new(Conversation::Direct)).collect();
    assert_eq!(direct.len(), 1);
    assert!(matches!(direct[0], ContentLine::Text(_)));
    assert_eq!(
        content
            .allowed(Place::new(Conversation::WithYourself))
            .count(),
        2
    );
}

#[test]
fn resync_leave_and_read_check() {
    // `RESYNC <seq>` in the group, `RESYNC <box> <seq>` with yourself
    // (12.9).
    let ContentLine::Resync { mailbox, seq } = round_trip("RESYNC 9121") else {
        panic!()
    };
    assert_eq!((mailbox, seq.get()), (None, 9121));
    let ContentLine::Resync { mailbox, seq } = round_trip(&format!("RESYNC {BOX} 7")) else {
        panic!()
    };
    assert_eq!(mailbox.map(|m| m.to_string()).as_deref(), Some(BOX));
    assert_eq!(seq.get(), 7);
    let resync = |mailbox: Option<BoxName>| ContentLine::Resync {
        mailbox,
        seq: Seq::FIRST,
    };
    let with_yourself = Place::new(Conversation::WithYourself);
    let direct = Place::new(Conversation::Direct);
    assert!(resync(None).allowed_in(direct));
    assert!(!resync(None).allowed_in(with_yourself));
    assert!(resync(Some(BOX.parse().unwrap())).allowed_in(with_yourself));
    assert!(!resync(Some(BOX.parse().unwrap())).allowed_in(direct));

    // `LEAVE <box>` only with yourself (6.1).
    let ContentLine::Leave { mailbox } = round_trip(&format!("LEAVE {BOX}")) else {
        panic!()
    };
    assert_eq!(mailbox.to_string(), BOX);
    let leave = ContentLine::Leave { mailbox };
    assert!(leave.allowed_in(with_yourself));
    assert!(!leave.allowed_in(direct));
    assert!(!leave.allowed_in(Place::new(Conversation::PrivateRoom(ConfirmMode::Pairwise))));
    assert!(!leave.allowed_in(Place::new(Conversation::PublicRoom)));

    // READ's check is the first 8 bytes of the epoch_authenticator.
    let authenticator: Vec<u8> = (1..=48).collect();
    let check = EpochCheck::of_authenticator(&authenticator).unwrap();
    assert_eq!(check.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(EpochCheck::of_authenticator(&[0; 7]), None);
    let ContentLine::Read { check: read, .. } = round_trip(&format!(
        "READ {BOX} 3 {}",
        BASE64.encode(&authenticator[..8])
    )) else {
        panic!()
    };
    assert_eq!(read, check);
}

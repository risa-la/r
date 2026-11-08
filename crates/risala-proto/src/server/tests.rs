//! Tests of the server lines (Section 13, second table).

use super::*;
use crate::error::ErrorCode;
use crate::types::{FileUrl, PushReason, Retention};

const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";
const T: &str = "2026-11-08T15:41:02.377Z";
/// A pseudonym: 16 bytes in base64 (7.3).
const PS: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

/// Valid base64 of `bytes` zero bytes.
fn zeros(bytes: usize) -> String {
    let len = bytes.div_ceil(3) * 4;
    let pad = (3 - bytes % 3) % 3;
    format!("{}{}", "A".repeat(len - pad), "=".repeat(pad))
}

fn blob() -> String {
    format!("sha384:{}", "5d".repeat(48))
}

fn parse(s: &str) -> Result<ServerMessage, ParseError> {
    s.parse()
}

fn rt_as(s: &str, canonical: &str) -> ServerMessage {
    let msg = parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
    let line = msg.to_line().to_string();
    assert_eq!(line, canonical, "{s}");
    assert_eq!(parse(&line), Ok(msg.clone()), "{s}");
    msg
}

fn rt(s: &str) -> ServerMessage {
    rt_as(s, s)
}

fn syntax(s: &str) {
    assert!(
        matches!(parse(s), Err(ParseError::BadSyntax(_))),
        "{s}: {:?}",
        parse(s)
    );
}

/// Every line of Section 13's second table, in canonical form.
fn every_line() -> Vec<String> {
    let blob = blob();
    vec![
        "RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e Welcome!".into(),
        "RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e".into(),
        "OK".into(),
        "OK seq=9121".into(),
        "OK uid=~sam token=k3f9q2abcdefghij resumed=yes".into(),
        "ERR not-found".into(),
        "@retry=30 ERR rate-limited slow down".into(),
        format!("@seq=9122;t={T} POST {BOX} AAEAAg=="),
        format!("@seq=9122;t={T} POST {BOX} {blob}"),
        format!("@t={T} POST {BOX} AAEAAg=="),
        format!("@seq=9122;t={T} POST {BOX} AAEAAg== next={}", zeros(48)),
        format!("ROOM #general {BOX} 812 General chat. Be kind."),
        format!("ROOM #general {BOX} 0"),
        format!("GROUPINFO {BOX} 4410 9120 AAEABA== {blob}"),
        format!("GROUPINFO {BOX} 0 0 AAEABA== AAEC"),
        format!("GONE {BOX} ~sam"),
        format!("DROP {BOX}"),
        format!("DROP {BOX} illegal content"),
        "USER alice@example.org online".into(),
        "USER alice@example.org away".into(),
        "MEMBER #general alice@example.org owner online".into(),
        "MEMBER #general ~sam member offline".into(),
        "PRESENCE online alice@example.org,bob@example.net".into(),
        "PRESENCE offline carol@example.com".into(),
        format!("@report=r7;t={T};pseudonym={PS} REPORT {BOX} AQIDBA=="),
        format!("@report=r7;t={T};pseudonym={PS};from=alice@example.org REPORT {BOX} AQIDBA=="),
        "RESOLVED r7".into(),
        format!("RECORD 0 {blob}"),
        format!("RECORD 812 {blob}"),
        format!("PAIR {BOX} AAEC"),
        "PUSH https://push.example/a x7Hq2".into(),
        format!("KEYPKG bob@example.net AAEABQ== {}", zeros(32)),
        "WELCOME w7k2 AAEABg==".into(),
        format!("WELCOME w7k2 {blob}"),
        format!("WELCOME w7k2 AAEABg== tree={blob}"),
        format!("WELCOME w7k2 {blob} tree=AAEC"),
        format!("BACKUP 3 {blob} {}", zeros(61)),
        format!("BACKUP 3 {blob} {} files={blob}", zeros(61)),
        "NOTICE Back in 5 minutes.".into(),
        "OP carol@example.com".into(),
        "SERVERBAN *@example.net".into(),
        "SERVERBAN 2001:db8::/32 spam".into(),
        format!("CONNECTION - 203.0.113.7 {T}"),
        format!("CONNECTION ~sam 203.0.113.7:51000 {T}"),
        format!("CONNECTION alice@example.org [2001:db8::1]:51000 {T}"),
        format!("CONNECTION alice@example.org 2001:db8::1 {T}"),
        "PING x".into(),
        "BYE".into(),
        "BYE shutting down".into(),
    ]
}

#[test]
fn every_line_round_trips() {
    for s in every_line() {
        let msg = rt(&s);
        assert!(!matches!(msg.line, ServerLine::Unknown(_)), "{s}");
        let with_ref = match s.strip_prefix('@') {
            Some(rest) => format!("@ref=7;{rest}"),
            None => format!("@ref=7 {s}"),
        };
        assert_eq!(
            rt(&with_ref).ref_.map(|r| r.to_string()).as_deref(),
            Some("7")
        );
    }
}

#[test]
fn every_verb_is_covered() {
    let mut seen: Vec<String> = every_line()
        .iter()
        .map(|s| parse(s).unwrap().line.verb().to_owned())
        .collect();
    seen.sort();
    seen.dedup();
    let mut want = vec![
        "RISALA",
        "OK",
        "ERR",
        "POST",
        "ROOM",
        "GROUPINFO",
        "GONE",
        "DROP",
        "USER",
        "MEMBER",
        "PRESENCE",
        "REPORT",
        "RESOLVED",
        "RECORD",
        "PAIR",
        "PUSH",
        "KEYPKG",
        "WELCOME",
        "BACKUP",
        "NOTICE",
        "OP",
        "SERVERBAN",
        "CONNECTION",
        "PING",
        "BYE",
    ];
    want.sort();
    assert_eq!(seen, want);
}

#[test]
fn posts() {
    let msg = rt(&format!(
        "@ref=7;seq=9121;t=2026-11-08T15:40:58.120Z POST {BOX} AAEAAQ=="
    ));
    let ServerLine::Post(post) = &msg.line else {
        panic!()
    };
    assert_eq!(post.seq, Seq::new(9121));
    assert!(!post.is_live());
    assert_eq!(post.mailbox.to_string(), BOX);
    assert_eq!(post.next, None);
    // A live post has t but no seq (5.2).
    let live = rt(&format!("@t={T} POST {BOX} AAEAAQ=="));
    let ServerLine::Post(post) = &live.line else {
        panic!()
    };
    assert!(post.is_live());
    // Every post has t (5.2).
    syntax(&format!("@seq=1 POST {BOX} AAEAAQ=="));
    syntax(&format!("POST {BOX} AAEAAQ=="));
    // A commit's post repeats its next (5.2).
    let next = zeros(48);
    let msg = rt(&format!("@seq=9;t={T} POST {BOX} AAEAAQ== next={next}"));
    let ServerLine::Post(post) = &msg.line else {
        panic!()
    };
    assert_eq!(post.next.map(|n| n.to_string()), Some(next.clone()));
    // next is a 48-byte hash; nothing else may follow the message.
    syntax(&format!(
        "@seq=9;t={T} POST {BOX} AAEAAQ== next={}",
        zeros(32)
    ));
    syntax(&format!("@seq=9;t={T} POST {BOX} AAEAAQ== next="));
    syntax(&format!("@seq=9;t={T} POST {BOX} AAEAAQ== live=yes"));
    syntax(&format!("@seq=0;t={T} POST {BOX} AAEAAQ=="));
    syntax(&format!("@seq;t={T} POST {BOX} AAEAAQ=="));
    syntax(&format!("@seq=1;t=yesterday POST {BOX} AAEAAQ=="));
    syntax(&format!("@t={T} POST {BOX}"));
    syntax(&format!("@t={T} POST {BOX} AAEAAQ== extra"));
    syntax(&format!("@t={T} POST general AAEAAQ=="));
    // Tags in canonical order, others dropped.
    rt_as(
        &format!("@x-y=1;t={T};seq=5 POST {BOX} AAEAAQ=="),
        &format!("@seq=5;t={T} POST {BOX} AAEAAQ=="),
    );
}

#[test]
fn reports() {
    let msg = rt(&format!(
        "@report=r7;t={T};pseudonym={PS};from=alice@example.org REPORT {BOX} AQIDBA=="
    ));
    let ServerLine::Report(report) = &msg.line else {
        panic!()
    };
    assert_eq!(report.id.as_str(), "r7");
    assert_eq!(
        report.from.as_ref().map(Uid::as_str),
        Some("alice@example.org")
    );
    assert_eq!(report.pseudonym.to_string(), PS);
    syntax(&format!("@t={T};pseudonym={PS} REPORT {BOX} AQIDBA=="));
    syntax(&format!("@report=r7;pseudonym={PS} REPORT {BOX} AQIDBA=="));
    // 5.8: the pseudonym is required, and is 16 bytes.
    syntax(&format!("@report=r7;t={T} REPORT {BOX} AQIDBA=="));
    syntax(&format!("@report=r7;t={T};pseudonym REPORT {BOX} AQIDBA=="));
    syntax(&format!(
        "@report=r7;t={T};pseudonym=AAAA REPORT {BOX} AQIDBA=="
    ));
    syntax(&format!(
        "@report=r7;t={T};pseudonym={PS};from=x REPORT {BOX} AQIDBA=="
    ));
}

#[test]
fn bad_lines() {
    for s in [
        "RISALA x chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e".to_owned(),
        "RISALA 1 chat.example.org 6f1c".into(),
        "OK seq".into(),
        "ERR".into(),
        format!("ROOM general {BOX} 1"),
        format!("ROOM #general {BOX} -1"),
        format!("GROUPINFO {BOX} 1 01 AAEC AAEC"),
        format!("GROUPINFO {BOX} 1 1 AAEC"),
        format!("GONE {BOX}"),
        "DROP #general".into(),
        "USER alice@example.org".into(),
        "MEMBER #general alice@example.org admin online".into(),
        "PRESENCE online".into(),
        "PRESENCE online a@b.org,".into(),
        "PRESENCE online a@b.org b@c.org".into(),
        "RESOLVED".into(),
        "RECORD 1 sha384:00".into(),
        format!("RECORD -1 {}", blob()),
        format!("PAIR {BOX}"),
        "PUSH http://push.example/a t".into(),
        "KEYPKG bob@example.net".into(),
        "KEYPKG bob@example.net AAEABQ==".into(),
        format!("KEYPKG bob@example.net AAEABQ== {}", zeros(31)),
        "WELCOME w7".into(),
        "WELCOME w7 AAEABg== AAEC".into(),
        "WELCOME w7 AAEABg== light=yes".into(),
        format!("BACKUP 4294967296 {} {}", blob(), zeros(61)),
        format!("BACKUP 1 {} AAE", blob()),
        format!("BACKUP 1 {} {} files=AAEC", blob(), zeros(61)),
        format!("BACKUP 1 {} {} {}", blob(), zeros(61), blob()),
        "NOTICE".into(),
        "OP".into(),
        "SERVERBAN".into(),
        format!("CONNECTION - 203.0.113 {T}"),
        "CONNECTION - 203.0.113.7".into(),
        "PING".into(),
        "PING a b".into(),
    ] {
        syntax(&s);
    }
    assert_eq!(
        parse(&format!("ROOM #general {BOX} 1 {}", "t".repeat(513))),
        Err(ParseError::TooLong)
    );
    assert_eq!(
        parse(&format!(
            "RISALA 1 h.example 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e {}",
            "w".repeat(513)
        )),
        Err(ParseError::TooLong)
    );
}

#[test]
fn unknown_verbs_are_kept() {
    // Clients ignore lines with verbs they do not know (3.8), and draft-02's
    // lines are unknown now.
    for s in [
        "FOO bar baz",
        "@seq=1;t=x;from=~sam MSG #general hi",
        "ENC #r 1 AAAA",
        "CONV #general k3 1 0",
        "TYPING #general",
    ] {
        let msg = rt(s);
        assert!(matches!(msg.line, ServerLine::Unknown(_)), "{s}");
    }
    let msg = rt("@ref=9;x=1 FOO");
    assert_eq!(msg.ref_.map(|r| r.to_string()).as_deref(), Some("9"));
    let ServerLine::Unknown(line) = &msg.line else {
        panic!()
    };
    assert!(!line.tags().has("ref"));
    assert_eq!(msg.line.verb(), "FOO");
}

#[test]
fn ok_values() {
    let ok = OkResponse::new()
        .with_seq(Seq::new(9121).unwrap())
        .with_head(0u64)
        .with_more(true)
        .with_uid(&"~sam".parse().unwrap())
        .with_token(&"k3f9q2abcdefghij".parse().unwrap())
        .with_resumed(true)
        .with_op(true)
        .with_id(&"r7".parse().unwrap())
        .with_exists()
        .with_count(4)
        .with_last_resort(false)
        .with_mailbox(&BOX.parse().unwrap())
        .with_members(812)
        .with_epoch(4410)
        .with_version(1)
        .with_anon(true)
        .with_guests(false)
        .with_register(&Register::Domain("example.org".parse().unwrap()))
        .with_log(&Log::Url("https://chat.example.org/risala-log/1".into()))
        .with_retention(Retention::new(30).unwrap())
        .with_push(true)
        .with_upload(Upload::MaxBytes(1 << 20))
        .with_quota(1 << 30);
    let ok = ok
        .with_files(&[
            "https://f.example".parse().unwrap(),
            "https://[2001:db8::1]:8443".parse().unwrap(),
        ])
        .unwrap()
        .with_blobs("https://chat.example.org/blobs/")
        .unwrap()
        .with_upload_urls(
            "https://f.example/put/1",
            &"https://f.example/get/1".parse().unwrap(),
            "https://f.example/del/1",
        )
        .unwrap();
    let line = ServerMessage::new(ok).to_line().to_string();
    let back = parse(&line).unwrap();
    let ServerLine::Ok(ok) = back.line else {
        panic!()
    };
    assert_eq!(ok.seq(), Ok(Seq::new(9121)));
    assert_eq!(ok.head(), Ok(Some(0)));
    assert_eq!(ok.more(), Ok(Some(true)));
    assert_eq!(ok.uid().unwrap().unwrap().as_str(), "~sam");
    assert_eq!(ok.token().unwrap().unwrap().to_string(), "k3f9q2abcdefghij");
    assert_eq!(ok.resumed(), Ok(Some(true)));
    assert_eq!(ok.op(), Ok(Some(true)));
    assert_eq!(ok.id().unwrap().unwrap().as_str(), "r7");
    assert_eq!(ok.exists(), Ok(Some(true)));
    assert_eq!(ok.count(), Ok(Some(4)));
    assert_eq!(ok.last_resort(), Ok(Some(false)));
    assert_eq!(ok.mailbox().unwrap().unwrap().to_string(), BOX);
    assert_eq!(ok.members(), Ok(Some(812)));
    assert_eq!(ok.epoch(), Ok(Some(4410)));
    assert_eq!(ok.version(), Ok(Some(1)));
    assert_eq!(ok.anon(), Ok(Some(true)));
    assert_eq!(ok.guests(), Ok(Some(false)));
    assert_eq!(
        ok.register(),
        Ok(Some(Register::Domain("example.org".parse().unwrap())))
    );
    assert_eq!(
        ok.log(),
        Ok(Some(Log::Url("https://chat.example.org/risala-log/1".into())))
    );
    assert_eq!(ok.retention(), Ok(Retention::new(30)));
    assert_eq!(ok.push(), Ok(Some(true)));
    assert_eq!(ok.upload(), Ok(Some(Upload::MaxBytes(1 << 20))));
    assert_eq!(ok.blobs(), Some("https://chat.example.org/blobs/"));
    assert_eq!(ok.put_url(), Some("https://f.example/put/1"));
    assert_eq!(
        ok.get_url().unwrap().unwrap().as_str(),
        "https://f.example/get/1"
    );
    assert_eq!(ok.del_url(), Some("https://f.example/del/1"));
    assert_eq!(ok.quota(), Ok(Some(1 << 30)));
    assert_eq!(
        ok.value("files"),
        Some("https://f.example,https://[2001:db8::1]:8443")
    );
    let files = ok.files().unwrap().unwrap();
    assert!(files[0].contains(&ok.get_url().unwrap().unwrap()));
    assert!(!files[1].contains(&ok.get_url().unwrap().unwrap()));
    // The guest token stays out of Debug.
    assert!(!format!("{ok:?}").contains("k3f9q2"));

    // `no` values.
    let ok: OkResponse = match parse("OK register=no log=no upload=no").unwrap().line {
        ServerLine::Ok(ok) => ok,
        _ => panic!(),
    };
    assert_eq!(ok.register(), Ok(Some(Register::No)));
    assert_eq!(ok.log(), Ok(Some(Log::No)));
    assert_eq!(ok.upload(), Ok(Some(Upload::No)));
    // Bad values are errors when read, not when parsed (3.6).
    let ok: OkResponse = match parse("OK more=2 retention=3 log=ftp://x unknown=1")
        .unwrap()
        .line
    {
        ServerLine::Ok(ok) => ok,
        _ => panic!(),
    };
    assert!(ok.more().is_err());
    assert!(ok.retention().is_err());
    assert!(ok.log().is_err());
    assert_eq!(ok.value("unknown"), Some("1"));
    // `log=` is https:// and the log's origin, exactly (4.5, 8.5).
    for url in [
        "https://chat.example.org/log",
        "https://chat.example.org/risala-log/1/",
        "https://chat.example.org/risala-log/0",
        "https://chat.example.org:443/risala-log/1",
        "https://Chat.example.org/risala-log/1",
        "HTTPS://chat.example.org/risala-log/1",
        "http://chat.example.org/risala-log/1",
    ] {
        assert!(url.parse::<Log>().is_err(), "{url}");
    }
    let log: Log = "https://chat.example.org/risala-log/2".parse().unwrap();
    assert_eq!(log.origin(), Some("chat.example.org/risala-log/2"));
    assert!(OkResponse::new().with_files(&[]).is_err());
}

#[test]
fn file_origins() {
    // INFO's `files=` (8.5): `https://<host>[:<port>]`, nothing after, in
    // one form.
    let origin = |s: &str| s.parse::<FileOrigin>();
    for s in [
        "https://f.example",
        "https://f.example:8443",
        "https://203.0.113.7",
        "https://[2001:db8::1]",
        "https://localhost:1",
    ] {
        assert_eq!(origin(s).unwrap().to_string(), s);
    }
    for s in [
        // Not the one form: upper case, `:443`, an IPv6 address not as
        // it is always written.
        "HTTPS://f.example",
        "https://F.Example:8443",
        "https://f.example:443",
        "https://[2001:DB8::1]",
        "https://[2001:0db8::1]",
        "https://1.2.3",
        "",
        "https://",
        "http://f.example",
        "https://f.example/",
        "https://f.example/files",
        "https://f.example:",
        "https://f.example:0",
        "https://f.example:65536",
        "https://f.example:08",
        "https://f_x.example",
        "https://2001:db8::1",
        "https://[2001:db8::1",
        "https://[f.example]",
        "https://:443",
    ] {
        assert!(origin(s).is_err(), "{s}");
    }
    // A `get` URL is on an origin with the same host and port, 443 by
    // default (5.6).
    let url = |s: &str| s.parse::<FileUrl>().unwrap();
    let o = origin("https://f.example").unwrap();
    assert!(o.contains(&url("https://f.example/get/1")));
    // The URL's origin is found as 8.5 writes one (8.5's example).
    assert!(o.contains(&url("https://F.EXAMPLE:443/get/1")));
    assert!(o.contains(&url("https://f.example:443/x")));
    assert!(o.contains(&url("https://f.example?x=1")));
    assert!(!o.contains(&url("https://f.example:8443/get/1")));
    assert!(!o.contains(&url("https://f.example.evil/get/1")));
    assert!(!o.contains(&url("https://evil@f.example/get/1")));
    assert!(!o.contains(&url("https://g.example/f.example")));
    let o = origin("https://f.example:8443").unwrap();
    assert!(o.contains(&url("https://f.example:8443/x")));
    assert!(!o.contains(&url("https://f.example/x")));
}

#[test]
fn errors() {
    let msg = rt("@ref=3;retry=30 ERR unavailable key file fetch failed");
    let ServerLine::Err(err) = &msg.line else {
        panic!()
    };
    assert_eq!(err.code, ErrorCode::Unavailable);
    assert_eq!(err.retry, Some(30));
    assert_eq!(err.message, "key file fetch failed");
    // An unknown code is kept (3.7).
    let msg = rt("ERR slow-down");
    let ServerLine::Err(err) = &msg.line else {
        panic!()
    };
    assert_eq!(err.code, ErrorCode::Other("slow-down".into()));
    let from: ErrResponse = ParseError::UnknownVerb("FOO".into()).into();
    assert_eq!(from.code, ErrorCode::UnknownCommand);
}

#[test]
fn final_responses() {
    for s in every_line() {
        let msg = parse(&s).unwrap();
        assert_eq!(
            msg.line.is_final(),
            s.starts_with("OK") || s.contains("ERR "),
            "{s}"
        );
    }
}

#[test]
fn hand_built_lines_are_checked() {
    let empty = ServerMessage::new(ServerLine::Presence {
        presence: Presence::Online,
        uids: Vec::new(),
    });
    assert!(empty.try_to_line().is_err());
    let notice = ServerMessage::new(ServerLine::Notice {
        message: String::new(),
    });
    assert!(notice.try_to_line().is_err());
    let not_canonical = ServerMessage::new(ErrResponse::new(ErrorCode::Other("stale".into())));
    assert!(not_canonical.try_to_line().is_err());
    let post = ServerMessage::new(Post::new(
        Seq::FIRST,
        T.parse().unwrap(),
        BOX.parse().unwrap(),
        "AAEAAQ==".parse().unwrap(),
    ));
    assert_eq!(
        post.to_line().to_string(),
        format!("@seq=1;t={T} POST {BOX} AAEAAQ==")
    );
    let next: crate::mls::TokenHash = zeros(48).parse().unwrap();
    let live = ServerMessage::new(
        Post::live(
            T.parse().unwrap(),
            BOX.parse().unwrap(),
            "AAEAAQ==".parse().unwrap(),
        )
        .with_next(next),
    );
    assert_eq!(
        live.to_line().to_string(),
        format!("@t={T} POST {BOX} AAEAAQ== next={}", zeros(48))
    );
    let notify = Notify {
        tag: "t".parse().unwrap(),
        reason: PushReason::Welcome.into(),
    };
    assert_eq!(notify.to_body(), "NOTIFY t welcome\n");
}

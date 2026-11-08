//! Tests of the client commands (Section 13).

use super::*;
use crate::connection::ConnectionKind::{self, Anonymous, Guest, New, SignedIn};
use crate::types::ServerSetting;

const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";

/// Valid base64 of `bytes` zero bytes: what every fixed-size value needs.
fn zeros(bytes: usize) -> String {
    let len = bytes.div_ceil(3) * 4;
    let pad = (3 - bytes % 3) % 3;
    format!("{}{}", "A".repeat(len - pad), "=".repeat(pad))
}

fn group_id() -> String {
    zeros(32)
}
fn token_hash() -> String {
    zeros(48)
}
fn token() -> String {
    "3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE=".into()
}
fn pseudonym() -> String {
    zeros(16)
}
fn kp_ref() -> String {
    zeros(48)
}
fn signature() -> String {
    zeros(2420)
}
fn blob() -> String {
    format!("sha384:{}", "5d".repeat(48))
}

fn parse(s: &str) -> Result<Request, ParseError> {
    s.parse()
}

/// Parses `s`, checks that it writes back as `canonical`, and that the
/// result parses to the same request.
fn rt_as(s: &str, canonical: &str) -> Request {
    let request = parse(s).unwrap_or_else(|e| panic!("{s}: {e}"));
    let line = request.to_line().to_string();
    assert_eq!(line, canonical, "{s}");
    assert_eq!(parse(&line), Ok(request.clone()), "{s}");
    assert_eq!(request.validate(), Ok(()), "{s}");
    request
}

/// Parses `s`, which must be canonical.
fn rt(s: &str) -> Request {
    rt_as(s, s)
}

fn syntax(s: &str) {
    assert!(
        matches!(parse(s), Err(ParseError::BadSyntax(_))),
        "{s}: {:?}",
        parse(s)
    );
}

fn too_long(s: &str) {
    assert_eq!(parse(s), Err(ParseError::TooLong), "{s}");
}

fn unknown(s: &str, verb: &str) {
    assert_eq!(parse(s), Err(ParseError::UnknownVerb(verb.into())), "{s}");
}

/// Every form of every command in Section 13, in canonical form.
fn every_form() -> Vec<String> {
    let (gid, th, tok, ps, r, sig, blob) = (
        group_id(),
        token_hash(),
        token(),
        pseudonym(),
        kp_ref(),
        signature(),
        blob(),
    );
    let key = zeros(65);
    let auth = zeros(16);
    let wrapped = zeros(61);
    vec![
        "INFO".into(),
        "INFO #general".into(),
        "ANON".into(),
        "GUEST sam".into(),
        "GUEST sam token=k3f9q2abcdefghij".into(),
        format!("AUTH alice@example.org {sig}"),
        format!("REGISTER alice AQ== {sig}"),
        "KEYS PUT - AQAB".into(),
        format!("KEYS PUT {blob} {blob}"),
        format!("PAIR PUT {BOX} AAEC"),
        format!("PAIR GET {BOX}"),
        "UNREGISTER alice@example.org".into(),
        format!("CREATE {BOX} {gid} {th}"),
        format!("CREATE {BOX} {gid} {th} epoch=1"),
        format!("CREATE {BOX} {gid} {th} epoch=9223372036854775807"),
        format!("CREATE {BOX} {gid} {th} #general AAEABA== AAEC"),
        format!("CREATE {BOX} {gid} {th} #general {blob} {blob}"),
        format!("POST {BOX} {tok} AAEAAQ=="),
        format!("POST {BOX} - AAEAAQ== groupinfo=AAEABA=="),
        format!("POST {BOX} {tok} {blob} live=yes"),
        format!("@cid=q2r8sv0alm3nb7xk POST {BOX} {tok} AAEAAQ=="),
        format!("POST {BOX} {tok} AAEAAQ== next={th}"),
        format!("POST {BOX} - AAEAAQ== groupinfo=AAEABA== next={th}"),
        format!("UPLOAD {BOX} {tok} 48213"),
        format!("REPORT {BOX} AQIDBA=="),
        "LIST".into(),
        "LIST after=#general limit=20".into(),
        format!("GROUPINFO {BOX}"),
        format!("MUTE {BOX} {ps}"),
        format!("MUTE {BOX} {ps} hours=2"),
        format!("UNMUTE {BOX} {ps}"),
        format!("FOLLOW {BOX}"),
        format!("FOLLOW {BOX} quiet=x7Hq2"),
        format!("UNFOLLOW {BOX}"),
        format!("FETCH {BOX} after=0"),
        format!("FETCH {BOX} after=9120 limit=2 leaf=7"),
        format!("TOKEN {BOX} 0 {tok} {th}"),
        format!("TOKEN {BOX} 41 {tok} {th}"),
        "PRESENCE ON".into(),
        "PRESENCE OFF".into(),
        "WATCH".into(),
        "WATCH alice@example.org,~sam,bob@example.net".into(),
        "WHOIS alice@example.org".into(),
        "MEMBERS #general".into(),
        format!("PUSH ADD https://push.example/a x7Hq2 {key} {auth}"),
        format!("PUSH ADD https://push.example/a x7Hq2 {key} {auth} box={BOX}"),
        "PUSH DEL https://push.example/a".into(),
        format!("PUSH DEL https://push.example/a box={BOX}"),
        "PUSH LIST".into(),
        "KEYPKG ADD AAEABQ==".into(),
        "KEYPKG COUNT".into(),
        "KEYPKG GET bob@example.net".into(),
        format!("WELCOME PUT {r} AAEABg=="),
        format!("WELCOME PUT {r} {blob}"),
        "WELCOME LIST".into(),
        "WELCOME DEL w7k2".into(),
        format!("WELCOME GET {r}"),
        format!("WELCOME GET {r} light=yes"),
        format!("BLOB {blob} 1048577"),
        format!("BLOB {blob} 0 box={BOX} token={tok}"),
        format!("BACKUP PUT 0 {blob} {wrapped}"),
        format!("BACKUP PUT 4294967295 {blob} {wrapped}"),
        format!("BACKUP PUT 1 {blob} {wrapped} files={blob}"),
        "BACKUP GET".into(),
        "BACKUP DEL".into(),
        "ADMIN OPS".into(),
        "ADMIN OP carol@example.com".into(),
        "ADMIN DEOP carol@example.com".into(),
        "ADMIN BAN spam@example.net".into(),
        "ADMIN BAN *@example.net spam, mostly".into(),
        "ADMIN BAN 2001:db8::/32".into(),
        "ADMIN UNBAN 203.0.113.7".into(),
        "ADMIN BANS".into(),
        "ADMIN WHO".into(),
        "ADMIN DISCONNECT ~sam".into(),
        "ADMIN DISCONNECT ~sam flooding".into(),
        "ADMIN NOTICE Back in 5 minutes.".into(),
        "ADMIN ROOMS".into(),
        "ADMIN ROOMS after=#a limit=1".into(),
        "ADMIN DROP #general".into(),
        format!("ADMIN DROP {BOX} illegal content"),
        format!("ADMIN MUTE {BOX} {ps}"),
        format!("ADMIN MUTE {BOX} {ps} hours=48"),
        format!("ADMIN UNMUTE {BOX} {ps}"),
        "ADMIN REPORTS".into(),
        "ADMIN UNREGISTER alice@example.org".into(),
        "ADMIN SET anon no".into(),
        "ADMIN SET guests yes".into(),
        "ADMIN SET registration closed".into(),
        "ADMIN SET retention 30".into(),
        "ADMIN SET welcome  Two leading spaces, kept.".into(),
        "ADMIN SET welcome".into(),
        "ADMIN SET slowmode 10 seconds".into(),
        "RESOLVE r7".into(),
        "PING".into(),
        "PING abc".into(),
        "PONG abc".into(),
        "QUIT".into(),
        "QUIT bye for now".into(),
    ]
}

#[test]
fn every_form_round_trips() {
    for s in every_form() {
        rt(&s);
        // With a ref, too, which comes first.
        let with_ref = match s.strip_prefix('@') {
            Some(rest) => format!("@ref=7;{rest}"),
            None => format!("@ref=7 {s}"),
        };
        rt(&with_ref);
    }
}

#[test]
fn every_verb_is_covered() {
    let mut seen: Vec<String> = every_form()
        .iter()
        .map(|s| {
            let c = parse(s).unwrap().command;
            match c.subcommand() {
                Some(sub) => format!("{} {sub}", c.verb()),
                None => c.verb().to_owned(),
            }
        })
        .collect();
    seen.sort();
    seen.dedup();
    // The commands of Section 13's first table, one per verb and
    // subcommand.
    let mut want = vec![
        "INFO",
        "ANON",
        "GUEST",
        "AUTH",
        "REGISTER",
        "KEYS PUT",
        "PAIR PUT",
        "PAIR GET",
        "UNREGISTER",
        "CREATE",
        "POST",
        "UPLOAD",
        "REPORT",
        "LIST",
        "GROUPINFO",
        "MUTE",
        "UNMUTE",
        "FOLLOW",
        "UNFOLLOW",
        "FETCH",
        "TOKEN",
        "PRESENCE ON",
        "PRESENCE OFF",
        "WATCH",
        "WHOIS",
        "MEMBERS",
        "PUSH ADD",
        "PUSH DEL",
        "PUSH LIST",
        "KEYPKG ADD",
        "KEYPKG COUNT",
        "KEYPKG GET",
        "WELCOME PUT",
        "WELCOME LIST",
        "WELCOME DEL",
        "WELCOME GET",
        "BLOB",
        "BACKUP PUT",
        "BACKUP GET",
        "BACKUP DEL",
        "ADMIN OPS",
        "ADMIN OP",
        "ADMIN DEOP",
        "ADMIN BAN",
        "ADMIN UNBAN",
        "ADMIN BANS",
        "ADMIN WHO",
        "ADMIN DISCONNECT",
        "ADMIN NOTICE",
        "ADMIN ROOMS",
        "ADMIN DROP",
        "ADMIN MUTE",
        "ADMIN UNMUTE",
        "ADMIN REPORTS",
        "ADMIN UNREGISTER",
        "ADMIN SET",
        "RESOLVE",
        "PING",
        "PONG",
        "QUIT",
    ];
    want.sort();
    assert_eq!(seen, want);
}

#[test]
fn case_folds() {
    // Verbs, subcommands, option keys, names, boxes and blob-refs fold
    // (3.1, 3.5).
    rt_as(
        &format!("@ref=7 fetch {} after=9120 LIMIT=2", BOX.to_uppercase()),
        &format!("@ref=7 FETCH {BOX} after=9120 limit=2"),
    );
    rt_as("keypkg get Bob@Example.NET", "KEYPKG GET bob@example.net");
    rt_as("presence on", "PRESENCE ON");
    rt_as("Admin Set Registration Open", "ADMIN SET registration open");
    rt_as(
        &format!("blob {} 1", blob().to_uppercase()),
        &format!("BLOB {} 1", blob()),
    );
    rt_as(
        &format!("post {BOX} - AAEAAQ== LIVE=YES"),
        &format!("POST {BOX} - AAEAAQ== live=yes"),
    );
    // Base64 is case-sensitive and kept.
    let r = rt(&format!("POST {BOX} {} AbCd", token()));
    let Command::Post { message, .. } = r.command else {
        panic!()
    };
    assert_eq!(message.to_string(), "AbCd");
}

#[test]
fn runs_of_spaces_and_false_flags() {
    rt_as(
        &format!("FOLLOW   {BOX}   quiet=t  "),
        &format!("FOLLOW {BOX} quiet=t"),
    );
    rt_as("LIST ", "LIST");
    // `live=no` and `light=no` mean the same as leaving them out.
    rt_as(
        &format!("POST {BOX} - AAEAAQ== live=no"),
        &format!("POST {BOX} - AAEAAQ=="),
    );
    rt_as(
        &format!("WELCOME GET {} light=no", kp_ref()),
        &format!("WELCOME GET {}", kp_ref()),
    );
}

#[test]
fn arity() {
    for s in [
        "ANON x".to_owned(),
        "GUEST".into(),
        "GUEST sam extra".into(),
        "GUEST sam colour=red".into(),
        "GUEST sam token=a token=b".into(),
        "AUTH alice@example.org".into(),
        format!("AUTH alice@example.org {} x", signature()),
        format!("REGISTER alice {}", signature()),
        "KEYS".into(),
        "KEYS PUT".into(),
        "KEYS PUT AQ== AQ==".into(),
        "KEYS PUT - AQ".into(),
        "KEYS PUT x AQAB".into(),
        "KEYS PUT sha384:00 AQAB".into(),
        format!("KEYS PUT - AQAB {}", self::blob()),
        format!("PAIR PUT {BOX}"),
        "PAIR".into(),
        "UNREGISTER".into(),
        format!("CREATE {BOX} {}", group_id()),
        format!("CREATE {BOX} {} {} #general", group_id(), token_hash()),
        format!("CREATE {BOX} {} {} epoch=0", group_id(), token_hash()),
        format!("CREATE {BOX} {} {} epoch=-1", group_id(), token_hash()),
        format!("CREATE {BOX} {} {} epoch=01", group_id(), token_hash()),
        format!(
            "CREATE {BOX} {} {} epoch=1 epoch=2",
            group_id(),
            token_hash()
        ),
        format!("CREATE {BOX} {} {} room=#general", group_id(), token_hash()),
        format!("CREATE {BOX} {} {} 7", group_id(), token_hash()),
        format!(
            "CREATE {BOX} {} {} #general AAEABA== AAEC epoch=1",
            group_id(),
            token_hash()
        ),
        format!(
            "CREATE {BOX} {} {} epoch=1 #general AAEABA== AAEC",
            group_id(),
            token_hash()
        ),
        format!(
            "CREATE {BOX} {} {} #general AAEABA==",
            group_id(),
            token_hash()
        ),
        format!(
            "CREATE {BOX} {} {} #general AAEABA== AAEC AAEC",
            group_id(),
            token_hash()
        ),
        format!("POST {BOX} {}", token()),
        format!("POST {BOX} {} AAEAAQ== extra", token()),
        format!("POST {BOX} {} AAEAAQ== cid=x", token()),
        format!("UPLOAD {BOX} {}", token()),
        format!("REPORT {BOX}"),
        "LIST #general".into(),
        "LIST limit=0".into(),
        "GROUPINFO".into(),
        format!("MUTE {BOX} {} hours=0", pseudonym()),
        format!("MUTE {BOX} {} 24", pseudonym()),
        format!("FETCH {BOX}"),
        format!("FETCH {BOX} limit=2"),
        format!("FETCH {BOX} after=01"),
        format!("FETCH {BOX} after=0 limit=0"),
        format!("FETCH {BOX} after=0 leaf=4294967296"),
        format!("FETCH {BOX} after=0 leaf=-1"),
        "TOKEN".into(),
        format!("TOKEN {BOX} 41 {}", token()),
        format!("TOKEN {BOX} 41 {} {} x", token(), token_hash()),
        format!("TOKEN {BOX} -1 {} {}", token(), token_hash()),
        format!("TOKEN {BOX} 01 {} {}", token(), token_hash()),
        format!("TOKEN {BOX} 41 - {}", token_hash()),
        format!("TOKEN {BOX} 41 {} {}", token_hash(), token_hash()),
        format!("TOKEN {BOX} 41 {} {}", token(), token()),
        format!("TOKEN {BOX} epoch=41 {} {}", token(), token_hash()),
        "PRESENCE".into(),
        "PRESENCE ON now".into(),
        "WATCH a@b.org c@d.org".into(),
        "WATCH a@b.org,".into(),
        "WATCH ,a@b.org".into(),
        "WATCH a@b.org,,c@d.org".into(),
        "WHOIS".into(),
        "MEMBERS".into(),
        "PUSH".into(),
        "PUSH LIST x".into(),
        "PUSH ADD https://push.example/a x7Hq2".into(),
        format!("PUSH DEL https://push.example/a box={BOX} box={BOX}"),
        "KEYPKG COUNT x".into(),
        "KEYPKG ADD".into(),
        "WELCOME LIST x".into(),
        format!("WELCOME PUT {}", kp_ref()),
        format!("WELCOME GET {} light=maybe", kp_ref()),
        format!("BLOB {}", blob()),
        format!("BLOB {} 1 box={BOX}", blob()),
        format!("BLOB {} 1 token={}", blob(), token()),
        format!("BACKUP PUT 0 {}", blob()),
        format!("BACKUP PUT 4294967296 {} {}", blob(), zeros(61)),
        format!("BACKUP PUT 0 {} {} {}", blob(), zeros(61), blob()),
        format!("BACKUP PUT 0 {} {} files={}", blob(), zeros(61), zeros(48)),
        format!("BACKUP PUT 0 {} {} hash={}", blob(), zeros(61), blob()),
        "BACKUP GET x".into(),
        "ADMIN".into(),
        "ADMIN OPS x".into(),
        "ADMIN OP".into(),
        "ADMIN NOTICE".into(),
        "ADMIN ROOMS #a".into(),
        "ADMIN DROP".into(),
        "ADMIN SET".into(),
        "ADMIN SET retention 6".into(),
        "RESOLVE".into(),
        "PONG".into(),
        "PING a b".into(),
    ] {
        syntax(&s);
    }
}

#[test]
fn values_have_their_grammar() {
    // Wrong lengths and bad base64 are bad-syntax (3.7).
    for s in [
        format!("CREATE {} {} {}", &BOX[1..], group_id(), token_hash()),
        format!("CREATE {BOX} {} {}", zeros(16), token_hash()),
        format!("CREATE {BOX} {} {}", group_id(), zeros(32)),
        format!(
            "CREATE {BOX} {} {} general AAEC AAEC",
            group_id(),
            token_hash()
        ),
        format!("POST {BOX} {} AAEAAQ==", zeros(16)),
        format!("POST {BOX} -- AAEAAQ=="),
        format!("POST {BOX} - AAEAAQ="),
        format!("POST {BOX} - sha384:abc"),
        format!("POST {BOX} - AAEAAQ== groupinfo=AAE"),
        // next is a token hash: 48 bytes (5.2).
        format!("POST {BOX} - AAEAAQ== next={}", zeros(32)),
        format!("POST {BOX} - AAEAAQ== next=-"),
        format!("UPLOAD {BOX} {} -1", token()),
        format!("UPLOAD {BOX} {} 1.5", token()),
        format!("MUTE {BOX} {}", zeros(15)),
        format!("PAIR GET {}", &BOX[..25]),
        "PAIR PUT aaaaaaaaaaaaaaaaaaaaaaaaab AAEC".into(),
        "AUTH ~sam AAAA".into(),
        format!("AUTH ~sam {}", signature()),
        format!("AUTH alice@example.org {}", zeros(2419)),
        "REGISTER alice@example.org AQ== AQ==".into(),
        format!(
            "PUSH ADD http://push.example/a t {} {}",
            zeros(65),
            zeros(16)
        ),
        format!(
            "PUSH ADD https://push.example/a t {} {}",
            zeros(64),
            zeros(16)
        ),
        format!(
            "PUSH ADD https://push.example/a t {} {}",
            zeros(65),
            zeros(17)
        ),
        format!("WELCOME PUT {} AAEABg==", zeros(32)),
        "WELCOME DEL w.7".into(),
        format!("BACKUP PUT 0 {} AAE", blob()),
        format!("BACKUP PUT 0 sha256:{} {}", "5d".repeat(32), zeros(61)),
        "ADMIN DROP general".into(),
        "ADMIN BAN 999.1.1.1".into(),
        "INFO general".into(),
        "KEYPKG GET alice".into(),
        "KEYS PUT AQ".into(),
    ] {
        syntax(&s);
    }
}

#[test]
fn length_limits() {
    // A valid name that is only too long is too-long (3.7).
    too_long(&format!("GUEST {}", "a".repeat(33)));
    too_long(&format!("@ref={} ANON", "r".repeat(65)));
    too_long(&format!("@cid={} POST {BOX} - AAEAAQ==", "c".repeat(65)));
    too_long(&format!("ADMIN SET welcome {}", "w".repeat(513)));
    too_long(&format!("MEMBERS #{}", "r".repeat(65)));
    too_long(&format!(
        "PUSH DEL https://push.example/{}",
        "a".repeat(512)
    ));
    too_long(&format!(
        "KEYPKG ADD {}",
        "A".repeat(crate::mls::MAX_BASE64_LEN + 4)
    ));
    // A cid shorter than 16 characters breaks its grammar (7.6).
    syntax(&format!("@cid=short POST {BOX} - AAEAAQ=="));
    syntax(&format!("@cid POST {BOX} - AAEAAQ=="));
    syntax("@ref ANON");
}

#[test]
fn unknown_verbs_and_subcommands() {
    unknown("FOO", "FOO");
    unknown("foo bar", "FOO");
    // draft-02's commands are gone (Section 13).
    for verb in [
        "JOIN",
        "PART",
        "MSG",
        "HISTORY",
        "SYNC",
        "RELATED",
        "SET",
        "ROLE",
        "ROLES",
        "INVITE",
        "KICK",
        "BAN",
        "UNBAN",
        "ENC",
        "REPORTENC",
        "NAME",
        "TYPING",
        "READ",
        "BLOCK",
        "UNBLOCK",
        "KEY",
        "INIT",
        "COMMIT",
        "CONVS",
        "TEXT",
        "DELETE",
    ] {
        unknown(&format!("{verb} #general x"), verb);
    }
    // An unknown subcommand of a known verb is unknown-command too (3.8).
    unknown("KEYPKG FOO", "KEYPKG FOO");
    unknown("keys get x", "KEYS GET");
    unknown("PAIR DEL x", "PAIR DEL");
    unknown("presence maybe", "PRESENCE MAYBE");
    unknown("PUSH SEND x", "PUSH SEND");
    unknown("WELCOME ACK x", "WELCOME ACK");
    unknown("BACKUP ADD x", "BACKUP ADD");
    for sub in ["PURGE", "KEYS", "ADDKEY", "DELKEY", "FOO"] {
        unknown(&format!("ADMIN {sub} x"), &format!("ADMIN {sub}"));
    }
    assert_eq!(
        ParseError::UnknownVerb("KEYPKG FOO".into()).code(),
        ErrorCode::UnknownCommand
    );
}

#[test]
fn other_tags_are_ignored() {
    // Only ref, and cid on POST, are read (3.2).
    rt_as("@x-foo=1;seq=5 ANON", "ANON");
    rt_as("@cid=0123456789abcdef ANON", "ANON");
    rt_as("@ ANON", "ANON");
    // ... including bad values of tags this command does not read.
    rt_as("@cid=x INFO", "INFO");
    let r = rt(&format!(
        "@ref=a;cid=0123456789abcdef POST {BOX} - AAEAAQ=="
    ));
    let Command::Post { cid, .. } = r.command else {
        panic!()
    };
    assert_eq!(
        cid.map(|c| c.to_string()).as_deref(),
        Some("0123456789abcdef")
    );
    assert_eq!(r.ref_.map(|r| r.to_string()).as_deref(), Some("a"));
}

#[test]
fn ref_of_reads_a_bad_line() {
    let line = Line::parse("@ref=9 FOO bar").unwrap();
    assert!(Request::parse(&line).is_err());
    assert_eq!(
        Request::ref_of(&line).map(|r| r.to_string()).as_deref(),
        Some("9")
    );
    let line = Line::parse(&format!("@ref={} ANON", "r".repeat(65))).unwrap();
    assert_eq!(Request::ref_of(&line), None);
}

#[test]
fn text_is_kept() {
    let r = rt("QUIT  two  spaces\\n");
    assert_eq!(
        r.command,
        Command::Quit {
            message: " two  spaces\\n".into()
        }
    );
    let r = rt("ADMIN BAN ~sam  flood");
    let Command::Admin(AdminCommand::Ban { reason, target }) = r.command else {
        panic!()
    };
    assert_eq!(reason, " flood");
    assert_eq!(target.to_string(), "~sam");
}

#[test]
fn secrets_stay_out_of_debug() {
    let guest = parse("GUEST sam token=k3f9q2abcdefghij").unwrap();
    assert!(!format!("{guest:?}").contains("k3f9q2"));
    let post = parse(&format!("POST {BOX} {} AAEAAQ==", token())).unwrap();
    assert!(!format!("{post:?}").contains("3J0n"), "{post:?}");
    let push = parse(&format!(
        "PUSH ADD https://push.example/a t {} {}",
        zeros(65),
        "QUJDREVGR0hJSktMTU5PUA=="
    ))
    .unwrap();
    assert!(!format!("{push:?}").contains("QUJD"), "{push:?}");
}

#[test]
fn hand_built_requests_are_checked() {
    let empty_notice = Request::new(Command::Admin(AdminCommand::Notice {
        message: String::new(),
    }));
    assert!(empty_notice.validate().is_err());
    let bad_text = Request::new(Command::Quit {
        message: "a\nb".into(),
    });
    assert!(bad_text.try_to_line().is_err());
    // A setting whose key is known must use its own variant.
    let other = Request::new(Command::Admin(AdminCommand::Set(ServerSetting::Other {
        key: "anon".into(),
        value: "yes".into(),
    })));
    assert!(other.validate().is_err());
    let token = Request::new(Command::Ping {
        token: Some("a b".into()),
    });
    assert!(token.validate().is_err());
    let ok = Request::new(Command::Watch {
        uids: vec!["a@b.org".parse().unwrap(), "~sam".parse().unwrap()],
    });
    assert_eq!(ok.to_string(), "WATCH a@b.org,~sam");
}

#[test]
fn pong_gets_no_response() {
    for s in every_form() {
        let c = parse(&s).unwrap().command;
        assert_eq!(c.gets_response(), !matches!(c, Command::Pong { .. }), "{s}");
    }
}

// ---- kinds of connection (Section 13)

/// Section 13's first table: for each command form, the kinds that may
/// send it, as `n`, `a`, `g` and `s` for new, anonymous, guest and signed
/// in.
fn table() -> Vec<(String, &'static str)> {
    let (gid, th, tok, ps, r, sig, blob) = (
        group_id(),
        token_hash(),
        token(),
        pseudonym(),
        kp_ref(),
        signature(),
        blob(),
    );
    let key = zeros(65);
    let auth = zeros(16);
    vec![
        ("INFO".into(), "nags"),
        ("INFO #general".into(), "ags"),
        ("ANON".into(), "n"),
        ("GUEST sam".into(), "n"),
        (format!("AUTH alice@example.org {sig}"), "n"),
        (format!("REGISTER alice AQ== {sig}"), "n"),
        ("KEYS PUT - AQAB".into(), "nas"),
        (format!("PAIR PUT {BOX} AAEC"), "nas"),
        (format!("PAIR GET {BOX}"), "nas"),
        ("UNREGISTER alice@example.org".into(), "s"),
        (format!("CREATE {BOX} {gid} {th}"), "ag"),
        (format!("CREATE {BOX} {gid} {th} epoch=12"), "ag"),
        (
            format!("CREATE {BOX} {gid} {th} #general AAEABA== AAEC"),
            "s",
        ),
        // Signed in: only a public room's PublicMessages, which the
        // server tells from the framing (5.2, 12.6, 13).
        (format!("POST {BOX} {tok} AAEAAQ=="), "ags"),
        (format!("UPLOAD {BOX} {tok} 1"), "a"),
        (format!("REPORT {BOX} AQIDBA=="), "ags"),
        ("LIST".into(), "ags"),
        (format!("GROUPINFO {BOX}"), "ag"),
        (format!("MUTE {BOX} {ps}"), "s"),
        (format!("UNMUTE {BOX} {ps}"), "s"),
        (format!("FOLLOW {BOX}"), "ag"),
        (format!("UNFOLLOW {BOX}"), "ag"),
        (format!("FETCH {BOX} after=0"), "ag"),
        (format!("TOKEN {BOX} 41 {tok} {th}"), "ag"),
        ("PRESENCE ON".into(), "s"),
        ("PRESENCE OFF".into(), "s"),
        ("WATCH a@b.org".into(), "ags"),
        ("WHOIS a@b.org".into(), "ags"),
        ("MEMBERS #general".into(), "ags"),
        (
            format!("PUSH ADD https://p.example/a t {key} {auth} box={BOX}"),
            "a",
        ),
        (format!("PUSH DEL https://p.example/a box={BOX}"), "a"),
        (format!("PUSH ADD https://p.example/a t {key} {auth}"), "s"),
        ("PUSH DEL https://p.example/a".into(), "s"),
        ("PUSH LIST".into(), "s"),
        ("KEYPKG ADD AAEABQ==".into(), "s"),
        ("KEYPKG COUNT".into(), "s"),
        ("KEYPKG GET bob@example.net".into(), "ags"),
        (format!("WELCOME PUT {r} AAEABg=="), "ags"),
        (format!("WELCOME GET {r}"), "ags"),
        ("WELCOME LIST".into(), "s"),
        ("WELCOME DEL w7".into(), "s"),
        (format!("BLOB {blob} 1 box={BOX} token={tok}"), "ags"),
        (format!("BACKUP PUT 0 {blob} {}", zeros(61)), "s"),
        ("BACKUP GET".into(), "s"),
        ("BACKUP DEL".into(), "s"),
        ("ADMIN OPS".into(), "s"),
        ("ADMIN BAN ~sam".into(), "s"),
        ("ADMIN WHO".into(), "s"),
        (format!("ADMIN DROP {BOX}"), "s"),
        (format!("ADMIN MUTE {BOX} {ps}"), "s"),
        ("ADMIN UNREGISTER a@b.org".into(), "s"),
        ("ADMIN SET anon yes".into(), "s"),
        ("RESOLVE r7".into(), "s"),
        ("PING".into(), "nags"),
        ("PONG x".into(), "nags"),
        ("QUIT".into(), "nags"),
    ]
}

fn letter(kind: ConnectionKind) -> char {
    match kind {
        New => 'n',
        Anonymous => 'a',
        Guest => 'g',
        SignedIn => 's',
    }
}

#[test]
fn kinds_follow_section_13() {
    for (s, allowed) in table() {
        let c = parse(&s).unwrap_or_else(|e| panic!("{s}: {e}")).command;
        for kind in ConnectionKind::ALL {
            let may = allowed.contains(letter(kind));
            assert_eq!(c.kinds().contains(kind), may, "{s} on {kind}");
            let want = if may {
                Ok(())
            } else if c.sets_kind() {
                Err(ErrorCode::AlreadyAuthenticated)
            } else if kind == New {
                Err(ErrorCode::NotAuthenticated)
            } else {
                Err(ErrorCode::WrongConnection)
            };
            assert_eq!(c.check_kind(kind), want, "{s} on {kind}");
        }
    }
}

#[test]
fn every_form_is_in_the_table() {
    let verbs = |s: &str| {
        let c = parse(s).unwrap().command;
        (c.verb(), c.subcommand())
    };
    let table: Vec<_> = table().iter().map(|(s, _)| verbs(s)).collect();
    for s in every_form() {
        let c = parse(&s).unwrap().command;
        if let Command::Admin(_) = c {
            // One row of the table covers every ADMIN command.
            assert_eq!(c.kinds(), Kinds::SIGNED_IN, "{s}");
        } else {
            assert!(table.contains(&verbs(&s)), "{s} is not in the table");
        }
    }
}

#[test]
fn new_connections() {
    // 4.1: until it has a kind, a connection may send only INFO without a
    // room, ANON, GUEST, AUTH, REGISTER, KEYS PUT, PAIR, PING, PONG and
    // QUIT.
    let allowed: Vec<String> = every_form()
        .into_iter()
        .filter(|s| parse(s).unwrap().command.check_kind(New).is_ok())
        .collect();
    let mut verbs: Vec<&str> = allowed
        .iter()
        .map(|s| s.split(' ').next().unwrap())
        .collect();
    verbs.dedup();
    assert_eq!(
        verbs,
        [
            "INFO", "ANON", "GUEST", "AUTH", "REGISTER", "KEYS", "PAIR", "PING", "PONG", "QUIT"
        ]
    );
    assert!(!allowed.contains(&"INFO #general".to_owned()));
}

#[test]
fn blob_needs_a_permit_from_anonymous_and_guest_connections() {
    let without = parse(&format!("BLOB {} 1", blob())).unwrap().command;
    assert_eq!(without.check_kind(SignedIn), Ok(()));
    assert_eq!(without.check_kind(Anonymous), Err(ErrorCode::BadSyntax));
    assert_eq!(without.check_kind(Guest), Err(ErrorCode::BadSyntax));
    assert_eq!(without.check_kind(New), Err(ErrorCode::NotAuthenticated));
}

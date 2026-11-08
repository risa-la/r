//! Property tests of the typed lines (SPEC Section 13): every command and
//! server line, built from random valid values, parses and writes back
//! byte for byte; and lines made of random words from the protocol's
//! vocabulary never panic the parsers, and round-trip when they parse.

use proptest::collection::vec;
use proptest::prelude::*;
use risala_proto::command::Request;
use risala_proto::connection::ConnectionKind;
use risala_proto::line::Line;
use risala_proto::names::{BlobRef, BoxName};
use risala_proto::server::{ServerLine, ServerMessage};

/// Explicit case counts keep `cargo test` fast in debug builds. Set
/// `PROPTEST_CASES` to run every property with that many cases instead.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Values, as their canonical wire forms

fn boxname() -> impl Strategy<Value = String> {
    any::<[u8; 16]>().prop_map(|b| BoxName::from_bytes(b).to_string())
}

fn blob_ref() -> impl Strategy<Value = String> {
    any::<[u8; 48]>().prop_map(|h| BlobRef::from_hash(h).to_string())
}

/// Strict base64 of exactly `n` bytes.
fn fixed(n: usize) -> impl Strategy<Value = String> {
    use base64::Engine as _;
    vec(any::<u8>(), n).prop_map(|b| base64::engine::general_purpose::STANDARD.encode(b))
}

/// Strict base64 of 1 to 64 bytes: opaque MLS data and the like.
fn data() -> impl Strategy<Value = String> {
    use base64::Engine as _;
    vec(any::<u8>(), 1..64).prop_map(|b| base64::engine::general_purpose::STANDARD.encode(b))
}

/// MLS data in a line, or a blob-ref in its place (12.12).
fn or_blob() -> impl Strategy<Value = String> {
    prop_oneof![3 => data(), 1 => blob_ref()]
}

fn name() -> impl Strategy<Value = String> {
    "[a-z0-9]([a-z0-9._-]{0,6}[a-z0-9_-])?"
}

fn identity() -> impl Strategy<Value = String> {
    (name(), "[a-z0-9]{1,8}", "[a-z]{2,4}").prop_map(|(n, d, t)| format!("{n}@{d}.{t}"))
}

fn uid() -> impl Strategy<Value = String> {
    prop_oneof![identity(), name().prop_map(|n| format!("~{n}"))]
}

fn room() -> impl Strategy<Value = String> {
    name().prop_map(|n| format!("#{n}"))
}

fn id() -> impl Strategy<Value = String> {
    "[a-z0-9_-]{1,20}"
}

fn number() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("0".to_owned()),
        (1..=i64::MAX as u64).prop_map(|n| n.to_string())
    ]
}

fn positive() -> impl Strategy<Value = String> {
    (1..=i64::MAX as u64).prop_map(|n| n.to_string())
}

/// Text without control characters, possibly with leading spaces.
fn text() -> impl Strategy<Value = String> {
    "[ -~é€👋]{0,30}"
}

/// Text that is not empty.
fn required_text() -> impl Strategy<Value = String> {
    "[!-~é€👋][ -~é€👋]{0,29}"
}

fn token() -> impl Strategy<Value = String> {
    "[!-~]{1,20}"
}

fn timestamp() -> impl Strategy<Value = String> {
    (0..=risala_proto::time::Timestamp::MAX.unix_millis()).prop_map(|ms| {
        let t = risala_proto::time::Timestamp::from_unix_millis(ms).unwrap();
        t.to_string()
    })
}

fn push_url() -> impl Strategy<Value = String> {
    "[a-z0-9/._-]{1,30}".prop_map(|p| format!("https://push.example/{p}"))
}

/// An optional ` key=value`, for options.
fn opt(key: &'static str, value: impl Strategy<Value = String>) -> impl Strategy<Value = String> {
    proptest::option::of(value)
        .prop_map(move |v| v.map_or(String::new(), |v| format!(" {key}={v}")))
}

/// Optional text after a space, as `[<reason...>]` writes it.
fn opt_text() -> impl Strategy<Value = String> {
    text().prop_map(|t| if t.is_empty() { t } else { format!(" {t}") })
}

fn sep(s: String) -> String {
    if s.is_empty() { s } else { format!(" {s}") }
}

// ---------------------------------------------------------------------------
// Commands

fn command() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("INFO".to_owned()),
        room().prop_map(|r| format!("INFO {r}")),
        Just("ANON".to_owned()),
        (name(), opt("token", id())).prop_map(|(n, t)| format!("GUEST {n}{t}")),
        (identity(), fixed(2420)).prop_map(|(i, s)| format!("AUTH {i} {s}")),
        (name(), data(), fixed(2420)).prop_map(|(n, k, s)| format!("REGISTER {n} {k} {s}")),
        (
            prop_oneof![Just("-".to_owned()), blob_ref()],
            prop_oneof![data(), blob_ref()]
        )
            .prop_map(|(a, k)| format!("KEYS PUT {a} {k}")),
        (boxname(), data()).prop_map(|(i, d)| format!("PAIR PUT {i} {d}")),
        boxname().prop_map(|i| format!("PAIR GET {i}")),
        uid().prop_map(|u| format!("UNREGISTER {u}")),
        (boxname(), fixed(32), fixed(48), opt("epoch", positive()))
            .prop_map(|(b, g, h, e)| format!("CREATE {b} {g} {h}{e}")),
        (
            boxname(),
            fixed(32),
            fixed(48),
            room(),
            or_blob(),
            or_blob()
        )
            .prop_map(|(b, g, h, r, i, t)| format!("CREATE {b} {g} {h} {r} {i} {t}")),
        (
            proptest::option::of("[!-:<-~]{16,64}"),
            boxname(),
            prop_oneof![Just("-".to_owned()), fixed(32)],
            or_blob(),
            any::<bool>(),
            opt("groupinfo", or_blob()),
        )
            .prop_map(|(cid, b, t, m, live, g)| {
                let cid = cid.map_or(String::new(), |c| format!("@cid={c} "));
                let live = if live { " live=yes" } else { "" };
                format!("{cid}POST {b} {t} {m}{live}{g}")
            }),
        (boxname(), fixed(32), number()).prop_map(|(b, t, n)| format!("UPLOAD {b} {t} {n}")),
        (boxname(), data()).prop_map(|(b, r)| format!("REPORT {b} {r}")),
        (opt("after", room()), opt("limit", positive())).prop_map(|(a, l)| format!("LIST{a}{l}")),
        boxname().prop_map(|b| format!("GROUPINFO {b}")),
        (boxname(), fixed(16), opt("hours", positive()))
            .prop_map(|(b, p, h)| format!("MUTE {b} {p}{h}")),
        (boxname(), fixed(16)).prop_map(|(b, p)| format!("UNMUTE {b} {p}")),
        (boxname(), opt("quiet", "[!-~]{1,64}")).prop_map(|(b, q)| format!("FOLLOW {b}{q}")),
        boxname().prop_map(|b| format!("UNFOLLOW {b}")),
        (boxname(), number(), fixed(32), fixed(48))
            .prop_map(|(b, e, t, h)| format!("TOKEN {b} {e} {t} {h}")),
        (
            boxname(),
            number(),
            opt("limit", positive()),
            opt("leaf", any::<u32>().prop_map(|n| n.to_string()))
        )
            .prop_map(|(b, a, l, f)| format!("FETCH {b} after={a}{l}{f}")),
        prop_oneof![
            Just("PRESENCE ON".to_owned()),
            Just("PRESENCE OFF".to_owned())
        ],
        vec(uid(), 0..5).prop_map(|u| format!("WATCH{}", sep(u.join(",")))),
        uid().prop_map(|u| format!("WHOIS {u}")),
        room().prop_map(|r| format!("MEMBERS {r}")),
        (
            push_url(),
            "[!-~]{1,64}",
            fixed(65),
            fixed(16),
            opt("box", boxname())
        )
            .prop_map(|(u, t, k, a, b)| format!("PUSH ADD {u} {t} {k} {a}{b}")),
        (push_url(), opt("box", boxname())).prop_map(|(u, b)| format!("PUSH DEL {u}{b}")),
        Just("PUSH LIST".to_owned()),
        data().prop_map(|k| format!("KEYPKG ADD {k}")),
        Just("KEYPKG COUNT".to_owned()),
        uid().prop_map(|u| format!("KEYPKG GET {u}")),
        (fixed(48), or_blob()).prop_map(|(r, w)| format!("WELCOME PUT {r} {w}")),
        Just("WELCOME LIST".to_owned()),
        id().prop_map(|i| format!("WELCOME DEL {i}")),
        (fixed(48), any::<bool>())
            .prop_map(|(r, l)| { format!("WELCOME GET {r}{}", if l { " light=yes" } else { "" }) }),
        (
            blob_ref(),
            number(),
            proptest::option::of((boxname(), fixed(32)))
        )
            .prop_map(|(h, n, p)| {
                let p = p.map_or(String::new(), |(b, t)| format!(" box={b} token={t}"));
                format!("BLOB {h} {n}{p}")
            }),
        (
            any::<u32>(),
            blob_ref(),
            fixed(61),
            opt("files", blob_ref())
        )
            .prop_map(|(g, h, k, f)| format!("BACKUP PUT {g} {h} {k}{f}")),
        Just("BACKUP GET".to_owned()),
        Just("BACKUP DEL".to_owned()),
        admin(),
        id().prop_map(|i| format!("RESOLVE {i}")),
        proptest::option::of(token()).prop_map(|t| format!("PING{}", sep(t.unwrap_or_default()))),
        token().prop_map(|t| format!("PONG {t}")),
        opt_text().prop_map(|t| format!("QUIT{t}")),
    ]
}

fn ban_target() -> impl Strategy<Value = String> {
    prop_oneof![
        identity(),
        "[a-z0-9]{1,8}\\.[a-z]{2,4}".prop_map(|d| format!("*@{d}")),
        name().prop_map(|n| format!("~{n}")),
        any::<std::net::Ipv4Addr>().prop_map(|a| a.to_string()),
    ]
}

fn admin() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("ADMIN OPS".to_owned()),
        uid().prop_map(|u| format!("ADMIN OP {u}")),
        uid().prop_map(|u| format!("ADMIN DEOP {u}")),
        (ban_target(), opt_text()).prop_map(|(t, r)| format!("ADMIN BAN {t}{r}")),
        ban_target().prop_map(|t| format!("ADMIN UNBAN {t}")),
        Just("ADMIN BANS".to_owned()),
        Just("ADMIN WHO".to_owned()),
        (uid(), opt_text()).prop_map(|(u, r)| format!("ADMIN DISCONNECT {u}{r}")),
        required_text().prop_map(|t| format!("ADMIN NOTICE {t}")),
        (opt("after", room()), opt("limit", positive()))
            .prop_map(|(a, l)| format!("ADMIN ROOMS{a}{l}")),
        (prop_oneof![room(), boxname()], opt_text())
            .prop_map(|(t, r)| format!("ADMIN DROP {t}{r}")),
        (boxname(), fixed(16), opt("hours", positive()))
            .prop_map(|(b, p, h)| format!("ADMIN MUTE {b} {p}{h}")),
        (boxname(), fixed(16)).prop_map(|(b, p)| format!("ADMIN UNMUTE {b} {p}")),
        Just("ADMIN REPORTS".to_owned()),
        uid().prop_map(|u| format!("ADMIN UNREGISTER {u}")),
        prop_oneof![
            any::<bool>().prop_map(|b| format!("anon {}", if b { "yes" } else { "no" })),
            any::<bool>().prop_map(|b| format!("guests {}", if b { "yes" } else { "no" })),
            any::<bool>()
                .prop_map(|b| { format!("registration {}", if b { "open" } else { "closed" }) }),
            (7..=u32::MAX).prop_map(|d| format!("retention {d}")),
            opt_text().prop_map(|t| format!("welcome{t}")),
        ]
        .prop_map(|s| format!("ADMIN SET {s}")),
    ]
}

// ---------------------------------------------------------------------------
// Server lines

fn server_line() -> impl Strategy<Value = String> {
    let hex = "[0-9a-f]{32,128}".prop_filter("even", |s| s.len() % 2 == 0);
    prop_oneof![
        (any::<u32>(), "[a-z0-9]{1,10}\\.[a-z]{2,4}", hex, opt_text())
            .prop_map(|(v, h, n, m)| format!("RISALA {v} {h} {n}{m}")),
        vec(("[a-z][a-z0-9-]{0,8}", token()), 0..4).prop_map(|kv| {
            let values: Vec<String> = kv.iter().map(|(k, v)| format!(" {k}={v}")).collect();
            let mut seen = std::collections::HashSet::new();
            let values: String = values
                .into_iter()
                .zip(&kv)
                .filter(|(_, (k, _))| seen.insert(k.clone()))
                .map(|(s, _)| s)
                .collect();
            format!("OK{values}")
        }),
        (
            proptest::option::of(0..=i64::MAX as u64),
            "[a-z][a-z0-9-]{0,15}",
            opt_text()
        )
            .prop_map(|(r, c, m)| {
                let r = r.map_or(String::new(), |r| format!("@retry={r} "));
                format!("{r}ERR {c}{m}")
            }),
        (
            proptest::option::of((positive(), timestamp())),
            boxname(),
            or_blob()
        )
            .prop_map(|(st, b, m)| {
                let tags = st.map_or(String::new(), |(s, t)| format!("@seq={s};t={t} "));
                format!("{tags}POST {b} {m}")
            }),
        (room(), boxname(), number(), opt_text())
            .prop_map(|(r, b, n, t)| format!("ROOM {r} {b} {n}{t}")),
        (boxname(), number(), number(), or_blob(), or_blob())
            .prop_map(|(b, e, s, g, t)| format!("GROUPINFO {b} {e} {s} {g} {t}")),
        (boxname(), uid()).prop_map(|(b, u)| format!("GONE {b} {u}")),
        (boxname(), opt_text()).prop_map(|(b, r)| format!("DROP {b}{r}")),
        (uid(), "[a-z][a-z0-9-]{0,8}").prop_map(|(u, p)| format!("USER {u} {p}")),
        (
            room(),
            uid(),
            prop::sample::select(vec!["owner", "mod", "member"]),
            "online|offline"
        )
            .prop_map(|(r, u, role, p)| format!("MEMBER {r} {u} {role} {p}")),
        ("online|offline", vec(uid(), 1..5))
            .prop_map(|(p, u)| format!("PRESENCE {p} {}", u.join(","))),
        (
            id(),
            timestamp(),
            fixed(16),
            proptest::option::of(uid()),
            boxname(),
            data()
        )
            .prop_map(|(i, t, p, f, b, r)| {
                let f = f.map_or(String::new(), |f| format!(";from={f}"));
                format!("@report={i};t={t};pseudonym={p}{f} REPORT {b} {r}")
            }),
        id().prop_map(|i| format!("RESOLVED {i}")),
        (number(), blob_ref()).prop_map(|(i, h)| format!("RECORD {i} {h}")),
        (boxname(), data()).prop_map(|(i, d)| format!("PAIR {i} {d}")),
        (push_url(), "[!-~]{1,64}").prop_map(|(u, t)| format!("PUSH {u} {t}")),
        (uid(), data()).prop_map(|(u, k)| format!("KEYPKG {u} {k}")),
        (id(), or_blob()).prop_map(|(i, w)| format!("WELCOME {i} {w}")),
        (
            any::<u32>(),
            blob_ref(),
            fixed(61),
            opt("files", blob_ref())
        )
            .prop_map(|(g, h, k, f)| format!("BACKUP {g} {h} {k}{f}")),
        required_text().prop_map(|t| format!("NOTICE {t}")),
        uid().prop_map(|u| format!("OP {u}")),
        (identity(), opt_text()).prop_map(|(t, r)| format!("SERVERBAN {t}{r}")),
        (
            proptest::option::of(uid()),
            any::<std::net::IpAddr>(),
            proptest::option::of(any::<u16>()),
            timestamp()
        )
            .prop_map(|(u, ip, port, t)| {
                let u = u.unwrap_or_else(|| "-".into());
                let a = match port {
                    Some(port) => std::net::SocketAddr::new(ip, port).to_string(),
                    None => ip.to_string(),
                };
                format!("CONNECTION {u} {a} {t}")
            }),
        token().prop_map(|t| format!("PING {t}")),
        opt_text().prop_map(|t| format!("BYE{t}")),
    ]
}

proptest! {
    #![proptest_config(config(512))]

    /// Every command form, from random valid values, parses, writes back
    /// unchanged, and has at least one kind of connection that may send
    /// it (Section 13).
    #[test]
    fn commands_round_trip(line in command(), ref_ in proptest::option::of("[!-:<-~]{1,64}")) {
        let line = match (&ref_, line.strip_prefix('@')) {
            (None, _) => line.clone(),
            (Some(r), Some(rest)) => format!("@ref={r};{rest}"),
            (Some(r), None) => format!("@ref={r} {line}"),
        };
        let request: Request = line.parse().map_err(|e| TestCaseError::fail(format!("{line}: {e}")))?;
        prop_assert_eq!(request.to_line().to_string(), line.as_str());
        prop_assert_eq!(request.validate(), Ok(()));
        prop_assert!(ConnectionKind::ALL.iter().any(|&k| request.command.check_kind(k).is_ok()));
        // Lower-case verbs and subcommands mean the same.
        let lower = Line::parse(&line).unwrap();
        let mut lowered = lower.to_string();
        if let Some(at) = lowered.find(request.command.verb()) {
            let end = at + request.command.verb().len();
            lowered.replace_range(at..end, &request.command.verb().to_ascii_lowercase());
        }
        prop_assert_eq!(lowered.parse::<Request>(), Ok(request));
    }

    /// Every server line, from random valid values, parses as a known
    /// line and writes back unchanged.
    #[test]
    fn server_lines_round_trip(line in server_line()) {
        let msg: ServerMessage = line.parse().map_err(|e| TestCaseError::fail(format!("{line}: {e}")))?;
        prop_assert!(!matches!(msg.line, ServerLine::Unknown(_)), "{}", line);
        prop_assert_eq!(msg.to_line().to_string(), line.as_str());
    }
}

// ---------------------------------------------------------------------------
// Token soup

/// A word from the protocol's vocabulary, or a random token.
fn word() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => prop::sample::select(vec![
            "INFO", "ANON", "GUEST", "AUTH", "REGISTER", "KEYS", "PUT", "GET", "PAIR", "CREATE",
            "POST", "UPLOAD", "REPORT", "LIST", "GROUPINFO", "MUTE", "UNMUTE", "FOLLOW",
            "UNFOLLOW", "FETCH", "TOKEN", "PRESENCE", "ON", "OFF", "WATCH", "WHOIS", "MEMBERS", "PUSH",
            "ADD", "DEL", "KEYPKG", "COUNT", "WELCOME", "BLOB", "BACKUP", "ADMIN", "SET", "BAN",
            "DROP", "RESOLVE", "PING", "PONG", "QUIT", "OK", "ERR", "RISALA", "ROOM", "GONE",
            "USER", "MEMBER", "RESOLVED", "RECORD", "NOTICE", "OP", "SERVERBAN", "CONNECTION",
            "BYE", "-", "0", "1", "after=0", "limit=1", "live=yes", "light=yes", "box=", "epoch=1", "files=",
            "token=", "#general", "~sam", "alice@example.org", "@ref=1", "@seq=1;t=x",
            "AAAA", "AA==", "anon",
        ])
        .prop_map(str::to_owned),
        1 => boxname(),
        1 => blob_ref(),
        1 => fixed(32),
        1 => fixed(16),
        1 => token(),
    ]
}

proptest! {
    #![proptest_config(config(2048))]

    /// No line made of protocol words panics either parser, and whatever
    /// parses writes back to a line that parses to the same value.
    #[test]
    fn token_soup(words in vec(word(), 1..8)) {
        let s = words.join(" ");
        let Ok(line) = Line::parse(&s) else { return Ok(()) };
        if let Ok(request) = Request::parse(&line) {
            let out = request.to_line();
            prop_assert_eq!(Request::parse(&out), Ok(request.clone()));
            prop_assert_eq!(out.to_string().parse::<Request>(), Ok(request.clone()));
            for kind in ConnectionKind::ALL {
                let _ = request.command.check_kind(kind);
            }
        }
        if let Ok(msg) = ServerMessage::parse(&line) {
            let out = msg.to_line();
            prop_assert_eq!(ServerMessage::parse(&out), Ok(msg.clone()));
        }
    }
}

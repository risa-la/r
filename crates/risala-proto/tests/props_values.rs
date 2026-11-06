//! Property tests for values: names (SPEC 3.5, 5.7, 10.2), timestamps
//! (3.5), text escaping (3.4), mentions (5.5) and the small shared types.
//!
//! Generators follow the grammar of 3.5, so the round trips run on valid
//! values. Arbitrary strings check that parsing never panics and that
//! whatever parses round-trips.

use std::collections::HashSet;
use std::fmt::{Debug, Display};
use std::net::IpAddr;
use std::str::FromStr;

use proptest::collection::vec;
use proptest::prelude::*;
use risala_proto::error::{ErrorCode, ParseError};
use risala_proto::frame::check_line;
use risala_proto::line::Line;
use risala_proto::names::{
    BlockTarget, Conv, Domain, Id, Identity, IpPrefix, Name, Room, Seq, ServerBanTarget, Uid,
};
use risala_proto::text::{escape, mentions, unescape};
use risala_proto::time::Timestamp;
use risala_proto::types::{
    Cid, GuestAccess, InfoRole, Presence, PushReason, PushTag, Ref, Relation, Role, RoomRetention,
    RoomSetting, ServerRetention, ServerSetting, parse_u64, parse_yes_no,
};

/// Explicit case counts keep `cargo test` fast in debug builds. Set
/// `PROPTEST_CASES` to run every property with that many cases instead.
/// Failures are not persisted to files; a minimal failing case found here
/// becomes a named test instead.
fn config(cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(cases);
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn fail(e: impl Display) -> TestCaseError {
    TestCaseError::fail(e.to_string())
}

/// `s` parses as a `T` that displays as `s`, and `s` in upper case parses
/// to the same value (3.5: names are case-insensitive).
fn check_canonical<T>(s: &str) -> Result<T, TestCaseError>
where
    T: FromStr<Err = ParseError> + Display + PartialEq + Debug,
{
    let value: T = s.parse().map_err(|e| fail(format!("{s:?}: {e}")))?;
    prop_assert_eq!(value.to_string(), s);
    let upper = s.to_ascii_uppercase();
    let folded: T = upper.parse().map_err(|e| fail(format!("{upper:?}: {e}")))?;
    prop_assert_eq!(&folded, &value);
    Ok(value)
}

/// Parsing `s` as a `T` never panics. If it succeeds, the display parses
/// back to the same value and displays the same again.
fn check_any<T>(s: &str) -> Result<Option<T>, TestCaseError>
where
    T: FromStr<Err = ParseError> + Display + PartialEq + Debug,
{
    let Ok(value) = s.parse::<T>() else {
        return Ok(None);
    };
    let shown = value.to_string();
    let again: T = shown.parse().map_err(|e| fail(format!("{shown:?}: {e}")))?;
    prop_assert_eq!(&again, &value);
    prop_assert_eq!(again.to_string(), shown);
    Ok(Some(value))
}

// ---------------------------------------------------------------------------
// Generators for 3.5

/// `name = alnum *31( alnum / "." / "_" / "-" )`.
fn name() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9._-]{0,31}"
}

/// `label = alnum [ *61( alnum / "-" ) alnum ]`, mostly short.
fn label() -> impl Strategy<Value = String> {
    prop_oneof![
        6 => "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?",
        1 => "xn--[a-z0-9]{1,10}",
        1 => "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
    ]
}

/// `domain = label 1*( "." label )`, at most 253 characters.
fn domain() -> impl Strategy<Value = String> {
    vec(label(), 2..5)
        .prop_map(|labels| labels.join("."))
        .prop_filter("a domain has at most 253 characters", |d| d.len() <= 253)
}

fn identity() -> impl Strategy<Value = String> {
    (name(), domain()).prop_map(|(n, d)| format!("{n}@{d}"))
}

fn guest() -> impl Strategy<Value = String> {
    name().prop_map(|n| format!("~{n}"))
}

fn uid() -> impl Strategy<Value = String> {
    prop_oneof![guest(), identity()]
}

/// `room = "#" alnum *63( alnum / "." / "_" / "-" )`.
fn room() -> impl Strategy<Value = String> {
    "#[a-z0-9][a-z0-9._-]{0,63}"
}

/// `id = 1*64( alnum / "-" / "_" )`.
fn id() -> impl Strategy<Value = String> {
    "[a-z0-9_-]{1,64}"
}

/// A CIDR prefix in normalised form (10.2).
fn prefix() -> impl Strategy<Value = IpPrefix> {
    (any::<IpAddr>(), any::<u8>()).prop_map(|(addr, len)| {
        let len = match addr {
            IpAddr::V4(_) => len % 33,
            IpAddr::V6(_) => len % 129,
        };
        IpPrefix::new(addr, len).expect("length is in range")
    })
}

/// Strings made of the characters names use, plus a few that they do not.
fn name_like() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[a-zA-Z0-9.@~#*_/:-]{0,40}",
        "[~#*]?[a-zA-Z0-9]{1,6}([.@-][a-zA-Z0-9]{1,6}){0,4}(/[0-9]{1,3})?",
    ]
}

// ---------------------------------------------------------------------------
// Names

proptest! {
    #![proptest_config(config(256))]

    /// Every name type from the grammar displays as written, and folds
    /// upper case to the same value (3.5).
    #[test]
    fn names_round_trip(
        name in name(),
        domain in domain(),
        guest in guest(),
        identity in identity(),
        room in room(),
        id in id(),
    ) {
        check_canonical::<Name>(&name)?;
        check_canonical::<Domain>(&domain)?;
        check_canonical::<Id>(&id)?;
        let room_value = check_canonical::<Room>(&room)?;
        prop_assert_eq!(room_value.bare(), &room[1..]);
        prop_assert_eq!(Room::from_bare(room_value.bare()), Ok(room_value.clone()));
        prop_assert_eq!(check_canonical::<Conv>(&room)?, Conv::Room(room_value));

        let g = check_canonical::<Uid>(&guest)?;
        prop_assert!(g.is_guest());
        prop_assert_eq!(g.name(), &guest[1..]);
        prop_assert_eq!(g.domain(), None);
        prop_assert_eq!(g.to_identity(), None);
        prop_assert_eq!(Uid::guest(&guest[1..].parse::<Name>()?), g.clone());
        prop_assert_eq!(check_canonical::<Conv>(&guest)?, Conv::Uid(g));
        prop_assert!(guest.parse::<Identity>().is_err());

        let i = check_canonical::<Uid>(&identity)?;
        let (n, d) = identity.split_once('@').unwrap();
        prop_assert!(i.is_identity());
        prop_assert_eq!(i.name(), n);
        prop_assert_eq!(i.domain(), Some(d));
        let ident = check_canonical::<Identity>(&identity)?;
        prop_assert_eq!(Identity::new(&n.parse()?, &d.parse()?), ident.clone());
        prop_assert_eq!(ident.to_uid(), i.clone());
        prop_assert_eq!(check_canonical::<Conv>(&identity)?, Conv::Uid(i));
    }

    /// `seq` from 1 to 2^63-1 round-trips; 0, 2^63 and leading zeros do
    /// not parse (3.5).
    #[test]
    fn seq_round_trips(n in 1..=i64::MAX as u64, zeros in 1..3usize) {
        let s = n.to_string();
        let seq = check_canonical::<Seq>(&s)?;
        prop_assert_eq!(seq.get(), n);
        prop_assert_eq!(Seq::new(n), Some(seq));
        prop_assert_eq!(Seq::parse_or_zero(&s), Ok(Some(seq)));
        let padded = format!("{}{s}", "0".repeat(zeros));
        prop_assert!(padded.parse::<Seq>().is_err());
        prop_assert!("0".parse::<Seq>().is_err());
        prop_assert_eq!(Seq::parse_or_zero("0"), Ok(None));
        prop_assert!((i64::MAX as u64 + 1).to_string().parse::<Seq>().is_err());
    }

    /// Block targets (5.7) and ban targets (10.2) round-trip.
    #[test]
    fn targets_round_trip(
        identity in identity(),
        domain in domain(),
        guest in name(),
        addr in any::<IpAddr>(),
        prefix in prefix(),
    ) {
        let wild = format!("*@{domain}");
        prop_assert!(matches!(check_canonical::<BlockTarget>(&identity)?, BlockTarget::Identity(_)));
        prop_assert!(matches!(check_canonical::<BlockTarget>(&wild)?, BlockTarget::Domain(_)));
        let guest_target = format!("~{guest}");
        prop_assert!(guest_target.parse::<BlockTarget>().is_err());

        prop_assert!(matches!(check_canonical::<ServerBanTarget>(&identity)?, ServerBanTarget::Identity(_)));
        prop_assert!(matches!(check_canonical::<ServerBanTarget>(&wild)?, ServerBanTarget::Domain(_)));
        let g = format!("~{guest}");
        prop_assert!(matches!(check_canonical::<ServerBanTarget>(&g)?, ServerBanTarget::Guest(_)));
        prop_assert_eq!(
            check_canonical::<ServerBanTarget>(&addr.to_string())?,
            ServerBanTarget::Address(addr)
        );
        prop_assert_eq!(
            check_canonical::<ServerBanTarget>(&prefix.to_string())?,
            ServerBanTarget::Prefix(prefix)
        );
        prop_assert_eq!(check_canonical::<IpPrefix>(&prefix.to_string())?, prefix);
    }

    /// A prefix with host bits set parses to its normalised form, which
    /// contains the address it was written with (10.2).
    #[test]
    fn prefixes_normalise(addr in any::<IpAddr>(), len in any::<u8>()) {
        let len = match addr {
            IpAddr::V4(_) => len % 33,
            IpAddr::V6(_) => len % 129,
        };
        let written = format!("{addr}/{len}");
        let parsed = check_any::<IpPrefix>(&written)?
            .ok_or_else(|| fail(format!("{written:?} did not parse")))?;
        prop_assert_eq!(parsed.prefix_len(), len);
        prop_assert!(parsed.contains(addr));
        prop_assert_eq!(parsed, IpPrefix::new(parsed.addr(), len)?);
    }

    /// Names that are only too long are `TooLong`, so a server replies
    /// `ERR too-long` (3.5).
    #[test]
    fn long_names_are_too_long(
        name in "[a-z0-9][a-z0-9._-]{32,40}",
        room in "#[a-z0-9][a-z0-9._-]{64,70}",
        id in "[a-z0-9_-]{65,70}",
        label in "[a-z0-9][a-z0-9-]{62,66}[a-z0-9]",
    ) {
        prop_assert_eq!(name.parse::<Name>(), Err(ParseError::TooLong));
        prop_assert_eq!(format!("~{name}").parse::<Uid>(), Err(ParseError::TooLong));
        prop_assert_eq!(room.parse::<Room>(), Err(ParseError::TooLong));
        prop_assert_eq!(id.parse::<Id>(), Err(ParseError::TooLong));
        prop_assert_eq!(format!("{label}.org").parse::<Domain>(), Err(ParseError::TooLong));
    }

    /// No string panics any name parser, and whatever parses
    /// round-trips. Names display as the input folded to lower case.
    #[test]
    fn any_name_round_trips(s in name_like()) {
        let lower = s.to_ascii_lowercase();
        if let Some(v) = check_any::<Name>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<Domain>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<Uid>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<Identity>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<Room>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<Conv>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<Id>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<BlockTarget>(&s)? { prop_assert_eq!(v.to_string(), lower.as_str()); }
        if let Some(v) = check_any::<Seq>(&s)? { prop_assert_eq!(v.to_string(), s.as_str()); }
        check_any::<ServerBanTarget>(&s)?;
        check_any::<IpPrefix>(&s)?;
        let _ = Seq::parse_or_zero(&s);
        let _ = Room::from_bare(&s);
    }
}

// ---------------------------------------------------------------------------
// Timestamps

/// A slow, obvious calendar: the wire form of `ms`, counting whole years
/// and months from 1970.
fn naive_timestamp(ms: u64) -> String {
    let leap = |y: u64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mut days = ms / 86_400_000;
    let rest = ms % 86_400_000;
    let mut year = 1970;
    loop {
        let len = if leap(year) { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        year += 1;
    }
    let lens = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    while days >= lens[month] {
        days -= lens[month];
        month += 1;
    }
    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        month + 1,
        days + 1,
        rest / 3_600_000,
        rest / 60_000 % 60,
        rest / 1000 % 60,
        rest % 1000
    )
}

/// Whether the fields make a timestamp in range (3.5).
fn naive_valid(y: u64, mo: u64, d: u64, h: u64, mi: u64, s: u64) -> bool {
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_len = match mo {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1970..=9999).contains(&y)
        && (1..=12).contains(&mo)
        && (1..=month_len).contains(&d)
        && h < 24
        && mi < 60
        && s < 60
}

proptest! {
    #![proptest_config(config(256))]

    /// Any millisecond count in range has the wire form a naive calendar
    /// gives, and parses back from it, in upper or lower case (3.5).
    #[test]
    fn timestamp_round_trips(ms in 0..=Timestamp::MAX.unix_millis()) {
        let t = Timestamp::from_unix_millis(ms).unwrap();
        prop_assert_eq!(t.unix_millis(), ms);
        let s = t.to_string();
        prop_assert_eq!(&s, &naive_timestamp(ms));
        prop_assert_eq!(s.parse::<Timestamp>(), Ok(t));
        prop_assert_eq!(s.to_ascii_lowercase().parse::<Timestamp>(), Ok(t));
        prop_assert_eq!(Timestamp::from_system_time(t.to_system_time()), Some(t));
    }

    /// Timestamps, their millisecond counts and their wire forms all sort
    /// the same way (3.5).
    #[test]
    fn timestamp_order(
        a in 0..=Timestamp::MAX.unix_millis(),
        b in prop_oneof![0..=Timestamp::MAX.unix_millis(), 0..100_000u64],
    ) {
        let (ta, tb) = (Timestamp::from_unix_millis(a).unwrap(), Timestamp::from_unix_millis(b).unwrap());
        prop_assert_eq!(ta.cmp(&tb), a.cmp(&b));
        prop_assert_eq!(ta.to_string().cmp(&tb.to_string()), a.cmp(&b));
    }

    /// Past the end of the range there is no timestamp.
    #[test]
    fn timestamp_out_of_range(ms in Timestamp::MAX.unix_millis() + 1..) {
        prop_assert_eq!(Timestamp::from_unix_millis(ms), None);
    }

    /// A string of the right shape parses exactly when its fields are a
    /// real date and time in range, and then displays as written (3.5).
    #[test]
    fn timestamp_fields(
        y in prop_oneof![1965..=2105u64, 0..=9999u64],
        mo in 0..=13u64,
        d in 0..=32u64,
        h in 0..=24u64,
        mi in 0..=60u64,
        s in 0..=60u64,
        milli in 0..=999u64,
        lower in any::<bool>(),
    ) {
        let (t, z) = if lower { ('t', 'z') } else { ('T', 'Z') };
        let text = format!("{y:04}-{mo:02}-{d:02}{t}{h:02}:{mi:02}:{s:02}.{milli:03}{z}");
        let parsed = text.parse::<Timestamp>();
        prop_assert_eq!(parsed.is_ok(), naive_valid(y, mo, d, h, mi, s), "{}", text);
        if let Ok(ts) = parsed {
            prop_assert_eq!(ts.to_string(), text.to_ascii_uppercase());
        }
    }

    /// No string panics the timestamp parser, and whatever parses
    /// displays back the same, apart from the case of `T` and `Z`.
    #[test]
    fn any_timestamp_round_trips(
        s in prop_oneof![
            any::<String>(),
            "[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{1,4}[Zz+]",
            "[0-9Tt:.Zz+-]{20,26}",
        ]
    ) {
        if let Some(t) = check_any::<Timestamp>(&s)? {
            prop_assert_eq!(t.to_string(), s.to_ascii_uppercase());
        }
    }
}

// ---------------------------------------------------------------------------
// Text

/// Characters for user input, with backslashes, `n`, line breaks and
/// control characters weighted up.
fn input_char() -> impl Strategy<Value = char> {
    prop_oneof![
        3 => Just('\\'),
        2 => Just('n'),
        2 => Just('\n'),
        1 => Just('\r'),
        1 => Just('\t'),
        3 => Just(' '),
        4 => prop::char::range('!', '~'),
        1 => prop::sample::select(vec!['é', '\u{85}', '\u{a0}', '\u{2028}', '👋', 'م']),
        1 => any::<char>(),
        1 => prop::char::range('\0', '\x1f'),
        1 => Just('\x7f'),
    ]
}

fn input() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => vec(input_char(), 0..40).prop_map(String::from_iter),
        1 => any::<String>(),
    ]
}

/// What `escape` documents it keeps: CRLF, CR and LF each become one LF,
/// TAB stays and other ASCII control characters go.
fn normalise(s: &str) -> String {
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    s.chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_ascii_control())
        .collect()
}

/// One word of a message: plain text, or a mention of a uid.
#[derive(Debug, Clone)]
enum Word {
    Plain(String),
    Mention { uid: String, upper: bool },
}

fn word() -> impl Strategy<Value = Word> {
    prop_oneof![
        "[a-z,!?']{0,8}".prop_map(Word::Plain),
        (uid(), any::<bool>()).prop_map(|(uid, upper)| Word::Mention { uid, upper }),
    ]
}

proptest! {
    #![proptest_config(config(512))]

    /// `unescape(escape(s))` gives back `s` with line breaks made LF and
    /// other control characters dropped (3.4), as `escape` documents.
    #[test]
    fn escape_then_unescape(s in input()) {
        let escaped = escape(&s);
        prop_assert_eq!(unescape(&escaped), normalise(&s));
    }

    /// For input with LF line breaks and no other control characters
    /// except TAB, `unescape(escape(s)) == s` exactly.
    #[test]
    fn escape_round_trips_clean_input(s in input().prop_map(|s| normalise(&s))) {
        let escaped = escape(&s);
        prop_assert_eq!(unescape(&escaped), s.as_str());
    }

    /// Escaped text is always valid in a line (2.3) and survives a trip
    /// through a MSG line as text (3.3).
    #[test]
    fn escaped_text_fits_in_a_line(s in input(), leading in 0..3usize) {
        let s = " ".repeat(leading) + &s;
        let escaped = escape(&s);
        prop_assert_eq!(check_line(&escaped), Ok(()));
        prop_assert!(!escaped.contains(['\n', '\r']));
        let line = Line::builder("MSG").token("#general").text(&escaped).build()?;
        let parsed = Line::parse(&line.to_string())?;
        let mut params = parsed.params();
        prop_assert_eq!(params.token()?, "#general");
        prop_assert_eq!(params.text(), escaped.as_str());
    }

    /// `unescape` never panics, never grows the text, and borrows text
    /// without backslashes (3.4).
    #[test]
    fn unescape_any(s in input()) {
        let u = unescape(&s);
        prop_assert!(u.len() <= s.len());
        if !s.contains('\\') {
            prop_assert!(matches!(u, std::borrow::Cow::Borrowed(_)));
            prop_assert_eq!(u, s.as_str());
        }
    }

    /// `mentions` never panics, returns no duplicates, and every uid it
    /// returns appears after an `@` in the unescaped text, ignoring case
    /// (5.5).
    #[test]
    fn mentions_any(
        s in prop_oneof![
            input(),
            "[@~a-zA-Z0-9.\\\\n _-]{0,60}",
            vec(prop_oneof![uid(), Just("@".to_owned()), "[ .\\\\n,a-z]{0,3}"], 0..8)
                .prop_map(|parts| parts.concat()),
        ]
    ) {
        let found = mentions(&s);
        let text = unescape(&s).to_ascii_lowercase();
        let mut seen = HashSet::new();
        for uid in &found {
            prop_assert!(seen.insert(uid.clone()), "duplicate {}", uid);
            prop_assert!(text.contains(&format!("@{uid}")), "{} not in {:?}", uid, text);
        }
    }

    /// Mentions written at the start or after white space, in any case,
    /// are all found, in order, folded, without duplicates and without
    /// trailing dots (5.5).
    #[test]
    fn mentions_found(
        words in vec(word(), 0..8),
        seps in vec(prop::sample::select(vec![" ", "  ", "\\n", "\t", " \\n "]), 8),
    ) {
        let mut text = String::new();
        let mut want: Vec<String> = Vec::new();
        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                text.push_str(seps[i]);
            }
            match word {
                Word::Plain(plain) => text.push_str(plain),
                Word::Mention { uid, upper } => {
                    text.push('@');
                    text.push_str(&if *upper { uid.to_ascii_uppercase() } else { uid.clone() });
                    let uid = uid.trim_end_matches('.').to_owned();
                    if !want.contains(&uid) {
                        want.push(uid);
                    }
                }
            }
        }
        let got: Vec<String> = mentions(&text).iter().map(Uid::to_string).collect();
        prop_assert_eq!(got, want, "{:?}", text);
    }
}

// ---------------------------------------------------------------------------
// Shared types

proptest! {
    #![proptest_config(config(256))]

    /// The keyword, retention, relation, token and setting types
    /// round-trip from valid values.
    #[test]
    fn types_round_trip(
        days in 1..=u32::MAX,
        seq in 1..=i64::MAX as u64,
        presence in "[a-z][a-z0-9-]{0,10}",
        tag_token in "[!-:<-~]{1,64}",
        cid in "[!-:<-~]{16,64}",
        push_tag in "[!-~]{1,64}",
        topic in "[ -~]{0,40}",
        key in "[a-z][a-z0-9-]{0,10}",
        value in "[ -~]{0,20}",
        n in any::<u64>(),
    ) {
        for role in Role::ALL {
            check_canonical::<Role>(role.as_str())?;
            check_canonical::<InfoRole>(role.as_str())?;
        }
        check_canonical::<InfoRole>("none")?;
        for g in GuestAccess::ALL {
            check_canonical::<GuestAccess>(g.as_str())?;
        }
        for r in PushReason::ALL {
            check_canonical::<PushReason>(r.as_str())?;
        }
        check_canonical::<Presence>(&presence)?;
        let d = days.to_string();
        check_canonical::<RoomRetention>(&d)?;
        check_canonical::<ServerRetention>(&d)?;
        check_canonical::<RoomRetention>("server")?;
        check_canonical::<ServerRetention>("forever")?;
        let seq = Seq::new(seq).unwrap();
        for relation in [Relation::Reply(seq), Relation::Edit(seq), Relation::React(seq)] {
            prop_assert_eq!(relation.to_string().parse::<Relation>(), Ok(relation));
            prop_assert_eq!(
                Relation::from_tag(relation.key(), Some(&seq.to_string())),
                Ok(Some(relation))
            );
        }
        prop_assert_eq!(tag_token.parse::<Ref>().map(|r| r.to_string()), Ok(tag_token.clone()));
        prop_assert_eq!(cid.parse::<Cid>().map(|c| c.to_string()), Ok(cid.clone()));
        prop_assert_eq!(push_tag.parse::<PushTag>().map(|t| t.to_string()), Ok(push_tag.clone()));

        let topic_setting = RoomSetting::Topic(topic.clone());
        prop_assert_eq!(topic_setting.to_string().parse::<RoomSetting>(), Ok(topic_setting));
        let welcome = ServerSetting::Welcome(topic);
        prop_assert_eq!(welcome.to_string().parse::<ServerSetting>(), Ok(welcome));
        for setting in [
            RoomSetting::Public(n % 2 == 0),
            RoomSetting::Guests(GuestAccess::ALL[n as usize % GuestAccess::ALL.len()]),
            RoomSetting::Retention(RoomRetention::Days(d.parse().unwrap())),
        ] {
            prop_assert_eq!(setting.to_string().parse::<RoomSetting>(), Ok(setting));
        }
        if let Ok(setting) = RoomSetting::parse(&key, &value) {
            prop_assert_eq!(setting.to_string().parse::<RoomSetting>(), Ok(setting));
        }
        for setting in [
            ServerSetting::Guests(n % 2 == 0),
            ServerSetting::Registration(n % 3 == 0),
            ServerSetting::Retention(ServerRetention::Days(d.parse().unwrap())),
        ] {
            prop_assert_eq!(setting.to_string().parse::<ServerSetting>(), Ok(setting));
        }
        if let Ok(setting) = ServerSetting::parse(&key, &value) {
            prop_assert_eq!(setting.to_string().parse::<ServerSetting>(), Ok(setting));
        }
        prop_assert_eq!(parse_u64(&n.to_string()), Ok(n));
        prop_assert!(parse_yes_no(&presence).is_ok() == ["yes", "no"].contains(&presence.as_str()));
    }

    /// No string panics the parsers of the shared types, and whatever
    /// parses round-trips.
    #[test]
    fn any_type_round_trips(s in prop_oneof![any::<String>(), "[a-zA-Z0-9 =-]{0,20}"]) {
        check_any::<Role>(&s)?;
        check_any::<InfoRole>(&s)?;
        check_any::<GuestAccess>(&s)?;
        check_any::<PushReason>(&s)?;
        check_any::<Presence>(&s)?;
        check_any::<RoomRetention>(&s)?;
        check_any::<ServerRetention>(&s)?;
        check_any::<Ref>(&s)?;
        check_any::<Cid>(&s)?;
        check_any::<PushTag>(&s)?;
        check_any::<RoomSetting>(&s)?;
        check_any::<ServerSetting>(&s)?;
        check_any::<ErrorCode>(&s)?;
        if let Ok(relation) = s.parse::<Relation>() {
            prop_assert_eq!(relation.to_string().parse::<Relation>(), Ok(relation));
        }
        if let Ok(n) = parse_u64(&s) {
            prop_assert_eq!(n.to_string(), s.as_str());
        }
        let _ = parse_yes_no(&s);
    }
}

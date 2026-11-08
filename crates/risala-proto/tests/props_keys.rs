//! Property tests for keys: the sign-in challenge and ML-DSA-44 values
//! (SPEC 4.6, App. B), M5a's key files and fingerprints (2.2). M5a's key
//! file tests go when `keyfile::m5a` does; draft-03's key files are
//! tested in `props_identity.rs`.

use std::collections::HashSet;
use std::sync::OnceLock;

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use proptest::sample::Index;
use risala_proto::auth::{
    CHALLENGE_PREFIX, Nonce, PUBLIC_KEY_BASE64_LEN, PublicKey, SIGNATURE_BASE64_LEN, SIGNATURE_LEN,
    SecretKey, Signature, challenge_bytes,
};
use risala_proto::error::ParseError;
use risala_proto::fingerprint::Fingerprint;
use risala_proto::keyfile::m5a::{
    KeyEntry, KeyFile, MAX_KEY_FILE_BYTES, MAX_KEY_LABEL, MAX_KEY_LINE_BYTES, MAX_KEYS, SkipReason,
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

/// Public keys made once, since deriving keys is slow in debug builds.
/// More than `MAX_KEYS`, so that key files can overflow.
const POOL_SIZE: usize = 96;

fn pool() -> &'static [PublicKey] {
    static POOL: OnceLock<Vec<PublicKey>> = OnceLock::new();
    POOL.get_or_init(|| {
        (0..POOL_SIZE)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
                SecretKey::from_seed(seed).public_key()
            })
            .collect()
    })
}

fn pool_key() -> impl Strategy<Value = PublicKey> {
    (0..POOL_SIZE).prop_map(|i| pool()[i].clone())
}

/// A character a person might put in a label: no control characters
/// other than TAB.
fn label_char() -> impl Strategy<Value = char> {
    prop_oneof![
        2 => Just(' '),
        1 => Just('\t'),
        8 => prop::char::range('!', '~'),
        1 => prop::sample::select(vec!['é', '\u{a0}', '\u{2028}', '\u{3000}', '👋', 'م']),
        1 => any::<char>().prop_filter("not a control character", |c| !c.is_control()),
    ]
}

/// The label as `KeyEntry::new` keeps it: trimmed of spaces and TABs.
fn trimmed(label: &str) -> &str {
    label.trim_matches([' ', '\t'])
}

/// A label as a person might write one: printable text with spaces and
/// TABs, including around it, at most `MAX_KEY_LABEL` bytes once
/// trimmed (4.4).
fn label() -> impl Strategy<Value = String> {
    vec(label_char(), 0..40)
        .prop_map(String::from_iter)
        .prop_filter("fits the label limit", |l| {
            trimmed(l).len() <= MAX_KEY_LABEL
        })
}

/// A label over `MAX_KEY_LABEL` bytes once trimmed (4.4).
fn long_label() -> impl Strategy<Value = String> {
    vec(label_char(), 17..100)
        .prop_map(String::from_iter)
        .prop_filter("over the label limit", |l| trimmed(l).len() > MAX_KEY_LABEL)
}

/// Blanks around fields, as 4.4's lenient parsing allows.
fn blanks(min: usize) -> impl Strategy<Value = String> {
    vec(prop_oneof![Just(' '), Just('\t')], min..min + 3).prop_map(String::from_iter)
}

/// The key type, in any case.
fn key_type() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["mldsa44", "MLDSA44", "MlDsa44", "mLdSa44"]).prop_map(str::to_owned)
}

/// One line of a generated key file.
#[derive(Debug, Clone)]
enum KfLine {
    Entry {
        key: usize,
        label: Option<String>,
        line: String,
    },
    Comment(String),
    Blank(String),
    OtherType(String),
    Malformed(String),
}

fn kf_line() -> impl Strategy<Value = KfLine> {
    let entry = (
        0..POOL_SIZE,
        option::of(label()),
        blanks(0),
        key_type(),
        blanks(1),
        blanks(1),
        blanks(0),
    )
        .prop_map(|(key, label, before, kt, sep1, sep2, after)| {
            let mut line = format!("{before}{kt}{sep1}{}", pool()[key]);
            if let Some(label) = &label {
                line.push_str(&sep2);
                line.push_str(label);
            }
            line.push_str(&after);
            KfLine::Entry { key, label, line }
        });
    let malformed =
        (0..POOL_SIZE, 0..7usize, key_type(), long_label()).prop_map(|(key, how, kt, long)| {
            let k = pool()[key].to_string();
            KfLine::Malformed(match how {
                0 => kt,
                1 => format!("{kt} {}", &k[..k.len() - 1]),
                2 => format!("{kt} {k}A"),
                3 => format!("{kt} {}", k.replace('=', "A")),
                4 => format!("{kt} {k} bad\u{1}label"),
                5 => format!("{kt} {k} {long}"),
                _ => format!("{kt} {}", "A".repeat(PUBLIC_KEY_BASE64_LEN)),
            })
        });
    prop_oneof![
        8 => entry,
        1 => "[ \t]{0,2}#[ -~]{0,20}".prop_map(KfLine::Comment),
        1 => "[ \t]{0,3}".prop_map(KfLine::Blank),
        1 => "(ed25519|mldsa65|mldsa44x|ssh-ed25519)[ \t][ -~]{0,30}".prop_map(KfLine::OtherType),
        1 => malformed,
    ]
}

fn kf_text(line: &KfLine) -> &str {
    match line {
        KfLine::Entry { line, .. } => line,
        KfLine::Comment(s) | KfLine::Blank(s) | KfLine::OtherType(s) | KfLine::Malformed(s) => s,
    }
}

/// Checks the invariants of any parsed key file: no more than
/// `MAX_KEYS`, no repeated keys, and every entry's display line parses
/// back as the same entry, alone or as a whole file.
fn check_key_file(file: &KeyFile) -> Result<(), TestCaseError> {
    prop_assert!(file.keys().len() <= MAX_KEYS);
    let distinct: HashSet<_> = file.public_keys().collect();
    prop_assert_eq!(distinct.len(), file.keys().len());
    let mut lines = String::new();
    for entry in file.keys() {
        let line = entry.to_string();
        prop_assert_eq!(line.parse::<KeyEntry>(), Ok(entry.clone()));
        prop_assert!(!line.contains(['\n', '\r']));
        prop_assert!(entry.label().is_none_or(|l| l.len() <= MAX_KEY_LABEL));
        prop_assert!(line.len() + 2 <= MAX_KEY_LINE_BYTES);
        lines.push_str(&line);
        lines.push('\n');
    }
    let again = KeyFile::parse(&lines)?;
    prop_assert_eq!(again.keys(), file.keys());
    prop_assert!(again.skipped().is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Key files

proptest! {
    #![proptest_config(config(256))]

    /// A key entry displays as one key file line that parses back to the
    /// same entry, and the label is trimmed as `KeyEntry::new` documents
    /// (4.4).
    #[test]
    fn key_entry_round_trips(
        key in pool_key(),
        label in option::of(label()),
        before in blanks(0),
        sep in blanks(1),
        kt in key_type(),
    ) {
        let entry = KeyEntry::new(key.clone(), label.as_deref())?;
        let want = label.as_deref().map(trimmed).filter(|l| !l.is_empty());
        prop_assert_eq!(entry.label(), want);
        prop_assert_eq!(entry.key(), &key);
        let line = entry.to_string();
        prop_assert_eq!(line.parse::<KeyEntry>(), Ok(entry.clone()));

        // The same entry written loosely, and inside a file with CRLF.
        let loose = format!("{before}{kt}{sep}{key}{sep}{}{before}", want.unwrap_or(""));
        prop_assert_eq!(loose.parse::<KeyEntry>(), Ok(entry.clone()));
        let file = KeyFile::parse(&format!("# comment\r\n\r\n{loose}\r\n"))?;
        prop_assert_eq!(file.keys(), std::slice::from_ref(&entry));
    }

    /// A label with a control character other than TAB inside it is
    /// rejected (4.4).
    #[test]
    fn key_entry_rejects_control_characters(
        key in pool_key(),
        a in "[a-z]{1,5}",
        b in "[a-z]{1,5}",
        c in prop_oneof![prop::char::range('\0', '\x08'), prop::char::range('\n', '\x1f'), Just('\x7f'), Just('\u{85}')],
    ) {
        let label = format!("{a}{c}{b}");
        prop_assert!(matches!(KeyEntry::new(key, Some(&label)), Err(ParseError::BadSyntax(_))));
    }

    /// A label over 64 bytes once trimmed is `TooLong`, alone or on a key
    /// file line, and a key file skips that line as malformed (4.4).
    #[test]
    fn key_entry_rejects_long_labels(key in pool_key(), label in long_label()) {
        prop_assert_eq!(KeyEntry::new(key.clone(), Some(&label)), Err(ParseError::TooLong));
        let line = format!("mldsa44 {key} {label}");
        prop_assert_eq!(line.parse::<KeyEntry>(), Err(ParseError::TooLong));
        let file = KeyFile::parse(&line)?;
        prop_assert!(file.keys().is_empty());
        prop_assert_eq!(&file.skipped()[0].reason, &SkipReason::Malformed(ParseError::TooLong));
    }

    /// A generated key file keeps exactly the first `MAX_KEYS` distinct
    /// valid keys, in order, with their labels, and lists every other
    /// line that is not blank or a comment as skipped (4.4).
    #[test]
    fn key_file_matches_model(lines in vec(kf_line(), 0..100), crlf in any::<bool>(), bom in any::<bool>()) {
        let sep = if crlf { "\r\n" } else { "\n" };
        let mut text = if bom { "\u{feff}".to_owned() } else { String::new() };
        text.push_str(&lines.iter().map(kf_text).collect::<Vec<_>>().join(sep));

        let mut want = Vec::new();
        let mut want_skipped = Vec::new();
        let mut seen = HashSet::new();
        for (i, line) in lines.iter().enumerate() {
            let line_no = i + 1;
            match line {
                KfLine::Entry { key, label, .. } => {
                    if !seen.insert(*key) {
                        want_skipped.push((line_no, "duplicate"));
                    } else if want.len() == MAX_KEYS {
                        want_skipped.push((line_no, "too many"));
                    } else {
                        want.push(KeyEntry::new(pool()[*key].clone(), label.as_deref())?);
                    }
                }
                KfLine::Comment(_) | KfLine::Blank(_) => {}
                KfLine::OtherType(_) => want_skipped.push((line_no, "other")),
                KfLine::Malformed(_) => want_skipped.push((line_no, "malformed")),
            }
        }

        let file = KeyFile::parse(&text)?;
        prop_assert_eq!(file.keys(), want.as_slice());
        let got_skipped: Vec<(usize, &str)> = file
            .skipped()
            .iter()
            .map(|s| {
                let kind = match s.reason {
                    SkipReason::Duplicate => "duplicate",
                    SkipReason::TooMany => "too many",
                    SkipReason::OtherKeyType(_) => "other",
                    SkipReason::Malformed(_) => "malformed",
                };
                (s.line, kind)
            })
            .collect();
        prop_assert_eq!(got_skipped, want_skipped);
        check_key_file(&file)?;
    }

    /// Any text either is over the size limit or parses into a key file
    /// that keeps its invariants (4.4).
    #[test]
    fn any_key_file_is_safe(
        text in prop_oneof![
            any::<String>(),
            vec(prop_oneof![
                kf_line().prop_map(|l| kf_text(&l).to_owned()),
                any::<String>(),
                "[mMlLdDsSaA4 \t\r#A-Za-z0-9+/=]{0,60}",
            ], 0..20).prop_map(|lines| lines.join("\n")),
        ]
    ) {
        let file = KeyFile::parse(&text)?;
        check_key_file(&file)?;
    }
}

#[test]
fn key_file_over_the_limit_is_too_long() {
    let line = format!("mldsa44 {}\n", pool()[0]);
    let text = line.repeat(MAX_KEY_FILE_BYTES / line.len() + 1);
    assert!(text.len() > MAX_KEY_FILE_BYTES);
    assert_eq!(KeyFile::parse(&text), Err(ParseError::TooLong));
    let at_limit = &text[..MAX_KEY_FILE_BYTES];
    let file = KeyFile::parse(at_limit).unwrap();
    assert_eq!(file.keys().len(), 1);
}

// ---------------------------------------------------------------------------
// Signing in

proptest! {
    #![proptest_config(config(24))]

    /// For any key, host, nonce and uid, a signed challenge verifies,
    /// also with the host and uid in another case, and stops verifying
    /// when any one byte of the signature changes, or when the host,
    /// nonce, uid or key differ (4.5). Signatures from the hedged variant
    /// verify too.
    #[test]
    fn sign_then_verify(
        seed in any::<[u8; 32]>(),
        rnd in any::<[u8; 32]>(),
        host in "[a-zA-Z0-9.-]{1,40}",
        nonce in vec(any::<u8>(), 16..=64),
        uid in "[a-zA-Z0-9~@._-]{1,40}",
        flip in any::<Index>(),
        mask in 1..=u8::MAX,
        other in pool_key(),
    ) {
        let secret = SecretKey::from_seed(seed);
        let public = secret.public_key();
        let nonce = Nonce::from_bytes(&nonce)?;
        let signature = secret.sign_challenge(&host, &nonce, &uid);
        prop_assert!(public.verify_challenge(&host, &nonce, &uid, &signature));
        prop_assert!(public.verify_challenge(
            &host.to_ascii_uppercase(),
            &nonce,
            &uid.to_ascii_uppercase(),
            &signature
        ));

        // Deterministic: the same inputs give the same signature.
        prop_assert_eq!(&secret.sign_challenge(&host, &nonce, &uid), &signature);
        let hedged = secret.sign_challenge_hedged(&host, &nonce, &uid, rnd);
        prop_assert!(public.verify_challenge(&host, &nonce, &uid, &hedged));

        let mut bytes = *signature.as_bytes();
        bytes[flip.index(SIGNATURE_LEN)] ^= mask;
        prop_assert!(!public.verify_challenge(&host, &nonce, &uid, &Signature::from_bytes(&bytes)));

        let (other_host, other_uid) = (format!("{host}x"), format!("{uid}x"));
        prop_assert!(!public.verify_challenge(&other_host, &nonce, &uid, &signature));
        prop_assert!(!public.verify_challenge(&host, &nonce, &other_uid, &signature));
        let mut other_nonce = nonce.to_bytes();
        other_nonce[0] ^= 1;
        prop_assert!(!public.verify_challenge(&host, &Nonce::from_bytes(&other_nonce)?, &uid, &signature));
        if other != public {
            prop_assert!(!other.verify_challenge(&host, &nonce, &uid, &signature));
        }
    }

    /// The challenge is the prefix, host, nonce and uid, each ending in
    /// LF, with host and uid in lower case (4.5).
    #[test]
    fn challenge_layout(
        host in "[a-zA-Z0-9.-]{1,40}",
        nonce in vec(any::<u8>(), 16..=64),
        uid in "[a-zA-Z0-9~@._-]{1,40}",
    ) {
        let nonce = Nonce::from_bytes(&nonce)?;
        let want = format!(
            "{CHALLENGE_PREFIX}\n{}\n{nonce}\n{}\n",
            host.to_ascii_lowercase(),
            uid.to_ascii_lowercase()
        );
        prop_assert_eq!(challenge_bytes(&host, &nonce, &uid), want.into_bytes());
    }

    /// A secret key survives PKCS#8 PEM (App. B).
    #[test]
    fn secret_key_pem_round_trips(seed in any::<[u8; 32]>()) {
        let secret = SecretKey::from_seed(seed);
        let pem = secret.to_pkcs8_pem();
        let again = SecretKey::from_pkcs8_pem(&pem)?;
        prop_assert_eq!(again.public_key(), secret.public_key());
        let again_pem = again.to_pkcs8_pem();
        prop_assert_eq!(again_pem.as_str(), pem.as_str());
    }
}

proptest! {
    #![proptest_config(config(256))]

    /// Public keys, signatures, nonces and fingerprints round-trip
    /// through their string forms (2.2, 4.1, 4.4, 4.5).
    #[test]
    fn key_values_round_trip(
        key in pool_key(),
        sig in vec(any::<u8>(), SIGNATURE_LEN),
        nonce in vec(any::<u8>(), 16..=64),
        hash in any::<[u8; 32]>(),
    ) {
        let s = key.to_string();
        prop_assert_eq!(s.len(), PUBLIC_KEY_BASE64_LEN);
        prop_assert_eq!(s.parse::<PublicKey>(), Ok(key.clone()));
        prop_assert_eq!(&PublicKey::from_bytes(key.as_bytes()), &key);
        let fingerprint = key.fingerprint().to_string();
        prop_assert!(fingerprint.starts_with("sha256:"));
        prop_assert_eq!(fingerprint.len(), 7 + 64);

        let sig = Signature::from_bytes(&sig.try_into().unwrap());
        let s = sig.to_string();
        prop_assert_eq!(s.len(), SIGNATURE_BASE64_LEN);
        prop_assert_eq!(s.parse::<Signature>(), Ok(sig));

        let n = Nonce::from_bytes(&nonce)?;
        let s = n.to_string();
        prop_assert_eq!(s.len(), nonce.len() * 2);
        prop_assert!(s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        prop_assert_eq!(n.to_bytes(), nonce);
        prop_assert_eq!(s.parse::<Nonce>(), Ok(n.clone()));
        prop_assert_eq!(s.to_ascii_uppercase().parse::<Nonce>(), Ok(n));

        let f = Fingerprint::from_bytes(hash);
        let s = f.to_string();
        prop_assert_eq!(s.parse::<Fingerprint>(), Ok(f));
        prop_assert_eq!(s.to_ascii_uppercase().parse::<Fingerprint>(), Ok(f));
        prop_assert_eq!(f.as_bytes(), &hash);
    }

    /// Nonces outside 16 to 64 bytes are refused (4.1).
    #[test]
    fn nonce_length_limits(short in vec(any::<u8>(), 0..16), long in vec(any::<u8>(), 65..100)) {
        prop_assert!(matches!(Nonce::from_bytes(&short), Err(ParseError::BadSyntax(_))));
        prop_assert_eq!(Nonce::from_bytes(&long), Err(ParseError::TooLong));
    }

    /// No string panics these parsers. Decoding is strict, so whatever
    /// parses displays exactly as written, apart from hex case.
    #[test]
    fn any_key_value_is_canonical(
        s in prop_oneof![
            any::<String>(),
            "[A-Za-z0-9+/]{1749,1751}={0,2}",
            "[A-Za-z0-9+/]{3225,3227}={0,2}",
            "[0-9a-fA-F]{30,130}",
            "(sha256|SHA256|sha-256):[0-9a-fA-F]{63,65}",
        ]
    ) {
        if let Ok(key) = s.parse::<PublicKey>() {
            prop_assert_eq!(key.to_string(), s.as_str());
        }
        if let Ok(sig) = s.parse::<Signature>() {
            prop_assert_eq!(sig.to_string(), s.as_str());
        }
        if let Ok(nonce) = s.parse::<Nonce>() {
            prop_assert_eq!(nonce.to_string(), s.to_ascii_lowercase());
        }
        if let Ok(f) = s.parse::<Fingerprint>() {
            prop_assert_eq!(f.to_string(), s.to_ascii_lowercase());
        }
        let _ = s.parse::<KeyEntry>();
        let _ = SecretKey::from_pkcs8_pem(&s);
    }

    /// Hashing is deterministic and fingerprints of different SPKI
    /// bytes differ (2.2).
    #[test]
    fn fingerprint_from_spki(a in vec(any::<u8>(), 0..200), b in vec(any::<u8>(), 0..200)) {
        let (fa, fb) = (Fingerprint::from_spki_der(&a), Fingerprint::from_spki_der(&b));
        prop_assert_eq!(fa, Fingerprint::from_spki_der(&a));
        prop_assert_eq!(a == b, fa == fb);
        prop_assert_eq!(fa.to_string().parse::<Fingerprint>(), Ok(fa));
    }
}

/// Flipping a bit of one fixed signature, byte by byte, stops it
/// verifying (4.5). The property above picks one byte per case; this
/// covers all 2420 for one key.
#[test]
fn every_flipped_signature_byte_fails() {
    let secret = SecretKey::from_seed([7; 32]);
    let public = secret.public_key();
    let nonce = Nonce::from_bytes(&[0x5a; 16]).unwrap();
    let signature = secret.sign_challenge("chat.example.org", &nonce, "alice@example.org");
    for i in 0..SIGNATURE_LEN {
        let mut bytes = *signature.as_bytes();
        bytes[i] ^= 0x01;
        assert!(
            !public.verify_challenge(
                "chat.example.org",
                &nonce,
                "alice@example.org",
                &Signature::from_bytes(&bytes)
            ),
            "byte {i}"
        );
    }
}

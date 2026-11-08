//! Appendix B's test vectors for the identity formats (B.1 to B.10), made
//! by this crate from fixed seeds and checked against the appendix. Print
//! them, and write their files, with
//!
//! ```text
//! RISALA_VECTORS=print cargo test -p risala-proto --test identity vectors -- --test-threads 1 --nocapture
//! ```
//!
//! Signatures use the deterministic variant of ML-DSA, so that they can be
//! checked. X-Wing keys are draft-06 KeyGen from their 32-byte seeds.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::auth::{Nonce, SecretKey, SignLabel, challenge_bytes, risala_sign_content};
use risala_proto::chain::{Chain, NoHandoffs};
use risala_proto::keyfile::{KeyFile, KeyFileState, NoEntries, Response, read_key_file};
use risala_proto::names::Identity;
use risala_proto::pairing::{NewDevice, NewDeviceContent, PairingCode, PairingError};
use risala_proto::record::{
    DeviceId, DeviceKeys, LogEntry, LogKey, Record, RecordBody, RecordContent, XWingPublicKey,
    decode_records, encode_records,
};
use risala_proto::recovery::RecoveryKey;
use risala_proto::safety::SafetyNumber;
use risala_proto::time::Timestamp;
use sha2::Digest as _;
use zeroize::Zeroizing;

use super::appendix::{Checker, FILES, sections};
use super::{T0, xwing_bytes};

/// Appendix B's private key seed.
const APPENDIX_B_SEED: &str = "c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&sha2::Sha256::digest(bytes))
}

fn seed(b: u8) -> [u8; 32] {
    [b; 32]
}

fn ml(b: u8) -> SecretKey {
    SecretKey::from_seed(seed(b))
}

fn xw(b: u8) -> XWingPublicKey {
    XWingPublicKey::from_bytes(&xwing_bytes(seed(b))).unwrap()
}

/// Everything the vectors are made of.
pub struct Fixture {
    pub uid: Identity,
    pub recovery: RecoveryKey,
    pub master: SecretKey,
    pub signing: SecretKey,
    pub log: LogKey,
    pub other_log: LogKey,
    pub device: DeviceKeys,
    pub device_secret: SecretKey,
    pub records: Vec<Record>,
}

/// The chain of the vectors:
///
/// 0. `master`: the master key from recovery key 00..1f, device-signing
///    key seed 02.., log `chat.example.org/risala-log/1` with key seed
///    03...
/// 1. `device`: Appendix B's key, attestation X-Wing seed 04.., `laptop`.
/// 2. `device`: key seed 05.., attestation seed 06.., `phone`.
/// 3. `signing`: new device-signing key seed 07.., removes record 2's
///    device.
/// 4. `master`: the master key from recovery key 20..3f, device-signing
///    key seed 08.., the same log.
/// 5. `log`: `keys.example.net/risala-log/1`, key seed 09...
/// 6. `retire`.
///
/// Record i has time 2026-11-01T00:00:00Z plus i minutes.
pub fn fixture() -> Fixture {
    let uid: Identity = "alice@example.org".parse().unwrap();
    let recovery = RecoveryKey::from_bytes(std::array::from_fn(|i| i as u8));
    let master = recovery.master_key(&uid);
    let signing = ml(0x02);
    let log = LogKey::new("chat.example.org/risala-log/1", ml(0x03).public_key()).unwrap();
    let other_log = LogKey::new("keys.example.net/risala-log/1", ml(0x09).public_key()).unwrap();
    let device_secret = SecretKey::from_seed(unhex(APPENDIX_B_SEED).try_into().unwrap());
    let device = DeviceKeys {
        device_key: device_secret.public_key(),
        attestation_key: xw(0x04),
        label: "laptop".into(),
    };
    let phone = DeviceKeys {
        device_key: ml(0x05).public_key(),
        attestation_key: xw(0x06),
        label: "phone".into(),
    };
    let content = |i: u64, previous: Option<&Record>, body| RecordContent {
        uid: uid.clone(),
        previous: previous.map(Record::hash),
        time: T0 + 60_000 * i,
        body,
    };
    let mut records: Vec<Record> = Vec::new();
    let r0 = Record::sign_deterministic(
        content(
            0,
            None,
            RecordBody::Master {
                master_key: master.public_key(),
                signing_key: signing.public_key(),
                log: log.clone(),
            },
        ),
        &master,
    )
    .unwrap();
    records.push(r0);
    let r1 = Record::sign_deterministic(
        content(1, records.last(), RecordBody::Device(device.clone())),
        &signing,
    )
    .unwrap();
    records.push(r1);
    let r2 = Record::sign_deterministic(
        content(2, records.last(), RecordBody::Device(phone.clone())),
        &signing,
    )
    .unwrap();
    records.push(r2);
    let signing2 = ml(0x07);
    let r3 = Record::sign_deterministic(
        content(
            3,
            records.last(),
            RecordBody::Signing {
                signing_key: signing2.public_key(),
                removed: vec![DeviceId::of(&phone.device_key)],
            },
        ),
        &master,
    )
    .unwrap();
    records.push(r3);
    let recovery2 = RecoveryKey::from_bytes(std::array::from_fn(|i| 0x20 + i as u8));
    let master2 = recovery2.master_key(&uid);
    let signing3 = ml(0x08);
    let r4 = Record::sign_rotation_deterministic(
        content(
            4,
            records.last(),
            RecordBody::Master {
                master_key: master2.public_key(),
                signing_key: signing3.public_key(),
                log: log.clone(),
            },
        ),
        &master,
        &master2,
    )
    .unwrap();
    records.push(r4);
    let r5 = Record::sign_deterministic(
        content(5, records.last(), RecordBody::Log(other_log.clone())),
        &master2,
    )
    .unwrap();
    records.push(r5);
    let r6 = Record::sign_deterministic(content(6, records.last(), RecordBody::Retire), &master2)
        .unwrap();
    records.push(r6);
    Fixture {
        uid,
        recovery,
        master,
        signing,
        log,
        other_log,
        device,
        device_secret,
        records,
    }
}

fn url(log: &LogKey) -> String {
    format!("https://{}/risala-log/{}", log.host(), log.number())
}

/// The key file of the first `n` records, the first `logged` of them by
/// index (0, 1, 2, ...) and the rest unlogged.
pub fn key_file(f: &Fixture, n: usize, logged: usize) -> String {
    let chain = Chain::replay(&f.uid, &f.records[..n]).unwrap();
    KeyFile::from_chain(&chain, &|i| (i < logged).then_some(i as u64), &url)
        .unwrap()
        .to_text()
}

/// Key files that MUST fail, by the rule of 4.4 they break, each made
/// from the vectors' chain.
pub fn must_fail(f: &Fixture) -> Vec<(&'static str, String)> {
    let good = key_file(f, 2, 0);
    let b64 = |r: &Record| BASE64.encode(r.encoded());
    let log_line = format!("log {} {}", f.log.vkey(), url(&f.log));
    let header = "risala-keys/1";
    let lines = |records: &[Record]| -> String {
        let mut t = format!("{header}\n{log_line}\n");
        for r in records {
            t.push_str(&format!("- {}\n", b64(r)));
        }
        t
    };
    let resign =
        |content: RecordContent, key: &SecretKey| Record::sign_deterministic(content, key).unwrap();
    let r = &f.records;
    let mut out = vec![
        (
            "parse 1, no LF after the last line",
            good[..good.len() - 1].to_owned(),
        ),
        (
            "parse 1, a CR before an LF",
            good.replacen(
                &format!("{}\n", url(&f.log)),
                &format!("{}\r\n", url(&f.log)),
                1,
            ),
        ),
        (
            "parse 1, two spaces in a row",
            good.replacen("- ", "-  ", 1),
        ),
        (
            "parse 1, first line is not risala-keys/1",
            good.replacen(header, "risala-keys/2", 1),
        ),
        (
            "parse 1, no log line before the records",
            good.replacen(&format!("{log_line}\n"), "", 1),
        ),
        (
            "parse 1, a log line follows another",
            good.replacen(&log_line, &format!("{log_line}\n# x\n{log_line}"), 1),
        ),
        (
            "parse 1, an index line after a - line",
            format!("{good}0 {}\n", r[0].hash()),
        ),
        ("parse 1, base64 without padding", {
            let full = b64(&r[1]);
            good.replacen(&full, full.trim_end_matches('='), 1)
        }),
    ];
    // Replaying.
    let mut wrong_uid = r[1].content().clone();
    wrong_uid.uid = "bob@example.org".parse().unwrap();
    out.push((
        "replay 1, a record of another uid",
        lines(&[r[0].clone(), resign(wrong_uid, &f.signing)]),
    ));
    out.push((
        "replay 2, the first record is not a master record",
        lines(&[r[1].clone()]),
    ));
    let mut wrong_prev = r[2].content().clone();
    wrong_prev.previous = Some(r[0].hash());
    out.push((
        "replay 2, previous is not the record before",
        lines(&[r[0].clone(), r[1].clone(), resign(wrong_prev, &f.signing)]),
    ));
    let mut same_time = r[1].content().clone();
    same_time.time = T0;
    out.push((
        "replay 3, a time not later than the one before",
        lines(&[r[0].clone(), resign(same_time, &f.signing)]),
    ));
    out.push((
        "replay 4, a device record signed by the master key",
        lines(&[r[0].clone(), resign(r[1].content().clone(), &f.master)]),
    ));
    let single = Record::new(r[4].content().clone(), &r[4].signature()[..2420]).unwrap();
    out.push((
        "replay 4, a later master record with one signature",
        lines(&[
            r[0].clone(),
            r[1].clone(),
            r[2].clone(),
            r[3].clone(),
            single,
        ]),
    ));
    let mut repeated = r[1].content().clone();
    if let RecordBody::Device(keys) = &mut repeated.body {
        keys.device_key = f.signing.public_key();
    }
    out.push((
        "replay 5, a device key that is the device-signing key",
        lines(&[r[0].clone(), resign(repeated, &f.signing)]),
    ));
    let mut other_log = r[4].content().clone();
    if let RecordBody::Master { log, .. } = &mut other_log.body {
        *log = f.other_log.clone();
    }
    let master2 =
        RecoveryKey::from_bytes(std::array::from_fn(|i| 0x20 + i as u8)).master_key(&f.uid);
    let rotated = Record::sign_rotation_deterministic(other_log, &f.master, &master2).unwrap();
    out.push((
        "replay 6, a later master record names another log",
        lines(&[
            r[0].clone(),
            r[1].clone(),
            r[2].clone(),
            r[3].clone(),
            rotated,
        ]),
    ));
    let mut not_current = r[3].content().clone();
    if let RecordBody::Signing { removed, .. } = &mut not_current.body {
        *removed = vec![DeviceId::from_bytes([0; 48])];
    }
    out.push((
        "replay 7, removed names a device that is not current",
        lines(&[
            r[0].clone(),
            r[1].clone(),
            r[2].clone(),
            resign(not_current, &f.master),
        ]),
    ));
    let mut same_log = r[5].content().clone();
    same_log.previous = Some(r[0].hash());
    same_log.body = RecordBody::Log(f.log.clone());
    out.push((
        "replay 9, a log record names the current log",
        lines(&[r[0].clone(), resign(same_log, &f.master)]),
    ));
    let mut after = r[1].content().clone();
    after.previous = Some(r[6].hash());
    after.time = T0 + 60_000 * 7;
    if let RecordBody::Device(keys) = &mut after.body {
        keys.device_key = ml(0x0e).public_key();
        keys.attestation_key = xw(0x0f);
    }
    let after = resign(after, &ml(0x08));
    let mut all = key_file(f, 7, 0);
    all.push_str(&format!("- {}\n", b64(&after)));
    out.push(("replay 10, a record after a retire record", all));
    let mut misplaced = key_file(f, 7, 0);
    let second_log = format!("log {} {}\n", f.other_log.vkey(), url(&f.other_log));
    misplaced = misplaced.replacen(&second_log, "", 1);
    out.push((
        "replay 11, a record listed under another log than its own",
        misplaced,
    ));

    // Encodings (4.4): record 1 changed after it was signed, which the
    // decoder catches before any signature is checked.
    let with = |bytes: Vec<u8>| good.replacen(&b64(&r[1]), &BASE64.encode(bytes), 1);
    let mut long_len = r[1].encoded().to_vec();
    assert_eq!(long_len[2], 17, "uid<V> of 17 bytes");
    long_len.splice(2..3, [0x40, 17]);
    out.push((
        "parse 2, uid length in two bytes where one is enough",
        with(long_len),
    ));
    let mut trailing = r[1].encoded().to_vec();
    trailing.push(0);
    out.push(("parse 2, a byte after its last field", with(trailing)));
    out.push(("parse 1, base64 whose unused bits are not zero", {
        let full = b64(&r[1]);
        let body = full.trim_end_matches('=');
        let last = body.chars().last().unwrap();
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let index = ALPHABET.find(last).unwrap();
        assert!(index.is_multiple_of(4), "two unused bits");
        let changed = ALPHABET.as_bytes()[index + 1] as char;
        let bad = format!(
            "{}{changed}{}",
            &body[..body.len() - 1],
            &full[body.len()..]
        );
        good.replacen(&full, &bad, 1)
    }));
    let mut repeated = r[3].content().clone();
    if let RecordBody::Signing { removed, .. } = &mut repeated.body {
        removed.push(removed[0]);
    }
    out.push((
        "replay 7, removed names a device twice",
        lines(&[
            r[0].clone(),
            r[1].clone(),
            r[2].clone(),
            resign(repeated, &f.master),
        ]),
    ));
    out.push((
        "parse 1, a log URL that is not https and its origin",
        good.replacen(&url(&f.log), "http://chat.example.org/risala-log/1", 1),
    ));
    // In the order of 4.4's rules: parsing, then replaying.
    out.sort_by_key(|(name, _)| {
        let (list, rest) = name.split_once(' ').unwrap();
        let number: u32 = rest.split(',').next().unwrap().parse().unwrap();
        (list == "replay", number)
    });
    out
}

// ---------------------------------------------------------------------------
// Appendix B, sections B.1 to B.10. Each test checks one section against
// the code; `RISALA_VECTORS=print` prints the sections instead (see
// `tests/common/appendix.rs`).

/// The key file of `text`, read for `f`'s uid an hour after record 0.
fn read(f: &Fixture, text: &str) -> KeyFileState {
    read_key_file(
        Response::Body {
            status: 200,
            body: text.as_bytes(),
        },
        &f.uid,
        &mut NoEntries,
        &NoHandoffs,
        Timestamp::from_unix_millis(T0 + 3_600_000).unwrap(),
    )
}

/// Appendix B's key.
fn appendix_key() -> SecretKey {
    SecretKey::from_seed(unhex(APPENDIX_B_SEED).try_into().unwrap())
}

/// A text block is base64 wrapped at 64 characters.
fn unwrap64(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let (last, full) = lines.split_last().unwrap();
    assert!(full.iter().all(|l| l.len() == 64) && last.len() <= 64);
    lines.concat()
}

#[test]
fn b1_key_and_auth() {
    let mut ck = Checker::open("B.1 ");
    let key = appendix_key();
    let public = key.public_key();
    let (host, uid) = ("chat.example.org", "alice@example.org");
    let nonce: Nonce = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e".parse().unwrap();
    ck.eq("seed", APPENDIX_B_SEED);
    ck.eq("public key SHA-256", sha256(public.as_bytes()));
    ck.eq("host", host);
    ck.eq("uid", uid);
    ck.eq("nonce", nonce.as_str());
    ck.gap();
    let signed = challenge_bytes(host, &nonce, uid);
    let signature = key.sign_challenge(host, &nonce, uid);
    ck.eq("signature SHA-256", sha256(signature.as_bytes()));
    ck.gap();
    ck.rejected(
        "the signature checked for host chat.example.net",
        !public.verify_challenge("chat.example.net", &nonce, uid, &signature),
    );
    let other: Nonce = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6f".parse().unwrap();
    ck.rejected(
        "the signature checked for nonce 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6f",
        !public.verify_challenge(host, &other, uid, &signature),
    );
    assert!(public.verify_challenge(host, &nonce, uid, &signature));
    // The text blocks: the PEM, the public key, the signed bytes, the
    // signature and the AUTH command.
    assert_eq!(format!("{}\n", ck.text()), *key.to_pkcs8_pem());
    assert_eq!(unwrap64(&ck.text()), public.to_string());
    let bytes = format!("{}\n", ck.text());
    assert_eq!(bytes.as_bytes(), &signed[..]);
    assert_eq!(signed.len(), 82);
    assert_eq!(unwrap64(&ck.text()), signature.to_string());
    assert_eq!(ck.text(), format!("AUTH {uid} {signature}"));
    ck.finish();
}

#[test]
fn b2_risala_sign() {
    use libcrux_ml_dsa::ml_dsa_44 as mldsa;
    let mut ck = Checker::open("B.2 ");
    let key = fixture().device_secret;
    let content = b"risala";
    ck.eq("key seed", APPENDIX_B_SEED);
    ck.eq("label", SignLabel::Record.as_str());
    ck.hex("content", content);
    ck.gap();
    let signed = risala_sign_content(SignLabel::Record, content);
    let signature = key.risala_sign_deterministic(SignLabel::Record, content);
    ck.hex("RisalaSignContent", &signed);
    ck.file("signature", "risalasign.bin", signature.as_bytes());
    assert!(
        key.public_key()
            .risala_verify(SignLabel::Record, content, signature.as_bytes())
    );
    ck.gap();
    for label in SignLabel::ALL {
        if label != SignLabel::Record {
            ck.rejected(
                &format!("the signature verified under label {}", label.as_str()),
                !key.public_key()
                    .risala_verify(label, content, signature.as_bytes()),
            );
        }
    }
    // ML-DSA's context string must be empty (4.3).
    let pair = mldsa::generate_key_pair(unhex(APPENDIX_B_SEED).try_into().unwrap());
    let with_context = mldsa::sign(&pair.signing_key, &signed, b"risala", [0; 32]).unwrap();
    let with_context = with_context.as_ref();
    ck.file(
        "the same signed with context string risala",
        "risalasign-context.bin",
        with_context,
    );
    ck.rejected(
        "that signature verified",
        !key.public_key()
            .risala_verify(SignLabel::Record, content, with_context),
    );
    ck.finish();
}

#[test]
fn b3_recovery_key() {
    let mut ck = Checker::open("B.3 ");
    let f = fixture();
    ck.hex("recovery key", f.recovery.as_bytes());
    ck.eq("uid", f.uid.to_string());
    ck.gap();
    let text = f.recovery.to_text();
    ck.eq("text form", text.to_string());
    ck.file(
        "master public key",
        "master-key.bin",
        f.master.public_key().as_bytes(),
    );
    assert_eq!(
        RecoveryKey::parse(&text).unwrap().as_bytes(),
        f.recovery.as_bytes()
    );
    ck.gap();
    // The last character holds 1 bit of the key and 4 zero bits.
    let last = text.chars().last().unwrap();
    let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    let changed = alphabet.as_bytes()[alphabet.find(last).unwrap() + 1] as char;
    let bad = format!("{}{changed}", &text[..text.len() - 1]);
    ck.rejected(
        &format!("the text form with its last character {last} changed to {changed}"),
        RecoveryKey::parse(&bad).is_err(),
    );
    ck.finish();
}

#[test]
fn b4_log_and_device() {
    let mut ck = Checker::open("B.4 ");
    let f = fixture();
    ck.eq("log origin", f.log.origin());
    ck.hex("log key seed", &seed(0x03));
    ck.eq("log URL", url(&f.log));
    ck.gap();
    ck.eq("key ID", format!("{:08x}", f.log.key_id()));
    ck.file("verifier key", "log-vkey.txt", f.log.vkey().as_bytes());
    ck.file(
        "log line",
        "log-line.txt",
        format!("log {} {}", f.log.vkey(), url(&f.log)).as_bytes(),
    );
    assert_eq!(LogKey::from_vkey(&f.log.vkey()).unwrap(), f.log);
    ck.gap();
    ck.eq("device key seed", APPENDIX_B_SEED);
    ck.hex("attestation key seed", &seed(0x04));
    ck.gap();
    ck.file(
        "attestation key",
        "attestation-key.bin",
        f.device.attestation_key.as_bytes(),
    );
    let id = DeviceId::of(&f.device.device_key);
    ck.eq("device id", id.to_string());
    ck.eq("short id", id.short());
    ck.finish();
}

#[test]
fn b5_records() {
    let mut ck = Checker::open("B.5 ");
    let f = fixture();
    ck.eq("uid", f.uid.to_string());
    ck.eq("time of record 0", T0.to_string());
    ck.hex("device-signing key seed", &seed(0x02));
    ck.eq("first device label", f.device.label.as_str());
    ck.hex("second device key seed", &seed(0x05));
    ck.hex("second attestation key seed", &seed(0x06));
    ck.eq("second device label", "phone");
    ck.hex("new device-signing key seed", &seed(0x07));
    ck.hex(
        "second recovery key",
        &std::array::from_fn::<u8, 32, _>(|i| 0x20 + i as u8),
    );
    ck.hex("third device-signing key seed", &seed(0x08));
    ck.eq("second log origin", f.other_log.origin());
    ck.hex("second log key seed", &seed(0x09));
    ck.gap();
    for (i, r) in f.records.iter().enumerate() {
        ck.file(
            &format!("record {i}"),
            &format!("record-{i}.bin"),
            r.encoded(),
        );
        ck.eq(&format!("record {i} hash"), r.hash().to_string());
        assert_eq!(&Record::decode(r.encoded()).unwrap(), r);
    }
    let chain = Chain::replay(&f.uid, &f.records[..6]).unwrap();
    ck.eq(
        "generation after records 0 to 5",
        chain.generation().to_string(),
    );
    assert!(Chain::replay(&f.uid, &f.records).unwrap().is_retired());
    ck.finish();
}

#[test]
fn b6_key_files() {
    let mut ck = Checker::open("B.6 ");
    let f = fixture();
    ck.eq("read at", (T0 + 3_600_000).to_string());
    ck.gap();
    let valid = [
        ("records 0 and 1, not logged", key_file(&f, 2, 0)),
        ("records 0 and 1, logged", key_file(&f, 2, 2)),
        ("records 0 to 6, 0 to 3 logged", key_file(&f, 7, 4)),
    ];
    for (i, (name, text)) in valid.iter().enumerate() {
        // The logged ones would need the log's entries to be accepted.
        assert!(
            !matches!(read(&f, text), KeyFileState::KeysMissing(_)),
            "{name}"
        );
        ck.file(name, &format!("keyfile-{}.txt", i + 1), text.as_bytes());
    }
    for n in 1..=7 {
        let text = key_file(&f, n, 0);
        assert!(
            matches!(read(&f, &text), KeyFileState::Keys(_)),
            "{n} records"
        );
    }
    ck.gap();
    for (i, (name, text)) in must_fail(&f).iter().enumerate() {
        let state = read(&f, text);
        assert!(
            matches!(state, KeyFileState::KeysMissing(_)),
            "{name}: {state:?}"
        );
        ck.file(
            name,
            &format!("keyfile-fail-{:02}.txt", i + 1),
            text.as_bytes(),
        );
    }
    ck.finish();
}

#[test]
fn b7_log_entries() {
    let mut ck = Checker::open("B.7 ");
    let f = fixture();
    let record = LogEntry::Record(f.records[0].clone());
    let next = LogKey::new("chat.example.org/risala-log/2", ml(0x0a).public_key()).unwrap();
    ck.eq("hand-off to", next.origin());
    ck.hex("its key seed", &seed(0x0a));
    ck.gap();
    ck.file("record 0's entry", "entry-record.bin", &record.encode());
    let handoff = LogEntry::Handoff(next).encode();
    ck.file("hand-off entry", "entry-handoff.bin", &handoff);
    assert_eq!(LogEntry::decode(&record.encode()).unwrap(), record);
    assert!(LogEntry::decode(&handoff).is_ok());
    ck.gap();
    let mut type0 = handoff.clone();
    type0[1] = 0;
    ck.rejected(
        "the hand-off entry with type 0",
        LogEntry::decode(&type0).is_err(),
    );
    let mut longer = handoff.clone();
    longer.push(0);
    ck.rejected(
        "the hand-off entry with a byte after it",
        LogEntry::decode(&longer).is_err(),
    );
    ck.finish();
}

#[test]
fn b8_register_and_keys_put() {
    let mut ck = Checker::open("B.8 ");
    let f = fixture();
    let register = encode_records(&f.records[..2]);
    ck.file("REGISTER keyfile", "register.bin", &register);
    ck.eq("KEYS PUT after", f.records[1].hash().to_string());
    let put = encode_records(&f.records[2..3]);
    ck.file("KEYS PUT records", "keys-put.bin", &put);
    assert_eq!(decode_records(&register).unwrap(), f.records[..2]);
    assert_eq!(decode_records(&put).unwrap(), f.records[2..3]);
    ck.finish();
}

#[test]
fn b9_pairing() {
    let mut ck = Checker::open("B.9 ");
    let new_secret = ml(0x0a);
    let content = NewDeviceContent {
        keys: DeviceKeys {
            device_key: new_secret.public_key(),
            attestation_key: xw(0x0b),
            label: "new phone".into(),
        },
        pairing_key: xw(0x0c),
    };
    ck.hex("device key seed", &seed(0x0a));
    ck.hex("attestation key seed", &seed(0x0b));
    ck.eq("label", content.keys.label.as_str());
    ck.hex("pairing key seed", &seed(0x0c));
    ck.eq("host", "chat.example.org");
    ck.hex("secret", &seed(0x0d));
    ck.gap();
    let new = NewDevice::sign_deterministic(content.clone(), &new_secret);
    ck.file("NewDevice", "newdevice.bin", new.encoded());
    let code = PairingCode {
        host: "chat.example.org".parse().unwrap(),
        secret: Zeroizing::new(seed(0x0d)),
        keys_hash: new.keys_hash(),
    };
    ck.hex("keys_hash", &new.keys_hash());
    ck.hex("PairingCode", &code.encode());
    let qr = code.to_qr_text();
    ck.eq("QR text", qr.to_string());
    assert_eq!(
        PairingCode::from_qr_text(&qr).unwrap().encode(),
        code.encode()
    );
    assert_eq!(NewDevice::decode(new.encoded()).unwrap(), new);
    assert_eq!(new.check(&code), Ok(()));
    ck.gap();
    let mut other_hash = code.keys_hash;
    other_hash[47] ^= 1;
    let other_code = PairingCode {
        host: code.host.clone(),
        secret: code.secret.clone(),
        keys_hash: other_hash,
    };
    ck.rejected(
        "the NewDevice checked against keys_hash with its last bit flipped",
        new.check(&other_code) == Err(PairingError::KeysHash),
    );
    let mut bad_signature = new.encoded().to_vec();
    *bad_signature.last_mut().unwrap() ^= 1;
    let bad_signature = NewDevice::decode(&bad_signature).unwrap();
    let bad_code = PairingCode {
        keys_hash: bad_signature.keys_hash(),
        ..code.clone()
    };
    ck.rejected(
        "the NewDevice with the last bit of its signature flipped",
        bad_signature.check(&bad_code) == Err(PairingError::Signature),
    );
    let repeated = NewDevice::sign_deterministic(
        NewDeviceContent {
            pairing_key: content.keys.attestation_key.clone(),
            ..content.clone()
        },
        &new_secret,
    );
    let repeated_code = PairingCode {
        keys_hash: repeated.keys_hash(),
        ..code.clone()
    };
    ck.rejected(
        "a NewDevice whose pairing key is its attestation key",
        repeated.check(&repeated_code) == Err(PairingError::RepeatedKey),
    );
    let mut version = new.encoded().to_vec();
    version[0] = 2;
    ck.rejected(
        "the NewDevice with version 2",
        NewDevice::decode(&version).is_err(),
    );
    let mut version = code.encode().to_vec();
    version[0] = 2;
    ck.rejected(
        "the PairingCode with version 2",
        PairingCode::decode(&version).is_err(),
    );
    ck.finish();
}

#[test]
fn b10_safety_number() {
    let mut ck = Checker::open("B.10 ");
    let f = fixture();
    ck.eq("uid", f.uid.to_string());
    ck.eq(
        "master public key SHA-256",
        sha256(f.master.public_key().as_bytes()),
    );
    ck.gap();
    let sn = SafetyNumber::new(&f.uid, &f.master.public_key());
    ck.hex("fingerprint", sn.fingerprint());
    ck.eq("digits", sn.to_string());
    ck.eq("QR text", sn.to_qr_text());
    assert_eq!(SafetyNumber::from_qr_text(&sn.to_qr_text()).unwrap(), sn);
    ck.finish();
}

/// Every section of Appendix B with vectors is checked: B.1 to B.10
/// here, B.11 to B.18 by risala-mls (`src/vectors.rs`).
#[test]
fn every_section_is_checked() {
    let titles: Vec<String> = sections()
        .into_iter()
        .filter(|s| !s.values.is_empty() || !s.texts.is_empty())
        .map(|s| s.title)
        .collect();
    let expected: Vec<String> = (1..=18).map(|n| format!("B.{n} ")).collect();
    assert_eq!(titles.len(), expected.len(), "{titles:?}");
    for (title, prefix) in titles.iter().zip(&expected) {
        assert!(title.starts_with(prefix), "{title} is not {prefix}");
    }
}

/// Every file in `tests/vectors/` is named in Appendix B, so that none is
/// left behind when a vector changes.
#[test]
fn every_file_is_named() {
    let named: Vec<String> = sections()
        .into_iter()
        .flat_map(|s| s.values)
        .filter_map(|(name, _)| {
            let (_, file) = name.strip_suffix(')')?.rsplit_once(" (file ")?;
            Some(file.to_owned())
        })
        .collect();
    for entry in std::fs::read_dir(FILES).unwrap() {
        let file = entry.unwrap().file_name().into_string().unwrap();
        assert!(named.contains(&file), "{file} is not in Appendix B");
    }
}

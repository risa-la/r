//! Appendix B's test vectors for the identity formats, made by this
//! crate from fixed seeds. Print them with
//!
//! ```text
//! cargo test -p risala-proto --test identity vectors::print -- --ignored --nocapture
//! ```
//!
//! Signatures use the deterministic variant of ML-DSA, so that they can be
//! checked. X-Wing keys are draft-06 KeyGen from their 32-byte seeds.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::auth::{SecretKey, SignLabel, risala_sign_content};
use risala_proto::chain::{Chain, NoHandoffs};
use risala_proto::keyfile::{KeyFile, KeyFileState, NoEntries, Response, read_key_file};
use risala_proto::names::Identity;
use risala_proto::pairing::{NewDevice, NewDeviceContent, PairingCode};
use risala_proto::record::{
    DeviceId, DeviceKeys, LogEntry, LogKey, Record, RecordBody, RecordContent, XWingPublicKey,
    encode_records,
};
use risala_proto::recovery::RecoveryKey;
use risala_proto::safety::SafetyNumber;
use risala_proto::time::Timestamp;
use sha2::Digest as _;
use zeroize::Zeroizing;

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
            "text: no LF after the last line",
            good[..good.len() - 1].to_owned(),
        ),
        (
            "text: a CR before an LF",
            good.replacen(
                &format!("{}\n", url(&f.log)),
                &format!("{}\r\n", url(&f.log)),
                1,
            ),
        ),
        ("text: two spaces in a row", good.replacen("- ", "-  ", 1)),
        (
            "text: first line is not risala-keys/1",
            good.replacen(header, "risala-keys/2", 1),
        ),
        (
            "text: no log line before the records",
            good.replacen(&format!("{log_line}\n"), "", 1),
        ),
        (
            "text: a log line follows another",
            good.replacen(&log_line, &format!("{log_line}\n# x\n{log_line}"), 1),
        ),
        (
            "text: an index line after a - line",
            format!("{good}0 {}\n", r[0].hash()),
        ),
        ("text: base64 without padding", {
            let full = b64(&r[1]);
            good.replacen(&full, full.trim_end_matches('='), 1)
        }),
    ];
    // Replaying.
    let mut wrong_uid = r[1].content().clone();
    wrong_uid.uid = "bob@example.org".parse().unwrap();
    out.push((
        "replay 1: a record of another uid",
        lines(&[r[0].clone(), resign(wrong_uid, &f.signing)]),
    ));
    out.push((
        "replay 2: the first record is not a master record",
        lines(&[r[1].clone()]),
    ));
    let mut wrong_prev = r[2].content().clone();
    wrong_prev.previous = Some(r[0].hash());
    out.push((
        "replay 2: previous is not the record before",
        lines(&[r[0].clone(), r[1].clone(), resign(wrong_prev, &f.signing)]),
    ));
    let mut same_time = r[1].content().clone();
    same_time.time = T0;
    out.push((
        "replay 3: a time not later than the one before",
        lines(&[r[0].clone(), resign(same_time, &f.signing)]),
    ));
    out.push((
        "replay 4: a device record signed by the master key",
        lines(&[r[0].clone(), resign(r[1].content().clone(), &f.master)]),
    ));
    let single = Record::new(r[4].content().clone(), &r[4].signature()[..2420]).unwrap();
    out.push((
        "replay 4: a later master record with one signature",
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
        "replay 5: a device key that is the device-signing key",
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
        "replay 6: a later master record names another log",
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
        "replay 7: removed names a device that is not current",
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
        "replay 9: a log record names the current log",
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
    out.push(("replay 10: a record after a retire record", all));
    let mut misplaced = key_file(f, 7, 0);
    let second_log = format!("log {} {}\n", f.other_log.vkey(), url(&f.other_log));
    misplaced = misplaced.replacen(&second_log, "", 1);
    out.push((
        "replay 11: a record listed under another log than its own",
        misplaced,
    ));
    out
}

/// The values of Appendix B, by name.
pub fn vectors() -> Vec<(String, String)> {
    let f = fixture();
    let mut v: Vec<(String, String)> = Vec::new();
    let mut add = |k: &str, val: String| v.push((k.to_owned(), val));

    // RisalaSign (4.3).
    let content = b"risala";
    let signed = risala_sign_content(SignLabel::Record, content);
    let sig = f
        .device_secret
        .risala_sign_deterministic(SignLabel::Record, content);
    add("risalasign.key", "Appendix B's key".into());
    add("risalasign.label", "record".into());
    add("risalasign.content", "the 6 ASCII bytes risala".into());
    add("risalasign.signcontent.hex", hex(&signed));
    add("risalasign.signature.sha256", sha256(sig.as_bytes()));
    add("risalasign.signature.b64", BASE64.encode(sig.as_bytes()));

    // Recovery key and master key (4.8).
    add("recovery.bytes.hex", hex(f.recovery.as_bytes()));
    add("recovery.text", f.recovery.to_text().to_string());
    add("recovery.uid", f.uid.to_string());
    add(
        "master.public.sha256",
        sha256(f.master.public_key().as_bytes()),
    );
    add("master.public.b64", f.master.public_key().to_string());

    // The log and its log line (4.4, 4.5).
    add("log.origin", f.log.origin().into());
    add("log.key_id", format!("{:08x}", f.log.key_id()));
    add("log.vkey", f.log.vkey());
    add("log.line", format!("log {} {}", f.log.vkey(), url(&f.log)));

    // Device id (4.4, 12.14).
    let id = DeviceId::of(&f.device.device_key);
    add("device.attestation.seed", hex(&seed(0x04)));
    add(
        "device.attestation.sha256",
        sha256(f.device.attestation_key.as_bytes()),
    );
    add("device.id.hex", id.to_string());
    add("device.id.short", id.short());

    // Each record (4.4).
    let names = [
        "master", "device", "device2", "signing", "master2", "log", "retire",
    ];
    for (name, r) in names.iter().zip(&f.records) {
        add(&format!("record.{name}.len"), r.encoded().len().to_string());
        add(&format!("record.{name}.hash"), r.hash().to_string());
        add(
            &format!("record.{name}.content.sha256"),
            sha256(r.content_bytes()),
        );
        add(&format!("record.{name}.b64"), BASE64.encode(r.encoded()));
    }
    let chain = Chain::replay(&f.uid, &f.records[..6]).unwrap();
    add("chain.generation.after_6", chain.generation().to_string());

    // Log entries (4.5).
    let entry = LogEntry::Record(f.records[0].clone()).encode();
    add("entry.record.sha256", sha256(&entry));
    let handoff = LogEntry::Handoff(
        LogKey::new("chat.example.org/risala-log/2", ml(0x0a).public_key()).unwrap(),
    )
    .encode();
    add("entry.handoff.hex", hex(&handoff));
    add("hint.uid.path", risala_proto::record::uid_hint_path(&f.uid));

    // Key files (4.4).
    add("keyfile.two_unlogged", key_file(&f, 2, 0));
    add("keyfile.two_logged", key_file(&f, 2, 2));
    add("keyfile.all_mixed", key_file(&f, 7, 4));
    for (name, text) in must_fail(&f) {
        add(&format!("must_fail.{name}"), text);
    }

    // REGISTER and KEYS PUT (4.7).
    let register = encode_records(&f.records[..2]);
    add("register.keyfile.sha256", sha256(&register));
    add("register.keyfile.b64", BASE64.encode(&register));
    let put = encode_records(&f.records[2..3]);
    add("keysput.after", f.records[1].hash().to_string());
    add("keysput.records.b64", BASE64.encode(&put));

    // Pairing (4.8).
    let new_secret = ml(0x0a);
    let content = NewDeviceContent {
        keys: DeviceKeys {
            device_key: new_secret.public_key(),
            attestation_key: xw(0x0b),
            label: "new phone".into(),
        },
        pairing_key: xw(0x0c),
    };
    let new = NewDevice::sign_deterministic(content, &new_secret);
    add("pair.newdevice.sha256", sha256(new.encoded()));
    add("pair.newdevice.b64", BASE64.encode(new.encoded()));
    let code = PairingCode {
        host: "chat.example.org".into(),
        secret: Zeroizing::new(seed(0x0d)),
        keys_hash: new.keys_hash(),
    };
    add("pair.code.hex", hex(&code.encode()));
    add("pair.qr", code.to_qr_text().to_string());

    // Safety number (12.14).
    let sn = SafetyNumber::new(&f.uid, &f.master.public_key());
    add("safety.fingerprint.hex", hex(sn.fingerprint()));
    add("safety.digits", sn.to_string());
    add("safety.qr", sn.to_qr_text());
    v
}

#[test]
#[ignore = "prints Appendix B's vectors"]
fn print() {
    for (name, value) in vectors() {
        if value.contains('\n') {
            let end = if value.ends_with('\n') {
                ""
            } else {
                "\n(no final LF)\n"
            };
            println!("== {name}\n{value}{end}== end");
        } else {
            println!("{name}: {value}");
        }
    }
}

/// The vectors are valid where they should be, fail where they should,
/// and do not change by accident.
#[test]
fn vectors_check() {
    let f = fixture();
    let now = Timestamp::from_unix_millis(T0 + 3_600_000).unwrap();
    let state = |text: &str| {
        read_key_file(
            Response::Body {
                status: 200,
                body: text.as_bytes(),
            },
            &f.uid,
            &mut NoEntries,
            &NoHandoffs,
            now,
        )
    };
    for n in 1..=7 {
        let text = key_file(&f, n, 0);
        assert!(matches!(state(&text), KeyFileState::Keys(_)), "{n} records");
    }
    let chain = Chain::replay(&f.uid, &f.records).unwrap();
    assert_eq!(chain.generation(), 2);
    assert!(chain.is_retired());
    for (name, text) in must_fail(&f) {
        assert!(
            matches!(state(&text), KeyFileState::KeysMissing(_)),
            "{name}: {:?}",
            state(&text)
        );
    }
    // Pinned values: a change here changes Appendix B.
    let v: std::collections::HashMap<String, String> = vectors().into_iter().collect();
    let digest = sha256(
        vectors()
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>()
            .as_bytes(),
    );
    assert_eq!(v["log.origin"], "chat.example.org/risala-log/1");
    assert_eq!(v["safety.digits"].len(), 47);
    assert_eq!(digest, VECTORS_SHA256, "the vectors changed");
}

/// SHA-256 of every vector, as `name=value` lines.
const VECTORS_SHA256: &str = "f7afeb224cb11e9529832ffea6cecf2ab125a89363435dffc190db11c2dc9b42";

//! Bytes into the identity formats (SPEC 4.4, 4.5, 4.7, 4.8, 12.14).
//!
//! - `KeyFile::parse` never panics; a file it accepts writes back to the
//!   same text, which parses to the same file; and checking it never
//!   panics either.
//! - `Record::decode`, `LogEntry::decode`, `decode_records`,
//!   `PairingCode::decode`, `NewDevice::decode`, `SealedBundle::decode`
//!   and `SafetyNumber::from_qr_text` never panic, and what they accept
//!   encodes back to the same bytes.
//!
//! A fuzzer never guesses a signed record or a 1,800-character verifier
//! key, so in key file input `$L` is replaced with a real `log` line and
//! `$R` followed by a byte with one of the real records of a short chain,
//! as a `- <record>` line or as an `<index> <hash>` line.

#![no_main]

use std::sync::OnceLock;

use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use risala_proto::auth::SecretKey;
use risala_proto::chain::NoHandoffs;
use risala_proto::keyfile::{EntryError, KeyFile, LogLine};
use risala_proto::names::Identity;
use risala_proto::pairing::{NewDevice, PairingCode, SealedBundle};
use risala_proto::record::{
    DeviceKeys, LogEntry, LogKey, Record, RecordBody, RecordContent, decode_records, encode_records,
};
use risala_proto::safety::SafetyNumber;
use risala_proto::time::Timestamp;

struct Fixture {
    log_line: String,
    records: Vec<Record>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let uid: Identity = "alice@example.org".parse().unwrap();
        let master = SecretKey::from_seed([1; 32]);
        let signing = SecretKey::from_seed([2; 32]);
        let log = LogKey::new(
            "chat.example.org/risala-log/1",
            SecretKey::from_seed([3; 32]).public_key(),
        )
        .unwrap();
        let first = Record::sign_deterministic(
            RecordContent {
                uid: uid.clone(),
                previous: None,
                time: 1,
                body: RecordBody::Master {
                    master_key: master.public_key(),
                    signing_key: signing.public_key(),
                    log: log.clone(),
                },
            },
            &master,
        )
        .unwrap();
        let mut records = vec![first];
        // An X-Wing-shaped key whose coefficients are all zero passes the
        // checks of 12.2, which is all the fuzzer needs.
        let attestation = risala_proto::record::XWingPublicKey::from_bytes(&[0u8; 1216]).unwrap();
        let content = RecordContent {
            uid: uid.clone(),
            previous: Some(records[0].hash()),
            time: 2,
            body: RecordBody::Device(DeviceKeys {
                device_key: SecretKey::from_seed([4; 32]).public_key(),
                attestation_key: attestation,
                label: "laptop".into(),
            }),
        };
        records.push(Record::sign_deterministic(content, &signing).unwrap());
        Fixture {
            log_line: format!("log {} https://chat.example.org/risala-log/1", log.vkey()),
            records,
        }
    })
}

/// Replaces `$L` with a log line and `$R<k>` with a record line.
fn expand(data: &[u8]) -> Vec<u8> {
    let f = fixture();
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        match (data[i], data.get(i + 1), data.get(i + 2)) {
            (b'$', Some(b'L'), _) => {
                out.extend_from_slice(f.log_line.as_bytes());
                i += 2;
            }
            (b'$', Some(b'R'), Some(&k)) => {
                let r = &f.records[usize::from(k >> 1) % f.records.len()];
                let line = if k & 1 == 0 {
                    format!(
                        "- {}",
                        base64::engine::general_purpose::STANDARD.encode(r.encoded())
                    )
                } else {
                    format!("{} {}", k >> 1, r.hash())
                };
                out.extend_from_slice(line.as_bytes());
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // Binary structures.
    if let Ok(r) = Record::decode(data) {
        assert_eq!(r.encoded(), data);
    }
    if let Ok(e) = LogEntry::decode(data) {
        assert_eq!(e.encode(), data);
    }
    if let Ok(records) = decode_records(data) {
        assert_eq!(encode_records(&records), data);
    }
    if let Ok(code) = PairingCode::decode(data) {
        assert_eq!(&code.encode()[..], data);
    }
    if let Ok(new) = NewDevice::decode(data) {
        assert_eq!(new.encoded(), data);
    }
    if let Ok(sealed) = SealedBundle::decode(data) {
        assert_eq!(sealed.encode(), data);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(sn) = SafetyNumber::from_qr_text(text) {
            assert_eq!(sn.to_qr_text(), text);
        }
    }

    // Key files.
    let text = expand(data);
    let Ok(file) = KeyFile::parse(&text) else {
        return;
    };
    let written = file.to_text();
    assert_eq!(KeyFile::parse(written.as_bytes()).as_ref(), Ok(&file));
    let f = fixture();
    let uid: Identity = "alice@example.org".parse().unwrap();
    let mut entries = |_: &LogLine, index: u64| -> Result<Vec<u8>, EntryError> {
        f.records
            .get(index as usize)
            .map(|r| LogEntry::Record(r.clone()).encode())
            .ok_or(EntryError::Missing)
    };
    let _ = file.check(
        &uid,
        &mut entries,
        &NoHandoffs,
        Timestamp::from_unix_millis(1_000_000).unwrap(),
    );
});

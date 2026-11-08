//! Encodings (4.3, 4.4, 4.5, 4.7, 4.8, 12.14) and their must-fail cases.

use risala_proto::auth::{RISALA_SIGN_PREFIX, SignLabel, risala_sign_content};
use risala_proto::codec::Writer;
use risala_proto::names::BlobRef;
use risala_proto::pairing::{
    NewDevice, NewDeviceContent, PAIR_QR_PREFIX, PairingCode, PairingError, SealedBundle,
    XWING_ENC_LEN,
};
use risala_proto::record::{
    LogEntry, LogKey, MAX_RECORD_LEN, Record, RecordBody, RecordContent, RecordError,
    XWingPublicKey, decode_records, encode_records, parse_origin,
};
use risala_proto::recovery::RecoveryKey;
use risala_proto::safety::{SAFETY_QR_PREFIX, SafetyNumber};
use zeroize::Zeroizing;

use super::*;

#[test]
fn risala_sign() {
    let k = key(1);
    let content = b"some content";
    let sig = k.risala_sign(SignLabel::Record, content, [3; 32]);
    assert!(
        k.public_key()
            .risala_verify(SignLabel::Record, content, sig.as_bytes())
    );
    // Another label, other content, another key or a cut signature fail.
    for label in SignLabel::ALL {
        let ok = k.public_key().risala_verify(label, content, sig.as_bytes());
        assert_eq!(ok, label == SignLabel::Record, "{label:?}");
    }
    assert!(
        !k.public_key()
            .risala_verify(SignLabel::Record, b"other", sig.as_bytes())
    );
    assert!(
        !key(2)
            .public_key()
            .risala_verify(SignLabel::Record, content, sig.as_bytes())
    );
    assert!(
        !k.public_key()
            .risala_verify(SignLabel::Record, content, &sig.as_bytes()[1..])
    );
    // The deterministic variant verifies too, and is reproducible.
    let det = k.risala_sign_deterministic(SignLabel::Pair, content);
    assert_eq!(det, k.risala_sign_deterministic(SignLabel::Pair, content));
    assert!(
        k.public_key()
            .risala_verify(SignLabel::Pair, content, det.as_bytes())
    );
    // The signed bytes: label<V> then content<V>.
    let signed = risala_sign_content(SignLabel::KeyPackage, b"ab");
    let mut want = vec![19];
    want.extend_from_slice(format!("{RISALA_SIGN_PREFIX}keypackage").as_bytes());
    want.extend_from_slice(&[2, b'a', b'b']);
    assert_eq!(signed, want);
    // Plain ML-DSA over the content alone does not verify as RisalaSign:
    // sign-in signatures (4.6) cannot be replayed as records.
    let nonce = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e".parse().unwrap();
    let auth = k.sign_challenge("chat.example.org", &nonce, "alice@example.org");
    let challenge =
        risala_proto::auth::challenge_bytes("chat.example.org", &nonce, "alice@example.org");
    assert!(
        !k.public_key()
            .risala_verify(SignLabel::Record, &challenge, auth.as_bytes())
    );
}

#[test]
fn log_keys() {
    let log = log1();
    assert_eq!(log.origin(), "chat.example.org/risala-log/1");
    assert_eq!((log.host(), log.number()), ("chat.example.org", 1));
    let vkey = log.vkey();
    assert_eq!(LogKey::from_vkey(&vkey).unwrap(), log);
    // The key log crate reads the same verifier key, with the same id.
    let theirs = risala_keylog::LogKey::from_vkey_str(&vkey).unwrap();
    assert_eq!(theirs.origin().to_string(), log.origin());
    let note: risala_keylog::VerifierKey = vkey.parse().unwrap();
    assert_eq!(note.key_id(), log.key_id());
    assert_eq!(note.public_key(), log.public_key().as_bytes());
    assert_eq!(note.sig_type(), 0x06);

    // A wrong key id, a key of another type, a bad origin.
    let mut parts: Vec<String> = vkey.splitn(3, '+').map(str::to_owned).collect();
    parts[1] = format!("{:08x}", log.key_id() ^ 1);
    assert!(LogKey::from_vkey(&parts.join("+")).is_err());
    let mut bytes = log.key_bytes();
    bytes[0] = 0x01;
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    assert!(LogKey::from_vkey(&format!("{}+{:08x}+{b64}", log.origin(), log.key_id())).is_err());
    assert!(LogKey::new("chat.example.org/log/1", key(1).public_key()).is_err());

    for bad in [
        "Chat.example.org/risala-log/1",
        "chat.example.org/risala-log/0",
        "chat.example.org/risala-log/01",
        "chat.example.org:443/risala-log/1",
        "/risala-log/1",
        "chat.example.org/risala-log/",
        "-chat.example.org/risala-log/1",
    ] {
        assert!(parse_origin(bad).is_none(), "{bad}");
    }
    assert_eq!(
        parse_origin("localhost/risala-log/12"),
        Some(("localhost", 12))
    );
}

#[test]
fn records_round_trip() {
    let mut b = Builder::new(&log1());
    b.device(1, "laptop")
        .device(2, "phone")
        .signing(151, &[2])
        .rotate(101, 152, &log1())
        .log(&log_on("keys.example.net", 1, 201))
        .retire();
    for record in &b.records {
        let decoded = Record::decode(record.encoded()).unwrap();
        assert_eq!(&decoded, record);
        assert_eq!(decoded.content(), record.content());
        assert_eq!(decoded.hash(), BlobRef::of(record.encoded()));
        assert_eq!(decoded.content_bytes(), &record.content().encode()[..]);
        // Every entry is a record entry, which decodes again.
        let entry = LogEntry::Record(record.clone());
        let bytes = entry.encode();
        assert_eq!(&bytes[..2], &[1, 1]);
        assert_eq!(LogEntry::decode(&bytes).unwrap(), entry);
        assert!(entry.is_record(&record.hash()));
    }
    // The payload of REGISTER and KEYS PUT.
    let payload = encode_records(&b.records);
    assert_eq!(payload[0], 1);
    assert_eq!(decode_records(&payload).unwrap(), b.records);
}

/// Writes a Record by hand, so that each field can be broken.
struct Raw {
    version: u8,
    ty: u8,
    uid: Vec<u8>,
    previous: Vec<u8>,
    time: u64,
    body: Vec<u8>,
    signature: Vec<u8>,
}

impl Raw {
    fn device() -> Raw {
        let keys = device_keys(1, "x");
        let mut body = Writer::new();
        body.vector(keys.device_key.as_bytes())
            .vector(keys.attestation_key.as_bytes())
            .vector(b"x");
        Raw {
            version: 1,
            ty: 3,
            uid: b"alice@example.org".to_vec(),
            previous: vec![7; 48],
            time: T0,
            body: body.finish(),
            signature: vec![0; 2420],
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version)
            .u8(self.ty)
            .vector(&self.uid)
            .vector(&self.previous)
            .u64(self.time)
            .fixed(&self.body)
            .vector(&self.signature);
        w.finish()
    }
}

#[test]
fn records_that_do_not_decode() {
    assert!(Record::decode(&Raw::device().encode()).is_ok());
    let fails = |raw: Raw| Record::decode(&raw.encode()).unwrap_err();
    assert_eq!(
        fails(Raw {
            version: 2,
            ..Raw::device()
        }),
        RecordError::Version(2)
    );
    assert_eq!(
        fails(Raw {
            ty: 0,
            ..Raw::device()
        }),
        RecordError::Type(0)
    );
    assert_eq!(
        fails(Raw {
            ty: 6,
            ..Raw::device()
        }),
        RecordError::Type(6)
    );
    // A uid in upper case, or not an identity.
    assert!(matches!(
        fails(Raw {
            uid: b"Alice@example.org".to_vec(),
            ..Raw::device()
        }),
        RecordError::Malformed(_)
    ));
    assert!(matches!(
        fails(Raw {
            uid: b"~sam".to_vec(),
            ..Raw::device()
        }),
        RecordError::Malformed(_)
    ));
    // previous neither empty nor 48 bytes.
    assert!(matches!(
        fails(Raw {
            previous: vec![7; 47],
            ..Raw::device()
        }),
        RecordError::Malformed(_)
    ));
    // Over 16 KiB.
    let big = Raw {
        signature: vec![0; MAX_RECORD_LEN],
        ..Raw::device()
    };
    assert_eq!(fails(big), RecordError::TooLarge);

    // Keys of the wrong length, an X-Wing key that fails the modulus
    // check, a label over 64 bytes or not UTF-8.
    let body = |dk: &[u8], ak: &[u8], label: &[u8]| {
        let mut w = Writer::new();
        w.vector(dk).vector(ak).vector(label);
        Raw {
            body: w.finish(),
            ..Raw::device()
        }
    };
    let (dk, ak) = (
        key(1).public_key().as_bytes().to_vec(),
        xwing(1).as_bytes().to_vec(),
    );
    assert!(Record::decode(&body(&dk, &ak, &[b'a'; 64]).encode()).is_ok());
    assert!(matches!(
        fails(body(&dk[1..], &ak, b"x")),
        RecordError::Malformed(_)
    ));
    assert!(matches!(
        fails(body(&dk, &ak[1..], b"x")),
        RecordError::Malformed(_)
    ));
    // The first coefficient is the low 12 bits of the first two bytes.
    let mut high = ak.clone();
    high[0] = 0x01;
    high[1] = (ak[1] & 0xf0) | 0x0d; // 0xd01 = 3329 = q
    assert!(XWingPublicKey::from_bytes(&high).is_err());
    assert!(matches!(
        fails(body(&dk, &high, b"x")),
        RecordError::Malformed(_)
    ));
    let mut ok = ak.clone();
    ok[0] = 0x00;
    ok[1] = (ak[1] & 0xf0) | 0x0d; // 3328, the largest coefficient
    assert!(XWingPublicKey::from_bytes(&ok).is_ok());
    // The last coefficient of t-hat, in bytes 1150 and 1151.
    let mut last = ak.clone();
    last[1151] = 0xd0;
    last[1150] = (last[1150] & 0x0f) | 0x10; // 0xd01
    assert!(XWingPublicKey::from_bytes(&last).is_err());
    // The X25519 part and rho are not checked.
    let mut tail = ak.clone();
    tail[1215] ^= 0xff;
    tail[1153] ^= 0xff;
    assert!(XWingPublicKey::from_bytes(&tail).is_ok());
    assert!(matches!(
        fails(body(&dk, &ak, &[b'a'; 65])),
        RecordError::Malformed(_)
    ));
    assert!(matches!(
        fails(body(&dk, &ak, &[0xff])),
        RecordError::Malformed(_)
    ));
    // Bytes after the last field.
    let mut trailing = Raw::device().encode();
    trailing.push(0);
    assert!(Record::decode(&trailing).is_err());
    // A vector length that is not in its shortest form.
    let mut long = Raw::device().encode();
    // The uid's length, 17, written in two bytes.
    assert_eq!(long[2], 17);
    long.splice(2..3, [0x40, 17]);
    assert!(Record::decode(&long).is_err());
    // Cut short anywhere.
    let whole = Raw::device().encode();
    for cut in [0, 1, 5, 40, whole.len() - 1] {
        assert!(Record::decode(&whole[..cut]).is_err(), "{cut}");
    }

    // A removed list that is not a multiple of 48 bytes.
    let mut w = Writer::new();
    w.vector(key(151).public_key().as_bytes()).vector(&[1; 47]);
    assert!(matches!(
        fails(Raw {
            ty: 2,
            body: w.finish(),
            ..Raw::device()
        }),
        RecordError::Malformed(_)
    ));
    // A LogKey whose key does not start with 0x06, or is too short.
    let log = |origin: &[u8], key: &[u8]| {
        let mut w = Writer::new();
        w.vector(origin).vector(key);
        Raw {
            ty: 4,
            body: w.finish(),
            ..Raw::device()
        }
    };
    let good = log1().key_bytes();
    assert!(Record::decode(&log(b"chat.example.org/risala-log/1", &good).encode()).is_ok());
    let mut wrong = good;
    wrong[0] = 0x04;
    assert!(matches!(
        fails(log(b"chat.example.org/risala-log/1", &wrong)),
        RecordError::Malformed(_)
    ));
    assert!(
        Record::decode(&log(b"chat.example.org/risala-log/1", &good[..1312]).encode()).is_err()
    );
    assert!(Record::decode(&log(b"chat.example.org/log/1", &good).encode()).is_err());
}

#[test]
fn payloads_that_do_not_decode() {
    let b = Builder::new(&log1());
    let good = encode_records(&b.records);
    let mut v2 = good.clone();
    v2[0] = 2;
    assert_eq!(decode_records(&v2).unwrap_err(), RecordError::Version(2));
    assert!(decode_records(&encode_records(&[])).is_err());
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(decode_records(&trailing).is_err());
    assert!(decode_records(&good[..good.len() - 1]).is_err());
}

#[test]
fn log_entries() {
    let next = log_on("chat.example.org", 2, 201);
    let entry = LogEntry::Handoff(next.clone());
    let bytes = entry.encode();
    assert_eq!(&bytes[..2], &[1, 2]);
    assert_eq!(LogEntry::decode(&bytes).unwrap(), entry);
    assert!(!entry.is_record(&BlobRef::of(b"")));
    let mut bad = bytes.clone();
    bad[1] = 3;
    assert_eq!(LogEntry::decode(&bad).unwrap_err(), RecordError::Type(3));
    bad[1] = 0;
    assert_eq!(LogEntry::decode(&bad).unwrap_err(), RecordError::Type(0));
    let mut bad = bytes.clone();
    bad[0] = 2;
    assert_eq!(LogEntry::decode(&bad).unwrap_err(), RecordError::Version(2));
    let mut trailing = bytes;
    trailing.push(1);
    assert!(LogEntry::decode(&trailing).is_err());
}

#[test]
fn log_entries_match_the_key_log() {
    // The key log crate writes the same LogEntry bytes (4.5).
    let b = Builder::new(&log1());
    let ours = LogEntry::Record(b.records[0].clone()).encode();
    let theirs = risala_keylog::entry::LogEntry::record(b.records[0].encoded())
        .unwrap()
        .encode();
    assert_eq!(ours, theirs);
    assert_eq!(
        risala_keylog::entry::record_hash(b.records[0].encoded()),
        *b.records[0].hash().hash()
    );
    let next = log_on("chat.example.org", 2, 201);
    let ours = LogEntry::Handoff(next.clone()).encode();
    let key = risala_keylog::LogKey::from_vkey_str(&next.vkey()).unwrap();
    let theirs = risala_keylog::entry::LogEntry::Handoff(key).encode();
    assert_eq!(ours, theirs);
    assert_eq!(LogEntry::decode(&theirs).unwrap(), LogEntry::Handoff(next));
}

#[test]
fn recovery_keys() {
    let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
    let recovery = RecoveryKey::from_bytes(bytes);
    let master = recovery.master_key(&alice());
    // Derivation: HKDF-SHA384 with an empty salt and the uid in the info.
    let b = Builder::with_keys(alice(), master.clone(), key(150), &log1());
    let chain = risala_proto::chain::Chain::replay(&b.uid, &b.records).unwrap();
    assert_eq!(
        recovery.master_key_for(&chain).unwrap().public_key(),
        master.public_key()
    );
    let wrong = RecoveryKey::from_bytes([9; 32]);
    assert!(wrong.master_key_for(&chain).is_none());
    // Typed back with other case, hyphens and no spaces.
    let typed = recovery.to_text().replace(' ', "-").to_uppercase();
    assert_eq!(RecoveryKey::parse(&typed).unwrap(), recovery);
}

fn new_device() -> (NewDevice, PairingCode) {
    let content = NewDeviceContent {
        keys: device_keys(5, "new phone"),
        pairing_key: xwing(50),
    };
    let new = NewDevice::sign_deterministic(content, &key(5));
    let code = PairingCode {
        host: "chat.example.org".into(),
        secret: Zeroizing::new([0x42; 32]),
        keys_hash: new.keys_hash(),
    };
    (new, code)
}

#[test]
fn pairing() {
    let (new, code) = new_device();
    assert_eq!(new.encoded()[0], 1);
    let decoded = NewDevice::decode(new.encoded()).unwrap();
    assert_eq!(decoded, new);
    decoded.check(&code).unwrap();

    // The QR code.
    let text = code.to_qr_text();
    assert!(text.starts_with(PAIR_QR_PREFIX));
    assert!(
        text[PAIR_QR_PREFIX.len()..]
            .bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
    );
    assert_eq!(PairingCode::from_qr_text(&text).unwrap(), code);
    assert!(PairingCode::from_qr_text(&text.to_lowercase()).is_err());
    assert!(PairingCode::from_qr_text(&text[PAIR_QR_PREFIX.len()..]).is_err());
    assert!(PairingCode::from_qr_text(&format!("{}A", *text)).is_err());
    assert!(
        !format!("{code:?}").contains("66"),
        "the secret stays out of Debug"
    );

    // A host in upper case, or with a port.
    let mut bad = code.clone();
    bad.host = "Chat.example.org".into();
    assert!(PairingCode::decode(&bad.encode()).is_err());
    bad.host = "chat.example.org:7472".into();
    assert!(PairingCode::decode(&bad.encode()).is_err());
    let mut v2 = code.encode().to_vec();
    v2[0] = 2;
    assert_eq!(
        PairingCode::decode(&v2).unwrap_err(),
        RecordError::Version(2)
    );

    // Another device's offer, a forged signature, a reused key.
    let other = PairingCode {
        keys_hash: [0; 48],
        ..code.clone()
    };
    assert_eq!(new.check(&other), Err(PairingError::KeysHash));
    let forged = NewDevice::sign_deterministic(new.content().clone(), &key(6));
    let forged_code = PairingCode {
        keys_hash: forged.keys_hash(),
        ..code.clone()
    };
    assert_eq!(forged.check(&forged_code), Err(PairingError::Signature));
    let mut content = new.content().clone();
    content.pairing_key = content.keys.attestation_key.clone();
    let reused = NewDevice::sign_deterministic(content, &key(5));
    let reused_code = PairingCode {
        keys_hash: reused.keys_hash(),
        ..code.clone()
    };
    assert_eq!(reused.check(&reused_code), Err(PairingError::RepeatedKey));
    // Signed as a record instead of under `pair`.
    let sig = key(5).risala_sign_deterministic(SignLabel::Record, &new.content().encode());
    let mut w = Writer::new();
    w.u8(1)
        .fixed(&new.content().encode())
        .vector(sig.as_bytes());
    let relabelled = NewDevice::decode(&w.finish()).unwrap();
    let relabelled_code = PairingCode {
        keys_hash: relabelled.keys_hash(),
        ..code
    };
    assert_eq!(
        relabelled.check(&relabelled_code),
        Err(PairingError::Signature)
    );

    // SealedBundle.
    let sealed = SealedBundle {
        enc: Box::new([9; XWING_ENC_LEN]),
        ciphertext: vec![1, 2, 3],
    };
    let bytes = sealed.encode();
    assert_eq!(bytes.len(), 1 + 1120 + 1 + 3);
    assert_eq!(SealedBundle::decode(&bytes).unwrap(), sealed);
    assert!(SealedBundle::decode(&bytes[..1100]).is_err());
}

#[test]
fn safety_numbers() {
    let sn = SafetyNumber::new(&alice(), &key(100).public_key());
    let digits = sn.digits();
    assert_eq!(digits.len(), 40);
    assert!(digits.bytes().all(|b| b.is_ascii_digit()));
    let shown = sn.to_string();
    assert_eq!(shown.split(' ').count(), 8);
    assert!(shown.split(' ').all(|g| g.len() == 5));
    // Each group is 5 bytes, big-endian, modulo 100000.
    let fp = sn.fingerprint();
    let first = fp[..5].iter().fold(0u64, |n, &b| (n << 8) | u64::from(b)) % 100_000;
    assert_eq!(&digits[..5], format!("{first:05}"));

    let text = sn.to_qr_text();
    assert!(text.starts_with(SAFETY_QR_PREFIX));
    assert_eq!(SafetyNumber::from_qr_text(&text).unwrap(), sn);
    assert!(SafetyNumber::from_qr_text(&text.to_lowercase()).is_err());
    // Another master key or another uid gives another number.
    assert_ne!(sn, SafetyNumber::new(&alice(), &key(101).public_key()));
    let bob = "bob@example.org".parse().unwrap();
    assert_ne!(
        sn.fingerprint(),
        SafetyNumber::new(&bob, &key(100).public_key()).fingerprint()
    );
}

#[test]
fn record_content_is_what_is_signed() {
    let b = Builder::new(&log1());
    let first = &b.records[0];
    let content: &RecordContent = first.content();
    assert!(content.is_first_master());
    assert!(key(100).public_key().risala_verify(
        SignLabel::Record,
        &content.encode(),
        first.signature()
    ));
    assert!(matches!(content.body, RecordBody::Master { .. }));
}

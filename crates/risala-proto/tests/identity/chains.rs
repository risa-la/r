//! Replaying chains (4.4), pins and forks (4.5), KEYS PUT and REGISTER
//! (4.7).

use risala_proto::auth::SignLabel;
use risala_proto::chain::{Chain, KeysPutError, NoHandoffs, Pin, Rule, check_register, keys_put};
use risala_proto::record::{
    DeviceId, LogKey, MAX_DEVICES, Record, RecordBody, RecordContent, decode_records,
    encode_records,
};

use super::*;

fn replay(b: &Builder) -> Result<Chain, Rule> {
    Chain::replay(&b.uid, &b.records).map_err(|e| e.rule)
}

/// The rule the last record of `b` breaks.
fn last_fails(b: &Builder, rule: Rule) {
    let e = Chain::replay(&b.uid, &b.records).unwrap_err();
    assert_eq!((e.index, e.rule), (b.records.len() - 1, rule));
}

#[test]
fn a_whole_chain_replays() {
    let other = log_on("keys.example.net", 1, 201);
    let mut b = Builder::new(&log1());
    b.device(1, "laptop").device(2, "phone");
    let chain = replay(&b).unwrap();
    assert_eq!(chain.generation(), 0);
    assert_eq!(chain.devices().len(), 2);
    assert_eq!(chain.devices()[&device_id(1)].keys.label, "laptop");
    assert_eq!(chain.device_by_key(&key(2).public_key()).unwrap().index, 2);

    b.signing(151, &[2]);
    let chain = replay(&b).unwrap();
    assert_eq!(chain.generation(), 1);
    assert_eq!(chain.devices().len(), 1);
    assert!(chain.removed().contains(&device_id(2)));
    assert_eq!(*chain.signing_key(), key(151).public_key());

    b.rotate(101, 152, &log1()).device(3, "tablet");
    let chain = replay(&b).unwrap();
    // Generation: one signing record and one later master record.
    assert_eq!(chain.generation(), 2);
    assert_eq!(*chain.master_key(), key(101).public_key());
    assert_eq!(*chain.first_master_key(), key(100).public_key());
    assert_eq!(
        chain.devices().len(),
        2,
        "devices stay across a new master key"
    );

    b.log(&other);
    let chain = replay(&b).unwrap();
    assert_eq!(chain.log(), &other);
    assert_eq!(chain.placements().last(), Some(&log1()));

    b.device(4, "desk").retire();
    let chain = replay(&b).unwrap();
    assert!(chain.is_retired());
    assert!(chain.devices().is_empty());
    for n in [1, 2, 3, 4] {
        assert!(chain.removed().contains(&device_id(n)), "{n}");
    }
    assert_eq!(chain.placements().last(), Some(&other));
}

#[test]
fn step_1_uid() {
    let mut b = Builder::new(&log1());
    let mut content = b.next(RecordBody::Device(device_keys(1, "x")));
    content.uid = "bob@example.org".parse().unwrap();
    let signing = b.signing.clone();
    b.push_signed(content, &signing);
    last_fails(&b, Rule::Uid);
    // The first record names another uid than the file's.
    let b = Builder::new(&log1());
    let bob = "bob@example.org".parse().unwrap();
    assert_eq!(Chain::replay(&bob, &b.records).unwrap_err().rule, Rule::Uid);
}

#[test]
fn step_2_first_and_previous() {
    // A first record that is not a master record.
    let b = Builder::new(&log1());
    let mut device = Builder::new(&log1());
    device.device(1, "x");
    let lone = device.records[1].clone();
    assert_eq!(
        Chain::replay(&b.uid, &[lone]).unwrap_err().rule,
        Rule::First
    );
    // A master record with a previous, first.
    let mut b2 = Builder::new(&log1());
    b2.rotate(101, 151, &log1());
    assert_eq!(
        Chain::replay(&b2.uid, &b2.records[1..]).unwrap_err().rule,
        Rule::First
    );
    // A second first master record.
    let mut b3 = Builder::new(&log1());
    let other = Builder::with_keys(alice(), key(101), key(151), &log1());
    b3.records.push(other.records[0].clone());
    last_fails(&b3, Rule::First);
    // A previous that is not the record before.
    let mut b4 = Builder::new(&log1());
    b4.device(1, "x");
    let mut content = b4.next(RecordBody::Device(device_keys(2, "y")));
    content.previous = Some(b4.records[0].hash());
    let signing = b4.signing.clone();
    b4.push_signed(content, &signing);
    last_fails(&b4, Rule::Previous);
}

#[test]
fn step_3_time_increases() {
    let mut b = Builder::new(&log1());
    let mut content = b.next(RecordBody::Device(device_keys(1, "x")));
    content.time = T0;
    let signing = b.signing.clone();
    b.push_signed(content, &signing);
    last_fails(&b, Rule::Time);
}

#[test]
fn step_4_signatures() {
    // Signed by the wrong key: a device record by the master key.
    let mut b = Builder::new(&log1());
    let content = b.next(RecordBody::Device(device_keys(1, "x")));
    let master = b.master.clone();
    b.push_signed(content, &master);
    last_fails(&b, Rule::Signature);

    // A signing record by the device-signing key.
    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let content = b.next(RecordBody::Signing {
        signing_key: key(151).public_key(),
        removed: vec![device_id(1)],
    });
    let signing = b.signing.clone();
    b.push_signed(content, &signing);
    last_fails(&b, Rule::Signature);

    // Under another label.
    let mut b = Builder::new(&log1());
    let content = b.next(RecordBody::Device(device_keys(1, "x")));
    let sig = b
        .signing
        .risala_sign_deterministic(SignLabel::Pair, &content.encode());
    b.records
        .push(Record::new(content, sig.as_bytes()).unwrap());
    last_fails(&b, Rule::Signature);

    // A later master record with only the old key's signature.
    let mut b = Builder::new(&log1());
    let content = b.next(RecordBody::Master {
        master_key: key(101).public_key(),
        signing_key: key(151).public_key(),
        log: log1(),
    });
    let master = b.master.clone();
    b.push_signed(content.clone(), &master);
    last_fails(&b, Rule::SignatureLength);
    // Two signatures, both by the old key.
    b.records.pop();
    let bytes = content.encode();
    let mut sig = master
        .risala_sign_deterministic(SignLabel::Record, &bytes)
        .as_bytes()
        .to_vec();
    sig.extend_from_slice(
        master
            .risala_sign_deterministic(SignLabel::Record, &bytes)
            .as_bytes(),
    );
    b.records.push(Record::new(content.clone(), &sig).unwrap());
    last_fails(&b, Rule::Signature);
    // The two signatures in the wrong order.
    b.records.pop();
    let new = key(101);
    let mut sig = new
        .risala_sign_deterministic(SignLabel::Record, &bytes)
        .as_bytes()
        .to_vec();
    sig.extend_from_slice(
        master
            .risala_sign_deterministic(SignLabel::Record, &bytes)
            .as_bytes(),
    );
    b.records.push(Record::new(content, &sig).unwrap());
    last_fails(&b, Rule::Signature);

    // A first master record with a double signature.
    let b = Builder::new(&log1());
    let first = &b.records[0];
    let mut sig = first.signature().to_vec();
    sig.extend_from_slice(first.signature());
    let doubled = Record::new(first.content().clone(), &sig).unwrap();
    assert_eq!(
        Chain::replay(&b.uid, &[doubled]).unwrap_err().rule,
        Rule::SignatureLength
    );
    // A first master record signed by another key.
    let content = first.content().clone();
    let bad = Record::sign_deterministic(content, &key(99)).unwrap();
    assert_eq!(
        Chain::replay(&b.uid, &[bad]).unwrap_err().rule,
        Rule::Signature
    );
}

#[test]
fn step_5_no_key_twice() {
    // The master key as the device-signing key.
    let b = Builder::with_keys(alice(), key(100), key(100), &log1());
    assert_eq!(replay(&b).unwrap_err(), Rule::RepeatedKey);
    // A device key that is the device-signing key.
    let mut b = Builder::new(&log1());
    b.device(150, "x");
    last_fails(&b, Rule::RepeatedKey);
    // A new device-signing key that was a master key.
    let mut b = Builder::new(&log1());
    b.device(1, "x").signing(100, &[1]);
    last_fails(&b, Rule::RepeatedKey);
    // A device whose attestation key another device has.
    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let mut keys = device_keys(2, "y");
    keys.attestation_key = xwing(1);
    let content = b.next(RecordBody::Device(keys));
    let signing = b.signing.clone();
    b.push_signed(content, &signing);
    last_fails(&b, Rule::RepeatedKey);
}

#[test]
fn step_6_later_master_keeps_the_log() {
    let mut b = Builder::new(&log1());
    b.rotate(101, 151, &log_on("chat.example.org", 2, 201));
    last_fails(&b, Rule::MasterLog);
}

#[test]
fn step_7_removed() {
    let mut b = Builder::new(&log1());
    b.device(1, "x").signing(151, &[]);
    last_fails(&b, Rule::NothingRemoved);

    let mut b = Builder::new(&log1());
    b.device(1, "x").device(2, "y");
    let mut removed = vec![device_id(1), device_id(2)];
    removed.sort();
    removed.reverse();
    let content = b.next(RecordBody::Signing {
        signing_key: key(151).public_key(),
        removed,
    });
    let master = b.master.clone();
    b.push_signed(content, &master);
    last_fails(&b, Rule::RemovedOrder);

    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let content = b.next(RecordBody::Signing {
        signing_key: key(151).public_key(),
        removed: vec![device_id(1), device_id(1)],
    });
    let master = b.master.clone();
    b.push_signed(content, &master);
    last_fails(&b, Rule::RemovedOrder);

    let mut b = Builder::new(&log1());
    b.device(1, "x").signing(151, &[2]);
    last_fails(&b, Rule::RemovedNotCurrent);
    // A device removed already is not current.
    let mut b = Builder::new(&log1());
    b.device(1, "x")
        .device(2, "y")
        .signing(151, &[2])
        .signing(152, &[2]);
    last_fails(&b, Rule::RemovedNotCurrent);
}

#[test]
fn step_8_devices() {
    // A removed device cannot come back.
    let mut b = Builder::new(&log1());
    b.device(1, "x")
        .device(2, "y")
        .signing(151, &[2])
        .device(2, "again");
    last_fails(&b, Rule::RepeatedKey);
    // Nor be added twice. Its keys repeat too, so step 5 fires first; the
    // id rule is checked by the replay of a chain with a fresh signing key
    // and the same device key, which step 5 also catches. Both are errors.
    let mut b = Builder::new(&log1());
    b.device(1, "x").device(1, "y");
    assert!(replay(&b).is_err());

    // At most 64 current devices.
    let mut b = Builder::new(&log1());
    for n in 1..=MAX_DEVICES as u8 {
        b.device(n, "d");
    }
    assert_eq!(replay(&b).unwrap().devices().len(), MAX_DEVICES);
    b.device(65, "one too many");
    last_fails(&b, Rule::TooManyDevices);
}

#[test]
fn step_9_and_10_log_and_retire() {
    let mut b = Builder::new(&log1());
    b.log(&log1());
    last_fails(&b, Rule::SameLog);

    let mut b = Builder::new(&log1());
    b.device(1, "x").retire().device(2, "y");
    last_fails(&b, Rule::AfterRetire);
}

#[test]
fn step_11_placement_and_handoffs() {
    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let log2 = log_on("chat.example.org", 2, 201);
    let other = log_on("keys.example.net", 1, 202);
    let placed = |logs: [&LogKey; 2], handoffs: &dyn risala_proto::chain::Handoffs| {
        Chain::replay_placed(
            &b.uid,
            b.records.iter().zip(logs).map(|(r, l)| (r, Some(l))),
            handoffs,
        )
        .map_err(|e| e.rule)
    };
    assert!(placed([&log1(), &log1()], &NoHandoffs).is_ok());
    // A first master record is in the log it names.
    assert_eq!(
        placed([&log2, &log2], &NoHandoffs).unwrap_err(),
        Rule::WrongLog
    );
    // A later log of the same host, only after a hand-off.
    assert_eq!(
        placed([&log1(), &log2], &NoHandoffs).unwrap_err(),
        Rule::WrongLog
    );
    let handed =
        |from: &LogKey, to: &LogKey| *from == log1() && *to == log_on("chat.example.org", 2, 201);
    let chain = placed([&log1(), &log2], &handed).unwrap();
    assert_eq!(chain.log(), &log2);
    // Never another host's log, nor an earlier log.
    let anything = |_: &LogKey, _: &LogKey| true;
    assert_eq!(
        placed([&log1(), &other], &anything).unwrap_err(),
        Rule::WrongLog
    );
    let log0 = log_on("chat.example.org", 1, 203);
    assert_eq!(
        placed([&log1(), &log0], &anything).unwrap_err(),
        Rule::WrongLog
    );

    // After a hand-off, a later master record names the new log.
    b.rotate(101, 151, &log2);
    let logs = [log1(), log1(), log2.clone()];
    let chain = Chain::replay_placed(
        &b.uid,
        b.records.iter().zip(&logs).map(|(r, l)| (r, Some(l))),
        &handed,
    )
    .unwrap();
    assert_eq!(chain.log(), &log2);
}

#[test]
fn a_failed_push_changes_nothing() {
    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let mut chain = replay(&b).unwrap();
    let before = chain.head_hash();
    b.device(150, "repeats the signing key");
    let bad = b.records.last().unwrap();
    assert!(chain.push(bad, None, &NoHandoffs).is_err());
    assert_eq!(chain.head_hash(), before);
    assert_eq!(chain.devices().len(), 1);
}

#[test]
fn pins_extends_and_new_master_keys() {
    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let old = replay(&b).unwrap();
    let pin = old.pin();
    b.device(2, "y");
    let newer = replay(&b).unwrap();
    let check = newer.check_pin(&pin);
    assert!(check.extends && !check.new_master_key);
    assert!(newer.extends(&pin.head));

    // A later master record is a new master key, but extends.
    b.rotate(101, 151, &log1());
    let rotated = replay(&b).unwrap();
    let check = rotated.check_pin(&pin);
    assert!(check.extends && check.new_master_key);

    // A rollback: a valid chain that does not hold the head.
    let mut fork = Builder::new(&log1());
    fork.device(3, "z");
    let check = replay(&fork).unwrap().check_pin(&newer.pin());
    assert!(!check.extends && !check.new_master_key);

    // Another chain from the start: a new master key, and no head.
    let other = Builder::with_keys(alice(), key(102), key(152), &log1());
    let check = replay(&other).unwrap().check_pin(&pin);
    assert!(!check.extends && check.new_master_key);

    let pin2 = Pin {
        master_key: key(100).public_key(),
        head: other.records[0].hash(),
    };
    assert!(!old.check_pin(&pin2).extends);
}

#[test]
fn forks() {
    let mut a = Builder::new(&log1());
    a.device(1, "x");
    let mut b = Builder::new(&log1());
    b.device(2, "y");
    let (ca, cb) = (replay(&a).unwrap(), replay(&b).unwrap());
    assert_eq!(ca.diverges_from(&cb), Some(1));
    assert_eq!(ca.fork_with(&b.records[1]), Some(1));
    assert!(a.records[1].forks_with(&b.records[1]));
    // The same content signed again with hedged signing is the same
    // record, not a fork.
    let resigned = Record::sign(a.records[1].content().clone(), &a.signing, [7; 32]).unwrap();
    assert_ne!(resigned, a.records[1]);
    assert!(!resigned.forks_with(&a.records[1]));
    assert!(resigned.same_content(&a.records[1]));
    // A prefix is not a fork.
    a.device(3, "z");
    assert_eq!(replay(&a).unwrap().diverges_from(&ca), None);
    // Two first master records of one uid.
    let other = Builder::with_keys(alice(), key(102), key(152), &log1());
    assert!(other.records[0].forks_with(&a.records[0]));
    assert_eq!(ca.fork_with(&other.records[0]), Some(0));
    // Another uid's records fork with nothing.
    let bob = Builder::with_keys(
        "bob@example.org".parse().unwrap(),
        key(103),
        key(153),
        &log1(),
    );
    assert!(!bob.records[0].forks_with(&a.records[0]));
}

#[test]
fn keys_put_checks() {
    let log = log1();
    let mut b = Builder::new(&log);
    b.device(1, "x");
    // A new identity: the whole chain, after `-`.
    let put = keys_put(None, None, &b.records, &log, &NoHandoffs).unwrap();
    assert_eq!((put.first_new, put.to_append.clone()), (0, vec![0, 1]));
    let held = put.chain;

    // Sending it again adds nothing.
    let again = keys_put(Some(&held), None, &b.records, &log, &NoHandoffs).unwrap();
    assert!(again.to_append.is_empty());

    // The next records, after the head.
    b.device(2, "y").device(3, "z");
    let after = held.head_hash();
    let put = keys_put(
        Some(&held),
        Some(&after),
        &b.records[2..],
        &log,
        &NoHandoffs,
    )
    .unwrap();
    assert_eq!((put.first_new, put.to_append.clone()), (2, vec![2, 3]));
    let held = put.chain;
    // Overlapping what the server holds is fine.
    let put = keys_put(
        Some(&held),
        Some(&b.records[1].hash()),
        &b.records[2..],
        &log,
        &NoHandoffs,
    )
    .unwrap();
    assert!(put.to_append.is_empty());

    // `<after>` that the server does not hold.
    let unknown = b.records[3].hash();
    let mut longer = Builder::new(&log);
    longer.device(1, "x");
    assert_eq!(
        keys_put(None, Some(&unknown), &b.records[3..], &log, &NoHandoffs).unwrap_err(),
        KeysPutError::NotFound
    );
    let mut c = Builder::new(&log);
    c.device(9, "other");
    assert_eq!(
        keys_put(
            Some(&held),
            Some(&c.records[1].hash()),
            &b.records[2..],
            &log,
            &NoHandoffs
        )
        .unwrap_err(),
        KeysPutError::NotFound
    );

    // A different record in the place of one the server holds.
    let mut fork = Builder::new(&log);
    fork.device(1, "x").device(4, "w");
    assert_eq!(
        keys_put(Some(&held), None, &fork.records, &log, &NoHandoffs).unwrap_err(),
        KeysPutError::Forbidden
    );
    // An invalid chain.
    let mut bad = Builder::new(&log);
    bad.device(1, "x").device(150, "the signing key");
    assert!(matches!(
        keys_put(None, None, &bad.records, &log, &NoHandoffs),
        Err(KeysPutError::Invalid(e)) if e.rule == Rule::RepeatedKey
    ));
    // Records for another log.
    let other = log_on("keys.example.net", 1, 201);
    assert_eq!(
        keys_put(None, None, &b.records, &other, &NoHandoffs).unwrap_err(),
        KeysPutError::NotThisLog
    );
}

#[test]
fn keys_put_across_logs() {
    let (log, other) = (log1(), log_on("keys.example.net", 1, 201));
    let mut b = Builder::new(&log);
    b.device(1, "x").log(&other);
    // The old log takes the log record, its last.
    let put = keys_put(None, None, &b.records, &log, &NoHandoffs).unwrap();
    assert_eq!(put.to_append, vec![0, 1, 2]);
    // The new log takes the whole chain and appends none of it: none of
    // it goes into the new log (4.8).
    let put = keys_put(None, None, &b.records, &other, &NoHandoffs).unwrap();
    assert!(put.to_append.is_empty());
    let held = put.chain;
    b.device(2, "y");
    let put = keys_put(
        Some(&held),
        Some(&held.head_hash()),
        &b.records[3..],
        &other,
        &NoHandoffs,
    )
    .unwrap();
    assert_eq!(put.to_append, vec![3]);
    // The old log refuses records that now go elsewhere.
    assert_eq!(
        keys_put(None, None, &b.records, &log, &NoHandoffs).unwrap_err(),
        KeysPutError::NotThisLog
    );

    // After a hand-off of log 1 to log 2, the next record goes to log 2.
    let log2 = log_on("chat.example.org", 2, 202);
    let mut b = Builder::new(&log);
    b.device(1, "x");
    let held = keys_put(None, None, &b.records, &log, &NoHandoffs)
        .unwrap()
        .chain;
    b.device(2, "y");
    let handed = |from: &LogKey, to: &LogKey| *from == log1() && to.number() == 2;
    assert_eq!(
        keys_put(
            Some(&held),
            Some(&held.head_hash()),
            &b.records[2..],
            &log2,
            &NoHandoffs
        )
        .unwrap_err(),
        KeysPutError::NotThisLog
    );
    let put = keys_put(
        Some(&held),
        Some(&held.head_hash()),
        &b.records[2..],
        &log2,
        &handed,
    )
    .unwrap();
    assert_eq!(put.to_append, vec![2]);
    assert_eq!(put.chain.log(), &log2);
}

#[test]
fn keys_put_limits() {
    // 4,096 records decode; 4,097 are too long. Decoding stops at the
    // limit, before it looks at the records' signatures.
    let mut b = Builder::new(&log1());
    b.device(1, "x");
    let mut many: Vec<Record> = Vec::new();
    for _ in 0..4097 {
        many.push(b.records[1].clone());
    }
    let bytes = encode_records(&many);
    assert_eq!(
        decode_records(&bytes).unwrap_err(),
        risala_proto::record::RecordError::TooLarge
    );
    let bytes = encode_records(&many[..4096]);
    assert_eq!(decode_records(&bytes).unwrap().len(), 4096);
}

#[test]
fn register_checks() {
    let log = log1();
    let mut b = Builder::new(&log);
    b.device(1, "laptop");
    let chain = check_register(&b.uid, &b.records, &log).unwrap();
    assert!(chain.device_by_key(&key(1).public_key()).is_some());
    // Not the server's log.
    let other = log_on("chat.example.org", 2, 201);
    assert_eq!(
        check_register(&b.uid, &b.records, &other).unwrap_err().rule,
        Rule::NotRegistration
    );
    // Only a master record, or three records.
    assert!(check_register(&b.uid, &b.records[..1], &log).is_err());
    b.device(2, "phone");
    assert!(check_register(&b.uid, &b.records, &log).is_err());
    // A master and a log record.
    let mut c = Builder::new(&log);
    c.log(&log_on("keys.example.net", 1, 202));
    assert_eq!(
        check_register(&c.uid, &c.records, &log).unwrap_err().rule,
        Rule::NotRegistration
    );
    // Another uid than the name registered.
    let bob = "bob@example.org".parse().unwrap();
    let mut d = Builder::new(&log);
    d.device(1, "x");
    assert_eq!(
        check_register(&bob, &d.records, &log).unwrap_err().rule,
        Rule::Uid
    );
}

#[test]
fn removed_ids_are_sorted_bytes() {
    let mut ids: Vec<DeviceId> = (1..=5).map(device_id).collect();
    ids.sort();
    assert!(ids.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()));
    let content = RecordContent {
        uid: alice(),
        previous: Some(Builder::new(&log1()).records[0].hash()),
        time: T0 + 1,
        body: RecordBody::Signing {
            signing_key: key(151).public_key(),
            removed: ids.clone(),
        },
    };
    let record = Record::sign_deterministic(content, &key(100)).unwrap();
    let decoded = Record::decode(record.encoded()).unwrap();
    assert_eq!(
        decoded.content().body,
        RecordBody::Signing {
            signing_key: key(151).public_key(),
            removed: ids
        }
    );
}

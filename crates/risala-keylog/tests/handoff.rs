//! Log entries, hints, hand-offs and the witness rules of SPEC 4.10, end
//! to end: a host's log 1 hands off to log 2, its witnesses follow, and a
//! device follows the hand-off.

use risala_keylog::addcheckpoint::AddCheckpoint;
use risala_keylog::client::{
    AcceptError, LogView, Seen, ViewError, accept_handoff, accept_record, inclusion_tiles,
    verify_bundle_entry,
};
use risala_keylog::cosig::Cosigner;
use risala_keylog::entry::{LogEntry, record_hash};
use risala_keylog::hint::{NEXT_PATH, UidHint, parse_next, uid_hint_path};
use risala_keylog::testlog::{MemoryLog, TestWitness, WitnessRefusal};
use risala_keylog::tile::{TileSet, bundle_for_entry};
use risala_keylog::witness::{Freshness, WitnessError, WitnessPolicy, WitnessedCheckpoint};
use risala_keylog::witnessing::{HostLimit, WitnessConfig};
use risala_keylog::{LogOrigin, SignedCheckpoint};

const NOW: u64 = 1_800_000_000;
const HOUR: u64 = 3600;
const UID: &str = "alice@chat.example.org";

fn origin(n: u64) -> LogOrigin {
    LogOrigin::new("chat.example.org", n).unwrap()
}

fn witnesses() -> Vec<TestWitness> {
    (0..3u8)
        .map(|i| TestWitness::new(&format!("witness{i}.example/w"), &[10 + i; 32]))
        .collect()
}

fn policy(ws: &[TestWitness]) -> WitnessPolicy {
    let vkeys: Vec<String> = ws.iter().map(|w| w.vkey().to_string()).collect();
    WitnessPolicy::from_vkeys(&vkeys, 2).unwrap()
}

/// The log's current checkpoint, cosigned by every witness.
fn publish(log: &MemoryLog, ws: &mut [TestWitness], now: u64) -> SignedCheckpoint {
    let mut cp = log.checkpoint(now);
    let results = log.witness(&mut cp, ws, now);
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    cp
}

fn fetch(log: &MemoryLog, tiles: &[risala_keylog::TileId]) -> TileSet {
    let mut set = TileSet::new();
    set.fetch(tiles, &mut &*log).unwrap();
    set
}

/// A record and its hash, as a key file's `<index> <hash>` line names it.
fn record(i: u32) -> (Vec<u8>, [u8; 48]) {
    let r = format!("record {i} of {UID}").into_bytes();
    let h = record_hash(&r);
    (r, h)
}

#[test]
fn a_host_hands_off_and_a_device_follows() {
    let mut ws = witnesses();
    let policy = policy(&ws);
    let mut log1 = MemoryLog::new(&origin(1), &[1; 32]);
    let log2 = MemoryLog::new(&origin(2), &[2; 32]);

    // Log 1 holds two records of the uid among others'.
    let (r0, h0) = record(0);
    let (r1, h1) = record(1);
    let i0 = log1.append_record(UID, &r0);
    log1.append_record("bob@chat.example.org", b"bob's record");
    let i1 = log1.append_record(UID, &r1);
    let served = publish(&log1, &mut ws, NOW);
    let cp = policy
        .verify(
            &log1.key(),
            served.to_text().as_bytes(),
            Freshness::fresh(NOW),
        )
        .unwrap();
    let mut view1 = LogView::new(log1.key(), cp.clone()).unwrap();

    // The device reads record i1 from its entry bundle and accepts it.
    let size = cp.checkpoint().size();
    let bundle = log1.tile(&bundle_for_entry(i1, size).unwrap()).unwrap();
    let set = fetch(&log1, &inclusion_tiles(i1, size));
    let entry = verify_bundle_entry(&bundle, i1, cp.checkpoint(), &mut set.reader(size)).unwrap();
    let set = fetch(&log1, &view1.tiles_for_entry(cp.checkpoint(), i1));
    let got = accept_record(
        &mut view1,
        cp.clone(),
        &entry,
        i1,
        &h1,
        &mut set.reader(size),
    )
    .unwrap();
    assert_eq!(got, r1);
    // Under another hash it is another record.
    assert_eq!(
        accept_record(
            &mut view1,
            cp.clone(),
            &entry,
            i1,
            &h0,
            &mut set.reader(size),
        ),
        Err(AcceptError::WrongRecord)
    );

    // The uid's hint lists both; a key file that lists only i1, with the
    // head before both, leaves i0 out.
    let hint = UidHint::parse(&log1.serve(&uid_hint_path(UID)).unwrap()).unwrap();
    assert_eq!(hint.indices(), [i0, i1]);
    assert_eq!(hint.unlisted(None, &[i1]), [i0]);
    assert_eq!(hint.unlisted(Some(i0), &[i1]), [] as [u64; 0]);
    assert_eq!(log1.serve(NEXT_PATH), None);

    // The host hands off to log 2, gets the hand-off witnessed, and shows
    // it to the witnesses.
    let h = log1.hand_off(&log2.key());
    let served = publish(&log1, &mut ws, NOW + HOUR);
    assert!(
        log1.send_handoff(&served, &mut ws)
            .iter()
            .all(Result::is_ok)
    );
    // Showing it again is fine.
    assert!(
        log1.send_handoff(&served, &mut ws)
            .iter()
            .all(Result::is_ok)
    );
    // Log 2 enrols with its first checkpoint, without a key: the witnesses
    // have it from the hand-off.
    let mut log2 = log2;
    let (r2, h2) = record(2);
    let i2 = log2.append_record(UID, &r2);
    let served2 = publish(&log2, &mut ws, NOW + HOUR);

    // The device follows `risala/next`.
    let next_index = parse_next(&log1.serve(NEXT_PATH).unwrap()).unwrap();
    assert_eq!(next_index, h);
    let cp1 = policy
        .verify(
            &log1.key(),
            served.to_text().as_bytes(),
            Freshness::fresh(NOW + HOUR),
        )
        .unwrap();
    let set = fetch(&log1, &view1.tiles_for_entry(cp1.checkpoint(), h));
    let next = accept_handoff(
        &mut view1,
        cp1.clone(),
        log1.entry(h).unwrap(),
        h,
        &mut set.reader(cp1.checkpoint().size()),
    )
    .unwrap();
    assert_eq!(next, log2.key());
    assert_eq!(view1.handoff(), Some(&(h, log2.key())));
    // The same hand-off again.
    assert_eq!(
        accept_handoff(
            &mut view1,
            cp1.clone(),
            log1.entry(h).unwrap(),
            h,
            &mut set.reader(cp1.checkpoint().size()),
        ),
        Ok(log2.key())
    );
    // A log that handed off gets no more checkpoints; its records stay
    // acceptable however old its last checkpoint is.
    assert!(view1.is_fresh(NOW + 30 * 24 * HOUR));
    let set = fetch(&log1, &view1.tiles_for_entry(cp.checkpoint(), i0));
    let entry0 = log1.entry(i0).unwrap();
    assert_eq!(
        accept_record(
            &mut view1,
            cp.clone(),
            entry0,
            i0,
            &h0,
            &mut set.reader(cp1.checkpoint().size()),
        ),
        Ok(r0)
    );

    // Log 2, under the key the hand-off names.
    let cp2 = policy
        .verify(
            &next,
            served2.to_text().as_bytes(),
            Freshness::fresh(NOW + HOUR),
        )
        .unwrap();
    let mut view2 = LogView::new(next, cp2.clone()).unwrap();
    let set = fetch(&log2, &view2.tiles_for_entry(cp2.checkpoint(), i2));
    assert_eq!(
        accept_record(
            &mut view2,
            cp2.clone(),
            log2.entry(i2).unwrap(),
            i2,
            &h2,
            &mut set.reader(1),
        ),
        Ok(r2.clone())
    );
    // A day later, without a new checkpoint, log 2's view is not fresh, but
    // its records are still accepted: that needs a witnessed checkpoint,
    // not a fresh one (SPEC 4.5).
    assert_eq!(
        accept_record(
            &mut view2,
            cp2.clone(),
            log2.entry(i2).unwrap(),
            i2,
            &h2,
            &mut set.reader(1),
        ),
        Ok(r2.clone())
    );
    assert!(!view2.is_fresh(NOW + 25 * HOUR));
    // A new checkpoint makes the view fresh again.
    let served2 = publish(&log2, &mut ws, NOW + 25 * HOUR);
    let cp2 = policy
        .verify(
            &log2.key(),
            served2.to_text().as_bytes(),
            Freshness::at(NOW + 25 * HOUR),
        )
        .unwrap();
    assert_eq!(
        accept_record(
            &mut view2,
            cp2,
            log2.entry(i2).unwrap(),
            i2,
            &h2,
            &mut set.reader(1),
        ),
        Ok(r2)
    );

    // Witnesses now cosign no larger tree of log 1: rebuild log 1 with an
    // entry after its hand-off, under the same key.
    let mut grown = MemoryLog::new(&origin(1), &[1; 32]);
    for i in 0..log1.size() {
        grown.append(log1.entry(i).unwrap());
    }
    grown.append(b"late");
    let size = log1.size();
    for w in &mut ws {
        let req = AddCheckpoint {
            old_size: size,
            proof: grown.consistency_proof(size, size + 1).unwrap(),
            checkpoint: grown.checkpoint(NOW + 2 * HOUR),
        };
        assert_eq!(
            w.add_checkpoint(&req, NOW + 2 * HOUR),
            Err(WitnessRefusal::Forbidden)
        );
    }
}

#[test]
fn witnesses_enrol_by_the_rules() {
    let mut ws = witnesses();
    let mut log1 = MemoryLog::new(&origin(1), &[1; 32]);
    let log2 = MemoryLog::new(&origin(2), &[2; 32]);
    log1.append_record(UID, b"r");
    publish(&log1, &mut ws, NOW);
    // Each witness got log 1's key from the host itself (SPEC 4.10).
    for w in &mut ws {
        assert_eq!(
            w.key_files().fetched(),
            ["https://chat.example.org/risala-log/1/risala/key"]
        );
    }

    // Log 2 before any hand-off: refused, even with its key.
    let mut log2 = log2;
    log2.append_record(UID, b"r2");
    let req2 = AddCheckpoint {
        old_size: 0,
        proof: vec![],
        checkpoint: log2.checkpoint(NOW),
    };
    assert_eq!(
        ws[0].add_checkpoint(&req2, NOW),
        Err(WitnessRefusal::Forbidden)
    );
    // Even if the host serves log 2's key: log n > 1 gets its key only
    // from a hand-off, and the witness fetches only log 1's key file.
    ws[0].serve_log(&log2);
    let fetches = ws[0].key_files().fetched().len();
    assert_eq!(
        ws[0].add_checkpoint(&req2, NOW + 1),
        Err(WitnessRefusal::Forbidden)
    );
    assert_eq!(ws[0].key_files().fetched().len(), fetches);
    // Log 1 of the same host under another key, even if the host serves
    // that key now: refused, since the origin has its key for good.
    let other1 = MemoryLog::new(&origin(1), &[9; 32]);
    ws[0].serve_log(&other1);
    let req = AddCheckpoint {
        old_size: 0,
        proof: vec![],
        checkpoint: other1.checkpoint(NOW + 60),
    };
    assert_eq!(
        ws[0].add_checkpoint(&req, NOW + 60),
        Err(WitnessRefusal::Forbidden)
    );
    ws[0].serve_log(&log1);

    // A hand-off shown before its checkpoint is cosigned: 409, with the
    // witness's size.
    log1.hand_off(&log2.key());
    let unwitnessed = log1.checkpoint(NOW + 60);
    let req = log1.handoff_request(&unwitnessed).unwrap();
    assert_eq!(ws[0].handoff(&req), Err(WitnessRefusal::Conflict(1)));
    let served = publish(&log1, &mut ws, NOW + 60);
    let good = log1.handoff_request(&served).unwrap();

    // Wrong proof, wrong index, not a hand-off entry, a body that does not
    // parse: refused.
    let mut bad = good.clone();
    bad.proof[0].0[0] ^= 1;
    assert_eq!(ws[0].handoff(&bad), Err(WitnessRefusal::Unprocessable));
    let mut bad = good.clone();
    bad.index -= 1;
    assert_eq!(ws[0].handoff(&bad), Err(WitnessRefusal::Unprocessable));
    let mut bad = good.clone();
    bad.entry = log1.entry(0).unwrap().to_vec();
    assert_eq!(ws[0].handoff(&bad), Err(WitnessRefusal::Unprocessable));
    assert_eq!(
        ws[0].handoff_body(b"risala-handoff/1\nindex 1\n\n"),
        Err(WitnessRefusal::BadRequest)
    );
    // A good body without its version line does not parse: 400.
    let body = good.to_body();
    let unversioned = body.strip_prefix("risala-handoff/1\n").unwrap();
    assert_eq!(
        ws[0].handoff_body(unversioned.as_bytes()),
        Err(WitnessRefusal::BadRequest)
    );
    // A hand-off from a log the witness does not know: 403 (SPEC 4.10).
    let stranger = MemoryLog::new(&LogOrigin::new("x.example", 1).unwrap(), &[5; 32]);
    let mut bad = good.clone();
    bad.checkpoint = stranger.checkpoint(NOW);
    assert_eq!(ws[0].handoff(&bad), Err(WitnessRefusal::Forbidden));

    assert_eq!(ws[0].handoff(&good), Ok(()));
    // Log 2 enrols only under the key the hand-off names.
    let impostor2 = MemoryLog::new(&origin(2), &[8; 32]);
    let req = AddCheckpoint {
        old_size: 0,
        proof: vec![],
        checkpoint: impostor2.checkpoint(NOW + 120),
    };
    assert_eq!(
        ws[0].add_checkpoint(&req, NOW + 120),
        Err(WitnessRefusal::Forbidden)
    );
    let req2 = AddCheckpoint {
        old_size: 0,
        proof: vec![],
        checkpoint: log2.checkpoint(NOW + 120),
    };
    assert!(ws[0].add_checkpoint(&req2, NOW + 120).is_ok());
    // Log 3 needs a hand-off from log 2.
    let log3 = MemoryLog::new(&origin(3), &[3; 32]);
    let req3 = AddCheckpoint {
        old_size: 0,
        proof: vec![],
        checkpoint: log3.checkpoint(NOW + 120),
    };
    ws[0].serve_log(&log3);
    assert_eq!(
        ws[0].add_checkpoint(&req3, NOW + 120),
        Err(WitnessRefusal::Forbidden)
    );
}

#[test]
fn a_handoff_must_name_the_next_log() {
    let mut ws = witnesses();
    let mut log1 = MemoryLog::new(&origin(1), &[1; 32]);
    log1.append_record(UID, b"r");
    // A hand-off entry naming log 3, which skips log 2.
    let log3 = MemoryLog::new(&origin(3), &[3; 32]);
    let h = log1.append(&LogEntry::Handoff(log3.key()).encode());
    let served = publish(&log1, &mut ws, NOW);
    let req = risala_keylog::handoff::HandoffRequest {
        index: h,
        entry: log1.entry(h).unwrap().to_vec(),
        proof: log1.inclusion_proof(h, log1.size()).unwrap(),
        checkpoint: served.clone(),
    };
    assert_eq!(ws[0].handoff(&req), Err(WitnessRefusal::Unprocessable));

    // Nor does a device follow it.
    let policy = policy(&ws);
    let cp = policy
        .verify(
            &log1.key(),
            served.to_text().as_bytes(),
            Freshness::fresh(NOW),
        )
        .unwrap();
    let mut view = LogView::new(log1.key(), cp.clone()).unwrap();
    let set = fetch(&log1, &view.tiles_for_entry(cp.checkpoint(), h));
    assert_eq!(
        accept_handoff(
            &mut view,
            cp.clone(),
            log1.entry(h).unwrap(),
            h,
            &mut set.reader(2)
        ),
        Err(AcceptError::NotAHandoff)
    );
    // A record entry is not a hand-off either.
    assert_eq!(
        accept_handoff(&mut view, cp, log1.entry(0).unwrap(), 0, &mut set.reader(2)),
        Err(AcceptError::NotAHandoff)
    );
    assert_eq!(view.handoff(), None);
}

/// Witnesses that sign whatever they are given, with the keys of
/// [`witnesses`]: what a device sees if a log and k witnesses misbehave.
fn colluding(log: &MemoryLog, size: u64, now: u64, policy: &WitnessPolicy) -> WitnessedCheckpoint {
    let mut sc = log.checkpoint_at(size, now).unwrap();
    for i in 0..2u8 {
        let w = Cosigner::from_seed(&format!("witness{i}.example/w"), &[10 + i; 32]).unwrap();
        sc.push_signature(w.cosign(sc.checkpoint(), now, [0; 32]))
            .unwrap();
    }
    policy
        .verify_signed(&log.key(), sc, Freshness::at(now))
        .unwrap()
}

#[test]
fn a_device_sees_a_log_grow_after_its_handoff() {
    let ws = witnesses();
    let policy = policy(&ws);
    let log2 = MemoryLog::new(&origin(2), &[2; 32]);
    let mut log1 = MemoryLog::new(&origin(1), &[1; 32]);
    log1.append_record(UID, b"r");
    let h = log1.hand_off(&log2.key());
    let mut grown = MemoryLog::new(&origin(1), &[1; 32]);
    for i in 0..log1.size() {
        grown.append(log1.entry(i).unwrap());
    }
    grown.append(b"late");

    // The device accepted the hand-off; a larger tree comes later.
    let cp = colluding(&log1, 2, NOW, &policy);
    let mut view = LogView::new(log1.key(), cp.clone()).unwrap();
    let set = fetch(&log1, &view.tiles_for_entry(cp.checkpoint(), h));
    accept_handoff(&mut view, cp, log1.entry(h).unwrap(), h, &mut set.reader(2)).unwrap();
    let later = colluding(&grown, 3, NOW + 60, &policy);
    let set = fetch(&grown, &view.tiles_for(later.checkpoint()));
    assert_eq!(
        view.check(later, &mut set.reader(3)),
        Err(ViewError::AfterHandoff)
    );

    // The device saw the larger tree first: the hand-off is not the last
    // entry of what the log showed it.
    let first = colluding(&grown, 3, NOW, &policy);
    let mut view = LogView::new(log1.key(), first).unwrap();
    let cp = colluding(&log1, 2, NOW, &policy);
    let set = fetch(&grown, &view.tiles_for_entry(cp.checkpoint(), h));
    assert_eq!(
        accept_handoff(&mut view, cp, log1.entry(h).unwrap(), h, &mut set.reader(3)),
        Err(AcceptError::View(ViewError::AfterHandoff))
    );
    assert_eq!(view.handoff(), None);

    // A hand-off that is not its checkpoint's last entry.
    let cp = colluding(&grown, 3, NOW, &policy);
    let mut view = LogView::new(log1.key(), cp.clone()).unwrap();
    let set = fetch(&grown, &view.tiles_for_entry(cp.checkpoint(), h));
    assert_eq!(
        accept_handoff(
            &mut view,
            cp,
            grown.entry(h).unwrap(),
            h,
            &mut set.reader(3)
        ),
        Err(AcceptError::NotLastEntry)
    );

    // Restoring a view checks that the hand-off fits it.
    let cp = colluding(&log1, 2, NOW, &policy);
    assert!(LogView::restore(log1.key(), cp.clone(), Some((h, log2.key()))).is_ok());
    assert!(LogView::restore(log1.key(), cp.clone(), Some((h - 1, log2.key()))).is_err());
    assert!(LogView::restore(log1.key(), cp, Some((h, log1.key()))).is_err());
}

#[test]
fn a_witness_list_that_does_not_fit() {
    let mut ws = witnesses();
    let mut log = MemoryLog::new(&origin(1), &[1; 32]);
    log.append_record(UID, b"r");
    let served = publish(&log, &mut ws, NOW);
    // A device whose list holds none of the log's witnesses.
    let others: Vec<TestWitness> = (0..3u8)
        .map(|i| TestWitness::new(&format!("other{i}.example/w"), &[40 + i; 32]))
        .collect();
    let err = policy(&others)
        .verify(
            &log.key(),
            served.to_text().as_bytes(),
            Freshness::fresh(NOW),
        )
        .unwrap_err();
    assert_eq!(err, WitnessError::NotEnoughWitnesses { have: 0, need: 2 });
    assert!(err.is_witness_list_problem(false));
    // An old checkpoint is a sign of a log behind, not a bad list.
    let err = policy(&ws)
        .verify(
            &log.key(),
            served.to_text().as_bytes(),
            Freshness::fresh(NOW + 2 * 24 * HOUR),
        )
        .unwrap_err();
    assert!(!err.is_witness_list_problem(false));
}

#[test]
fn witnesses_limit_new_hosts_per_domain() {
    let config = WitnessConfig {
        new_hosts: Some(HostLimit {
            max: 2,
            window: 24 * HOUR,
        }),
        ..WitnessConfig::default()
    };
    let mut w = TestWitness::with_config("witness.example/w", &[7; 32], config);
    let mut enrol = |host: &str, now: u64| {
        let log = MemoryLog::new(&LogOrigin::new(host, 1).unwrap(), &[host.len() as u8; 32]);
        let req = AddCheckpoint {
            old_size: 0,
            proof: vec![],
            checkpoint: log.checkpoint(now),
        };
        w.serve_log(&log);
        w.add_checkpoint(&req, now).map(|_| ())
    };
    assert_eq!(enrol("a.example.org", NOW), Ok(()));
    assert_eq!(enrol("bb.example.org", NOW + 1), Ok(()));
    assert_eq!(
        enrol("ccc.example.org", NOW + 2),
        Err(WitnessRefusal::TooManyRequests)
    );
    assert_eq!(enrol("example.net", NOW + 3), Ok(()));
    assert_eq!(enrol("ccc.example.org", NOW + 24 * HOUR + 1), Ok(()));
}

#[test]
fn the_view_checks_handoffs_against_its_newest() {
    // A checkpoint of the right size from a forked log 1 is a fork, even
    // when it ends in the same hand-off.
    let ws = witnesses();
    let policy = policy(&ws);
    let log2 = MemoryLog::new(&origin(2), &[2; 32]);
    let mut a = MemoryLog::new(&origin(1), &[1; 32]);
    let mut b = MemoryLog::new(&origin(1), &[1; 32]);
    a.append_record(UID, b"a");
    b.append_record(UID, b"b");
    let h = a.hand_off(&log2.key());
    b.hand_off(&log2.key());
    let cpa = colluding(&a, 2, NOW, &policy);
    let cpb = colluding(&b, 2, NOW, &policy);
    let mut view = LogView::new(a.key(), cpa.clone()).unwrap();
    let set = fetch(&a, &view.tiles_for_entry(cpa.checkpoint(), h));
    assert_eq!(
        risala_keylog::client::accept_entry(
            &mut view,
            cpa,
            a.entry(h).unwrap(),
            h,
            &mut set.reader(2)
        ),
        Ok(Seen::Same)
    );
    let set = fetch(&b, &view.tiles_for_entry(cpb.checkpoint(), h));
    assert!(matches!(
        accept_handoff(&mut view, cpb, b.entry(h).unwrap(), h, &mut set.reader(2)),
        Err(AcceptError::View(ViewError::Fork(_)))
    ));
}

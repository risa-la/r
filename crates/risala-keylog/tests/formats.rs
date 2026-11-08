//! Property tests of the formats: signed notes, verifier keys,
//! checkpoints, add-checkpoint and hand-off requests, log entries and
//! hints.

use proptest::prelude::*;
use risala_keylog::addcheckpoint::AddCheckpoint;
use risala_keylog::checkpoint::{Checkpoint, SignedCheckpoint};
use risala_keylog::cosig::Cosigner;
use risala_keylog::entry::LogEntry;
use risala_keylog::handoff::HandoffRequest;
use risala_keylog::hint::{UidHint, parse_next};
use risala_keylog::merkle::Hash;
use risala_keylog::note::{Note, NoteSignature, VerifierKey};
use risala_keylog::witness::LogKey;

/// Key names: no space, no plus, no control character.
fn name() -> impl Strategy<Value = String> {
    "[a-z0-9./_\u{e9}\u{2014}-]{1,40}"
}

/// Note text: lines with no control characters, blank lines allowed.
fn text() -> impl Strategy<Value = String> {
    prop::collection::vec("[^\\x00-\\x1f]{0,30}", 1..6).prop_map(|lines| {
        let mut s = lines.join("\n");
        s.push('\n');
        s
    })
}

fn signature() -> impl Strategy<Value = NoteSignature> {
    (
        name(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 1..200),
    )
        .prop_map(|(name, key_id, signature)| NoteSignature {
            name,
            key_id,
            signature,
        })
}

proptest! {
    #[test]
    fn notes_round_trip(text in text(), sigs in prop::collection::vec(signature(), 1..20)) {
        let mut note = Note::new(text.clone()).unwrap();
        for s in &sigs {
            note.push_signature(s.clone()).unwrap();
        }
        let encoded = note.to_text();
        let parsed = Note::parse(encoded.as_bytes()).unwrap();
        prop_assert_eq!(parsed.text(), text.as_str());
        prop_assert_eq!(parsed.signatures(), &sigs[..]);
        prop_assert_eq!(parsed.to_text(), encoded);
    }

    #[test]
    fn note_parsing_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        if let Ok(n) = Note::parse(&bytes) {
            // Whatever parses writes back to the same bytes.
            let again = n.to_text();
            prop_assert_eq!(again.as_bytes(), &bytes[..]);
        }
    }

    #[test]
    fn note_like_input(s in "([a-z \u{2014}+=/]{0,12}\n){1,6}") {
        if let Ok(n) = Note::parse(s.as_bytes()) {
            prop_assert_eq!(n.to_text(), s);
        }
    }

    #[test]
    fn vkeys_round_trip(name in name(), sig_type in any::<u8>(), key in prop::collection::vec(any::<u8>(), 1..100)) {
        let v = VerifierKey::new(&name, sig_type, &key).unwrap();
        let s = v.to_string();
        prop_assert_eq!(s.parse::<VerifierKey>(), Ok(v));
    }

    #[test]
    fn vkey_parsing_never_panics(s in "[a-zA-Z0-9+/=.]{0,80}") {
        if let Ok(v) = s.parse::<VerifierKey>() {
            prop_assert_eq!(v.to_string(), s);
        }
    }

    #[test]
    fn checkpoints_round_trip(origin in name(), size in any::<u64>(), root in any::<[u8; 32]>(), sigs in prop::collection::vec(signature(), 1..5)) {
        let cp = Checkpoint::new(&origin, size, Hash(root)).unwrap();
        prop_assert_eq!(Checkpoint::from_text(&cp.to_text()), Ok(cp.clone()));
        let mut sc = SignedCheckpoint::unsigned(cp);
        for s in sigs {
            sc.push_signature(s).unwrap();
        }
        let text = sc.to_text();
        let parsed = SignedCheckpoint::parse(text.as_bytes()).unwrap();
        prop_assert_eq!(&parsed, &sc);
        let req = AddCheckpoint { old_size: size / 2, proof: vec![Hash(root); (size % 64) as usize], checkpoint: sc };
        prop_assert_eq!(AddCheckpoint::parse(req.to_body().as_bytes()), Ok(req));
    }

    #[test]
    fn checkpoint_parsing_never_panics(s in "([a-zA-Z0-9+/= ]{0,50}\n){0,6}") {
        if let Ok(cp) = Checkpoint::from_text(&s) {
            prop_assert_eq!(cp.to_text(), s);
        }
    }

    #[test]
    fn log_entries_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1500)) {
        if let Ok(e) = LogEntry::decode(&bytes) {
            prop_assert_eq!(e.encode(), bytes);
        }
    }

    #[test]
    fn handoff_entries_round_trip(n in 1u64..1_000_000, host in "[a-z0-9]{1,20}(\\.[a-z0-9]{1,20}){0,3}", seed in any::<[u8; 32]>()) {
        let origin = format!("{host}/risala-log/{n}");
        let key = LogKey::new(Cosigner::from_seed(&origin, &seed).unwrap().verifier()).unwrap();
        let e = LogEntry::Handoff(key);
        let bytes = e.encode();
        prop_assert_eq!(LogEntry::decode(&bytes), Ok(e));
        // Every shorter prefix fails.
        for cut in [0, 1, 2, 3, bytes.len() / 2, bytes.len() - 1] {
            prop_assert!(LogEntry::decode(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn record_entries_round_trip(record in prop::collection::vec(any::<u8>(), 1..2000)) {
        let e = LogEntry::record(&record).unwrap();
        prop_assert_eq!(LogEntry::decode(&e.encode()), Ok(e));
    }

    #[test]
    fn hints_never_panic(s in "(risala-hint/1\n)?([0-9]{0,4}\n?){0,8}") {
        if let Ok(h) = UidHint::parse(s.as_bytes()) {
            prop_assert_eq!(h.to_body(), s.clone());
        }
        if let Ok(n) = parse_next(s.as_bytes()) {
            prop_assert_eq!(format!("risala-hint/1\n{n}\n"), s);
        }
    }

    #[test]
    fn uid_hints_round_trip(mut indices in prop::collection::btree_set(0u64..(1 << 62), 1..50)) {
        let h = UidHint::new(std::mem::take(&mut indices).into_iter().collect()).unwrap();
        prop_assert_eq!(UidHint::parse(h.to_body().as_bytes()), Ok(h));
    }

    #[test]
    fn handoff_requests_never_panic(s in "(risala-handoff/1\n)?(index [0-9]{1,3}\n)?([A-Za-z0-9+/=]{0,12}\n){0,3}\n?([a-z0-9+/= ]{0,20}\n){0,4}") {
        let _ = HandoffRequest::parse(s.as_bytes());
    }

    #[test]
    fn handoff_requests_round_trip(index in 0u64..1 << 40, entry in prop::collection::vec(any::<u8>(), 1..100), proof in prop::collection::vec(any::<[u8; 32]>(), 0..10), size in any::<u64>(), root in any::<[u8; 32]>(), sigs in prop::collection::vec(signature(), 1..3)) {
        let cp = Checkpoint::new("log.example/risala-log/1", size, Hash(root)).unwrap();
        let mut checkpoint = SignedCheckpoint::unsigned(cp);
        for sig in sigs {
            checkpoint.push_signature(sig).unwrap();
        }
        let req = HandoffRequest { index, entry, proof: proof.into_iter().map(Hash).collect(), checkpoint };
        prop_assert_eq!(HandoffRequest::parse(req.to_body().as_bytes()), Ok(req));
    }
}

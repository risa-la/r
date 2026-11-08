//! Property tests of the text formats: signed notes, verifier keys,
//! checkpoints and add-checkpoint requests.

use proptest::prelude::*;
use risala_keylog::addcheckpoint::AddCheckpoint;
use risala_keylog::checkpoint::{Checkpoint, SignedCheckpoint};
use risala_keylog::merkle::Hash;
use risala_keylog::note::{Note, NoteSignature, VerifierKey};

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
}

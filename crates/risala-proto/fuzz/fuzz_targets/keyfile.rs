//! Text into `KeyFile::parse` (SPEC 4.4).
//!
//! Parsing never fails except on size, never keeps more than `MAX_KEYS`
//! keys or a key twice, and every kept entry's line parses back as the
//! same entry, alone or as a whole file.
//!
//! A fuzzer almost never guesses a valid 44-character Ed25519 key, so
//! `$` followed by any byte is replaced with one of 80 real keys (more
//! than `MAX_KEYS`). That lets it reach valid, duplicate and surplus keys.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use risala_proto::auth::SecretKey;
use risala_proto::keyfile::{KeyEntry, KeyFile, MAX_KEY_FILE_BYTES, MAX_KEYS};

const KEYS: usize = 80;

fn keys() -> &'static [String] {
    static KEYS_B64: OnceLock<Vec<String>> = OnceLock::new();
    KEYS_B64.get_or_init(|| {
        (0..KEYS)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                SecretKey::from_seed(seed).public_key().to_string()
            })
            .collect()
    })
}

/// Replaces each `$` and the byte after it with a real key.
fn expand(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut bytes = data.iter();
    while let Some(&b) = bytes.next() {
        match (b, bytes.next()) {
            (b'$', Some(&k)) => out.extend_from_slice(keys()[usize::from(k) % KEYS].as_bytes()),
            (b, next) => {
                out.push(b);
                out.extend(next);
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let data = expand(data);
    let text = String::from_utf8_lossy(&data);
    let file = match KeyFile::parse(&text) {
        Ok(file) => file,
        Err(e) => {
            assert!(text.len() > MAX_KEY_FILE_BYTES, "{e}");
            return;
        }
    };
    assert!(file.keys().len() <= MAX_KEYS);

    let mut lines = String::new();
    for (i, entry) in file.keys().iter().enumerate() {
        assert!(!file.keys()[..i].iter().any(|e| e.key() == entry.key()));
        let line = entry.to_string();
        assert!(!line.contains(['\n', '\r']));
        assert_eq!(line.parse::<KeyEntry>().as_ref(), Ok(entry), "{line:?}");
        lines.push_str(&line);
        lines.push('\n');
    }
    let again = KeyFile::parse(&lines).expect("a list of entries is small");
    assert_eq!(again.keys(), file.keys());
    assert!(again.skipped().is_empty());

    // Each line on its own, as a key tool would read it.
    for line in text.lines() {
        if let Ok(entry) = line.parse::<KeyEntry>() {
            let shown = entry.to_string();
            assert_eq!(shown.parse::<KeyEntry>().as_ref(), Ok(&entry), "{shown:?}");
        }
    }
});

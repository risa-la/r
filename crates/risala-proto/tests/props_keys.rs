//! Property tests for keys: the sign-in challenge and ML-DSA-44 values
//! (SPEC 4.6, App. B) and fingerprints (2.2). Key files are tested in
//! `props_identity.rs`.

use std::sync::OnceLock;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;
use risala_proto::auth::{
    CHALLENGE_PREFIX, Nonce, PUBLIC_KEY_BASE64_LEN, PublicKey, SIGNATURE_BASE64_LEN, SIGNATURE_LEN,
    SecretKey, Signature, challenge_bytes,
};
use risala_proto::error::ParseError;
use risala_proto::fingerprint::Fingerprint;

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
/// Keys made from 96 seeds.
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

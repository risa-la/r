//! Certificate fingerprints for trust on first use (SPEC 2.2, App. A).

use std::fmt;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

use crate::auth::{hex_digit, hex_lower};
use crate::error::ParseError;

/// The prefix of a fingerprint's text form (2.2).
pub const FINGERPRINT_PREFIX: &str = "sha256:";

/// A server certificate's fingerprint: the SHA-256 hash of its DER-encoded
/// SubjectPublicKeyInfo (2.2).
///
/// It is written `sha256:` followed by 64 lower-case hex digits. Parsing
/// folds upper case, so `SHA256:AB...` is accepted; nothing else is.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Hashes a certificate's DER-encoded SubjectPublicKeyInfo (2.2).
    ///
    /// The bytes are hashed as given; extracting them from the
    /// certificate is the caller's job, as is checking that they are DER.
    pub fn from_spki_der(spki_der: &[u8]) -> Fingerprint {
        Fingerprint(Sha256::digest(spki_der).into())
    }

    /// Makes a fingerprint from a SHA-256 hash (2.2).
    pub fn from_bytes(hash: [u8; 32]) -> Fingerprint {
        Fingerprint(hash)
    }

    /// The 32-byte SHA-256 hash (2.2).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FromStr for Fingerprint {
    type Err = ParseError;

    /// Parses `sha256:<64 hex digits>` (2.2).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix_len = FINGERPRINT_PREFIX.len();
        if s.len() != prefix_len + 64 {
            return Err(ParseError::BadSyntax(
                "fingerprint is not sha256: and 64 hex digits",
            ));
        }
        let (prefix, hex) = s.split_at_checked(prefix_len).ok_or(ParseError::BadSyntax(
            "fingerprint is not sha256: and 64 hex digits",
        ))?;
        if !prefix.eq_ignore_ascii_case(FINGERPRINT_PREFIX) {
            return Err(ParseError::BadSyntax(
                "fingerprint does not start with sha256:",
            ));
        }
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            match (hex_digit(pair[0]), hex_digit(pair[1])) {
                (Some(hi), Some(lo)) => *byte = (hi << 4) | lo,
                _ => return Err(ParseError::BadSyntax("fingerprint is not hex")),
            }
        }
        Ok(Fingerprint(out))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{FINGERPRINT_PREFIX}{}", hex_lower(&self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The SubjectPublicKeyInfo of Appendix B's public key, as written by
    // `openssl pkey -pubout -outform der`.
    const SPKI: [u8; 44] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x27, 0xf2, 0xa6,
        0xba, 0x9b, 0x94, 0x61, 0xc4, 0x5d, 0xd8, 0x2d, 0xb2, 0x35, 0x97, 0x8a, 0xcf, 0xad, 0x49,
        0x21, 0xb2, 0x0a, 0x6d, 0xd4, 0x69, 0xfd, 0xd2, 0xfc, 0x95, 0xfa, 0xae, 0x0d, 0x86,
    ];
    // From `openssl dgst -sha256`, as in Appendix A.
    const EXPECTED: &str =
        "sha256:014eee5bd33d3d5d13947e30af2c96571d421f72b181664c1ee91eee190e0489";

    #[test]
    fn known_value() {
        let fp = Fingerprint::from_spki_der(&SPKI);
        assert_eq!(fp.to_string(), EXPECTED);
        assert_eq!(EXPECTED.parse::<Fingerprint>().unwrap(), fp);
        assert_eq!(Fingerprint::from_bytes(*fp.as_bytes()), fp);
    }

    #[test]
    fn parsing() {
        let fp: Fingerprint = EXPECTED.parse().unwrap();
        assert_eq!(
            EXPECTED
                .to_ascii_uppercase()
                .parse::<Fingerprint>()
                .unwrap(),
            fp
        );

        assert!("".parse::<Fingerprint>().is_err());
        assert!(EXPECTED[7..].parse::<Fingerprint>().is_err());
        assert!(EXPECTED[..70].parse::<Fingerprint>().is_err());
        assert!(format!("{EXPECTED}0").parse::<Fingerprint>().is_err());
        assert!(
            EXPECTED
                .replace("sha256:", "sha512:")
                .parse::<Fingerprint>()
                .is_err()
        );
        assert!(
            EXPECTED
                .replace("sha256:", "sha256=")
                .parse::<Fingerprint>()
                .is_err()
        );
        assert!(EXPECTED.replace('e', "g").parse::<Fingerprint>().is_err());
        // Multi-byte characters of the right total length.
        assert!(
            format!("sha256:{}é", &EXPECTED[7..69])
                .parse::<Fingerprint>()
                .is_err()
        );
        assert!(
            format!("sha25é{}", &EXPECTED[7..])
                .parse::<Fingerprint>()
                .is_err()
        );
    }

    #[test]
    fn openssl_interop() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        fn run(args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
            let mut child = Command::new("openssl")
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .ok()?;
            child.stdin.take().unwrap().write_all(stdin).unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "openssl {args:?} failed");
            Some(out.stdout)
        }

        let Some(key) = run(
            &[
                "genpkey",
                "-algorithm",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
            ],
            b"",
        ) else {
            eprintln!("openssl not found, skipping");
            return;
        };
        let spki = run(&["pkey", "-pubout", "-outform", "der"], &key).unwrap();
        let digest = run(&["dgst", "-sha256", "-r"], &spki).unwrap();
        let hex = String::from_utf8(digest).unwrap();
        let hex = hex.split_whitespace().next().unwrap();
        assert_eq!(
            Fingerprint::from_spki_der(&spki).to_string(),
            format!("sha256:{hex}")
        );
    }
}

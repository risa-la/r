//! Base32 of any length \[RFC4648\], without padding: recovery keys (4.8),
//! short device ids and QR codes (4.8, 12.14).

const LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const UPPER: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 of `bytes`, without padding, in lower case or upper case.
pub(crate) fn encode(bytes: &[u8], upper: bool) -> String {
    let alphabet = if upper { UPPER } else { LOWER };
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(alphabet[(acc >> bits) as usize & 31]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(alphabet[(acc << (5 - bits)) as usize & 31]));
    }
    out
}

/// Reads base32 without padding. `upper` picks the one case accepted:
/// QR codes are written in upper case (4.8, 12.14), and a reader folds
/// typed input itself before calling this. A length that no byte string
/// encodes to, or bits after the last byte that are not zero, fail, so
/// that each value has one spelling.
pub(crate) fn decode(s: &str, upper: bool) -> Option<Vec<u8>> {
    // Lengths mod 8 of 1, 3 and 6 encode no whole number of bytes.
    if matches!(s.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'a'..=b'z' if !upper => c - b'a',
            b'A'..=b'Z' if upper => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (plain, coded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode(plain.as_bytes(), true), coded);
            assert_eq!(encode(plain.as_bytes(), false), coded.to_lowercase());
            assert_eq!(decode(coded, true).unwrap(), plain.as_bytes());
            assert_eq!(
                decode(&coded.to_lowercase(), false).unwrap(),
                plain.as_bytes()
            );
        }
    }

    #[test]
    fn strict() {
        // Wrong case, a bad length, non-zero trailing bits, padding.
        assert!(decode("my", true).is_none());
        assert!(decode("MZX", true).is_none());
        assert!(decode("MZ", true).is_none());
        assert!(decode("MY======", true).is_none());
        assert!(decode("M1", true).is_none());
    }
}

//! The primitives of cipher suite `0x0020` that risala uses outside MLS
//! itself (12.9-12.13): SHA-384, HKDF-SHA384, HMAC-SHA-384 and
//! ChaCha20-Poly1305, from the same libcrux crates as the provider, and the
//! labelled functions of \[RFC9420\] built from them.

use tls_codec::{Serialize as _, TlsSerialize, TlsSize, VLBytes};
use zeroize::Zeroizing;

/// The length of a SHA-384 hash, and of HKDF-SHA384's PRK.
pub const HASH_LEN: usize = 48;

/// The key, nonce and tag lengths of ChaCha20-Poly1305 \[RFC8439\].
pub const AEAD_KEY_LEN: usize = libcrux_chacha20poly1305::KEY_LEN;
pub const AEAD_NONCE_LEN: usize = libcrux_chacha20poly1305::NONCE_LEN;
pub const AEAD_TAG_LEN: usize = libcrux_chacha20poly1305::TAG_LEN;

/// The prefix of every MLS label [RFC9420, 5.1.2, 8].
pub const MLS_LABEL_PREFIX: &str = "MLS 1.0 ";

/// SHA-384.
pub fn sha384(data: &[u8]) -> [u8; HASH_LEN] {
    <sha2::Sha384 as sha2::Digest>::digest(data).into()
}

/// HKDF-Extract with SHA-384 \[RFC5869\].
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    let mut prk = Zeroizing::new([0; HASH_LEN]);
    libcrux_hkdf::extract(libcrux_hkdf::Algorithm::Sha384, &mut prk[..], salt, ikm)
        .expect("the PRK is one hash long and the inputs are small");
    prk
}

/// HKDF-Expand with SHA-384 \[RFC5869\], filling `okm`.
///
/// `prk` must be at least 48 bytes, and `okm` at most 255 times that. The
/// callers in this crate pass fixed lengths that are.
pub fn hkdf_expand(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    libcrux_hkdf::expand(libcrux_hkdf::Algorithm::Sha384, okm, prk, info)
        .expect("PRK and output lengths are fixed by the callers");
}

/// HMAC-SHA-384 \[RFC2104\].
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    let tag = libcrux_hmac::hmac(libcrux_hmac::Algorithm::Sha384, key, data, None);
    tag.try_into().expect("HMAC-SHA-384 gives 48 bytes")
}

/// ChaCha20-Poly1305 encryption \[RFC8439\]: the ciphertext followed by the
/// 16-byte tag.
pub fn seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut out = vec![0; plaintext.len() + AEAD_TAG_LEN];
    libcrux_chacha20poly1305::encrypt(key, plaintext, &mut out, aad, nonce)
        .expect("inputs are far below 4 GiB");
    out
}

/// ChaCha20-Poly1305 decryption \[RFC8439\] of a ciphertext that ends in its
/// tag, or `None` if it does not verify.
pub fn open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let len = ciphertext.len().checked_sub(AEAD_TAG_LEN)?;
    let mut out = Zeroizing::new(vec![0; len]);
    libcrux_chacha20poly1305::decrypt(key, &mut out, ciphertext, aad, nonce).ok()?;
    Some(out)
}

/// Whether two secrets of the same length are equal, in time that does
/// not depend on where they differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `N` bytes from the operating system's secure random source.
pub fn random<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut out = [0; N];
    getrandom::fill(&mut out)?;
    Ok(out)
}

/// SignContent [RFC9420, 5.1.2], the bytes that SignWithLabel signs:
/// `"MLS 1.0 " + label`, then `content`, each as a variable-size vector.
pub fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    #[derive(TlsSerialize, TlsSize)]
    struct SignContent<'a> {
        label: VLBytes,
        content: tls_codec::VLByteSlice<'a>,
    }
    let label = [MLS_LABEL_PREFIX.as_bytes(), label.as_bytes()].concat();
    SignContent {
        label: label.into(),
        content: tls_codec::VLByteSlice(content),
    }
    .tls_serialize_detached()
    .expect("lengths fit a variable-size vector")
}

/// ExpandWithLabel [RFC9420, 8] with HKDF-SHA384, filling `out`:
/// HKDF-Expand(secret, KDFLabel, out.len()), where KDFLabel holds the
/// length, `"MLS 1.0 " + label` and `context`.
///
/// `label` is bytes, since the test vectors of \[RFC9420\] have labels that
/// are not UTF-8. `out` is at most 65535 bytes.
pub fn expand_with_label(secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    #[derive(TlsSerialize, TlsSize)]
    struct KdfLabel<'a> {
        length: u16,
        label: VLBytes,
        context: tls_codec::VLByteSlice<'a>,
    }
    let info = KdfLabel {
        length: u16::try_from(out.len()).expect("ExpandWithLabel gives at most 65535 bytes"),
        label: [MLS_LABEL_PREFIX.as_bytes(), label].concat().into(),
        context: tls_codec::VLByteSlice(context),
    }
    .tls_serialize_detached()
    .expect("lengths fit a variable-size vector");
    hkdf_expand(secret, &info, out);
}

/// DeriveSecret [RFC9420, 8]: ExpandWithLabel(secret, label, "", 48).
pub fn derive_secret(secret: &[u8], label: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    let mut out = Zeroizing::new([0; HASH_LEN]);
    expand_with_label(secret, label, b"", &mut out[..]);
    out
}

/// The MLS exporter [RFC9420, 8.5] from an epoch's `exporter_secret`:
/// ExpandWithLabel(DeriveSecret(exporter_secret, label), "exported",
/// SHA-384(context), out.len()).
pub fn mls_exporter(exporter_secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let derived = derive_secret(exporter_secret, label);
    expand_with_label(&derived[..], b"exported", &sha384(context), out);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 4231 test case 2, and RFC 5869-style checks of HKDF-SHA384
    /// against HMAC: HKDF-Expand for one block is HMAC(prk, info || 1).
    #[test]
    fn hmac_and_hkdf() {
        assert_eq!(
            hex(&hmac_sha384(b"Jefe", b"what do ya want for nothing?")),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        );
        let prk = hkdf_extract(b"salt", b"ikm");
        assert_eq!(*prk, hmac_sha384(b"salt", b"ikm"));
        let mut okm = [0; 48];
        hkdf_expand(&prk[..], b"info", &mut okm);
        assert_eq!(okm, hmac_sha384(&prk[..], b"info\x01"));
        // An empty salt is the same as 48 zero bytes (RFC 5869, 2.2).
        assert_eq!(*hkdf_extract(b"", b"ikm"), *hkdf_extract(&[0; 48], b"ikm"));
    }

    /// RFC 8439, 2.8.2.
    #[test]
    fn chacha20poly1305() {
        let key: [u8; 32] = std::array::from_fn(|i| 0x80 + i as u8);
        let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
                          only one tip for the future, sunscreen would be it.";
        let sealed = seal(&key, &nonce, &aad, plaintext);
        assert_eq!(
            hex(&sealed[sealed.len() - 16..]),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
        assert_eq!(hex(&sealed[..8]), "d31a8d34648e60db");
        assert_eq!(&open(&key, &nonce, &aad, &sealed).unwrap()[..], plaintext);

        let mut tampered = sealed.clone();
        tampered[3] ^= 1;
        assert!(open(&key, &nonce, &aad, &tampered).is_none());
        assert!(open(&key, &nonce, b"", &sealed).is_none());
        assert!(open(&key, &nonce, &aad, &sealed[..15]).is_none());
    }

    /// RFC 9420's test vectors for cipher suite 7, which uses the same hash
    /// and KDF as `0x0020` (12.9, App. B), from mlswg/mls-implementations:
    /// `crypto-basics.json` and two epochs of `key-schedule.json`.
    #[test]
    fn rfc9420_suite_7_vectors() {
        let mut out = [0; 32];
        expand_with_label(
            &unhex(
                "39bb10928726fffb2b9b61fa4b07fed7ef5e554021a83c9d3af3aac9a8abab3d\
                 b0bae67df71e8b3dd7ab3cf17dc783ce",
            ),
            b"ExpandWithLabel",
            &unhex(
                "2588d6b1ca306a9fc348a8b1b4de45c7111c4fb86ee362086ecf3f8f18f0b869\
                 df492fc5d30af6dd2d53e7b1eddf7d2f",
            ),
            &mut out,
        );
        assert_eq!(
            hex(&out),
            "a2b96cd5edc41d0d56ce7a2282ce52aa792c7990483a52cbb044ee3f1f14f159"
        );

        let derived = derive_secret(
            &unhex(
                "ee9426e58f77d9e2c16a18a8758097143645c523a1e3050c7e61c54b6703c721\
                 d3747961660a163230a03515f0ca0746",
            ),
            b"DeriveSecret",
        );
        assert_eq!(
            hex(&derived[..]),
            "ad64a2748a2894e725825fbb97d8e9e11b30c7df09056b825a9328d7dd95a354\
             36c326929b964afb181c747c1e95c3da"
        );

        // (exporter_secret, label, context, secret). The label is text that
        // looks like hex, used as is.
        for (secret, label, context, expected) in [
            (
                "15069e73a02efc7168fccd5438e046762db53c708d9bd9ca0fc4602db7811e1f\
                 f25d653c9e23c11713bfe0cfc0cab050",
                "fe3a0807822eee9bbf74b4ecdb5b81ab68f961b8641c2182cfcc98321aae211f\
                 d1c71af98857b9e9e76834a57f6f001f",
                "575673f68ec4de0b8fffd678599636ec8688e135318739723a81b9505f3546e5\
                 655031e29180a308e4cd93f07ab349c7",
                "e8b44bd61781e56a4436239124e14709d9e0f607d463f406bd5d6160bad5297d\
                 8953763db9190521d20643a6efc97537",
            ),
            (
                "b7d9e24338964a571448654a00a77a4edaaf9841f8561ca6bb9daa5288b3942b\
                 5674b20a161728ad8fae37b220a04fa2",
                "3bfa901fa99aefa0c88ddd412a63932e55f32aa2ec016200fef54118d195cbf8\
                 0ee8014f21d512e7a9bbbceb1118122f",
                "510a846edd7258cf8fb3e4b8206ed772465babce448fe06d8cd94e24f8e13eb4\
                 d5b6bd12ec036610c9d5b2e3182aef11",
                "79542d77a234e4d562294a74079c8b4f7bdecd500c104f3c68b6875d44bbacac\
                 257075c767675fd9c71df63fb73aac87",
            ),
        ] {
            let label: String = label.split_whitespace().collect();
            let mut out = [0; 48];
            mls_exporter(&unhex(secret), label.as_bytes(), &unhex(context), &mut out);
            assert_eq!(hex(&out), expected.split_whitespace().collect::<String>());
        }
    }

    #[test]
    fn sign_content_encoding() {
        let bytes = sign_content("risala message", b"abc");
        assert_eq!(bytes[0], 22);
        assert_eq!(&bytes[1..23], b"MLS 1.0 risala message");
        assert_eq!(&bytes[23..], b"\x03abc");
    }
}

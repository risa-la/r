//! One sealed Welcome per device (12.8).
//!
//! An MLS Welcome lists in the clear the KeyPackageRef of every device it
//! adds, and the part every new member decrypts is the same for all of
//! them. So for each device added from a KeyPackage that KEYPKG GET handed
//! out, the committer makes a Welcome of its own, whose `secrets` holds
//! only that device's entry, and seals it to the device:
//!
//! ```text
//! struct {
//!     uint8 version;               // 1
//!     opaque kem_output<V>;
//!     opaque ciphertext<V>;
//! } SealedWelcome;
//! ```
//!
//! HPKE SealBase with the suite's HPKE, to the KeyPackage's `init_key`,
//! with info `risala/1 welcome` and the KeyPackageRef as associated data.
//! The plain text is the MLSMessage holding the Welcome, followed by zero
//! bytes up to the Padmé length (12.11) of the MLSMessage's length.
//!
//! Welcomes for a public room's join proposals are not sealed.

use openmls::prelude::{HpkeCiphertext, KeyPackage, KeyPackageBundle, KeyPackageRef};
use openmls::storage::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::storage::StorageProvider as _;

use crate::CIPHERSUITE;
use crate::codec::{DecodeError, Reader, Writer};
use crate::file::padme;
use crate::framing::{CIPHER_SUITE, MLS10};

/// The HPKE info of a sealed Welcome (12.8, 15).
pub const WELCOME_INFO: &[u8] = b"risala/1 welcome";

/// The MLSMessage wire format of a Welcome [RFC9420].
const WIRE_FORMAT_WELCOME: u16 = 3;

/// Why a Welcome could not be split, sealed or opened (12.8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WelcomeError {
    /// It is not one MLSMessage holding a Welcome of the suite.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
    /// The Welcome has no entry for a KeyPackage it should add.
    #[error("the Welcome has no entry for this KeyPackage")]
    NoEntry,
    /// HPKE failed: a key that fails the checks of 12.2, or a sealed
    /// Welcome that does not open.
    #[error("HPKE failed")]
    Hpke,
    /// The padding after the MLSMessage is not all zero, or not the Padmé
    /// length.
    #[error("bad padding")]
    Padding,
    /// No KeyPackage of this device has that ref.
    #[error("no KeyPackage of this device has that ref")]
    UnknownKeyPackage,
    /// Storage failed.
    #[error("storage")]
    Storage,
}

/// A Welcome's parts, read from its MLSMessage without keys.
struct Parts<'a> {
    /// Each EncryptedGroupSecrets entry, whole, with its KeyPackageRef.
    entries: Vec<(&'a [u8], &'a [u8])>,
    encrypted_group_info: &'a [u8],
}

fn read_parts(message: &[u8]) -> Result<Parts<'_>, DecodeError> {
    let mut r = Reader::new(message);
    if r.u16()? != MLS10 || r.u16()? != WIRE_FORMAT_WELCOME || r.u16()? != CIPHER_SUITE {
        return Err(DecodeError("not a Welcome of the suite"));
    }
    let secrets = r.vector()?;
    let encrypted_group_info = r.vector()?;
    r.finish()?;
    let mut entries = Vec::new();
    let mut s = Reader::new(secrets);
    while s.remaining() > 0 {
        let start = s.remaining();
        let new_member = s.vector()?;
        let _kem_output = s.vector()?;
        let _ciphertext = s.vector()?;
        let used = start - s.remaining();
        let offset = secrets.len() - start;
        entries.push((new_member, &secrets[offset..offset + used]));
    }
    Ok(Parts {
        entries,
        encrypted_group_info,
    })
}

fn write_welcome(entry: &[u8], encrypted_group_info: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.fixed(&MLS10.to_be_bytes())
        .fixed(&WIRE_FORMAT_WELCOME.to_be_bytes())
        .fixed(&CIPHER_SUITE.to_be_bytes())
        .vector(entry)
        .vector(encrypted_group_info);
    w.into_bytes()
}

/// Splits `welcome`, an MLSMessage holding a Welcome, into one Welcome for
/// each of `refs`, whose `secrets` holds only that KeyPackage's entry
/// (12.8).
pub fn split_welcome(welcome: &[u8], refs: &[&[u8]]) -> Result<Vec<Vec<u8>>, WelcomeError> {
    let parts = read_parts(welcome)?;
    refs.iter()
        .map(|reference| {
            let (_, entry) = parts
                .entries
                .iter()
                .find(|(r, _)| r == reference)
                .ok_or(WelcomeError::NoEntry)?;
            Ok(write_welcome(entry, parts.encrypted_group_info))
        })
        .collect()
}

/// A Welcome sealed to one device (12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedWelcome {
    /// The KeyPackageRef it is for, for `WELCOME PUT <ref>`.
    pub key_package_ref: Vec<u8>,
    /// The encoded SealedWelcome, the `<welcome>` of WELCOME PUT.
    pub sealed: Vec<u8>,
}

/// Seals `welcome`, the MLSMessage of a commit's Welcome, to each of
/// `key_packages`, the KeyPackages that KEYPKG GET handed out which the
/// commit adds: one Welcome for each, with only its entry, sealed to its
/// init key (12.8). Send each after a random wait of its own, once the
/// commit has won (7.2).
pub fn seal_welcomes(
    crypto: &impl OpenMlsCrypto,
    welcome: &[u8],
    key_packages: &[KeyPackage],
) -> Result<Vec<SealedWelcome>, WelcomeError> {
    let refs: Vec<KeyPackageRef> = key_packages
        .iter()
        .map(|kp| kp.hash_ref(crypto).map_err(|_| WelcomeError::Hpke))
        .collect::<Result<_, _>>()?;
    let ref_slices: Vec<&[u8]> = refs.iter().map(KeyPackageRef::as_slice).collect();
    let welcomes = split_welcome(welcome, &ref_slices)?;
    key_packages
        .iter()
        .zip(ref_slices)
        .zip(welcomes)
        .map(|((kp, reference), mut plain)| {
            let padded = padme(plain.len() as u64).ok_or(WelcomeError::Padding)? as usize;
            plain.resize(padded, 0);
            let sealed = crypto
                .hpke_seal(
                    CIPHERSUITE.hpke_config(),
                    kp.hpke_init_key().as_slice(),
                    WELCOME_INFO,
                    reference,
                    &plain,
                )
                .map_err(|_| WelcomeError::Hpke)?;
            let mut w = Writer::new();
            w.u8(1)
                .vector(sealed.kem_output.as_slice())
                .vector(sealed.ciphertext.as_slice());
            Ok(SealedWelcome {
                key_package_ref: reference.to_vec(),
                sealed: w.into_bytes(),
            })
        })
        .collect()
}

/// Opens a SealedWelcome with the init private key of one of this
/// device's KeyPackages, from storage, checks that the bytes after the
/// MLSMessage are all zero and up to its Padmé length, and returns the
/// KeyPackageRef it was for and the MLSMessage, for
/// [`crate::group::join_by_welcome`] (12.8).
///
/// A `WELCOME` line does not say which KeyPackage a Welcome is for, so the
/// device tries each of `candidates`, the KeyPackageRefs of the
/// KeyPackages it has uploaded and not yet seen used; HPKE opens it under
/// one only.
pub fn open_sealed_welcome<P: OpenMlsProvider>(
    provider: &P,
    sealed: &[u8],
    candidates: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>), WelcomeError> {
    let mut r = Reader::new(sealed);
    if r.u8()? != 1 {
        return Err(DecodeError("unknown SealedWelcome version").into());
    }
    let kem_output = r.vector()?;
    let ciphertext = r.vector()?;
    r.finish()?;
    let input = HpkeCiphertext {
        kem_output: kem_output.to_vec().into(),
        ciphertext: ciphertext.to_vec().into(),
    };
    for candidate in candidates {
        let Ok(reference) = key_package_ref(candidate) else {
            continue;
        };
        let Some(bundle): Option<KeyPackageBundle> = provider
            .storage()
            .key_package(&reference)
            .map_err(|_| WelcomeError::Storage)?
        else {
            continue;
        };
        let Ok(plain) = provider.crypto().hpke_open(
            CIPHERSUITE.hpke_config(),
            &input,
            bundle.init_private_key(),
            WELCOME_INFO,
            candidate,
        ) else {
            continue;
        };
        return Ok((candidate.clone(), unpad(&plain)?.to_vec()));
    }
    Err(WelcomeError::UnknownKeyPackage)
}

/// The MLSMessage at the start of a sealed Welcome's plain text, after
/// checking its padding.
fn unpad(plain: &[u8]) -> Result<&[u8], WelcomeError> {
    // The MLSMessage's own length, read from its structure.
    let mut m = Reader::new(plain);
    m.u16()?;
    m.u16()?;
    m.u16()?;
    m.vector()?;
    m.vector()?;
    let len = plain.len() - m.remaining();
    let (message, padding) = plain.split_at(len);
    if padme(len as u64) != Some(plain.len() as u64) || padding.iter().any(|b| *b != 0) {
        return Err(WelcomeError::Padding);
    }
    read_parts(message)?;
    Ok(message)
}

/// A KeyPackageRef from its bytes.
fn key_package_ref(bytes: &[u8]) -> Result<KeyPackageRef, DecodeError> {
    use tls_codec::Deserialize as _;
    let mut w = Writer::new();
    w.vector(bytes);
    KeyPackageRef::tls_deserialize_exact(w.into_bytes())
        .map_err(|_| DecodeError("not a KeyPackageRef"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(reference: &[u8], fill: u8) -> Vec<u8> {
        let mut w = Writer::new();
        w.vector(reference).vector(&[fill; 3]).vector(&[fill; 5]);
        w.into_bytes()
    }

    #[test]
    fn splitting() {
        let mut secrets = entry(&[1; 48], 0xa1);
        secrets.extend(entry(&[2; 48], 0xb2));
        let mut w = Writer::new();
        w.fixed(&1u16.to_be_bytes())
            .fixed(&3u16.to_be_bytes())
            .fixed(&0x20u16.to_be_bytes())
            .vector(&secrets)
            .vector(b"group info");
        let welcome = w.into_bytes();
        let split = split_welcome(&welcome, &[&[2; 48], &[1; 48]]).unwrap();
        assert_eq!(
            split[0],
            write_welcome(&entry(&[2; 48], 0xb2), b"group info")
        );
        assert_eq!(
            split[1],
            write_welcome(&entry(&[1; 48], 0xa1), b"group info")
        );
        // No two copies share an entry.
        assert!(!split[0].windows(5).any(|w| w == [0xa1; 5]));
        assert_eq!(
            split_welcome(&welcome, &[&[3; 48]]),
            Err(WelcomeError::NoEntry)
        );
        let mut other_suite = welcome.clone();
        other_suite[5] = 0x21;
        assert!(split_welcome(&other_suite, &[&[1; 48]]).is_err());
    }
}

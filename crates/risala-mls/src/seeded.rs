//! Building a KeyPackage twice, so that its leaf can carry a device
//! binding (12.3) of keys OpenMLS makes inside. (Public rooms' joins and
//! external commits carry no binding, so only KeyPackages need this.)
//!
//! A device binding signs the init key and the leaf's encryption key, and
//! sits in the KeyPackage's leaf node's extensions, which OpenMLS signs
//! together with those keys. OpenMLS draws the keys from the
//! provider's random source while it builds, and takes the extensions
//! before. So this crate builds once with a random source seeded with
//! fresh randomness, against a throwaway storage, to learn the keys; signs
//! the binding; and builds again with the same seed, which gives the same
//! keys, now with the binding. Nothing of the first build is kept.
//!
//! Tests check that every binding this crate makes verifies, so an OpenMLS
//! upgrade that draws randomness differently fails them.

use std::sync::Mutex;

use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};
use zeroize::Zeroizing;

use crate::primitives::{HASH_LEN, hmac_sha384};

/// A deterministic random source: HMAC-SHA-384 of a 48-byte secret seed
/// over a block counter, in counter mode. Seeded from the operating
/// system, it is as good as the seed for the keys made from it.
pub(crate) struct SeededRand {
    seed: Zeroizing<[u8; HASH_LEN]>,
    counter: Mutex<u64>,
}

/// The random source failed: the seed's stream is used up, which no build
/// can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("seeded random source exhausted")]
pub(crate) struct SeededRandError;

impl SeededRand {
    /// A new seed from the operating system.
    pub(crate) fn fresh() -> Result<Zeroizing<[u8; HASH_LEN]>, getrandom::Error> {
        let mut seed = Zeroizing::new([0; HASH_LEN]);
        getrandom::fill(&mut seed[..])?;
        Ok(seed)
    }

    /// A random source whose stream starts again from `seed`.
    pub(crate) fn new(seed: &[u8; HASH_LEN]) -> SeededRand {
        SeededRand {
            seed: Zeroizing::new(*seed),
            counter: Mutex::new(0),
        }
    }

    fn fill(&self, out: &mut [u8]) -> Result<(), SeededRandError> {
        let mut counter = self.counter.lock().map_err(|_| SeededRandError)?;
        for chunk in out.chunks_mut(HASH_LEN) {
            *counter = counter.checked_add(1).ok_or(SeededRandError)?;
            let mut input = b"risala-mls seeded rand ".to_vec();
            input.extend_from_slice(&counter.to_be_bytes());
            let block = Zeroizing::new(hmac_sha384(&self.seed[..], &input));
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

impl OpenMlsRand for SeededRand {
    type Error = SeededRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0; N];
        self.fill(&mut out)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0; len];
        self.fill(&mut out)?;
        Ok(out)
    }
}

/// An OpenMLS provider put together from parts.
pub(crate) struct Parts<'a, C, R, S> {
    pub(crate) crypto: &'a C,
    pub(crate) rand: &'a R,
    pub(crate) storage: &'a S,
}

impl<C, R, S> OpenMlsProvider for Parts<'_, C, R, S>
where
    C: OpenMlsCrypto,
    R: OpenMlsRand,
    S: StorageProvider<CURRENT_VERSION>,
{
    type CryptoProvider = C;
    type RandProvider = R;
    type StorageProvider = S;

    fn storage(&self) -> &S {
        self.storage
    }

    fn crypto(&self) -> &C {
        self.crypto
    }

    fn rand(&self) -> &R {
        self.rand
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let seed = SeededRand::fresh().unwrap();
        let a = SeededRand::new(&seed);
        let b = SeededRand::new(&seed);
        let first: [u8; 100] = a.random_array().unwrap();
        assert_eq!(first.to_vec(), b.random_vec(100).unwrap());
        // The stream goes on, and another seed gives another one.
        assert_ne!(a.random_vec(100).unwrap(), first.to_vec());
        let other = SeededRand::new(&SeededRand::fresh().unwrap());
        assert_ne!(other.random_vec(100).unwrap(), first.to_vec());
    }
}

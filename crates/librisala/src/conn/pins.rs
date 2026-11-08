//! What the user decides about a server's certificate (2.2, PLAN.md 58):
//! accepting a fingerprint on first use, setting or clearing a strict
//! pin, and approving a strictly pinned server's new key.
//!
//! Every change is one compare-and-swap on the trust store
//! ([`TrustStore::replace`]), so a record written meanwhile, by another
//! connection or process, is never overwritten. The trust store may block
//! (SQLite), so call these off the async runtime's worker threads.

use risala_proto::fingerprint::Fingerprint;

use super::error::{Error, TrustError};
use crate::addr::{Replaced, ServerAddr, TrustRecord, TrustStore};

/// Records the fingerprint the user accepted for a server that had no
/// record (2.2), after a [`TrustError::Unknown`].
///
/// It refuses to replace a record that differs: after a mismatch the user
/// must delete the record explicitly, with [`TrustStore::forget`], first.
/// Doing it again with the same fingerprint is fine.
pub fn accept_fingerprint(
    trust: &dyn TrustStore,
    addr: &ServerAddr,
    fingerprint: Fingerprint,
) -> Result<(), Error> {
    match trust.pin_if_unknown(addr, fingerprint)? {
        None => Ok(()),
        Some(TrustRecord::Pinned(fp) | TrustRecord::Strict(fp)) if fp == fingerprint => Ok(()),
        Some(recorded) => Err(TrustError::Mismatch {
            recorded,
            presented: fingerprint,
            ca_error: "a different record exists".into(),
        }
        .into()),
    }
}

/// Sets a strict pin on `fingerprint` (2.2): from now on every
/// certificate of the server, CA-valid or not, must have it, and another
/// needs the user's approval ([`approve_new_pin`]).
///
/// `fingerprint` is the one the user saw, usually that of the connection
/// open now ([`Verified::fingerprint`](super::Verified)). It replaces
/// whatever record there is, unless the server has no record yet, which
/// needs a connection first; then it fails with [`TrustError::Unknown`].
pub fn set_strict_pin(
    trust: &dyn TrustStore,
    addr: &ServerAddr,
    fingerprint: Fingerprint,
) -> Result<(), Error> {
    let current = trust.get(addr)?;
    match &current {
        None => {
            return Err(TrustError::Unknown {
                fingerprint,
                ca_error: "the server has not been connected to".into(),
            }
            .into());
        }
        Some(TrustRecord::Strict(fp)) if *fp == fingerprint => return Ok(()),
        Some(_) => {}
    }
    let strict = TrustRecord::Strict(fingerprint);
    match trust.replace(addr, current.as_ref(), strict, None)? {
        Replaced::Done => Ok(()),
        Replaced::Found(_) => Err(TrustError::RecordChanged.into()),
    }
}

/// Turns a strict pin back into an ordinary one (2.2): a CA-valid
/// certificate is then accepted again, and replaces the pin with "CA".
/// Does nothing if the pin is not strict.
pub fn clear_strict_pin(trust: &dyn TrustStore, addr: &ServerAddr) -> Result<(), Error> {
    let Some(TrustRecord::Strict(fp)) = trust.get(addr)? else {
        return Ok(());
    };
    let current = TrustRecord::Strict(fp);
    match trust.replace(addr, Some(&current), TrustRecord::Pinned(fp), None)? {
        Replaced::Done => Ok(()),
        Replaced::Found(_) => Err(TrustError::RecordChanged.into()),
    }
}

/// Records a strictly pinned server's new fingerprint, which the user
/// approved after a [`TrustError::StrictMismatch`] (2.2). The pin stays
/// strict. It fails with [`TrustError::RecordChanged`] if the pin is no
/// longer `pinned`.
pub fn approve_new_pin(
    trust: &dyn TrustStore,
    addr: &ServerAddr,
    pinned: Fingerprint,
    presented: Fingerprint,
) -> Result<(), Error> {
    let old = TrustRecord::Strict(pinned);
    match trust.replace(addr, Some(&old), TrustRecord::Strict(presented), None)? {
        Replaced::Done => Ok(()),
        Replaced::Found(Some(TrustRecord::Strict(fp))) if fp == presented => Ok(()),
        Replaced::Found(_) => Err(TrustError::RecordChanged.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::MemoryTrustStore;

    fn addr() -> ServerAddr {
        "chat.example.org".parse().unwrap()
    }

    #[test]
    fn accepting_keeps_any_other_record() {
        let trust = MemoryTrustStore::default();
        let (a, b) = (
            Fingerprint::from_bytes([1; 32]),
            Fingerprint::from_bytes([2; 32]),
        );
        accept_fingerprint(&trust, &addr(), a).unwrap();
        accept_fingerprint(&trust, &addr(), a).unwrap();
        assert!(matches!(
            accept_fingerprint(&trust, &addr(), b),
            Err(Error::Trust(TrustError::Mismatch { .. }))
        ));
        assert_eq!(trust.get(&addr()).unwrap(), Some(TrustRecord::Pinned(a)));
    }

    #[test]
    fn strict_pins() {
        let trust = MemoryTrustStore::default();
        let (a, b, c) = (
            Fingerprint::from_bytes([1; 32]),
            Fingerprint::from_bytes([2; 32]),
            Fingerprint::from_bytes([3; 32]),
        );
        // No record yet: connect first.
        assert!(matches!(
            set_strict_pin(&trust, &addr(), a),
            Err(Error::Trust(TrustError::Unknown { .. }))
        ));
        trust.replace(&addr(), None, TrustRecord::Ca, None).unwrap();
        set_strict_pin(&trust, &addr(), a).unwrap();
        assert_eq!(trust.get(&addr()).unwrap(), Some(TrustRecord::Strict(a)));
        set_strict_pin(&trust, &addr(), a).unwrap();

        // Approving a new key keeps it strict, and only replaces the pin
        // the user saw.
        assert!(matches!(
            approve_new_pin(&trust, &addr(), b, c),
            Err(Error::Trust(TrustError::RecordChanged))
        ));
        approve_new_pin(&trust, &addr(), a, b).unwrap();
        approve_new_pin(&trust, &addr(), a, b).unwrap();
        assert_eq!(trust.get(&addr()).unwrap(), Some(TrustRecord::Strict(b)));

        clear_strict_pin(&trust, &addr()).unwrap();
        assert_eq!(trust.get(&addr()).unwrap(), Some(TrustRecord::Pinned(b)));
        clear_strict_pin(&trust, &addr()).unwrap();
        assert_eq!(trust.get(&addr()).unwrap(), Some(TrustRecord::Pinned(b)));
    }
}

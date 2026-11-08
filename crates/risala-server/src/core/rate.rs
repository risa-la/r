//! Limits on how often something may happen in a sliding window, such as
//! registrations per network address (4.6, 14) and rooms created per
//! identity (6.1, 14).
//!
//! A slot is taken when the check passes, before the work it guards, and
//! given back if that work fails. So work still in progress counts too, and
//! running it on several connections at once does not get around the
//! limit (4.6).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use risala_proto::time::Timestamp;

/// The network an address counts against, for limits by address (13):
/// the address, or the /64 of an IPv6 address, since one host usually
/// has a whole /64. An IPv4-mapped IPv6 address counts as the IPv4
/// address.
pub(super) fn network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let bits = u128::from(v6) & !((1u128 << 64) - 1);
                IpAddr::V6(bits.into())
            }
        },
    }
}

/// At most some number of slots per key in any `window`.
#[derive(Debug)]
pub(super) struct WindowLimit<K> {
    window: Duration,
    /// When each key took its slots in the last window, oldest first. Keys
    /// with none are forgotten.
    taken: Mutex<HashMap<K, VecDeque<Timestamp>>>,
}

/// A slot taken by [`WindowLimit::take`]. It is given back when dropped,
/// unless [`keep`](Self::keep) was called.
#[must_use = "a slot is given back when dropped"]
#[derive(Debug)]
pub(super) struct Slot<'a, K: Eq + Hash> {
    limit: &'a WindowLimit<K>,
    key: K,
    at: Timestamp,
    kept: bool,
}

impl<K: Eq + Hash + Clone> WindowLimit<K> {
    pub(super) fn new(window: Duration) -> WindowLimit<K> {
        WindowLimit {
            window,
            taken: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, VecDeque<Timestamp>>> {
        self.taken.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes one of `key`'s `max` slots at `now`. Fails with the seconds
    /// until one is free again, at least 1, if all are taken. A `max` of 0
    /// means no limit, and takes nothing.
    pub(super) fn take(
        &self,
        key: K,
        max: u32,
        now: Timestamp,
    ) -> Result<Option<Slot<'_, K>>, u64> {
        if max == 0 {
            return Ok(None);
        }
        let mut all = self.lock();
        // Forget what is older than the window, everywhere, so the map
        // holds only the last window's slots.
        all.retain(|_, times| {
            while times
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= self.window)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        let times = all.entry(key.clone()).or_default();
        if times.len() >= max as usize {
            let oldest = times.front().copied().unwrap_or(now);
            let waited = now.saturating_duration_since(oldest);
            return Err(self.window.saturating_sub(waited).as_secs().max(1));
        }
        times.push_back(now);
        Ok(Some(Slot {
            limit: self,
            key,
            at: now,
            kept: false,
        }))
    }
}

impl<K: Eq + Hash> Slot<'_, K> {
    /// The work succeeded: the slot stays taken for the rest of the
    /// window.
    pub(super) fn keep(mut self) {
        self.kept = true;
    }
}

impl<K: Eq + Hash> Drop for Slot<'_, K> {
    fn drop(&mut self) {
        if !self.kept {
            let mut all = self.limit.taken.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(times) = all.get_mut(&self.key) {
                if let Some(i) = times.iter().rposition(|t| *t == self.at) {
                    times.remove(i);
                }
                if times.is_empty() {
                    all.remove(&self.key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_counted_while_taken_and_given_back_on_failure() {
        let limit = WindowLimit::new(Duration::from_secs(100));
        let t0: Timestamp = "2026-11-07T00:00:00.000Z".parse().unwrap();
        let a = limit.take("a", 2, t0).unwrap().unwrap();
        let b = limit.take("a", 2, t0).unwrap().unwrap();
        // Two in progress: a third waits, even though neither finished.
        assert_eq!(limit.take("a", 2, t0).unwrap_err(), 100);
        assert!(limit.take("b", 2, t0).unwrap().is_some());
        // One failed: its slot is free again.
        drop(a);
        let c = limit.take("a", 2, t0).unwrap().unwrap();
        b.keep();
        c.keep();
        let later = t0.checked_add(Duration::from_secs(40)).unwrap();
        assert_eq!(limit.take("a", 2, later).unwrap_err(), 60);
        let much_later = t0.checked_add(Duration::from_secs(100)).unwrap();
        assert!(limit.take("a", 2, much_later).unwrap().is_some());
        // No limit.
        assert!(limit.take("a", 0, t0).unwrap().is_none());
    }
}

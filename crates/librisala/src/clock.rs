//! The time, behind a clock that tests can replace (docs/plans/M2-M5.md,
//! conventions). Every time in draft-03 is in milliseconds since
//! 1970-01-01T00:00:00Z (4.4, 12.9), as a [`Timestamp`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use risala_proto::time::Timestamp;

/// Where the time comes from.
pub trait Clock: Send + Sync {
    /// The time now.
    fn now(&self) -> Timestamp;
}

/// The system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// A clock that stands still until it is moved, for tests.
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    /// A clock at `millis` milliseconds since 1970, which must be a time
    /// a [`Timestamp`] can hold.
    pub fn new(millis: u64) -> ManualClock {
        ManualClock(Arc::new(AtomicU64::new(millis)))
    }

    /// Moves the clock on by `millis` milliseconds.
    pub fn advance(&self, millis: u64) {
        self.0.fetch_add(millis, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        let ms = self.0.load(Ordering::SeqCst);
        Timestamp::from_unix_millis(ms).unwrap_or(Timestamp::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now().unix_millis(), 1_000);
        clock.clone().advance(500);
        assert_eq!(clock.now().unix_millis(), 1_500);
        assert!(SystemClock.now() > clock.now());
    }
}

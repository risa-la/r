//! A small seeded random number generator (SplitMix64), so that a
//! scenario looks the same on every run. Not for anything secret.

/// SplitMix64: fast, with a 64-bit state, good enough to shuffle data.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator from `seed`.
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    /// A generator for one purpose, derived from `seed` and `stream`, so
    /// that drawing more numbers for one thing does not change another.
    pub fn stream(seed: u64, stream: u64) -> Rng {
        let mut rng = Rng(seed ^ stream.wrapping_mul(0xA076_1D64_78BD_642F));
        rng.next_u64();
        rng
    }

    /// The next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `lo..hi`, or `lo` when the range is empty.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo)
    }

    /// An index below `n`, which must not be 0.
    pub fn below(&mut self, n: usize) -> usize {
        assert!(n > 0, "choosing from nothing");
        (self.next_u64() % n as u64) as usize
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    /// A number in `0.0..1.0`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// One of `items`, which must not be empty.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// 32 random bytes, for a key's seed.
    pub fn seed32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        out
    }

    /// Shuffles `items` in place.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_numbers() {
        let a: Vec<u64> = (0..5).map(|_| Rng::new(7).next_u64()).collect();
        let mut r = Rng::new(7);
        let first = r.next_u64();
        assert!(a.iter().all(|&x| x == first));
        assert_ne!(Rng::stream(7, 1).next_u64(), Rng::stream(7, 2).next_u64());
    }

    #[test]
    fn ranges_stay_in_bounds() {
        let mut r = Rng::new(1);
        for _ in 0..1000 {
            let x = r.range(10, 20);
            assert!((10..20).contains(&x));
            assert!(r.unit() < 1.0);
        }
        assert_eq!(r.range(5, 5), 5);
    }
}

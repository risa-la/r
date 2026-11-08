//! SipRound and the word stream.

/// The SipHash initial values, used to start a stream.
const IV: [u64; 4] = [
    0x736f_6d65_7073_6575,
    0x646f_7261_6e64_6f6d,
    0x6c79_6765_6e65_7261,
    0x7465_6462_7974_6573,
];

/// One SipRound on four words.
#[inline(always)]
pub(crate) fn sip_round(s: &mut [u64; 4]) {
    let [mut a, mut b, mut c, mut d] = *s;
    a = a.wrapping_add(b);
    b = b.rotate_left(13);
    b ^= a;
    a = a.rotate_left(32);
    c = c.wrapping_add(d);
    d = d.rotate_left(16);
    d ^= c;
    a = a.wrapping_add(d);
    d = d.rotate_left(21);
    d ^= a;
    c = c.wrapping_add(b);
    b = b.rotate_left(17);
    b ^= c;
    c = c.rotate_left(32);
    *s = [a, b, c, d];
}

/// Splits a 16-byte key into two little-endian words.
pub(crate) fn key_words(key: &[u8; 16]) -> [u64; 2] {
    let (k0, k1) = key.split_at(8);
    [
        u64::from_le_bytes(k0.try_into().expect("8 bytes")),
        u64::from_le_bytes(k1.try_into().expect("8 bytes")),
    ]
}

/// The endless word stream, made from a 16-byte key (as two
/// words) and a 64-bit tweak.
#[derive(Clone, Debug)]
pub(crate) struct WordStream {
    k: [u64; 2],
    /// The state (a, b, c, d).
    s: [u64; 4],
    /// How many words of the current state have been yielded. The state is
    /// refreshed only when a fifth word is wanted.
    used: usize,
}

impl WordStream {
    /// Starts a stream.
    pub(crate) fn new(k: [u64; 2], tweak: u64) -> Self {
        let mut s = [
            k[0] ^ IV[0],
            k[1] ^ IV[1],
            k[0] ^ IV[2],
            k[1] ^ IV[3] ^ tweak,
        ];
        sip_round(&mut s);
        s[0] ^= tweak;
        s[2] ^= 0xbb;
        for _ in 0..3 {
            sip_round(&mut s);
        }
        WordStream { k, s, used: 0 }
    }

    /// The next four words, in the order d, c, b, a.
    /// Only valid at the start of a group of four.
    pub(crate) fn next_four(&mut self) -> [u64; 4] {
        if self.used == 4 {
            self.refresh();
        }
        debug_assert_eq!(self.used, 0);
        self.used = 4;
        let [a, b, c, d] = self.s;
        [d, c, b, a]
    }

    /// The next word.
    pub(crate) fn next_word(&mut self) -> u64 {
        if self.used == 4 {
            self.refresh();
        }
        let w = self.s[3 - self.used];
        self.used += 1;
        w
    }

    /// Refreshes the state before the next group of four.
    fn refresh(&mut self) {
        self.s[0] ^= self.k[0];
        self.s[1] ^= self.k[1];
        self.s[2] ^= self.k[0];
        self.s[3] ^= self.k[1];
        for _ in 0..4 {
            sip_round(&mut self.s);
        }
        self.used = 0;
    }
}

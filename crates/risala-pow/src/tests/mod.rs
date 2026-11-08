//! Test vectors and edge cases.

mod listings;

use core::num::NonZeroU64;
use std::format;
use std::string::{String, ToString as _};
use std::vec::Vec;

use sha2::{Digest as _, Sha256};

use crate::hash::{HashWx, SCRATCHPAD_LEN, Scratchpad};
use crate::program::{Layout, Program, WORDS_PER_PROGRAM};
use crate::puzzle::Puzzle;
use crate::stream::{WordStream, key_words};
use crate::tables::{GROUP_PATTERNS, LARGE_SOURCES, SMALL_SOURCES};

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N, "{s}");
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn nz(x: u64) -> NonZeroU64 {
    NonZeroU64::new(x).expect("non-zero")
}

/// R1: "risala proof of work test seed 1".
const R1: &str = "726973616c612070726f6f66206f6620776f726b207465737420736565642031";
/// R2: "a second seed for the risala pow".
const R2: &str = "61207365636f6e64207365656420666f722074686520726973616c6120706f77";
/// Z: 32 zero bytes.
const Z: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// F: 32 bytes of ff.
const F: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// Q: the bytes 0 to 31.
const Q: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn seeds_r1_r2_are_the_ascii_texts() {
    assert_eq!(&unhex::<32>(R1), b"risala proof of work test seed 1");
    assert_eq!(&unhex::<32>(R2), b"a second seed for the risala pow");
}

// Word stream.

fn stream_words(key: &str, tweak: u64, count: usize) -> Vec<u64> {
    let mut s = WordStream::new(key_words(&unhex(key)), tweak);
    (0..count).map(|_| s.next_word()).collect()
}

#[test]
fn word_stream_vectors() {
    let cases: [(&str, u64, [u64; 12]); 3] = [
        (
            "726973616c612070726f6f66206f6620",
            18446744073709551615,
            [
                0xd09d9f7b71c02e8f,
                0xf658c8e5297d2d34,
                0xf9e320a37e7ab795,
                0x6913118a6a9f2334,
                0xc791fd53f63bbae0,
                0xa56e16b458f99ae2,
                0xb2652ca2b272ef24,
                0xd51cdb3d582fac7c,
                0x951db9ad7f0c6398,
                0x70aed24cda30aef0,
                0x671254f8df13e3f2,
                0x95e7b324d11f2bc6,
            ],
        ),
        (
            "726973616c612070726f6f66206f6620",
            0,
            [
                0x651ee9c4c2a13130,
                0xec93e1d21d8de2b3,
                0x33eabd2a25bad9c8,
                0x9f84e92df6c3acaf,
                0xedc8fb63476bd4bb,
                0xb2e55a285356ac00,
                0x0665a7041fc6c9ab,
                0xb8b0a02316105544,
                0xbe21feeca4a1815d,
                0xbbca66b8be340582,
                0x71f4ba9db0de34ce,
                0x35501f44be3d72fc,
            ],
        ),
        (
            "00000000000000000000000000000000",
            0,
            [
                0xf57973a503390e3f,
                0x2a44eccf3848ebe1,
                0x6a50e07d85ac7eba,
                0x46af611dcd8a2969,
                0x2fc40ce487e0e297,
                0xe3534549d6fbeab0,
                0xa36f5d44da315575,
                0xd41154c973e9983c,
                0xdf4f503800781470,
                0x072802216e95261a,
                0x587f6adf430d7f28,
                0xd4ed6b9d16fbda56,
            ],
        ),
    ];
    for (key, tweak, want) in cases {
        assert_eq!(
            stream_words(key, tweak, 12),
            want,
            "key {key} tweak {tweak}"
        );
        // Drawing four at a time gives the same words.
        let mut s = WordStream::new(key_words(&unhex(key)), tweak);
        let fours: Vec<u64> = (0..3).flat_map(|_| s.next_four()).collect();
        assert_eq!(fours, want, "key {key} tweak {tweak}, by fours");
    }
}

// Building programs 0 and 1 of seed R1.

struct BuildVector {
    index: usize,
    words: [u64; WORDS_PER_PROGRAM],
    pattern: usize,
    pattern_text: &'static str,
    mix_ops: [u32; 7],
    multiply_ops: [u32; 7],
    dst: [u8; 8],
    small_table: bool,
    source_index: usize,
    sources: &'static str,
}

#[test]
fn program_build_vectors() {
    let vectors = [
        BuildVector {
            index: 0,
            words: [
                0xd09d9f7b71c02e8f,
                0xf658c8e5297d2d34,
                0xf9e320a37e7ab795,
                0x6913118a6a9f2334,
                0xc791fd53f63bbae0,
                0xa56e16b458f99ae2,
                0xb2652ca2b272ef24,
                0xd51cdb3d582fac7c,
                0x951db9ad7f0c6398,
                0x70aed24cda30aef0,
                0x671254f8df13e3f2,
                0x95e7b324d11f2bc6,
                0xe247c951c4a3f5c3,
                0xa0779bd313451ae6,
                0xf1751945ab031e8a,
                0xaa30946e3e21c2cb,
            ],
            pattern: 22,
            pattern_text: ">*>>**>",
            mix_ops: [2, 5, 7, 7, 7, 0, 6],
            multiply_ops: [2, 2, 1, 1, 1, 0, 0],
            dst: [0, 2, 7, 3, 4, 5, 1, 6],
            small_table: true,
            source_index: 4,
            sources: "6123475",
        },
        BuildVector {
            index: 1,
            words: [
                0x07eefcdcff45f435,
                0x74046db506211157,
                0x23e5e7cd16267eaa,
                0x15601700ceec3827,
                0x81a12c71c2e1d41e,
                0xef702add6cc410ba,
                0x7830041b95871bd0,
                0xcd6632c810493943,
                0xee398bb5ccac20f6,
                0x0a38737b0f632470,
                0xa4d946cce2e3aab0,
                0x8adc4d0de4d4d38c,
                0xc55fe0d7a33f47b0,
                0x64e465589aa5dbde,
                0x11437b9ed05bf9fa,
                0xe0ac053bb85b6393,
            ],
            pattern: 25,
            pattern_text: ">>***>>",
            mix_ops: [3, 5, 8, 6, 1, 2, 6],
            multiply_ops: [0, 2, 2, 0, 1, 2, 0],
            dst: [4, 3, 2, 7, 1, 6, 0, 5],
            small_table: false,
            source_index: 67,
            sources: "6157430",
        },
    ];

    let mut stream = WordStream::new(key_words(&unhex::<32>(R1)[..16].try_into().unwrap()), !0);
    for v in vectors {
        let words: [u64; WORDS_PER_PROGRAM] = core::array::from_fn(|_| stream.next_word());
        assert_eq!(words, v.words, "program {}", v.index);

        let lo_mod = |m: u32| -> [u32; 7] { core::array::from_fn(|i| (words[i] as u32) % m) };
        assert_eq!(lo_mod(9), v.mix_ops, "program {}", v.index);
        assert_eq!(lo_mod(3), v.multiply_ops, "program {}", v.index);

        let layout = Layout::new(&words, v.index);
        assert_eq!(
            layout,
            Layout {
                pattern: v.pattern,
                dst: v.dst,
                small_table: v.small_table,
                source_index: v.source_index,
                sources: v.sources,
            },
            "program {}",
            v.index
        );
        assert_eq!(GROUP_PATTERNS[layout.pattern], v.pattern_text);
        assert_eq!(
            Program::from_words(&words, v.index).to_string(),
            listings::R1_PROGRAMS[v.index]
        );
    }
}

// Program listings.

#[test]
fn program_listings() {
    for (seed, want) in [
        (R1, &listings::R1_PROGRAMS),
        (Z, &listings::ZERO_SEED_PROGRAMS),
    ] {
        let hashwx = HashWx::new(&unhex(seed));
        for (i, (program, line)) in hashwx.programs().iter().zip(want.iter()).enumerate() {
            assert_eq!(program.to_string(), *line, "seed {seed} program {i}");
        }
    }
}

// Register states.

struct StateVector {
    seed: &'static str,
    nonce: u64,
    start: [u64; 9],
    after_write: [u64; 9],
    scratchpad: &'static str,
    after_read: [u64; 9],
    hash: u64,
}

#[test]
fn register_state_vectors() {
    let vectors = [
        StateVector {
            seed: R1,
            nonce: 0,
            start: [
                0x48a70a413635d204,
                0x5f19d6a16ec82d01,
                0x2ed44424dd2e7153,
                0xfca0666b560f6498,
                0x94a3f598cdd63d72,
                0x8dd9d2c9a0a911c3,
                0xb3e8d70a21d7f26a,
                0x986ab74d3f08a7c0,
                0xdc04ffd9fbe3ef73,
            ],
            after_write: [
                0xb00f71dbc21b4d69,
                0x354ce7e1462c33d1,
                0x4d0b680cba57df01,
                0x80359d4b4d821f65,
                0xd39ab80fa5e06631,
                0x0284758d52255f5e,
                0xbb1bf4720aaac74f,
                0x8c02edf31d8ec759,
                0xdc04ffd9fbe3ef73,
            ],
            scratchpad: "35aef413d7f4dc6b5be0c1c303c4670f017e39dbb0beeee1e32ce13c5bfc3211",
            after_read: [
                0x4dfe7f8171b54f31,
                0x2235d78cbff81eda,
                0x6f0c06781cfa3b35,
                0xc6c8024d53338f53,
                0xf701ffae2f05815d,
                0xc7d7f18b96271518,
                0xa2bbff96470dee24,
                0x739951a13822eb79,
                0xdc04ffd9fbe3ef73,
            ],
            hash: 0xe40faca40ffc1aa6,
        },
        StateVector {
            seed: R2,
            nonce: 123456,
            start: [
                0xb6887f5b809d8917,
                0x889dc47bcfa84b8d,
                0x52e7c1c036f10edc,
                0x8acdef0e3f8c7ad2,
                0x8b817fd702620844,
                0x28e3da16b3434cd0,
                0x00817d9989aa0820,
                0x4955505a6b176750,
                0x3d09008c82ff8153,
            ],
            after_write: [
                0x5f27803e34280048,
                0x144a60bf942a8738,
                0xe423fcf0cf120bf8,
                0x2f9e79b5a6e236b8,
                0x5a034e09a9ec63e8,
                0xb18dfb6530f76a98,
                0xc74bf676a7c70698,
                0xe81532bc5d0e3dbe,
                0x3d09008c82ff8153,
            ],
            scratchpad: "5387dc2698ca65a5476a757fa7bde8469d0cf85568152c6b5d44051b6cfa4986",
            after_read: [
                0x0004c6c03bb2e794,
                0x179380b3bff42402,
                0xae57cbff6ca3d967,
                0x95bae26c3a5f10fb,
                0xdda5dff047d52ff8,
                0x8a6d5c60f2e986d0,
                0x7ae9db30db7e6af2,
                0xc5be536e83bfe503,
                0x3d09008c82ff8153,
            ],
            hash: 0xf3284431dd483783,
        },
    ];
    for v in vectors {
        let hashwx = HashWx::new(&unhex(v.seed));
        let t = hashwx.trace(&mut Scratchpad::new(), v.nonce);
        let what = format!("seed {} nonce {}", v.seed, v.nonce);
        assert_eq!(t.start, v.start, "{what}: start");
        // R8 mod 8 = 3.
        assert_eq!(t.start[8] % 8, 3, "{what}: R8");
        assert_eq!(t.after_write, v.after_write, "{what}: after write");
        // The write phase saves 256 blocks of 64 bytes, so P ends at 0.
        assert_eq!(t.save_pointer_after_write, 0, "{what}: save pointer");
        assert_eq!(t.scratchpad_after_write.len(), SCRATCHPAD_LEN);
        assert_eq!(
            sha256_hex(&t.scratchpad_after_write),
            v.scratchpad,
            "{what}: scratchpad"
        );
        assert_eq!(t.after_read, v.after_read, "{what}: after read");
        assert_eq!(t.hash, v.hash, "{what}: hash");
    }
}

// Hash values.

struct HashVector {
    name: &'static str,
    seed: &'static str,
    nonce: u64,
    hash: u64,
    /// How many reads reach into the R8 slot, where given.
    r8_slot_reads: Option<u32>,
    /// The note "stops: n", where given.
    stops: Option<u32>,
}

const HASH_VECTORS: [HashVector; 19] = [
    HashVector {
        name: "H1",
        seed: R1,
        nonce: 0,
        hash: 0xe40faca40ffc1aa6,
        r8_slot_reads: Some(1),
        stops: Some(27),
    },
    HashVector {
        name: "H2",
        seed: R1,
        nonce: 123456,
        hash: 0x478cf1fd8091d1c0,
        r8_slot_reads: Some(0),
        stops: Some(8),
    },
    HashVector {
        name: "H3",
        seed: R2,
        nonce: 123456,
        hash: 0xf3284431dd483783,
        r8_slot_reads: Some(1),
        stops: Some(10),
    },
    HashVector {
        name: "H4",
        seed: R2,
        nonce: 987654321123456789,
        hash: 0x05935d416315ee4d,
        r8_slot_reads: Some(0),
        stops: Some(6),
    },
    HashVector {
        name: "H5",
        seed: Z,
        nonce: 0,
        hash: 0x2cc690000e3a1f70,
        r8_slot_reads: None,
        stops: Some(14),
    },
    HashVector {
        name: "H6",
        seed: Z,
        nonce: 1,
        hash: 0x3a9f0afd767b27a5,
        r8_slot_reads: Some(1),
        stops: Some(5),
    },
    HashVector {
        name: "H7",
        seed: Z,
        nonce: 18446744073709551615,
        hash: 0x79be83f298813cfb,
        r8_slot_reads: Some(1),
        stops: None,
    },
    HashVector {
        name: "H8",
        seed: F,
        nonce: 0,
        hash: 0xa4ccba8656d94570,
        r8_slot_reads: Some(2),
        stops: None,
    },
    HashVector {
        name: "H9",
        seed: F,
        nonce: 18446744073709551615,
        hash: 0x4463dcf9dd12693d,
        r8_slot_reads: Some(1),
        stops: None,
    },
    HashVector {
        name: "H10",
        seed: Q,
        nonce: 0,
        hash: 0xe92a9e0220544f08,
        r8_slot_reads: Some(1),
        stops: None,
    },
    HashVector {
        name: "H11",
        seed: Q,
        nonce: 1,
        hash: 0xde3bbe6f99d2d457,
        r8_slot_reads: Some(2),
        stops: Some(12),
    },
    HashVector {
        name: "H12",
        seed: Q,
        nonce: 2,
        hash: 0xd00e955a0b494047,
        r8_slot_reads: None,
        stops: Some(9),
    },
    HashVector {
        name: "H13",
        seed: Q,
        nonce: 463,
        hash: 0x206d04db18f8116a,
        r8_slot_reads: Some(3),
        stops: Some(18),
    },
    HashVector {
        name: "H14",
        seed: Q,
        nonce: 65535,
        hash: 0xd00b6cc3b394237a,
        r8_slot_reads: None,
        stops: Some(20),
    },
    HashVector {
        name: "H15",
        seed: Q,
        nonce: 65536,
        hash: 0x01d9e8881d3b7897,
        r8_slot_reads: None,
        stops: Some(11),
    },
    HashVector {
        name: "H16",
        seed: Q,
        nonce: 4294967296,
        hash: 0x05974976a43ddafa,
        r8_slot_reads: Some(1),
        stops: None,
    },
    HashVector {
        name: "H17",
        seed: Q,
        nonce: 9223372036854775808,
        hash: 0x86ab97151dbe63cd,
        r8_slot_reads: None,
        stops: None,
    },
    HashVector {
        name: "H18",
        seed: Q,
        nonce: 18446744073709551615,
        hash: 0xc939c32ba900a0ab,
        r8_slot_reads: None,
        stops: None,
    },
    HashVector {
        name: "H19",
        seed: R2,
        nonce: 1000003,
        hash: 0x823303f79b8a820e,
        r8_slot_reads: Some(2),
        stops: Some(23),
    },
];

#[test]
fn hash_vectors() {
    let mut scratchpad = Scratchpad::new();
    for v in &HASH_VECTORS {
        let hashwx = HashWx::new(&unhex(v.seed));
        assert_eq!(hashwx.hash(&mut scratchpad, v.nonce), v.hash, "{}", v.name);
        assert_eq!(
            hashwx.hash_one(v.nonce),
            v.hash,
            "{} (fresh scratchpad)",
            v.name
        );
    }
}

/// For some vectors: how many reads reach into the R8 slot and
/// how many times `LOOP_IF` stopped for want of budget.
#[test]
fn hash_vector_notes() {
    let mut scratchpad = Scratchpad::new();
    for v in &HASH_VECTORS {
        let t = HashWx::new(&unhex(v.seed)).trace(&mut scratchpad, v.nonce);
        assert_eq!(t.hash, v.hash, "{}", v.name);
        if let Some(reads) = v.r8_slot_reads {
            assert_eq!(t.r8_slot_reads, reads, "{}: R8 slot reads", v.name);
        }
        if let Some(stops) = v.stops {
            assert_eq!(t.stops, stops, "{}: stops", v.name);
        }
    }
}

// Puzzles.

struct PuzzleVector {
    name: &'static str,
    challenge: &'static str,
    n: u64,
    d: u64,
    target: u64,
    nonce: u64,
    block: u64,
    seed: &'static str,
    hash: u64,
    /// The hash of N - 1, if N > 0.
    hash_before: Option<u64>,
}

const PUZZLE_VECTORS: [PuzzleVector; 4] = [
    PuzzleVector {
        name: "P1",
        challenge: Q,
        n: 463,
        d: 3000,
        target: 0x0015d867c3ece2a5,
        nonce: 4961,
        block: 10,
        seed: "ef876348123975ffea33e0197da8af9c3187728ac640d4e6b7b9dae11a24f69b",
        hash: 0x000d3e69449872cb,
        hash_before: Some(0x8f6c65619b16c19e),
    },
    PuzzleVector {
        name: "P2",
        challenge: Z,
        n: 16,
        d: 200,
        target: 0x0147ae147ae147ae,
        nonce: 42,
        block: 2,
        seed: "1de986ac168dcfb8a52b6320497a49a9cb6e9e9728ab59cfbb4b0d44da18fc04",
        hash: 0x004e946a69091a0a,
        hash_before: Some(0x6ee0d830de8c3e3b),
    },
    PuzzleVector {
        name: "P3",
        challenge: F,
        n: 65536,
        d: 1000,
        target: 0x004189374bc6a7ef,
        nonce: 1515,
        block: 0,
        seed: "a5d57364d057595dd9d30b02c1a99184b8cdf9353ad37f670c2421edcbacf4ae",
        hash: 0x0019366a984e9e51,
        hash_before: Some(0x016172e1098e04aa),
    },
    PuzzleVector {
        name: "P4",
        challenge: Z,
        n: 463,
        d: 1,
        target: 0xffffffffffffffff,
        nonce: 0,
        block: 0,
        seed: "2c34ce1df23b838c5abf2a7f6437cca3d3067ed509ff25f11df6b11b582b51eb",
        hash: 0x47742bcc04135764,
        hash_before: None,
    },
];

#[test]
fn puzzle_vectors() {
    for v in &PUZZLE_VECTORS {
        let p = Puzzle::new(unhex(v.challenge), nz(v.n), nz(v.d));
        assert_eq!(p.target(), v.target, "{}", v.name);
        assert_eq!(p.block(v.nonce), v.block, "{}", v.name);
        assert_eq!(hex(&p.seed(v.block)), v.seed, "{}", v.name);
        assert_eq!(p.hash(v.nonce), v.hash, "{}", v.name);
        assert!(p.verify(v.nonce), "{}", v.name);
        if let Some(before) = v.hash_before {
            assert_eq!(p.hash(v.nonce - 1), before, "{}", v.name);
            assert!(before > v.target, "{}", v.name);
            assert!(!p.verify(v.nonce - 1), "{}", v.name);
        }
        // N is the first solving nonce from 0: every nonce below it fails.
        assert_eq!(p.solve(0, u64::MAX), Some(v.nonce), "{}", v.name);
        // A search that stops just short of N finds nothing.
        assert_eq!(p.solve(0, v.nonce), None, "{}", v.name);
    }
}

// Table checksums.

#[test]
fn table_checksums() {
    assert_eq!(
        sha256_hex(GROUP_PATTERNS.concat().as_bytes()),
        "12c3c7d1615622c36510058968db5875bc0ac56488141b5460f1f552c36b0065"
    );
    assert_eq!(
        sha256_hex(LARGE_SOURCES.concat().as_bytes()),
        "1c63d7fe828a583e9c71f40849308a42dd85bf74fa72431fc53b94fa59264ff2"
    );
    assert_eq!(
        sha256_hex(SMALL_SOURCES.concat().as_bytes()),
        "ca8c5af71d0e821fb8da542e5736f0f70fb43d3db63ab33c58fb7b2268cc763e"
    );
}

/// Properties the tables must have.
#[test]
fn table_properties() {
    let mut patterns = GROUP_PATTERNS.to_vec();
    for p in &patterns {
        assert_eq!(p.len(), 7);
        assert_eq!(p.bytes().filter(|&b| b == b'*').count(), 3, "{p}");
        assert_eq!(p.bytes().filter(|&b| b == b'>').count(), 4, "{p}");
    }
    patterns.dedup();
    assert_eq!(patterns.len(), 35);
    assert!(GROUP_PATTERNS.is_sorted(), "`*` sorts before `>`");

    // No entry has T_m = m, so a slot never reads the register it writes.
    for entry in LARGE_SOURCES.iter().chain(SMALL_SOURCES.iter()) {
        assert_eq!(entry.len(), 7);
        for (i, digit) in entry.bytes().enumerate() {
            assert!((b'0'..=b'7').contains(&digit), "{entry}");
            assert_ne!(usize::from(digit - b'0'), i + 1, "{entry}");
        }
    }
}

// Edge cases.

/// Every seed gives a valid list of programs. For a spread of seeds,
/// check their structure: each of R0 to R7 is
/// written once, no slot reads what it writes, and constants are in range.
#[test]
fn every_seed_gives_well_formed_programs() {
    let mut seed = [0u8; 32];
    for round in 0..64u8 {
        let hashwx = HashWx::new(&seed);
        for (i, p) in hashwx.programs().iter().enumerate() {
            let mut written = [p.step_dst, 0, 0, 0, 0, 0, 0, 0];
            for (slot, ins) in p.ops.iter().enumerate() {
                written[slot + 1] = ins.dst;
                assert_ne!(ins.src, ins.dst, "seed {} program {i}", hex(&seed));
                assert!(ins.k >= 1 && ins.k <= 63);
            }
            written.sort_unstable();
            assert_eq!(
                written,
                [0, 1, 2, 3, 4, 5, 6, 7],
                "each register written once"
            );
            assert!((1..=63).contains(&p.step_k));
            assert_eq!(p.always_loop, i == 31);
        }
        // Change the seed widely and deterministically.
        seed = Sha256::digest([&seed[..], &[round]].concat()).into();
    }
}

/// The program stream takes exactly 512 words, so the word
/// after program 31 is word 513 of the stream.
#[test]
fn programs_take_exactly_512_words() {
    let key = key_words(&unhex::<32>(R1)[..16].try_into().unwrap());
    let mut a = WordStream::new(key, !0);
    let built: Vec<Program> = (0..32).map(|i| Program::build(&mut a, i)).collect();
    let mut b = WordStream::new(key, !0);
    for _ in 0..512 {
        b.next_word();
    }
    assert_eq!(a.next_word(), b.next_word());
    assert_eq!(
        built.as_slice(),
        HashWx::new(&unhex(R1)).programs().as_slice()
    );
}

/// With the all-zero seed and nonce 2^64 - 1, R0 to R7 equal w0 to
/// w7 of program 0.
#[test]
fn same_key_for_both_streams() {
    let t = HashWx::new(&[0; 32]).trace(&mut Scratchpad::new(), u64::MAX);
    let w = stream_words(&Z[..32], u64::MAX, 8);
    assert_eq!(&t.start[..8], w.as_slice());
    assert_eq!(t.hash, 0x79be83f298813cfb);
}

/// The scratchpad need not be cleared between hashes, but the R8 slot
/// must be rewritten for each nonce. Hashing with a dirty scratchpad gives
/// the same result as with a fresh one.
#[test]
fn scratchpad_reuse_and_r8_slot() {
    let hashwx = HashWx::new(&unhex(Q));
    let mut scratchpad = Scratchpad::new();
    // A scratchpad full of junk, then a nonce whose hash reads the R8 slot.
    scratchpad.bytes_mut().fill(0xa5);
    assert_eq!(hashwx.hash(&mut scratchpad, 463), 0x206d04db18f8116a);
    // The R8 slot now holds R8 of nonce 463.
    let t = hashwx.trace(&mut Scratchpad::new(), 463);
    assert_eq!(scratchpad.bytes()[16384..], t.start[8].to_le_bytes());
    // Nonces in either order on one scratchpad agree with fresh ones.
    for nonce in [0, 1, 463, 1, 0] {
        assert_eq!(
            hashwx.hash(&mut scratchpad, nonce),
            hashwx.hash_one(nonce),
            "nonce {nonce}"
        );
    }
}

/// About one hash in two reads the R8 slot; the vectors with R8 slot reads
/// prove those bytes are read with their true value. Here, check that
/// such reads do happen across many nonces, so the path is exercised.
#[test]
fn r8_slot_reads_are_common() {
    let hashwx = HashWx::new(&unhex(Q));
    let mut scratchpad = Scratchpad::new();
    let with_reads = (0..64)
        .filter(|&n| hashwx.trace(&mut scratchpad, n).r8_slot_reads > 0)
        .count();
    assert!((10..=54).contains(&with_reads), "{with_reads} of 64");
}

/// Wrapping arithmetic, and sar against shr.
#[test]
fn instruction_arithmetic() {
    use crate::program::{Instr, Op};
    let ins = |op, k| Instr {
        op,
        dst: 0,
        src: 1,
        k,
    };
    let top = 0x8000_0000_0000_0001u64;
    assert_eq!(ins(Op::SarXor, 1).apply(top, 0), 0xc000_0000_0000_0000);
    assert_eq!(ins(Op::ShrXor, 1).apply(top, 0), 0x4000_0000_0000_0000);
    assert_eq!(ins(Op::SarAdd, 3).apply(u64::MAX, 1), 0);
    assert_eq!(ins(Op::ShrSub, 3).apply(0, 1), u64::MAX);
    // x + k wraps before the multiplication.
    assert_eq!(ins(Op::AddMul, 33).apply(u64::MAX - 1, 5), 31 * 5);
    assert_eq!(ins(Op::OrMul, 9).apply(0, 3), 27);
    assert_eq!(ins(Op::XorMul, 1).apply(1, 7), 0);
    assert_eq!(ins(Op::RorXor, 1).apply(1, 0), 1 << 63);
    assert_eq!(ins(Op::RorAdd, 63).apply(1 << 63, 0), 1);
    // v is subtracted from the shifted value, not the other way round.
    assert_eq!(ins(Op::RorSub, 32).apply(1 << 32, 2), u64::MAX);
}

// Puzzle edge cases.

/// With d = 1 every nonce solves.
#[test]
fn difficulty_one_solves_everything() {
    let p = Puzzle::new([7; 32], nz(463), nz(1));
    assert_eq!(p.target(), u64::MAX);
    for nonce in [0, 1, 462, 463, u64::MAX] {
        assert!(p.verify(nonce));
        assert_eq!(p.solve(nonce, 1), Some(nonce));
    }
}

/// The search stops at its limit and at the end of the nonce space.
#[test]
fn solve_limits() {
    let p = Puzzle::new([0; 32], nz(16), nz(u64::MAX));
    assert_eq!(p.target(), 1);
    assert_eq!(p.solve(0, 0), None);
    assert_eq!(p.solve(u64::MAX - 2, u64::MAX), None);
    // The last block is short when n does not divide 2^64.
    let p = Puzzle::new([0; 32], nz(u64::MAX), nz(1));
    assert_eq!(p.block(u64::MAX), 1);
    assert_eq!(p.solve(u64::MAX, 5), Some(u64::MAX));
}

/// The search crosses blocks and makes the right function for each: with
/// n = 16, P2's solution 42 lies in block 2, found from a start in block 1.
#[test]
fn solve_across_blocks() {
    let p = Puzzle::new([0; 32], nz(16), nz(200));
    assert_eq!(p.solve(17, 100), Some(42));
    assert_eq!(p.solve(43, 0), None);
}

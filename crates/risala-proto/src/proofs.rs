//! Kani proofs. Run them with `cargo kani -p risala-proto`.
//!
//! Each harness states a property and lets Kani check it for every input
//! within its bounds. Where a harness compares against the spec, such as
//! the control characters of 2.3, it restates the rule here, written
//! without the code under test.
//!
//! Only proofs that finish in under a minute are kept, so the whole set
//! runs quickly in CI. Proofs over parsers of longer strings (timestamps,
//! lines, tags, mentions, nonces) were tried and dropped: within a
//! 90-second to 4-minute cap the checker timed out on each of them,
//! without finding a counterexample. The property tests and fuzz targets
//! cover those parsers instead.
//!
//! Proofs that need private functions sit at the end of their module:
//! `time.rs` (calendar arithmetic) and `names.rs` (name shapes).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::frame::{check_line_len, is_forbidden_control};
use crate::names::{IpPrefix, ServerBanTarget};
use crate::types::Retention;

/// A few non-ASCII characters: 2-, 3- and 4-byte UTF-8, a C1 control
/// (U+0085) and the first character after the C1 range (U+00A0).
const NON_ASCII: [char; 5] = ['é', '\u{85}', '\u{a0}', '€', '👋'];

/// A string of up to `max` symbolic characters. Each is any ASCII
/// character or, unless `ascii` is set, one of [`NON_ASCII`]. Building
/// the string from characters is much cheaper for the checker than
/// validating symbolic bytes as UTF-8, and still reaches every byte
/// boundary case: one-byte and multi-byte characters side by side.
fn any_string(max: usize, ascii: bool) -> String {
    let len: usize = kani::any();
    kani::assume(len <= max);
    let mut s = String::with_capacity(4 * max);
    for _ in 0..len {
        let b: u8 = kani::any();
        if b < 0x80 {
            s.push(char::from(b));
        } else {
            kani::assume(!ascii);
            s.push(NON_ASCII[usize::from(b) % NON_ASCII.len()]);
        }
    }
    s
}

/// The control characters of 2.3, as code point ranges.
fn spec_control(c: char) -> bool {
    let c = c as u32;
    c <= 0x08 || (0x0A..=0x1F).contains(&c) || (0x7F..=0x9F).contains(&c)
}

// ---------------------------------------------------------------------------
// frame.rs: lines (2.3)

/// `is_forbidden_control` is exactly the set of 2.3, for every `char`.
#[kani::proof]
fn forbidden_controls_match_spec() {
    let c: char = kani::any();
    assert_eq!(is_forbidden_control(c), spec_control(c));
}

/// `check_line_len` accepts a line exactly when it and its LF fit.
#[kani::proof]
#[kani::unwind(6)]
fn check_line_len_counts_the_lf() {
    let s = any_string(4, false);
    let max_len: usize = kani::any();
    assert_eq!(check_line_len(&s, max_len).is_ok(), s.len() + 1 <= max_len);
}

/// `IpPrefix::new` on IPv4: any address and any length. Lengths past 32
/// fail; otherwise the address keeps its first `len` bits and loses the
/// rest, the prefix contains the original address, normalising again
/// changes nothing, and `contains` is exactly "same first `len` bits".
#[kani::proof]
fn ip_prefix_v4() {
    let a: u32 = kani::any();
    let other: u32 = kani::any();
    let len: u8 = kani::any();
    let Ok(p) = IpPrefix::new(IpAddr::V4(Ipv4Addr::from(a)), len) else {
        assert!(len > 32);
        return;
    };
    assert!(len <= 32);
    assert_eq!(p.prefix_len(), len);
    let IpAddr::V4(m) = p.addr() else {
        panic!("family changed")
    };
    let m = u32::from(m);
    let host_bits = 32 - u32::from(len);
    let net = |x: u32| x.checked_shr(host_bits).unwrap_or(0);
    let host = |x: u32| x.checked_shl(32 - host_bits).unwrap_or(0);
    assert_eq!(net(m), net(a));
    assert_eq!(host(m), 0);
    assert!(p.contains(IpAddr::V4(Ipv4Addr::from(a))));
    assert_eq!(IpPrefix::new(p.addr(), len), Ok(p));
    assert_eq!(
        p.contains(IpAddr::V4(Ipv4Addr::from(other))),
        net(other) == net(a)
    );
}

/// The same for IPv6, with lengths up to 128.
#[kani::proof]
fn ip_prefix_v6() {
    let a: u128 = kani::any();
    let other: u128 = kani::any();
    let len: u8 = kani::any();
    let Ok(p) = IpPrefix::new(IpAddr::V6(Ipv6Addr::from(a)), len) else {
        assert!(len > 128);
        return;
    };
    assert!(len <= 128);
    assert_eq!(p.prefix_len(), len);
    let IpAddr::V6(m) = p.addr() else {
        panic!("family changed")
    };
    let m = u128::from(m);
    let host_bits = 128 - u32::from(len);
    let net = |x: u128| x.checked_shr(host_bits).unwrap_or(0);
    let host = |x: u128| x.checked_shl(128 - host_bits).unwrap_or(0);
    assert_eq!(net(m), net(a));
    assert_eq!(host(m), 0);
    assert!(p.contains(IpAddr::V6(Ipv6Addr::from(a))));
    assert_eq!(IpPrefix::new(p.addr(), len), Ok(p));
    // An IPv4-mapped `other` may also match through its IPv4 form, so
    // only check the plain IPv6 case.
    if Ipv6Addr::from(other).to_ipv4_mapped().is_none() {
        assert_eq!(
            p.contains(IpAddr::V6(Ipv6Addr::from(other))),
            net(other) == net(a)
        );
    }
}

/// For every IPv4 prefix and every IPv4 address, the address and its
/// IPv4-mapped IPv6 form (`::ffff:a.b.c.d`) are both inside or both
/// outside, as the doc of `contains` says, "so that a ban works the same
/// on a dual-stack socket". The same holds for a ban on one address of
/// either family.
#[kani::proof]
fn ip_prefix_mapped_addresses_match_ipv4() {
    let v4 = Ipv4Addr::from(kani::any::<u32>());
    let mapped = IpAddr::V6(v4.to_ipv6_mapped());
    let Ok(p) = IpPrefix::new(IpAddr::V4(Ipv4Addr::from(kani::any::<u32>())), kani::any()) else {
        return;
    };
    assert_eq!(p.contains(IpAddr::V4(v4)), p.contains(mapped));
    let ban = ServerBanTarget::Prefix(p);
    assert_eq!(
        ban.covers_address(IpAddr::V4(v4)),
        ban.covers_address(mapped)
    );
    let addr = if kani::any() {
        IpAddr::V4(Ipv4Addr::from(kani::any::<u32>()))
    } else {
        IpAddr::V6(Ipv6Addr::from(kani::any::<u128>()))
    };
    let ban = ServerBanTarget::Address(addr);
    assert_eq!(
        ban.covers_address(IpAddr::V4(v4)),
        ban.covers_address(mapped)
    );
}

/// The same for IPv6 prefixes: `::ffff:203.0.113.0/120` and `::/1` contain
/// both `::ffff:203.0.113.7` and `203.0.113.7`. Kani found that the plain
/// IPv4 form used to be missed; see
/// `names::tests::ip_prefix_mapped_prefix_matches_ipv4`.
#[kani::proof]
fn ip_prefix_v6_mapped_addresses_match_ipv4() {
    let v4 = Ipv4Addr::from(kani::any::<u32>());
    let mapped = IpAddr::V6(v4.to_ipv6_mapped());
    let Ok(p) = IpPrefix::new(IpAddr::V6(Ipv6Addr::from(kani::any::<u128>())), kani::any()) else {
        return;
    };
    assert_eq!(p.contains(IpAddr::V4(v4)), p.contains(mapped));
}

/// A retention period is at least 7 days (7.5, 10.6), and keeps the
/// number it was made from.
#[kani::proof]
fn retention_is_at_least_seven_days() {
    let days: u32 = kani::any();
    match Retention::new(days) {
        Some(r) => {
            assert!(days >= 7);
            assert_eq!(r.days(), days);
        }
        None => assert!(days < 7),
    }
}

//! The address guard (SPEC 4.4): a server MUST NOT connect to loopback,
//! private, link-local or other special-purpose addresses [RFC 6890]
//! unless its operator allows it.
//!
//! [`is_special`] refuses every block in IANA's IPv4 and IPv6
//! Special-Purpose Address Registries (RFC 6890 and the RFCs that add to
//! them), and multicast. Two IPv6 blocks carry an IPv4 address, and are
//! judged by that address instead:
//!
//! - `::ffff:0:0/96`, IPv4-mapped addresses, which some resolvers return;
//! - `64:ff9b::/96`, the well-known NAT64 prefix (RFC 6052), which DNS64
//!   returns on IPv6-only networks. Refusing it would cut such a server
//!   off from every IPv4-only web server.
//!
//! The registries mark a few small blocks inside special-purpose ranges
//! as globally reachable (for example `192.0.0.9/32`, a PCP anycast
//! address). They serve protocols other than HTTPS, so the guard refuses
//! them too.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether the guard refuses `ip` (4.4): it is in a special-purpose block
/// [RFC 6890], or is multicast. See the module documentation for the
/// list.
pub fn is_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_special_v4(v4),
        IpAddr::V6(v6) => is_special_v6(v6),
    }
}

/// IPv4 blocks in the IANA IPv4 Special-Purpose Address Registry, plus
/// multicast (224.0.0.0/4), as (address, prefix length).
const V4_BLOCKS: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),          // "this network" (RFC 791)
    ([10, 0, 0, 0], 8),         // private (RFC 1918)
    ([100, 64, 0, 0], 10),      // shared address space (RFC 6598)
    ([127, 0, 0, 0], 8),        // loopback (RFC 1122)
    ([169, 254, 0, 0], 16),     // link local (RFC 3927)
    ([172, 16, 0, 0], 12),      // private (RFC 1918)
    ([192, 0, 0, 0], 24),       // IETF protocol assignments (RFC 6890)
    ([192, 0, 2, 0], 24),       // documentation, TEST-NET-1 (RFC 5737)
    ([192, 31, 196, 0], 24),    // AS112-v4 (RFC 7535)
    ([192, 52, 193, 0], 24),    // AMT (RFC 7450)
    ([192, 88, 99, 0], 24),     // deprecated 6to4 relay anycast (RFC 7526)
    ([192, 168, 0, 0], 16),     // private (RFC 1918)
    ([192, 175, 48, 0], 24),    // direct delegation AS112 (RFC 7534)
    ([198, 18, 0, 0], 15),      // benchmarking (RFC 2544)
    ([198, 51, 100, 0], 24),    // documentation, TEST-NET-2 (RFC 5737)
    ([203, 0, 113, 0], 24),     // documentation, TEST-NET-3 (RFC 5737)
    ([224, 0, 0, 0], 4),        // multicast (RFC 5771)
    ([240, 0, 0, 0], 4),        // reserved (RFC 1112)
    ([255, 255, 255, 255], 32), // limited broadcast (RFC 919), inside 240/4
];

/// IPv6 blocks in the IANA IPv6 Special-Purpose Address Registry, plus
/// multicast (ff00::/8) and the deprecated site-local and IPv4-compatible
/// blocks. IPv4-mapped and NAT64 addresses are handled before these.
const V6_BLOCKS: &[([u16; 8], u8)] = &[
    ([0, 0, 0, 0, 0, 0, 0, 0], 96), // unspecified, loopback, IPv4-compatible (RFC 4291)
    ([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48), // local-use NAT64 (RFC 8215)
    ([0x100, 0, 0, 0, 0, 0, 0, 0], 64), // discard-only (RFC 6666)
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23), // IETF protocol assignments (RFC 2928), Teredo, ORCHID...
    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), // documentation (RFC 3849)
    ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16), // 6to4 (RFC 3056)
    ([0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0], 48), // direct delegation AS112 (RFC 7534)
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20), // documentation (RFC 9637)
    ([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16), // segment routing SIDs (RFC 9602)
    ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7), // unique local (RFC 4193)
    ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), // link local (RFC 4291)
    ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10), // deprecated site local (RFC 3879)
    ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8), // multicast (RFC 4291)
];

fn is_special_v4(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    V4_BLOCKS.iter().any(|&(net, len)| {
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        ip & mask == u32::from_be_bytes(net) & mask
    })
}

fn is_special_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // ::ffff:a.b.c.d (RFC 4291) and 64:ff9b::a.b.c.d (RFC 6052) carry an
    // IPv4 address; judge that.
    if segments[..6] == [0, 0, 0, 0, 0, 0xffff] || segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., a, b, c, d] = ip.octets();
        return is_special_v4(Ipv4Addr::new(a, b, c, d));
    }
    let ip = u128::from(ip);
    V6_BLOCKS.iter().any(|&(net, len)| {
        let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
        ip & mask == u128::from(Ipv6Addr::from(net)) & mask
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn special(s: &str) -> bool {
        is_special(s.parse().unwrap())
    }

    #[test]
    fn refused_v4() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.1.2.3",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(special(ip), "{ip} should be refused");
        }
    }

    #[test]
    fn allowed_v4() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            assert!(!special(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn refused_v6() {
        for ip in [
            "::",
            "::1",
            "::7f00:1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:db8::1",
            "2002:c000:0201::1",
            "2620:4f:8000::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(special(ip), "{ip} should be refused");
        }
    }

    #[test]
    fn allowed_v6() {
        for ip in [
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2a00:1450::1",
            "2001:200::1",
            "::ffff:1.1.1.1",
            "64:ff9b::1.1.1.1",
            "fbff::1",
        ] {
            assert!(!special(ip), "{ip} should be allowed");
        }
    }
}

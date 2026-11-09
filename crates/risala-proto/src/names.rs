//! Names (SPEC 3.5): uids, rooms, mailboxes (boxes), sequence numbers,
//! ids and blob-refs, plus the targets of BLOCK (5.7) and ADMIN BAN
//! (10.2).
//!
//! Every type here checks itself: a [`Room`] value is always a valid room.
//! Parsing (`FromStr`) folds ASCII upper case to lower case, as 3.5 makes
//! names case-insensitive, and `Display` writes the lower-case wire form.
//! Names are ASCII only: domains must be written as A-labels.
//!
//! The string types share their storage through an `Arc<str>`, so cloning
//! a [`Uid`] or a [`Room`] is cheap.
//!
//! A value that has only valid characters but is longer than the grammar
//! allows (a 33-character name, a 64-character domain label, a domain over
//! 253 characters) is reported as [`ParseError::TooLong`], so that a server
//! replies `ERR too-long`. Everything else that breaks the grammar is
//! [`ParseError::BadSyntax`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use crate::error::ParseError;

/// The longest `name`, in characters (3.5).
pub const MAX_NAME_LEN: usize = 32;
/// The longest `room`, in characters, including the `#` (3.5).
pub const MAX_ROOM_LEN: usize = 65;
/// The longest domain `label`, in characters (3.5).
pub const MAX_LABEL_LEN: usize = 63;
/// The longest `domain`, in characters (3.5, following RFC 1035).
pub const MAX_DOMAIN_LEN: usize = 253;
/// The longest `id`, in characters (3.5).
pub const MAX_ID_LEN: usize = 64;
/// The longest `uid`, in characters: an identity with the longest name and
/// the longest domain (3.5).
pub const MAX_UID_LEN: usize = MAX_NAME_LEN + 1 + MAX_DOMAIN_LEN;

// ---------------------------------------------------------------------------
// Grammar checks. They work on bytes that are already folded to lower case.
// Each returns `Ok(true)` if the value fits its length limits, `Ok(false)`
// if only the length is wrong, and `Err` for any other grammar error. This
// lets a caller report a syntax error in one part ahead of a length error
// in another.

type Shape = Result<bool, &'static str>;

/// `alnum = %x61-7A / DIGIT` (3.5).
fn is_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// The characters allowed after the first one in a `name` or `room`.
fn is_name_char(b: u8) -> bool {
    is_alnum(b) || matches!(b, b'.' | b'_' | b'-')
}

/// `alnum [ *N( alnum / "." / "_" / "-" ) ( alnum / "_" / "-" ) ]`, the
/// shape shared by `name` and the part of `room` after `#`. It never ends
/// with `.` (3.5).
fn name_shape(s: &[u8], max: usize) -> Shape {
    match s.first() {
        None => Err("empty name"),
        Some(&b) if !is_alnum(b) => Err("a name must start with a-z or 0-9"),
        _ if !s.iter().all(|&b| is_name_char(b)) => {
            Err("a name may contain only a-z, 0-9, '.', '_' and '-'")
        }
        _ if s.ends_with(b".") => Err("a name must not end with '.'"),
        _ => Ok(s.len() <= max),
    }
}

/// `label = alnum [ *61( alnum / "-" ) alnum ]`.
fn label_shape(s: &[u8]) -> Shape {
    match (s.first(), s.last()) {
        (Some(&first), Some(&last)) if is_alnum(first) && is_alnum(last) => {
            if s.iter().all(|&b| is_alnum(b) || b == b'-') {
                Ok(s.len() <= MAX_LABEL_LEN)
            } else {
                Err("a domain label may contain only a-z, 0-9 and '-'")
            }
        }
        (None, _) | (_, None) => Err("empty domain label"),
        _ => Err("a domain label must start and end with a-z or 0-9"),
    }
}

/// `domain = label 1*( "." label )`, at most 253 characters, and the last
/// label is not all digits, so an IP address is never a domain (3.5).
fn domain_shape(s: &[u8]) -> Shape {
    let mut labels = 0;
    let mut fits = s.len() <= MAX_DOMAIN_LEN;
    let mut last: &[u8] = &[];
    for label in s.split(|&b| b == b'.') {
        fits &= label_shape(label)?;
        labels += 1;
        last = label;
    }
    if labels < 2 {
        return Err("a domain needs at least two labels");
    }
    if last.iter().all(u8::is_ascii_digit) {
        return Err("a domain's last label must not be all digits");
    }
    Ok(fits)
}

/// `identity = name "@" domain`.
fn identity_shape(s: &[u8]) -> Shape {
    let at = s
        .iter()
        .position(|&b| b == b'@')
        .ok_or("an identity is name@domain")?;
    let name = name_shape(&s[..at], MAX_NAME_LEN)?;
    let domain = domain_shape(&s[at + 1..])?;
    Ok(name && domain)
}

/// `uid = guest / identity`.
fn uid_shape(s: &[u8]) -> Shape {
    match s.strip_prefix(b"~") {
        Some(name) => name_shape(name, MAX_NAME_LEN),
        None if s.contains(&b'@') => identity_shape(s),
        None => Err("a uid is ~name or name@domain"),
    }
}

/// `room = "#" alnum [ *62( alnum / "." / "_" / "-" ) ( alnum / "_" / "-" ) ]`.
fn room_shape(s: &[u8]) -> Shape {
    let rest = s.strip_prefix(b"#").ok_or("a room starts with '#'")?;
    name_shape(rest, MAX_ROOM_LEN - 1)
}

/// `id = 1*64( alnum / "-" / "_" )`.
fn id_shape(s: &[u8]) -> Shape {
    if s.is_empty() {
        Err("empty id")
    } else if s.iter().all(|&b| is_alnum(b) || b == b'-' || b == b'_') {
        Ok(s.len() <= MAX_ID_LEN)
    } else {
        Err("an id may contain only a-z, 0-9, '-' and '_'")
    }
}

fn finish(shape: Shape) -> Result<(), ParseError> {
    match shape {
        Ok(true) => Ok(()),
        Ok(false) => Err(ParseError::TooLong),
        Err(msg) => Err(ParseError::BadSyntax(msg)),
    }
}

/// Whether `lower`, already folded to lower case, is a valid uid. Used by the
/// mention scanner (5.5), which tries many prefixes and must not allocate.
pub(crate) fn is_valid_uid(lower: &[u8]) -> bool {
    matches!(uid_shape(lower), Ok(true))
}

/// Checks that a name is ASCII and folds it to lower case (3.5).
fn fold(s: &str) -> Result<String, ParseError> {
    if s.is_ascii() {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(ParseError::BadSyntax("names must be ASCII"))
    }
}

/// Parses `s` into the `Arc<str>` of a string newtype: folds, then checks.
fn parse_folded(s: &str, shape: fn(&[u8]) -> Shape) -> Result<Arc<str>, ParseError> {
    let lower = fold(s)?;
    finish(shape(lower.as_bytes()))?;
    Ok(Arc::from(lower))
}

/// Defines a newtype over a checked, lower-case `Arc<str>`.
macro_rules! name_type {
    ($(#[$meta:meta])* $ty:ident, $shape:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty(Arc<str>);

        impl $ty {
            /// The wire form, in lower case (3.5).
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_folded(s, $shape).map($ty)
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

name_type!(
    /// A `name` (3.5): 1 to 32 characters of `a-z 0-9 . _ -`, starting with
    /// a letter or digit. Guest names (4.2) and the local part of identities
    /// (4.3, 4.6) are names.
    Name,
    |s| name_shape(s, MAX_NAME_LEN)
);

name_type!(
    /// A `domain` (3.5): at least two labels separated by `.`, each 1 to 63
    /// characters of `a-z 0-9 -` that neither starts nor ends with `-`, and
    /// 253 characters at most. Internationalised domains must be written as
    /// A-labels (`xn--...`); the crate does not check the Punycode inside.
    Domain,
    domain_shape
);

name_type!(
    /// A `uid` (3.5): a guest such as `~sam` (4.2) or an identity such as
    /// `alice@example.org` (4.3).
    ///
    /// Uids cannot contain commas or spaces, which PRESENCE relies on (8.3).
    Uid,
    uid_shape
);

name_type!(
    /// An `identity` (3.5, 4.3): a uid of the form `name@domain`, never a
    /// guest. Convert with [`Uid::from`] and [`Identity::try_from`].
    Identity,
    identity_shape
);

name_type!(
    /// A `room` (3.5), such as `#general`: `#` followed by 1 to 64
    /// characters of `a-z 0-9 . _ -`, starting with a letter or digit.
    Room,
    room_shape
);

name_type!(
    /// An `id` (3.5): 1 to 64 characters of `a-z 0-9 - _`. Reports (5.8),
    /// Welcomes (12.8) and guest tokens (4.2) are ids.
    Id,
    id_shape
);

impl Domain {
    /// Whether `domain` is this domain or one of its subdomains, as a domain
    /// block (5.7) or a domain ban (10.2) covers it. `example.net` covers
    /// `example.net` and `mail.example.net`, but not `badexample.net`.
    ///
    /// The comparison ignores ASCII case, so `domain` need not be folded.
    pub fn covers(&self, domain: &str) -> bool {
        let (outer, inner) = (domain.as_bytes(), self.0.as_bytes());
        if outer.len() == inner.len() {
            return outer.eq_ignore_ascii_case(inner);
        }
        outer.len() > inner.len()
            && outer[outer.len() - inner.len() - 1] == b'.'
            && outer[outer.len() - inner.len()..].eq_ignore_ascii_case(inner)
    }
}

impl Uid {
    /// The guest uid `~<name>` (4.2).
    pub fn guest(name: &Name) -> Uid {
        Uid(Arc::from(format!("~{name}")))
    }

    /// Whether this is a guest (`~name`, 4.2).
    pub fn is_guest(&self) -> bool {
        self.0.starts_with('~')
    }

    /// Whether this is an identity (`name@domain`, 4.3).
    pub fn is_identity(&self) -> bool {
        !self.is_guest()
    }

    /// The name: `sam` for `~sam`, `alice` for `alice@example.org` (3.5).
    pub fn name(&self) -> &str {
        match self.0.strip_prefix('~') {
            Some(name) => name,
            None => self.0.split_once('@').map_or(&self.0, |(name, _)| name),
        }
    }

    /// The domain of an identity, or `None` for a guest (3.5).
    pub fn domain(&self) -> Option<&str> {
        if self.is_guest() {
            None
        } else {
            self.0.split_once('@').map(|(_, domain)| domain)
        }
    }

    /// This uid as an [`Identity`], or `None` for a guest (4.3). Cheap: the
    /// two share their storage.
    pub fn to_identity(&self) -> Option<Identity> {
        self.is_identity().then(|| Identity(self.0.clone()))
    }
}

impl Identity {
    /// The identity `<name>@<domain>` (4.3).
    pub fn new(name: &Name, domain: &Domain) -> Identity {
        Identity(Arc::from(format!("{name}@{domain}")))
    }

    /// The name before the `@` (3.5).
    pub fn name(&self) -> &str {
        self.0.split_once('@').map_or(&self.0, |(name, _)| name)
    }

    /// The domain after the `@` (3.5).
    pub fn domain(&self) -> &str {
        self.0.split_once('@').map_or("", |(_, domain)| domain)
    }

    /// This identity as a [`Uid`] (3.5). Cheap: the two share their storage.
    pub fn to_uid(&self) -> Uid {
        Uid(self.0.clone())
    }
}

impl From<Identity> for Uid {
    fn from(identity: Identity) -> Uid {
        Uid(identity.0)
    }
}

impl TryFrom<Uid> for Identity {
    type Error = ParseError;

    fn try_from(uid: Uid) -> Result<Identity, ParseError> {
        if uid.is_identity() {
            Ok(Identity(uid.0))
        } else {
            Err(ParseError::BadSyntax("a guest is not an identity"))
        }
    }
}

impl PartialEq<Identity> for Uid {
    fn eq(&self, other: &Identity) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<Uid> for Identity {
    fn eq(&self, other: &Uid) -> bool {
        self.0 == other.0
    }
}

impl Room {
    /// The room without its `#`, as written in `risala://` URIs (15):
    /// `general` for `#general`.
    pub fn bare(&self) -> &str {
        &self.0[1..]
    }

    /// Parses a room written without its `#`, as in a `risala://` URI (15).
    pub fn from_bare(bare: &str) -> Result<Room, ParseError> {
        format!("#{bare}").parse()
    }
}

// ---------------------------------------------------------------------------

/// The lower-case base32 alphabet of RFC 4648 (3.5).
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The value of a base32 character, already folded to lower case.
fn base32_value(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// `N` bytes in lower-case base32, without padding: 26 characters for 16
/// bytes, 52 for 32.
fn base32_encode<const N: usize>(bytes: &[u8; N]) -> String {
    let mut out = String::with_capacity((8 * N).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[(acc >> bits) as usize & 31]));
        }
    }
    // Bits left over are padded with zero bits to a last character: 3 of
    // 128, 1 of 256.
    if bits > 0 {
        out.push(char::from(BASE32[(acc << (5 - bits)) as usize & 31]));
    }
    out
}

/// Reads `N` bytes from base32, folding ASCII upper case (3.5): 26
/// characters for 16 bytes, 52 for 32. The bits after the last byte must
/// be zero, so that every value has one spelling. Any other length,
/// character or trailing bits are `BadSyntax` (3.7).
fn base32_decode<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N], ParseError> {
    let b = s.as_bytes();
    if b.len() != (8 * N).div_ceil(5) {
        return Err(ParseError::BadSyntax(what));
    }
    let mut out = [0u8; N];
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut i = 0;
    for &c in b {
        let v = base32_value(c.to_ascii_lowercase()).ok_or(ParseError::BadSyntax(what))?;
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[i] = (acc >> bits) as u8;
            i += 1;
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return Err(ParseError::BadSyntax(what));
    }
    Ok(out)
}

/// The length of a `box` in characters: 16 bytes in base32 (3.5).
pub const BOX_LEN: usize = 26;

/// Defines a newtype over 16 bytes written as a `box` (3.5).
macro_rules! box_type {
    ($(#[$meta:meta])* $ty:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty([u8; 16]);

        impl $ty {
            /// Makes the value from its 16 bytes.
            pub const fn from_bytes(bytes: [u8; 16]) -> $ty {
                $ty(bytes)
            }

            /// The 16 bytes.
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            /// The 26 characters of lower-case base32 (3.5).
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&base32_encode(&self.0))
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($ty))
            }
        }

        impl FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<$ty, ParseError> {
                base32_decode(s, $what).map($ty)
            }
        }
    };
}

box_type!(
    /// A `box` (3.5, 5.2): the name of a mailbox, 16 random bytes written
    /// as 26 characters of lower-case base32 (RFC 4648) without padding,
    /// such as `ujzdegxdncf32epf3dhodzdoci`.
    ///
    /// Parsing folds ASCII upper case, as for every name (3.5). A value of
    /// the wrong length, a character outside `a-z 2-7`, or non-zero bits
    /// after the 16th byte are `BadSyntax` (3.7), so each mailbox has
    /// exactly one spelling.
    BoxName,
    "a box is 26 characters of base32"
);

box_type!(
    /// The `<id>` of PAIR PUT, PAIR GET and the PAIR line (4.8): 16 bytes
    /// derived from a pairing secret, written as a box (3.5).
    PairId,
    "a pairing id is 26 characters of base32"
);

/// The length of a SHA-384 hash, the hash a [`BlobRef`] names (12.12).
pub const BLOB_HASH_LEN: usize = 48;

/// A `blob-ref` (3.5, 12.12): `sha384:` followed by 96 lower-case hex
/// digits, the SHA-384 hash of a blob's bytes. RECORD lines name records
/// the same way (4.7).
///
/// Parsing folds ASCII upper case, as for every name (3.5). Any number of
/// digits other than 96, or a character that is not a hex digit, is
/// `BadSyntax` (3.7).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobRef([u8; BLOB_HASH_LEN]);

impl BlobRef {
    /// The prefix of every blob-ref (3.5).
    pub const PREFIX: &'static str = "sha384:";

    /// The blob-ref of `bytes`: their SHA-384 hash (12.12).
    pub fn of(bytes: &[u8]) -> BlobRef {
        use sha2::{Digest as _, Sha384};
        BlobRef(Sha384::digest(bytes).into())
    }

    /// Makes the value from the hash.
    pub const fn from_hash(hash: [u8; BLOB_HASH_LEN]) -> BlobRef {
        BlobRef(hash)
    }

    /// The hash.
    pub const fn hash(&self) -> &[u8; BLOB_HASH_LEN] {
        &self.0
    }

    /// The 96 hex digits without the prefix, as they follow the `blobs`
    /// URL prefix of INFO in a blob's URL (8.5, 12.12).
    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(2 * BLOB_HASH_LEN);
        for b in self.0 {
            out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            out.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
        }
        out
    }
}

impl fmt::Display for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", BlobRef::PREFIX, self.hex())
    }
}

impl fmt::Debug for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobRef({self})")
    }
}

impl FromStr for BlobRef {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<BlobRef, ParseError> {
        const WHAT: ParseError = ParseError::BadSyntax("a blob-ref is sha384: and 96 hex digits");
        let prefix = s.get(..BlobRef::PREFIX.len()).ok_or(WHAT)?;
        if !prefix.eq_ignore_ascii_case(BlobRef::PREFIX) {
            return Err(WHAT);
        }
        let hex = &s.as_bytes()[BlobRef::PREFIX.len()..];
        if hex.len() != 2 * BLOB_HASH_LEN {
            return Err(WHAT);
        }
        let digit = |c: u8| (c as char).to_digit(16).ok_or(WHAT);
        let mut out = [0u8; BLOB_HASH_LEN];
        let (pairs, _) = hex.as_chunks::<2>();
        for (byte, [hi, lo]) in out.iter_mut().zip(pairs) {
            *byte = (digit(*hi)? << 4 | digit(*lo)?) as u8;
        }
        Ok(BlobRef(out))
    }
}

// ---------------------------------------------------------------------------

/// The port a server listens on when none is written (2.1).
pub const DEFAULT_PORT: u16 = 7472;

/// `host = label *( "." label )` (3.5): like a domain, but a single label
/// such as `localhost` is allowed. At most 253 characters, and the last
/// label is not all digits, so an IP address is never a host.
fn host_shape(s: &[u8]) -> Shape {
    let mut fits = s.len() <= MAX_DOMAIN_LEN;
    let mut last: &[u8] = &[];
    for label in s.split(|&b| b == b'.') {
        fits &= label_shape(label)?;
        last = label;
    }
    if last.iter().all(u8::is_ascii_digit) {
        return Err("a host's last label must not be all digits");
    }
    Ok(fits)
}

/// A `server` (2.1, 3.5): a server address in its one written form,
/// `host [":" port]`. The host is in lower case, without a trailing `.`,
/// and never an IP address; the port is written only when it is not
/// [`DEFAULT_PORT`], without leading zeros.
///
/// 2.1 says receivers compare server addresses byte for byte and treat
/// one not in this form as malformed, so parsing does not fold case:
/// `Chat.example.org`, `chat.example.org:7472` and `chat.example.org:07000`
/// are all `BadSyntax`. Links (15) fold case before they read a server;
/// [`Link`] does that itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServerAddr {
    host: Arc<str>,
    port: u16,
}

impl ServerAddr {
    /// A server address from a host and a port, in the one written form.
    /// The host is folded to lower case and may end with one `.`, which is
    /// dropped (2.1). `BadSyntax` for an IP address, an invalid host or
    /// port 0.
    pub fn new(host: &str, port: u16) -> Result<ServerAddr, ParseError> {
        let host = host.strip_suffix('.').unwrap_or(host);
        let host = fold(host)?;
        finish(host_shape(host.as_bytes()))?;
        if port == 0 {
            return Err(ParseError::BadSyntax("a port is 1 to 65535"));
        }
        Ok(ServerAddr {
            host: Arc::from(host),
            port,
        })
    }

    /// The host, in lower case.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, [`DEFAULT_PORT`] when none is written.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl From<Domain> for ServerAddr {
    /// A domain on the default port.
    fn from(domain: Domain) -> ServerAddr {
        ServerAddr {
            host: domain.0,
            port: DEFAULT_PORT,
        }
    }
}

impl fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host)?;
        if self.port != DEFAULT_PORT {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

impl FromStr for ServerAddr {
    type Err = ParseError;

    /// `server = host [ ":" port ]`, `port = %x31-39 *4DIGIT`, 1 to 65535
    /// and never 7472 (3.5). Upper case is `BadSyntax` (2.1).
    fn from_str(s: &str) -> Result<ServerAddr, ParseError> {
        const PORT: ParseError = ParseError::BadSyntax(
            "a server's port is 1 to 65535, never 7472, without leading zeros",
        );
        let (host, port) = match s.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (s, None),
        };
        if !host.is_ascii() {
            return Err(ParseError::BadSyntax("names must be ASCII"));
        }
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(ParseError::BadSyntax("a server is written in lower case"));
        }
        finish(host_shape(host.as_bytes()))?;
        let port = match port {
            None => DEFAULT_PORT,
            Some(p) => {
                let b = p.as_bytes();
                if b.is_empty() || b.len() > 5 || b[0] == b'0' || !b.iter().all(u8::is_ascii_digit)
                {
                    return Err(PORT);
                }
                match p.parse::<u16>() {
                    Ok(n) if n != DEFAULT_PORT => n,
                    _ => return Err(PORT),
                }
            }
        };
        Ok(ServerAddr {
            host: Arc::from(host),
            port,
        })
    }
}

// ---------------------------------------------------------------------------

/// A `risala://` link (15): `risala://<server>[/<room>[?g=<group-id>]]`.
///
/// `<server>` is a server address in its one written form (2.1, 3.5),
/// `<room>` a public room without its `#`, and `<group-id>` the room's
/// 32-byte group id in lower-case base32 without padding, 52 characters.
/// A device that follows a link with a group id joins only the group with
/// that id (6.1).
///
/// Parsing folds ASCII upper case to lower case first, then reads the
/// link by 15's grammar. Anything else, such as a `/` at the end, a query
/// other than one `g`, a fragment, user information, an IP address,
/// `:7472` or an empty part, is `BadSyntax`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    /// The server.
    pub server: ServerAddr,
    /// The public room the link points to.
    pub room: Option<Room>,
    /// The room's group id, which only a link with a room may carry.
    pub group_id: Option<crate::mls::GroupId>,
}

impl Link {
    /// The scheme, with its `://`.
    pub const SCHEME: &'static str = "risala://";

    /// The length of a group id in a link: 32 bytes in base32 (15).
    pub const GROUP_ID_LEN: usize = 52;
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", Link::SCHEME, self.server)?;
        if let Some(room) = &self.room {
            write!(f, "/{}", room.bare())?;
            if let Some(group_id) = &self.group_id {
                write!(f, "?g={}", base32_encode(group_id.as_bytes()))?;
            }
        }
        Ok(())
    }
}

impl FromStr for Link {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Link, ParseError> {
        const WHAT: ParseError =
            ParseError::BadSyntax("a link is risala://<server>[/<room>[?g=<group-id>]]");
        let s = fold(s)?;
        let rest = s.strip_prefix(Link::SCHEME).ok_or(WHAT)?;
        let (server, path) = match rest.split_once('/') {
            Some((server, path)) => (server, Some(path)),
            None => (rest, None),
        };
        let server: ServerAddr = server.parse().map_err(|_| WHAT)?;
        let (room, group_id) = match path {
            None => (None, None),
            Some(path) => {
                let (room, query) = match path.split_once('?') {
                    Some((room, query)) => (room, Some(query)),
                    None => (path, None),
                };
                let room = Room::from_bare(room).map_err(|_| WHAT)?;
                let group_id = match query {
                    None => None,
                    Some(query) => {
                        let g = query.strip_prefix("g=").ok_or(WHAT)?;
                        let bytes =
                            base32_decode(g, "a link's group id is 52 characters of base32")?;
                        Some(crate::mls::GroupId::from_bytes(bytes))
                    }
                };
                (Some(room), group_id)
            }
        };
        Ok(Link {
            server,
            room,
            group_id,
        })
    }
}

// ---------------------------------------------------------------------------

/// A sequence number (3.5, 5.2): 1 to 2^63-1, written in decimal with no
/// leading zeros.
///
/// Some places in the protocol write `0` for "none", such as FETCH's
/// `after=0` and FOLLOW's `head=0` (7.1), and GROUPINFO's `<seq>` in
/// epoch 0 (6.1). [`Seq::parse_or_zero`] reads those.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Seq(u64);

impl Seq {
    /// The first post of every mailbox (5.2).
    pub const FIRST: Seq = Seq(1);
    /// The largest sequence number, 2^63-1 (3.5).
    pub const MAX: Seq = Seq(i64::MAX as u64);

    /// A sequence number, or `None` if `n` is 0 or above 2^63-1 (3.5).
    pub const fn new(n: u64) -> Option<Seq> {
        if n >= 1 && n <= Seq::MAX.0 {
            Some(Seq(n))
        } else {
            None
        }
    }

    /// The number (3.5).
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next sequence number, or `None` after [`Seq::MAX`] (5.2).
    pub const fn next(self) -> Option<Seq> {
        Seq::new(self.0 + 1)
    }

    /// Parses a sequence number, or `0` meaning none, as in FETCH's
    /// `after=` (7.1).
    pub fn parse_or_zero(s: &str) -> Result<Option<Seq>, ParseError> {
        if s == "0" {
            Ok(None)
        } else {
            s.parse().map(Some)
        }
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Seq {
    type Err = ParseError;

    /// `seq = %x31-39 *18DIGIT`, at most 2^63-1.
    fn from_str(s: &str) -> Result<Seq, ParseError> {
        let b = s.as_bytes();
        if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
            return Err(ParseError::BadSyntax("a seq is a decimal number"));
        }
        if b[0] == b'0' {
            return Err(ParseError::BadSyntax("a seq starts with 1-9"));
        }
        if b.len() > 19 {
            return Err(ParseError::BadSyntax("seq is out of range"));
        }
        // 19 digits always fit in a u64.
        let n: u64 = s
            .parse()
            .map_err(|_| ParseError::BadSyntax("a seq is a decimal number"))?;
        Seq::new(n).ok_or(ParseError::BadSyntax("seq is out of range"))
    }
}

impl TryFrom<u64> for Seq {
    type Error = ParseError;

    fn try_from(n: u64) -> Result<Seq, ParseError> {
        Seq::new(n).ok_or(ParseError::BadSyntax("seq is out of range"))
    }
}

impl From<Seq> for u64 {
    fn from(seq: Seq) -> u64 {
        seq.0
    }
}

// ---------------------------------------------------------------------------

/// The target of BLOCK and UNBLOCK (5.7): an identity, or a whole domain
/// written `*@domain`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockTarget {
    /// One identity, such as `spam@example.net`.
    Identity(Identity),
    /// Every identity at a domain or its subdomains, written `*@example.net`.
    Domain(Domain),
}

impl BlockTarget {
    /// Whether this block covers `uid` (5.7). A domain block covers the
    /// domain's subdomains. Guests are never covered, since blocks apply to
    /// direct conversations, which guests cannot take part in.
    pub fn covers(&self, uid: &Uid) -> bool {
        match self {
            BlockTarget::Identity(identity) => uid == identity,
            BlockTarget::Domain(domain) => uid.domain().is_some_and(|d| domain.covers(d)),
        }
    }
}

impl fmt::Display for BlockTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockTarget::Identity(identity) => f.write_str(identity.as_str()),
            BlockTarget::Domain(domain) => write!(f, "*@{domain}"),
        }
    }
}

impl FromStr for BlockTarget {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<BlockTarget, ParseError> {
        match s.strip_prefix("*@") {
            Some(domain) => domain.parse().map(BlockTarget::Domain),
            None if s.starts_with('~') => Err(ParseError::BadSyntax("guests cannot be blocked")),
            None => s.parse().map(BlockTarget::Identity),
        }
    }
}

impl From<Identity> for BlockTarget {
    fn from(identity: Identity) -> BlockTarget {
        BlockTarget::Identity(identity)
    }
}

// ---------------------------------------------------------------------------

/// A network prefix in CIDR notation, such as `2001:db8::/32` (10.2).
///
/// The address is normalised: bits past the prefix length are cleared, so
/// `10.1.2.3/8` parses as `10.0.0.0/8`. The prefix length is at most 32 for
/// IPv4 and 128 for IPv6, and is written in decimal with no leading zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpPrefix {
    addr: IpAddr,
    len: u8,
}

impl IpPrefix {
    /// A prefix of `len` bits starting at `addr`, with the address
    /// normalised (10.2). Fails if `len` is longer than the address.
    pub fn new(addr: IpAddr, len: u8) -> Result<IpPrefix, ParseError> {
        let addr = match addr {
            IpAddr::V4(v4) if len <= 32 => {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) if len <= 128 => {
                let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
            _ => return Err(ParseError::BadSyntax("prefix length is too long")),
        };
        Ok(IpPrefix { addr, len })
    }

    /// The first address of the prefix (10.2).
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits (10.2).
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    /// Whether `ip` is inside this prefix. An IPv4 address and its
    /// IPv4-mapped IPv6 form, such as `203.0.113.7` and
    /// `::ffff:203.0.113.7`, count as the same address, in both directions,
    /// so a ban works the same whether or not the guest came in on a
    /// dual-stack socket.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let inside = |ip: IpAddr| IpPrefix::new(ip, self.len).is_ok_and(|p| p.addr == self.addr);
        let mapped = match ip.to_canonical() {
            IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
            v6 => v6,
        };
        inside(ip) || inside(ip.to_canonical()) || inside(mapped)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl FromStr for IpPrefix {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<IpPrefix, ParseError> {
        let (addr, len) = s
            .split_once('/')
            .ok_or(ParseError::BadSyntax("a prefix is address/length"))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| ParseError::BadSyntax("bad IP address"))?;
        let lb = len.as_bytes();
        if lb.is_empty()
            || lb.len() > 3
            || !lb.iter().all(u8::is_ascii_digit)
            || (lb.len() > 1 && lb[0] == b'0')
        {
            return Err(ParseError::BadSyntax("bad prefix length"));
        }
        let len: u8 = len
            .parse()
            .map_err(|_| ParseError::BadSyntax("prefix length is too long"))?;
        IpPrefix::new(addr, len)
    }
}

/// The target of ADMIN BAN and ADMIN UNBAN, and of SERVERBAN lines (10.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServerBanTarget {
    /// One identity, such as `spam@example.net`. It cannot sign in.
    Identity(Identity),
    /// Every identity at a domain or its subdomains, written `*@example.net`.
    Domain(Domain),
    /// A connected guest, written `~sam`. The server bans the address the
    /// guest is connected from, and lists the ban under that address.
    Guest(Name),
    /// One network address, such as `203.0.113.7`. No guest can connect
    /// from it.
    Address(IpAddr),
    /// A network prefix, such as `2001:db8::/32`. No guest can connect from
    /// it.
    Prefix(IpPrefix),
}

impl ServerBanTarget {
    /// Whether this ban stops `uid` from signing in (10.2). Only identity
    /// and domain bans name uids; a guest ban works through the guest's
    /// address, which the server resolves when the ban is made.
    pub fn covers_uid(&self, uid: &Uid) -> bool {
        match self {
            ServerBanTarget::Identity(identity) => uid == identity,
            ServerBanTarget::Domain(domain) => uid.domain().is_some_and(|d| domain.covers(d)),
            _ => false,
        }
    }

    /// Whether this ban stops a guest connecting from `ip` (10.2). IPv4-mapped
    /// IPv6 addresses count as the IPv4 address they map.
    pub fn covers_address(&self, ip: IpAddr) -> bool {
        match self {
            ServerBanTarget::Address(addr) => addr.to_canonical() == ip.to_canonical(),
            ServerBanTarget::Prefix(prefix) => prefix.contains(ip),
            _ => false,
        }
    }
}

impl fmt::Display for ServerBanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerBanTarget::Identity(identity) => f.write_str(identity.as_str()),
            ServerBanTarget::Domain(domain) => write!(f, "*@{domain}"),
            ServerBanTarget::Guest(name) => write!(f, "~{name}"),
            ServerBanTarget::Address(addr) => write!(f, "{addr}"),
            ServerBanTarget::Prefix(prefix) => write!(f, "{prefix}"),
        }
    }
}

impl FromStr for ServerBanTarget {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<ServerBanTarget, ParseError> {
        if let Some(domain) = s.strip_prefix("*@") {
            domain.parse().map(ServerBanTarget::Domain)
        } else if let Some(name) = s.strip_prefix('~') {
            name.parse().map(ServerBanTarget::Guest)
        } else if s.contains('@') {
            s.parse().map(ServerBanTarget::Identity)
        } else if s.contains('/') {
            s.parse().map(ServerBanTarget::Prefix)
        } else {
            s.parse()
                .map(ServerBanTarget::Address)
                .map_err(|_| ParseError::BadSyntax("bad ban target"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T: FromStr<Err = ParseError> + fmt::Display>(s: &str) -> String {
        match s.parse::<T>() {
            Ok(v) => v.to_string(),
            Err(e) => panic!("{s:?} should parse: {e}"),
        }
    }

    fn err<T: FromStr<Err = ParseError> + fmt::Debug>(s: &str) -> ParseError {
        match s.parse::<T>() {
            Ok(v) => panic!("{s:?} should not parse, got {v:?}"),
            Err(e) => e,
        }
    }

    fn syntax<T: FromStr<Err = ParseError> + fmt::Debug>(s: &str) {
        assert!(
            matches!(err::<T>(s), ParseError::BadSyntax(_)),
            "{s:?} should be BadSyntax"
        );
    }

    fn too_long<T: FromStr<Err = ParseError> + fmt::Debug>(s: &str) {
        assert_eq!(err::<T>(s), ParseError::TooLong, "{s:?}");
    }

    #[test]
    fn name_grammar() {
        for s in ["a", "0", "sam", "a.b_c-d", "a-", "a_", "9lives", "a__"] {
            assert_eq!(ok::<Name>(s), s);
        }
        assert_eq!(ok::<Name>(&"a".repeat(32)), "a".repeat(32));
        too_long::<Name>(&"a".repeat(33));
        for s in [
            "", "-a", ".a", "_a", "a b", "a@b", "a~", "a#", "é", "a/b", "a+", "a.", "a..",
        ] {
            syntax::<Name>(s);
        }
        // A bad character wins over the length.
        syntax::<Name>(&format!("-{}", "a".repeat(40)));
    }

    #[test]
    fn names_fold_case() {
        assert_eq!(ok::<Name>("Sam"), "sam");
        assert_eq!(ok::<Uid>("Alice@Example.ORG"), "alice@example.org");
        assert_eq!(ok::<Uid>("~SAM"), "~sam");
        assert_eq!(ok::<Room>("#General"), "#general");
        assert_eq!(ok::<Id>("K3F9Q2"), "k3f9q2");
        assert_eq!(ok::<Domain>("EXAMPLE.Org"), "example.org");
        assert_eq!(
            "Alice@Example.org".parse::<Uid>(),
            "alice@example.org".parse::<Uid>()
        );
        // Non-ASCII letters that fold to ASCII elsewhere are still rejected.
        syntax::<Name>("\u{212a}elvin"); // KELVIN SIGN
    }

    #[test]
    fn domain_grammar() {
        for s in [
            "example.org",
            "a.b",
            "chat.example.org",
            "xn--mgbh0fb.example",
            "a-b.c-d",
            "1.2a",
            "1.2.3.example",
            "a--b.org",
        ] {
            assert_eq!(ok::<Domain>(s), s);
        }
        let label63 = "a".repeat(63);
        assert_eq!(
            ok::<Domain>(&format!("{label63}.org")),
            format!("{label63}.org")
        );
        too_long::<Domain>(&format!("{}.org", "a".repeat(64)));
        for s in [
            "",
            "org",
            "example.",
            ".example.org",
            "example..org",
            "-a.org",
            "a-.org",
            "a.-org",
            "a.org-",
            "a_b.org",
            "a b.org",
            "exämple.org",
            "a.org.",
            "1.2",
            "1.2.3.4",
            "example.123",
        ] {
            syntax::<Domain>(s);
        }
        // 253 characters is the limit.
        let d253 = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61));
        assert_eq!(d253.len(), 253);
        assert_eq!(ok::<Domain>(&d253), d253);
        too_long::<Domain>(&format!("a{d253}"));
    }

    #[test]
    fn domain_covers() {
        let d: Domain = "example.net".parse().unwrap();
        assert!(d.covers("example.net"));
        assert!(d.covers("mail.example.net"));
        assert!(d.covers("a.b.example.net"));
        assert!(d.covers("Mail.Example.NET"));
        assert!(!d.covers("badexample.net"));
        assert!(!d.covers("example.network"));
        assert!(!d.covers("net"));
        assert!(!d.covers("éexample.net"));
        assert!(!d.covers(""));
    }

    #[test]
    fn uid_grammar() {
        for s in [
            "~sam",
            "alice@example.org",
            "a@b.c",
            "~a_",
            "bob.smith@mail.example.net",
        ] {
            assert_eq!(ok::<Uid>(s), s);
        }
        for s in [
            "",
            "~",
            "sam",
            "@example.org",
            "alice@",
            "alice@org",
            "~sam@example.org",
            "alice@@example.org",
            "alice@example.org@x.y",
            "a,b@example.org",
            "~-sam",
            "alice @example.org",
            "~sam,~bob",
            "~sam.",
            "alice.@example.org",
            "alice@203.0.113.7",
        ] {
            syntax::<Uid>(s);
        }
        let name32 = "a".repeat(32);
        assert_eq!(ok::<Uid>(&format!("~{name32}")), format!("~{name32}"));
        too_long::<Uid>(&format!("~{name32}a"));
        too_long::<Uid>(&format!("{name32}a@example.org"));
        // A syntax error in the domain wins over a long name.
        syntax::<Uid>(&format!("{name32}a@example"));
    }

    #[test]
    fn uid_parts() {
        let guest: Uid = "~Sam".parse().unwrap();
        assert!(guest.is_guest());
        assert!(!guest.is_identity());
        assert_eq!(guest.name(), "sam");
        assert_eq!(guest.domain(), None);
        assert_eq!(guest.to_identity(), None);
        assert!(Identity::try_from(guest.clone()).is_err());
        assert_eq!(Uid::guest(&"sam".parse().unwrap()), guest);

        let alice: Uid = "alice@example.org".parse().unwrap();
        assert!(alice.is_identity());
        assert_eq!(alice.name(), "alice");
        assert_eq!(alice.domain(), Some("example.org"));
        let identity = alice.to_identity().unwrap();
        assert_eq!(identity.name(), "alice");
        assert_eq!(identity.domain(), "example.org");
        assert_eq!(identity, alice);
        assert_eq!(Uid::from(identity.clone()), alice);
        assert_eq!(identity.to_uid(), alice);
        assert_eq!(
            Identity::new(&"alice".parse().unwrap(), &"example.org".parse().unwrap()),
            identity
        );
    }

    #[test]
    fn identity_grammar() {
        assert_eq!(ok::<Identity>("Bob@Example.net"), "bob@example.net");
        syntax::<Identity>("~sam");
        syntax::<Identity>("bob");
    }

    #[test]
    fn room_grammar() {
        for s in ["#general", "#a", "#0", "#a.b_c-d", "#rust-lang"] {
            assert_eq!(ok::<Room>(s), s);
        }
        let r64 = format!("#{}", "a".repeat(64));
        assert_eq!(ok::<Room>(&r64), r64);
        too_long::<Room>(&format!("#{}", "a".repeat(65)));
        for s in [
            "",
            "#",
            "general",
            "##a",
            "#-a",
            "#.a",
            "#a b",
            "#a#",
            "#é",
            "~sam",
            "#general.",
        ] {
            syntax::<Room>(s);
        }
        let room: Room = "#General".parse().unwrap();
        assert_eq!(room.bare(), "general");
        assert_eq!(Room::from_bare("general").unwrap(), room);
        assert!(Room::from_bare("#general").is_err());
    }

    #[test]
    fn id_grammar() {
        for s in ["k3f9q2", "-", "_", "a-b_c", "p4x8n2"] {
            assert_eq!(ok::<Id>(s), s);
        }
        let id64 = "a".repeat(64);
        assert_eq!(ok::<Id>(&id64), id64);
        too_long::<Id>(&"a".repeat(65));
        for s in ["", "a.b", "a b", "a=b", "é"] {
            syntax::<Id>(s);
        }
    }

    #[test]
    fn box_grammar() {
        // The spec's example box (1.3, 3.6).
        let b: BoxName = "ujzdegxdncf32epf3dhodzdoci".parse().unwrap();
        assert_eq!(b.to_string(), "ujzdegxdncf32epf3dhodzdoci");
        assert_eq!(ok::<BoxName>("UJZDEGXDNCF32EPF3DHODZDOCI"), b.to_string());
        assert_eq!(BoxName::from_bytes(*b.as_bytes()), b);
        assert_eq!(
            BoxName::from_bytes([0; 16]).to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            BoxName::from_bytes([0xff; 16]).to_string(),
            format!("{}4", "7".repeat(25))
        );
        // RFC 4648's test vector, the first 5 bytes "foobar" give
        // "mzxw6ytb".
        let mut bytes = [0u8; 16];
        bytes[..6].copy_from_slice(b"foobar");
        assert!(
            BoxName::from_bytes(bytes)
                .to_string()
                .starts_with("mzxw6ytboi")
        );
        for len in [0, 25, 27, 32] {
            syntax::<BoxName>(&"a".repeat(len));
        }
        // Characters outside a-z 2-7, padding, and trailing bits that are
        // not zero (the last character carries 3 bits and 2 zero bits).
        for s in [
            "ujzdegxdncf32epf3dhodzdoc1",
            "ujzdegxdncf32epf3dhodzdoc8",
            "ujzdegxdncf32epf3dhodzdoc=",
            "ujzdegxdncf32epf3dhodzdocj",
            "ujzdegxdncf32epf3dhodzdocb",
            "ujzdegxdncf32epf3dhodzdoc-",
            "ujzdegxdncf32epf3dhodzdocé",
        ] {
            syntax::<BoxName>(s);
        }
        assert_eq!(ok::<PairId>("aaaaaaaaaaaaaaaaaaaaaaaaaa"), "a".repeat(26));
    }

    #[test]
    fn servers() {
        // 2.1 and 3.5: one written form, compared byte for byte.
        for s in [
            "chat.example.org",
            "chat.example.org:7000",
            "localhost",
            "localhost:1",
            "a.b:65535",
            "xn--mgbh0fb.example",
        ] {
            assert_eq!(ok::<ServerAddr>(s), s);
        }
        let server: ServerAddr = "chat.example.org".parse().unwrap();
        assert_eq!((server.host(), server.port()), ("chat.example.org", 7472));
        for s in [
            "",
            "Chat.example.org",
            "chat.example.org.",
            "chat.example.org:7472",
            "chat.example.org:07000",
            "chat.example.org:0",
            "chat.example.org:65536",
            "chat.example.org:",
            "chat.example.org:x",
            "chat.example.org:7000:1",
            "192.0.2.1",
            "192.0.2.1:7000",
            "[2001:db8::1]",
            "-chat.example.org",
            "chat..example.org",
            "chat example.org",
        ] {
            syntax::<ServerAddr>(s);
        }
        // `new` writes the one form: lower case, no `.` at the end, and
        // no port when it is 7472.
        let made = ServerAddr::new("Chat.Example.org.", 7472).unwrap();
        assert_eq!(made.to_string(), "chat.example.org");
        assert_eq!(
            ServerAddr::new("chat.example.org", 7000)
                .unwrap()
                .to_string(),
            "chat.example.org:7000"
        );
        assert!(ServerAddr::new("127.0.0.1", 7000).is_err());
        assert!(ServerAddr::new("chat.example.org", 0).is_err());
        let domain: Domain = "example.net".parse().unwrap();
        assert_eq!(ServerAddr::from(domain).to_string(), "example.net");
    }

    #[test]
    fn links() {
        // 15's example, and the forms of the grammar.
        let gid = format!("{}q", "a".repeat(51));
        for s in [
            "risala://chat.example.org".to_owned(),
            "risala://chat.example.org/general".to_owned(),
            "risala://chat.example.org:7000/general".to_owned(),
            "risala://localhost:7000".to_owned(),
            format!("risala://chat.example.org/general?g={gid}"),
        ] {
            assert_eq!(ok::<Link>(&s), s);
        }
        let link: Link = "RISALA://Chat.Example.ORG/General?g=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ"
            .parse()
            .unwrap();
        assert_eq!(
            link.to_string(),
            "risala://chat.example.org/general?g=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaq"
        );
        assert_eq!(link.room.as_ref().map(Room::as_str), Some("#general"));
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        assert_eq!(link.group_id.map(|g| *g.as_bytes()), Some(bytes));
        // 32 bytes are 52 characters; the last carries one bit and four
        // zero bits.
        let id = crate::mls::GroupId::from_bytes([0xff; 32]);
        let full = Link {
            group_id: Some(id),
            ..link
        };
        let text = full.to_string();
        assert!(text.ends_with(&format!("?g={}q", "7".repeat(51))), "{text}");
        assert_eq!(text.parse::<Link>(), Ok(full));
        for s in [
            "",
            "risala:",
            "risala://",
            "https://chat.example.org/general",
            "risala://chat.example.org/",
            "risala://chat.example.org/#general",
            "risala://chat.example.org/general/",
            "risala://chat.example.org/general?",
            "risala://chat.example.org/general?x=1",
            "risala://chat.example.org/general#x",
            "risala://chat.example.org?g=aaaa",
            "risala://chat.example.org:0/general",
            "risala://chat.example.org:7472/general",
            "risala://chat.example.org:07000/general",
            "risala://chat.example.org:65536",
            "risala://[2001:db8::1]:7000",
            "risala://192.0.2.1",
            "risala://chat.example.org.",
            "risala://user@chat.example.org",
            "risala:///general",
            "risala://chat.example.org/general?g=aaaa",
            &format!("risala://chat.example.org/general?g={}r", "a".repeat(51)),
            &format!("risala://chat.example.org/general?g={gid}&x=1"),
            &format!("risala://chat.example.org/general?g={gid}a"),
        ] {
            syntax::<Link>(s);
        }
    }

    #[test]
    fn box_last_characters() {
        // 3.5: the last character's two unused bits are zero, so it is
        // one of `a e i m q u y 4`; any other is bad-syntax.
        let alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        for c in alphabet.chars() {
            let s = format!("{}{c}", "a".repeat(25));
            let parsed = s.parse::<BoxName>();
            assert_eq!(parsed.is_ok(), "aeimquy4".contains(c), "{s}");
        }
    }

    #[test]
    fn box_round_trips_every_last_character() {
        for last in 0..=255u8 {
            let mut bytes = [0x5a; 16];
            bytes[15] = last;
            let b = BoxName::from_bytes(bytes);
            let s = b.to_string();
            assert_eq!(s.len(), BOX_LEN);
            assert_eq!(s.parse::<BoxName>(), Ok(b));
        }
    }

    #[test]
    fn blob_ref_grammar() {
        let hex = "5d0c9a1e".repeat(12);
        let s = format!("sha384:{hex}");
        let r: BlobRef = s.parse().unwrap();
        assert_eq!(r.to_string(), s);
        assert_eq!(r.hex(), hex);
        assert_eq!(r.hash()[..4], [0x5d, 0x0c, 0x9a, 0x1e]);
        assert_eq!(ok::<BlobRef>(&s.to_ascii_uppercase()), s);
        // SHA-384 of the empty string.
        assert_eq!(
            BlobRef::of(b"").to_string(),
            "sha384:38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        for bad in [
            String::new(),
            "sha384:".into(),
            hex.clone(),
            format!("sha256:{hex}"),
            format!("sha384:{}", &hex[1..]),
            format!("sha384:{hex}0"),
            format!("sha384:{}g", &hex[1..]),
            format!("sha384: {}", &hex[1..]),
            format!("sha384:{}…", &hex[3..]),
        ] {
            syntax::<BlobRef>(&bad);
        }
    }

    #[test]
    fn seq_grammar() {
        assert_eq!(ok::<Seq>("1"), "1");
        assert_eq!(ok::<Seq>("8812"), "8812");
        assert_eq!(ok::<Seq>("9223372036854775807"), "9223372036854775807");
        assert_eq!("9223372036854775807".parse::<Seq>().unwrap(), Seq::MAX);
        for s in [
            "",
            "0",
            "01",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1.0",
            "١",
            "9223372036854775808",
            "18446744073709551615",
            "18446744073709551616",
            "99999999999999999999",
            "10000000000000000000000",
        ] {
            syntax::<Seq>(s);
        }
        assert_eq!(Seq::new(0), None);
        assert_eq!(Seq::new(1), Some(Seq::FIRST));
        assert_eq!(Seq::new(1 << 63), None);
        assert_eq!(Seq::MAX.next(), None);
        assert_eq!(Seq::FIRST.next().unwrap().get(), 2);
        assert_eq!(Seq::try_from(0u64).ok(), None);
        assert_eq!(u64::from(Seq::FIRST), 1);
        assert_eq!(Seq::parse_or_zero("0"), Ok(None));
        assert_eq!(Seq::parse_or_zero("12"), Ok(Seq::new(12)));
        assert!(Seq::parse_or_zero("00").is_err());
        assert!(Seq::new(2) > Seq::new(1));
    }

    #[test]
    fn block_target() {
        let one: BlockTarget = "Spam@Example.net".parse().unwrap();
        assert_eq!(one.to_string(), "spam@example.net");
        let all: BlockTarget = "*@Example.net".parse().unwrap();
        assert_eq!(all.to_string(), "*@example.net");
        for s in [
            "~sam",
            "*@",
            "*@net",
            "*example.net",
            "example.net",
            "*@*.example.net",
            "*",
        ] {
            syntax::<BlockTarget>(s);
        }

        let spam: Uid = "spam@example.net".parse().unwrap();
        let sub: Uid = "x@mail.example.net".parse().unwrap();
        let other: Uid = "spam@badexample.net".parse().unwrap();
        let guest: Uid = "~spam".parse().unwrap();
        assert!(one.covers(&spam));
        assert!(!one.covers(&sub));
        assert!(all.covers(&spam));
        assert!(all.covers(&sub));
        assert!(!all.covers(&other));
        assert!(!all.covers(&guest));
        assert!(!one.covers(&guest));
    }

    #[test]
    fn ip_prefix() {
        assert_eq!(ok::<IpPrefix>("2001:db8::/32"), "2001:db8::/32");
        assert_eq!(ok::<IpPrefix>("2001:DB8::1/32"), "2001:db8::/32");
        assert_eq!(ok::<IpPrefix>("10.1.2.3/8"), "10.0.0.0/8");
        assert_eq!(ok::<IpPrefix>("203.0.113.7/32"), "203.0.113.7/32");
        assert_eq!(ok::<IpPrefix>("203.0.113.7/0"), "0.0.0.0/0");
        assert_eq!(ok::<IpPrefix>("::1/128"), "::1/128");
        assert_eq!(ok::<IpPrefix>("2001:db8::1/0"), "::/0");
        assert_eq!(ok::<IpPrefix>("192.168.1.255/23"), "192.168.0.0/23");
        for s in [
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/",
            "10.0.0.0/08",
            "10.0.0.0/+8",
            "10.0.0.0/-1",
            "10.0.0.0/1000",
            "10.0.0/8",
            "/8",
            "10.0.0.0/8/8",
            "fe80::1%eth0/64",
            "example.net/8",
        ] {
            syntax::<IpPrefix>(s);
        }

        let p: IpPrefix = "203.0.113.0/24".parse().unwrap();
        assert!(p.contains("203.0.113.7".parse().unwrap()));
        assert!(p.contains("::ffff:203.0.113.7".parse().unwrap()));
        assert!(!p.contains("203.0.114.7".parse().unwrap()));
        assert!(!p.contains("2001:db8::1".parse().unwrap()));
        let p6: IpPrefix = "2001:db8::/32".parse().unwrap();
        assert!(p6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!p6.contains("2001:db9::".parse().unwrap()));
        assert!(!p6.contains("10.0.0.1".parse().unwrap()));
        assert_eq!(p6.prefix_len(), 32);
        assert_eq!(p6.addr(), "2001:db8::".parse::<IpAddr>().unwrap());
    }

    /// Found by Kani: a prefix over `::ffff:0:0/96` covered the mapped form
    /// of an address but not the plain IPv4 form.
    #[test]
    fn ip_prefix_mapped_prefix_matches_ipv4() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        for prefix in ["::ffff:203.0.113.0/120", "::/1", "203.0.113.0/24"] {
            let p: IpPrefix = prefix.parse().unwrap();
            assert!(p.contains(mapped), "{prefix}");
            assert_eq!(p.contains(v4), p.contains(mapped), "{prefix}");
        }
        let other: IpPrefix = "::ffff:198.51.100.0/120".parse().unwrap();
        assert!(!other.contains(v4));
        let v6: IpPrefix = "2001:db8::/32".parse().unwrap();
        assert!(!v6.contains(v4));
    }

    #[test]
    fn server_ban_target() {
        let cases = [
            ("spam@example.net", "spam@example.net"),
            ("*@Example.NET", "*@example.net"),
            ("~Sam", "~sam"),
            ("203.0.113.7", "203.0.113.7"),
            ("2001:DB8::1", "2001:db8::1"),
            ("2001:db8::/32", "2001:db8::/32"),
            ("198.51.100.9/24", "198.51.100.0/24"),
        ];
        for (input, output) in cases {
            let target: ServerBanTarget = input.parse().unwrap();
            assert_eq!(target.to_string(), output);
            assert_eq!(output.parse::<ServerBanTarget>().unwrap(), target);
        }
        assert!(matches!(
            "~sam".parse::<ServerBanTarget>(),
            Ok(ServerBanTarget::Guest(_))
        ));
        assert!(matches!(
            "203.0.113.7".parse::<ServerBanTarget>(),
            Ok(ServerBanTarget::Address(_))
        ));
        for s in [
            "",
            "example.net",
            "*@net",
            "~",
            "~-a",
            "203.0.113",
            "203.0.113.7/33",
            "*",
            "spam@",
            "1.2.3.4.5",
        ] {
            syntax::<ServerBanTarget>(s);
        }

        let domain: ServerBanTarget = "*@example.net".parse().unwrap();
        let spam: Uid = "spam@sub.example.net".parse().unwrap();
        assert!(domain.covers_uid(&spam));
        assert!(!domain.covers_uid(&"~spam".parse().unwrap()));
        assert!(!domain.covers_address("203.0.113.7".parse().unwrap()));
        let identity: ServerBanTarget = "spam@sub.example.net".parse().unwrap();
        assert!(identity.covers_uid(&spam));
        assert!(!identity.covers_uid(&"spam@example.net".parse().unwrap()));
        let guest: ServerBanTarget = "~spam".parse().unwrap();
        assert!(!guest.covers_uid(&"~spam".parse().unwrap()));

        let addr: ServerBanTarget = "203.0.113.7".parse().unwrap();
        assert!(addr.covers_address("203.0.113.7".parse().unwrap()));
        assert!(addr.covers_address("::ffff:203.0.113.7".parse().unwrap()));
        assert!(!addr.covers_address("203.0.113.8".parse().unwrap()));
        let prefix: ServerBanTarget = "2001:db8::/32".parse().unwrap();
        assert!(prefix.covers_address("2001:db8::99".parse().unwrap()));
        assert!(!prefix.covers_uid(&spam));
    }

    #[test]
    fn is_valid_uid_matches_parse() {
        for s in [
            "~sam",
            "~sam.",
            "alice@example.org",
            "alice@example",
            "~",
            "x",
            "a@b.c",
        ] {
            assert_eq!(is_valid_uid(s.as_bytes()), s.parse::<Uid>().is_ok(), "{s}");
        }
        assert!(!is_valid_uid(format!("~{}", "a".repeat(33)).as_bytes()));
        assert!(!is_valid_uid(b"~Sam"));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_bytes<const N: usize>() -> ([u8; N], usize) {
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        (bytes, len)
    }

    fn alnum(b: u8) -> bool {
        b.is_ascii_digit() || (b'a'..=b'z').contains(&b)
    }

    /// `alnum [ *( alnum / "." / "_" / "-" ) ( alnum / "_" / "-" ) ]`,
    /// without the length limit.
    fn spec_name(s: &[u8]) -> bool {
        match s {
            [] => false,
            [a] => alnum(*a),
            [a, mid @ .., z] => {
                alnum(*a)
                    && mid
                        .iter()
                        .all(|&b| alnum(b) || b == b'.' || b == b'_' || b == b'-')
                    && (alnum(*z) || *z == b'_' || *z == b'-')
            }
        }
    }

    /// `alnum [ *( alnum / "-" ) alnum ]`, without the length limit.
    fn spec_label(s: &[u8]) -> bool {
        match s {
            [] => false,
            [a] => alnum(*a),
            [a, mid @ .., z] => {
                alnum(*a) && alnum(*z) && mid.iter().all(|&b| alnum(b) || b == b'-')
            }
        }
    }

    /// For any bytes and any limit, `name_shape` accepts the grammar, says
    /// "too long" only for a well-formed name over the limit, and so never
    /// accepts a name ending in `.`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn name_shape_matches_grammar() {
        let (b, len) = any_bytes::<6>();
        let s = &b[..len];
        let max: usize = kani::any();
        match name_shape(s, max) {
            Ok(fits) => {
                assert!(spec_name(s));
                assert_eq!(fits, s.len() <= max);
                assert!(s.last() != Some(&b'.'));
            }
            Err(_) => {
                assert!(!spec_name(s));
            }
        }
    }

    /// `label_shape` accepts the grammar of `label`. Labels this short
    /// always fit, so it never says "too long".
    #[kani::proof]
    #[kani::unwind(8)]
    fn label_shape_matches_grammar() {
        let (b, len) = any_bytes::<6>();
        let s = &b[..len];
        match label_shape(s) {
            Ok(fits) => {
                assert!(fits && spec_label(s));
            }
            Err(_) => {
                assert!(!spec_label(s));
            }
        }
    }

    /// `room_shape` is `"#" name`, and `id_shape` is
    /// `1*( alnum / "-" / "_" )`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn room_and_id_shapes_match_grammar() {
        let (b, len) = any_bytes::<6>();
        let s = &b[..len];
        let room = matches!(s, [b'#', rest @ ..] if spec_name(rest));
        match room_shape(s) {
            Ok(fits) => {
                assert!(fits && room);
            }
            Err(_) => {
                assert!(!room);
            }
        }
        let id = !s.is_empty() && s.iter().all(|&b| alnum(b) || b == b'-' || b == b'_');
        match id_shape(s) {
            Ok(fits) => {
                assert!(fits && id);
            }
            Err(_) => {
                assert!(!id);
            }
        }
    }
}

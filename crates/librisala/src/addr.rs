//! Server addresses (2.1) and the trust records of 2.2.
//!
//! These types are shared by [`crate::conn`], which checks certificates,
//! and [`crate::store`], which keeps the records. Owned by task C0.

use std::fmt;
use std::str::FromStr;

use risala_proto::fingerprint::Fingerprint;

/// A server address: a hostname with an optional port (2.1), for example
/// `chat.example.org` or `chat.example.org:7000`.
///
/// The host is normalized as 2.1 says: lower-cased, with one trailing `.`
/// dropped, so `Chat.Example.org.` and `chat.example.org` are the same
/// server. The normalized host is what the client sends in SNI, the key of
/// the trust record (2.2) and what it signs in AUTH (4.6). An IP address
/// is allowed, but cannot sign in as an identity (2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServerAddr {
    host: String,
    port: u16,
}

/// An address that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid server address: {0}")]
pub struct BadAddr(String);

impl ServerAddr {
    /// Makes an address from a host and a port (2.1). The host is folded to
    /// lower case and loses one trailing `.`. A name with an empty label,
    /// such as `a..b` or `.`, is refused, and so is a host with `:` that is
    /// not an IPv6 address.
    pub fn new(host: &str, port: u16) -> Result<ServerAddr, BadAddr> {
        let bad = || BadAddr(host.to_owned());
        let h = host.trim_start_matches('[').trim_end_matches(']');
        if port == 0 {
            return Err(bad());
        }
        if h.contains(':') {
            let ip: std::net::Ipv6Addr = h.parse().map_err(|_| bad())?;
            return Ok(ServerAddr {
                host: ip.to_string(),
                port,
            });
        }
        let h = h.strip_suffix('.').unwrap_or(h);
        let ok = !h.is_empty()
            && h.len() <= 253
            && h.split('.')
                .all(|label| !label.is_empty() && label.len() <= 63)
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
        if !ok {
            return Err(bad());
        }
        Ok(ServerAddr {
            host: h.to_ascii_lowercase(),
            port,
        })
    }

    /// The host, in lower case, without brackets around an IPv6 address.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the host is an IP address rather than a name.
    pub fn is_ip(&self) -> bool {
        self.host.parse::<std::net::IpAddr>().is_ok()
    }
}

impl FromStr for ServerAddr {
    type Err = BadAddr;

    /// Parses `host`, `host:port`, `[v6]` or `[v6]:port`. The default port
    /// is 7472 (15).
    fn from_str(s: &str) -> Result<ServerAddr, BadAddr> {
        let bad = || BadAddr(s.to_owned());
        let default = risala_proto::DEFAULT_PORT;
        if let Some(rest) = s.strip_prefix('[') {
            let (host, after) = rest.split_once(']').ok_or_else(bad)?;
            let port = match after {
                "" => default,
                p => p
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(bad)?,
            };
            return ServerAddr::new(host, port);
        }
        match s.matches(':').count() {
            0 => ServerAddr::new(s, default),
            1 => {
                let (host, port) = s.split_once(':').ok_or_else(bad)?;
                ServerAddr::new(host, port.parse().map_err(|_| bad())?)
            }
            // A bare IPv6 address, with no port.
            _ => ServerAddr::new(s, default),
        }
    }
}

impl fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == risala_proto::DEFAULT_PORT {
            f.write_str(&host)
        } else {
            write!(f, "{host}:{}", self.port)
        }
    }
}

/// How a server was verified (2.2). "Nothing yet" is the absence of a
/// record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TrustRecord {
    /// The server showed a CA-valid certificate. From now on it must keep
    /// doing so, or match a pin the user accepts.
    Ca,
    /// The user accepted this fingerprint on first use. A CA-valid
    /// certificate replaces it with [`Ca`](Self::Ca), with a one-time
    /// [`PinChange`] notice.
    Pinned(Fingerprint),
    /// A strict pin the user set (2.2, PLAN.md 58): every certificate,
    /// CA-valid or not, must have this fingerprint, and a different one
    /// needs the user's approval.
    Strict(Fingerprint),
}

impl TrustRecord {
    /// The pinned fingerprint, strict or not.
    pub fn pin(&self) -> Option<&Fingerprint> {
        match self {
            TrustRecord::Ca => None,
            TrustRecord::Pinned(fp) | TrustRecord::Strict(fp) => Some(fp),
        }
    }
}

impl fmt::Display for TrustRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustRecord::Ca => f.write_str("CA"),
            TrustRecord::Pinned(fp) => write!(f, "pinned {fp}"),
            TrustRecord::Strict(fp) => write!(f, "strictly pinned {fp}"),
        }
    }
}

/// A pin replaced by "CA" because the server showed a CA-valid
/// certificate with another key (2.2). The client tells the user once,
/// showing both fingerprints, since whoever can get a certificate for
/// the name could be behind the change.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PinChange {
    /// The fingerprint that was pinned.
    pub old: Fingerprint,
    /// The fingerprint of the CA-valid certificate that replaced it.
    pub new: Fingerprint,
}

/// What [`TrustStore::replace`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replaced {
    /// The record was the one expected, and has been replaced.
    Done,
    /// The record was not the one expected, so nothing was written. It
    /// holds the record found.
    Found(Option<TrustRecord>),
}

/// Somewhere to keep trust records, one per server address, and the
/// notices of pins replaced by "CA" (2.2).
///
/// [`crate::store`] implements it on SQLite. Tests can use
/// [`MemoryTrustStore`]. Calls may block.
pub trait TrustStore: Send + Sync {
    /// The record for `addr`, if any.
    fn get(&self, addr: &ServerAddr) -> Result<Option<TrustRecord>, TrustStoreError>;
    /// Replaces the record for `addr` with `new` if it is still
    /// `expected` (`None`: no record), in one step, so that a record
    /// written meanwhile by another connection or process is never
    /// overwritten. With `notice`, the notice is kept in the same step,
    /// replacing any earlier one for `addr`.
    fn replace(
        &self,
        addr: &ServerAddr,
        expected: Option<&TrustRecord>,
        new: TrustRecord,
        notice: Option<PinChange>,
    ) -> Result<Replaced, TrustStoreError>;
    /// Deletes the record for `addr`, as the user must do explicitly after
    /// a mismatch (2.2). Its notice goes too.
    fn forget(&self, addr: &ServerAddr) -> Result<(), TrustStoreError>;
    /// The notices not yet dismissed, by server.
    fn notices(&self) -> Result<Vec<(ServerAddr, PinChange)>, TrustStoreError>;
    /// Dismisses the notice for `addr`, once the user has seen it.
    fn dismiss_notice(&self, addr: &ServerAddr) -> Result<(), TrustStoreError>;

    /// Records `Pinned(fingerprint)` for `addr` if it has no record, and
    /// returns the record it had before, if any.
    fn pin_if_unknown(
        &self,
        addr: &ServerAddr,
        fingerprint: Fingerprint,
    ) -> Result<Option<TrustRecord>, TrustStoreError> {
        match self.replace(addr, None, TrustRecord::Pinned(fingerprint), None)? {
            Replaced::Done => Ok(None),
            Replaced::Found(found) => Ok(found),
        }
    }
}

/// A trust store failed to read or write.
#[derive(Debug, thiserror::Error)]
#[error("trust store: {0}")]
pub struct TrustStoreError(pub String);

/// A [`TrustStore`] in memory, for tests and short-lived tools.
#[derive(Debug, Default)]
pub struct MemoryTrustStore(std::sync::Mutex<MemoryTrust>);

/// What a [`MemoryTrustStore`] holds.
#[derive(Debug, Default)]
pub struct MemoryTrust {
    records: std::collections::HashMap<ServerAddr, TrustRecord>,
    notices: std::collections::BTreeMap<ServerAddr, PinChange>,
}

impl MemoryTrustStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryTrust> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl TrustStore for MemoryTrustStore {
    fn get(&self, addr: &ServerAddr) -> Result<Option<TrustRecord>, TrustStoreError> {
        Ok(self.lock().records.get(addr).cloned())
    }

    fn replace(
        &self,
        addr: &ServerAddr,
        expected: Option<&TrustRecord>,
        new: TrustRecord,
        notice: Option<PinChange>,
    ) -> Result<Replaced, TrustStoreError> {
        let mut t = self.lock();
        let found = t.records.get(addr);
        if found != expected {
            return Ok(Replaced::Found(found.cloned()));
        }
        t.records.insert(addr.clone(), new);
        if let Some(notice) = notice {
            t.notices.insert(addr.clone(), notice);
        }
        Ok(Replaced::Done)
    }

    fn forget(&self, addr: &ServerAddr) -> Result<(), TrustStoreError> {
        let mut t = self.lock();
        t.records.remove(addr);
        t.notices.remove(addr);
        Ok(())
    }

    fn notices(&self) -> Result<Vec<(ServerAddr, PinChange)>, TrustStoreError> {
        Ok(self
            .lock()
            .notices
            .iter()
            .map(|(a, n)| (a.clone(), n.clone()))
            .collect())
    }

    fn dismiss_notice(&self, addr: &ServerAddr) -> Result<(), TrustStoreError> {
        self.lock().notices.remove(addr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        for (input, host, port, shown) in [
            (
                "chat.example.org",
                "chat.example.org",
                7472,
                "chat.example.org",
            ),
            (
                "Chat.Example.ORG:7000",
                "chat.example.org",
                7000,
                "chat.example.org:7000",
            ),
            ("127.0.0.1:7472", "127.0.0.1", 7472, "127.0.0.1"),
            ("[::1]:9000", "::1", 9000, "[::1]:9000"),
            ("::1", "::1", 7472, "[::1]"),
            ("[0:0::1]", "::1", 7472, "[::1]"),
            // 2.1: lower case, and one trailing dot dropped.
            (
                "Chat.Example.org.",
                "chat.example.org",
                7472,
                "chat.example.org",
            ),
            (
                "Chat.Example.org.:7000",
                "chat.example.org",
                7000,
                "chat.example.org:7000",
            ),
        ] {
            let a: ServerAddr = input.parse().unwrap();
            assert_eq!((a.host(), a.port()), (host, port), "{input}");
            assert_eq!(a.to_string(), shown);
            assert_eq!(a.to_string().parse::<ServerAddr>().unwrap(), a);
        }
        assert!("127.0.0.1".parse::<ServerAddr>().unwrap().is_ip());
        assert_eq!(
            "Chat.Example.org.".parse::<ServerAddr>().unwrap(),
            "chat.example.org".parse::<ServerAddr>().unwrap()
        );
    }

    #[test]
    fn bad() {
        for s in [
            "", ":7472", "a b", "host:0", "host:x", "[::1", "a/b", ".", "a..b", ".a", "a..",
            "[a:b]", "x:y:z",
        ] {
            assert!(s.parse::<ServerAddr>().is_err(), "{s}");
        }
    }
}

//! Server addresses (2.1) and the trust records of 2.2.
//!
//! These types are shared by [`crate::conn`], which checks certificates,
//! and [`crate::store`], which keeps the records.

use std::fmt;
use std::str::FromStr;

use risala_proto::fingerprint::Fingerprint;

/// A server address: a hostname with an optional port (2.1), for example
/// `chat.example.org` or `chat.example.org:7000`.
///
/// The host is kept in lower case. It is what the client sends in SNI and
/// signs in AUTH (4.5). An IP address is allowed, but cannot sign in as an
/// identity (2.1).
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
    /// Makes an address from a host and a port. The host is folded to lower
    /// case.
    pub fn new(host: &str, port: u16) -> Result<ServerAddr, BadAddr> {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        let ok = !h.is_empty()
            && h.len() <= 253
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
        if !ok || port == 0 {
            return Err(BadAddr(host.to_owned()));
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
    /// is 7472 (14).
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
    /// doing so.
    Ca,
    /// The user accepted this fingerprint on first use.
    Pinned(Fingerprint),
}

/// Somewhere to keep trust records, one per server address.
///
/// [`crate::store`] implements it on SQLite. Tests can use
/// [`MemoryTrustStore`].
pub trait TrustStore: Send + Sync {
    /// The record for `addr`, if any.
    fn get(&self, addr: &ServerAddr) -> Result<Option<TrustRecord>, TrustStoreError>;
    /// Sets the record for `addr`, replacing any other.
    fn set(&self, addr: &ServerAddr, record: TrustRecord) -> Result<(), TrustStoreError>;
    /// Deletes the record for `addr`, as the user must do explicitly after
    /// a mismatch (2.2).
    fn forget(&self, addr: &ServerAddr) -> Result<(), TrustStoreError>;
}

/// A trust store failed to read or write.
#[derive(Debug, thiserror::Error)]
#[error("trust store: {0}")]
pub struct TrustStoreError(pub String);

/// A [`TrustStore`] in memory, for tests and short-lived tools.
#[derive(Debug, Default)]
pub struct MemoryTrustStore(std::sync::Mutex<std::collections::HashMap<ServerAddr, TrustRecord>>);

impl TrustStore for MemoryTrustStore {
    fn get(&self, addr: &ServerAddr) -> Result<Option<TrustRecord>, TrustStoreError> {
        Ok(self.0.lock().expect("poisoned").get(addr).cloned())
    }

    fn set(&self, addr: &ServerAddr, record: TrustRecord) -> Result<(), TrustStoreError> {
        self.0
            .lock()
            .expect("poisoned")
            .insert(addr.clone(), record);
        Ok(())
    }

    fn forget(&self, addr: &ServerAddr) -> Result<(), TrustStoreError> {
        self.0.lock().expect("poisoned").remove(addr);
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
        ] {
            let a: ServerAddr = input.parse().unwrap();
            assert_eq!((a.host(), a.port()), (host, port), "{input}");
            assert_eq!(a.to_string(), shown);
            assert_eq!(a.to_string().parse::<ServerAddr>().unwrap(), a);
        }
        assert!("127.0.0.1".parse::<ServerAddr>().unwrap().is_ip());
    }

    #[test]
    fn bad() {
        for s in ["", ":7472", "a b", "host:0", "host:x", "[::1", "a/b"] {
            assert!(s.parse::<ServerAddr>().is_err(), "{s}");
        }
    }
}

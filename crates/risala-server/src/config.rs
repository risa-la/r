//! The server's configuration file, in TOML (PLAN.md 3.2).
//!
//! Every field has a default, so an empty file is a working development
//! server: it listens on port 7472, keeps its database and a generated
//! self-signed certificate in the current directory, and allows guests.
//!
//! ```toml
//! hostname = "chat.example.org"
//! listen = ["[::]:7472"]
//! state_dir = "/var/lib/risala"
//! operators = ["alice@example.org"]
//! rooms = ["#general"]
//!
//! [[tls.certs]]
//! cert = "/var/lib/acme/chat.example.org/fullchain.pem"
//! key = "/var/lib/acme/chat.example.org/key.pem"
//!
//! [server]
//! welcome = "Welcome!"
//! guests = true
//! retention = "forever"
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The whole configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The server's main hostname, in lower case. The greeting uses it when
    /// a client sends no SNI (4.1). It also names the generated self-signed
    /// certificate.
    pub hostname: String,
    /// Addresses to listen on for risala over TLS (2.1).
    pub listen: Vec<SocketAddr>,
    /// Where the database and any generated certificate live.
    pub state_dir: PathBuf,
    /// The server's first operators (10.1). They cannot be removed with
    /// ADMIN DEOP.
    pub operators: Vec<String>,
    /// Rooms that exist from the start, with no owner. Guests cannot create
    /// rooms (4.2), so a guests-only server needs at least one. Created at
    /// startup if missing, never deleted because they left this list.
    pub rooms: Vec<String>,
    /// TLS certificates.
    pub tls: TlsConfig,
    /// Server settings. ADMIN SET (10.6) changes them at run time; these
    /// are only the values a new database starts with.
    pub server: ServerConfig,
    /// Limits and timers.
    pub limits: Limits,
}

/// TLS certificates (2.1, 2.2).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Certificates, chosen by SNI. Each file is re-read when it changes on
    /// disk, without dropping connections (2.2). A client that sends no SNI,
    /// or a name no certificate covers, gets the first one. When this is
    /// empty, the server generates a self-signed certificate for
    /// `hostname` in `state_dir` and logs its fingerprint.
    pub certs: Vec<CertPair>,
}

/// One certificate chain and its private key, both PEM.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertPair {
    /// The certificate chain, leaf first.
    pub cert: PathBuf,
    /// The private key.
    pub key: PathBuf,
}

/// The settings of ADMIN SET (10.6), as the database first gets them.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// The greeting's welcome text, at most 512 bytes, already escaped
    /// (3.4). Empty means none.
    pub welcome: String,
    /// Whether guests may connect.
    pub guests: bool,
    /// The retention period: a number of days as a string, or `forever`.
    pub retention: String,
}

/// Limits and timers. Defaults follow the spec where it names a value.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Seconds a new connection has to sign in (4.1: at least 120).
    pub sign_in_secs: u64,
    /// Seconds of silence before the server sends PING (11).
    pub idle_ping_secs: u64,
    /// Further seconds of silence before the server closes (11).
    pub ping_timeout_secs: u64,
    /// The most lines queued for one connection before it is dropped as
    /// too slow.
    pub out_queue: usize,
    /// The most events one HISTORY or RELATED page returns, whatever the
    /// client asks for (7.2).
    pub max_page: u64,
    /// The most rooms one LIST page returns (6.1).
    pub max_list: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hostname: "localhost".into(),
            listen: vec![SocketAddr::from(([0, 0, 0, 0], risala_proto::DEFAULT_PORT))],
            state_dir: PathBuf::from("."),
            operators: Vec::new(),
            rooms: Vec::new(),
            tls: TlsConfig::default(),
            server: ServerConfig::default(),
            limits: Limits::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            welcome: String::new(),
            guests: true,
            retention: "forever".into(),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            sign_in_secs: 120,
            idle_ping_secs: 120,
            ping_timeout_secs: 60,
            out_queue: 1024,
            max_page: 500,
            max_list: 500,
        }
    }
}

/// An error reading the configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The file is not valid TOML, or has unknown or mistyped keys.
    #[error("parsing {path}: {source}")]
    Toml {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: toml::de::Error,
    },
}

impl Config {
    /// Reads and parses a configuration file.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        Config::parse(&text).map_err(|source| ConfigError::Toml {
            path: path.to_owned(),
            source,
        })
    }

    /// Parses configuration text.
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }

    /// The path of the SQLite database.
    pub fn database_path(&self) -> PathBuf {
        self.state_dir.join("risala.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_is_a_dev_server() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.hostname, "localhost");
        assert_eq!(c.listen[0].port(), 7472);
        assert!(c.server.guests);
        assert_eq!(c.limits.sign_in_secs, 120);
    }

    #[test]
    fn full_file() {
        let c = Config::parse(
            r##"
            hostname = "chat.example.org"
            listen = ["[::]:7000"]
            rooms = ["#general"]
            [[tls.certs]]
            cert = "a.pem"
            key = "b.pem"
            [server]
            guests = false
            retention = "30"
            [limits]
            out_queue = 8
            "##,
        )
        .unwrap();
        assert_eq!(c.listen[0].port(), 7000);
        assert_eq!(c.tls.certs.len(), 1);
        assert!(!c.server.guests);
        assert_eq!(c.limits.out_queue, 8);
        assert_eq!(c.limits.idle_ping_secs, 120);
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(Config::parse("hostnme = \"x\"").is_err());
    }
}

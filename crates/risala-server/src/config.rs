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

use risala_proto::frame::MAX_SERVER_LINE;
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
    /// Seconds a guest's session waits to be resumed after its connection
    /// closes, before it ends and the guest leaves its rooms (4.2). At
    /// least [`MIN_GUEST_RESUME_SECS`].
    pub guest_resume_secs: u64,
    /// Seconds of silence before the server sends PING (11).
    pub idle_ping_secs: u64,
    /// Further seconds of silence before the server closes (11).
    pub ping_timeout_secs: u64,
    /// The most lines queued for one connection before it is dropped as
    /// too slow. Before it runs each command, a connection waits until its
    /// queue has room for the command's whole response and for live events
    /// besides ([`Limits::command_room`]), so this must be at least that.
    pub out_queue: usize,
    /// The most bytes of lines queued for one connection before it is
    /// dropped as too slow, counting each line and its LF as sent. Like
    /// `out_queue`, it must leave room for a whole response and live
    /// events besides, at [`MAX_SERVER_LINE`] bytes a line
    /// ([`Limits::command_room_bytes`]).
    ///
    /// A line sent to many connections is kept once, so this bounds
    /// memory from above.
    pub out_queue_bytes: usize,
    /// The most events one HISTORY or RELATED page returns, whatever the
    /// client asks for (7.2).
    pub max_page: u64,
    /// The most rooms one LIST page returns (6.1).
    pub max_list: u64,
}

/// The most lines a command's response has besides a full page of events
/// (HISTORY) or rooms (LIST): the snapshot SETs of JOIN and INFO, the
/// command's own event, and the final response.
pub const REPLY_MARGIN: usize = 16;

/// The room a connection's queue keeps for live events from other people
/// while it holds a response of the largest size (see
/// [`Limits::command_room`]).
pub const FANOUT_ROOM: usize = 128;

/// The least `limits.sign_in_secs` the spec recommends (4.1).
pub const MIN_SIGN_IN_SECS: u64 = 120;

/// The least `limits.guest_resume_secs` the spec allows (4.2).
pub const MIN_GUEST_RESUME_SECS: u64 = 120;

impl Limits {
    /// The most lines one command's response queues: a full HISTORY or
    /// LIST page, plus [`REPLY_MARGIN`]. SYNC is not bounded by this: it
    /// has a line for every conversation the user is in.
    pub fn reply_lines(&self) -> usize {
        let page = self.max_page.max(self.max_list);
        usize::try_from(page)
            .unwrap_or(usize::MAX)
            .saturating_add(REPLY_MARGIN)
    }

    /// The free lines a connection's queue must have before the network
    /// layer hands it its next command: room for the largest response
    /// ([`reply_lines`](Self::reply_lines)) and [`FANOUT_ROOM`] more for
    /// live events that arrive meanwhile.
    ///
    /// So a client that sends many commands at once, such as a HISTORY
    /// for every room after SYNC, gets them answered as fast as it reads,
    /// and is not dropped as too slow. Live events from other people still
    /// drop a connection whose queue is full.
    pub fn command_room(&self) -> usize {
        self.reply_lines().saturating_add(FANOUT_ROOM)
    }

    /// [`command_room`](Self::command_room) in bytes: that many lines of
    /// the longest a server line may be ([`MAX_SERVER_LINE`]).
    pub fn command_room_bytes(&self) -> usize {
        self.command_room().saturating_mul(MAX_SERVER_LINE)
    }
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
            guest_resume_secs: 300,
            idle_ping_secs: 120,
            ping_timeout_secs: 60,
            out_queue: 1024,
            out_queue_bytes: 16 * 1024 * 1024,
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
    /// A value that parses but cannot work.
    #[error("configuration: {0}")]
    Invalid(String),
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

    /// Checks the limits for values that cannot work: timers of zero, pages
    /// of no lines, and queues too short for a response (see
    /// [`Limits::command_room`]).
    ///
    /// Returns warnings for values that work but go against what the spec
    /// recommends, for the caller to log.
    pub fn validate(&self) -> Result<Vec<String>, ConfigError> {
        let l = &self.limits;
        let invalid = |message: String| Err(ConfigError::Invalid(message));
        for (name, value) in [
            ("sign_in_secs", l.sign_in_secs),
            ("idle_ping_secs", l.idle_ping_secs),
            ("ping_timeout_secs", l.ping_timeout_secs),
            ("max_page", l.max_page),
            ("max_list", l.max_list),
        ] {
            if value == 0 {
                return invalid(format!("limits.{name} must be at least 1"));
            }
        }
        if l.guest_resume_secs < MIN_GUEST_RESUME_SECS {
            return invalid(format!(
                "limits.guest_resume_secs is {}, but must be at least {MIN_GUEST_RESUME_SECS} (4.2)",
                l.guest_resume_secs
            ));
        }
        if l.out_queue < l.command_room() {
            return invalid(format!(
                "limits.out_queue is {}, but must be at least {}: room for the longest \
                 response ({} lines: max_page or max_list, whichever is larger, plus \
                 {REPLY_MARGIN}) and {FANOUT_ROOM} lines for live events",
                l.out_queue,
                l.command_room(),
                l.reply_lines(),
            ));
        }
        if l.out_queue_bytes < l.command_room_bytes() {
            return invalid(format!(
                "limits.out_queue_bytes is {}, but must be at least {}: {} lines \
                 (see limits.out_queue) of up to {MAX_SERVER_LINE} bytes",
                l.out_queue_bytes,
                l.command_room_bytes(),
                l.command_room(),
            ));
        }
        let mut warnings = Vec::new();
        if l.sign_in_secs < MIN_SIGN_IN_SECS {
            warnings.push(format!(
                "limits.sign_in_secs is {}; the spec recommends at least {MIN_SIGN_IN_SECS} (4.1)",
                l.sign_in_secs
            ));
        }
        Ok(warnings)
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
        assert_eq!(c.limits.guest_resume_secs, 300);
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
    fn limits_are_checked() {
        assert_eq!(Config::default().validate().unwrap(), Vec::<String>::new());
        let with = |f: fn(&mut Limits)| {
            let mut c = Config::default();
            f(&mut c.limits);
            c.validate()
        };
        let invalid = |f: fn(&mut Limits), what: &str| match with(f) {
            Err(ConfigError::Invalid(m)) => assert!(m.contains(what), "{m}"),
            other => panic!("{what}: {other:?}"),
        };
        invalid(|l| l.sign_in_secs = 0, "sign_in_secs");
        invalid(|l| l.idle_ping_secs = 0, "idle_ping_secs");
        invalid(|l| l.ping_timeout_secs = 0, "ping_timeout_secs");
        invalid(|l| l.max_page = 0, "max_page");
        invalid(|l| l.max_list = 0, "max_list");
        invalid(|l| l.guest_resume_secs = 119, "guest_resume_secs");
        assert!(with(|l| l.guest_resume_secs = 120).is_ok());

        // The queue holds the longest response and room for live events.
        let l = Limits::default();
        assert_eq!(l.reply_lines(), 500 + REPLY_MARGIN);
        assert_eq!(l.command_room(), 500 + REPLY_MARGIN + FANOUT_ROOM);
        invalid(|l| l.out_queue = 8, "out_queue");
        invalid(|l| l.max_page = 1000, "out_queue");
        invalid(|l| l.max_list = 1000, "out_queue");
        invalid(|l| l.max_page = u64::MAX, "out_queue");
        assert_eq!(
            l.command_room_bytes(),
            (500 + REPLY_MARGIN + FANOUT_ROOM) * MAX_SERVER_LINE
        );
        invalid(|l| l.out_queue_bytes = 1 << 20, "out_queue_bytes");
        assert!(
            with(|l| {
                l.max_page = 1000;
                l.out_queue = 1000 + REPLY_MARGIN + FANOUT_ROOM;
                l.out_queue_bytes = l.out_queue * MAX_SERVER_LINE;
            })
            .is_ok()
        );
        assert!(
            with(|l| {
                l.out_queue = 500 + REPLY_MARGIN + FANOUT_ROOM - 1;
            })
            .is_err()
        );

        // A short sign-in time works, but goes against 4.1.
        let warnings = with(|l| l.sign_in_secs = 10).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("sign_in_secs"), "{warnings:?}");
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(Config::parse("hostnme = \"x\"").is_err());
    }
}

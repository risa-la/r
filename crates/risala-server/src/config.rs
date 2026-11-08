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
//! identity_domain = "example.org"
//! room_creation = "identities"
//!
//! [[tls.certs]]
//! cert = "/var/lib/acme/chat.example.org/fullchain.pem"
//! key = "/var/lib/acme/chat.example.org/key.pem"
//!
//! [server]
//! welcome = "Welcome!"
//! guests = true
//! registration = true
//! retention = "forever"
//!
//! [limits]
//! registrations_per_hour = 5
//! reports_per_hour = 30
//! presence_offline_secs = 30
//!
//! [keys]
//! allow_private = false
//!
//! [http]
//! listen = ["[::]:443"]
//! key_dir = "/var/lib/risala/keys"
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use risala_proto::frame::MAX_SERVER_LINE;
use risala_proto::names::{Domain, Identity};
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
    /// The server's identity domain (4.6): REGISTER creates identities
    /// `<name>@<identity_domain>`, which the server hosts, and INFO reports
    /// it (8.5). The server must then publish their key files at
    /// `https://<identity_domain>/.well-known/risala/<name>` (4.3). Without
    /// it, the server hosts no identities, and REGISTER and KEY get
    /// `ERR not-supported`. Whether REGISTER is open is the server setting
    /// `registration` (10.6), first set from `server.registration`.
    pub identity_domain: Option<String>,
    /// Who may create a room by joining one that does not exist (6.1).
    /// Guests never may (4.2).
    pub room_creation: RoomCreation,
    /// TLS certificates.
    pub tls: TlsConfig,
    /// Server settings. ADMIN SET (10.6) changes them at run time; these
    /// are only the values a new database starts with.
    pub server: ServerConfig,
    /// Limits and timers.
    pub limits: Limits,
    /// Fetching key files (4.4).
    pub keys: KeysConfig,
    /// The HTTPS listener and the key file directory (4.6).
    pub http: HttpConfig,
}

/// Fetching key files over HTTPS (4.4), to check sign-ins (4.5).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysConfig {
    /// Lets the server fetch key files from loopback, private, link-local
    /// and other special-purpose addresses (RFC 6890). Off by default: users
    /// choose the domains, and 4.4 forbids this unless the operator allows
    /// it, so that they cannot make the server probe its own network. Turn
    /// it on only for internal deployments and tests.
    pub allow_private: bool,
    /// Seconds a fetch may take, from resolving the domain to the end of
    /// the file: 1 to 10 (4.4).
    pub fetch_timeout_secs: u64,
    /// The most key files kept in the cache. Each is kept for up to an hour
    /// (4.4). At least 1.
    pub cache_size: usize,
    /// PEM files of CA certificates to trust besides the public ones built
    /// in (Mozilla's). For tests and private deployments; 4.4 asks for
    /// public CAs.
    pub extra_roots: Vec<PathBuf>,
}

/// The HTTPS listener, which serves hosted identities' key files at
/// `/.well-known/risala/<name>` (4.6), and the directory those files are
/// written to (PLAN.md section 6).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// Addresses for the HTTPS listener. Empty, the default, means no
    /// listener: serve `key_dir` from another web server instead.
    pub listen: Vec<SocketAddr>,
    /// Certificates for the listener, chosen by SNI and re-read when they
    /// change, as in `[tls]`. Empty means the same certificates as the
    /// risala listener. Key files are fetched with the certificate checked
    /// against public CAs (4.4), so a real deployment needs one for the
    /// identity domain.
    pub certs: Vec<CertPair>,
    /// Where hosted identities' key files are written, one file per name,
    /// so that another web server can serve them. The default is
    /// `<state_dir>/keys`. It may not be the state directory, nor hold it,
    /// nor be anywhere else inside it, since the state directory holds the
    /// database and the private key of the generated certificate. Files in
    /// it named like a hosted name and holding only key lines are removed
    /// at startup if the server no longer hosts that name.
    pub key_dir: Option<PathBuf>,
}

/// Who may create rooms by joining them (6.1): `room_creation` in the
/// configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoomCreation {
    /// Any identity. The default.
    #[default]
    Identities,
    /// Only identities the server hosts (4.6), and operators.
    Hosted,
    /// Only the server's operators (10.1).
    Operators,
    /// Nobody: rooms come only from `rooms`.
    Nobody,
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
    /// Whether REGISTER is open (10.6). It takes effect only with an
    /// `identity_domain`.
    pub registration: bool,
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
    /// The most identities REGISTER may create from one network address in
    /// an hour (13, 14). IPv6 addresses count by their /64. Further
    /// REGISTERs get `ERR rate-limited`. 0 means no limit.
    pub registrations_per_hour: u32,
    /// The most rooms one identity may create, by joining them, in a day
    /// (6.1, 14), since anyone who controls a domain can make any number
    /// of identities. Further creations get `ERR rate-limited`. Operators
    /// are not limited. 0 means no limit.
    pub rooms_per_day: u32,
    /// The most reports one identity, or the guests of one network, may
    /// make in an hour (5.8: servers SHOULD rate-limit reports). Guests
    /// count by their address, IPv6 addresses by their /64, since a guest
    /// can take a new name at will. Further REPORTs get `ERR
    /// rate-limited`. A report repeated, which gets the existing id, does
    /// not count. 0 means no limit.
    pub reports_per_hour: u32,
    /// Seconds after an identity's last connection closes before the
    /// people who share a conversation with it are told it is offline
    /// (8.3: about 30). A connection that opens meanwhile cancels it, and
    /// nothing is sent. 0 reports it at once.
    pub presence_offline_secs: u64,
    /// Milliseconds the server collects presence changes before it sends
    /// them, so that one PRESENCE line covers many users (8.3: up to a few
    /// seconds). At least 1.
    pub presence_batch_ms: u64,
    /// The least milliseconds between two TYPING notifications one
    /// connection sends on to a conversation (8.1, 13). Clients repeat
    /// TYPING about every 4 seconds, so this stops only floods. Those in
    /// between still get `OK`, but are not passed on. 0 means no limit.
    pub typing_interval_ms: u64,
    /// The most blocks one account may have (5.7). BLOCK beyond it gets
    /// `ERR forbidden`.
    pub max_blocks: usize,
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
    /// LIST page, plus [`REPLY_MARGIN`]. SYNC has a line for every
    /// conversation the user is in, so it queues them in chunks of fewer
    /// than this, waiting for [`command_room`](Self::command_room) again
    /// before each chunk.
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
            identity_domain: None,
            room_creation: RoomCreation::default(),
            tls: TlsConfig::default(),
            server: ServerConfig::default(),
            limits: Limits::default(),
            keys: KeysConfig::default(),
            http: HttpConfig::default(),
        }
    }
}

impl Default for KeysConfig {
    fn default() -> Self {
        KeysConfig {
            allow_private: false,
            fetch_timeout_secs: MAX_FETCH_TIMEOUT_SECS,
            cache_size: 10_000,
            extra_roots: Vec::new(),
        }
    }
}

/// The most seconds a key file fetch may take (4.4).
pub const MAX_FETCH_TIMEOUT_SECS: u64 = 10;

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            welcome: String::new(),
            guests: true,
            registration: false,
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
            registrations_per_hour: 5,
            rooms_per_day: 10,
            reports_per_hour: 30,
            presence_offline_secs: 30,
            presence_batch_ms: 1000,
            typing_interval_ms: 1000,
            max_blocks: 1000,
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

    /// Checks for values that cannot work: an identity domain or operator
    /// that is not one, timers of zero, pages of no lines, and queues too
    /// short for a response (see [`Limits::command_room`]).
    ///
    /// Returns warnings for values that work but go against what the spec
    /// recommends, for the caller to log.
    pub fn validate(&self) -> Result<Vec<String>, ConfigError> {
        let l = &self.limits;
        let invalid = |message: String| Err(ConfigError::Invalid(message));
        if let Some(domain) = &self.identity_domain
            && let Err(e) = domain.parse::<Domain>()
        {
            return invalid(format!("identity_domain {domain:?} is not a domain: {e}"));
        }
        for op in &self.operators {
            if let Err(e) = op.parse::<Identity>() {
                return invalid(format!("operator {op:?} is not an identity: {e}"));
            }
        }
        for (name, value) in [
            ("sign_in_secs", l.sign_in_secs),
            ("idle_ping_secs", l.idle_ping_secs),
            ("ping_timeout_secs", l.ping_timeout_secs),
            ("max_page", l.max_page),
            ("max_list", l.max_list),
            ("presence_batch_ms", l.presence_batch_ms),
            ("max_blocks", l.max_blocks as u64),
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
        let k = &self.keys;
        if !(1..=MAX_FETCH_TIMEOUT_SECS).contains(&k.fetch_timeout_secs) {
            return invalid(format!(
                "keys.fetch_timeout_secs is {}, but must be 1 to {MAX_FETCH_TIMEOUT_SECS} (4.4)",
                k.fetch_timeout_secs
            ));
        }
        if k.cache_size == 0 {
            return invalid("keys.cache_size must be at least 1".into());
        }
        if let Some(dir) = &self.http.key_dir {
            let (keys, state) = (lexical_absolute(dir), lexical_absolute(&self.state_dir));
            if state.starts_with(&keys) {
                return invalid(format!(
                    "http.key_dir {} is the state directory or holds it: key files are \
                     served from it, and the state directory holds the database",
                    dir.display()
                ));
            }
            if keys.starts_with(&state) && keys != state.join("keys") {
                return invalid(format!(
                    "http.key_dir {} is inside the state directory: leave it out to use \
                     <state_dir>/keys, or choose a directory elsewhere",
                    dir.display()
                ));
            }
        }
        let mut warnings = Vec::new();
        if k.allow_private {
            warnings.push(
                "keys.allow_private is on: key files may be fetched from loopback and \
                 private addresses (4.4)"
                    .into(),
            );
        }
        if l.sign_in_secs < MIN_SIGN_IN_SECS {
            warnings.push(format!(
                "limits.sign_in_secs is {}; the spec recommends at least {MIN_SIGN_IN_SECS} (4.1)",
                l.sign_in_secs
            ));
        }
        Ok(warnings)
    }

    /// The identity domain (4.6), if the server has one.
    pub fn identity_domain(&self) -> Option<Domain> {
        self.identity_domain.as_deref().and_then(|d| d.parse().ok())
    }

    /// The operators from the configuration (10.1), leaving out any that
    /// are not identities (see [`validate`](Self::validate)).
    pub fn operators(&self) -> Vec<Identity> {
        self.operators
            .iter()
            .filter_map(|op| op.parse().ok())
            .collect()
    }

    /// The path of the SQLite database.
    pub fn database_path(&self) -> PathBuf {
        self.state_dir.join("risala.db")
    }

    /// The key file directory: `http.key_dir`, or `<state_dir>/keys`.
    pub fn key_dir(&self) -> PathBuf {
        self.http
            .key_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("keys"))
    }
}

/// `path` made absolute against the current directory, with `.` and `..`
/// resolved by its components alone. Symbolic links are not followed, so
/// two paths through different links still look different.
fn lexical_absolute(path: &Path) -> PathBuf {
    use std::path::Component;
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_owned());
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
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
        assert_eq!(c.identity_domain, None);
        assert!(!c.server.registration);
        assert_eq!(c.room_creation, RoomCreation::Identities);
        assert_eq!(c.limits.registrations_per_hour, 5);
        assert_eq!(c.limits.reports_per_hour, 30);
        assert_eq!(c.limits.presence_offline_secs, 30);
        assert_eq!(c.limits.presence_batch_ms, 1000);
        assert_eq!(c.limits.typing_interval_ms, 1000);
        assert_eq!(c.limits.max_blocks, 1000);
    }

    #[test]
    fn identity_settings() {
        let c = Config::parse(
            r##"
            identity_domain = "Example.org"
            room_creation = "operators"
            operators = ["alice@example.org"]
            [server]
            registration = true
            [limits]
            registrations_per_hour = 0
            "##,
        )
        .unwrap();
        assert!(c.validate().is_ok());
        assert_eq!(c.identity_domain().unwrap().as_str(), "example.org");
        assert_eq!(c.room_creation, RoomCreation::Operators);
        assert!(c.server.registration);
        assert_eq!(c.limits.registrations_per_hour, 0);
        assert_eq!(c.operators()[0].to_string(), "alice@example.org");
        assert!(Config::parse("room_creation = \"everyone\"").is_err());
        for (text, what) in [
            ("identity_domain = \"not a domain\"", "identity_domain"),
            ("identity_domain = \"127.0.0.1\"", "identity_domain"),
            ("operators = [\"~sam\"]", "operator"),
            ("operators = [\"example.org\"]", "operator"),
        ] {
            match Config::parse(text).unwrap().validate() {
                Err(ConfigError::Invalid(m)) => assert!(m.contains(what), "{m}"),
                other => panic!("{text}: {other:?}"),
            }
        }
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
        invalid(|l| l.presence_batch_ms = 0, "presence_batch_ms");
        invalid(|l| l.max_blocks = 0, "max_blocks");
        assert!(with(|l| l.presence_offline_secs = 0).is_ok());
        assert!(with(|l| l.typing_interval_ms = 0).is_ok());
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
    fn keys_and_http() {
        let c = Config::default();
        assert!(!c.keys.allow_private);
        assert_eq!(c.keys.fetch_timeout_secs, 10);
        assert!(c.http.listen.is_empty());
        assert_eq!(c.key_dir(), PathBuf::from("./keys"));

        let c = Config::parse(
            r#"
            state_dir = "/var/lib/risala"
            [keys]
            allow_private = true
            fetch_timeout_secs = 5
            cache_size = 100
            extra_roots = ["ca.pem"]
            [http]
            listen = ["[::]:443"]
            key_dir = "/srv/keys"
            [[http.certs]]
            cert = "a.pem"
            key = "b.pem"
            "#,
        )
        .unwrap();
        assert!(c.keys.allow_private);
        assert_eq!(c.keys.fetch_timeout_secs, 5);
        assert_eq!(c.keys.cache_size, 100);
        assert_eq!(c.keys.extra_roots, [PathBuf::from("ca.pem")]);
        assert_eq!(c.http.listen[0].port(), 443);
        assert_eq!(c.http.certs.len(), 1);
        assert_eq!(c.key_dir(), PathBuf::from("/srv/keys"));
        let warnings = c.validate().unwrap();
        assert!(warnings[0].contains("allow_private"), "{warnings:?}");

        assert!(Config::parse("[http]\nlisten = []\nbogus = 1").is_err());
        assert!(Config::parse("[keys]\nbogus = 1").is_err());
        let invalid = |f: fn(&mut KeysConfig), what: &str| {
            let mut c = Config::default();
            f(&mut c.keys);
            match c.validate() {
                Err(ConfigError::Invalid(m)) => assert!(m.contains(what), "{m}"),
                other => panic!("{what}: {other:?}"),
            }
        };
        invalid(|k| k.fetch_timeout_secs = 0, "fetch_timeout_secs");
        invalid(|k| k.fetch_timeout_secs = 11, "fetch_timeout_secs");
        invalid(|k| k.cache_size = 0, "cache_size");
    }

    /// The key directory is served by a web server, so it may not be or
    /// hold the state directory, which holds the database, nor be any
    /// other part of it but `<state_dir>/keys`.
    #[test]
    fn key_dir_stays_out_of_the_state_directory() {
        let check = |state: &str, keys: Option<&str>| {
            let mut c = Config {
                state_dir: state.into(),
                ..Config::default()
            };
            c.http.key_dir = keys.map(PathBuf::from);
            c.validate()
        };
        for (state, keys) in [
            ("/var/lib/risala", None),
            ("/var/lib/risala", Some("/var/lib/risala/keys")),
            ("/var/lib/risala", Some("/var/lib/risala/./keys/")),
            ("/var/lib/risala", Some("/srv/www/.well-known/risala")),
            ("/var/lib/risala", Some("/var/lib/risala-keys")),
            ("state", Some("keys")),
        ] {
            assert!(check(state, keys).is_ok(), "{state} {keys:?}");
        }
        for (state, keys, what) in [
            (
                "/var/lib/risala",
                "/var/lib/risala",
                "is the state directory",
            ),
            (
                "/var/lib/risala",
                "/var/lib/risala/",
                "is the state directory",
            ),
            (
                "/var/lib/risala",
                "/var/lib/risala/keys/..",
                "is the state directory",
            ),
            ("/var/lib/risala", "/var/lib", "holds it"),
            ("/var/lib/risala", "/", "holds it"),
            (
                "/var/lib/risala",
                "/var/lib/risala/selfsigned",
                "inside the state",
            ),
            (
                "/var/lib/risala",
                "/var/lib/risala/keys/more",
                "inside the state",
            ),
            (".", ".", "is the state directory"),
            ("state", "./state", "is the state directory"),
        ] {
            match check(state, Some(keys)) {
                Err(ConfigError::Invalid(m)) => assert!(m.contains(what), "{keys}: {m}"),
                other => panic!("{state} {keys}: {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(Config::parse("hostnme = \"x\"").is_err());
    }
}

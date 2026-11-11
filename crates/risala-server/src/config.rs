//! The server's configuration file, in TOML (PLAN.md 3.2).
//!
//! Every field has a default, so an empty file is a working development
//! server: it listens on port 7472, keeps its database and a generated
//! self-signed certificate in the current directory, and allows
//! anonymous connections and guests.
//!
//! ```toml
//! hostname = "chat.example.org"
//! listen = ["[::]:7472"]
//! state_dir = "/var/lib/risala"
//! operators = ["alice@example.org"]
//! identity_domain = "example.org"
//! room_creation = "identities"
//!
//! [[tls.certs]]
//! cert = "/var/lib/acme/chat.example.org/fullchain.pem"
//! key = "/var/lib/acme/chat.example.org/key.pem"
//!
//! [server]
//! welcome = "Welcome!"
//! anon = true
//! guests = true
//! registration = true
//! retention = 30
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
//!
//! [log]
//! k = 2
//! witnesses = [
//!     { vkey = "witness.example/w+1234abcd+Bg…", url = "https://witness.example/w" },
//! ]
//!
//! [witness]
//! enabled = false
//!
//! [files]
//! url = "https://chat.example.org"
//! max_upload = 104857600
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use risala_proto::frame::{MAX_LONG_SERVER_LINE, MAX_SERVER_LINE};
use risala_proto::names::{Domain, Identity};
use risala_proto::types::MIN_RETENTION_DAYS;
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
    /// The server's identity domain (4.7): REGISTER creates identities
    /// `<name>@<identity_domain>`, which the server hosts, and INFO reports
    /// it (8.5). The server must then publish their key files at
    /// `https://<identity_domain>/.well-known/risala/<name>` (4.3). Without
    /// it, the server hosts no identities, and REGISTER gets
    /// `ERR not-supported`. Whether REGISTER is open is the server setting
    /// `registration` (10.6), first set from `server.registration`.
    pub identity_domain: Option<String>,
    /// Who may create public rooms, with the second form of CREATE (5.2,
    /// 6.1). Guests never may (4.2). Mailboxes of direct conversations and
    /// private rooms are not affected: the server cannot tell who creates
    /// them.
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
    /// The HTTPS listener and the key file directory (4.7).
    pub http: HttpConfig,
    /// The key log and its witnesses (4.5).
    pub log: LogConfig,
    /// Acting as a witness for other servers' key logs (4.10).
    pub witness: WitnessConfig,
    /// Push notifications (Section 9).
    pub push: PushConfig,
    /// Blobs, uploaded files and backups (5.6, 12.12, 12.13).
    pub files: FilesConfig,
}

/// The key log (4.5): its URL, its number, and the witnesses asked to
/// cosign its checkpoints. The log is served by the HTTPS listener, at
/// `/risala-log/<n>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Whether the server keeps a key log. The default is to keep one when
    /// it has an `identity_domain`, since every server that hosts
    /// identities must (4.5).
    pub enabled: Option<bool>,
    /// Where the HTTPS listener is reached, as `https://<host>[:<port>]`,
    /// with no path. The log's URL prefix is this and `/risala-log/<n>`.
    /// The default is `https://<hostname>`.
    pub url: Option<String>,
    /// The log's number, `<n>` in its origin `<hostname>/risala-log/<n>`.
    /// Raising it hands the log off to the next one (4.5), one number at a
    /// time; it can never go down. The default keeps the current log, or
    /// starts log 1.
    pub number: Option<u64>,
    /// The witnesses asked to cosign each checkpoint (4.5, 4.10).
    pub witnesses: Vec<LogWitness>,
    /// How many cosignatures make a checkpoint witnessed, so that the log
    /// serves it. The default is more than half of `witnesses`.
    pub k: Option<usize>,
    /// How often the log gets a new witnessed checkpoint when nothing is
    /// added, in seconds: 60 to 43200. Devices want cosignatures less than
    /// 24 hours old (4.5).
    pub refresh_secs: u64,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            enabled: None,
            url: None,
            number: None,
            witnesses: Vec::new(),
            k: None,
            refresh_secs: 3600,
        }
    }
}

/// A witness the key log sends its checkpoints to (4.5).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogWitness {
    /// The witness's signed-note verifier key, of type `0x06`.
    pub vkey: String,
    /// Its URL prefix, `https://…`, without a `/` at the end:
    /// `add-checkpoint` and `risala/handoff` go under it.
    pub url: String,
}

/// Acting as a witness for other servers' key logs (4.10), at
/// `/risala-witness` on the HTTPS listener.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WitnessConfig {
    /// Whether the server is a witness. Off by default.
    pub enabled: bool,
    /// The name of the witness's key. The default is
    /// `<hostname>/risala-witness`.
    ///
    /// Enrolment needs no configuration: the witness fetches the key of a
    /// host's first log from `https://<host>/risala-log/1/risala/key`, and
    /// takes later logs' keys from hand-offs (4.10).
    pub name: Option<String>,
}

/// Push notifications (Section 9): PUSH ADD, and sending pushes over
/// HTTPS (9.3).
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PushConfig {
    /// Whether PUSH is supported (8.5). Off, PUSH gets `ERR not-supported`.
    pub enabled: bool,
    /// Lets the server send pushes to loopback, private, link-local and
    /// other special-purpose addresses (9.3, 4.4). Off by default; for
    /// tests and internal deployments only.
    pub allow_private: bool,
    /// PEM files of CA certificates to trust besides the public ones built
    /// in, for push URLs. For tests and private deployments.
    pub extra_roots: Vec<PathBuf>,
    /// The most subscriptions one mailbox may have (9.1). At least 1. The
    /// server never applies less than one per leaf the group may hold
    /// (6.1): 4,096, or 32,768 for a public room.
    pub max_per_mailbox: usize,
    /// The most mailbox subscriptions one connection may add (9.1). At
    /// least 1.
    pub max_per_connection: usize,
    /// The most account subscriptions one device may have (9.1). At least
    /// 1.
    pub max_per_device: usize,
    /// The most mailbox subscriptions one network address may add in an
    /// hour (9.1). IPv6 addresses count by their /64. 0 means no limit.
    pub adds_per_hour: u32,
    /// The most pushes on their way at once, to everyone (9.1): further
    /// ones wait. At least 1.
    pub max_in_flight: usize,
    /// The most pushes sent to one host in a second, whatever their paths
    /// (9.1), so that subscriptions cannot point the server at a host to
    /// flood it. Further ones wait. At least 1.
    pub per_host_per_second: u32,
}

impl Default for PushConfig {
    fn default() -> Self {
        PushConfig {
            enabled: true,
            allow_private: false,
            extra_roots: Vec::new(),
            max_per_mailbox: 4_096,
            max_per_connection: 1024,
            max_per_device: 16,
            adds_per_hour: 1024,
            max_in_flight: 256,
            per_host_per_second: 50,
        }
    }
}

/// Blobs (12.12), uploaded files (5.6) and backups (12.13): where they are
/// kept, the URLs they are reached at, and their limits.
///
/// Their bytes travel over HTTPS, through the listener of `[http]`. Without
/// one, and without `url`, the server offers no blobs or uploads: BLOB,
/// UPLOAD and BACKUP PUT get `ERR not-supported`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesConfig {
    /// The origin clients reach the HTTPS listener at, `https://<host>` or
    /// `https://<host>:<port>`, from which the `put`, `get` and `del` URLs
    /// and the `blobs` prefix (8.5) are made. The default is
    /// `https://<hostname>`, with the port of the first address in
    /// `http.listen` unless it is 443. Set it when a proxy stands in front
    /// of the listener.
    pub url: Option<String>,
    /// Where the bytes of blobs and files are kept. The default is
    /// `<state_dir>/files`.
    pub dir: Option<PathBuf>,
    /// The largest file UPLOAD accepts, in bytes (5.6). 0 offers no
    /// uploads (`upload=no`, 8.5).
    pub max_upload: u64,
    /// The largest blob BLOB accepts, in bytes (12.12): at least
    /// [`MIN_MAX_BLOB`], 256 MiB.
    pub max_blob: u64,
    /// The most bytes one identity may ask to store with BLOB in a day
    /// (12.12). 0 means no limit.
    pub identity_bytes_per_day: u64,
    /// The most bytes one identity's backup may name, its lists included
    /// (12.13). Larger backups get `ERR too-long`.
    pub max_backup: u64,
    /// The most blobs one backup may name besides its first archive
    /// (12.13): its list is read in one piece. More get `ERR too-long`.
    pub max_backup_blobs: u64,
    /// The most Welcomes pending for one device (12.8). More get
    /// `ERR rate-limited`.
    pub max_pending_welcomes: u64,
    /// The slowest a blob or file may go over HTTPS, upload or download,
    /// in bytes a second averaged over `min_rate_secs`, besides the
    /// deadline for the whole transfer (10.6, 12.12): a client that keeps
    /// below it is cut off, so that slow clients cannot hold the
    /// listener's transfer slots for long. A transfer smaller than
    /// `min_rate * min_rate_secs` bytes must finish within
    /// `min_rate_secs`. 0 turns it off.
    pub min_rate: u64,
    /// The seconds [`min_rate`](Self::min_rate) is averaged over: at
    /// least 1.
    pub min_rate_secs: u64,
    /// The most HTTPS connections that may send or receive blobs and
    /// files at once; further blob and file requests get 503. At most
    /// [`MAX_HTTP_TRANSFERS`](crate::http::server::MAX_HTTP_TRANSFERS), so
    /// that the rest of the listener's connections stay for key files, log
    /// tiles and the witness (4.3, 4.5, 4.10).
    pub max_transfers: usize,
}

/// The least [`FilesConfig::max_blob`] may be: 256 MiB (12.12).
pub const MIN_MAX_BLOB: u64 = 256 * 1024 * 1024;

/// The least `limits.max_room_blob` a server may set (12.12): it holds the
/// largest resync commit of a public room (12.7).
pub const MIN_ROOM_BLOB: u64 = 40 * 1024 * 1024;

impl Default for FilesConfig {
    fn default() -> Self {
        FilesConfig {
            url: None,
            dir: None,
            max_upload: 100 * 1024 * 1024,
            max_blob: MIN_MAX_BLOB,
            identity_bytes_per_day: 16 * 1024 * 1024 * 1024,
            max_backup: 16 * 1024 * 1024 * 1024,
            max_backup_blobs: 100_000,
            max_pending_welcomes: 1000,
            min_rate: 16 * 1024,
            min_rate_secs: 30,
            max_transfers: crate::http::server::MAX_HTTP_TRANSFERS,
        }
    }
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
    /// public CAs. The key log's requests to its witnesses (4.5) trust
    /// them too.
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

/// Who may create public rooms (5.2, 6.1): `room_creation` in the
/// configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoomCreation {
    /// Any identity. The default.
    #[default]
    Identities,
    /// Only identities the server hosts (4.7), and operators.
    Hosted,
    /// Only the server's operators (10.1).
    Operators,
    /// Nobody: the server has no public rooms.
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
    /// Whether anonymous connections may be opened (4.2). A server that
    /// allows none cannot carry conversations (8.5).
    pub anon: bool,
    /// Whether guests may connect (4.2).
    pub guests: bool,
    /// Whether REGISTER is open (10.6). It takes effect only with an
    /// `identity_domain`.
    pub registration: bool,
    /// The retention period, in days (7.5): at least 7, and the spec
    /// recommends at least 30.
    pub retention: u32,
}

/// Limits and timers. Defaults follow the spec where it names a value.
///
/// Limits per network address (an IPv4 address, or an IPv6 /64) are set
/// for many people behind one address, as behind a Tor exit or a carrier
/// NAT (2.1, 4.2, 14): connections, guests, room joins and pending
/// proposals, KEYS PUT and AUTHs that fetch key files. They are the free
/// tier; past them a client will go on by proof of work, from M6a (PLAN
/// items 42 and 63).
///
/// The other limits that count by address, alone or with the connection
/// or identity, keep their defaults as they are (PLAN item 66): posts,
/// commits, creates and guests' reports, KEYPKG GET, which counts by
/// identity, and HTTPS connections (`https_connections_per_address` and
/// `https_connections_per_prefix`, PLAN items 67 and 68). Operators tune
/// them to their users.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Seconds a new connection has to sign in or become anonymous or a
    /// guest (4.1: at least 120).
    pub sign_in_secs: u64,
    /// Seconds a guest's session waits to be resumed after its connection
    /// closes, before it ends and its public rooms get GONE (4.2, 6.1). At
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
    /// The most posts one FETCH returns, whatever the client asks for
    /// (7.1).
    pub max_page: u64,
    /// The most rooms one LIST page returns (6.1).
    pub max_list: u64,
    /// The most identities REGISTER may create from one network address in
    /// an hour (4.7, 14). IPv6 addresses count by their /64. Further
    /// REGISTERs get `ERR rate-limited`. 0 means no limit.
    pub registrations_per_hour: u32,
    /// The most public rooms one identity may create in a day (5.2, 14),
    /// since anyone who controls a domain can make any number of
    /// identities. Further creations get `ERR rate-limited`. Operators are
    /// not limited. 0 means no limit.
    pub rooms_per_day: u32,
    /// The most reports one identity, or the guests of one network, may
    /// make in an hour (5.8: servers SHOULD rate-limit reports). Guests
    /// count by their address, IPv6 addresses by their /64, since a guest
    /// can take a new name at will. Further REPORTs get `ERR
    /// rate-limited`. 0 means no limit.
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
    /// The most ordinary KeyPackages the server keeps for one device
    /// (12.5: devices keep about ten). KEYPKG ADD beyond it gets
    /// `ERR forbidden`. A device's last-resort KeyPackage does not count.
    pub max_key_packages: usize,
    /// The most KEYPKG GET one identity may send in an hour (12.5: servers
    /// SHOULD rate-limit it, since each one uses KeyPackages up). Further
    /// ones get `ERR rate-limited`. 0 means no limit.
    pub key_package_gets_per_hour: u32,
    /// The largest KeyPackage KEYPKG ADD takes, in bytes once decoded
    /// (12.5). Larger ones get `ERR too-long`. At least
    /// [`MIN_KEY_PACKAGE_BYTES`], since 12.5 allows no lower limit.
    pub max_key_package_bytes: usize,
    /// The most bytes one mailbox keeps at once, counting its posts and
    /// the files and blobs stored with its token (7.5), reported by INFO
    /// as `quota=`. Over it, the mailbox's oldest posts expire early to
    /// make room for a post, file or blob; a post larger than what its
    /// files and blobs leave, or a file or blob that does not fit beside
    /// them, gets `ERR rate-limited`. At least [`MIN_MAX_BLOB`], so that a
    /// mailbox holds a blob of the size every server takes (12.12).
    pub mailbox_quota: u64,
    /// The most bytes one network address may store in an hour, counting
    /// POST, UPLOAD and BLOB together (7.5). Further ones get
    /// `ERR rate-limited`. IPv6 addresses count by their /64. 0 means no
    /// limit. At the default of 1 GiB, one address alone takes about 9
    /// days to fill what the default `max_stored_bytes` leaves files.
    pub address_bytes_per_hour: u64,
    /// The most mailboxes one connection, and one network address, may
    /// create in an hour (5.2). 0 means no limit.
    pub creates_per_hour: u32,
    /// The most posts one connection, and one network address, may send in
    /// a minute (4.2, 5.2). 0 means no limit.
    pub posts_per_minute: u32,
    /// The most commits and TOKEN commands one connection, and one network
    /// address, may send in an hour (7.2). 0 means no limit.
    pub commits_per_hour: u32,
    /// The most mailboxes one connection may follow (7.1): at least 1,000.
    pub max_follows: usize,
    /// The most bytes the server stores in all: blobs, uploaded files and
    /// kept posts (7.5), apart from what open reports keep
    /// (`max_reported_bytes`). It is checked on UPLOAD and BLOB only,
    /// which get `ERR rate-limited` for everyone once what is stored is
    /// within `post_reserve_bytes` of it, until enough expires, so that a
    /// few addresses cannot fill the disk. Posts are never refused for
    /// it: the reserve keeps room for them, and each mailbox's quota and
    /// each address's window bound them. 0 means no limit.
    pub max_stored_bytes: u64,
    /// The bytes of `max_stored_bytes` that UPLOAD and BLOB leave for
    /// posts, inline ones and commits, so that conversations go on when
    /// files and blobs have filled the rest (7.5). Less than
    /// `max_stored_bytes`, unless that is 0.
    pub post_reserve_bytes: u64,
    /// The most bytes of blobs and uploaded files that open reports keep
    /// until they are resolved (5.8), counted apart from
    /// `max_stored_bytes`. A report whose blobs or files would go over it
    /// is still made, without keeping those past their retention, and the
    /// server logs a warning (PLAN item 66). 0 means no limit.
    pub max_reported_bytes: u64,
    /// The most bytes of blobs the server reads into memory at once, for
    /// everyone (12.12): a public room's commits, GroupInfos and trees and
    /// KEYS PUT's records. Readers wait for room beyond it. At least 1 MiB.
    pub blob_memory: u64,
    /// The largest blob a public room's commit or proposal, or a commit's
    /// GroupInfo, may be (6.1, 12.12), since the server reads these whole
    /// to check them. Other posts' blobs are not read, only their framing.
    /// A new room's GroupInfo and tree are never blobs, nor is a post with
    /// the token `-` (an external commit or proposal) or its GroupInfo,
    /// except on a signed-in connection to a public room, where a device
    /// posts its external commits (PLAN items 67 to 69). At least 40 MiB,
    /// which holds the largest resync commit (12.7, 12.12).
    pub max_room_blob: u64,
    /// The most KEYS PUT one network address may send in an hour (4.7: a
    /// server MUST rate-limit it per network address). 0 means no limit.
    pub keys_puts_per_hour: u32,
    /// Whether the server logs identities it does not host whose key files
    /// name its log (4.7). Off, their KEYS PUT gets `ERR not-supported`.
    pub log_outside_identities: bool,
    /// The most identities the server does not host that it starts to log
    /// in a day, per registered domain (the last two labels of the
    /// identity's domain), since each one adds entries to the log for
    /// ever (4.5, 4.7). Further ones get `ERR rate-limited`. 0 means no
    /// limit.
    pub outside_identities_per_day: u32,
    /// The most risala connections one network address may have open at
    /// once (4.2). IPv6 addresses count by their /64. Others are closed as
    /// soon as they are accepted. 0 means no limit.
    pub connections_per_address: usize,
    /// The most HTTPS connections one network address may have open at
    /// once, to the `[http]` listener (4.3, 5.6, 12.12), so that one
    /// client that opens connections and sends nothing cannot take them
    /// all. IPv6 addresses count by their /64; see also
    /// `https_connections_per_prefix`. Others are closed as soon as they
    /// are accepted. 0 means no limit.
    pub https_connections_per_address: usize,
    /// The most HTTPS connections one IPv6 /48 may have open at once, to
    /// the `[http]` listener, whatever each of its addresses has: a /48
    /// holds 65,536 /64s, each of which `https_connections_per_address`
    /// counts as an address. IPv4 addresses have no such prefix. Others
    /// are closed as soon as they are accepted. 0 means no limit (PLAN
    /// item 68).
    pub https_connections_per_prefix: usize,
    /// The most guest sessions one network address may have at once,
    /// those waiting to be resumed included (4.2). Further GUESTs get
    /// `ERR rate-limited`. 0 means no limit.
    pub guests_per_address: usize,
    /// The most AUTHs of identities whose key file is not cached that one
    /// network address may send in an hour, since each one may make the
    /// server fetch a key file (4.4, 4.6). Further ones get
    /// `ERR rate-limited`. 0 means no limit.
    pub fetching_auths_per_hour: u32,
    /// The most join proposals with `-` one network address may post in
    /// an hour, to all public rooms together (6.1, 12.6). Further ones get
    /// `ERR rate-limited`. 0 means no limit.
    pub joins_per_hour: u32,
    /// The most proposals from one network address that may be pending in
    /// one epoch of a public room (12.6), so that one address cannot fill
    /// the epoch's proposals and keep others from joining. 0 means no
    /// limit.
    pub pending_per_address: u32,
}

/// The most lines a command's response has besides a full page of posts
/// (FETCH) or rooms (LIST): the live posts it causes, and the final
/// response.
pub const REPLY_MARGIN: usize = 16;

/// The room a connection's queue keeps for live events from other people
/// while it holds a response of the largest size (see
/// [`Limits::command_room`]).
pub const FANOUT_ROOM: usize = 128;

/// The least `limits.sign_in_secs` the spec recommends (4.1).
pub const MIN_SIGN_IN_SECS: u64 = 120;

/// The least `limits.guest_resume_secs` the spec allows (4.2).
pub const MIN_GUEST_RESUME_SECS: u64 = 120;

/// The fewest mailboxes [`Limits::max_follows`] may allow (7.1).
pub const MIN_FOLLOWS: usize = 1000;

/// The lowest [`Limits::max_key_package_bytes`] may be (12.5).
pub const MIN_KEY_PACKAGE_BYTES: usize = 16 * 1024;

impl Limits {
    /// The most lines one command's response queues: a full FETCH or LIST
    /// page, plus [`REPLY_MARGIN`].
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
    /// So a client that sends many commands at once, such as a FETCH for
    /// every mailbox it follows (7.4), gets them answered as fast as it reads,
    /// and is not dropped as too slow. Live events from other people still
    /// drop a connection whose queue is full.
    pub fn command_room(&self) -> usize {
        self.reply_lines().saturating_add(FANOUT_ROOM)
    }

    /// [`command_room`](Self::command_room) in bytes: that many lines of
    /// the longest a server line may be ([`MAX_SERVER_LINE`]), but at least
    /// room for one long line ([`MAX_LONG_SERVER_LINE`], 2.3) and
    /// [`FANOUT_ROOM`] lines besides. A command that sends several long
    /// lines, such as KEYPKG GET or WELCOME LIST (Section 12), waits for
    /// this much room again before each one after the first.
    pub fn command_room_bytes(&self) -> usize {
        let long = FANOUT_ROOM
            .saturating_mul(MAX_SERVER_LINE)
            .saturating_add(MAX_LONG_SERVER_LINE);
        self.command_room()
            .saturating_mul(MAX_SERVER_LINE)
            .max(long)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            hostname: "localhost".into(),
            listen: vec![SocketAddr::from(([0, 0, 0, 0], risala_proto::DEFAULT_PORT))],
            state_dir: PathBuf::from("."),
            operators: Vec::new(),
            identity_domain: None,
            room_creation: RoomCreation::default(),
            tls: TlsConfig::default(),
            server: ServerConfig::default(),
            limits: Limits::default(),
            keys: KeysConfig::default(),
            http: HttpConfig::default(),
            log: LogConfig::default(),
            witness: WitnessConfig::default(),
            push: PushConfig::default(),
            files: FilesConfig::default(),
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
            anon: true,
            guests: true,
            registration: false,
            retention: 30,
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
            max_key_packages: 100,
            key_package_gets_per_hour: 600,
            max_key_package_bytes: 64 * 1024,
            mailbox_quota: 4 * 1024 * 1024 * 1024,
            address_bytes_per_hour: 1024 * 1024 * 1024,
            creates_per_hour: 120,
            posts_per_minute: 600,
            commits_per_hour: 600,
            max_follows: 4096,
            max_stored_bytes: 256 * 1024 * 1024 * 1024,
            post_reserve_bytes: 32 * 1024 * 1024 * 1024,
            max_reported_bytes: 16 * 1024 * 1024 * 1024,
            blob_memory: 1024 * 1024 * 1024,
            max_room_blob: 64 * 1024 * 1024,
            keys_puts_per_hour: 240,
            log_outside_identities: true,
            outside_identities_per_day: 100,
            connections_per_address: 256,
            https_connections_per_address: crate::http::server::DEFAULT_HTTP_PER_ADDRESS,
            https_connections_per_prefix: crate::http::server::DEFAULT_HTTP_PER_PREFIX,
            guests_per_address: 64,
            fetching_auths_per_hour: 480,
            joins_per_hour: 120,
            pending_per_address: 32,
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
            ("max_key_packages", l.max_key_packages as u64),
            ("max_room_blob", l.max_room_blob),
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
        if self.server.retention < MIN_RETENTION_DAYS {
            return invalid(format!(
                "server.retention is {} days, but must be at least {MIN_RETENTION_DAYS} (7.5)",
                self.server.retention
            ));
        }
        if l.max_key_package_bytes < MIN_KEY_PACKAGE_BYTES {
            return invalid(format!(
                "limits.max_key_package_bytes is {}, but must be at least {MIN_KEY_PACKAGE_BYTES} (12.5)",
                l.max_key_package_bytes
            ));
        }
        if l.max_stored_bytes > 0 && l.post_reserve_bytes >= l.max_stored_bytes {
            return invalid(format!(
                "limits.post_reserve_bytes is {}, but must be less than limits.max_stored_bytes ({}), \
                 or no blob or file could be stored (7.5)",
                l.post_reserve_bytes, l.max_stored_bytes
            ));
        }
        if l.blob_memory < 1024 * 1024 {
            return invalid("limits.blob_memory must be at least 1 MiB".into());
        }
        if l.max_follows < MIN_FOLLOWS {
            return invalid(format!(
                "limits.max_follows is {}, but must be at least {MIN_FOLLOWS} (7.1)",
                l.max_follows
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
                 (see limits.out_queue) of up to {MAX_SERVER_LINE} bytes, or one line \
                 of MLS data (up to {MAX_LONG_SERVER_LINE} bytes) and {FANOUT_ROOM} lines \
                 for live events, whichever is more",
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
        let p = &self.push;
        for (name, value) in [
            ("max_per_mailbox", p.max_per_mailbox),
            ("max_per_connection", p.max_per_connection),
            ("max_per_device", p.max_per_device),
            ("max_in_flight", p.max_in_flight),
            ("per_host_per_second", p.per_host_per_second as usize),
        ] {
            if value == 0 {
                return invalid(format!("push.{name} must be at least 1 (9.1)"));
            }
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
        let f = &self.files;
        if f.max_blob < MIN_MAX_BLOB {
            return invalid(format!(
                "files.max_blob is {}, but must be at least {MIN_MAX_BLOB} (12.12)",
                f.max_blob
            ));
        }
        if let Some(url) = &f.url
            && url.parse::<risala_proto::server::FileOrigin>().is_err()
        {
            return invalid(format!(
                "files.url {url:?} is not https://<host> or https://<host>:<port>"
            ));
        }
        if f.min_rate_secs == 0 {
            return invalid("files.min_rate_secs must be at least 1".into());
        }
        let most = crate::http::server::MAX_HTTP_TRANSFERS;
        if !(1..=most).contains(&f.max_transfers) {
            return invalid(format!(
                "files.max_transfers is {}, but must be 1 to {most}, so that HTTPS connections \
                 stay for key files, log tiles and the witness",
                f.max_transfers
            ));
        }
        for (name, value) in [
            ("max_backup", f.max_backup),
            ("max_pending_welcomes", f.max_pending_welcomes),
        ] {
            if value == 0 {
                return invalid(format!("files.{name} must be at least 1"));
            }
        }
        let mut warnings = crate::core::keylog::check_config(self).map_err(ConfigError::Invalid)?;
        if k.allow_private {
            warnings.push(
                "keys.allow_private is on: key files may be fetched from loopback and \
                 private addresses (4.4)"
                    .into(),
            );
        }
        if self.push.allow_private {
            warnings.push(
                "push.allow_private is on: pushes may be sent to loopback and private \
                 addresses (9.3)"
                    .into(),
            );
        }
        // A warning, not an error, so that tests and small servers may set
        // less; such a server keeps no blob of 12.12's minimum size for a
        // mailbox (a choice to confirm).
        if self.limits.mailbox_quota < MIN_MAX_BLOB {
            warnings.push(format!(
                "limits.mailbox_quota is {}; a mailbox then cannot hold a blob of {MIN_MAX_BLOB} \
                 bytes, the least every server must take (7.5, 12.12)",
                self.limits.mailbox_quota
            ));
        }
        if l.max_room_blob < MIN_ROOM_BLOB {
            warnings.push(format!(
                "limits.max_room_blob is {}; a large public room's resync commit, up to \
                 {MIN_ROOM_BLOB} bytes, would then be refused, and the room could not recover \
                 (12.7, 12.12)",
                l.max_room_blob
            ));
        }
        if l.blob_memory < l.max_room_blob {
            warnings.push(format!(
                "limits.blob_memory is {}, less than limits.max_room_blob ({}): a public room's \
                 commits that large could never be read (12.12)",
                l.blob_memory, l.max_room_blob
            ));
        }
        if self.server.retention < 30 {
            warnings.push(format!(
                "server.retention is {} days; the spec recommends at least 30 (7.5)",
                self.server.retention
            ));
        }
        if l.sign_in_secs < MIN_SIGN_IN_SECS {
            warnings.push(format!(
                "limits.sign_in_secs is {}; the spec recommends at least {MIN_SIGN_IN_SECS} (4.1)",
                l.sign_in_secs
            ));
        }
        Ok(warnings)
    }

    /// The identity domain (4.7), if the server has one.
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

    /// Where blobs and files are kept: `files.dir`, or
    /// `<state_dir>/files`.
    pub fn files_dir(&self) -> PathBuf {
        self.files
            .dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("files"))
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
        assert!(c.server.anon);
        assert!(c.server.guests);
        assert_eq!(c.server.retention, 30);
        assert_eq!(c.limits.sign_in_secs, 120);
        assert_eq!(c.limits.guest_resume_secs, 300);
        assert_eq!(c.identity_domain, None);
        assert!(!c.server.registration);
        assert_eq!(c.room_creation, RoomCreation::Identities);
        assert_eq!(c.limits.registrations_per_hour, 5);
        assert_eq!(c.limits.reports_per_hour, 30);
        assert_eq!(c.limits.presence_offline_secs, 30);
        assert_eq!(c.limits.presence_batch_ms, 1000);
        assert_eq!(c.limits.max_key_packages, 100);
        assert_eq!(c.limits.key_package_gets_per_hour, 600);
        assert_eq!(c.limits.max_key_package_bytes, 65536);
        assert_eq!(c.limits.https_connections_per_address, 16);
        assert_eq!(c.limits.https_connections_per_prefix, 64);
        let c = Config::parse("[limits]\nhttps_connections_per_prefix = 0").unwrap();
        assert_eq!(c.limits.https_connections_per_prefix, 0);
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
            [[tls.certs]]
            cert = "a.pem"
            key = "b.pem"
            [server]
            anon = false
            guests = false
            retention = 60
            [limits]
            out_queue = 8
            "##,
        )
        .unwrap();
        assert_eq!(c.listen[0].port(), 7000);
        assert_eq!(c.tls.certs.len(), 1);
        assert!(!c.server.anon);
        assert!(!c.server.guests);
        assert_eq!(c.server.retention, 60);
        assert_eq!(c.limits.out_queue, 8);
        // Draft-02's settings are gone.
        assert!(Config::parse("rooms = [\"#general\"]").is_err());
        assert!(Config::parse("[server]\nretention = \"forever\"").is_err());
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
        invalid(|l| l.max_key_packages = 0, "max_key_packages");
        assert!(with(|l| l.presence_offline_secs = 0).is_ok());
        invalid(|l| l.max_key_package_bytes = 16383, "max_key_package_bytes");
        assert!(with(|l| l.max_key_package_bytes = 16384).is_ok());
        invalid(|l| l.max_follows = 999, "max_follows");
        assert!(with(|l| l.max_follows = 1000).is_ok());
        invalid(|l| l.guest_resume_secs = 119, "guest_resume_secs");
        assert!(with(|l| l.guest_resume_secs = 120).is_ok());
        // A mailbox that cannot hold a blob of the size every server takes
        // is warned about (12.12).
        let warnings = with(|l| l.mailbox_quota = MIN_MAX_BLOB - 1).unwrap();
        assert!(warnings.iter().any(|w| w.contains("mailbox_quota")));

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
        // Short pages still leave room for one long line (2.3).
        let short = Limits {
            max_page: 10,
            max_list: 10,
            ..Limits::default()
        };
        assert_eq!(
            short.command_room_bytes(),
            MAX_LONG_SERVER_LINE + FANOUT_ROOM * MAX_SERVER_LINE
        );
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

        // A room blob limit below 12.12's 40 MiB works, but a large room's
        // resync commit would be refused; and blob memory below it could
        // never read one.
        assert_eq!(Config::default().limits.max_room_blob, 64 * 1024 * 1024);
        let warnings = with(|l| l.max_room_blob = MIN_ROOM_BLOB - 1).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("max_room_blob"), "{warnings:?}");
        assert!(
            with(|l| l.max_room_blob = MIN_ROOM_BLOB)
                .unwrap()
                .is_empty()
        );
        let warnings = with(|l| l.blob_memory = 32 * 1024 * 1024).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("blob_memory"), "{warnings:?}");

        // Retention is at least 7 days, and should be at least 30 (7.5).
        let mut c = Config::default();
        c.server.retention = 6;
        assert!(matches!(c.validate(), Err(ConfigError::Invalid(m)) if m.contains("retention")));
        c.server.retention = 7;
        let warnings = c.validate().unwrap();
        assert!(warnings[0].contains("retention"), "{warnings:?}");
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

//! The greeting (4.1) and the final responses OK and ERR (3.6, 3.7).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use super::ServerLine;
use crate::auth::Nonce;
use crate::command::GuestToken;
use crate::error::{ErrorCode, ParseError};
use crate::line::{LineBuilder, Params, Tags, is_token};
use crate::names::{BoxName, Id, Seq, Uid};
use crate::parse::{bad, limit, tag_value, tok};
use crate::types::{FileUrl, MAX_WELCOME, Retention, parse_u64, parse_yes_no, yes_no};

/// Parses the lines of this module; `None` for any other verb.
pub(super) fn parse(
    verb: &str,
    tags: &Tags,
    p: Params<'_>,
) -> Option<Result<ServerLine, ParseError>> {
    Some(match verb {
        "RISALA" => Greeting::parse(p).map(ServerLine::Greeting),
        "OK" => OkResponse::parse(p).map(ServerLine::Ok),
        "ERR" => ErrResponse::parse(tags, p).map(ServerLine::Err),
        _ => return None,
    })
}

/// Writes the lines of this module; `false` for any other line.
pub(super) fn write(line: &ServerLine, b: &mut LineBuilder) -> bool {
    match line {
        ServerLine::Greeting(greeting) => greeting.write(b),
        ServerLine::Ok(ok) => ok.write(b),
        ServerLine::Err(err) => err.write(b),
        _ => return false,
    }
    true
}

// ---------------------------------------------------------------------------
// Greeting

/// The greeting, `RISALA <version> <host> <nonce> [<message...>]` (4.1).
///
/// A client that does not support `version` must close the connection
/// (3.8); the version is kept whatever it is, so that the caller decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// The protocol version, `1` for this spec
    /// ([`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION)).
    pub version: u32,
    /// The hostname from SNI, in lower case. A client signs with the
    /// hostname it sent, not this one (4.6).
    pub host: Host,
    /// The connection's nonce, signed when signing in (4.6): 16 to 64
    /// bytes in lower-case hex.
    pub nonce: Nonce,
    /// The welcome message, escaped; empty if none. At most 512 bytes.
    pub message: String,
}

impl Greeting {
    fn parse(mut p: Params<'_>) -> Result<Greeting, ParseError> {
        let version = u32::try_from(parse_u64(p.token()?)?)
            .map_err(|_| bad("protocol version is out of range"))?;
        let host = tok(&mut p)?;
        let nonce = tok(&mut p)?;
        let message = p.text().to_owned();
        limit(&message, MAX_WELCOME)?;
        Ok(Greeting {
            version,
            host,
            nonce,
            message,
        })
    }

    fn write(&self, b: &mut LineBuilder) {
        b.token(self.version)
            .token(&self.host)
            .token(&self.nonce)
            .text(&self.message);
    }
}

/// The `<host>` of the greeting (4.1): the hostname the client sent in SNI
/// (2.1), in lower case.
///
/// This is a light check, not a [`Domain`](crate::names::Domain): a host
/// may be a single label such as `localhost`. It is 1 to 253 characters
/// of labels separated by `.`, each 1 to 63 characters of `a-z 0-9 -`.
/// An IP address is accepted too, for a server that was reached without
/// SNI and names itself by address. Parsing folds ASCII upper case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Host(String);

impl Host {
    /// The host as written, in lower case (4.1).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Host {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Host, ParseError> {
        let host = s.to_ascii_lowercase();
        if host.parse::<IpAddr>().is_ok() {
            return Ok(Host(host));
        }
        if host.len() > 253 {
            return Err(ParseError::TooLong);
        }
        let label_ok = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if host.split('.').all(label_ok) {
            Ok(Host(host))
        } else {
            Err(bad("a host is a hostname"))
        }
    }
}

impl AsRef<str> for Host {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// One of the origins in INFO's `files=` (8.5, 5.6): `https://<host>`
/// or `https://<host>:<port>`, with nothing after it. A server's `get`
/// URLs must be on these origins, and devices download a file without
/// asking only from them (12.11).
///
/// Parsing folds the scheme and host to lower case. The host is a
/// [`Host`], or an IPv6 address in brackets. A port is 1 to 65535.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileOrigin {
    host: Host,
    port: Option<u16>,
}

impl FileOrigin {
    /// The origin `https://<host>[:<port>]`.
    pub fn new(host: Host, port: Option<u16>) -> FileOrigin {
        FileOrigin { host, port }
    }

    /// The host, in lower case.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The port, if one is written.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Whether `url` is on this origin: same host, and same port, where
    /// no port means 443 (RFC 6454). Used by devices before they
    /// download a file without asking (5.6, 12.11).
    pub fn contains(&self, url: &FileUrl) -> bool {
        // A `get` URL is `https://` and then the authority, up to the
        // first `/`, `?` or `#`.
        let rest = &url.as_str()["https://".len()..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        match format!("https://{}", &rest[..end]).parse::<FileOrigin>() {
            Ok(other) => {
                other.host == self.host && other.port.unwrap_or(443) == self.port.unwrap_or(443)
            }
            Err(_) => false,
        }
    }
}

impl fmt::Display for FileOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("https://")?;
        write_authority(f, &self.host, self.port)
    }
}

impl FromStr for FileOrigin {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<FileOrigin, ParseError> {
        const WHAT: ParseError = bad("a files origin is https://<host>[:<port>]");
        let rest = match s.get(..8) {
            Some(scheme) if scheme.eq_ignore_ascii_case("https://") => &s[8..],
            _ => return Err(WHAT),
        };
        let (host, port) = parse_authority(rest).ok_or(WHAT)?;
        Ok(FileOrigin { host, port })
    }
}

/// Reads `<host>[:<port>]` (2.1): a [`Host`], or an IPv6 address in
/// brackets, and a port of 1 to 65535. `None` for anything else.
pub(crate) fn parse_authority(s: &str) -> Option<(Host, Option<u16>)> {
    let (host, port) = match s.strip_prefix('[') {
        Some(v6) => {
            let (addr, after) = v6.split_once(']')?;
            let addr: Ipv6Addr = addr.parse().ok()?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':')?),
            };
            (Host(addr.to_string()), port)
        }
        None => {
            let (host, port) = match s.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (s, None),
            };
            if host.is_empty() {
                return None;
            }
            (host.parse().ok()?, port)
        }
    };
    let port = match port.map(parse_u64) {
        None => None,
        Some(Ok(n @ 1..=65535)) => Some(n as u16),
        Some(_) => return None,
    };
    Some((host, port))
}

/// Writes `<host>[:<port>]`, with an IPv6 address in brackets.
pub(crate) fn write_authority(
    f: &mut fmt::Formatter<'_>,
    host: &Host,
    port: Option<u16>,
) -> fmt::Result {
    if host.as_str().contains(':') {
        write!(f, "[{host}]")?;
    } else {
        f.write_str(host.as_str())?;
    }
    match port {
        Some(port) => write!(f, ":{port}"),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// OK

/// `OK [<key>=<value> ...]`, a successful final response (3.6).
///
/// The result values are kept in order, as strings, with keys in lower
/// case. Unknown values are kept, since clients must ignore them rather
/// than fail (3.6). The typed accessors read the values the spec defines;
/// each returns `Ok(None)` if the value is absent and an error if it is
/// malformed.
///
/// ```
/// use risala_proto::names::Seq;
/// use risala_proto::server::OkResponse;
///
/// let ok = OkResponse::new().with("id", "k3f9q2").with("head", 9121);
/// assert_eq!(ok.head()?, Some(9121));
/// assert_eq!(ok.value("id"), Some("k3f9q2"));
/// assert_eq!(ok.more()?, None);
/// # Ok::<(), risala_proto::error::ParseError>(())
/// ```
///
/// `Debug` leaves out the value of `token=`, a guest session's secret
/// (4.2), so that a response written to a log does not give it away.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OkResponse {
    values: Vec<(String, String)>,
}

/// The keys whose values [`OkResponse`]'s `Debug` leaves out.
const SECRET_KEYS: [&str; 1] = ["token"];

impl fmt::Debug for OkResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let values: Vec<(&str, &str)> = self
            .values
            .iter()
            .map(|(k, v)| {
                let shown = if SECRET_KEYS.contains(&k.as_str()) {
                    ".."
                } else {
                    v.as_str()
                };
                (k.as_str(), shown)
            })
            .collect();
        f.debug_struct("OkResponse")
            .field("values", &values)
            .finish()
    }
}

impl OkResponse {
    /// An `OK` with no values.
    pub fn new() -> OkResponse {
        OkResponse::default()
    }

    /// Adds the value `key=value`, replacing an earlier value with the same
    /// key, and returns the response for chaining.
    ///
    /// # Panics
    ///
    /// If `key` or `value` is not a valid option (see
    /// [`try_with`](Self::try_with)). Values from this crate's types always
    /// are.
    pub fn with(self, key: &str, value: impl fmt::Display) -> OkResponse {
        let value = value.to_string();
        match self.try_with(key, &value) {
            Ok(ok) => ok,
            Err(e) if SECRET_KEYS.contains(&key) => panic!("bad OK value {key}=..: {e}"),
            Err(e) => panic!("bad OK value {key}={value}: {e}"),
        }
    }

    /// Adds the value `key=value`, replacing an earlier value with the same
    /// key. Fails with `BadSyntax` if `key`, folded, is not `a-z 0-9 -`, or
    /// if `value` is not a non-empty token (3.3).
    pub fn try_with(
        mut self,
        key: &str,
        value: impl fmt::Display,
    ) -> Result<OkResponse, ParseError> {
        self.insert(key, value)?;
        Ok(self)
    }

    /// Sets the value `key=value` in place, as [`try_with`](Self::try_with)
    /// does. The key is folded to lower case and must then be `a-z 0-9 -`;
    /// the value must be a non-empty token (3.3).
    pub fn insert(&mut self, key: &str, value: impl fmt::Display) -> Result<(), ParseError> {
        let value = value.to_string();
        let key = key.to_ascii_lowercase();
        if !crate::line::is_option_key(&key) {
            return Err(bad("bad result key"));
        }
        if !is_token(&value) {
            return Err(bad("bad result value"));
        }
        match self.values.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.values.push((key, value)),
        }
        Ok(())
    }

    /// Removes the value `key`. Returns whether it was there.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.values.len();
        self.values.retain(|(k, _)| k != key);
        self.values.len() != before
    }

    /// The raw value of `key`, which must be given in lower case.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The values in order, as `(key, value)`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The number of values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether there are no values.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn parse(p: Params<'_>) -> Result<OkResponse, ParseError> {
        let values = p
            .options()?
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        Ok(OkResponse { values })
    }

    fn write(&self, b: &mut LineBuilder) {
        for (key, value) in &self.values {
            b.option(key, value);
        }
    }

    fn typed<T>(
        &self,
        key: &str,
        parse: impl FnOnce(&str) -> Result<T, ParseError>,
    ) -> Result<Option<T>, ParseError> {
        self.value(key).map(parse).transpose()
    }

    /// `seq=`: the seq of the post POST created, or of the post with the
    /// same `cid` (5.2, 7.6).
    pub fn seq(&self) -> Result<Option<Seq>, ParseError> {
        self.typed("seq", str::parse)
    }

    /// `head=`: a mailbox's newest seq, from FOLLOW, or `0` if it has none
    /// (7.1).
    pub fn head(&self) -> Result<Option<u64>, ParseError> {
        self.typed("head", |v| Ok(Seq::parse_or_zero(v)?.map_or(0, Seq::get)))
    }

    /// `more=`: whether FETCH, LIST or ADMIN ROOMS has more, from `0` or
    /// `1` (6.1, 7.1, 10.4).
    pub fn more(&self) -> Result<Option<bool>, ParseError> {
        self.typed("more", |v| match v {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(bad("more is 0 or 1")),
        })
    }

    /// `uid=`: who the connection is, from GUEST, AUTH or REGISTER (4.2,
    /// 4.6, 4.7).
    pub fn uid(&self) -> Result<Option<Uid>, ParseError> {
        self.typed("uid", str::parse)
    }

    /// `token=`: the secret that resumes a guest session, from GUEST (4.2).
    pub fn token(&self) -> Result<Option<GuestToken>, ParseError> {
        self.typed("token", str::parse)
    }

    /// `resumed=`: whether GUEST resumed a session, from `yes` or `no`
    /// (4.2).
    pub fn resumed(&self) -> Result<Option<bool>, ParseError> {
        self.typed("resumed", parse_yes_no)
    }

    /// `op=`: whether the identity is a server operator, from AUTH and
    /// REGISTER (4.6, 10.1).
    pub fn op(&self) -> Result<Option<bool>, ParseError> {
        self.typed("op", parse_yes_no)
    }

    /// `id=`: a report's id, from REPORT (5.8).
    pub fn id(&self) -> Result<Option<Id>, ParseError> {
        self.typed("id", str::parse)
    }

    /// `put=`: where to upload, from UPLOAD and BLOB (5.6, 12.12). Opaque
    /// to this crate.
    pub fn put_url(&self) -> Option<&str> {
        self.value("put")
    }

    /// `get=`: where to download an uploaded file from, from UPLOAD (5.6).
    pub fn get_url(&self) -> Result<Option<FileUrl>, ParseError> {
        self.typed("get", str::parse)
    }

    /// `del=`: where to delete an uploaded file, from UPLOAD (5.6). Opaque
    /// to this crate.
    pub fn del_url(&self) -> Option<&str> {
        self.value("del")
    }

    /// `exists=`: whether the server already has a blob, from BLOB (12.12).
    pub fn exists(&self) -> Result<Option<bool>, ParseError> {
        self.typed("exists", parse_yes_no)
    }

    /// `count=`: how many ordinary KeyPackages the server holds, from
    /// KEYPKG COUNT (12.5).
    pub fn count(&self) -> Result<Option<u64>, ParseError> {
        self.typed("count", parse_u64)
    }

    /// `last-resort=`: whether the server holds a last-resort KeyPackage,
    /// from KEYPKG COUNT (12.5).
    pub fn last_resort(&self) -> Result<Option<bool>, ParseError> {
        self.typed("last-resort", parse_yes_no)
    }

    /// `box=`: a public room's mailbox, from `INFO <room>` (6.1).
    pub fn mailbox(&self) -> Result<Option<BoxName>, ParseError> {
        self.typed("box", str::parse)
    }

    /// `members=`: a public room's number of members, from `INFO <room>`
    /// (6.1).
    pub fn members(&self) -> Result<Option<u64>, ParseError> {
        self.typed("members", parse_u64)
    }

    /// `epoch=`: a public room's epoch, from `INFO <room>` (6.1).
    pub fn epoch(&self) -> Result<Option<u64>, ParseError> {
        self.typed("epoch", parse_u64)
    }

    /// `version=`: the protocol version, from INFO (8.5).
    pub fn version(&self) -> Result<Option<u32>, ParseError> {
        self.typed("version", |v| {
            u32::try_from(parse_u64(v)?).map_err(|_| bad("version is out of range"))
        })
    }

    /// `anon=`: whether anonymous connections are allowed, from INFO
    /// (8.5).
    pub fn anon(&self) -> Result<Option<bool>, ParseError> {
        self.typed("anon", parse_yes_no)
    }

    /// `guests=`: whether guests are allowed, from INFO (8.5).
    pub fn guests(&self) -> Result<Option<bool>, ParseError> {
        self.typed("guests", parse_yes_no)
    }

    /// `register=`: the identity domain for REGISTER, or `no`, from INFO
    /// (4.7, 8.5).
    pub fn register(&self) -> Result<Option<Register>, ParseError> {
        self.typed("register", str::parse)
    }

    /// `log=`: the URL prefix of the server's key log, or `no`, from INFO
    /// (4.5, 8.5).
    pub fn log(&self) -> Result<Option<Log>, ParseError> {
        self.typed("log", str::parse)
    }

    /// `retention=`: the retention period in days, from INFO (7.5, 8.5).
    pub fn retention(&self) -> Result<Option<Retention>, ParseError> {
        self.typed("retention", str::parse)
    }

    /// `push=`: whether PUSH is supported, from INFO (8.5).
    pub fn push(&self) -> Result<Option<bool>, ParseError> {
        self.typed("push", parse_yes_no)
    }

    /// `upload=`: the largest file UPLOAD accepts, or `no`, from INFO (5.6,
    /// 8.5).
    pub fn upload(&self) -> Result<Option<Upload>, ParseError> {
        self.typed("upload", str::parse)
    }

    /// `blobs=`: the URL prefix blobs are fetched from, from INFO (8.5,
    /// 12.12). Opaque to this crate.
    pub fn blobs(&self) -> Option<&str> {
        self.value("blobs")
    }

    /// `quota=`: the most a mailbox may hold at once, in bytes, from INFO
    /// (7.5, 8.5).
    pub fn quota(&self) -> Result<Option<u64>, ParseError> {
        self.typed("quota", parse_u64)
    }

    /// `files=`: the origins of the server's `get` URLs, from INFO (5.6,
    /// 8.5). One or more, separated by commas.
    pub fn files(&self) -> Result<Option<Vec<FileOrigin>>, ParseError> {
        self.typed("files", |v| v.split(',').map(str::parse).collect())
    }

    /// Sets `seq=`.
    pub fn with_seq(self, seq: Seq) -> OkResponse {
        self.with("seq", seq)
    }

    /// Sets `head=`, `0` for a mailbox with no posts.
    pub fn with_head(self, head: impl Into<u64>) -> OkResponse {
        self.with("head", head.into())
    }

    /// Sets `more=` to `1` or `0`.
    pub fn with_more(self, more: bool) -> OkResponse {
        self.with("more", u8::from(more))
    }

    /// Sets `uid=`.
    pub fn with_uid(self, uid: &Uid) -> OkResponse {
        self.with("uid", uid)
    }

    /// Sets `token=`, the guest session's secret.
    pub fn with_token(self, token: &GuestToken) -> OkResponse {
        self.with("token", token)
    }

    /// Sets `resumed=`. A server sends only `resumed=yes` (4.2), so
    /// `false` leaves the value out.
    pub fn with_resumed(self, resumed: bool) -> OkResponse {
        if resumed {
            self.with("resumed", "yes")
        } else {
            self
        }
    }

    /// Sets `op=`. A server sends only `op=yes` (4.6), so `false` leaves
    /// the value out.
    pub fn with_op(self, op: bool) -> OkResponse {
        if op { self.with("op", "yes") } else { self }
    }

    /// Sets `id=`.
    pub fn with_id(self, id: &Id) -> OkResponse {
        self.with("id", id)
    }

    /// Sets `put=`, `get=` and `del=`, the URLs of UPLOAD (5.6). Fails if
    /// `put` or `del` is not a token.
    pub fn with_upload_urls(
        self,
        put: &str,
        get: &FileUrl,
        del: &str,
    ) -> Result<OkResponse, ParseError> {
        self.try_with("put", put)?
            .try_with("get", get)?
            .try_with("del", del)
    }

    /// Sets `put=`, the URL of BLOB (12.12). Fails if it is not a token.
    pub fn with_put_url(self, put: &str) -> Result<OkResponse, ParseError> {
        self.try_with("put", put)
    }

    /// Sets `exists=yes` (12.12).
    pub fn with_exists(self) -> OkResponse {
        self.with("exists", "yes")
    }

    /// Sets `count=`.
    pub fn with_count(self, count: u64) -> OkResponse {
        self.with("count", count)
    }

    /// Sets `last-resort=`.
    pub fn with_last_resort(self, last_resort: bool) -> OkResponse {
        self.with("last-resort", yes_no(last_resort))
    }

    /// Sets `box=`.
    pub fn with_mailbox(self, mailbox: &BoxName) -> OkResponse {
        self.with("box", mailbox)
    }

    /// Sets `members=`.
    pub fn with_members(self, members: u64) -> OkResponse {
        self.with("members", members)
    }

    /// Sets `epoch=`.
    pub fn with_epoch(self, epoch: u64) -> OkResponse {
        self.with("epoch", epoch)
    }

    /// Sets `version=`.
    pub fn with_version(self, version: u32) -> OkResponse {
        self.with("version", version)
    }

    /// Sets `anon=`.
    pub fn with_anon(self, anon: bool) -> OkResponse {
        self.with("anon", yes_no(anon))
    }

    /// Sets `guests=`.
    pub fn with_guests(self, guests: bool) -> OkResponse {
        self.with("guests", yes_no(guests))
    }

    /// Sets `register=`.
    pub fn with_register(self, register: &Register) -> OkResponse {
        self.with("register", register)
    }

    /// Sets `log=`.
    pub fn with_log(self, log: &Log) -> OkResponse {
        self.with("log", log)
    }

    /// Sets `retention=`.
    pub fn with_retention(self, retention: Retention) -> OkResponse {
        self.with("retention", retention)
    }

    /// Sets `push=`.
    pub fn with_push(self, push: bool) -> OkResponse {
        self.with("push", yes_no(push))
    }

    /// Sets `upload=`.
    pub fn with_upload(self, upload: Upload) -> OkResponse {
        self.with("upload", upload)
    }

    /// Sets `blobs=`. Fails if it is not a token.
    pub fn with_blobs(self, blobs: &str) -> Result<OkResponse, ParseError> {
        self.try_with("blobs", blobs)
    }

    /// Sets `quota=`.
    pub fn with_quota(self, quota: u64) -> OkResponse {
        self.with("quota", quota)
    }

    /// Sets `files=`. Fails if `files` is empty: a server without uploads
    /// leaves the value out (8.5).
    pub fn with_files(self, files: &[FileOrigin]) -> Result<OkResponse, ParseError> {
        if files.is_empty() {
            return Err(bad("files= lists at least one origin"));
        }
        let list: Vec<String> = files.iter().map(ToString::to_string).collect();
        self.try_with("files", list.join(","))
    }
}

/// The `register=` value of INFO (8.5): the server's identity domain
/// (4.7), or `no`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Register {
    /// `no`: the server offers no registration.
    No,
    /// REGISTER creates identities under this domain.
    Domain(crate::names::Domain),
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Register::No => f.write_str("no"),
            Register::Domain(domain) => f.write_str(domain.as_str()),
        }
    }
}

impl FromStr for Register {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Register, ParseError> {
        if s.eq_ignore_ascii_case("no") {
            Ok(Register::No)
        } else {
            s.parse().map(Register::Domain)
        }
    }
}

/// The `upload=` value of INFO (5.6, 8.5): the largest file in bytes, or
/// `no`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Upload {
    /// `no`: the server offers no uploads.
    No,
    /// The largest file UPLOAD accepts, in bytes.
    MaxBytes(u64),
}

impl fmt::Display for Upload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upload::No => f.write_str("no"),
            Upload::MaxBytes(n) => write!(f, "{n}"),
        }
    }
}

impl FromStr for Upload {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Upload, ParseError> {
        if s.eq_ignore_ascii_case("no") {
            Ok(Upload::No)
        } else {
            parse_u64(s).map(Upload::MaxBytes)
        }
    }
}

/// The `log=` value of INFO (4.5, 8.5): the URL prefix of the server's
/// key log, or `no`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Log {
    /// `no`: the server keeps no key log.
    No,
    /// The log's `https` URL prefix [TLOG-TILES], as given.
    Url(String),
}

impl fmt::Display for Log {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Log::No => f.write_str("no"),
            Log::Url(url) => f.write_str(url),
        }
    }
}

impl FromStr for Log {
    type Err = ParseError;

    /// `no`, or a token that starts with `https://`, in any case.
    fn from_str(s: &str) -> Result<Log, ParseError> {
        if s.eq_ignore_ascii_case("no") {
            return Ok(Log::No);
        }
        let https = s
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
        if https && s.len() > 8 && is_token(s) {
            Ok(Log::Url(s.to_owned()))
        } else {
            Err(bad("log is an https URL or no"))
        }
    }
}

// ---------------------------------------------------------------------------
// ERR

/// `ERR <code> [<message...>]`, a failed final response (3.6, 3.7), with
/// the `retry` tag of `ERR rate-limited` or `ERR unavailable` (3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrResponse {
    /// The error code. Clients treat an unknown code as a general failure
    /// (3.7).
    pub code: ErrorCode,
    /// The `retry` tag: seconds to wait before trying again (3.2). Read on
    /// any ERR, though the spec sends it only with `rate-limited` and
    /// `unavailable`.
    pub retry: Option<u64>,
    /// The message for people, escaped; empty if none.
    pub message: String,
}

impl ErrResponse {
    /// An ERR with this code, no `retry` and no message.
    pub fn new(code: ErrorCode) -> ErrResponse {
        ErrResponse {
            code,
            retry: None,
            message: String::new(),
        }
    }

    /// Sets the message, escaped text (3.4).
    pub fn with_message(mut self, message: impl Into<String>) -> ErrResponse {
        self.message = message.into();
        self
    }

    /// Sets the `retry` tag, in seconds (3.2).
    pub fn with_retry(mut self, seconds: u64) -> ErrResponse {
        self.retry = Some(seconds);
        self
    }

    fn parse(tags: &Tags, mut p: Params<'_>) -> Result<ErrResponse, ParseError> {
        let retry = tag_value(tags, "retry")?.map(parse_u64).transpose()?;
        let code = tok(&mut p)?;
        let message = p.text().to_owned();
        Ok(ErrResponse {
            code,
            retry,
            message,
        })
    }

    fn write(&self, b: &mut LineBuilder) {
        if let Some(retry) = self.retry {
            b.tag("retry", retry);
        }
        b.token(&self.code).text(&self.message);
    }
}

impl From<ErrorCode> for ErrResponse {
    /// An ERR with this code and no message, such as the refusal of a
    /// command that the connection's kind may not send (Section 13).
    fn from(code: ErrorCode) -> ErrResponse {
        ErrResponse::new(code)
    }
}

impl From<ParseError> for ErrResponse {
    /// The ERR a server replies with to a command that did not parse: the
    /// error's code (3.7) with its description as the message.
    fn from(e: ParseError) -> ErrResponse {
        ErrResponse::new(e.code()).with_message(crate::text::escape(&e.to_string()))
    }
}

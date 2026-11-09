//! Sending pushes (9.3): the encrypted body, and the HTTPS request.
//!
//! # The body
//!
//! [`encrypt`] makes a push body with Message Encryption for Web Push
//! [RFC 8291], in the `aes128gcm` content coding [RFC 8188]: one record
//! holding `NOTIFY <tag> <reason>` and its LF, padded with RFC 8188's
//! record padding to [`NOTIFY_PADDED_LEN`] bytes, so that every body has
//! the same size, encrypted under a fresh ephemeral P-256 key and a fresh
//! salt for every push. [`decrypt`] is the receiving side, for tests and
//! for anyone checking a server.
//!
//! # The request
//!
//! [`HttpsPusher`] POSTs a body to a subscription's URL, as 9.3 requires:
//! over HTTPS with the certificate checked, following no redirect, to no
//! special-purpose address unless the operator allows it (4.4), and
//! giving up after 10 seconds. It returns the response's status code, and
//! reads nothing else. One request per connection, with
//! `Connection: close`, like the key file fetcher (4.4).
//!
//! [`PushTransport`] lets the hub's tests record pushes instead.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::{aead, agreement, hmac};
use risala_proto::binary::{PushAuth, PushKey};
use risala_proto::server::{NOTIFY_PADDED_LEN, Notify};
use risala_proto::types::PushUrl;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::PushConfig;

/// The `TTL` of every push, in seconds: a day (9.3).
pub const PUSH_TTL_SECS: u64 = 86_400;

/// The record size written in the body's header [RFC 8188]. The body is
/// one record, much smaller than this; 4096 is what [RFC 8291] uses.
pub const RECORD_SIZE: u32 = 4096;

/// The length of the body's header: salt, record size, key id length and
/// the 65-byte key id [RFC 8188, 2.1].
pub const HEADER_LEN: usize = 16 + 4 + 1 + 65;

/// The length of every push body: the header, then one record of
/// [`NOTIFY_PADDED_LEN`] bytes and its 16-byte tag.
pub const BODY_LEN: usize = HEADER_LEN + NOTIFY_PADDED_LEN + 16;

/// How long a push request may take, from resolving the host to the
/// response's status line (9.3: SHOULD give up after 10 seconds).
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes of response head read.
const MAX_HEAD: usize = 16 * 1024;

/// Why a push body could not be made or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The subscription's key is not a P-256 point.
    #[error("the push key is not a P-256 public key")]
    BadKey,
    /// The body is not one RFC 8188 record that decrypts.
    #[error("the push body does not decrypt")]
    BadBody,
    /// No randomness, or the crypto library failed.
    #[error("crypto failure")]
    Failed,
}

/// Whether `key` is a P-256 public key a push can be encrypted to (9.1).
pub fn valid_key(key: &PushKey) -> bool {
    agreement::ParsedPublicKey::try_from(agreement::UnparsedPublicKey::new(
        &agreement::ECDH_P256,
        key.as_bytes(),
    ))
    .is_ok()
}

/// HMAC-SHA-256 of the concatenation of `parts` under `key`.
fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, key));
    for part in parts {
        ctx.update(part);
    }
    ctx.sign()
        .as_ref()
        .try_into()
        .expect("HMAC-SHA-256 is 32 bytes")
}

/// The content encryption key and nonce of [RFC 8291, 3.4]: from the ECDH
/// secret, the authentication secret, both public keys and the salt.
fn derive(
    ecdh: &[u8],
    auth: &[u8; 16],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8; 16],
) -> ([u8; 16], [u8; 12]) {
    // PRK_key = HMAC-SHA-256(auth_secret, ecdh_secret)
    let prk_key = hmac256(auth, &[ecdh]);
    // IKM = HMAC-SHA-256(PRK_key, "WebPush: info" || 0x00 || ua_public ||
    // as_public || 0x01)
    let ikm = hmac256(&prk_key, &[b"WebPush: info\0", ua_public, as_public, &[1]]);
    // PRK = HMAC-SHA-256(salt, IKM)
    let prk = hmac256(salt, &[&ikm]);
    let cek = hmac256(&prk, &[b"Content-Encoding: aes128gcm\0", &[1]]);
    let nonce = hmac256(&prk, &[b"Content-Encoding: nonce\0", &[1]]);
    (
        cek[..16].try_into().expect("16 bytes"),
        nonce[..12].try_into().expect("12 bytes"),
    )
}

fn aead_key(cek: &[u8; 16]) -> Result<aead::LessSafeKey, CryptoError> {
    let key = aead::UnboundKey::new(&aead::AES_128_GCM, cek).map_err(|_| CryptoError::Failed)?;
    Ok(aead::LessSafeKey::new(key))
}

/// Encrypts `notify` to a subscription (9.3): the line and its LF, padded
/// to [`NOTIFY_PADDED_LEN`] bytes, under a fresh ephemeral key and salt.
/// The body is always [`BODY_LEN`] bytes.
pub fn encrypt(notify: &Notify, key: &PushKey, auth: &PushAuth) -> Result<Vec<u8>, CryptoError> {
    let private =
        agreement::PrivateKey::generate(&agreement::ECDH_P256).map_err(|_| CryptoError::Failed)?;
    let mut salt = [0; 16];
    aws_lc_rs::rand::fill(&mut salt).map_err(|_| CryptoError::Failed)?;
    let mut plain = notify.to_body().into_bytes();
    // The last record's delimiter, then zeros [RFC 8188, 2].
    plain.push(2);
    if plain.len() > NOTIFY_PADDED_LEN {
        return Err(CryptoError::Failed);
    }
    plain.resize(NOTIFY_PADDED_LEN, 0);
    encrypt_record(&plain, key.as_bytes(), auth.as_bytes(), &private, &salt)
}

/// Encrypts one last record, `plain`, its delimiter and padding included,
/// with the application server key `private` and `salt` [RFC 8291].
/// Exposed so that tests can check [RFC 8291]'s example.
pub fn encrypt_record(
    plain: &[u8],
    ua_public: &[u8; 65],
    auth: &[u8; 16],
    private: &agreement::PrivateKey,
    salt: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    let as_public = private
        .compute_public_key()
        .map_err(|_| CryptoError::Failed)?;
    let ecdh = agreement::agree(
        private,
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &ua_public[..]),
        CryptoError::BadKey,
        |secret| Ok(secret.to_vec()),
    )?;
    let (cek, nonce) = derive(&ecdh, auth, ua_public, as_public.as_ref(), salt);
    let mut record = plain.to_vec();
    aead_key(&cek)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut record,
        )
        .map_err(|_| CryptoError::Failed)?;
    let key_id = as_public.as_ref();
    let mut body = Vec::with_capacity(HEADER_LEN + record.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(u8::try_from(key_id.len()).map_err(|_| CryptoError::Failed)?);
    body.extend_from_slice(key_id);
    body.extend_from_slice(&record);
    Ok(body)
}

/// Decrypts a push body made by [`encrypt`], or any one-record
/// `aes128gcm` body [RFC 8291], with the subscription's private key and
/// authentication secret. Returns the plain text without its padding.
pub fn decrypt(
    body: &[u8],
    private: &agreement::PrivateKey,
    auth: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    let bad = CryptoError::BadBody;
    let salt: &[u8; 16] = body.get(..16).ok_or(bad.clone())?.try_into().expect("16");
    let id_len = usize::from(*body.get(20).ok_or(bad.clone())?);
    let key_id = body.get(21..21 + id_len).ok_or(bad.clone())?;
    let mut record = body.get(21 + id_len..).ok_or(bad.clone())?.to_vec();
    let ua_public = private
        .compute_public_key()
        .map_err(|_| CryptoError::Failed)?;
    let ecdh = agreement::agree(
        private,
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, key_id),
        bad.clone(),
        |secret| Ok(secret.to_vec()),
    )?;
    let (cek, nonce) = derive(&ecdh, auth, ua_public.as_ref(), key_id, salt);
    let plain = aead_key(&cek)?
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut record,
        )
        .map_err(|_| bad.clone())?;
    // Strip the padding: zeros, then the last record's delimiter, 2.
    let end = plain.iter().rposition(|&b| b != 0).ok_or(bad.clone())?;
    if plain[end] != 2 {
        return Err(bad);
    }
    Ok(plain[..end].to_vec())
}

// ---------------------------------------------------------------------------
// Sending

/// One push to send (9.3).
#[derive(Clone, PartialEq, Eq)]
pub struct PushRequest {
    /// The subscription's URL.
    pub url: PushUrl,
    /// The encrypted body.
    pub body: Vec<u8>,
    /// The `Urgency` header [RFC 8030].
    pub urgency: &'static str,
}

impl fmt::Debug for PushRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The URL is a capability: keep it out of logs (9.1).
        f.debug_struct("PushRequest")
            .field("body", &self.body.len())
            .field("urgency", &self.urgency)
            .finish_non_exhaustive()
    }
}

/// Why a push was not delivered, short of an HTTP status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The URL is not one this client can send to.
    #[error("bad push URL: {0}")]
    Url(&'static str),
    /// Every address of the host is a special-purpose one (4.4).
    #[error("the push host has only special-purpose addresses")]
    Refused,
    /// Resolving, connecting, TLS or the response failed.
    #[error("push failed: {0}")]
    Io(String),
    /// It took longer than [`PUSH_TIMEOUT`].
    #[error("push timed out")]
    Timeout,
}

/// A boxed future, so that [`PushTransport`] can be a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Sends pushes: [`HttpsPusher`], or a recorder in tests.
pub trait PushTransport: Send + Sync + 'static {
    /// POSTs `push`, and returns the response's status code.
    fn send<'a>(&'a self, push: &'a PushRequest) -> BoxFuture<'a, Result<u16, SendError>>;
}

/// Sends pushes over HTTPS, as 9.3 requires.
#[derive(Clone)]
pub struct HttpsPusher {
    connector: TlsConnector,
    allow_private: bool,
}

impl fmt::Debug for HttpsPusher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsPusher")
            .field("allow_private", &self.allow_private)
            .finish_non_exhaustive()
    }
}

impl HttpsPusher {
    /// A pusher that trusts the public CAs (Mozilla's, as built in) and
    /// `extra`, and connects to special-purpose addresses only if
    /// `allow_private`.
    pub fn new(extra: Vec<CertificateDer<'static>>, allow_private: bool) -> HttpsPusher {
        let mut roots = RootCertStore::empty();
        let (_, bad) = roots.add_parsable_certificates(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .cloned()
                .chain(extra),
        );
        if bad > 0 {
            tracing::warn!(bad, "ignored push trust anchors that do not parse");
        }
        let mut config = ClientConfig::builder_with_provider(risala_keyfetch::provider())
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs supports TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // No resumption: every push is a fresh handshake (2.1).
        config.resumption = rustls::client::Resumption::disabled();
        HttpsPusher {
            connector: TlsConnector::from(Arc::new(config)),
            allow_private,
        }
    }

    /// The pusher `config` asks for. Reads the `extra_roots` files, so
    /// call it from a blocking context.
    pub fn from_config(config: &PushConfig) -> io::Result<HttpsPusher> {
        let mut extra = Vec::new();
        for path in &config.extra_roots {
            let invalid = |e: &dyn fmt::Display| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("push.extra_roots: {}: {e}", path.display()),
                )
            };
            let certs = CertificateDer::pem_file_iter(path)
                .map_err(|e| invalid(&e))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| invalid(&e))?;
            if certs.is_empty() {
                return Err(invalid(&"no certificate in the file"));
            }
            extra.extend(certs);
        }
        Ok(HttpsPusher::new(extra, config.allow_private))
    }

    async fn post(&self, push: &PushRequest) -> Result<u16, SendError> {
        let url = ParsedUrl::parse(push.url.as_str())?;
        let addrs: Vec<SocketAddr> = match url.host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, url.port)],
            Err(_) => tokio::net::lookup_host((url.host.as_str(), url.port))
                .await
                .map_err(|e| SendError::Io(e.to_string()))?
                .collect(),
        };
        let guarded = !self.allow_private;
        let mut refused = false;
        let mut last_error = None;
        let mut tcp = None;
        for addr in addrs {
            if guarded && risala_keyfetch::guard::is_special(addr.ip()) {
                refused = true;
                continue;
            }
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(e) => last_error = Some(e.to_string()),
            }
        }
        let tcp = match (tcp, last_error, refused) {
            (Some(tcp), _, _) => tcp,
            (None, Some(e), _) => return Err(SendError::Io(e)),
            (None, None, true) => return Err(SendError::Refused),
            (None, None, false) => return Err(SendError::Io("no addresses".into())),
        };
        let name = ServerName::try_from(url.host.clone())
            .map_err(|_| SendError::Url("the host is not a server name"))?;
        let mut tls = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|e| SendError::Io(e.to_string()))?;
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: risalad/{}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Encoding: aes128gcm\r\n\
             Content-Length: {}\r\n\
             TTL: {PUSH_TTL_SECS}\r\n\
             Urgency: {}\r\n\
             Connection: close\r\n\
             \r\n",
            url.path,
            url.authority,
            env!("CARGO_PKG_VERSION"),
            push.body.len(),
            push.urgency,
        );
        let io = |e: io::Error| SendError::Io(e.to_string());
        tls.write_all(request.as_bytes()).await.map_err(io)?;
        tls.write_all(&push.body).await.map_err(io)?;
        tls.flush().await.map_err(io)?;
        read_status(&mut tls).await
    }
}

impl PushTransport for HttpsPusher {
    fn send<'a>(&'a self, push: &'a PushRequest) -> BoxFuture<'a, Result<u16, SendError>> {
        Box::pin(async move {
            tokio::time::timeout(PUSH_TIMEOUT, self.post(push))
                .await
                .unwrap_or(Err(SendError::Timeout))
        })
    }
}

/// Reads response heads until one that is not interim (1xx), and returns
/// its status code. Redirects are statuses like any other: nothing is
/// followed (9.3).
async fn read_status<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<u16, SendError> {
    let mut buf = Vec::new();
    loop {
        let end = loop {
            if let Some(end) = find_head_end(&buf) {
                break end;
            }
            if buf.len() > MAX_HEAD {
                return Err(SendError::Io("response head too long".into()));
            }
            let mut chunk = [0u8; 4096];
            let n = match stream.read(&mut chunk).await {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(SendError::Io(e.to_string())),
            };
            if n == 0 {
                return Err(SendError::Io("closed before the response".into()));
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let status = parse_status(&buf[..end])?;
        buf.drain(..end);
        if !(100..200).contains(&status) || status == 101 {
            return Ok(status);
        }
    }
}

/// Where the head that starts `buf` ends, after its blank line.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The status code of a response head.
fn parse_status(head: &[u8]) -> Result<u16, SendError> {
    let bad = || SendError::Io("not an HTTP/1 response".into());
    let line = head.split(|&b| b == b'\n').next().ok_or_else(bad)?;
    let line = std::str::from_utf8(line).map_err(|_| bad())?;
    let mut parts = line.trim_end_matches('\r').splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(bad());
    }
    let code = parts.next().ok_or_else(bad)?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    code.parse().map_err(|_| bad())
}

/// The host and port a push URL leads to, `<host> <port>`, for the limit
/// on pushes per host (9.1): the name in lower case without a trailing
/// dot, or the address, an IPv6 one in its usual form, and the port, 443
/// if the URL names none. So `HTTPS://Push.Example.:443/a` and
/// `https://push.example/b` share a host. A URL with user info, or one
/// that names no usable host or port, is an error: PUSH ADD refuses it
/// with `ERR bad-syntax`.
pub fn push_host(url: &str) -> Result<String, SendError> {
    let url = ParsedUrl::parse(url)?;
    Ok(format!("{} {}", url.host, url.port))
}

/// The parts of a push URL a request needs.
#[derive(Debug, PartialEq, Eq)]
struct ParsedUrl {
    /// The host, without brackets: a name in lower case without a
    /// trailing dot, or an address, an IPv6 one in its usual form.
    host: String,
    /// The port, 443 unless the URL names one.
    port: u16,
    /// The `Host` header: the authority as written, without user info.
    authority: String,
    /// The path and query, `/` if empty, without a fragment.
    path: String,
}

impl ParsedUrl {
    fn parse(url: &str) -> Result<ParsedUrl, SendError> {
        let rest = match url.get(..8) {
            Some(scheme) if scheme.eq_ignore_ascii_case("https://") => &url[8..],
            _ => return Err(SendError::Url("not https")),
        };
        let rest = rest.split('#').next().unwrap_or("");
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains('@') {
            return Err(SendError::Url("user info"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (addr, after) = v6.split_once(']').ok_or(SendError::Url("bad IPv6"))?;
            let addr = addr
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| SendError::Url("bad IPv6"))?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or(SendError::Url("bad port"))?),
            };
            (addr.to_string(), port)
        } else {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            // `push.example.` is `push.example` (9.1).
            let host = host.strip_suffix('.').unwrap_or(host);
            (host.to_ascii_lowercase(), port)
        };
        if host.is_empty() {
            return Err(SendError::Url("no host"));
        }
        let port = match port {
            None => 443,
            Some(p) => match p.parse::<u16>() {
                Ok(n) if n > 0 && n.to_string() == p => n,
                _ => return Err(SendError::Url("bad port")),
            },
        };
        let path = match path {
            "" => "/".to_owned(),
            p if p.starts_with('?') => format!("/{p}"),
            p => p.to_owned(),
        };
        Ok(ParsedUrl {
            host,
            port,
            authority: authority.to_owned(),
            path,
        })
    }
}

#[cfg(test)]
mod tests {
    use risala_proto::types::{NotifyReason, PushReason};

    use super::*;

    /// Decodes base64url without padding, as RFC 8291's example is written.
    fn b64url(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0;
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => panic!("not base64url: {c}"),
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }

    /// The example of RFC 8291, Section 5 and Appendix A.
    #[test]
    fn rfc8291_example() {
        let plain = b64url("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24");
        let as_private = b64url("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw");
        let ua_public = b64url(
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
        );
        let ua_private = b64url("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94");
        let salt = b64url("DGv6ra1nlYgDCS1FRnbzlw");
        let auth = b64url("BTBZMqHH6r4Tts7J_aSIgg");
        let expected = b64url(
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
        );
        let private =
            agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, &as_private).unwrap();
        let mut record = plain.clone();
        record.push(2);
        let body = encrypt_record(
            &record,
            &ua_public.clone().try_into().unwrap(),
            &auth.clone().try_into().unwrap(),
            &private,
            &salt.try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(body, expected);
        let ua =
            agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, &ua_private).unwrap();
        assert_eq!(
            decrypt(&body, &ua, &auth.try_into().unwrap()).unwrap(),
            plain
        );
    }

    #[test]
    fn bodies_have_one_size_and_decrypt() {
        let ua = agreement::PrivateKey::generate(&agreement::ECDH_P256).unwrap();
        let public: [u8; 65] = ua
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let key = PushKey::from_bytes(public);
        assert!(valid_key(&key));
        let auth = PushAuth::from_bytes([7; 16]);
        let mut seen = Vec::new();
        for tag in ["a", &"x".repeat(64)] {
            let notify = Notify {
                tag: tag.parse().unwrap(),
                reason: NotifyReason::Known(PushReason::Message),
            };
            let body = encrypt(&notify, &key, &auth).unwrap();
            assert_eq!(body.len(), BODY_LEN);
            let plain = decrypt(&body, &ua, auth.as_bytes()).unwrap();
            assert_eq!(plain, notify.to_body().into_bytes());
            seen.push(body);
        }
        // A fresh key and salt every time.
        let notify = Notify {
            tag: "a".parse().unwrap(),
            reason: NotifyReason::Known(PushReason::Welcome),
        };
        let one = encrypt(&notify, &key, &auth).unwrap();
        let two = encrypt(&notify, &key, &auth).unwrap();
        assert_ne!(one[..HEADER_LEN], two[..HEADER_LEN]);
        // The wrong secret does not decrypt.
        assert_eq!(decrypt(&one, &ua, &[8; 16]), Err(CryptoError::BadBody));
        // A key that is not on the curve is refused.
        assert!(!valid_key(&PushKey::from_bytes([4; 65])));
    }

    #[test]
    fn urls() {
        let p = ParsedUrl::parse("https://Push.Example:8443/n/3f9c?x=1#frag").unwrap();
        assert_eq!(
            p,
            ParsedUrl {
                host: "push.example".into(),
                port: 8443,
                authority: "Push.Example:8443".into(),
                path: "/n/3f9c?x=1".into(),
            }
        );
        let p = ParsedUrl::parse("https://[::1]:9/").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("::1", 9));
        let p = ParsedUrl::parse("https://push.example").unwrap();
        assert_eq!((p.port, p.path.as_str()), (443, "/"));
        let p = ParsedUrl::parse("https://Push.Example./x").unwrap();
        assert_eq!(
            (p.host.as_str(), p.authority.as_str()),
            ("push.example", "Push.Example.")
        );
        for bad in [
            "http://push.example/",
            "https://user@push.example/",
            "https://push.example:0/",
            "https://push.example:x/",
            "https:///x",
            "https://./x",
        ] {
            assert!(ParsedUrl::parse(bad).is_err(), "{bad}");
        }
    }

    /// Pushes to one host count together, however its URLs write it
    /// (9.1).
    #[test]
    fn push_hosts() {
        let host = |url: &str| push_host(url).unwrap();
        for same in [
            "https://victim.example/a",
            "HTTPS://victim.example/b",
            "https://VICTIM.example/c?x",
            "https://victim.example:443/d",
            "https://victim.example./e",
            "https://Victim.Example.:443",
            "https://victim.example#f",
        ] {
            assert_eq!(host(same), "victim.example 443", "{same}");
        }
        assert_eq!(host("https://victim.example:8443/"), "victim.example 8443");
        assert_eq!(host("https://[2001:DB8:0::1]/"), "2001:db8::1 443");
        assert_eq!(host("https://[2001:db8::1]:443/"), "2001:db8::1 443");
        assert_eq!(host("https://192.0.2.1:443/"), "192.0.2.1 443");
        for bad in [
            "https://user@victim.example/",
            "https://user:pass@victim.example/",
            "https://@victim.example/",
            "https://victim.example:0/",
            "https://victim.example:0443/",
            "https://[2001:db8::1/",
        ] {
            assert!(push_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn statuses() {
        assert_eq!(parse_status(b"HTTP/1.1 201 Created\r\n"), Ok(201));
        assert_eq!(parse_status(b"HTTP/1.0 410\n"), Ok(410));
        assert!(parse_status(b"HTTP/2 200\r\n").is_err());
        assert!(parse_status(b"HTTP/1.1 20 OK\r\n").is_err());
    }
}

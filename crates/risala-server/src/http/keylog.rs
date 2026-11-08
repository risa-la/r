//! The key log and the witness over HTTPS (4.5, 4.10):
//!
//! - [`route`]: which requests the listener hands to the hub's log
//!   ([`Hub::serve_log`]: `GET /risala-log/<n>/…`, [TLOG-TILES]) and
//!   witness ([`Hub::witness_request`]: `POST /risala-witness/…`,
//!   [TLOG-WITNESS]);
//! - [`HttpsPoster`]: how the log sends `add-checkpoint` and
//!   `risala/handoff` requests to its witnesses: one HTTPS POST per
//!   connection, TLS 1.3, certificates checked against the public CAs and
//!   `keys.extra_roots`, no redirects.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::core::Hub;
use crate::core::keylog::{
    Answer, LOG_PATH, MAX_WITNESS_RESPONSE, Transport, WITNESS_PATH, WITNESS_TIMEOUT,
};

/// The largest request body the witness takes: an `add-checkpoint` or
/// hand-off request is a few kilobytes (4.10).
pub const MAX_WITNESS_REQUEST: usize = 64 * 1024;

/// Whether `path` is the witness's, so that the listener reads a body.
pub(crate) fn is_witness_path(path: &str) -> bool {
    path.strip_prefix(WITNESS_PATH)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Answers a request for the log or the witness, or `None` if it is for
/// neither. `GET` and `HEAD` go to the log, `POST` to the witness.
pub(crate) async fn route(hub: &Hub, method: &str, path: &str, body: Vec<u8>) -> Option<Answer> {
    if path.starts_with(LOG_PATH) {
        return match method {
            "GET" | "HEAD" => hub.serve_log(path).await,
            _ => None,
        };
    }
    if is_witness_path(path) {
        return match method {
            "POST" => hub.witness_request(path, body).await,
            _ => None,
        };
    }
    None
}

/// The reason phrase of a status the log or the witness answers with.
pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        _ => "Error",
    }
}

/// Sends the log's requests to its witnesses over HTTPS.
pub(crate) struct HttpsPoster {
    connector: TlsConnector,
}

impl HttpsPoster {
    /// A client trusting the public CAs and the certificates in
    /// `extra_roots`, PEM files. Reads them, so call it from a blocking
    /// context.
    pub(crate) fn new(extra_roots: &[PathBuf]) -> io::Result<HttpsPoster> {
        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        for path in extra_roots {
            let certs = CertificateDer::pem_file_iter(path)
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("keys.extra_roots: {}: {e}", path.display()),
                    )
                })?;
            store.add_parsable_certificates(certs);
        }
        let mut config = ClientConfig::builder_with_provider(risala_keyfetch::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_root_certificates(store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(HttpsPoster {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    async fn post_once(&self, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("{url} is not an https URL"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (
                h.trim_start_matches('[').trim_end_matches(']'),
                p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?,
            ),
            _ => (authority, 443),
        };
        let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string())?;
        let mut tls = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: risalad/{}\r\n\
             Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
             Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION"),
            body.len()
        );
        tls.write_all(head.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        tls.write_all(&body).await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        (&mut tls)
            .take((MAX_WITNESS_RESPONSE + 16 * 1024) as u64)
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        parse_response(&response)
    }
}

impl Transport for HttpsPoster {
    fn post<'a>(
        &'a self,
        url: &'a str,
        body: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(u16, Vec<u8>), String>> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::timeout(WITNESS_TIMEOUT, self.post_once(url, body))
                .await
                .map_err(|_| "timed out".to_owned())?
        })
    }
}

/// Reads a whole HTTP/1.1 response: its status and its body, framed by
/// `Content-Length`, by chunks, or by the end of the connection. Interim
/// (1xx) responses are skipped.
pub(crate) fn parse_response(mut bytes: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let bad = |what: &str| format!("malformed response: {what}");
    loop {
        let end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| bad("no end of head"))?;
        let head = std::str::from_utf8(&bytes[..end]).map_err(|_| bad("head is not UTF-8"))?;
        let rest = &bytes[end + 4..];
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut parts = status_line.splitn(3, ' ');
        let (version, status) = (parts.next(), parts.next());
        if !matches!(version, Some("HTTP/1.1" | "HTTP/1.0")) {
            return Err(bad("status line"));
        }
        let status: u16 = status
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("status"))?;
        if (100..200).contains(&status) {
            bytes = rest;
            continue;
        }
        let mut length = None;
        let mut chunked = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err(bad("header"));
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.parse::<usize>().map_err(|_| bad("content-length"))?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.eq_ignore_ascii_case("chunked");
            }
        }
        let body = if chunked {
            dechunk(rest).ok_or_else(|| bad("chunks"))?
        } else if let Some(n) = length {
            rest.get(..n).ok_or_else(|| bad("short body"))?.to_vec()
        } else {
            rest.to_vec()
        };
        if body.len() > MAX_WITNESS_RESPONSE {
            return Err(bad("body too large"));
        }
        return Ok((status, body));
    }
}

/// Decodes a chunked body, ignoring chunk extensions and trailers.
fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&rest[..eol]).ok()?;
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size..)?.strip_prefix(b"\r\n")?;
        if out.len() > MAX_WITNESS_RESPONSE {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef"),
            Ok((200, b"abc".to_vec()))
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 409 Conflict\r\n\
                  Transfer-Encoding: chunked\r\n\r\n2;x=y\r\n12\r\n1\r\n\n\r\n0\r\n\r\n"
            ),
            Ok((409, b"12\n".to_vec()))
        );
        assert_eq!(
            parse_response(b"HTTP/1.0 404 Not Found\r\n\r\nno"),
            Ok((404, b"no".to_vec()))
        );
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc").is_err());
        assert!(parse_response(b"HTTP/2 200\r\n\r\n").is_err());
        assert!(parse_response(b"garbage").is_err());
    }

    #[test]
    fn witness_paths() {
        assert!(is_witness_path("/risala-witness/add-checkpoint"));
        assert!(is_witness_path("/risala-witness/risala/handoff"));
        assert!(!is_witness_path("/risala-witness"));
        assert!(!is_witness_path("/risala-witnesses/add-checkpoint"));
    }
}

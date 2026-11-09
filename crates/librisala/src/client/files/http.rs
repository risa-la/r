//! A small HTTPS client for files and blobs (5.6, 12.12): one request per
//! connection, PUT, GET and DELETE, under the rules devices follow for
//! HTTPS elsewhere (4.4): TLS 1.3 with the CA check, no redirects, no TLS
//! resumption, and limits on time and size.
//!
//! Files and blobs are ciphertext checked by their hash, so what TLS adds
//! is keeping the URLs, which are capabilities (5.6), from the network.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{FileHttps, HttpError};
use crate::conn::{BoxFuture, CaVerifier};

/// How long connecting and the TLS handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the server may stay silent once connected.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most bytes of response head read.
const MAX_HEAD: usize = 16 * 1024;

/// [`FileHttps`] over TLS 1.3, checking certificates with a CA verifier.
#[derive(Clone)]
pub struct TlsFileHttps {
    verifier: CaVerifier,
    /// Where some hosts are reached instead of through DNS, for tests and
    /// development servers.
    hosts: Arc<std::collections::HashMap<String, std::net::SocketAddr>>,
}

impl std::fmt::Debug for TlsFileHttps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsFileHttps").finish_non_exhaustive()
    }
}

impl TlsFileHttps {
    /// A client that checks certificates with `verifier`, such as the
    /// platform's CA check.
    pub fn new(verifier: CaVerifier) -> TlsFileHttps {
        TlsFileHttps {
            verifier,
            hosts: Arc::default(),
        }
    }

    /// The same client, reaching each named host at the address given
    /// instead of through DNS: for tests and development servers. The
    /// certificate is still checked against the host's name.
    pub fn connect_to(
        mut self,
        hosts: impl IntoIterator<Item = (String, std::net::SocketAddr)>,
    ) -> TlsFileHttps {
        self.hosts = Arc::new(hosts.into_iter().collect());
        self
    }

    fn config(&self) -> Result<rustls::ClientConfig, HttpError> {
        // The default aws-lc-rs provider, which prefers X25519MLKEM768 but
        // also offers classical groups: file and blob hosts may be object
        // stores or CDNs, which 2.1's rule for chat servers does not bind.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| HttpError::Failed(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(self.verifier.clone())
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        max: usize,
    ) -> Result<(u16, Vec<u8>), HttpError> {
        let target = Target::parse(url).ok_or(HttpError::Url)?;
        let connector = TlsConnector::from(Arc::new(self.config()?));
        let name = ServerName::try_from(target.host.clone())
            .map_err(|e| HttpError::Failed(e.to_string()))?;
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let tcp = match self.hosts.get(&target.host) {
                Some(addr) => TcpStream::connect(addr).await,
                None => TcpStream::connect((target.host.as_str(), target.port)).await,
            }
            .map_err(|e| HttpError::Failed(e.to_string()))?;
            connector
                .connect(name, tcp)
                .await
                .map_err(|e| HttpError::Failed(e.to_string()))
        })
        .await
        .map_err(|_| HttpError::Failed("timed out connecting".into()))??;
        exchange(&mut stream, method, &target, body, max).await
    }
}

/// Sends one request on `stream` and reads its response: the status and
/// a body of at most `max` bytes.
pub(crate) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    method: &str,
    target: &Target,
    body: Option<&[u8]>,
    max: usize,
) -> Result<(u16, Vec<u8>), HttpError> {
    let host = if target.port == 443 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: risala\r\nConnection: close\r\n",
        target.path
    );
    if let Some(body) = body {
        head.push_str(&format!(
            "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
            body.len()
        ));
    } else if method != "GET" {
        head.push_str("Content-Length: 0\r\n");
    }
    head.push_str("\r\n");
    let io = |e: std::io::Error| HttpError::Failed(e.to_string());
    timed(stream.write_all(head.as_bytes()))
        .await?
        .map_err(io)?;
    if let Some(body) = body {
        for chunk in body.chunks(64 * 1024) {
            timed(stream.write_all(chunk)).await?.map_err(io)?;
        }
    }
    timed(stream.flush()).await?.map_err(io)?;

    let mut reader = Reader {
        stream,
        buf: Vec::new(),
    };
    let head = reader.head().await?;
    let status = head.status;
    // 3xx included: redirects are not followed (4.4).
    if !(200..300).contains(&status) {
        return Ok((status, Vec::new()));
    }
    let body = if method == "HEAD" || status == 204 {
        Vec::new()
    } else if head.chunked {
        reader.chunked(max).await?
    } else if let Some(len) = head.length {
        if len > max as u64 {
            return Err(HttpError::TooLarge);
        }
        reader.exact(len as usize).await?
    } else {
        reader.until_close(max).await?
    };
    Ok((status, body))
}

async fn timed<F: std::future::Future>(f: F) -> Result<F::Output, HttpError> {
    tokio::time::timeout(IDLE_TIMEOUT, f)
        .await
        .map_err(|_| HttpError::Failed("timed out".into()))
}

/// An `https` URL, split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Target {
    /// Splits an `https://host[:port]/path` URL. No user information, and
    /// IPv6 literals in brackets.
    pub(crate) fn parse(url: &str) -> Option<Target> {
        let rest = url
            .get(..8)
            .filter(|p| p.eq_ignore_ascii_case("https://"))
            .map(|_| &url[8..])?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.is_empty() || authority.contains('@') {
            return None;
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']')?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().ok()?,
                None if after.is_empty() => 443,
                None => return None,
            };
            (h.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_owned(), p.parse().ok()?),
                None => (authority.to_owned(), 443),
            }
        };
        if host.is_empty() {
            return None;
        }
        let path = path.split('#').next().unwrap_or("");
        let path = if path.is_empty() || path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        Some(Target { host, port, path })
    }
}

struct Head {
    status: u16,
    length: Option<u64>,
    chunked: bool,
}

struct Reader<'a, S> {
    stream: &'a mut S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Reader<'_, S> {
    async fn fill(&mut self) -> Result<bool, HttpError> {
        let mut chunk = [0u8; 16 * 1024];
        let n = timed(self.stream.read(&mut chunk))
            .await?
            .map_err(|e| HttpError::Failed(e.to_string()))?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    }

    async fn head(&mut self) -> Result<Head, HttpError> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..end]).into_owned();
                self.buf.drain(..end + 4);
                return parse_head(&head);
            }
            if self.buf.len() > MAX_HEAD {
                return Err(HttpError::Failed("response head too long".into()));
            }
            if !self.fill().await? {
                return Err(HttpError::Failed("connection closed".into()));
            }
        }
    }

    async fn exact(&mut self, len: usize) -> Result<Vec<u8>, HttpError> {
        while self.buf.len() < len {
            if !self.fill().await? {
                return Err(HttpError::Failed("body cut short".into()));
            }
        }
        let rest = self.buf.split_off(len);
        Ok(std::mem::replace(&mut self.buf, rest))
    }

    async fn until_close(&mut self, max: usize) -> Result<Vec<u8>, HttpError> {
        while self.fill().await? {
            if self.buf.len() > max {
                return Err(HttpError::TooLarge);
            }
        }
        Ok(std::mem::take(&mut self.buf))
    }

    async fn line(&mut self) -> Result<String, HttpError> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n") {
                let line = String::from_utf8_lossy(&self.buf[..end]).into_owned();
                self.buf.drain(..end + 2);
                return Ok(line);
            }
            if self.buf.len() > MAX_HEAD {
                return Err(HttpError::Failed("chunk line too long".into()));
            }
            if !self.fill().await? {
                return Err(HttpError::Failed("body cut short".into()));
            }
        }
    }

    async fn chunked(&mut self, max: usize) -> Result<Vec<u8>, HttpError> {
        let mut body = Vec::new();
        loop {
            let line = self.line().await?;
            let size = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size, 16)
                .map_err(|_| HttpError::Failed("bad chunk size".into()))?;
            if size == 0 {
                // Trailers, up to the empty line.
                while !self.line().await?.is_empty() {}
                return Ok(body);
            }
            if body.len() + size > max {
                return Err(HttpError::TooLarge);
            }
            body.extend(self.exact(size).await?);
            if !self.line().await?.is_empty() {
                return Err(HttpError::Failed("bad chunk end".into()));
            }
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_head(head: &str) -> Result<Head, HttpError> {
    let bad = || HttpError::Failed("bad response".into());
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(bad)?;
    let mut parts = status_line.splitn(3, ' ');
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(bad());
    }
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse().map_err(|_| bad())?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    Ok(Head {
        status,
        length,
        chunked,
    })
}

fn status_result(status: u16) -> Result<(), HttpError> {
    match status {
        200..=299 => Ok(()),
        404 | 410 => Err(HttpError::Gone(status)),
        other => Err(HttpError::Status(other)),
    }
}

impl FileHttps for TlsFileHttps {
    fn put<'a>(&'a self, url: &'a str, body: &'a [u8]) -> BoxFuture<'a, Result<(), HttpError>> {
        Box::pin(async move {
            let (status, _) = self.request("PUT", url, Some(body), 64 * 1024).await?;
            status_result(status)
        })
    }

    fn get<'a>(&'a self, url: &'a str, max: usize) -> BoxFuture<'a, Result<Vec<u8>, HttpError>> {
        Box::pin(async move {
            let (status, body) = self.request("GET", url, None, max).await?;
            status_result(status)?;
            Ok(body)
        })
    }

    fn delete<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), HttpError>> {
        Box::pin(async move {
            let (status, _) = self.request("DELETE", url, None, 64 * 1024).await?;
            status_result(status)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split() {
        assert_eq!(
            Target::parse("https://files.example.org/f/abc?x=1"),
            Some(Target {
                host: "files.example.org".into(),
                port: 443,
                path: "/f/abc?x=1".into()
            })
        );
        assert_eq!(
            Target::parse("HTTPS://h.test:8443").unwrap(),
            Target {
                host: "h.test".into(),
                port: 8443,
                path: "/".into()
            }
        );
        assert_eq!(Target::parse("https://[::1]:9/p").unwrap().host, "::1");
        assert!(Target::parse("http://h.test/").is_none());
        assert!(Target::parse("https://u@h.test/").is_none());
        assert!(Target::parse("https:///p").is_none());
    }

    async fn run(
        response: &[u8],
        method: &str,
        body: Option<&[u8]>,
    ) -> (Result<(u16, Vec<u8>), HttpError>, String) {
        let (mut client, mut server) = tokio::io::duplex(1 << 20);
        let response = response.to_vec();
        let server = tokio::spawn(async move {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = server.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                if let Some(end) = find(&got, b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&got[..end]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .map_or(0, |l| l.parse::<usize>().unwrap());
                    if got.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
            String::from_utf8_lossy(&got).to_string()
        });
        let target = Target::parse("https://files.test/f/x").unwrap();
        let result = exchange(&mut client, method, &target, body, 1000).await;
        (result, server.await.unwrap())
    }

    #[tokio::test]
    async fn requests_and_responses() {
        let (r, sent) = run(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
            "GET",
            None,
        )
        .await;
        assert_eq!(r.unwrap(), (200, b"abc".to_vec()));
        assert!(sent.starts_with("GET /f/x HTTP/1.1\r\nHost: files.test\r\n"));

        let (r, sent) = run(b"HTTP/1.1 201 Created\r\n\r\n", "PUT", Some(b"12345")).await;
        assert_eq!(r.unwrap().0, 201);
        assert!(sent.contains("Content-Length: 5\r\n"));
        assert!(sent.contains("Content-Type: application/octet-stream\r\n"));
        assert!(sent.ends_with("\r\n\r\n12345"));

        let (r, _) = run(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n",
            "GET",
            None,
        )
        .await;
        assert_eq!(r.unwrap().1, b"abc");

        let (r, _) = run(
            b"HTTP/1.1 302 Found\r\nLocation: https://x/\r\n\r\n",
            "GET",
            None,
        )
        .await;
        assert_eq!(r.unwrap().0, 302);

        let (r, _) = run(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n",
            "GET",
            None,
        )
        .await;
        assert_eq!(r, Err(HttpError::TooLarge));
    }
}

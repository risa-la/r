//! A small HTTP/1.1 client: one GET per connection, nothing else (4.4).
//!
//! It sends `Connection: close` and reads one response (4.4):
//!
//! - a 200 is a key file, whose body is read up to a size limit; one over
//!   it is [`Got::TooLarge`];
//! - a 404 or 410 is [`Got::Gone`];
//! - any other status, redirects included, is [`FetchError::Status`],
//!   returned without reading the body or following anything.
//!
//! Bodies may be framed by `Content-Length`, by chunked transfer coding or
//! by the end of the connection.
//!
//! It works over any stream, so the tests drive it through an in-memory
//! pipe.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::FetchError;

/// The most bytes of response head (status line and headers) read.
const MAX_HEAD: usize = 16 * 1024;

/// The longest chunk size line, extensions included, read in a chunked
/// body.
const MAX_CHUNK_LINE: usize = 1024;

/// The most interim (1xx) responses skipped before the real one.
const MAX_INTERIM: usize = 8;

/// What a response said, when it was an answer about the file (4.4).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Got {
    /// A 200, with its body.
    Body(Vec<u8>),
    /// A 200 whose body is larger than the limit. It was not read to the
    /// end.
    TooLarge,
    /// A 404 or 410: there is no key file.
    Gone,
}

/// Sends `GET <path>` for `host` over `stream`, and returns what the
/// response said: the body of a 200 response of at most `max_body` bytes,
/// a 200 that is larger, or a 404 or 410.
pub(crate) async fn get<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    max_body: usize,
) -> Result<Got, FetchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: risala-keyfetch/{}\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\
         \r\n",
        env!("CARGO_PKG_VERSION")
    );
    stream.write_all(request.as_bytes()).await.map_err(io)?;
    stream.flush().await.map_err(io)?;

    let mut reader = Reader {
        stream,
        buf: Vec::new(),
    };
    let mut interim = 0;
    let head = loop {
        let head = reader.head().await?;
        match head.status {
            // Interim responses such as 103 Early Hints come before the
            // real one.
            100 | 102..=199 if interim < MAX_INTERIM => interim += 1,
            200 => break head,
            404 | 410 => return Ok(Got::Gone),
            status => return Err(FetchError::Status(status)),
        }
    };
    let body = match head.framing {
        Framing::Chunked => reader.chunked(max_body).await,
        Framing::Length(len) => reader.exact(len, max_body).await,
        Framing::Close => reader.until_close(max_body).await,
    };
    match body {
        Ok(body) => Ok(Got::Body(body)),
        Err(TooLarge) => Ok(Got::TooLarge),
        Err(Failed(e)) => Err(e),
    }
}

/// Why a body was not read.
enum BodyError {
    /// It is larger than the limit.
    TooLarge,
    /// The response or the connection failed.
    Failed(FetchError),
}

use BodyError::{Failed, TooLarge};

impl From<FetchError> for BodyError {
    fn from(e: FetchError) -> BodyError {
        Failed(e)
    }
}

fn io(e: std::io::Error) -> FetchError {
    FetchError::Io(e.to_string())
}

/// How the body of a response ends.
#[derive(Debug, PartialEq, Eq)]
enum Framing {
    Chunked,
    Length(u64),
    Close,
}

/// The parts of a response head this client uses.
#[derive(Debug)]
struct Head {
    status: u16,
    framing: Framing,
}

/// Parses a response head: the status line and headers, without the blank
/// line that ends them. Lines end in CRLF, or LF alone (RFC 9112 2.2).
fn parse_head(head: &[u8]) -> Result<Head, FetchError> {
    let bad = FetchError::BadResponse;
    let head = std::str::from_utf8(head).map_err(|_| bad("the response head is not text"))?;
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(bad("not an HTTP/1 status line"));
    }
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("bad status code"));
    }
    let status: u16 = code.parse().map_err(|_| bad("bad status code"))?;

    let mut chunked = false;
    let mut length: Option<u64> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("bad header line"));
        };
        if name.is_empty() || name.contains([' ', '\t']) {
            return Err(bad("bad header name"));
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("transfer-encoding") {
            // Only chunked alone is understood: nothing asks for more.
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(bad("unsupported transfer coding"));
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad("bad Content-Length"));
            }
            let n: u64 = value.parse().unwrap_or(u64::MAX);
            if length.is_some_and(|old| old != n) {
                return Err(bad("conflicting Content-Length"));
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err(bad("compressed body"));
        }
    }
    let framing = match (chunked, length) {
        // RFC 9112 6.3: chunked wins, but a response with both is suspect.
        (true, Some(_)) => return Err(bad("both chunked and Content-Length")),
        (true, None) => Framing::Chunked,
        (false, Some(n)) => Framing::Length(n),
        (false, None) => Framing::Close,
    };
    Ok(Head { status, framing })
}

/// Reads from a stream through a buffer.
struct Reader<'a, S> {
    stream: &'a mut S,
    /// Bytes read but not yet used.
    buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Reader<'_, S> {
    /// Reads more into the buffer. Returns `false` at the end of the
    /// stream.
    ///
    /// A TLS connection closed without close_notify counts as an end. A
    /// body framed by its length or by chunks is checked to be complete
    /// anyway, and one framed by the close can only lose keys from its end,
    /// which anyone who can cut the connection can bring about in any case.
    async fn fill(&mut self) -> Result<bool, FetchError> {
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk).await {
            Ok(0) => Ok(false),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
            Err(e) => Err(io(e)),
        }
    }

    /// Reads a response head, through the blank line that ends it.
    async fn head(&mut self) -> Result<Head, FetchError> {
        loop {
            if let Some((end, skip)) = find_head_end(&self.buf) {
                let head = parse_head(&self.buf[..end]);
                self.buf.drain(..end + skip);
                return head;
            }
            if self.buf.len() > MAX_HEAD {
                return Err(FetchError::BadResponse("response head too long"));
            }
            if !self.fill().await? {
                return Err(FetchError::BadResponse("closed before the response head"));
            }
        }
    }

    /// Reads one line ending in LF (CRLF accepted), without the ending.
    async fn line(&mut self, max: usize) -> Result<Vec<u8>, FetchError> {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=i).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.buf.len() > max {
                return Err(FetchError::BadResponse("line too long in chunked body"));
            }
            if !self.fill().await? {
                return Err(FetchError::BadResponse("chunked body cut short"));
            }
        }
    }

    /// Takes `n` bytes, which must arrive before the stream ends.
    async fn take(&mut self, n: usize) -> Result<Vec<u8>, FetchError> {
        while self.buf.len() < n {
            if !self.fill().await? {
                return Err(FetchError::BadResponse("body cut short"));
            }
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// A body of `len` bytes (`Content-Length`).
    async fn exact(&mut self, len: u64, max: usize) -> Result<Vec<u8>, BodyError> {
        let len = usize::try_from(len).map_err(|_| TooLarge)?;
        if len > max {
            return Err(TooLarge);
        }
        Ok(self.take(len).await?)
    }

    /// A body that ends with the connection.
    async fn until_close(&mut self, max: usize) -> Result<Vec<u8>, BodyError> {
        loop {
            if self.buf.len() > max {
                return Err(TooLarge);
            }
            if !self.fill().await? {
                return Ok(std::mem::take(&mut self.buf));
            }
        }
    }

    /// A chunked body (RFC 9112 7.1). Chunk extensions and trailers are
    /// read and ignored.
    async fn chunked(&mut self, max: usize) -> Result<Vec<u8>, BodyError> {
        let mut body = Vec::new();
        loop {
            let line = self.line(MAX_CHUNK_LINE).await?;
            let size = line.split(|&b| b == b';').next().unwrap_or(&[]);
            let size = std::str::from_utf8(size)
                .ok()
                .map(|s| s.trim_matches([' ', '\t']))
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or(Failed(FetchError::BadResponse("bad chunk size")))?;
            // More than 16 hex digits does not fit, and is too large anyway.
            let size = u64::from_str_radix(size, 16).unwrap_or(u64::MAX);
            if size == 0 {
                // Trailers, up to the blank line.
                let mut trailers = 0;
                while !self.line(MAX_CHUNK_LINE).await?.is_empty() {
                    trailers += 1;
                    if trailers > 64 {
                        return Err(Failed(FetchError::BadResponse("too many trailers")));
                    }
                }
                return Ok(body);
            }
            let size = usize::try_from(size).map_err(|_| TooLarge)?;
            if size > max.saturating_sub(body.len()) {
                return Err(TooLarge);
            }
            body.extend(self.take(size).await?);
            if !self.line(0).await?.is_empty() {
                return Err(Failed(FetchError::BadResponse(
                    "chunk not followed by CRLF",
                )));
            }
        }
    }
}

/// Finds the blank line that ends a response head. Returns where the head
/// ends (at the LF of its last line, so the head may end in CR) and how
/// many bytes from there the blank line takes.
fn find_head_end(buf: &[u8]) -> Option<(usize, usize)> {
    for (i, _) in buf.iter().enumerate().filter(|&(_, &b)| b == b'\n') {
        match (buf.get(i + 1), buf.get(i + 2)) {
            (Some(b'\n'), _) => return Some((i, 2)),
            (Some(b'\r'), Some(b'\n')) => return Some((i, 3)),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `get` against a server that replies `response` and then
    /// closes. Returns the result and the request the server saw.
    async fn exchange(response: &[u8], max: usize) -> (Result<Got, FetchError>, String) {
        let (mut client, mut server) = tokio::io::duplex(1 << 20);
        let response = response.to_vec();
        let server = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
            String::from_utf8(request).unwrap()
        });
        let result = get(&mut client, "example.org", "/.well-known/risala/alice", max).await;
        drop(client);
        (result, server.await.unwrap())
    }

    #[tokio::test]
    async fn request_is_a_plain_get() {
        let (result, request) =
            exchange(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 100).await;
        assert_eq!(result.unwrap(), Got::Body(b"hi".to_vec()));
        assert!(
            request.starts_with("GET /.well-known/risala/alice HTTP/1.1\r\nHost: example.org\r\n")
        );
        assert!(request.contains("\r\nConnection: close\r\n"));
    }

    #[tokio::test]
    async fn framings() {
        let ok = |r: Result<Got, FetchError>| match r.unwrap() {
            Got::Body(body) => String::from_utf8(body).unwrap(),
            other => panic!("{other:?}"),
        };
        // Content-Length, with more bytes after it that are not read.
        let (r, _) = exchange(
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello world",
            100,
        )
        .await;
        assert_eq!(ok(r), "hello");
        // Until the connection closes, with LF-only lines.
        let (r, _) = exchange(b"HTTP/1.0 200 OK\nServer: x\n\nhello\nworld\n", 100).await;
        assert_eq!(ok(r), "hello\nworld\n");
        // Chunked, with an extension and a trailer.
        let (r, _) = exchange(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\nX-T: 1\r\n\r\n",
            100,
        )
        .await;
        assert_eq!(ok(r), "hello world");
        // An interim response first.
        let (r, _) = exchange(
            b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            100,
        )
        .await;
        assert_eq!(ok(r), "ok");
    }

    #[tokio::test]
    async fn only_200_404_and_410_are_answers() {
        for status in [
            201u16, 204, 301, 302, 304, 307, 308, 401, 403, 429, 500, 503,
        ] {
            let response = format!(
                "HTTP/1.1 {status} X\r\nLocation: https://example.org/elsewhere\r\nContent-Length: 0\r\n\r\n"
            );
            let (r, _) = exchange(response.as_bytes(), 100).await;
            assert_eq!(r, Err(FetchError::Status(status)));
        }
        for status in [404u16, 410] {
            let response = format!("HTTP/1.1 {status} X\r\nContent-Length: 3\r\n\r\nno\n");
            let (r, _) = exchange(response.as_bytes(), 100).await;
            assert_eq!(r, Ok(Got::Gone));
        }
    }

    #[tokio::test]
    async fn size_limit() {
        let len = |r: Result<Got, FetchError>| match r.unwrap() {
            Got::Body(body) => body.len(),
            other => panic!("{other:?}"),
        };
        let body = "x".repeat(100);
        let at = |n: usize| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n{}",
                &body[..n]
            )
        };
        assert_eq!(len(exchange(at(10).as_bytes(), 10).await.0), 10);
        assert_eq!(exchange(at(11).as_bytes(), 10).await.0, Ok(Got::TooLarge));
        // A huge Content-Length is refused before any body is read.
        let huge = b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n";
        assert_eq!(exchange(huge, 10).await.0, Ok(Got::TooLarge));

        let close = |n: usize| format!("HTTP/1.1 200 OK\r\n\r\n{}", &body[..n]);
        assert_eq!(len(exchange(close(10).as_bytes(), 10).await.0), 10);
        assert_eq!(
            exchange(close(11).as_bytes(), 10).await.0,
            Ok(Got::TooLarge)
        );

        let chunked = |n: usize| {
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nxxxxx\r\n{n:x}\r\n{}\r\n0\r\n\r\n",
                &body[..n]
            )
        };
        assert_eq!(len(exchange(chunked(5).as_bytes(), 10).await.0), 10);
        assert_eq!(
            exchange(chunked(6).as_bytes(), 10).await.0,
            Ok(Got::TooLarge)
        );
        let huge =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffffffff\r\n";
        assert_eq!(exchange(huge, 10).await.0, Ok(Got::TooLarge));
    }

    #[tokio::test]
    async fn bad_responses() {
        for response in [
            &b""[..],
            b"HTTP/1.1 200 OK\r\n",
            b"SSH-2.0-OpenSSH\r\n\r\n",
            b"HTTP/2 200\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabc\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ] {
            let (r, _) = exchange(response, 100).await;
            assert!(
                matches!(r, Err(FetchError::BadResponse(_) | FetchError::Status(101))),
                "{:?}: {r:?}",
                String::from_utf8_lossy(response)
            );
        }
        // A head that never ends.
        let mut long = b"HTTP/1.1 200 OK\r\n".to_vec();
        long.extend(std::iter::repeat_n(b"X-A: b\r\n", MAX_HEAD / 8 + 2).flatten());
        let (r, _) = exchange(&long, 100).await;
        assert_eq!(r, Err(FetchError::BadResponse("response head too long")));
    }

    #[test]
    fn head_end() {
        assert_eq!(find_head_end(b"a\r\n\r\nb"), Some((2, 3)));
        assert_eq!(find_head_end(b"a\n\nb"), Some((1, 2)));
        assert_eq!(find_head_end(b"a\r\nb\r\n\r\n"), Some((5, 3)));
        assert_eq!(find_head_end(b"a\r\nb\r\n"), None);
        assert_eq!(find_head_end(b"a\n\rb\n\n"), Some((4, 2)));
    }
}

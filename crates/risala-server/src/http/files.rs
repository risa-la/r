//! Blobs (12.12) and uploaded files (5.6) over HTTPS.
//!
//! | Request | What |
//! |---|---|
//! | `GET` or `HEAD /blobs/<96 hex digits>` | a blob, by its SHA-384 hash; INFO's `blobs` prefix (8.5) |
//! | `PUT /blob/<id>/<secret>` | BLOB's `put` URL |
//! | `PUT /up/<id>/<secret>` | UPLOAD's `put` URL |
//! | `GET` or `HEAD /f/<id>/<secret>` | UPLOAD's `get` URL |
//! | `DELETE /del/<id>/<secret>` | UPLOAD's `del` URL |
//!
//! A `put` URL works for one upload, which must start within 10 minutes.
//! Its body must have a `Content-Length` equal to the size BLOB or UPLOAD
//! named, and no `Transfer-Encoding`; a blob's must hash to its name. The
//! body goes to a temporary file, and is moved into place only once it is
//! complete and checked, so nothing is served half-written. Bodies and
//! downloads are streamed: each read or write may wait at most
//! [`IDLE_TIMEOUT`], and the whole must keep up at least [`MIN_RATE`]
//! ([`transfer_deadline`]), so that slow clients cannot hold the
//! listener's connections for hours.
//!
//! Answers: `201` for a stored body, `204` for a deletion, `400` for a
//! body of the wrong length or hash, `404` for a URL that leads nowhere
//! (unknown, wrong secret, expired, deleted, or a blob's `put` URL once
//! used), `410` for a `put` URL whose 10 minutes are over or an upload's
//! that was used, `411` without a
//! `Content-Length`, and `405` for another method.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest as _, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::server::Request;
use crate::core::keys::disk::{Files, PutTarget, Refused, blob_hash_of};
use crate::core::keys::paths;
use crate::secret::ct_eq;

/// The longest a body or download may stall: each read or write must make
/// progress within this.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The slowest a whole body or download may go, in bytes a second, after
/// [`TRANSFER_GRACE`].
pub const MIN_RATE: u64 = 64 * 1024;

/// The time every transfer has besides what [`MIN_RATE`] gives it.
pub const TRANSFER_GRACE: Duration = Duration::from_secs(60);

/// How long a body or download of `size` bytes may take in all.
pub fn transfer_deadline(size: u64) -> Duration {
    TRANSFER_GRACE.saturating_add(Duration::from_secs(size / MIN_RATE))
}

/// The size of each read and write while streaming.
const CHUNK: usize = 64 * 1024;

/// Whether `path` is one of blobs and files.
pub(crate) fn claims(path: &str) -> bool {
    [
        paths::BLOBS,
        paths::BLOB_PUT,
        paths::UPLOAD_PUT,
        paths::UPLOAD_GET,
        paths::UPLOAD_DEL,
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

/// A response with no body worth streaming.
struct Head {
    status: u16,
    reason: &'static str,
    allow: Option<&'static str>,
}

impl Head {
    const fn new(status: u16, reason: &'static str) -> Head {
        Head {
            status,
            reason,
            allow: None,
        }
    }
}

const CREATED: Head = Head::new(201, "Created");
const NO_CONTENT: Head = Head::new(204, "No Content");
const BAD_REQUEST: Head = Head::new(400, "Bad Request");
const NOT_FOUND: Head = Head::new(404, "Not Found");
const GONE: Head = Head::new(410, "Gone");
const LENGTH_REQUIRED: Head = Head::new(411, "Length Required");
const TIMEOUT: Head = Head::new(408, "Request Timeout");
const INTERNAL: Head = Head::new(500, "Internal Server Error");
const NOT_IMPLEMENTED: Head = Head::new(501, "Not Implemented");

fn refused(r: Refused) -> Head {
    match r {
        Refused::NotFound => NOT_FOUND,
        Refused::Gone => GONE,
        Refused::Internal => INTERNAL,
    }
}

/// Writes a short response, with its status as a text body.
async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, head: &Head) {
    let body = if head.status == 204 || head.status == 201 {
        String::new()
    } else {
        format!("{} {}\n", head.status, head.reason)
    };
    let mut text = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n",
        head.status,
        head.reason,
        body.len()
    );
    if let Some(allow) = head.allow {
        text.push_str(&format!("Allow: {allow}\r\n"));
    }
    text.push_str("\r\n");
    text.push_str(&body);
    let _ = tokio::time::timeout(IDLE_TIMEOUT, async {
        stream.write_all(text.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
}

fn method_not_allowed(allow: &'static str) -> Head {
    Head {
        allow: Some(allow),
        ..Head::new(405, "Method Not Allowed")
    }
}

/// Answers a request for a blob or file. `body` is what of its body came
/// with its head.
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &Request,
    body: Vec<u8>,
    files: &Files,
    peer: SocketAddr,
) {
    let path = request.path.as_str();
    let method = request.method.as_str();
    let status = if let Some(hex) = path.strip_prefix(paths::BLOBS) {
        match method {
            "GET" | "HEAD" => match blob_hash_of(hex) {
                Some(hash) => match files.blob(hash).await {
                    Ok((file, size)) => download(stream, file, size, method == "HEAD").await,
                    Err(r) => refused(r),
                },
                None => NOT_FOUND,
            },
            _ => method_not_allowed("GET, HEAD"),
        }
    } else if let Some(rest) = path.strip_prefix(paths::UPLOAD_GET) {
        match method {
            "GET" | "HEAD" => match files.upload(rest).await {
                Ok((file, size)) => download(stream, file, size, method == "HEAD").await,
                Err(r) => refused(r),
            },
            _ => method_not_allowed("GET, HEAD"),
        }
    } else if let Some(rest) = path.strip_prefix(paths::UPLOAD_DEL) {
        match method {
            "DELETE" => match files.delete(rest).await {
                Ok(()) => NO_CONTENT,
                Err(r) => refused(r),
            },
            _ => method_not_allowed("DELETE"),
        }
    } else {
        let (prefix, rest) = match path.strip_prefix(paths::BLOB_PUT) {
            Some(rest) => (paths::BLOB_PUT, rest),
            None => (
                paths::UPLOAD_PUT,
                path.strip_prefix(paths::UPLOAD_PUT).unwrap_or_default(),
            ),
        };
        match method {
            "PUT" => put(stream, request, body, files, prefix, rest).await,
            _ => method_not_allowed("PUT"),
        }
    };
    tracing::debug!(target: crate::net::ADDRESSES, %peer, status = status.status, "HTTPS request for a blob or file");
    if status.status != 200 {
        respond(stream, &status).await;
    }
}

/// The 200 the downloads send themselves.
const SENT: Head = Head::new(200, "OK");

/// Sends the file at `file`, of `size` bytes, or only its head.
async fn download<S: AsyncWrite + Unpin>(
    stream: &mut S,
    file: PathBuf,
    size: u64,
    head_only: bool,
) -> Head {
    let mut file = match tokio::fs::File::open(&file).await {
        Ok(file) => file,
        // Deleted since it was looked up.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return NOT_FOUND,
        Err(e) => {
            tracing::error!(path = %file.display(), "opening a blob or file: {e}");
            return INTERNAL;
        }
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\n\
         X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n"
    );
    let sent = async {
        within(stream.write_all(head.as_bytes())).await?;
        if !head_only {
            let mut left = size;
            let mut buf = vec![0u8; CHUNK];
            while left > 0 {
                let want = usize::try_from(left.min(CHUNK as u64)).unwrap_or(CHUNK);
                let n = within(file.read(&mut buf[..want])).await?;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                within(stream.write_all(&buf[..n])).await?;
                left -= n as u64;
            }
        }
        within(stream.shutdown()).await
    };
    match tokio::time::timeout(transfer_deadline(size), sent).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::debug!("sending a blob or file: {e}"),
        Err(_) => tracing::debug!("sending a blob or file: too slow"),
    }
    SENT
}

/// Runs one read or write, failing if it makes no progress within
/// [`IDLE_TIMEOUT`].
async fn within<T>(io: impl Future<Output = std::io::Result<T>>) -> std::io::Result<T> {
    tokio::time::timeout(IDLE_TIMEOUT, io)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

/// Takes a body for the `put` URL `<prefix><rest>`.
async fn put<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &Request,
    mut body: Vec<u8>,
    files: &Files,
    prefix: &str,
    rest: &str,
) -> Head {
    if request.transfer_encoding {
        return NOT_IMPLEMENTED;
    }
    let Some(length) = request.content_length else {
        return LENGTH_REQUIRED;
    };
    let target = match files.claim_put(prefix, rest).await {
        Ok(target) => target,
        Err(r) => return refused(r),
    };
    // 5.6, 12.12: a body whose length differs from the size is refused.
    // The URL is used up all the same: it works for one upload.
    if length != target.size() || body.len() as u64 > length {
        return BAD_REQUEST;
    }
    if request.expect_continue
        && within(stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n"))
            .await
            .is_err()
    {
        return TIMEOUT;
    }
    let (tmp, mut file) = match files.temp_file().await {
        Ok(tmp) => tmp,
        Err(e) => {
            tracing::error!("creating a temporary file: {e}");
            return INTERNAL;
        }
    };
    let mut hasher = Sha384::new();
    let received = async {
        let mut left = length;
        let mut buf = vec![0u8; CHUNK];
        loop {
            if !body.is_empty() {
                hasher.update(&body);
                within(file.write_all(&body)).await?;
                left -= body.len() as u64;
                body.clear();
            }
            if left == 0 {
                break;
            }
            let want = usize::try_from(left.min(CHUNK as u64)).unwrap_or(CHUNK);
            let n = within(stream.read(&mut buf[..want])).await?;
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            body.extend_from_slice(&buf[..n]);
        }
        within(file.sync_all()).await
    };
    let result = tokio::time::timeout(transfer_deadline(length), received)
        .await
        .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
    drop(file);
    let status = match result {
        Err(e) => {
            tracing::debug!("receiving a blob or file: {e}");
            if e.kind() == std::io::ErrorKind::TimedOut {
                TIMEOUT
            } else {
                BAD_REQUEST
            }
        }
        Ok(()) => match &target {
            PutTarget::Blob(put) if !ct_eq(&hasher.finalize()[..], put.hash.hash()) => BAD_REQUEST,
            _ => match files.commit(target, tmp.clone()).await {
                Ok(true) => return CREATED,
                Ok(false) => NOT_FOUND,
                Err(r) => refused(r),
            },
        },
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    status
}

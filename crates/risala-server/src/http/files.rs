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
//! [`IDLE_TIMEOUT`], the whole must keep up at least [`MIN_RATE`]
//! ([`transfer_deadline`]), and at every moment the last
//! `files.min_rate_secs` must have moved `files.min_rate` bytes a second
//! ([`Pace`], 10.6), so that slow clients cannot hold the listener's
//! transfer slots for long.
//!
//! Answers: `201` for a stored body, `204` for a deletion, `400` for a
//! body of the wrong length or hash, `404` for a URL that leads nowhere
//! (unknown, wrong secret, expired, deleted, or a blob's `put` URL once
//! used), `410` for a `put` URL whose 10 minutes are over or an upload's
//! that was used, `411` without a
//! `Content-Length`, and `405` for another method.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest as _, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::Instant;

use super::server::Request;
use crate::core::keys::disk::{Files, PutTarget, Refused, blob_hash_of};
use crate::core::keys::paths;
use crate::secret::ct_eq;

/// The longest a body or download may stall: each read or write must make
/// progress within this.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The slowest a whole body or download may go on average, in bytes a
/// second, after [`TRANSFER_GRACE`], for its overall deadline. A running
/// minimum ([`Pace`]) applies besides.
pub const MIN_RATE: u64 = 64 * 1024;

/// The time every transfer has besides what [`MIN_RATE`] gives it.
pub const TRANSFER_GRACE: Duration = Duration::from_secs(60);

/// How long a body or download of `size` bytes may take in all.
pub fn transfer_deadline(size: u64) -> Duration {
    TRANSFER_GRACE.saturating_add(Duration::from_secs(size / MIN_RATE))
}

/// The size of each read and write while streaming.
const CHUNK: usize = 64 * 1024;

/// A running minimum rate for one transfer (10.6, PLAN item 63): at every
/// moment, the bytes moved in the last `window` must be at least `rate`
/// a second over it, or all that is left if that is less. The overall
/// deadline ([`transfer_deadline`]) alone would let a client that reads
/// slowly hold a slot for over an hour.
#[derive(Debug)]
pub(crate) struct Pace {
    window: Duration,
    /// The bytes each window must move.
    need: u64,
    /// The bytes moved so far.
    moved: u64,
    /// When the bytes moved reached each count, oldest first: only those
    /// that may still decide the deadline, at most about one a
    /// [`granule`](Self::granule).
    points: VecDeque<(Instant, u64)>,
}

impl Pace {
    /// The pace of a transfer of `size` bytes starting now, or none if
    /// `rate` is 0.
    pub(crate) fn new(rate: u64, window: Duration, size: u64) -> Option<Pace> {
        Pace::starting(rate, window, size, Instant::now())
    }

    fn starting(rate: u64, window: Duration, size: u64, now: Instant) -> Option<Pace> {
        if rate == 0 {
            return None;
        }
        let per_window = u128::from(rate) * window.as_millis() / 1000;
        let need = u64::try_from(per_window).unwrap_or(u64::MAX).min(size);
        Some(Pace {
            window,
            need,
            moved: 0,
            points: VecDeque::from([(now, 0)]),
        })
    }

    /// Progress closer together than this counts as one point.
    fn granule(&self) -> Duration {
        self.window / 32
    }

    /// `n` more bytes moved at `now`.
    fn moved_at(&mut self, n: usize, now: Instant) {
        self.moved = self.moved.saturating_add(n as u64);
        let granule = self.granule();
        let several = self.points.len() > 1;
        match self.points.back_mut() {
            // The first point is when the transfer started, and stays so.
            Some((at, count)) if several && now.saturating_duration_since(*at) < granule => {
                *count = self.moved;
            }
            _ => self.points.push_back((now, self.moved)),
        }
        // A point whose count is at most `moved - need` can no longer
        // decide when the transfer is too slow.
        if let Some(threshold) = self.moved.checked_sub(self.need) {
            while self.points.len() > 1 && self.points.front().is_some_and(|(_, c)| *c <= threshold) {
                self.points.pop_front();
            }
        }
    }

    /// When the transfer is too slow if nothing more moves: a window after
    /// the earliest point with more than `moved - need` bytes.
    fn deadline(&self) -> Option<Instant> {
        if self.need == 0 {
            return None;
        }
        let threshold = self.moved.checked_sub(self.need);
        self.points
            .iter()
            .find(|(_, count)| threshold.is_none_or(|t| *count > t))
            .map(|(at, _)| *at + self.window)
    }
}

/// Runs one read or write of a transfer: it fails if it makes no progress
/// within [`IDLE_TIMEOUT`], or by the time `pace` says the transfer is too
/// slow. `bytes` says how many bytes its result moved.
async fn paced<T>(
    pace: &mut Option<Pace>,
    io: impl Future<Output = std::io::Result<T>>,
    bytes: impl FnOnce(&T) -> usize,
) -> std::io::Result<T> {
    let idle = Instant::now() + IDLE_TIMEOUT;
    let until = match pace.as_ref().and_then(Pace::deadline) {
        Some(deadline) => deadline.min(idle),
        None => idle,
    };
    let done = tokio::time::timeout_at(until, io)
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    if let Some(pace) = pace {
        pace.moved_at(bytes(&done), Instant::now());
    }
    Ok(done)
}

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
                    Ok((file, size)) => download(stream, file, size, method == "HEAD", files).await,
                    Err(r) => refused(r),
                },
                None => NOT_FOUND,
            },
            _ => method_not_allowed("GET, HEAD"),
        }
    } else if let Some(rest) = path.strip_prefix(paths::UPLOAD_GET) {
        match method {
            "GET" | "HEAD" => match files.upload(rest).await {
                Ok((file, size)) => download(stream, file, size, method == "HEAD", files).await,
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
    files: &Files,
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
    let (rate, window) = files.min_rate();
    let mut pace = Pace::new(rate, window, if head_only { 0 } else { size });
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
                paced(&mut pace, stream.write_all(&buf[..n]), |()| n).await?;
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
    let (rate, window) = files.min_rate();
    let mut pace = Pace::new(rate, window, length.saturating_sub(body.len() as u64));
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
            let n = paced(&mut pace, stream.read(&mut buf[..want]), |n| *n).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;

    /// A transfer is too slow once the last window moved less than the
    /// rate over it: 16 KiB a second over 30 seconds is 480 KiB a window.
    #[test]
    fn pace_keeps_a_running_minimum() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let window = s(30);
        let mut pace = Pace::starting(16 * KIB, window, 10_000 * KIB, t0).unwrap();
        // Nothing yet: the first 480 KiB are due 30 seconds in.
        assert_eq!(pace.deadline(), Some(t0 + s(30)));
        // Fast at first: 1 MiB in the first second, then nothing more is
        // due until a window after the point past which 480 KiB still
        // count, here the first second.
        pace.moved_at(1024 * KIB as usize, t0 + s(1));
        assert_eq!(pace.deadline(), Some(t0 + s(31)));
        // A trickle afterwards does not keep it alive: 1 KiB a second for
        // 29 seconds leaves the deadline where it was.
        for i in 2..=30 {
            pace.moved_at(KIB as usize, t0 + s(i));
        }
        assert_eq!(pace.deadline(), Some(t0 + s(31)));
        // At 16 KiB a second it goes on for as long as it keeps that up.
        let mut pace = Pace::starting(16 * KIB, window, 10_000 * KIB, t0).unwrap();
        for i in 1..=300 {
            pace.moved_at(16 * KIB as usize, t0 + s(i));
            assert!(pace.deadline().unwrap() > t0 + s(i), "{i}");
        }
        assert!(pace.points.len() <= 40, "{}", pace.points.len());
    }

    /// A transfer smaller than a window's bytes must finish within the
    /// window; one of no bytes has no deadline; a rate of 0 is no pace.
    #[test]
    fn pace_of_small_transfers() {
        let t0 = Instant::now();
        let window = Duration::from_secs(30);
        let mut pace = Pace::starting(16 * KIB, window, 100 * KIB, t0).unwrap();
        pace.moved_at(50 * KIB as usize, t0 + Duration::from_secs(10));
        assert_eq!(pace.deadline(), Some(t0 + window));
        assert_eq!(Pace::starting(16 * KIB, window, 0, t0).unwrap().deadline(), None);
        assert!(Pace::starting(0, window, 100, t0).is_none());
    }
}

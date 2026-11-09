//! Reports to the operators (5.8): REPORT, RESOLVE, ADMIN REPORTS and the
//! report lines.
//!
//! ```text
//! struct {
//!     uint64 seq;              // the post's seq in the mailbox
//!     opaque frank_key[32];
//!     opaque content<V>;       // the RisalaMessage's content
//! } ReportedPost;
//!
//! struct {
//!     uint8 version;           // 1
//!     ReportedPost target;
//!     ReportedPost context<V>; // up to 10 earlier posts, oldest first
//!     opaque author<V>;        // the uid the reporter says wrote the target
//!     opaque reason<V>;        // UTF-8, at most 512 bytes
//! } RisalaReport;
//! ```
//!
//! The server checks that every post named is still kept and is an
//! application message, that HMAC-SHA-384(`frank_key`, `content`) is the
//! franking tag in its RisalaAAD (compared in constant time), and the
//! report's own limits. It then keeps copies of the posts until the report
//! is resolved, and sends the report line to every operator's connections.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::hmac;
use risala_mls::framing::{ContentType, read_post};
use risala_proto::binary::{ReportData, ReportRef};
use risala_proto::codec::{DecodeError, Reader};
use risala_proto::content::{Content, ContentLine, FileUrl};
use risala_proto::error::ErrorCode;
use risala_proto::mls::Pseudonym;
use risala_proto::names::{BoxName, Id, Uid};
use risala_proto::server::{ErrResponse, OkResponse, Report, ServerLine};

use super::super::Inner;
use super::super::command::{Cx, Reply, err};
use super::super::rate::{WindowLimit, network};
use super::super::state::Who;
use super::super::{admin, keys};
use crate::store::{KeptPost, NewReport, PostBody, StoredReport};

/// How much of a reported post that is a blob the server reads: enough
/// for its framing and RisalaAAD, which hold the franking tag (12.9).
const REPORT_PREFIX: usize = 16 * 1024;

/// The most context posts a report may name (5.8).
pub(crate) const MAX_CONTEXT: usize = 10;

/// The longest reason, in bytes (5.8).
pub(crate) const MAX_REASON: usize = 512;

/// The length of a frank key (5.8, 12.9).
pub(crate) const FRANK_KEY_LEN: usize = 32;

/// Who a report counts against, for its rate limit (5.8: servers SHOULD
/// rate-limit reports).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Reporter {
    /// A signed-in identity.
    Identity(Uid),
    /// Anonymous and guest connections, by network (`rate::network`).
    Network(IpAddr),
}

/// The report part of the misc area's state.
#[derive(Debug)]
pub(crate) struct State {
    limit: WindowLimit<Reporter>,
}

impl Default for State {
    fn default() -> State {
        State {
            limit: WindowLimit::new(Duration::from_secs(60 * 60)),
        }
    }
}

/// One post a report names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportedPost {
    /// Its seq in the mailbox.
    pub(crate) seq: u64,
    /// The key of its franking tag.
    pub(crate) frank_key: [u8; FRANK_KEY_LEN],
    /// The RisalaMessage's content.
    pub(crate) content: Vec<u8>,
}

/// A RisalaReport (5.8), read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RisalaReport {
    pub(crate) target: ReportedPost,
    pub(crate) context: Vec<ReportedPost>,
    pub(crate) author: Uid,
    pub(crate) reason: String,
}

fn reported_post(r: &mut Reader<'_>) -> Result<ReportedPost, DecodeError> {
    Ok(ReportedPost {
        seq: r.u64()?,
        frank_key: *r.fixed::<FRANK_KEY_LEN>()?,
        content: r.vector()?.to_vec(),
    })
}

impl RisalaReport {
    /// Reads a RisalaReport, and checks its own limits (5.8): version 1, at
    /// most 10 context posts with strictly increasing seqs below the
    /// target's, an author that is a uid, a reason of UTF-8 of at most 512
    /// bytes, and nothing after it. Any failure is `ERR invalid`.
    pub(crate) fn decode(bytes: &[u8]) -> Result<RisalaReport, &'static str> {
        let mut r = Reader::new(bytes);
        let read = |r: &mut Reader<'_>| -> Result<_, DecodeError> {
            if r.u8()? != 1 {
                return Err(DecodeError("unknown RisalaReport version"));
            }
            let target = reported_post(r)?;
            let context = r.nested(|r| {
                let mut posts = Vec::new();
                while !r.is_empty() {
                    if posts.len() == MAX_CONTEXT {
                        return Err(DecodeError("more than 10 context posts"));
                    }
                    posts.push(reported_post(r)?);
                }
                Ok(posts)
            })?;
            let author = r.vector()?.to_vec();
            let reason = r.vector()?.to_vec();
            r.end()?;
            Ok((target, context, author, reason))
        };
        let (target, context, author, reason) = read(&mut r).map_err(|e| e.0)?;
        let mut last = 0;
        for post in &context {
            if post.seq <= last || post.seq >= target.seq {
                return Err("context seqs must increase and come before the target");
            }
            last = post.seq;
        }
        if target.seq == 0 {
            return Err("a seq is at least 1");
        }
        let author = std::str::from_utf8(&author)
            .ok()
            .and_then(|a| a.parse::<Uid>().ok())
            .filter(|uid| uid.as_str().as_bytes() == author.as_slice())
            .ok_or("the author is not a uid")?;
        if reason.len() > MAX_REASON {
            return Err("the reason is longer than 512 bytes");
        }
        let reason = String::from_utf8(reason).map_err(|_| "the reason is not UTF-8")?;
        Ok(RisalaReport {
            target,
            context,
            author,
            reason,
        })
    }

    /// The target, then the context posts.
    fn posts(&self) -> impl Iterator<Item = &ReportedPost> {
        std::iter::once(&self.target).chain(&self.context)
    }
}

/// HMAC-SHA-384(`frank_key`, `content`) (12.9).
fn frank(frank_key: &[u8], content: &[u8]) -> [u8; 48] {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA384, frank_key), content)
        .as_ref()
        .try_into()
        .expect("HMAC-SHA-384 is 48 bytes")
}

/// Why a reported post does not pass: it is not an application message,
/// or the franking does not match (`ERR invalid`).
struct PostCheck(&'static str);

/// Checks one reported post against the post the server keeps (5.8), and
/// returns the pseudonym of its RisalaAAD.
fn check_post(post: &ReportedPost, kept: &[u8]) -> Result<Pseudonym, PostCheck> {
    let (framing, aad) = read_post(kept).map_err(|_| PostCheck("not an MLS message"))?;
    if framing.content_type != ContentType::Application {
        return Err(PostCheck("not an application message"));
    }
    let tag = aad.frank.ok_or(PostCheck("no franking tag"))?;
    let expected = frank(&post.frank_key, &post.content);
    if !crate::secret::ct_eq(&expected, &tag) {
        return Err(PostCheck("the franking tag does not match"));
    }
    // An application message is a PrivateMessage, whose RisalaAAD has a
    // pseudonym (7.3, 12.9).
    let pseudonym = aad.pseudonym.ok_or(PostCheck("no pseudonym"))?;
    Ok(Pseudonym::from_bytes(pseudonym.0))
}

/// The `get` URLs of files the content shares (5.6), which the server
/// keeps with the report.
fn file_urls(content: &[u8]) -> Vec<FileUrl> {
    let Ok(content) = Content::parse(content) else {
        return Vec::new();
    };
    content
        .lines()
        .iter()
        .filter_map(|line| match line {
            ContentLine::Text(text) => text.file.as_ref().map(|f| f.url.clone()),
            _ => None,
        })
        .collect()
}

/// The report line for the operators (5.8).
pub(crate) fn report_line(report: &StoredReport) -> ServerLine {
    ServerLine::Report(Report {
        id: report.id.clone(),
        t: report.t,
        pseudonym: report.pseudonym,
        from: report.from.clone(),
        mailbox: report.mailbox,
        report: ReportRef::Inline(report.report.clone()),
    })
}

/// `REPORT <box> <report>` (5.8), on any kind of connection.
pub(super) async fn report(cx: &Cx, mailbox: BoxName, data: ReportData) -> Reply {
    let inner: &Arc<Inner> = &cx.inner;
    let reporter = match &cx.who {
        Who::SignedIn(device) => Reporter::Identity(device.uid.clone()),
        _ => Reporter::Network(network(cx.peer.ip())),
    };
    let max = inner.config.limits.reports_per_hour;
    // Every REPORT uses up its slot, whatever becomes of it: one that fails
    // has made the server read posts all the same.
    match inner.misc.reports.limit.take(reporter, max, inner.now()) {
        Ok(slot) => {
            if let Some(slot) = slot {
                slot.keep();
            }
        }
        Err(retry) => return Err(err(ErrorCode::RateLimited).with_retry(retry)),
    }
    let report = RisalaReport::decode(&data.decode())
        .map_err(|why| err(ErrorCode::Invalid).with_message(why))?;
    // Every post named must still be kept (5.8).
    let seqs: Vec<u64> = report.posts().map(|p| p.seq).collect();
    let kept: Vec<Option<KeptPost>> = cx
        .db(move |store| {
            seqs.iter()
                .map(|seq| store.kept_post(&mailbox, *seq))
                .collect()
        })
        .await?;
    let mut copies = Vec::new();
    let mut pseudonym = None;
    for (post, kept) in report.posts().zip(kept) {
        let Some(kept) = kept else {
            return Err(err(ErrorCode::NotFound));
        };
        // The franking tag is in the RisalaAAD, near the start: a post
        // that is a blob is checked from its first bytes, and kept by its
        // hash, never read whole (12.12).
        let (framing, copy) = match kept.message {
            Ok(message) => (message.clone(), PostBody::Inline(message)),
            Err(blob) => {
                let (prefix, size) = keys::blob_prefix(inner, &blob, REPORT_PREFIX)
                    .await
                    .map_err(ErrResponse::from)?;
                let framing = if prefix.len() as u64 == size {
                    prefix
                } else {
                    super::super::mailbox::private_message_stub(&prefix, size)
                        .ok_or_else(|| err(ErrorCode::Invalid).with_message("not an MLS message"))?
                };
                (framing, PostBody::Blob(blob))
            }
        };
        match check_post(post, &framing) {
            Ok(p) => {
                pseudonym.get_or_insert(p);
            }
            Err(PostCheck(why)) => return Err(err(ErrorCode::Invalid).with_message(why)),
        }
        copies.push((post.seq, kept.t, copy));
    }
    let pseudonym = pseudonym.expect("a report names its target");
    let id: Id = crate::secret::random_token(26)
        .map_err(|e| {
            tracing::error!("no random report id: {e}");
            err(ErrorCode::Internal)
        })?
        .parse()
        .expect("a random token is an id");
    let stored = StoredReport {
        id: id.clone(),
        mailbox,
        report: data,
        t: inner.now(),
        pseudonym,
        from: cx.device().map(|d| d.uid.clone()),
    };
    let new = NewReport {
        id: stored.id.clone(),
        mailbox: stored.mailbox,
        report: stored.report.clone(),
        t: stored.t,
        pseudonym: stored.pseudonym,
        from: stored.from.clone(),
        posts: copies,
    };
    // Blobs and files kept for reports count apart from what the server
    // stores for conversations, so that reports cannot keep that full,
    // with their own bound (PLAN item 63; 5.8 is silent on it).
    let max_reported = inner.config.limits.max_reported_bytes;
    let dropped = cx
        .db(move |store| store.add_report(&new, max_reported))
        .await?;
    if dropped > 0 {
        tracing::warn!(
            "a report's {dropped} blob posts are not kept past retention: \
             limits.max_reported_bytes is reached"
        );
    }
    // Files the posts share stay until the report is resolved (5.8).
    let urls: Vec<FileUrl> = report.posts().flat_map(|p| file_urls(&p.content)).collect();
    if !urls.is_empty() {
        keys::keep_files_for_report(inner, &id, &urls).await;
    }
    tracing::info!("report made");
    super::to_operators(inner, &report_line(&stored), None);
    Ok(OkResponse::new().with_id(&id))
}

/// `RESOLVE <id>` (5.8): closes a report. Someone who is not an operator
/// gets `ERR not-found`, as for an id that does not exist.
pub(super) async fn resolve(cx: &Cx, id: Id) -> Reply {
    let operator = cx
        .device()
        .is_some_and(|d| admin::is_operator(&cx.inner, &d.uid));
    if !operator {
        return Err(err(ErrorCode::NotFound));
    }
    let which = id.clone();
    if !cx.db(move |store| store.resolve_report(&which)).await? {
        return Err(err(ErrorCode::NotFound));
    }
    keys::release_files_for_report(&cx.inner, &id).await;
    tracing::info!("report resolved");
    super::to_operators(&cx.inner, &ServerLine::Resolved { id }, Some(cx.conn));
    Ok(OkResponse::new())
}

/// `ADMIN REPORTS` (5.8, 10.4): the line of every open report.
pub(crate) async fn admin_reports(cx: &Cx) -> Reply {
    let reports = cx.db(|store| store.open_reports()).await?;
    for (i, report) in reports.iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            cx.wait_for_room().await;
        }
        cx.send(report_line(report));
    }
    Ok(OkResponse::new())
}

#[cfg(test)]
pub(crate) mod tests {
    use risala_proto::codec::Writer;

    use super::*;

    /// Encodes a RisalaReport.
    pub(crate) fn encode(
        target: &ReportedPost,
        context: &[ReportedPost],
        author: &str,
        reason: &str,
    ) -> Vec<u8> {
        let post = |w: &mut Writer, p: &ReportedPost| {
            w.u64(p.seq).fixed(&p.frank_key).vector(&p.content);
        };
        let mut ctx = Writer::new();
        for p in context {
            post(&mut ctx, p);
        }
        let mut w = Writer::new();
        w.u8(1);
        post(&mut w, target);
        w.vector(&ctx.finish())
            .vector(author.as_bytes())
            .vector(reason.as_bytes());
        w.finish()
    }

    pub(crate) fn post(seq: u64) -> ReportedPost {
        ReportedPost {
            seq,
            frank_key: [seq as u8; 32],
            content: format!("TEXT post {seq}\n").into_bytes(),
        }
    }

    #[test]
    fn decoding_checks_the_limits() {
        let ok = encode(&post(9), &[post(2), post(5)], "bob@example.org", "spam");
        let r = RisalaReport::decode(&ok).unwrap();
        assert_eq!(r.target.seq, 9);
        assert_eq!(r.context.len(), 2);
        assert_eq!(r.author.as_str(), "bob@example.org");
        assert_eq!(r.reason, "spam");
        // Guests are uids too.
        assert!(RisalaReport::decode(&encode(&post(9), &[], "~sam", "")).is_ok());

        let eleven: Vec<ReportedPost> = (1..=11).map(post).collect();
        let ten = &eleven[..10];
        assert!(RisalaReport::decode(&encode(&post(20), ten, "a@b.org", "")).is_ok());
        for bad in [
            encode(&post(20), &eleven, "a@b.org", ""),
            encode(&post(9), &[post(5), post(2)], "a@b.org", ""),
            encode(&post(9), &[post(5), post(5)], "a@b.org", ""),
            encode(&post(5), &[post(5)], "a@b.org", ""),
            encode(&post(5), &[post(7)], "a@b.org", ""),
            encode(&post(0), &[], "a@b.org", ""),
            encode(&post(9), &[], "not a uid", ""),
            encode(&post(9), &[], "Bob@example.org", ""),
            encode(&post(9), &[], "a@b.org", &"x".repeat(513)),
        ] {
            assert!(RisalaReport::decode(&bad).is_err());
        }
        assert!(RisalaReport::decode(&encode(&post(9), &[], "a@b.org", &"x".repeat(512))).is_ok());
        let mut trailing = ok.clone();
        trailing.push(0);
        assert!(RisalaReport::decode(&trailing).is_err());
        let mut version = ok;
        version[0] = 2;
        assert!(RisalaReport::decode(&version).is_err());
        let mut bad_utf8 = encode(&post(9), &[], "a@b.org", "ab");
        let n = bad_utf8.len();
        bad_utf8[n - 1] = 0xff;
        assert!(RisalaReport::decode(&bad_utf8).is_err());
    }

    #[test]
    fn franking_is_hmac_sha384() {
        // RFC 4231, test case 2, for HMAC-SHA-384.
        let tag = frank(b"Jefe", b"what do ya want for nothing?");
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        );
    }

    #[test]
    fn files_in_content() {
        let content = format!(
            "@file=https://chat.example.org/f/abc;file-key={}=;file-hash={} TEXT a file\nTEXT no file\n",
            "A".repeat(43),
            "A".repeat(64)
        );
        let content = content.as_bytes();
        let urls = file_urls(content);
        assert_eq!(urls.len(), 1, "{urls:?}");
        assert_eq!(urls[0].as_str(), "https://chat.example.org/f/abc");
        assert!(file_urls(b"not lines").is_empty());
    }
}

//! The lines of Sections 5 to 7: posts (5.2, 7.1), ROOM, GROUPINFO, GONE
//! and DROP (6.1, 10.4), and REPORT and RESOLVED (5.8).

use super::ServerLine;
use crate::binary::ReportData;
use crate::error::ParseError;
use crate::line::{LineBuilder, Params, Tags};
use crate::mls::{MlsMessage, OrBlob, Pseudonym};
use crate::names::{BoxName, Id, Seq, Uid};
use crate::parse::{bad, last, number, parse_tag, required_tag, text_max, tok};
use crate::time::Timestamp;
use crate::types::MAX_TOPIC;

/// A post (5.2): `@seq=<seq>;t=<timestamp> POST <box> <message>`, sent
/// live to the connections that follow the mailbox, or in response to
/// FETCH (7.1).
///
/// A live post, from `POST ... live=yes`, has no `seq` (5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    /// The `seq` tag: the post's position in its mailbox, or `None` for a
    /// live post, which is not kept.
    pub seq: Option<Seq>,
    /// The `t` tag: when the server accepted the post. Every kept post has
    /// it.
    ///
    /// The spec does not say whether a live post has `t` (5.2), so it is
    /// optional only when `seq` is absent.
    pub t: Option<Timestamp>,
    /// The mailbox.
    pub mailbox: BoxName,
    /// The MLSMessage, or a blob-ref if it is too large for a line.
    pub message: OrBlob<MlsMessage>,
}

impl Post {
    /// A kept post, with its `seq` and `t`.
    pub fn new(seq: Seq, t: Timestamp, mailbox: BoxName, message: OrBlob<MlsMessage>) -> Post {
        Post {
            seq: Some(seq),
            t: Some(t),
            mailbox,
            message,
        }
    }

    /// Whether this is a live post (5.2): one without a `seq`.
    pub fn is_live(&self) -> bool {
        self.seq.is_none()
    }
}

/// A report to the operators (5.8):
/// `@report=<id>;t=<timestamp>;pseudonym=<pseudonym>[;from=<uid>] REPORT <box> <report>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The `report` tag: the report's id.
    pub id: Id,
    /// The `t` tag: when the report was made.
    pub t: Timestamp,
    /// The `pseudonym` tag: the pseudonym in the target post's RisalaAAD
    /// (7.3), so that an operator can mute it with ADMIN MUTE. The target
    /// is an application message, a PrivateMessage, so its pseudonym is
    /// always 16 bytes (5.2).
    pub pseudonym: Pseudonym,
    /// The `from` tag: the reporter, if they were signed in.
    pub from: Option<Uid>,
    /// The mailbox the reported posts are in.
    pub mailbox: BoxName,
    /// The RisalaReport.
    pub report: ReportData,
}

/// Parses the lines of this module; `None` for any other verb.
pub(super) fn parse(
    verb: &str,
    tags: &Tags,
    p: Params<'_>,
) -> Option<Result<ServerLine, ParseError>> {
    let parse: fn(&Tags, Params<'_>) -> Result<ServerLine, ParseError> = match verb {
        "POST" => |tags, mut p| {
            let seq = parse_tag(tags, "seq")?;
            let t = parse_tag(tags, "t")?;
            if seq.is_some() && t.is_none() {
                return Err(bad("a post with seq has t"));
            }
            let mailbox = tok(&mut p)?;
            let message = last(p)?;
            Ok(ServerLine::Post(Post {
                seq,
                t,
                mailbox,
                message,
            }))
        },
        "ROOM" => |_, mut p| {
            let room = tok(&mut p)?;
            let mailbox = tok(&mut p)?;
            let members = number(&mut p)?;
            let topic = text_max(p, MAX_TOPIC)?;
            Ok(ServerLine::Room {
                room,
                mailbox,
                members,
                topic,
            })
        },
        "GROUPINFO" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let epoch = number(&mut p)?;
            let seq = Seq::parse_or_zero(p.token()?)?;
            let groupinfo = tok(&mut p)?;
            let tree = last(p)?;
            Ok(ServerLine::GroupInfo {
                mailbox,
                epoch,
                seq,
                groupinfo,
                tree,
            })
        },
        "GONE" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            let uid = last(p)?;
            Ok(ServerLine::Gone { mailbox, uid })
        },
        "DROP" => |_, mut p| {
            let mailbox = tok(&mut p)?;
            Ok(ServerLine::Drop {
                mailbox,
                reason: p.text().to_owned(),
            })
        },
        "REPORT" => |tags, mut p| {
            let id = required_tag(tags, "report")?;
            let t = required_tag(tags, "t")?;
            let pseudonym = required_tag(tags, "pseudonym")?;
            let from = parse_tag(tags, "from")?;
            let mailbox = tok(&mut p)?;
            let report = last(p)?;
            Ok(ServerLine::Report(Report {
                id,
                t,
                pseudonym,
                from,
                mailbox,
                report,
            }))
        },
        "RESOLVED" => |_, p| Ok(ServerLine::Resolved { id: last(p)? }),
        _ => return None,
    };
    Some(parse(tags, p))
}

/// Writes the lines of this module; `false` for any other line.
pub(super) fn write(line: &ServerLine, b: &mut LineBuilder) -> bool {
    match line {
        ServerLine::Post(post) => {
            if let Some(seq) = post.seq {
                b.tag("seq", seq);
            }
            if let Some(t) = post.t {
                b.tag("t", t);
            }
            b.token(post.mailbox).token(&post.message);
        }
        ServerLine::Room {
            room,
            mailbox,
            members,
            topic,
        } => {
            b.token(room).token(mailbox).token(members).text(topic);
        }
        ServerLine::GroupInfo {
            mailbox,
            epoch,
            seq,
            groupinfo,
            tree,
        } => {
            b.token(mailbox)
                .token(epoch)
                .token(seq.map_or(0, Seq::get))
                .token(groupinfo)
                .token(tree);
        }
        ServerLine::Gone { mailbox, uid } => {
            b.token(mailbox).token(uid);
        }
        ServerLine::Drop { mailbox, reason } => {
            b.token(mailbox).text(reason);
        }
        ServerLine::Report(report) => {
            b.tag("report", &report.id)
                .tag("t", report.t)
                .tag("pseudonym", report.pseudonym);
            if let Some(from) = &report.from {
                b.tag("from", from);
            }
            b.token(report.mailbox).token(&report.report);
        }
        ServerLine::Resolved { id } => {
            b.token(id);
        }
        _ => return false,
    }
    true
}

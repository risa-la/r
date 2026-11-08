//! Reports (5.8): to a room's owners and moderators, inside the
//! encryption, or to the server's operators, with franking.
//!
//! Owned by task C4.
//!
//! The reporter is told, before sending, who will see the report and what
//! they will see ([`Client::report_recipients`], [`ReportTo::explain`]):
//!
//! - **Moderators** are members. They get a REPORT line in a direct
//!   conversation with each of them, which names the messages by id, and
//!   see them from their own copies, with their authors as they confirmed
//!   them. They learn who reported.
//! - **Operators** are not members. They get `REPORT <box> <report>`: the
//!   franked content of the reported message and up to 10 earlier ones,
//!   which proves what was posted, and the reporter's claim of who wrote
//!   it, which proves nothing. It goes on the anonymous connection that
//!   follows the room, so they do not learn who reported.
//!
//! Guests' report conversations (5.8) need the guest flows of task C2, and
//! are not built here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_mls::message::{FrankKey, ReportedPost, RisalaReport};
use risala_proto::binary::{ReportData, ReportRef};
use risala_proto::command::Command;
use risala_proto::content::{ContentLine, MessageId as LineId, Report};
use risala_proto::names::BlobRef;

use super::files::{TransferError, ok};
use super::types::{AccountId, ConversationId, MessageId, Timestamp, Uid};
use super::{Client, Error, Event, Result};
use crate::store::conversations::ConvKind;
use crate::store::messages::MessageRow;
use crate::sync::Target;
use crate::sync::conversations::content;

/// The most context messages a report carries (5.8).
pub const MAX_CONTEXT: usize = 10;

/// The longest reason, in bytes (5.8).
pub const MAX_REASON: usize = 512;

/// The longest RisalaReport sent inline, in base64: above it, the report
/// goes in a blob (5.8, 12.12). A long line is at most 1 MiB (2.3).
const MAX_INLINE_REPORT: usize = 1024 * 1024 - 1024;

/// Who sees a report (5.8). The reporter is told this before sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportTo {
    /// The room's owners and moderators, who can trust who wrote it.
    Moderators(Vec<Uid>),
    /// The server's operators, who see the content, proven by franking,
    /// but not who wrote it.
    Operators,
}

impl ReportTo {
    /// What to tell the reporter before sending (5.8).
    pub fn explain(&self) -> String {
        match self {
            ReportTo::Moderators(uids) => format!(
                "The room's owners and moderators ({}) will see that you reported the message, \
                 the message and the earlier messages you add, from their own copies, with \
                 their authors as their devices confirmed them, and your reason.",
                uids.iter()
                    .map(|u| u.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            ReportTo::Operators => "The server's operators will see the text of the message \
                 and of the earlier messages you add, which they can check was posted, the \
                 author you name, which they cannot check, and your reason. They will not \
                 learn who you are, or the names of the people in the room."
                .to_owned(),
        }
    }
}

/// A report received as a room's owner or moderator (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedReport {
    /// Its id on this device.
    pub id: i64,
    /// The account.
    pub account: AccountId,
    /// Who reported, as their leaf showed in the direct conversation.
    pub reporter: Uid,
    /// The room, if this device is in it.
    pub room: Option<ConversationId>,
    /// The reported message, from this device's own copy, if it has one.
    pub target: ReportedMessage,
    /// The earlier messages the reporter added, oldest first.
    pub context: Vec<ReportedMessage>,
    /// The reason, unescaped.
    pub reason: String,
    /// When it arrived.
    pub received: Timestamp,
    /// Whether it was marked dealt with.
    pub resolved: bool,
}

/// A message a report names, as this device holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedMessage {
    /// Its id.
    pub id: MessageId,
    /// Its author, as this device received it; `None` if it does not hold
    /// the message.
    pub author: Option<Uid>,
    /// Whether this device confirmed the author's leaf (12.10).
    pub verified: bool,
    /// Its text, if this device holds it and it is not deleted.
    pub text: Option<String>,
}

fn message(rows: &[MessageRow], id: [u8; 16]) -> ReportedMessage {
    let row = rows.iter().find(|r| r.message_id == id);
    ReportedMessage {
        id: MessageId(id),
        author: row.map(|r| r.sender.clone()),
        verified: row.is_some_and(|r| r.verified),
        text: row.and_then(|r| r.text.clone()),
    }
}

/// The post of a stored message, for a report to operators (5.8): its
/// seq, frank key and content, which the server checks against the
/// post's frank.
fn reported(row: &MessageRow) -> Option<ReportedPost> {
    Some(ReportedPost {
        seq: row.seq?,
        frank_key: FrankKey::from_bytes(row.frank_key?),
        content: row.content.clone()?,
    })
}

/// The RisalaReport of `target`, with the `context` messages that are
/// earlier posts of the same conversation, oldest first (5.8). The author
/// is the sender this device received the message from: the reporter's
/// claim, which the operators cannot check.
pub(crate) fn operator_report(
    rows: &[MessageRow],
    target: &MessageRow,
    context: &[MessageId],
    reason: &str,
) -> std::result::Result<RisalaReport, TransferError> {
    let target_post = reported(target).ok_or(TransferError::NotPossible(
        "the message is not posted, or its content is gone".into(),
    ))?;
    let mut posts: Vec<ReportedPost> = context
        .iter()
        .filter_map(|id| rows.iter().find(|r| r.message_id == id.0))
        .filter_map(reported)
        .filter(|p| p.seq < target_post.seq)
        .collect();
    posts.sort_by_key(|p| p.seq);
    posts.dedup_by_key(|p| p.seq);
    let report = RisalaReport {
        target: target_post,
        context: posts,
        author: target.sender.clone(),
        reason: reason.to_owned(),
    };
    report
        .check()
        .map_err(|e| TransferError::NotPossible(e.to_string()))?;
    Ok(report)
}

impl Client {
    /// Who would see a report of a message in this conversation, for each
    /// way of reporting (5.8): in a room, its owners and moderators (other
    /// than this identity) and the server's operators; elsewhere the
    /// operators only. Tell the reporter with [`ReportTo::explain`].
    pub fn report_recipients(&self, conversation: ConversationId) -> Result<Vec<ReportTo>> {
        let row = self.conv_row(conversation)?;
        let mut out = Vec::new();
        if matches!(row.kind, ConvKind::Private | ConvKind::Public) {
            let own = self.account(row.account)?.uid;
            let ext = self.room_extension(&row)?;
            let mut uids: Vec<Uid> = ext
                .owners
                .iter()
                .chain(&ext.mods)
                .filter(|u| **u != own)
                .cloned()
                .collect();
            uids.dedup();
            if !uids.is_empty() {
                out.push(ReportTo::Moderators(uids));
            }
        }
        if row.kind != ConvKind::WithYourself {
            out.push(ReportTo::Operators);
        }
        Ok(out)
    }

    fn room_extension(
        &self,
        row: &crate::store::conversations::ConvRow,
    ) -> Result<risala_mls::conversation::RisalaConversation> {
        let (ext, _) = self
            .store()
            .write_with(|tx| crate::sync::transfer::extension(tx, &row.group_id))
            .map_err(|e| Error::Internal(e.to_string()))?;
        ext.ok_or(Error::Conversation(
            super::conversations::ConversationError::NotInGroup,
        ))
    }

    /// Reports `message`, with up to 10 earlier messages of the same
    /// conversation as `context` (5.8), to `to`. `reason` is free text of
    /// at most 512 bytes. Returns the operators' report id, for a report
    /// to them.
    pub async fn report(
        &self,
        conversation: ConversationId,
        message: MessageId,
        context: &[MessageId],
        to: ReportTo,
        reason: &str,
    ) -> Result<Option<String>> {
        if context.len() > MAX_CONTEXT {
            return Err(Error::invalid(
                "context, at most 10 messages",
                context.len().to_string(),
            ));
        }
        let escaped = risala_proto::text::escape(reason);
        if escaped.len() > MAX_REASON || reason.len() > MAX_REASON {
            return Err(Error::invalid("reason, at most 512 bytes", reason));
        }
        let row = self.conv_row(conversation)?;
        let rows = self.store().message_rows(conversation)?;
        let target = rows
            .iter()
            .find(|r| r.message_id == message.0)
            .ok_or(TransferError::NotPossible("no such message".into()))?;
        match to {
            ReportTo::Moderators(uids) => {
                self.report_to_moderators(&row, target, context, &uids, &escaped)
                    .await?;
                Ok(None)
            }
            ReportTo::Operators => {
                let report = operator_report(&rows, target, context, reason)?;
                self.report_to_operators(&row, &report).await.map(Some)
            }
        }
    }

    /// REPORT lines in a direct conversation with each of `uids`, who must
    /// be the room's owners or moderators (5.8).
    async fn report_to_moderators(
        &self,
        row: &crate::store::conversations::ConvRow,
        target: &MessageRow,
        context: &[MessageId],
        uids: &[Uid],
        reason: &str,
    ) -> Result<()> {
        if !matches!(row.kind, ConvKind::Private | ConvKind::Public) {
            return Err(TransferError::NotPossible("only rooms have moderators".into()).into());
        }
        let ext = self.room_extension(row)?;
        let mailbox = self
            .store()
            .mailbox_rows(row.id)?
            .into_iter()
            .find(|m| m.current)
            .ok_or(TransferError::NotPossible("the room has no mailbox".into()))?
            .mailbox;
        let line = ContentLine::Report(Report {
            mailbox,
            target: LineId::from_bytes(target.message_id),
            context: context.iter().map(|id| LineId::from_bytes(id.0)).collect(),
            reason: reason.to_owned(),
        });
        let own = self.account(row.account)?.uid;
        for uid in uids {
            if ext.role(uid) < risala_mls::conversation::Role::Mod {
                return Err(Error::invalid("moderator", uid.as_str()));
            }
        }
        for uid in uids {
            // The direct conversation with each, started if there is none.
            let direct = self.direct(row.account, uid.as_str()).await?;
            let now = self.options().clock.now().unix_millis();
            let line = line.clone();
            let own = own.clone();
            let (_, changes) = self
                .store()
                .write_with(|tx| content::queue_lines(tx, direct, &own, vec![line], false, now))
                .map_err(|e| Error::Internal(e.to_string()))?;
            for c in changes {
                self.emit(Event::Changed(c));
            }
        }
        self.kick(row.account).await;
        Ok(())
    }

    /// `REPORT <box> <report>` on the anonymous connection that follows the
    /// room (5.8), in a blob if it is too large for a line. Returns the
    /// report's id.
    async fn report_to_operators(
        &self,
        row: &crate::store::conversations::ConvRow,
        report: &RisalaReport,
    ) -> Result<String> {
        let jobs = self.jobs(row.account)?;
        let mailbox = self
            .store()
            .mailbox_rows(row.id)?
            .into_iter()
            .find(|m| m.current)
            .ok_or(TransferError::NotPossible("no mailbox".into()))?
            .mailbox;
        let bytes = report.encode();
        let report = if BASE64.encode(&bytes).len() <= MAX_INLINE_REPORT {
            ReportRef::Inline(
                ReportData::from_bytes(&bytes).map_err(|e| Error::Internal(e.to_string()))?,
            )
        } else {
            // A blob, stored on the same anonymous connection with the
            // room's token, so that it says nothing about the reporter
            // (12.12).
            let token = self
                .store()
                .write_with(|tx| crate::sync::transfer::send_token(tx, &row.group_id))
                .map_err(|e| Error::Internal(e.to_string()))?
                .0;
            let hash = BlobRef::of(&bytes);
            let response = jobs
                .command(
                    Target::Mailbox(mailbox),
                    Command::Blob {
                        hash,
                        size: bytes.len() as u64,
                        permit: Some(risala_proto::command::MailboxPermit {
                            mailbox,
                            token: risala_proto::mls::SendToken::from_bytes(*token.as_bytes()),
                        }),
                    },
                )
                .await?;
            if let Some(put) = ok(&response)?.put_url() {
                jobs.https
                    .put(put, &bytes)
                    .await
                    .map_err(TransferError::from)?;
            }
            ReportRef::Blob(hash)
        };
        let response = jobs
            .command(
                Target::Mailbox(mailbox),
                Command::Report { mailbox, report },
            )
            .await?;
        Ok(ok(&response)?
            .id()
            .ok()
            .flatten()
            .map(|id| id.to_string())
            .unwrap_or_default())
    }

    /// The reports the account received as a room's owner or moderator
    /// (5.8), newest first, with the messages from this device's copies.
    pub fn received_reports(&self, account: AccountId) -> Result<Vec<ReceivedReport>> {
        let mut out = Vec::new();
        for r in self.store().report_rows(account)? {
            let rows = match r.room {
                Some(room) => self.store().message_rows(room)?,
                None => Vec::new(),
            };
            out.push(ReceivedReport {
                id: r.id,
                account: r.account,
                reporter: r
                    .reporter
                    .parse()
                    .map_err(|_| Error::invalid("uid", r.reporter.clone()))?,
                room: r.room,
                target: message(&rows, r.target),
                context: r.context.iter().map(|id| message(&rows, *id)).collect(),
                reason: risala_proto::text::unescape(&r.reason).into_owned(),
                received: Timestamp::from_unix_millis(r.received).unwrap_or(Timestamp::MIN),
                resolved: r.resolved,
            });
        }
        Ok(out)
    }

    /// Marks a received report as dealt with.
    pub fn resolve_received_report(&self, id: i64) -> Result<()> {
        let (_, changes) = self.store().write(|tx| tx.resolve_report(id))?;
        for c in changes {
            self.emit(Event::Changed(c));
        }
        Ok(())
    }
}

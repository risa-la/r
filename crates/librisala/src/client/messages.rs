//! Messages (5.3, 5.4, 7.4, 7.7, 8.1, 12.9): reading a conversation's
//! messages, sending, replying, editing, reacting, deleting, typing and
//! read markers.
//!
//! Owned by task C2. Sending queues the message in the outbox, where the
//! account's group engine encrypts and posts it once the conversation is
//! caught up (12.9); it works offline, and is sent once the account is
//! connected.

use std::collections::BTreeMap;

use risala_proto::content::{ContentLine, EpochCheck, MessageId as LineId, Target, Text};
use risala_proto::names::Seq;

use super::conversations::ConversationError;
use super::types::{ConversationId, MessageId, Timestamp, Uid};
use super::{Client, Error, Result};
use crate::store::conversations::ConvKind;
use crate::store::messages::MessageRow;
use crate::sync::conversations::{EngineError, content};

/// A message, as shown (12.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its id in the group.
    pub id: MessageId,
    /// The conversation.
    pub conversation: ConversationId,
    /// Its post's seq, if it was posted.
    pub seq: Option<u64>,
    /// The sender.
    pub sender: Uid,
    /// Whether this device sent it.
    pub own: bool,
    /// The sender's time (12.9).
    pub sent: Timestamp,
    /// The server's time, if it was posted.
    pub received: Option<Timestamp>,
    /// Whether the two times differ by more than 10 minutes (12.9).
    pub time_mismatch: bool,
    /// Whether the sender's leaf was confirmed (12.10).
    pub verified: bool,
    /// Whether it came from a backup or a transfer (12.13).
    pub restored: bool,
    /// Whether its sender is blocked (5.7): apps SHOULD offer to hide it.
    pub hidden: bool,
    /// Its text, after edits, escaped as on the wire (3.4); `None` once
    /// deleted.
    pub text: Option<String>,
    /// The message it replies to (5.3), if that is one the device has and
    /// may quote.
    pub reply_to: Option<MessageId>,
    /// Whether it was edited (5.3), by an edit as trusted as the message.
    pub edited: bool,
    /// The text of a newer edit that may not replace `text`: from a leaf
    /// this device has not confirmed while the message is verified, or
    /// copied by a transfer or backup while the message was received here
    /// (12.7, 12.13). Apps show it apart, as an unverified edit.
    pub unverified_edit: Option<String>,
    /// Reactions, with how many of each.
    pub reactions: Vec<(String, u32)>,
}

/// Messages the device did not get (7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// The sender.
    pub sender: Uid,
    /// How many messages are missing.
    pub missing: u64,
    /// Whether retention explains them; otherwise the server held them
    /// back.
    pub expired: bool,
}

fn timestamp(ms: u64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap_or(Timestamp::MAX)
}

/// Whether this device checked a message itself: it sent it, or received
/// it from a leaf it confirmed (12.10), not by transfer or backup (12.13).
fn checked_here(row: &MessageRow) -> bool {
    row.own || (row.verified && !row.restored)
}

/// Whether `edit` may replace the text of `original` (12.7, 12.13): an
/// edit this device checked always; otherwise only if the original was not
/// checked here either, and a copied edit only of a copied message.
fn edit_may_replace(original: &MessageRow, edit: &MessageRow) -> bool {
    checked_here(edit) || (!checked_here(original) && (original.restored || !edit.restored))
}

/// Puts a conversation's rows together into messages (5.3): edits from
/// the author only, the newest shown; reactions counted once per person
/// and text; deleted messages without text.
fn assemble(rows: &[MessageRow], direct: bool) -> Vec<Message> {
    let by_id: BTreeMap<[u8; 16], &MessageRow> = rows.iter().map(|r| (r.message_id, r)).collect();
    let mut out = Vec::new();
    for row in rows {
        if row.edit_of.is_some() || row.react_to.is_some() {
            continue;
        }
        // 5.7: in a direct conversation, a blocked person's messages are
        // not shown.
        if row.hidden && direct {
            continue;
        }
        let edits: Vec<&MessageRow> = rows
            .iter()
            .filter(|r| r.edit_of == Some(row.message_id) && r.sender == row.sender && !r.deleted)
            .collect();
        let newest = |list: &[&MessageRow]| -> Option<MessageRow> {
            list.iter()
                .max_by_key(|r| (r.seq.unwrap_or(u64::MAX), r.sent))
                .map(|r| (*r).clone())
        };
        // 12.7, 12.13: an edit replaces the text only if it is as trusted
        // as the message: a verified or own message only by a verified or
        // own edit, and a message received here never by a copied one.
        let (trusted, untrusted): (Vec<&MessageRow>, Vec<&MessageRow>) =
            edits.iter().partition(|e| edit_may_replace(row, e));
        let latest = newest(&trusted);
        let unverified_edit = newest(&untrusted)
            .filter(|u| {
                latest.as_ref().is_none_or(|l| {
                    (u.seq.unwrap_or(u64::MAX), u.sent) > (l.seq.unwrap_or(u64::MAX), l.sent)
                })
            })
            .filter(|_| !row.deleted)
            .and_then(|u| u.text);
        let text = if row.deleted {
            None
        } else {
            latest
                .as_ref()
                .and_then(|r| r.text.clone())
                .or_else(|| row.text.clone())
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut reactions: BTreeMap<String, u32> = BTreeMap::new();
        for r in rows
            .iter()
            .filter(|r| r.react_to == Some(row.message_id) && !r.deleted && !(r.hidden && direct))
        {
            if let Some(t) = &r.text
                && seen.insert((r.sender.to_string(), t.clone()))
            {
                *reactions.entry(t.clone()).or_default() += 1;
            }
        }
        // 5.3: a reply's target must be a message of the conversation, not
        // deleted, and not an edit or a reaction.
        let reply_to = row.reply_to.filter(|id| {
            by_id
                .get(id)
                .is_some_and(|t| !t.deleted && t.edit_of.is_none() && t.react_to.is_none())
        });
        out.push(Message {
            id: MessageId(row.message_id),
            conversation: row.conv,
            seq: row.seq,
            sender: row.sender.clone(),
            own: row.own,
            sent: timestamp(row.sent),
            received: row.received.map(timestamp),
            time_mismatch: row.time_mismatch,
            verified: row.verified,
            restored: row.restored,
            hidden: row.hidden,
            text,
            reply_to: reply_to.map(MessageId),
            edited: latest.is_some(),
            unverified_edit,
            reactions: reactions.into_iter().collect(),
        });
    }
    out
}

impl Client {
    /// Up to `limit` messages of a conversation, oldest first, before
    /// `before` (or the newest, without it).
    pub fn messages(
        &self,
        conversation: ConversationId,
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<Message>> {
        let row = self.conv_row(conversation)?;
        let rows = self.store().message_rows(conversation)?;
        let mut all = assemble(&rows, row.kind == ConvKind::Direct);
        if let Some(before) = before
            && let Some(i) = all.iter().position(|m| m.id == before)
        {
            all.truncate(i);
        }
        let skip = all.len().saturating_sub(limit);
        Ok(all.split_off(skip))
    }

    /// Queues lines to send in a conversation, and lets the engine send
    /// them.
    async fn send_lines(
        &self,
        conversation: ConversationId,
        lines: Vec<ContentLine>,
        live: bool,
    ) -> Result<MessageId> {
        let row = self.conv_row(conversation)?;
        if !row.state.in_group() {
            return Err(Error::Conversation(ConversationError::NotInGroup));
        }
        let own = self.account(row.account)?.uid;
        let now = self.options().clock.now().unix_millis();
        let (id, _) = self
            .store()
            .write_with(|tx| content::queue_lines(tx, conversation, &own, lines, live, now))
            .map_err(Error::from)?;
        self.kick(row.account).await;
        Ok(MessageId(id))
    }

    /// Sends a TEXT line, as a reply to `reply_to` if given (5.3). `text`
    /// is plain text; it is escaped (3.4).
    pub async fn send_text(
        &self,
        conversation: ConversationId,
        text: &str,
        reply_to: Option<MessageId>,
    ) -> Result<MessageId> {
        let escaped = risala_proto::text::escape(text);
        if risala_proto::text::is_blank(&escaped) {
            return Err(Error::invalid("message text", text));
        }
        let line = ContentLine::Text(Text {
            text: escaped,
            target: reply_to.map(|id| Target::Reply(LineId::from_bytes(id.0))),
            file: None,
        });
        self.send_lines(conversation, vec![line], false).await
    }

    /// Edits one of this identity's messages (5.3).
    pub async fn edit(
        &self,
        conversation: ConversationId,
        id: MessageId,
        text: &str,
    ) -> Result<()> {
        let escaped = risala_proto::text::escape(text);
        let line = ContentLine::Text(Text {
            text: escaped,
            target: Some(Target::Edit(LineId::from_bytes(id.0))),
            file: None,
        });
        self.send_lines(conversation, vec![line], false)
            .await
            .map(drop)
    }

    /// Reacts to a message (5.3); at most 64 bytes of escaped text.
    pub async fn react(
        &self,
        conversation: ConversationId,
        id: MessageId,
        reaction: &str,
    ) -> Result<()> {
        let escaped = risala_proto::text::escape(reaction);
        let line = ContentLine::Text(Text {
            text: escaped,
            target: Some(Target::React(LineId::from_bytes(id.0))),
            file: None,
        });
        self.send_lines(conversation, vec![line], false)
            .await
            .map(drop)
    }

    /// Deletes a message: one's own, or anyone's as an owner or moderator
    /// of a room (5.4).
    pub async fn delete(&self, conversation: ConversationId, id: MessageId) -> Result<()> {
        let line = ContentLine::Delete {
            id: LineId::from_bytes(id.0),
        };
        self.send_lines(conversation, vec![line], false)
            .await
            .map(drop)
    }

    /// Says that this device's user is typing (8.1), as a live post. Not
    /// sent in rooms of more than 100 members.
    pub async fn typing(&self, conversation: ConversationId) -> Result<()> {
        let members = self.store().leaf_rows(conversation)?.len();
        if members > risala_proto::content::MAX_TYPING_MEMBERS {
            return Ok(());
        }
        self.send_lines(conversation, vec![ContentLine::Typing], true)
            .await
            .map(drop)
    }

    /// Marks a conversation read up to `id` (7.7), here and, with a READ
    /// line in the conversation with yourself, on the identity's other
    /// devices. The READ carries the check of the epoch this device holds
    /// (12.9).
    pub async fn mark_read(&self, conversation: ConversationId, id: MessageId) -> Result<()> {
        let row = self.conv_row(conversation)?;
        let rows = self.store().message_rows(conversation)?;
        let Some(seq) = rows
            .iter()
            .find(|m| m.message_id == id.0)
            .and_then(|m| m.seq)
        else {
            return Ok(());
        };
        let mailbox = self
            .store()
            .mailbox_rows(conversation)?
            .into_iter()
            .find(|m| m.current)
            .ok_or(Error::Conversation(ConversationError::NotInGroup))?
            .mailbox;
        let own = self.account(row.account)?.uid;
        let self_conv = self
            .store()
            .conversation_rows(row.account)?
            .into_iter()
            .find(|r| r.kind == ConvKind::WithYourself && r.state.in_group())
            .map(|r| r.id);
        let now = self.options().clock.now().unix_millis();
        let crypto = std::sync::Arc::new(
            risala_mls::RisalaCrypto::new().map_err(|e| Error::Internal(e.to_string()))?,
        );
        let account = self.account(row.account)?;
        // The server as the conversation extension writes it (3.5, 12.4).
        let host: risala_proto::names::ServerAddr = account
            .server
            .to_string()
            .parse()
            .map_err(|_| Error::invalid("server", account.server.to_string()))?;
        self.store()
            .write_with(|tx| {
                tx.mark_read(conversation, seq)?;
                let Some(self_conv) = self_conv else {
                    return Ok(());
                };
                let hooks = crate::sync::conversations::NoHooks;
                let config = crate::sync::conversations::Config::default();
                let cx = crate::sync::conversations::Ctx {
                    account: row.account,
                    uid: &own,
                    host: &host,
                    guest: false,
                    crypto: &crypto,
                    hooks: &hooks,
                    device_key: None,
                    now,
                    config: &config,
                };
                let check = crate::sync::conversations::group::epoch_check(tx, &cx, &row)?;
                let seq = Seq::new(seq).ok_or(EngineError::Invalid("seq".into()))?;
                content::queue_lines(
                    tx,
                    self_conv,
                    &own,
                    vec![ContentLine::Read {
                        mailbox,
                        seq,
                        check: EpochCheck::from_bytes(check),
                    }],
                    false,
                    now,
                )?;
                Ok::<_, EngineError>(())
            })
            .map_err(Error::from)?;
        self.kick(row.account).await;
        Ok(())
    }

    /// The gaps in a conversation (7.4).
    pub fn gaps(&self, conversation: ConversationId) -> Result<Vec<Gap>> {
        Ok(self
            .store()
            .gap_rows(conversation)?
            .into_iter()
            .map(|g| Gap {
                sender: g.sender,
                missing: g.last - g.first + 1,
                expired: g.expired,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::conversations::ConversationId as Id;

    fn row(id: u8, sender: &str) -> MessageRow {
        MessageRow {
            conv: Id(1),
            message_id: [id; 16],
            seq: Some(u64::from(id)),
            epoch: Some(1),
            sender: sender.parse().unwrap(),
            leaf: Some(0),
            own: false,
            sent: u64::from(id),
            received: None,
            verified: false,
            time_mismatch: false,
            restored: false,
            hidden: false,
            content: None,
            text: Some(format!("text {id}")),
            reply_to: None,
            edit_of: None,
            react_to: None,
            deleted: false,
            frank_key: None,
        }
    }

    #[test]
    fn edits_from_the_author_only_and_reactions_once() {
        let a = "alice@example.org";
        let b = "bob@example.net";
        let mut edit = row(2, a);
        edit.edit_of = Some([1; 16]);
        edit.text = Some("fixed".into());
        let mut forged = row(3, b);
        forged.edit_of = Some([1; 16]);
        forged.text = Some("not alice".into());
        let mut like = row(4, b);
        like.react_to = Some([1; 16]);
        like.text = Some("+1".into());
        let mut again = row(5, b);
        again.react_to = Some([1; 16]);
        again.text = Some("+1".into());
        let mut reply = row(6, b);
        reply.reply_to = Some([2; 16]);
        let shown = assemble(&[row(1, a), edit, forged, like, again, reply], true);
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].text.as_deref(), Some("fixed"));
        assert!(shown[0].edited);
        assert_eq!(shown[0].reactions, vec![("+1".to_owned(), 1)]);
        // A reply to an edit is shown without the quote (5.3).
        assert_eq!(shown[1].reply_to, None);
    }

    /// LR-H3: an edit from a leaf this device has not confirmed, or one
    /// copied by a transfer, never replaces the text of a message it
    /// verified itself; it is shown apart, as an unverified edit (12.7,
    /// 12.13).
    #[test]
    fn edits_never_replace_verified_text_with_less_trusted_text() {
        let a = "alice@example.org";
        let mut original = row(1, a);
        original.verified = true;
        // An unconfirmed leaf of Alice's identity edits it.
        let mut forged = row(2, a);
        forged.edit_of = Some([1; 16]);
        forged.text = Some("forged".into());
        let shown = assemble(&[original.clone(), forged.clone()], false);
        assert_eq!(shown[0].text.as_deref(), Some("text 1"));
        assert!(shown[0].verified);
        assert!(!shown[0].edited);
        assert_eq!(shown[0].unverified_edit.as_deref(), Some("forged"));
        // A copied edit from a transfer, even one flagged as verified by
        // the device that sent it.
        let mut copied = row(3, a);
        copied.edit_of = Some([1; 16]);
        copied.text = Some("copied".into());
        copied.restored = true;
        copied.verified = true;
        let shown = assemble(&[original.clone(), copied], false);
        assert_eq!(shown[0].text.as_deref(), Some("text 1"));
        assert_eq!(shown[0].unverified_edit.as_deref(), Some("copied"));
        // Even an unverified message received here is not changed by a
        // transfer.
        let mut plain = original.clone();
        plain.verified = false;
        let mut copied = row(3, a);
        copied.edit_of = Some([1; 16]);
        copied.text = Some("copied".into());
        copied.restored = true;
        let shown = assemble(&[plain, copied], false);
        assert_eq!(shown[0].text.as_deref(), Some("text 1"));
        // A verified edit replaces it; a later unverified one is shown
        // apart.
        let mut good = row(4, a);
        good.edit_of = Some([1; 16]);
        good.text = Some("good".into());
        good.verified = true;
        let shown = assemble(&[original.clone(), good.clone(), forged.clone()], false);
        assert_eq!(shown[0].text.as_deref(), Some("good"));
        assert!(shown[0].edited);
        assert_eq!(
            shown[0].unverified_edit, None,
            "older than the verified edit"
        );
        let mut later = forged;
        later.seq = Some(9);
        let shown = assemble(&[original, good, later], false);
        assert_eq!(shown[0].text.as_deref(), Some("good"));
        assert_eq!(shown[0].unverified_edit.as_deref(), Some("forged"));
    }
}

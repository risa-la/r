//! Messages in and out (5.3, 5.4, 5.7, 7.4, 7.7, 8.1, 12.9).
//!
//! [`receive`] takes a decrypted application message through the steps of
//! 12.9 and acts on its lines; [`queue_lines`] writes a message to send.
//! Lines of other areas go to the hooks: CHALLENGE, ANSWER, ATTEST and
//! REVEAL to leaf confirmation (task C3); RECORD, ALERT, RECORDS,
//! SIGNINGKEY, BACKUPKEY, PIN and SERVERS to identity (task C1); WANT,
//! TRANSFER and REPORT to transfers and reports (task C4).

use risala_mls::conversation::{ConfirmMode, Role, SendMode};
use risala_proto::content::{Content, ContentLine, Conversation, Place, Target};
use risala_proto::names::Uid;
use risala_proto::types::ConfirmMode as LineConfirm;

use super::group::{self, Applied};
use super::wire::RisalaMessage;
use super::{Ctx, EngineError, Note};
use crate::store::Tx;
use crate::store::conversations::{ConvKind, ConvRow, ConversationId, is_blocked};
use crate::store::messages::{NewMessage, NewOutbox, OutboxKind};

type Result<T> = std::result::Result<T, EngineError>;

/// How far the sender's clock may be from the post's `t` before the
/// message is marked (12.9, step 5).
const CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;

/// A decrypted application message.
#[derive(Debug)]
pub(crate) struct Received<'a> {
    /// The sending leaf.
    pub leaf: u32,
    /// The pseudonym in its RisalaAAD.
    pub pseudonym: [u8; 16],
    /// The `frank` in its RisalaAAD.
    pub frank: Option<[u8; 48]>,
    /// The RisalaMessage.
    pub body: &'a [u8],
    /// The post's seq; `None` for a live post.
    pub seq: Option<u64>,
    /// The post's `t`.
    pub t: u64,
    /// The epoch it was posted in.
    pub epoch: u64,
}

/// The place of a conversation's lines (12.9).
pub(crate) fn place(
    conv: &ConvRow,
    ext_confirm: Option<ConfirmMode>,
    live: bool,
    guest: bool,
) -> Place {
    let conversation = match conv.kind {
        ConvKind::WithYourself => Conversation::WithYourself,
        ConvKind::Direct => Conversation::Direct,
        ConvKind::Private => Conversation::PrivateRoom(match ext_confirm {
            Some(ConfirmMode::Epochal) => LineConfirm::Epochal,
            _ => LineConfirm::Pairwise,
        }),
        ConvKind::Public => Conversation::PublicRoom,
    };
    Place {
        conversation,
        live,
        guest,
    }
}

/// Reads a message as 12.9 says, and acts on its lines.
pub(crate) fn receive(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    r: Received<'_>,
    applied: &mut Applied,
) -> Result<()> {
    let Ok(message) = RisalaMessage::decode(r.body) else {
        return Ok(());
    };
    let Some(leaf) = tx.leaf(conv.id, r.leaf)? else {
        // 12.9, late messages: a leaf that a commit with a lower seq has
        // removed.
        return Ok(());
    };
    if leaf.self_removed {
        return Ok(());
    }
    // 12.7: nothing from a leaf of a device removed by record.
    if let Some(device) = leaf.device_id {
        let facts = cx.hooks.key_facts(tx, cx.account);
        let removed = facts.device_removed(&leaf.uid, &risala_mls::identity::DeviceId(device));
        if removed == risala_mls::checks::Fact::Known(true) {
            return Ok(());
        }
    }
    // Step 1: the pseudonym (7.3).
    match leaf.pseudonym {
        Some(pinned) if pinned != r.pseudonym => return Ok(()),
        Some(_) => {}
        None => {
            if r.seq.is_some() {
                tx.pin_pseudonym(conv.id, r.leaf, r.pseudonym)?;
            }
        }
    }
    // Step 2: the franking tag, in constant time.
    let Some(frank) = r.frank else { return Ok(()) };
    if !message.frank_ok(&frank) {
        return Ok(());
    }
    // Step 3: a message id seen before is a replay.
    if tx.message_seen(conv.id, &message.message_id)? {
        return Ok(());
    }
    let Ok(content) = Content::parse(&message.content) else {
        tx.mark_seen(conv.id, &message.message_id)?;
        return Ok(());
    };
    let live = r.seq.is_none();
    let ext = group::load(tx, cx, &conv.group_id)
        .ok()
        .and_then(|g| risala_mls::group::conversation(&g));
    let guest = leaf.uid.is_guest();
    let where_ = place(conv, ext.as_ref().map(|e| e.confirm), live, guest);

    if live {
        // 8.1: only TYPING is live, and does not count.
        if message.counter == 0
            && content
                .allowed(where_)
                .any(|l| matches!(l, ContentLine::Typing))
            && may_send(ext.as_ref(), &leaf.uid)
            && !hidden(tx, cx, conv, &leaf.uid)?
        {
            applied.notes.push(Note::Typing {
                conv: conv.id,
                uid: leaf.uid.clone(),
            });
        }
        return Ok(());
    }

    // Step 4: counter and previous, for gaps (7.4).
    if message.counter > leaf.counter + 1 {
        let expired = false;
        tx.add_gap(
            conv.id,
            &leaf.uid,
            r.leaf,
            leaf.counter + 1,
            message.counter - 1,
            expired,
        )?;
    } else if message.counter <= leaf.counter {
        tx.fill_gap(conv.id, r.leaf, message.counter)?;
    }
    tx.leaf_sent(conv.id, r.leaf, message.counter, message.message_id)?;
    // Step 5: the sender's clock.
    let time_mismatch = message.time.abs_diff(r.t) > CLOCK_SKEW_MS;
    // Step 6: verified only if the leaf is confirmed (12.10).
    let verified = cx.hooks.leaf_confirmed(tx, conv.id, &leaf);
    let hidden = hidden(tx, cx, conv, &leaf.uid)?;
    let own_identity = leaf.uid == *cx.uid;

    let mut shown = false;
    for line in content.allowed(where_) {
        match line {
            ContentLine::Text(text) => {
                // 6.2, 5.3: in a room with `send mods`, only reactions from
                // plain members; guests only where `guests write`.
                let reaction = matches!(text.target, Some(Target::React(_)));
                if !reaction && !may_send(ext.as_ref(), &leaf.uid) {
                    continue;
                }
                if guest
                    && let Some(e) = &ext
                    && e.guests != risala_mls::conversation::GuestMode::Write
                {
                    continue;
                }
                let (reply_to, edit_of, react_to) = match text.target {
                    Some(Target::Reply(id)) => (Some(*id.as_bytes()), None, None),
                    Some(Target::Edit(id)) => (None, Some(*id.as_bytes()), None),
                    Some(Target::React(id)) => (None, None, Some(*id.as_bytes())),
                    None => (None, None, None),
                };
                let inserted = tx.insert_message(
                    conv.id,
                    &NewMessage {
                        message_id: message.message_id,
                        seq: r.seq,
                        epoch: Some(r.epoch),
                        sender: Some(&leaf.uid),
                        leaf: Some(r.leaf),
                        own: false,
                        sent: message.time,
                        received: Some(r.t),
                        verified,
                        time_mismatch,
                        hidden,
                        content: Some(&message.content),
                        text: Some(&text.text),
                        reply_to,
                        edit_of,
                        react_to,
                        frank_key: Some(message.frank_key),
                        ..NewMessage::default()
                    },
                )?;
                if inserted {
                    shown = true;
                    // A DELETE that arrived first (5.4).
                    for (by, with_role) in tx.kept_deletes(conv.id, &message.message_id)? {
                        if by == leaf.uid || with_role {
                            tx.erase_message(conv.id, &message.message_id)?;
                        }
                    }
                }
                // One TEXT line per message is shown (5.3).
                break;
            }
            ContentLine::Delete { id } => {
                delete(tx, conv, ext.as_ref(), &leaf.uid, id.as_bytes())?;
            }
            ContentLine::Resync { mailbox: None, seq } => {
                // 12.7: replace the leaf, after a random wait.
                tx.mark_resync(conv.id, r.leaf, seq.get())?;
                applied.notes.push(Note::Resync {
                    conv: conv.id,
                    leaf: r.leaf,
                });
            }
            line if conv.kind == ConvKind::WithYourself => {
                // 12.9: only from confirmed leaves of the own identity.
                if !own_identity || !verified {
                    continue;
                }
                self_line(tx, cx, conv, line, applied)?;
            }
            line => {
                applied.notes.extend(
                    cx.hooks
                        .content_line(tx, conv.id, &leaf, line)
                        .into_iter()
                        .map(|a| Note::Hook(Box::new(a))),
                );
            }
        }
    }
    if !shown {
        tx.mark_seen(conv.id, &message.message_id)?;
    } else {
        tx.touch(conv.id, message.time.min(r.t))?;
        if !hidden {
            applied.notes.push(Note::NewMessage);
        }
    }
    Ok(())
}

/// Whether `uid` may send TEXT lines and typing (6.2): every member unless
/// the room is `send mods`.
fn may_send(ext: Option<&risala_mls::conversation::RisalaConversation>, uid: &Uid) -> bool {
    match ext {
        Some(e) if e.send == SendMode::Mods => e.role(uid) >= Role::Mod,
        _ => true,
    }
}

/// Whether messages from `uid` are hidden here because of a block (5.7).
fn hidden(tx: &Tx<'_>, cx: &Ctx<'_>, _conv: &ConvRow, uid: &Uid) -> Result<bool> {
    Ok(is_blocked(&tx.blocks(cx.account)?, uid))
}

/// A DELETE (5.4): by the author, or in a room by an owner or moderator
/// at the message's epoch and at its place in the order of posts, which
/// for this device are the same extension, since it applies posts in
/// order.
fn delete(
    tx: &mut Tx<'_>,
    conv: &ConvRow,
    ext: Option<&risala_mls::conversation::RisalaConversation>,
    by: &Uid,
    target: &[u8; 16],
) -> Result<()> {
    let room = matches!(conv.kind, ConvKind::Private | ConvKind::Public);
    let with_role = room && ext.is_some_and(|e| e.role(by) >= Role::Mod);
    match tx.message(conv.id, target)? {
        Some(m) => {
            if m.sender == *by || with_role {
                tx.erase_message(conv.id, target)?;
            }
        }
        None => tx.keep_delete(conv.id, target, by, with_role)?,
    }
    Ok(())
}

/// A line of the conversation with yourself (12.9), from a confirmed leaf
/// of the own identity.
fn self_line(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    line: &ContentLine,
    applied: &mut Applied,
) -> Result<()> {
    match line {
        ContentLine::Read {
            mailbox,
            seq,
            check,
        } => {
            let Some(mb) = tx.mailbox(cx.account, mailbox)? else {
                return Ok(());
            };
            let target = tx.conversation(mb.conv)?;
            if !mb.current {
                return Ok(());
            }
            if tx.mark_read(target.id, seq.get())? {
                applied.notes.push(Note::Read);
            }
            // 7.7: the epoch check. Compare only when this device holds
            // the same epoch for that seq, which it knows for its own
            // messages' epochs: here, when the seq is a message it has.
            if let Some(epoch) = message_epoch_at(tx, target.id, seq.get())?
                && epoch == target.epoch
                && let Ok(own) = group::epoch_check(tx, cx, &target)
                && own != *check.as_bytes()
            {
                applied.notes.push(Note::Split { conv: target.id });
            }
        }
        ContentLine::Block(target) => {
            if tx.set_block(cx.account, &target.to_string(), true, cx.now)? {
                applied.notes.push(Note::Blocks);
            }
        }
        ContentLine::Unblock(target) => {
            if tx.set_block(cx.account, &target.to_string(), false, cx.now)? {
                applied.notes.push(Note::Blocks);
            }
        }
        ContentLine::Resync {
            mailbox: Some(mailbox),
            seq,
        } => {
            // 12.7: replace the sending device's leaf in that group, if
            // this device holds it and a commit at that seq.
            if let Some(mb) = tx.mailbox(cx.account, mailbox)? {
                applied.notes.push(Note::OwnResync {
                    conv: mb.conv,
                    seq: seq.get(),
                    from: conv.id,
                });
            }
        }
        other => {
            let leaf = tx.leaves(conv.id)?.into_iter().find(|l| l.uid == *cx.uid);
            if let Some(leaf) = leaf {
                applied.notes.extend(
                    cx.hooks
                        .content_line(tx, conv.id, &leaf, other)
                        .into_iter()
                        .map(|a| Note::Hook(Box::new(a))),
                );
            }
        }
    }
    Ok(())
}

/// The epoch of the message at `seq`, if the cache has one there.
fn message_epoch_at(tx: &Tx<'_>, conv: ConversationId, seq: u64) -> Result<Option<u64>> {
    use rusqlite::OptionalExtension as _;
    let epoch: Option<Option<i64>> = tx
        .conn()
        .query_row(
            "SELECT epoch FROM messages WHERE conv = ?1 AND seq = ?2",
            rusqlite::params![conv.0, seq as i64],
            |r| r.get(0),
        )
        .optional()
        .map_err(crate::store::StoreError::from)?;
    Ok(epoch.flatten().map(|e| e as u64))
}

/// Queues a message of `lines` to send in `conv` (12.9): counts it, and
/// stores it as shown if it has a TEXT line. A live message (8.1) has
/// counter 0 and does not count. Returns its id.
///
/// Other areas use this to send their lines: CHALLENGE and ANSWER (C3),
/// RECORD (C1), TRANSFER (C4).
pub(crate) fn queue_lines(
    tx: &mut Tx<'_>,
    conv: ConversationId,
    sender: &Uid,
    lines: Vec<ContentLine>,
    live: bool,
    now: u64,
) -> Result<[u8; 16]> {
    let content = Content::new(lines).map_err(|e| EngineError::Invalid(e.to_string()))?;
    let row = tx.conversation(conv)?;
    if !row.state.in_group() {
        return Err(EngineError::Invalid("not in this conversation".into()));
    }
    let mut message = RisalaMessage::new(0, None, now, content.as_bytes().to_vec())
        .map_err(|_| EngineError::Random)?;
    if !live {
        let (counter, previous) = tx.next_counter(conv, message.message_id)?;
        message.counter = counter;
        message.previous = previous;
    }
    if let Some(ContentLine::Text(text)) = content
        .lines()
        .iter()
        .find(|l| matches!(l, ContentLine::Text(_)))
    {
        let (reply_to, edit_of, react_to) = match text.target {
            Some(Target::Reply(id)) => (Some(*id.as_bytes()), None, None),
            Some(Target::Edit(id)) => (None, Some(*id.as_bytes()), None),
            Some(Target::React(id)) => (None, None, Some(*id.as_bytes())),
            None => (None, None, None),
        };
        tx.insert_message(
            conv,
            &NewMessage {
                message_id: message.message_id,
                sender: Some(sender),
                own: true,
                sent: now,
                verified: true,
                content: Some(&message.content),
                text: Some(&text.text),
                reply_to,
                edit_of,
                react_to,
                frank_key: Some(message.frank_key),
                ..NewMessage::default()
            },
        )?;
        tx.touch(conv, now)?;
    } else if !live {
        tx.mark_seen(conv, &message.message_id)?;
    }
    for line in content.lines() {
        if let ContentLine::Delete { id } = line {
            // The device acts on its own DELETE at once (5.4).
            let ext_role = true;
            let _ = ext_role;
            if let Some(m) = tx.message(conv, id.as_bytes())?
                && (m.sender == *sender || matches!(row.kind, ConvKind::Private | ConvKind::Public))
            {
                tx.erase_message(conv, id.as_bytes())?;
            }
        }
    }
    tx.queue_outbox(
        conv,
        if live {
            OutboxKind::Live
        } else {
            OutboxKind::Message
        },
        &NewOutbox {
            message_id: Some(message.message_id),
            body: Some(message.encode()),
            ..NewOutbox::default()
        },
        now,
    )?;
    Ok(message.message_id)
}

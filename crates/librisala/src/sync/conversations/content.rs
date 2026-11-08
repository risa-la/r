//! Messages in and out (5.3, 5.4, 5.7, 7.4, 7.7, 8.1, 12.9).
//!
//! [`receive`] takes a message that `risala_mls::message::receive` has
//! decrypted and checked (12.9, steps 1 to 5) and acts on its lines;
//! [`queue_lines`] writes a message to send. Lines of other areas go to
//! the hooks: CHALLENGE, ANSWER, ATTEST and REVEAL to leaf confirmation
//! (task C3); RECORD, ALERT, RECORDS, SIGNINGKEY, BACKUPKEY, PIN and
//! SERVERS to identity (task C1); WANT, TRANSFER and REPORT to transfers
//! and reports (task C4).

use risala_mls::conversation::{Role, SendMode};
use risala_mls::message::{Clock, Decrypted, Order, RisalaMessage, SendCounter, Trust};
use risala_mls::openmls::group::MlsGroup;
use risala_proto::content::{Content, ContentLine, MessageId, Target};
use risala_proto::names::Uid;
use risala_proto::time::Timestamp;

use super::group::{self, Applied};
use super::{Ctx, EngineError, Note};
use crate::store::Tx;
use crate::store::conversations::{ConvKind, ConvRow, ConversationId, LeafRow, is_blocked};
use crate::store::messages::{NewMessage, NewOutbox, OutboxKind};

type Result<T> = std::result::Result<T, EngineError>;

type Targets = (Option<[u8; 16]>, Option<[u8; 16]>, Option<[u8; 16]>);

fn targets(target: Option<Target>) -> Targets {
    match target {
        Some(Target::Reply(id)) => (Some(*id.as_bytes()), None, None),
        Some(Target::Edit(id)) => (None, Some(*id.as_bytes()), None),
        Some(Target::React(id)) => (None, None, Some(*id.as_bytes())),
        None => (None, None, None),
    }
}

/// Acts on a message that passed the checks of 12.9 steps 1 to 5, posted
/// at `seq` (`None` for a live post) with `t`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn receive(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: &ConvRow,
    group: &MlsGroup,
    d: Decrypted,
    seq: Option<u64>,
    t: u64,
    applied: &mut Applied,
) -> Result<()> {
    let leaf_index = d.sender.u32();
    let uid = d.identity.uid.clone();
    // 12.7: nothing from a leaf of a device removed by record.
    if let Some(device) = d.identity.device_id {
        let facts = cx.hooks.key_facts(tx, cx.account);
        if facts.device_removed(&uid, &device) == risala_mls::checks::Fact::Known(true) {
            return Ok(());
        }
    }
    let Some(ext) = risala_mls::group::conversation(group) else {
        return Ok(());
    };
    let leaf = tx.leaf(conv.id, leaf_index)?.unwrap_or(LeafRow {
        leaf: leaf_index,
        uid: uid.clone(),
        device_id: d.identity.device_id.map(|d| *d.as_bytes()),
        signature_key: Vec::new(),
        display_name: None,
        updated: None,
        self_removed: false,
        resync_seq: None,
    });
    // Step 6: shown as verified only if the sender's leaf is confirmed
    // (12.10). Leaf confirmation (C3) acts on the message's lines first,
    // so that an ANSWER or ATTEST counts for the message that carries it.
    let received = cx.hooks.message_received(tx, cx, conv, &leaf, group, &d, t);
    applied.notes.extend(
        received
            .actions
            .into_iter()
            .map(|a| Note::Hook(Box::new(a))),
    );
    let trust = match (received.pinned, received.confirmed) {
        // 7.3: its ATTEST pinned the pseudonym it was withheld for.
        (true, true) => Trust::Verified,
        (true, false) => Trust::Unverified,
        (false, confirmed) => d.trust(confirmed),
    };
    let place = d.place(&ext);
    let message = &d.message;
    let message_id = *message.message_id.as_bytes();
    let hidden = is_blocked(&tx.blocks(cx.account)?, &uid);

    if trust == Trust::Withheld {
        // An epochal group's new pseudonym: nothing is shown until leaf
        // confirmation (C3) checks the ATTEST that carries it (7.3, 12.10).
        for line in message.content.allowed(place) {
            if matches!(line, ContentLine::Attest { .. }) {
                applied.notes.extend(
                    cx.hooks
                        .content_line(tx, conv.id, &leaf, line)
                        .into_iter()
                        .map(|a| Note::Hook(Box::new(a))),
                );
            }
        }
        return Ok(());
    }

    if d.order == Order::Live {
        // 8.1: only TYPING is live.
        if message
            .content
            .allowed(place)
            .any(|l| matches!(l, ContentLine::Typing))
            && may_send(&ext, &uid)
            && !hidden
        {
            applied.notes.push(Note::Typing {
                conv: conv.id,
                uid: uid.clone(),
            });
        }
        return Ok(());
    }

    // Step 4: gaps (7.4).
    match d.order {
        Order::Gap { missing } => {
            let last = message.counter - 1;
            tx.add_gap(conv.id, &uid, leaf_index, last + 1 - missing, last, false)?;
        }
        Order::Late => tx.fill_gap(conv.id, leaf_index, message.counter)?,
        _ => {}
    }
    let time_mismatch = d.clock == Clock::Disagrees;
    let verified = trust == Trust::Verified;
    let own_identity = uid == *cx.uid;

    let mut shown = false;
    for line in message.content.allowed(place) {
        match line {
            ContentLine::Text(text) => {
                // 6.2, 5.3: in a room with `send mods`, only reactions from
                // plain members. Guests' lines where `guests read` are
                // already left out by `allowed`.
                let reaction = matches!(text.target, Some(Target::React(_)));
                if !reaction && !may_send(&ext, &uid) {
                    continue;
                }
                let (reply_to, edit_of, react_to) = targets(text.target);
                let inserted = tx.insert_message(
                    conv.id,
                    &NewMessage {
                        message_id,
                        seq,
                        epoch: Some(d.epoch),
                        sender: Some(&uid),
                        leaf: Some(leaf_index),
                        own: false,
                        sent: message.time,
                        received: Some(t),
                        verified,
                        time_mismatch,
                        hidden,
                        content: Some(message.content.as_bytes()),
                        text: Some(&text.text),
                        reply_to,
                        edit_of,
                        react_to,
                        frank_key: Some(*message.frank_key.as_bytes()),
                        ..NewMessage::default()
                    },
                )?;
                if inserted {
                    shown = true;
                    // What transfers carry besides the content (C4, 12.13).
                    crate::sync::transfer::note_message(
                        tx,
                        conv.id,
                        &message_id,
                        message.counter,
                        message.previous.map(|p| *p.as_bytes()),
                        d.identity.device_id.map(|d| *d.as_bytes()),
                    )?;
                    // A DELETE that arrived first (5.4).
                    for (by, with_role) in tx.kept_deletes(conv.id, &message_id)? {
                        if by == uid || with_role {
                            tx.erase_message(conv.id, &message_id)?;
                        }
                    }
                }
                // One TEXT line per message is shown (5.3).
                break;
            }
            ContentLine::Delete { id } => {
                delete(tx, conv, &ext, &uid, id.as_bytes())?;
            }
            ContentLine::Resync { mailbox: None, seq } => {
                // 12.7: replace the leaf, after a random wait.
                tx.mark_resync(conv.id, leaf_index, seq.get())?;
                applied.notes.push(Note::Resync {
                    conv: conv.id,
                    leaf: leaf_index,
                });
            }
            line if conv.kind == ConvKind::WithYourself => {
                // 12.9: only from confirmed leaves of the own identity.
                if !own_identity || !verified {
                    continue;
                }
                self_line(tx, cx, conv, &leaf, line, applied)?;
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
    if shown {
        tx.touch(conv.id, message.time.min(t))?;
        if !hidden {
            applied.notes.push(Note::NewMessage);
        }
    }
    Ok(())
}

/// Whether `uid` may send TEXT lines and typing (6.2): every member unless
/// the room is `send mods`.
fn may_send(ext: &risala_mls::conversation::RisalaConversation, uid: &Uid) -> bool {
    ext.send != SendMode::Mods || ext.role(uid) >= Role::Mod
}

/// A DELETE (5.4): by the author, or in a room by an owner or moderator
/// at the message's epoch and at its place in the order of posts. This
/// device applies posts in order, so the extension it holds is the one at
/// the DELETE's place; the message's own epoch is almost always the same
/// one.
fn delete(
    tx: &mut Tx<'_>,
    conv: &ConvRow,
    ext: &risala_mls::conversation::RisalaConversation,
    by: &Uid,
    target: &[u8; 16],
) -> Result<()> {
    let room = matches!(conv.kind, ConvKind::Private | ConvKind::Public);
    let with_role = room && ext.role(by) >= Role::Mod;
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
    leaf: &LeafRow,
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
            // 7.7: the epoch check, made when this device holds the epoch
            // of the post at that seq, which it knows for the messages it
            // stored.
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
            // this device holds it.
            if let Some(mb) = tx.mailbox(cx.account, mailbox)? {
                applied.notes.push(Note::OwnResync {
                    conv: mb.conv,
                    seq: seq.get(),
                    device: leaf.device_id,
                });
            }
        }
        other => {
            applied.notes.extend(
                cx.hooks
                    .content_line(tx, conv.id, leaf, other)
                    .into_iter()
                    .map(|a| Note::Hook(Box::new(a))),
            );
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

/// Queues a message of `lines` to send in `conv` (12.9): written with the
/// leaf's send counter, which is stored now, and stored as shown if it has
/// a TEXT line. A live message (8.1) has counter 0 and does not count.
/// Returns its id.
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
    let now_ts = Timestamp::from_unix_millis(now).unwrap_or(Timestamp::MAX);
    let message = if live {
        RisalaMessage::live(content, now_ts).map_err(|_| EngineError::Random)?
    } else {
        let mut counter = SendCounter {
            written: row.sent,
            last: row.last_sent.map(MessageId::from_bytes),
        };
        let message = counter
            .write(content, now_ts)
            .map_err(|e| EngineError::Invalid(e.to_string()))?;
        tx.set_send_counter(conv, counter.written, counter.last.map(|l| *l.as_bytes()))?;
        message
    };
    let message_id = *message.message_id.as_bytes();
    let text = message.content.lines().iter().find_map(|l| match l {
        ContentLine::Text(t) => Some(t.clone()),
        _ => None,
    });
    if let Some(text) = text {
        let (reply_to, edit_of, react_to) = targets(text.target);
        tx.insert_message(
            conv,
            &NewMessage {
                message_id,
                sender: Some(sender),
                own: true,
                sent: now,
                verified: true,
                content: Some(message.content.as_bytes()),
                text: Some(&text.text),
                reply_to,
                edit_of,
                react_to,
                frank_key: Some(*message.frank_key.as_bytes()),
                ..NewMessage::default()
            },
        )?;
        // What transfers carry besides the content (C4, 12.13).
        crate::sync::transfer::note_message(
            tx,
            conv,
            &message_id,
            message.counter,
            message.previous.map(|p| *p.as_bytes()),
            None,
        )?;
        tx.touch(conv, now)?;
    } else if !live {
        tx.mark_seen(conv, &message_id)?;
    }
    for line in message.content.lines() {
        if let ContentLine::Delete { id } = line
            && let Some(m) = tx.message(conv, id.as_bytes())?
            && (m.sender == *sender || matches!(row.kind, ConvKind::Private | ConvKind::Public))
        {
            // The device acts on its own DELETE at once (5.4).
            tx.erase_message(conv, id.as_bytes())?;
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
            message_id: Some(message_id),
            body: Some(message.encode().to_vec()),
            ..NewOutbox::default()
        },
        now,
    )?;
    Ok(message_id)
}

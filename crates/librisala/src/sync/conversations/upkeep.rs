//! The group engine's upkeep (task R2):
//!
//! - every minute, the key checks of 12.7 that wait on facts, and their
//!   repairs ([`super::keycheck::recheck`], LR-C2);
//! - every ten minutes, past epochs' secrets deleted by the clock, 2 hours
//!   after the commit that ended each (12.9, LR-H1); outbox rows done or
//!   lost for a day deleted (LR-M2); DELETEs whose target never came
//!   forgotten after retention (LR-L3); and the WAL truncated, so that
//!   what was deleted does not stay in it (LR-M1);
//! - after a restart, the timers that the spec relies on, brought back
//!   from the groups and the cache (LR-M4): pending proposals to commit
//!   (6.1), leaves that asked with RESYNC to replace (12.7), and, from the
//!   `engine_timers` table, the RESYNC escalation, the commits this device
//!   could not process, and the 7.8 move fallback.

use std::collections::{BTreeMap, HashMap};

use risala_proto::names::BoxName;
use serde_json::{Value, json};

use super::{ConversationEngine, EngineError, Me, group, keycheck};
use crate::store::conversations::{ConvState, ConversationId};
use crate::sync::{Action, Context};

/// A day, in ms.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// How often the ten-minute upkeep runs.
const TEN_MINUTES_MS: u64 = 10 * 60 * 1000;

/// What the upkeep keeps between steps.
#[derive(Debug, Default)]
pub(super) struct Upkeep {
    /// Whether the timers were brought back after start.
    restored: bool,
    /// When the key checks ran last.
    last_checks: u64,
    /// When the ten-minute upkeep ran last.
    last_ten: u64,
    /// The timers as last saved.
    saved: Option<String>,
}

impl ConversationEngine {
    /// Runs what is due of the upkeep.
    pub(super) fn upkeep(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        if !self.upkeep.restored {
            self.upkeep.restored = true;
            if let Err(e) = self.restore_timers(cx, me, now, out) {
                tracing::warn!(error = %e, "could not bring the engine's timers back");
            }
        }
        if now >= self.upkeep.last_checks + keycheck::RECHECK_EVERY_MS {
            self.upkeep.last_checks = now;
            let actions = self.write(cx, me, out, keycheck::recheck)?;
            out.extend(actions);
        }
        if now >= self.upkeep.last_ten + TEN_MINUTES_MS {
            self.upkeep.last_ten = now;
            self.write(cx, me, out, |tx, c| {
                for row in tx.conversations_of(c.account)? {
                    if !row.state.in_group() && row.state != ConvState::Leaving {
                        continue;
                    }
                    if let Err(e) = group::expire_by_clock(tx, c, &row) {
                        tracing::debug!(conv = %row.id, error = %e, "no past epochs to expire");
                    }
                }
                let purged = tx.purge_outbox(c.now, DAY_MS)?;
                if purged > 0 {
                    tracing::debug!(purged, "outbox rows purged");
                }
                // LR-L3: a DELETE whose target has not come within
                // retention, and a day, never will.
                tx.expire_deletes(
                    c.now
                        .saturating_sub(c.config.retention_ms)
                        .saturating_sub(DAY_MS),
                )?;
                Ok(())
            })?;
            if let Err(e) = cx.store.checkpoint() {
                tracing::debug!(error = %e, "a checkpoint could not finish");
            }
        }
        Ok(())
    }

    /// Brings back the timers after a restart (LR-M4).
    fn restore_timers(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let max_wait = self.config.max_commit_wait_ms;
        let (proposals, resyncs, saved) = self.write(cx, me, out, |tx, c| {
            let mut proposals = Vec::new();
            let mut resyncs = Vec::new();
            for row in tx.conversations_of(c.account)? {
                if row.state != ConvState::Active {
                    continue;
                }
                let Ok(group) = group::load(tx, c, &row.group_id) else {
                    continue;
                };
                if group.pending_proposals().next().is_some() {
                    proposals.push(row.id);
                }
                let own = group.own_leaf_index().u32();
                for leaf in crate::store::conversations::read::leaves(tx.conn(), row.id)? {
                    if leaf.resync_seq.is_some() && leaf.leaf != own {
                        resyncs.push((row.id, leaf.leaf));
                    }
                }
            }
            Ok((proposals, resyncs, tx.engine_timers(c.account)?))
        })?;
        for conv in proposals {
            let wait = super::random_below(max_wait)?;
            self.proposal_timers.entry(conv).or_insert(now + wait);
        }
        for key in resyncs {
            let wait = super::random_below(max_wait)?;
            self.resync_timers.entry(key).or_insert(now + wait);
        }
        if let Some(saved) = saved {
            self.load_saved(&saved);
            self.upkeep.saved = Some(saved);
        }
        Ok(())
    }

    fn load_saved(&mut self, saved: &str) {
        let Ok(v) = serde_json::from_str::<Value>(saved) else {
            return;
        };
        let pairs = |key: &str| -> Vec<Vec<Value>> {
            v.get(key)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|e| e.as_array().cloned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let num = |e: &[Value], i: usize| e.get(i).and_then(Value::as_u64);
        for e in pairs("unprocessable") {
            if let (Some(c), Some(epoch), Some(seq)) = (num(&e, 0), num(&e, 1), num(&e, 2)) {
                self.unprocessable
                    .entry(ConversationId(c as i64))
                    .or_insert((epoch, seq));
            }
        }
        for e in pairs("resync_since") {
            if let (Some(c), Some(at), Some(seq)) = (num(&e, 0), num(&e, 1), num(&e, 2)) {
                self.resync_since
                    .entry(ConversationId(c as i64))
                    .or_insert((at, seq));
            }
        }
        for e in pairs("resynced") {
            if let Some(c) = num(&e, 0) {
                self.resynced.insert(ConversationId(c as i64));
            }
        }
        for e in pairs("move") {
            if let (Some(c), Some(at), Some(mailbox)) = (
                num(&e, 0),
                num(&e, 1),
                e.get(2)
                    .and_then(Value::as_str)
                    .and_then(|b| b.parse::<BoxName>().ok()),
            ) {
                self.move_timers
                    .entry(ConversationId(c as i64))
                    .or_insert((at, mailbox));
            }
        }
    }

    /// Saves the timers that no other state brings back, if they changed
    /// (LR-M4).
    pub(super) fn save_timers(&mut self, cx: &Context, me: &Me, out: &mut Vec<Action>) {
        if !self.upkeep.restored {
            return;
        }
        let sorted = |m: &HashMap<ConversationId, (u64, u64)>| -> Vec<Value> {
            m.iter()
                .map(|(c, (a, b))| (c.0, (*a, *b)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(c, (a, b))| json!([c, a, b]))
                .collect()
        };
        let mut resynced: Vec<i64> = self.resynced.iter().map(|c| c.0).collect();
        resynced.sort_unstable();
        let moves: Vec<Value> = self
            .move_timers
            .iter()
            .map(|(c, (at, b))| (c.0, (*at, b.to_string())))
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(c, (at, b))| json!([c, at, b]))
            .collect();
        let timers = json!({
            "unprocessable": sorted(&self.unprocessable),
            "resync_since": sorted(&self.resync_since),
            "resynced": resynced.into_iter().map(|c| json!([c])).collect::<Vec<_>>(),
            "move": moves,
        })
        .to_string();
        if self.upkeep.saved.as_deref() == Some(timers.as_str()) {
            return;
        }
        let saved = self.write(cx, me, out, |tx, c| {
            Ok(tx.set_engine_timers(c.account, &timers)?)
        });
        match saved {
            Ok(()) => self.upkeep.saved = Some(timers),
            Err(e) => tracing::warn!(error = %e, "could not save the engine's timers"),
        }
    }
}

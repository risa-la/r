//! Push subscriptions (Section 9): PUSH ADD and DEL for mailboxes on
//! anonymous connections and for the account on the signed-in one, and
//! FOLLOW's `quiet`.
//!
//! Owned by task C4 in docs/plans/M5b.md.
//!
//! Once the app turns push on for an account
//! ([`Client::enable_push`](crate::client::Client::enable_push)) and hands
//! over URLs from its push gateway (Appendix C), [`PushEngine`] keeps:
//!
//! - one **account subscription**, on the signed-in connection, for
//!   Welcomes (9.1, 9.2);
//! - one **mailbox subscription** for each conversation's current mailbox,
//!   on the anonymous connection that follows it, with a send token of the
//!   group, unless the user turned that conversation's pushes off (9.2).
//!   Each is renewed at a random time within a week, well inside the
//!   retention period it lasts (9.1), and deleted with PUSH DEL once the
//!   device leaves the group or the group moves (7.8).
//!
//! Every subscription has its own URL, random tag, P-256 key and
//! authentication secret, so that the server cannot link them (9.1). The
//! keys are kept in the cache to decrypt pushes (9.3, RFC 8291).

use std::collections::{HashMap, HashSet};

use risala_proto::binary::{PushAuth, PushKey};
use risala_proto::command::{Command, PushCommand};
use risala_proto::connection::ConnectionKind;
use risala_proto::error::ErrorCode;
use risala_proto::names::BoxName;
use risala_proto::types::{PushTag, PushUrl};

use super::conversations::EngineError;
use super::{Action, Context, Engine, Input, Target, Token};
use crate::client::Event;
use crate::client::files::TransferEvent;
use crate::conn::{End, Slot};
use crate::store::push::{NewSubscription, SubState, SubscriptionRow};
use crate::store::{AccountId, Store, StoreError, Tx};

/// How often the engine looks at its subscriptions.
const CHECK_EVERY_MS: u64 = 10_000;

/// The longest time before a mailbox subscription is renewed: a week
/// (9.1). Renewals are spread at random over the second half of it.
pub const RENEW_MAX_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// How long to wait before trying a refused or failed PUSH ADD again.
const RETRY_MS: u64 = 60 * 60 * 1000;

/// The setting that turns push on for an account.
pub(crate) fn setting(account: AccountId) -> String {
    format!("push.{}", account.get())
}

/// The setting that makes FOLLOW carry `quiet` (7.1, 9.2). Off by default:
/// a quiet tag links sessions, so devices SHOULD leave it out.
pub(crate) fn quiet_setting(account: AccountId) -> String {
    format!("push.quiet.{}", account.get())
}

/// The keys of a new subscription: a P-256 key pair and a 16-byte
/// authentication secret (RFC 8291), and a random tag.
pub(crate) struct NewKeys {
    pub public: [u8; 65],
    pub private: Vec<u8>,
    pub auth: [u8; 16],
    pub tag: String,
}

/// Makes the keys of a new subscription.
pub(crate) fn new_keys() -> Result<NewKeys, EngineError> {
    use aws_lc_rs::agreement::{ECDH_P256, PrivateKey};
    use aws_lc_rs::encoding::{AsBigEndian as _, EcPrivateKeyBin};
    let private = PrivateKey::generate(&ECDH_P256).map_err(|_| EngineError::Random)?;
    let public: [u8; 65] = private
        .compute_public_key()
        .map_err(|_| EngineError::Random)?
        .as_ref()
        .try_into()
        .map_err(|_| EngineError::Random)?;
    let bin: EcPrivateKeyBin<'static> = private.as_be_bytes().map_err(|_| EngineError::Random)?;
    let auth: [u8; 16] = risala_mls::primitives::random().map_err(|_| EngineError::Random)?;
    let tag: [u8; 12] = risala_mls::primitives::random().map_err(|_| EngineError::Random)?;
    Ok(NewKeys {
        public,
        private: bin.as_ref().to_vec(),
        auth,
        tag: tag.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// PUSH ADD (9.1). A mailbox subscription carries `box=` and a send token
/// of the group: until the proto change that adds `token=` to PUSH ADD
/// lands on `m5b`, only `box=` is sent.
fn push_add(
    row: &SubscriptionRow,
    permit: Option<(BoxName, risala_mls::token::SendToken)>,
) -> Option<Command> {
    let url: PushUrl = row.url.parse().ok()?;
    let tag: PushTag = row.tag.parse().ok()?;
    let key = PushKey::from_bytes(row.p256dh.as_slice().try_into().ok()?);
    let auth = PushAuth::from_bytes(row.auth.as_slice().try_into().ok()?);
    let mailbox = permit.map(|(mailbox, _token)| mailbox);
    Some(Command::Push(PushCommand::Add {
        url,
        tag,
        key,
        auth,
        mailbox,
    }))
}

fn push_del(row: &SubscriptionRow) -> Option<Command> {
    Some(Command::Push(PushCommand::Del {
        url: row.url.parse().ok()?,
        mailbox: match &row.mailbox {
            Some(m) => Some(m.parse().ok()?),
            None => None,
        },
    }))
}

/// A random time in the second half of the week after `now`.
fn renew_time(now: u64) -> u64 {
    let half = RENEW_MAX_MS / 2;
    now + half + super::conversations::random_below(half).unwrap_or(0)
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Add(i64),
    Del(i64),
}

/// The engine of this area, for one account. See the [module
/// docs](self).
#[derive(Debug, Default)]
pub struct PushEngine {
    ready: HashMap<Slot, ConnectionKind>,
    inflight: HashMap<Token, Op>,
    busy: HashSet<i64>,
    next_token: u64,
    last_check: u64,
    /// The time of the last tick.
    now: u64,
    /// The number of subscriptions waiting for a URL, last told to the app.
    told_waiting: usize,
}

impl PushEngine {
    fn token(&mut self, op: Op) -> Token {
        self.next_token += 1;
        let token = Token(self.next_token);
        self.inflight.insert(token, op);
        token
    }

    fn signed_in(&self) -> bool {
        self.ready.values().any(|k| *k == ConnectionKind::SignedIn)
    }

    fn anonymous(&self) -> bool {
        self.ready.values().any(|k| *k == ConnectionKind::Anonymous)
    }

    fn send(&mut self, out: &mut Vec<Action>, target: Target, command: Command, op: Op) {
        let id = match op {
            Op::Add(id) | Op::Del(id) => id,
        };
        self.busy.insert(id);
        let token = self.token(op);
        out.push(Action::Send {
            target,
            command,
            token,
        });
    }

    /// Brings the account's subscriptions in line with what push wants.
    fn check(&mut self, cx: &Context, now: u64) -> Result<Vec<Action>, EngineError> {
        let account = cx.account;
        if is_guest(&cx.store, account)? {
            return Ok(Vec::new());
        }
        let on = cx.store.setting(&setting(account))?.as_deref() == Some("on");
        let mut out = Vec::new();
        let (plan, changes) = cx.store.write_with(|tx| plan(tx, account, on, now))?;
        out.extend(changes.into_iter().map(|c| Action::Emit(Event::Changed(c))));
        for step in plan.steps {
            let (row, permit, add) = match step {
                Step::Add(row, permit) => (row, permit, true),
                Step::Del(row) => (row, None, false),
            };
            if self.busy.contains(&row.id) {
                continue;
            }
            let target = match &row.mailbox {
                None if self.signed_in() => Target::SignedIn,
                Some(m) if self.anonymous() => match m.parse() {
                    Ok(mailbox) => Target::Mailbox(mailbox),
                    Err(_) => continue,
                },
                _ => continue,
            };
            let command = if add {
                push_add(&row, permit)
            } else {
                push_del(&row)
            };
            if let Some(command) = command {
                let op = if add {
                    Op::Add(row.id)
                } else {
                    Op::Del(row.id)
                };
                self.send(&mut out, target, command, op);
            }
        }
        if plan.waiting_for_urls != self.told_waiting {
            self.told_waiting = plan.waiting_for_urls;
            if plan.waiting_for_urls > 0 {
                out.push(Action::Emit(Event::Transfer(
                    TransferEvent::PushUrlsNeeded {
                        account,
                        count: plan.waiting_for_urls,
                    },
                )));
            }
        }
        Ok(out)
    }

    fn reply(
        &mut self,
        cx: &Context,
        op: Op,
        end: &End,
        now: u64,
    ) -> Result<Vec<Action>, EngineError> {
        let id = match op {
            Op::Add(id) | Op::Del(id) => id,
        };
        self.busy.remove(&id);
        let (_, changes) = cx.store.write_with(|tx| -> Result<(), EngineError> {
            let Some(row) = tx
                .subscriptions(cx.account)?
                .into_iter()
                .find(|r| r.id == id)
            else {
                return Ok(());
            };
            match (op, end) {
                (Op::Add(_), End::Ok(_)) => {
                    // A mailbox subscription lasts one retention period
                    // from its PUSH ADD (9.1): renewed within a week.
                    let renew = row.mailbox.as_ref().map(|_| renew_time(now));
                    tx.set_subscription(id, SubState::Active, renew)?;
                }
                (Op::Add(_), End::Err(e)) => match e.code {
                    // The token's epoch passed: try again with a fresh one.
                    ErrorCode::Stale => tx.set_subscription(id, row.state, Some(now))?,
                    // The mailbox is gone, or the server takes no pushes.
                    ErrorCode::NotFound | ErrorCode::NotSupported | ErrorCode::Invalid => {
                        tx.remove_subscription(id)?
                    }
                    _ => tx.set_subscription(id, row.state, Some(now + RETRY_MS))?,
                },
                (Op::Del(_), End::Ok(_)) => tx.remove_subscription(id)?,
                (Op::Del(_), End::Err(e)) if e.code == ErrorCode::NotFound => {
                    tx.remove_subscription(id)?
                }
                // No reply: the connection went. Try again later.
                _ => {}
            }
            Ok(())
        })?;
        Ok(changes
            .into_iter()
            .map(|c| Action::Emit(Event::Changed(c)))
            .collect())
    }
}

fn is_guest(store: &Store, account: AccountId) -> Result<bool, StoreError> {
    Ok(store
        .accounts()?
        .iter()
        .find(|a| a.id == account)
        .is_none_or(|a| a.kind == crate::store::AccountKind::Guest))
}

enum Step {
    Add(
        SubscriptionRow,
        Option<(BoxName, risala_mls::token::SendToken)>,
    ),
    Del(SubscriptionRow),
}

struct Plan {
    steps: Vec<Step>,
    waiting_for_urls: usize,
}

/// What to send: new subscriptions, renewals and removals. New ones are
/// stored here, in state `adding`, each with a URL of its own.
fn plan(tx: &mut Tx<'_>, account: AccountId, on: bool, now: u64) -> Result<Plan, EngineError> {
    let mut steps = Vec::new();
    let mut waiting = 0;
    let subs = tx.subscriptions(account)?;
    // The mailboxes that want a subscription: each current mailbox of a
    // conversation the device is in, whose pushes are on.
    let mut wanted: HashMap<String, (crate::store::conversations::ConversationId, Vec<u8>)> =
        HashMap::new();
    if on {
        for conv in tx.conversations_of(account)? {
            if !conv.state.in_group() || tx.push_off(conv.id)? {
                continue;
            }
            if let Ok(mb) = tx.current_mailbox(conv.id) {
                wanted.insert(mb.mailbox.to_string(), (conv.id, conv.group_id.clone()));
            }
        }
    }
    let token_for = |tx: &Tx<'_>, mailbox: &str, group: &[u8]| {
        let mailbox: BoxName = mailbox.parse().ok()?;
        let token = crate::sync::transfer::send_token(tx, group).ok()?;
        Some((mailbox, token))
    };
    let mut have_account = false;
    let mut have: HashSet<String> = HashSet::new();
    for row in subs {
        let keep = on
            && row.state != SubState::Removing
            && match &row.mailbox {
                None => !have_account,
                Some(m) => wanted.contains_key(m) && !have.contains(m),
            };
        if !keep {
            if row.state == SubState::Adding && row.renew_at.is_none() {
                // Never accepted: nothing to delete on the server.
                tx.remove_subscription(row.id)?;
            } else {
                if row.state != SubState::Removing {
                    tx.set_subscription(row.id, SubState::Removing, None)?;
                }
                steps.push(Step::Del(row));
            }
            continue;
        }
        match &row.mailbox {
            None => have_account = true,
            Some(m) => {
                have.insert(m.clone());
            }
        }
        let due = row.state == SubState::Adding || row.renew_at.is_some_and(|t| t <= now);
        if due {
            let permit = match &row.mailbox {
                Some(m) => match token_for(tx, m, &wanted[m].1) {
                    Some(p) => Some(p),
                    None => continue,
                },
                None => None,
            };
            steps.push(Step::Add(row, permit));
        }
    }
    if on {
        let mut new: Vec<(
            Option<String>,
            Option<crate::store::conversations::ConversationId>,
        )> = Vec::new();
        if !have_account {
            new.push((None, None));
        }
        for (mailbox, (conv, _)) in &wanted {
            if !have.contains(mailbox) {
                new.push((Some(mailbox.clone()), Some(*conv)));
            }
        }
        for (mailbox, conv) in new {
            let Some(url) = tx.take_push_url(account)? else {
                waiting += 1;
                continue;
            };
            let keys = new_keys()?;
            let id = tx.add_subscription(
                &NewSubscription {
                    account,
                    conv,
                    mailbox: mailbox.as_deref(),
                    url: &url,
                    tag: &keys.tag,
                    p256dh: &keys.public,
                    auth: &keys.auth,
                    private_key: &keys.private,
                },
                now,
            )?;
            let row = tx
                .subscriptions(account)?
                .into_iter()
                .find(|r| r.id == id)
                .ok_or(StoreError::NotFound("subscription"))?;
            let permit = match &mailbox {
                Some(m) => match token_for(tx, m, &wanted[m].1) {
                    Some(p) => Some(p),
                    None => continue,
                },
                None => None,
            };
            steps.push(Step::Add(row, permit));
        }
    }
    Ok(Plan {
        steps,
        waiting_for_urls: waiting,
    })
}

impl Engine for PushEngine {
    fn handle(&mut self, cx: &Context, input: &Input<'_>) -> Vec<Action> {
        let result = match input {
            Input::Ready { slot, kind } => {
                self.ready.insert(*slot, *kind);
                // Check at the next tick.
                self.last_check = 0;
                Ok(Vec::new())
            }
            Input::Closed { slot } => {
                self.ready.remove(slot);
                Ok(Vec::new())
            }
            Input::Tick { now } => {
                let now = now.unix_millis();
                self.now = now;
                if now < self.last_check + CHECK_EVERY_MS {
                    return Vec::new();
                }
                self.last_check = now;
                self.check(cx, now)
            }
            Input::Reply {
                token, response, ..
            } => match self.inflight.remove(token) {
                Some(op) => {
                    let now = self.now;
                    self.reply(cx, op, &response.end, now)
                }
                None => Ok(Vec::new()),
            },
            Input::Line { .. } => Ok(Vec::new()),
        };
        result.unwrap_or_else(|e| {
            tracing::info!(error = %e, "push subscriptions");
            Vec::new()
        })
    }
}

/// The tag to give FOLLOW's `quiet` for `mailbox` (7.1, 9.2): the
/// mailbox subscription's, if the app asked for quiet follows. `None`
/// otherwise, as devices SHOULD leave it out.
pub(crate) fn follow_quiet(
    store: &Store,
    account: AccountId,
    mailbox: &BoxName,
) -> Option<PushTag> {
    if store.setting(&quiet_setting(account)).ok()?.as_deref() != Some("on") {
        return None;
    }
    let mailbox = mailbox.to_string();
    store
        .subscription_rows()
        .ok()?
        .into_iter()
        .find(|r| r.account == account && r.mailbox.as_deref() == Some(&mailbox))
        .and_then(|r| r.tag.parse().ok())
}

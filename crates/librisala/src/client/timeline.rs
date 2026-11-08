//! [`Timeline`]: a window on a conversation's messages that tells the UI
//! what changed.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use risala_proto::names::Seq;
use tokio::sync::{Notify, broadcast};

use super::account::{Batch, Conversation};
use super::blocking;
use super::types::{ClientError, Message, OutboxEntry, OutboxStatus, page_size};
use crate::store::{
    AccountId, Change, ConvId, OutboxId, OutboxItem, OutboxState, Store, StoreError,
};
use risala_proto::types::Relation;

/// A change to a [`Timeline`]'s items, to apply in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineDiff {
    /// Replace every item: the history was discarded (7.1), or changes
    /// were missed.
    Reset {
        /// The items now.
        items: Vec<Message>,
    },
    /// Insert an item at `index`; later items move up.
    Insert {
        /// Where.
        index: u32,
        /// The item.
        item: Message,
    },
    /// The item at `index` changed: edited, deleted or reacted to, or an
    /// outbox entry was replaced by its stored event. Its
    /// [`id`](Message::id) stays the same.
    Update {
        /// Where.
        index: u32,
        /// The item now.
        item: Message,
    },
    /// Remove the item at `index`; later items move down.
    Remove {
        /// Where.
        index: u32,
    },
}

/// A window on a conversation's messages, oldest first, that follows every
/// change to the cache and reports it as [`TimelineDiff`]s.
///
/// After the stored messages come the account's messages still in the
/// outbox (7.6), queued, sending or failed, oldest first. They have seq 0
/// and [`Message::outbox`] set. When one is sent, its stored event takes
/// its place with the same [`Message::id`]: an [`Update`] when it stays
/// at the same index, as it does unless others' messages came in between,
/// or else a [`Remove`] of the entry and an [`Insert`] among the stored
/// ones. When it fails, it is updated, and stays until the app removes it
/// with [`Account::remove_outbox`](super::Account::remove_outbox), or
/// retries it with [`Account::retry_outbox`](super::Account::retry_outbox),
/// which updates it to queued again in the same place. Edits
/// and reactions in the outbox are not shown as items.
///
/// The server sends a message's event before the OK that names it (5.3).
/// While an entry is being sent, an own event with the same text that
/// arrives is held back until the OK says whether it is the entry's, so
/// that the message is never shown twice. If the OK names an event that
/// is not stored yet, the entry is removed, and the event is inserted
/// with the entry's id when it arrives.
///
/// It starts with the newest messages in the cache. Messages that arrive
/// later are inserted in seq order, so a page of older history that
/// catching up stores shows up in its place. [`paginate_back`] widens the
/// window into older messages, from the cache and then from the server,
/// until [`at_start`](Self::at_start).
///
/// Get one from [`Conversation::timeline`]. Read the starting items with
/// [`items`](Self::items), then call [`next`](Self::next) in a loop.
///
/// [`paginate_back`]: Self::paginate_back
/// [`Update`]: TimelineDiff::Update
/// [`Remove`]: TimelineDiff::Remove
/// [`Insert`]: TimelineDiff::Insert
pub struct Timeline {
    conv: Conversation,
    state: Arc<Mutex<State>>,
    rx: Arc<tokio::sync::Mutex<broadcast::Receiver<Arc<Batch>>>>,
    notify: Arc<Notify>,
    rt: tokio::runtime::Handle,
}

impl std::fmt::Debug for Timeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timeline")
            .field("conv", &self.conv)
            .finish_non_exhaustive()
    }
}

struct State {
    account: AccountId,
    /// The account's uid, the sender of messages in the outbox.
    uid: String,
    store: Store,
    conv: risala_proto::names::Conv,
    /// The conversation's row, once it is in the cache.
    row: Option<ConvId>,
    /// Stored items, by seq.
    items: Vec<Message>,
    /// Messages in the outbox, after the stored items, by outbox id.
    outbox: Vec<Message>,
    /// Own stored messages not shown yet, by seq: each may be the event of
    /// an outbox entry being sent, whose OK has not come.
    held: Vec<Message>,
    /// The lowest seq in the window. `None`: every stored item is in it.
    floor: Option<u64>,
    /// See [`Timeline::at_start`].
    at_start: bool,
    /// Diffs from [`Timeline::paginate_back`] for [`Timeline::next`].
    pending: VecDeque<Vec<TimelineDiff>>,
}

impl Timeline {
    pub(crate) fn new(conv: Conversation, limit: u32) -> Result<Timeline, ClientError> {
        let shared = conv.account().shared().clone();
        // Subscribe first, so that nothing stored after the read is missed.
        // A change already in the items is applied again as an update.
        let rx = shared.events.subscribe();
        let mut state = State {
            account: shared.id,
            uid: shared.uid.to_string(),
            store: shared.store.clone(),
            conv: conv.conv().clone(),
            row: None,
            items: Vec::new(),
            outbox: Vec::new(),
            held: Vec::new(),
            floor: None,
            at_start: false,
            pending: VecDeque::new(),
        };
        state.load(page_size(limit))?;
        Ok(Timeline {
            conv,
            state: Arc::new(Mutex::new(state)),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            notify: Arc::new(Notify::new()),
            rt: shared.rt.clone(),
        })
    }

    /// The conversation.
    pub fn conversation(&self) -> Conversation {
        self.conv.clone()
    }

    /// The items now, oldest first, then the messages in the outbox.
    pub fn items(&self) -> Vec<Message> {
        self.state.lock().expect("poisoned").all()
    }

    /// Whether the window reaches the start of the conversation's history:
    /// it holds every stored item, and the server keeps nothing older that
    /// the cache lacks, because the sync point reaches the oldest item
    /// (7.1), older events having expired (7.5) or never existed. Then
    /// [`paginate_back`](Self::paginate_back) has nothing to add.
    ///
    /// It is `true` for a conversation the cache does not know, and turns
    /// `false` when one is stored with history still to load. It reflects
    /// every batch queued for [`next`](Self::next), so read it after each
    /// one; a batch with no diffs means only this changed.
    pub fn at_start(&self) -> bool {
        self.state.lock().expect("poisoned").at_start
    }

    /// The next changes, in order. Waits until there are some, or until
    /// [`at_start`](Self::at_start) changes, which comes as an empty batch.
    /// `None` once the account has been removed.
    ///
    /// It is cancel-safe: if the future is dropped, as in a
    /// `tokio::select!` loop, no change is lost; the next call returns it.
    pub async fn next(&self) -> Option<Vec<TimelineDiff>> {
        loop {
            if let Some(diffs) = self.pop() {
                return Some(diffs);
            }
            let mut rx = self.rx.clone().lock_owned().await;
            // A call dropped while applying may have queued diffs.
            if let Some(diffs) = self.pop() {
                return Some(diffs);
            }
            tokio::select! {
                r = rx.recv() => {
                    let reload = match r {
                        Ok(batch) if batch.reload => None,
                        Ok(batch) if batch.changes.is_empty() => continue,
                        Ok(batch) => Some(batch),
                        Err(broadcast::error::RecvError::Lagged(_)) => None,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    };
                    // The receiver goes with the work, so nothing else is
                    // applied before it, even if this call is dropped. The
                    // diffs are queued in the same step.
                    let state = self.state.clone();
                    blocking(&self.rt, move || {
                        let _rx = rx;
                        let mut st = state.lock().expect("poisoned");
                        let was_at_start = st.at_start;
                        let diffs = match &reload {
                            Some(batch) => st.apply(&batch.changes),
                            None => st.reload(),
                        };
                        match diffs {
                            Ok(diffs) if diffs.is_empty() && st.at_start == was_at_start => {}
                            Ok(diffs) => st.pending.push_back(diffs),
                            Err(e) => tracing::warn!(error = %e, "timeline: reading the cache"),
                        }
                    })
                    .await;
                }
                () = self.notify.notified() => {}
            }
        }
    }

    /// Reads the window again from the cache, and queues a
    /// [`TimelineDiff::Reset`] for [`next`](Self::next). Use it after
    /// another process wrote to the cache; see
    /// [`Client::check_for_external_changes`](super::Client::check_for_external_changes),
    /// which does it for every timeline.
    pub async fn refresh(&self) -> Result<(), ClientError> {
        let state = self.state.clone();
        let notify = self.notify.clone();
        blocking(&self.rt, move || -> Result<(), StoreError> {
            let mut st = state.lock().expect("poisoned");
            let diffs = st.reload()?;
            st.pending.push_back(diffs);
            notify.notify_one();
            Ok(())
        })
        .await?;
        Ok(())
    }

    fn pop(&self) -> Option<Vec<TimelineDiff>> {
        self.state.lock().expect("poisoned").pending.pop_front()
    }

    /// Widens the window by up to `count` older messages from the cache,
    /// at most [`MAX_PAGE`](super::types::MAX_PAGE).
    /// The diffs arrive through [`next`](Self::next).
    ///
    /// When the cache has no more, it asks the server for the page below
    /// (see [`Conversation::load_older`]), whose messages arrive through
    /// `next` too, and returns `true`. That is not the start of the
    /// history; see [`at_start`](Self::at_start) for that.
    pub async fn paginate_back(&self, count: u32) -> Result<bool, ClientError> {
        let state = self.state.clone();
        let notify = self.notify.clone();
        let exhausted = blocking(&self.rt, move || -> Result<bool, StoreError> {
            let mut st = state.lock().expect("poisoned");
            let was_at_start = st.at_start;
            let (diffs, exhausted) = st.older(page_size(count))?;
            if !diffs.is_empty() || st.at_start != was_at_start {
                st.pending.push_back(diffs);
                notify.notify_one();
            }
            Ok(exhausted)
        })
        .await?;
        if exhausted {
            match self.conv.load_older().await {
                Ok(()) | Err(ClientError::NotConnected) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(exhausted)
    }
}

impl State {
    fn resolve(&mut self) -> Result<Option<ConvId>, StoreError> {
        if self.row.is_none() {
            self.row = self
                .store
                .conversation(self.account, &self.conv)?
                .map(|c| c.id);
        }
        Ok(self.row)
    }

    /// Every item: the stored ones, then the outbox.
    fn all(&self) -> Vec<Message> {
        let mut all = self.items.clone();
        all.extend(self.outbox.iter().cloned());
        all
    }

    /// Recomputes [`Timeline::at_start`].
    fn check_start(&mut self) -> Result<(), StoreError> {
        self.at_start = match (self.floor, self.resolve()?) {
            (Some(_), _) => false,
            (None, None) => true,
            (None, Some(row)) => {
                let lowest = self
                    .items
                    .first()
                    .into_iter()
                    .chain(self.held.first())
                    .map(|m| m.seq)
                    .min()
                    .and_then(Seq::new);
                self.store.complete_below(row, lowest)?
            }
        };
        Ok(())
    }

    /// Whether an outbox entry is shown as an item: a message or a reply
    /// that has not been sent yet, or failed. Not a DELETE (5.4).
    fn shows(item: &OutboxItem) -> bool {
        !matches!(item.state, OutboxState::Sent(_))
            && item.delete.is_none()
            && matches!(item.draft.relation, None | Some(Relation::Reply(_)))
    }

    fn load_outbox(&mut self) -> Result<(), StoreError> {
        self.outbox = self
            .store
            .outbox_for(self.account, &self.conv)?
            .into_iter()
            .filter(State::shows)
            .map(|item| Message::outgoing(OutboxEntry::from(item), &self.uid))
            .collect();
        Ok(())
    }

    /// Whether own stored `item` may be the event of an outbox entry being
    /// sent: one with the same text and reply.
    fn awaits(&self, item: &Message) -> bool {
        self.outbox.iter().any(|m| {
            m.outbox
                .as_ref()
                .is_some_and(|e| e.status == OutboxStatus::Sending)
                && m.text == item.text
                && m.reply_to == item.reply_to
        })
    }

    /// Shows stored item `item` at its seq: an insert, or an update of the
    /// item there. An update that changes the id is a remove and an insert.
    fn put(&mut self, item: Message, diffs: &mut Vec<TimelineDiff>) {
        match self.items.binary_search_by_key(&item.seq, |m| m.seq) {
            Ok(i) => {
                let index = i as u32;
                if self.items[i].id != item.id {
                    diffs.push(TimelineDiff::Remove { index });
                    diffs.push(TimelineDiff::Insert {
                        index,
                        item: item.clone(),
                    });
                } else {
                    diffs.push(TimelineDiff::Update {
                        index,
                        item: item.clone(),
                    });
                }
                self.items[i] = item;
            }
            Err(i) => {
                self.items.insert(i, item.clone());
                diffs.push(TimelineDiff::Insert {
                    index: i as u32,
                    item,
                });
            }
        }
    }

    /// Shows a stored item that was inserted or changed. The event of an
    /// outbox entry that is shown takes its place; an own message that
    /// may be one is held back until its OK.
    fn stored(&mut self, item: Message, diffs: &mut Vec<TimelineDiff>) {
        if let Ok(h) = self.held.binary_search_by_key(&item.seq, |m| m.seq) {
            if item.unclaimed_own() && self.awaits(&item) {
                self.held[h] = item;
                return;
            }
            self.held.remove(h);
        }
        if let Some(i) = self.outbox.iter().position(|m| m.id == item.id) {
            self.replace_outbox(i, item, diffs);
            return;
        }
        let shown = self
            .items
            .binary_search_by_key(&item.seq, |m| m.seq)
            .is_ok();
        if !shown && item.unclaimed_own() && self.awaits(&item) {
            let at = self
                .held
                .binary_search_by_key(&item.seq, |m| m.seq)
                .unwrap_or_else(|i| i);
            self.held.insert(at, item);
            return;
        }
        self.put(item, diffs);
    }

    /// Puts stored item `item`, the event of the outbox item at `i`, in its
    /// place: an update when it lands at the same index, else a remove and
    /// an insert.
    fn replace_outbox(&mut self, i: usize, item: Message, diffs: &mut Vec<TimelineDiff>) {
        let base = self.items.len();
        self.outbox.remove(i);
        match self.items.binary_search_by_key(&item.seq, |m| m.seq) {
            Err(k) if i == 0 && k == base => {
                self.items.push(item.clone());
                diffs.push(TimelineDiff::Update {
                    index: base as u32,
                    item,
                });
            }
            _ => {
                diffs.push(TimelineDiff::Remove {
                    index: (base + i) as u32,
                });
                self.put(item, diffs);
            }
        }
    }

    /// Shows the held messages that no entry being sent may claim any more.
    fn release(&mut self, diffs: &mut Vec<TimelineDiff>) {
        let mut h = 0;
        while h < self.held.len() {
            if self.awaits(&self.held[h]) {
                h += 1;
            } else {
                let item = self.held.remove(h);
                self.put(item, diffs);
            }
        }
    }

    /// Applies a change to an outbox entry.
    fn outbox_changed(
        &mut self,
        id: OutboxId,
        diffs: &mut Vec<TimelineDiff>,
    ) -> Result<(), StoreError> {
        let item = self
            .store
            .outbox_item(id)?
            .filter(|i| i.account == self.account && i.conv == self.conv);
        let at = self
            .outbox
            .binary_search_by_key(&id.get(), |m| m.outbox.as_ref().map_or(0, |o| o.id));
        // Sent: its event takes its place, if it is stored and in the
        // window with the entry's id.
        if let (Some(OutboxState::Sent(seq)), Ok(i), Some(row)) =
            (item.as_ref().map(|i| &i.state), at, self.resolve()?)
        {
            let seq = *seq;
            let in_window = self.floor.is_none_or(|f| seq.get() >= f);
            if in_window && let Some(event) = self.store.message(row, seq)? {
                let event = Message::from(event);
                if event.id == self.outbox[i].id {
                    if let Ok(h) = self.held.binary_search_by_key(&event.seq, |m| m.seq) {
                        self.held.remove(h);
                    }
                    self.replace_outbox(i, event, diffs);
                    self.release(diffs);
                    return Ok(());
                }
            }
        }
        let base = self.items.len();
        match (item.filter(State::shows), at) {
            (Some(item), Ok(i)) => {
                let m = Message::outgoing(OutboxEntry::from(item), &self.uid);
                self.outbox[i] = m.clone();
                diffs.push(TimelineDiff::Update {
                    index: (base + i) as u32,
                    item: m,
                });
            }
            (Some(item), Err(i)) => {
                let m = Message::outgoing(OutboxEntry::from(item), &self.uid);
                self.outbox.insert(i, m.clone());
                diffs.push(TimelineDiff::Insert {
                    index: (base + i) as u32,
                    item: m,
                });
            }
            (None, Ok(i)) => {
                self.outbox.remove(i);
                diffs.push(TimelineDiff::Remove {
                    index: (base + i) as u32,
                });
            }
            (None, Err(_)) => {}
        }
        self.release(diffs);
        Ok(())
    }

    fn load(&mut self, limit: u32) -> Result<(), StoreError> {
        self.items.clear();
        self.held.clear();
        self.floor = None;
        self.load_outbox()?;
        if let Some(row) = self.resolve()? {
            let items = self.store.timeline(row, None, limit as usize)?;
            if items.len() >= limit as usize {
                self.floor = items.first().map(|i| i.seq.get());
            }
            self.items = items.into_iter().map(Message::from).collect();
        }
        self.check_start()
    }

    /// Reads the window again, after missed changes. Messages held back
    /// for their OK are shown: the cache no longer says which came when.
    fn reload(&mut self) -> Result<Vec<TimelineDiff>, StoreError> {
        self.row = None;
        self.held.clear();
        self.load_outbox()?;
        match self.resolve()? {
            Some(row) => {
                let floor = self.floor.and_then(Seq::new);
                let mut items: Vec<Message> = Vec::new();
                // Everything from the floor up: page back from the newest.
                let mut before = None;
                loop {
                    let page = self.store.timeline(row, before, 500)?;
                    let Some(first) = page.first() else { break };
                    let stop = floor.is_some_and(|f| first.seq <= f) || page.len() < 500;
                    before = Some(first.seq);
                    let mut page: Vec<Message> = page
                        .into_iter()
                        .filter(|i| floor.is_none_or(|f| i.seq >= f))
                        .map(Message::from)
                        .collect();
                    page.append(&mut items);
                    items = page;
                    if stop {
                        break;
                    }
                }
                self.items = items;
            }
            None => self.items.clear(),
        }
        self.check_start()?;
        Ok(vec![TimelineDiff::Reset { items: self.all() }])
    }

    fn older(&mut self, count: u32) -> Result<(Vec<TimelineDiff>, bool), StoreError> {
        let (Some(row), Some(floor)) = (self.resolve()?, self.floor) else {
            return Ok((Vec::new(), true));
        };
        let older = self.store.timeline(row, Seq::new(floor), count as usize)?;
        let exhausted = older.len() < count as usize;
        self.floor = if exhausted {
            None
        } else {
            older.first().map(|i| i.seq.get())
        };
        let older: Vec<Message> = older.into_iter().map(Message::from).collect();
        let diffs = older
            .iter()
            .enumerate()
            .map(|(i, item)| TimelineDiff::Insert {
                index: i as u32,
                item: item.clone(),
            })
            .collect();
        self.items.splice(0..0, older);
        self.check_start()?;
        Ok((diffs, exhausted))
    }

    fn apply(&mut self, changes: &[Change]) -> Result<Vec<TimelineDiff>, StoreError> {
        let mut diffs = Vec::new();
        // Whether the conversation changed, which may move the start.
        let mut touched = false;
        for change in changes {
            let row = self.resolve()?;
            match *change {
                Change::Cleared { conv } if Some(conv) == row => {
                    self.items.clear();
                    self.held.clear();
                    self.floor = None;
                    touched = true;
                    diffs.push(TimelineDiff::Reset { items: self.all() });
                }
                Change::ConversationRemoved { conv, .. } if Some(conv) == row => {
                    self.items.clear();
                    self.held.clear();
                    self.floor = None;
                    self.row = None;
                    touched = true;
                    diffs.push(TimelineDiff::Reset { items: self.all() });
                }
                Change::Conversation { conv } if Some(conv) == row => touched = true,
                Change::Outbox { id } => self.outbox_changed(id, &mut diffs)?,
                Change::Inserted { conv, seq } if Some(conv) == row => {
                    touched = true;
                    if self.floor.is_some_and(|f| seq.get() < f) {
                        continue;
                    }
                    let Some(item) = self.store.message(conv, seq)? else {
                        // An edit, reaction or DELETE: it updates others.
                        continue;
                    };
                    self.stored(Message::from(item), &mut diffs);
                }
                Change::Updated { conv, seq } if Some(conv) == row => {
                    touched = true;
                    let by_seq = |m: &Message| m.seq;
                    let held = self.held.binary_search_by_key(&seq.get(), by_seq);
                    let shown = self.items.binary_search_by_key(&seq.get(), by_seq);
                    if held.is_err() && shown.is_err() {
                        continue;
                    }
                    match self.store.message(conv, seq)? {
                        Some(item) => self.stored(Message::from(item), &mut diffs),
                        None => {
                            if let Ok(h) = held {
                                self.held.remove(h);
                            }
                            if let Ok(i) = shown {
                                self.items.remove(i);
                                diffs.push(TimelineDiff::Remove { index: i as u32 });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if touched {
            self.check_start()?;
        }
        Ok(diffs)
    }
}

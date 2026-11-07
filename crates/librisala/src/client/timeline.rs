//! [`Timeline`]: a window on a conversation's messages that tells the UI
//! what changed.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use risala_proto::names::Seq;
use tokio::sync::{Notify, broadcast};

use super::account::{Batch, Conversation};
use super::blocking;
use super::types::{ClientError, Message};
use crate::store::{AccountId, Change, ConvId, Store, StoreError};

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
    /// The item at `index` changed: edited, deleted or reacted to.
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
/// It starts with the newest messages in the cache. Messages that arrive
/// later are inserted in seq order, so a page of older history that
/// catching up stores shows up in its place. [`paginate_back`] widens the
/// window into older messages, from the cache and then from the server.
///
/// Get one from [`Conversation::timeline`]. Read the starting items with
/// [`items`](Self::items), then call [`next`](Self::next) in a loop.
///
/// [`paginate_back`]: Self::paginate_back
pub struct Timeline {
    conv: Conversation,
    state: Arc<Mutex<State>>,
    rx: Arc<tokio::sync::Mutex<broadcast::Receiver<Arc<Batch>>>>,
    notify: Arc<Notify>,
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
    store: Store,
    conv: risala_proto::names::Conv,
    /// The conversation's row, once it is in the cache.
    row: Option<ConvId>,
    items: Vec<Message>,
    /// The lowest seq in the window. `None`: every stored item is in it.
    floor: Option<u64>,
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
            store: shared.store.clone(),
            conv: conv.conv().clone(),
            row: None,
            items: Vec::new(),
            floor: None,
            pending: VecDeque::new(),
        };
        state.load(limit.max(1))?;
        Ok(Timeline {
            conv,
            state: Arc::new(Mutex::new(state)),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            notify: Arc::new(Notify::new()),
        })
    }

    /// The conversation.
    pub fn conversation(&self) -> Conversation {
        self.conv.clone()
    }

    /// The items now, oldest first.
    pub fn items(&self) -> Vec<Message> {
        self.state.lock().expect("poisoned").items.clone()
    }

    /// The next changes, in order. Waits until there are some. `None` once
    /// the account has been removed.
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
                        Ok(batch) if batch.changes.is_empty() => continue,
                        Ok(batch) => Some(batch),
                        Err(broadcast::error::RecvError::Lagged(_)) => None,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    };
                    // The receiver goes with the work, so nothing else is
                    // applied before it, even if this call is dropped. The
                    // diffs are queued in the same step.
                    let state = self.state.clone();
                    blocking(move || {
                        let _rx = rx;
                        let mut st = state.lock().expect("poisoned");
                        let diffs = match &reload {
                            Some(batch) => st.apply(&batch.changes),
                            None => st.reload(),
                        };
                        match diffs {
                            Ok(diffs) if diffs.is_empty() => {}
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

    fn pop(&self) -> Option<Vec<TimelineDiff>> {
        self.state.lock().expect("poisoned").pending.pop_front()
    }

    /// Widens the window by up to `count` older messages from the cache.
    /// The diffs arrive through [`next`](Self::next).
    ///
    /// When the cache has no more, it asks the server for the page below
    /// (see [`Conversation::load_older`]), whose messages arrive through
    /// `next` too, and returns `true`.
    pub async fn paginate_back(&self, count: u32) -> Result<bool, ClientError> {
        let state = self.state.clone();
        let notify = self.notify.clone();
        let exhausted = blocking(move || -> Result<bool, StoreError> {
            let mut st = state.lock().expect("poisoned");
            let (diffs, exhausted) = st.older(count.max(1))?;
            if !diffs.is_empty() {
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

    fn load(&mut self, limit: u32) -> Result<(), StoreError> {
        self.items.clear();
        self.floor = None;
        let Some(row) = self.resolve()? else {
            return Ok(());
        };
        let items = self.store.timeline(row, None, limit as usize)?;
        if items.len() >= limit as usize {
            self.floor = items.first().map(|i| i.seq.get());
        }
        self.items = items.into_iter().map(Message::from).collect();
        Ok(())
    }

    /// Reads the window again, after missed changes.
    fn reload(&mut self) -> Result<Vec<TimelineDiff>, StoreError> {
        self.row = None;
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
        Ok(vec![TimelineDiff::Reset {
            items: self.items.clone(),
        }])
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
        Ok((diffs, exhausted))
    }

    fn apply(&mut self, changes: &[Change]) -> Result<Vec<TimelineDiff>, StoreError> {
        let mut diffs = Vec::new();
        for change in changes {
            let row = self.resolve()?;
            match *change {
                Change::Cleared { conv } if Some(conv) == row => {
                    self.items.clear();
                    self.floor = None;
                    diffs.push(TimelineDiff::Reset { items: Vec::new() });
                }
                Change::ConversationRemoved { conv, .. } if Some(conv) == row => {
                    self.items.clear();
                    self.floor = None;
                    self.row = None;
                    diffs.push(TimelineDiff::Reset { items: Vec::new() });
                }
                Change::Inserted { conv, seq } if Some(conv) == row => {
                    if self.floor.is_some_and(|f| seq.get() < f) {
                        continue;
                    }
                    let Some(item) = self.store.message(conv, seq)? else {
                        // An edit, reaction or DELETE: it updates others.
                        continue;
                    };
                    let item = Message::from(item);
                    match self.items.binary_search_by_key(&seq.get(), |m| m.seq) {
                        Ok(i) => {
                            self.items[i] = item.clone();
                            diffs.push(TimelineDiff::Update {
                                index: i as u32,
                                item,
                            });
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
                Change::Updated { conv, seq } if Some(conv) == row => {
                    let Ok(i) = self.items.binary_search_by_key(&seq.get(), |m| m.seq) else {
                        continue;
                    };
                    match self.store.message(conv, seq)? {
                        Some(item) => {
                            let item = Message::from(item);
                            self.items[i] = item.clone();
                            diffs.push(TimelineDiff::Update {
                                index: i as u32,
                                item,
                            });
                        }
                        None => {
                            self.items.remove(i);
                            diffs.push(TimelineDiff::Remove { index: i as u32 });
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(diffs)
    }
}

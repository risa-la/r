//! [`ChatList`]: every account's conversations, newest activity first, as
//! a window that tells the UI what changed.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use risala_proto::names::{Conv, Uid};
use risala_proto::text::unescape;
use tokio::sync::{Notify, broadcast};

use super::account::Batch;
use super::people::{labels, shown_name};
use super::types::{
    AccountRef, ChatCounts, ChatFilter, ChatKind, ChatPreview, ChatSummary, ClientError, Delivery,
    Label, page_size,
};
use super::{Client, blocking, parse_server};
use crate::addr::ServerAddr;
use crate::store::{
    AccountId, Change, ChatKey, ChatQuery, ChatRow, ConvId, FailReason, OutboxState, Store,
    StoreError, key_order,
};

/// A change to a [`ChatList`]'s items, to apply in order, as
/// [`TimelineDiff`](super::TimelineDiff).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatListDiff {
    /// Replace every item: the filter changed, changes were missed, or
    /// another process wrote to the cache.
    Reset {
        /// The items now.
        items: Vec<ChatSummary>,
    },
    /// Insert an item at `index`; later items move up.
    Insert {
        /// Where.
        index: u32,
        /// The item.
        item: ChatSummary,
    },
    /// The item at `index` changed in place. Its
    /// [`id`](ChatSummary::id) stays the same.
    Update {
        /// Where.
        index: u32,
        /// The item now.
        item: ChatSummary,
    },
    /// Remove the item at `index`; later items move down.
    Remove {
        /// Where.
        index: u32,
    },
}

/// What [`ChatList::next`] returns: the changes to the items, in order, and
/// the counts after them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatListBatch {
    /// The changes. Empty when only the counts changed.
    pub diffs: Vec<ChatListDiff>,
    /// The counts now.
    pub counts: ChatCounts,
}

/// Every account's conversations, newest activity first, ties broken by
/// the order they entered the cache, as a window that follows every change
/// and reports it as [`ChatListDiff`]s. See [`Client::chat_list`].
///
/// - **The window** is the first rows that the [`ChatFilter`] shows, as
///   many as asked for. [`load_more`](Self::load_more) widens it. When a
///   row moves up into the window, the row pushed past its end is
///   removed, so the window keeps its size.
/// - **A row that moves** comes as a [`Remove`](ChatListDiff::Remove) and
///   an [`Insert`](ChatListDiff::Insert). A row that changes in place is
///   an [`Update`](ChatListDiff::Update). The [`id`](ChatSummary::id)
///   never changes.
/// - [`set_filter`](Self::set_filter), missed changes and a write by
///   another process (see
///   [`Client::check_for_external_changes`](super::Client::check_for_external_changes))
///   come as one [`Reset`](ChatListDiff::Reset).
///
/// The account's connection state is not on its rows: follow it with
/// [`Account::subscribe`](super::Account::subscribe)
/// ([`AccountEvent::State`](super::AccountEvent::State)). It needs no
/// connection.
///
/// Read the starting items with [`items`](Self::items) and
/// [`counts`](Self::counts), then call [`next`](Self::next) in a loop.
pub struct ChatList {
    state: Arc<Mutex<Shown>>,
    rx: Arc<tokio::sync::Mutex<broadcast::Receiver<Arc<Batch>>>>,
    notify: Arc<Notify>,
    rt: tokio::runtime::Handle,
}

impl std::fmt::Debug for ChatList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatList").finish_non_exhaustive()
    }
}

/// The window, with the batches not yet returned by [`ChatList::next`].
struct Shown {
    chats: ChatState,
    pending: VecDeque<ChatListBatch>,
    /// The counts last reported.
    reported: ChatCounts,
}

impl Shown {
    /// Queues `diffs`, if there are any or the counts changed.
    fn queue(&mut self, diffs: Vec<ChatListDiff>) {
        let counts = self.chats.counts();
        if !diffs.is_empty() || counts != self.reported {
            self.reported = counts;
            self.pending.push_back(ChatListBatch { diffs, counts });
        }
    }
}

/// What a batch from the accounts asks of the list.
enum Work {
    Apply(Arc<Batch>),
    Reload,
}

impl Client {
    /// Every account's conversations, newest activity first, as a window
    /// of the first `limit` that `filter` shows, which then follows every
    /// change. See [`ChatList`]. `limit` is capped at
    /// [`MAX_PAGE`](super::types::MAX_PAGE); 0 asks for
    /// [`DEFAULT_PAGE`](super::types::DEFAULT_PAGE). It needs no
    /// connection; the first read is one query.
    pub fn chat_list(&self, filter: ChatFilter, limit: u32) -> Result<ChatList, ClientError> {
        let query = query_of(&filter)?;
        // Subscribe first, so that nothing stored after the read is missed.
        // A change already in the items is applied again as an update.
        let rx = self.inner.chats.subscribe();
        let chats = ChatState::new(self.inner.store.clone(), query, page_size(limit) as usize)?;
        let reported = chats.counts();
        Ok(ChatList {
            state: Arc::new(Mutex::new(Shown {
                chats,
                pending: VecDeque::new(),
                reported,
            })),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            notify: Arc::new(Notify::new()),
            rt: self.inner.rt.clone(),
        })
    }
}

impl ChatList {
    /// The items now, in order.
    pub fn items(&self) -> Vec<ChatSummary> {
        self.state.lock().expect("poisoned").chats.items()
    }

    /// The counts now. They reflect every batch queued for
    /// [`next`](Self::next).
    pub fn counts(&self) -> ChatCounts {
        self.state.lock().expect("poisoned").chats.counts()
    }

    /// The next changes, in order, with the counts after them. Waits until
    /// the items or the counts change. `None` once the client is gone.
    ///
    /// It is cancel-safe: if the future is dropped, as in a
    /// `tokio::select!` loop, no change is lost; the next call returns it.
    pub async fn next(&self) -> Option<ChatListBatch> {
        loop {
            if let Some(batch) = self.pop() {
                return Some(batch);
            }
            let mut rx = self.rx.clone().lock_owned().await;
            // A call dropped while applying may have queued a batch.
            if let Some(batch) = self.pop() {
                return Some(batch);
            }
            tokio::select! {
                r = rx.recv() => {
                    let work = match r {
                        Ok(batch) if batch.changes.is_empty() && batch.reload => Work::Reload,
                        Ok(batch) if batch.changes.is_empty() => continue,
                        Ok(batch) => Work::Apply(batch),
                        Err(broadcast::error::RecvError::Lagged(_)) => Work::Reload,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    };
                    // The receiver goes with the work, so nothing else is
                    // applied before it, even if this call is dropped. The
                    // diffs are queued in the same step.
                    let state = self.state.clone();
                    blocking(&self.rt, move || {
                        let mut rx = rx;
                        let mut st = state.lock().expect("poisoned");
                        let diffs = match work {
                            Work::Apply(batch) => st.chats.apply(&batch.changes),
                            Work::Reload => {
                                // One read covers whatever is queued too.
                                while let Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) =
                                    rx.try_recv()
                                {}
                                st.chats.reload()
                            }
                        };
                        match diffs {
                            Ok(diffs) => st.queue(diffs),
                            Err(e) => tracing::warn!(error = %e, "chat list: reading the cache"),
                        }
                    })
                    .await;
                }
                () = self.notify.notified() => {}
            }
        }
    }

    fn pop(&self) -> Option<ChatListBatch> {
        self.state.lock().expect("poisoned").pending.pop_front()
    }

    /// Widens the window by up to `count` rows, at most
    /// [`MAX_PAGE`](super::types::MAX_PAGE); 0 asks for
    /// [`DEFAULT_PAGE`](super::types::DEFAULT_PAGE). The diffs arrive
    /// through [`next`](Self::next). [`ChatCounts::total`] says whether
    /// there are more.
    pub async fn load_more(&self, count: u32) -> Result<(), ClientError> {
        let count = page_size(count) as usize;
        self.change(move |chats| chats.widen(count)).await
    }

    /// Shows what `filter` shows instead, in a window of the same size.
    /// One [`ChatListDiff::Reset`] arrives through [`next`](Self::next).
    pub async fn set_filter(&self, filter: ChatFilter) -> Result<(), ClientError> {
        let query = query_of(&filter)?;
        self.change(move |chats| chats.set_query(query)).await
    }

    /// Changes the window with `f` and queues its diffs for
    /// [`next`](Self::next). It reads the cache, and may wait for `next`
    /// to finish applying a batch, so it runs on the runtime's blocking
    /// threads rather than the caller's, which may be a UI thread.
    async fn change(
        &self,
        f: impl FnOnce(&mut ChatState) -> Result<Vec<ChatListDiff>, StoreError> + Send + 'static,
    ) -> Result<(), ClientError> {
        let state = self.state.clone();
        let notify = self.notify.clone();
        blocking(&self.rt, move || {
            let mut st = state.lock().expect("poisoned");
            let diffs = f(&mut st.chats)?;
            st.queue(diffs);
            notify.notify_one();
            Ok(())
        })
        .await
    }
}

/// The store's query for `filter`, with the server in its display form.
fn query_of(filter: &ChatFilter) -> Result<ChatQuery, ClientError> {
    Ok(ChatQuery {
        server: filter
            .server
            .as_deref()
            .map(|s| parse_server(s).map(|a| a.to_string()))
            .transpose()?,
        unread: filter.unread,
        favourites: filter.favourites,
        rooms: filter.rooms,
    })
}

/// Whether `server` is the home server of the account `uid`: see
/// [`ChatSummary::home_server`].
fn home_server(server: &ServerAddr, uid: &Uid) -> bool {
    let Some(domain) = uid.domain() else {
        return true;
    };
    let host = server.host();
    host.eq_ignore_ascii_case(domain)
        || host.len() > domain.len()
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
            && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
}

/// The row an app shows for `row`.
fn summary(row: ChatRow) -> ChatSummary {
    let other = match &row.name {
        Conv::Uid(uid) => Some(uid.clone()),
        Conv::Room(_) => None,
    };
    // The people the row names, labelled among themselves (8.2).
    let mut people = vec![(row.uid.clone(), shown_name(row.own_name.as_deref()))];
    if let Some(o) = other.as_ref().filter(|o| **o != row.uid) {
        people.push((o.clone(), shown_name(row.other_name.as_deref())));
    }
    if let Some(p) = &row.last
        && !people.iter().any(|(u, _)| *u == p.from)
    {
        people.push((p.from.clone(), shown_name(p.from_name.as_deref())));
    }
    let shown = labels(&people);
    let label = |uid: &Uid| -> Label {
        people.iter().position(|(u, _)| u == uid).map_or_else(
            || Label {
                name: uid.to_string(),
                uid: None,
            },
            |i| shown[i].clone(),
        )
    };
    let name = match &other {
        Some(o) => label(o),
        None => Label {
            name: row.name.to_string(),
            uid: None,
        },
    };
    let last = row.last.as_ref().map(|p| ChatPreview {
        from: label(&p.from),
        own: p.own,
        text: unescape(&p.text).into_owned(),
        deleted: p.deleted,
        time_ms: p.t,
        delivery: match &p.outbox {
            None | Some(OutboxState::Sent(_)) => Delivery::Sent,
            Some(OutboxState::Queued | OutboxState::Sending) => Delivery::Sending,
            Some(OutboxState::Failed(why)) => Delivery::Failed {
                maybe_sent: *why == FailReason::Unconfirmed,
            },
        },
    });
    ChatSummary {
        id: format!("c{}", row.id.get()),
        account: AccountRef {
            server: row.server.to_string(),
            uid: row.uid.to_string(),
        },
        conversation: row.name.to_string(),
        kind: if other.is_some() {
            ChatKind::Direct
        } else {
            ChatKind::Room
        },
        name,
        topic: row
            .topic
            .as_deref()
            .map(|t| unescape(t).into_owned())
            .unwrap_or_default(),
        guest: other.as_ref().is_some_and(Uid::is_guest),
        home_server: home_server(&row.server, &row.uid),
        server: row.server.to_string(),
        activity_ms: row.activity,
        last,
        unread: row.unread,
        favourite: row.favourite,
        joined: row.joined,
    }
}

/// One row of the window.
#[derive(Debug, Clone)]
struct Entry {
    key: ChatKey,
    account: AccountId,
    item: ChatSummary,
}

/// The chat list's window and counts, kept in step with the cache by the
/// changes it is given. It does no I/O but reads of the cache, so the
/// sync simulator drives it as [`ChatList`] does.
pub(crate) struct ChatState {
    store: Store,
    query: ChatQuery,
    /// How many rows the window holds at most.
    limit: usize,
    /// The window, in order, by the keys it was read with.
    rows: Vec<Entry>,
    /// Whether rows the query shows may come after the window. Otherwise
    /// the window holds every one.
    more: bool,
    /// Every conversation the query shows, not counting its `unread`
    /// toggle, with whether it has unread messages: for the counts.
    base: HashMap<ConvId, bool>,
}

impl ChatState {
    /// The first `limit` rows `query` shows.
    pub(crate) fn new(
        store: Store,
        query: ChatQuery,
        limit: usize,
    ) -> Result<ChatState, StoreError> {
        let mut state = ChatState {
            store,
            query,
            limit,
            rows: Vec::new(),
            more: false,
            base: HashMap::new(),
        };
        state.load()?;
        Ok(state)
    }

    fn load(&mut self) -> Result<(), StoreError> {
        let rows = self.store.chat_rows(&self.query, None, self.limit)?;
        self.more = rows.len() >= self.limit;
        self.rows = rows.into_iter().map(entry).collect();
        self.base = self.store.chat_unread(&self.query)?.into_iter().collect();
        Ok(())
    }

    pub(crate) fn items(&self) -> Vec<ChatSummary> {
        self.rows.iter().map(|e| e.item.clone()).collect()
    }

    /// How many rows the window holds at most.
    #[cfg(test)]
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// What it shows.
    #[cfg(test)]
    pub(crate) fn query(&self) -> &ChatQuery {
        &self.query
    }

    pub(crate) fn counts(&self) -> ChatCounts {
        let unread = self.base.values().filter(|u| **u).count() as u64;
        ChatCounts {
            unread_chats: unread,
            total: if self.query.unread {
                unread
            } else {
                self.base.len() as u64
            },
        }
    }

    /// Reads the window again, with the same size.
    pub(crate) fn reload(&mut self) -> Result<Vec<ChatListDiff>, StoreError> {
        self.load()?;
        Ok(vec![ChatListDiff::Reset {
            items: self.items(),
        }])
    }

    /// Shows what `query` shows instead.
    pub(crate) fn set_query(&mut self, query: ChatQuery) -> Result<Vec<ChatListDiff>, StoreError> {
        self.query = query;
        self.reload()
    }

    /// Widens the window by `count` rows.
    pub(crate) fn widen(&mut self, count: usize) -> Result<Vec<ChatListDiff>, StoreError> {
        self.limit = self.limit.saturating_add(count);
        let mut diffs = Vec::new();
        self.fill(&mut diffs)?;
        Ok(diffs)
    }

    /// Applies the cache's changes, which the store made in this order.
    /// Rows are read as the cache has them now, which may be after later
    /// changes; those are applied again when they come, and change nothing.
    pub(crate) fn apply(&mut self, changes: &[Change]) -> Result<Vec<ChatListDiff>, StoreError> {
        let mut touched = BTreeSet::new();
        for change in changes {
            match change {
                Change::Inserted { conv, .. }
                | Change::Updated { conv, .. }
                | Change::Cleared { conv }
                | Change::Conversation { conv }
                | Change::ConversationRemoved { conv, .. } => {
                    touched.insert(*conv);
                }
                Change::Outbox { id } => {
                    // A removed entry also changes its conversation, which
                    // the store reports.
                    if let Some(conv) = self.store.outbox_conversation(*id)? {
                        touched.insert(conv);
                    }
                }
                // Names show only in the rows' labels.
                Change::User { account, .. } => {
                    touched.extend(
                        self.rows
                            .iter()
                            .filter(|e| e.account == *account)
                            .map(|e| e.key.1),
                    );
                }
                // Previews and unread counts may change in every one of the
                // account's conversations.
                Change::Blocks { account } => {
                    touched.extend(self.store.conversation_ids(*account)?);
                    touched.extend(
                        self.rows
                            .iter()
                            .filter(|e| e.account == *account)
                            .map(|e| e.key.1),
                    );
                }
                Change::Members { .. } => {}
            }
        }
        let mut diffs = Vec::new();
        for conv in touched {
            let row = self.store.chat_row(conv)?;
            self.update(conv, row, &mut diffs);
        }
        self.fill(&mut diffs)?;
        Ok(diffs)
    }

    /// Puts conversation `conv` where it now belongs: `row` as the cache
    /// has it, or `None` if it is gone.
    fn update(&mut self, conv: ConvId, row: Option<ChatRow>, diffs: &mut Vec<ChatListDiff>) {
        match &row {
            Some(r) if r.matches_base(&self.query) => {
                self.base.insert(conv, r.unread > 0);
            }
            _ => {
                self.base.remove(&conv);
            }
        }
        let shown = row.filter(|r| r.matches(&self.query));
        match (self.rows.iter().position(|e| e.key.1 == conv), shown) {
            (Some(p), Some(r)) if r.key() == self.rows[p].key => {
                let item = summary(r);
                if item != self.rows[p].item {
                    self.rows[p].item = item.clone();
                    diffs.push(ChatListDiff::Update {
                        index: p as u32,
                        item,
                    });
                }
            }
            (Some(p), shown) => {
                self.rows.remove(p);
                diffs.push(ChatListDiff::Remove { index: p as u32 });
                if let Some(r) = shown {
                    self.insert(r, diffs);
                }
            }
            (None, Some(r)) => self.insert(r, diffs),
            (None, None) => {}
        }
    }

    /// Inserts a row where it sorts, if that is in the window. The row
    /// pushed past the end, if any, goes.
    fn insert(&mut self, row: ChatRow, diffs: &mut Vec<ChatListDiff>) {
        let key = row.key();
        let at = self
            .rows
            .partition_point(|e| key_order(&e.key, &key) == std::cmp::Ordering::Less);
        // Past the end, where rows not read yet may come first: filling
        // reads it if it belongs.
        if self.more && at == self.rows.len() {
            return;
        }
        let e = entry(row);
        diffs.push(ChatListDiff::Insert {
            index: at as u32,
            item: e.item.clone(),
        });
        self.rows.insert(at, e);
        if self.rows.len() > self.limit {
            self.rows.pop();
            diffs.push(ChatListDiff::Remove {
                index: self.limit as u32,
            });
            self.more = true;
        }
    }

    /// Fills the window up to its size from the rows after it.
    fn fill(&mut self, diffs: &mut Vec<ChatListDiff>) -> Result<(), StoreError> {
        let mut after = self.rows.last().map(|e| e.key);
        while self.more && self.rows.len() < self.limit {
            let want = self.limit - self.rows.len();
            let rows = self.store.chat_rows(&self.query, after, want)?;
            if rows.len() < want {
                self.more = false;
            }
            if rows.is_empty() {
                break;
            }
            for row in rows {
                after = Some(row.key());
                // In the window by an older key: its change will move it.
                if self.rows.iter().any(|e| e.key.1 == row.id) {
                    continue;
                }
                let e = entry(row);
                diffs.push(ChatListDiff::Insert {
                    index: self.rows.len() as u32,
                    item: e.item.clone(),
                });
                self.rows.push(e);
            }
        }
        Ok(())
    }
}

fn entry(row: ChatRow) -> Entry {
    Entry {
        key: row.key(),
        account: row.account,
        item: summary(row),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_is_the_server_named_by_the_identitys_domain() {
        let home =
            |server: &str, uid: &str| home_server(&server.parse().unwrap(), &uid.parse().unwrap());
        assert!(home("chat.example.org", "~sam"));
        assert!(home("example.org", "alice@example.org"));
        assert!(home("chat.example.org:7000", "alice@example.org"));
        assert!(home("CHAT.Example.org", "alice@example.org"));
        assert!(!home("chat.example.net", "alice@example.org"));
        assert!(!home("badexample.org", "alice@example.org"));
        assert!(!home("192.0.2.1", "alice@example.org"));
    }
}

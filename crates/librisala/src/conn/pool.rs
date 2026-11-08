//! The connections a device keeps to one server for one account (4.1):
//! one signed-in connection for what belongs to the account, and
//! anonymous connections for its conversations, or one guest connection
//! for a guest.
//!
//! [`ServerConnections`] runs a [`Supervisor`] for each, and merges their
//! events into one queue, each tagged with its [`Slot`]. Events of one
//! slot keep their order; events of different slots interleave as they
//! happen.
//!
//! [`MailboxSlots`] decides which anonymous or guest connection follows
//! which mailbox (7.1): a mailbox stays on one connection until it is
//! released, and new ones go to the connection that follows fewest.
//!
//! Section 14 says what this does not hide: the server can link an
//! anonymous connection to a signed-in one from the same address, or
//! opened at the same time. The connections share nothing else: each has
//! its own TLS session, with no resumption ([`super::tls`]).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use risala_proto::names::BoxName;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::session::SessionOptions;
use super::supervisor::{Anonymous, Backoff, Establish, Supervisor, SupervisorEvent};
use crate::addr::{ServerAddr, TrustStore};

/// Which of an account's connections an event is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Slot {
    /// The signed-in connection (4.6).
    SignedIn,
    /// The `n`th anonymous connection (4.2), from 0.
    Anonymous(usize),
    /// The anonymous connection kept apart for WATCH and its PRESENCE
    /// lines (4.1, 8.3), since whom a device watches says whom it talks
    /// to.
    Watch,
    /// The guest connection (4.2).
    Guest,
}

/// An event of one of the connections.
#[derive(Debug)]
pub struct PoolEvent {
    /// The connection.
    pub slot: Slot,
    /// What happened.
    pub event: SupervisorEvent,
}

/// Which connections to keep (4.1).
#[derive(Clone)]
pub struct ConnectionPlan {
    /// The signed-in connection's sign-in, for an identity:
    /// [`IdentitySignIn`](super::IdentitySignIn).
    pub signed_in: Option<Arc<dyn Establish>>,
    /// How many anonymous connections to keep. A device keeps at least
    /// one while it is online (4.1).
    pub anonymous: usize,
    /// Whether to keep a separate anonymous connection for WATCH (4.1,
    /// 8.3).
    pub watch: bool,
    /// The guest connection's sign-in, for a guest:
    /// [`GuestSignIn`](super::GuestSignIn). A guest posts, follows and
    /// fetches on it, and has no other connection.
    pub guest: Option<Arc<dyn Establish>>,
}

impl ConnectionPlan {
    /// An identity's connections: signed in with `sign_in`, and
    /// `anonymous` anonymous connections (at least one).
    pub fn identity(sign_in: Arc<dyn Establish>, anonymous: usize) -> ConnectionPlan {
        ConnectionPlan {
            signed_in: Some(sign_in),
            anonymous: anonymous.max(1),
            watch: false,
            guest: None,
        }
    }

    /// A guest's one connection.
    pub fn guest(sign_in: Arc<dyn Establish>) -> ConnectionPlan {
        ConnectionPlan {
            signed_in: None,
            anonymous: 0,
            watch: false,
            guest: Some(sign_in),
        }
    }

    /// The slots of the plan, in order: signed in, the anonymous ones,
    /// the one for WATCH, then the guest.
    pub fn slots(&self) -> Vec<Slot> {
        let mut slots = Vec::new();
        if self.signed_in.is_some() {
            slots.push(Slot::SignedIn);
        }
        slots.extend((0..self.anonymous).map(Slot::Anonymous));
        if self.watch {
            slots.push(Slot::Watch);
        }
        if self.guest.is_some() {
            slots.push(Slot::Guest);
        }
        slots
    }

    fn establish(&self, slot: Slot) -> Arc<dyn Establish> {
        match slot {
            Slot::SignedIn => self.signed_in.clone().expect("a signed-in slot"),
            Slot::Anonymous(_) | Slot::Watch => Arc::new(Anonymous),
            Slot::Guest => self.guest.clone().expect("a guest slot"),
        }
    }
}

impl std::fmt::Debug for ConnectionPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPlan")
            .field("slots", &self.slots())
            .finish()
    }
}

/// The connections of one account to one server: one [`Supervisor`] per
/// [`Slot`], with their events merged into one queue.
#[derive(Debug)]
pub struct ServerConnections {
    supervisors: Vec<(Slot, Supervisor)>,
    forwarders: Vec<JoinHandle<()>>,
}

impl ServerConnections {
    /// Starts keeping the plan's connections to `addr` up. Each has its
    /// own [`Supervisor`] and backoff.
    ///
    /// If `options` has no CA verifier, the platform's is loaded once
    /// here and shared by every connection.
    pub async fn spawn(
        addr: ServerAddr,
        trust: Arc<dyn TrustStore>,
        mut options: SessionOptions,
        plan: &ConnectionPlan,
        backoff: Backoff,
    ) -> (ServerConnections, mpsc::Receiver<PoolEvent>) {
        if options.ca_verifier.is_none() {
            options.ca_verifier = Some(super::tls::platform_ca_verifier_blocking().await);
        }
        let (tx, rx) = mpsc::channel(64);
        let mut supervisors = Vec::new();
        let mut forwarders = Vec::new();
        for slot in plan.slots() {
            let (supervisor, mut events) = Supervisor::spawn(
                addr.clone(),
                trust.clone(),
                options.clone(),
                plan.establish(slot),
                backoff,
            );
            let tx = tx.clone();
            forwarders.push(tokio::spawn(async move {
                while let Some(event) = events.recv().await {
                    if tx.send(PoolEvent { slot, event }).await.is_err() {
                        break;
                    }
                }
            }));
            supervisors.push((slot, supervisor));
        }
        (
            ServerConnections {
                supervisors,
                forwarders,
            },
            rx,
        )
    }

    /// The slots running.
    pub fn slots(&self) -> Vec<Slot> {
        self.supervisors.iter().map(|(slot, _)| *slot).collect()
    }

    /// Skips every wait and tries again now, for example when the network
    /// comes back. See [`Supervisor::reconnect_now`].
    pub fn reconnect_now(&self) {
        for (_, s) in &self.supervisors {
            s.reconnect_now();
        }
    }

    /// Stops connecting again, but leaves open connections open. See
    /// [`Supervisor::hold`].
    pub fn hold(&self) {
        for (_, s) in &self.supervisors {
            s.hold();
        }
    }

    /// Closes every connection and stops. The queue ends once each
    /// supervisor has reported [`SupervisorEvent::Stopped`].
    pub async fn stop(self) {
        for (_, s) in self.supervisors {
            s.stop().await;
        }
        for f in self.forwarders {
            let _ = f.await;
        }
    }
}

/// Which connection follows which mailbox (7.1).
///
/// A server must let one connection follow at least 1,000 mailboxes
/// (7.1); past `per_connection` on every connection, [`assign`] has no
/// room, and the caller opens another connection with
/// [`add_connection`](Self::add_connection).
///
/// [`assign`]: Self::assign
#[derive(Debug, Clone)]
pub struct MailboxSlots {
    per_connection: usize,
    connections: Vec<BTreeSet<BoxName>>,
    by_box: HashMap<BoxName, usize>,
}

impl MailboxSlots {
    /// What a server must allow at least (7.1).
    pub const MIN_SERVER_LIMIT: usize = 1000;

    /// Slots for `connections` connections, each following at most
    /// `per_connection` mailboxes (at least 1).
    pub fn new(connections: usize, per_connection: usize) -> MailboxSlots {
        MailboxSlots {
            per_connection: per_connection.max(1),
            connections: vec![BTreeSet::new(); connections],
            by_box: HashMap::new(),
        }
    }

    /// The connection that follows `mailbox`, assigning it to the one that
    /// follows fewest (the first of those) if it has none. `None` if
    /// every connection is full.
    pub fn assign(&mut self, mailbox: &BoxName) -> Option<usize> {
        if let Some(&n) = self.by_box.get(mailbox) {
            return Some(n);
        }
        let (n, boxes) = self
            .connections
            .iter_mut()
            .enumerate()
            .filter(|(_, b)| b.len() < self.per_connection)
            .min_by_key(|(_, b)| b.len())?;
        boxes.insert(*mailbox);
        self.by_box.insert(*mailbox, n);
        Some(n)
    }

    /// The connection that follows `mailbox`, if any.
    pub fn connection_of(&self, mailbox: &BoxName) -> Option<usize> {
        self.by_box.get(mailbox).copied()
    }

    /// The mailboxes connection `n` follows, sorted.
    pub fn mailboxes(&self, n: usize) -> impl Iterator<Item = &BoxName> {
        self.connections.get(n).into_iter().flatten()
    }

    /// The mailboxes connection `n` follows, in a new random order: the
    /// order to send FOLLOW in after each reconnect, so that it does not
    /// link one session to the next (7.4).
    pub fn follow_order(&self, n: usize) -> Vec<BoxName> {
        let mut boxes: Vec<BoxName> = self.mailboxes(n).copied().collect();
        // Fisher-Yates. If the system's random source fails, the sorted
        // order is kept: it is the same for every device.
        for i in (1..boxes.len()).rev() {
            let Ok(r) = getrandom::u64() else {
                break;
            };
            let j = usize::try_from(r % (i as u64 + 1)).unwrap_or(0);
            boxes.swap(i, j);
        }
        boxes
    }

    /// Stops following `mailbox`. Returns the connection that followed
    /// it.
    pub fn release(&mut self, mailbox: &BoxName) -> Option<usize> {
        let n = self.by_box.remove(mailbox)?;
        self.connections[n].remove(mailbox);
        Some(n)
    }

    /// Adds a connection, and returns its number.
    pub fn add_connection(&mut self) -> usize {
        self.connections.push(BTreeSet::new());
        self.connections.len() - 1
    }

    /// How many connections there are.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether there are no connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(n: u8) -> BoxName {
        BoxName::from_bytes([n; 16])
    }

    #[test]
    fn plans() {
        let sign_in: Arc<dyn Establish> = Arc::new(Anonymous);
        assert_eq!(
            ConnectionPlan::identity(sign_in.clone(), 2).slots(),
            [Slot::SignedIn, Slot::Anonymous(0), Slot::Anonymous(1)]
        );
        // At least one anonymous connection (4.1).
        assert_eq!(
            ConnectionPlan::identity(sign_in.clone(), 0).slots(),
            [Slot::SignedIn, Slot::Anonymous(0)]
        );
        let mut watching = ConnectionPlan::identity(sign_in.clone(), 1);
        watching.watch = true;
        assert_eq!(
            watching.slots(),
            [Slot::SignedIn, Slot::Anonymous(0), Slot::Watch]
        );
        assert_eq!(ConnectionPlan::guest(sign_in).slots(), [Slot::Guest]);
    }

    #[test]
    fn mailboxes_spread_and_stay() {
        let mut slots = MailboxSlots::new(2, 2);
        assert_eq!(slots.assign(&mailbox(1)), Some(0));
        assert_eq!(slots.assign(&mailbox(2)), Some(1));
        assert_eq!(slots.assign(&mailbox(1)), Some(0));
        assert_eq!(slots.assign(&mailbox(3)), Some(0));
        assert_eq!(slots.assign(&mailbox(4)), Some(1));
        // Full.
        assert_eq!(slots.assign(&mailbox(5)), None);
        assert_eq!(slots.connection_of(&mailbox(5)), None);
        let n = slots.add_connection();
        assert_eq!(slots.assign(&mailbox(5)), Some(n));
        assert_eq!(slots.len(), 3);

        assert_eq!(
            slots.mailboxes(0).cloned().collect::<Vec<_>>(),
            [mailbox(1), mailbox(3)]
        );
        assert_eq!(slots.release(&mailbox(1)), Some(0));
        assert_eq!(slots.release(&mailbox(1)), None);
        assert_eq!(slots.assign(&mailbox(6)), Some(0));
        assert_eq!(slots.mailboxes(9).count(), 0);
    }

    #[test]
    fn follow_order_is_random() {
        let mut slots = MailboxSlots::new(1, 100);
        for n in 0..32 {
            slots.assign(&mailbox(n));
        }
        let sorted: Vec<BoxName> = slots.mailboxes(0).copied().collect();
        let orders: Vec<Vec<BoxName>> = (0..4).map(|_| slots.follow_order(0)).collect();
        for order in &orders {
            let mut again = order.clone();
            again.sort();
            assert_eq!(again, sorted);
        }
        // Four shuffles of 32 all sorted: about 1 in 10^140.
        assert!(orders.iter().any(|o| *o != sorted));
    }
}

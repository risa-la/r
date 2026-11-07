//! The interface between the network layer ([`crate::net`]) and the core
//! ([`crate::core`]).
//!
//! The network layer accepts TCP, runs TLS, splits the byte stream into
//! lines and parses them. Each line that parses as a
//! [`Request`] goes to the [`Handler`], one at a time and in arrival order
//! (3.6). Lines that do not parse never reach the handler: the network
//! layer answers them with `ERR` itself (2.3), using
//! [`ParseError::code`](risala_proto::error::ParseError::code).
//!
//! Everything the server sends to a connection goes through its
//! [`ConnHandle`]: the greeting, responses, live events and closing. One
//! queue per connection keeps the order the spec needs: the events a
//! command causes reach its sender before the command's final response
//! (3.6).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use risala_proto::command::Request;
use risala_proto::server::ServerMessage;
use risala_proto::time::Timestamp;
use tokio::sync::{Notify, mpsc};

/// Identifies one connection for as long as the server runs. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// What the network layer knows about a connection when it opens.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// The client's address and port, for ADMIN WHO (10.3) and address bans
    /// (10.2).
    pub peer: SocketAddr,
    /// The SNI hostname the client sent, in lower case, or `None` if it sent
    /// none (2.1, 4.1).
    pub sni: Option<String>,
    /// When the TLS handshake finished.
    pub since: Timestamp,
}

/// One item in a connection's outgoing queue.
#[derive(Debug, Clone)]
pub enum Outgoing {
    /// A line to send.
    Line(Box<ServerMessage>),
    /// Send everything queued before this, then close the connection.
    /// With `bye: Some(text)`, a `BYE` line with that text is sent first
    /// (11). After QUIT's `OK`, the core uses `bye: None`.
    Close {
        /// The text of the `BYE` line, if one is sent.
        bye: Option<String>,
    },
}

/// The sending half of a connection, held by the core.
///
/// The queue is bounded. A client that reads too slowly fills it, and then
/// the connection is killed at once rather than letting the server's memory
/// grow (PLAN.md 3.2). Sending never blocks, so one slow client cannot hold
/// up fan-out to everyone else.
#[derive(Debug, Clone)]
pub struct ConnHandle {
    id: ConnId,
    tx: mpsc::Sender<Outgoing>,
    killed: Arc<Killed>,
}

#[derive(Debug, Default)]
struct Killed {
    flag: AtomicBool,
    notify: Notify,
}

/// The receiving half of a connection, held by the network layer.
#[derive(Debug)]
pub struct ConnReceiver {
    /// Items to write, in order.
    pub rx: mpsc::Receiver<Outgoing>,
    killed: Arc<Killed>,
}

/// Makes the two halves of a connection's queue, holding at most `capacity`
/// items.
pub fn conn_channel(id: ConnId, capacity: usize) -> (ConnHandle, ConnReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    let killed = Arc::new(Killed::default());
    (
        ConnHandle {
            id,
            tx,
            killed: killed.clone(),
        },
        ConnReceiver { rx, killed },
    )
}

impl ConnHandle {
    /// This connection's id.
    pub fn id(&self) -> ConnId {
        self.id
    }

    /// Queues a line. Returns `false`, and kills the connection, if the
    /// queue is full. Returns `false` if the connection is already gone.
    pub fn send(&self, msg: ServerMessage) -> bool {
        self.push(Outgoing::Line(Box::new(msg)))
    }

    /// Queues a close, optionally with a `BYE` line (11).
    pub fn close(&self, bye: Option<String>) {
        self.push(Outgoing::Close { bye });
    }

    /// Drops the connection straight away, without sending what is queued.
    pub fn kill(&self) {
        self.killed.flag.store(true, Ordering::SeqCst);
        self.killed.notify.notify_waiters();
        self.killed.notify.notify_one();
    }

    /// Whether the connection has been killed or its receiver dropped.
    pub fn is_closed(&self) -> bool {
        self.killed.flag.load(Ordering::SeqCst) || self.tx.is_closed()
    }

    fn push(&self, item: Outgoing) -> bool {
        if self.is_closed() {
            return false;
        }
        match self.tx.try_send(item) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.kill();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

impl ConnReceiver {
    /// Resolves once the connection has been killed. The network layer
    /// selects on this next to its reads and writes, and drops the
    /// connection when it fires.
    pub async fn killed(&self) {
        loop {
            let notified = self.killed.notify.notified();
            if self.killed.flag.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    /// Whether the connection has been killed.
    pub fn is_killed(&self) -> bool {
        self.killed.flag.load(Ordering::SeqCst)
    }
}

/// The core, as the network layer sees it.
///
/// The network layer calls [`open`](Handler::open) once the TLS handshake
/// is done, then [`command`](Handler::command) for each parsed line,
/// awaiting each call before it reads the next command, then
/// [`closed`](Handler::closed) exactly once when the connection is gone for
/// any reason (EOF, error, timeout, kill, or after a `Close`).
pub trait Handler: Send + Sync + 'static {
    /// A connection has opened. The handler sends the greeting (4.1)
    /// through `conn`, and keeps `conn` to send to it later.
    fn open(&self, info: ConnInfo, conn: ConnHandle);

    /// Handles one command from `conn`. Before it returns, it has queued
    /// the command's final response (`OK` or `ERR`), unless the command is
    /// PONG, which gets none (3.6).
    fn command(&self, conn: ConnId, req: Request) -> impl Future<Output = ()> + Send;

    /// The connection is gone. A guest's automatic PARTs happen here (4.2).
    fn closed(&self, conn: ConnId) -> impl Future<Output = ()> + Send;
}

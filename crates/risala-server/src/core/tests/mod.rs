//! Transcript tests of the hub, through the [`Handler`] trait, with no
//! sockets: each test opens connections with [`conn_channel`], sends
//! [`Request`]s and checks the lines queued for each connection.
//!
//! [`Harness`] is shared by every area's tests: `session` and `kinds` test
//! the core, and each area has its own file.

mod admin;
mod identity;
mod keylog;
mod keys;
mod kinds;
mod mailbox;
mod misc;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::PublicKey;
use risala_proto::command::Request;
use risala_proto::names::Uid;
use risala_proto::server::ServerMessage;
use risala_proto::time::Timestamp;

use super::state::{Device, Who};
use super::{Hub, Inner, ManualClock, Timers};
use crate::config::Config;
use crate::handler::{
    ConnHandle, ConnId, ConnInfo, ConnReceiver, Handler as _, Outgoing, conn_channel,
};
use crate::keyfiles::KeyServices;
use crate::store::SqliteStore;

/// The time the clock is stopped at: it does not move unless a test moves
/// it.
pub(super) const T: &str = "2026-11-09T12:00:00.000Z";

/// The configuration of most tests: `chat.example.org`, with a welcome
/// text, and `op@example.org` as an operator.
pub(super) fn config() -> Config {
    let mut c = Config::parse(
        r##"
        hostname = "chat.example.org"
        operators = ["op@example.org"]
        [server]
        welcome = "Welcome!"
        "##,
    )
    .unwrap();
    c.state_dir = std::env::temp_dir();
    c
}

/// The hub's timers in most tests: the configuration's.
pub(super) fn timers() -> Timers {
    Timers::from_config(&config())
}

/// A hub on an in-memory store, with a stopped clock.
pub(super) struct Harness {
    pub(super) hub: Hub,
    /// The store, for setting up rows that no command writes yet.
    pub(super) store: Arc<SqliteStore>,
    #[allow(dead_code, reason = "for the areas' tests of time and retention")]
    pub(super) clock: Arc<ManualClock>,
    next: u64,
}

/// One connection's end of its queue.
pub(super) struct Client {
    pub(super) id: ConnId,
    /// The hub's end, to see the kind the network layer is told (2.3).
    pub(super) handle: ConnHandle,
    pub(super) rx: ConnReceiver,
}

impl Harness {
    pub(super) fn new() -> Harness {
        Harness::with(config(), timers())
    }

    /// A hub on `config`, with `timers`.
    pub(super) fn with(config: Config, timers: Timers) -> Harness {
        Harness::on(config, timers, SqliteStore::open_in_memory().unwrap())
    }

    /// A hub on `store`.
    pub(super) fn on(config: Config, timers: Timers, store: SqliteStore) -> Harness {
        Harness::with_keys(config, timers, store, KeyServices::default())
    }

    /// A hub on `store`, fetching and publishing key files with `keys`
    /// (4.4, 4.7).
    pub(super) fn with_keys(
        config: Config,
        timers: Timers,
        store: SqliteStore,
        keys: KeyServices,
    ) -> Harness {
        let store = Arc::new(store);
        let clock = Arc::new(ManualClock::new(T.parse().unwrap()));
        let hub = Hub::build(config, store.clone(), clock.clone(), timers, keys).unwrap();
        Harness {
            hub,
            store,
            clock,
            next: 0,
        }
    }

    pub(super) fn inner(&self) -> &Arc<Inner> {
        &self.hub.inner
    }

    /// A new connection from `peer` with SNI `sni`, its greeting unread.
    pub(super) fn open(&mut self, peer: &str, sni: Option<&str>) -> Client {
        self.next += 1;
        let id = ConnId(self.next);
        let (handle, rx) = conn_channel(id, 4096, usize::MAX);
        self.hub.open(
            ConnInfo {
                peer: peer.parse::<SocketAddr>().unwrap(),
                sni: sni.map(str::to_owned),
                sni_certified: false,
                since: T.parse::<Timestamp>().unwrap(),
            },
            handle.clone(),
        );
        Client { id, handle, rx }
    }

    /// A new connection to `chat.example.org`, with its greeting read.
    pub(super) fn connect(&mut self) -> Client {
        self.connect_from("203.0.113.7:51000")
    }

    /// A new connection from `peer`, with its greeting read.
    pub(super) fn connect_from(&mut self, peer: &str) -> Client {
        let mut c = self.open(peer, Some("chat.example.org"));
        let greeting = c.lines();
        assert_eq!(greeting.len(), 1, "{greeting:?}");
        assert!(greeting[0].starts_with("RISALA 1 "), "{greeting:?}");
        c
    }

    /// A new anonymous connection (4.2).
    pub(super) async fn anon(&mut self) -> Client {
        let mut c = self.connect();
        self.send(&c, "anon").await;
        assert_eq!(c.lines(), ["OK"]);
        c
    }

    /// A new connection of the guest `~name` (4.2), and its session's
    /// token.
    pub(super) async fn guest(&mut self, name: &str) -> (Client, String) {
        let mut c = self.connect();
        self.send(&c, &format!("guest {name}")).await;
        let ok = c.raw_lines();
        assert_eq!(ok.len(), 1, "{ok:?}");
        let token = value(&ok[0], "token");
        assert_eq!(ok[0], format!("OK uid=~{name} token={token}"));
        (c, token)
    }

    /// A new connection, signed in as the identity `uid` with a made-up
    /// device key, without AUTH, for tests of what comes after signing in.
    pub(super) fn signed_in_as(&mut self, uid: &str) -> Client {
        let c = self.connect();
        let device = Device {
            uid: uid.parse().unwrap(),
            key: PublicKey::from_bytes(&[7; risala_proto::auth::PUBLIC_KEY_LEN]),
        };
        assert!(self.inner().reg().set_who(c.id, Who::SignedIn(device)));
        c
    }

    /// Sends one line from `c`, and waits until the hub has handled it.
    pub(super) async fn send(&self, c: &Client, line: &str) {
        let req: Request = line.parse().unwrap();
        self.hub.command(c.id, req).await;
    }

    /// The connection closes. A guest's session waits to be resumed.
    pub(super) async fn close(&self, c: Client) {
        drop(c.rx);
        self.hub.closed(c.id).await;
    }

    /// Ends the session of the guest `~name` at once (4.2).
    pub(super) async fn end(&self, name: &str) {
        let uid: Uid = format!("~{name}").parse().unwrap();
        assert!(
            self.hub.end_guest_session(&uid, "bye").await,
            "no session for {uid}"
        );
    }
}

impl Client {
    /// Everything queued so far, as lines, with any `token=` value shown
    /// as `<token>` and the greeting's nonce as `<nonce>`. A close is
    /// `<close>`, or `<close> BYE text`.
    pub(super) fn lines(&mut self) -> Vec<String> {
        self.raw_lines()
            .into_iter()
            .map(|line| {
                let line = hide(&line, " token=", "<token>");
                if line.starts_with("RISALA ") {
                    let mut words: Vec<&str> = line.splitn(5, ' ').collect();
                    if words.len() >= 4 {
                        words[3] = "<nonce>";
                    }
                    words.join(" ")
                } else {
                    line
                }
            })
            .collect()
    }

    /// Everything queued so far, as lines, as they are.
    pub(super) fn raw_lines(&mut self) -> Vec<String> {
        self.items()
            .into_iter()
            .map(|item| match item {
                Outgoing::Line(m) => m.to_line().to_string(),
                Outgoing::Close { bye: None } => "<close>".into(),
                Outgoing::Close { bye: Some(text) } => format!("<close> BYE {text}"),
            })
            .collect()
    }

    /// Everything queued so far, as messages; closes are left out.
    #[allow(dead_code, reason = "for the areas' tests of typed lines")]
    pub(super) fn messages(&mut self) -> Vec<ServerMessage> {
        self.items()
            .into_iter()
            .filter_map(|item| match item {
                Outgoing::Line(m) => Some(m.message().clone()),
                Outgoing::Close { .. } => None,
            })
            .collect()
    }

    fn items(&mut self) -> Vec<Outgoing> {
        std::iter::from_fn(|| self.rx.try_recv()).collect()
    }
}

/// `line` with the value after `key` (such as `" token="`) replaced by
/// `shown`, up to the next space.
fn hide(line: &str, key: &str, shown: &str) -> String {
    match line.find(key) {
        Some(at) => {
            let start = at + key.len();
            let end = line[start..].find(' ').map_or(line.len(), |e| start + e);
            format!("{}{shown}{}", &line[..start], &line[end..])
        }
        None => line.to_owned(),
    }
}

/// The value of `key=` in `line`.
pub(super) fn value(line: &str, key: &str) -> String {
    let at = line
        .find(&format!(" {key}="))
        .unwrap_or_else(|| panic!("no {key}= in {line:?}"));
    let rest = &line[at + key.len() + 2..];
    rest.split(' ').next().unwrap().to_owned()
}

/// Timers with a short resume period, for tests that watch guest sessions
/// end.
pub(super) fn short_resume() -> Timers {
    Timers {
        guest_resume: Duration::from_secs(5),
        ..timers()
    }
}

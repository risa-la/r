//! Transcript tests of the hub, through the [`Handler`] trait, with no
//! sockets: each test opens connections with [`conn_channel`], sends
//! [`Request`]s and checks the lines queued for each connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use risala_proto::command::Request;
use risala_proto::names::{Room, Uid};
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::{GuestAccess, RoomSetting};

use super::*;
use crate::config::Config;
use crate::handler::{ConnId, ConnInfo, ConnReceiver, Outgoing, conn_channel};
use crate::store::{
    Appended, ConvKey, EventKind, HistoryQuery, NewEvent, Page, RoomRecord, SqliteStore,
    StoredEvent,
};

/// The time on every event: the clock does not move unless a test moves
/// it.
const T: &str = "2026-11-06T15:40:58.120Z";

fn start() -> Timestamp {
    T.parse().unwrap()
}

fn config() -> Config {
    let mut c = Config::parse(
        r##"
        hostname = "chat.example.org"
        rooms = ["#general"]
        [server]
        welcome = "Welcome!"
        "##,
    )
    .unwrap();
    c.state_dir = std::env::temp_dir();
    c
}

/// A hub with an in-memory store and a stopped clock.
struct Harness {
    hub: Hub,
    store: Arc<dyn Store>,
    clock: Arc<ManualClock>,
    next: u64,
}

/// One connection's end of the queue.
struct Client {
    id: ConnId,
    rx: ConnReceiver,
}

impl Harness {
    fn new() -> Harness {
        Harness::with(config(), |_| {})
    }

    /// A hub on `config`, after `prepare` has had a go at the store.
    fn with(config: Config, prepare: impl FnOnce(&SqliteStore)) -> Harness {
        let store = SqliteStore::open_in_memory().unwrap();
        for room in &config.rooms {
            store.ensure_room(&room.parse().unwrap(), start()).unwrap();
        }
        prepare(&store);
        Harness::on(config, Arc::new(store), Duration::from_secs(120))
    }

    fn on(config: Config, store: Arc<dyn Store>, sign_in: Duration) -> Harness {
        let clock = Arc::new(ManualClock::new(start()));
        let hub = Hub::build(config, store.clone(), clock.clone(), sign_in).unwrap();
        Harness {
            hub,
            store,
            clock,
            next: 0,
        }
    }

    fn connect_sni(&mut self, sni: Option<&str>, capacity: usize) -> Client {
        self.next += 1;
        let id = ConnId(self.next);
        let (handle, rx) = conn_channel(id, capacity);
        self.hub.open(
            ConnInfo {
                peer: SocketAddr::from(([203, 0, 113, 7], 51000)),
                sni: sni.map(str::to_owned),
                since: start(),
            },
            handle,
        );
        Client { id, rx }
    }

    /// A new connection, with its greeting read.
    fn connect(&mut self) -> Client {
        let mut c = self.connect_sni(Some("chat.example.org"), 4096);
        let greeting = c.lines();
        assert_eq!(greeting.len(), 1);
        assert!(greeting[0].starts_with("RISALA 1 "), "{greeting:?}");
        c
    }

    /// A new connection, signed in as `~name`.
    async fn guest(&mut self, name: &str) -> Client {
        let mut c = self.connect();
        self.send(&c, &format!("guest {name}")).await;
        assert_eq!(c.lines(), [format!("OK uid=~{name}")]);
        c
    }

    /// A guest that has joined `room`. Returns the room's id.
    async fn joined(&mut self, name: &str, room: &str) -> (Client, String) {
        let mut c = self.guest(name).await;
        self.send(&c, &format!("join {room}")).await;
        let lines = c.lines();
        let id = value(lines.last().unwrap(), "id");
        (c, id)
    }

    async fn send(&self, c: &Client, line: &str) {
        let req: Request = line.parse().unwrap();
        self.hub.command(c.id, req).await;
    }

    async fn close(&self, c: Client) {
        drop(c.rx);
        self.hub.closed(c.id).await;
    }
}

impl Client {
    /// Everything queued so far, as lines. A close is `<close>`, or
    /// `<close> BYE text`.
    fn lines(&mut self) -> Vec<String> {
        self.items()
            .into_iter()
            .map(|item| match item {
                Outgoing::Line(m) => m.to_line().to_string(),
                Outgoing::Close { bye: None } => "<close>".into(),
                Outgoing::Close { bye: Some(text) } => format!("<close> BYE {text}"),
            })
            .collect()
    }

    fn messages(&mut self) -> Vec<ServerMessage> {
        self.items()
            .into_iter()
            .filter_map(|item| match item {
                Outgoing::Line(m) => Some(*m),
                Outgoing::Close { .. } => None,
            })
            .collect()
    }

    fn items(&mut self) -> Vec<Outgoing> {
        let mut out = Vec::new();
        while let Ok(item) = self.rx.rx.try_recv() {
            out.push(item);
        }
        out
    }
}

/// The value of `key=` in a line.
fn value(line: &str, key: &str) -> String {
    let start = line
        .find(&format!("{key}="))
        .unwrap_or_else(|| panic!("no {key} in {line:?}"))
        + key.len()
        + 1;
    line[start..].split([' ', ';']).next().unwrap().to_owned()
}

/// The snapshot after JOIN and INFO of a room with default settings.
fn default_settings(room: &str) -> Vec<String> {
    vec![
        format!("SET {room} topic"),
        format!("SET {room} public yes"),
        format!("SET {room} guests write"),
        format!("SET {room} retention server"),
    ]
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Appends an event straight to the store, as if it had happened earlier.
fn put(store: &SqliteStore, room: &str, from: &str, kind: EventKind) {
    let key = store.room(&room.parse().unwrap()).unwrap().unwrap().key;
    let event = NewEvent {
        t: start(),
        from: from.parse().unwrap(),
        kind,
        cid: None,
    };
    store.append(key, &event).unwrap();
}

fn set(store: &SqliteStore, room: &str, setting: RoomSetting) {
    put(store, room, "alice@example.org", EventKind::Set(setting));
}

// ---------------------------------------------------------------------------
// Greeting and sign-in (4.1, 4.2)

#[tokio::test]
async fn greeting_uses_sni_and_a_fresh_nonce() {
    let mut h = Harness::new();
    let mut a = h.connect_sni(Some("chat.example.net"), 16);
    let mut b = h.connect_sni(None, 16);
    let a = a.lines();
    let b = b.lines();
    assert_eq!(a.len(), 1);
    let parts: Vec<&str> = a[0].split(' ').collect();
    assert_eq!(parts[..3], ["RISALA", "1", "chat.example.net"]);
    assert_eq!(parts[4..], ["Welcome!"]);
    let nonce = parts[3];
    assert_eq!(nonce.len(), 2 * NONCE_BYTES);
    assert!(
        nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    // Without SNI, the server's own name. Every connection has its own
    // nonce.
    let parts_b: Vec<&str> = b[0].split(' ').collect();
    assert_eq!(parts_b[2], "chat.example.org");
    assert_ne!(parts_b[3], nonce);
}

#[tokio::test]
async fn greeting_without_welcome_text() {
    let mut c = config();
    c.server.welcome = String::new();
    let mut h = Harness::with(c, |_| {});
    let mut a = h.connect_sni(None, 16);
    let line = &a.lines()[0];
    assert_eq!(line.split(' ').count(), 4, "{line}");
}

#[tokio::test]
async fn only_some_commands_before_sign_in() {
    let mut h = Harness::new();
    let mut c = h.connect();
    for cmd in [
        "@ref=1 join #general",
        "@ref=1 list",
        "@ref=1 sync",
        "@ref=1 history #general",
        "@ref=1 msg #general hi",
        "@ref=1 info #general",
        "@ref=1 part #general",
        "@ref=1 typing #general",
    ] {
        h.send(&c, cmd).await;
        assert_eq!(
            c.lines(),
            ["@ref=1 ERR not-authenticated sign in first"],
            "{cmd}"
        );
    }
    h.send(&c, "@ref=2 ping").await;
    h.send(&c, "pong abc").await;
    h.send(&c, "@ref=3 info").await;
    assert_eq!(
        c.lines(),
        [
            "@ref=2 OK",
            "@ref=3 OK version=1 guests=yes register=no retention=forever push=no upload=no",
        ]
    );
}

#[tokio::test]
async fn guest_signs_in_once() {
    let mut h = Harness::new();
    let mut c = h.connect();
    h.send(&c, "@ref=a GUEST Sam").await;
    assert_eq!(c.lines(), ["@ref=a OK uid=~sam"]);
    for cmd in ["guest sam", "guest other"] {
        h.send(&c, cmd).await;
        assert_eq!(
            c.lines(),
            ["ERR already-authenticated already signed in"],
            "{cmd}"
        );
    }
}

#[tokio::test]
async fn guest_names_are_unique_while_connected() {
    let mut h = Harness::new();
    let a = h.guest("sam").await;
    let mut b = h.connect();
    h.send(&b, "guest SAM").await;
    assert_eq!(b.lines(), ["ERR name-taken a guest has that name"]);
    h.close(a).await;
    h.send(&b, "guest sam").await;
    assert_eq!(b.lines(), ["OK uid=~sam"]);
}

#[tokio::test]
async fn guests_can_be_turned_off() {
    let mut c = config();
    c.server.guests = false;
    let mut h = Harness::with(c, |_| {});
    let mut a = h.connect();
    h.send(&a, "info").await;
    h.send(&a, "guest sam").await;
    assert_eq!(
        a.lines(),
        [
            "OK version=1 guests=no register=no retention=forever push=no upload=no",
            "ERR forbidden guests are not allowed",
        ]
    );
}

#[tokio::test]
async fn auth_and_register_are_not_supported_yet() {
    let mut h = Harness::new();
    let mut c = h.connect();
    let key = "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY=";
    let sig = "A".repeat(86) + "==";
    h.send(&c, &format!("auth alice@example.org {sig}")).await;
    h.send(&c, &format!("register alice {key} {sig}")).await;
    assert_eq!(
        c.lines(),
        [
            "ERR not-supported not supported yet",
            "ERR not-supported not supported yet"
        ]
    );
    // Still not signed in.
    h.send(&c, "guest sam").await;
    assert_eq!(c.lines(), ["OK uid=~sam"]);
}

#[tokio::test]
async fn sign_in_timeout_closes_with_bye() {
    let store = SqliteStore::open_in_memory().unwrap();
    let mut h = Harness::on(config(), Arc::new(store), Duration::from_millis(50));
    let mut late = h.connect();
    let mut prompt = h.connect();
    h.send(&prompt, "guest sam").await;
    assert_eq!(prompt.lines(), ["OK uid=~sam"]);
    let item = tokio::time::timeout(Duration::from_secs(10), late.rx.rx.recv())
        .await
        .expect("the connection is closed in time")
        .unwrap();
    assert!(
        matches!(&item, Outgoing::Close { bye: Some(text) } if text == "sign-in timeout"),
        "{item:?}"
    );
    // Well past the timeout, the guest is still connected.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(prompt.lines(), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// Keepalive and closing (11)

#[tokio::test]
async fn ping_pong_and_quit() {
    let mut h = Harness::new();
    let mut c = h.guest("sam").await;
    h.send(&c, "@ref=p ping hello").await;
    h.send(&c, "pong hello").await;
    h.send(&c, "@ref=q quit bye all").await;
    assert_eq!(c.lines(), ["@ref=p OK", "@ref=q OK", "<close>"]);
}

#[tokio::test]
async fn later_commands_are_not_supported() {
    let mut h = Harness::new();
    let mut c = h.guest("sam").await;
    for cmd in [
        "typing #general",
        "name Sam",
        "members #general",
        "whois ~bob",
        "roles #general",
        "delete #general 1",
        "report #general 1 spam",
        "related #general 1 2",
        "@edit=1 msg #general fixed",
        "@react=1 msg #general 👍",
        "@file=https://files.example.org/f/x/a.png msg #general look",
    ] {
        h.send(&c, cmd).await;
        assert_eq!(c.lines(), ["ERR not-supported not supported yet"], "{cmd}");
    }
    // What guests may never do is forbidden, whatever the milestone.
    for cmd in [
        "set #general topic hi",
        "read #general 1",
        "blocks",
        "push list",
        "admin ops",
        "msg bob@example.net hi",
        "kick #general ~bob",
    ] {
        h.send(&c, cmd).await;
        assert_eq!(c.lines(), ["ERR forbidden not for guests"], "{cmd}");
    }
}

// ---------------------------------------------------------------------------
// Rooms (6.1)

#[tokio::test]
async fn join_sends_the_event_settings_and_ok() {
    let mut h = Harness::new();
    let mut sam = h.guest("sam").await;
    h.send(&sam, "@ref=j join #General").await;
    let lines = sam.lines();
    let id = value(&lines[0], "id");
    assert_eq!(id.len(), crate::store::ID_LEN);
    let mut want = vec![format!("@seq=1;t={T};from=~sam;id={id} JOIN #general")];
    want.extend(
        default_settings("#general")
            .iter()
            .map(|l| format!("@ref=j {l}")),
    );
    want.push(format!("@ref=j OK id={id} head=1"));
    assert_eq!(lines, want);

    // A second member: both see the JOIN.
    let mut bob = h.guest("bob").await;
    h.send(&bob, "join #general").await;
    let mut want = vec![format!("@seq=2;t={T};from=~bob;id={id} JOIN #general")];
    want.extend(default_settings("#general"));
    want.push(format!("OK id={id} head=2"));
    assert_eq!(bob.lines(), want);
    assert_eq!(
        sam.lines(),
        [format!("@seq=2;t={T};from=~bob;id={id} JOIN #general")]
    );

    // Joining again: the settings and the OK, with no event.
    h.send(&bob, "join #general").await;
    let mut want = default_settings("#general");
    want.push(format!("OK id={id} head=2"));
    assert_eq!(bob.lines(), want);
    assert_eq!(sam.lines(), Vec::<String>::new());
}

#[tokio::test]
async fn join_shows_current_settings() {
    let mut h = Harness::with(config(), |s| {
        set(
            s,
            "#general",
            RoomSetting::Topic("General chat. Be kind.".into()),
        );
        set(s, "#general", RoomSetting::Guests(GuestAccess::Read));
    });
    let mut sam = h.guest("sam").await;
    h.send(&sam, "join #general").await;
    let lines = sam.lines();
    let id = value(&lines[0], "id");
    assert_eq!(
        lines,
        [
            format!("@seq=3;t={T};from=~sam;id={id} JOIN #general"),
            "SET #general topic General chat. Be kind.".into(),
            "SET #general public yes".into(),
            "SET #general guests read".into(),
            "SET #general retention server".into(),
            format!("OK id={id} head=3"),
        ]
    );
}

#[tokio::test]
async fn guests_cannot_join_everywhere() {
    let mut c = config();
    c.rooms = strings(&["#general", "#private", "#members", "#readonly"]);
    let mut h = Harness::with(c, |s| {
        set(s, "#private", RoomSetting::Public(false));
        set(s, "#members", RoomSetting::Guests(GuestAccess::None));
        set(s, "#readonly", RoomSetting::Guests(GuestAccess::Read));
    });
    let mut sam = h.guest("sam").await;
    // Private rooms stay hidden; a visible room closed to guests says so.
    for room in ["#private", "#nowhere"] {
        h.send(&sam, &format!("join {room}")).await;
        assert_eq!(sam.lines(), ["ERR not-found no such room"], "{room}");
    }
    h.send(&sam, "join #members").await;
    assert_eq!(
        sam.lines(),
        ["ERR forbidden guests may not enter this room"]
    );
    h.send(&sam, "join #readonly").await;
    let lines = sam.lines();
    assert_eq!(
        lines.last().unwrap(),
        &format!("OK id={} head=2", value(&lines[0], "id"))
    );
    h.send(&sam, "msg #readonly hello?").await;
    assert_eq!(sam.lines(), ["ERR forbidden guests may not send here"]);
}

#[tokio::test]
async fn part_reaches_everyone_then_stops_events() {
    let mut h = Harness::new();
    let (mut sam, id) = h.joined("sam", "#general").await;
    let (mut bob, _) = h.joined("bob", "#general").await;
    sam.lines();
    h.send(&bob, "@ref=x part #general see you later").await;
    let part = format!("@seq=3;t={T};from=~bob PART #general see you later");
    assert_eq!(bob.lines(), [part.clone(), "@ref=x OK".into()]);
    assert_eq!(sam.lines(), [part]);
    h.send(&sam, "msg #general anyone?").await;
    assert_eq!(
        sam.lines(),
        [
            format!("@seq=4;t={T};from=~sam MSG #general anyone?"),
            "OK seq=4".into()
        ]
    );
    assert_eq!(bob.lines(), Vec::<String>::new());
    // Not a member any more.
    h.send(&bob, "part #general").await;
    h.send(&bob, "part #nowhere").await;
    assert_eq!(
        bob.lines(),
        ["ERR not-found not a member", "ERR not-found no such room"]
    );
    // Joining again gets the same room.
    h.send(&bob, "join #general").await;
    assert_eq!(bob.lines().last().unwrap(), &format!("OK id={id} head=5"));
}

#[tokio::test]
async fn a_closing_guest_leaves_its_rooms() {
    let mut c = config();
    c.rooms = strings(&["#general", "#other"]);
    let mut h = Harness::with(c, |_| {});
    let (mut sam, _) = h.joined("sam", "#general").await;
    let (bob, _) = h.joined("bob", "#general").await;
    h.send(&bob, "join #other").await;
    let (mut carol, _) = h.joined("carol", "#other").await;
    sam.lines();
    carol.lines();
    h.close(bob).await;
    assert_eq!(
        sam.lines(),
        [format!("@seq=3;t={T};from=~bob PART #general")]
    );
    assert_eq!(
        carol.lines(),
        [format!("@seq=3;t={T};from=~bob PART #other")]
    );
    h.send(&sam, "info #general").await;
    assert!(sam.lines().last().unwrap().contains(" members=1 "));
    // The PART is stored.
    h.send(&sam, "history #general limit=1").await;
    let lines = sam.lines();
    assert_eq!(lines[0], format!("@seq=3;t={T};from=~bob PART #general"));
    // Closing twice, or closing an unknown connection, does nothing.
    h.hub.closed(ConnId(999)).await;
}

#[tokio::test]
async fn closing_before_sign_in_records_nothing() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let anon = h.connect();
    h.close(anon).await;
    assert_eq!(sam.lines(), Vec::<String>::new());
}

#[tokio::test]
async fn list_shows_public_rooms_in_order() {
    let mut c = config();
    c.rooms = strings(&[
        "#b",
        "#a",
        "#c-hidden",
        "#c-no-guests",
        "#d",
        "#a.b",
        "#a-b",
        "#general",
    ]);
    c.limits.max_list = 3;
    let mut h = Harness::with(c, |s| {
        set(s, "#c-hidden", RoomSetting::Public(false));
        // Guests do not see rooms they may not enter.
        set(s, "#c-no-guests", RoomSetting::Guests(GuestAccess::None));
        set(s, "#d", RoomSetting::Topic("the d room".into()));
    });
    let mut sam = h.guest("sam").await;
    h.send(&sam, "join #d").await;
    sam.lines();
    h.send(&sam, "@ref=l list").await;
    assert_eq!(
        sam.lines(),
        [
            "@ref=l ROOM #a 0",
            "@ref=l ROOM #a-b 0",
            "@ref=l ROOM #a.b 0",
            "@ref=l OK more=1",
        ]
    );
    h.send(&sam, "list after=#a.b limit=500").await;
    assert_eq!(
        sam.lines(),
        [
            "ROOM #b 0",
            "ROOM #d 1 the d room",
            "ROOM #general 0",
            "OK more=0"
        ]
    );
    h.send(&sam, "list after=#b limit=2").await;
    assert_eq!(
        sam.lines(),
        ["ROOM #d 1 the d room", "ROOM #general 0", "OK more=0"]
    );
    h.send(&sam, "list after=#d limit=1").await;
    assert_eq!(sam.lines(), ["ROOM #general 0", "OK more=0"]);
    h.send(&sam, "list after=#zzz").await;
    assert_eq!(sam.lines(), ["OK more=0"]);
    h.send(&sam, "list after=#b limit=1").await;
    assert_eq!(sam.lines(), ["ROOM #d 1 the d room", "OK more=1"]);
}

#[tokio::test]
async fn list_defaults_to_100_rooms() {
    let mut c = config();
    c.rooms = (0..105).map(|i| format!("#r{i:03}")).collect();
    let mut h = Harness::with(c, |_| {});
    let mut sam = h.guest("sam").await;
    h.send(&sam, "list").await;
    let lines = sam.lines();
    assert_eq!(lines.len(), 101);
    assert_eq!(lines[99], "ROOM #r099 0");
    assert_eq!(lines[100], "OK more=1");
}

// ---------------------------------------------------------------------------
// Server information (8.5, 6.2)

#[tokio::test]
async fn info_reports_the_server() {
    let mut c = config();
    c.server.retention = "30".into();
    let mut h = Harness::with(c, |_| {});
    let mut sam = h.guest("sam").await;
    h.send(&sam, "@ref=i info").await;
    assert_eq!(
        sam.lines(),
        ["@ref=i OK version=1 guests=yes register=no retention=30 push=no upload=no"]
    );
}

#[tokio::test]
async fn info_room_before_and_after_joining() {
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    let mut h = Harness::with(c, |s| set(s, "#private", RoomSetting::Public(false)));
    let mut sam = h.guest("sam").await;
    let id = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .id;
    // No events yet, so the head is 0 (6.2).
    h.send(&sam, "@ref=i info #general").await;
    let mut want: Vec<String> = default_settings("#general")
        .iter()
        .map(|l| format!("@ref=i {l}"))
        .collect();
    want.push(format!(
        "@ref=i OK id={id} members=0 head=0 role=none joined=no"
    ));
    assert_eq!(sam.lines(), want);

    h.send(&sam, "join #general").await;
    sam.lines();
    h.send(&sam, "info #general").await;
    let mut want = default_settings("#general");
    want.push(format!(
        "OK id={id} members=1 head=1 role=member joined=yes"
    ));
    assert_eq!(sam.lines(), want);

    for room in ["#private", "#nowhere"] {
        h.send(&sam, &format!("info {room}")).await;
        assert_eq!(sam.lines(), ["ERR not-found no such room"]);
    }
}

// ---------------------------------------------------------------------------
// Messages (5.3)

#[tokio::test]
async fn msg_reaches_everyone_before_its_ok() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let (mut bob, _) = h.joined("bob", "#general").await;
    let mut outsider = h.guest("eve").await;
    sam.lines();
    h.send(&sam, "@ref=m;cid=0123456789abcdef msg #General hi \\n all")
        .await;
    let event = format!("@seq=3;t={T};from=~sam MSG #general hi \\n all");
    assert_eq!(sam.lines(), [event.clone(), "@ref=m OK seq=3".into()]);
    assert_eq!(bob.lines(), [event]);
    assert_eq!(outsider.lines(), Vec::<String>::new());
}

#[tokio::test]
async fn msg_needs_membership() {
    let mut h = Harness::new();
    let mut sam = h.guest("sam").await;
    h.send(&sam, "msg #general hi").await;
    h.send(&sam, "msg #nowhere hi").await;
    assert_eq!(
        sam.lines(),
        [
            "ERR forbidden join the room first",
            "ERR not-found no such room"
        ]
    );
}

#[tokio::test]
async fn replies_need_a_message_to_reply_to() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "msg #general first").await;
    h.send(&sam, "@reply=2 msg #general a reply").await;
    h.send(&sam, "@reply=3 msg #general a reply to a reply")
        .await;
    let lines = sam.lines();
    assert_eq!(
        lines[2],
        format!("@seq=3;t={T};from=~sam;reply=2 MSG #general a reply")
    );
    assert_eq!(
        lines[4],
        format!("@seq=4;t={T};from=~sam;reply=3 MSG #general a reply to a reply")
    );
    // Not a message, not there, or deleted.
    h.send(&sam, "@reply=1 msg #general to a join").await;
    h.send(&sam, "@reply=99 msg #general to nothing").await;
    assert_eq!(
        sam.lines(),
        [
            "ERR not-found no such message",
            "ERR not-found no such message"
        ]
    );
}

#[tokio::test]
async fn replies_to_deleted_edits_and_reactions_are_refused() {
    let mut h = Harness::with(config(), |s| {
        let msg = |relation| EventKind::Msg {
            relation,
            file: None,
            text: "x".into(),
        };
        put(s, "#general", "~old", msg(None)); // 1
        put(s, "#general", "~old", msg(Some(Relation::Edit(seq(1))))); // 2
        put(s, "#general", "~old", msg(Some(Relation::React(seq(1))))); // 3
        put(s, "#general", "~old", msg(None)); // 4
        put(s, "#general", "~old", EventKind::Delete { target: seq(4) }); // 5
    });
    let (mut sam, _) = h.joined("sam", "#general").await;
    for target in [2, 3, 4, 5] {
        h.send(&sam, &format!("@reply={target} msg #general hm"))
            .await;
        assert_eq!(sam.lines(), ["ERR not-found no such message"], "{target}");
    }
    h.send(&sam, "@reply=1 msg #general ok").await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=7");
}

#[tokio::test]
async fn a_resent_guest_message_is_stored_once() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let (mut bob, _) = h.joined("bob", "#general").await;
    sam.lines();
    let cid = "cid=0123456789abcdef";
    h.send(&sam, &format!("@{cid} msg #general hi")).await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=3");
    bob.lines();
    // Same cid: the same seq, and nothing new for anyone.
    h.send(&sam, &format!("@ref=again;{cid} msg #general hi"))
        .await;
    assert_eq!(sam.lines(), ["@ref=again OK seq=3"]);
    assert_eq!(bob.lines(), Vec::<String>::new());
    // Another guest's cids are its own.
    h.send(&bob, &format!("@{cid} msg #general hi")).await;
    assert_eq!(bob.lines().last().unwrap(), "OK seq=4");
    // After 24 hours, the cid is forgotten.
    h.clock
        .advance(Duration::from_millis(crate::store::CID_WINDOW_MS + 1));
    h.send(&sam, &format!("@{cid} msg #general hi")).await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=5");
    // A guest's cids last only as long as its connection (7.6).
    h.close(sam).await;
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, &format!("@{cid} msg #general hi")).await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=8");
}

#[tokio::test]
async fn a_resent_message_gets_its_seq_even_after_leaving() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let cid = "cid=0123456789abcdef";
    h.send(&sam, &format!("@{cid} msg #general hi")).await;
    h.send(&sam, "part #general").await;
    sam.lines();
    h.send(&sam, &format!("@{cid} msg #general hi")).await;
    assert_eq!(sam.lines(), ["OK seq=2"]);
}

// ---------------------------------------------------------------------------
// History and sync (7.1, 7.2)

/// A hub whose #general has 10 messages from ~old (seq 1 to 10).
fn ten_messages() -> Harness {
    let mut c = config();
    c.limits.max_page = 4;
    Harness::with(c, |s| {
        for n in 1..=10 {
            put(
                s,
                "#general",
                "~old",
                EventKind::Msg {
                    relation: None,
                    file: None,
                    text: format!("message {n}"),
                },
            );
        }
    })
}

fn msg_line(n: u64) -> String {
    format!("@seq={n};t={T};from=~old MSG #general message {n}")
}

#[tokio::test]
async fn history_pages_at_every_edge() {
    let mut h = ten_messages();
    // Not a member: a public room can still be read (7.2).
    let mut sam = h.guest("sam").await;
    let id = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .id;
    let cases: &[(&str, &[u64], bool)] = &[
        // The latest page, capped at max_page (4).
        ("", &[7, 8, 9, 10], true),
        ("limit=2", &[9, 10], true),
        ("limit=50", &[7, 8, 9, 10], true),
        ("before=5", &[1, 2, 3, 4], false),
        ("before=4", &[1, 2, 3], false),
        ("before=2 limit=1", &[1], false),
        ("before=1", &[], false),
        ("before=11 limit=1", &[10], true),
        ("before=99 limit=1", &[10], true),
        // From a point.
        ("after=0", &[1, 2, 3, 4], true),
        ("after=0 limit=2", &[1, 2], true),
        ("after=6", &[7, 8, 9, 10], false),
        ("after=7", &[8, 9, 10], false),
        ("after=9", &[10], false),
        ("after=10", &[], false),
        ("after=500", &[], false),
        ("after=2 before=6", &[3, 4, 5], false),
        ("after=2 before=8", &[3, 4, 5, 6], true),
        ("after=2 before=7", &[3, 4, 5, 6], false),
        ("after=2 before=3", &[], false),
        ("after=8 before=2", &[], false),
    ];
    for &(options, seqs, more) in cases {
        h.send(&sam, &format!("@ref=h history #general {options}"))
            .await;
        let mut want: Vec<String> = seqs
            .iter()
            .map(|&n| format!("@ref=h;{}", &msg_line(n)[1..]))
            .collect();
        want.push(format!("@ref=h OK id={id} more={}", u8::from(more)));
        assert_eq!(sam.lines(), want, "{options}");
    }
}

#[tokio::test]
async fn history_includes_joins_parts_and_placeholders() {
    let mut h = Harness::with(config(), |s| {
        put(
            s,
            "#general",
            "~old",
            EventKind::Msg {
                relation: None,
                file: None,
                text: "oops".into(),
            },
        );
        put(s, "#general", "~old", EventKind::Delete { target: seq(1) });
    });
    let (mut sam, id) = h.joined("sam", "#general").await;
    h.send(&sam, "part #general bye").await;
    sam.lines();
    h.send(&sam, "history #general after=0").await;
    assert_eq!(
        sam.lines(),
        [
            format!("@seq=1;t={T};from=~old;deleted MSG #general"),
            format!("@seq=2;t={T};from=~old DELETE #general 1"),
            format!("@seq=3;t={T};from=~sam;id={id} JOIN #general"),
            format!("@seq=4;t={T};from=~sam PART #general bye"),
            format!("OK id={id} more=0"),
        ]
    );
}

#[tokio::test]
async fn history_follows_the_guest_rules() {
    let mut c = config();
    c.rooms = strings(&["#general", "#private", "#members", "#empty"]);
    let mut h = Harness::with(c, |s| {
        set(s, "#private", RoomSetting::Public(false));
        set(s, "#members", RoomSetting::Guests(GuestAccess::None));
    });
    let mut sam = h.guest("sam").await;
    for conv in ["#private", "#nowhere"] {
        h.send(&sam, &format!("history {conv}")).await;
        assert_eq!(sam.lines(), ["ERR not-found no such room"], "{conv}");
    }
    h.send(&sam, "history #members").await;
    assert_eq!(
        sam.lines(),
        ["ERR forbidden guests may not enter this room"]
    );
    h.send(&sam, "history bob@example.net").await;
    h.send(&sam, "history ~bob").await;
    assert_eq!(
        sam.lines(),
        [
            "ERR not-found no such conversation",
            "ERR not-found no such conversation"
        ]
    );
    // A room with no events.
    h.send(&sam, "history #empty after=0").await;
    let lines = sam.lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("OK id=") && lines[0].ends_with(" more=0"));
}

#[tokio::test]
async fn sync_lists_the_rooms_of_the_connection() {
    let mut c = config();
    c.rooms = strings(&["#general", "#other", "#unjoined"]);
    let mut h = Harness::with(c, |_| {});
    let mut sam = h.guest("sam").await;
    h.send(&sam, "@ref=s sync").await;
    assert_eq!(sam.lines(), ["@ref=s OK"]);
    h.send(&sam, "join #other").await;
    h.send(&sam, "join #general").await;
    let lines = sam.lines();
    let other = value(&lines[0], "id");
    let general = value(&lines[6], "id");
    let (mut bob, _) = h.joined("bob", "#general").await;
    h.send(&bob, "msg #general hi").await;
    sam.lines();
    h.send(&sam, "@ref=s sync").await;
    assert_eq!(
        sam.lines(),
        [
            format!("@ref=s CONV #general {general} 3 0"),
            format!("@ref=s CONV #other {other} 1 0"),
            "@ref=s OK".into(),
        ]
    );
    bob.lines();
}

// ---------------------------------------------------------------------------
// Ordering and fan-out (5.2, 3.6)

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_posters_see_one_order() {
    const POSTS: u64 = 200;
    let mut h = Harness::new();
    let mut clients = Vec::new();
    for name in ["sam", "bob", "eve"] {
        let (c, _) = h.joined(name, "#general").await;
        clients.push(c);
    }
    for c in &mut clients {
        c.lines();
    }
    // sam and bob post at the same time; eve only listens.
    let tasks: Vec<_> = clients[..2]
        .iter()
        .map(|c| {
            let hub = h.hub.clone();
            let id = c.id;
            tokio::spawn(async move {
                for n in 0..POSTS {
                    let req: Request = format!("msg #general {n}").parse().unwrap();
                    hub.command(id, req).await;
                }
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    let first = 4; // after three JOINs
    let last = 3 + 2 * POSTS;
    for c in &mut clients {
        let mut expect = first;
        let mut sent = Vec::new();
        for m in c.messages() {
            match m.line {
                ServerLine::Event(e) => {
                    let seq = e.meta.unwrap().seq.get();
                    assert_eq!(seq, expect, "events in seq order with no gaps");
                    expect += 1;
                }
                ServerLine::Ok(ok) => {
                    // The sender has its event before the OK.
                    let seq = ok.seq().unwrap().unwrap().get();
                    assert!(seq < expect, "OK seq={seq} before its event");
                    sent.push(seq);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(expect, last + 1);
        assert!(sent.is_empty() || sent.len() as u64 == POSTS);
        assert!(sent.windows(2).all(|w| w[0] < w[1]));
    }
    // And the store agrees.
    let key = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .key;
    let page = h
        .store
        .history(
            key,
            HistoryQuery {
                after: Some(0),
                before: None,
                limit: 1000,
            },
        )
        .unwrap();
    assert_eq!(page.events.len() as u64, last);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joins_and_parts_race_with_posts() {
    // While sam posts, bob joins and leaves over and over. Every
    // connection still sees one gap-free order while it is a member.
    let mut h = Harness::new();
    let (sam, _) = h.joined("sam", "#general").await;
    let mut bob = h.guest("bob").await;
    let hub = h.hub.clone();
    let poster = tokio::spawn({
        let hub = hub.clone();
        let id = sam.id;
        async move {
            for n in 0..200 {
                hub.command(id, format!("msg #general {n}").parse().unwrap())
                    .await;
            }
        }
    });
    for _ in 0..50 {
        hub.command(bob.id, "join #general".parse().unwrap()).await;
        hub.command(bob.id, "part #general".parse().unwrap()).await;
    }
    poster.await.unwrap();
    // Between its JOIN and its PART, bob sees every event in order.
    let mut inside: Option<u64> = None;
    for m in bob.messages() {
        let ServerLine::Event(e) = m.line else {
            continue;
        };
        if e.is_snapshot() {
            continue;
        }
        let seq = e.meta.as_ref().unwrap().seq.get();
        match (&e.body, inside) {
            (risala_proto::server::EventBody::Join { .. }, None) => inside = Some(seq),
            (risala_proto::server::EventBody::Part { .. }, Some(prev)) => {
                assert_eq!(seq, prev + 1);
                inside = None;
            }
            (_, Some(prev)) => {
                assert_eq!(seq, prev + 1);
                inside = Some(seq);
            }
            (body, None) => panic!("{body:?} while not a member"),
        }
    }
    assert_eq!(inside, None);
}

#[tokio::test]
async fn a_slow_reader_is_dropped_alone() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let slow = h.connect_sni(None, 4);
    h.send(&slow, "guest slow").await;
    h.send(&slow, "join #general").await;
    // Greeting, OK, JOIN: then the settings overflow the queue.
    assert!(slow.rx.is_killed());
    for n in 0..10 {
        h.send(&sam, &format!("msg #general {n}")).await;
    }
    assert_eq!(sam.lines().len(), 1 + 20);
    // The network layer notices and reports the close; the slow guest
    // leaves.
    h.close(slow).await;
    assert_eq!(
        sam.lines(),
        [format!("@seq=13;t={T};from=~slow PART #general")]
    );
}

// ---------------------------------------------------------------------------
// Persistence

#[tokio::test]
async fn a_restart_keeps_rooms_ids_and_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config();
    c.state_dir = dir.path().join("state");
    let open = |c: &Config| {
        let c = c.clone();
        let hub = Hub::open(c).unwrap();
        let store = Arc::new(SqliteStore::open_in_memory().unwrap()) as Arc<dyn Store>;
        Harness {
            hub,
            store,
            clock: Arc::new(ManualClock::new(start())),
            next: 100,
        }
    };
    let id = {
        let mut h = open(&c);
        let (sam, id) = h.joined("sam", "#general").await;
        h.send(&sam, "msg #general before the restart").await;
        h.close(sam).await;
        id
    };
    let mut h = open(&c);
    let (mut sam, id2) = h.joined("sam", "#general").await;
    assert_eq!(id, id2);
    h.send(&sam, "history #general after=0").await;
    let lines = sam.lines();
    assert_eq!(lines.len(), 5);
    assert!(lines[1].ends_with("from=~sam MSG #general before the restart"));
    assert!(lines[2].ends_with("from=~sam PART #general"));
    assert!(lines[3].contains("seq=4;"));
    assert_eq!(lines[4], format!("OK id={id} more=0"));
}

#[tokio::test]
async fn the_configuration_is_checked() {
    let store = || Arc::new(SqliteStore::open_in_memory().unwrap()) as Arc<dyn Store>;
    let clock = || Arc::new(SystemClock) as Arc<dyn Clock>;
    let build = |c: Config| Hub::build(c, store(), clock(), Duration::from_secs(1));
    let mut c = config();
    c.rooms = strings(&["general"]);
    assert!(matches!(build(c), Err(HubError::Config(_))));
    let mut c = config();
    c.server.retention = "never".into();
    assert!(matches!(build(c), Err(HubError::Config(_))));
    let mut c = config();
    c.server.welcome = "x".repeat(513);
    assert!(matches!(build(c), Err(HubError::Config(_))));
    let mut c = config();
    c.hostname = "not a host".into();
    assert!(matches!(build(c), Err(HubError::Config(_))));
}

// ---------------------------------------------------------------------------
// Store failures

/// A store that fails every append once `broken` is set.
struct Flaky {
    inner: SqliteStore,
    broken: AtomicBool,
}

impl Store for Flaky {
    fn load_server_settings(
        &self,
        d: &crate::store::ServerSettings,
    ) -> crate::store::Result<crate::store::ServerSettings> {
        self.inner.load_server_settings(d)
    }
    fn set_server_setting(
        &self,
        s: &risala_proto::types::ServerSetting,
    ) -> crate::store::Result<()> {
        self.inner.set_server_setting(s)
    }
    fn ensure_room(&self, r: &Room, t: Timestamp) -> crate::store::Result<RoomRecord> {
        self.inner.ensure_room(r, t)
    }
    fn rooms(&self) -> crate::store::Result<Vec<RoomRecord>> {
        self.inner.rooms()
    }
    fn room(&self, r: &Room) -> crate::store::Result<Option<RoomRecord>> {
        self.inner.room(r)
    }
    fn append(&self, c: ConvKey, e: &NewEvent) -> crate::store::Result<Appended> {
        if self.broken.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::Corrupt("broken on purpose".into()));
        }
        self.inner.append(c, e)
    }
    fn event(&self, c: ConvKey, s: Seq) -> crate::store::Result<Option<StoredEvent>> {
        self.inner.event(c, s)
    }
    fn history(&self, c: ConvKey, q: HistoryQuery) -> crate::store::Result<Page> {
        self.inner.history(c, q)
    }
    fn cid_seq(
        &self,
        c: ConvKey,
        f: &Uid,
        cid: &risala_proto::types::Cid,
        now: Timestamp,
    ) -> crate::store::Result<Option<Seq>> {
        self.inner.cid_seq(c, f, cid, now)
    }
    fn prune_cids(&self, b: Timestamp) -> crate::store::Result<u64> {
        self.inner.prune_cids(b)
    }
}

#[tokio::test]
async fn store_failures_are_internal_errors() {
    let store = Arc::new(Flaky {
        inner: SqliteStore::open_in_memory().unwrap(),
        broken: AtomicBool::new(false),
    });
    let mut h = Harness::on(config(), store.clone(), Duration::from_secs(120));
    let (mut sam, _) = h.joined("sam", "#general").await;
    let (mut bob, _) = h.joined("bob", "#general").await;
    sam.lines();
    store
        .broken
        .store(true, std::sync::atomic::Ordering::SeqCst);
    h.send(&sam, "@ref=1 msg #general lost").await;
    assert_eq!(sam.lines(), ["@ref=1 ERR internal internal error"]);
    assert_eq!(bob.lines(), Vec::<String>::new());
    store
        .broken
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // No seq was used up.
    h.send(&sam, "msg #general kept").await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=3");
}

// ---------------------------------------------------------------------------
// The example session of 1.4, as far as M2 goes.

#[tokio::test]
async fn the_overview_session() {
    let mut h = Harness::with(config(), |s| {
        set(
            s,
            "#general",
            RoomSetting::Topic("General chat. Be kind.".into()),
        );
        for (from, text) in [
            ("alice@example.org", "anyone around?"),
            ("bob@example.net", "yep"),
        ] {
            put(
                s,
                "#general",
                from,
                EventKind::Msg {
                    relation: None,
                    file: None,
                    text: text.into(),
                },
            );
        }
    });
    let mut c = h.connect_sni(Some("chat.example.org"), 64);
    let greeting = c.lines();
    assert!(greeting[0].starts_with("RISALA 1 chat.example.org "));
    assert!(greeting[0].ends_with(" Welcome!"));
    h.send(&c, "guest sam").await;
    assert_eq!(c.lines(), ["OK uid=~sam"]);
    h.send(&c, "join #general").await;
    let lines = c.lines();
    let id = value(&lines[0], "id");
    assert_eq!(
        lines,
        [
            format!("@seq=4;t={T};from=~sam;id={id} JOIN #general"),
            "SET #general topic General chat. Be kind.".into(),
            "SET #general public yes".into(),
            "SET #general guests write".into(),
            "SET #general retention server".into(),
            format!("OK id={id} head=4"),
        ]
    );
    h.send(&c, "history #general before=4 limit=2").await;
    assert_eq!(
        c.lines(),
        [
            format!("@seq=2;t={T};from=alice@example.org MSG #general anyone around?"),
            format!("@seq=3;t={T};from=bob@example.net MSG #general yep"),
            format!("OK id={id} more=1"),
        ]
    );
    h.send(&c, "@reply=2 msg #general hi alice, I'm new here")
        .await;
    assert_eq!(
        c.lines(),
        [
            format!("@seq=5;t={T};from=~sam;reply=2 MSG #general hi alice, I'm new here"),
            "OK seq=5".into(),
        ]
    );
}

fn seq(n: u64) -> risala_proto::names::Seq {
    risala_proto::names::Seq::new(n).unwrap()
}

use risala_proto::names::Seq;
use risala_proto::types::Relation;

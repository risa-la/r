//! Every M2 behaviour, over TLS against a whole server: guests (4.2),
//! rooms (6.1, 6.2), messages (5.3), history and sync (7.1, 7.2, 7.6),
//! server information (8.5), keepalive and closing (11), and a restart.
//!
//! The hub's own tests (`src/core/tests.rs`) cover each rule at every
//! edge, without sockets. These check that the rules hold end to end,
//! through TLS, framing and the connection tasks.

mod common;

use std::time::{Duration, Instant};

use common::{Session, command, put, recv, settled, until_closed, value};
use risala_proto::types::{GuestAccess, RoomSetting};
use risala_server::config::Limits;
use risala_server::store::EventKind;
use risala_server::testing::{ClientOptions, TestClient, TestServer};

/// A server with rooms of every kind a guest meets in M2:
///
/// - `#general`, `#help` (topic "Ask here") and `#empty`: public, open to
///   guests, no events
/// - `#private`: `public no`
/// - `#closed`: `guests none`
/// - `#readonly`: `guests read`
async fn rooms_server() -> TestServer {
    TestServer::builder()
        .hostname("chat.example.org")
        .room("#general")
        .room("#help")
        .room("#empty")
        .room("#private")
        .room("#closed")
        .room("#readonly")
        .prepare(|store| {
            let set = |room: &str, setting: RoomSetting| {
                put(store, room, "carol@example.org", EventKind::Set(setting));
            };
            set("#help", RoomSetting::Topic("Ask here".into()));
            set("#private", RoomSetting::Public(false));
            set("#closed", RoomSetting::Guests(GuestAccess::None));
            set("#readonly", RoomSetting::Guests(GuestAccess::Read));
        })
        .start()
        .await
}

/// The snapshot SET lines of a room with default settings, for a script.
fn default_settings(who: &str, room: &str) -> String {
    format!(
        "{who} S: SET {room} topic
         {who} S: SET {room} public yes
         {who} S: SET {room} guests write
         {who} S: SET {room} retention server
         {who} S: SET {room} e2ee no"
    )
}

/// Signs in as `~<name>` once the name is free.
///
/// A closing guest's PARTs are recorded before its name is given up, so a
/// client that has just seen them can still get `name-taken` for a moment
/// (4.2). It tries again, as the spec says clients should.
async fn guest_once_free(server: &TestServer, name: &str) -> TestClient {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut c = server.connect().await;
        assert!(recv(&mut c).await.starts_with("RISALA 1 "));
        let answer = command(&mut c, &format!("guest {name}")).await;
        if answer == [format!("OK uid=~{name}")] {
            return c;
        }
        assert!(answer[0].starts_with("ERR name-taken"), "{answer:?}");
        assert!(Instant::now() < deadline, "~{name} is still taken");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Joins `room` and returns its id.
async fn join(client: &mut TestClient, room: &str) -> String {
    let lines = command(client, &format!("JOIN {room}")).await;
    let ok = lines.last().unwrap();
    assert!(ok.starts_with("OK id="), "{lines:?}");
    value(ok, "id")
}

// ---------------------------------------------------------------------
// Greeting and sign-in (4.1, 4.2)

#[tokio::test(flavor = "multi_thread")]
async fn greeting_names_the_host() {
    let server = TestServer::builder()
        .hostname("chat.example.org")
        .welcome("Hello\\nthere")
        .start()
        .await;
    let mut vars = Default::default();
    // SNI names the host.
    let mut c = server
        .connect_with(ClientOptions::sni("other.example"))
        .await;
    let greeting = recv(&mut c).await;
    common::matches(
        "RISALA 1 other.example {nonce} Hello\\nthere",
        &greeting,
        &mut vars,
    )
    .unwrap();
    let nonce = vars["nonce"].clone();
    assert_eq!(nonce.len(), 64, "32 bytes of hex");
    // Without SNI, it is the server's main hostname. Every nonce is new.
    let mut c = server.connect_with(ClientOptions::default()).await;
    let greeting = recv(&mut c).await;
    common::matches(
        "RISALA 1 chat.example.org {*} Hello\\nthere",
        &greeting,
        &mut vars,
    )
    .unwrap();
    assert!(!greeting.contains(&nonce));
    // No ALPN works too (2.1), as with openssl s_client.
    let options = ClientOptions {
        alpn: false,
        ..ClientOptions::sni("chat.example.org")
    };
    let mut c = server.connect_with(options).await;
    assert!(recv(&mut c).await.starts_with("RISALA 1 chat.example.org "));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_in_as_a_guest() {
    let server = rooms_server().await;
    let mut s = Session::new();
    s.add("sam", server.connect().await);
    s.add("other", server.connect().await);
    s.play(
        "S: RISALA 1 chat.example.org {*}
         C: join #general
         S: ERR not-authenticated{..}
         C: list
         S: ERR not-authenticated{..}
         C: info
         S: OK version=1 guests=yes register=no retention=forever push=no upload=no
         C: info #general
         S: ERR not-authenticated{..}
         C: ping
         S: OK
         C: guest sam
         S: OK uid=~sam
         C: guest sam2
         S: ERR already-authenticated{..}
         other S: RISALA 1 chat.example.org {*}
         other C: GUEST Sam
         other S: ERR name-taken{..}
         other C: guest bad!name
         other S: ERR bad-syntax{..}
         other C: guest sam2
         other S: OK uid=~sam2",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn guests_can_be_turned_off() {
    let server = TestServer::builder().guests(false).start().await;
    let mut s = Session::new();
    s.add("sam", server.connect().await);
    s.play(
        "S: RISALA 1 localhost {*}
         C: info
         S: OK version=1 guests=no register=no retention=forever push=no upload=no
         C: guest sam
         S: ERR forbidden{..}",
    )
    .await;
    server.stop().await;
}

// ---------------------------------------------------------------------
// Chatting (5.3, 6.1)

#[tokio::test(flavor = "multi_thread")]
async fn two_guests_chat() {
    let server = TestServer::builder().room("#general").start().await;
    let mut s = Session::new();
    s.add("alice", server.guest("alice").await);
    s.add("bob", server.guest("bob").await);
    s.play(&format!(
        "alice C: join #general
         alice S: @seq=1;t={{*}};from=~alice;id={{id}} JOIN #general
         {}
         alice S: OK id={{id}} head=1
         bob C: JOIN #General
         bob S: @seq=2;t={{*}};from=~bob;id={{id}} JOIN #general
         {}
         bob S: OK id={{id}} head=2
         alice S: @seq=2;t={{*}};from=~bob;id={{id}} JOIN #general
         alice C: msg #general hi bob!
         alice S: @seq=3;t={{*}};from=~alice MSG #general hi bob!
         alice S: OK seq=3
         bob S: @seq=3;t={{*}};from=~alice MSG #general hi bob!
         bob C: @ref=b1 MSG #general  two lines,\\nand  spaces 👋
         bob S: @seq=4;t={{*}};from=~bob MSG #general  two lines,\\nand  spaces 👋
         bob S: @ref=b1 OK seq=4
         alice S: @seq=4;t={{*}};from=~bob MSG #general  two lines,\\nand  spaces 👋
         alice C: @reply=4 msg #general C:\\Users is a path
         alice S: @seq=5;t={{*}};from=~alice;reply=4 MSG #general C:\\Users is a path
         alice S: OK seq=5
         bob S: @seq=5;t={{*}};from=~alice;reply=4 MSG #general C:\\Users is a path
         bob C: msg #general \\n
         bob S: ERR bad-syntax{{..}}
         bob C: @reply=99 msg #general to nothing
         bob S: ERR not-found{{..}}",
        default_settings("alice", "#general"),
        default_settings("bob", "#general"),
    ))
    .await;
    s.settled().await;
    server.stop().await;
}

/// Three guests post at once, each sending all its lines without waiting.
/// Everyone gets every event once, in one order with no gaps (5.2), and
/// each poster gets its own event before its `OK` (3.6).
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_posters_see_one_order() {
    const EACH: usize = 50;
    let server = TestServer::builder().room("#general").start().await;
    let mut clients = Vec::new();
    for name in ["a", "b", "c"] {
        let mut c = server.guest(name).await;
        join(&mut c, "#general").await;
        clients.push(c);
    }
    // Seq 1 to 3 are the JOINs. Read the JOINs of later guests first.
    for (i, c) in clients.iter_mut().enumerate() {
        for _ in i + 1..3 {
            assert!(recv(c).await.ends_with(" JOIN #general"));
        }
    }
    let tasks: Vec<_> = clients
        .into_iter()
        .zip(["a", "b", "c"])
        .map(|(mut c, name)| {
            tokio::spawn(async move {
                let mut batch = String::new();
                for n in 0..EACH {
                    batch.push_str(&format!("msg #general {name}{n}\n"));
                }
                c.send_raw(batch.as_bytes()).await.unwrap();
                // (seq, line without its time) of every event, in order.
                let mut events = Vec::new();
                let mut oks = 0;
                while oks < EACH || events.len() < 3 * EACH {
                    let line = recv(&mut c).await;
                    if let Some(seq) = line.strip_prefix("OK seq=") {
                        // The poster's own event came first.
                        let seq: u64 = seq.parse().unwrap();
                        let (last_seq, last): &(u64, String) = events.last().unwrap();
                        assert!(*last_seq >= seq);
                        let own = events.iter().find(|(s, _)| *s == seq).unwrap();
                        assert!(own.1.starts_with(&format!("~{name} ")), "{own:?} {last}");
                        oks += 1;
                        continue;
                    }
                    let seq: u64 = value(&line, "seq").parse().unwrap();
                    let text = line.split_once(' ').unwrap().1.to_owned();
                    events.push((seq, format!("{} {text}", value(&line, "from"))));
                }
                settled(&mut c).await;
                events
            })
        })
        .collect();
    let mut all = Vec::new();
    for task in tasks {
        all.push(task.await.unwrap());
    }
    let seqs: Vec<u64> = all[0].iter().map(|(s, _)| *s).collect();
    assert_eq!(seqs, (4..4 + 3 * EACH as u64).collect::<Vec<_>>());
    assert_eq!(all[0], all[1]);
    assert_eq!(all[0], all[2]);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn join_again_part_and_come_back() {
    let server = TestServer::builder().room("#general").start().await;
    let mut s = Session::new();
    s.add("alice", server.guest("alice").await);
    s.add("bob", server.guest("bob").await);
    let id = join(s.client("alice"), "#general").await;
    s.bind("id", &id);
    join(s.client("bob"), "#general").await;
    s.play(&format!(
        "alice S: @seq=2;t={{*}};from=~bob;id={{id}} JOIN #general

         bob C: join #general
         {}
         bob S: OK id={{id}} head=2

         bob C: part #general see you later
         bob S: @seq=3;t={{*}};from=~bob PART #general see you later
         bob S: OK
         alice S: @seq=3;t={{*}};from=~bob PART #general see you later
         bob C: part #general
         bob S: ERR not-found{{..}}
         bob C: msg #general still here?
         bob S: ERR forbidden{{..}}
         alice C: msg #general bob is gone
         alice S: @seq=4;t={{*}};from=~alice MSG #general bob is gone
         alice S: OK seq=4",
        default_settings("bob", "#general"),
    ))
    .await;
    // Bob, no longer a member, receives nothing.
    s.settled().await;
    s.play(&format!(
        "bob C: join #general
         bob S: @seq=5;t={{*}};from=~bob;id={{id}} JOIN #general
         {}
         bob S: OK id={{id}} head=5
         alice S: @seq=5;t={{*}};from=~bob;id={{id}} JOIN #general
         alice C: part #general
         alice S: @seq=6;t={{*}};from=~alice PART #general
         alice S: OK
         bob S: @seq=6;t={{*}};from=~alice PART #general",
        default_settings("bob", "#general"),
    ))
    .await;
    s.settled().await;
    server.stop().await;
}

/// A guest leaves its rooms when its connection closes, however it closes
/// (4.2), and its name is free again.
#[tokio::test(flavor = "multi_thread")]
async fn a_guest_leaves_its_rooms_when_it_disconnects() {
    let server = TestServer::builder()
        .room("#general")
        .room("#help")
        .start()
        .await;
    let mut alice = server.guest("alice").await;
    join(&mut alice, "#general").await;
    join(&mut alice, "#help").await;

    // A clean close, with close_notify.
    let mut bob = server.guest("bob").await;
    join(&mut bob, "#general").await;
    join(&mut bob, "#help").await;
    let mut s = Session::new();
    s.add("alice", alice);
    s.play(
        "alice S: @seq=2;t={*};from=~bob;id={*} JOIN #general
         alice S: @seq=2;t={*};from=~bob;id={*} JOIN #help",
    )
    .await;
    bob.close().await.unwrap();
    s.play(
        "alice S: @seq=3;t={*};from=~bob PART #general
         alice S: @seq=3;t={*};from=~bob PART #help",
    )
    .await;

    // A connection dropped without close_notify.
    let mut carl = server.guest("carl").await;
    join(&mut carl, "#general").await;
    s.play("alice S: @seq=4;t={*};from=~carl;id={*} JOIN #general")
        .await;
    drop(carl);
    s.play("alice S: @seq=5;t={*};from=~carl PART #general")
        .await;

    // After QUIT.
    let mut dan = server.guest("dan").await;
    join(&mut dan, "#general").await;
    s.play("alice S: @seq=6;t={*};from=~dan;id={*} JOIN #general")
        .await;
    assert_eq!(command(&mut dan, "quit gotta go").await, ["OK"]);
    assert_eq!(until_closed(&mut dan).await, Vec::<String>::new());
    s.play("alice S: @seq=7;t={*};from=~dan PART #general")
        .await;
    s.settled().await;

    // The names are free again, and the PARTs are history.
    for name in ["bob", "carl", "dan"] {
        guest_once_free(&server, name).await;
    }
    s.play(
        "alice C: history #general after=2
         alice S: @seq=3;t={*};from=~bob PART #general
         alice S: @seq=4;t={*};from=~carl;id={*} JOIN #general
         alice S: @seq=5;t={*};from=~carl PART #general
         alice S: @seq=6;t={*};from=~dan;id={*} JOIN #general
         alice S: @seq=7;t={*};from=~dan PART #general
         alice S: OK id={*} more=0",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------
// LIST, INFO and who may see what (6.1, 6.2, 8.5)

#[tokio::test(flavor = "multi_thread")]
async fn list_shows_public_rooms_open_to_guests() {
    let server = rooms_server().await;
    let mut sam = server.guest("sam").await;
    join(&mut sam, "#general").await;
    let mut s = Session::new();
    s.add("sam", sam);
    // Not #private (public no) and not #closed (guests none).
    s.play(
        "C: list
         S: ROOM #empty 0
         S: ROOM #general 1
         S: ROOM #help 0 Ask here
         S: ROOM #readonly 0
         S: OK more=0
         C: @ref=l1 LIST limit=2
         S: @ref=l1 ROOM #empty 0
         S: @ref=l1 ROOM #general 1
         S: @ref=l1 OK more=1
         C: list after=#general limit=2
         S: ROOM #help 0 Ask here
         S: ROOM #readonly 0
         S: OK more=0
         C: list after=#f
         S: ROOM #general 1
         S: ROOM #help 0 Ask here
         S: ROOM #readonly 0
         S: OK more=0
         C: list after=#readonly
         S: OK more=0
         C: list limit=0
         S: ERR bad-syntax{..}",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn info_about_the_server_and_rooms() {
    let server = rooms_server().await;
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.play(&format!(
        "C: info
         S: OK version=1 guests=yes register=no retention=forever push=no upload=no
         C: info #general
         {}
         S: OK id={{id}} members=0 head=0 role=none joined=no
         C: join #general
         S: @seq=1;t={{*}};from=~sam;id={{id}} JOIN #general
         {}
         S: OK id={{id}} head=1
         C: @ref=i INFO #general
         S: @ref=i SET #general topic
         S: @ref=i SET #general public yes
         S: @ref=i SET #general guests write
         S: @ref=i SET #general retention server
         S: @ref=i SET #general e2ee no
         S: @ref=i OK id={{id}} members=1 head=1 role=member joined=yes
         C: info #help
         S: SET #help topic Ask here
         S: SET #help public yes
         S: SET #help guests write
         S: SET #help retention server
         S: SET #help e2ee no
         S: OK id={{help}} members=0 head=1 role=none joined=no
         C: info #readonly
         S: SET #readonly topic
         S: SET #readonly public yes
         S: SET #readonly guests read
         S: SET #readonly retention server
         S: SET #readonly e2ee no
         S: OK id={{*}} members=0 head=1 role=none joined=no",
        default_settings("sam", "#general"),
        default_settings("sam", "#general"),
    ))
    .await;
    assert_ne!(s.var("id"), s.var("help"), "every room has its own id");
    s.settled().await;
    server.stop().await;
}

/// A room you cannot see gets `not-found`, one you can see but may not
/// join or read gets `forbidden` (6.1, PLAN.md 5.14).
#[tokio::test(flavor = "multi_thread")]
async fn forbidden_and_not_found() {
    let server = rooms_server().await;
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.add("ann", server.guest("ann").await);
    s.play(
        "C: join #nowhere
         S: ERR not-found{..}
         C: info #nowhere
         S: ERR not-found{..}
         C: history #nowhere
         S: ERR not-found{..}
         C: msg #nowhere hello?
         S: ERR not-found{..}

         C: join #private
         S: ERR not-found{..}
         C: info #private
         S: ERR not-found{..}
         C: history #private
         S: ERR not-found{..}
         C: msg #private hello?
         S: ERR not-found{..}

         C: join #closed
         S: ERR forbidden{..}
         C: info #closed
         S: ERR forbidden{..}
         C: history #closed
         S: ERR forbidden{..}
         C: msg #closed hello?
         S: ERR forbidden{..}

         C: msg #general not a member
         S: ERR forbidden{..}

         ann C: join #readonly
         ann S: @seq=2;t={*};from=~ann;id={id} JOIN #readonly
         ann S: SET #readonly topic
         ann S: SET #readonly public yes
         ann S: SET #readonly guests read
         ann S: SET #readonly retention server
         ann S: SET #readonly e2ee no
         ann S: OK id={id} head=2
         C: join #readonly
         S: @seq=3;t={*};from=~sam;id={id} JOIN #readonly
         S: SET #readonly topic
         S: SET #readonly public yes
         S: SET #readonly guests read
         S: SET #readonly retention server
         S: SET #readonly e2ee no
         S: OK id={id} head=3
         ann S: @seq=3;t={*};from=~sam;id={id} JOIN #readonly
         C: msg #readonly may I?
         S: ERR forbidden{..}
         C: history #readonly
         S: @seq=1;t={*};from=carol@example.org SET #readonly guests read
         S: @seq=2;t={*};from=~ann;id={id} JOIN #readonly
         S: @seq=3;t={*};from=~sam;id={id} JOIN #readonly
         S: OK id={id} more=0

         C: @edit=3 msg #readonly an edit
         S: ERR not-supported{..}
         C: read #readonly 3
         S: ERR forbidden{..}",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// INFO, HISTORY and SYNC of a room from the configuration that nobody
/// has joined: it has no events, and its head is 0 (6.2).
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_config_room_has_head_0() {
    let server = TestServer::builder().room("#empty").start().await;
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.play(&format!(
        "C: info #empty
         {}
         S: OK id={{id}} members=0 head=0 role=none joined=no
         C: history #empty
         S: OK id={{id}} more=0
         C: history #empty after=0
         S: OK id={{id}} more=0
         C: sync
         S: OK
         C: list
         S: ROOM #empty 0
         S: OK more=0
         C: join #empty
         S: @seq=1;t={{*}};from=~sam;id={{id}} JOIN #empty
         {}
         S: OK id={{id}} head=1
         C: sync
         S: CONV #empty {{id}} 1 0
         S: OK",
        default_settings("sam", "#empty"),
        default_settings("sam", "#empty"),
    ))
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------
// History and sync (7.1, 7.2)

#[tokio::test(flavor = "multi_thread")]
async fn history_pages() {
    let server = TestServer::builder()
        .room("#general")
        .room("#help")
        .configure(|c| c.limits.max_page = 4)
        .start()
        .await;
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.add("ann", server.guest("ann").await);
    // Seq 1 is the JOIN, 2 to 9 are messages.
    let id = join(s.client("sam"), "#general").await;
    s.bind("id", &id);
    for n in 2..=9 {
        let ok = command(s.client("sam"), &format!("msg #general m{n}")).await;
        assert_eq!(ok.last().unwrap(), &format!("OK seq={n}"));
    }
    let m = |n: u64| format!("S: @seq={n};t={{*}};from=~sam MSG #general m{n}");
    s.play(
        &[
            // The latest events, capped at max_page.
            "C: history #general".to_owned(),
            m(6),
            m(7),
            m(8),
            m(9),
            "S: OK id={id} more=1".into(),
            // From the start.
            "C: @ref=h history #general after=0 limit=2".into(),
            "S: @ref=h;seq=1;t={*};from=~sam;id={id} JOIN #general".into(),
            "S: @ref=h;seq=2;t={*};from=~sam MSG #general m2".into(),
            "S: @ref=h OK id={id} more=1".into(),
            // Forwards.
            "C: history #general after=7 limit=50".into(),
            m(8),
            m(9),
            "S: OK id={id} more=0".into(),
            "C: history #general after=9".into(),
            "S: OK id={id} more=0".into(),
            // Backwards.
            "C: history #general before=4".into(),
            "S: @seq=1;t={*};from=~sam;id={id} JOIN #general".into(),
            m(2),
            m(3),
            "S: OK id={id} more=0".into(),
            "C: history #general before=6 limit=2".into(),
            m(4),
            m(5),
            "S: OK id={id} more=1".into(),
            // Between: more=1 counts only events below before.
            "C: history #general after=3 before=6".into(),
            m(4),
            m(5),
            "S: OK id={id} more=0".into(),
            "C: history #general after=3 before=6 limit=1".into(),
            m(4),
            "S: OK id={id} more=1".into(),
            // A public room the guest is not in.
            "ann C: history #general after=8".into(),
            "ann S: @seq=9;t={*};from=~sam MSG #general m9".into(),
            "ann S: OK id={id} more=0".into(),
            "C: history #general limit=0".into(),
            "S: ERR bad-syntax{..}".into(),
            "C: history #general before=0".into(),
            "S: ERR bad-syntax{..}".into(),
        ]
        .join("\n"),
    )
    .await;
    s.settled().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn many_pages_at_once_reach_a_slow_reader() {
    // A client may send a HISTORY for every room at once, as librisala
    // does after SYNC, and then read the pages at its own pace. Its
    // queue (1024 lines) holds two pages of 500 at most, so the server
    // must wait for the client to read before it runs the next HISTORY,
    // rather than drop the connection as too slow.
    const PAGES: usize = 20;
    let text = "x".repeat(1000);
    let server = TestServer::builder()
        .room("#general")
        .prepare(move |store| {
            for _ in 0..500 {
                put(store, "#general", "carol@example.org", common::msg(&text));
            }
        })
        .start()
        .await;
    let mut sam = server.guest("sam").await;
    join(&mut sam, "#general").await;
    let commands: String = (0..PAGES)
        .map(|i| format!("@ref=h{i} history #general limit=500\n"))
        .collect();
    sam.send_raw(commands.as_bytes()).await.unwrap();
    // Long enough for the socket's buffers to fill.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for i in 0..PAGES {
        for n in 0..500 {
            let line = sam.expect_line().await.unwrap();
            assert!(line.starts_with(&format!("@ref=h{i};seq=")), "{line}");
            if n % 50 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        let ok = sam.expect_line().await.unwrap();
        assert!(ok.starts_with(&format!("@ref=h{i} OK ")), "{ok}");
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_lists_the_rooms_of_the_connection() {
    let server = TestServer::builder()
        .room("#general")
        .room("#help")
        .room("#zoo")
        .start()
        .await;
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.add("ann", server.guest("ann").await);
    let general = join(s.client("sam"), "#general").await;
    let help = join(s.client("sam"), "#help").await;
    join(s.client("ann"), "#help").await;
    s.bind("general", &general);
    s.bind("help", &help);
    s.play(
        "S: @seq=2;t={*};from=~ann;id={help} JOIN #help
         C: msg #general hello
         S: @seq=2;t={*};from=~sam MSG #general hello
         S: OK seq=2
         C: sync
         S: CONV #general {general} 2 0
         S: CONV #help {help} 2 0
         S: OK
         ann C: @ref=s SYNC
         ann S: @ref=s CONV #help {help} 2 0
         ann S: @ref=s OK",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------
// Resending safely (7.6)

#[tokio::test(flavor = "multi_thread")]
async fn a_resent_cid_is_stored_once() {
    let server = TestServer::builder().room("#general").start().await;
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.add("ann", server.guest("ann").await);
    let id = join(s.client("sam"), "#general").await;
    s.bind("id", &id);
    join(s.client("ann"), "#general").await;
    s.play(
        "S: @seq=2;t={*};from=~ann;id={id} JOIN #general
         C: @cid=0123456789abcdef msg #general only once
         S: @seq=3;t={*};from=~sam MSG #general only once
         S: OK seq=3
         ann S: @seq=3;t={*};from=~sam MSG #general only once
         C: @cid=0123456789abcdef msg #general only once
         S: OK seq=3
         C: @cid=0123456789abcdef;reply=1 msg #general different text
         S: OK seq=3
         C: @cid=fedcba9876543210 msg #general another
         S: @seq=4;t={*};from=~sam MSG #general another
         S: OK seq=4
         ann S: @seq=4;t={*};from=~sam MSG #general another
         C: part #general
         S: @seq=5;t={*};from=~sam PART #general
         S: OK
         ann S: @seq=5;t={*};from=~sam PART #general
         C: @cid=0123456789abcdef msg #general only once
         S: OK seq=3",
    )
    .await;
    // Nothing reached ann for the resends.
    s.settled().await;

    // For guests, cids count only within one connection (7.6).
    s.take("sam").close().await.unwrap();
    let mut sam = server.guest("sam2").await;
    join(&mut sam, "#general").await;
    s.add("sam2", sam);
    s.play(
        "ann S: @seq=6;t={*};from=~sam2;id={id} JOIN #general
         sam2 C: @cid=0123456789abcdef msg #general only once
         sam2 S: @seq=7;t={*};from=~sam2 MSG #general only once
         sam2 S: OK seq=7
         ann S: @seq=7;t={*};from=~sam2 MSG #general only once",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------
// Keepalive and closing (11)

#[tokio::test(flavor = "multi_thread")]
async fn ping_pong_and_quit() {
    let server = TestServer::builder().room("#general").start().await;
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.play(
        "C: ping
         S: OK
         C: PING some-token
         S: OK
         C: @ref=p ping
         S: @ref=p OK
         C: pong abc
         C: @ref=9 frobnicate
         S: @ref=9 ERR unknown-command{..}
         C: msg
         S: ERR bad-syntax{..}",
    )
    .await;
    // PONG and empty lines get no answer.
    s.client("sam").send("").await.unwrap();
    s.client("sam").send_raw(b"\r\n").await.unwrap();
    s.settled().await;
    // QUIT is the last command: lines after it are ignored (11).
    let mut sam = s.take("sam");
    sam.send_raw(b"quit see you\r\nping\nguest again\n")
        .await
        .unwrap();
    assert_eq!(until_closed(&mut sam).await, ["OK"]);
    server.stop().await;
}

/// With short timers: a client that stays silent gets PING, then BYE, and
/// a guest that times out leaves its rooms. One that answers stays.
#[tokio::test(flavor = "multi_thread")]
async fn silent_clients_are_pinged_then_closed() {
    let server = TestServer::builder()
        .room("#general")
        .limits(Limits {
            idle_ping_secs: 1,
            ping_timeout_secs: 1,
            ..Limits::default()
        })
        .start()
        .await;
    let mut ann = server.guest("ann").await;
    join(&mut ann, "#general").await;
    let mut sam = server.guest("sam").await;
    join(&mut sam, "#general").await;

    // Sam says nothing more.
    let sam_task = tokio::spawn(async move { until_closed(&mut sam).await });

    // Ann answers every PING, and sees sam join, then leave.
    let mut seen = Vec::new();
    loop {
        let line = recv(&mut ann).await;
        if let Some(token) = line.strip_prefix("PING ") {
            ann.send(&format!("PONG {token}")).await.unwrap();
            continue;
        }
        seen.push(line.split(' ').skip(1).collect::<Vec<_>>().join(" "));
        if seen.len() == 2 {
            break;
        }
    }
    assert_eq!(seen, ["JOIN #general", "PART #general"]);

    let lines = sam_task.await.unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].starts_with("PING "), "{lines:?}");
    assert_eq!(lines[1], "BYE ping timeout");

    // Ann is still connected.
    ann.send("@ref=still PING").await.unwrap();
    loop {
        let line = recv(&mut ann).await;
        if line == "@ref=still OK" {
            break;
        }
        let token = line.strip_prefix("PING ").expect("a PING");
        ann.send(&format!("PONG {token}")).await.unwrap();
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_in_has_a_time_limit() {
    let server = TestServer::builder()
        .limits(Limits {
            sign_in_secs: 1,
            ..Limits::default()
        })
        .start()
        .await;
    let mut slow = server.connect().await;
    let mut quick = server.guest("quick").await;
    let lines = until_closed(&mut slow).await;
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].starts_with("RISALA 1 localhost "));
    assert_eq!(lines[1], "BYE sign-in timeout");
    // A guest that signed in stays.
    settled(&mut quick).await;
    server.stop().await;
}

/// The longest line a client may send (2.3) is relayed with the server's
/// tags. One byte more gets `too-long`, and the connection goes on.
#[tokio::test(flavor = "multi_thread")]
async fn the_longest_message_is_relayed() {
    let server = TestServer::builder().room("#general").start().await;
    let mut sam = server.guest("sam").await;
    join(&mut sam, "#general").await;
    let prefix = "msg #general ";
    // 8192 bytes with the LF.
    let text = "é".repeat((8191 - prefix.len()) / 2) + &"x".repeat((8191 - prefix.len()) % 2);
    let line = format!("{prefix}{text}");
    assert_eq!(line.len() + 1, risala_proto::frame::MAX_CLIENT_LINE);
    let answer = command(&mut sam, &line).await;
    assert_eq!(answer.len(), 2, "{answer:?}");
    assert!(answer[0].ends_with(&format!(";from=~sam MSG #general {text}")));
    assert_eq!(answer[1], "OK seq=2");
    let answer = command(&mut sam, &format!("{line}x")).await;
    assert!(answer[0].starts_with("ERR too-long"), "{answer:?}");
    settled(&mut sam).await;
    server.stop().await;
}

// ---------------------------------------------------------------------
// The test server itself

/// Stopping a test server, or dropping it, deletes its directory.
#[tokio::test(flavor = "multi_thread")]
async fn test_servers_clean_up() {
    let server = TestServer::start().await;
    let dir = server.state_dir().to_owned();
    assert!(dir.join("risala.db").exists());
    server.stop().await;
    assert!(!dir.exists());

    let server = TestServer::start().await;
    let dir = server.state_dir().to_owned();
    let mut c = server.guest("sam").await;
    drop(server);
    // The server stops in the background, closing connections.
    assert_eq!(until_closed(&mut c).await, ["BYE server shutting down"]);
    let deadline = Instant::now() + Duration::from_secs(10);
    while dir.exists() {
        assert!(
            Instant::now() < deadline,
            "{} is still there",
            dir.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------
// Restarting (5.1, 7.1)

/// A restart on the same state directory keeps rooms, their ids and their
/// history, and seqs go on from where they were.
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_keeps_rooms_ids_and_history() {
    let mut server = rooms_server().await;
    let fingerprint = server.fingerprint();
    let addr = server.addr();
    let mut s = Session::new();
    s.add("sam", server.guest("sam").await);
    s.add("ann", server.guest("ann").await);
    let id = join(s.client("sam"), "#general").await;
    s.bind("id", &id);
    join(s.client("ann"), "#general").await;
    s.play(
        "S: @seq=2;t={*};from=~ann;id={id} JOIN #general
         C: msg #general before the restart
         S: @seq=3;t={*};from=~sam MSG #general before the restart
         S: OK seq=3
         ann S: @seq=3;t={*};from=~sam MSG #general before the restart",
    )
    .await;
    let before = command(s.client("sam"), "list").await;
    let help_before = command(s.client("sam"), "info #help").await;

    server.restart().await;
    assert_eq!(server.addr(), addr);
    assert_eq!(server.fingerprint(), fingerprint);
    // Everyone was told, and the guests left #general as they went.
    for who in ["sam", "ann"] {
        let mut c = s.take(who);
        assert_eq!(until_closed(&mut c).await, ["BYE server shutting down"]);
    }

    let mut s = Session::new();
    s.bind("id", &id);
    s.add("sam", server.guest("sam").await);
    s.play(
        "C: history #general
         S: @seq=1;t={*};from=~sam;id={id} JOIN #general
         S: @seq=2;t={*};from=~ann;id={id} JOIN #general
         S: @seq=3;t={*};from=~sam MSG #general before the restart
         S: @seq={*};t={*};from={*} PART #general
         S: @seq={*};t={*};from={*} PART #general
         S: OK id={id} more=0
         C: info #general
         S: SET #general topic
         S: SET #general public yes
         S: SET #general guests write
         S: SET #general retention server
         S: SET #general e2ee no
         S: OK id={id} members=0 head=5 role=none joined=no
         C: join #general
         S: @seq=6;t={*};from=~sam;id={id} JOIN #general
         S: SET #general topic
         S: SET #general public yes
         S: SET #general guests write
         S: SET #general retention server
         S: SET #general e2ee no
         S: OK id={id} head=6
         C: msg #general after the restart
         S: @seq=7;t={*};from=~sam MSG #general after the restart
         S: OK seq=7",
    )
    .await;
    // The other rooms and their settings are unchanged. #general had two
    // members before, and has one now.
    let after = command(s.client("sam"), "list").await;
    assert_eq!(
        after,
        before
            .iter()
            .map(|l| l.replace("#general 2", "#general 1"))
            .collect::<Vec<_>>()
    );
    assert_eq!(command(s.client("sam"), "info #help").await, help_before);
    s.play(
        "C: join #private
         S: ERR not-found{..}",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

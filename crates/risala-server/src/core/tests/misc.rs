//! Server information, presence, push and reports (5.8, 6.1, 8, 9).

use std::sync::Mutex;
use std::time::Duration;

use aws_lc_rs::{agreement, hmac};
use risala_mls::{Pseudonym as MlsPseudonym, RisalaAad};
use risala_proto::binary::{PushAuth, PushKey};
use risala_proto::codec::Writer;
use risala_proto::command::Command;
use risala_proto::mls::{GroupId, TokenHash};
use risala_proto::names::BoxName;
use risala_proto::record::DeviceId;
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::types::PushTag;

use crate::core::{Clock as _, misc};
use crate::push::{BoxFuture, PushRequest, PushTransport, SendError};
use crate::store::{MailboxStore as _, MiscStore as _, NewMailbox, PushTarget};

use super::*;

/// A connection signed in as `uid`, with presence told, as AUTH does.
pub(super) async fn sign_in(h: &mut Harness, uid: &str) -> Client {
    let c = h.signed_in_as(uid);
    misc::signed_in(h.inner(), &uid.parse().unwrap()).await;
    c
}

/// Makes a mailbox numbered `n`, as CREATE would.
pub(super) fn add_mailbox(h: &Harness, n: u8) -> BoxName {
    let mailbox = BoxName::from_bytes([n; 16]);
    h.store
        .create_mailbox(&NewMailbox {
            mailbox,
            group_id: GroupId::from_bytes([n; 32]),
            first_epoch: 0,
            token_hash: TokenHash::from_bytes([n; 48]),
            created: T.parse().unwrap(),
        })
        .unwrap();
    mailbox
}

/// Makes the public room `room` on mailbox `n`, with `members` and their
/// roles, as the mailbox area would.
pub(super) fn add_room(
    h: &Harness,
    room: &str,
    n: u8,
    guests: &str,
    topic: &str,
    members: &[(&str, &str)],
) -> BoxName {
    let mailbox = add_mailbox(h, n);
    let raw = h.store.raw();
    raw.execute(
        "INSERT INTO public_rooms (box, room, creator, epoch, epoch_seq, group_info, tree,
         members, topic, guests) VALUES (?, ?, 'op@example.org', 3, 7, x'00', x'00', ?, ?, ?)",
        rusqlite::params![
            &mailbox.as_bytes()[..],
            room,
            members.len() as i64,
            topic,
            guests
        ],
    )
    .unwrap();
    for (uid, role) in members {
        raw.execute(
            "INSERT INTO room_members (box, uid, role) VALUES (?, ?, ?)",
            rusqlite::params![&mailbox.as_bytes()[..], uid, role],
        )
        .unwrap();
    }
    mailbox
}

/// Stores a kept post, as POST would.
pub(super) fn add_post(h: &Harness, mailbox: &BoxName, seq: u64, message: &[u8]) {
    h.store
        .raw()
        .execute(
            "INSERT INTO posts (box, seq, t, message) VALUES (?, ?, ?, ?)",
            rusqlite::params![
                &mailbox.as_bytes()[..],
                seq as i64,
                1_794_225_600_000i64,
                message
            ],
        )
        .unwrap();
}

/// An MLS PrivateMessage of `content_type` with `aad`, as the server sees
/// it (12.2).
pub(super) fn private_message(content_type: u8, aad: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.fixed(&1u16.to_be_bytes()).fixed(&2u16.to_be_bytes());
    w.vector(&[4; 32]).u64(7).u8(content_type).vector(aad);
    w.vector(b"sender").vector(b"ciphertext");
    w.finish()
}

/// An application message from the leaf with `pseudonym`, franked for
/// `content` with `frank_key` (12.9).
pub(super) fn franked(pseudonym: u8, frank_key: &[u8; 32], content: &[u8]) -> Vec<u8> {
    let tag: [u8; 48] = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA384, frank_key), content)
        .as_ref()
        .try_into()
        .unwrap();
    let aad = RisalaAad::application(MlsPseudonym([pseudonym; 16]), tag);
    private_message(1, &aad.encode())
}

/// A RisalaReport, in base64 (5.8).
pub(super) fn report_b64(
    target: (u64, [u8; 32], &[u8]),
    context: &[(u64, [u8; 32], &[u8])],
    author: &str,
    reason: &str,
) -> String {
    let post = |w: &mut Writer, (seq, key, content): &(u64, [u8; 32], &[u8])| {
        w.u64(*seq).fixed(key).vector(content);
    };
    let mut ctx = Writer::new();
    for p in context {
        post(&mut ctx, p);
    }
    let mut w = Writer::new();
    w.u8(1);
    post(&mut w, &target);
    w.vector(&ctx.finish())
        .vector(author.as_bytes())
        .vector(reason.as_bytes());
    risala_proto::binary::ReportData::from_bytes(&w.finish())
        .unwrap()
        .to_string()
}

fn presence_timers() -> Timers {
    Timers {
        presence_offline: Duration::from_millis(300),
        presence_batch: Duration::from_millis(20),
        ..timers()
    }
}

async fn wait(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

// ---------------------------------------------------------------------------
// INFO (8.5) and public rooms (6.1)

#[tokio::test]
async fn info_on_every_kind_of_connection() {
    let mut h = Harness::new();
    let mut new = h.connect();
    h.send(&new, "INFO").await;
    let want =
        "OK version=1 anon=yes guests=yes register=no log=no retention=30 push=yes upload=no";
    assert_eq!(new.lines(), [want]);
    let mut anon = h.anon().await;
    h.send(&anon, "@ref=i INFO").await;
    assert_eq!(anon.lines(), [format!("@ref=i {want}")]);
    // INFO <room> needs a kind (Section 13).
    h.send(&new, "INFO #general").await;
    assert_eq!(new.lines(), ["ERR not-authenticated"]);
}

#[tokio::test]
async fn info_follows_the_settings() {
    let mut config = Config::parse(
        r##"
        hostname = "chat.example.org"
        identity_domain = "example.org"
        operators = ["op@example.org"]
        [server]
        registration = true
        guests = false
        retention = 7
        [push]
        enabled = false
        "##,
    )
    .unwrap();
    config.state_dir = std::env::temp_dir();
    let mut h = Harness::with(config, timers());
    let mut c = h.connect();
    h.send(&c, "INFO").await;
    assert_eq!(
        c.lines(),
        [
            "OK version=1 anon=yes guests=no register=example.org log=no retention=7 push=no upload=no"
        ]
    );
    // Closed registration is register=no (8.5), and ADMIN SET shows at once.
    let mut op = h.signed_in_as("op@example.org");
    h.send(&op, "ADMIN SET registration closed").await;
    h.send(&op, "ADMIN SET anon no").await;
    assert_eq!(op.lines(), ["OK", "OK"]);
    h.send(&c, "INFO").await;
    assert_eq!(
        c.lines(),
        ["OK version=1 anon=no guests=no register=no log=no retention=7 push=no upload=no"]
    );
    // Without push, PUSH is not supported.
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, "PUSH LIST").await;
    assert_eq!(alice.lines(), ["ERR not-supported"]);
}

#[tokio::test]
async fn list_pages_rooms_in_order_and_hides_guestless_rooms_from_guests() {
    let config = {
        let mut c = config();
        c.limits.max_list = 3;
        c
    };
    let mut h = Harness::with(config, timers());
    let general = add_room(
        &h,
        "#general",
        1,
        "write",
        "Hello\\sall",
        &[("a@x.org", "owner")],
    );
    add_room(&h, "#zeta", 2, "read", "", &[]);
    add_room(
        &h,
        "#alpha",
        3,
        "none",
        "staff",
        &[("a@x.org", "owner"), ("b@x.org", "member")],
    );
    add_room(&h, "#beta", 4, "write", "", &[]);
    // A mailbox that is not a public room is never listed.
    add_mailbox(&h, 5);
    let b = |n: u8| BoxName::from_bytes([n; 16]).to_string();

    let mut anon = h.anon().await;
    h.send(&anon, "LIST limit=2").await;
    assert_eq!(
        anon.lines(),
        [
            format!("ROOM #alpha {} 2 staff", b(3)),
            format!("ROOM #beta {} 0", b(4)),
            "OK more=1".into(),
        ]
    );
    h.send(&anon, "LIST after=#beta").await;
    assert_eq!(
        anon.lines(),
        [
            format!("ROOM #general {general} 1 Hello\\sall"),
            format!("ROOM #zeta {} 0", b(2)),
            "OK more=0".into(),
        ]
    );
    // The server's cap (limits.max_list) and an after= that is no room.
    h.send(&anon, "LIST").await;
    assert_eq!(anon.lines().len(), 4);
    h.send(&anon, "LIST after=#b").await;
    assert_eq!(anon.lines()[0], format!("ROOM #beta {} 0", b(4)));
    h.send(&anon, "LIST after=#zz").await;
    assert_eq!(anon.lines(), ["OK more=0"]);

    // A guest does not see #alpha, whose guests setting is none (6.1).
    let (mut sam, _) = h.guest("sam").await;
    h.send(&sam, "LIST").await;
    let lines = sam.lines();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert!(lines.iter().all(|l| !l.contains("#alpha")), "{lines:?}");
    h.send(&sam, "INFO #alpha").await;
    h.send(&sam, "MEMBERS #alpha").await;
    assert_eq!(sam.lines(), ["ERR not-found", "ERR not-found"]);

    // An operator's ADMIN ROOMS lists them all (10.4).
    let mut op = h.signed_in_as("op@example.org");
    h.send(&op, "ADMIN ROOMS limit=1").await;
    assert_eq!(
        op.lines(),
        [format!("ROOM #alpha {} 2 staff", b(3)), "OK more=1".into()]
    );
}

#[tokio::test]
async fn info_of_a_room_and_its_members() {
    let mut h = Harness::with(config(), presence_timers());
    let general = add_room(
        &h,
        "#general",
        1,
        "write",
        "",
        &[
            ("alice@example.org", "owner"),
            ("bob@example.org", "mod"),
            ("~sam", "member"),
        ],
    );
    let mut anon = h.anon().await;
    h.send(&anon, "INFO #General").await;
    assert_eq!(
        anon.lines(),
        [format!("OK box={general} members=3 epoch=3")]
    );
    h.send(&anon, "INFO #nope").await;
    h.send(&anon, "MEMBERS #nope").await;
    assert_eq!(anon.lines(), ["ERR not-found", "ERR not-found"]);

    // Alice is online with presence on; Bob is online with it off; guests
    // have no presence (8.3).
    let alice = sign_in(&mut h, "alice@example.org").await;
    h.send(&alice, "PRESENCE ON").await;
    let _bob = sign_in(&mut h, "bob@example.org").await;
    h.send(&anon, "MEMBERS #general").await;
    assert_eq!(
        anon.lines(),
        [
            "MEMBER #general alice@example.org owner online",
            "MEMBER #general bob@example.org mod offline",
            "MEMBER #general ~sam member offline",
            "OK",
        ]
    );
}

// ---------------------------------------------------------------------------
// Presence (8.3)

#[tokio::test]
async fn presence_is_off_until_turned_on() {
    let mut h = Harness::with(config(), presence_timers());
    let mut watcher = h.anon().await;
    let mut alice = sign_in(&mut h, "alice@example.org").await;
    h.send(&watcher, "WATCH alice@example.org,bob@example.org")
        .await;
    assert_eq!(
        watcher.lines(),
        [
            "USER alice@example.org offline",
            "USER bob@example.org offline",
            "OK"
        ]
    );
    // Only a signed-in connection may turn it on (Section 13).
    h.send(&watcher, "PRESENCE ON").await;
    assert_eq!(watcher.lines(), ["ERR wrong-connection"]);

    h.send(&alice, "PRESENCE ON").await;
    assert_eq!(alice.lines(), ["OK"]);
    wait(80).await;
    assert_eq!(watcher.lines(), ["PRESENCE online alice@example.org"]);
    assert!(
        h.store
            .presence_on(&"alice@example.org".parse().unwrap())
            .unwrap()
    );

    // Off: reported offline to everyone, without the offline delay.
    h.send(&alice, "PRESENCE OFF").await;
    wait(80).await;
    assert_eq!(watcher.lines(), ["PRESENCE offline alice@example.org"]);
    h.send(&watcher, "WHOIS alice@example.org").await;
    assert_eq!(watcher.lines(), ["ERR not-found"]);
}

#[tokio::test]
async fn changes_are_batched_and_the_offline_delay_hides_reconnects() {
    let mut h = Harness::with(config(), presence_timers());
    for uid in ["alice@example.org", "bob@example.org"] {
        h.store.set_presence(&uid.parse().unwrap(), true).unwrap();
    }
    let mut watcher = h.anon().await;
    h.send(&watcher, "WATCH alice@example.org,bob@example.org,~sam")
        .await;
    assert_eq!(watcher.lines().len(), 4);
    let alice = sign_in(&mut h, "alice@example.org").await;
    let bob = sign_in(&mut h, "bob@example.org").await;
    wait(80).await;
    assert_eq!(
        watcher.lines(),
        ["PRESENCE online alice@example.org,bob@example.org"]
    );

    // Alice's client reconnects within the delay: nobody hears of it.
    h.close(alice).await;
    wait(80).await;
    assert!(watcher.lines().is_empty());
    let alice = sign_in(&mut h, "alice@example.org").await;
    wait(400).await;
    assert!(watcher.lines().is_empty());

    // A second connection keeps her online when the first closes.
    let alice2 = sign_in(&mut h, "alice@example.org").await;
    h.close(alice).await;
    wait(400).await;
    assert!(watcher.lines().is_empty());

    // Gone for longer than the delay: offline, after it.
    h.close(alice2).await;
    h.close(bob).await;
    wait(150).await;
    assert!(watcher.lines().is_empty());
    wait(300).await;
    assert_eq!(
        watcher.lines(),
        ["PRESENCE offline alice@example.org,bob@example.org"]
    );

    // A cleared list hears nothing more.
    h.send(&watcher, "WATCH").await;
    assert_eq!(watcher.lines(), ["OK"]);
    let _alice = sign_in(&mut h, "alice@example.org").await;
    wait(80).await;
    assert!(watcher.lines().is_empty());
}

#[tokio::test]
async fn watch_takes_a_thousand_uids_and_whois_knows_who_signed_in() {
    let mut h = Harness::with(config(), presence_timers());
    let mut watcher = h.anon().await;
    let uids: Vec<risala_proto::names::Uid> = (0..=1000)
        .map(|i| format!("u{i}@example.org").parse().unwrap())
        .collect();
    h.hub
        .command(
            watcher.id,
            Request::new(Command::Watch {
                uids: uids[..1000].to_vec(),
            }),
        )
        .await;
    let lines = watcher.lines();
    assert_eq!(lines.len(), 1001);
    assert_eq!(lines[1000], "OK");
    h.hub
        .command(watcher.id, Request::new(Command::Watch { uids }))
        .await;
    assert_eq!(watcher.lines(), ["ERR too-long at most 1000 uids"]);

    // WHOIS: not-found for identities that never signed in here, and for
    // guests, which have no presence (8.3).
    h.send(&watcher, "WHOIS carol@example.org").await;
    h.send(&watcher, "WHOIS ~sam").await;
    assert_eq!(watcher.lines(), ["ERR not-found", "ERR not-found"]);
    use crate::store::IdentityStore as _;
    h.store
        .note_sign_in(&"carol@example.org".parse().unwrap(), T.parse().unwrap())
        .unwrap();
    h.send(&watcher, "@ref=w WHOIS carol@example.org").await;
    assert_eq!(
        watcher.lines(),
        ["@ref=w USER carol@example.org offline", "@ref=w OK"]
    );
    h.store
        .set_presence(&"carol@example.org".parse().unwrap(), true)
        .unwrap();
    let _carol = sign_in(&mut h, "carol@example.org").await;
    h.send(&watcher, "WHOIS carol@example.org").await;
    assert_eq!(watcher.lines(), ["USER carol@example.org online", "OK"]);
}

// ---------------------------------------------------------------------------
// Push (9)

/// Records pushes instead of sending them, and answers with `status`.
pub(super) struct Recorder {
    pub(super) pushes: Mutex<Vec<PushRequest>>,
    pub(super) status: Mutex<u16>,
}

impl Recorder {
    pub(super) fn new() -> Arc<Recorder> {
        Arc::new(Recorder {
            pushes: Mutex::default(),
            status: Mutex::new(201),
        })
    }

    pub(super) fn take(&self) -> Vec<PushRequest> {
        std::mem::take(&mut *self.pushes.lock().unwrap())
    }
}

impl PushTransport for Recorder {
    fn send<'a>(&'a self, push: &'a PushRequest) -> BoxFuture<'a, Result<u16, SendError>> {
        self.pushes.lock().unwrap().push(push.clone());
        let status = *self.status.lock().unwrap();
        Box::pin(std::future::ready(Ok(status)))
    }
}

/// A subscription's keys: the private key, and its public key and secret
/// as PUSH ADD sends them.
pub(super) struct Keys {
    pub(super) private: agreement::PrivateKey,
    pub(super) key: PushKey,
    pub(super) auth: PushAuth,
}

impl Keys {
    pub(super) fn new() -> Keys {
        let private = agreement::PrivateKey::generate(&agreement::ECDH_P256).unwrap();
        let public: [u8; 65] = private
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        Keys {
            private,
            key: PushKey::from_bytes(public),
            auth: PushAuth::from_bytes([5; 16]),
        }
    }

    /// The body of `push`, decrypted.
    pub(super) fn open(&self, push: &PushRequest) -> String {
        assert_eq!(push.body.len(), crate::push::BODY_LEN);
        let plain = crate::push::decrypt(&push.body, &self.private, self.auth.as_bytes()).unwrap();
        String::from_utf8(plain).unwrap()
    }
}

fn push_timers() -> Timers {
    Timers {
        push_delay: Duration::ZERO,
        push_interval: Duration::from_millis(300),
        push_liveness: Duration::from_millis(100),
        ..timers()
    }
}

fn push_harness(config: Config) -> (Harness, Arc<Recorder>) {
    let h = Harness::with(config, push_timers());
    let recorder = Recorder::new();
    h.inner().misc.push.set_transport(recorder.clone());
    (h, recorder)
}

#[tokio::test]
async fn mailbox_subscriptions_are_checked_limited_and_replaced() {
    let mut config = config();
    config.push.max_per_mailbox = 2;
    config.push.max_per_connection = 3;
    let (mut h, _) = push_harness(config);
    let mailbox = add_mailbox(&h, 1);
    let other = add_mailbox(&h, 2);
    let keys = Keys::new();
    let add = |url: &str, tag: &str, mailbox: &BoxName| {
        format!(
            "PUSH ADD {url} {tag} {} {} box={mailbox}",
            keys.key, keys.auth
        )
    };
    let mut anon = h.anon().await;
    h.send(&anon, &add("https://p.example/1", "t1", &mailbox))
        .await;
    h.send(&anon, &add("https://p.example/1", "t2", &mailbox))
        .await;
    h.send(&anon, &add("https://p.example/2", "t3", &mailbox))
        .await;
    // A third subscription for one mailbox is refused (9.1).
    h.send(&anon, &add("https://p.example/3", "t4", &mailbox))
        .await;
    assert_eq!(anon.lines(), ["OK", "OK", "OK", "ERR rate-limited"]);
    let subs = h
        .store
        .push_subscriptions(&PushTarget::Mailbox(mailbox), h.clock.now())
        .unwrap();
    let tags: Vec<&str> = subs.iter().map(|s| s.tag.as_str()).collect();
    assert_eq!(tags, ["t2", "t3"]);

    // The connection may add three, replacements not counted.
    h.send(&anon, &add("https://p.example/4", "t5", &other))
        .await;
    h.send(&anon, &add("https://p.example/5", "t6", &other))
        .await;
    assert_eq!(anon.lines(), ["OK", "ERR rate-limited"]);

    // A key that is not on P-256 is invalid; an unknown mailbox not found.
    let bad = format!(
        "PUSH ADD https://p.example/6 t {} {} box={other}",
        PushKey::from_bytes([4; 65]),
        keys.auth
    );
    let mut fresh = h.anon().await;
    h.send(&fresh, &bad).await;
    let unknown = BoxName::from_bytes([9; 16]);
    h.send(&fresh, &add("https://p.example/7", "t", &unknown))
        .await;
    assert_eq!(
        fresh.lines(),
        ["ERR invalid not a P-256 public key", "ERR not-found"]
    );

    // PUSH DEL.
    h.send(
        &fresh,
        &format!("PUSH DEL https://p.example/2 box={mailbox}"),
    )
    .await;
    h.send(
        &fresh,
        &format!("PUSH DEL https://p.example/2 box={mailbox}"),
    )
    .await;
    assert_eq!(fresh.lines(), ["OK", "ERR not-found"]);

    // Guests cannot register for push, and mailbox subscriptions are made
    // on anonymous connections (9.1, Section 13).
    let (mut sam, _) = h.guest("sam").await;
    h.send(&sam, &add("https://p.example/8", "t", &mailbox))
        .await;
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, &add("https://p.example/8", "t", &mailbox))
        .await;
    assert_eq!(sam.lines(), ["ERR wrong-connection"]);
    assert_eq!(alice.lines(), ["ERR wrong-connection"]);
}

#[tokio::test]
async fn mailbox_subscriptions_last_one_retention_period() {
    let (mut h, _) = push_harness(config());
    let mailbox = add_mailbox(&h, 1);
    let keys = Keys::new();
    let add = format!(
        "PUSH ADD https://p.example/1 t1 {} {} box={mailbox}",
        keys.key, keys.auth
    );
    let mut anon = h.anon().await;
    h.send(&anon, &add).await;
    let target = PushTarget::Mailbox(mailbox);
    // Renewed after 20 days, it lasts until 30 days after the renewal.
    h.clock.advance(Duration::from_secs(20 * 86_400));
    h.send(&anon, &add).await;
    assert_eq!(anon.lines(), ["OK", "OK"]);
    h.clock.advance(Duration::from_secs(29 * 86_400));
    misc::push::maintain_once(h.inner()).await;
    assert_eq!(
        h.store
            .push_subscriptions(&target, h.clock.now())
            .unwrap()
            .len(),
        1
    );
    h.clock.advance(Duration::from_secs(2 * 86_400));
    assert!(
        h.store
            .push_subscriptions(&target, h.clock.now())
            .unwrap()
            .is_empty()
    );
    misc::push::maintain_once(h.inner()).await;
    let left: i64 = h
        .store
        .raw()
        .query_row("SELECT count(*) FROM push_subscriptions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn kept_posts_push_encrypted_bodies_at_most_every_interval() {
    let (mut h, recorder) = push_harness(config());
    let mailbox = add_mailbox(&h, 1);
    let other = add_mailbox(&h, 2);
    let keys = Keys::new();
    let mut anon = h.anon().await;
    for (mailbox, tag) in [(&mailbox, "x7Hq2"), (&other, "y8")] {
        h.send(
            &anon,
            &format!(
                "PUSH ADD https://p.example/same {tag} {} {} box={mailbox}",
                keys.key, keys.auth
            ),
        )
        .await;
    }
    assert_eq!(anon.lines(), ["OK", "OK"]);

    misc::post_kept(h.inner(), mailbox);
    misc::post_kept(h.inner(), mailbox);
    wait(100).await;
    let pushes = recorder.take();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert_eq!(pushes[0].url.as_str(), "https://p.example/same");
    assert_eq!(pushes[0].urgency, "normal");
    assert_eq!(keys.open(&pushes[0]), "NOTIFY x7Hq2 message\n");

    // Within the interval, the next post waits for it; so does a push to
    // the same URL for another mailbox (9.2).
    misc::post_kept(h.inner(), mailbox);
    misc::post_kept(h.inner(), other);
    wait(100).await;
    assert!(recorder.take().is_empty());
    wait(300).await;
    let pushes = recorder.take();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    wait(350).await;
    let more = recorder.take();
    assert_eq!(more.len(), 1, "{more:?}");
    let mut bodies = vec![keys.open(&pushes[0]), keys.open(&more[0])];
    bodies.sort();
    assert_eq!(bodies, ["NOTIFY x7Hq2 message\n", "NOTIFY y8 message\n"]);
}

#[tokio::test]
async fn quiet_followers_that_are_alive_hold_pushes_back() {
    let (mut h, recorder) = push_harness(config());
    let mailbox = add_mailbox(&h, 1);
    let keys = Keys::new();
    let mut anon = h.anon().await;
    h.send(
        &anon,
        &format!(
            "PUSH ADD https://p.example/1 qtag {} {} box={mailbox}",
            keys.key, keys.auth
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["OK"]);
    let tag: PushTag = "qtag".parse().unwrap();

    // A follower with another tag does not hold it back.
    let mut reader = h.anon().await;
    misc::follow_quiet(
        h.inner(),
        reader.id,
        mailbox,
        Some("other".parse().unwrap()),
    );
    misc::post_kept(h.inner(), mailbox);
    wait(80).await;
    assert_eq!(recorder.take().len(), 1);

    // One that follows with the tag, and was heard from within the check,
    // holds it back without a PING (9.2).
    wait(300).await;
    misc::follow_quiet(h.inner(), reader.id, mailbox, Some(tag.clone()));
    misc::post_kept(h.inner(), mailbox);
    wait(200).await;
    assert!(recorder.take().is_empty());
    assert!(reader.lines().is_empty());

    // Quiet for longer: it gets a PING, and any line within the check
    // holds the push back.
    misc::post_kept(h.inner(), mailbox);
    wait(50).await;
    assert_eq!(reader.lines(), ["PING push"]);
    h.send(&reader, "PONG push").await;
    wait(150).await;
    assert!(recorder.take().is_empty());

    // No answer: the push goes out as if nobody followed.
    wait(150).await;
    misc::post_kept(h.inner(), mailbox);
    wait(50).await;
    assert_eq!(reader.lines(), ["PING push"]);
    wait(150).await;
    assert_eq!(recorder.take().len(), 1);

    // Unfollowed, nothing holds it back, and no PING is sent.
    misc::unfollow(h.inner(), reader.id, &mailbox);
    wait(350).await;
    misc::post_kept(h.inner(), mailbox);
    wait(80).await;
    assert_eq!(recorder.take().len(), 1);
    assert!(reader.lines().is_empty());
}

#[tokio::test]
async fn account_subscriptions_wake_devices_that_are_not_connected() {
    let (mut h, recorder) = push_harness(config());
    let keys = Keys::new();
    let mut alice = h.signed_in_as("alice@example.org");
    let add = format!(
        "PUSH ADD https://p.example/w wtag {} {}",
        keys.key, keys.auth
    );
    h.send(&alice, &add).await;
    h.send(&alice, "PUSH LIST").await;
    assert_eq!(alice.lines(), ["OK", "PUSH https://p.example/w wtag", "OK"]);
    let uid: risala_proto::names::Uid = "alice@example.org".parse().unwrap();
    let device = DeviceId::of(&risala_proto::auth::PublicKey::from_bytes(
        &[7; risala_proto::auth::PUBLIC_KEY_LEN],
    ));
    // While the device is signed in, it gets no push (9.2).
    misc::welcome_arrived(h.inner(), &uid, device);
    wait(80).await;
    assert!(recorder.take().is_empty());
    h.close(alice).await;
    misc::welcome_arrived(h.inner(), &uid, device);
    wait(80).await;
    let pushes = recorder.take();
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].urgency, "high");
    assert_eq!(keys.open(&pushes[0]), "NOTIFY wtag welcome\n");

    // 410: the subscription is deleted (9.3).
    *recorder.status.lock().unwrap() = 410;
    wait(350).await;
    misc::welcome_arrived(h.inner(), &uid, device);
    wait(80).await;
    assert_eq!(recorder.take().len(), 1);
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, "PUSH LIST").await;
    h.send(&alice, "PUSH DEL https://p.example/w").await;
    assert_eq!(alice.lines(), ["OK", "ERR not-found"]);

    // Removing the device removes its account subscriptions (9.1).
    h.send(&alice, &add).await;
    misc::device_removed(h.inner(), device).await;
    h.send(&alice, "PUSH LIST").await;
    assert_eq!(alice.lines(), ["OK", "OK"]);
}

#[tokio::test]
async fn failing_subscriptions_are_retried_then_dropped_after_a_day() {
    let (mut h, recorder) = push_harness(config());
    let mailbox = add_mailbox(&h, 1);
    let keys = Keys::new();
    let mut anon = h.anon().await;
    h.send(
        &anon,
        &format!(
            "PUSH ADD https://p.example/1 t {} {} box={mailbox}",
            keys.key, keys.auth
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["OK"]);
    *recorder.status.lock().unwrap() = 503;
    misc::post_kept(h.inner(), mailbox);
    wait(80).await;
    assert_eq!(recorder.take().len(), 1);
    let target = PushTarget::Mailbox(mailbox);
    let sub = h.store.push_subscriptions(&target, h.clock.now()).unwrap();
    assert_eq!(sub[0].failing_since, Some(h.clock.now()));

    // A day of failures later, the next failure deletes it.
    h.clock.advance(Duration::from_secs(86_400));
    let id = sub[0].id;
    // The retry is far off; a new push goes out once it is due.
    misc::push::deliver_now(h.inner(), id).await;
    assert_eq!(recorder.take().len(), 1);
    assert!(h.store.push_subscription(id).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Reports (5.8)

fn report_config(per_hour: u32) -> Config {
    let mut c = config();
    c.limits.reports_per_hour = per_hour;
    c
}

#[tokio::test]
async fn reports_are_checked_and_reach_the_operators() {
    let mut h = Harness::with(report_config(30), timers());
    let mailbox = add_mailbox(&h, 1);
    let (k1, k2, k3) = ([1; 32], [2; 32], [3; 32]);
    let (c1, c2, c3): (&[u8], &[u8], &[u8]) = (b"TEXT hi\n", b"TEXT you\n", b"TEXT spam\n");
    add_post(&h, &mailbox, 3, &franked(8, &k1, c1));
    add_post(&h, &mailbox, 5, &franked(8, &k2, c2));
    add_post(&h, &mailbox, 9, &franked(6, &k3, c3));
    let commit = private_message(3, &RisalaAad::handshake(MlsPseudonym([6; 16])).encode());
    add_post(&h, &mailbox, 10, &commit);

    let mut op = h.signed_in_as("op@example.org");
    let mut reporter = h.anon().await;
    let ok = report_b64(
        (9, k3, c3),
        &[(3, k1, c1), (5, k2, c2)],
        "bob@example.org",
        "spam",
    );
    h.send(&reporter, &format!("REPORT {mailbox} {ok}")).await;
    let lines = reporter.lines();
    assert_eq!(lines.len(), 1);
    let id = value(&lines[0], "id");
    assert_eq!(lines[0], format!("OK id={id}"));
    // The operators get the line, with the target's pseudonym and no from=.
    let pseudonym = risala_proto::mls::Pseudonym::from_bytes([6; 16]);
    assert_eq!(
        op.lines(),
        [format!(
            "@report={id};t={T};pseudonym={pseudonym} REPORT {mailbox} {ok}"
        )]
    );

    // Checks (5.8): not-found for a post not kept; invalid for a wrong
    // frank, a post that is not an application message, a malformed
    // report.
    let cases = [
        (
            report_b64((11, k3, c3), &[], "b@x.org", ""),
            "ERR not-found",
        ),
        (
            report_b64((9, k3, c3), &[(4, k1, c1)], "b@x.org", ""),
            "ERR not-found",
        ),
        (
            report_b64((9, k3, b"TEXT edited\n"), &[], "b@x.org", ""),
            "ERR invalid the franking tag does not match",
        ),
        (
            report_b64((9, k1, c3), &[], "b@x.org", ""),
            "ERR invalid the franking tag does not match",
        ),
        (
            report_b64((10, k3, c3), &[], "b@x.org", ""),
            "ERR invalid not an application message",
        ),
        (
            report_b64((9, k3, c3), &[(5, k2, c2), (3, k1, c1)], "b@x.org", ""),
            "ERR invalid context seqs must increase and come before the target",
        ),
        (
            report_b64((9, k3, c3), &[], "nobody", ""),
            "ERR invalid the author is not a uid",
        ),
        ("AQID".to_owned(), "ERR invalid "),
    ];
    for (report, want) in cases {
        h.send(&reporter, &format!("REPORT {mailbox} {report}"))
            .await;
        let got = reporter.lines();
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].starts_with(want), "{got:?} != {want}");
    }
    assert!(op.lines().is_empty());

    // A signed-in reporter, and a guest, may report too; from= names only
    // the signed-in one.
    let mut alice = h.signed_in_as("alice@example.org");
    let short = report_b64((5, k2, c2), &[], "carol@example.org", "");
    h.send(&alice, &format!("REPORT {mailbox} {short}")).await;
    let id2 = value(&alice.lines()[0], "id");
    let reports = op.messages();
    let ServerLine::Report(r) = &reports[0].line else {
        panic!("{reports:?}")
    };
    assert_eq!(
        r.from.as_ref().map(|u| u.as_str()),
        Some("alice@example.org")
    );
    assert_eq!(r.id.as_str(), id2);
    let (mut sam, _) = h.guest("sam").await;
    h.send(&sam, &format!("REPORT {mailbox} {short}")).await;
    assert!(sam.lines()[0].starts_with("OK id="));
    let ServerLine::Report(r) = &op.messages()[0].line else {
        panic!()
    };
    assert_eq!(r.from, None);

    // The copies outlive the posts (5.8).
    h.store.raw().execute("DELETE FROM posts", []).unwrap();
    h.send(&op, "ADMIN REPORTS").await;
    let lines = op.lines();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert!(lines[0].starts_with(&format!("@report={id};")), "{lines:?}");
    let copies: i64 = h
        .store
        .raw()
        .query_row("SELECT count(*) FROM report_posts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(copies, 5);
}

#[tokio::test]
async fn reports_are_resolved_by_operators_only() {
    let mut h = Harness::with(report_config(30), timers());
    let mailbox = add_mailbox(&h, 1);
    add_post(&h, &mailbox, 1, &franked(8, &[1; 32], b"TEXT x\n"));
    let mut op = h.signed_in_as("op@example.org");
    let mut op2 = h.signed_in_as("op@example.org");
    let mut alice = h.signed_in_as("alice@example.org");
    let report = report_b64((1, [1; 32], b"TEXT x\n"), &[], "b@x.org", "");
    h.send(&alice, &format!("REPORT {mailbox} {report}")).await;
    let id = value(&alice.lines()[0], "id");
    assert_eq!(op.lines().len(), 1);
    assert_eq!(op2.lines().len(), 1);
    // Someone who is not an operator gets not-found, as for no report.
    h.send(&alice, &format!("RESOLVE {id}")).await;
    assert_eq!(alice.lines(), ["ERR not-found"]);
    let mut anon = h.anon().await;
    h.send(&anon, &format!("RESOLVE {id}")).await;
    assert_eq!(anon.lines(), ["ERR wrong-connection"]);
    // An operator resolves it; the other operators' connections hear.
    h.send(&op, &format!("RESOLVE {id}")).await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(op2.lines(), [format!("RESOLVED {id}")]);
    assert!(alice.lines().is_empty());
    h.send(&op, &format!("RESOLVE {id}")).await;
    h.send(&op, "ADMIN REPORTS").await;
    assert_eq!(op.lines(), ["ERR not-found", "OK"]);
    let copies: i64 = h
        .store
        .raw()
        .query_row("SELECT count(*) FROM report_posts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(copies, 0);
}

#[tokio::test]
async fn reports_are_rate_limited() {
    let mut h = Harness::with(report_config(2), timers());
    let mailbox = add_mailbox(&h, 1);
    add_post(&h, &mailbox, 1, &franked(8, &[1; 32], b"TEXT x\n"));
    let report = report_b64((1, [1; 32], b"TEXT x\n"), &[], "b@x.org", "");
    let line = format!("REPORT {mailbox} {report}");
    // Anonymous connections count by network, whichever connection.
    let mut one = h.anon().await;
    let mut two = h.anon().await;
    h.send(&one, &line).await;
    h.send(&two, &line).await;
    assert!(one.lines()[0].starts_with("OK id="));
    assert!(two.lines()[0].starts_with("OK id="));
    h.send(&one, &line).await;
    let got = one.lines();
    assert!(
        got[0].starts_with("@retry=") && got[0].ends_with("ERR rate-limited"),
        "{got:?}"
    );
    // A failed report does not use up a slot; an identity has its own.
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, &format!("REPORT {mailbox} AQID")).await;
    h.send(&alice, &line).await;
    h.send(&alice, &line).await;
    let got = alice.lines();
    assert_eq!(got.len(), 3);
    assert!(
        got[1].starts_with("OK") && got[2].starts_with("OK"),
        "{got:?}"
    );
}

/// A typed check that report lines parse back, with `pseudonym=` (5.8).
#[test]
fn report_lines_parse_back() {
    let line: ServerMessage = "@report=k3f9q2;t=2026-11-09T12:00:00.000Z;pseudonym=BgYGBgYGBgYGBgYGBgYGBg==;from=alice@example.org REPORT ujzdegxdncf32epf3dhodzdoci AQID"
        .parse()
        .unwrap();
    assert!(matches!(line.line, ServerLine::Report(_)));
}

//! M5b's goal against a whole `risalad` (task C5): devices talk in an
//! encrypted direct conversation and a private room over anonymous
//! connections; a third device is paired by QR text and gets the history
//! by transfer; an identity is recovered from its recovery key; and every
//! key file record a device accepts has a witnessed inclusion proof.
//!
//! The server keeps its key log and witnesses it (risala-dev's world). The
//! log takes a checkpoint at most every 10 seconds, so the test waits for
//! each new record; it takes a few minutes.

use std::sync::Arc;
use std::time::Duration;

use librisala::client::ConnectionState;
use librisala::client::conversations::ConversationKind;
use librisala::client::identity::{Contact, KeyFetcherHttps};
use librisala::client::types::ConversationId;
use librisala::conn::{SessionOptions, Slot};
use librisala::keyfetch::{FetchOptions, KeyFetcher, Roots, StaticResolver};
use librisala::store::AccountId;
use librisala::{Client, ClientOptions, Event};
use risala_dev::{HOST, World};

struct Env {
    world: World,
    https: Arc<KeyFetcherHttps>,
    files: Arc<dyn librisala::client::files::FileHttps>,
    dir: tempfile::TempDir,
}

async fn env() -> Env {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let world = World::start().await;
    let mut resolver = StaticResolver::new();
    for (name, addr) in world.resolves() {
        resolver.insert(&name, [addr]);
    }
    let fetcher = KeyFetcher::new(FetchOptions {
        roots: Roots::Only(world.roots()),
        allow_private: true,
        min_refetch: Duration::ZERO,
        resolver: Arc::new(resolver),
        ..FetchOptions::default()
    });
    let files = librisala::client::files::TlsFileHttps::new(
        librisala::conn::roots_ca_verifier(world.roots()).expect("a CA check"),
    )
    .connect_to(world.resolves());
    Env {
        world,
        https: Arc::new(KeyFetcherHttps(fetcher)),
        files: Arc::new(files),
        dir: tempfile::tempdir().unwrap(),
    }
}

impl Env {
    fn client(&self, name: &str) -> Client {
        let options = ClientOptions {
            session: SessionOptions {
                connect_to: Some(self.world.server.addr()),
                ..Default::default()
            },
            https: Some(self.https.clone()),
            file_https: Some(self.files.clone()),
            download_dir: Some(self.dir.path().join(name)),
            // The spec's random waits of up to 10 minutes, cut to a second
            // or two.
            conversations: librisala::sync::conversations::Config {
                max_welcome_wait_ms: 1_000,
                max_follow_wait_ms: 1_000,
                max_commit_wait_ms: 1_000,
                retry_ms: 1_000,
                ..librisala::sync::conversations::Config::default()
            },
            maintenance_every: Duration::from_secs(5),
            ..ClientOptions::default()
        };
        let c = Client::open_in_memory(options).unwrap();
        c.accept_fingerprint(HOST, &self.world.server.fingerprint().to_string())
            .unwrap();
        c.set_witness_policy(std::slice::from_ref(&self.world.witness), 1)
            .unwrap();
        c
    }
}

/// Waits for `done`, polling every half second, for up to `secs`.
async fn eventually<T>(secs: u64, what: &str, mut done: impl FnMut() -> Option<T>) -> T {
    for _ in 0..secs * 2 {
        if let Some(t) = done() {
            return t;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("timed out: {what}");
}

/// Runs `f` until it succeeds, for up to a minute: a device that just
/// connected may not have uploaded its KeyPackages yet (12.5).
async fn retry<T, F: std::future::Future<Output = librisala::Result<T>>>(
    what: &str,
    mut f: impl FnMut() -> F,
) -> T {
    let mut last = None;
    for _ in 0..30 {
        match f().await {
            Ok(t) => return t,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("{what}: {last:?}");
}

/// Fetches `uid` until `done` holds of what the device knows, for up to
/// a minute and a half.
async fn until(c: &Client, uid: &str, done: impl Fn(&Contact) -> bool) -> Contact {
    for _ in 0..180 {
        let contact = c.refresh_identity(uid).await.unwrap();
        if done(&contact) {
            return contact;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{uid}: {:?}", c.refresh_identity(uid).await.unwrap());
}

/// Connects an account and waits for its signed-in connection.
async fn connect(c: &Client, account: AccountId) {
    let mut events = c.subscribe();
    c.connect(account).await.unwrap();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(30), events.recv())
            .await
            .expect("an event in time")
            .expect("events");
        if let Event::Connection(e) = event
            && e.account == account
            && e.slot == Slot::SignedIn
        {
            match e.state {
                ConnectionState::Ready => return,
                ConnectionState::Failed(why) => panic!("sign-in failed: {why}"),
                _ => {}
            }
        }
    }
}

fn texts(c: &Client, conv: ConversationId) -> Vec<String> {
    c.messages(conv, None, 1000)
        .unwrap()
        .into_iter()
        .filter_map(|m| m.text)
        .collect()
}

/// The conversation of `kind` named `name` (the peer's uid for a direct
/// one), once the device is in it.
fn find(
    c: &Client,
    account: AccountId,
    kind: ConversationKind,
    name: &str,
) -> Option<ConversationId> {
    c.conversations(account)
        .unwrap()
        .into_iter()
        .find(|s| s.kind == kind && s.name == name && s.active)
        .map(|s| s.id)
}

async fn new_identity(env: &Env, name: &str, label: &str) -> (Client, String, String, AccountId) {
    let c = env.client(&format!("{name}-{label}"));
    let new = c.create_identity(HOST, name, label).await.unwrap();
    let uid = new.uid.to_string();
    let recovery = new.recovery_key.to_string();
    until(&c, &uid, |k| {
        !k.devices.is_empty() && k.devices.iter().all(|d| d.accepted)
    })
    .await;
    let account = c.accounts().unwrap()[0].id;
    (c, uid, recovery, account)
}

/// Checks that every record the device accepted of `uid` is in a
/// checkpoint of its log that the world's witness cosigned, with an
/// inclusion proof from the log's tiles (4.5). Returns how many it
/// checked.
async fn witnessed_inclusion(env: &Env, c: &Client, uid: &str) -> usize {
    let mut checked = 0;
    for r in c
        .store()
        .records(uid)
        .unwrap()
        .iter()
        .filter(|r| r.accepted)
    {
        assert!(
            r.witnessed.is_some(),
            "{uid}: an accepted record not witnessed"
        );
        let index = r.log_index.expect("an accepted record has its index");
        env.world
            .check_witnessed(&r.log.0, &r.log.1, index, &r.record)
            .await
            .unwrap_or_else(|e| panic!("{uid}, record {index}: {e}"));
        checked += 1;
    }
    checked
}

fn has(c: &Client, conv: ConversationId, text: &str) -> Option<()> {
    texts(c, conv).iter().any(|t| t == text).then_some(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_goal_against_risalad() {
    let env = env().await;
    let (alice, alice_uid, _alice_recovery, alice_acc) =
        new_identity(&env, "alice", "laptop").await;
    let (bob, bob_uid, bob_recovery, bob_acc) = new_identity(&env, "bob", "laptop").await;
    connect(&alice, alice_acc).await;
    connect(&bob, bob_acc).await;

    // A direct conversation (5.1, 6.1, 12.7), over anonymous connections.
    let direct = retry("alice starts the direct conversation", || {
        alice.direct(alice_acc, &bob_uid)
    })
    .await;
    alice.send_text(direct, "hello bob", None).await.unwrap();
    let bob_direct = eventually(60, "bob joins the direct conversation", || {
        find(&bob, bob_acc, ConversationKind::Direct, &alice_uid)
    })
    .await;
    eventually(60, "bob reads alice", || has(&bob, bob_direct, "hello bob")).await;
    bob.send_text(bob_direct, "hello alice", None)
        .await
        .unwrap();
    eventually(60, "alice reads bob", || has(&alice, direct, "hello alice")).await;

    // A private room (6.1, 6.3): alice creates it and invites bob.
    let room = alice
        .create_private_room(alice_acc, "garden")
        .await
        .unwrap();
    alice.invite(room, &bob_uid).await.unwrap();
    alice
        .send_text(room, "welcome to the garden", None)
        .await
        .unwrap();
    let bob_room = eventually(60, "bob joins the room", || {
        find(&bob, bob_acc, ConversationKind::PrivateRoom, "garden")
    })
    .await;
    eventually(60, "bob reads the room", || {
        has(&bob, bob_room, "welcome to the garden")
    })
    .await;
    bob.send_text(bob_room, "thanks", None).await.unwrap();
    eventually(60, "alice reads the room", || has(&alice, room, "thanks")).await;

    // A third device, paired by QR text (4.8), gets the history by
    // transfer (12.13) once alice's laptop adds it to her groups.
    let phone = env.client("alice-phone");
    let offer = phone.start_pairing(HOST, "phone").await.unwrap();
    assert!(offer.qr.starts_with("RISALA-PAIR:"));
    let request = alice.scan_pairing(&alice_uid, &offer.qr).await.unwrap();
    assert_eq!(request.label, "phone");
    alice.confirm_pairing(&alice_uid, true).await.unwrap();
    let own = phone.finish_pairing().await.unwrap();
    assert_eq!(own.uid.to_string(), alice_uid);
    let phone_acc = phone.accounts().unwrap()[0].id;
    connect(&phone, phone_acc).await;
    let phone_direct = eventually(120, "the phone is added to the direct conversation", || {
        find(&phone, phone_acc, ConversationKind::Direct, &bob_uid)
    })
    .await;
    eventually(120, "the phone has the history", || {
        has(&phone, phone_direct, "hello bob")?;
        has(&phone, phone_direct, "hello alice")
    })
    .await;
    let phone_room = eventually(120, "the phone is added to the room", || {
        find(&phone, phone_acc, ConversationKind::PrivateRoom, "garden")
    })
    .await;
    phone
        .send_text(phone_direct, "from the phone", None)
        .await
        .unwrap();
    eventually(60, "bob reads the phone", || {
        has(&bob, bob_direct, "from the phone")
    })
    .await;
    eventually(60, "the laptop reads the phone", || {
        has(&alice, direct, "from the phone")
    })
    .await;
    eventually(120, "the phone has the room's history", || {
        has(&phone, phone_room, "welcome to the garden")
    })
    .await;

    // Bob names himself (8.2), a commit in each group. Alice's devices
    // have made the last commits, and 12.7's streak rule would hold a
    // fourth for 10 minutes.
    bob.set_display_name(bob_acc, "Bob").await.unwrap();
    for conv in [direct, room] {
        eventually(60, "alice sees bob's name", || {
            alice
                .members(conv)
                .unwrap()
                .iter()
                .any(|m| m.uid.as_str() == bob_uid && m.display_name.as_deref() == Some("Bob"))
                .then_some(())
        })
        .await;
    }

    // Bob loses his laptop and recovers on a new device (4.8): alice's
    // devices remove the laptop's leaves, and her laptop adds the new
    // device to the direct conversation (12.7, 12.14).
    let spare = env.client("bob-spare");
    let recovered = spare
        .recover(HOST, &bob_uid, &bob_recovery, "spare")
        .await
        .unwrap();
    until(&alice, &bob_uid, |k| {
        k.devices
            .iter()
            .any(|d| d.id == recovered.device && d.accepted)
    })
    .await;
    let spare_acc = spare.accounts().unwrap()[0].id;
    connect(&spare, spare_acc).await;
    let spare_direct = eventually(180, "the new device joins the direct conversation", || {
        find(&spare, spare_acc, ConversationKind::Direct, &alice_uid)
    })
    .await;
    spare
        .send_text(spare_direct, "back again", None)
        .await
        .unwrap();
    eventually(60, "alice reads the new device", || {
        has(&alice, direct, "back again")
    })
    .await;
    alice.send_text(direct, "welcome back", None).await.unwrap();
    eventually(60, "the new device reads alice", || {
        has(&spare, spare_direct, "welcome back")
    })
    .await;
    // The old laptop is out of the direct conversation.
    eventually(60, "the old laptop's leaf is removed", || {
        let leaves = alice.leaf_status(direct).unwrap();
        (!leaves.iter().any(|l| {
            l.uid.as_str() == bob_uid && l.device.map(|d| d.0) != Some(recovered.device.0)
        }))
        .then_some(())
    })
    .await;

    // A public room (6.1): alice creates it, bob's new device joins by
    // proposal, which alice's laptop commits, and they talk once their
    // ATTESTs pin their pseudonyms (7.3, 12.10).
    let plaza = retry("alice creates a public room", || {
        alice.create_public_room(alice_acc, "#plaza")
    })
    .await;
    let rooms = spare.list_public_rooms(spare_acc, None).await.unwrap();
    assert!(
        rooms.iter().any(|r| r.room.as_str() == "#plaza"),
        "{rooms:?}"
    );
    let spare_plaza = retry("bob joins the public room", || {
        spare.join_public_room(spare_acc, "#plaza")
    })
    .await;
    alice.send_text(plaza, "hello plaza", None).await.unwrap();
    eventually(120, "bob reads the public room", || {
        has(&spare, spare_plaza, "hello plaza")
    })
    .await;
    spare
        .send_text(spare_plaza, "hi from bob", None)
        .await
        .unwrap();
    eventually(120, "alice reads the public room", || {
        has(&alice, plaza, "hi from bob")
    })
    .await;

    // Every record each device accepted is in a witnessed checkpoint.
    let mut checked = 0;
    for (c, uids) in [
        (&alice, [&alice_uid, &bob_uid]),
        (&bob, [&alice_uid, &bob_uid]),
        (&phone, [&alice_uid, &bob_uid]),
        (&spare, [&alice_uid, &bob_uid]),
    ] {
        for uid in uids {
            checked += witnessed_inclusion(&env, c, uid).await;
        }
    }
    assert!(checked >= 10, "only {checked} records checked");
}

/// A public room between two identities whose records the log witnessed:
/// their messages show once their ATTESTs pin their pseudonyms (6.1, 7.3,
/// 12.10).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_public_room_against_risalad() {
    let env = env().await;
    let (alice, _alice_uid, _, alice_acc) = new_identity(&env, "alice", "laptop").await;
    let (bob, _bob_uid, _, bob_acc) = new_identity(&env, "bob", "laptop").await;
    connect(&alice, alice_acc).await;
    connect(&bob, bob_acc).await;
    let plaza = retry("alice creates a public room", || {
        alice.create_public_room(alice_acc, "#plaza")
    })
    .await;
    let bob_plaza = retry("bob joins the public room", || {
        bob.join_public_room(bob_acc, "#plaza")
    })
    .await;
    alice.send_text(plaza, "hello plaza", None).await.unwrap();
    eventually(120, "bob reads the public room", || {
        has(&bob, bob_plaza, "hello plaza")
    })
    .await;
    bob.send_text(bob_plaza, "hi from bob", None).await.unwrap();
    eventually(120, "alice reads the public room", || {
        has(&alice, plaza, "hi from bob")
    })
    .await;
}

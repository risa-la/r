//! Two clients talking through the driver, over TLS, to the group
//! engine's in-memory server ([`crate::sync::conversations::tests::server`])
//! behind a socket. It stands in for `risalad` until its mailbox and
//! Welcome areas (tasks SV3, SV4) land on `m5b`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_proto::command::{Command, Request};
use risala_proto::names::Identity;
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::super::*;
use crate::clock::Clock as _;
use crate::conn::tests::server::TestCa;
use crate::conn::{ConnectionPlan, End, IdentitySignIn, Slot, roots_ca_verifier};
use crate::keys::{KeyStore, MemoryKeyStore, generate_device_key, key_seed};
use crate::sync::conversations::Config;
use crate::sync::conversations::tests::server::FakeServer;

/// The fake server behind TLS: each connection is a task, and live lines
/// go to the others through their channels.
struct Shared {
    server: FakeServer,
    outbound: HashMap<(usize, Slot), mpsc::UnboundedSender<String>>,
    /// The device id of each identity, for AUTH: one device each.
    devices: HashMap<String, Vec<u8>>,
}

async fn serve(ca: &TestCa, shared: Arc<Mutex<Shared>>) -> std::net::SocketAddr {
    let cert = ca.issue("chat.test");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key = Arc::new(rustls::sign::CertifiedKey::new(cert.chain, cert.key));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(key)));
    config.alpn_protocols = vec![risala_proto::ALPN.to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut n = 0;
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            n += 1;
            let (acceptor, shared) = (acceptor.clone(), shared.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                connection(n, tls, shared).await;
            });
        }
    });
    addr
}

#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn render(message: ServerMessage) -> String {
    message.to_line().to_string()
}

async fn connection(
    n: usize,
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    shared: Arc<Mutex<Shared>>,
) {
    let (read, mut write) = tokio::io::split(tls);
    let mut lines = BufReader::new(read).lines();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if write
                .write_all(format!("{line}\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let _ = tx.send("RISALA 1 chat.test 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e hi".into());
    let mut conn = (n, Slot::Anonymous(0));
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(request) = line.parse::<Request>() else {
            continue;
        };
        let ref_ = request.ref_.clone();
        let reply = |end: ServerLine| {
            render(ServerMessage {
                ref_: ref_.clone(),
                line: end,
            })
        };
        let mut s = shared.lock().unwrap();
        match request.command {
            Command::Anon => {
                s.outbound.insert(conn, tx.clone());
                let _ = tx.send(reply(ServerLine::Ok(OkResponse::new())));
            }
            Command::Auth { identity, .. } => {
                conn = (n, Slot::SignedIn);
                let device = s.devices[identity.to_uid().as_str()].clone();
                s.server
                    .signed_in
                    .insert(conn, (identity.to_uid().to_string(), device));
                s.outbound.insert(conn, tx.clone());
                let _ = tx.send(reply(ServerLine::Ok(OkResponse::new())));
            }
            Command::Ping { .. } | Command::Pong { .. } | Command::Quit { .. } => {}
            command => {
                let (response, live) = s.server.handle(conn, command);
                for (to, message) in live {
                    if let Some(out) = s.outbound.get(&to) {
                        let _ = out.send(render(message));
                    }
                }
                for mut message in response.lines {
                    message.ref_ = ref_.clone();
                    let _ = tx.send(render(message));
                }
                let end = match response.end {
                    End::Ok(ok) => ServerLine::Ok(ok),
                    End::Err(e) => ServerLine::Err(e),
                    End::Unparseable(_) => unreachable!(),
                };
                let _ = tx.send(reply(end));
            }
        }
    }
    shared.lock().unwrap().server.close(conn);
}

struct Person {
    client: Client,
    account: crate::store::AccountId,
}

/// A client of `uid`, whose device key is in its key store under the
/// `key_id` of an `identities` row, as the identity area keeps it.
async fn person(
    uid: &str,
    ca: &TestCa,
    addr: std::net::SocketAddr,
    shared: &Arc<Mutex<Shared>>,
) -> Person {
    let keys = Arc::new(MemoryKeyStore::default());
    let key = generate_device_key().unwrap();
    keys.save(uid, &key).unwrap();
    let signing = risala_mls::mldsa::SigningKey::from_seed(*key_seed(&key));
    let device = signing.device_id();
    shared
        .lock()
        .unwrap()
        .devices
        .insert(uid.to_owned(), device.as_bytes().to_vec());
    let options = ClientOptions {
        keys,
        ca_verifier: Some(roots_ca_verifier([ca.cert.clone()]).unwrap()),
        session: crate::conn::SessionOptions {
            connect_to: Some(addr),
            ..Default::default()
        },
        // Without key files: the key checks of 12.7 could never pass.
        skip_key_checks: true,
        ..ClientOptions::default()
    };
    let client = Client::open_in_memory(options).unwrap();
    let account = client.add_identity_account("chat.test", uid).unwrap().id;
    client
        .store()
        .write(|tx| {
            tx.conn().execute(
                "INSERT INTO identities (uid, device_id, key_id, home, created)
                 VALUES (?1, ?2, ?3, 'chat.test', 0)",
                rusqlite::params![uid, &device.as_bytes()[..], uid],
            )?;
            Ok(())
        })
        .unwrap();
    let identity: Identity = uid.parse().unwrap();
    let plan = ConnectionPlan::identity(Arc::new(IdentitySignIn::new(identity, key)), 1);
    let config = Config {
        self_conversation: false,
        ..Config::immediate()
    };
    client
        .connect_with(account, plan, None, config)
        .await
        .unwrap();
    Person { client, account }
}

/// Waits until `f` holds, checking every 50 ms, for at most 20 seconds.
async fn until(mut f: impl FnMut() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_clients_talk_through_the_driver() {
    let ca = TestCa::new();
    let shared = Arc::new(Mutex::new(Shared {
        server: FakeServer::new(crate::clock::SystemClock.now().unix_millis()),
        outbound: HashMap::new(),
        devices: HashMap::new(),
    }));
    let addr = serve(&ca, shared.clone()).await;
    let alice = person("alice@example.org", &ca, addr, &shared).await;
    let bob = person("bob@example.net", &ca, addr, &shared).await;
    // Both upload KeyPackages once signed in (12.5).
    until(|| {
        let s = shared.lock().unwrap();
        s.server
            .key_package_count("bob@example.net", &s.devices["bob@example.net"])
            == 11
            && s.server
                .key_package_count("alice@example.org", &s.devices["alice@example.org"])
                == 11
    })
    .await;

    let conv = tokio::time::timeout(
        Duration::from_secs(30),
        alice.client.direct(alice.account, "bob@example.net"),
    )
    .await
    .expect("in time")
    .unwrap();
    // Bob joins by Welcome.
    until(|| !bob.client.conversations(bob.account).unwrap().is_empty()).await;
    let bconv = bob.client.conversations(bob.account).unwrap()[0].id;
    assert_eq!(
        bob.client.conversation(bconv).unwrap().name,
        "alice@example.org"
    );

    alice
        .client
        .send_text(conv, "hello over TLS", None)
        .await
        .unwrap();
    until(|| bob.client.messages(bconv, None, 10).unwrap().len() == 1).await;
    let got = bob.client.messages(bconv, None, 10).unwrap();
    assert_eq!(got[0].text.as_deref(), Some("hello over TLS"));
    assert_eq!(got[0].sender.as_str(), "alice@example.org");

    bob.client
        .send_text(bconv, "and back", Some(got[0].id))
        .await
        .unwrap();
    until(|| alice.client.messages(conv, None, 10).unwrap().len() == 2).await;
    let mine = alice.client.messages(conv, None, 10).unwrap();
    assert_eq!(mine[1].reply_to, Some(mine[0].id));
    assert!(mine[0].seq.is_some(), "the own message was posted");
    assert_eq!(alice.client.members(conv).unwrap().len(), 2);

    alice.client.disconnect(alice.account).await.unwrap();
    bob.client.disconnect(bob.account).await.unwrap();
}

/// LR-M5: blob fetches are bounded: two at a time, a few fetched blobs
/// kept, and no more bytes held than the largest blob, whatever refs come.
#[tokio::test]
async fn blob_fetches_are_bounded() {
    use crate::client::conversations::BlobFetcher;
    use crate::client::identity::{Fetched, Https};
    use crate::sync::conversations::BlobFetch;

    struct Slow {
        calls: Mutex<usize>,
        go: tokio::sync::Semaphore,
        size: usize,
    }
    impl Https for Slow {
        fn get<'a>(&'a self, _: &'a str, _: usize) -> crate::conn::BoxFuture<'a, Fetched> {
            Box::pin(async move {
                *self.calls.lock().unwrap() += 1;
                self.go.acquire().await.unwrap().forget();
                Fetched::Body(vec![0; self.size])
            })
        }
    }
    let https = Arc::new(Slow {
        calls: Mutex::new(0),
        go: tokio::sync::Semaphore::new(0),
        size: 100 << 20,
    });
    let fetcher = Arc::new(BlobFetcher::new(Some(https.clone())));
    let refs: Vec<risala_proto::names::BlobRef> = (0..8u8)
        .map(|i| risala_proto::names::BlobRef::from_hash([i; 48]))
        .collect();
    for r in &refs {
        assert!(matches!(
            fetcher.get(Some("https://b.test/"), r),
            BlobFetch::Waiting
        ));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(*https.calls.lock().unwrap(), 2, "two at a time");
    assert_eq!(fetcher.counts().0, 2);
    // Each ask starts the next one as a slot frees up.
    for round in 0..4 {
        https.go.add_permits(2);
        tokio::time::sleep(Duration::from_millis(50)).await;
        for r in &refs {
            let _ = fetcher.get(Some("https://b.test/"), r);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (in_flight, ready, held) = fetcher.counts();
        assert!(in_flight <= 2, "round {round}");
        assert!(ready <= 4, "round {round}");
        assert!(held <= 256 << 20, "round {round}: {held}");
    }
}

/// 6.4: a ban fills `bans` up to 10,000 uids, and a ban past that is
/// refused with its own error before any commit is made. Banning a uid
/// that is banned already adds nothing, so it is fine at the cap.
#[test]
fn a_ban_past_the_cap_is_refused() {
    use super::ConversationError;
    use risala_mls::conversation::{MAX_BANS, RisalaConversation};
    use risala_proto::names::Uid;
    let uid = |s: &str| -> Uid { s.parse().unwrap() };
    let mut ext = RisalaConversation::private_room(
        "chat.example.org".parse().unwrap(),
        [0; 16],
        "big",
        &uid("o@x.org"),
    );
    ext.mods.push(uid("m@x.org"));
    ext.bans = (0..MAX_BANS - 1)
        .map(|i| uid(&format!("b{i}@x.org")))
        .collect();

    // The 10,000th ban, of a moderator, takes it out of `mods`.
    let full = super::banned(&ext, &uid("m@x.org")).unwrap();
    assert_eq!(full.bans.len(), MAX_BANS);
    assert!(full.mods.is_empty());
    assert_eq!(full.check(), Ok(()));

    // One more is refused.
    let err = super::banned(&full, &uid("p@x.org")).unwrap_err();
    assert!(
        matches!(err, Error::Conversation(ConversationError::TooManyBans)),
        "{err}"
    );
    assert_eq!(err.to_string(), "a room bans at most 10,000 identities");

    // Banning one already banned changes nothing.
    assert_eq!(super::banned(&full, &uid("b0@x.org")).unwrap(), full);
}

//! Mailboxes over TLS against a whole server (5.2, 7.1, 7.2): two
//! anonymous connections, one that creates a direct conversation's
//! mailbox and posts to it, and one that follows and fetches it, with a
//! real MLS group from risala-mls.
//!
//! The hub's own tests (`src/core/tests/mailbox.rs`) cover each rule
//! without sockets.

use openmls_memory_storage::MemoryStorage;
use risala_mls::conversation::RisalaConversation;
use risala_mls::group::{
    Changes, commit, create_group, encrypt_application, merge_own_commit, own_pseudonym,
};
use risala_mls::identity::RisalaIdentity;
use risala_mls::keypackage::make_key_package;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::{Provider, RisalaAad, RisalaProfile, SendToken, SigningKey};
use risala_proto::mls::{GroupId, MlsMessage, TokenHash};
use risala_proto::names::{BoxName, Uid};
use risala_proto::time::Timestamp;
use risala_server::testing::TestServer;

struct Dev {
    uid: Uid,
    key: SigningKey,
    provider: Provider<MemoryStorage>,
}

impl Dev {
    fn new(uid: &str, seed: u8) -> Dev {
        Dev {
            uid: uid.parse().unwrap(),
            key: SigningKey::from_seed([seed; 32]),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
        }
    }

    fn profile(&self) -> RisalaProfile {
        RisalaProfile::new(self.uid.name(), Timestamp::now().unix_millis()).unwrap()
    }

    fn token(&self, group: &MlsGroup) -> SendToken {
        SendToken::of_group(group, self.provider.crypto()).unwrap()
    }
}

fn b64(bytes: &[u8]) -> String {
    MlsMessage::from_bytes(bytes).unwrap().to_string()
}

fn token(token: &SendToken) -> String {
    risala_proto::mls::SendToken::from_bytes(*token.as_bytes()).to_string()
}

#[tokio::test]
async fn two_anonymous_connections() {
    let server = TestServer::start().await;
    let mut poster = server.anon().await;
    let mut reader = server.anon().await;

    let alice = Dev::new("alice@example.org", 1);
    let bob = Dev::new("bob@example.org", 2);
    let m = BoxName::from_bytes([0x42; 16]);
    let conv = RisalaConversation::direct(
        server.hostname().parse().unwrap(),
        *m.as_bytes(),
        &alice.uid,
        &bob.uid,
    );
    let identity = RisalaIdentity::device(alice.uid.clone(), alice.key.device_id());
    let (mut a, _, mut state) = create_group(
        &alice.provider,
        &identity,
        &alice.profile(),
        &conv,
        Timestamp::now(),
    )
    .unwrap();
    let gid = GroupId::from_bytes(a.group_id().as_slice().try_into().unwrap());
    let hash0 = TokenHash::from_bytes(alice.token(&a).hash());

    poster
        .send(&format!("CREATE {m} {gid} {hash0}"))
        .await
        .unwrap();
    assert_eq!(poster.expect_line().await.unwrap(), "OK");
    reader.send(&format!("@ref=f FOLLOW {m}")).await.unwrap();
    assert_eq!(reader.expect_line().await.unwrap(), "@ref=f OK head=0");

    // Alice adds Bob: the commit, with its next (5.2, 7.2).
    let kp = make_key_package(
        &bob.provider,
        &bob.key,
        &bob.uid,
        &bob.profile(),
        false,
        Timestamp::now(),
    )
    .unwrap()
    .key_package;
    let token0 = alice.token(&a);
    let out = commit(
        &alice.provider,
        &mut a,
        &alice.profile(),
        &state,
        Changes {
            add: vec![kp],
            ..Changes::default()
        },
    )
    .unwrap();
    let commit = b64(&out.message);
    let next = TokenHash::from_bytes(out.next_token_hash);
    poster
        .send(&format!("POST {m} {} {commit} next={next}", token(&token0)))
        .await
        .unwrap();
    assert_eq!(poster.expect_line().await.unwrap(), "OK seq=1");
    let event = reader.expect_line().await.unwrap();
    assert!(event.starts_with("@seq=1;t="), "{event}");
    assert!(event.ends_with(&format!(" POST {m} {commit} next={next}")));
    merge_own_commit(&alice.provider, &mut a, &mut state).unwrap();

    // A message of epoch 1, live to the reader, and kept for FETCH.
    // Outside public rooms, the pseudonym is the leaf's for the epoch (7.3).
    let pseudonym = own_pseudonym::<()>(&a, alice.provider.crypto()).unwrap();
    let aad = RisalaAad::application(pseudonym, [7; 48]);
    let message = b64(&encrypt_application(&alice.provider, &mut a, &aad, b"hello").unwrap());
    poster
        .send(&format!(
            "@cid=0123456789abcdef POST {m} {} {message}",
            token(&alice.token(&a))
        ))
        .await
        .unwrap();
    assert_eq!(poster.expect_line().await.unwrap(), "OK seq=2");
    let event = reader.expect_line().await.unwrap();
    assert!(event.starts_with("@seq=2;t="), "{event}");
    assert!(event.ends_with(&format!(" POST {m} {message}")));
    // Resending with the same cid makes no new post (7.6).
    poster
        .send(&format!(
            "@cid=0123456789abcdef POST {m} {} {message}",
            token(&alice.token(&a))
        ))
        .await
        .unwrap();
    assert_eq!(poster.expect_line().await.unwrap(), "OK seq=2");

    reader.send(&format!("FETCH {m} after=1")).await.unwrap();
    assert_eq!(reader.expect_line().await.unwrap(), event);
    assert_eq!(reader.expect_line().await.unwrap(), "OK more=0");
    reader.send(&format!("UNFOLLOW {m}")).await.unwrap();
    assert_eq!(reader.expect_line().await.unwrap(), "OK");
    reader.send("PING").await.unwrap();
    let ok = reader.expect_line().await.unwrap();
    assert!(ok.starts_with("@t=") && ok.ends_with(" OK"), "{ok}");
    server.stop().await;
}

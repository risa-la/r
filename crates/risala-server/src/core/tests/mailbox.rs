//! Mailboxes and delivery (5.2, 6.1, 6.4, 7), through the hub, with real
//! MLS groups from risala-mls wherever the framing matters.

use std::time::Duration;

use openmls_memory_storage::MemoryStorage;
use risala_mls::conversation::{GuestMode, RisalaConversation};
use std::cell::RefCell;
use std::collections::HashMap;

use risala_mls::checks::EpochState;
use risala_mls::group::{
    Changes, CommitOutput, commit, create_group, encrypt_application, join_by_welcome,
    join_proposal, merge_own_commit, own_leaf_key, process_message, propose_update,
    sending_pseudonym,
};
use risala_mls::identity::RisalaIdentity;
use risala_mls::keypackage::make_join_key_package;
use risala_mls::keypackage::make_key_package;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::KeyPackage;
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::wire::{to_bytes, tree_to_bytes};
use risala_mls::{Provider, RisalaAad, RisalaProfile, SendToken, SigningKey};
use risala_proto::auth::PublicKey;
use risala_proto::mls::{GroupId, MlsMessage, Pseudonym, TokenHash};
use risala_proto::names::{BoxName, Room, Uid};
use risala_proto::time::Timestamp;
use rusqlite::params;

use super::*;
use crate::core::mailbox::{check_token, drop_mailbox, run_maintenance};
use crate::store::{MailboxStore as _, NewMailbox};
use risala_proto::error::ErrorCode;

const HOST: &str = "chat.example.org";

/// [`HOST`] as a server address, as the conversation extension holds it.
fn host() -> risala_proto::names::ServerAddr {
    HOST.parse().unwrap()
}

/// One device of an identity, with its own MLS storage, and the history of
/// each of its groups (12.7).
struct Dev {
    uid: Uid,
    key: SigningKey,
    provider: Provider<MemoryStorage>,
    pseudonym: risala_mls::Pseudonym,
    states: RefCell<HashMap<Vec<u8>, EpochState>>,
}

/// The time now, in ms, as devices and the group checks take it.
fn now_ms() -> u64 {
    Timestamp::now().unix_millis()
}

impl Dev {
    fn new(uid: &str, seed: u8) -> Dev {
        Dev {
            uid: uid.parse().unwrap(),
            key: SigningKey::from_seed([seed; 32]),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
            pseudonym: risala_mls::Pseudonym([seed; 16]),
            states: RefCell::default(),
        }
    }

    fn identity(&self) -> RisalaIdentity {
        RisalaIdentity::device(self.uid.clone(), self.key.device_id())
    }

    fn profile(&self) -> RisalaProfile {
        RisalaProfile::new(self.uid.name(), now_ms()).unwrap()
    }

    fn key_package(&self) -> KeyPackage {
        make_key_package(&self.provider, &self.key, &self.uid, &self.profile(), false)
            .unwrap()
            .key_package
    }

    fn state(&self, group: &MlsGroup) -> EpochState {
        self.states
            .borrow()
            .get(group.group_id().as_slice())
            .cloned()
            .unwrap_or_default()
    }

    fn set_state(&self, group: &MlsGroup, state: EpochState) {
        self.states
            .borrow_mut()
            .insert(group.group_id().as_slice().to_vec(), state);
    }

    fn create(&self, conversation: &RisalaConversation) -> MlsGroup {
        let (group, _, state) = create_group(
            &self.provider,
            &self.identity(),
            &self.profile(),
            conversation,
        )
        .unwrap();
        self.set_state(&group, state);
        group
    }

    fn commit(&self, group: &mut MlsGroup, changes: Changes) -> CommitOutput {
        commit(
            &self.provider,
            group,
            &self.profile(),
            &self.state(group),
            changes,
        )
        .unwrap()
    }

    /// Merges this device's pending commit, which won (7.2).
    fn merge(&self, group: &mut MlsGroup, _out: &CommitOutput) {
        let mut state = self.state(group);
        merge_own_commit(&self.provider, group, &mut state).unwrap();
        self.set_state(group, state);
    }

    fn join(&self, welcome: &[u8]) -> MlsGroup {
        let expect = risala_mls::checks::JoinExpectation {
            host: host(),
            own_uid: self.uid.clone(),
            public_room: None,
        };
        let joined = join_by_welcome(&self.provider, welcome, None, &expect).unwrap();
        self.set_state(&joined.group, joined.state);
        joined.group
    }

    /// The group's send token now (7.2), in base64.
    fn token(&self, group: &MlsGroup) -> String {
        let token = SendToken::of_group(group, self.provider.crypto()).unwrap();
        risala_proto::mls::SendToken::from_bytes(*token.as_bytes()).to_string()
    }

    /// The hash of the group's send token now, in base64.
    fn token_hash(&self, group: &MlsGroup) -> String {
        let token = SendToken::of_group(group, self.provider.crypto()).unwrap();
        TokenHash::from_bytes(token.hash()).to_string()
    }

    /// The pseudonym this device sends under in `group` now (7.3): derived
    /// from the epoch outside public rooms, its own for the period in one.
    fn pseudonym_in(&self, group: &MlsGroup) -> risala_mls::Pseudonym {
        let public = risala_mls::group::conversation(group)
            .is_some_and(|c| c.kind == risala_mls::ConversationKind::PublicRoom);
        sending_pseudonym::<()>(
            group,
            self.provider.crypto(),
            public.then_some(self.pseudonym),
        )
        .unwrap()
    }

    /// An application message, in base64.
    fn send(&self, group: &mut MlsGroup, text: &[u8]) -> String {
        let aad = RisalaAad::application(self.pseudonym_in(group), [7; 48]);
        b64(&encrypt_application(&self.provider, group, &aad, text).unwrap())
    }

    /// A new connection signed in as this device (4.6), without AUTH.
    fn sign_in(&self, h: &mut Harness) -> Client {
        let c = h.connect();
        let device = Device {
            uid: self.uid.clone(),
            key: PublicKey::from_bytes(self.key.public_key()),
        };
        assert!(h.inner().reg().set_who(c.id, Who::SignedIn(device)));
        c
    }
}

fn b64(bytes: &[u8]) -> String {
    MlsMessage::from_bytes(bytes).unwrap().to_string()
}

fn gid(group: &MlsGroup) -> String {
    GroupId::from_bytes(group.group_id().as_slice().try_into().unwrap()).to_string()
}

fn hash(bytes: [u8; 48]) -> String {
    TokenHash::from_bytes(bytes).to_string()
}

fn mailbox(n: u8) -> BoxName {
    BoxName::from_bytes([n; 16])
}

fn now(h: &Harness) -> String {
    h.inner().now().to_string()
}

/// A direct conversation between Alice and Bob in mailbox `m`, created on
/// `anon`, with Alice's commit that adds Bob posted and merged: the group
/// is in epoch 1, its first post seq 1.
struct Direct {
    alice: Dev,
    bob: Dev,
    a: MlsGroup,
    b: MlsGroup,
    m: BoxName,
    /// The commit, as posted.
    commit: String,
    /// Its `next`.
    next: String,
}

impl Direct {
    async fn new(h: &Harness, anon: &mut Client, n: u8) -> Direct {
        let alice = Dev::new("alice@example.org", n);
        let bob = Dev::new("bob@example.org", n.wrapping_add(100));
        let m = mailbox(n);
        let conv = RisalaConversation::direct(host(), *m.as_bytes(), &alice.uid, &bob.uid);
        let mut a = alice.create(&conv);
        h.send(
            anon,
            &format!("CREATE {m} {} {}", gid(&a), alice.token_hash(&a)),
        )
        .await;
        assert_eq!(anon.lines(), ["OK"]);
        let token = alice.token(&a);
        let out = alice.commit(
            &mut a,
            Changes {
                add: vec![bob.key_package()],
                ..Changes::default()
            },
        );
        let commit = b64(&out.message);
        let next = hash(out.next_token_hash);
        h.send(anon, &format!("POST {m} {token} {commit} next={next}"))
            .await;
        assert_eq!(anon.lines(), ["OK seq=1"]);
        alice.merge(&mut a, &out);
        let b = bob.join(&out.welcome.unwrap());
        Direct {
            alice,
            bob,
            a,
            b,
            m,
            commit,
            next,
        }
    }
}

/// CREATE's first form, and the boxes and group ids it never takes twice
/// (5.2); with `epoch`, `from` and `token`, a group that moves (7.8).
#[tokio::test]
async fn create() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let (mut guest, _) = h.guest("sam").await;
    let gid1 = GroupId::from_bytes([1; 32]);
    let gid2 = GroupId::from_bytes([2; 32]);
    // The send token of epoch 0, and its hash.
    let token0 = risala_proto::mls::SendToken::from_bytes([5; 32]);
    let hash0 = token0.hash();
    let (m1, m2, m3) = (mailbox(1), mailbox(2), mailbox(3));
    h.send(&anon, &format!("CREATE {m1} {gid1} {hash0}")).await;
    assert_eq!(anon.lines(), ["OK"]);
    // A guest creates its report conversation's mailbox the same way (4.2).
    h.send(&guest, &format!("CREATE {m2} {gid2} {hash0}")).await;
    assert_eq!(guest.lines(), ["OK"]);
    for line in [
        format!("CREATE {m1} {} {hash0}", GroupId::from_bytes([3; 32])),
        format!("CREATE {m3} {gid1} {hash0}"),
        format!("CREATE {m1} {gid1} {hash0} epoch=1 from={m1} token={token0}"),
    ] {
        h.send(&anon, &line).await;
        assert_eq!(anon.lines(), ["ERR name-taken"], "{line}");
    }
    // A move needs `from` to be a mailbox of the group, and a token of the
    // epoch before in its set (7.8).
    let wrong = risala_proto::mls::SendToken::from_bytes([6; 32]);
    for (line, want) in [
        (
            format!(
                "CREATE {m3} {gid1} {hash0} epoch=1 from={} token={token0}",
                mailbox(9)
            ),
            "ERR not-found",
        ),
        (
            format!("CREATE {m3} {gid1} {hash0} epoch=1 from={m2} token={token0}"),
            "ERR not-found",
        ),
        (
            format!("CREATE {m3} {gid1} {hash0} epoch=1 from={m1} token={wrong}"),
            "ERR stale",
        ),
        (
            format!("CREATE {m3} {gid1} {hash0} epoch=2 from={m1} token={token0}"),
            "ERR stale",
        ),
    ] {
        h.send(&anon, &line).await;
        assert_eq!(anon.lines(), [want], "{line}");
    }
    let hash1 = hash([8; 48]);
    let moving = format!("CREATE {m3} {gid1} {hash1} epoch=1 from={m1} token={token0}");
    h.send(&anon, &moving).await;
    assert_eq!(anon.lines(), ["OK"]);
    // Two members who both move create the same box: OK, and nothing
    // changes (7.8).
    h.send(&guest, &moving).await;
    assert_eq!(guest.lines(), ["OK"]);
    let record = h.store.mailbox(&m3).unwrap().unwrap();
    assert_eq!((record.first_epoch, record.moved_from), (1, Some(m1)));
    assert!(
        h.store
            .has_token(&m3, 1, &TokenHash::from_bytes([8; 48]))
            .unwrap()
    );
    // A box is never used again, even once its mailbox is gone (5.2).
    assert!(drop_mailbox(h.inner(), &m2, "").await.unwrap());
    h.send(
        &anon,
        &format!("CREATE {m2} {} {hash0}", GroupId::from_bytes([5; 32])),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR name-taken"]);
    // A signed-in connection creates only public rooms (13).
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, &format!("CREATE {} {gid1} {hash0}", mailbox(4)))
        .await;
    assert_eq!(alice.lines(), ["ERR wrong-connection"]);
}

/// Posts go to every follower in seq order, as event lines, the poster's
/// before its OK; FETCH pages through them; FOLLOW reports the head (5.2,
/// 7.1).
#[tokio::test]
async fn post_follow_and_fetch() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut watcher = h.anon().await;
    let (mut guest, _) = h.guest("sam").await;
    let m = mailbox(1);
    let alice = Dev::new("alice@example.org", 1);
    let bob = Dev::new("bob@example.org", 2);
    let conv = RisalaConversation::direct(host(), *m.as_bytes(), &alice.uid, &bob.uid);
    let mut a = alice.create(&conv);
    h.send(
        &anon,
        &format!("CREATE {m} {} {}", gid(&a), alice.token_hash(&a)),
    )
    .await;
    assert_eq!(anon.lines(), ["OK"]);
    h.send(&watcher, &format!("FOLLOW {m}")).await;
    assert_eq!(watcher.lines(), ["OK head=0"]);
    h.send(&guest, &format!("@ref=g FOLLOW {m}")).await;
    assert_eq!(guest.lines(), ["@ref=g OK head=0"]);
    h.send(&anon, &format!("FOLLOW {m}")).await;
    assert_eq!(anon.lines(), ["OK head=0"]);

    let token = alice.token(&a);
    let out = alice.commit(
        &mut a,
        Changes {
            add: vec![bob.key_package()],
            ..Changes::default()
        },
    );
    let (commit, next) = (b64(&out.message), hash(out.next_token_hash));
    h.send(
        &anon,
        &format!("@ref=p POST {m} {token} {commit} next={next}"),
    )
    .await;
    let event = format!("@seq=1;t={} POST {m} {commit} next={next}", now(&h));
    // Live posts carry no ref; the poster gets the post before its OK.
    assert_eq!(anon.lines(), [event.clone(), "@ref=p OK seq=1".into()]);
    assert_eq!(watcher.lines(), std::slice::from_ref(&event));
    assert_eq!(guest.lines(), std::slice::from_ref(&event));
    alice.merge(&mut a, &out);
    let mut b = bob.join(&out.welcome.unwrap());

    // Epoch 1: the commit's next opened it (7.2).
    let mut events = vec![event];
    for (i, dev) in [&bob, &alice, &bob].into_iter().enumerate() {
        let group = if dev.uid == bob.uid { &mut b } else { &mut a };
        let message = dev.send(group, format!("hello {i}").as_bytes());
        h.send(&guest, &format!("POST {m} {} {message}", dev.token(group)))
            .await;
        let seq = i + 2;
        let event = format!("@seq={seq};t={} POST {m} {message}", now(&h));
        assert_eq!(guest.lines(), [event.clone(), format!("OK seq={seq}")]);
        assert_eq!(watcher.lines(), std::slice::from_ref(&event));
        events.push(event);
    }

    // FETCH: the earliest posts after a position, in order (7.1).
    h.send(&watcher, &format!("@ref=f FETCH {m} after=0")).await;
    let mut want: Vec<String> = events
        .iter()
        .map(|e| format!("@ref=f;{}", &e[1..]))
        .collect();
    want.push("@ref=f OK more=0".into());
    assert_eq!(watcher.lines(), want);
    h.send(&watcher, &format!("FETCH {m} after=1 limit=2"))
        .await;
    assert_eq!(
        watcher.lines(),
        [events[1].clone(), events[2].clone(), "OK more=1".into()]
    );
    h.send(&watcher, &format!("FETCH {m} after=4")).await;
    assert_eq!(watcher.lines(), ["OK more=0"]);
    h.send(&watcher, &format!("FETCH {m} after=9")).await;
    assert_eq!(watcher.lines(), ["OK more=0"]);
    // FOLLOW again: OK, with the head.
    h.send(&watcher, &format!("FOLLOW {m}")).await;
    assert_eq!(watcher.lines(), ["OK head=4"]);

    // UNFOLLOW stops it; unfollowing again is OK.
    h.send(&watcher, &format!("UNFOLLOW {m}")).await;
    h.send(&watcher, &format!("UNFOLLOW {m}")).await;
    assert_eq!(watcher.lines(), ["OK", "OK"]);
    anon.lines();
    let message = alice.send(&mut a, b"quiet");
    h.send(&anon, &format!("POST {m} {} {message}", alice.token(&a)))
        .await;
    assert_eq!(anon.lines().len(), 2);
    assert!(watcher.lines().is_empty());

    // A box that does not exist (7.1).
    let none = mailbox(9);
    for line in [
        format!("FOLLOW {none}"),
        format!("UNFOLLOW {none}"),
        format!("FETCH {none} after=0"),
        format!("POST {none} {} {message}", alice.token(&a)),
        format!("TOKEN {none} 1 {} {}", alice.token(&a), hash([1; 48])),
        format!("GROUPINFO {none}"),
    ] {
        h.send(&watcher, &line).await;
        assert_eq!(watcher.lines(), ["ERR not-found"], "{line}");
    }
    // `leaf` is for public rooms (7.1).
    h.send(&watcher, &format!("FETCH {m} after=0 leaf=3")).await;
    assert_eq!(watcher.lines(), ["ERR invalid leaf is for public rooms"]);
}

/// FETCH returns at most `limit` posts, 50 by default, and the server's
/// cap, which is never under 50 (7.1).
#[tokio::test]
async fn fetch_limits() {
    let mut config = config();
    config.limits.max_page = 60;
    config.limits.posts_per_minute = 0;
    let mut h = Harness::with(config, timers());
    let mut anon = h.anon().await;
    let d = Direct::new(&h, &mut anon, 1).await;
    let mut a = d.a;
    for i in 0..70 {
        let message = d.alice.send(&mut a, format!("{i}").as_bytes());
        h.send(
            &anon,
            &format!("POST {} {} {message}", d.m, d.alice.token(&a)),
        )
        .await;
    }
    anon.lines();
    h.send(&anon, &format!("FETCH {} after=0", d.m)).await;
    let lines = anon.lines();
    assert_eq!(lines.len(), 51);
    assert_eq!(lines[50], "OK more=1");
    h.send(&anon, &format!("FETCH {} after=0 limit=1000", d.m))
        .await;
    let lines = anon.lines();
    assert_eq!(lines.len(), 61);
    assert!(lines[59].starts_with("@seq=60;"));
    h.send(&anon, &format!("FETCH {} after=60 limit=1000", d.m))
        .await;
    let lines = anon.lines();
    assert_eq!(lines.len(), 12);
    assert_eq!(lines[11], "OK more=0");
}

/// The checks of POST's points 1 and 2: the message's group, framing,
/// RisalaAAD, and the options its content type needs (5.2).
#[tokio::test]
async fn post_framing() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let m = d.m;
    let token = d.alice.token(&d.a);
    let app = d.alice.send(&mut d.a, b"hi");
    let invalid = |line: &[String]| {
        assert_eq!(line.len(), 1, "{line:?}");
        assert!(line[0].starts_with("ERR invalid"), "{line:?}");
    };

    // Another group's message.
    let other = Dev::new("carol@example.org", 7);
    let conv = RisalaConversation::direct(host(), [7; 16], &other.uid, &d.bob.uid);
    let mut o = other.create(&conv);
    let foreign = other.send(&mut o, b"x");
    h.send(&anon, &format!("POST {m} {token} {foreign}")).await;
    invalid(&anon.lines());
    // Not an MLS message, or a KeyPackage.
    let kp = b64(&to_bytes(&d.bob.key_package().into()));
    for junk in [b64(&[0; 64]), kp] {
        h.send(&anon, &format!("POST {m} {token} {junk}")).await;
        invalid(&anon.lines());
    }
    // An application message has no next; a commit needs it.
    h.send(
        &anon,
        &format!("POST {m} {token} {app} next={}", hash([1; 48])),
    )
    .await;
    invalid(&anon.lines());
    let out = d.alice.commit(&mut d.a, Changes::default());
    let commit = b64(&out.message);
    h.send(&anon, &format!("POST {m} {token} {commit}")).await;
    invalid(&anon.lines());
    // Only application messages may be live; groupinfo is a public room's.
    let next = hash(out.next_token_hash);
    h.send(
        &anon,
        &format!("POST {m} {token} {commit} next={next} live=yes"),
    )
    .await;
    invalid(&anon.lines());
    let group_info = b64(&[1; 40]);
    h.send(
        &anon,
        &format!("POST {m} {token} {app} groupinfo={group_info}"),
    )
    .await;
    invalid(&anon.lines());
    // A PublicMessage outside a public room: a public room's commit, in a
    // mailbox made for its group.
    let owen = Dev::new("owen@example.org", 8);
    let room: Room = "#general".parse().unwrap();
    let pm = mailbox(8);
    let mut p = owen.create(&RisalaConversation::public_room(
        host(),
        *pm.as_bytes(),
        &room,
        &owen.uid,
    ));
    h.send(
        &anon,
        &format!("CREATE {pm} {} {}", gid(&p), owen.token_hash(&p)),
    )
    .await;
    assert_eq!(anon.lines(), ["OK"]);
    let ptoken = owen.token(&p);
    let out = owen.commit(&mut p, Changes::default());
    h.send(
        &anon,
        &format!(
            "POST {pm} {ptoken} {} next={}",
            b64(&out.message),
            hash(out.next_token_hash)
        ),
    )
    .await;
    assert_eq!(
        anon.lines(),
        ["ERR invalid a PublicMessage outside a public room"]
    );

    // Nothing was kept.
    h.send(&anon, &format!("FETCH {m} after=1")).await;
    assert_eq!(anon.lines(), ["OK more=0"]);
    // The commit, posted properly, is kept.
    h.send(&anon, &format!("POST {m} {token} {commit} next={next}"))
        .await;
    assert_eq!(anon.lines(), ["OK seq=2"]);
}

/// Send tokens: POST checks a post's token against its epoch's set; `-`
/// is for joining public rooms; a commit's next opens the next epoch;
/// TOKEN adds a hash for a holder of the epoch before (7.2).
#[tokio::test]
async fn send_tokens() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let m = d.m;
    let message = d.alice.send(&mut d.a, b"hi");
    let token1 = d.alice.token(&d.a);
    // Epoch 0's token, or a made-up one, for a message of epoch 1.
    let wrong = risala_proto::mls::SendToken::from_bytes([3; 32]).to_string();
    h.send(&anon, &format!("POST {m} {wrong} {message}")).await;
    assert_eq!(anon.lines(), ["ERR stale"]);
    h.send(&anon, &format!("POST {m} - {message}")).await;
    assert_eq!(
        anon.lines(),
        ["ERR forbidden - is only for joining a public room"]
    );
    h.send(&anon, &format!("POST {m} {token1} {message}")).await;
    assert_eq!(anon.lines(), ["OK seq=2"]);

    // A commit whose next is wrong opens nothing; TOKEN repairs it.
    let out = d.alice.commit(&mut d.a, Changes::default());
    let bogus = hash([4; 48]);
    h.send(
        &anon,
        &format!("POST {m} {token1} {} next={bogus}", b64(&out.message)),
    )
    .await;
    assert_eq!(anon.lines(), ["OK seq=3"]);
    d.alice.merge(&mut d.a, &out);
    let message = d.alice.send(&mut d.a, b"epoch 2");
    let token2 = d.alice.token(&d.a);
    let hash2 = d.alice.token_hash(&d.a);
    h.send(&anon, &format!("POST {m} {token2} {message}")).await;
    assert_eq!(anon.lines(), ["ERR stale"]);
    // TOKEN with a token that is not of epoch 1, or of the wrong epoch.
    for line in [
        format!("TOKEN {m} 1 {wrong} {hash2}"),
        format!("TOKEN {m} 0 {token1} {hash2}"),
        format!("TOKEN {m} 2 {token1} {hash2}"),
    ] {
        h.send(&anon, &line).await;
        assert_eq!(anon.lines(), ["ERR stale"], "{line}");
    }
    h.send(&anon, &format!("TOKEN {m} 1 {token1} {hash2}"))
        .await;
    assert_eq!(anon.lines(), ["OK"]);
    // A hash the set holds already: OK, and nothing changes.
    h.send(&anon, &format!("TOKEN {m} 1 {token1} {hash2}"))
        .await;
    assert_eq!(anon.lines(), ["OK"]);
    h.send(&anon, &format!("POST {m} {token2} {message}")).await;
    assert_eq!(anon.lines(), ["OK seq=4"]);
    // The bogus hash is in epoch 2's set too: it is what the commit named.
    assert!(
        h.store
            .has_token(&m, 2, &TokenHash::from_bytes([4; 48]))
            .unwrap()
    );

    // UPLOAD and BLOB check a token without its epoch (5.6, 12.12).
    let proto = |t: &str| t.parse::<risala_proto::mls::SendToken>().unwrap();
    assert_eq!(check_token(h.inner(), &m, &proto(&token2)).await, Ok(()));
    assert_eq!(check_token(h.inner(), &m, &proto(&token1)).await, Ok(()));
    assert_eq!(
        check_token(h.inner(), &m, &proto(&wrong)).await,
        Err(ErrorCode::Stale)
    );
    assert_eq!(
        check_token(h.inner(), &mailbox(99), &proto(&token1)).await,
        Err(ErrorCode::NotFound)
    );
    // An epoch of 2^63-1 has no next epoch (7.2).
    h.send(
        &anon,
        &format!("TOKEN {m} 9223372036854775807 {token2} {hash2}"),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR stale"]);
    // A guest may send TOKEN; a signed-in connection may not (13).
    let (mut guest, _) = h.guest("sam").await;
    h.send(&guest, &format!("TOKEN {m} 2 {token2} {}", hash([5; 48])))
        .await;
    assert_eq!(guest.lines(), ["OK"]);
}

/// A moved mailbox starts at the move's epoch; TOKEN for the epoch before
/// it is checked against the mailbox the group moved from (7.8).
#[tokio::test]
async fn moves() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let token1 = d.alice.token(&d.a);
    let out = d.alice.commit(&mut d.a, Changes::default());
    d.alice.merge(&mut d.a, &out);
    // The mover gives a wrong hash for epoch 2.
    let new = mailbox(2);
    let (group, old) = (gid(&d.a), d.m);
    let create = |m: BoxName| {
        format!(
            "CREATE {m} {group} {} epoch=2 from={old} token={token1}",
            hash([6; 48]),
        )
    };
    h.send(&anon, &create(new)).await;
    assert_eq!(anon.lines(), ["OK"]);
    let message = d.alice.send(&mut d.a, b"moved");
    let token2 = d.alice.token(&d.a);
    let hash2 = d.alice.token_hash(&d.a);
    h.send(&anon, &format!("POST {new} {token2} {message}"))
        .await;
    assert_eq!(anon.lines(), ["ERR stale"]);
    // A member repairs it with its token of epoch 1, which only the old
    // mailbox knows.
    h.send(&anon, &format!("TOKEN {new} 1 {token1} {hash2}"))
        .await;
    assert_eq!(anon.lines(), ["OK"]);
    h.send(&anon, &format!("POST {new} {token2} {message}"))
        .await;
    assert_eq!(anon.lines(), ["OK seq=1"]);
    // Only for the epoch just before the move.
    h.send(&anon, &format!("TOKEN {new} 0 {token1} {hash2}"))
        .await;
    assert_eq!(anon.lines(), ["ERR stale"]);
    // Once the old mailbox is gone, nothing can be checked against it.
    let newer = mailbox(3);
    h.send(&anon, &create(newer)).await;
    assert_eq!(anon.lines(), ["OK"]);
    assert!(drop_mailbox(h.inner(), &d.m, "").await.unwrap());
    h.send(&anon, &format!("TOKEN {newer} 1 {token1} {hash2}"))
        .await;
    assert_eq!(anon.lines(), ["ERR stale"]);
    // Nor can a move come from it.
    h.send(&anon, &create(mailbox(4))).await;
    assert_eq!(anon.lines(), ["ERR not-found"]);
}

/// A cid makes resending safe: within 24 hours the same cid gets the
/// existing seq, checked before the token, and no new post (7.6).
#[tokio::test]
async fn cids() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut other = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let m = d.m;
    h.send(&other, &format!("FOLLOW {m}")).await;
    other.lines();
    let token = d.alice.token(&d.a);
    let message = d.alice.send(&mut d.a, b"once");
    let cid = "abcdefghijklmnop";
    h.send(&anon, &format!("@cid={cid} POST {m} {token} {message}"))
        .await;
    assert_eq!(anon.lines(), ["OK seq=2"]);
    // The cid is not part of the post.
    assert_eq!(
        other.lines(),
        [format!("@seq=2;t={} POST {m} {message}", now(&h))]
    );
    // Again, even with a stale token and on another connection.
    let wrong = risala_proto::mls::SendToken::from_bytes([3; 32]);
    h.send(&other, &format!("@cid={cid} POST {m} {wrong} {message}"))
        .await;
    assert_eq!(other.lines(), ["OK seq=2"]);
    // In another mailbox the cid means nothing.
    let mut e = Direct::new(&h, &mut anon, 2).await;
    let message2 = e.alice.send(&mut e.a, b"other");
    h.send(
        &anon,
        &format!("@cid={cid} POST {} {} {message2}", e.m, e.alice.token(&e.a)),
    )
    .await;
    assert_eq!(anon.lines(), ["OK seq=2"]);
    // After 24 hours it is a new post.
    h.clock.advance(Duration::from_secs(24 * 60 * 60 + 1));
    h.send(&anon, &format!("@cid={cid} POST {m} {token} {message}"))
        .await;
    assert_eq!(anon.lines(), ["OK seq=3"]);
}

/// A live post is not kept: it goes to the followers of now, with `t` and
/// no `seq` (5.2).
#[tokio::test]
async fn live_posts() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut other = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let m = d.m;
    h.send(&other, &format!("FOLLOW {m}")).await;
    other.lines();
    let message = d.alice.send(&mut d.a, b"typing");
    h.send(
        &anon,
        &format!(
            "@cid=abcdefghijklmnop POST {m} {} {message} live=yes",
            d.alice.token(&d.a)
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["OK"]);
    assert_eq!(
        other.lines(),
        [format!("@t={} POST {m} {message}", now(&h))]
    );
    h.send(&other, &format!("FETCH {m} after=1")).await;
    assert_eq!(other.lines(), ["OK more=0"]);
    h.send(&other, &format!("FOLLOW {m}")).await;
    assert_eq!(other.lines(), ["OK head=1"]);
}

/// A signed-in connection posts only a public room's PublicMessages (5.2
/// point 5, 13).
#[tokio::test]
async fn signed_in_connections_do_not_post_privately() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let mut signed = d.alice.sign_in(&mut h);
    let message = d.alice.send(&mut d.a, b"hi");
    h.send(
        &signed,
        &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
    )
    .await;
    assert_eq!(signed.lines(), ["ERR wrong-connection"]);
}

/// A muted pseudonym's posts are refused (5.2 point 4, 6.4, 10.4).
#[tokio::test]
async fn muted_pseudonyms() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    // Outside public rooms, the pseudonym of Bob's leaf in this epoch
    // (7.3).
    let pseudonym = Pseudonym::from_bytes(d.bob.pseudonym_in(&d.b).0);
    let until: Timestamp = "2026-11-09T13:00:00.000Z".parse().unwrap();
    assert!(h.store.set_mute(&d.m, &pseudonym, until).unwrap());
    let message = d.bob.send(&mut d.b, b"spam");
    let line = format!("POST {} {} {message}", d.m, d.bob.token(&d.b));
    h.send(&anon, &line).await;
    assert_eq!(anon.lines(), ["ERR forbidden muted"]);
    // Alice is not muted.
    let message = d.alice.send(&mut d.a, b"fine");
    h.send(
        &anon,
        &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
    )
    .await;
    assert_eq!(anon.lines(), ["OK seq=2"]);
    // The mute ends.
    h.clock.advance(Duration::from_secs(60 * 60));
    h.send(&anon, &line).await;
    assert_eq!(anon.lines(), ["OK seq=3"]);
}

/// Limits per connection and per network address: CREATE, posts, commits
/// and TOKEN, and the bytes an address stores (4.2, 5.2, 7.2, 7.5).
#[tokio::test]
async fn rate_limits() {
    let mut config = config();
    config.limits.creates_per_hour = 2;
    config.limits.posts_per_minute = 3;
    config.limits.commits_per_hour = 2;
    let mut h = Harness::with(config, timers());
    let mut anon = h.anon().await;
    // Direct::new creates a mailbox and posts a commit.
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let token = hash([1; 48]);
    h.send(
        &anon,
        &format!(
            "CREATE {} {} {token}",
            mailbox(2),
            GroupId::from_bytes([2; 32])
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["OK"]);
    let create3 = format!(
        "CREATE {} {} {token}",
        mailbox(3),
        GroupId::from_bytes([3; 32])
    );
    h.send(&anon, &create3).await;
    let lines = anon.lines();
    assert!(lines[0].starts_with("@retry="), "{lines:?}");
    assert!(lines[0].ends_with(" ERR rate-limited"), "{lines:?}");
    // The same address, on another connection.
    let mut other = h.anon().await;
    h.send(&other, &create3).await;
    assert!(other.lines()[0].ends_with("ERR rate-limited"));
    h.clock.advance(Duration::from_secs(60 * 60));
    h.send(&other, &create3).await;
    assert_eq!(other.lines(), ["OK"]);

    // Posts: 3 a minute, the commit of Direct::new included... a minute
    // has passed, so three more.
    for i in 0..3 {
        let message = d.alice.send(&mut d.a, &[i]);
        h.send(
            &anon,
            &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
        )
        .await;
        assert!(anon.lines()[0].starts_with("OK seq="));
    }
    let message = d.alice.send(&mut d.a, b"one too many");
    let post = format!("POST {} {} {message}", d.m, d.alice.token(&d.a));
    h.send(&anon, &post).await;
    assert_eq!(anon.lines(), ["@retry=60 ERR rate-limited"]);
    // Another address is not limited by this one.
    let mut far = h.connect_from("198.51.100.9:4000");
    h.send(&far, "ANON").await;
    h.send(&far, &post).await;
    assert_eq!(far.lines(), ["OK", "OK seq=5"]);

    // TOKEN and commits: 2 an hour (Direct::new's commit was over an hour
    // ago).
    let token1 = d.alice.token(&d.a);
    for n in [7, 8] {
        h.send(&far, &format!("TOKEN {} 1 {token1} {}", d.m, hash([n; 48])))
            .await;
        assert_eq!(far.lines(), ["OK"]);
    }
    h.send(&far, &format!("TOKEN {} 1 {token1} {}", d.m, hash([9; 48])))
        .await;
    assert!(far.lines()[0].ends_with("ERR rate-limited"));
    // A commit over its limit does not use up a post's slot either: the
    // two slots are taken together, or neither.
    let first = d.alice.send(&mut d.a, b"first");
    let second = d.alice.send(&mut d.a, b"second");
    let out = d.alice.commit(&mut d.a, Changes::default());
    h.send(
        &far,
        &format!(
            "POST {} {token1} {} next={}",
            d.m,
            b64(&out.message),
            hash(out.next_token_hash)
        ),
    )
    .await;
    assert!(far.lines()[0].ends_with("ERR rate-limited"));
    for message in [first, second] {
        h.send(&far, &format!("POST {} {token1} {message}", d.m))
            .await;
        assert!(far.lines()[0].starts_with("OK seq="));
    }
}

/// The bytes one address stores in an hour (7.5).
#[tokio::test]
async fn address_bytes() {
    let mut config = config();
    config.limits.address_bytes_per_hour = 40_000;
    let mut h = Harness::with(config, timers());
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let mut kept = 0;
    let mut refused = None;
    for i in 0..50 {
        let message = d.alice.send(&mut d.a, &[i; 100]);
        h.send(
            &anon,
            &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
        )
        .await;
        let lines = anon.lines();
        if lines[0].starts_with("OK") {
            kept += 1;
        } else {
            refused = Some(lines[0].clone());
            break;
        }
    }
    assert!(kept > 0);
    let refused = refused.expect("the limit was reached");
    assert!(refused.ends_with("ERR rate-limited"), "{refused}");
    // Live posts store nothing.
    let message = d.alice.send(&mut d.a, b"typing");
    h.send(
        &anon,
        &format!("POST {} {} {message} live=yes", d.m, d.alice.token(&d.a)),
    )
    .await;
    assert_eq!(anon.lines(), ["OK"]);
    h.clock.advance(Duration::from_secs(60 * 60));
    let message = d.alice.send(&mut d.a, b"later");
    h.send(
        &anon,
        &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
    )
    .await;
    assert!(anon.lines()[0].starts_with("OK seq="));
}

/// Over its quota a mailbox's oldest posts expire early, and a post larger
/// than the quota is refused (7.5).
#[tokio::test]
async fn quotas() {
    let mut config = config();
    config.limits.mailbox_quota = 60_000;
    config.limits.posts_per_minute = 0;
    let mut h = Harness::with(config, timers());
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    for i in 0..20u8 {
        let message = d.alice.send(&mut d.a, &[i; 1000]);
        h.send(
            &anon,
            &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
        )
        .await;
        assert!(anon.lines()[0].starts_with("OK seq="));
        assert!(h.store.mailbox_bytes(&d.m).unwrap() <= 60_000);
    }
    h.send(&anon, &format!("FETCH {} after=0", d.m)).await;
    let lines = anon.lines();
    // The oldest messages expired early, but not the commit (seq 1); the
    // newest are all there.
    assert!(lines[0].starts_with("@seq=1;"), "{lines:?}");
    assert!(!lines[1].starts_with("@seq=2;"), "{lines:?}");
    assert!(lines[lines.len() - 2].starts_with("@seq=21;"));
    let big = d.alice.send(&mut d.a, &[9; 70_000]);
    h.send(
        &anon,
        &format!("POST {} {} {big}", d.m, d.alice.token(&d.a)),
    )
    .await;
    assert!(anon.lines()[0].ends_with("ERR rate-limited"));
}

/// One quota for a mailbox's posts, files and blobs (7.5): files and
/// blobs make its oldest posts expire early, never the other way round,
/// and its posts get what they leave.
#[tokio::test]
async fn one_quota_for_posts_and_files() {
    const QUOTA: u64 = 100_000;
    let mut config = config();
    config.limits.mailbox_quota = QUOTA;
    config.limits.posts_per_minute = 0;
    let mut h = Harness::with(config, timers());
    h.hub.set_files_url("https://chat.example.org");
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    // The commit that added Bob, which never expires early.
    let commit = h.store.mailbox_bytes(&d.m).unwrap();
    for i in 0..20u8 {
        let message = d.alice.send(&mut d.a, &[i; 1000]);
        h.send(
            &anon,
            &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
        )
        .await;
        assert!(anon.lines()[0].starts_with("OK seq="));
    }
    let posts = h.store.mailbox_bytes(&d.m).unwrap();
    assert!(posts > commit + 20_000, "{posts}");
    // A blob that fits beside the posts only if some expire: it leaves the
    // posts the commit and 10,000 bytes.
    let room = commit + 10_000;
    let token = d.alice.token(&d.a);
    let blob = |b: &[u8]| risala_proto::names::BlobRef::of(b);
    h.send(
        &anon,
        &format!(
            "BLOB {} {} box={} token={token}",
            blob(b"a"),
            QUOTA - room,
            d.m
        ),
    )
    .await;
    assert!(anon.raw_lines()[0].starts_with("OK put="));
    assert!(h.store.mailbox_bytes(&d.m).unwrap() <= room);
    // Another that does not fit beside it.
    h.send(
        &anon,
        &format!("BLOB {} 20000 box={} token={token}", blob(b"b"), d.m),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR rate-limited"]);
    // A post larger than what the blob leaves.
    let big = d.alice.send(&mut d.a, &[9; 15_000]);
    h.send(&anon, &format!("POST {} {token} {big}", d.m)).await;
    assert!(anon.lines()[0].ends_with("ERR rate-limited"));
    // A smaller one fits, and the posts stay within what is left.
    let small = d.alice.send(&mut d.a, &[9; 3000]);
    h.send(&anon, &format!("POST {} {token} {small}", d.m))
        .await;
    assert!(anon.lines()[0].starts_with("OK seq="));
    assert!(h.store.mailbox_bytes(&d.m).unwrap() <= room);
    // Once only the commit is left, a blob that does not fit beside it
    // is refused rather than the commit expired (7.5).
    h.send(
        &anon,
        &format!(
            "BLOB {} {} box={} token={token}",
            blob(b"c"),
            room - commit + 1,
            d.m
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR rate-limited"]);
    assert!(h.store.mailbox_bytes(&d.m).unwrap() >= commit);
}

/// POST, UPLOAD and BLOB share one window per network address (7.5).
#[tokio::test]
async fn one_address_window() {
    let mut config = config();
    config.limits.address_bytes_per_hour = 1_000_000;
    let mut h = Harness::with(config, timers());
    h.hub.set_files_url("https://chat.example.org");
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let token = d.alice.token(&d.a);
    // The commit that made the group took some of the window.
    let commit = d.commit.parse::<MlsMessage>().unwrap().decode().len() as u64;
    let size = 1_000_000 - commit - 3000;
    let blob = risala_proto::names::BlobRef::of(b"a");
    h.send(
        &anon,
        &format!("BLOB {blob} {size} box={} token={token}", d.m),
    )
    .await;
    let lines = anon.raw_lines();
    assert!(lines[0].starts_with("OK put="), "{lines:?}");
    let message = d.alice.send(&mut d.a, &[1; 6000]);
    h.send(&anon, &format!("POST {} {token} {message}", d.m))
        .await;
    assert!(anon.lines()[0].ends_with("ERR rate-limited"));
}

/// Retention: posts expire oldest first, and a mailbox whose posts have
/// all expired and that nobody follows ends (7.5).
#[tokio::test]
async fn retention() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let mut e = Direct::new(&h, &mut anon, 2).await;
    let day = Duration::from_secs(24 * 60 * 60);
    h.clock.advance(day * 20);
    let message = d.alice.send(&mut d.a, b"later");
    h.send(
        &anon,
        &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
    )
    .await;
    assert_eq!(anon.lines(), ["OK seq=2"]);
    h.send(&anon, &format!("FOLLOW {}", e.m)).await;
    assert_eq!(anon.lines(), ["OK head=1"]);
    // 30 days after the first posts.
    h.clock.advance(day * 10 + Duration::from_secs(1));
    run_maintenance(h.inner()).await.unwrap();
    h.send(&anon, &format!("FETCH {} after=0", d.m)).await;
    assert_eq!(anon.lines().len(), 2, "only seq 2 is left");
    h.send(&anon, &format!("FETCH {} after=0", e.m)).await;
    assert_eq!(anon.lines(), ["OK more=0"]);
    // Both are kept: one has a post, the other a follower.
    assert!(h.store.mailbox(&d.m).unwrap().is_some());
    assert!(h.store.mailbox(&e.m).unwrap().is_some());
    // Its token sets went with them, unused for a retention period (7.2).
    let message = e.alice.send(&mut e.a, b"still here");
    h.send(
        &anon,
        &format!("POST {} {} {message}", e.m, e.alice.token(&e.a)),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR stale"]);
    // Once nobody follows a mailbox whose posts have all gone, it ends.
    h.send(&anon, &format!("UNFOLLOW {}", e.m)).await;
    assert_eq!(anon.lines(), ["OK"]);
    h.clock.advance(day * 31);
    run_maintenance(h.inner()).await.unwrap();
    assert!(h.store.mailbox(&d.m).unwrap().is_none());
    assert!(h.store.mailbox(&e.m).unwrap().is_none());
    // Its box is never used again.
    h.send(
        &anon,
        &format!(
            "CREATE {} {} {}",
            d.m,
            GroupId::from_bytes([9; 32]),
            hash([1; 48])
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR name-taken"]);
}

/// FOLLOW's OK agrees with the live posts (3.6): posts sent to the
/// connection before it are at most its head, and those after it newer.
#[tokio::test]
async fn follow_agrees_with_live_posts() {
    let mut config = config();
    config.limits.posts_per_minute = 0;
    let mut h = Harness::with(config, timers());
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let messages: Vec<String> = (0..40).map(|i| d.alice.send(&mut d.a, &[i])).collect();
    let token = d.alice.token(&d.a);
    let mut posters = Vec::new();
    for _ in 0..4 {
        posters.push(h.anon().await);
    }
    let mut followers = Vec::new();
    for _ in 0..8 {
        followers.push(h.anon().await);
    }
    let posting = async {
        for (i, message) in messages.iter().enumerate() {
            h.send(&posters[i % 4], &format!("POST {} {token} {message}", d.m))
                .await;
        }
    };
    let following = async {
        for f in &followers {
            h.send(f, &format!("FOLLOW {}", d.m)).await;
            tokio::task::yield_now().await;
        }
    };
    tokio::join!(posting, following);
    for f in &mut followers {
        let lines = f.lines();
        let ok = lines
            .iter()
            .position(|l| l.starts_with("OK head="))
            .unwrap();
        let head: u64 = lines[ok]["OK head=".len()..].parse().unwrap();
        let seqs: Vec<u64> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("@seq="))
            .map(|l| l[..l.find(';').unwrap()].parse().unwrap())
            .collect();
        // Every post after the head, in order, and none before it.
        assert_eq!(seqs, ((head + 1)..=41).collect::<Vec<_>>(), "head {head}");
        assert!(lines[..ok].is_empty());
    }
}

/// A connection follows at most `max_follows` mailboxes (7.1).
#[tokio::test]
async fn follow_limit() {
    let mut config = config();
    config.limits.max_follows = 1000;
    let mut h = Harness::with(config, timers());
    let mut anon = h.anon().await;
    for n in 0..1001u32 {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        let mut gid = [0; 32];
        gid[..4].copy_from_slice(&n.to_be_bytes());
        h.store
            .create_mailbox(&NewMailbox {
                mailbox: BoxName::from_bytes(bytes),
                group_id: GroupId::from_bytes(gid),
                first_epoch: 0,
                moved_from: None,
                token_hash: TokenHash::from_bytes([1; 48]),
                created: T.parse().unwrap(),
            })
            .unwrap();
        h.send(&anon, &format!("FOLLOW {}", BoxName::from_bytes(bytes)))
            .await;
        let want = if n < 1000 {
            "OK head=0"
        } else {
            "ERR forbidden following too many mailboxes"
        };
        assert_eq!(anon.lines(), [want], "{n}");
    }
}

/// When an operator drops a mailbox, its followers get DROP, and nothing
/// of it is left but its box (6.1, 10.4).
#[tokio::test]
async fn drop_lines() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut other = h.anon().await;
    let d = Direct::new(&h, &mut anon, 1).await;
    h.send(&other, &format!("FOLLOW {}", d.m)).await;
    other.lines();
    assert!(drop_mailbox(h.inner(), &d.m, "spam\\sroom").await.unwrap());
    assert_eq!(other.lines(), [format!("DROP {} spam\\sroom", d.m)]);
    assert!(h.inner().mailbox.followers(&d.m).is_empty());
    assert!(!drop_mailbox(h.inner(), &d.m, "").await.unwrap());
    h.send(&other, &format!("FETCH {} after=0", d.m)).await;
    assert_eq!(other.lines(), ["ERR not-found"]);
    let _ = d.commit;
    let _ = d.next;
}

/// Nothing the store keeps names an anonymous or guest connection or its
/// address (4.2).
#[tokio::test]
async fn nothing_kept_about_anonymous_connections() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    let (guest, _) = h.guest("sam").await;
    let message = d.bob.send(&mut d.b, b"hi");
    h.send(
        &guest,
        &format!(
            "@cid=abcdefghijklmnop POST {} {} {message}",
            d.m,
            d.bob.token(&d.b)
        ),
    )
    .await;
    h.send(&guest, &format!("FOLLOW {}", d.m)).await;
    h.send(
        &anon,
        &format!("TOKEN {} 1 {} {}", d.m, d.bob.token(&d.b), hash([2; 48])),
    )
    .await;
    let conn = h.store.raw();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for table in tables {
        let mut select = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = select.column_count();
        let mut rows = select.query(params![]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for i in 0..columns {
                let text = match row.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                    rusqlite::types::ValueRef::Blob(b) => String::from_utf8_lossy(b).into_owned(),
                    _ => continue,
                };
                assert!(!text.contains("203.0.113.7"), "{table}: {text}");
                assert!(!text.contains("~sam"), "{table}: {text}");
            }
        }
    }
}

/// A public room for the tests of GONE, with `members` holding a leaf in
/// its group, set up in the store directly.
fn public_room(h: &Harness, n: u8, room: &str, members: &[&str]) -> BoxName {
    let mailbox = BoxName::from_bytes([n; 16]);
    h.store
        .create_mailbox(&NewMailbox {
            mailbox,
            group_id: GroupId::from_bytes([n; 32]),
            first_epoch: 0,
            moved_from: None,
            token_hash: TokenHash::from_bytes([n; 48]),
            created: T.parse().unwrap(),
        })
        .unwrap();
    let conn = h.store.raw();
    conn.execute(
        "INSERT INTO public_rooms (box, room, creator, epoch, epoch_seq, group_info, tree)
         VALUES (?, ?, 'alice@example.org', 0, 0, x'00', x'00')",
        params![&mailbox.as_bytes()[..], room],
    )
    .unwrap();
    for uid in members {
        conn.execute(
            "INSERT INTO room_members (box, uid) VALUES (?, ?)",
            params![&mailbox.as_bytes()[..], uid],
        )
        .unwrap();
    }
    mailbox
}

/// When a guest's session ends, the connections that follow a public room
/// it had a leaf in get GONE (4.2, 6.1), and nobody else does.
#[tokio::test]
async fn gone_when_a_guest_session_ends() {
    let mut h = Harness::new();
    let general = public_room(&h, 1, "#general", &["~sam", "alice@example.org"]);
    let help = public_room(&h, 2, "#help", &["~sam"]);
    let quiet = public_room(&h, 3, "#quiet", &["alice@example.org"]);

    let (sam, _) = h.guest("sam").await;
    let mut a = h.anon().await;
    let mut b = h.anon().await;
    let mut c = h.anon().await;
    for (conn, room) in [(&a, general), (&a, help), (&b, general), (&c, quiet)] {
        h.send(conn, &format!("FOLLOW {room}")).await;
    }
    for conn in [&mut a, &mut b, &mut c] {
        conn.lines();
    }

    // While the session waits to be resumed, nothing is sent.
    h.close(sam).await;
    assert!(a.lines().is_empty());
    h.end("sam").await;
    assert_eq!(
        a.lines(),
        [format!("GONE {general} ~sam"), format!("GONE {help} ~sam")]
    );
    assert_eq!(b.lines(), [format!("GONE {general} ~sam")]);
    assert!(c.lines().is_empty());

    // A connection that closed follows nothing.
    let mailbox = &h.inner().mailbox;
    h.close(b).await;
    assert_eq!(mailbox.followers(&general), [a.id]);
}

// ---- Public rooms (6.1, 6.4, 12.6)

/// A public room created on the owner's signed-in connection.
struct PublicRoomSetup {
    owen: Dev,
    o: MlsGroup,
    m: BoxName,
    signed: Client,
}

/// The GroupInfo and tree of a public room's group, as CREATE and
/// GROUPINFO carry them.
fn public_state(device: &Dev, group: &MlsGroup) -> (String, String) {
    let leaf_key = own_leaf_key(&device.provider, group).unwrap();
    let group_info = group
        .export_group_info(device.provider.crypto(), &leaf_key, false)
        .unwrap();
    (
        b64(&to_bytes(&group_info)),
        b64(&tree_to_bytes(&group.export_ratchet_tree())),
    )
}

fn public_conv(owner: &Dev, m: BoxName, guests: GuestMode) -> RisalaConversation {
    let room: Room = "#general".parse().unwrap();
    let mut conv = RisalaConversation::public_room(host(), *m.as_bytes(), &room, &owner.uid);
    conv.guests = guests;
    conv
}

/// The harness, with its clock at the system's time, so that KeyPackages
/// made now are within their lifetimes (12.5).
fn harness_now() -> Harness {
    let h = Harness::new();
    h.clock.set(Timestamp::now());
    h
}

async fn create_room(h: &mut Harness, n: u8) -> PublicRoomSetup {
    create_room_with(h, n, "#general", |_| {}).await
}

/// A public room named `room`, whose conversation extension `f` changes.
async fn create_room_with(
    h: &mut Harness,
    n: u8,
    room: &str,
    f: impl FnOnce(&mut RisalaConversation),
) -> PublicRoomSetup {
    let owen = Dev::new("owen@example.org", n);
    let m = mailbox(n);
    let mut conv = public_conv(&owen, m, GuestMode::Write);
    conv.name = room.into();
    f(&mut conv);
    let o = owen.create(&conv);
    let (group_info, tree) = public_state(&owen, &o);
    let mut signed = owen.sign_in(h);
    h.send(
        &signed,
        &format!(
            "CREATE {m} {} {} {room} {group_info} {tree}",
            gid(&o),
            owen.token_hash(&o)
        ),
    )
    .await;
    assert_eq!(signed.lines(), ["OK"]);
    PublicRoomSetup { owen, o, m, signed }
}

/// A join proposal (6.1) for the room's group as GROUPINFO shows it, by
/// `identity`, in base64.
fn join(device: &Dev, identity: &RisalaIdentity, room: &PublicRoomSetup) -> String {
    let made = make_join_key_package(
        &device.provider,
        identity,
        (!identity.is_guest()).then(|| device.profile()).as_ref(),
    )
    .unwrap();
    let context = room.o.public_group().group_context();
    b64(&join_proposal::<Provider<MemoryStorage>>(
        &made.key_package,
        context.group_id(),
        context.epoch().as_u64(),
        &made.leaf_key,
    )
    .unwrap())
}

/// Joining a public room by external proposal, with the token `-` (6.1,
/// 12.6): an identity's from any connection, a guest's from its own
/// guest connection, never a banned identity's or, with `guests none`, a
/// guest's. A full client commits them; the server then knows the room's
/// members, and a guest's end sends GONE.
#[tokio::test]
async fn public_room_joins() {
    let mut h = harness_now();
    let mut room = create_room(&mut h, 1).await;
    let m = room.m;
    let mut anon = h.anon().await;
    h.send(&anon, &format!("FOLLOW {m}")).await;
    anon.lines();
    let (mut sam_conn, _) = h.guest("sam").await;
    let dave = Dev::new("dave@example.org", 4);
    let sam = Dev::new("~sam", 5);
    let dave_join = join(&dave, &dave.identity(), &room);
    let sam_join = join(&sam, &RisalaIdentity::guest("~sam".parse().unwrap()), &room);

    h.send(&anon, &format!("POST {m} - {dave_join}")).await;
    let lines = anon.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[1], "OK seq=1");
    h.send(&anon, &format!("POST {m} - {sam_join}")).await;
    assert_eq!(
        anon.lines(),
        ["ERR forbidden a guest joins from its own connection"]
    );
    h.send(&sam_conn, &format!("POST {m} - {sam_join}")).await;
    assert_eq!(sam_conn.lines(), ["OK seq=2"]);
    // The owner's device commits both, by reference.
    for message in [&dave_join, &sam_join] {
        let bytes = message.parse::<MlsMessage>().unwrap().decode();
        process_message(&room.owen.provider, &mut room.o, &bytes).unwrap();
    }
    let token0 = room.owen.token(&room.o);
    let out = room.owen.commit(&mut room.o, Changes::default());
    h.send(
        &room.signed,
        &format!(
            "POST {m} {token0} {} next={} groupinfo={}",
            b64(&out.message),
            hash(out.next_token_hash),
            b64(out.group_info.as_ref().unwrap())
        ),
    )
    .await;
    assert_eq!(room.signed.lines(), ["OK seq=3"]);
    room.owen.merge(&mut room.o, &out);
    let role = |uid: &str| h.store.room_member(&m, &uid.parse().unwrap()).unwrap();
    assert_eq!(
        role("dave@example.org"),
        Some(risala_proto::types::Role::Member)
    );
    assert_eq!(role("~sam"), Some(risala_proto::types::Role::Member));
    assert_eq!(
        role("owen@example.org"),
        Some(risala_proto::types::Role::Owner)
    );
    // An old join, for epoch 0, is stale now.
    h.send(&anon, &format!("POST {m} - {dave_join}")).await;
    assert_eq!(anon.lines().last().unwrap(), "ERR stale");
    // Sam's session ends: the room's followers get GONE (6.1).
    h.close(sam_conn).await;
    h.end("sam").await;
    assert_eq!(anon.lines(), [format!("GONE {m} ~sam")]);

    // A room without guests, which has banned Mallory.
    let mallory = Dev::new("mallory@example.org", 6);
    let other = create_room_with(&mut h, 2, "#closed", |conv| {
        conv.guests = GuestMode::None;
        conv.bans = vec![mallory.uid.clone()];
    })
    .await;
    let (bea_conn, _) = h.guest("bea").await;
    let mut bea_conn = bea_conn;
    let bea = Dev::new("~bea", 7);
    let bea_join = join(
        &bea,
        &RisalaIdentity::guest("~bea".parse().unwrap()),
        &other,
    );
    h.send(&bea_conn, &format!("POST {} - {bea_join}", other.m))
        .await;
    assert_eq!(
        bea_conn.lines(),
        ["ERR forbidden this room does not let guests in"]
    );
    let mallory_join = join(&mallory, &mallory.identity(), &other);
    h.send(&anon, &format!("POST {} - {mallory_join}", other.m))
        .await;
    assert_eq!(anon.lines(), ["ERR forbidden banned"]);
    // `-` is only for joins.
    let message = room.owen.send(&mut room.o, b"hello");
    h.send(&anon, &format!("POST {m} - {message}")).await;
    assert_eq!(
        anon.lines(),
        ["ERR forbidden - is only for joining a public room"]
    );
}

/// A device joins a public room by external proposal; the owner's device
/// commits it and puts its Welcome with `-`; the joiner gets it with the
/// tree of its epoch, and joins (6.1, 12.6, 12.8).
#[tokio::test]
async fn public_room_welcomes() {
    let mut h = harness_now();
    let mut room = create_room(&mut h, 1).await;
    let m = room.m;
    let dave = Dev::new("dave@example.org", 4);
    let made =
        make_join_key_package(&dave.provider, &dave.identity(), Some(&dave.profile())).unwrap();
    let context = room.o.public_group().group_context();
    let proposal = b64(&join_proposal::<Provider<MemoryStorage>>(
        &made.key_package,
        context.group_id(),
        context.epoch().as_u64(),
        &made.leaf_key,
    )
    .unwrap());
    let kp_ref = made.key_package.hash_ref(dave.provider.crypto()).unwrap();
    let kp_ref =
        risala_proto::mls::KeyPackageRef::from_bytes(kp_ref.as_slice().try_into().unwrap());
    let mut anon = h.anon().await;
    h.send(&anon, &format!("POST {m} - {proposal}")).await;
    assert_eq!(anon.lines(), ["OK seq=1"]);
    // Nothing to fetch yet, and nothing to put before a commit applies it.
    h.send(&anon, &format!("WELCOME GET {kp_ref}")).await;
    assert_eq!(anon.lines(), ["ERR not-found"]);

    // The owner's device commits it.
    let bytes = proposal.parse::<MlsMessage>().unwrap().decode();
    process_message(&room.owen.provider, &mut room.o, &bytes).unwrap();
    let token0 = room.owen.token(&room.o);
    let out = room.owen.commit(&mut room.o, Changes::default());
    assert_eq!(out.added.len(), 1);
    h.send(
        &room.signed,
        &format!(
            "POST {m} {token0} {} next={} groupinfo={}",
            b64(&out.message),
            hash(out.next_token_hash),
            b64(out.group_info.as_ref().unwrap())
        ),
    )
    .await;
    assert_eq!(room.signed.lines(), ["OK seq=2"]);
    room.owen.merge(&mut room.o, &out);
    let welcome = risala_proto::mls::Welcome::from_bytes(out.welcome.as_ref().unwrap()).unwrap();

    // Only the committing device puts it.
    let other = Dev::new("owen@example.org", 9);
    let mut other_conn = other.sign_in(&mut h);
    h.send(&other_conn, &format!("WELCOME PUT {kp_ref} - {welcome}"))
        .await;
    assert_eq!(other_conn.lines(), ["ERR forbidden"]);
    h.send(&room.signed, &format!("WELCOME PUT {kp_ref} - {welcome}"))
        .await;
    assert_eq!(room.signed.lines(), ["OK"]);

    // The joiner gets it with the tree, and joins.
    h.send(&anon, &format!("WELCOME GET {kp_ref}")).await;
    let lines = anon.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[1], "OK");
    let words: Vec<&str> = lines[0].split(' ').collect();
    assert_eq!(words[0], "WELCOME");
    assert_eq!(words[2], welcome.to_string());
    // A tree too long for the line is a blob the server keeps (12.12).
    let tree = match words[3].strip_prefix("tree=").expect("a tree") {
        blob if blob.starts_with("sha384:") => {
            let blob: risala_proto::names::BlobRef = blob.parse().unwrap();
            crate::core::keys::blob_bytes(h.inner(), &blob, u64::MAX)
                .await
                .unwrap()
                .bytes
        }
        inline => inline
            .parse::<risala_proto::mls::RatchetTree>()
            .unwrap()
            .decode(),
    };
    let expect = risala_mls::checks::JoinExpectation {
        host: host(),
        own_uid: dave.uid.clone(),
        public_room: Some(("#general".parse().unwrap(), *m.as_bytes())),
    };
    let joined =
        join_by_welcome(&dave.provider, &out.welcome.unwrap(), Some(&tree), &expect).unwrap();
    assert_eq!(joined.group.epoch(), room.o.epoch());
    assert_eq!(
        joined.group.epoch_authenticator().as_slice(),
        room.o.epoch_authenticator().as_slice()
    );
}

/// Public rooms never move: CREATE with `from` naming one gets
/// `ERR forbidden`, even with the group's id and token (5.2, 7.8).
#[tokio::test]
async fn public_rooms_do_not_move() {
    let mut h = harness_now();
    let room = create_room(&mut h, 1).await;
    let mut anon = h.anon().await;
    h.send(
        &anon,
        &format!(
            "CREATE {} {} {} epoch=1 from={} token={}",
            mailbox(9),
            gid(&room.o),
            hash([6; 48]),
            room.m,
            room.owen.token(&room.o)
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR forbidden"]);
}

/// The second form of CREATE: a public room, on its owner's device's
/// signed-in connection, checked as 12.6 says (5.2, 6.1).
#[tokio::test]
async fn create_public_rooms() {
    let mut h = harness_now();
    let owen = Dev::new("owen@example.org", 1);
    let m = mailbox(1);
    let o = owen.create(&public_conv(&owen, m, GuestMode::Write));
    let (group_info, tree) = public_state(&owen, &o);
    let line = |m: BoxName, room: &str| {
        format!(
            "CREATE {m} {} {} {room} {group_info} {tree}",
            gid(&o),
            owen.token_hash(&o)
        )
    };
    // Not on another identity's connection, nor another device's.
    let mut mallory = h.signed_in_as("mallory@example.org");
    h.send(&mallory, &line(m, "#general")).await;
    assert!(mallory.lines()[0].starts_with("ERR invalid"));
    let mut other_device = h.signed_in_as("owen@example.org");
    h.send(&other_device, &line(m, "#general")).await;
    assert_eq!(
        other_device.lines(),
        ["ERR invalid the leaf is not this device's"]
    );
    let mut signed = owen.sign_in(&mut h);
    // Another name or box than the group's.
    h.send(&signed, &line(m, "#other")).await;
    assert!(signed.lines()[0].starts_with("ERR invalid"));
    h.send(&signed, &line(mailbox(2), "#general")).await;
    assert!(signed.lines()[0].starts_with("ERR invalid"));
    // Junk.
    let junk = b64(&[1; 100]);
    h.send(
        &signed,
        &format!(
            "CREATE {m} {} {} #general {junk} {tree}",
            gid(&o),
            owen.token_hash(&o)
        ),
    )
    .await;
    assert!(signed.lines()[0].starts_with("ERR invalid"));
    h.send(&signed, &line(m, "#general")).await;
    assert_eq!(signed.lines(), ["OK"]);
    // The name is taken; so are the box and the group id.
    let owen2 = Dev::new("owen@example.org", 2);
    let o2 = owen2.create(&public_conv(&owen2, mailbox(2), GuestMode::Write));
    let (gi2, tree2) = public_state(&owen2, &o2);
    let mut signed2 = owen2.sign_in(&mut h);
    h.send(
        &signed2,
        &format!(
            "CREATE {} {} {} #general {gi2} {tree2}",
            mailbox(2),
            gid(&o2),
            owen2.token_hash(&o2)
        ),
    )
    .await;
    assert_eq!(signed2.lines(), ["ERR name-taken"]);
    h.send(&signed, &line(m, "#general")).await;
    assert_eq!(signed.lines(), ["ERR name-taken"]);
    // GROUPINFO: epoch 0, seq 0.
    let mut anon = h.anon().await;
    h.send(&anon, &format!("GROUPINFO {m}")).await;
    assert_eq!(
        anon.lines(),
        [
            format!("GROUPINFO {m} 0 0 {group_info} {tree}"),
            "OK".into()
        ]
    );
    let room = h.store.room_member(&m, &owen.uid).unwrap();
    assert_eq!(room, Some(risala_proto::types::Role::Owner));
    // A private mailbox is not a public room.
    let d = Direct::new(&h, &mut anon, 9).await;
    h.send(&anon, &format!("GROUPINFO {}", d.m)).await;
    assert_eq!(anon.lines(), ["ERR not-found"]);
}

/// Who may create public rooms (5.2, 6.1), and how many a day.
#[tokio::test]
async fn room_creation_limits() {
    let mut config = config();
    config.limits.rooms_per_day = 1;
    let mut h = Harness::with(config.clone(), timers());
    h.clock.set(Timestamp::now());
    create_room(&mut h, 1).await;
    let owen = Dev::new("owen@example.org", 2);
    let o = owen.create(&public_conv(&owen, mailbox(2), GuestMode::Write));
    let (gi, tree) = public_state(&owen, &o);
    let mut signed = owen.sign_in(&mut h);
    let line = format!(
        "CREATE {} {} {} #other {gi} {tree}",
        mailbox(2),
        gid(&o),
        owen.token_hash(&o)
    );
    h.send(&signed, &line).await;
    assert!(signed.lines()[0].ends_with("ERR rate-limited"));

    config.room_creation = crate::config::RoomCreation::Nobody;
    let mut h = Harness::with(config, timers());
    h.clock.set(Timestamp::now());
    let mut signed = owen.sign_in(&mut h);
    h.send(&signed, &line).await;
    assert_eq!(
        signed.lines(),
        ["ERR forbidden this server does not let you create rooms"]
    );
}

/// A public room's commits: for the current epoch only, one an epoch, from
/// the committer's device's signed-in connection, with the GroupInfo the
/// commit makes; then GROUPINFO serves the new state (6.1, 12.6).
#[tokio::test]
async fn public_room_commits() {
    let mut h = harness_now();
    let PublicRoomSetup {
        owen,
        mut o,
        m,
        mut signed,
    } = create_room(&mut h, 1).await;
    let mut anon = h.anon().await;
    h.send(&anon, &format!("FOLLOW {m}")).await;
    assert_eq!(anon.lines(), ["OK head=0"]);
    let token0 = owen.token(&o);
    let out = owen.commit(&mut o, Changes::default());
    let commit = b64(&out.message);
    let next = hash(out.next_token_hash);
    let gi = b64(out.group_info.as_ref().unwrap());

    // Without its GroupInfo, or with another's.
    h.send(&signed, &format!("POST {m} {token0} {commit} next={next}"))
        .await;
    assert!(signed.lines()[0].starts_with("ERR invalid"));
    let (old_gi, _) = public_state(&owen, &o);
    h.send(
        &signed,
        &format!("POST {m} {token0} {commit} next={next} groupinfo={old_gi}"),
    )
    .await;
    assert!(signed.lines()[0].starts_with("ERR invalid"));
    // From an anonymous connection, or another device's.
    h.send(
        &anon,
        &format!("POST {m} {token0} {commit} next={next} groupinfo={gi}"),
    )
    .await;
    assert!(anon.lines()[0].starts_with("ERR forbidden"));
    let mut other = h.signed_in_as("owen@example.org");
    h.send(
        &other,
        &format!("POST {m} {token0} {commit} next={next} groupinfo={gi}"),
    )
    .await;
    assert!(other.lines()[0].starts_with("ERR forbidden"));
    // As it should be.
    h.send(
        &signed,
        &format!("POST {m} {token0} {commit} next={next} groupinfo={gi}"),
    )
    .await;
    let event = format!("@seq=1;t={} POST {m} {commit} next={next}", now(&h));
    assert_eq!(signed.lines(), ["OK seq=1"]);
    assert_eq!(anon.lines(), [event]);
    // A second commit for epoch 0 is stale.
    h.send(
        &signed,
        &format!("POST {m} {token0} {commit} next={next} groupinfo={gi}"),
    )
    .await;
    assert_eq!(signed.lines(), ["ERR stale"]);
    owen.merge(&mut o, &out);
    h.send(&anon, &format!("GROUPINFO {m}")).await;
    let (_, tree) = public_state(&owen, &o);
    assert_eq!(
        anon.lines(),
        [format!("GROUPINFO {m} 1 1 {gi} {tree}"), "OK".into()]
    );

    // Application messages are PrivateMessages, posted anonymously; a
    // commit as a PrivateMessage is refused.
    let message = owen.send(&mut o, b"hello room");
    let token1 = owen.token(&o);
    h.send(&anon, &format!("POST {m} {token1} {message}")).await;
    let event = format!("@seq=2;t={} POST {m} {message}", now(&h));
    assert_eq!(anon.lines(), [event, "OK seq=2".into()]);
    h.send(&signed, &format!("POST {m} {token1} {message}"))
        .await;
    assert_eq!(signed.lines(), ["ERR wrong-connection"]);

    // TOKEN is not for public rooms (7.2); light clients are not in this
    // version (12.6).
    h.send(&anon, &format!("TOKEN {m} 1 {token1} {}", hash([3; 48])))
        .await;
    assert_eq!(anon.lines(), ["ERR forbidden not in a public room"]);
    h.send(&anon, &format!("FETCH {m} after=0 leaf=0")).await;
    assert_eq!(anon.lines(), ["ERR not-supported light clients"]);

    // Once restarted, the hub rebuilds the room's group from the store.
    h.inner().mailbox.forget_room(&m);
    let out = owen.commit(&mut o, Changes::default());
    h.send(
        &signed,
        &format!(
            "POST {m} {token1} {} next={} groupinfo={}",
            b64(&out.message),
            hash(out.next_token_hash),
            b64(out.group_info.as_ref().unwrap())
        ),
    )
    .await;
    assert_eq!(signed.lines(), ["OK seq=3"]);
}

/// MUTE and UNMUTE (6.4): owners and moderators with a leaf, on a
/// signed-in connection, until the hours or the period's end.
#[tokio::test]
async fn mutes() {
    let mut h = harness_now();
    let PublicRoomSetup {
        owen,
        mut o,
        m,
        mut signed,
        ..
    } = create_room(&mut h, 1).await;
    let mut anon = h.anon().await;
    let pseudonym = Pseudonym::from_bytes(owen.pseudonym.0);
    // Nobody else may mute: not a member, nor a member of another room.
    let mut mallory = h.signed_in_as("mallory@example.org");
    h.send(&mallory, &format!("MUTE {m} {pseudonym}")).await;
    assert_eq!(
        mallory.lines(),
        ["ERR forbidden only the room's owners and moderators mute"]
    );
    // A private mailbox is not found.
    let d = Direct::new(&h, &mut anon, 9).await;
    h.send(&signed, &format!("MUTE {} {pseudonym}", d.m)).await;
    assert_eq!(signed.lines(), ["ERR not-found"]);
    h.send(&anon, &format!("MUTE {m} {pseudonym}")).await;
    assert_eq!(anon.lines(), ["ERR wrong-connection"]);

    h.send(&signed, &format!("MUTE {m} {pseudonym} hours=1"))
        .await;
    assert_eq!(signed.lines(), ["OK"]);
    let message = owen.send(&mut o, b"muted");
    let post = format!("POST {m} {} {message}", owen.token(&o));
    h.send(&anon, &post).await;
    assert_eq!(anon.lines(), ["ERR forbidden muted"]);
    h.send(&signed, &format!("UNMUTE {m} {pseudonym}")).await;
    assert_eq!(signed.lines(), ["OK"]);
    h.send(&anon, &post).await;
    assert_eq!(anon.lines(), ["OK seq=1"]);

    // At most until the end of the period: muted at 23:00 for 24 hours,
    // free at midnight.
    let late: Timestamp = format!("{}T23:00:00.000Z", &h.inner().now().to_string()[..10])
        .parse()
        .unwrap();
    h.clock.set(late);
    h.send(&signed, &format!("MUTE {m} {pseudonym}")).await;
    assert_eq!(signed.lines(), ["OK"]);
    h.send(&anon, &post).await;
    assert_eq!(anon.lines(), ["ERR forbidden muted"]);
    h.clock.advance(Duration::from_secs(60 * 60));
    h.send(&anon, &post).await;
    assert_eq!(anon.lines(), ["OK seq=2"]);
}

/// The commands' kinds as Section 13 has them, for this area (4.1).
#[tokio::test]
async fn kinds() {
    let mut h = Harness::new();
    let mut alice = h.signed_in_as("alice@example.org");
    let m = mailbox(1);
    for line in [
        format!("FOLLOW {m}"),
        format!("FETCH {m} after=0"),
        format!("GROUPINFO {m}"),
    ] {
        h.send(&alice, &line).await;
        assert_eq!(alice.lines(), ["ERR wrong-connection"], "{line}");
    }
    let mut anon = h.anon().await;
    let p = Pseudonym::from_bytes([1; 16]);
    h.send(&anon, &format!("UNMUTE {m} {p}")).await;
    assert_eq!(anon.lines(), ["ERR wrong-connection"]);
}

/// Proposals posted on their own in a public room (6.1, 12.6): an Update
/// comes from its leaf's device's signed-in connection; a proposal is for
/// the current epoch, and is kept for the commit that applies it.
#[tokio::test]
async fn public_room_updates() {
    let mut h = harness_now();
    let mut room = create_room(&mut h, 1).await;
    let m = room.m;
    let mut anon = h.anon().await;
    let token0 = room.owen.token(&room.o);
    let update =
        propose_update(&room.owen.provider, &mut room.o, &room.owen.profile(), None).unwrap();
    let message = b64(&update.message);
    h.send(&anon, &format!("POST {m} {token0} {message}")).await;
    assert_eq!(
        anon.lines(),
        ["ERR forbidden an identity's Update comes from its device's signed-in connection"]
    );
    let mut other = h.signed_in_as("owen@example.org");
    h.send(&other, &format!("POST {m} {token0} {message}"))
        .await;
    assert!(other.lines()[0].starts_with("ERR forbidden"));
    h.send(&room.signed, &format!("POST {m} {token0} {message}"))
        .await;
    assert_eq!(room.signed.lines(), ["OK seq=1"]);
    let stored = h.store.room_group(&m).unwrap().unwrap();
    assert_eq!(stored.proposals.len(), 1);
    // Proposals have no next and no groupinfo (5.2).
    h.send(
        &room.signed,
        &format!("POST {m} {token0} {message} next={}", hash([1; 48])),
    )
    .await;
    assert!(room.signed.lines()[0].starts_with("ERR invalid"));
    // Once restarted, the hub rebuilds the group with its pending
    // proposal, and the owner's commit that applies it is accepted.
    h.inner().mailbox.forget_room(&m);
    let out = room.owen.commit(&mut room.o, Changes::default());
    h.send(
        &room.signed,
        &format!(
            "POST {m} {token0} {} next={} groupinfo={}",
            b64(&out.message),
            hash(out.next_token_hash),
            b64(out.group_info.as_ref().unwrap())
        ),
    )
    .await;
    assert_eq!(room.signed.lines(), ["OK seq=2"]);
    assert!(
        h.store
            .room_group(&m)
            .unwrap()
            .unwrap()
            .proposals
            .is_empty()
    );
}

// ---- Resource limits (the code review's findings)

/// The owner's device commits whatever proposals it has, and posts the
/// commit; the server must take it.
async fn commit_pending(h: &Harness, room: &mut PublicRoomSetup, seq: u64) {
    let token = room.owen.token(&room.o);
    let out = room.owen.commit(&mut room.o, Changes::default());
    h.send(
        &room.signed,
        &format!(
            "POST {} {token} {} next={} groupinfo={}",
            room.m,
            b64(&out.message),
            hash(out.next_token_hash),
            b64(out.group_info.as_ref().unwrap())
        ),
    )
    .await;
    assert_eq!(room.signed.lines(), [format!("OK seq={seq}")]);
    room.owen.merge(&mut room.o, &out);
}

/// The owner's device takes a join proposal the server accepted.
fn take_proposal(room: &mut PublicRoomSetup, message: &str) {
    let bytes = message.parse::<MlsMessage>().unwrap().decode();
    process_message(&room.owen.provider, &mut room.o, &bytes).unwrap();
}

/// A post whose message is a blob is read only as far as its framing:
/// a PrivateMessage of any size posts, a blob that is not one is refused,
/// and the post's slot is used up before the blob is read, so that posts
/// that fail cost their sender too (5.2, 12.12).
#[tokio::test]
async fn blob_posts_are_read_only_to_their_framing() {
    let mut config = config();
    config.limits.posts_per_minute = 4;
    let mut h = Harness::with(config, timers());
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    // A message much larger than what POST reads of a blob.
    let big = d.alice.send(&mut d.a, &[5; 100_000]);
    let bytes = big.parse::<MlsMessage>().unwrap().decode();
    assert!(bytes.len() > 64 * 1024);
    let blob = hold_blob(&h, &bytes, Some(&d.m));
    let token = d.alice.token(&d.a);
    h.send(&anon, &format!("POST {} {token} {blob}", d.m)).await;
    assert_eq!(anon.lines(), ["OK seq=2"]);
    h.send(&anon, &format!("FETCH {} after=1", d.m)).await;
    let lines = anon.lines();
    assert!(lines[0].ends_with(&format!(" {blob}")), "{lines:?}");
    // Not a PrivateMessage.
    let junk = hold_blob(&h, &[7; 70_000], Some(&d.m));
    h.send(&anon, &format!("POST {} {token} {junk}", d.m)).await;
    assert!(anon.lines()[0].starts_with("ERR invalid"));
    // A wrong token: refused, but the slot is used up all the same.
    let wrong = risala_proto::mls::SendToken::from_bytes([9; 32]).to_string();
    assert_ne!(wrong, token);
    h.send(&anon, &format!("POST {} {wrong} {blob}", d.m)).await;
    let lines = anon.lines();
    assert!(lines[0].starts_with("ERR"), "{lines:?}");
    h.send(&anon, &format!("POST {} {token} {blob}", d.m)).await;
    let lines = anon.lines();
    assert!(lines[0].ends_with("ERR rate-limited"), "{lines:?}");
}

/// The framing of a PrivateMessage in a blob, from its first bytes: the
/// lengths must add up to the blob's size (5.2).
#[test]
fn private_message_stubs() {
    use crate::core::mailbox::private_message_stub;
    use risala_proto::codec::Writer;
    let message = |ciphertext: &[u8]| {
        let mut w = Writer::new();
        w.fixed(&1u16.to_be_bytes()).fixed(&2u16.to_be_bytes());
        w.vector(&[4; 32]).u64(7).u8(1).vector(b"aad");
        w.vector(b"sender").vector(ciphertext);
        w.finish()
    };
    let whole = message(&[9; 50_000]);
    let prefix = &whole[..1000];
    let stub = private_message_stub(prefix, whole.len() as u64).unwrap();
    let read = |bytes: &[u8]| {
        let (framing, _) = risala_mls::framing::read_message(bytes)
            .map(|m| match m {
                risala_mls::framing::MlsMessage::Message(f) => {
                    (f.epoch, f.authenticated_data.to_vec())
                }
                other => panic!("{other:?}"),
            })
            .unwrap();
        framing
    };
    assert_eq!(read(&stub), read(&whole));
    // The wrong size, or a PublicMessage, gives none.
    assert!(private_message_stub(prefix, whole.len() as u64 + 1).is_none());
    assert!(private_message_stub(prefix, whole.len() as u64 - 1).is_none());
    let mut public = whole.clone();
    public[3] = 1;
    assert!(private_message_stub(&public[..1000], whole.len() as u64).is_none());
    assert!(private_message_stub(&whole[..10], whole.len() as u64).is_none());
}

/// A post to a public room that fails its checks leaves the room's group
/// in memory, so that it is not rebuilt for the next post (12.6).
#[tokio::test]
async fn failed_room_posts_keep_the_group_in_memory() {
    let mut h = harness_now();
    let room = create_room(&mut h, 1).await;
    let m = room.m;
    assert!(h.inner().mailbox.room_cached(&m));
    let mut anon = h.anon().await;
    let dave = Dev::new("dave@example.org", 4);
    let good = join(&dave, &dave.identity(), &room);
    // Its signature, at the end, broken.
    let mut bytes = good.parse::<MlsMessage>().unwrap().decode();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    h.send(&anon, &format!("POST {m} - {}", b64(&bytes))).await;
    assert!(anon.lines()[0].starts_with("ERR invalid"));
    assert!(h.inner().mailbox.room_cached(&m));
    h.send(&anon, &format!("POST {m} - {good}")).await;
    assert_eq!(anon.lines(), ["OK seq=1"]);
    assert!(h.inner().mailbox.room_cached(&m));
}

/// FETCH stops a page of long posts at a budget of bytes, with `more=1`,
/// so that the page fits in the connection's queue (7.1).
#[tokio::test]
async fn fetch_pages_stop_at_a_byte_budget() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let mut d = Direct::new(&h, &mut anon, 1).await;
    for i in 0..14u8 {
        let message = d.alice.send(&mut d.a, &vec![i; 700_000]);
        h.send(
            &anon,
            &format!("POST {} {} {message}", d.m, d.alice.token(&d.a)),
        )
        .await;
        assert!(anon.lines()[0].starts_with("OK seq="));
    }
    h.send(&anon, &format!("FETCH {} after=0 limit=50", d.m))
        .await;
    let lines = anon.lines();
    let posts = lines.len() - 1;
    assert_eq!(lines[posts], "OK more=1");
    let bytes: usize = lines[..posts].iter().map(|l| l.len()).sum();
    assert!(bytes <= 8 * 1024 * 1024, "{bytes}");
    assert!(posts < 15, "{posts}");
    // The rest come with the next page.
    h.send(&anon, &format!("FETCH {} after={posts} limit=50", d.m))
        .await;
    let rest = anon.lines();
    assert_eq!(rest.last().unwrap(), "OK more=0");
    assert_eq!(posts + rest.len() - 1, 15);
}

/// The server refuses joins of public rooms, by proposal or by external
/// commit, from identities it bans (10.2); and a guest connection posts
/// no join but its own guest's (12.6).
#[tokio::test]
async fn server_bans_and_guests_in_public_room_joins() {
    let mut h = harness_now();
    let mut room = create_room(&mut h, 1).await;
    let m = room.m;
    let mut anon = h.anon().await;
    let dave = Dev::new("dave@example.org", 4);
    let dave_join = join(&dave, &dave.identity(), &room);
    // From a guest's connection.
    let (mut sam_conn, _) = h.guest("sam").await;
    h.send(&sam_conn, &format!("POST {m} - {dave_join}")).await;
    assert_eq!(
        sam_conn.lines(),
        ["ERR forbidden a guest connection joins only its own guest"]
    );
    // Dave joins, and the owner commits it.
    h.send(&anon, &format!("POST {m} - {dave_join}")).await;
    assert_eq!(anon.lines(), ["OK seq=1"]);
    take_proposal(&mut room, &dave_join);
    commit_pending(&h, &mut room, 2).await;
    // The server bans Dave's identity, and Mallory's domain.
    let mut op = h.signed_in_as("op@example.org");
    h.send(&op, "ADMIN BAN dave@example.org").await;
    h.send(&op, "ADMIN BAN *@evil.example").await;
    assert_eq!(op.lines(), ["OK", "OK"]);
    let mallory = Dev::new("mallory@evil.example", 6);
    let mallory_join = join(&mallory, &mallory.identity(), &room);
    h.send(&anon, &format!("POST {m} - {mallory_join}")).await;
    assert_eq!(anon.lines(), ["ERR forbidden banned from this server"]);
    // Dave's device resyncs (12.7): refused while he is banned.
    let resync = resync_commit(&h, &mut anon, &dave, &room).await;
    let mut dave_conn = dave.sign_in(&mut h);
    h.send(&dave_conn, &resync).await;
    assert_eq!(dave_conn.lines(), ["ERR forbidden banned from this server"]);
    h.send(&op, "ADMIN UNBAN dave@example.org").await;
    assert_eq!(op.lines(), ["OK"]);
    h.send(&dave_conn, &resync).await;
    assert_eq!(dave_conn.lines(), ["OK seq=3"]);
}

/// A resync commit (12.7): a member's device whose group cannot follow
/// joins again by external commit against GROUPINFO, which removes the
/// leaf that signed the GroupInfo. The server checks it as one, from the
/// member's own signed-in connection, and the room's epoch moves on.
#[tokio::test]
async fn public_room_resync_commits() {
    let mut h = harness_now();
    let mut room = create_room(&mut h, 1).await;
    let m = room.m;
    let mut anon = h.anon().await;
    let dave = Dev::new("dave@example.org", 4);
    let dave_join = join(&dave, &dave.identity(), &room);
    h.send(&anon, &format!("POST {m} - {dave_join}")).await;
    assert_eq!(anon.lines(), ["OK seq=1"]);
    take_proposal(&mut room, &dave_join);
    commit_pending(&h, &mut room, 2).await;
    let resync = resync_commit(&h, &mut anon, &dave, &room).await;
    // Not from an anonymous connection, nor from another device's.
    h.send(&anon, &resync).await;
    assert!(anon.lines()[0].starts_with("ERR forbidden"));
    let mut dave_conn = dave.sign_in(&mut h);
    h.send(&dave_conn, &resync).await;
    assert_eq!(dave_conn.lines(), ["OK seq=3"]);
    // The owner's leaf, which signed the GroupInfo, is gone; Dave's is in.
    let role = |uid: &str| h.store.room_member(&m, &uid.parse().unwrap()).unwrap();
    assert_eq!(role("owen@example.org"), None);
    assert!(role("dave@example.org").is_some());
    h.send(&anon, &format!("GROUPINFO {m}")).await;
    let lines = anon.lines();
    assert!(
        lines[0].starts_with(&format!("GROUPINFO {m} 2 3 ")),
        "{lines:?}"
    );
    // The same commit again is for an old epoch now.
    h.send(&dave_conn, &resync).await;
    assert_eq!(dave_conn.lines(), ["ERR stale"]);
}

/// Dave's resync commit against the room's GROUPINFO, as a POST line.
async fn resync_commit(
    h: &Harness,
    anon: &mut Client,
    dave: &Dev,
    room: &PublicRoomSetup,
) -> String {
    let m = room.m;
    h.send(anon, &format!("GROUPINFO {m}")).await;
    let lines = anon.lines();
    assert_eq!(lines[1], "OK");
    let words: Vec<&str> = lines[0].split(' ').collect();
    let group_info = words[4].parse::<MlsMessage>().unwrap().decode();
    let tree = words[5]
        .parse::<risala_proto::mls::RatchetTree>()
        .unwrap()
        .decode();
    let expect = risala_mls::checks::JoinExpectation {
        host: host(),
        own_uid: dave.uid.clone(),
        public_room: Some(("#general".parse().unwrap(), *m.as_bytes())),
    };
    let fresh = Dev::new(dave.uid.as_str(), 40);
    let resync = risala_mls::group::external_commit(
        &fresh.provider,
        &dave.identity(),
        &dave.profile(),
        &group_info,
        &tree,
        &expect,
        risala_mls::checks::External::Resync,
        &[],
    )
    .unwrap();
    format!(
        "POST {m} - {} next={} groupinfo={}",
        b64(&resync.message),
        hash(resync.next_token_hash),
        b64(&resync.group_info)
    )
}

/// Join proposals have their own limit per network address, and one
/// address may have only so many proposals pending in one epoch (6.1,
/// 12.6).
#[tokio::test]
async fn join_proposals_are_limited_per_address() {
    let mut h = Harness::with(
        {
            let mut c = config();
            c.limits.joins_per_hour = 3;
            c.limits.pending_per_address = 2;
            c
        },
        timers(),
    );
    h.clock.set(Timestamp::now());
    let mut room = create_room(&mut h, 1).await;
    let m = room.m;
    let mut anon = h.anon().await;
    let devs: Vec<Dev> = (0..5)
        .map(|i| Dev::new(&format!("j{i}@example.org"), 10 + i))
        .collect();
    let joins: Vec<String> = devs.iter().map(|d| join(d, &d.identity(), &room)).collect();
    for join in &joins[..2] {
        h.send(&anon, &format!("POST {m} - {join}")).await;
        assert!(anon.lines()[0].starts_with("OK seq="));
    }
    // Two of this address's proposals are pending in the epoch.
    h.send(&anon, &format!("POST {m} - {}", joins[2])).await;
    assert_eq!(anon.lines(), ["@retry=60 ERR rate-limited"]);
    // Another address may still propose.
    let mut other = h.connect_from("198.51.100.9:4000");
    h.send(&other, "ANON").await;
    other.lines();
    h.send(&other, &format!("POST {m} - {}", joins[2])).await;
    assert_eq!(other.lines(), ["OK seq=3"]);
    // Once a commit starts a new epoch, the first address may propose
    // again, until its joins for the hour are used up.
    for join in &joins[..3] {
        take_proposal(&mut room, join);
    }
    commit_pending(&h, &mut room, 4).await;
    let fresh = join(&devs[3], &devs[3].identity(), &room);
    h.send(&anon, &format!("POST {m} - {fresh}")).await;
    assert_eq!(anon.lines(), ["OK seq=5"]);
    let more = join(&devs[4], &devs[4].identity(), &room);
    h.send(&anon, &format!("POST {m} - {more}")).await;
    assert!(anon.lines()[0].ends_with("ERR rate-limited"));
}

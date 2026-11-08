//! Transcript tests of encrypted conversations with real MLS groups
//! (Section 12): KEYPKG ADD (12.4), INIT, COMMIT and GROUPINFO (12.5,
//! 12.6), ENC (12.8), direct conversations (5.1) and REPORTENC (5.8).
//!
//! Each [`Device`] is an OpenMLS client built with `risala-mls`, as
//! librisala's is, with its state in memory. The hub's clock is the
//! system's time, since OpenMLS stamps KeyPackages with it.

use std::sync::Arc;
use std::time::Duration;

use openmls_memory_storage::MemoryStorage;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::{
    KeyPackage, LeafNodeIndex, ProcessedMessageContent, ProtocolMessage,
};
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::wire;
use risala_mls::{Changes, Provider, RisalaConversation};
use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::mls;
use risala_proto::names::{Identity, Uid};
use risala_proto::time::Timestamp;
use risala_proto::types::{HistoryMode, SendMode};

use super::tests::{Client, Harness, config, timers};
use super::*;
use crate::store::SqliteStore;

/// Hosted here.
pub(super) const ALICE: &str = "alice@example.org";
/// Not hosted: its key file comes from the fetcher.
pub(super) const BOB: &str = "bob@example.net";
/// Hosted here.
pub(super) const CAROL: &str = "carol@example.org";

pub(super) fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn identity(s: &str) -> Identity {
    s.parse().unwrap()
}

pub(super) fn secret(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

pub(super) fn key(n: u8) -> PublicKey {
    secret(n).public_key()
}

/// A device: an identity, its device key `n`, and its MLS state.
pub(super) struct Device {
    pub(super) uid: Uid,
    pub(super) secret: SecretKey,
    pub(super) provider: Provider<MemoryStorage>,
}

impl Device {
    pub(super) fn new(who: &str, n: u8) -> Device {
        Device {
            uid: uid(who),
            secret: secret(n),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
        }
    }

    pub(super) fn signer(&self) -> risala_mls::DeviceSigner<'_> {
        risala_mls::DeviceSigner::new(&self.secret)
    }

    /// A new KeyPackage of this device, as on the wire.
    pub(super) fn key_package(&self, last_resort: bool) -> mls::KeyPackage {
        let bundle =
            risala_mls::key_package(&self.provider, &self.signer(), &self.uid, last_resort)
                .unwrap();
        wire::key_package_to_wire(bundle.key_package()).unwrap()
    }

    /// A new KeyPackage of this device, to add it with.
    pub(super) fn kp(&self) -> KeyPackage {
        risala_mls::key_package(&self.provider, &self.signer(), &self.uid, false)
            .unwrap()
            .key_package()
            .clone()
    }

    /// A new group with this device alone in it.
    pub(super) fn create(&self, conversation: &RisalaConversation) -> MlsGroup {
        risala_mls::create_group(&self.provider, &self.signer(), &self.uid, conversation).unwrap()
    }

    /// The INIT line for `group`, of the conversation `conv`.
    pub(super) fn init_line(&self, conv: &str, group: &MlsGroup) -> String {
        let gi = group
            .export_group_info(self.provider.crypto(), &self.signer(), false)
            .unwrap();
        let gi = wire::group_info_to_wire(&gi).unwrap();
        let tree = wire::tree_to_wire(&group.export_ratchet_tree()).unwrap();
        format!("init {conv} {gi} {tree}")
    }

    /// A commit of `changes`, left pending in `group`.
    pub(super) fn commit(&self, group: &mut MlsGroup, changes: Changes) -> Sent {
        let bundle = risala_mls::commit(&self.provider, group, &self.signer(), changes).unwrap();
        Sent::of(bundle.into_messages())
    }

    /// Joins by the Welcome and tree of a WELCOME line.
    pub(super) fn join(&self, line: &str) -> MlsGroup {
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts[0], "WELCOME", "{line}");
        let welcome: mls::Welcome = parts[4].parse().unwrap();
        let tree: mls::RatchetTree = parts[5].parse().unwrap();
        risala_mls::stage_welcome(
            &self.provider,
            wire::welcome_from_wire(&welcome).unwrap(),
            wire::tree_from_wire(&tree).unwrap(),
        )
        .unwrap()
        .into_group(&self.provider)
        .unwrap()
    }

    /// Joins by external commit, from a GROUPINFO line.
    pub(super) fn join_external(&self, line: &str) -> (MlsGroup, Sent) {
        let parts: Vec<&str> = line.split(' ').collect();
        assert_eq!(parts[0], "GROUPINFO", "{line}");
        let gi: mls::GroupInfo = parts[4].parse().unwrap();
        let tree: mls::RatchetTree = parts[5].parse().unwrap();
        let (group, bundle) = risala_mls::join_by_external_commit(
            &self.provider,
            &self.signer(),
            &self.uid,
            wire::group_info_from_wire(&gi).unwrap(),
            wire::tree_from_wire(&tree).unwrap(),
        )
        .unwrap();
        (group, Sent::of(bundle.into_messages()))
    }

    /// Applies the commit of a COMMIT event line.
    pub(super) fn apply(&self, group: &mut MlsGroup, line: &str) {
        let commit: mls::CommitMessage = line.rsplit(' ').next().unwrap().parse().unwrap();
        let message: ProtocolMessage = wire::commit_from_wire(&commit).unwrap();
        let processed = group.process_message(&self.provider, message).unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not a commit");
        };
        group.merge_staged_commit(&self.provider, *staged).unwrap();
    }

    /// The leaf of `key` in `group`.
    pub(super) fn leaf(group: &MlsGroup, key: &PublicKey) -> LeafNodeIndex {
        group
            .members()
            .find(|m| m.signature_key == key.as_bytes())
            .unwrap()
            .index
    }
}

/// What a device sends with COMMIT.
pub(super) struct Sent {
    pub(super) commit: mls::CommitMessage,
    pub(super) group_info: mls::GroupInfo,
    pub(super) welcome: Option<mls::Welcome>,
}

impl Sent {
    fn of(
        (commit, welcome, group_info): (
            risala_mls::openmls::prelude::MlsMessageOut,
            Option<risala_mls::openmls::prelude::MlsMessageOut>,
            Option<risala_mls::openmls::prelude::MlsMessageOut>,
        ),
    ) -> Sent {
        Sent {
            commit: wire::commit_to_wire(&commit).unwrap(),
            group_info: wire::group_info_to_wire(&group_info.unwrap()).unwrap(),
            welcome: welcome.map(|w| wire::welcome_to_wire(&w).unwrap()),
        }
    }

    /// The COMMIT line, with the Welcome if there is one.
    pub(super) fn line(&self, conv: &str) -> String {
        match &self.welcome {
            Some(w) => format!("commit {conv} {} {} {w}", self.commit, self.group_info),
            None => format!("commit {conv} {} {}", self.commit, self.group_info),
        }
    }

    /// The COMMIT line without its Welcome.
    pub(super) fn line_without_welcome(&self, conv: &str) -> String {
        format!("commit {conv} {} {}", self.commit, self.group_info)
    }
}

/// A line without its tags.
pub(super) fn untagged(line: &str) -> &str {
    match line.strip_prefix('@') {
        Some(rest) => rest.split_once(' ').map_or(rest, |(_, l)| l),
        None => line,
    }
}

/// The lines without their tags, with long values cut to 12 characters.
pub(super) fn short(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| {
            untagged(l)
                .split(' ')
                .map(|w| if w.len() > 40 { &w[..12] } else { w })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// The line of `lines` that starts with `start`, once its tags are gone.
pub(super) fn find<'a>(lines: &'a [String], start: &str) -> &'a str {
    lines
        .iter()
        .find(|l| untagged(l).starts_with(start))
        .unwrap_or_else(|| panic!("no {start:?} in {:?}", short(lines)))
}

/// A hub that hosts `example.org`, where alice is registered with keys 1,
/// 2 and 3 and carol with 7, and bob of `example.net` has signed in before
/// with key file 5 and 6. Its clock is the system's.
pub(super) struct World {
    pub(super) h: Harness,
    #[allow(dead_code)] // For the tests of commits.
    pub(super) fetcher: Arc<MemoryFetcher>,
}

impl World {
    pub(super) fn new() -> World {
        let mut c = config();
        c.identity_domain = Some("example.org".into());
        let store = SqliteStore::open_in_memory().unwrap();
        let now = Timestamp::now();
        store.register(&uid(ALICE), &key(1), now).unwrap();
        for n in [2, 3] {
            store
                .add_hosted_key(&uid(ALICE), &key(n), "", 64, now)
                .unwrap();
        }
        store.register(&uid(CAROL), &key(7), now).unwrap();
        store.touch_identity(&uid(BOB), now).unwrap();
        let store: Arc<dyn Store> = Arc::new(store);
        let fetcher = Arc::new(MemoryFetcher::new());
        fetcher.set(&identity(BOB), vec![key(5), key(6)]);
        let keys = KeyServices::shared(fetcher.clone(), Arc::new(NoPublisher));
        let clock = Arc::new(ManualClock::new(now));
        let hub = Hub::build(c, store.clone(), clock.clone(), timers(), keys).unwrap();
        World {
            h: Harness {
                hub,
                store,
                clock,
                next: 0,
            },
            fetcher,
        }
    }

    /// A connection signed in as `d`'s identity with its device key,
    /// without AUTH.
    pub(super) fn connect(&mut self, d: &Device) -> Client {
        let c = self.h.connect();
        assert!(
            self.h
                .hub
                .inner
                .reg()
                .attach(c.id, &d.uid, Some(d.secret.public_key()))
        );
        c
    }

    pub(super) async fn send(&self, c: &Client, line: &str) {
        self.h.send(c, line).await;
    }

    /// Sends `line` from `c`, and returns what `c` got.
    pub(super) async fn ask(&self, c: &mut Client, line: &str) -> Vec<String> {
        self.h.send(c, line).await;
        c.lines()
    }
}

// ---------------------------------------------------------------------------
// KEYPKG ADD (12.4)

#[tokio::test]
async fn keypkg_add_checks_key_packages() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c = w.connect(&a1);

    let kp = a1.key_package(false);
    w.send(&c, &format!("keypkg add {kp}")).await;
    assert_eq!(c.lines(), ["OK"]);
    // The same one again is stored once.
    w.send(&c, &format!("keypkg add {kp}")).await;
    assert_eq!(c.lines(), ["OK"]);
    w.send(&c, &format!("keypkg add {}", a1.key_package(true)))
        .await;
    assert_eq!(c.lines(), ["OK"]);
    w.send(&c, "keypkg count").await;
    assert_eq!(c.lines(), ["OK count=1 last-resort=yes"]);

    // Another device's KeyPackage, of the same identity or not.
    for other in [Device::new(ALICE, 2), Device::new(CAROL, 7)] {
        w.send(&c, &format!("keypkg add {}", other.key_package(false)))
            .await;
        assert_eq!(
            c.lines(),
            ["ERR invalid the KeyPackage's signature key is not the device key"]
        );
    }
    // The right key under another uid.
    let mut wrong = Device::new(CAROL, 1);
    wrong.uid = uid(CAROL);
    w.send(&c, &format!("keypkg add {}", wrong.key_package(false)))
        .await;
    assert_eq!(
        c.lines(),
        ["ERR invalid the KeyPackage's credential is not the uid"]
    );
    // A GroupInfo is not a KeyPackage.
    let group = risala_mls::create_group(
        &a1.provider,
        &a1.signer(),
        &a1.uid,
        &risala_mls::RisalaConversation::direct(&a1.uid, &uid(BOB)),
    )
    .unwrap();
    let gi = group
        .export_group_info(a1.provider.crypto(), &a1.signer(), false)
        .unwrap();
    let gi = wire::group_info_to_wire(&gi).unwrap();
    w.send(&c, &format!("keypkg add {gi}")).await;
    assert_eq!(
        c.lines(),
        ["ERR invalid the MLSMessage is not a KeyPackage"]
    );

    // Out of its lifetime: two weeks before it starts, and after it ends.
    w.h.clock.set(
        Timestamp::now()
            .checked_sub(std::time::Duration::from_secs(14 * 86400))
            .unwrap(),
    );
    w.send(&c, &format!("keypkg add {}", a1.key_package(false)))
        .await;
    assert_eq!(
        c.lines(),
        ["ERR invalid the KeyPackage's lifetime is not acceptable"]
    );
    w.send(&c, "keypkg count").await;
    assert_eq!(c.lines(), ["OK count=1 last-resort=yes"]);
}

#[test]
fn lifetimes_agree() {
    assert_eq!(
        MAX_KEY_PACKAGE_LIFETIME,
        risala_mls::group::MAX_LIFETIME_SPAN
    );
}

// ---------------------------------------------------------------------------
// Encrypted rooms: INIT, COMMIT and GROUPINFO (12.3, 12.5, 12.6)

/// The value of `key=` in the last line of `lines`.
fn ok_value(lines: &[String], key: &str) -> String {
    super::tests::value(lines.last().unwrap(), key)
}

/// `#r`, created by alice's device 1 and encrypted by it, with `history`
/// and `send` as given. Returns the room's id and alice's group.
async fn encrypted_room(
    w: &mut World,
    a1: &Device,
    c: &mut Client,
    history: HistoryMode,
    send: SendMode,
) -> (risala_proto::names::Id, MlsGroup) {
    let lines = w.ask(c, "join #r").await;
    let id: risala_proto::names::Id = ok_value(&lines, "id").parse().unwrap();
    let group = a1.create(&RisalaConversation::room(&id, history, send));
    let lines = w.ask(c, &a1.init_line("#r", &group)).await;
    assert_eq!(lines.last().unwrap(), &format!("OK id={id} epoch=0"));
    (id, group)
}

#[tokio::test]
async fn init_encrypts_a_room_for_good() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c = w.connect(&a1);
    let lines = w.ask(&mut c, "join #r").await;
    let id: risala_proto::names::Id = ok_value(&lines, "id").parse().unwrap();

    // The extension must name this room.
    let other = a1.create(&RisalaConversation::room(
        &"zzzz".parse().unwrap(),
        HistoryMode::Shared,
        SendMode::All,
    ));
    assert_eq!(
        w.ask(&mut c, &a1.init_line("#r", &other)).await,
        ["ERR invalid the conversation extension names another conversation"]
    );
    let direct = a1.create(&RisalaConversation::direct(&a1.uid, &uid(BOB)));
    assert_eq!(
        w.ask(&mut c, &a1.init_line("#r", &direct)).await,
        ["ERR invalid the conversation extension names another conversation"]
    );
    // Another device's group.
    let a2 = Device::new(ALICE, 2);
    let theirs = a2.create(&RisalaConversation::room(
        &id,
        HistoryMode::Shared,
        SendMode::All,
    ));
    assert_eq!(
        w.ask(&mut c, &a2.init_line("#r", &theirs)).await,
        ["ERR invalid the leaf is not this device's"]
    );
    // Not while another identity is a member.
    let mut c7 = w.connect(&Device::new(CAROL, 7));
    w.ask(&mut c7, "join #r").await;
    c.lines();
    let group = a1.create(&RisalaConversation::room(
        &id,
        HistoryMode::Joined,
        SendMode::Mods,
    ));
    assert_eq!(
        w.ask(&mut c, &a1.init_line("#r", &group)).await,
        ["ERR forbidden a room is encrypted while its owner is its only member"]
    );
    w.ask(&mut c7, "part #r").await;
    c.lines();
    // An invitation made before is ended by INIT.
    w.ask(&mut c, "invite #r bob@example.net").await;

    let lines = w.ask(&mut c, &a1.init_line("#r", &group)).await;
    assert_eq!(
        short(&lines),
        [
            "SET #r public no",
            "SET #r guests none",
            "SET #r e2ee yes",
            "SET #r history joined",
            "SET #r send mods",
            &format!("OK id={id} epoch=0"),
        ]
    );
    // Once only, and the same group id never again.
    assert_eq!(
        w.ask(&mut c, &a1.init_line("#r", &group)).await,
        ["ERR stale the room is encrypted already"]
    );
    let info = w.ask(&mut c, "info #r").await;
    assert_eq!(
        short(&info)[..7],
        [
            "SET #r topic",
            "SET #r public no",
            "SET #r guests none",
            "SET #r retention server",
            "SET #r e2ee yes",
            "SET #r history joined",
            "SET #r send mods",
        ]
    );
    for (line, error) in [
        (
            "set #r public yes",
            "ERR forbidden an encrypted room stays private and closed to guests",
        ),
        (
            "set #r guests read",
            "ERR forbidden an encrypted room stays private and closed to guests",
        ),
        ("set #r e2ee no", "ERR forbidden e2ee is set by INIT only"),
        (
            "set #r history shared",
            "ERR encrypted the room's group holds this setting; an owner changes it with COMMIT",
        ),
        (
            "set #r send all",
            "ERR encrypted the room's group holds this setting; an owner changes it with COMMIT",
        ),
        (
            "invite #r carol@example.org",
            "ERR encrypted invite by adding the invitee's devices with COMMIT",
        ),
        ("msg #r hello", "ERR encrypted send with ENC"),
    ] {
        assert_eq!(w.ask(&mut c, line).await, [error], "{line}");
    }
    // The invitation INIT ended does not let bob in.
    let mut b5 = w.connect(&Device::new(BOB, 5));
    assert_eq!(
        w.ask(&mut b5, "join #r").await,
        ["ERR not-found no such room"]
    );
    assert_eq!(
        w.ask(&mut c, "set #r topic still works").await.len(),
        2,
        "the topic is not in the group"
    );
}

#[tokio::test]
async fn commits_add_invite_and_remove_devices() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let (_, mut ga1) =
        encrypted_room(&mut w, &a1, &mut c1, HistoryMode::Shared, SendMode::All).await;
    let b5 = Device::new(BOB, 5);
    let mut cb = w.connect(&b5);

    // A commit that adds bob's device invites bob (12.6).
    let sent = a1.commit(
        &mut ga1,
        Changes {
            add: vec![b5.kp()],
            ..Changes::default()
        },
    );
    // Without its Welcome, or with one it does not need.
    assert_eq!(
        w.ask(&mut c1, &sent.line_without_welcome("#r")).await,
        ["ERR invalid a commit that adds devices comes with a Welcome"]
    );
    let lines = w.ask(&mut c1, &sent.line("#r")).await;
    assert_eq!(
        short(&lines),
        [
            &format!("COMMIT #r 1 {}", &sent.commit.as_str()[..12]),
            "INVITE #r bob@example.net",
            "OK seq=6 epoch=1",
        ]
    );
    ga1.merge_pending_commit(&a1.provider).unwrap();
    // Bob gets the INVITE and his Welcome, and joins the group and room.
    let lines = cb.lines();
    assert_eq!(untagged(&lines[0]), "INVITE #r bob@example.net");
    let welcome = find(&lines, "WELCOME #r ");
    assert!(welcome.contains(" 6 "), "{welcome}");
    let mut gb5 = b5.join(welcome);
    assert_eq!(gb5.epoch().as_u64(), 1);
    let lines = w.ask(&mut cb, "join #r").await;
    assert!(untagged(&lines[0]).starts_with("JOIN #r"), "{lines:?}");
    c1.lines();

    // A stale commit: bob commits for epoch 1 after alice moved on.
    let sent = a1.commit(&mut ga1, Changes::default());
    let stale = b5.commit(&mut gb5, Changes::default());
    let lines = w.ask(&mut c1, &sent.line("#r")).await;
    assert_eq!(lines.last().unwrap(), "OK seq=9 epoch=2");
    ga1.merge_pending_commit(&a1.provider).unwrap();
    let commit = find(&cb.lines(), "COMMIT #r 2").to_owned();
    assert_eq!(
        w.ask(&mut cb, &stale.line("#r")).await,
        ["ERR stale the commit is for epoch 1, and the group is in epoch 2"]
    );
    gb5.clear_pending_commit(b5.provider.storage()).unwrap();
    b5.apply(&mut gb5, &commit);
    // The GroupInfo of another commit.
    let one = a1.commit(&mut ga1, Changes::default());
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();
    let two = a1.commit(&mut ga1, Changes::default());
    let mixed = format!("commit #r {} {}", two.commit, one.group_info);
    assert_eq!(
        w.ask(&mut c1, &mixed).await,
        ["ERR invalid the GroupInfo is not for the commit's new epoch"]
    );
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();

    // Alice may not remove bob's leaf while he is a member.
    let bob_leaf = Device::leaf(&ga1, &b5.secret.public_key());
    let sent = a1.commit(
        &mut ga1,
        Changes {
            remove: vec![bob_leaf],
            ..Changes::default()
        },
    );
    assert_eq!(
        w.ask(&mut c1, &sent.line("#r")).await,
        ["ERR forbidden no reason to remove a leaf of bob@example.net"]
    );
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();
    // Once he has left, she must.
    w.ask(&mut cb, "part #r").await;
    let sent = a1.commit(
        &mut ga1,
        Changes {
            remove: vec![bob_leaf],
            ..Changes::default()
        },
    );
    let lines = w.ask(&mut c1, &sent.line("#r")).await;
    assert_eq!(lines.last().unwrap(), "OK seq=11 epoch=3");
    ga1.merge_pending_commit(&a1.provider).unwrap();
    // Bob is gone, so he gets nothing more of the room.
    assert!(cb.lines().iter().all(|l| !l.contains("COMMIT")));
}

#[tokio::test]
async fn commits_are_refused_by_the_rules() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let (id, mut ga1) =
        encrypted_room(&mut w, &a1, &mut c1, HistoryMode::Shared, SendMode::All).await;

    // From another device of the committer's identity, or another
    // identity that is not in the room.
    let a2 = Device::new(ALICE, 2);
    let mut c2 = w.connect(&a2);
    let sent = a1.commit(&mut ga1, Changes::default());
    assert_eq!(
        w.ask(&mut c2, &sent.line("#r")).await,
        ["ERR forbidden the committer is not this connection's device"]
    );
    let mut c5 = w.connect(&Device::new(BOB, 5));
    assert_eq!(
        w.ask(&mut c5, &sent.line("#r")).await,
        ["ERR not-found no such room"]
    );
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();

    // A key that is not in its identity's key file: bob's device 9.
    let b9 = Device::new(BOB, 9);
    let sent = a1.commit(
        &mut ga1,
        Changes {
            add: vec![b9.kp()],
            ..Changes::default()
        },
    );
    assert_eq!(
        w.ask(&mut c1, &sent.line("#r")).await,
        ["ERR forbidden a key of bob@example.net that is not in its key file"]
    );
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();

    // A KeyPackage whose lifetime is over at the server's time.
    w.h.clock.advance(Duration::from_secs(13 * 7 * 86400));
    let b5 = Device::new(BOB, 5);
    let sent = a1.commit(
        &mut ga1,
        Changes {
            add: vec![b5.kp()],
            ..Changes::default()
        },
    );
    assert_eq!(
        w.ask(&mut c1, &sent.line("#r")).await,
        ["ERR invalid an added KeyPackage's lifetime is not acceptable"]
    );
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();
    w.h.clock.set(Timestamp::now());

    // Renaming the conversation, or changing it as a plain member.
    let renamed = RisalaConversation::room(
        &"other".parse().unwrap(),
        HistoryMode::Shared,
        SendMode::All,
    );
    let sent = a1.commit(
        &mut ga1,
        Changes {
            conversation: Some(renamed),
            ..Changes::default()
        },
    );
    assert_eq!(
        w.ask(&mut c1, &sent.line("#r")).await,
        ["ERR forbidden GroupContextExtensions changes only history and send"]
    );
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();

    // Changing the committer's credential in its path (12.2).
    let mut bundle = ga1
        .commit_builder()
        .force_self_update(true)
        .leaf_node_parameters(
            risala_mls::openmls::prelude::LeafNodeParameters::builder()
                .with_credential_with_key(risala_mls::credential_with_key(
                    CAROL,
                    &a1.secret.public_key(),
                ))
                .build(),
        )
        .load_psks(a1.provider.storage())
        .unwrap()
        .create_group_info(true)
        .build(
            a1.provider.rand(),
            a1.provider.crypto(),
            &a1.signer(),
            |_| true,
        )
        .unwrap()
        .stage_commit(&a1.provider)
        .unwrap();
    let _ = &mut bundle;
    let sent = Sent::of(bundle.into_messages());
    assert_eq!(
        w.ask(&mut c1, &sent.line("#r")).await,
        ["ERR forbidden a commit keeps the credential and key of the committer's leaf"]
    );
    ga1.clear_pending_commit(a1.provider.storage()).unwrap();

    // The owner changes `history` and `send`, which the server records.
    let changed = RisalaConversation::room(&id, HistoryMode::Joined, SendMode::Mods);
    let sent = a1.commit(
        &mut ga1,
        Changes {
            conversation: Some(changed),
            ..Changes::default()
        },
    );
    let lines = w.ask(&mut c1, &sent.line("#r")).await;
    assert_eq!(
        short(&lines)[1..],
        [
            "SET #r history joined",
            "SET #r send mods",
            "OK seq=6 epoch=1"
        ]
    );
    ga1.merge_pending_commit(&a1.provider).unwrap();
}

#[tokio::test]
async fn devices_join_by_external_commit() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let (_, mut ga1) =
        encrypted_room(&mut w, &a1, &mut c1, HistoryMode::Shared, SendMode::All).await;

    // Alice's second device: a member, whose identity has a leaf.
    let a2 = Device::new(ALICE, 2);
    let mut c2 = w.connect(&a2);
    let gi = w.ask(&mut c2, "groupinfo #r").await;
    assert_eq!(gi.last().unwrap(), "OK");
    assert!(gi[0].starts_with("GROUPINFO #r 0 0 "), "{}", &gi[0][..30]);
    let (mut ga2, sent) = a2.join_external(&gi[0]);
    let lines = w.ask(&mut c2, &sent.line("#r")).await;
    assert_eq!(lines.last().unwrap(), "OK seq=6 epoch=1");
    let commit = find(&c1.lines(), "COMMIT #r 1").to_owned();
    a1.apply(&mut ga1, &commit);
    assert_eq!(ga1.members().count(), 2);

    // The same device again, as after a reinstall: its old leaf goes.
    let a2b = Device::new(ALICE, 2);
    let gi = w.ask(&mut c2, "groupinfo #r").await;
    assert!(gi[0].starts_with("GROUPINFO #r 1 6 "));
    let (_, sent) = a2b.join_external(&gi[0]);
    let lines = w.ask(&mut c2, &sent.line("#r")).await;
    assert_eq!(lines.last().unwrap(), "OK seq=7 epoch=2");
    let commit = find(&c1.lines(), "COMMIT #r 2").to_owned();
    a1.apply(&mut ga1, &commit);
    assert_eq!(ga1.members().count(), 2);
    // The stale state of the old one is behind.
    let stale = a2.commit(&mut ga2, Changes::default());
    assert!(w.ask(&mut c2, &stale.line("#r")).await[0].starts_with("ERR stale"),);

    // Carol, a member with no leaf, may not join by herself.
    let c7 = Device::new(CAROL, 7);
    let mut cc = w.connect(&c7);
    assert_eq!(
        w.ask(&mut cc, "groupinfo #r").await,
        ["ERR not-found no such room"]
    );
}

// ---------------------------------------------------------------------------
// ENC (12.8)

impl Device {
    /// An ENC line with `content`, encrypted under `group`'s current
    /// history key.
    pub(super) fn enc(&self, conv: &str, group: &MlsGroup, content: &str) -> String {
        let (payload, frank) = self.encrypt(group, content);
        format!(
            "@frank={frank} enc {conv} {} {payload}",
            group.epoch().as_u64()
        )
    }

    pub(super) fn encrypt(&self, group: &MlsGroup, content: &str) -> (mls::Ciphertext, mls::Frank) {
        let key = risala_mls::HistoryKey::of_group(group, self.provider.crypto()).unwrap();
        let sent = risala_mls::encrypt(
            &self.signer(),
            &key,
            group.group_id().as_slice(),
            group.epoch().as_u64(),
            content.as_bytes(),
        )
        .unwrap();
        (sent.payload, sent.frank)
    }

    /// The content of an ENC event line, decrypted with `group`'s current
    /// history key, from a sender who has a leaf.
    pub(super) fn read(&self, group: &MlsGroup, line: &str) -> String {
        String::from_utf8(self.message(group, line).content).unwrap()
    }

    /// An ENC event line, decrypted and verified as [`read`](Self::read)
    /// does.
    pub(super) fn message(&self, group: &MlsGroup, line: &str) -> risala_mls::Message {
        let event: risala_proto::server::ServerMessage = line.parse().unwrap();
        let risala_proto::server::ServerLine::Event(event) = event.line else {
            panic!("not an event: {line}");
        };
        let risala_proto::server::EventBody::Enc(enc) = &event.body else {
            panic!("not ENC: {line}");
        };
        let key = risala_mls::HistoryKey::of_group(group, self.provider.crypto()).unwrap();
        let unverified = risala_mls::decrypt(
            &key,
            group.group_id().as_slice(),
            enc.epoch,
            enc.payload.as_ref().unwrap(),
            enc.frank.as_ref().unwrap(),
        )
        .unwrap();
        let leaves: Vec<PublicKey> = group
            .members()
            .map(|m| risala_mls::signer::signature_key(&m.signature_key).unwrap())
            .collect();
        let sender = unverified.find_sender(&leaves).unwrap().clone();
        unverified.verify(&sender).unwrap()
    }
}

/// An encrypted room `#r` of alice's device 1, which bob's device 5 has
/// joined, both in epoch 1.
struct Pair {
    a1: Device,
    c1: Client,
    ga1: MlsGroup,
    b5: Device,
    cb: Client,
    gb5: MlsGroup,
}

async fn pair(w: &mut World, send: SendMode) -> Pair {
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let (_, mut ga1) = encrypted_room(w, &a1, &mut c1, HistoryMode::Shared, send).await;
    let b5 = Device::new(BOB, 5);
    let mut cb = w.connect(&b5);
    let sent = a1.commit(
        &mut ga1,
        Changes {
            add: vec![b5.kp()],
            ..Changes::default()
        },
    );
    w.ask(&mut c1, &sent.line("#r")).await;
    ga1.merge_pending_commit(&a1.provider).unwrap();
    let gb5 = b5.join(find(&cb.lines(), "WELCOME"));
    w.ask(&mut cb, "join #r").await;
    c1.lines();
    Pair {
        a1,
        c1,
        ga1,
        b5,
        cb,
        gb5,
    }
}

#[tokio::test]
async fn enc_sends_to_the_room() {
    let mut w = World::new();
    let Pair {
        a1,
        mut c1,
        ga1,
        b5,
        mut cb,
        gb5,
    } = pair(&mut w, SendMode::Mods).await;

    let line = a1.enc("#r", &ga1, "TEXT hello\n");
    let lines = w
        .ask(&mut c1, &format!("@cid=q2r8sv0alm3nb7xk;{}", &line[1..]))
        .await;
    assert_eq!(lines.last().unwrap(), "OK seq=10");
    let event = find(&cb.lines(), "ENC #r 1 ").to_owned();
    assert!(event.contains(";from=alice@example.org;frank="), "{event}");
    assert_eq!(b5.read(&gb5, &event), "TEXT hello\n");
    // Sent again with its cid: the same seq, and nothing new.
    let again = w
        .ask(&mut c1, &format!("@cid=q2r8sv0alm3nb7xk;{}", &line[1..]))
        .await;
    assert_eq!(again, ["OK seq=10"]);
    assert!(cb.lines().is_empty());
    // A plain member of a room with `send mods` may send ENC (12.8).
    let lines = w
        .ask(&mut cb, &b5.enc("#r", &gb5, "@react=10 TEXT 👍\n"))
        .await;
    assert_eq!(lines.last().unwrap(), "OK seq=11");
    assert_eq!(
        a1.read(&ga1, find(&c1.lines(), "ENC")),
        "@react=10 TEXT 👍\n"
    );

    // The payload and the `frank` tag.
    let (payload, frank) = a1.encrypt(&ga1, "TEXT hi\n");
    for (line, error) in [
        (
            format!("enc #r 1 {payload}"),
            "ERR invalid ENC needs the frank tag",
        ),
        (
            format!(
                "@frank={frank} enc #r 1 {}",
                mls::Ciphertext::from_bytes(&[1; 47]).unwrap()
            ),
            "ERR invalid a payload is at least 48 bytes, the salt and the tag",
        ),
        (
            format!("@frank={frank} enc #r 0 {payload}"),
            "ERR stale the group is in epoch 1",
        ),
    ] {
        assert_eq!(w.ask(&mut c1, &line).await, [error], "{line}");
    }
    // A device of a member with no leaf.
    let a2 = Device::new(ALICE, 2);
    let mut c2 = w.connect(&a2);
    assert_eq!(
        w.ask(&mut c2, &format!("@frank={frank} enc #r 1 {payload}"))
            .await,
        ["ERR forbidden this device has no leaf in the group"]
    );
    // HISTORY returns it; DELETE leaves a placeholder without `frank`.
    let lines = w.ask(&mut c1, "delete #r 10").await;
    assert_eq!(lines.last().unwrap(), "OK seq=12");
    let lines = w.ask(&mut c1, "history #r after=9 limit=2").await;
    assert!(lines[0].ends_with(";deleted ENC #r 1"), "{}", &lines[0]);
    assert!(!lines[0].contains("frank="));
    assert!(lines[1].contains(";frank=") && untagged(&lines[1]).starts_with("ENC #r 1 "));
    // In a room that is not encrypted.
    w.ask(&mut c1, "join #plain").await;
    assert_eq!(
        w.ask(&mut c1, &format!("@frank={frank} enc #plain 1 {payload}"))
            .await,
        ["ERR forbidden the room is not encrypted"]
    );
}

#[tokio::test]
async fn enc_waits_for_leaves_that_must_go() {
    let mut w = World::new();
    let Pair {
        a1,
        mut c1,
        mut ga1,
        b5,
        mut cb,
        ..
    } = pair(&mut w, SendMode::All).await;

    // Bob leaves: his leaf must go before anyone sends (12.6).
    w.ask(&mut cb, "part #r").await;
    c1.lines();
    assert_eq!(
        w.ask(&mut c1, &a1.enc("#r", &ga1, "TEXT hi\n")).await,
        ["ERR stale the group has a leaf that must be removed; commit its removal first"]
    );
    let bob_leaf = Device::leaf(&ga1, &b5.secret.public_key());
    let sent = a1.commit(
        &mut ga1,
        Changes {
            remove: vec![bob_leaf],
            ..Changes::default()
        },
    );
    w.ask(&mut c1, &sent.line("#r")).await;
    ga1.merge_pending_commit(&a1.provider).unwrap();
    assert!(w.ask(&mut c1, &a1.enc("#r", &ga1, "TEXT hi\n")).await[1].starts_with("OK seq="));

    // A key that left alice's key file: her device 3's leaf.
    let a3 = Device::new(ALICE, 3);
    let sent = a1.commit(
        &mut ga1,
        Changes {
            add: vec![a3.kp()],
            ..Changes::default()
        },
    );
    w.ask(&mut c1, &sent.line("#r")).await;
    ga1.merge_pending_commit(&a1.provider).unwrap();
    let lines = w.ask(&mut c1, &format!("key del {}", key(3))).await;
    assert_eq!(lines.last().unwrap(), "OK");
    assert_eq!(
        w.ask(&mut c1, &a1.enc("#r", &ga1, "TEXT hi\n")).await,
        ["ERR stale the group has a leaf that must be removed; commit its removal first"]
    );
    // Removing it needs no other reason.
    let leaf = Device::leaf(&ga1, &key(3));
    let sent = a1.commit(
        &mut ga1,
        Changes {
            remove: vec![leaf],
            ..Changes::default()
        },
    );
    assert!(
        w.ask(&mut c1, &sent.line("#r"))
            .await
            .last()
            .unwrap()
            .starts_with("OK seq=")
    );
    ga1.merge_pending_commit(&a1.provider).unwrap();
    assert!(w.ask(&mut c1, &a1.enc("#r", &ga1, "TEXT hi\n")).await[1].starts_with("OK seq="));
}

// ---------------------------------------------------------------------------
// Direct conversations (5.1, 5.2, 12.5, 12.6)

#[tokio::test]
async fn direct_conversations_start_with_init() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let b5 = Device::new(BOB, 5);
    let mut cb = w.connect(&b5);
    let me = RisalaConversation::direct(&a1.uid, &uid(BOB));

    // Not before INIT, and MSG never.
    assert_eq!(
        w.ask(&mut c1, "history bob@example.net").await,
        ["ERR not-found no such conversation"]
    );
    assert_eq!(
        w.ask(&mut c1, "msg bob@example.net hi").await,
        ["ERR encrypted send with ENC"]
    );
    assert_eq!(
        w.ask(&mut c1, "msg nobody@example.net hi").await,
        ["ERR not-found no such identity"]
    );
    // Only with identities the server knows, and named right.
    let group = a1.create(&RisalaConversation::direct(
        &a1.uid,
        &uid("nobody@example.net"),
    ));
    assert_eq!(
        w.ask(&mut c1, &a1.init_line("nobody@example.net", &group))
            .await,
        ["ERR not-found no such identity"]
    );
    assert_eq!(
        w.ask(&mut c1, &a1.init_line(BOB, &group)).await,
        ["ERR invalid the conversation extension names another conversation"]
    );
    // Not by someone blocked.
    w.ask(&mut cb, "block alice@example.org").await;
    let mut ga1 = a1.create(&me);
    assert_eq!(
        w.ask(&mut c1, &a1.init_line(BOB, &ga1)).await,
        ["ERR forbidden you may not start a conversation with them"]
    );
    w.ask(&mut cb, "unblock alice@example.org").await;

    let lines = w.ask(&mut c1, &a1.init_line(BOB, &ga1)).await;
    let id = ok_value(&lines, "id");
    assert_eq!(lines, [format!("OK id={id} epoch=0")]);
    // Bob's INIT comes second.
    let gb = b5.create(&me);
    assert_eq!(
        w.ask(&mut cb, &b5.init_line(ALICE, &gb)).await,
        ["ERR stale the conversation has a group already"]
    );

    // Alice adds Bob's device and her own second one (12.6).
    let a2 = Device::new(ALICE, 2);
    let mut c2 = w.connect(&a2);
    let sent = a1.commit(
        &mut ga1,
        Changes {
            add: vec![b5.kp(), a2.kp()],
            ..Changes::default()
        },
    );
    let lines = w.ask(&mut c1, &sent.line(BOB)).await;
    assert_eq!(
        short(&lines),
        [
            &format!("COMMIT bob@example.net 1 {}", &sent.commit.as_str()[..12]),
            "OK seq=1 epoch=1",
        ]
    );
    ga1.merge_pending_commit(&a1.provider).unwrap();
    // Each side's lines name the other (5.2).
    let lines = cb.lines();
    assert!(untagged(&lines[0]).starts_with("COMMIT alice@example.org 1 "));
    let mut gb5 = b5.join(find(&lines, "WELCOME alice@example.org "));
    let lines = c2.lines();
    assert!(untagged(&lines[0]).starts_with("COMMIT bob@example.net 1 "));
    let ga2 = a2.join(find(&lines, "WELCOME bob@example.net "));
    assert_eq!(ga2.epoch().as_u64(), 1);

    // SYNC lists it for both, by the other's name.
    let lines = w.ask(&mut cb, "sync").await;
    assert!(
        lines.contains(&format!("CONV alice@example.org {id} 1 0")),
        "{lines:?}"
    );
    let lines = w.ask(&mut c2, "sync").await;
    assert!(lines.contains(&format!("CONV bob@example.net {id} 1 0")));

    // ENC both ways.
    let lines = w
        .ask(&mut cb, &b5.enc(ALICE, &gb5, "TEXT hi alice\n"))
        .await;
    assert_eq!(lines.last().unwrap(), "OK seq=2");
    let event = find(&c1.lines(), "ENC bob@example.net 1 ").to_owned();
    assert_eq!(a1.read(&ga1, &event), "TEXT hi alice\n");
    assert!(find(&lines, "ENC alice@example.org 1 ").contains("from=bob@example.net"));
    // READ and TYPING.
    assert_eq!(w.ask(&mut cb, "read alice@example.org 2").await, ["OK"]);
    assert_eq!(w.ask(&mut cb, "typing alice@example.org").await, ["OK"]);
    assert_eq!(untagged(&c1.lines()[0]), "TYPING bob@example.net");
    // Blocks stop ENC and TYPING both ways (5.7).
    w.ask(&mut c1, "block bob@example.net").await;
    assert_eq!(
        w.ask(&mut cb, &b5.enc(ALICE, &gb5, "TEXT hi\n")).await,
        ["ERR forbidden one of you has blocked the other"]
    );
    assert_eq!(
        w.ask(&mut c1, &a1.enc(BOB, &ga1, "TEXT hi\n")).await,
        ["ERR forbidden one of you has blocked the other"]
    );
    assert_eq!(
        w.ask(&mut cb, "typing alice@example.org").await,
        ["ERR forbidden one of you has blocked the other"]
    );
    w.ask(&mut c1, "unblock bob@example.net").await;

    // Only the author deletes.
    assert_eq!(
        w.ask(&mut c1, "delete bob@example.net 2").await,
        ["ERR forbidden only the author may delete a message here"]
    );
    let lines = w.ask(&mut cb, "delete alice@example.org 2").await;
    assert_eq!(lines.last().unwrap(), "OK seq=3");
    assert_eq!(untagged(&c1.lines()[0]), "DELETE bob@example.net 2");

    // HISTORY, and its COMMIT events only.
    let lines = w.ask(&mut c1, "history bob@example.net after=0").await;
    assert_eq!(
        short(&lines),
        [
            &format!("COMMIT bob@example.net 1 {}", &sent.commit.as_str()[..12]),
            "ENC bob@example.net 1",
            "DELETE bob@example.net 2",
            &format!("OK id={id} more=0"),
        ]
    );
    let lines = w
        .ask(&mut cb, "history alice@example.org after=0 only=commit")
        .await;
    assert_eq!(lines.len(), 2);
    assert!(untagged(&lines[0]).starts_with("COMMIT alice@example.org 1 "));

    // Only participants' devices may be added, and GroupContextExtensions
    // is for rooms.
    let c7 = Device::new(CAROL, 7);
    let sent = b5.commit(
        &mut gb5,
        Changes {
            add: vec![c7.kp()],
            ..Changes::default()
        },
    );
    assert_eq!(
        w.ask(&mut cb, &sent.line(ALICE)).await,
        ["ERR forbidden carol@example.org is not a participant of this conversation"]
    );
    gb5.clear_pending_commit(b5.provider.storage()).unwrap();
    let mut changed = me.clone();
    changed.history = HistoryMode::Joined;
    let sent = b5.commit(
        &mut gb5,
        Changes {
            conversation: Some(changed),
            ..Changes::default()
        },
    );
    assert_eq!(
        w.ask(&mut cb, &sent.line(ALICE)).await,
        ["ERR forbidden only a room's owners change the group's extensions"]
    );
    gb5.clear_pending_commit(b5.provider.storage()).unwrap();

    // Bob's second device joins by external commit, with no leaf of its
    // own: a participant may (12.6).
    w.fetcher.set(&identity(BOB), vec![key(5), key(6)]);
    let b6 = Device::new(BOB, 6);
    let mut cb6 = w.connect(&b6);
    let gi = w.ask(&mut cb6, "groupinfo alice@example.org").await;
    assert!(gi[0].starts_with("GROUPINFO alice@example.org 1 1 "));
    let (_, sent) = b6.join_external(&gi[0]);
    let lines = w.ask(&mut cb6, &sent.line(ALICE)).await;
    assert_eq!(lines.last().unwrap(), "OK seq=4 epoch=2");
    // Carol cannot even name it.
    let mut cc = w.connect(&c7);
    assert_eq!(
        w.ask(&mut cc, "groupinfo alice@example.org").await,
        ["ERR not-found no such conversation"]
    );
}

#[tokio::test]
async fn a_conversation_with_yourself() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let mut g = a1.create(&RisalaConversation::direct(&a1.uid, &a1.uid));
    let lines = w.ask(&mut c1, &a1.init_line(ALICE, &g)).await;
    assert!(lines[0].starts_with("OK id="));
    let a2 = Device::new(ALICE, 2);
    let mut c2 = w.connect(&a2);
    let sent = a1.commit(
        &mut g,
        Changes {
            add: vec![a2.kp()],
            ..Changes::default()
        },
    );
    let lines = w.ask(&mut c1, &sent.line(ALICE)).await;
    assert!(untagged(&lines[0]).starts_with("COMMIT alice@example.org 1 "));
    let lines = c2.lines();
    let g2 = a2.join(find(&lines, "WELCOME alice@example.org "));
    let lines = w.ask(&mut c2, "sync").await;
    assert!(lines[0].starts_with("CONV alice@example.org "));
    g.merge_pending_commit(&a1.provider).unwrap();
    w.ask(&mut c1, &a1.enc(ALICE, &g, "KEY x 0 y\n")).await;
    assert_eq!(
        a2.read(&g2, find(&c2.lines(), "ENC alice@example.org 1")),
        "KEY x 0 y\n"
    );
}

#[tokio::test]
async fn direct_conversations_outlive_a_restart() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let g = a1.create(&RisalaConversation::direct(&a1.uid, &uid(CAROL)));
    let id = ok_value(&w.ask(&mut c1, &a1.init_line(CAROL, &g)).await, "id");
    let hub = Hub::build(
        config(),
        w.h.store.clone(),
        w.h.clock.clone(),
        timers(),
        KeyServices::default(),
    )
    .unwrap();
    w.h.hub = hub;
    let mut c7 = w.connect(&Device::new(CAROL, 7));
    // With no event yet, SYNC cannot list it: a CONV line's head is at
    // least 1 (7.1). GROUPINFO finds it.
    assert_eq!(w.ask(&mut c7, "sync").await, ["OK"]);
    let lines = w.ask(&mut c7, "groupinfo alice@example.org").await;
    assert!(lines[0].starts_with("GROUPINFO alice@example.org 0 0 "));
    let lines = w.ask(&mut c7, "history alice@example.org").await;
    assert_eq!(lines, [format!("OK id={id} more=0")]);
}

// ---------------------------------------------------------------------------
// REPORTENC (5.8)

#[tokio::test]
async fn reportenc_reveals_content_that_matches_its_commitment() {
    let mut w = World::new();
    w.h.hub.inner.operators.write().unwrap().insert(uid(CAROL));
    let mut op = w.connect(&Device::new(CAROL, 7));
    let a1 = Device::new(ALICE, 1);
    let mut c1 = w.connect(&a1);
    let b5 = Device::new(BOB, 5);
    let mut cb = w.connect(&b5);
    let mut ga1 = a1.create(&RisalaConversation::direct(&a1.uid, &b5.uid));
    let id = ok_value(&w.ask(&mut c1, &a1.init_line(BOB, &ga1)).await, "id");
    let sent = a1.commit(
        &mut ga1,
        Changes {
            add: vec![b5.kp()],
            ..Changes::default()
        },
    );
    w.ask(&mut c1, &sent.line(BOB)).await;
    ga1.merge_pending_commit(&a1.provider).unwrap();
    let gb5 = b5.join(find(&cb.lines(), "WELCOME"));
    w.ask(&mut c1, &a1.enc(BOB, &ga1, "TEXT buy now\n")).await;
    let event = find(&cb.lines(), "ENC alice@example.org 1 ").to_owned();
    let message = b5.message(&gb5, &event);
    let franking = message.franking().unwrap();

    // REPORT is for MSG, and the content must be what was committed to.
    assert_eq!(
        w.ask(&mut cb, "report alice@example.org 2 spam").await,
        ["ERR invalid report an ENC event with REPORTENC"]
    );
    let other = mls::Content::from_bytes(b"TEXT something else\n").unwrap();
    assert_eq!(
        w.ask(
            &mut cb,
            &format!(
                "reportenc alice@example.org 2 {} {other} spam",
                franking.key
            )
        )
        .await,
        ["ERR invalid the content does not match the message's franking commitment"]
    );
    // Not one's own, and not a COMMIT.
    let line = format!(
        "reportenc bob@example.net 2 {} {} spam",
        franking.key, franking.content
    );
    assert_eq!(
        w.ask(&mut c1, &line).await,
        ["ERR forbidden you cannot report your own message"]
    );
    let line = format!(
        "reportenc alice@example.org 1 {} {} spam",
        franking.key, franking.content
    );
    assert_eq!(
        w.ask(&mut cb, &line).await,
        ["ERR not-found no such message"]
    );

    let line = format!(
        "reportenc alice@example.org 2 {} {} spam",
        franking.key, franking.content
    );
    let lines = w.ask(&mut cb, &line).await;
    let report = ok_value(&lines, "id");
    // Sent again, the same report.
    assert_eq!(w.ask(&mut cb, &line).await, [format!("OK id={report}")]);
    // The operators review reports in direct conversations: the REPORTENC
    // line, then the ENC event without its payload.
    let lines = op.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].starts_with(&format!("@report={report};id={id};t=")),
        "{}",
        lines[0]
    );
    assert!(lines[0].ends_with(&format!(
        ";from=bob@example.net REPORTENC alice@example.org 2 {} {} spam",
        franking.key, franking.content
    )));
    let frank = event
        .split(";frank=")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    assert!(
        lines[1].ends_with(&format!(
            ";from=alice@example.org;frank={frank} ENC alice@example.org 1"
        )),
        "{}",
        lines[1]
    );
    // And again from ADMIN REPORTS, once the message is gone.
    w.ask(&mut c1, "delete bob@example.net 2").await;
    let lines = w.ask(&mut op, "admin reports").await;
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[0].contains(" REPORTENC alice@example.org 2 "));
    assert!(lines[1].ends_with(" ENC alice@example.org 1"));
    // REPORTENC of a MSG in a room is refused.
    let mut cr = w.connect(&Device::new(BOB, 5));
    w.ask(&mut c1, "join #plain").await;
    w.ask(&mut cr, "join #plain").await;
    w.ask(&mut c1, "msg #plain hello").await;
    cr.lines();
    let line = format!(
        "reportenc #plain 3 {} {} spam",
        franking.key, franking.content
    );
    assert_eq!(
        w.ask(&mut cr, &line).await,
        ["ERR invalid REPORTENC is for ENC events"]
    );
}

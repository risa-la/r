//! This device's own commits (12.5, 12.7): removals go before other
//! queued commits, and a commit is posted only if it passes the group
//! checks that the others will make, with KeyPackages within their
//! lifetimes as of the post.

use risala_mls::framing::ContentType;
use risala_proto::command::KeyPkgCommand;
use risala_proto::server::ServerLine;

use super::*;

const MINUTE: u64 = 60 * 1000;
const DAY: u64 = 24 * 60 * MINUTE;

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn direct(net: &mut Net, a: usize, b: usize) -> (ConversationId, ConversationId) {
    let peer = net.devices[b].uid.clone();
    let ca = net.job(a, Job::Direct { peer }).unwrap();
    let cb = net.same_conv(b, a, ca).expect("joined");
    (ca, cb)
}

/// A KeyPackage of `uid`'s device `device`, fetched with KEYPKG GET, as a
/// job would have fetched it.
fn fetch_kp(net: &mut Net, uid: &str, device: &[u8]) -> wire::Fetched {
    let (response, _) = net.server.handle(
        (usize::MAX, Slot::Anonymous(0)),
        Command::KeyPkg(KeyPkgCommand::Get {
            uid: uid.parse().unwrap(),
        }),
    );
    let crypto = RisalaCrypto::new().unwrap();
    response
        .lines
        .iter()
        .find_map(|l| match &l.line {
            ServerLine::KeyPkg {
                key_package,
                secret,
                ..
            } => {
                let bytes = key_package.decode();
                let kp = risala_mls::keypackage::verify_key_package(
                    &crypto,
                    risala_mls::keypackage::read_key_package(&bytes).unwrap(),
                )
                .unwrap();
                let identity = risala_mls::identity::RisalaIdentity::from_credential(
                    kp.leaf_node().credential(),
                )
                .unwrap();
                (identity.device_id?.as_bytes().as_slice() == device).then(|| wire::Fetched {
                    key_package: bytes,
                    secret: secret.as_bytes().to_vec(),
                })
            }
            _ => None,
        })
        .expect("a KeyPackage of the device")
}

/// The signature key of the leaf of a KeyPackage.
fn kp_signature_key(fetched: &wire::Fetched) -> Vec<u8> {
    let crypto = RisalaCrypto::new().unwrap();
    risala_mls::keypackage::verify_key_package(
        &crypto,
        risala_mls::keypackage::read_key_package(&fetched.key_package).unwrap(),
    )
    .unwrap()
    .leaf_node()
    .signature_key()
    .as_slice()
    .to_vec()
}

fn commit_posts(net: &Net, d: usize, conv: ConversationId) -> usize {
    let mailbox = net.devices[d].store.mailbox_rows(conv).unwrap()[0].mailbox;
    net.server
        .posts(&mailbox)
        .into_iter()
        .filter(|p| p.1 == ContentType::Commit)
        .count()
}

fn queue(net: &Net, d: usize, conv: ConversationId, intent: Intent) {
    let now = net.clock.now().unix_millis();
    net.write(d, |tx| group::queue_intent(tx, conv, &intent, now));
}

fn display_name(net: &Net, d: usize, conv: ConversationId) -> Option<String> {
    let own = net.devices[d].device_id.as_slice().try_into().ok();
    net.devices[d]
        .store
        .leaf_rows(conv)
        .unwrap()
        .into_iter()
        .find(|l| l.device_id == own)
        .and_then(|l| l.display_name)
}

/// 12.7: a commit held while sending is held, here a new display name,
/// does not hold back a removal queued after it: the removal goes first,
/// and is not held; the held commit is made after it, once sending is no
/// longer held. A peer removed for a check has not left: the conversation
/// stays (6.1).
#[test]
fn a_removal_goes_before_a_held_commit() {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let alice = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    let tablet = net.device_of("tablet", bob);
    let alice_keys = super::keychecks::own_facts(&mut net, alice);
    for d in [laptop, alice, bob] {
        net.connect(d);
    }
    let (l, _) = direct(&mut net, laptop, bob);
    net.job(
        laptop,
        Job::Invite {
            conv: l,
            uids: vec![uid("alice@example.org")],
        },
    )
    .unwrap();
    net.advance(MINUTE);
    let a = net.same_conv(alice, laptop, l).expect("the phone joined");
    // Alice's phone can no longer tell Bob's devices (12.7): his tablet,
    // which her laptop adds, is added unchecked, and the phone holds
    // sending.
    alice_keys.set_unknown(&uid("bob@example.net"), true);
    net.connect(tablet);
    net.job(
        laptop,
        Job::Invite {
            conv: l,
            uids: vec![uid("bob@example.net")],
        },
    )
    .unwrap();
    net.advance(MINUTE);
    assert_eq!(net.leaves(alice, a).len(), 4);
    assert!(net.write(alice, |tx| Ok(tx.sending_held(a)?)));
    let tablet_id: [u8; 48] = net.devices[tablet].device_id.clone().try_into().unwrap();
    queue(
        &net,
        alice,
        a,
        Intent {
            display_name: Some("Alice".into()),
            ..Intent::default()
        },
    );
    net.tick();
    assert_ne!(display_name(&net, alice, a).as_deref(), Some("Alice"));
    // A removal for a check, queued after the held commit, as a repair
    // queues it.
    queue(
        &net,
        alice,
        a,
        Intent {
            remove: vec![("bob@example.net".into(), Some(tablet_id))],
            ..Intent::default()
        },
    );
    net.tick();
    assert_eq!(net.leaves(alice, a).len(), 3, "removed first");
    assert_ne!(display_name(&net, alice, a).as_deref(), Some("Alice"));
    assert_eq!(net.state(alice, a), ConvState::Active);
    // The leaf is gone, and with it the check that held sending: the held
    // commit is made after the removal, once the phone's streak of own
    // commits lets it (12.7).
    for _ in 0..15 {
        net.advance(MINUTE);
    }
    assert!(!net.write(alice, |tx| Ok(tx.sending_held(a)?)));
    assert_eq!(display_name(&net, alice, a).as_deref(), Some("Alice"));
    assert_eq!(net.state(alice, a), ConvState::Active);
}

/// 12.7: a commit that the other members would hold invalid, here an Add
/// of a third identity's device to a direct conversation, is not posted:
/// the device would merge it alone, and split from the group.
#[test]
fn an_own_commit_that_fails_the_group_checks_is_not_posted() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let carol = net.device("carol", "carol@example.com");
    for d in [alice, bob, carol] {
        net.connect(d);
    }
    let (a, b) = direct(&mut net, alice, bob);
    let epoch = net.epoch(alice, a);
    let commits = commit_posts(&net, alice, a);
    let carol_device = net.devices[carol].device_id.clone();
    let kp = fetch_kp(&mut net, "carol@example.com", &carol_device);
    queue(
        &net,
        alice,
        a,
        Intent {
            add: vec![kp],
            ..Intent::default()
        },
    );
    net.tick();
    net.advance(MINUTE);
    assert_eq!(commit_posts(&net, alice, a), commits, "nothing posted");
    assert_eq!(net.epoch(alice, a), epoch);
    assert!(net.same_conv(carol, alice, a).is_none());
    let queued = net.write(alice, |tx| Ok(tx.pending_outbox(a)?));
    assert!(queued.is_empty(), "dropped: {queued:?}");
    // The group goes on.
    net.say(alice, a, "still here");
    assert!(
        net.texts(bob, b).iter().any(|(_, t)| t == "still here"),
        "{:?}",
        net.texts(bob, b)
    );
}

/// 12.5: a KeyPackage fetched a while ago, whose lifetime ends within the
/// hour, is not added: the others would check it against the server's
/// `t`, give or take an hour, so the device takes the hour inward. It
/// fetches the identity's KeyPackages again, and adds the device from a
/// new one.
#[test]
fn an_added_keypackage_near_the_end_of_its_lifetime_is_fetched_again() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let (a, _) = direct(&mut net, alice, bob);
    let phone = net.device_of("bob-phone", bob);
    net.connect(phone);
    let phone_id = net.devices[phone].device_id.clone();
    let old = fetch_kp(&mut net, "bob@example.net", &phone_id);
    // Twelve weeks on, but for half an hour: within the lifetime that the
    // others allow, give or take an hour, but not with the hour taken
    // inward. The phone's KeyPackages on the server are new ones by now.
    // The clock moves a few days at a time, so that Alice's and Bob's
    // weekly fresh-leaf commits keep their leaves from going stale (12.7).
    net.disconnect(phone);
    let mut left = risala_mls::keypackage::KEY_PACKAGE_LIFETIME * 1000 - 30 * MINUTE;
    while left > 0 {
        let step = left.min(4 * DAY);
        net.advance(step);
        left -= step;
    }
    net.server.drop_key_packages("bob@example.net", &phone_id);
    net.connect(phone);
    assert!(net.server.key_package_count("bob@example.net", &phone_id) > 0);
    queue(
        &net,
        alice,
        a,
        Intent {
            add: vec![old.clone()],
            ..Intent::default()
        },
    );
    for _ in 0..5 {
        net.advance(MINUTE);
    }
    let p = net.same_conv(phone, alice, a).expect("the phone was added");
    assert_eq!(net.state(phone, p), ConvState::Active);
    let phone_leaf = net.devices[alice]
        .store
        .leaf_rows(a)
        .unwrap()
        .into_iter()
        .find(|l| l.device_id.map(|d| d.to_vec()) == Some(phone_id.clone()))
        .expect("the phone's leaf");
    assert_ne!(
        phone_leaf.signature_key,
        kp_signature_key(&old),
        "added from a new KeyPackage"
    );
}

/// 12.5: the hour's margin taken inward, at both ends of a lifetime.
#[test]
fn lifetimes_for_an_own_commit() {
    use risala_mls::openmls::prelude::Lifetime;
    let hour = 60 * MINUTE;
    let start = 1_800_000_000;
    let end = start + risala_mls::keypackage::KEY_PACKAGE_LIFETIME;
    let lifetime = Lifetime::init(start, end);
    let ms = |s: u64| s * 1000;
    for (now, ok) in [
        (ms(start), false),
        (ms(start) + hour - 1, false),
        (ms(start) + hour, true),
        (ms(end) - hour, true),
        (ms(end) - hour + 1, false),
        (ms(end), false),
    ] {
        assert_eq!(group::lifetime_ok_to_post(&lifetime, now), ok, "{now}");
    }
}

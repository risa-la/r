//! Server administration (Section 10).

use risala_proto::names::{BoxName, Uid};

use crate::core::{Clock as _, admin};
use crate::store::{AdminStore as _, MiscStore as _, PushTarget};

use super::misc::{Keys, add_mailbox, add_room};
use super::*;

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// Operators are those in the configuration and those the store has
/// (10.1); only they get past the gate on ADMIN commands.
#[tokio::test]
async fn operators_come_from_the_configuration_and_the_store() {
    let store = SqliteStore::open_in_memory().unwrap();
    let bob: Uid = "bob@example.org".parse().unwrap();
    store.add_operator(&bob, T.parse().unwrap()).unwrap();
    let mut h = Harness::on(config(), timers(), store);
    let op: Uid = "op@example.org".parse().unwrap();
    assert!(admin::is_operator(h.inner(), &op));
    assert!(admin::is_configured_operator(h.inner(), &op));
    assert!(admin::is_operator(h.inner(), &bob));
    assert!(!admin::is_configured_operator(h.inner(), &bob));
    assert!(!admin::is_operator(h.inner(), &uid("alice@example.org")));

    let mut bob_conn = h.signed_in_as("bob@example.org");
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&bob_conn, "ADMIN OPS").await;
    h.send(&alice, "ADMIN OPS").await;
    assert_eq!(
        bob_conn.lines(),
        ["OP bob@example.org", "OP op@example.org", "OK"]
    );
    assert_eq!(alice.lines(), ["ERR forbidden"]);
}

#[tokio::test]
async fn op_and_deop() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    for (line, want) in [
        // Guests cannot be operators (10.1).
        ("ADMIN OP ~sam", "ERR forbidden guests cannot be operators"),
        ("ADMIN OP alice@example.org", "OK"),
        ("ADMIN OP alice@example.org", "OK"),
        // Configured operators cannot be removed; others can, once.
        (
            "ADMIN DEOP op@example.org",
            "ERR forbidden named in the configuration",
        ),
        ("ADMIN DEOP bob@example.org", "ERR not-found"),
    ] {
        h.send(&op, line).await;
        assert_eq!(op.lines(), [want], "{line}");
    }
    assert_eq!(h.store.operators().unwrap(), [uid("alice@example.org")]);
    // Alice may now use ADMIN commands.
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, "ADMIN OPS").await;
    assert_eq!(
        alice.lines(),
        ["OP alice@example.org", "OP op@example.org", "OK"]
    );
    h.send(&op, "ADMIN DEOP alice@example.org").await;
    assert_eq!(op.lines(), ["OK"]);
    h.send(&alice, "ADMIN OPS").await;
    assert_eq!(alice.lines(), ["ERR forbidden"]);
    assert!(h.store.operators().unwrap().is_empty());

    // ADMIN OP of a banned identity is refused (10.1).
    h.send(&op, "ADMIN BAN *@spam.example").await;
    h.send(&op, "ADMIN OP x@a.spam.example").await;
    assert_eq!(op.lines(), ["OK", "ERR forbidden lift the ban first"]);
}

#[tokio::test]
async fn identity_and_domain_bans() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    let mut spam = h.signed_in_as("spam@example.net");
    let mut other = h.signed_in_as("ham@example.net");
    h.send(&op, "ADMIN BAN spam@example.net sends spam").await;
    assert_eq!(op.lines(), ["OK"]);
    // Its signed-in connections close (10.2).
    assert_eq!(spam.lines(), ["<close> BYE sends spam"]);
    assert!(other.lines().is_empty());
    assert!(admin::banned(h.inner(), &uid("spam@example.net")));
    assert!(!admin::banned(h.inner(), &uid("ham@example.net")));

    // A domain ban covers its subdomains, and closes with the default BYE.
    let mut sub = h.signed_in_as("x@mail.example.net");
    h.send(&op, "ADMIN BAN *@example.net").await;
    assert_eq!(op.lines(), ["OK"]);
    let bye = format!("<close> BYE {}", admin::BYE_BANNED);
    assert_eq!(other.lines(), std::slice::from_ref(&bye));
    assert_eq!(sub.lines(), [bye]);
    assert!(admin::banned(h.inner(), &uid("ham@mail.example.net")));

    // Bans that cover an operator are refused, the sender's own included.
    h.send(&op, "ADMIN OP boss@example.com").await;
    assert_eq!(op.lines(), ["OK"]);
    for line in [
        "ADMIN BAN op@example.org",
        "ADMIN BAN *@example.org",
        "ADMIN BAN boss@example.com",
        "ADMIN BAN *@example.com",
    ] {
        h.send(&op, line).await;
        assert_eq!(
            op.lines(),
            ["ERR forbidden the ban covers an operator"],
            "{line}"
        );
    }

    // ADMIN BANS lists the bans with their reasons; a repeated ban
    // replaces the reason.
    h.send(&op, "ADMIN BAN spam@example.net still spam").await;
    h.send(&op, "ADMIN BANS").await;
    assert_eq!(
        op.lines(),
        [
            "OK",
            "SERVERBAN spam@example.net still spam",
            "SERVERBAN *@example.net",
            "OK"
        ]
    );
    // UNBAN, once.
    h.send(&op, "ADMIN UNBAN *@example.net").await;
    h.send(&op, "ADMIN UNBAN *@example.net").await;
    assert_eq!(op.lines(), ["OK", "ERR not-found"]);
    assert!(!admin::banned(h.inner(), &uid("ham@example.net")));
    assert!(admin::banned(h.inner(), &uid("spam@example.net")));

    // Bans outlast a restart.
    let bans = h.store.server_bans().unwrap();
    assert_eq!(bans.len(), 1);
}

/// Server bans never apply to operators named in the configuration, even
/// one made before they were added to it (10.2).
#[tokio::test]
async fn configured_operators_are_never_banned() {
    let store = SqliteStore::open_in_memory().unwrap();
    store
        .add_server_ban(&"*@example.org".parse().unwrap(), "", T.parse().unwrap())
        .unwrap();
    let h = Harness::on(config(), timers(), store);
    assert!(!admin::banned(h.inner(), &uid("op@example.org")));
    assert!(admin::banned(h.inner(), &uid("alice@example.org")));
}

#[tokio::test]
async fn address_bans_cover_anonymous_and_guest_connections_only() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    // Connections from inside 198.51.100.0/24, and one from outside.
    let mut anon = h.connect_from("198.51.100.7:4000");
    h.send(&anon, "ANON").await;
    let mut guest = h.connect_from("198.51.100.8:4000");
    h.send(&guest, "GUEST sam").await;
    let mut signed = h.connect_from("198.51.100.9:4000");
    let device = super::super::state::Device {
        uid: uid("alice@example.org"),
        key: risala_proto::auth::PublicKey::from_bytes(&[7; risala_proto::auth::PUBLIC_KEY_LEN]),
    };
    h.inner()
        .reg()
        .set_who(signed.id, super::super::state::Who::SignedIn(device));
    let mut outside = h.anon().await;
    assert_eq!(anon.lines(), ["OK"]);
    assert_eq!(guest.lines().len(), 1);

    h.send(&op, "ADMIN BAN 198.51.100.0/24 abuse").await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(anon.lines(), ["<close> BYE abuse"]);
    assert_eq!(guest.lines(), ["<close> BYE abuse"]);
    // The guest's session ended at once, freeing the name.
    assert!(h.hub.guest_sessions().is_empty());
    // Signed-in connections from inside, and others, are not affected.
    assert!(signed.lines().is_empty());
    assert!(outside.lines().is_empty());

    // No anonymous or guest connection opens from inside it any more.
    let mut again = h.connect_from("198.51.100.20:4000");
    h.send(&again, "ANON").await;
    h.send(&again, "GUEST bea").await;
    assert_eq!(
        again.lines(),
        [
            "ERR forbidden this network is banned",
            "ERR forbidden this network is banned"
        ]
    );
    h.send(&op, "ADMIN UNBAN 198.51.100.0/24").await;
    assert_eq!(op.lines(), ["OK"]);
    h.send(&again, "ANON").await;
    assert_eq!(again.lines(), ["OK"]);
}

#[tokio::test]
async fn banning_a_guest_bans_its_address() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    let mut v6 = h.connect_from("[2001:db8:1:2:3:4:5:6]:4000");
    h.send(&v6, "GUEST sam").await;
    assert_eq!(v6.lines().len(), 1);
    h.send(&op, "ADMIN BAN ~sam").await;
    h.send(&op, "ADMIN BAN ~nobody").await;
    h.send(&op, "ADMIN BANS").await;
    assert_eq!(
        op.lines(),
        ["OK", "ERR not-found", "SERVERBAN 2001:db8:1:2::/64", "OK"]
    );
    assert_eq!(v6.lines(), [format!("<close> BYE {}", admin::BYE_BANNED)]);
    // UNBAN takes the address, not the guest's uid (10.2).
    h.send(&op, "ADMIN UNBAN ~sam").await;
    h.send(&op, "ADMIN UNBAN 2001:db8:1:2::/64").await;
    assert_eq!(
        op.lines(),
        ["ERR not-found unban the guest's address", "OK"]
    );

    let (_, _) = h.guest("bea").await;
    h.send(&op, "ADMIN BAN ~bea").await;
    h.send(&op, "ADMIN BANS").await;
    assert_eq!(op.lines(), ["OK", "SERVERBAN 203.0.113.7", "OK"]);
}

#[tokio::test]
async fn who_disconnect_and_notice() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    let mut alice = h.signed_in_as("alice@example.org");
    let mut alice2 = h.signed_in_as("alice@example.org");
    let mut anon = h.connect_from("[2001:db8::1]:51001");
    h.send(&anon, "ANON").await;
    assert_eq!(anon.lines(), ["OK"]);
    let (mut sam, _) = h.guest("sam").await;
    let mut new = h.connect();

    h.send(&op, "ADMIN WHO").await;
    let since = T;
    assert_eq!(
        op.lines(),
        [
            format!("CONNECTION op@example.org 203.0.113.7:51000 {since}"),
            format!("CONNECTION alice@example.org 203.0.113.7:51000 {since}"),
            format!("CONNECTION alice@example.org 203.0.113.7:51000 {since}"),
            format!("CONNECTION - [2001:db8::1]:51001 {since}"),
            format!("CONNECTION ~sam 203.0.113.7:51000 {since}"),
            format!("CONNECTION - 203.0.113.7:51000 {since}"),
            "OK".into(),
        ]
    );

    h.send(&op, "ADMIN NOTICE Back\\sin 5 minutes").await;
    assert_eq!(op.lines(), ["NOTICE Back\\sin 5 minutes", "OK"]);
    for c in [&mut alice, &mut alice2, &mut anon, &mut sam, &mut new] {
        assert_eq!(c.lines(), ["NOTICE Back\\sin 5 minutes"]);
    }

    h.send(&op, "ADMIN DISCONNECT alice@example.org go away")
        .await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(alice.lines(), ["<close> BYE go away"]);
    assert_eq!(alice2.lines(), ["<close> BYE go away"]);
    // A guest's session ends too, even one waiting to be resumed (10.3).
    h.close(sam).await;
    assert_eq!(h.hub.guest_sessions(), [uid("~sam")]);
    h.send(&op, "ADMIN DISCONNECT ~sam").await;
    assert_eq!(op.lines(), ["OK"]);
    assert!(h.hub.guest_sessions().is_empty());
    h.send(&op, "ADMIN DISCONNECT ~sam").await;
    h.send(&op, "ADMIN DISCONNECT nobody@example.org").await;
    assert_eq!(op.lines(), ["ERR not-found", "ERR not-found"]);
}

#[tokio::test]
async fn drop_rooms_and_mailboxes() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    let room = add_room(&h, "#general", 1, "write", "", &[("a@x.org", "owner")]);
    let other = add_mailbox(&h, 2);
    let mut follower = h.anon().await;
    let mut unrelated = h.anon().await;
    h.inner().mailbox.follow(room, follower.id);
    // A push subscription of the room goes with it (10.4).
    let keys = Keys::new();
    h.send(
        &follower,
        &format!(
            "PUSH ADD https://p.example/1 t {} {} box={room}",
            keys.key, keys.auth
        ),
    )
    .await;
    assert_eq!(follower.lines(), ["OK"]);

    h.send(&op, "ADMIN DROP #general spam\\sroom").await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(follower.lines(), [format!("DROP {room} spam\\sroom")]);
    assert!(unrelated.lines().is_empty());
    assert!(h.inner().mailbox.followers(&room).is_empty());
    assert!(
        h.store
            .push_subscriptions(&PushTarget::Mailbox(room), h.clock.now())
            .unwrap()
            .is_empty()
    );
    // Its name is free, and the box is gone.
    h.send(&op, "LIST").await;
    h.send(&op, "ADMIN DROP #general").await;
    h.send(&op, &format!("ADMIN DROP {room}")).await;
    assert_eq!(op.lines(), ["OK more=0", "ERR not-found", "ERR not-found"]);
    use crate::store::MailboxStore as _;
    assert!(h.store.mailbox(&room).unwrap().is_none());

    // Any mailbox, by its box.
    h.send(&op, &format!("ADMIN DROP {other}")).await;
    assert_eq!(op.lines(), ["OK"]);
    assert!(h.store.mailbox(&other).unwrap().is_none());
}

#[tokio::test]
async fn mute_and_unmute_any_mailbox() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    let mailbox = add_mailbox(&h, 1);
    let room = add_room(&h, "#general", 2, "write", "", &[]);
    let pseudonym = risala_proto::mls::Pseudonym::from_bytes([6; 16]);
    let unknown = BoxName::from_bytes([9; 16]);
    let until = |h: &Harness, b: &BoxName| -> i64 {
        h.store
            .raw()
            .query_row(
                "SELECT until FROM mutes WHERE box = ?",
                [&b.as_bytes()[..]],
                |r| r.get(0),
            )
            .unwrap()
    };
    h.send(&op, &format!("ADMIN MUTE {mailbox} {pseudonym} hours=3"))
        .await;
    h.send(&op, &format!("ADMIN MUTE {unknown} {pseudonym}"))
        .await;
    assert_eq!(op.lines(), ["OK", "ERR not-found"]);
    // 12:00 plus 3 hours.
    assert_eq!(until(&h, &mailbox), 1_794_236_400_000);
    // The default is 24 hours; in a public room, which is epochal, it
    // stops at the end of the period (6.4, 10.4).
    h.send(&op, &format!("ADMIN MUTE {mailbox} {pseudonym}"))
        .await;
    h.send(&op, &format!("ADMIN MUTE {room} {pseudonym}")).await;
    assert_eq!(until(&h, &mailbox), 1_794_312_000_000);
    assert_eq!(until(&h, &room), 1_794_268_800_000);
    h.send(&op, &format!("ADMIN UNMUTE {mailbox} {pseudonym}"))
        .await;
    h.send(&op, &format!("ADMIN UNMUTE {mailbox} {pseudonym}"))
        .await;
    assert_eq!(op.lines(), ["OK", "OK", "OK", "ERR not-found"]);
}

#[tokio::test]
async fn settings() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    let mut anon = h.anon().await;
    let (mut sam, _) = h.guest("sam").await;
    let (sea, _) = h.guest("sea").await;
    h.close(sea).await;
    assert_eq!(h.hub.guest_sessions().len(), 2);

    // anon no closes every anonymous connection (10.6).
    h.send(&op, "ADMIN SET anon no").await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(
        anon.lines(),
        [format!("<close> BYE {}", admin::BYE_NO_ANON)]
    );
    assert!(sam.lines().is_empty());
    let mut c = h.connect();
    h.send(&c, "ANON").await;
    assert_eq!(c.lines(), ["ERR forbidden anonymous connections are off"]);

    // guests no ends every guest session, waiting ones too.
    h.send(&op, "ADMIN SET guests no").await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(
        sam.lines(),
        [format!("<close> BYE {}", admin::BYE_NO_GUESTS)]
    );
    assert!(h.hub.guest_sessions().is_empty());

    // Changes show in INFO and outlast a restart.
    h.send(&op, "ADMIN SET retention 7").await;
    h.send(&op, "ADMIN SET welcome  Hi there ").await;
    h.send(&op, "ADMIN SET colour blue").await;
    assert_eq!(op.lines(), ["OK", "OK", "ERR not-supported"]);
    h.send(&c, "INFO").await;
    assert_eq!(
        c.lines(),
        ["OK version=1 anon=no guests=no register=no log=no retention=7 push=yes upload=no"]
    );
    let settings = h.store.settings(&h.inner().settings()).unwrap();
    assert_eq!(settings.retention.days(), 7);
    assert_eq!(settings.welcome, " Hi there ");
    let mut next = h.open("203.0.113.7:1", Some("chat.example.org"));
    let greeting = next.lines();
    assert!(greeting[0].ends_with("  Hi there "), "{greeting:?}");
}

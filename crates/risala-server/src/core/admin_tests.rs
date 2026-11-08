//! Transcript tests of the ADMIN commands of Section 10 that are in
//! `admin`: operators (10.1), bans (10.2), connections (10.3), hosted
//! identities (10.5) and server settings (10.6).

use std::sync::Arc;

use risala_proto::auth::{Nonce, PublicKey, SecretKey};
use risala_proto::command::Request;
use risala_proto::names::Uid;

use super::tests::{Client, Flaky, Harness, T, config, start, stored, timers};
use super::*;
use crate::handler::{ConnInfo, conn_channel};
use crate::store::SqliteStore;

/// The hostname clients connect to, as they send it in SNI.
const HOST: &str = "chat.example.org";

/// The address every connection of [`Harness::connect`] comes from.
const HOME: &str = "203.0.113.7:51000";

fn secret(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn public(n: u8) -> PublicKey {
    secret(n).public_key()
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// A server whose identity domain is `example.org`, with registration
/// open, `op@example.net` as its operator, and the room `#general`.
fn admin_config() -> Config {
    let mut c = config();
    c.identity_domain = Some("example.org".into());
    c.server.registration = true;
    c.operators = vec!["op@example.net".into()];
    c
}

/// A hub, its key file fetcher and its publisher, and the operator's
/// connection.
struct World {
    h: Harness,
    fetcher: Arc<MemoryFetcher>,
    publisher: Arc<MemoryPublisher>,
    op: Client,
}

impl World {
    fn new() -> World {
        World::with(admin_config())
    }

    fn with(config: Config) -> World {
        let store = SqliteStore::open_in_memory().unwrap();
        for room in &config.rooms {
            store.ensure_room(&room.parse().unwrap(), start()).unwrap();
        }
        World::on(config, Arc::new(store))
    }

    fn on(config: Config, store: Arc<dyn Store>) -> World {
        let fetcher = Arc::new(MemoryFetcher::new());
        let publisher = Arc::new(MemoryPublisher::new());
        let clock = Arc::new(ManualClock::new(start()));
        let keys = KeyServices::shared(fetcher.clone(), publisher.clone());
        let hub = Hub::build(config, store.clone(), clock.clone(), timers(), keys).unwrap();
        let mut h = Harness {
            hub,
            store,
            clock,
            next: 0,
        };
        let op = h.signed_in_as("op@example.net");
        World {
            h,
            fetcher,
            publisher,
            op,
        }
    }

    /// Sends `line` as the operator, and returns what the operator got.
    async fn admin(&mut self, line: &str) -> Vec<String> {
        self.h.send(&self.op, line).await;
        self.op.lines()
    }

    /// A new connection from `peer`, with SNI, and its greeting's nonce.
    fn dial_from(&mut self, peer: &str) -> (Client, Nonce) {
        dial_from(&mut self.h, peer)
    }

    /// A new connection from `peer`, signed in as the guest `~name`.
    async fn guest_from(&mut self, name: &str, peer: &str) -> Client {
        let (mut c, _) = self.dial_from(peer);
        self.h.send(&c, &format!("guest {name}")).await;
        let ok = c.lines();
        assert!(ok[0].starts_with(&format!("OK uid=~{name} ")), "{ok:?}");
        c
    }

    /// AUTH as `who` with key `n` on a new connection from [`HOME`]. Returns
    /// the connection and its response.
    async fn auth(&mut self, who: &str, n: u8) -> (Client, Vec<String>) {
        let (mut c, nonce) = self.dial_from(HOME);
        let sig = secret(n).sign_challenge(HOST, &nonce, who);
        self.h.send(&c, &format!("auth {who} {sig}")).await;
        let lines = c.lines();
        (c, lines)
    }

    /// REGISTER `<name>@example.org` with key `n` on a new connection.
    async fn register(&mut self, name: &str, n: u8) -> (Client, Vec<String>) {
        let (mut c, nonce) = self.dial_from(HOME);
        let who = format!("{name}@example.org");
        let sig = secret(n).sign_challenge(HOST, &nonce, &who);
        self.h
            .send(&c, &format!("register {name} {} {sig}", public(n)))
            .await;
        let lines = c.lines();
        (c, lines)
    }
}

/// A new connection from `peer`, with SNI, and its greeting's nonce.
fn dial_from(h: &mut Harness, peer: &str) -> (Client, Nonce) {
    h.next += 1;
    let id = crate::handler::ConnId(h.next);
    let (handle, rx) = conn_channel(id, 4096, usize::MAX);
    h.hub.open(
        ConnInfo {
            peer: peer.parse().unwrap(),
            sni: Some(HOST.into()),
            sni_certified: false,
            since: start(),
        },
        handle,
    );
    let mut c = Client { id, rx };
    let greeting = c.lines();
    let nonce = greeting[0].split(' ').nth(3).unwrap().parse().unwrap();
    (c, nonce)
}

fn none() -> Vec<String> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Who may use ADMIN (Section 10)

#[tokio::test]
async fn only_operators_may_use_admin() {
    let mut w = World::new();
    let mut bob = w.h.signed_in_as("bob@example.net");
    let mut sam = w.h.guest("sam").await;
    for line in [
        "admin ops",
        "admin op bob@example.net",
        "admin ban *@example.net",
        "admin bans",
        "admin who",
        "admin notice hi",
        "admin keys bob@example.org",
        "admin set guests no",
    ] {
        w.h.send(&bob, line).await;
        assert_eq!(
            bob.lines(),
            ["ERR forbidden only operators may use ADMIN"],
            "{line}"
        );
        w.h.send(&sam, line).await;
        assert_eq!(sam.lines(), ["ERR forbidden not for guests"], "{line}");
    }
    // Nothing changed.
    assert_eq!(w.admin("admin bans").await, ["OK"]);
    assert_eq!(w.admin("admin ops").await, ["OP op@example.net", "OK"]);
}

// ---------------------------------------------------------------------------
// Operators (10.1)

#[tokio::test]
async fn operators_are_added_and_removed() {
    let mut w = World::new();
    w.fetcher
        .set(&"bob@example.net".parse().unwrap(), vec![public(1)]);
    let mut bob = w.h.signed_in_as("bob@example.net");
    w.h.send(&bob, "admin ops").await;
    assert_eq!(bob.lines(), ["ERR forbidden only operators may use ADMIN"]);

    assert_eq!(
        w.admin("@ref=1 admin op bob@example.net").await,
        ["@ref=1 OK"]
    );
    // At once, and again without an error.
    w.h.send(&bob, "@ref=2 admin ops").await;
    assert_eq!(
        bob.lines(),
        [
            "@ref=2 OP bob@example.net",
            "@ref=2 OP op@example.net",
            "@ref=2 OK"
        ]
    );
    assert_eq!(w.admin("admin op bob@example.net").await, ["OK"]);
    assert_eq!(w.h.store.operators().unwrap(), [uid("bob@example.net")]);
    // The identity learns it when it signs in (4.5).
    let (_c, ok) = w.auth("bob@example.net", 1).await;
    assert_eq!(ok, ["OK uid=bob@example.net op=yes"]);

    // Guests cannot be operators.
    assert_eq!(
        w.admin("admin op ~sam").await,
        ["ERR forbidden guests cannot be operators"]
    );
    // Operators from the configuration stay, even for themselves.
    assert_eq!(
        w.admin("admin deop op@example.net").await,
        ["ERR forbidden operators from the configuration cannot be removed"]
    );
    w.h.send(&bob, "admin deop op@example.net").await;
    assert_eq!(
        bob.lines(),
        ["ERR forbidden operators from the configuration cannot be removed"]
    );

    assert_eq!(w.admin("admin deop bob@example.net").await, ["OK"]);
    w.h.send(&bob, "admin ops").await;
    assert_eq!(bob.lines(), ["ERR forbidden only operators may use ADMIN"]);
    assert_eq!(
        w.admin("admin deop bob@example.net").await,
        ["ERR not-found not an operator"]
    );
    assert_eq!(w.h.store.operators().unwrap(), Vec::<Uid>::new());
    let (_c, ok) = w.auth("bob@example.net", 1).await;
    assert_eq!(ok, ["OK uid=bob@example.net"]);
}

#[tokio::test]
async fn added_operators_survive_a_restart() {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    let mut w = World::on(admin_config(), store.clone());
    assert_eq!(w.admin("admin op carol@example.com").await, ["OK"]);
    drop(w);
    let mut w = World::on(admin_config(), store);
    assert_eq!(
        w.admin("admin ops").await,
        ["OP carol@example.com", "OP op@example.net", "OK"]
    );
}

// ---------------------------------------------------------------------------
// Bans (10.2)

#[tokio::test]
async fn identity_and_domain_bans() {
    let mut w = World::new();
    for who in ["bob@spam.example", "eve@x.spam.example", "dan@example.net"] {
        w.fetcher.set(&who.parse().unwrap(), vec![public(1)]);
    }
    let (mut bob, _) = w.auth("bob@spam.example", 1).await;
    let (mut bob2, _) = w.auth("bob@spam.example", 1).await;
    let (mut eve, _) = w.auth("eve@x.spam.example", 1).await;
    let (mut dan, _) = w.auth("dan@example.net", 1).await;

    // A domain ban covers its subdomains, and closes their connections.
    assert_eq!(
        w.admin("@ref=b admin ban *@spam.example mass spam").await,
        ["@ref=b OK"]
    );
    assert_eq!(bob.lines(), ["<close> BYE mass spam"]);
    assert_eq!(bob2.lines(), ["<close> BYE mass spam"]);
    assert_eq!(eve.lines(), ["<close> BYE mass spam"]);
    assert_eq!(dan.lines(), none());
    // A closed connection runs nothing more.
    w.h.send(&bob, "sync").await;
    assert_eq!(bob.lines(), none());

    let (_c, refused) = w.auth("bob@spam.example", 1).await;
    assert_eq!(
        refused,
        ["ERR forbidden this identity is banned from this server"]
    );
    let (_c, refused) = w.auth("eve@x.spam.example", 1).await;
    assert_eq!(
        refused,
        ["ERR forbidden this identity is banned from this server"]
    );
    // Only someone holding a key learns of the ban: the signature is
    // checked first (PLAN.md 5, item 31).
    let (_c, refused) = w.auth("bob@spam.example", 9).await;
    assert_eq!(refused, ["ERR auth-failed the signature did not verify"]);
    // `spam.example` itself is a domain, not an identity, and
    // `notspam.example` is not a subdomain.
    w.fetcher
        .set(&"amy@notspam.example".parse().unwrap(), vec![public(1)]);
    let (_c, ok) = w.auth("amy@notspam.example", 1).await;
    assert_eq!(ok, ["OK uid=amy@notspam.example"]);

    // An identity ban, without a reason, and REGISTER of a banned name.
    assert_eq!(w.admin("admin ban dan@example.net").await, ["OK"]);
    assert_eq!(dan.lines(), ["<close> BYE banned from this server"]);
    assert_eq!(w.admin("admin ban mallory@example.org").await, ["OK"]);
    let (_c, refused) = w.register("mallory", 2).await;
    assert_eq!(
        refused,
        ["ERR forbidden this identity is banned from this server"]
    );
    assert!(
        w.h.store
            .identity(&uid("mallory@example.org"))
            .unwrap()
            .is_none()
    );
    // Banning again replaces the reason. Bans are listed in byte order.
    assert_eq!(w.admin("admin ban dan@example.net again").await, ["OK"]);
    assert_eq!(
        w.admin("@ref=l admin bans").await,
        [
            "@ref=l SERVERBAN *@spam.example mass spam",
            "@ref=l SERVERBAN dan@example.net again",
            "@ref=l SERVERBAN mallory@example.org",
            "@ref=l OK"
        ]
    );

    // Lifting a ban.
    assert_eq!(w.admin("admin unban *@spam.example").await, ["OK"]);
    assert_eq!(
        w.admin("admin unban *@spam.example").await,
        ["ERR not-found no such ban"]
    );
    let (_c, ok) = w.auth("bob@spam.example", 1).await;
    assert_eq!(ok, ["OK uid=bob@spam.example"]);
    let (_c, ok) = w.register("mallory", 2).await;
    assert_eq!(
        ok,
        ["ERR forbidden this identity is banned from this server"]
    );
    assert_eq!(w.admin("admin unban mallory@example.org").await, ["OK"]);
    let (_c, ok) = w.register("mallory", 2).await;
    assert_eq!(ok, ["OK uid=mallory@example.org"]);
}

/// Bans outlive a restart.
#[tokio::test]
async fn bans_survive_a_restart() {
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
    let mut w = World::on(admin_config(), store.clone());
    assert_eq!(w.admin("admin ban *@spam.example").await, ["OK"]);
    assert_eq!(
        w.admin("admin ban 198.51.100.0/24 open proxy").await,
        ["OK"]
    );
    drop(w);
    let mut w = World::on(admin_config(), store);
    w.fetcher
        .set(&"bob@spam.example".parse().unwrap(), vec![public(1)]);
    let (_c, refused) = w.auth("bob@spam.example", 1).await;
    assert_eq!(
        refused,
        ["ERR forbidden this identity is banned from this server"]
    );
    let (mut c, _) = w.dial_from("198.51.100.9:4000");
    w.h.send(&c, "guest sam").await;
    assert_eq!(
        c.lines(),
        ["ERR forbidden guests may not connect from this address"]
    );
    assert_eq!(
        w.admin("admin bans").await,
        [
            "SERVERBAN *@spam.example",
            "SERVERBAN 198.51.100.0/24 open proxy",
            "OK"
        ]
    );
}

#[tokio::test]
async fn banning_a_guest_bans_its_ipv4_address() {
    let mut w = World::new();
    let mut sam = w.guest_from("sam", HOME).await;
    w.h.send(&sam, "join #general").await;
    let mut ann = w.guest_from("ann", "198.51.100.1:4000").await;
    w.h.send(&ann, "join #general").await;
    sam.lines();
    ann.lines();

    assert_eq!(w.admin("admin ban ~sam flooding").await, ["OK"]);
    assert_eq!(sam.lines(), ["<close> BYE flooding"]);
    assert_eq!(
        ann.lines(),
        [format!("@seq=3;t={T};from=~sam PART #general")]
    );
    assert_eq!(w.h.hub.guest_sessions(), [uid("~ann")]);
    assert_eq!(
        w.admin("admin bans").await,
        ["SERVERBAN 203.0.113.7 flooding", "OK"]
    );

    // No guest can connect from the address, nor its IPv4-mapped form,
    // by any name, resuming or not.
    for peer in [HOME, "[::ffff:203.0.113.7]:1"] {
        let (mut c, _) = w.dial_from(peer);
        w.h.send(&c, "guest sam2").await;
        assert_eq!(
            c.lines(),
            ["ERR forbidden guests may not connect from this address"]
        );
    }
    // Identities from the same address are not affected.
    w.fetcher
        .set(&"bob@example.net".parse().unwrap(), vec![public(1)]);
    let (_c, ok) = w.auth("bob@example.net", 1).await;
    assert_eq!(ok, ["OK uid=bob@example.net"]);

    // A guest that is not connected cannot be banned this way.
    assert_eq!(
        w.admin("admin ban ~nobody").await,
        ["ERR not-found no such guest is connected"]
    );
    // The ban is lifted by its address.
    assert_eq!(
        w.admin("admin unban ~sam").await,
        ["ERR not-found a guest's ban is listed under its address; unban that"]
    );
    assert_eq!(w.admin("admin unban ::ffff:203.0.113.7").await, ["OK"]);
    let sam = w.guest_from("sam", HOME).await;
    drop(sam);
}

#[tokio::test]
async fn banning_an_ipv6_guest_bans_its_64() {
    let mut w = World::new();
    let mut v6 = w.guest_from("v6", "[2001:db8:1:2::5]:4000").await;
    let mut near = w.guest_from("near", "[2001:db8:1:2:ffff::9]:4000").await;
    let mut far = w.guest_from("far", "[2001:db8:1:3::5]:4000").await;
    assert_eq!(w.admin("admin ban ~v6").await, ["OK"]);
    // Everyone in the /64 goes.
    assert_eq!(v6.lines(), ["<close> BYE banned from this server"]);
    assert_eq!(near.lines(), ["<close> BYE banned from this server"]);
    assert_eq!(far.lines(), none());
    assert_eq!(
        w.admin("admin bans").await,
        ["SERVERBAN 2001:db8:1:2::/64", "OK"]
    );
    let (mut c, _) = w.dial_from("[2001:db8:1:2:abcd::1]:4000");
    w.h.send(&c, "guest new").await;
    assert_eq!(
        c.lines(),
        ["ERR forbidden guests may not connect from this address"]
    );
    w.guest_from("new", "[2001:db8:1:3::6]:4000").await;
}

#[tokio::test]
async fn address_and_prefix_bans_stop_guests() {
    let mut w = World::new();
    let mut ann = w.guest_from("ann", "198.51.100.1:4000").await;
    let mut sam = w.guest_from("sam", HOME).await;
    assert_eq!(w.admin("admin ban 198.51.100.0/24").await, ["OK"]);
    // Guests already connected from inside it are closed too.
    assert_eq!(ann.lines(), ["<close> BYE banned from this server"]);
    assert_eq!(sam.lines(), none());
    assert_eq!(w.admin("admin ban 203.0.113.8 one host").await, ["OK"]);
    assert_eq!(sam.lines(), none());
    let (mut c, _) = w.dial_from("203.0.113.8:1");
    w.h.send(&c, "guest x").await;
    assert_eq!(
        c.lines(),
        ["ERR forbidden guests may not connect from this address"]
    );
    assert_eq!(
        w.admin("admin bans").await,
        [
            "SERVERBAN 198.51.100.0/24",
            "SERVERBAN 203.0.113.8 one host",
            "OK"
        ]
    );
    assert_eq!(
        w.admin("admin unban 198.51.100.0/25").await,
        ["ERR not-found no such ban"]
    );
    assert_eq!(w.admin("admin unban 198.51.100.0/24").await, ["OK"]);
    w.guest_from("ann", "198.51.100.1:4000").await;
}

/// A ban made while an AUTH has checked the signature but not signed the
/// connection in yet: the AUTH is refused.
#[tokio::test]
async fn a_ban_while_signing_in() {
    let store = Arc::new(Flaky::new());
    let mut w = World::on(admin_config(), store.clone());
    w.fetcher
        .set(&"bob@spam.example".parse().unwrap(), vec![public(1)]);
    let (mut bob, nonce) = w.dial_from(HOME);
    let sig = secret(1).sign_challenge(HOST, &nonce, "bob@spam.example");
    store.pause.arm("touch_identity");
    let (hub, id) = (w.h.hub.clone(), bob.id);
    let req: Request = format!("auth bob@spam.example {sig}").parse().unwrap();
    let auth = tokio::spawn(async move { hub.command(id, req).await });
    store.pause.reached().await;
    assert_eq!(w.admin("admin ban *@spam.example").await, ["OK"]);
    store.pause.release();
    auth.await.unwrap();
    assert_eq!(
        bob.lines(),
        ["ERR forbidden this identity is banned from this server"]
    );
}

/// A guest that signs in while a ban of its address is being stored is
/// closed once the ban is made.
#[tokio::test]
async fn a_guest_signing_in_while_its_address_is_banned() {
    let store = Arc::new(Flaky::new());
    let mut w = World::on(admin_config(), store.clone());
    store.pause.arm("add_server_ban");
    let (hub, id) = (w.h.hub.clone(), w.op.id);
    let req: Request = "admin ban 203.0.113.0/24".parse().unwrap();
    let ban = tokio::spawn(async move { hub.command(id, req).await });
    store.pause.reached().await;
    let mut sam = w.guest_from("sam", HOME).await;
    store.pause.release();
    ban.await.unwrap();
    assert_eq!(w.op.lines(), ["OK"]);
    assert_eq!(sam.lines(), ["<close> BYE banned from this server"]);
    assert_eq!(w.h.hub.guest_sessions(), Vec::<Uid>::new());
}

/// An operator that bans its own domain gets the `OK` before its BYE.
#[tokio::test]
async fn an_operator_can_ban_itself() {
    let mut w = World::new();
    assert_eq!(
        w.admin("admin ban *@example.net oops").await,
        ["OK", "<close> BYE oops"]
    );
}

// ---------------------------------------------------------------------------
// Connections (10.3)

#[tokio::test]
async fn who_lists_every_connection() {
    let mut w = World::new();
    let _unsigned = w.dial_from("[2001:db8::1]:443");
    let _sam = w.guest_from("sam", "198.51.100.1:4000").await;
    let closed = w.guest_from("ann", HOME).await;
    w.h.close(closed).await;
    assert_eq!(
        w.admin("@ref=w admin who").await,
        [
            format!("@ref=w CONNECTION op@example.net {HOME} {T}"),
            format!("@ref=w CONNECTION - [2001:db8::1]:443 {T}"),
            format!("@ref=w CONNECTION ~sam 198.51.100.1:4000 {T}"),
            "@ref=w OK".into(),
        ]
    );
}

#[tokio::test]
async fn disconnect_closes_every_connection() {
    let mut w = World::new();
    let mut bob = w.h.signed_in_as("bob@example.net");
    let mut bob2 = w.h.signed_in_as("bob@example.net");
    let mut dan = w.h.signed_in_as("dan@example.net");
    assert_eq!(
        w.admin("admin disconnect bob@example.net take a break")
            .await,
        ["OK"]
    );
    assert_eq!(bob.lines(), ["<close> BYE take a break"]);
    assert_eq!(bob2.lines(), ["<close> BYE take a break"]);
    assert_eq!(dan.lines(), none());
    assert_eq!(
        w.admin("admin disconnect bob@example.net").await,
        ["ERR not-found not connected"]
    );

    // A guest's session ends at once, even while it waits to be resumed
    // (4.2).
    let mut sam = w.h.guest("sam").await;
    w.h.send(&sam, "join #general").await;
    let mut ann = w.h.guest("ann").await;
    w.h.send(&ann, "join #general").await;
    sam.lines();
    ann.lines();
    assert_eq!(w.admin("admin disconnect ~sam").await, ["OK"]);
    assert_eq!(sam.lines(), ["<close> BYE disconnected by an operator"]);
    assert_eq!(
        ann.lines(),
        [format!("@seq=3;t={T};from=~sam PART #general")]
    );
    w.h.close(ann).await;
    assert_eq!(w.admin("admin disconnect ~ann").await, ["OK"]);
    assert_eq!(w.h.hub.guest_sessions(), Vec::<Uid>::new());
    assert_eq!(
        stored(&w.h, "#general"),
        ["~sam JOIN", "~ann JOIN", "~sam PART", "~ann PART"]
    );
    assert_eq!(
        w.admin("admin disconnect ~sam").await,
        ["ERR not-found no such guest"]
    );
    // The guest may come back: a ban stops that.
    w.h.guest("sam").await;

    // An operator may disconnect itself: the OK comes first.
    assert_eq!(
        w.admin("admin disconnect op@example.net").await,
        ["OK", "<close> BYE disconnected by an operator"]
    );
}

#[tokio::test]
async fn notice_reaches_every_connection() {
    let mut w = World::new();
    let (mut unsigned, _) = w.dial_from(HOME);
    let mut sam = w.h.guest("sam").await;
    let mut bob = w.h.signed_in_as("bob@example.net");
    let notice = "NOTICE Down for upgrades at 22:00\\sUTC";
    assert_eq!(
        w.admin("@ref=n admin notice Down for upgrades at 22:00\\sUTC")
            .await,
        [notice, "@ref=n OK"]
    );
    for c in [&mut unsigned, &mut sam, &mut bob] {
        assert_eq!(c.lines(), [notice]);
    }
}

// ---------------------------------------------------------------------------
// Hosted identities (10.5)

#[tokio::test]
async fn keys_of_hosted_identities() {
    let mut w = World::new();
    let (mut alice, ok) = w.register("alice", 1).await;
    assert_eq!(ok, ["OK uid=alice@example.org"]);

    assert_eq!(
        w.admin("@ref=k admin keys alice@example.org").await,
        [format!("@ref=k KEY {}", public(1)), "@ref=k OK".into()]
    );
    // ADDKEY works like KEY ADD (4.7).
    assert_eq!(
        w.admin(&format!(
            "admin addkey alice@example.org {} new phone",
            public(2)
        ))
        .await,
        ["OK"]
    );
    assert_eq!(
        w.admin("admin keys alice@example.org").await,
        [
            format!("KEY {}", public(1)),
            format!("KEY {} new phone", public(2)),
            "OK".into()
        ]
    );
    let file = w.publisher.get("alice").unwrap();
    assert_eq!(file.len(), 2);
    let (mut phone, ok) = w.auth("alice@example.org", 2).await;
    assert_eq!(ok, ["OK uid=alice@example.org"]);

    // DELKEY closes the connections that use the key, and may remove the
    // last key, which locks the identity.
    assert_eq!(
        w.admin(&format!("admin delkey alice@example.org {}", public(1)))
            .await,
        ["OK"]
    );
    assert_eq!(alice.lines(), ["<close> BYE this device's key was removed"]);
    assert_eq!(phone.lines(), none());
    assert_eq!(
        w.admin(&format!("admin delkey alice@example.org {}", public(1)))
            .await,
        ["ERR not-found no such key"]
    );
    assert_eq!(
        w.admin(&format!("admin delkey alice@example.org {}", public(2)))
            .await,
        ["OK"]
    );
    assert_eq!(phone.lines(), ["<close> BYE this device's key was removed"]);
    assert_eq!(w.publisher.get("alice").unwrap().len(), 0);
    assert_eq!(w.admin("admin keys alice@example.org").await, ["OK"]);
    let (_c, refused) = w.auth("alice@example.org", 2).await;
    assert_eq!(refused, ["ERR auth-failed the signature did not verify"]);

    // An operator lets them back in.
    assert_eq!(
        w.admin(&format!("admin addkey alice@example.org {}", public(4)))
            .await,
        ["OK"]
    );
    let (_c, ok) = w.auth("alice@example.org", 4).await;
    assert_eq!(ok, ["OK uid=alice@example.org"]);
}

#[tokio::test]
async fn hosted_commands_need_a_hosted_identity() {
    let mut w = World::new();
    w.h.signed_in_as("bob@example.org");
    for target in ["bob@example.org", "bob@example.net", "~sam"] {
        for line in [
            format!("admin keys {target}"),
            format!("admin addkey {target} {}", public(1)),
            format!("admin delkey {target} {}", public(1)),
            format!("admin unregister {target}"),
        ] {
            assert_eq!(
                w.admin(&line).await,
                ["ERR not-found this server does not host that identity"],
                "{line}"
            );
        }
    }
    // A server that hosts nobody offers none of them.
    let mut w = World::with(config_without_domain());
    assert_eq!(
        w.admin("admin keys bob@example.org").await,
        ["ERR not-supported this server hosts no identities"]
    );
}

fn config_without_domain() -> Config {
    let mut c = admin_config();
    c.identity_domain = None;
    c
}

#[tokio::test]
async fn unregister_deletes_a_hosted_identity() {
    let mut w = World::new();
    let (mut alice, _) = w.register("alice", 1).await;
    w.h.send(&alice, "join #general").await;
    alice.lines();
    let (mut alice2, _) = w.auth("alice@example.org", 1).await;
    w.h.send(&w.op, "join #general").await;
    w.op.lines();
    alice.lines();
    alice2.lines();

    assert_eq!(
        w.admin("admin unregister alice@example.org").await,
        [
            format!("@seq=3;t={T};from=alice@example.org PART #general"),
            "OK".into()
        ]
    );
    assert_eq!(
        alice.lines(),
        [
            format!("@seq=3;t={T};from=alice@example.org PART #general"),
            "<close> BYE identity deleted".into()
        ]
    );
    assert_eq!(
        alice2.lines(),
        [
            format!("@seq=3;t={T};from=alice@example.org PART #general"),
            "<close> BYE identity deleted".into()
        ]
    );
    assert!(w.publisher.get("alice").is_none());
    assert!(
        w.h.store
            .identity(&uid("alice@example.org"))
            .unwrap()
            .is_none()
    );
    // The name is never registered again (10.5).
    let (_c, taken) = w.register("alice", 2).await;
    assert_eq!(taken, ["ERR name-taken that name was used before"]);
    assert_eq!(
        w.admin("admin unregister alice@example.org").await,
        ["ERR not-found this server does not host that identity"]
    );
}

// ---------------------------------------------------------------------------
// Server settings (10.6)

#[tokio::test]
async fn settings_show_in_info_at_once() {
    let mut w = World::new();
    assert_eq!(
        w.admin("info").await,
        ["OK version=1 guests=yes register=example.org retention=forever push=no upload=no"]
    );
    for line in [
        "admin set registration closed  ",
        "admin set retention 30 ",
        "admin set welcome Be kind.  ",
    ] {
        assert_eq!(w.admin(line).await, ["OK"], "{line}");
    }
    assert_eq!(
        w.admin("info").await,
        ["OK version=1 guests=yes register=no retention=30 push=no upload=no"]
    );
    // The greeting has the new text, trailing spaces and all.
    let mut c = w.h.connect_sni(Some(HOST), 16);
    let greeting = c.lines();
    assert!(greeting[0].ends_with(" Be kind.  "), "{greeting:?}");
    let (_c, refused) = w.register("alice", 1).await;
    assert_eq!(refused, ["ERR forbidden registration is closed"]);

    assert_eq!(
        w.admin("admin set colour blue").await,
        ["ERR not-supported that setting is left to the configuration"]
    );

    // Stored: a restart keeps them, whatever the configuration says.
    let settings =
        w.h.store
            .load_server_settings(&ServerSettings {
                guests: false,
                registration: true,
                retention: "1".parse().unwrap(),
                welcome: String::new(),
            })
            .unwrap();
    assert!(settings.guests);
    assert!(!settings.registration);
    assert_eq!(settings.retention.to_string(), "30");
    assert_eq!(settings.welcome, "Be kind.  ");
}

#[tokio::test]
async fn guests_no_ends_every_guest_session() {
    let mut w = World::new();
    let mut bob = w.h.signed_in_as("bob@example.net");
    w.h.send(&bob, "join #general").await;
    let mut sam = w.h.guest("sam").await;
    w.h.send(&sam, "join #general").await;
    let ann = w.h.guest("ann").await;
    w.h.send(&ann, "join #general").await;
    // ann's session waits to be resumed.
    w.h.close(ann).await;
    bob.lines();
    sam.lines();

    assert_eq!(w.admin("admin set guests no").await, ["OK"]);
    // In uid order.
    let ann_part = format!("@seq=4;t={T};from=~ann PART #general");
    assert_eq!(
        sam.lines(),
        [
            ann_part.clone(),
            "<close> BYE guests are no longer allowed".into()
        ]
    );
    assert_eq!(
        bob.lines(),
        [ann_part, format!("@seq=5;t={T};from=~sam PART #general")]
    );
    assert_eq!(w.h.hub.guest_sessions(), Vec::<Uid>::new());
    let (mut c, _) = w.dial_from(HOME);
    w.h.send(&c, "guest sam").await;
    assert_eq!(c.lines(), ["ERR forbidden guests are not allowed"]);
    assert_eq!(
        w.admin("info").await[0],
        "OK version=1 guests=no register=example.org retention=forever push=no upload=no"
    );

    assert_eq!(w.admin("admin set guests yes").await, ["OK"]);
    w.h.guest("sam").await;
}

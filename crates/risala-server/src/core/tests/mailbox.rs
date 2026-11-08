//! Mailboxes and delivery (5.2, 6.1, 6.4, 7).

use rusqlite::params;

use risala_proto::mls::{GroupId, TokenHash};
use risala_proto::names::BoxName;

use crate::store::{MailboxStore as _, NewMailbox};

use super::*;

/// Nothing is built yet: the area's commands reply `not-supported` on the
/// kinds that may send them.
#[tokio::test]
async fn not_built_yet() {
    let mut h = Harness::new();
    let mut anon = h.anon().await;
    let (mut guest, _) = h.guest("sam").await;
    for line in [
        "FOLLOW ujzdegxdncf32epf3dhodzdoci",
        "FETCH ujzdegxdncf32epf3dhodzdoci after=0",
        "GROUPINFO ujzdegxdncf32epf3dhodzdoci",
    ] {
        h.send(&anon, line).await;
        assert_eq!(anon.lines(), ["ERR not-supported"], "{line}");
        h.send(&guest, line).await;
        assert_eq!(guest.lines(), ["ERR not-supported"], "{line}");
    }
}

/// A public room for tests, with `members` holding a leaf in its group.
fn public_room(h: &Harness, n: u8, room: &str, members: &[&str]) -> BoxName {
    let mailbox = BoxName::from_bytes([n; 16]);
    h.store
        .create_mailbox(&NewMailbox {
            mailbox,
            group_id: GroupId::from_bytes([n; 32]),
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
    let mailbox = &h.inner().mailbox;
    mailbox.follow(general, a.id);
    mailbox.follow(help, a.id);
    mailbox.follow(general, b.id);
    mailbox.follow(quiet, c.id);

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
    h.close(b).await;
    assert_eq!(mailbox.followers(&general), [a.id]);
}

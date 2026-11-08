//! M4's room behaviour over TLS against a whole server: edits, reactions
//! and DELETE (5.3, 5.4), RELATED (7.3), settings, roles and moderation
//! (6.2-6.4), reports (5.8) and retention (7.5), and above all where they
//! meet: a reported message deleted or expired, a ban of someone holding
//! an invitation and a role, a DELETE sent again or naming an old room.
//!
//! The hub's own tests (`src/core/*tests.rs`) cover each rule at every
//! edge, without sockets. These check that the rules hold end to end.

mod common;

use std::time::Duration;

use common::{Session, command, exchange, expect, join, until_closed, value};
use risala_server::testing::{TestIdentity, TestServer};

/// Presence changes held for an hour, so that no PRESENCE line turns up.
const NO_PRESENCE: (Duration, Duration) = (Duration::from_secs(30), Duration::from_secs(3600));

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// A server that hosts `example.org`, where `op@example.net` is an
/// operator, with a stopped clock. It has no rooms: the first identity to
/// join one creates it and owns it (6.1).
async fn server() -> TestServer {
    TestServer::builder()
        .identity_domain("example.org")
        .key_domains(&["example.net"])
        .operator("op@example.net")
        .presence(NO_PRESENCE.0, NO_PRESENCE.1)
        .manual_clock()
        .configure(|c| c.server.retention = "30".into())
        .start()
        .await
}

/// A session with `names` registered at `example.org` and signed in, and
/// the operator `op@example.net` signed in as `op`.
async fn people(server: &TestServer, names: &[&str]) -> Session {
    people_and_op(server, names).await.0
}

/// [`people`], and the operator's identity.
async fn people_and_op(server: &TestServer, names: &[&str]) -> (Session, TestIdentity) {
    let mut s = Session::new();
    for name in names {
        let (_, conn) = server.register(name).await;
        s.add(name, conn);
    }
    let op = server.identity("op@example.net");
    s.add("op", server.sign_in(&op).await);
    (s, op)
}

// ---------------------------------------------------------------------------
// Edits, reactions and DELETE (5.3, 5.4, 7.3)

#[tokio::test(flavor = "multi_thread")]
async fn edits_reactions_and_deletes() {
    let server = server().await;
    let mut s = people(&server, &["alice", "bob"]).await;
    let ok = join(&mut s, "alice", "#r").await;
    s.bind("id", &value(&ok, "id"));
    join(&mut s, "bob", "#r").await;
    s.play(
        "alice S: @seq=2;t={*};from=bob@example.org;id={id} JOIN #r

         bob C: msg #r hello
         bob S: @seq=3;t={*};from=bob@example.org MSG #r hello
         bob S: OK seq=3
         alice S: @seq=3;t={*};from=bob@example.org MSG #r hello

         bob C: @edit=3 msg #r hello there
         bob S: @seq=4;t={*};from=bob@example.org;edit=3 MSG #r hello there
         bob S: OK seq=4
         alice S: @seq=4;t={*};from=bob@example.org;edit=3 MSG #r hello there

         alice C: @edit=3 msg #r not yours
         alice S: ERR forbidden{..}
         alice C: @react=4 msg #r 👍
         alice S: ERR not-found{..}

         alice C: @react=3 msg #r 👍
         alice S: @seq=5;t={*};from=alice@example.org;react=3 MSG #r 👍
         alice S: OK seq=5
         bob S: @seq=5;t={*};from=alice@example.org;react=3 MSG #r 👍
         alice C: @react=3 msg #r 👍
         alice S: OK seq=5

         alice C: @reply=3 msg #r welcome
         alice S: @seq=6;t={*};from=alice@example.org;reply=3 MSG #r welcome
         alice S: OK seq=6
         bob S: @seq=6;t={*};from=alice@example.org;reply=3 MSG #r welcome",
    )
    .await;

    // A plain member may not delete someone else's message.
    exchange(&mut s, "bob", "delete #r 6", &["ERR forbidden{..}"]).await;

    s.play(
        "bob C: delete #r 3
         bob S: @seq=7;t={*};from=bob@example.org DELETE #r 3
         bob S: OK seq=7
         alice S: @seq=7;t={*};from=bob@example.org DELETE #r 3",
    )
    .await;
    // Sent again, and for the edit and the reaction deleted along with it:
    // the earlier DELETE's seq, and nothing recorded (5.4).
    exchange(&mut s, "bob", "delete #r 3", &["OK seq=7"]).await;
    exchange(&mut s, "bob", "delete #r 4", &["OK seq=7"]).await;
    exchange(&mut s, "alice", "delete #r 5", &["OK seq=7"]).await;
    // The rules on who may delete come first.
    exchange(&mut s, "bob", "delete #r 5", &["ERR forbidden{..}"]).await;
    // Neither can be edited, reacted to or reported any more.
    exchange(
        &mut s,
        "alice",
        "@react=3 msg #r 👎",
        &["ERR not-found{..}"],
    )
    .await;
    exchange(&mut s, "alice", "report #r 3", &["ERR not-found{..}"]).await;
    exchange(&mut s, "alice", "delete #r 2", &["ERR {..}"]).await;

    // History keeps the places, with placeholders (5.4). The reply stays.
    exchange(
        &mut s,
        "alice",
        "history #r after=2",
        &[
            "@seq=3;t={*};from=bob@example.org;deleted MSG #r",
            "@seq=4;t={*};from=bob@example.org;edit=3;deleted MSG #r",
            "@seq=5;t={*};from=alice@example.org;react=3;deleted MSG #r",
            "@seq=6;t={*};from=alice@example.org;reply=3 MSG #r welcome",
            "@seq=7;t={*};from=bob@example.org DELETE #r 3",
            "OK id={id} more=0",
        ],
    )
    .await;
    exchange(
        &mut s,
        "bob",
        "related #r 1 3",
        &[
            "@seq=4;t={*};from=bob@example.org;edit=3;deleted MSG #r",
            "@seq=5;t={*};from=alice@example.org;react=3;deleted MSG #r",
            "OK id={id} more=0",
        ],
    )
    .await;

    // The id tag: a stale one deletes nothing; the right one works.
    exchange(
        &mut s,
        "alice",
        "@id=zzzzzz delete #r 6",
        &["ERR not-found{..}"],
    )
    .await;
    let id = s.var("id").to_owned();
    s.play(&format!(
        "alice C: @id={id} delete #r 6
         alice S: @seq=8;t={{*}};from=alice@example.org DELETE #r 6
         alice S: OK seq=8
         bob S: @seq=8;t={{*}};from=alice@example.org DELETE #r 6"
    ))
    .await;

    // A moderator deletes anyone's message; so does an operator, who is
    // not even a member.
    s.play(
        "bob C: msg #r one
         bob S: @seq=9;t={*};from=bob@example.org MSG #r one
         bob S: OK seq=9
         alice S: @seq=9;t={*};from=bob@example.org MSG #r one
         bob C: msg #r two
         bob S: @seq=10;t={*};from=bob@example.org MSG #r two
         bob S: OK seq=10
         alice S: @seq=10;t={*};from=bob@example.org MSG #r two
         alice C: delete #r 9
         alice S: @seq=11;t={*};from=alice@example.org DELETE #r 9
         alice S: OK seq=11
         bob S: @seq=11;t={*};from=alice@example.org DELETE #r 9
         op C: delete #r 10
         op S: OK seq=12
         alice S: @seq=12;t={*};from=op@example.net DELETE #r 10
         bob S: @seq=12;t={*};from=op@example.net DELETE #r 10",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// An author may delete their own messages in a room they can no longer
/// read (5.4), and the `id` tag stops a seq of a dropped room from naming
/// a message in the new room of the same name.
#[tokio::test(flavor = "multi_thread")]
async fn delete_after_leaving_and_after_a_drop() {
    let server = server().await;
    let mut s = people(&server, &["alice", "bob"]).await;
    let ok = join(&mut s, "alice", "#p").await;
    let old_id = value(&ok, "id");
    exchange(
        &mut s,
        "alice",
        "set #p public no",
        &["*SET #p public no", "OK seq=2"],
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "invite #p bob@example.org",
        &["*INVITE #p bob@example.org", "OK seq=3"],
    )
    .await;
    // The invitation reaches bob, as a notification.
    expect(
        &mut s,
        "bob",
        "@seq=3;t={*};from=alice@example.org INVITE #p bob@example.org",
    )
    .await;
    join(&mut s, "bob", "#p").await;
    expect(
        &mut s,
        "alice",
        "@seq=4;t={*};from=bob@example.org;id={*} JOIN #p",
    )
    .await;
    for (who, text, seq) in [
        ("bob", "mine", 5),
        ("alice", "hers", 6),
        ("bob", "also mine", 7),
    ] {
        let lines = command(s.client(who), &format!("msg #p {text}")).await;
        assert_eq!(lines.last().unwrap(), &format!("OK seq={seq}"));
        let other = if who == "bob" { "alice" } else { "bob" };
        expect(
            &mut s,
            other,
            &format!("@seq={seq};t={{*}};from={who}@example.org MSG #p {text}"),
        )
        .await;
    }
    exchange(&mut s, "bob", "part #p", &["*PART #p", "OK"]).await;
    expect(&mut s, "alice", "@seq=8;t={*};from=bob@example.org PART #p").await;

    // Gone from a private room: his own message, yes; hers, not-found.
    exchange(&mut s, "bob", "delete #p 5", &["OK seq=9"]).await;
    expect(
        &mut s,
        "alice",
        "@seq=9;t={*};from=bob@example.org DELETE #p 5",
    )
    .await;
    exchange(&mut s, "bob", "delete #p 6", &["ERR not-found{..}"]).await;
    exchange(&mut s, "bob", "delete #p 5", &["OK seq=9"]).await;
    exchange(&mut s, "bob", "history #p", &["ERR not-found{..}"]).await;

    // The room is dropped and made again, and seq 7 now names alice's
    // message in the new room.
    exchange(&mut s, "op", "admin drop #p", &["OK"]).await;
    expect(&mut s, "alice", &format!("@id={old_id} DROP #p")).await;
    let ok = join(&mut s, "alice", "#p").await;
    let new_id = value(&ok, "id");
    assert_ne!(new_id, old_id);
    for n in 2..=7 {
        let lines = command(s.client("alice"), &format!("msg #p new {n}")).await;
        assert_eq!(lines.last().unwrap(), &format!("OK seq={n}"));
    }
    exchange(
        &mut s,
        "bob",
        &format!("@id={old_id} delete #p 7"),
        &["ERR not-found{..}"],
    )
    .await;
    // Without the tag, the seq names alice's message, which is not his.
    exchange(&mut s, "bob", "delete #p 7", &["ERR forbidden{..}"]).await;
    exchange(
        &mut s,
        "alice",
        "history #p after=6",
        &[
            "@seq=7;t={*};from=alice@example.org MSG #p new 7",
            "OK id={*} more=0",
        ],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Settings, roles and moderation (6.2-6.4)

/// BAN of someone who holds an invitation, and of someone who holds a
/// role and has left: the invitation and the role go, and the BAN reaches
/// them because they could see the room (6.4).
#[tokio::test(flavor = "multi_thread")]
async fn ban_of_someone_with_an_invitation_and_a_role() {
    let server = server().await;
    let mut s = people(&server, &["alice", "bob", "carol", "dave"]).await;
    join(&mut s, "alice", "#p").await;
    exchange(
        &mut s,
        "alice",
        "set #p public no",
        &["*SET #p public no", "OK seq=2"],
    )
    .await;
    for (who, seq) in [("bob", 3), ("dave", 5)] {
        exchange(
            &mut s,
            "alice",
            &format!("invite #p {who}@example.org"),
            &["*", &format!("OK seq={seq}")],
        )
        .await;
        expect(
            &mut s,
            who,
            &format!("@seq={seq};t={{*}};from=alice@example.org INVITE #p {who}@example.org"),
        )
        .await;
        join(&mut s, who, "#p").await;
        expect(
            &mut s,
            "alice",
            &format!(
                "@seq={};t={{*}};from={who}@example.org;id={{*}} JOIN #p",
                seq + 1
            ),
        )
        .await;
        if who == "dave" {
            expect(
                &mut s,
                "bob",
                "@seq=5;t={*};from=alice@example.org INVITE #p dave@example.org",
            )
            .await;
            expect(
                &mut s,
                "bob",
                "@seq=6;t={*};from=dave@example.org;id={*} JOIN #p",
            )
            .await;
        }
    }
    // bob becomes a moderator, then leaves, keeping the role (6.3).
    exchange(
        &mut s,
        "alice",
        "role #p bob@example.org mod",
        &["*ROLE #p bob@example.org mod", "OK seq=7"],
    )
    .await;
    expect(
        &mut s,
        "bob",
        "@seq=7;t={*};from=alice@example.org ROLE #p bob@example.org mod",
    )
    .await;
    expect(
        &mut s,
        "dave",
        "@seq=7;t={*};from=alice@example.org ROLE #p bob@example.org mod",
    )
    .await;
    exchange(&mut s, "bob", "part #p", &["*PART #p", "OK"]).await;
    expect(&mut s, "alice", "@seq=8;t={*};from=bob@example.org PART #p").await;
    expect(&mut s, "dave", "@seq=8;t={*};from=bob@example.org PART #p").await;

    // carol is invited, by bob, who has left but keeps his rights.
    exchange(&mut s, "bob", "invite #p carol@example.org", &["OK seq=9"]).await;
    for who in ["alice", "dave", "carol"] {
        expect(
            &mut s,
            who,
            "@seq=9;t={*};from=bob@example.org INVITE #p carol@example.org",
        )
        .await;
    }
    exchange(
        &mut s,
        "carol",
        "info #p",
        &[
            "*",
            "*",
            "*",
            "*",
            "*",
            "OK id={*} members=2 head=9 role=none joined=no",
        ],
    )
    .await;

    // A moderator may not ban the owner, nor an operator (6.3).
    exchange(
        &mut s,
        "bob",
        "ban #p alice@example.org",
        &["ERR forbidden{..}"],
    )
    .await;
    exchange(
        &mut s,
        "bob",
        "ban #p op@example.net",
        &["ERR forbidden{..}"],
    )
    .await;

    // bob bans carol before she joins: the invitation goes. She could see
    // the room, so the BAN reaches her (6.4).
    exchange(
        &mut s,
        "bob",
        "ban #p carol@example.org spam",
        &["OK seq=10"],
    )
    .await;
    for who in ["alice", "dave", "carol"] {
        expect(
            &mut s,
            who,
            "@seq=10;t={*};from=bob@example.org BAN #p carol@example.org spam",
        )
        .await;
    }
    // The ban took her invitation, so the private room is hidden from her
    // again (6.1).
    exchange(&mut s, "carol", "join #p", &["ERR not-found{..}"]).await;
    exchange(
        &mut s,
        "alice",
        "invite #p carol@example.org",
        &["ERR forbidden{..}"],
    )
    .await;
    // Banned again: only the reason changes.
    exchange(
        &mut s,
        "alice",
        "ban #p carol@example.org spam, really",
        &["OK"],
    )
    .await;
    exchange(&mut s, "dave", "bans #p", &["ERR forbidden{..}"]).await;
    exchange(
        &mut s,
        "alice",
        "bans #p",
        &["BAN #p carol@example.org spam, really", "OK"],
    )
    .await;
    // Unbanned, the invitation does not come back: the room is private,
    // so carol cannot even see it.
    exchange(
        &mut s,
        "alice",
        "unban #p carol@example.org",
        &["*UNBAN #p carol@example.org", "OK seq=11"],
    )
    .await;
    expect(
        &mut s,
        "dave",
        "@seq=11;t={*};from=alice@example.org UNBAN #p carol@example.org",
    )
    .await;
    exchange(&mut s, "carol", "join #p", &["ERR not-found{..}"]).await;
    exchange(
        &mut s,
        "alice",
        "unban #p carol@example.org",
        &["ERR not-found{..}"],
    )
    .await;

    // KICK of someone who has left gets not-found, role or not (6.4).
    exchange(
        &mut s,
        "alice",
        "kick #p bob@example.org",
        &["ERR not-found{..}"],
    )
    .await;
    // BAN takes bob's role. He held it, so he could see the room, and the
    // BAN reaches him.
    exchange(
        &mut s,
        "alice",
        "ban #p bob@example.org",
        &["*BAN #p bob@example.org", "OK seq=12"],
    )
    .await;
    for who in ["dave", "bob"] {
        expect(
            &mut s,
            who,
            "@seq=12;t={*};from=alice@example.org BAN #p bob@example.org",
        )
        .await;
    }
    exchange(
        &mut s,
        "alice",
        "roles #p",
        &["ROLE #p alice@example.org owner", "OK"],
    )
    .await;
    exchange(&mut s, "bob", "join #p", &["ERR not-found{..}"]).await;
    exchange(
        &mut s,
        "bob",
        "invite #p carol@example.org",
        &["ERR not-found{..}"],
    )
    .await;

    // The only owner cannot ban or kick themselves.
    exchange(
        &mut s,
        "alice",
        "ban #p alice@example.org",
        &["ERR last-owner{..}"],
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "kick #p alice@example.org",
        &["ERR last-owner{..}"],
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "role #p alice@example.org member",
        &["ERR last-owner{..}"],
    )
    .await;

    // KICK reaches its target, and then nothing more does.
    exchange(
        &mut s,
        "alice",
        "kick #p dave@example.org bye",
        &["*KICK #p dave@example.org bye", "OK seq=13"],
    )
    .await;
    expect(
        &mut s,
        "dave",
        "@seq=13;t={*};from=alice@example.org KICK #p dave@example.org bye",
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "msg #p after",
        &["*MSG #p after", "OK seq=14"],
    )
    .await;
    exchange(&mut s, "dave", "history #p", &["ERR not-found{..}"]).await;
    s.settled().await;
    server.stop().await;
}

/// `guests read` stops guests from sending; `guests none` removes them
/// with a PART each (6.2). Only owners change them; mods set the topic.
#[tokio::test(flavor = "multi_thread")]
async fn room_settings_and_guests() {
    let server = server().await;
    let mut s = people(&server, &["alice", "bob"]).await;
    s.add("sam", server.guest("sam").await);
    join(&mut s, "alice", "#r").await;
    join(&mut s, "bob", "#r").await;
    expect(
        &mut s,
        "alice",
        "@seq=2;t={*};from=bob@example.org;id={*} JOIN #r",
    )
    .await;
    join(&mut s, "sam", "#r").await;
    for who in ["alice", "bob"] {
        expect(&mut s, who, "@seq=3;t={*};from=~sam;id={*} JOIN #r").await;
    }
    exchange(
        &mut s,
        "alice",
        "role #r bob@example.org mod",
        &["*", "OK seq=4"],
    )
    .await;
    for who in ["bob", "sam"] {
        expect(
            &mut s,
            who,
            "@seq=4;t={*};from=alice@example.org ROLE #r bob@example.org mod",
        )
        .await;
    }
    exchange(&mut s, "alice", "role #r ~sam mod", &["ERR forbidden{..}"]).await;
    exchange(&mut s, "bob", "set #r guests read", &["ERR forbidden{..}"]).await;
    exchange(&mut s, "bob", "set #r e2ee yes", &["ERR forbidden{..}"]).await;
    exchange(
        &mut s,
        "bob",
        "set #r colour blue",
        &["ERR not-supported{..}"],
    )
    .await;
    exchange(
        &mut s,
        "bob",
        "set #r topic  spaces kept ",
        &[
            "@seq=5;t={*};from=bob@example.org SET #r topic  spaces kept ",
            "OK seq=5",
        ],
    )
    .await;
    for who in ["alice", "sam"] {
        expect(
            &mut s,
            who,
            "@seq=5;t={*};from=bob@example.org SET #r topic  spaces kept ",
        )
        .await;
    }

    exchange(
        &mut s,
        "alice",
        "set #r guests read ",
        &[
            "@seq=6;t={*};from=alice@example.org SET #r guests read",
            "OK seq=6",
        ],
    )
    .await;
    for who in ["bob", "sam"] {
        expect(
            &mut s,
            who,
            "@seq=6;t={*};from=alice@example.org SET #r guests read",
        )
        .await;
    }
    exchange(&mut s, "alice", "set #r guests read", &["OK"]).await;
    exchange(&mut s, "sam", "msg #r hi", &["ERR forbidden{..}"]).await;
    exchange(&mut s, "sam", "@react=5 msg #r 👋", &["ERR forbidden{..}"]).await;
    exchange(&mut s, "sam", "typing #r", &["ERR forbidden{..}"]).await;
    exchange(
        &mut s,
        "sam",
        "history #r after=5",
        &["*SET #r guests read", "OK id={*} more=0"],
    )
    .await;

    // The guest's PART is recorded before the OK.
    exchange(
        &mut s,
        "alice",
        "set #r guests none",
        &[
            "*SET #r guests none",
            "@seq=8;t={*};from=~sam PART #r",
            "OK seq=7",
        ],
    )
    .await;
    for who in ["bob", "sam"] {
        expect(
            &mut s,
            who,
            "@seq=7;t={*};from=alice@example.org SET #r guests none",
        )
        .await;
        expect(&mut s, who, "@seq=8;t={*};from=~sam PART #r").await;
    }
    exchange(&mut s, "sam", "join #r", &["ERR forbidden{..}"]).await;
    exchange(&mut s, "sam", "history #r", &["ERR forbidden{..}"]).await;
    exchange(
        &mut s,
        "alice",
        "info #r",
        &[
            "SET #r topic  spaces kept ",
            "SET #r public yes",
            "SET #r guests none",
            "SET #r retention server",
            "SET #r e2ee no",
            "OK id={*} members=2 head=8 role=owner joined=yes",
        ],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Reports (5.8)

/// A report reaches every reviewer, keeps its copy when the message is
/// deleted, and when its room is dropped; RESOLVE tells the others.
#[tokio::test(flavor = "multi_thread")]
async fn reports_outlive_delete_and_drop() {
    let server = server().await;
    let (mut s, op) = people_and_op(&server, &["alice", "bob", "carol"]).await;
    let op_phone = server.new_device(&op).await;
    s.add("op2", server.sign_in(&op_phone).await);
    s.add("spam", server.guest("spam").await);

    let ok = join(&mut s, "alice", "#r").await;
    s.bind("id", &value(&ok, "id"));
    join(&mut s, "bob", "#r").await;
    join(&mut s, "carol", "#r").await;
    join(&mut s, "spam", "#r").await;
    // Everyone sees the JOINs after their own, and the ROLE.
    for (who, from) in [("alice", 2), ("bob", 3), ("carol", 4)] {
        for seq in from..=4 {
            expect(
                &mut s,
                who,
                &format!("@seq={seq};t={{*}};from={{*}};id={{id}} JOIN #r"),
            )
            .await;
        }
    }
    exchange(
        &mut s,
        "alice",
        "role #r bob@example.org mod",
        &["*", "OK seq=5"],
    )
    .await;
    for who in ["bob", "carol", "spam"] {
        expect(
            &mut s,
            who,
            "@seq=5;t={*};from=alice@example.org ROLE #r bob@example.org mod",
        )
        .await;
    }
    exchange(
        &mut s,
        "spam",
        "msg #r cheap pills",
        &["*MSG #r cheap pills", "OK seq=6"],
    )
    .await;
    for who in ["alice", "bob", "carol"] {
        expect(&mut s, who, "@seq=6;t={*};from=~spam MSG #r cheap pills").await;
    }

    // You cannot report your own message.
    exchange(&mut s, "spam", "report #r 6", &["ERR forbidden{..}"]).await;
    exchange(&mut s, "carol", "report #r 6 spam", &["OK id={rid}"]).await;
    // Owners and mods get the lines without `from`; operators with it.
    for who in ["alice", "bob"] {
        s.play(&format!(
            "{who} S: @report={{rid}};t={{*}} REPORT #r 6 spam
             {who} S: @report={{rid}};seq=6;t={{*}};from=~spam MSG #r cheap pills"
        ))
        .await;
    }
    for who in ["op", "op2"] {
        s.play(&format!(
            "{who} S: @report={{rid}};t={{*}};from=carol@example.org REPORT #r 6 spam
             {who} S: @report={{rid}};seq=6;t={{*}};from=~spam MSG #r cheap pills"
        ))
        .await;
    }
    // Reported again: the same id, and nothing sent.
    exchange(&mut s, "carol", "report #r 6 spam", &["OK id={rid}"]).await;

    // The spammer deletes it. The room's copy is erased; the report's is
    // not, and reporting again still gets the same id.
    exchange(&mut s, "spam", "delete #r 6", &["*DELETE #r 6", "OK seq=7"]).await;
    for who in ["alice", "bob", "carol"] {
        expect(&mut s, who, "@seq=7;t={*};from=~spam DELETE #r 6").await;
    }
    exchange(&mut s, "carol", "report #r 6 again", &["OK id={rid}"]).await;
    exchange(
        &mut s,
        "alice",
        "history #r after=5 limit=1",
        &[
            "@seq=6;t={*};from=~spam;deleted MSG #r",
            "OK id={id} more=1",
        ],
    )
    .await;
    let report = [
        "@report={rid};t={*} REPORT #r 6 spam",
        "@report={rid};seq=6;t={*};from=~spam MSG #r cheap pills",
        "OK",
    ];
    exchange(&mut s, "bob", "reports #r", &report).await;
    exchange(&mut s, "carol", "reports #r", &["ERR forbidden{..}"]).await;

    // bob leaves, still a moderator. An operator drops the room: every
    // member and bob get DROP, and the report stays (10.4).
    exchange(&mut s, "bob", "part #r", &["*PART #r", "OK"]).await;
    for who in ["alice", "carol", "spam"] {
        expect(&mut s, who, "@seq=8;t={*};from=bob@example.org PART #r").await;
    }
    exchange(&mut s, "op", "admin drop #r enough", &["OK"]).await;
    for who in ["alice", "bob", "carol", "spam"] {
        expect(&mut s, who, "@id={id} DROP #r enough").await;
    }
    exchange(&mut s, "alice", "sync", &["OK"]).await;
    exchange(&mut s, "alice", "reports #r", &["ERR not-found{..}"]).await;
    exchange(
        &mut s,
        "op",
        "admin reports",
        &[
            "@report={rid};t={*};from=carol@example.org REPORT #r 6 spam",
            "@report={rid};seq=6;t={*};from=~spam MSG #r cheap pills",
            "OK",
        ],
    )
    .await;
    // The room's roles went with it, so alice is no longer a reviewer.
    let rid = s.var("rid").to_owned();
    exchange(
        &mut s,
        "alice",
        &format!("resolve {rid}"),
        &["ERR not-found{..}"],
    )
    .await;
    exchange(&mut s, "op", &format!("resolve {rid}"), &["OK"]).await;
    expect(&mut s, "op2", &format!("RESOLVED {rid}")).await;
    exchange(&mut s, "op2", "admin reports", &["OK"]).await;
    exchange(
        &mut s,
        "op",
        &format!("resolve {rid}"),
        &["ERR not-found{..}"],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Retention (7.5)

/// Shortening retention with SET and then ADMIN SET expires stored events
/// at once, in seq order. A reported message's copy outlives it.
#[tokio::test(flavor = "multi_thread")]
async fn retention_shortened_by_set_and_admin_set() {
    let server = server().await;
    let mut s = people(&server, &["alice", "bob"]).await;
    let ok = join(&mut s, "alice", "#r").await;
    s.bind("id", &value(&ok, "id"));
    join(&mut s, "bob", "#r").await;
    expect(
        &mut s,
        "alice",
        "@seq=2;t={*};from=bob@example.org;id={id} JOIN #r",
    )
    .await;
    exchange(&mut s, "bob", "msg #r day 0", &["*", "OK seq=3"]).await;
    expect(
        &mut s,
        "alice",
        "@seq=3;t={*};from=bob@example.org MSG #r day 0",
    )
    .await;
    // alice owns the room, so she is a reviewer too, and gets the lines.
    exchange(
        &mut s,
        "alice",
        "report #r 3 old",
        &[
            "@report={rid};t={*} REPORT #r 3 old",
            "@report={rid};seq=3;t={*};from=bob@example.org MSG #r day 0",
            "OK id={rid}",
        ],
    )
    .await;
    s.play(
        "op S: @report={rid};t={*};from=alice@example.org REPORT #r 3 old
         op S: @report={rid};seq=3;t={*};from=bob@example.org MSG #r day 0",
    )
    .await;

    server.advance(3 * DAY);
    exchange(&mut s, "bob", "msg #r day 3", &["*", "OK seq=4"]).await;
    expect(
        &mut s,
        "alice",
        "@seq=4;t={*};from=bob@example.org MSG #r day 3",
    )
    .await;
    server.advance(DAY + Duration::from_secs(60));
    exchange(&mut s, "bob", "msg #r day 4", &["*", "OK seq=5"]).await;
    expect(
        &mut s,
        "alice",
        "@seq=5;t={*};from=bob@example.org MSG #r day 4",
    )
    .await;
    // Nothing is older than the server's 30 days.
    assert_eq!(server.expire_now().await, 0);

    // The limits on the value (6.2).
    exchange(
        &mut s,
        "alice",
        "set #r retention 0",
        &["ERR bad-syntax{..}"],
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "set #r retention 31",
        &["ERR forbidden{..}"],
    )
    .await;
    exchange(&mut s, "bob", "set #r retention 2", &["ERR forbidden{..}"]).await;

    // Two days: the first three events go at once.
    exchange(
        &mut s,
        "alice",
        "set #r retention 2 ",
        &[
            "@seq=6;t={*};from=alice@example.org SET #r retention 2",
            "OK seq=6",
        ],
    )
    .await;
    expect(
        &mut s,
        "bob",
        "@seq=6;t={*};from=alice@example.org SET #r retention 2",
    )
    .await;
    exchange(
        &mut s,
        "bob",
        "history #r after=0",
        &[
            "@seq=4;t={*};from=bob@example.org MSG #r day 3",
            "@seq=5;t={*};from=bob@example.org MSG #r day 4",
            "@seq=6;t={*};from=alice@example.org SET #r retention 2",
            "OK id={id} more=0",
        ],
    )
    .await;
    exchange(&mut s, "bob", "related #r 1 3", &["OK id={id} more=0"]).await;
    // The report's copy did not expire with it.
    exchange(
        &mut s,
        "alice",
        "reports #r",
        &[
            "@report={rid};t={*} REPORT #r 3 old",
            "@report={rid};seq=3;t={*};from=bob@example.org MSG #r day 0",
            "OK",
        ],
    )
    .await;
    // The expired message cannot be targeted any more.
    exchange(
        &mut s,
        "alice",
        "@react=3 msg #r 👋",
        &["ERR not-found{..}"],
    )
    .await;
    exchange(&mut s, "bob", "delete #r 3", &["ERR not-found{..}"]).await;

    // The server's period goes down to one day, below the room's: it
    // applies, and at once (7.5, 10.6).
    exchange(
        &mut s,
        "alice",
        "admin set retention 1",
        &["ERR forbidden{..}"],
    )
    .await;
    exchange(&mut s, "op", "admin set retention 1", &["OK"]).await;
    exchange(
        &mut s,
        "bob",
        "history #r after=0",
        &[
            "@seq=5;t={*};from=bob@example.org MSG #r day 4",
            "@seq=6;t={*};from=alice@example.org SET #r retention 2",
            "OK id={id} more=0",
        ],
    )
    .await;
    let mut anon = server.connect().await;
    common::recv(&mut anon).await;
    let info = command(&mut anon, "info").await;
    assert!(info[0].contains(" retention=1"), "{info:?}");

    // Later, the background run takes the rest; seqs are not reused.
    server.advance(DAY + Duration::from_secs(1));
    assert_eq!(server.expire_now().await, 2);
    exchange(&mut s, "bob", "history #r after=0", &["OK id={id} more=0"]).await;
    exchange(
        &mut s,
        "bob",
        "msg #r fresh",
        &["@seq=7;t={*};from=bob@example.org MSG #r fresh", "OK seq=7"],
    )
    .await;
    expect(
        &mut s,
        "alice",
        "@seq=7;t={*};from=bob@example.org MSG #r fresh",
    )
    .await;
    exchange(
        &mut s,
        "alice",
        "info #r",
        &[
            "*",
            "*",
            "*",
            "SET #r retention 2",
            "*",
            "OK id={id} members=2 head=7 role=owner joined=yes",
        ],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// A report outlives its dropped room, and the owner of a new room of the
/// same name is not one of its reviewers (5.8, 10.4).
#[tokio::test(flavor = "multi_thread")]
async fn a_new_room_of_the_same_name_does_not_inherit_reports() {
    let server = server().await;
    let mut s = people(&server, &["alice", "bob", "carol"]).await;
    join(&mut s, "alice", "#r").await;
    join(&mut s, "bob", "#r").await;
    expect(
        &mut s,
        "alice",
        "@seq=2;t={*};from=bob@example.org;id={*} JOIN #r",
    )
    .await;
    exchange(&mut s, "alice", "msg #r rude", &["*", "OK seq=3"]).await;
    expect(
        &mut s,
        "bob",
        "@seq=3;t={*};from=alice@example.org MSG #r rude",
    )
    .await;
    exchange(&mut s, "bob", "report #r 3", &["OK id={rid}"]).await;
    expect(&mut s, "alice", "@report={rid};t={*} REPORT #r 3").await;
    expect(&mut s, "alice", "*MSG #r rude").await;
    expect(
        &mut s,
        "op",
        "@report={rid};t={*};from=bob@example.org REPORT #r 3",
    )
    .await;
    expect(&mut s, "op", "*MSG #r rude").await;
    exchange(&mut s, "op", "admin drop #r", &["OK"]).await;
    expect(&mut s, "alice", "@id={*} DROP #r").await;
    expect(&mut s, "bob", "@id={*} DROP #r").await;

    // carol makes #r again and owns it.
    join(&mut s, "carol", "#r").await;
    exchange(&mut s, "carol", "reports #r", &["OK"]).await;
    let rid = s.var("rid").to_owned();
    exchange(
        &mut s,
        "carol",
        &format!("resolve {rid}"),
        &["ERR not-found{..}"],
    )
    .await;
    // The same seq in the new room is another message, and bob's report
    // of it is a new report, which carol reviews.
    exchange(&mut s, "carol", "msg #r two", &["*", "OK seq=2"]).await;
    exchange(&mut s, "carol", "msg #r three", &["*", "OK seq=3"]).await;
    join(&mut s, "bob", "#r").await;
    expect(
        &mut s,
        "carol",
        "@seq=4;t={*};from=bob@example.org;id={*} JOIN #r",
    )
    .await;
    exchange(&mut s, "bob", "report #r 3", &["OK id={rid2}"]).await;
    assert_ne!(s.var("rid2"), rid);
    expect(&mut s, "carol", "@report={rid2};t={*} REPORT #r 3").await;
    expect(
        &mut s,
        "carol",
        "@report={rid2};seq=3;t={*};from=carol@example.org MSG #r three",
    )
    .await;
    expect(
        &mut s,
        "op",
        "@report={rid2};t={*};from=bob@example.org REPORT #r 3",
    )
    .await;
    expect(&mut s, "op", "*MSG #r three").await;
    exchange(
        &mut s,
        "carol",
        "reports #r",
        &["*REPORT #r 3", "*MSG #r three", "OK"],
    )
    .await;
    let rid2 = s.var("rid2").to_owned();
    exchange(&mut s, "carol", &format!("resolve {rid2}"), &["OK"]).await;
    expect(&mut s, "op", &format!("RESOLVED {rid2}")).await;
    // The old one is still open, for operators.
    exchange(
        &mut s,
        "op",
        "admin reports",
        &["*REPORT #r 3", "*MSG #r rude", "OK"],
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// Reports are rate-limited per uid (5.8), by the hour.
#[tokio::test(flavor = "multi_thread")]
async fn reports_are_rate_limited() {
    let server = TestServer::builder()
        .identity_domain("example.org")
        .presence(NO_PRESENCE.0, NO_PRESENCE.1)
        .manual_clock()
        .configure(|c| c.limits.reports_per_hour = 2)
        .start()
        .await;
    let (_, alice) = server.register("alice").await;
    let (_, bob) = server.register("bob").await;
    let mut s = Session::new();
    s.add("alice", alice);
    s.add("bob", bob);
    join(&mut s, "alice", "#r").await;
    for n in 2..=5 {
        exchange(
            &mut s,
            "alice",
            &format!("msg #r m{n}"),
            &["*", &format!("OK seq={n}")],
        )
        .await;
    }
    exchange(&mut s, "bob", "report #r 2", &["OK id={*}"]).await;
    exchange(&mut s, "bob", "report #r 3", &["OK id={*}"]).await;
    exchange(
        &mut s,
        "bob",
        "report #r 4",
        &["@retry={*} ERR rate-limited{..}"],
    )
    .await;
    server.advance(Duration::from_secs(60 * 60 + 1));
    exchange(&mut s, "bob", "report #r 4", &["OK id={*}"]).await;
    // Each report reached alice, the owner.
    for _ in 0..3 {
        expect(&mut s, "alice", "@report={*};t={*} REPORT #r {*}").await;
        expect(&mut s, "alice", "*").await;
    }
    s.settled().await;
    server.stop().await;
}

/// A guest removed from a room by KICK, BAN or `guests none` is no longer
/// in it when its session ends: no second PART is recorded, then or after
/// a restart (4.2, 6.2, 6.4).
#[tokio::test(flavor = "multi_thread")]
async fn removed_guests_leave_once() {
    let mut server = server().await;
    let (alice, conn) = server.register("alice").await;
    let op = server.identity("op@example.net");
    let mut s = Session::new();
    s.add("alice", conn);
    s.add("op", server.sign_in(&op).await);
    let ok = join(&mut s, "alice", "#r").await;
    s.bind("id", &value(&ok, "id"));
    for (n, guest) in ["kim", "lee", "max"].into_iter().enumerate() {
        s.add(guest, server.guest(guest).await);
        join(&mut s, guest, "#r").await;
        expect(
            &mut s,
            "alice",
            &format!("@seq={};t={{*}};from=~{guest};id={{id}} JOIN #r", n + 2),
        )
        .await;
    }
    // Each guest also sees the later JOINs.
    expect(&mut s, "kim", "@seq=3;t={*};from=~lee;id={id} JOIN #r").await;
    expect(&mut s, "kim", "@seq=4;t={*};from=~max;id={id} JOIN #r").await;
    expect(&mut s, "lee", "@seq=4;t={*};from=~max;id={id} JOIN #r").await;

    exchange(
        &mut s,
        "alice",
        "kick #r ~kim",
        &["*KICK #r ~kim", "OK seq=5"],
    )
    .await;
    for who in ["kim", "lee", "max"] {
        expect(
            &mut s,
            who,
            "@seq=5;t={*};from=alice@example.org KICK #r ~kim",
        )
        .await;
    }
    exchange(
        &mut s,
        "alice",
        "ban #r ~lee",
        &["*BAN #r ~lee", "OK seq=6"],
    )
    .await;
    for who in ["lee", "max"] {
        expect(
            &mut s,
            who,
            "@seq=6;t={*};from=alice@example.org BAN #r ~lee",
        )
        .await;
    }
    // The ban is of the uid only.
    exchange(&mut s, "alice", "bans #r", &["BAN #r ~lee", "OK"]).await;
    exchange(
        &mut s,
        "alice",
        "set #r guests none",
        &[
            "*SET #r guests none",
            "@seq=8;t={*};from=~max PART #r",
            "OK seq=7",
        ],
    )
    .await;
    expect(&mut s, "max", "*SET #r guests none").await;
    expect(&mut s, "max", "@seq=8;t={*};from=~max PART #r").await;

    // kim's session ends now, the others' at the restart.
    exchange(&mut s, "op", "admin disconnect ~kim", &["OK"]).await;
    until_closed(s.client("kim")).await;
    s.take("kim");
    exchange(&mut s, "alice", "set #r guests write", &["*", "OK seq=9"]).await;
    s.settled().await;
    drop(s);
    server.restart().await;
    let mut conn = server.sign_in(&alice).await;
    let page = command(&mut conn, "history #r after=8").await;
    assert_eq!(page.len(), 2, "{page:?}");
    assert!(page[0].ends_with(" SET #r guests write"), "{page:?}");
    assert!(page[1].starts_with("OK id="), "{page:?}");
    let info = command(&mut conn, "info #r").await;
    assert!(
        info.last().unwrap().contains(" members=1 head=9 "),
        "{info:?}"
    );
    // lee's name is still banned; kim may come back.
    let mut lee = server.guest("lee").await;
    let answer = command(&mut lee, "join #r").await;
    assert!(answer[0].starts_with("ERR forbidden"), "{answer:?}");
    let mut kim = server.guest("kim").await;
    let answer = command(&mut kim, "join #r").await;
    assert!(answer.last().unwrap().ends_with(" head=10"), "{answer:?}");
    server.stop().await;
}

/// A BAN of a non-member reaches them only if they could see the room
/// before it (6.4): always for a public room, never for a private room
/// they had no invitation or role in.
#[tokio::test(flavor = "multi_thread")]
async fn ban_events_reach_who_could_see_the_room() {
    let server = server().await;
    let mut s = people(&server, &["alice", "bob", "carol"]).await;
    join(&mut s, "alice", "#pub").await;
    exchange(
        &mut s,
        "alice",
        "ban #pub bob@example.org",
        &["*BAN #pub bob@example.org", "OK seq=2"],
    )
    .await;
    expect(
        &mut s,
        "bob",
        "@seq=2;t={*};from=alice@example.org BAN #pub bob@example.org",
    )
    .await;
    exchange(&mut s, "bob", "join #pub", &["ERR forbidden{..}"]).await;
    // Already banned and not a member: nothing recorded.
    exchange(&mut s, "alice", "ban #pub bob@example.org", &["OK"]).await;

    join(&mut s, "alice", "#priv").await;
    exchange(&mut s, "alice", "set #priv public no", &["*", "OK seq=2"]).await;
    exchange(
        &mut s,
        "alice",
        "ban #priv carol@example.org",
        &["*BAN #priv carol@example.org", "OK seq=3"],
    )
    .await;
    // carol hears nothing, and the room stays hidden from her.
    exchange(&mut s, "carol", "join #priv", &["ERR not-found{..}"]).await;
    exchange(&mut s, "carol", "related #priv 1 2", &["ERR not-found{..}"]).await;
    // The room's events are readable by its owner, of course.
    exchange(&mut s, "alice", "related #priv 1 3", &["OK id={*} more=0"]).await;
    s.settled().await;
    server.stop().await;
}

/// KICK and INVITE reach every connection of their target (6.4).
#[tokio::test(flavor = "multi_thread")]
async fn kick_reaches_every_device() {
    let server = server().await;
    let (bob, bob_laptop) = server.register("bob").await;
    let (_, alice) = server.register("alice").await;
    let bob_phone = server.sign_in(&server.new_device(&bob).await).await;
    let mut s = Session::new();
    s.add("alice", alice);
    s.add("laptop", bob_laptop);
    s.add("phone", bob_phone);
    join(&mut s, "alice", "#p").await;
    exchange(&mut s, "alice", "set #p public no", &["*", "OK seq=2"]).await;
    exchange(
        &mut s,
        "alice",
        "invite #p bob@example.org",
        &["*", "OK seq=3"],
    )
    .await;
    for who in ["laptop", "phone"] {
        expect(
            &mut s,
            who,
            "@seq=3;t={*};from=alice@example.org INVITE #p bob@example.org",
        )
        .await;
    }
    join(&mut s, "laptop", "#p").await;
    for who in ["alice", "phone"] {
        expect(
            &mut s,
            who,
            "@seq=4;t={*};from=bob@example.org;id={*} JOIN #p",
        )
        .await;
    }
    exchange(
        &mut s,
        "alice",
        "kick #p bob@example.org",
        &["*", "OK seq=5"],
    )
    .await;
    for who in ["laptop", "phone"] {
        expect(
            &mut s,
            who,
            "@seq=5;t={*};from=alice@example.org KICK #p bob@example.org",
        )
        .await;
    }
    exchange(&mut s, "alice", "msg #p private again", &["*", "OK seq=6"]).await;
    exchange(&mut s, "phone", "info #p", &["ERR not-found{..}"]).await;
    s.settled().await;
    server.stop().await;
}

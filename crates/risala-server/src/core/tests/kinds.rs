//! Which kinds of connection may send which commands (4.1, Section 13),
//! and the routing of every command to its area.

use risala_proto::command::{AdminCommand, Command, Request};
use risala_proto::connection::ConnectionKind;

use super::*;

/// `n` bytes of zeros in base64 with padding.
fn b64(n: usize) -> String {
    let tail = match n % 3 {
        0 => "",
        1 => "AA==",
        _ => "AAA=",
    };
    format!("{}{tail}", "A".repeat(n / 3 * 4))
}

const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";

/// One line of every command and form of Section 13's first table, but
/// ANON and GUEST, which change the kind.
fn samples() -> Vec<String> {
    let blob = format!("sha384:{}", "ab".repeat(48));
    let (gid, hash, token, msg) = (b64(32), b64(48), b64(32), b64(100));
    let signature = b64(2420);
    vec![
        "INFO".into(),
        "INFO #general".into(),
        format!("AUTH alice@example.org {signature}"),
        format!("REGISTER alice {} {signature}", b64(10)),
        format!("KEYS PUT {}", b64(10)),
        format!("PAIR PUT {BOX} {}", b64(40)),
        format!("PAIR GET {BOX}"),
        "UNREGISTER alice@example.org".into(),
        format!("CREATE {BOX} {gid} {hash}"),
        format!("CREATE {BOX} {gid} {hash} epoch=3"),
        format!("CREATE {BOX} {gid} {hash} #general {msg} {msg}"),
        format!("POST {BOX} {token} {msg}"),
        format!("POST {BOX} - {msg}"),
        format!("UPLOAD {BOX} {token} 100"),
        format!("REPORT {BOX} {}", b64(40)),
        "LIST".into(),
        format!("GROUPINFO {BOX}"),
        format!("MUTE {BOX} {}", b64(16)),
        format!("UNMUTE {BOX} {}", b64(16)),
        format!("FOLLOW {BOX}"),
        format!("UNFOLLOW {BOX}"),
        format!("FETCH {BOX} after=0"),
        format!("TOKEN {BOX} 41 {token} {hash}"),
        "PRESENCE ON".into(),
        "PRESENCE OFF".into(),
        "WATCH alice@example.org,~sam".into(),
        "WHOIS alice@example.org".into(),
        "MEMBERS #general".into(),
        format!(
            "PUSH ADD https://push.example.net/a tag {} {} box={BOX}",
            b64(65),
            b64(16)
        ),
        format!("PUSH DEL https://push.example.net/a box={BOX}"),
        format!(
            "PUSH ADD https://push.example.net/a tag {} {}",
            b64(65),
            b64(16)
        ),
        "PUSH DEL https://push.example.net/a".into(),
        "PUSH LIST".into(),
        format!("KEYPKG ADD {msg}"),
        "KEYPKG COUNT".into(),
        "KEYPKG GET alice@example.org".into(),
        format!("WELCOME PUT {hash} {msg}"),
        format!("WELCOME GET {hash}"),
        "WELCOME LIST".into(),
        "WELCOME DEL w1".into(),
        format!("BLOB {blob} 10"),
        format!("BLOB {blob} 10 box={BOX} token={token}"),
        format!("BACKUP PUT 0 {blob} {}", b64(60)),
        "BACKUP GET".into(),
        "BACKUP DEL".into(),
        "ADMIN OPS".into(),
        "ADMIN BAN spam@example.net spam".into(),
        format!("ADMIN DROP {BOX}"),
        "ADMIN SET guests no".into(),
        "ADMIN UNREGISTER alice@example.org".into(),
        "RESOLVE r1".into(),
        "PING".into(),
    ]
}

/// What the hub answers `request` on a connection of `kind`: the error of
/// Section 13 if the kind may not send it, `forbidden` for ADMIN from
/// someone who is not an operator (Section 10), `OK` for PING, and
/// `not-supported` for every area's commands, which are not built yet.
fn expected(request: &Request, kind: ConnectionKind, operator: bool) -> String {
    let code = match request.command.check_kind(kind) {
        Err(code) => code.to_string(),
        Ok(()) => match &request.command {
            Command::Ping { .. } => return "OK".into(),
            Command::Admin(_) if !operator => "forbidden".into(),
            _ => "not-supported".into(),
        },
    };
    format!("ERR {code}")
}

/// Every command, on every kind of connection, gets the answer Section 13
/// gives it, or `not-supported` from its area.
#[tokio::test]
async fn every_command_on_every_kind() {
    let mut h = Harness::new();
    let mut conns = vec![
        (ConnectionKind::New, false, h.connect()),
        (ConnectionKind::Anonymous, false, h.anon().await),
        (ConnectionKind::Guest, false, h.guest("sam").await.0),
        (
            ConnectionKind::SignedIn,
            false,
            h.signed_in_as("alice@example.org"),
        ),
        (
            ConnectionKind::SignedIn,
            true,
            h.signed_in_as("op@example.org"),
        ),
    ];
    for line in samples() {
        let request: Request = line
            .parse()
            .unwrap_or_else(|e| panic!("sample {line:?}: {e}"));
        for (kind, operator, conn) in &mut conns {
            h.send(conn, &format!("@ref=k {line}")).await;
            let want = format!("@ref=k {}", expected(&request, *kind, *operator));
            assert_eq!(
                conn.lines(),
                [want],
                "{line} on {kind} (operator: {operator})"
            );
            assert_eq!(conn.handle.kind(), *kind, "{line} changed the kind");
        }
    }
}

/// Spot checks of the table in Section 13, written out, so that the test
/// above does not only agree with `check_kind`.
#[tokio::test]
async fn section_13_by_hand() {
    let mut h = Harness::new();
    const NEW: usize = 0;
    const ANON: usize = 1;
    const GUEST: usize = 2;
    const ALICE: usize = 3;
    let mut conns = [
        h.connect(),
        h.anon().await,
        h.guest("sam").await.0,
        h.signed_in_as("alice@example.org"),
    ];
    let gid = b64(32);
    let hash = b64(48);
    let token = b64(32);
    let msg = b64(100);
    let cases: Vec<(usize, String, &str)> = vec![
        // Only INFO without a room, ANON, GUEST, AUTH, REGISTER, KEYS PUT,
        // PAIR, PING, PONG and QUIT before a kind (4.1).
        (NEW, "INFO #general".into(), "ERR not-authenticated"),
        (NEW, format!("FOLLOW {BOX}"), "ERR not-authenticated"),
        (NEW, "INFO".into(), "ERR not-supported"),
        (NEW, "KEYS PUT AAAA".into(), "ERR not-supported"),
        (NEW, format!("PAIR GET {BOX}"), "ERR not-supported"),
        // Once it has a kind, a command for another kind gets
        // wrong-connection (4.1, Section 13).
        (GUEST, "KEYS PUT AAAA".into(), "ERR wrong-connection"),
        (
            GUEST,
            format!("CREATE {BOX} {gid} {hash} #general {msg} {msg}"),
            "ERR wrong-connection",
        ),
        (ALICE, format!("FOLLOW {BOX}"), "ERR wrong-connection"),
        (
            ALICE,
            format!("UPLOAD {BOX} {token} 1"),
            "ERR wrong-connection",
        ),
        (
            ALICE,
            format!("TOKEN {BOX} 1 {token} {hash}"),
            "ERR wrong-connection",
        ),
        (ANON, "KEYPKG COUNT".into(), "ERR wrong-connection"),
        (ANON, "BACKUP GET".into(), "ERR wrong-connection"),
        (ANON, "ADMIN OPS".into(), "ERR wrong-connection"),
        (GUEST, "ADMIN OPS".into(), "ERR wrong-connection"),
        // A guest may follow, and create a report conversation (4.2).
        (GUEST, format!("FOLLOW {BOX}"), "ERR not-supported"),
        (
            GUEST,
            format!("CREATE {BOX} {gid} {hash}"),
            "ERR not-supported",
        ),
        // ADMIN needs an operator (Section 10).
        (ALICE, "ADMIN OPS".into(), "ERR forbidden"),
        // BLOB from an anonymous connection needs box= and token= (12.12).
        (
            ANON,
            format!("BLOB sha384:{} 1", "ab".repeat(48)),
            "ERR bad-syntax",
        ),
        // The kind-setting commands, once there is a kind.
        (ALICE, "ANON".into(), "ERR already-authenticated"),
        (GUEST, "GUEST bea".into(), "ERR already-authenticated"),
    ];
    for (who, line, want) in cases {
        h.send(&conns[who], &line).await;
        assert_eq!(conns[who].lines(), [want], "{line}");
    }
}

/// An ADMIN command an operator sends reaches its area: ADMIN UNREGISTER
/// the identity area's, the rest the admin area's (both not built yet).
#[tokio::test]
async fn admin_commands_reach_their_area() {
    let mut h = Harness::new();
    let mut op = h.signed_in_as("op@example.org");
    for line in ["ADMIN OPS", "ADMIN UNREGISTER alice@example.org"] {
        h.send(&op, line).await;
        assert_eq!(op.lines(), ["ERR not-supported"], "{line}");
    }
    // The route itself is the one the command table names.
    let unregister: Request = "ADMIN UNREGISTER a@example.org".parse().unwrap();
    assert!(matches!(
        unregister.command,
        Command::Admin(AdminCommand::Unregister { .. })
    ));
}

//! Seeding a scenario on a real server, and the held-back kick.

use std::collections::HashMap;
use std::time::Duration;

use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_server::testing::{TestClient, TestIdentity, TestServer};

use crate::plan::{self, ME, Scenario};
use crate::{kick, seed};

const SEED: u64 = 1;

/// A server like risala-dev's, in a temporary directory, with its clock
/// stopped where `plan` starts, `end` being when it ends.
async fn server_for(plan: &plan::Plan, end: Timestamp) -> TestServer {
    let first = plan.items.first().map_or(0, |i| i.ago);
    TestServer::builder()
        .identity_domain(seed::IDENTITY_DOMAIN)
        .limits(crate::limits())
        .manual_clock_at(end.checked_sub(Duration::from_millis(first)).unwrap())
        .start()
        .await
}

fn me(plan: &plan::Plan) -> TestIdentity {
    match seed::actors(plan, SEED).swap_remove(ME).who {
        crate::actors::Who::Identity(i) => i,
        crate::actors::Who::Guest { .. } => unreachable!("the account is an identity"),
    }
}

/// Sends `line` with `@ref=t` and returns the lines up to its OK.
async fn command(conn: &mut TestClient, line: &str) -> Vec<String> {
    conn.send(&format!("@ref=t {line}")).await.unwrap();
    let mut lines = Vec::new();
    loop {
        let line = conn.expect_line().await.unwrap();
        if line.starts_with("@ref=t OK") {
            return lines;
        }
        assert!(!line.starts_with("@ref=t ERR"), "{line}");
        if let Some(rest) = line.strip_prefix("@ref=t ") {
            lines.push(rest.to_owned());
        }
    }
}

/// `busy` seeds with nothing refused, at past times, and leaves the
/// account in its rooms with the planned read markers.
#[tokio::test]
async fn busy_seeds_through_the_protocol() {
    let plan = plan::build(Scenario::Busy, SEED);
    let end = Timestamp::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap();
    let server = server_for(&plan, end).await;
    let outcome = seed::seed(&server, &plan, SEED, end).await;
    assert_eq!(outcome.refused, 0);
    assert!(server.now() <= end, "steps after the end");
    server.follow_system_clock();

    let mut conn = server.sign_in(&me(&plan)).await;
    // CONV <conv> <id> <head> <read>
    let convs: HashMap<String, (u64, u64)> = command(&mut conn, "SYNC")
        .await
        .iter()
        .map(|l| {
            let p: Vec<&str> = l.split(' ').collect();
            assert_eq!(p[0], "CONV", "{l}");
            (
                p[1].to_owned(),
                (p[3].parse().unwrap(), p[4].parse().unwrap()),
            )
        })
        .collect();
    // Every room, the one the account is to be kicked from included.
    assert_eq!(convs.len(), plan.rooms.len());
    for r in &plan.rooms {
        let (head, read) = convs[&r.name];
        assert!(read <= head, "{}", r.name);
        if r.unread == 0 {
            assert_eq!(read, head, "{} has nothing unread", r.name);
        } else {
            assert!(read < head, "{} has unread messages", r.name);
        }
    }
    // History is weeks old: the newest event of #old-project.
    conn.send("@ref=h HISTORY #old-project limit=1")
        .await
        .unwrap();
    let t = loop {
        let line = conn.expect_line().await.unwrap();
        if let Ok(ServerMessage {
            line: ServerLine::Event(event),
            ..
        }) = line.parse::<ServerMessage>()
            && let Some(meta) = event.meta
        {
            break meta.t;
        }
        assert!(!line.starts_with("@ref=h "), "no event: {line}");
    };
    assert!(
        Timestamp::now().saturating_duration_since(t) > Duration::from_secs(40 * 24 * 3600),
        "{t}"
    );
    server.stop().await;
}

/// The account is kicked from its room once it comes online, and only
/// then.
#[tokio::test]
async fn the_kick_waits_for_the_account() {
    let plan = plan::build(Scenario::Busy, SEED);
    let end = Timestamp::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap();
    let mut server = server_for(&plan, end).await;
    seed::seed(&server, &plan, SEED, end).await;
    server.follow_system_clock();
    server.restart().await;

    let (tasks, rooms) = kick::arm(&server, &plan, SEED).await;
    let room = plan.rooms.iter().find(|r| r.kicked).unwrap();
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].as_str(), room.name);

    let mut conn = server.sign_in(&me(&plan)).await;
    let kick = loop {
        let line = tokio::time::timeout(Duration::from_secs(20), conn.expect_line())
            .await
            .expect("kicked in time")
            .unwrap();
        if line.contains(" KICK ") {
            break line;
        }
    };
    assert!(
        kick.contains(&format!("KICK {} me@risala.test", room.name)),
        "{kick}"
    );
    for task in tasks {
        let _ = task.await;
    }
    // Armed again, there is nothing left to do.
    let (tasks, rooms) = kick::arm(&server, &plan, SEED).await;
    assert!(tasks.is_empty() && rooms.is_empty());
    server.stop().await;
}

#[cfg(unix)]
#[test]
fn the_key_file_is_the_owners_alone_even_when_it_was_there_before() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("me.pem");
    std::fs::write(&path, "old").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    crate::write_key(dir.path(), &seed::key_for(SEED, ME)).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("PRIVATE KEY")
    );
}

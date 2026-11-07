//! Connections cut at random points while catching up and while sending.
//! After recovery, the cache holds exactly the server's events, the sync
//! points are truthful, and no message was sent twice (7.1, 7.6).
//!
//! The cuts come from a proxy between the client and the server, after a
//! random number of bytes from the server, so they land anywhere: in the
//! TLS handshake, in the middle of a HISTORY page, between a MSG and its
//! OK. The seeds make each run's choices the same, but the invariants are
//! checked for whatever interleaving happens.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::*;
use librisala::client::{Account, Conversation, OutboxStatus};
use librisala::proto::server::{EventBody, ServerLine, ServerMessage};
use risala_server::testing::{Proxy, TestServer};

/// Lets connections run, then waits until the cache matches the server.
async fn settle(server: &TestServer, proxy: &Proxy, account: &Account, conv: &Conversation) {
    proxy.cut_after(None);
    proxy.cut();
    let room = conv.name();
    within("the cache matching the server", async {
        loop {
            if account.state().is_online()
                && tokio::time::timeout(Duration::from_millis(200), account.wait_synced())
                    .await
                    .is_ok_and(|r| r.is_ok())
            {
                let ours = conv.export().unwrap();
                let theirs = server_history(server, &room).await;
                if ours == theirs {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    check_sync_point(server, conv).await;
}

/// The sync point is truthful: the cache holds every event up to it.
async fn check_sync_point(server: &TestServer, conv: &Conversation) {
    let info = conv.info().unwrap().unwrap();
    let theirs = server_history(server, &conv.name()).await;
    let last = seq_of(theirs.last().unwrap());
    assert!(info.caught_up, "{info:?}");
    assert_eq!(info.sync_point, last, "{info:?}");
    assert_eq!(info.newest, last, "{info:?}");
    let ours: Vec<u64> = conv.export().unwrap().iter().map(|l| seq_of(l)).collect();
    assert_eq!(
        ours,
        (1..=last).collect::<Vec<_>>(),
        "no gaps, no duplicates"
    );
}

fn seq_of(line: &str) -> u64 {
    let msg: ServerMessage = line.parse().unwrap();
    match msg.line {
        ServerLine::Event(e) => e.meta.unwrap().seq.get(),
        other => panic!("{other:?}"),
    }
}

/// The text of each MSG the server keeps, with how many times it appears
/// and its seqs.
fn msgs(history: &[String]) -> HashMap<String, Vec<u64>> {
    let mut out: HashMap<String, Vec<u64>> = HashMap::new();
    for line in history {
        let msg: ServerMessage = line.parse().unwrap();
        if let ServerLine::Event(e) = msg.line
            && let EventBody::Msg(m) = e.body
        {
            out.entry(m.text)
                .or_default()
                .push(e.meta.unwrap().seq.get());
        }
    }
    out
}

/// Cuts the current connection, and makes the next one end after a random
/// number of bytes from the server, from inside the TLS handshake to a few
/// pages past it. Returns the connection count before the cut.
fn cut(proxy: &Proxy, rng: &mut Rng, lo: u64, hi: u64) -> u64 {
    let n = proxy.connections();
    proxy.cut_after(Some(rng.range(lo, hi)));
    proxy.cut();
    n
}

/// Waits until the connection after connection `n` has ended too, and
/// returns true; or returns false once the client has caught up to `head`
/// on it, so its budget will not run out soon.
async fn wait_cut_again(proxy: &Proxy, n: u64, account: &Account, head: u64) -> bool {
    let conv = account.conversation("#a").unwrap();
    within("the connection ending or catching up", async {
        loop {
            if proxy.connections() >= n + 2 {
                return true;
            }
            if proxy.connections() == n + 1
                && account.is_synced()
                && conv.info().unwrap().unwrap().sync_point >= head
            {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
}

async fn catch_up_with_cuts(seed: u64) {
    let mut rng = Rng::new(seed);
    let server = TestServer::builder().room("#a").start().await;
    let mut ann = guest_in(&server, "ann", "#a").await;
    let proxy = Proxy::start(server.addr()).await;
    let (client, addr) = trusting_client(&server, proxy.addr(), 3);
    let sam = client.add_guest(&addr, "sam").unwrap();
    within("connect", sam.connect()).await.unwrap();
    within("join", sam.join("#a")).await.unwrap();
    within("sync", sam.wait_synced()).await.unwrap();
    let a = sam.conversation("#a").unwrap();

    // Each round: cut, post a burst while the client reconnects, and let
    // the next connection end after a random number of bytes, most often
    // partway through catching up, 3 events a page.
    let mut halfway = 0;
    let mut head = 0;
    for round in 0..15 {
        let n = cut(&proxy, &mut rng, 500, 6_000);
        for i in 0..rng.range(5, 30) {
            head = post(&mut ann, "#a", &format!("seed{seed} round {round} {i}")).await;
        }
        if wait_cut_again(&proxy, n, &sam, head).await
            && a.info().unwrap().unwrap().sync_point < head
        {
            halfway += 1;
        }
    }
    settle(&server, &proxy, &sam, &a).await;
    assert!(
        halfway > 0,
        "no connection ended halfway through catching up"
    );
    let texts = msgs(&a.export().unwrap());
    assert!(texts.values().all(|seqs| seqs.len() == 1));
    client.shutdown().await;
    server.stop().await;
}

async fn sends_with_cuts(seed: u64) {
    let mut rng = Rng::new(seed);
    let server = TestServer::builder().room("#a").start().await;
    let mut ann = guest_in(&server, "ann", "#a").await;
    post(&mut ann, "#a", "hello").await;
    let proxy = Proxy::start(server.addr()).await;
    let (client, addr) = trusting_client(&server, proxy.addr(), 4);
    let sam = client.add_guest(&addr, "sam").unwrap();
    within("connect", sam.connect()).await.unwrap();
    within("join", sam.join("#a")).await.unwrap();
    let a = sam.conversation("#a").unwrap();

    // Each round: cut, then send a burst, some while offline and some on
    // a connection that ends after a random number of bytes, often between
    // a MSG and its OK.
    let mut sent = Vec::new();
    for round in 0..12 {
        cut(&proxy, &mut rng, 1_000, 5_000);
        for i in 0..rng.range(2, 8) {
            let entry = a
                .send(&format!("seed{seed} round {round} {i}"))
                .await
                .unwrap();
            sent.push(entry.id);
            if rng.next().is_multiple_of(4) {
                post(&mut ann, "#a", &format!("seed{seed} ann {round} {i}")).await;
            }
            tokio::time::sleep(Duration::from_millis(rng.range(0, 25))).await;
        }
    }
    settle(&server, &proxy, &sam, &a).await;

    // Every message ends sent, or as possibly sent after a cut (a guest
    // cannot resend, 7.6). Each is on the server at most once, and a sent
    // one exactly once, with the seq its OK named.
    let history = msgs(&server_history(&server, "#a").await);
    let mut confirmed = 0;
    for id in sent {
        let entry = within("outbox", sam.wait_outbox(id)).await.unwrap();
        let on_server = history.get(&entry.text).cloned().unwrap_or_default();
        match entry.status {
            OutboxStatus::Sent { seq } => {
                confirmed += 1;
                assert_eq!(on_server, [seq], "{entry:?}");
            }
            OutboxStatus::Failed {
                maybe_sent: true, ..
            } => assert!(on_server.len() <= 1, "{entry:?} {on_server:?}"),
            other => panic!("{} ended {other:?}", entry.text),
        }
    }
    assert!(confirmed > 0);
    assert!(history.values().all(|seqs| seqs.len() == 1), "{history:?}");
    client.shutdown().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catching_up_survives_cuts_at_random_points() {
    for seed in 1..=4 {
        catch_up_with_cuts(seed).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sending_survives_cuts_at_random_points() {
    for seed in 1..=4 {
        sends_with_cuts(seed).await;
    }
}

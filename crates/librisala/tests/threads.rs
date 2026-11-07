//! The client from threads with no tokio runtime, as an app's main thread
//! is (Swift, GTK): the client runs on a runtime of its own, and its async
//! methods may be awaited on any executor.

mod common;

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::Thread;
use std::time::Instant;

use common::*;
use librisala::client::{Client, OutboxStatus};
use risala_server::testing::TestServer;

/// Wakes a thread parked in [`block_on`].
struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Runs a future to completion on this thread, with no tokio runtime: the
/// smallest executor there is. Fails the test after [`LONG`].
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    let deadline = Instant::now() + LONG;
    loop {
        if let Poll::Ready(t) = f.as_mut().poll(&mut cx) {
            return t;
        }
        let left = deadline
            .checked_duration_since(Instant::now())
            .expect("timed out");
        std::thread::park_timeout(left);
    }
}

#[test]
fn a_client_works_without_a_runtime() {
    // The server runs on a runtime of its own thread, out of the way.
    let server_rt = tokio::runtime::Runtime::new().unwrap();
    let server = server_rt.block_on(TestServer::builder().room("#general").start());
    assert!(tokio::runtime::Handle::try_current().is_err());

    let client = Client::open_in_memory(options(50)).unwrap();
    let addr = addr_of(server.addr());
    client
        .accept_fingerprint(&addr, &server.fingerprint().to_string())
        .unwrap();
    let sam = client.add_guest(&addr, "sam").unwrap();
    // Neither of these needs a runtime on this thread.
    sam.start();
    assert_eq!(block_on(sam.connect()).unwrap(), "~sam");
    let general = block_on(sam.join("#general")).unwrap();
    let timeline = general.timeline(50).unwrap();
    let entry = block_on(general.send("hello")).unwrap();
    let entry = block_on(sam.wait_outbox(entry.id)).unwrap();
    assert!(matches!(entry.status, OutboxStatus::Sent { .. }));
    block_on(async {
        loop {
            timeline.next().await.unwrap();
            if timeline
                .items()
                .iter()
                .any(|m| m.text.as_deref() == Some("hello"))
            {
                return;
            }
        }
    });
    block_on(sam.wait_synced()).unwrap();

    // From another plain thread too.
    let other = {
        let sam = sam.clone();
        std::thread::spawn(move || block_on(sam.part("#general", "bye")))
    };
    other.join().unwrap().unwrap();
    block_on(sam.disconnect());
    drop((timeline, general, sam, client));
    server_rt.block_on(server.stop());
}

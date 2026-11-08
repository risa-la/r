//! The identity area (4.6-4.9, 10.5).

use super::*;

/// Nothing is built yet: the area's commands reply `not-supported` on the
/// kinds that may send them, and no key file is hosted.
#[tokio::test]
async fn not_built_yet() {
    let mut h = Harness::new();
    let signature = format!("{}AAA=", "A".repeat(3224));
    let mut new = h.connect();
    h.send(&new, &format!("AUTH alice@example.org {signature}"))
        .await;
    h.send(&new, &format!("REGISTER alice AAAA {signature}"))
        .await;
    assert_eq!(new.lines(), ["ERR not-supported", "ERR not-supported"]);
    let mut anon = h.anon().await;
    h.send(&anon, "KEYS PUT - AAAA").await;
    h.send(&anon, "PAIR GET ujzdegxdncf32epf3dhodzdoci").await;
    assert_eq!(anon.lines(), ["ERR not-supported", "ERR not-supported"]);
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, "UNREGISTER alice@example.org").await;
    assert_eq!(alice.lines(), ["ERR not-supported"]);
    let name = "alice".parse().unwrap();
    assert_eq!(h.hub.hosted_key_file(&name).unwrap(), None);
}

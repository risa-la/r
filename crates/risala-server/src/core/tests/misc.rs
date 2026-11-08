//! Server information, presence, push and reports (5.8, 6.1, 8, 9).

use super::*;

/// Nothing is built yet: the area's commands reply `not-supported` on the
/// kinds that may send them.
#[tokio::test]
async fn not_built_yet() {
    let mut h = Harness::new();
    let mut new = h.connect();
    h.send(&new, "INFO").await;
    assert_eq!(new.lines(), ["ERR not-supported"]);
    let mut alice = h.signed_in_as("alice@example.org");
    for line in ["LIST", "PRESENCE ON", "WHOIS bob@example.org", "PUSH LIST"] {
        h.send(&alice, line).await;
        assert_eq!(alice.lines(), ["ERR not-supported"], "{line}");
    }
}

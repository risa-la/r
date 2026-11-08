//! KeyPackages, Welcomes, blobs, backups and uploads (5.6, 12.5, 12.8,
//! 12.12, 12.13).

use super::*;

/// Nothing is built yet: the area's commands reply `not-supported` on the
/// kinds that may send them.
#[tokio::test]
async fn not_built_yet() {
    let mut h = Harness::new();
    let mut alice = h.signed_in_as("alice@example.org");
    for line in ["KEYPKG COUNT", "WELCOME LIST", "BACKUP GET"] {
        h.send(&alice, line).await;
        assert_eq!(alice.lines(), ["ERR not-supported"], "{line}");
    }
    let mut anon = h.anon().await;
    let token = format!("{}AAA=", "A".repeat(40));
    h.send(
        &anon,
        &format!("UPLOAD ujzdegxdncf32epf3dhodzdoci {token} 10"),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR not-supported"]);
}

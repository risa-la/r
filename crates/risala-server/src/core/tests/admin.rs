//! Server administration (Section 10).

use risala_proto::names::Uid;

use crate::core::admin;
use crate::store::AdminStore as _;

use super::*;

/// Operators are those in the configuration and those the store has
/// (10.1); only they get past the gate on ADMIN commands.
#[tokio::test]
async fn operators_come_from_the_configuration_and_the_store() {
    let store = SqliteStore::open_in_memory().unwrap();
    let bob: Uid = "bob@example.org".parse().unwrap();
    store.add_operator(&bob, T.parse().unwrap()).unwrap();
    let mut h = Harness::on(config(), timers(), store);
    let op: Uid = "op@example.org".parse().unwrap();
    assert!(admin::is_operator(h.inner(), &op));
    assert!(admin::is_configured_operator(h.inner(), &op));
    assert!(admin::is_operator(h.inner(), &bob));
    assert!(!admin::is_configured_operator(h.inner(), &bob));
    assert!(!admin::is_operator(
        h.inner(),
        &"alice@example.org".parse().unwrap()
    ));

    let mut bob_conn = h.signed_in_as("bob@example.org");
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&bob_conn, "ADMIN WHO").await;
    h.send(&alice, "ADMIN WHO").await;
    assert_eq!(bob_conn.lines(), ["ERR not-supported"]);
    assert_eq!(alice.lines(), ["ERR forbidden"]);
}

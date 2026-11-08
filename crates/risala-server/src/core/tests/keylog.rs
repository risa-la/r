//! The key log (4.5), which has no commands of its own.

use crate::store::KeyLogStore as _;

use super::*;

/// The hub starts with an empty log.
#[tokio::test]
async fn the_log_starts_empty() {
    let h = Harness::new();
    assert_eq!(h.store.log_size().unwrap(), 0);
}

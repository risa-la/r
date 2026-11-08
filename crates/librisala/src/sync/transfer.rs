//! Blobs (12.12), files (5.6, 12.11), history transfers and backups
//! (12.13), and reports (5.8).
//!
//! Owned by task C4 in docs/plans/M5b.md. Empty for now: it does
//! nothing with its inputs.

use super::Engine;

/// The engine of this area, for one account.
#[derive(Debug, Default)]
pub struct TransferEngine {}

impl Engine for TransferEngine {}

//! Confirming leaves (12.10): pairwise CHALLENGE and ANSWER, and epochal
//! ATTEST and REVEAL with period keys.
//!
//! Owned by task C3 in docs/plans/M5b.md. Empty for now: it does
//! nothing with its inputs.

use super::Engine;

/// The engine of this area, for one account.
#[derive(Debug, Default)]
pub struct ConfirmEngine {}

impl Engine for ConfirmEngine {}

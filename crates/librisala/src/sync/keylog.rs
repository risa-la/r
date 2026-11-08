//! Key logs (4.5): fetching checkpoints and tiles, inclusion and
//! consistency proofs with `risala-keylog`, the witness policy, pending
//! records, forks, and watching the device's own identities' records
//! daily.
//!
//! Owned by task C1 in docs/plans/M5b.md. Empty for now: it does
//! nothing with its inputs.

use super::Engine;

/// The engine of this area, for one account.
#[derive(Debug, Default)]
pub struct KeyLogEngine {}

impl Engine for KeyLogEngine {}

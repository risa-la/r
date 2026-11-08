//! Key files and the device's own identities (4.4-4.8, 12.14): fetching
//! key files (at least daily for every identity it shares a conversation
//! with), checking chains, RECORD lines from KEYS PUT, and the pairing
//! relay (PAIR PUT and GET).
//!
//! Owned by task C1 in docs/plans/M5b.md. Empty for now: it does
//! nothing with its inputs.

use super::Engine;

/// The engine of this area, for one account.
#[derive(Debug, Default)]
pub struct IdentityEngine {}

impl Engine for IdentityEngine {}

//! Push subscriptions (Section 9): PUSH ADD and DEL for mailboxes on
//! anonymous connections and for the account on the signed-in one, and
//! FOLLOW's `quiet`.
//!
//! Owned by task C4 in docs/plans/M5b.md. Empty for now: it does
//! nothing with its inputs.

use super::Engine;

/// The engine of this area, for one account.
#[derive(Debug, Default)]
pub struct PushEngine {}

impl Engine for PushEngine {}

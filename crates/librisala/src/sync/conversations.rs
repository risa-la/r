//! The group engine (5-8, 12.4-12.9): FOLLOW and FETCH on anonymous
//! connections and the sync points of 7.4, posting with send tokens and
//! pseudonyms, the first valid commit of each epoch (7.2), Welcomes and
//! KeyPackages, membership, roles, profiles, typing, read markers,
//! blocks, deletes, gaps, presence and guests in public rooms.
//!
//! Owned by task C2 in docs/plans/M5b.md. Empty for now: it does
//! nothing with its inputs.

use super::Engine;

/// The engine of this area, for one account.
#[derive(Debug, Default)]
pub struct ConversationEngine {}

impl Engine for ConversationEngine {}

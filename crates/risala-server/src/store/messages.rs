//! Storage for M4's message work: edits, reactions, DELETE (5.3, 5.4),
//! RELATED (7.3), retention (7.5), ADMIN PURGE (10.4) and UNREGISTER
//! `purge=yes` (4.8).

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait MessageStore {}

//! The sync engine: a state machine with no I/O that turns server lines
//! into stored events and tells the caller which commands to send.
//!
//! Owned by task D in docs/plans/M2-M5.md.

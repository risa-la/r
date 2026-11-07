//! TLS listeners, connection tasks, line framing and keepalive.
//!
//! Drives a [`crate::handler::Handler`]. Owned by task B in
//! docs/plans/M2-M5.md.

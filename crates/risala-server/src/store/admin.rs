//! Storage for the ADMIN commands (Section 10), except ADMIN PURGE, which
//! is in [`super::MessageStore`], and ADMIN REPORTS, ROOMS and DROP, which
//! are in [`super::ReportStore`].

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait AdminStore {}

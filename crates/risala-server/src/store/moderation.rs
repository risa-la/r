//! Storage for room settings, roles and moderation: SET (6.2), ROLE and
//! ROLES (6.3), INVITE, KICK, BAN, UNBAN and BANS (6.4).

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait ModerationStore {}

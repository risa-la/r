//! Storage for room settings, roles and moderation: SET (6.2), ROLE and
//! ROLES (6.3), INVITE, KICK, BAN, UNBAN and BANS (6.4).
//!
//! What these events change (settings, roles, invitations, bans and
//! membership) is applied by [`super::Store::append`], in the event's own
//! transaction. This trait holds what only moderation reads.

use risala_proto::names::Uid;

use super::{ConvKey, Result};

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait ModerationStore {
    /// The bans of a room (6.4), in uid order, each with its reason,
    /// escaped (3.4); empty if none. For BANS.
    fn room_bans(&self, conv: ConvKey) -> Result<Vec<(Uid, String)>>;
}

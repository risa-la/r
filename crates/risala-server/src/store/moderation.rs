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

    /// Replaces the reason of an existing room ban, escaped (3.4), without
    /// recording an event: BAN of someone already banned (PLAN.md 5, item
    /// 31). Does nothing if `uid` is not banned.
    fn set_room_ban_reason(&self, conv: ConvKey, uid: &Uid, reason: &str) -> Result<()>;

    /// Removes the role and the invitation of `uid` in one room, if it has
    /// them, without recording an event: for UNREGISTER (4.8), which
    /// removes them from the room in memory at the same time, under the
    /// room's lock.
    fn forget_room_roles(&self, conv: ConvKey, uid: &Uid) -> Result<()>;
}

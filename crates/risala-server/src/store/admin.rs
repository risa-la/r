//! Server administration (Section 10): the server settings of ADMIN SET,
//! operators added with ADMIN OP, and server bans.
//!
//! Tables (`sqlite/admin.rs`):
//!
//! - `settings`: the settings of ADMIN SET (10.6), each as its key and its
//!   value as on the wire. A setting with no row has its value from the
//!   configuration.
//! - `operators`: operators added with ADMIN OP (10.1). Those in the
//!   configuration are not stored.
//! - `server_bans`: identity, domain and address bans (10.2).

use risala_proto::names::Uid;
use risala_proto::time::Timestamp;
use risala_proto::types::{Retention, ServerSetting};

use super::Result;

/// The settings of ADMIN SET (10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSettings {
    /// Whether anonymous connections may be opened (4.2).
    pub anon: bool,
    /// Whether guests may connect (4.2).
    pub guests: bool,
    /// Whether REGISTER is accepted (4.7), on a server with an identity
    /// domain.
    pub registration: bool,
    /// The retention period (7.5).
    pub retention: Retention,
    /// The greeting's welcome text (4.1), escaped, at most 512 bytes.
    pub welcome: String,
}

impl ServerSettings {
    /// Applies `setting`. Returns `false`, and changes nothing, for a
    /// setting this server does not know.
    pub fn apply(&mut self, setting: &ServerSetting) -> bool {
        match setting {
            ServerSetting::Anon(on) => self.anon = *on,
            ServerSetting::Guests(on) => self.guests = *on,
            ServerSetting::Registration(open) => self.registration = *open,
            ServerSetting::Retention(retention) => self.retention = *retention,
            ServerSetting::Welcome(text) => self.welcome.clone_from(text),
            ServerSetting::Other { .. } => return false,
        }
        true
    }
}

/// Settings, operators and bans (Section 10).
pub trait AdminStore {
    /// The server settings: those set with ADMIN SET, and `defaults` for
    /// the rest (10.6).
    fn settings(&self, defaults: &ServerSettings) -> Result<ServerSettings>;

    /// Stores a setting, which then outlasts restarts (10.6). A setting
    /// this server does not know is not stored, and gives `false`.
    fn save_setting(&self, setting: &ServerSetting) -> Result<bool>;

    /// The operators added with ADMIN OP (10.1), in order.
    fn operators(&self) -> Result<Vec<Uid>>;

    /// Adds an operator at `now` (10.1). Returns `false` if it was one.
    fn add_operator(&self, uid: &Uid, now: Timestamp) -> Result<bool>;

    /// Removes an operator added with ADMIN OP (10.1). Returns `false` if
    /// it was not one.
    fn remove_operator(&self, uid: &Uid) -> Result<bool>;
}

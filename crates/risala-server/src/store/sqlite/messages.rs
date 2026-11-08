//! [`MessageStore`] on SQLite.

use super::SqliteStore;
use crate::store::MessageStore;

impl MessageStore for SqliteStore {}

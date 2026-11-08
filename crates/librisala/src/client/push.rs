//! Push notifications (Section 9, Appendix C).
//!
//! Owned by task C4.
//!
//! The app registers with its push gateway, or a UnifiedPush distributor,
//! and hands the client URLs from it ([`Client::add_push_urls`]), one for
//! each subscription: the account's, for Welcomes, and one per
//! conversation's mailbox (9.1). The account's push engine
//! ([`crate::sync::push`]) registers and renews them, and asks for more
//! URLs with [`TransferEvent::PushUrlsNeeded`](super::files::TransferEvent).
//! When a push arrives, the app hands its body to
//! [`Client::handle_push`], which decrypts it (RFC 8291) and says what it
//! is about; the app then connects and syncs, and shows its own
//! notification if one is due (9.3).

use aws_lc_rs::{aead, agreement, hmac};
use risala_proto::server::Notify;
use risala_proto::types::{NotifyReason, PushReason};

use super::files::TransferError;
use super::types::{AccountId, ConversationId};
use super::{Client, Event, Result};
use crate::store::push::SubscriptionRow;
use crate::sync::push::{quiet_setting, setting};

/// A push gateway the app registers with (9.1, Appendix C). Kept for the
/// app's own use: the client takes URLs, not a gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushGateway {
    /// The gateway's URL.
    pub url: String,
}

/// What a push is about (9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushNotice {
    /// New posts in a conversation: fetch them, then notify if due.
    Message {
        /// The account.
        account: AccountId,
        /// The conversation.
        conversation: ConversationId,
    },
    /// A Welcome for the account: sign in and send WELCOME LIST.
    Welcome {
        /// The account.
        account: AccountId,
    },
    /// A reason this version does not know: treat it as new activity, and
    /// connect and sync (9.3).
    Activity {
        /// The account.
        account: AccountId,
    },
}

/// HMAC-SHA-256 of the concatenation of `parts` under `key`.
fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, key));
    for part in parts {
        ctx.update(part);
    }
    ctx.sign()
        .as_ref()
        .try_into()
        .expect("HMAC-SHA-256 is 32 bytes")
}

/// Decrypts a one-record `aes128gcm` push body (RFC 8188, RFC 8291) with
/// a subscription's private key and authentication secret, and strips its
/// padding.
pub(crate) fn decrypt(body: &[u8], private_key: &[u8], auth: &[u8]) -> Option<Vec<u8>> {
    let private =
        agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, private_key).ok()?;
    let salt = body.get(..16)?;
    let id_len = usize::from(*body.get(20)?);
    let key_id = body.get(21..21 + id_len)?;
    let mut record = body.get(21 + id_len..)?.to_vec();
    let ua_public = private.compute_public_key().ok()?;
    let ecdh = agreement::agree(
        &private,
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, key_id),
        (),
        |secret| Ok(secret.to_vec()),
    )
    .ok()?;
    // RFC 8291, 3.4.
    let prk_key = hmac256(auth, &[&ecdh]);
    let ikm = hmac256(
        &prk_key,
        &[b"WebPush: info\0", ua_public.as_ref(), key_id, &[1]],
    );
    let prk = hmac256(salt, &[&ikm]);
    let cek = hmac256(&prk, &[b"Content-Encoding: aes128gcm\0", &[1]]);
    let nonce = hmac256(&prk, &[b"Content-Encoding: nonce\0", &[1]]);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek[..16]).ok()?);
    let plain = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce[..12].try_into().ok()?),
            aead::Aad::empty(),
            &mut record,
        )
        .ok()?;
    // The padding: zeros after the last record's delimiter, 2 (RFC 8188).
    let end = plain.iter().rposition(|&b| b != 0)?;
    (plain[end] == 2).then(|| plain[..end].to_vec())
}

/// What a decrypted push body says, for the subscription it came to.
fn notice(row: &SubscriptionRow, plain: &[u8]) -> Option<PushNotice> {
    let text = std::str::from_utf8(plain).ok()?;
    let notify: Notify = text.parse().ok()?;
    // The tag is compared byte for byte with the subscription's (9.1).
    if notify.tag.to_string() != row.tag {
        return None;
    }
    let account = row.account;
    Some(match (&notify.reason, row.conv) {
        (NotifyReason::Known(PushReason::Message), Some(conversation)) => PushNotice::Message {
            account,
            conversation,
        },
        (NotifyReason::Known(PushReason::Welcome), None) => PushNotice::Welcome { account },
        _ => PushNotice::Activity { account },
    })
}

impl Client {
    /// Turns push on for the account (9.1): its push engine subscribes the
    /// account, for Welcomes, and each conversation's mailbox, with one of
    /// the URLs from [`add_push_urls`](Self::add_push_urls) each. Guests
    /// cannot register for push.
    pub async fn enable_push(&self, account: AccountId, urls: &[String]) -> Result<()> {
        self.add_push_urls(account, urls)?;
        self.store().set_setting(&setting(account), Some("on"))?;
        self.kick(account).await;
        Ok(())
    }

    /// Hands over push URLs from the app's push gateway (Appendix C), one
    /// for each subscription to make. A URL already used is skipped.
    pub fn add_push_urls(&self, account: AccountId, urls: &[String]) -> Result<usize> {
        for url in urls {
            url.parse::<risala_proto::types::PushUrl>()
                .map_err(|_| super::Error::invalid("push URL", url.as_str()))?;
        }
        let now = self.options().clock.now().unix_millis();
        let (added, changes) = self
            .store()
            .write(|tx| tx.add_push_urls(account, urls, now))?;
        for c in changes {
            self.emit(Event::Changed(c));
        }
        Ok(added)
    }

    /// Removes the account's push subscriptions (9.1): the push engine
    /// sends PUSH DEL for each, and the URLs not used are forgotten.
    pub async fn disable_push(&self, account: AccountId) -> Result<()> {
        self.store().set_setting(&setting(account), None)?;
        let (_, changes) = self.store().write(|tx| tx.clear_push_urls(account))?;
        for c in changes {
            self.emit(Event::Changed(c));
        }
        self.kick(account).await;
        Ok(())
    }

    /// Turns a conversation's pushes off or on (9.2): with them off, the
    /// app checks it from time to time instead.
    pub async fn set_conversation_push(
        &self,
        conversation: ConversationId,
        on: bool,
    ) -> Result<()> {
        let row = self.conv_row(conversation)?;
        let (_, changes) = self
            .store()
            .write(|tx| tx.set_push_off(conversation, !on))?;
        for c in changes {
            self.emit(Event::Changed(c));
        }
        self.kick(row.account).await;
        Ok(())
    }

    /// Makes FOLLOW carry the mailbox subscription's tag as `quiet` (7.1,
    /// 9.2), so that the server holds pushes back while this device reads.
    /// Off by default: a quiet tag stays the same from one session to the
    /// next and links them (7.4), so devices SHOULD leave it out and drop
    /// pushes that arrive while they read.
    pub fn set_quiet_follows(&self, account: AccountId, on: bool) -> Result<()> {
        self.store()
            .set_setting(&quiet_setting(account), on.then_some("on"))?;
        Ok(())
    }

    /// Decrypts a push body (9.3, RFC 8291) and says what it is about,
    /// without the network, so that an iOS notification extension can
    /// call it (PLAN.md 3.4). `url` is the subscription's URL, if the app
    /// knows which one the push came to; otherwise every subscription is
    /// tried.
    pub fn handle_push(&self, body: &[u8], url: Option<&str>) -> Result<PushNotice> {
        let rows = self.store().subscription_rows()?;
        for row in rows.iter().filter(|r| url.is_none_or(|u| u == r.url)) {
            if let Some(plain) = decrypt(body, &row.private_key, &row.auth)
                && let Some(notice) = notice(row, &plain)
            {
                return Ok(notice);
            }
        }
        Err(TransferError::BadPush.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use risala_proto::binary::{PushAuth, PushKey};

    /// A body made by `risalad` (9.3) decrypts here, for every length of
    /// tag, and the wrong secret does not open it.
    #[test]
    fn the_servers_pushes_decrypt() {
        let keys = crate::sync::push::new_keys().unwrap();
        let key = PushKey::from_bytes(keys.public);
        let auth = PushAuth::from_bytes(keys.auth);
        for tag in ["a", keys.tag.as_str(), &"x".repeat(64)] {
            for reason in [PushReason::Message, PushReason::Welcome] {
                let notify = Notify {
                    tag: tag.parse().unwrap(),
                    reason: NotifyReason::Known(reason),
                };
                let body = risala_server::push::encrypt(&notify, &key, &auth).unwrap();
                let plain = decrypt(&body, &keys.private, &keys.auth).unwrap();
                assert_eq!(plain, notify.to_body().into_bytes());
                assert!(decrypt(&body, &keys.private, &[0; 16]).is_none());
            }
        }
    }
}

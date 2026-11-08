//! Files, blobs and backups against a whole `risalad` (tasks SV4 and
//! SV5): INFO, BLOB and BACKUP on a signed-in connection, UPLOAD on an
//! anonymous one, and the bodies over the server's HTTPS listener through
//! [`TlsFileHttps`]. Conversations are the group engine's tests'; here the
//! server's mailbox is made directly, as `risalad`'s own tests do.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use risala_mls::backup::RecoveryKey;
use risala_proto::command::{Command, Request};
use risala_proto::mls::GroupId;
use risala_proto::names::BoxName;
use risala_proto::server::{ServerLine, ServerMessage};
use risala_server::store::{MailboxStore as _, NewMailbox};
use risala_server::testing::{TestClient, TestServer};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::sync::{Mutex, broadcast};

use super::*;
use crate::clock::ManualClock;
use crate::conn::End;
use crate::keys::{KeyNames, KeyStore as _, MemoryKeyStore};
use crate::store::AccountKind;
use crate::store::identity::OwnRow;

const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";
const TOKEN: [u8; 32] = [5; 32];

/// Accepts any certificate, for the test server's self-signed one.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// [`Commands`] over the test server's raw connections: one signed in,
/// one anonymous.
struct ServerCommands {
    signed: Mutex<TestClient>,
    anon: Mutex<TestClient>,
    next: AtomicU64,
}

impl Commands for ServerCommands {
    fn request<'a>(&'a self, target: Target, command: Command) -> BoxFuture<'a, Result<Response>> {
        Box::pin(async move {
            let n = self.next.fetch_add(1, Ordering::Relaxed);
            let ref_ = format!("c{n}").parse().unwrap();
            let request = Request {
                ref_: Some(ref_),
                command,
            };
            let mut client = match target {
                Target::SignedIn => self.signed.lock().await,
                _ => self.anon.lock().await,
            };
            client.send(&request.to_string()).await.unwrap();
            let mut lines = Vec::new();
            loop {
                let line = client.expect_line().await.unwrap();
                let message: ServerMessage = line.parse().unwrap();
                if message.ref_.as_ref().map(ToString::to_string) != Some(format!("c{n}")) {
                    continue;
                }
                match message.line {
                    ServerLine::Ok(ok) => {
                        return Ok(Response {
                            lines,
                            end: End::Ok(ok),
                        });
                    }
                    ServerLine::Err(err) => {
                        return Ok(Response {
                            lines,
                            end: End::Err(err),
                        });
                    }
                    _ => lines.push(message),
                }
            }
        })
    }
}

#[tokio::test]
async fn files_blobs_and_backups_against_risalad() {
    let server = TestServer::builder()
        .identity_domain("example.org")
        .configure(|c| c.http.listen = vec!["127.0.0.1:0".parse().unwrap()])
        .prepare(|store| {
            store
                .create_mailbox(&NewMailbox {
                    mailbox: BOX.parse().unwrap(),
                    group_id: GroupId::from_bytes([1; 32]),
                    first_epoch: 0,
                    token_hash: risala_proto::mls::SendToken::from_bytes(TOKEN).hash(),
                    created: risala_proto::time::Timestamp::now(),
                    moved_from: None,
                })
                .unwrap();
        })
        .start()
        .await;
    let (signed, _chain, _device) = server.register("alice").await;
    let anon = server.anon().await;

    let store = Store::open_in_memory().unwrap();
    let addr: crate::addr::ServerAddr = "chat.test".parse().unwrap();
    let uid: risala_proto::names::Uid = "alice@example.org".parse().unwrap();
    let account = store
        .add_account(&addr, AccountKind::Identity, &uid)
        .unwrap();
    store
        .write(|tx| {
            tx.add_own(&OwnRow {
                uid: uid.to_string(),
                device_id: [3; 48],
                key_id: uid.to_string(),
                home: "chat.test".into(),
                backup_generation: 0,
                created: 0,
                told_full: false,
            })
        })
        .unwrap();
    let keys = Arc::new(MemoryKeyStore::default());
    let recovery = RecoveryKey::generate().unwrap();
    let backup_key = recovery.backup_key(&"alice@example.org".parse().unwrap(), 0);
    keys.save_seed(&KeyNames::new(uid.as_str()).backup(), backup_key.as_bytes())
        .unwrap();
    let provider = risala_keyfetch::provider();
    let jobs = Jobs {
        store: store.clone(),
        account,
        server: addr.to_string(),
        uid: uid.clone(),
        commands: Arc::new(ServerCommands {
            signed: Mutex::new(signed),
            anon: Mutex::new(anon),
            next: AtomicU64::new(1),
        }),
        https: Arc::new(TlsFileHttps::new(Arc::new(AcceptAny(provider)))),
        clock: Arc::new(ManualClock::new(
            risala_proto::time::Timestamp::now().unix_millis(),
        )),
        keys: keys.clone(),
        events: broadcast::channel(16).0,
        downloads: std::env::temp_dir(),
        max_blob: ARCHIVE_BLOB,
    };

    // INFO: the server's file origins and blobs prefix (8.5).
    let info = jobs.info(true).await.unwrap();
    assert!(info.upload.is_some(), "{info:?}");
    let blobs = info.blobs.clone().expect("a blobs prefix");
    assert!(blobs.starts_with("https://localhost:"), "{blobs}");

    // A blob of the account: BLOB on the signed-in connection, PUT, then
    // anyone fetches it from the prefix and checks its hash (12.12).
    let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
    let hash = jobs.put_blob(&bytes).await.unwrap();
    assert_eq!(jobs.get_blob(&hash).await.unwrap(), bytes);
    // The same blob again: exists=yes, nothing uploaded.
    assert_eq!(jobs.put_blob(&bytes).await.unwrap(), hash);

    // A file: UPLOAD on the anonymous connection with the group's token,
    // PUT, GET from an origin INFO lists, decrypt; DELETE removes it
    // (5.6, 12.11).
    let file = b"a file for the conversation".to_vec();
    let encrypted = risala_mls::file::encrypt(Label::File, &file).unwrap();
    let mailbox: BoxName = BOX.parse().unwrap();
    let (get, del) = jobs
        .upload(mailbox, TOKEN, &encrypted.upload)
        .await
        .unwrap();
    assert!(on_origins(&info.files, &get), "{get} on {:?}", info.files);
    let fetched = jobs.https.get(get.as_str(), 1 << 20).await.unwrap();
    let plain =
        risala_mls::file::decrypt(&encrypted.key, Label::File, &encrypted.hash, &fetched).unwrap();
    assert_eq!(&plain[..], &file[..]);
    jobs.https.delete(&del.unwrap()).await.unwrap();
    assert!(matches!(
        jobs.https.get(get.as_str(), 1 << 20).await,
        Err(HttpError::Gone(_))
    ));
    // A wrong token is refused.
    assert!(
        jobs.upload(mailbox, [6; 32], &encrypted.upload)
            .await
            .is_err()
    );

    // Push subscriptions as the push engine makes them (9.1): the
    // account's on the signed-in connection, a mailbox's with box and
    // token on the anonymous one; PUSH LIST shows the account's only.
    let sub = |mailbox: Option<&str>, n: u8| {
        let keys = crate::sync::push::new_keys().unwrap();
        crate::store::push::SubscriptionRow {
            id: 0,
            account,
            conv: None,
            mailbox: mailbox.map(str::to_owned),
            url: format!("https://push.example.net/w/{n}"),
            tag: keys.tag,
            p256dh: keys.public.to_vec(),
            auth: keys.auth.to_vec(),
            private_key: keys.private,
            state: crate::store::push::SubState::Adding,
            renew_at: None,
        }
    };
    let account_sub = sub(None, 1);
    let add = crate::sync::push::push_add(&account_sub, None).unwrap();
    jobs.command(Target::SignedIn, add).await.unwrap();
    let mailbox_sub = sub(Some(BOX), 2);
    let token = risala_mls::token::SendToken::from_bytes(TOKEN);
    let add = crate::sync::push::push_add(&mailbox_sub, Some((mailbox, token))).unwrap();
    jobs.command(Target::Mailbox(mailbox), add).await.unwrap();
    let wrong = sub(Some(BOX), 3);
    let add = crate::sync::push::push_add(
        &wrong,
        Some((mailbox, risala_mls::token::SendToken::from_bytes([6; 32]))),
    )
    .unwrap();
    assert!(jobs.command(Target::Mailbox(mailbox), add).await.is_err());
    let listed = jobs
        .command(
            Target::SignedIn,
            Command::Push(risala_proto::command::PushCommand::List),
        )
        .await
        .unwrap();
    assert_eq!(listed.lines.len(), 1);
    let del = crate::sync::push::push_del(&mailbox_sub).unwrap();
    jobs.command(Target::Mailbox(mailbox), del).await.unwrap();

    // A backup: archives as blobs, the wrapped key, BACKUP PUT; then
    // BACKUP GET and a restore with the recovery key (12.13).
    assert_eq!(jobs.backup_get().await.unwrap(), None);
    let row = jobs.backup_now().await.unwrap();
    let backup = jobs.backup_get().await.unwrap().expect("the backup");
    assert_eq!(backup.generation, 0);
    assert_eq!(backup.hash.as_bytes(), &row.blob_hash);
    let restored = jobs
        .restore_generation(&recovery.to_display(), 0)
        .await
        .unwrap();
    assert_eq!(restored.made.unix_millis(), row.made);
    // Another generation's key does not open it.
    let wrong = RecoveryKey::generate().unwrap();
    assert!(
        jobs.restore_generation(&wrong.to_display(), 0)
            .await
            .is_err()
    );
}

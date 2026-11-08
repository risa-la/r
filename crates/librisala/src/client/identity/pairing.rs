//! Pairing a new device by QR text (4.8), on both sides.
//!
//! The new device ([`Client::start_pairing`], [`Client::finish_pairing`])
//! makes its keys and a one-time secret, puts its encrypted, signed
//! NewDevice on the relay with `PAIR PUT`, and shows the QR text. The
//! device that scans it ([`Client::scan_pairing`],
//! [`Client::confirm_pairing`]) reads and checks the NewDevice, makes the
//! `device` record, publishes it, and puts the IdentityBundle, sealed to
//! the new device's pairing key, on the relay. Each relay command goes on
//! a connection of its own (4.1). The server sees random ids and
//! ciphertext only.

use std::time::Duration;

use risala_mls::{IdentityBundle, PairingKey, PairingSecret, Relay};
use risala_proto::auth::SecretKey;
use risala_proto::binary::PairData;
use risala_proto::command::{Command, PairCommand};
use risala_proto::error::ErrorCode;
use risala_proto::names::{PairId, ServerAddr as WireAddr};
use risala_proto::pairing::{NewDevice, NewDeviceContent, PairingCode};
use risala_proto::record::{DeviceKeys, LogKey, Record, RecordBody, RecordContent};
use risala_proto::server::ServerLine;
use zeroize::Zeroizing;

use super::own::record_time;
use super::{
    IdentityError, OwnIdentity, PairingOffer, PairingRequest, parse_identity, rnd, to_uid,
};
use crate::addr::ServerAddr;
use crate::client::servers::server_addr;
use crate::client::types::DeviceId;
use crate::client::{Client, Error, Result};
use crate::conn::{SingleUse, single_use};
use crate::keys::{KeyNames, attestation_public_key, random_seed};
use crate::store::AccountKind;
use crate::store::identity::{OwnRow, PairingRow};

/// How long a pairing lasts: the relay keeps its data for 10 minutes
/// (4.8).
pub const PAIRING_TTL_MS: u64 = 10 * 60 * 1000;

/// How often the new device asks the relay for the bundle.
const POLL: Duration = Duration::from_secs(2);

fn pairing_error(e: impl std::fmt::Display) -> Error {
    IdentityError::Pairing(e.to_string()).into()
}

fn pair_id(id: &risala_mls::RelayId) -> PairId {
    PairId::from_bytes(*id.as_bytes())
}

impl Client {
    /// Sends a relay command on a connection of its own (4.1).
    async fn pair(&self, addr: &ServerAddr, command: PairCommand) -> Result<Option<Vec<u8>>> {
        let response = single_use(
            addr,
            self.trust(),
            self.session_options(),
            SingleUse::New,
            Command::Pair(command),
        )
        .await?;
        match response.into_result() {
            Ok((lines, _)) => Ok(lines.into_iter().find_map(|m| match m.line {
                ServerLine::Pair { data, .. } => Some(data.decode()),
                _ => None,
            })),
            Err(e) if e.code() == Some(&ErrorCode::NotFound) => Ok(None),
            Err(e) if e.code() == Some(&ErrorCode::NameTaken) => Err(pairing_error(
                "the relay holds other data under this id; start again",
            )),
            Err(e) => Err(Error::Connection(e.into())),
        }
    }

    /// Starts pairing this device to an identity (4.8, step 1), with
    /// `server` as the relay: makes the device's keys, a one-time secret
    /// and pairing key, puts the encrypted NewDevice on the relay, and
    /// returns the QR text to show. The server must have a name, not an
    /// IP address (2.1, 4.8).
    pub async fn start_pairing(&self, server: &str, device_label: &str) -> Result<PairingOffer> {
        let addr = server_addr(server)?;
        let host = to_wire(&addr).ok_or_else(|| Error::invalid("pairing server", server))?;
        let rng = |e: getrandom::Error| Error::Internal(format!("random: {e}"));
        let device_seed = random_seed().map_err(rng)?;
        let attest_seed = random_seed().map_err(rng)?;
        let pairing_seed = random_seed().map_err(rng)?;
        let device = SecretKey::from_seed(*device_seed);
        let pairing_key = PairingKey::from_seed(Zeroizing::new(*pairing_seed));
        let content = NewDeviceContent {
            keys: DeviceKeys {
                device_key: device.public_key(),
                attestation_key: attestation_public_key(&attest_seed),
                label: device_label.to_owned(),
            },
            pairing_key: pairing_key.public().clone(),
        };
        if content.keys.label.len() > risala_proto::record::MAX_DEVICE_LABEL {
            return Err(Error::invalid("device label", device_label));
        }
        let new_device = NewDevice::sign(content, &device, rnd()?);
        let secret = PairingSecret::generate().map_err(rng)?;
        let relay = secret.relay();
        let code = secret.code(host, &new_device);
        let data = relay
            .seal_new_device(&new_device, &code)
            .map_err(pairing_error)?;

        // The keys wait under a name of their own until the identity is
        // known.
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(rng)?;
        let key_id = format!(
            "pairing-{}",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let names = KeyNames::new(&key_id);
        self.options()
            .keys
            .save_seed(&names.device(), &device_seed)?;
        self.options()
            .keys
            .save_seed(&names.attestation(), &attest_seed)?;
        let row = PairingRow {
            id: 0,
            new: true,
            uid: None,
            host: addr.to_string(),
            secret: secret.as_bytes().to_vec(),
            key_id: Some(key_id),
            label: Some(device_label.to_owned()),
            pairing_seed: Some(pairing_seed.to_vec()),
            new_device: new_device.encoded().to_vec(),
            record: None,
            sealed: None,
            created: self.now_ms(),
        };
        self.store().write(|tx| tx.add_pairing(&row))?;

        let data = PairData::from_bytes(&data).map_err(pairing_error)?;
        self.pair(
            &addr,
            PairCommand::Put {
                id: pair_id(&relay.new_id()),
                data,
            },
        )
        .await?;
        Ok(PairingOffer {
            qr: code.to_qr_text().to_string(),
        })
    }

    /// Waits, for as long as the pairing lasts, for the other device to
    /// finish the pairing started with [`start_pairing`](Self::start_pairing)
    /// (4.8, step 5): opens the IdentityBundle, fetches the identity's key
    /// file and checks the bundle against it, and returns the identity
    /// this device now holds. Its record may still be pending (4.5); the
    /// device signs in once the server's key file has it.
    pub async fn finish_pairing(&self) -> Result<OwnIdentity> {
        let row = self
            .store()
            .latest_pairing(true, None)?
            .ok_or_else(|| pairing_error("no pairing in progress"))?;
        let addr: ServerAddr = row
            .host
            .parse()
            .map_err(|_| pairing_error("bad relay host"))?;
        let secret: [u8; 32] = row
            .secret
            .as_slice()
            .try_into()
            .map_err(|_| pairing_error("bad secret"))?;
        let relay = PairingSecret::from_bytes(secret).relay();
        let deadline = row.created + PAIRING_TTL_MS;
        let data = loop {
            if let Some(data) = self
                .pair(
                    &addr,
                    PairCommand::Get {
                        id: pair_id(&relay.old_id()),
                    },
                )
                .await?
            {
                break data;
            }
            if self.now_ms() >= deadline {
                return Err(pairing_error("the other device did not answer in time"));
            }
            tokio::time::sleep(POLL).await;
        };
        self.finish_with(&row, &relay, &data).await
    }

    async fn finish_with(
        &self,
        row: &PairingRow,
        relay: &Relay,
        data: &[u8],
    ) -> Result<OwnIdentity> {
        let seed: [u8; 32] = row
            .pairing_seed
            .as_deref()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| pairing_error("bad pairing key"))?;
        let bundle = relay
            .open_bundle(data, &PairingKey::from_seed(Zeroizing::new(seed)))
            .map_err(pairing_error)?;
        let new_device = NewDevice::decode(&row.new_device).map_err(pairing_error)?;
        let uid = bundle.uid.clone();
        if self.store().own_identity(uid.as_str())?.is_some() {
            return Err(Error::invalid(
                "identity, already on this device",
                uid.as_str(),
            ));
        }

        // Check the bundle against the identity's key file (4.8, step 5).
        // The other device logged the record just before it sent the
        // bundle, so the device waits, while the pairing lasts, until the
        // log has witnessed it and the key file can be read up to it.
        let ours = &new_device.content().keys;
        let holds = |chain: &risala_proto::chain::Chain| {
            chain.records().iter().any(|r| {
                r.hash().hash() == &bundle.record_hash
                    && matches!(&r.content().body, RecordBody::Device(k) if k == ours)
            })
        };
        let mut chain = None;
        for _ in 0..PAIRING_TTL_MS / POLL.as_millis() as u64 {
            self.refresh_uid(&uid).await?;
            let rows = self.store().records(uid.as_str())?;
            let read = crate::sync::identity::kept_chain(&uid, &rows, false);
            if read.as_ref().is_some_and(holds) {
                chain = read;
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        let chain = chain
            .ok_or_else(|| pairing_error("the key file does not hold this device's record"))?;
        if chain.master_key().as_bytes()[..] != bundle.master_key[..] {
            return Err(pairing_error(
                "the bundle's master key is not the key file's",
            ));
        }
        if bundle.backup.generation() != chain.generation() {
            return Err(pairing_error(
                "the bundle's generation is not the key file's",
            ));
        }
        let signing = SecretKey::from_seed(*bundle.signing_seed);
        if signing.public_key() != *chain.signing_key() {
            return Err(pairing_error(
                "the bundle's device-signing key is not current",
            ));
        }

        let key_id = row.key_id.clone().ok_or_else(|| pairing_error("no keys"))?;
        let names = KeyNames::new(&key_id);
        self.options()
            .keys
            .save_seed(&names.signing(), &bundle.signing_seed)?;
        self.options()
            .keys
            .save_seed(&names.backup(), bundle.backup.as_bytes())?;
        let home = bundle
            .hosts
            .first()
            .ok_or_else(|| pairing_error("no hosts"))?;
        let own = OwnRow {
            uid: uid.as_str().to_owned(),
            device_id: *ours.device_id().as_bytes(),
            key_id,
            home: home.to_string(),
            backup_generation: bundle.backup.generation(),
            created: self.now_ms(),
            told_full: false,
        };
        let (_, changes) = self.store().write(|tx| {
            tx.add_own(&own)?;
            tx.delete_pairing(row.id)?;
            for r in chain.records() {
                tx.add_announced(uid.as_str(), &r.hash())?;
            }
            Ok(())
        })?;
        self.emit_changes(changes);
        for host in &bundle.hosts {
            if let Some(addr) = from_wire(host) {
                self.store()
                    .add_account(&addr, AccountKind::Identity, &uid.to_uid())?;
            }
        }
        // Task C4: the history transfer, fetched once the home account
        // connects, and applied as the device is added to conversations.
        if let Some(transfer) = &bundle.transfer
            && let Some(home) = from_wire(home)
        {
            self.keep_pairing_transfer(&uid, &home, transfer)?;
        }
        Ok(OwnIdentity {
            uid: to_uid(&uid),
            device: DeviceId(*ours.device_id().as_bytes()),
        })
    }

    /// Reads a new device's QR text on a device of `uid` (4.8, step 2):
    /// fetches its NewDevice from the relay, decrypts and checks it (its
    /// hash is the code's, its signature verifies, its keys pass 4.4), and
    /// returns its label for the user to confirm.
    pub async fn scan_pairing(&self, uid: &str, qr: &str) -> Result<PairingRequest> {
        let identity = parse_identity(uid)?;
        self.own_row(&identity)?;
        let code = PairingCode::from_qr_text(qr.trim()).map_err(pairing_error)?;
        let addr = from_wire(&code.host).ok_or_else(|| pairing_error("bad relay host"))?;
        let secret = PairingSecret::of_code(&code);
        let relay = secret.relay();
        let data = self
            .pair(
                &addr,
                PairCommand::Get {
                    id: pair_id(&relay.new_id()),
                },
            )
            .await?
            .ok_or_else(|| pairing_error("the new device's data is not on the relay"))?;
        // Decrypts it, and makes risala-proto's checks of a NewDevice
        // against the code (4.8, step 2).
        let new_device = relay.open_new_device(&data, &code).map_err(pairing_error)?;
        let (chain, _) = self.own_chain(&identity)?;
        let id = new_device.content().keys.device_id();
        if chain.devices().contains_key(&id) || chain.removed().contains(&id) {
            return Err(pairing_error("the device is already in the chain"));
        }
        if chain.devices().len() >= risala_proto::record::MAX_DEVICES {
            return Err(pairing_error("the identity has 64 devices"));
        }
        let row = PairingRow {
            id: 0,
            new: false,
            uid: Some(identity.as_str().to_owned()),
            host: addr.to_string(),
            secret: secret.as_bytes().to_vec(),
            key_id: None,
            label: Some(new_device.content().keys.label.clone()),
            pairing_seed: None,
            new_device: new_device.encoded().to_vec(),
            record: None,
            sealed: None,
            created: self.now_ms(),
        };
        self.store().write(|tx| tx.add_pairing(&row))?;
        Ok(PairingRequest {
            label: new_device.content().keys.label.clone(),
            device: DeviceId(*id.as_bytes()),
            short: id.short(),
        })
    }

    /// Adds the device the user confirmed after
    /// [`scan_pairing`](Self::scan_pairing), and sends it the identity
    /// (4.8, steps 3 and 4): a `device` record signed by the
    /// device-signing key, published with KEYS PUT, and the IdentityBundle
    /// sealed to the new device on the relay. With `transfer`, the bundle
    /// carries the history of this device's conversations on the home
    /// server (12.13, task C4), if the account there is connected.
    pub async fn confirm_pairing(&self, uid: &str, transfer: bool) -> Result<()> {
        let identity = parse_identity(uid)?;
        let own = self.own_row(&identity)?;
        let row = self
            .store()
            .latest_pairing(false, Some(identity.as_str()))?
            .ok_or_else(|| pairing_error("no device scanned"))?;
        if self.now_ms() >= row.created + PAIRING_TTL_MS {
            return Err(pairing_error("the pairing has expired"));
        }
        let new_device = NewDevice::decode(&row.new_device).map_err(pairing_error)?;
        let names = KeyNames::new(&own.key_id);
        let signing_seed = self
            .options()
            .keys
            .load_seed(&names.signing())?
            .ok_or(IdentityError::MissingKey("device-signing key"))?;
        let backup = self
            .options()
            .keys
            .load_seed(&names.backup())?
            .ok_or(IdentityError::MissingKey("backup key"))?;
        let signing = SecretKey::from_seed(*signing_seed);
        let (chain, rows) = self.own_chain(&identity)?;
        if signing.public_key() != *chain.signing_key() {
            return Err(IdentityError::MissingKey("device-signing key").into());
        }
        if own.backup_generation != chain.generation() {
            return Err(IdentityError::MissingKey("backup key").into());
        }

        // Step 3: the device record, kept and published.
        let record = match &row.record {
            Some(bytes) => Record::decode(bytes).map_err(pairing_error)?,
            None => Record::sign(
                RecordContent {
                    uid: identity.clone(),
                    previous: Some(chain.head_hash()),
                    time: record_time(self.now_ms(), Some(chain.head())),
                    body: RecordBody::Device(new_device.content().keys.clone()),
                },
                &signing,
                rnd()?,
            )
            .map_err(pairing_error)?,
        };
        if row.record.is_none() {
            let mut next = chain.clone();
            next.push(&record, None, &|_: &LogKey, _: &LogKey| false)
                .map_err(pairing_error)?;
            self.keep_own_record(&identity, &chain, &rows, &record)?;
        }
        if let Err(e) = self.publish_own(&identity, None).await {
            tracing::info!(%identity, error = %e, "KEYS PUT failed; will retry");
        }

        // Step 4: the IdentityBundle, sealed to the new device.
        let secret: [u8; 32] = row
            .secret
            .as_slice()
            .try_into()
            .map_err(|_| pairing_error("bad secret"))?;
        let relay = PairingSecret::from_bytes(secret).relay();
        let sealed = match &row.sealed {
            Some(sealed) => sealed.clone(),
            None => {
                let mut hosts: Vec<WireAddr> = Vec::new();
                let home = own.home.parse::<ServerAddr>().ok();
                let accounts = self.accounts()?;
                let servers = home.into_iter().chain(
                    accounts
                        .iter()
                        .filter(|a| a.uid.as_str() == identity.as_str())
                        .map(|a| a.server.clone()),
                );
                for server in servers {
                    if let Some(d) = to_wire(&server)
                        && !hosts.contains(&d)
                    {
                        hosts.push(d);
                    }
                }
                let bundle = IdentityBundle {
                    uid: identity.clone(),
                    master_key: chain.master_key().as_bytes().to_vec(),
                    signing_seed: Zeroizing::new(*signing_seed),
                    backup: risala_mls::BackupKey::from_bytes(own.backup_generation, *backup),
                    record_hash: *record.hash().hash(),
                    hosts,
                    // Task C4: archives of this device's history (12.13).
                    transfer: match transfer {
                        true => self.transfer_for_pairing(&identity, &own.home).await,
                        false => None,
                    },
                };
                let mls_device =
                    risala_mls::NewDevice::decode(&row.new_device).map_err(pairing_error)?;
                let sealed = relay
                    .seal_bundle(&bundle, &mls_device)
                    .map_err(pairing_error)?
                    .encode();
                // Kept, so that a repeated PAIR PUT sends the same bytes.
                self.store()
                    .write(|tx| tx.set_pairing_sent(row.id, record.encoded(), &sealed))?;
                sealed
            }
        };
        let addr: ServerAddr = row
            .host
            .parse()
            .map_err(|_| pairing_error("bad relay host"))?;
        self.pair(
            &addr,
            PairCommand::Put {
                id: pair_id(&relay.old_id()),
                data: PairData::from_bytes(&sealed).map_err(pairing_error)?,
            },
        )
        .await?;
        self.store().write(|tx| tx.delete_pairing(row.id))?;
        Ok(())
    }

    /// Forgets pairings older than 10 minutes, and the new device's keys
    /// of those that never finished (4.8).
    pub(crate) fn expire_pairings(&self) -> Result<()> {
        let before = self.now_ms().saturating_sub(PAIRING_TTL_MS);
        let (old, _) = self.store().write(|tx| tx.delete_old_pairings(before))?;
        for row in old.iter().filter(|r| r.new) {
            if let Some(key_id) = &row.key_id {
                for id in KeyNames::new(key_id).all() {
                    self.options().keys.delete(&id)?;
                }
            }
        }
        Ok(())
    }
}

/// A server address as librisala keeps it, in the one written form of 2.1
/// and 3.5; `None` for an IP address, which an identity cannot use (2.1).
fn to_wire(addr: &ServerAddr) -> Option<WireAddr> {
    addr.to_string().parse().ok()
}

/// A server address from a pairing code or IdentityBundle, as librisala
/// keeps it.
fn from_wire(addr: &WireAddr) -> Option<ServerAddr> {
    ServerAddr::new(addr.host(), addr.port()).ok()
}

//! Tests of the identity formats (SPEC 4.3-4.8, 12.14): records and their
//! chains, key files and their three states, KEYS PUT and REGISTER,
//! recovery keys, pairing and safety numbers. `vectors.rs` prints
//! Appendix B's test vectors.

#[path = "../common/appendix.rs"]
mod appendix;
mod chains;
mod formats;
mod keyfiles;
mod vectors;

use std::sync::OnceLock;

use risala_proto::auth::SecretKey;
use risala_proto::names::Identity;
use risala_proto::record::{
    DeviceId, DeviceKeys, LogKey, Record, RecordBody, RecordContent, XWingPublicKey,
};

/// 2026-11-01T00:00:00Z, the time of every first record here.
pub const T0: u64 = 1_793_491_200_000;

/// An ML-DSA-44 key from a seed of `n` repeated. Cached, since key
/// generation is slow in debug builds.
pub fn key(n: u8) -> SecretKey {
    static KEYS: OnceLock<Vec<SecretKey>> = OnceLock::new();
    KEYS.get_or_init(|| (0..=255).map(|n| SecretKey::from_seed([n; 32])).collect())[usize::from(n)]
        .clone()
}

/// An X-Wing public key from a seed of `n` repeated (draft-06 KeyGen).
pub fn xwing(n: u8) -> XWingPublicKey {
    XWingPublicKey::from_bytes(&xwing_bytes([n; 32])).unwrap()
}

/// The X-Wing public key of a 32-byte seed.
pub fn xwing_bytes(seed: [u8; 32]) -> Vec<u8> {
    let (_, pk) =
        libcrux_kem::key_gen_derand(libcrux_kem::Algorithm::XWingKemDraft06, &seed).unwrap();
    pk.encode()
}

pub fn alice() -> Identity {
    "alice@example.org".parse().unwrap()
}

/// Log `n` of `host`, with a key from seed `seed`.
pub fn log_on(host: &str, n: u64, seed: u8) -> LogKey {
    LogKey::new(&format!("{host}/risala-log/{n}"), key(seed).public_key()).unwrap()
}

/// The log of the chains here: `chat.example.org/risala-log/1`.
pub fn log1() -> LogKey {
    log_on("chat.example.org", 1, 200)
}

/// Device `n`'s keys: device key from seed `n`, attestation key from
/// X-Wing seed `n`.
pub fn device_keys(n: u8, label: &str) -> DeviceKeys {
    DeviceKeys {
        device_key: key(n).public_key(),
        attestation_key: xwing(n),
        label: label.to_owned(),
    }
}

pub fn device_id(n: u8) -> DeviceId {
    DeviceId::of(&key(n).public_key())
}

/// Builds chains of records with deterministic signatures. Master keys
/// use seeds from 100, device-signing keys from 150, devices from 1.
pub struct Builder {
    pub uid: Identity,
    pub master: SecretKey,
    pub signing: SecretKey,
    pub records: Vec<Record>,
    pub time: u64,
}

impl Builder {
    /// A chain whose first record names `log`.
    pub fn new(log: &LogKey) -> Builder {
        Builder::with_keys(alice(), key(100), key(150), log)
    }

    pub fn with_keys(
        uid: Identity,
        master: SecretKey,
        signing: SecretKey,
        log: &LogKey,
    ) -> Builder {
        let content = RecordContent {
            uid: uid.clone(),
            previous: None,
            time: T0,
            body: RecordBody::Master {
                master_key: master.public_key(),
                signing_key: signing.public_key(),
                log: log.clone(),
            },
        };
        let first = Record::sign_deterministic(content, &master).unwrap();
        Builder {
            uid,
            master,
            signing,
            records: vec![first],
            time: T0,
        }
    }

    /// The content of the next record.
    pub fn next(&mut self, body: RecordBody) -> RecordContent {
        self.time += 60_000;
        RecordContent {
            uid: self.uid.clone(),
            previous: Some(self.records.last().unwrap().hash()),
            time: self.time,
            body,
        }
    }

    /// Adds a record signed by `key`.
    pub fn push_signed(&mut self, content: RecordContent, key: &SecretKey) -> &mut Builder {
        let record = Record::sign_deterministic(content, key).unwrap();
        self.records.push(record);
        self
    }

    pub fn device(&mut self, n: u8, label: &str) -> &mut Builder {
        let content = self.next(RecordBody::Device(device_keys(n, label)));
        let signing = self.signing.clone();
        self.push_signed(content, &signing)
    }

    pub fn signing(&mut self, new: u8, removed: &[u8]) -> &mut Builder {
        let mut removed: Vec<DeviceId> = removed.iter().map(|&n| device_id(n)).collect();
        removed.sort();
        self.signing = key(new);
        let content = self.next(RecordBody::Signing {
            signing_key: self.signing.public_key(),
            removed,
        });
        let master = self.master.clone();
        self.push_signed(content, &master)
    }

    pub fn log(&mut self, log: &LogKey) -> &mut Builder {
        let content = self.next(RecordBody::Log(log.clone()));
        let master = self.master.clone();
        self.push_signed(content, &master)
    }

    pub fn retire(&mut self) -> &mut Builder {
        let content = self.next(RecordBody::Retire);
        let master = self.master.clone();
        self.push_signed(content, &master)
    }

    /// A later `master` record, to `master` and `signing`, naming `log`.
    pub fn rotate(&mut self, master: u8, signing: u8, log: &LogKey) -> &mut Builder {
        let (old, new) = (self.master.clone(), key(master));
        self.signing = key(signing);
        let content = self.next(RecordBody::Master {
            master_key: new.public_key(),
            signing_key: self.signing.public_key(),
            log: log.clone(),
        });
        let record = Record::sign_rotation_deterministic(content, &old, &new).unwrap();
        self.records.push(record);
        self.master = new;
        self
    }
}

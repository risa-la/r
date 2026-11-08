//! Byte formats the group engine reads and writes besides OpenMLS's:
//! RisalaMessage (12.9), SealedWelcome and one Welcome per device (12.8),
//! and the engine's own records of what a commit does.
//!
//! **RisalaMessage is a seam.** Task M2 is writing it, with franking and
//! times, as `risala_mls::message`. Until that lands on `m5b`, this module
//! encodes and checks it as 12.9 says; replace [`RisalaMessage`] with M2's
//! type then, keeping [`RisalaMessage::new`], [`RisalaMessage::encode`],
//! [`RisalaMessage::decode`] and [`RisalaMessage::frank_ok`] as the
//! engine's interface to it.

use risala_mls::CIPHERSUITE;
use risala_mls::openmls::prelude::tls_codec::Deserialize as _;
use risala_mls::openmls::prelude::{KeyPackage, MlsMessageIn};
use risala_mls::openmls_traits::crypto::OpenMlsCrypto;
use risala_mls::openmls_traits::types::HpkeCiphertext;
use risala_mls::primitives::{HASH_LEN, ct_eq, hmac_sha384};

/// A value could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed {0}")]
pub struct Malformed(pub &'static str);

// ---------------------------------------------------------------------------
// The codec of RFC 9420, 2.1: big-endian integers and vectors with a
// variable-length prefix.

pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Writer {
        Writer(Vec::new())
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    pub(crate) fn vector(&mut self, b: &[u8]) -> &mut Self {
        write_varint(&mut self.0, b.len());
        self.0.extend_from_slice(b);
        self
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) fn write_varint(out: &mut Vec<u8>, len: usize) {
    if len < 1 << 6 {
        out.push(len as u8);
    } else if len < 1 << 14 {
        out.extend_from_slice(&((len as u16) | 0x4000).to_be_bytes());
    } else {
        assert!(len < 1 << 30, "a vector too long for MLS");
        out.extend_from_slice(&((len as u32) | 0x8000_0000).to_be_bytes());
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, pos: 0 }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(n).ok_or(Malformed("length"))?;
        let out = self
            .bytes
            .get(self.pos..end)
            .ok_or(Malformed("truncated value"))?;
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    pub(crate) fn varint(&mut self) -> Result<usize, Malformed> {
        let first = self.u8()?;
        let len = match first >> 6 {
            0 => usize::from(first & 0x3f),
            1 => {
                let v = (usize::from(first & 0x3f) << 8) | usize::from(self.u8()?);
                if v < 1 << 6 {
                    return Err(Malformed("a length not in its shortest form"));
                }
                v
            }
            2 => {
                let rest = self.take(3)?;
                let v = (usize::from(first & 0x3f) << 24)
                    | (usize::from(rest[0]) << 16)
                    | (usize::from(rest[1]) << 8)
                    | usize::from(rest[2]);
                if v < 1 << 14 {
                    return Err(Malformed("a length not in its shortest form"));
                }
                v
            }
            _ => return Err(Malformed("length prefix")),
        };
        Ok(len)
    }

    pub(crate) fn vector(&mut self) -> Result<&'a [u8], Malformed> {
        let n = self.varint()?;
        self.take(n)
    }

    pub(crate) fn finish(&self) -> Result<(), Malformed> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Malformed("trailing bytes"))
        }
    }
}

// ---------------------------------------------------------------------------
// RisalaMessage (12.9)

/// The content of an application message (12.9).
#[derive(Clone, PartialEq, Eq)]
pub struct RisalaMessage {
    /// Its id in the group.
    pub message_id: [u8; 16],
    /// How many messages the leaf has written, this one included; 0 for a
    /// live message.
    pub counter: u64,
    /// The leaf's previous message, if any.
    pub previous: Option<[u8; 16]>,
    /// The sender's clock, in ms.
    pub time: u64,
    /// The franking key.
    pub frank_key: [u8; 32],
    /// The content lines.
    pub content: Vec<u8>,
}

impl std::fmt::Debug for RisalaMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RisalaMessage")
            .field("message_id", &self.message_id)
            .field("counter", &self.counter)
            .field("time", &self.time)
            .finish_non_exhaustive()
    }
}

impl RisalaMessage {
    /// A new message with a random id and frank key (12.9, step 2).
    pub fn new(
        counter: u64,
        previous: Option<[u8; 16]>,
        time: u64,
        content: Vec<u8>,
    ) -> Result<RisalaMessage, getrandom::Error> {
        let mut message_id = [0; 16];
        let mut frank_key = [0; 32];
        getrandom::fill(&mut message_id)?;
        getrandom::fill(&mut frank_key)?;
        Ok(RisalaMessage {
            message_id,
            counter,
            previous,
            time,
            frank_key,
            content,
        })
    }

    /// HMAC-SHA-384(`frank_key`, `content`), for the RisalaAAD (12.9,
    /// step 4).
    pub fn frank(&self) -> [u8; HASH_LEN] {
        hmac_sha384(&self.frank_key, &self.content)
    }

    /// Whether `frank` is this message's franking tag, compared in
    /// constant time (12.9, receiving step 2).
    pub fn frank_ok(&self, frank: &[u8]) -> bool {
        ct_eq(&self.frank(), frank)
    }

    /// The encoded RisalaMessage.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).fixed(&self.message_id).u64(self.counter);
        w.vector(self.previous.as_ref().map_or(&[][..], |p| &p[..]));
        w.u64(self.time)
            .fixed(&self.frank_key)
            .vector(&self.content);
        w.into_bytes()
    }

    /// Reads exactly one RisalaMessage of version 1.
    pub fn decode(bytes: &[u8]) -> Result<RisalaMessage, Malformed> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(Malformed("RisalaMessage version"));
        }
        let message_id = r.array()?;
        let counter = r.u64()?;
        let previous = match r.vector()? {
            [] => None,
            p => Some(p.try_into().map_err(|_| Malformed("previous"))?),
        };
        let time = r.u64()?;
        let frank_key = r.array()?;
        let content = r.vector()?.to_vec();
        r.finish()?;
        Ok(RisalaMessage {
            message_id,
            counter,
            previous,
            time,
            frank_key,
            content,
        })
    }
}

// ---------------------------------------------------------------------------
// One Welcome per device, sealed (12.8)

/// The HPKE `info` of a SealedWelcome (12.8, 15).
pub const WELCOME_INFO: &[u8] = b"risala/1 welcome";

/// One device's entry of a Welcome: its KeyPackageRef, and the Welcome
/// that holds only that entry, as an MLSMessage.
#[derive(Debug, Clone)]
pub struct DeviceWelcome {
    /// The KeyPackageRef.
    pub reference: Vec<u8>,
    /// The MLSMessage holding the Welcome.
    pub welcome: Vec<u8>,
}

/// Splits the MLSMessage of a Welcome into one per added device (12.8,
/// step 1): each has the same cipher suite and encrypted GroupInfo, and
/// only its own `secrets` entry.
pub fn split_welcome(message: &[u8]) -> Result<Vec<DeviceWelcome>, Malformed> {
    let mut r = Reader::new(message);
    let header = r.take(6)?; // version, wire_format (welcome), cipher_suite
    if header[2..4] != [0, 3] {
        return Err(Malformed("not a Welcome"));
    }
    let secrets = r.vector()?;
    let group_info = r.vector()?;
    r.finish()?;
    let mut entries = Vec::new();
    let mut s = Reader::new(secrets);
    while s.pos() < secrets.len() {
        let start = s.pos();
        let reference = s.vector()?.to_vec();
        s.vector()?; // kem_output
        s.vector()?; // ciphertext
        entries.push((reference, &secrets[start..s.pos()]));
    }
    Ok(entries
        .into_iter()
        .map(|(reference, entry)| {
            let mut w = Writer::new();
            w.fixed(header).vector(entry).vector(group_info);
            DeviceWelcome {
                reference,
                welcome: w.into_bytes(),
            }
        })
        .collect())
}

/// Seals one device's Welcome to its KeyPackage (12.8, step 2): HPKE
/// SealBase to the `init_key`, with info `risala/1 welcome` and the
/// KeyPackageRef as associated data, over the MLSMessage padded with zero
/// bytes to its Padmé length. Returns the encoded SealedWelcome.
pub fn seal_welcome(
    crypto: &impl OpenMlsCrypto,
    key_package: &KeyPackage,
    welcome: &DeviceWelcome,
) -> Result<Vec<u8>, Malformed> {
    let len = welcome.welcome.len() as u64;
    let padded = risala_mls::file::padme(len).ok_or(Malformed("Welcome length"))?;
    let mut plain = welcome.welcome.clone();
    plain.resize(padded as usize, 0);
    let sealed = crypto
        .hpke_seal(
            CIPHERSUITE.hpke_config(),
            key_package.hpke_init_key().as_slice(),
            WELCOME_INFO,
            &welcome.reference,
            &plain,
        )
        .map_err(|_| Malformed("Welcome sealing"))?;
    let mut w = Writer::new();
    w.u8(1)
        .vector(sealed.kem_output.as_slice())
        .vector(sealed.ciphertext.as_slice());
    Ok(w.into_bytes())
}

/// Opens a SealedWelcome with a KeyPackage's init private key, and checks
/// that the bytes after the MLSMessage are all zero (12.8). Returns the
/// MLSMessage holding the Welcome.
pub fn open_welcome(
    crypto: &impl OpenMlsCrypto,
    init_private_key: &[u8],
    reference: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, Malformed> {
    let mut r = Reader::new(sealed);
    if r.u8()? != 1 {
        return Err(Malformed("SealedWelcome version"));
    }
    let kem_output = r.vector()?.to_vec();
    let ciphertext = r.vector()?.to_vec();
    r.finish()?;
    let input = HpkeCiphertext {
        kem_output: kem_output.into(),
        ciphertext: ciphertext.into(),
    };
    let plain = crypto
        .hpke_open(
            CIPHERSUITE.hpke_config(),
            &input,
            init_private_key,
            WELCOME_INFO,
            reference,
        )
        .map_err(|_| Malformed("SealedWelcome: does not open"))?;
    let mut rest = &plain[..];
    MlsMessageIn::tls_deserialize(&mut rest).map_err(|_| Malformed("the sealed MLSMessage"))?;
    if rest.iter().any(|b| *b != 0) {
        return Err(Malformed("SealedWelcome padding"));
    }
    let used = plain.len() - rest.len();
    Ok(plain[..used].to_vec())
}

// ---------------------------------------------------------------------------
// What a commit does, kept with it to make it again if it loses (7.2)

/// What a commit of this device does. It is kept in the outbox, so that
/// a commit that loses its epoch can be made again, against the group as
/// it then is (7.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Intent {
    /// KeyPackages of devices to add, as MLSMessages.
    pub add: Vec<Vec<u8>>,
    /// Leaves to remove, by uid and device id (`None` for a guest).
    pub remove: Vec<(String, Option<[u8; 48]>)>,
    /// A new conversation extension (12.4), encoded.
    pub conversation: Option<Vec<u8>>,
    /// Commit a new leaf key (12.3, 12.5).
    pub new_leaf_key: bool,
    /// What to do once it wins.
    pub then: Then,
    /// A new display name for this device's leaf (8.2).
    pub display_name: Option<String>,
}

/// What to do once a commit wins.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Then {
    /// Nothing more.
    #[default]
    Nothing,
    /// Post a SelfRemove (6.1).
    SelfRemove,
}

impl Intent {
    /// Encodes it.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1);
        let mut adds = Writer::new();
        for kp in &self.add {
            adds.vector(kp);
        }
        w.vector(&adds.into_bytes());
        let mut removes = Writer::new();
        for (uid, device) in &self.remove {
            removes
                .vector(uid.as_bytes())
                .vector(device.as_ref().map_or(&[][..], |d| &d[..]));
        }
        w.vector(&removes.into_bytes());
        w.vector(self.conversation.as_deref().unwrap_or_default());
        w.u8(u8::from(self.conversation.is_some()));
        w.u8(u8::from(self.new_leaf_key));
        w.u8(match self.then {
            Then::Nothing => 0,
            Then::SelfRemove => 1,
        });
        w.u8(u8::from(self.display_name.is_some()));
        w.vector(self.display_name.as_deref().unwrap_or_default().as_bytes());
        w.into_bytes()
    }

    /// Reads one back.
    pub fn decode(bytes: &[u8]) -> Result<Intent, Malformed> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(Malformed("intent version"));
        }
        let adds = r.vector()?;
        let mut a = Reader::new(adds);
        let mut add = Vec::new();
        while a.pos() < adds.len() {
            add.push(a.vector()?.to_vec());
        }
        let removes = r.vector()?;
        let mut m = Reader::new(removes);
        let mut remove = Vec::new();
        while m.pos() < removes.len() {
            let uid = String::from_utf8(m.vector()?.to_vec()).map_err(|_| Malformed("uid"))?;
            let device = match m.vector()? {
                [] => None,
                d => Some(d.try_into().map_err(|_| Malformed("device id"))?),
            };
            remove.push((uid, device));
        }
        let conversation = r.vector()?.to_vec();
        let has_conversation = r.u8()? == 1;
        let new_leaf_key = r.u8()? == 1;
        let then = match r.u8()? {
            0 => Then::Nothing,
            1 => Then::SelfRemove,
            _ => return Err(Malformed("intent then")),
        };
        let has_name = r.u8()? == 1;
        let name = String::from_utf8(r.vector()?.to_vec()).map_err(|_| Malformed("name"))?;
        r.finish()?;
        Ok(Intent {
            add,
            remove,
            conversation: has_conversation.then_some(conversation),
            new_leaf_key,
            then,
            display_name: has_name.then_some(name),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for len in [0usize, 1, 63, 64, 300, 16383, 16384, 1 << 20] {
            let mut out = Vec::new();
            write_varint(&mut out, len);
            let mut r = Reader::new(&out);
            assert_eq!(r.varint().unwrap(), len);
            r.finish().unwrap();
        }
        // Not in its shortest form.
        assert!(Reader::new(&[0x40, 0x01]).varint().is_err());
    }

    #[test]
    fn risala_message_round_trip() {
        let m =
            RisalaMessage::new(3, Some([7; 16]), 1_700_000_000_000, b"TEXT hi\n".to_vec()).unwrap();
        let back = RisalaMessage::decode(&m.encode()).unwrap();
        assert_eq!(back, m);
        assert!(back.frank_ok(&m.frank()));
        let mut other = m.clone();
        other.content = b"TEXT bye\n".to_vec();
        assert!(!other.frank_ok(&m.frank()));
        let first = RisalaMessage::new(1, None, 0, b"x".to_vec()).unwrap();
        assert_eq!(
            RisalaMessage::decode(&first.encode()).unwrap().previous,
            None
        );
        let mut bytes = m.encode();
        bytes.push(0);
        assert!(RisalaMessage::decode(&bytes).is_err());
    }

    #[test]
    fn intents_round_trip() {
        let intent = Intent {
            add: vec![vec![1, 2, 3], vec![4; 100]],
            remove: vec![
                ("bob@example.org".into(), Some([9; 48])),
                ("~sam".into(), None),
            ],
            conversation: Some(vec![5; 10]),
            new_leaf_key: true,
            then: Then::SelfRemove,
            display_name: Some("Alice".into()),
        };
        assert_eq!(Intent::decode(&intent.encode()).unwrap(), intent);
        let empty = Intent::default();
        assert_eq!(Intent::decode(&empty.encode()).unwrap(), empty);
    }
}

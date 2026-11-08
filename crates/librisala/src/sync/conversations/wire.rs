//! The engine's own record of what a commit does, kept in the outbox so
//! that a commit that loses its epoch can be made again (7.2).
//!
//! RisalaMessage is `risala_mls::message` (task M2), and sealed Welcomes
//! are `risala_mls::welcome`.

/// A value could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed {0}")]
pub struct Malformed(pub &'static str);

// ---------------------------------------------------------------------------
// The codec of RFC 9420, 2.1: big-endian integers and vectors with a
// variable-length prefix.

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Writer {
        Writer(Vec::new())
    }

    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    fn vector(&mut self, b: &[u8]) -> &mut Self {
        write_varint(&mut self.0, b.len());
        self.0.extend_from_slice(b);
        self
    }

    fn into_bytes(self) -> Vec<u8> {
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

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(n).ok_or(Malformed("length"))?;
        let out = self
            .bytes
            .get(self.pos..end)
            .ok_or(Malformed("truncated value"))?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn varint(&mut self) -> Result<usize, Malformed> {
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

    fn vector(&mut self) -> Result<&'a [u8], Malformed> {
        let n = self.varint()?;
        self.take(n)
    }
}

// ---------------------------------------------------------------------------
// What a commit does (7.2)

/// A KeyPackage fetched with KEYPKG GET, with the put secret of its
/// handout, which its Welcome must carry (12.5, 12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The KeyPackage, as an MLSMessage.
    pub key_package: Vec<u8>,
    /// The put secret, 32 bytes.
    pub secret: Vec<u8>,
}

/// What a commit of this device does. It is kept in the outbox, so that
/// a commit that loses its epoch can be made again, against the group as
/// it then is (7.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Intent {
    /// Devices to add.
    pub add: Vec<Fetched>,
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
    /// A move to a new mailbox (7.8): the commit changes the box and
    /// nothing else. The box is derived when the commit is made.
    pub move_box: bool,
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
        w.u8(2);
        let mut adds = Writer::new();
        for f in &self.add {
            adds.vector(&f.key_package).vector(&f.secret);
        }
        w.vector(&adds.into_bytes());
        let mut removes = Writer::new();
        for (uid, device) in &self.remove {
            removes
                .vector(uid.as_bytes())
                .vector(device.as_ref().map_or(&[][..], |d| &d[..]));
        }
        w.vector(&removes.into_bytes());
        w.u8(u8::from(self.conversation.is_some()));
        w.vector(self.conversation.as_deref().unwrap_or_default());
        w.u8(u8::from(self.new_leaf_key));
        w.u8(match self.then {
            Then::Nothing => 0,
            Then::SelfRemove => 1,
        });
        w.u8(u8::from(self.display_name.is_some()));
        w.vector(self.display_name.as_deref().unwrap_or_default().as_bytes());
        w.u8(u8::from(self.move_box));
        w.into_bytes()
    }

    /// Reads one back.
    pub fn decode(bytes: &[u8]) -> Result<Intent, Malformed> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 2 {
            return Err(Malformed("intent version"));
        }
        let mut a = Reader::new(r.vector()?);
        let mut add = Vec::new();
        while !a.done() {
            add.push(Fetched {
                key_package: a.vector()?.to_vec(),
                secret: a.vector()?.to_vec(),
            });
        }
        let mut m = Reader::new(r.vector()?);
        let mut remove = Vec::new();
        while !m.done() {
            let uid = String::from_utf8(m.vector()?.to_vec()).map_err(|_| Malformed("uid"))?;
            let device = match m.vector()? {
                [] => None,
                d => Some(d.try_into().map_err(|_| Malformed("device id"))?),
            };
            remove.push((uid, device));
        }
        let has_conversation = r.u8()? == 1;
        let conversation = r.vector()?.to_vec();
        let new_leaf_key = r.u8()? == 1;
        let then = match r.u8()? {
            0 => Then::Nothing,
            1 => Then::SelfRemove,
            _ => return Err(Malformed("intent then")),
        };
        let has_name = r.u8()? == 1;
        let name = String::from_utf8(r.vector()?.to_vec()).map_err(|_| Malformed("name"))?;
        let move_box = r.u8()? == 1;
        if !r.done() {
            return Err(Malformed("trailing bytes"));
        }
        Ok(Intent {
            add,
            remove,
            conversation: has_conversation.then_some(conversation),
            new_leaf_key,
            then,
            display_name: has_name.then_some(name),
            move_box,
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
            assert!(r.done());
        }
        // Not in its shortest form.
        assert!(Reader::new(&[0x40, 0x01]).varint().is_err());
    }

    #[test]
    fn intents_round_trip() {
        let intent = Intent {
            add: vec![
                Fetched {
                    key_package: vec![1, 2, 3],
                    secret: vec![7; 32],
                },
                Fetched {
                    key_package: vec![4; 100],
                    secret: vec![8; 32],
                },
            ],
            remove: vec![
                ("bob@example.org".into(), Some([9; 48])),
                ("~sam".into(), None),
            ],
            conversation: Some(vec![5; 10]),
            new_leaf_key: true,
            then: Then::SelfRemove,
            display_name: Some("Alice".into()),
            move_box: false,
        };
        assert_eq!(Intent::decode(&intent.encode()).unwrap(), intent);
        let empty = Intent::default();
        assert_eq!(Intent::decode(&empty.encode()).unwrap(), empty);
    }
}

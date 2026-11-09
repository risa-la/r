//! The TLS presentation language as \[RFC9420\] uses it, for risala's own
//! binary structures: key file records (4.4), key log entries (4.5),
//! pairing messages (4.8) and safety numbers (12.14).
//!
//! Variable-size vectors (`opaque x<V>`) carry their length as an
//! \[RFC9420\] variable-length integer: two bits that give the length of
//! the integer (1, 2 or 4 bytes; `0b11` is invalid), then the value.
//! [`Reader`] insists on the shortest form, as \[RFC9420\] 2.1.2 requires,
//! so that every structure has exactly one encoding and its hash is
//! well defined.

use thiserror::Error;

/// The largest length a variable-size vector may have, 2^30 - 1.
pub const MAX_VECTOR_LEN: usize = (1 << 30) - 1;

/// Why bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct DecodeError(pub &'static str);

/// Writes a structure, field by field.
#[derive(Debug, Default, Clone)]
pub struct Writer(Vec<u8>);

impl Writer {
    /// An empty writer.
    pub fn new() -> Writer {
        Writer(Vec::new())
    }

    /// A `uint8`.
    pub fn u8(&mut self, v: u8) -> &mut Writer {
        self.0.push(v);
        self
    }

    /// A `uint32`, big-endian.
    pub fn u32(&mut self, v: u32) -> &mut Writer {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A `uint64`, big-endian.
    pub fn u64(&mut self, v: u64) -> &mut Writer {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A fixed-size field, such as `opaque secret[32]`.
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Writer {
        self.0.extend_from_slice(bytes);
        self
    }

    /// A variable-size vector, `opaque x<V>`, of these bytes.
    ///
    /// # Panics
    ///
    /// If `bytes` is longer than [`MAX_VECTOR_LEN`]. Nothing in this crate
    /// comes near it.
    pub fn vector(&mut self, bytes: &[u8]) -> &mut Writer {
        self.length(bytes.len());
        self.0.extend_from_slice(bytes);
        self
    }

    /// A variable-size vector whose contents `f` writes, such as a vector
    /// of structures.
    pub fn nested(&mut self, f: impl FnOnce(&mut Writer)) -> &mut Writer {
        let mut inner = Writer::new();
        f(&mut inner);
        self.vector(&inner.0)
    }

    /// The bytes written.
    pub fn finish(self) -> Vec<u8> {
        self.0
    }

    /// The bytes written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// A length, as a variable-length integer in its shortest form.
    fn length(&mut self, len: usize) {
        assert!(len <= MAX_VECTOR_LEN, "a vector is at most 2^30 - 1 bytes");
        if len < 1 << 6 {
            self.0.push(len as u8);
        } else if len < 1 << 14 {
            self.0
                .extend_from_slice(&(0x4000 | len as u16).to_be_bytes());
        } else {
            self.0
                .extend_from_slice(&(0x8000_0000 | len as u32).to_be_bytes());
        }
    }
}

/// Reads a structure, field by field, from the front of some bytes.
#[derive(Debug, Clone)]
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// A reader of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader(bytes)
    }

    /// A `uint8`.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.fixed::<1>()?[0])
    }

    /// A `uint32`, big-endian.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(*self.fixed::<4>()?))
    }

    /// A `uint64`, big-endian.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(*self.fixed::<8>()?))
    }

    /// A fixed-size field of `N` bytes.
    pub fn fixed<const N: usize>(&mut self) -> Result<&'a [u8; N], DecodeError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(DecodeError("cut short"))?;
        self.0 = rest;
        Ok(head)
    }

    /// A variable-size vector's contents.
    pub fn vector(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.length()?;
        if len > self.0.len() {
            return Err(DecodeError("a vector is longer than what is left"));
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    /// A variable-size vector, read with its own reader, which must use
    /// all of it.
    pub fn nested<T>(
        &mut self,
        f: impl FnOnce(&mut Reader<'a>) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        let mut inner = Reader(self.vector()?);
        let value = f(&mut inner)?;
        inner.end()?;
        Ok(value)
    }

    /// Whether everything has been read.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// What is left.
    pub fn rest(&self) -> &'a [u8] {
        self.0
    }

    /// Checks that everything has been read.
    pub fn end(&self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError("bytes after the last field"))
        }
    }

    /// A variable-length integer, which must be in its shortest form.
    fn length(&mut self) -> Result<usize, DecodeError> {
        let first = self.u8()?;
        let high = usize::from(first & 0x3f);
        let (len, min) = match first >> 6 {
            0 => (high, 0),
            1 => (high << 8 | usize::from(self.u8()?), 1 << 6),
            2 => {
                let b = self.fixed::<3>()?;
                let len = high << 24 | usize::from(b[0]) << 16 | usize::from(b[1]) << 8;
                (len | usize::from(b[2]), 1 << 14)
            }
            _ => return Err(DecodeError("a vector length starts with 0b11")),
        };
        if len < min {
            return Err(DecodeError("a vector length is not in its shortest form"));
        }
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(len: usize, prefix: &[u8]) {
        let bytes = vec![7u8; len];
        let mut w = Writer::new();
        w.vector(&bytes);
        let out = w.finish();
        assert!(out.starts_with(prefix), "{len}: {:x?}", &out[..4]);
        let mut r = Reader::new(&out);
        assert_eq!(r.vector().unwrap(), &bytes[..]);
        r.end().unwrap();
    }

    #[test]
    fn lengths() {
        round_trip(0, &[0]);
        round_trip(63, &[63]);
        round_trip(64, &[0x40, 64]);
        round_trip(16383, &[0x7f, 0xff]);
        round_trip(16384, &[0x80, 0, 0x40, 0]);
    }

    #[test]
    fn rejects_long_forms_and_0b11() {
        // 5 written in two bytes.
        assert!(Reader::new(&[0x40, 5, 0, 0, 0, 0, 0]).vector().is_err());
        // 5 written in four bytes.
        assert!(
            Reader::new(&[0x80, 0, 0, 5, 0, 0, 0, 0, 0])
                .vector()
                .is_err()
        );
        assert!(Reader::new(&[0xc0, 0, 0, 0, 0, 0, 0, 0]).vector().is_err());
        // Longer than what is left.
        assert!(Reader::new(&[3, 1, 2]).vector().is_err());
        // Trailing bytes.
        let mut r = Reader::new(&[1, 9, 0]);
        r.vector().unwrap();
        assert!(r.end().is_err());
    }
}

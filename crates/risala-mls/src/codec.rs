//! The TLS presentation language as MLS uses it [RFC9420, 2.1], for
//! risala's own structures (12.3, 12.4, 12.9) and for reading the framing
//! of MLS messages without OpenMLS (12.2, 7.2).
//!
//! Reading is strict, since it runs on what anyone sends: lengths are
//! variable-size integers in their shortest form, every read is bounds
//! checked, and a value must use up exactly the bytes it is read from.

/// Why bytes are not one value of the expected structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed: {0}")]
pub struct DecodeError(pub &'static str);

/// The largest length a variable-size vector may have [RFC9420, 2.1.2].
pub const MAX_VECTOR_LEN: usize = (1 << 30) - 1;

/// Writes values into a byte buffer.
#[derive(Debug, Default)]
pub(crate) struct Writer(pub(crate) Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Writer {
        Writer(Vec::new())
    }

    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Fixed-size bytes, as `opaque x[N]`.
    pub(crate) fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// A variable-size vector, `opaque x<V>`. Panics on a vector of 2^30
    /// bytes or more, which no caller can build.
    pub(crate) fn vector(&mut self, bytes: &[u8]) -> &mut Self {
        write_varint(&mut self.0, bytes.len());
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Writes `len` as a variable-size integer, in its shortest form.
pub(crate) fn write_varint(out: &mut Vec<u8>, len: usize) {
    assert!(len <= MAX_VECTOR_LEN, "vector too long for MLS");
    if len < 1 << 6 {
        out.push(len as u8);
    } else if len < 1 << 14 {
        out.extend_from_slice(&(0x4000 | len as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&(0x8000_0000 | len as u32).to_be_bytes());
    }
}

/// Reads values off the front of a byte slice.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes }
    }

    /// How many bytes are left.
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        let (&first, rest) = self.bytes.split_first().ok_or(DecodeError("too short"))?;
        self.bytes = rest;
        Ok(first)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// `N` bytes, as `opaque x[N]`.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (head, rest) = self
            .bytes
            .split_first_chunk::<N>()
            .ok_or(DecodeError("too short"))?;
        self.bytes = rest;
        Ok(*head)
    }

    /// `len` bytes.
    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if len > self.bytes.len() {
            return Err(DecodeError("too short"));
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }

    /// A variable-size length [RFC9420, 2.1.2], in its shortest form.
    pub(crate) fn varint(&mut self) -> Result<usize, DecodeError> {
        let first = self.u8()?;
        let high = usize::from(first & 0x3f);
        match first >> 6 {
            0 => Ok(high),
            1 => {
                let len = high << 8 | usize::from(self.u8()?);
                if len < 1 << 6 {
                    return Err(DecodeError("length not in its shortest form"));
                }
                Ok(len)
            }
            2 => {
                let b: [u8; 3] = self.array()?;
                let len = high << 24 | usize::from(b[0]) << 16 | usize::from(b[1]) << 8;
                let len = len | usize::from(b[2]);
                if len < 1 << 14 {
                    return Err(DecodeError("length not in its shortest form"));
                }
                Ok(len)
            }
            _ => Err(DecodeError("invalid length prefix")),
        }
    }

    /// A variable-size vector, `opaque x<V>`.
    pub(crate) fn vector(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.varint()?;
        self.take(len)
    }

    /// Fails unless every byte has been read.
    pub(crate) fn finish(&self) -> Result<(), DecodeError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(DecodeError("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for (len, encoded) in [
            (0usize, &b"\x00"[..]),
            (63, b"\x3f"),
            (64, b"\x40\x40"),
            (16383, b"\x7f\xff"),
            (16384, b"\x80\x00\x40\x00"),
            (MAX_VECTOR_LEN, b"\xbf\xff\xff\xff"),
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, len);
            assert_eq!(out, encoded, "{len}");
            let mut reader = Reader::new(encoded);
            assert_eq!(reader.varint(), Ok(len));
            reader.finish().unwrap();
        }
        // Longer forms than needed, the reserved prefix, and short input.
        for bad in [
            &b"\x40\x3f"[..],
            b"\x80\x00\x3f\xff",
            b"\xc0\x00\x00\x00\x00\x00\x00\x01",
            b"\x40",
            b"\x80\x00\x40",
            b"",
        ] {
            assert!(Reader::new(bad).varint().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn vectors_are_bounds_checked() {
        let mut w = Writer::new();
        w.u8(1)
            .vector(b"abc")
            .fixed(&7u32.to_be_bytes())
            .u64(9)
            .fixed(b"xy");
        let bytes = w.into_bytes();
        assert_eq!(
            bytes,
            b"\x01\x03abc\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x09xy"
        );
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.vector(), Ok(&b"abc"[..]));
        assert_eq!(r.u32(), Ok(7));
        assert_eq!(r.u64(), Ok(9));
        assert!(r.finish().is_err());
        assert_eq!(r.array::<2>(), Ok(*b"xy"));
        r.finish().unwrap();
        assert!(r.u8().is_err());

        // A length beyond the end.
        assert!(Reader::new(b"\x05abc").vector().is_err());
        assert!(Reader::new(b"\x7f\xff").vector().is_err());
    }
}

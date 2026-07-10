//! TLS 1.3 presentation-language encoding, with the two extensions used by
//! the MoLE drafts (draft-jms-mole-http-transport, "Presentation Language"):
//!
//! * **Variable-size vector length headers** (`opaque data<V>`): a QUIC
//!   variable-length integer (RFC 9000 Section 16) length prefix, with the
//!   additional requirement that the *minimum-size* encoding is used. A
//!   non-minimal length encoding is rejected as malformed.
//! * **Optional values** (`optional<T>`): a presence octet (0 or 1) followed
//!   by the value if present. Any other presence octet is malformed.
//!
//! All integers are network byte order.

use thiserror::Error;

/// An error encoding or decoding a MoLE wire value.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum WireError {
    /// The input ended before a complete value was read.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// Bytes remained after a complete value was decoded.
    #[error("trailing bytes after value")]
    TrailingBytes,
    /// A variable-length integer was not minimally encoded.
    #[error("non-minimal variable-length integer")]
    NonMinimalVarint,
    /// A value exceeded the range its encoding can carry.
    #[error("value out of range for its encoding")]
    OutOfRange,
    /// An `optional<T>` presence octet was neither 0 nor 1.
    #[error("malformed optional presence octet")]
    MalformedOptional,
    /// A field constraint was violated (e.g. a fixed-size field of the wrong
    /// length, or an unknown discriminant).
    #[error("malformed value: {0}")]
    Malformed(&'static str),
}

/// Canonical byte encoding of a MoLE protocol message.
pub trait Wire: Sized {
    /// Append the canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>);

    /// Decode one value from the front of `buf`, advancing it past the bytes
    /// read.
    fn decode(buf: &mut &[u8]) -> Result<Self, WireError>;

    /// The canonical byte encoding.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Decode from a complete slice, erroring if any bytes remain.
    fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut cursor = bytes;
        let value = Self::decode(&mut cursor)?;
        if cursor.is_empty() {
            Ok(value)
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// Split `n` bytes off the front of `buf`, advancing it.
pub fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if buf.len() < n {
        return Err(WireError::UnexpectedEof);
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}

pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub fn get_u8(buf: &mut &[u8]) -> Result<u8, WireError> {
    Ok(take(buf, 1)?[0])
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn get_u16(buf: &mut &[u8]) -> Result<u16, WireError> {
    let raw = take(buf, 2)?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn get_u64(buf: &mut &[u8]) -> Result<u64, WireError> {
    let raw = take(buf, 8)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(raw);
    Ok(u64::from_be_bytes(b))
}

/// The largest value a QUIC variable-length integer can carry (2^62 - 1).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Encode a QUIC variable-length integer (RFC 9000 Section 16), always using
/// the minimum-size encoding as the MoLE transport draft requires.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        assert!(v <= VARINT_MAX, "varint value out of range");
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// Decode a QUIC variable-length integer, rejecting non-minimal encodings.
pub fn get_varint(buf: &mut &[u8]) -> Result<u64, WireError> {
    let first = take(buf, 1)?[0];
    let prefix = first >> 6;
    let value = match prefix {
        0 => u64::from(first & 0x3F),
        1 => {
            let rest = take(buf, 1)?;
            let v = (u64::from(first & 0x3F) << 8) | u64::from(rest[0]);
            if v < 1 << 6 {
                return Err(WireError::NonMinimalVarint);
            }
            v
        }
        2 => {
            let rest = take(buf, 3)?;
            let v = (u64::from(first & 0x3F) << 24)
                | (u64::from(rest[0]) << 16)
                | (u64::from(rest[1]) << 8)
                | u64::from(rest[2]);
            if v < 1 << 14 {
                return Err(WireError::NonMinimalVarint);
            }
            v
        }
        _ => {
            let rest = take(buf, 7)?;
            let mut v = u64::from(first & 0x3F);
            for b in rest {
                v = (v << 8) | u64::from(*b);
            }
            if v < 1 << 30 {
                return Err(WireError::NonMinimalVarint);
            }
            v
        }
    };
    Ok(value)
}

/// Encode an `opaque data<V>` vector: varint length then the bytes.
pub fn put_opaque_v(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(bytes.len() as u64 <= VARINT_MAX, "opaque<V> too long");
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Decode an `opaque data<V>` vector.
pub fn get_opaque_v(buf: &mut &[u8]) -> Result<Vec<u8>, WireError> {
    let len = get_varint(buf)?;
    let len = usize::try_from(len).map_err(|_| WireError::OutOfRange)?;
    Ok(take(buf, len)?.to_vec())
}

/// Encode an `optional<T>`: presence octet then the value if present.
pub fn put_optional<T: Wire>(out: &mut Vec<u8>, value: &Option<T>) {
    match value {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            v.encode(out);
        }
    }
}

/// Decode an `optional<T>`, rejecting presence octets other than 0 and 1.
pub fn get_optional<T: Wire>(buf: &mut &[u8]) -> Result<Option<T>, WireError> {
    match get_u8(buf)? {
        0 => Ok(None),
        1 => Ok(Some(T::decode(buf)?)),
        _ => Err(WireError::MalformedOptional),
    }
}

/// Decode a fixed-size byte array.
pub fn get_fixed<const N: usize>(buf: &mut &[u8]) -> Result<[u8; N], WireError> {
    let raw = take(buf, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_at_boundaries() {
        for v in [
            0u64,
            1,
            63,
            64,
            (1 << 14) - 1,
            1 << 14,
            (1 << 30) - 1,
            1 << 30,
            VARINT_MAX,
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut cursor = out.as_slice();
            assert_eq!(get_varint(&mut cursor).unwrap(), v, "value {v}");
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn varint_sizes_are_minimal() {
        let size = |v: u64| {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            out.len()
        };
        assert_eq!(size(63), 1);
        assert_eq!(size(64), 2);
        assert_eq!(size((1 << 14) - 1), 2);
        assert_eq!(size(1 << 14), 4);
        assert_eq!(size((1 << 30) - 1), 4);
        assert_eq!(size(1 << 30), 8);
    }

    #[test]
    fn non_minimal_varint_rejected() {
        // 5 encoded in two bytes (prefix 01) instead of one.
        let bytes = [0x40, 0x05];
        let mut cursor = bytes.as_slice();
        assert_eq!(get_varint(&mut cursor), Err(WireError::NonMinimalVarint));
    }

    #[test]
    fn opaque_v_round_trips() {
        for len in [0usize, 1, 63, 64, 1000, 20000] {
            let bytes = vec![0xAB; len];
            let mut out = Vec::new();
            put_opaque_v(&mut out, &bytes);
            let mut cursor = out.as_slice();
            assert_eq!(get_opaque_v(&mut cursor).unwrap(), bytes, "len {len}");
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn malformed_optional_rejected() {
        struct Unit;
        impl Wire for Unit {
            fn encode(&self, _out: &mut Vec<u8>) {}
            fn decode(_buf: &mut &[u8]) -> Result<Self, WireError> {
                Ok(Unit)
            }
        }
        let bytes = [2u8];
        let mut cursor = bytes.as_slice();
        assert_eq!(
            get_optional::<Unit>(&mut cursor).err(),
            Some(WireError::MalformedOptional)
        );
    }
}

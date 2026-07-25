//! Transport-only binary encoding for [`FfiValue`] trees and
//! [`CipherText`] containers crossing an FFI boundary (e.g. the Go/WASI
//! binding's wasm linear-memory copy).
//!
//! This is a **transport encoding, not a storage format**: it exists so a
//! host language and a guest can hand each other a tree in one linear-memory
//! copy. Nothing here is a compatibility commitment — the only frozen byte
//! format in the stack is the sealed leaf payload (`[tag] ++ payload`, see
//! [`tags`]), which lives *inside* the AEAD envelope and never touches this
//! codec. Durable cross-language storage is the EQL layer's job.
//!
//! Value leaves reuse the frozen tag constants for the scalar kinds so the
//! two tables can't drift apart on meaning; [`ARRAY`]/[`OBJECT`] framing
//! tags are transport-local (the sealed format has no container tags —
//! container shape is carried by the ciphertext tree itself).
//!
//! All lengths and counts are `u32` little-endian. Object keys are UTF-8.

use crate::{tags, FfiValue};
use vitaminc_aead::CipherText;
use vitaminc_protected::{Controlled, Protected};

/// Transport-local framing tag for [`FfiValue::Array`].
pub const ARRAY: u8 = 0x10;
/// Transport-local framing tag for [`FfiValue::Object`].
pub const OBJECT: u8 = 0x11;

/// Ciphertext node kind: a single sealed leaf.
pub const CT_SINGLE: u8 = 0x01;
/// Ciphertext node kind: a sealed "no value" marker (`Option::None`).
pub const CT_NONE: u8 = 0x02;
/// Ciphertext node kind: a sequence of nodes.
pub const CT_SEQ: u8 = 0x03;
/// Ciphertext node kind: a map of clear keys to nodes.
pub const CT_MAP: u8 = 0x04;

/// Mirrors the hardening bound used by the NAPI conversion layer.
pub const MAX_DEPTH: usize = 128;

/// Opaque codec error. Like the trait-layer `Unspecified`, it carries no
/// detail: malformed transport bytes on the decrypt path are
/// attacker-reachable input.
#[derive(Debug, PartialEq, Eq)]
pub struct CodecError;

/// A cursor over a transport buffer, tracking how many bytes are consumed.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a buffer for decoding.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        let b = *self.buf.get(self.pos).ok_or(CodecError)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(len).ok_or(CodecError)?;
        let slice = self.buf.get(self.pos..end).ok_or(CodecError)?;
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| CodecError)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// A count of items still to be decoded can never exceed the bytes
    /// remaining (every item costs at least one byte); rejecting early
    /// keeps a hostile count from driving a huge preallocation.
    fn count(&mut self) -> Result<usize, CodecError> {
        let n = self.u32()? as usize;
        if n > self.buf.len() - self.pos {
            return Err(CodecError);
        }
        Ok(n)
    }

    fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), CodecError> {
    let len: u32 = len.try_into().map_err(|_| CodecError)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CodecError> {
    write_len(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// Encode a value tree. The output buffer contains **plaintext** — callers
/// own wiping it (the wasm ABI layer zeroizes transport buffers on dealloc).
///
/// Consumes the value; `Protected` leaves are wiped as they drop here.
pub fn encode_value(value: FfiValue, out: &mut Vec<u8>) -> Result<(), CodecError> {
    match value {
        FfiValue::Null => out.push(tags::NULL),
        FfiValue::Undefined => out.push(tags::UNDEFINED),
        FfiValue::Bool(false) => out.push(tags::BOOL_FALSE),
        FfiValue::Bool(true) => out.push(tags::BOOL_TRUE),
        FfiValue::Int32(i) => {
            out.push(tags::INT32);
            out.extend_from_slice(&i.to_le_bytes());
        }
        FfiValue::Int64(i) => {
            out.push(tags::INT64);
            out.extend_from_slice(&i.to_le_bytes());
        }
        FfiValue::UInt32(u) => {
            out.push(tags::UINT32);
            out.extend_from_slice(&u.to_le_bytes());
        }
        FfiValue::UInt64(u) => {
            out.push(tags::UINT64);
            out.extend_from_slice(&u.to_le_bytes());
        }
        FfiValue::Float32(f) => {
            out.push(tags::FLOAT32);
            out.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        FfiValue::Float64(f) => {
            out.push(tags::FLOAT64);
            out.extend_from_slice(&f.to_bits().to_le_bytes());
        }
        FfiValue::String(s) => {
            out.push(tags::STRING);
            write_bytes(out, s.risky_ref())?;
        }
        FfiValue::Bytes(b) => {
            out.push(tags::BYTES);
            write_bytes(out, b.risky_ref())?;
        }
        FfiValue::Array(items) => {
            out.push(ARRAY);
            write_len(out, items.len())?;
            for item in items {
                encode_value(item, out)?;
            }
        }
        FfiValue::Object(entries) => {
            out.push(OBJECT);
            write_len(out, entries.len())?;
            for (key, value) in entries {
                write_bytes(out, key.as_bytes())?;
                encode_value(value, out)?;
            }
        }
    }
    Ok(())
}

/// Decode a value tree, requiring the reader to be fully consumed.
pub fn decode_value(reader: &mut Reader<'_>) -> Result<FfiValue, CodecError> {
    let value = decode_value_inner(reader, 0)?;
    if !reader.finished() {
        return Err(CodecError);
    }
    Ok(value)
}

fn decode_value_inner(reader: &mut Reader<'_>, depth: usize) -> Result<FfiValue, CodecError> {
    if depth > MAX_DEPTH {
        return Err(CodecError);
    }
    match reader.byte()? {
        tags::NULL => Ok(FfiValue::Null),
        tags::UNDEFINED => Ok(FfiValue::Undefined),
        tags::BOOL_FALSE => Ok(FfiValue::Bool(false)),
        tags::BOOL_TRUE => Ok(FfiValue::Bool(true)),
        tags::INT32 => {
            let bytes: [u8; 4] = reader.take(4)?.try_into().map_err(|_| CodecError)?;
            Ok(FfiValue::Int32(i32::from_le_bytes(bytes)))
        }
        tags::INT64 => {
            let bytes: [u8; 8] = reader.take(8)?.try_into().map_err(|_| CodecError)?;
            Ok(FfiValue::Int64(i64::from_le_bytes(bytes)))
        }
        tags::UINT32 => {
            let bytes: [u8; 4] = reader.take(4)?.try_into().map_err(|_| CodecError)?;
            Ok(FfiValue::UInt32(u32::from_le_bytes(bytes)))
        }
        tags::UINT64 => {
            let bytes: [u8; 8] = reader.take(8)?.try_into().map_err(|_| CodecError)?;
            Ok(FfiValue::UInt64(u64::from_le_bytes(bytes)))
        }
        tags::FLOAT32 => {
            let bits: [u8; 4] = reader.take(4)?.try_into().map_err(|_| CodecError)?;
            Ok(FfiValue::Float32(f32::from_bits(u32::from_le_bytes(bits))))
        }
        tags::FLOAT64 => {
            let bits: [u8; 8] = reader.take(8)?.try_into().map_err(|_| CodecError)?;
            Ok(FfiValue::Float64(f64::from_bits(u64::from_le_bytes(bits))))
        }
        tags::STRING => {
            let len = reader.count()?;
            let bytes = reader.take(len)?;
            std::str::from_utf8(bytes).map_err(|_| CodecError)?;
            Ok(FfiValue::String(Protected::new(bytes.to_vec())))
        }
        tags::BYTES => {
            let len = reader.count()?;
            Ok(FfiValue::Bytes(Protected::new(reader.take(len)?.to_vec())))
        }
        ARRAY => {
            let count = reader.count()?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_value_inner(reader, depth + 1)?);
            }
            Ok(FfiValue::Array(items))
        }
        OBJECT => {
            let count = reader.count()?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let key_len = reader.count()?;
                let key = std::str::from_utf8(reader.take(key_len)?)
                    .map_err(|_| CodecError)?
                    .to_owned();
                entries.push((key, decode_value_inner(reader, depth + 1)?));
            }
            Ok(FfiValue::Object(entries))
        }
        _ => Err(CodecError),
    }
}

/// Encode a ciphertext tree. `Passthrough` nodes cannot cross this
/// transport (a wasm guest has no passthrough currency) and are an error.
pub fn encode_ciphertext<Leaf, P>(
    ct: &CipherText<Leaf, P>,
    out: &mut Vec<u8>,
) -> Result<(), CodecError>
where
    Leaf: AsRef<[u8]>,
{
    match ct {
        CipherText::Single(leaf) => {
            out.push(CT_SINGLE);
            write_bytes(out, leaf.as_ref())?;
        }
        CipherText::None(leaf) => {
            out.push(CT_NONE);
            write_bytes(out, leaf.as_ref())?;
        }
        CipherText::Sequence(items) => {
            out.push(CT_SEQ);
            write_len(out, items.len())?;
            for item in items {
                encode_ciphertext(item, out)?;
            }
        }
        CipherText::Map(entries) => {
            out.push(CT_MAP);
            write_len(out, entries.len())?;
            for (key, value) in entries {
                write_bytes(out, key.as_bytes())?;
                encode_ciphertext(value, out)?;
            }
        }
        CipherText::Passthrough(_) => return Err(CodecError),
    }
    Ok(())
}

/// Decode a ciphertext tree, requiring the reader to be fully consumed.
pub fn decode_ciphertext<Leaf, P>(
    reader: &mut Reader<'_>,
) -> Result<CipherText<Leaf, P>, CodecError>
where
    Leaf: From<Vec<u8>>,
{
    let ct = decode_ciphertext_inner(reader, 0)?;
    if !reader.finished() {
        return Err(CodecError);
    }
    Ok(ct)
}

fn decode_ciphertext_inner<Leaf, P>(
    reader: &mut Reader<'_>,
    depth: usize,
) -> Result<CipherText<Leaf, P>, CodecError>
where
    Leaf: From<Vec<u8>>,
{
    if depth > MAX_DEPTH {
        return Err(CodecError);
    }
    match reader.byte()? {
        CT_SINGLE => {
            let len = reader.count()?;
            Ok(CipherText::Single(Leaf::from(reader.take(len)?.to_vec())))
        }
        CT_NONE => {
            let len = reader.count()?;
            Ok(CipherText::None(Leaf::from(reader.take(len)?.to_vec())))
        }
        CT_SEQ => {
            let count = reader.count()?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_ciphertext_inner(reader, depth + 1)?);
            }
            Ok(CipherText::Sequence(items))
        }
        CT_MAP => {
            let count = reader.count()?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let key_len = reader.count()?;
                let key = std::str::from_utf8(reader.take(key_len)?)
                    .map_err(|_| CodecError)?
                    .to_owned();
                entries.push((key, decode_ciphertext_inner(reader, depth + 1)?));
            }
            Ok(CipherText::Map(entries))
        }
        _ => Err(CodecError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_encrypt::AesCipherText;

    fn string(s: &str) -> FfiValue {
        FfiValue::String(Protected::new(s.as_bytes().to_vec()))
    }

    fn sample() -> FfiValue {
        FfiValue::Object(vec![
            ("name".into(), string("Ada")),
            ("age".into(), FfiValue::Int64(36)),
            ("rank".into(), FfiValue::Int32(-7)),
            ("port".into(), FfiValue::UInt32(65535)),
            ("huge".into(), FfiValue::UInt64(u64::MAX)),
            ("score".into(), FfiValue::Float64(1.5)),
            ("ratio".into(), FfiValue::Float32(0.5)),
            ("active".into(), FfiValue::Bool(true)),
            ("nothing".into(), FfiValue::Null),
            (
                "tags".into(),
                FfiValue::Array(vec![
                    string("a"),
                    FfiValue::Bytes(Protected::new(vec![1, 2, 3])),
                    FfiValue::Undefined,
                ]),
            ),
        ])
    }

    /// Structural equality via re-encoding: the codec is deterministic, so
    /// equal transport bytes ⇔ equal trees (Number compared by bit pattern).
    fn encoded(value: FfiValue) -> Vec<u8> {
        let mut out = Vec::new();
        encode_value(value, &mut out).expect("codec");
        out
    }

    #[test]
    fn value_round_trips() {
        let bytes = encoded(sample());
        let decoded = decode_value(&mut Reader::new(&bytes)).expect("codec");
        assert_eq!(encoded(decoded), bytes);
    }

    #[test]
    fn scalar_encodings_are_pinned() {
        assert_eq!(encoded(FfiValue::Null), [0x00]);
        assert_eq!(encoded(FfiValue::Undefined), [0x01]);
        assert_eq!(encoded(FfiValue::Bool(false)), [0x02]);
        assert_eq!(encoded(FfiValue::Bool(true)), [0x03]);
        assert_eq!(encoded(FfiValue::Int32(-1)), [0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            encoded(FfiValue::Int64(-1)),
            [0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            encoded(FfiValue::UInt32(u32::MAX)),
            [0x06, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            encoded(FfiValue::UInt64(u64::MAX)),
            [0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // 1.5f32 = 0x3FC00000; 1.5f64 = 0x3FF8000000000000, little-endian.
        assert_eq!(encoded(FfiValue::Float32(1.5)), [0x08, 0, 0, 0xC0, 0x3F]);
        assert_eq!(
            encoded(FfiValue::Float64(1.5)),
            [0x09, 0, 0, 0, 0, 0, 0, 0xF8, 0x3F]
        );
        assert_eq!(encoded(string("hi")), [0x0A, 2, 0, 0, 0, b'h', b'i']);
        assert_eq!(
            encoded(FfiValue::Array(vec![FfiValue::Null])),
            [0x10, 1, 0, 0, 0, 0x00]
        );
    }

    #[test]
    fn uint_round_trips() {
        for u in [0u64, 1, i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
            let bytes = encoded(FfiValue::UInt64(u));
            let decoded = decode_value(&mut Reader::new(&bytes)).expect("codec");
            assert_eq!(encoded(decoded), bytes);
        }
    }

    #[test]
    fn narrow_numeric_round_trips() {
        // The 32-bit numeric tags preserve width and signedness through the
        // codec (edge values included).
        for v in [i32::MIN, -1, 0, i32::MAX] {
            let bytes = encoded(FfiValue::Int32(v));
            let decoded = decode_value(&mut Reader::new(&bytes)).expect("codec");
            assert_eq!(encoded(decoded), bytes);
        }
        for v in [0u32, 1, u32::MAX] {
            let bytes = encoded(FfiValue::UInt32(v));
            let decoded = decode_value(&mut Reader::new(&bytes)).expect("codec");
            assert_eq!(encoded(decoded), bytes);
        }
        // Raw-bits floats: -0.0 and a NaN payload survive in binary32.
        for v in [
            f32::from_bits(0x8000_0000),
            f32::from_bits(0x7fc0_0001),
            1.5,
        ] {
            let bytes = encoded(FfiValue::Float32(v));
            let decoded = decode_value(&mut Reader::new(&bytes)).expect("codec");
            assert_eq!(encoded(decoded), bytes);
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = encoded(FfiValue::Null);
        bytes.push(0x00);
        assert!(decode_value(&mut Reader::new(&bytes)).is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        let bytes = encoded(sample());
        for end in 0..bytes.len() - 1 {
            assert!(
                decode_value(&mut Reader::new(&bytes[..end])).is_err(),
                "truncation at {end} must not decode"
            );
        }
    }

    #[test]
    fn hostile_count_is_rejected_before_allocation() {
        // ARRAY claiming u32::MAX items with no bytes behind it.
        let bytes = [ARRAY, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(decode_value(&mut Reader::new(&bytes)).is_err());
    }

    #[test]
    fn invalid_utf8_key_is_rejected() {
        let mut bytes = vec![OBJECT, 1, 0, 0, 0, 1, 0, 0, 0, 0xFF];
        bytes.push(tags::NULL);
        assert!(decode_value(&mut Reader::new(&bytes)).is_err());
    }

    #[test]
    fn depth_bomb_is_rejected() {
        let mut bytes = Vec::new();
        for _ in 0..(MAX_DEPTH + 2) {
            bytes.extend_from_slice(&[ARRAY, 1, 0, 0, 0]);
        }
        bytes.push(tags::NULL);
        assert!(decode_value(&mut Reader::new(&bytes)).is_err());
    }

    #[test]
    fn ciphertext_round_trips() {
        let ct: AesCipherText = CipherText::Map(vec![
            ("a".into(), CipherText::Single(vec![9u8; 40].into())),
            (
                "b".into(),
                CipherText::Sequence(vec![
                    CipherText::Single(vec![1u8; 3].into()),
                    CipherText::None(vec![2u8; 3].into()),
                ]),
            ),
        ]);
        let mut out = Vec::new();
        encode_ciphertext(&ct, &mut out).expect("codec");
        let decoded: AesCipherText = decode_ciphertext(&mut Reader::new(&out)).expect("codec");
        let mut out2 = Vec::new();
        encode_ciphertext(&decoded, &mut out2).expect("codec");
        assert_eq!(out, out2);
    }

    #[test]
    fn passthrough_cannot_cross_the_transport() {
        let ct: AesCipherText = CipherText::Passthrough(Box::new(42u32));
        let mut out = Vec::new();
        assert_eq!(encode_ciphertext(&ct, &mut out), Err(CodecError));
    }
}

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

use std::any::Any;

use crate::{tags, FfiValue, Utf8String};
use vitaminc_aead::CipherText;
use vitaminc_protected::{Controlled, Protected};

/// Transport-local framing tag for [`FfiValue::Array`].
pub const ARRAY: u8 = 0x10;
/// Transport-local framing tag for [`FfiValue::Object`].
pub const OBJECT: u8 = 0x11;
/// Transport-local framing tag for [`FfiValue::Passthrough`]: the next value
/// node is a passthrough (unencrypted, unauthenticated) subtree. Like
/// [`ARRAY`]/[`OBJECT`] this is transport-local — the sealed leaf format has
/// no passthrough tag; the ciphertext tree carries passthrough via
/// [`CT_PASSTHROUGH`].
pub const PASSTHROUGH: u8 = 0x12;

/// Ciphertext node kind: a single sealed leaf.
pub const CT_SINGLE: u8 = 0x01;
/// Ciphertext node kind: a sealed "no value" marker (`Option::None`).
pub const CT_NONE: u8 = 0x02;
/// Ciphertext node kind: a sequence of nodes.
pub const CT_SEQ: u8 = 0x03;
/// Ciphertext node kind: a map of clear keys to nodes.
pub const CT_MAP: u8 = 0x04;
/// Ciphertext node kind: a passthrough value — one encoded plaintext value
/// node travelling in the clear beside the sealed nodes.
pub const CT_PASSTHROUGH: u8 = 0x05;
/// Ciphertext node kind: an empty sequence's authenticated marker leaf.
pub const CT_EMPTY_SEQ: u8 = 0x06;
/// Ciphertext node kind: an empty map's authenticated marker leaf.
pub const CT_EMPTY_MAP: u8 = 0x07;

/// A passthrough payload the ciphertext transport can carry as an embedded
/// plaintext value node.
///
/// The generic [`CipherText<Leaf, P>`] passthrough payload type `P` is opaque,
/// but to cross this transport a passthrough value must be serializable as a
/// value node. This trait supplies that, implemented for [`FfiValue`] — the
/// type the guest re-homes the Rust-native `Box<dyn Any + Send>` into (via
/// [`CipherText::map_passthrough`]) before encoding, and back into after
/// decoding. See [`encode_ciphertext_boxed`] / [`decode_ciphertext_boxed`].
pub trait TransportPassthrough: Sized {
    /// Encode this payload as one value node.
    fn encode_node(&self, out: &mut Vec<u8>) -> Result<(), CodecError>;
    /// Decode one value node into this payload, honouring the recursion bound.
    fn decode_node(reader: &mut Reader<'_>, depth: usize) -> Result<Self, CodecError>;
}

impl TransportPassthrough for FfiValue {
    fn encode_node(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_value_ref(self, out)
    }
    fn decode_node(reader: &mut Reader<'_>, depth: usize) -> Result<Self, CodecError> {
        decode_value_inner(reader, depth)
    }
}

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

    /// The bytes not yet consumed.
    fn remaining(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// A count of items (or a byte length) still to be decoded can never
    /// exceed the bytes remaining — every item costs at least one byte, and a
    /// byte length costs exactly itself. Rejecting early keeps a hostile count
    /// from driving a huge preallocation.
    ///
    /// Phrased against the remaining slice's length rather than
    /// `len - pos`: arithmetic on the two cursors admits an off-by-one that no
    /// input can distinguish (a too-large count that slips past the guard
    /// still fails when the reader runs dry, so only the transient allocation
    /// differs), whereas this form is exercised by every decode.
    fn count(&mut self) -> Result<usize, CodecError> {
        let n = self.u32()? as usize;
        if n > self.remaining().len() {
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
/// Consumes the value; `Protected` leaves are wiped as `value` drops here.
pub fn encode_value(value: FfiValue, out: &mut Vec<u8>) -> Result<(), CodecError> {
    // Borrow-encode, then let `value` drop (wiping any `Protected` leaves).
    encode_value_ref(&value, out)
}

/// Borrowing core of [`encode_value`]: encode a value tree without consuming
/// it. Reads secret leaves through `risky_ref` (they are not wiped here); the
/// owning caller is responsible for the value's lifetime. Also the encoder for
/// a passthrough payload node (see [`TransportPassthrough`]).
fn encode_value_ref(value: &FfiValue, out: &mut Vec<u8>) -> Result<(), CodecError> {
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
                encode_value_ref(item, out)?;
            }
        }
        FfiValue::Object(entries) => {
            out.push(OBJECT);
            write_len(out, entries.len())?;
            for (key, value) in entries {
                write_bytes(out, key.as_bytes())?;
                encode_value_ref(value, out)?;
            }
        }
        FfiValue::Passthrough(inner) => {
            out.push(PASSTHROUGH);
            encode_value_ref(inner, out)?;
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

/// Decode the recursive part of a value node: the container framings, which
/// need the depth budget. Anything else is a leaf and is delegated to
/// [`decode_leaf`], keeping each function's branch count modest.
fn decode_value_inner(reader: &mut Reader<'_>, depth: usize) -> Result<FfiValue, CodecError> {
    if depth > MAX_DEPTH {
        return Err(CodecError);
    }
    match reader.byte()? {
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
                let key = decode_key(reader)?;
                entries.push((key, decode_value_inner(reader, depth + 1)?));
            }
            Ok(FfiValue::Object(entries))
        }
        PASSTHROUGH => {
            // One wrapped value node, one level deeper for the recursion bound.
            let inner = decode_value_inner(reader, depth + 1)?;
            Ok(FfiValue::Passthrough(Box::new(inner)))
        }
        tag => decode_leaf(tag, reader),
    }
}

/// Decode a length-prefixed UTF-8 object key. Shared by the value and
/// ciphertext decoders, which frame keys identically.
fn decode_key(reader: &mut Reader<'_>) -> Result<String, CodecError> {
    let len = reader.count()?;
    Ok(std::str::from_utf8(reader.take(len)?)
        .map_err(|_| CodecError)?
        .to_owned())
}

/// Decode a non-container value node — the frozen scalar tag table. Split out
/// of [`decode_value_inner`] so neither function carries the branch count of
/// the whole tag space.
fn decode_leaf(tag: u8, reader: &mut Reader<'_>) -> Result<FfiValue, CodecError> {
    /// Read exactly `N` bytes as a fixed-width little-endian payload.
    fn fixed<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], CodecError> {
        reader.take(N)?.try_into().map_err(|_| CodecError)
    }

    match tag {
        tags::NULL => Ok(FfiValue::Null),
        tags::UNDEFINED => Ok(FfiValue::Undefined),
        tags::BOOL_FALSE => Ok(FfiValue::Bool(false)),
        tags::BOOL_TRUE => Ok(FfiValue::Bool(true)),
        tags::INT32 => Ok(FfiValue::Int32(i32::from_le_bytes(fixed(reader)?))),
        tags::INT64 => Ok(FfiValue::Int64(i64::from_le_bytes(fixed(reader)?))),
        tags::UINT32 => Ok(FfiValue::UInt32(u32::from_le_bytes(fixed(reader)?))),
        tags::UINT64 => Ok(FfiValue::UInt64(u64::from_le_bytes(fixed(reader)?))),
        tags::FLOAT32 => Ok(FfiValue::Float32(f32::from_bits(u32::from_le_bytes(
            fixed(reader)?,
        )))),
        tags::FLOAT64 => Ok(FfiValue::Float64(f64::from_bits(u64::from_le_bytes(
            fixed(reader)?,
        )))),
        tags::STRING => {
            let len = reader.count()?;
            let bytes = reader.take(len)?;
            // `Utf8String::try_from` validates — a malformed transport frame
            // is a codec error, mirroring the decrypt visitor's rejection.
            let s = Utf8String::try_from(Protected::new(bytes.to_vec())).map_err(|_| CodecError)?;
            Ok(FfiValue::String(s))
        }
        tags::BYTES => {
            let len = reader.count()?;
            Ok(FfiValue::Bytes(Protected::new(reader.take(len)?.to_vec())))
        }
        _ => Err(CodecError),
    }
}

/// Encode a ciphertext tree. A `Passthrough` node carries its payload as one
/// embedded plaintext value node, so the payload type `P` must be
/// serializable via [`TransportPassthrough`]. The Rust-native `Box<dyn Any +
/// Send>` is not — re-home it to [`FfiValue`] first (see
/// [`encode_ciphertext_boxed`]).
pub fn encode_ciphertext<Leaf, P>(
    ct: &CipherText<Leaf, P>,
    out: &mut Vec<u8>,
) -> Result<(), CodecError>
where
    Leaf: AsRef<[u8]>,
    P: TransportPassthrough,
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
        CipherText::EmptySequence(leaf) => {
            out.push(CT_EMPTY_SEQ);
            write_bytes(out, leaf.as_ref())?;
        }
        CipherText::EmptyMap(leaf) => {
            out.push(CT_EMPTY_MAP);
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
        CipherText::Passthrough(payload) => {
            out.push(CT_PASSTHROUGH);
            payload.encode_node(out)?;
        }
    }
    Ok(())
}

/// Encode an `AesCipherText`-shaped tree (Rust-native `Box<dyn Any + Send>`
/// passthrough payload type) by first re-homing each passthrough payload to an
/// [`FfiValue`] value node via [`CipherText::map_passthrough`]. A boxed
/// payload whose concrete type is not `FfiValue` (a foreign passthrough that
/// cannot cross the transport) is rejected.
pub fn encode_ciphertext_boxed<Leaf>(
    ct: CipherText<Leaf, Box<dyn Any + Send + 'static>>,
    out: &mut Vec<u8>,
) -> Result<(), CodecError>
where
    Leaf: AsRef<[u8]>,
{
    let rehomed: CipherText<Leaf, FfiValue> = ct.map_passthrough(&mut |boxed| {
        boxed
            .downcast::<FfiValue>()
            .map(|inner| *inner)
            .map_err(|_| CodecError)
    })?;
    encode_ciphertext(&rehomed, out)
}

/// Decode a ciphertext tree, requiring the reader to be fully consumed.
pub fn decode_ciphertext<Leaf, P>(
    reader: &mut Reader<'_>,
) -> Result<CipherText<Leaf, P>, CodecError>
where
    Leaf: From<Vec<u8>>,
    P: TransportPassthrough,
{
    let ct = decode_ciphertext_inner(reader, 0)?;
    if !reader.finished() {
        return Err(CodecError);
    }
    Ok(ct)
}

/// Decode a ciphertext tree into the `AesCipherText`-shaped `Box<dyn Any +
/// Send>` passthrough payload type, re-homing each decoded [`FfiValue`] payload
/// into a box via [`CipherText::map_passthrough`] so the tree can be handed to
/// the Rust-native decipher.
pub fn decode_ciphertext_boxed<Leaf>(
    reader: &mut Reader<'_>,
) -> Result<CipherText<Leaf, Box<dyn Any + Send + 'static>>, CodecError>
where
    Leaf: From<Vec<u8>>,
{
    let ct: CipherText<Leaf, FfiValue> = decode_ciphertext(reader)?;
    ct.map_passthrough(&mut |inner| {
        Ok::<Box<dyn Any + Send + 'static>, CodecError>(Box::new(inner))
    })
}

fn decode_ciphertext_inner<Leaf, P>(
    reader: &mut Reader<'_>,
    depth: usize,
) -> Result<CipherText<Leaf, P>, CodecError>
where
    Leaf: From<Vec<u8>>,
    P: TransportPassthrough,
{
    if depth > MAX_DEPTH {
        return Err(CodecError);
    }
    match reader.byte()? {
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
                let key = decode_key(reader)?;
                entries.push((key, decode_ciphertext_inner(reader, depth + 1)?));
            }
            Ok(CipherText::Map(entries))
        }
        CT_PASSTHROUGH => {
            // The payload is one plaintext value node, decoded one level deeper
            // so a hostile nesting through passthrough stays bounded.
            Ok(CipherText::Passthrough(P::decode_node(reader, depth + 1)?))
        }
        tag => decode_ciphertext_leaf(tag, reader),
    }
}

/// Decode a leaf-shaped ciphertext node — the four variants that carry one
/// sealed byte string and no children. Split out of
/// [`decode_ciphertext_inner`] so neither function carries every branch.
fn decode_ciphertext_leaf<Leaf, P>(
    tag: u8,
    reader: &mut Reader<'_>,
) -> Result<CipherText<Leaf, P>, CodecError>
where
    Leaf: From<Vec<u8>>,
{
    // Every leaf variant is framed identically; only the variant differs.
    let wrap: fn(Leaf) -> CipherText<Leaf, P> = match tag {
        CT_SINGLE => CipherText::Single,
        CT_NONE => CipherText::None,
        CT_EMPTY_SEQ => CipherText::EmptySequence,
        CT_EMPTY_MAP => CipherText::EmptyMap,
        _ => return Err(CodecError),
    };
    let len = reader.count()?;
    Ok(wrap(Leaf::from(reader.take(len)?.to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_encrypt::AesCipherText;

    fn string(s: &str) -> FfiValue {
        FfiValue::String(s.into())
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

    /// Wrap a NULL leaf in `n` nested single-element arrays.
    fn nested_value(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.extend_from_slice(&[ARRAY, 1, 0, 0, 0]);
        }
        bytes.push(tags::NULL);
        bytes
    }

    #[test]
    fn value_depth_bound_is_exact() {
        // The bound is `depth > MAX_DEPTH`, and n nested arrays put the
        // innermost leaf at depth n — so MAX_DEPTH wrappers is the last
        // accepted shape and one more is rejected. Pins the comparison
        // itself, not just "deep enough fails".
        assert!(decode_value(&mut Reader::new(&nested_value(MAX_DEPTH))).is_ok());
        assert!(decode_value(&mut Reader::new(&nested_value(MAX_DEPTH + 1))).is_err());
    }

    /// Wrap a NULL leaf in `n` nested single-entry objects.
    fn nested_object(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.push(OBJECT);
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(b'k');
        }
        bytes.push(tags::NULL);
        bytes
    }

    /// Wrap a NULL leaf in `n` nested passthrough markers.
    fn nested_passthrough(n: usize) -> Vec<u8> {
        let mut bytes = vec![PASSTHROUGH; n];
        bytes.push(tags::NULL);
        bytes
    }

    #[test]
    fn object_nesting_counts_against_the_depth_bound() {
        // Every container spends a level, not just arrays — an object that
        // failed to charge its depth would be an unbounded recursion route.
        assert!(decode_value(&mut Reader::new(&nested_object(MAX_DEPTH))).is_ok());
        assert!(decode_value(&mut Reader::new(&nested_object(MAX_DEPTH + 1))).is_err());
    }

    #[test]
    fn passthrough_nesting_counts_against_the_depth_bound() {
        assert!(decode_value(&mut Reader::new(&nested_passthrough(MAX_DEPTH))).is_ok());
        assert!(decode_value(&mut Reader::new(&nested_passthrough(MAX_DEPTH + 1))).is_err());
    }

    #[test]
    fn value_nesting_costs_exactly_one_level_per_container() {
        // Each container recurses at `depth + 1`; anything else (a `-`, a `*`,
        // or a missed increment) would move the accept/reject boundary found
        // above, so check the two adjacent shapes decode to the right depth.
        let ok = decode_value(&mut Reader::new(&nested_value(3))).expect("codec");
        let mut d = 0;
        let mut cur = &ok;
        while let FfiValue::Array(items) = cur {
            d += 1;
            cur = &items[0];
        }
        assert_eq!(d, 3);
        assert!(matches!(cur, FfiValue::Null));
    }

    #[test]
    fn object_key_length_is_read_per_entry() {
        // Two entries with differently-sized keys: an arithmetic slip in the
        // key/entry framing desynchronises the reader and fails to decode.
        let mut bytes = vec![OBJECT, 2, 0, 0, 0];
        for key in ["a", "bcd"] {
            bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(tags::NULL);
        }
        let decoded = decode_value(&mut Reader::new(&bytes)).expect("codec");
        match decoded {
            FfiValue::Object(entries) => {
                let keys: Vec<_> = entries.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, vec!["a", "bcd"]);
            }
            _ => panic!("expected Object"),
        }
    }

    #[test]
    fn count_is_bounded_by_bytes_remaining_not_buffer_length() {
        // `count` compares against the bytes left *after* the cursor. A count
        // that would fit in the whole buffer but not in the remainder must
        // still be rejected — the guard is `len - pos`, not `len`.
        //
        // 5 leading bytes consumed (ARRAY + count), leaving 1 byte; a claimed
        // count of 3 fits the 6-byte buffer but not the 1-byte remainder.
        let bytes = [ARRAY, 3, 0, 0, 0, tags::NULL];
        assert!(decode_value(&mut Reader::new(&bytes)).is_err());

        // And the in-bounds neighbour still decodes, so the guard is not just
        // rejecting everything.
        let ok = [ARRAY, 1, 0, 0, 0, tags::NULL];
        assert!(decode_value(&mut Reader::new(&ok)).is_ok());
    }

    #[test]
    fn every_scalar_tag_decodes_to_its_own_variant() {
        // One decode per frozen tag, so deleting any single leaf arm fails
        // here rather than silently falling through to the catch-all.
        let cases: Vec<(Vec<u8>, FfiValue)> = vec![
            (vec![tags::NULL], FfiValue::Null),
            (vec![tags::UNDEFINED], FfiValue::Undefined),
            (vec![tags::BOOL_FALSE], FfiValue::Bool(false)),
            (vec![tags::BOOL_TRUE], FfiValue::Bool(true)),
            (encoded(FfiValue::Int32(-7)), FfiValue::Int32(-7)),
            (encoded(FfiValue::Int64(-8)), FfiValue::Int64(-8)),
            (encoded(FfiValue::UInt32(9)), FfiValue::UInt32(9)),
            (encoded(FfiValue::UInt64(10)), FfiValue::UInt64(10)),
            (encoded(FfiValue::Float32(1.5)), FfiValue::Float32(1.5)),
            (encoded(FfiValue::Float64(2.5)), FfiValue::Float64(2.5)),
            (encoded(string("hi")), string("hi")),
            (
                encoded(FfiValue::Bytes(Protected::new(vec![1, 2]))),
                FfiValue::Bytes(Protected::new(vec![1, 2])),
            ),
        ];
        for (bytes, want) in cases {
            let got = decode_value(&mut Reader::new(&bytes)).expect("codec");
            assert_eq!(
                encoded(got),
                encoded(want),
                "tag {:#04x} decoded to the wrong variant",
                bytes[0]
            );
        }
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
        encode_ciphertext_boxed(ct, &mut out).expect("codec");
        let decoded: AesCipherText =
            decode_ciphertext_boxed(&mut Reader::new(&out)).expect("codec");
        let mut out2 = Vec::new();
        encode_ciphertext_boxed(decoded, &mut out2).expect("codec");
        assert_eq!(out, out2);
    }

    /// Round-trip a ciphertext tree and return the decoded value, asserting
    /// the encoding is stable across the trip.
    fn ct_round_trip(ct: AesCipherText) -> AesCipherText {
        let mut out = Vec::new();
        encode_ciphertext_boxed(ct, &mut out).expect("codec");
        let decoded: AesCipherText =
            decode_ciphertext_boxed(&mut Reader::new(&out)).expect("codec");
        let mut out2 = Vec::new();
        encode_ciphertext_boxed(decoded, &mut out2).expect("codec");
        assert_eq!(out, out2, "re-encode must be byte-stable");
        decode_ciphertext_boxed(&mut Reader::new(&out2)).expect("codec")
    }

    #[test]
    fn every_ciphertext_leaf_variant_round_trips_as_itself() {
        // The four leaf-shaped nodes are framed identically, so only the tag
        // distinguishes them: a dropped or swapped arm would decode one as
        // another. Check each lands on its own variant.
        assert!(matches!(
            ct_round_trip(CipherText::Single(vec![1u8; 4].into())),
            CipherText::Single(_)
        ));
        assert!(matches!(
            ct_round_trip(CipherText::None(vec![2u8; 4].into())),
            CipherText::None(_)
        ));
        assert!(matches!(
            ct_round_trip(CipherText::EmptySequence(vec![3u8; 4].into())),
            CipherText::EmptySequence(_)
        ));
        assert!(matches!(
            ct_round_trip(CipherText::EmptyMap(vec![4u8; 4].into())),
            CipherText::EmptyMap(_)
        ));
    }

    #[test]
    fn empty_composite_markers_keep_their_leaf_bytes() {
        // The marker's sealed bytes are what authenticates the empty
        // composite, so they must survive the transport verbatim.
        let leaf = vec![7u8; 40];
        match ct_round_trip(CipherText::EmptySequence(leaf.clone().into())) {
            CipherText::EmptySequence(l) => assert_eq!(l.as_ref(), leaf.as_slice()),
            other => panic!("expected EmptySequence, got {other:?}"),
        }
        match ct_round_trip(CipherText::EmptyMap(leaf.clone().into())) {
            CipherText::EmptyMap(l) => assert_eq!(l.as_ref(), leaf.as_slice()),
            other => panic!("expected EmptyMap, got {other:?}"),
        }
    }

    #[test]
    fn empty_markers_nest_inside_containers() {
        // The shape a map-valued empty composite actually takes on the wire.
        let ct: AesCipherText = CipherText::Map(vec![
            (
                "tags".into(),
                CipherText::EmptySequence(vec![1u8; 8].into()),
            ),
            ("meta".into(), CipherText::EmptyMap(vec![2u8; 8].into())),
            ("email".into(), CipherText::Single(vec![3u8; 40].into())),
        ]);
        match ct_round_trip(ct) {
            CipherText::Map(entries) => {
                let kinds: Vec<_> = entries
                    .iter()
                    .map(|(k, v)| {
                        let kind = match v {
                            CipherText::EmptySequence(_) => "eseq",
                            CipherText::EmptyMap(_) => "emap",
                            CipherText::Single(_) => "single",
                            _ => "other",
                        };
                        (k.as_str(), kind)
                    })
                    .collect();
                assert_eq!(
                    kinds,
                    vec![("tags", "eseq"), ("meta", "emap"), ("email", "single")]
                );
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    /// Wrap a leaf ciphertext node in `n` nested single-element sequences.
    fn nested_ciphertext(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.push(CT_SEQ);
            bytes.extend_from_slice(&1u32.to_le_bytes());
        }
        bytes.push(CT_SINGLE);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0xAB);
        bytes
    }

    #[test]
    fn ciphertext_depth_bound_is_exact() {
        // Same bound as the value decoder, checked at the boundary so the
        // comparison itself is pinned.
        let ok = nested_ciphertext(MAX_DEPTH);
        assert!(
            decode_ciphertext_boxed::<vitaminc_aead::LocalCipherText>(&mut Reader::new(&ok))
                .is_ok()
        );
        let too_deep = nested_ciphertext(MAX_DEPTH + 1);
        assert!(
            decode_ciphertext_boxed::<vitaminc_aead::LocalCipherText>(&mut Reader::new(&too_deep))
                .is_err()
        );
    }

    /// Wrap a leaf ciphertext node in `n` nested single-entry maps.
    fn nested_ciphertext_map(n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..n {
            bytes.push(CT_MAP);
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(b'k');
        }
        bytes.push(CT_SINGLE);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0xAB);
        bytes
    }

    /// `n` nested value-node passthroughs behind a single ciphertext
    /// passthrough marker — the route from the ciphertext tree into the value
    /// decoder, which must keep charging depth.
    fn ciphertext_passthrough_nest(n: usize) -> Vec<u8> {
        let mut bytes = vec![CT_PASSTHROUGH];
        bytes.extend_from_slice(&vec![PASSTHROUGH; n]);
        bytes.push(tags::NULL);
        bytes
    }

    #[test]
    fn ciphertext_map_nesting_counts_against_the_depth_bound() {
        let ok = nested_ciphertext_map(MAX_DEPTH);
        assert!(
            decode_ciphertext_boxed::<vitaminc_aead::LocalCipherText>(&mut Reader::new(&ok))
                .is_ok()
        );
        let too_deep = nested_ciphertext_map(MAX_DEPTH + 1);
        assert!(
            decode_ciphertext_boxed::<vitaminc_aead::LocalCipherText>(&mut Reader::new(&too_deep))
                .is_err()
        );
    }

    #[test]
    fn ciphertext_passthrough_carries_depth_into_the_value_decoder() {
        // The passthrough payload is decoded one level deeper, so the value
        // nesting behind it shares the ciphertext tree's budget rather than
        // restarting it.
        let ok = ciphertext_passthrough_nest(MAX_DEPTH - 1);
        assert!(
            decode_ciphertext_boxed::<vitaminc_aead::LocalCipherText>(&mut Reader::new(&ok))
                .is_ok()
        );
        let too_deep = ciphertext_passthrough_nest(MAX_DEPTH);
        assert!(
            decode_ciphertext_boxed::<vitaminc_aead::LocalCipherText>(&mut Reader::new(&too_deep))
                .is_err()
        );
    }

    #[test]
    fn ciphertext_map_keys_are_read_per_entry() {
        // Differently-sized keys in one map: an arithmetic slip in the key
        // framing desynchronises the reader.
        let ct: AesCipherText = CipherText::Map(vec![
            ("a".into(), CipherText::Single(vec![1u8; 4].into())),
            ("bcd".into(), CipherText::Single(vec![2u8; 4].into())),
        ]);
        match ct_round_trip(ct) {
            CipherText::Map(entries) => {
                let keys: Vec<_> = entries.iter().map(|(k, _)| k.as_str()).collect();
                assert_eq!(keys, vec!["a", "bcd"]);
            }
            other => panic!("expected Map, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Passthrough over the wire
    // ---------------------------------------------------------------

    #[test]
    fn passthrough_marker_is_pinned() {
        // PASSTHROUGH (0x12) then the wrapped value node.
        assert_eq!(
            encoded(FfiValue::Passthrough(Box::new(FfiValue::Null))),
            [0x12, 0x00]
        );
        assert_eq!(
            encoded(FfiValue::Passthrough(Box::new(FfiValue::Int32(-1)))),
            [0x12, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn passthrough_value_round_trips() {
        // Passthrough at array/object positions and wrapping a whole subtree.
        let make = || {
            FfiValue::Object(vec![
                (
                    "id".into(),
                    FfiValue::Passthrough(Box::new(FfiValue::Int64(42))),
                ),
                (
                    "meta".into(),
                    FfiValue::Passthrough(Box::new(FfiValue::Array(vec![
                        string("a"),
                        FfiValue::Bool(true),
                    ]))),
                ),
                ("email".into(), string("sealed-elsewhere")),
            ])
        };
        let bytes = encoded(make());
        let decoded = decode_value(&mut Reader::new(&bytes)).expect("codec");
        assert_eq!(encoded(decoded), bytes);
    }

    #[test]
    fn truncated_passthrough_node_is_rejected() {
        // A PASSTHROUGH marker with no value node behind it.
        assert!(decode_value(&mut Reader::new(&[PASSTHROUGH])).is_err());
    }

    #[test]
    fn passthrough_depth_bomb_is_rejected() {
        // Nesting exclusively through passthrough markers must still hit the
        // recursion bound.
        let mut bytes = vec![PASSTHROUGH; MAX_DEPTH + 2];
        bytes.push(tags::NULL);
        assert!(decode_value(&mut Reader::new(&bytes)).is_err());
    }

    #[test]
    fn passthrough_crosses_the_ciphertext_transport() {
        // A passthrough with an FfiValue payload round-trips through the
        // ciphertext transport once the Box payload type is re-homed.
        let ct: AesCipherText = CipherText::Map(vec![
            (
                "id".into(),
                CipherText::Passthrough(Box::new(FfiValue::Int64(42))),
            ),
            ("email".into(), CipherText::Single(vec![9u8; 40].into())),
        ]);
        let mut out = Vec::new();
        encode_ciphertext_boxed(ct, &mut out).expect("codec");
        let decoded: AesCipherText =
            decode_ciphertext_boxed(&mut Reader::new(&out)).expect("codec");
        let mut out2 = Vec::new();
        encode_ciphertext_boxed(decoded, &mut out2).expect("codec");
        assert_eq!(out, out2);
    }

    #[test]
    fn foreign_passthrough_payload_cannot_cross() {
        // A boxed payload that is not an FfiValue cannot be serialized as a
        // value node; re-homing rejects it rather than emitting garbage.
        let ct: AesCipherText = CipherText::Passthrough(Box::new(42u32));
        let mut out = Vec::new();
        assert_eq!(encode_ciphertext_boxed(ct, &mut out), Err(CodecError));
    }
}

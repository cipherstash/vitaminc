//! Leaf type tags — the cross-language wire commitment.
//!
//! Every scalar [`Value`](crate::Value) seals as `[tag] ++ payload`
//! **inside** the AEAD envelope, so the tag is authenticated: flipping a
//! value's type requires forging the AEAD authentication tag. Containers
//! (arrays, objects) are structural — they use the cipher's sequence and map
//! modes and carry no tag.
//!
//! # ⚠️ Frozen wire format
//!
//! These constants and their payload encodings are shared by every language
//! binding and are pinned byte-for-byte by known-answer tests. Changing one
//! breaks decryption of existing ciphertexts everywhere. New types must be
//! assigned **new** tags; tags are never reused or renumbered.

/// Null (JS `null`, Python `None`, Go `nil`). No payload.
pub const NULL: u8 = 0x00;
/// JavaScript `undefined`. No payload. Languages without an analog decode
/// this to their null value and never encode it.
pub const UNDEFINED: u8 = 0x01;
/// Boolean `false`. No payload — the value is the tag.
pub const BOOL_FALSE: u8 = 0x02;
/// Boolean `true`. No payload.
pub const BOOL_TRUE: u8 = 0x03;
/// 32-bit signed integer: 4 bytes, two's-complement, little-endian. Exists
/// for schema fidelity with Postgres `int4` at the EQL layer (not byte
/// savings) — integer-typed languages keep 16/32-bit values distinct from
/// [`INT64`].
pub const INT32: u8 = 0x04;
/// 64-bit signed integer: 8 bytes, two's-complement, little-endian.
/// Distinct from [`FLOAT64`] so integer-typed languages (Python, Go)
/// round-trip integers as integers.
pub const INT64: u8 = 0x05;
/// 32-bit unsigned integer: 4 bytes, little-endian. Exists for schema
/// fidelity with Postgres unsigned/`int4`-range values at the EQL layer.
pub const UINT32: u8 = 0x06;
/// 64-bit unsigned integer: 8 bytes, little-endian. Distinct from
/// [`INT64`] so unsigned values above `i64::MAX` (which [`INT64`] cannot
/// represent) round-trip losslessly without widening to [`UINT128`].
pub const UINT64: u8 = 0x07;
/// 32-bit floating-point number: 4 bytes, IEEE-754 binary32 bit pattern,
/// little-endian. Raw bits (not a numeric encoding) so `NaN` payloads and
/// `-0.0` survive round trips. Exists for schema fidelity with Postgres
/// `float4` at the EQL layer.
pub const FLOAT32: u8 = 0x08;
/// 64-bit floating-point number: 8 bytes, IEEE-754 binary64 bit pattern,
/// little-endian. Raw bits (not a numeric encoding) so `NaN` payloads and
/// `-0.0` survive round trips. This is the tag a JavaScript `number` maps
/// to.
pub const FLOAT64: u8 = 0x09;
/// String: UTF-8 bytes. Validated on decrypt.
pub const STRING: u8 = 0x0A;
/// Binary data: raw bytes.
pub const BYTES: u8 = 0x0B;

/// 8-bit signed integer: 1 bytes, little-endian (two's complement).
pub const INT8: u8 = 0x0C;
/// 8-bit unsigned integer: 1 bytes, little-endian.
pub const UINT8: u8 = 0x0D;
/// 16-bit signed integer: 2 bytes, little-endian (two's complement).
pub const INT16: u8 = 0x0E;
/// 16-bit unsigned integer: 2 bytes, little-endian.
pub const UINT16: u8 = 0x0F;
/// 128-bit signed integer: 16 bytes, little-endian (two's complement).
pub const INT128: u8 = 0x10;
/// 128-bit unsigned integer: 16 bytes, little-endian.
pub const UINT128: u8 = 0x11;
/// Date: `i32` days from CE (0001-01-01 is day 1), little-endian.
pub const DATE: u8 = 0x12;
/// UTC timestamp: `i64` Unix seconds, then `u32` nanoseconds, little-endian.
/// Uses chrono's leap-second representation: nanos may exceed 999,999,999
/// only at a leap second (seconds modulo 60 is 59), and must be < 2,000,000,000.
pub const TIMESTAMP: u8 = 0x13;
/// Decimal: rust_decimal's 16-byte `serialize()` layout, preserving scale.
/// Little-endian flags (sign bit 31, scale in bits 16–23, at most 28), then
/// low, middle and high `u32` words of the 96-bit mantissa. Other flag bits
/// must be zero. This finite format has no NaN or infinity.
pub const DECIMAL: u8 = 0x14;

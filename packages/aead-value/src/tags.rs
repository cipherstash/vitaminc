//! Leaf type tags — the cross-language wire commitment.
//!
//! Every scalar [`FfiValue`](crate::FfiValue) seals as `[tag] ++ payload`
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
/// Floating-point number: 8 bytes, IEEE-754 binary64 bit pattern,
/// little-endian. Raw bits (not a numeric encoding) so `NaN` payloads and
/// `-0.0` survive round trips.
pub const NUMBER: u8 = 0x04;
/// String: UTF-8 bytes. Validated on decrypt.
pub const STRING: u8 = 0x05;
/// Binary data: raw bytes.
pub const BYTES: u8 = 0x06;
/// 64-bit signed integer: 8 bytes, two's-complement, little-endian.
/// Distinct from [`NUMBER`] so integer-typed languages (Python, Go)
/// round-trip integers as integers.
pub const INT64: u8 = 0x07;
/// 64-bit unsigned integer: 8 bytes, little-endian. Distinct from
/// [`INT64`] so unsigned values above `i64::MAX` (which [`INT64`] cannot
/// represent) round-trip losslessly — this closes the model's only
/// representational hole in the integer space.
pub const UINT64: u8 = 0x08;

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
//!
//! ## Governance note: this is v2 (post one-time pre-release renumber)
//!
//! This table was renumbered and renamed **once**, on 2026-07-25, before any
//! ciphertext had shipped, to widen the numeric family (adding fixed-width
//! 32-bit variants for schema fidelity with the EQL layer) and to give the
//! floating-point tag a language-neutral name (`FLOAT64`, formerly the
//! JS-centric `NUMBER`). Nothing was in the wild, so the renumber cost
//! nothing. **That was the last renumber.** From v2 onward the freeze is
//! absolute: the only permitted change is *appending* a new tag for a value
//! class that genuinely cannot be represented in the existing model.

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
/// represent) round-trip losslessly — this closes the model's only
/// representational hole in the integer space.
pub const UINT64: u8 = 0x07;
/// 32-bit floating-point number: 4 bytes, IEEE-754 binary32 bit pattern,
/// little-endian. Raw bits (not a numeric encoding) so `NaN` payloads and
/// `-0.0` survive round trips. Exists for schema fidelity with Postgres
/// `float4` at the EQL layer.
pub const FLOAT32: u8 = 0x08;
/// 64-bit floating-point number: 8 bytes, IEEE-754 binary64 bit pattern,
/// little-endian. Raw bits (not a numeric encoding) so `NaN` payloads and
/// `-0.0` survive round trips. This is the tag a JavaScript `number` maps
/// to (it was named `NUMBER` before the v2 renumber).
pub const FLOAT64: u8 = 0x09;
/// String: UTF-8 bytes. Validated on decrypt.
pub const STRING: u8 = 0x0A;
/// Binary data: raw bytes.
pub const BYTES: u8 = 0x0B;

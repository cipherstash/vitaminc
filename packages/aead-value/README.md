# vitaminc-aead-value

A language-neutral, self-describing value tree — [`FfiValue`] — for
encrypting dynamically typed values from host languages (JavaScript,
Python, Go, …) with the Vitamin-C AEAD traits.

Host-language bindings convert native values into `FfiValue` at the FFI
boundary; encryption and decryption then run against any
[`Cipher`]/[`Decipher`] implementation, on any thread (`FfiValue` is owned
and `Send`). Because every language converts through the same tree and the
same leaf encoding, a value encrypted from one language decrypts from any
other.

This crate is consumed by the per-language binding crates (e.g.
`vitaminc-aead-napi` for Node.js); applications normally use those rather
than this crate directly.

## The contract is the tag table, not this enum

The cross-language contract is the **frozen tag table plus the sealed leaf
encodings** (`[tag] ++ payload`, sealed inside the AEAD envelope). That
model — and only that model — is what every language binding agrees on.
`FfiValue` is simply Rust's materialization of it; a Go, Python, or
JavaScript binding implements the same model in whatever local shape fits
its language, not this enum.

The model is deliberately narrow — JSON/CBOR-class, not serde-class. It
carries a small, fixed set of value classes, and governs its own growth:

> A new tag is added only when a value class cannot be represented in the
> existing model, and requires a defined decode mapping for every supported
> language before it ships.

The numeric family is the worked example. It divides the number space by
both **signedness** and **width**: `INT32`/`INT64`/`UINT32`/`UINT64` for
exact integers and `FLOAT32`/`FLOAT64` for IEEE-754 values. The unsigned
tags close a genuine representational hole (values above `i64::MAX` had no
home); the 32-bit widths exist for **schema fidelity with the EQL layer**
(Postgres `int4`/`float4`), not byte savings, so an `int4` column
round-trips as a 32-bit value rather than silently widening. Every tag has
a defined Go/Python/JavaScript decode mapping (below).

> **Governance note — this table is v2.** It was renumbered and renamed
> once, on 2026-07-25, *before any ciphertext shipped*, to add the
> fixed-width 32-bit numeric variants and to rename the floating-point tag
> from the JS-centric `NUMBER` to the language-neutral `FLOAT64`. Nothing
> was in the wild, so the renumber cost nothing — and it was the **last**
> one. From v2 onward the freeze is absolute: the only permitted change is
> *appending* a new tag for a genuinely unrepresentable value class.

## Leaf encoding (cross-language wire commitment)

Scalar values seal as a one-byte type tag followed by the payload,
**inside** the AEAD envelope — the tag is authenticated, so an attacker
holding a ciphertext cannot flip a value's type without forging the
authentication tag. Arrays and objects are containers, not leaves: they map
onto the cipher's sequence and map modes and carry no tag of their own.

| Tag | Name | Payload |
|-----|------|---------|
| `0x00` | `NULL` | none |
| `0x01` | `UNDEFINED` | none |
| `0x02` | `BOOL_FALSE` | none |
| `0x03` | `BOOL_TRUE` | none |
| `0x04` | `INT32` | 4 bytes, two's-complement, little-endian |
| `0x05` | `INT64` | 8 bytes, two's-complement, little-endian |
| `0x06` | `UINT32` | 4 bytes, little-endian |
| `0x07` | `UINT64` | 8 bytes, little-endian |
| `0x08` | `FLOAT32` | 4 bytes, IEEE-754 binary32 bit pattern, little-endian |
| `0x09` | `FLOAT64` | 8 bytes, IEEE-754 binary64 bit pattern, little-endian |
| `0x0A` | `STRING` | UTF-8 bytes |
| `0x0B` | `BYTES` | raw bytes |

The float tags carry the **raw IEEE-754 bit pattern** (not a numeric
encoding), so `NaN` payloads and `-0.0` survive a round trip.

This table is a **frozen wire format**: changing a tag or payload encoding
breaks decryption of existing ciphertexts in every language. New types must
take new tags. The known-answer tests in this crate pin each encoding
byte-for-byte. (See the governance note above: the table was renumbered
once pre-release, on 2026-07-25, and is now frozen for good.)

## Cross-language type mapping

Each binding encodes its host language's semantics and documents its decode
mapping. The defining rules:

| `FfiValue` | JavaScript | Python | Go |
|---|---|---|---|
| `Null` | `null` | `None` | `nil` |
| `Undefined` | `undefined` | decodes as `None` | decodes as `nil` |
| `Bool` | `boolean` | `bool` | `bool` |
| `Int32` | decodes as `number` (never encoded — JS has no `int32`) | `int` | `int8`/`int16`/`int32` → encode; decodes as `int32` |
| `Int64` | encodes from `BigInt` that fits `i64`; decodes as `number` when within ±2⁵³, else `BigInt` | `int` | `int`/`int64` → encode; decodes as `int64` |
| `UInt32` | decodes as `number` (never encoded) | `int` | `uint8`/`uint16`/`uint32` → encode; decodes as `uint32` |
| `UInt64` | encodes from `BigInt` above `i64::MAX` that fits `u64`; decodes as `number` when ≤ 2⁵³−1, else `BigInt` | `int` | `uint`/`uint64`/`uintptr` → encode; decodes as `uint64` |
| `Float32` | decodes as `number` (exact widening; never encoded) | `float` | `float32` |
| `Float64` | `number` (always — integral JS numbers do **not** become an integer tag) | `float` | `float64` |
| `String` | `string` | `str` | `string` |
| `Bytes` | `Buffer`/`Uint8Array` | `bytes` | `[]byte` |
| `Array` | `Array` | `list` | `[]any` |
| `Object` | plain object | `dict` (string keys) | `map[string]any` |

`Undefined` exists for JavaScript round-trip fidelity; languages without an
analog decode it to their null value and never encode it.

**JavaScript.** A JS `number` always encodes as `Float64`, never an integer
tag — `42` and `42.0` are the same value in JS. Integer typing comes from
`BigInt`: one that fits `i64` encodes as `Int64`, one above `i64::MAX` that
fits `u64` encodes as `UInt64`, and anything larger is rejected. JS has no
32-bit numeric types, so it never *encodes* `Int32`/`UInt32`/`Float32`; on
decode it widens all of them to a JS `number` (a `Float32` widens exactly
via `f64::from(f32)`; 32-bit integers always fit `Number.MAX_SAFE_INTEGER`).

**Go.** Go maps **exactly in both directions**, unlike JS which widens on
decode: `INT32`↔`int32`, `UINT32`↔`uint32`, `FLOAT32`↔`float32`, and the
64-bit tags to their 64-bit Go types. Narrower Go integer kinds encode up to
the matching width (e.g. `int16`→`INT32`), and `uint`/`uintptr` map to
`UINT64`.

## Security notes

- String and byte leaves are held in `Protected`, so the Rust-side copies
  are wiped on drop. Copies owned by the host language's runtime (e.g. the
  V8 heap) are outside this crate's control.
- Object keys travel in the clear but are bound into each value's AAD via
  [`Aad::for_map_entry`], so keys in a stored ciphertext cannot be swapped
  or renamed undetected.
- Decryption failures are reported as [`Unspecified`] with no detail, as
  everywhere in Vitamin-C.

[`FfiValue`]: crate::FfiValue
[`Cipher`]: vitaminc_aead::Cipher
[`Decipher`]: vitaminc_aead::Decipher
[`Aad::for_map_entry`]: vitaminc_aead::Aad::for_map_entry
[`Unspecified`]: vitaminc_aead::Unspecified

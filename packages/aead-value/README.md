# vitaminc-aead-value

A language-neutral, self-describing value tree — [`Value`] — for
encrypting dynamically typed values from host languages (JavaScript,
Python, Go, …) with the Vitamin-C AEAD traits.

Host-language bindings convert native values into `Value` at the FFI
boundary; encryption and decryption then run against any
[`Cipher`]/[`Decipher`] implementation, on any thread (`Value` is owned
and `Send`). Because every language converts through the same tree and the
same leaf encoding, a value encrypted from one language decrypts from any
other.

`Value` is the value model for any Vitamin-C cipher, including Rust
applications and per-language bindings such as `vitaminc-aead-napi`.
`FfiValue` remains as a deprecated type alias for one release.

`Value::clone` makes a deep copy with fresh `Protected` storage for every
string and byte leaf, including those inside passthrough subtrees. The clone
is under the same custody as the original: protected leaves are wiped on
drop, and callers retain responsibility for any exposed plaintext.
`Value` and `ValueKind` are non-exhaustive; downstream matches must include
an arm for unsupported variants.

## The contract is the tag table, not this enum

The cross-language contract is the **frozen tag table plus the sealed leaf
encodings** (`[tag] ++ payload`, sealed inside the AEAD envelope). That
model — and only that model — is what every language binding agrees on.
`Value` is simply Rust's materialization of it; a Go, Python, or
JavaScript binding implements the same model in whatever local shape fits
its language, not this enum.

The model is deliberately narrow — JSON/CBOR-class, not serde-class. It
carries a small, fixed set of value classes, and governs its own growth:

> A new tag is added only when a value class cannot be represented in the
> existing model, and requires a defined decode mapping for every supported
> language before it ships.

The numeric family is the worked example. It divides the number space by
both **signedness** and **width**: 8-, 16-, 32-, 64- and 128-bit signed
and unsigned integers, plus `FLOAT32`/`FLOAT64` for IEEE-754 values. The unsigned
tags close a genuine representational hole (values above `i64::MAX` had no
home); the 32-bit widths exist for **schema fidelity with the EQL layer**
(Postgres `int4`/`float4`), not byte savings, so an `int4` column
round-trips as a 32-bit value rather than silently widening. Every tag has
an explicit payload encoding. The existing binding mappings are below;
the new kinds' host conversions are tracked in
[issue #375](https://github.com/cipherstash/vitaminc/issues/375) and must
be implemented before these kinds ship across languages.

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
| `0x0C` | `INT8` | 1 byte, two's complement |
| `0x0D` | `UINT8` | 1 byte |
| `0x0E` | `INT16` | 2 bytes, two's complement, little-endian |
| `0x0F` | `UINT16` | 2 bytes, little-endian |
| `0x10` | `INT128` | 16 bytes, two's complement, little-endian |
| `0x11` | `UINT128` | 16 bytes, little-endian |
| `0x12` | `DATE` | `i32` CE day count, little-endian (0001-01-01 is day 1) |
| `0x13` | `TIMESTAMP` | `i64` Unix seconds then `u32` nanoseconds, little-endian, UTC |
| `0x14` | `DECIMAL` | rust_decimal's 16-byte `serialize()`, preserving scale |

The float tags carry the **raw IEEE-754 bit pattern** (not a numeric
encoding), so `NaN` payloads and `-0.0` survive a round trip.

This table is a **frozen wire format**: changing a tag or payload encoding
breaks decryption of existing ciphertexts in every language. New types must
take new tags. The known-answer tests in this crate pin each encoding
byte-for-byte.

## Optional scalar payloads

Enable `chrono` for `Value::Date(chrono::NaiveDate)` and
`Value::Timestamp(chrono::DateTime<chrono::Utc>)`, or `rust_decimal` for
`Value::Decimal(rust_decimal::Decimal)`. Neither feature is enabled by
default. `ValueKind` names and tag constants remain available with all
feature configurations; decoding a disabled payload kind returns an error.

Dates use chrono's `num_days_from_ce`, including its supported BCE dates.
Timestamps preserve nanoseconds and chrono's leap-second representation:
nanoseconds may be at least one billion only when Unix seconds modulo 60 is
59, and must be below two billion. Out-of-range dates/times are rejected.

Decimals retain scale: `1.50` decrypts as `1.50`, with different bytes from
`1.5`. The payload has four little-endian `u32` words: flags, then the low,
middle and high words of the 96-bit mantissa. Flags have the sign in bit 31
and scale (0–28) in bits 16–23; all other bits must be zero. Invalid flags
or scale are rejected rather than masked or rounded. This finite type has
no NaN or infinity. No search-term normalization happens during encryption.

These optional scalars are inline values, like numbers; they do not use
`Protected` storage. Their external types do not implement `Zeroize`, so
`Value::zeroize` skips them. Strings and bytes retain protected custody.

Rust's primitive `i128` and `u128` also implement `Encrypt`/`Decrypt` in
`vitaminc-aead`: these statically typed values seal as 16 untagged
little-endian bytes. Use `Value::Int128`/`Value::UInt128` for tagged,
self-describing values. Both primitive types support `Protected` custody.

## Cross-language type mapping

Each binding encodes its host language's semantics and documents its decode
mapping. The defining rules:

| `Value` | JavaScript | Python | Go |
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

## Declaring a kind without a value

A binding often has to say what a field's values are before it has one.
[`ValueKind`] is the `Value` model without the payload: `bool`, `int32`,
`int64`, `uint32`, `uint64`, `float32`, `float64`, `string`, `bytes`,
`int8`, `uint8`, `int16`, `uint16`, `int128`, `uint128`, `date`,
`timestamp`, `decimal`, `array` and `object`. Those names are frozen wire format, like the tag
table. `Null`, `Undefined` and `Passthrough` have no kind: the first two
are single-valued, and passthrough is a transport choice, not a type.
`Value::kind` reports a value's kind, `ValueKind::holds` checks one,
and `ValueKind::tags` maps a kind to the tags above.

**Breaking:** `ValueKind::ALL` changes from `[ValueKind; 11]` to
`&'static [ValueKind]` so new kinds can be added without changing its type.
Iteration now yields `&ValueKind`; use `for &kind in ValueKind::ALL` or
`ValueKind::ALL.iter().copied()` when owned values are needed. Code requiring
the fixed-size array type must migrate to a slice.

## Transport compatibility

Transport framing uses `0xF0` (array), `0xF1` (object), and `0xF2`
(passthrough), leaving the lower tags available for future scalar kinds.
This changes the transport encoding; hosts and guests must ship together.
The frozen sealed leaf tags and stored ciphertext payloads are unchanged.

## Security notes

- String and byte leaves are held in `Protected`, so the Rust-side copies
  are wiped on drop. Copies owned by the host language's runtime (e.g. the
  V8 heap) are outside this crate's control.
- Object keys travel in the clear but are bound into each value's AAD via
  [`Context::for_map_entry`], so keys in a stored ciphertext cannot be swapped
  or renamed undetected.
- Decryption failures are reported as [`Unspecified`] with no detail, as
  everywhere in Vitamin-C.

[`Value`]: crate::Value
[`ValueKind`]: crate::ValueKind
[`Cipher`]: vitaminc_aead::Cipher
[`Decipher`]: vitaminc_aead::Decipher
[`Context::for_map_entry`]: vitaminc_aead::Context::for_map_entry
[`Unspecified`]: vitaminc_aead::Unspecified

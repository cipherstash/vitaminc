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
| `0x04` | `NUMBER` | 8 bytes, IEEE-754 binary64 bit pattern, little-endian |
| `0x05` | `STRING` | UTF-8 bytes |
| `0x06` | `BYTES` | raw bytes |
| `0x07` | `INT64` | 8 bytes, two's-complement, little-endian |

This table is a **frozen wire format**: changing a tag or payload encoding
breaks decryption of existing ciphertexts in every language. New types must
take new tags. The known-answer tests in this crate pin each encoding
byte-for-byte.

## Cross-language type mapping

Each binding encodes its host language's semantics and documents its decode
mapping. The defining rules:

| `FfiValue` | JavaScript | Python | Go |
|---|---|---|---|
| `Null` | `null` | `None` | `nil` |
| `Undefined` | `undefined` | decodes as `None` | decodes as `nil` |
| `Bool` | `boolean` | `bool` | `bool` |
| `Number` | `number` (always — integral JS numbers do **not** become `Int`) | `float` | `float64` |
| `Int` | encodes from `BigInt`; decodes as `number` when within ±2⁵³, else `BigInt` | `int` (error outside i64 range) | `int`/`int64` |
| `String` | `string` | `str` | `string` |
| `Bytes` | `Buffer`/`Uint8Array` | `bytes` | `[]byte` |
| `Array` | `Array` | `list` | `[]any` |
| `Object` | plain object | `dict` (string keys) | `map[string]any` |

`Undefined` exists for JavaScript round-trip fidelity; languages without an
analog decode it to their null value and never encode it.

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

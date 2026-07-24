# vitaminc-aead-napi

NAPI (Node-API) value bridge for the Vitamin-C AEAD encryption traits — the
building blocks for exposing `vitaminc` encryption to Node.js with a
robust, typed FFI boundary.

This crate provides the pieces a Node addon composes; it is **not** itself a
cdylib/npm package.

## What's here

- **`NapiValue`** — an owned, `Send`, self-describing representation of a JS
  value (`null`, `undefined`, booleans, numbers, strings, `Buffer`s, arrays,
  plain objects). JS values convert in on the JS thread; encryption and
  decryption then run against any [`Cipher`]/[`Decipher`] implementation on
  any thread, which keeps the API async-ready. Secret-bearing leaves are held
  in `Protected` so Rust-side copies are wiped on drop.
- **`Encrypt`/`Decrypt` impls for `NapiValue`** — leaves seal as a one-byte
  type tag plus payload *inside* the AEAD envelope, so a value's JS type
  round-trips and cannot be confused by tampering; arrays and objects map
  onto the cipher's sequence and map modes, preserving structure (object
  keys travel in the clear but are bound into each value's AAD).
- **`JsCipherText<Leaf, P>`** — projects the generic `CipherText` container
  onto plain JS values (`{ t, v }` nodes with `Buffer` leaves) and back.
  Only leaf ciphertexts have a byte-format commitment; how the projected
  tree is persisted (JSONB, BSON, …) is the application's choice.

## Safety notes

- The original copies of encrypted values in the V8 heap are owned by the
  JS engine and cannot be wiped from Rust.
- Property names that would touch the prototype chain (`__proto__`,
  `constructor`, `prototype`) are rejected in both directions.
- Errors carry no cryptographic detail (`Unspecified` at the trait layer).

[`Cipher`]: vitaminc_aead::Cipher
[`Decipher`]: vitaminc_aead::Decipher

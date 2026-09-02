# Changelog

All notable changes to `vitaminc-aead` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]


### Documentation

- docs(aead),refactor(encrypt): address decrypt-path review findings
- docs(aead),test(encrypt): document ContextTag limits; add negative-AAD tests
- write the `#[aead(...)]` reference once and inline it everywhere
- fix every broken intra-doc link and gate them in CI

### Features

- re-introduce ContextTag on the revised Cipher/Decipher traits
- add ContextTag::context + decrypt/decrypt_with_aad helper
- implement Encrypt/Decrypt for the Equatable controlled type
- authenticate map keys and accept runtime-derived keys
- shared generic CipherText container and typed passthrough currency
- self-describing decryption and passthrough re-homing
- NAPI value bridge crate for Node.js FFI encryption
- authenticated wire-version byte on every ciphertext leaf
- add Aad::for_leaf_type expectation-side type binding
- add type-erased passthrough channel for self-describing values
- carry unencrypted subtrees via FfiValue::Passthrough
- add Element wrapper for row-at-a-time sequence access
- derive Encrypt and Decrypt so structs need no hand-written impls
- store chosen fields in the clear with #[aead(passthrough)]
- add NonEmpty context wrapper checked once at construction

### Fixes

- authenticate empty composite values
- close marker and passthrough authentication bypasses
- authenticate container shape and reject duplicate map keys on decrypt
- bind the outer key of static nested map entries
- keep hostile input from leveraging quadratic scans and eager reservations
- close the derive's three review findings and pin the guards with trybuild
- let a decipher without passthrough inherit a refusal
- judge context emptiness before encoding, and align conversion coverage

### Refactoring

- thread AAD through the decrypt path to mirror encrypt
- align ContextTag::aad_with arg order with encrypt_with_aad
- address ContextTag decrypt-helper review
- merge duplicate HashMap Encrypt impls into one generic impl
- capture composite AAD once at sub-cipher construction
- route fixed-array sealing through CipherTextBuilder
- move leaf-type AAD binding into aead-value as an IntoAad type
- move Decrypt into its own module to mirror Encrypt

### Testing

- close Tier-1 cargo-mutants gaps (ConstantTimeEq, PAE invariant)
- close remaining Tier-1 cargo-mutants gaps (ts_ne, zeroize, read_nonce, hlist CI)
- address code-review findings on the Tier-1 mutation fixes
- test(aead),test(encrypt): close ContextTag coverage gaps from review
- cover passthrough re-homing and exempt the untestable NAPI boundary
- close the CRAP and mutants gate gaps in the NAPI bridge PR
- pin the defaulted MapAccess::next_entry and its contract


### Documentation

- rewrite READMEs for revised Cipher/Decipher traits
- rustdoc public items and link TODOs to tracking issues

### Features

- revised Cipher/Decipher traits with visitor pattern
- add encrypt_some/encrypt_none/passthrough
- add HList-based static cipher shape behind `hlist` feature

### Fixes

- enforce MapCipher key→value pairing; route u32 via array path
- address #175 review on the hlist static cipher

### Refactoring

- address PR #148 review feedback
- thread Protected<T> through cipher boundary
- thread Protected<T> through the hlist Cipher boundary

### Style

- cargo fmt


### Features

- add IntoAad impls for [u8; N] and &[u8; N]

### Testing

- assert None IntoAad produces PAE zero-piece encoding


### Documentation

- update doctests to show vitaminc::* import paths


### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- bump quickcheck from 1.0.3 to 1.1.0
- release v0.1.0-pre4.1


### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- bump quickcheck from 1.0.3 to 1.1.0

### Added

- `Encrypt` and `Decrypt` traits with lifetime at the trait level (`Encrypt<'a>`)
  to support borrowed AAD like `&str` without higher-ranked trait bounds.
- `ContextTag` for binding AAD to plaintext values at the type level, with
  `refine()` for building hierarchical context.
- `ContextTag::decrypt` and `ContextTag::decrypt_with_aad` for symmetric
  decryption without exposing internal AAD encoding details.
- PAE (Pre-Authentication Encoding) for compound AAD types, preventing
  canonicalization attacks where different AAD components could produce
  identical byte strings.

### Changed

- **Breaking:** Tuple `(A, B)` AAD is now PAE-encoded instead of naively
  concatenated. Existing ciphertexts encrypted with tuple AAD will not decrypt.
- **Breaking:** `Option<T>` AAD is now domain-separated using PAE.
  `None` encodes as `PAE([])` and `Some(v)` encodes as `PAE([v])`, making them
  distinct from each other, from `()`, and from bare values. Existing
  ciphertexts encrypted with `Option<T>` AAD will not decrypt.
- **Breaking:** `ContextTag` fields `inner` and `aad` are now private.
  Use `ContextTag::new()` to construct values.

### Removed

- **Breaking:** `Extend<u8>` impl for `Aad`. This prevented bypassing PAE
  encoding by manually extending AAD with raw bytes.

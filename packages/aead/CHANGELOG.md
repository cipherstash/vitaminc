## [0.2.0] - 2026-09-02

### Breaking

- **Breaking:** Ciphertexts sealed by earlier versions no longer decrypt. Structural authentication changed on every path — map values are now sealed against their key, sequence elements against a labelled per-position derivation, and empty/absent markers under their own domain. Re-encrypt before upgrading; there is no migration path and none is planned before 1.0.
- **Breaking:** Every leaf now carries an authenticated wire-version byte (`version ‖ nonce ‖ ciphertext ‖ tag`). Unknown versions are rejected at parse time, and because the byte is bound under the tag, relabelling a stored leaf fails verification rather than selecting different parsing rules. `LocalCipherText::wire_version` is a keyless peek, so operators and migration tooling can tell an old-format record from a current one on a decrypt failure.
- **Breaking:** Map keys are authenticated. They travel in the clear but are now cryptographically inseparable from their value, so a stored ciphertext's keys can no longer be swapped or renamed to reassign encrypted values to different fields.
- **Breaking:** `decrypt_map` rejects duplicate keys before the visitor sees any entry. Both copies of a duplicated key verify under the same AAD, so a last-wins visitor let an attacker splice one stale field into an otherwise-current ciphertext.
- **Breaking:** Composites containing only passthrough items are refused on both the encrypt and decrypt sides. They previously carried no AEAD tag at all, decrypted under any AAD, and as a map value re-opened the key-renaming attack.
- **Breaking:** `Decrypt` takes AAD symmetrically with `Encrypt`, and `Cipher::encrypt_seq`/`encrypt_map` take the AAD once when the sub-cipher is built — `encrypt_next`, `encrypt_value`, `encrypt_entry` and `end` no longer take their own. A hand-written impl can no longer thread one AAD to the elements and a different one to the empty marker, which used to produce a ciphertext that encrypted fine and was unreadable on the first empty collection in production.
- **Breaking:** `CipherText<Leaf, P>` replaces the per-cipher ciphertext containers, and a `Passthrough` associated type replaces the `T: Any` generics on the passthrough methods, so a cipher declares its passthrough currency once and FFI ciphers can carry an owned host value with no type erasure. `AesCipherText` is now an alias for it — pattern matches and variant construction are unaffected.
- **Breaking:** `StaticMapBuilder::nested_entry` builds its inner map through a closure instead of attaching a pre-built one. A renamed outer key or a nested map spliced from another record now fails at every inner open.

Sequence element order and membership are still deliberately unauthenticated — retrieval order differs from insertion order for the database-record use case. The residual caller obligations are documented on `decrypt_seq` and `decrypt_map`.

### Features

- Derive `Encrypt` and `Decrypt` on your own structs instead of hand-writing impls, which is also what keeps two same-typed fields from being swappable in stored ciphertext. Fields that should stay readable are marked `#[aead(passthrough)]`.
- `ContextTag` returns on the revised `Cipher`/`Decipher` traits, with `context` plus `decrypt`/`decrypt_with_aad` helpers, and `NonEmpty` makes an AAD context's non-emptiness a type-level guarantee checked once at construction.
- `Encrypt`/`Decrypt` for the `Equatable` controlled type.
- Map keys can now be derived at runtime: the entry methods accept any `Into<Cow<'static, str>>`, and `HashMap<String, T>` gained an `Encrypt` impl to match the existing `Decrypt`.
- `Element` wraps row-at-a-time sequence access, and `Aad::for_leaf_type` binds a leaf's declared type on the expectation side.

### Fixes

- Hostile input can no longer drive quadratic scans or eager allocations during decode.

# Changelog

All notable changes to `vitaminc-aead` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]


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

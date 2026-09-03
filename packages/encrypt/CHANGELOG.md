
## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** thread AAD through the decrypt path to mirror encrypt
- **Breaking:** authenticate map keys and accept runtime-derived keys
- **Breaking:** close marker and passthrough authentication bypasses
- **Breaking:** capture composite AAD once at sub-cipher construction
- **Breaking:** shared generic CipherText container and typed passthrough currency
- **Breaking:** authenticate container shape and reject duplicate map keys on decrypt
- **Breaking:** authenticated wire-version byte on every ciphertext leaf
- **Breaking:** bind the outer key of static nested map entries

### Documentation

- correct stale #181 zeroize note on Aes256Cipher::open
- fix fabricated APIs, wrong metadata, and stale claims; add SECURITY.md
- write the `#[aead(...)]` reference once and inline it everywhere
- correct two comments the custody work outdated
- correct doc claims flagged by review

### Features

- expose Aes256Cipher::decipher to construct a Decipher
- re-introduce ContextTag on the revised Cipher/Decipher traits
- add ContextTag::context + decrypt/decrypt_with_aad helper
- self-describing decryption and passthrough re-homing
- add type-erased passthrough channel for self-describing values
- carry unencrypted subtrees via FfiValue::Passthrough
- add Element wrapper for row-at-a-time sequence access
- derive Encrypt and Decrypt so structs need no hand-written impls
- store chosen fields in the clear with #[aead(passthrough)]

### Fixes

- authenticate empty composite values
- address review findings across the FFI value stack
- keep hostile input from leveraging quadratic scans and eager reservations
- require an empty payload when verifying absence markers
- close the derive's three review findings and pin the guards with trybuild

### Performance

- borrow AAD per seq/map element instead of cloning
- seal fixed-width arrays without a reallocating copy


### Documentation

- rewrite READMEs for revised Cipher/Decipher traits
- rustdoc public items and link TODOs to tracking issues
- document Key SAFETY, map dedup posture, nested Option shape

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

### Testing

- cover AesMapCipher key→value contract
- close coverage gaps from #174 review

### Style

- cargo fmt


### CI

- test both AES-256-GCM backends on every PR

### Documentation

- document wasm32 support and dual cryptographic backend

### Features

- add wasm32 support via RustCrypto backend

### Miscellaneous

- bump aws-lc-rs from 1.16.1 to 1.16.2
- bump aws-lc-rs from 1.16.2 to 1.16.3

### Refactoring

- tighten backend abstraction

### Testing

- add cross-backend KAT for AES-256-GCM byte parity
- exercise wasm32 codegen via wasm-pack and enable zeroize
- add deterministic round-trip tests for wasm32 path

### Style

- apply rustfmt to KAT test


### Documentation

- update doctests to show vitaminc::* import paths


### Miscellaneous

- bump aws-lc-rs from 1.14.1 to 1.15.0
- bump aws-lc-rs from 1.15.0 to 1.15.1
- bump quickcheck from 1.0.3 to 1.1.0
- release v0.1.0-pre4.1


### Miscellaneous

- bump aws-lc-rs from 1.14.1 to 1.15.0
- bump aws-lc-rs from 1.15.0 to 1.15.1
- bump quickcheck from 1.0.3 to 1.1.0



### Documentation

- correct stale #181 zeroize note on Aes256Cipher::open
- docs(aead),refactor(encrypt): address decrypt-path review findings
- docs(aead),test(encrypt): document ContextTag limits; add negative-AAD tests
- fix fabricated APIs, wrong metadata, and stale claims; add SECURITY.md

### Features

- expose Aes256Cipher::decipher to construct a Decipher
- re-introduce ContextTag on the revised Cipher/Decipher traits
- add ContextTag::context + decrypt/decrypt_with_aad helper

### Miscellaneous

- rustfmt context_tag test to satisfy CI

### Performance

- borrow AAD per seq/map element instead of cloning

### Refactoring

- thread AAD through the decrypt path to mirror encrypt
- tidy decrypt AAD path per code review
- align ContextTag::aad_with arg order with encrypt_with_aad
- address ContextTag decrypt-helper review

### Testing

- split test-module cfg so cargo-mutants skips it
- add positive AAD roundtrip for the sequence path
- test(aead),test(encrypt): close ContextTag coverage gaps from review
- cover Equatable AEAD round-trip and tamper axes


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

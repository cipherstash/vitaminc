
## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** Ciphertexts written by 0.2.0-pre.1 do not decrypt with this release: every leaf carries an authenticated wire-version byte, container shape and map keys are authenticated, and AAD encodings changed. Re-encrypt prerelease data; there is no migration path.
- **Breaking:** Decryption requires the AAD used at encrypt time; duplicate map keys are rejected on decrypt; absence markers must carry an empty payload.
- **Breaking:** Ciphertexts use the shared generic `CipherText<Leaf, P>` container with a typed `Passthrough` currency; code built against the old concrete container needs updating.

### Features

- `Aes256Cipher::decipher` constructs a `Decipher` directly.
- `ContextTag` on the revised traits with `context`, `decrypt` and `decrypt_with_aad` helpers.
- Self-describing decryption and passthrough re-homing, `Element` for row-at-a-time sequence access, and struct `#[derive(Encrypt, Decrypt)]` including `#[aead(passthrough)]` clear fields.

### Fixes

- Empty composites are authenticated; hostile input can no longer force quadratic scans or eager allocations during decode.

### Performance

- AAD is borrowed per sequence/map element instead of cloned; fixed-width arrays seal without a reallocating copy.

### Documentation

- READMEs and rustdoc corrected (fabricated APIs, stale zeroize claims); SECURITY.md added.


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

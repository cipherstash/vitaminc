## [0.2.0] - 2026-09-02

### Breaking

- **Breaking:** Ciphertexts sealed by earlier versions no longer decrypt — the leaf format gained an authenticated wire-version byte and structural authentication changed on every path. Re-encrypt before upgrading; there is no migration path and none is planned before 1.0.
- **Breaking:** `Decrypt` takes AAD symmetrically with `Encrypt`, and sequence and map ciphers capture the AAD once at construction rather than per element and again at `end`. Hand-written impls need updating; see `vitaminc-aead` for the full trait changes.
- **Breaking:** `AesCipherText` is now an alias for the shared `CipherText<LocalCipherText, BoxedPassthrough>`. Pattern matches and variant construction are unaffected; boxed passthrough payloads come back out through `AesDecipher::decrypt_passthrough_as`.

### Features

- Derive `Encrypt` and `Decrypt` on your own structs, and keep chosen fields readable with `#[aead(passthrough)]`.
- `Aes256Cipher::decipher` constructs a `Decipher` directly, and `ContextTag` gains `context` plus `decrypt`/`decrypt_with_aad` helpers.
- Self-describing decryption re-homes passthrough values, and `Element` wraps row-at-a-time sequence access.

### Fixes

- Closed three authentication bypasses reachable by an attacker holding a stored ciphertext: all-passthrough composites carried no tag at all, a `Some` leaf could be laundered into a `None`, and absence markers were verified without checking their payload was empty.
- Map keys, container shape and empty composites are all authenticated now; `decrypt_map` rejects duplicate keys before the visitor sees an entry.

### Performance

- Fixed-width arrays seal without a reallocating copy, and sequence and map elements borrow their AAD instead of cloning it per element.



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

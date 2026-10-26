
## [0.8.1] - 2026-10-26

## [0.8.0] - 2026-10-21

### Breaking

- **Breaking:** A `None` of a fixed-width type sealed under this crate's cipher is now padded to a `Some`'s length, and a 0.7 reader refuses it (`vitaminc-aead` 0.8.0). An `Absent` is unchanged: an `Encrypted` holds bytes, which have no fixed width, so its absence is still the one-byte null and is not padded.

## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.
- **Breaking:** `Aes256Cipher` follows `vitaminc-aead` 0.6's new data model (ADR 0001). It implements the new `Cipher` trait (`seal` and `open` one leaf) and nothing else. For a caller upgrading from 0.5.1:
  - `encrypt(key, value)` becomes `encrypt_with_key(key, value)`. `encrypt` is now `vitaminc_aead::encrypt(value, &cipher, aad)`, re-exported here, with `decrypt::<T, _, _>(&cipher, ciphertext, aad)` and `decrypt_into`. `decrypt_with_key` is the one-shot form of `decrypt`.
  - `Aes256Cipher::decrypt`, `decrypt_with_aad` and `decipher` are removed, with `AesDecipher`, `AesSeqCipher`, `AesMapCipher`, `BoxedPassthrough` and `decrypt_passthrough_as`. A passthrough field is decrypted by its type's `Decrypt`.
  - `AesCipherText` is now `Node<LocalCipherText>`. Errors are `EncryptError` and `DecryptError` instead of `Unspecified`.
  - `Key` no longer implements `Encrypt`. Wrap a key with `key.wrap(&kek, aad)` and read it back with `Key::from_wrapped(&kek, wrapped, aad)`.
  - With the `hlist` feature, the static openers `open` and `open_entry` are renamed `open_encrypted` and `open_encrypted_entry`, so they no longer shadow `Cipher::open`.
- **Breaking:** 0.5.x ciphertext does not decrypt under 0.6.0, and 0.6.0 ciphertext does not decrypt under 0.5.x. Leaves are sealed under wire version 2 and their plaintext now starts with a type tag. 0.5's `Encrypt` path sealed raw, untagged bytes under version 1, so `Aes256Cipher`, `decrypt`, `decrypt_with_key` and the `hlist` openers refuse every version 1 leaf with `DecryptError::Cipher` (or `Unspecified`) rather than read the first byte of the value as a tag. There is no in-place upgrade: decrypt 0.5 data with 0.5 and encrypt it again with 0.6. This covers keys wrapped with 0.5 too.
- **Breaking:** with the `hlist` feature, `encrypt_bytes` seals a tagged bytes leaf and an absence is a null leaf sealed under the field's own AAD, the same leaves the sink-based path seals. A value and an absence cannot stand in for each other. Ciphertext from the 0.5 static cipher does not open.

### Security

- `Key` no longer implements `Encrypt`. In 0.5 any crate could walk a key into its own cipher and receive the key bytes. `Key::wrap` and `Key::from_wrapped` keep that walk inside this crate.

### Features

- `Aes256Cipher::opening_version_1()` gives a view that also opens version 1 leaves, for ciphertext from the tagged 0.5 `Value` path (`vitaminc-aead-value` and the Go binding). It still seals version 2. Do not use it for data from 0.5's `Encrypt` path: such a leaf can open as a different value with no error.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

### Fixes

- preserve Aad compatibility

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

# vitaminc

## 0.6.1 — 2026-10-18

## 0.6.0 — 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none. The `aws-kms` feature needs Rust 1.94.1, because `vitaminc-kms` carries the AWS SDK's floor.

### Features

- New `normalize` feature, which re-exports `vitaminc-normalize` as `vitaminc::normalize` (normalized equality terms for the plaintext data model). It also turns on the `aead` feature. With `prf` enabled as well, it turns on `vitaminc-prf`'s `normalize` feature, so `vitaminc::prf::EqualityTerm` is available and `vitaminc::normalize::Normalized` implements `vitaminc::prf::PrfValue`.
- New `ore` feature, which re-exports `vitaminc-ore` as `vitaminc::ore` (order terms for the plaintext data model). It turns on `normalize`.

## 0.5.1 — 2026-10-05

## 0.5.0 — 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

### Documentation

- show the typed context in the Element example, not the raw-byte escape hatch

## 0.4.0 — 2026-09-12

## 0.3.0 — 2026-09-07

## 0.2.0 — 2026-09-03

### Features

- Structured PRF support: the `prf` feature exposes `vitaminc-prf` and the `vitaminc-hmac` HMAC-SHA256 backend, and works standalone without other features.

### Fixes

- PRF keys must be full strength — keys shorter than 32 bytes are rejected.

### Documentation

- READMEs and rustdoc corrected (fabricated APIs, stale claims); SECURITY.md added.




### Refactoring

- normalize vitaminc re-exports to module aliases


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

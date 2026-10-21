
## [0.8.0] - 2026-10-21

### Breaking

- **Breaking:** give every null an equality term so the index no longer shows which values were absent

## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.

### Features

- The backend derives the new equality terms from `vitaminc-prf` (`Normalized` and `EqualityTerm`, behind `vitaminc-prf`'s `normalize` feature) with no change to its own API. Every equality domain is pinned by an HMAC known-answer vector. Output for the inputs 0.5.1 accepted is unchanged, so terms you stored with 0.5.1 still match.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

First release.

### Features

- Local HMAC-SHA256 backend for the vitaminc structured PRF. The PRF owns its key, wipes it when dropped, and is deliberately not `Clone` — wrap it in `Arc` to share. Construct through `PrfKeyInit` (`new` / `try_from_bytes`).
- Keys shorter than 32 bytes are rejected with `WeakKeyError`; HMAC itself would silently accept them.

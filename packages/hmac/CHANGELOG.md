
## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** Construct `HmacSha256Prf` through the `PrfKeyInit` trait (`new` / `try_from_bytes`) — the inherent constructors are gone, so import the trait. The PRF owns its key, wipes it when dropped, and is deliberately not `Clone`; wrap it in `Arc` to share.
- **Breaking:** Keys shorter than 32 bytes are rejected with `WeakKeyError` instead of silently accepted.

### Features

- The HMAC-SHA256 structured-PRF backend now lives in its own crate.

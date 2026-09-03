
## [0.2.0] - 2026-09-03

First release.

### Features

- Local HMAC-SHA256 backend for the vitaminc structured PRF. The PRF owns its key, wipes it when dropped, and is deliberately not `Clone` — wrap it in `Arc` to share. Construct through `PrfKeyInit` (`new` / `try_from_bytes`).
- Keys shorter than 32 bytes are rejected with `WeakKeyError`; HMAC itself would silently accept them.

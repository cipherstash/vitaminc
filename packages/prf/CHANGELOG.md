## [0.2.0] - 2026-09-02

### Features

- Structured PRF foundation: derive deterministic index terms from structured values under a keyed PRF, with duplicate map keys rejected at build time.
- `NonEmpty` contexts are checked once at construction rather than at each call site.

### Fixes

- Distinct values can no longer produce the same encoding: `Option` contexts carry an option-some domain tag, `refine` derives under its own domain tag, and `HashMap` terms derive in a deterministic order.
- Secret lifecycles are preserved through the digest path, and HMAC key-normalization temporaries are wiped.

### Performance

- Fixed-size leaves stream without heap copies.



## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** Derived values changed since 0.2.0-pre.1: `Option` contexts, `refine` chains and value encodings are now domain-separated, and `HashMap` terms derive in deterministic order. Terms derived with the prerelease will not match — re-derive anything persisted.
- **Breaking:** A PRF owns its key and is passed by reference to derivation; construct backends through `PrfKeyInit` (`new` / `try_from_bytes`) instead of handing keys to each call.

### Features

- Structured PRF foundation: derive terms over values, sequences and maps with typed, non-empty contexts (checked once at construction) and visitor-shaped drivers; duplicate map keys are rejected at build time.

### Fixes

- Key-normalization temporaries are wiped and protected secret lifecycles are preserved end to end.

### Performance

- Fixed-size leaves stream without heap copies.

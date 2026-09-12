
## [0.4.0] - 2026-09-12

### Breaking

- **Breaking:** `AadPiece` is the identity of a context on both derivations ([#338](https://github.com/cipherstash/vitaminc/pull/338))

## [0.3.0] - 2026-09-07

### Breaking

- **Breaking:** rename `IsEmpty` to `MaybeEmpty`

### Features

- `NonEmpty::with` and `From<integer>` for `NonEmpty`

## [0.2.0] - 2026-09-03

First release.

### Features

- Structured PRF foundation: derive terms over values, sequences and maps with typed, non-empty contexts (checked once at construction) and visitor-shaped drivers; duplicate map keys are rejected at build time.
- Domain separation throughout: `Option` contexts, `refine` chains and value encodings are domain-separated, and `HashMap` terms derive in a deterministic order.
- A PRF owns its key and derivation borrows it, so one instance serves any number of derivations; backends are constructed through `PrfKeyInit` (`new` / `try_from_bytes`).

### Performance

- Fixed-size leaves stream without heap copies.

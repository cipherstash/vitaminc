
## [0.4.0] - 2026-09-12

### Breaking

- **Breaking:** `Some(x)` PRF contexts now match equivalent runtime contexts built from `AadPiece`. Derived terms change for contexts containing `Some`; regenerate any saved terms using those contexts. `None` and optional-value encoding are unchanged. ([#338](https://github.com/cipherstash/vitaminc/pull/338))

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

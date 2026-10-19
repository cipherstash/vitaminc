
## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** `PrfError` is now `#[non_exhaustive]`. Add a wildcard arm to any exhaustive `match` on it.
- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.

### Features

- New `normalize` feature: equality terms for `vitaminc-aead`'s plaintext data model. `PrfValue` is implemented for `vitaminc_normalize::Normalized` (owned and borrowed). `EqualityTerm::new(logical, physical)` normalizes one scalar on the way in, for a single value such as a query parameter. A scalar with no equality term (a null, a boolean, an unknown logical type), text with a code point unassigned in Unicode 16, a value invalid for its logical type, or a `Normalized` with an empty domain fails with the new `PrfError::Normalize` instead of deriving anything. With the feature off, the crate does not depend on `vitaminc-normalize`, `vitaminc-aead` or the Unicode tables.
- These terms match equal values across widths: every integer width shares one domain, so a JavaScript `BigInt` read as `i8` matches the same number written as `i64` from Go, and `f32` and `f64` share one domain (an `f32` widens exactly, so `f32` 0.1 and `f64` 0.1 are different numbers and do not match). Integers and floats are separate, so a JavaScript `number` 5 does not match an `i64` 5. Text is Unicode 16 NFC with no case or accent folding.
- Terms from the existing `PrfValue` impls (`String`, `&str`, byte containers, `u8`..`i128`) are unchanged, so terms you stored with 0.5.1 still match. They use different domains from the `normalize` terms, so a `u32` derived through its built-in impl does not match the same number as a `Normalized` term. Use the same input API and context for writes and queries.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

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

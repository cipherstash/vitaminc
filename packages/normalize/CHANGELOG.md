
## [0.8.2] - 2026-10-26

## [0.8.1] - 2026-10-26

### Dependencies

- `orderable-bytes` 0.2.1. It changes no encoding, so every term is the same as 0.8.0's, and terms you stored still compare.

## [0.8.0] - 2026-10-21

Existing equality terms do not change: every domain label and encoding of 0.7 stays as it is, and the null term is a new label beside them. An index built by 0.7 holds a SQL `NULL` where a value was absent; 0.8 writes a term there instead. Both read correctly, but the rows 0.7 wrote still show their absences until they are re-indexed.

### Breaking

- **Breaking:** Every null, typed or plain, now has an equality term, under the new frozen domain `vitaminc/prf/value/null/v1` with the one byte `0x00`. A sealed `None` is now as long as a `Some` (`vitaminc-aead` 0.8.0), but the term column still held a SQL `NULL` exactly where a value was absent. So `normalize(None, Physical::Null)` succeeds where it returned `NoDomain`, and a walk over a value with a null returns one more term, at the null's path. A layer that must keep a SQL `NULL` for some column drops the term whose domain is `domain::NULL`; producing it is the default because dropping a term should be an explicit act. A boolean and an `undefined` still have no term. `domain::ALL` now lists nine labels.

### Features

- `NormalizeError::Reserved`, which an order space that places nulls returns for the one value it keeps for them (`vitaminc-ore` 0.8.0). `NormalizeError` is `#[non_exhaustive]`, so a match on it still compiles.

### Not guaranteed

- In an equality index the nulls are one more group of equal terms, as any repeated value is. That is never more than the SQL `NULL` it replaces, which needed no inference to read.

## [0.7.0] - 2026-10-20

### Fixes

- Each fixed-width and decimal encoder writes straight into the wiped buffer it returns, so no unwiped intermediate copy of an encoded value is made. The encoded bytes, and so stored terms, do not change.

### Not guaranteed

- `vitaminc_normalize::text` runs text through the `unicode-normalization` iterators, whose small internal buffers move to the heap as soon as a character's combining marks pass four code points (four marks followed by any character is enough), and are then freed without being wiped. This is outside this crate's control (#488).

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Features

- First release. `vitaminc-normalize` decides the equality terms for `vitaminc-aead`'s plaintext data model: for each scalar kind that can be indexed, a frozen domain label (the `domain` module) and an encoding to bytes. `normalize(logical, physical)` returns a `Normalized` (domain and protected bytes) that a PRF such as `vitaminc-prf` derives a term from. It has no cryptography.
- Equal values give equal terms whatever width or scale wrote them: every integer width shares one domain, `f32` widens exactly to `f64`, decimals normalize scale and signed zero, and timestamps in any unit truncate to microseconds. Values that only look alike do not match: a date, timestamp, decimal and uuid each have their own domain, separate from the physical value they are stored as. Text is Unicode 16 NFC with no case or accent folding. A code point unassigned in Unicode 16 is refused. A null, boolean or `undefined`, and any logical type the crate does not know, has no term (`NormalizeError::NoDomain`). The encodings are documented in the README and on `decimal`; changing one means a new domain label.
- `Terms` is a sink that collects one `Term` (path and normalized value) per indexable scalar. Run it beside encryption with `encrypt_with_terms` or `encrypt_with_terms_async`, which have every term before the first cipher call (and before the first await), with `plan_with_terms`, or alone with `terms`. `terms` refuses exactly what encryption refuses, at the same path: read a shape refusal with `TermsError::refusal`.
- A refused scalar is reported as a `TermError` holding the `NormalizeError`, the `Path` to the field and the index it was for. The error message names neither the field nor the value, because map keys can be user data; read the path with `TermError::path`. `Debug` masks the value of a `Normalized` or `Term`, and the map keys in a path.
- In a walk, a null, boolean or `undefined` produces no term and does not stop the walk. A logical type with no domain does stop it, so an index is never left silently incomplete.
- `Terms::by` and `terms_by` run the same walk under a normalizer of your own (the `Normalize` trait, which must be `Copy`). `vitaminc-ore`'s order index is the first.
- Text normalization is variable-time. The integer and float paths use no floating-point arithmetic.

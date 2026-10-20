
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

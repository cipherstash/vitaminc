
## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

### Breaking

- **Breaking:** rename `IsEmpty` to `MaybeEmpty`

### Documentation

- scope the Usage wipe claim to fields that carry drop glue
- stop describing map as an escape hatch
- spell out what `NonEmpty::with` does not do for the tail

### Features

- `NonEmpty::with` and `From<integer>` for `NonEmpty`
- keep `IsEmpty` as a deprecated alias for `MaybeEmpty`

### Fixes

- bound `NonEmpty::with` on `MaybeEmpty` and document its shape
- lift the `MaybeEmpty` bound from `with`'s tail; mark constructors `#[must_use]`

## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** Controlled types (`Protected`, `Equatable`, `Exportable`) now zeroize their contents on drop, and `Controlled` requires `Zeroize` ([#181](https://github.com/cipherstash/vitaminc/pull/181)). Payload types and custom `Controlled` impls must implement `Zeroize`.

### Features

- `NonEmpty` wrapper proves a context non-empty once, at construction; the `nonempty!` macro accepts byte strings and wider inputs, and `Cow` emptiness is judged generically.

### Fixes

- `ProtectedDigest` secret lifecycle hardened: digest state must implement `ZeroizeOnDrop`, and outputs write directly into protected or explicitly public destinations.

### Documentation

- READMEs and rustdoc corrected (fabricated APIs, stale claims); SECURITY.md added.

### Security

- require `ProtectedDigest` state to implement `ZeroizeOnDrop`
- write digest outputs directly into protected or explicitly public destinations

### Breaking changes

- remove return-by-value `ProtectedDigest` finalization helpers
- add explicit public input and output methods to `ProtectedDigest`



### Miscellaneous

- bump digest to 0.11 and sha2 to 0.11

### Style

- apply rustfmt to long array literal in conversions test


### Documentation

- update doctests to show vitaminc::* import paths


### Fixes

- replace bincode with rmp-serde in tests

### Miscellaneous

- bump serde_json from 1.0.145 to 1.0.149
- bump bincode from 1.3.3 to 3.0.0
- bump quickcheck from 1.0.3 to 1.1.0
- bump opaque-debug from 0.3.1 to 0.4.0
- release v0.1.0-pre4.1


### Fixes

- replace bincode with rmp-serde in tests

### Miscellaneous

- bump serde_json from 1.0.145 to 1.0.149
- bump bincode from 1.3.3 to 3.0.0
- bump quickcheck from 1.0.3 to 1.1.0
- bump opaque-debug from 0.3.1 to 0.4.0

## [0.2.0] - 2026-09-02

### Breaking

- **Breaking:** Controlled types wipe their contents on drop for `T: Zeroize` (#181). `Protected<T>` is no longer `Copy`, and the `Zeroize` bound propagates to code generic over it.
- **Breaking:** `TryIntoNonEmpty` is removed — a bare literal cannot be compile-checked through it. Use the `nonempty!` macro, which checks at compile time.

### Features

- `NonEmpty` wraps an AAD context and checks non-emptiness once at construction, so the guarantee travels in the type rather than being re-asserted at every call site.
- Compile-time byte-string contexts, a wider `nonempty!`, and generic `Cow` emptiness.

### Fixes

- Hardened the digest secret lifecycle, and `refine` now derives under its own domain tag.


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

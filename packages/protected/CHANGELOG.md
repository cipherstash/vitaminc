
## [0.2.0-pre.2] - 2026-09-03

### Documentation

- fix fabricated APIs, wrong metadata, and stale claims; add SECURITY.md

### Features

- add NonEmpty context wrapper checked once at construction
- compile-time byte-string contexts, wider nonempty!, generic Cow emptiness

### Fixes

- zeroize controlled types on drop ([#181](https://github.com/cipherstash/vitaminc/pull/181))
- harden digest secret lifecycle
- skip trybuild harness under Miri
- give refine its own domain tag

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

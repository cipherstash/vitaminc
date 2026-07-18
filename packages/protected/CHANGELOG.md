

### Documentation

- fix fabricated APIs, wrong metadata, and stale claims; add SECURITY.md

### Fixes

- zeroize controlled types on drop ([#181](https://github.com/cipherstash/vitaminc/pull/181))

### Refactoring

- move instead of copy in flatten_array
- single-source into_inner_unchecked; document drop-glue guarantees
- make move_inner_out a safe fn via an unsafe trait



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

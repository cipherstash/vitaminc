
## [0.2.0-pre.2] - 2026-09-03

### Breaking

- **Breaking:** extract language-neutral FfiValue crate with INT64 tag
- **Breaking:** renumber tag table to v2 and widen the numeric family

### Features

- NAPI value bridge crate for Node.js FFI encryption
- add UINT64 tag to close the unsigned-range hole
- carry unencrypted subtrees via FfiValue::Passthrough

### Fixes

- close prototype-chain, exotic-object, and allocation holes at the JS boundary
- address review findings across the FFI value stack

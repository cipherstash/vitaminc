

### Features

- NAPI value bridge crate for Node.js FFI encryption
- extract language-neutral FfiValue crate with INT64 tag
- add UINT64 tag to close the unsigned-range hole
- renumber tag table to v2 and widen the numeric family
- carry unencrypted subtrees via FfiValue::Passthrough

### Fixes

- close prototype-chain, exotic-object, and allocation holes at the JS boundary
- address review findings across the FFI value stack

### Testing

- cover passthrough re-homing and exempt the untestable NAPI boundary
- close the CRAP and mutants gate gaps in the NAPI bridge PR


## [0.6.0] - 2026-10-09

### Breaking

- **Breaking:** make the value model reusable
- **Breaking:** preserve extended scalar kinds
- **Breaking:** expose ValueKind::ALL as a slice
- **Breaking:** read ciphertext nodes from own fields and carry depth into payloads

### Documentation

- steer integer data to BigInt for equality terms

### Fixes

- keep scalar wrappers lossless and their errors typed
- close prototype and lossy-key leaks at the N-API boundary
- check ownership immediately before each property read
- measure and drop deep Rust-built trees without recursing

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

First release.

### Features

- Node.js FFI bridge: encrypt and decrypt JS values (null, undefined, booleans, numbers, strings, bytes, arrays, objects) through the `vitaminc-aead-value` tree, with unencrypted subtrees carried via passthrough.
- The JS boundary is hardened: prototype-chain keys (`__proto__`, `constructor`, `prototype`) are rejected in both directions, exotic objects are refused, and allocation limits apply.

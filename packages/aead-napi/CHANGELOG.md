
## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** make the value model reusable
- **Breaking:** preserve extended scalar kinds
- **Breaking:** expose ValueKind::ALL as a slice
- **Breaking:** read ciphertext nodes from own fields and carry depth into payloads
- **Breaking:** raise the MSRV to 1.88 and pin kms to the AWS SDK floor
- **Breaking:** walk live JavaScript values with JsRef and build them with JsBuilder
- **Breaking:** pin the ADR 0001 format changes in the corpus and carry them in Go
- **Breaking:** remove Encrypt, Decipher, DecipherVisitor, SeqAccess and MapAccess
- **Breaking:** name the source trait Encrypt so it pairs with Decrypt

### Documentation

- steer integer data to BigInt for equality terms
- name every runtime failure a derived type can still hit, and say an Encrypt

### Fixes

- keep scalar wrappers lossless and their errors typed
- close prototype and lossy-key leaks at the N-API boundary
- check ownership immediately before each property read
- measure and drop deep Rust-built trees without recursing
- refresh the napi addon and Go guest lockfiles for proc-macro-crate
- refresh the napi addon and Go guest lockfiles for futures-util
- keep the wrapper classes out of the addon's instance data and harden them
- free refused typed arrays and wipe every copy of text on the way in
- give the CRAP-exempt functions names no other function shares

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

First release.

### Features

- Node.js FFI bridge: encrypt and decrypt JS values (null, undefined, booleans, numbers, strings, bytes, arrays, objects) through the `vitaminc-aead-value` tree, with unencrypted subtrees carried via passthrough.
- The JS boundary is hardened: prototype-chain keys (`__proto__`, `constructor`, `prototype`) are rejected in both directions, exotic objects are refused, and allocation limits apply.


## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** The value types moved to the new `vitaminc-aead-value` crate and the tag table is v2 (`INT64`/`UINT64` added); values encoded with 0.2.0-pre.1 do not decode. Update imports and re-encode prerelease data.

### Features

- Node.js FFI bridge: encrypt and decrypt JS values (null, undefined, booleans, numbers, strings, bytes, arrays, objects), with unencrypted subtrees carried via passthrough.

### Fixes

- The JS boundary is hardened: prototype-chain keys (`__proto__`, `constructor`, `prototype`) are rejected in both directions, exotic objects are refused, and allocation limits apply.

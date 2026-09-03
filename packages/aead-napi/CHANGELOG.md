
## [0.2.0] - 2026-09-03

First release.

### Features

- Node.js FFI bridge: encrypt and decrypt JS values (null, undefined, booleans, numbers, strings, bytes, arrays, objects) through the `vitaminc-aead-value` tree, with unencrypted subtrees carried via passthrough.
- The JS boundary is hardened: prototype-chain keys (`__proto__`, `constructor`, `prototype`) are rejected in both directions, exotic objects are refused, and allocation limits apply.

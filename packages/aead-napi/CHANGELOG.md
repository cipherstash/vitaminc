## [0.2.0] - 2026-09-02

### Breaking

- **Breaking:** The value tag table is renumbered to v2 (see `vitaminc-aead-value`). JavaScript `number` now maps to `FLOAT64` and `BigInt` to `INT64`/`UINT64`; values encoded against the v1 table do not decode.

### Features

- Encrypt and decrypt dynamically typed JavaScript values from Node.js over the shared, language-neutral value model.
- Unencrypted subtrees cross the boundary as passthrough values.

### Fixes

- Closed prototype-chain, exotic-object and allocation holes at the JavaScript boundary.


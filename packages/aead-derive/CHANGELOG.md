## [0.2.0] - 2026-09-02

### Features

- `#[derive(Encrypt, Decrypt)]` generates the impls a struct previously needed by hand — which is also what stops two same-typed fields being swappable in stored ciphertext.
- `#[aead(passthrough)]` keeps chosen fields in the clear inside an otherwise encrypted value.

### Fixes

- Closed three review findings in the generated code, with the guards pinned by compile-fail tests.


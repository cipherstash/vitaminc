## [0.2.0] - 2026-09-02

### Breaking

- **Breaking:** The cross-language tag table is renumbered to v2 and is now frozen. The numeric family divides by signedness and width (`INT32`/`INT64`/`UINT32`/`UINT64`, `FLOAT32`/`FLOAT64`), so a Postgres `int4` column round-trips as a 32-bit value instead of silently widening, and float tags round-trip by raw IEEE-754 bit pattern so NaN payloads and `-0.0` survive. `NUMBER` is renamed `FLOAT64`. Values encoded against the v1 table do not decode.

### Features

- `FfiValue` is a language-neutral, self-describing value tree with an authenticated leaf wire format: a value encrypted from one language decrypts from any other. Known-answer tests pin every leaf encoding byte-for-byte as cross-language conformance vectors.
- Unencrypted subtrees travel as `FfiValue::Passthrough` and are framed by the transport codec, so a value can mix sealed and cleartext fields across an FFI boundary.

### Fixes

- Empty-composite markers survive the FFI transport instead of being dropped.
- The transport decoders reject duplicate keys.
- Hostile input can no longer drive quadratic scans or eager allocations during decode.


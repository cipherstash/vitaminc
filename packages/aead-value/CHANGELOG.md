
## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** The tag table is renumbered to v2 with a widened numeric family (`INT64`, `UINT64`); values encoded with the 0.2.0-pre.1 table do not decode. Re-encode prerelease data.
- **Breaking:** `FfiValue` now lives in this language-neutral crate, extracted from the NAPI bridge; update imports that pointed at `vitaminc-aead-napi`.

### Features

- Strings ride a dedicated `Utf8String` type and ciphertext leaves carry the authenticated wire-version byte.
- Unencrypted subtrees travel via `FfiValue::Passthrough`, framed in the transport codec, with the v2 numeric family propagated to the Go bindings and the wasm guest.
- Empty-composite markers survive the FFI transport round-trip.

### Fixes

- Transport decoders reject duplicate keys, and hostile input can no longer force quadratic scans or eager allocations.

### Documentation

- Intra-doc links fixed and gated in CI.

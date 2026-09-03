
## [0.2.0-pre.2] - 2026-09-03

### Breaking

- **Breaking:** extract language-neutral FfiValue crate with INT64 tag
- **Breaking:** renumber tag table to v2 and widen the numeric family

### Documentation

- fix every broken intra-doc link and gate them in CI
- correct two comments the custody work outdated

### Features

- add UINT64 tag to close the unsigned-range hole
- carry unencrypted subtrees via FfiValue::Passthrough
- propagate tag table v2 numeric family to Go and the guest
- frame passthrough values in the transport codec
- store chosen fields in the clear with #[aead(passthrough)]

### Fixes

- address review findings across the FFI value stack
- carry empty-composite markers across the FFI transport
- adopt Utf8String and the authenticated wire-version byte
- keep hostile input from leveraging quadratic scans and eager reservations
- reject duplicate keys in the transport decoders

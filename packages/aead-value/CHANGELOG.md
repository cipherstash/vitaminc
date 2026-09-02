

### Documentation

- fix every broken intra-doc link and gate them in CI
- correct two comments the custody work outdated

### Features

- extract language-neutral FfiValue crate with INT64 tag
- add UINT64 tag to close the unsigned-range hole
- renumber tag table to v2 and widen the numeric family
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

### Refactoring

- tighten tagged-leaf constructors per review
- move leaf-type AAD binding into aead-value as an IntoAad type
- split Go spike into durable vcvalue layer and reference harness
- derive Encrypt for Key and the tagged leaves

### Testing

- pin eager_capacity against constant-replacement mutants

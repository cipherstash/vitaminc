// Package vcvalue is the durable, dependency-free module of the vitaminc Go
// bindings: the value currency and its transport codec, with no dependency
// on wazero or any crypto. A future stack-encrypt Go SDK is expected to
// import this module for its encode/decode surface; the wasm reference
// harness (module vcencrypt) is only one consumer of it.
//
// # The model, not this package
//
// The cross-language contract is the frozen tag table plus the sealed leaf
// encodings ([tag] ++ payload, sealed inside the AEAD envelope) defined in
// the Rust crate vitaminc-aead-value. This package is Go's materialization
// of that model — the Encoder channels and the decode natives implement the
// model; they are not themselves the contract. A new tag is added only when
// a value class cannot be represented in the existing model, and requires a
// defined decode mapping for every supported language before it ships.
//
// # Encoding
//
// User types implement Encryptable to control their own sealing (Go's answer
// to Rust's Encrypt, since Go has no orphan impls). For everything else,
// Encode/Marshal walk Go values with encoding/json-style rules — builtins,
// slices, maps (keys sorted for deterministic structure), and structs (by
// field name, honoring `vc:"..."` tags). The Encoder is a recorder that
// writes the transport form; it is not a live cipher handle.
//
// # Passthrough
//
// Non-secret fields can travel in the clear (unencrypted and unauthenticated)
// beside the sealed ones. It never happens implicitly: reflection encode
// requires the Plain{V: ...} marker, and the Encoder exposes an explicit
// Passthrough() channel. A decoded passthrough field surfaces back as
// Plain{V: ...}, and a passthrough ciphertext node is KindPassthrough with a
// readable value.
//
// # Decoding
//
// Unmarshal turns value transport bytes into Go natives (nil, bool, the exact
// numeric widths, string, []byte, []any, the ordered Object type for maps, and
// Plain for passthrough). A reflection-based Unmarshal into caller structs is
// future work.
//
// # Transport, not storage
//
// The transport encoding here exists to hand a tree across an FFI boundary
// in one copy. It is NOT a storage format and carries no compatibility
// commitment; the only frozen bytes are the sealed leaves inside the AEAD
// envelope. Durable cross-language database interop is a schema-aware layer's
// job, which this package knows nothing about.
package vcvalue

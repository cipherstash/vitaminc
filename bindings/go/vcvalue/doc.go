// Package vcvalue is the durable, dependency-free module of the vitaminc Go
// bindings: the value model — the types application code holds and stores —
// with no dependency on wazero, any crypto, or any wire format. A future
// stack-encrypt Go SDK is expected to import this module; the wasm reference
// harness (module vcencrypt) is one consumer of it.
//
// # The model
//
//   - Plain{V: ...} marks (and surfaces) a field that travels in the clear —
//     unencrypted and unauthenticated — beside the sealed ones. It is always
//     an explicit opt-in, never inferred.
//   - Sealed is one encrypted leaf (version || nonce || ciphertext || tag),
//     the only frozen byte format in the model. SealedNone, SealedEmptySeq
//     and SealedEmptyMap are its authenticated marker siblings for absent
//     values and empty composites.
//   - Object is the ordered map-decode shape (entry order preserved, so
//     results compare deterministically); Field is one entry of it.
//
// All of the sealed leaf types and Plain implement driver.Valuer (and the
// leaves sql.Scanner), so a map-shaped ciphertext binds directly as database
// named parameters and sealed columns load back without conversion.
//
// # What is deliberately NOT here
//
// The transport codec — the wire encoding that carries a value tree across
// an FFI boundary — is an unexported detail of the consumer that owns the
// boundary (module vcencrypt, for the wasm harness). It is not a storage
// format, so this module does not export it: the only bytes an application
// should ever persist are the sealed leaves above. The Encryptable/Encoder
// extension point for custom encodings lives with the codec in vcencrypt
// for the same reason.
//
// The cross-language contract is the frozen tag table plus the sealed leaf
// encodings defined in the Rust crate vitaminc-aead-value — the model, not
// any package. A new tag is added only when a value class cannot be
// represented in the existing model, and requires a defined decode mapping
// for every supported language before it ships.
package vcvalue

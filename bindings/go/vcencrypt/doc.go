// Package vcencrypt is the demonstration binding of the vitaminc-encrypt
// crate: it runs the Rust AEAD stack as a wasm32-wasip1 guest under wazero
// (CGO_ENABLED=0) and drives it through the vcvalue model end-to-end.
//
// vitaminc-encrypt is a single-static-key cipher BY DESIGN — that is exactly
// what this package binds. Key management, rotation and ZeroKMS envelope keys
// belong to the forthcoming stack-encrypt SDK and are out of scope here. This
// package exists to prove the value model works end-to-end through wasm; it
// is a reference tool, not the product surface. The value model itself (the
// types application code touches: Plain, Sealed and the marker leaves,
// Object) lives in the dependency-free sibling module vcvalue.
//
// # Shape
//
//	client, _ := vcencrypt.NewClient(ctx)   // one wasm instance
//	defer client.Close(ctx)
//	cipher, _ := client.NewCipher(ctx, key) // a key schedule (handle) in the guest
//	defer cipher.Close(ctx)
//	ct, _ := cipher.Encrypt(ctx, value, aad)
//	got, _ := cipher.Decrypt(ctx, ct, aad)
//
// The Rust guest (bindings/go/vcencrypt/guest) is compiled to wasm and
// embedded here; wazero runs it in-process — no shared libraries, no cgo
// toolchain. A process-wide compilation cache means only the first client
// pays the compile cost.
//
// # Encoding
//
// Encrypt walks ordinary Go values with encoding/json-style rules: builtins,
// slices, maps (keys sorted for deterministic structure) and structs (by
// field name, honoring `vc:"..."` tags). A user type implements Encryptable
// to control its own sealing (Go's answer to Rust's Encrypt, since Go has no
// orphan impls); the Encoder it receives is a recorder, not a live cipher
// handle. Non-secret fields travel in the clear only by explicit opt-in:
// the vcvalue.Plain{V: ...} marker under reflection, or the Encoder's
// Passthrough channel — never implicitly.
//
// Decrypt returns the self-describing decode shape: Go natives at the exact
// numeric widths, []any for sequences, the ordered vcvalue.Object for maps,
// vcvalue.Sealed leaves where fields stay encrypted, and vcvalue.Plain for
// passthrough fields. Decoding into caller structs (the mirror of the
// reflection encode) is deliberately future work.
//
// # Transport, not storage
//
// The wire bytes this package shuttles across the wasm boundary are an FFI
// detail: the codec is NOT a storage format and carries no compatibility
// commitment. It lives in the sibling module vcffi — one implementation
// shared by every binding that owns such a boundary — and this package
// re-exports its Encryptable/Encoder extension point as aliases. The only
// frozen bytes are the sealed leaves inside the AEAD envelope (see
// vcvalue.Sealed). Durable cross-language database interop is a schema-aware
// layer's job, which this package knows nothing about.
//
// Security notes:
//   - Buffers inside guest memory are zeroized before being freed, and the
//     key is wiped inside the guest right after the key schedule is built.
//     Copies on the Go heap (the key, plaintext values) cannot be reliably
//     wiped from Go; treat process memory as sensitive.
//   - Decryption failures reveal nothing about the plaintext, but the binding
//     does separate failure *kinds*: ErrAuthentication (wrong key/AAD or
//     tamper — indistinguishable from one another), ErrEncoding (malformed
//     transport bytes), ErrBadHandle (unknown/closed cipher) and ErrInternal.
package vcencrypt

// Package vitaminc is the reference harness for the vitaminc Go bindings: it
// runs the Rust AEAD stack as a wasm32-wasip1 guest under wazero
// (CGO_ENABLED=0) and drives it through the vcvalue currency end-to-end.
//
// vitaminc-encrypt is a reference tool; this package proves the currency and
// transport end-to-end — the product surface is the forthcoming
// stack-encrypt SDK. Application code that wants only the value currency and
// transport codec (with no wasm or crypto dependency) should import the
// sibling vcvalue package instead.
//
// The Rust guest (bindings/go/guest) is compiled to wasm and embedded here;
// wazero runs it in-process — no shared libraries, no cgo toolchain, one
// self-contained Go module.
//
// Security notes:
//   - Buffers inside guest memory are zeroized before being freed. Copies on
//     the Go heap (the key, plaintext values) cannot be reliably wiped from
//     Go; treat process memory as sensitive.
//   - Decryption failures are deliberately opaque (like the Rust layer's
//     Unspecified): wrong key, wrong AAD, tampered ciphertext, renamed map
//     key and malformed input are indistinguishable, all ErrUnspecified.
package vitaminc

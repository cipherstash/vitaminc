// Package vcencrypt is the demonstration binding of the vitaminc-encrypt
// crate: it runs the Rust AEAD stack as a wasm32-wasip1 guest under wazero
// (CGO_ENABLED=0) and drives it through the vcvalue currency end-to-end.
//
// vitaminc-encrypt is a single-static-key cipher BY DESIGN — that is exactly
// what this package binds. Key management, rotation and ZeroKMS envelope keys
// belong to the forthcoming stack-encrypt SDK and are out of scope here. This
// package exists to prove the value currency and transport work end-to-end
// through wasm; it is a reference tool, not the product surface. Application
// code that wants only the value currency and transport codec (with no wasm
// or crypto dependency) should import the sibling vcvalue module instead.
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

//! # vitaminc-wasi-guest
//!
//! WASI guest module exposing `vitaminc` AEAD encryption of transport
//! frames to non-Rust hosts — the Go bindings spike. Built for
//! `wasm32-wasip1` and embedded by the Go module in the parent directory
//! (wazero host, `CGO_ENABLED=0`).
//!
//! The guest is deliberately minimal: it needs **no host imports beyond
//! WASI itself** (`random_get` supplies nonce entropy) because, unlike the
//! full cipherstash-suite bridge, there is no network access in scope —
//! keys come in by value from the host.
//!
//! On wasm32 the `vitaminc-encrypt` crate uses its pure-Rust
//! (RustCrypto `aes-gcm`) backend; the trade-offs are documented there.
//!
//! See [`abi`] for the export surface and buffer-ownership rules. A value
//! arrives as one [`Frame`] and is encrypted in place, walking its bytes
//! into the encrypting sink; a ciphertext is decrypted into a
//! [`FrameWriter`], so no value tree is built on either path. The ciphertext
//! transport lives in `vitaminc_aead_frame::transport` (transport-only — the
//! sealed leaf format inside the envelope is the only frozen byte format).
//!
//! [`Frame`]: vitaminc_aead::Frame
//! [`FrameWriter`]: vitaminc_aead::FrameWriter

// The ABI's packed u64 results embed 32-bit pointers and its bounds checks
// read the wasm linear-memory size, so the module only exists on wasm32
// targets. A native cdylib build therefore exports no vc_* symbols at all —
// failing loudly at symbol lookup — instead of exporting a silently wrong
// ABI (the `ptr << 32` packing would truncate a 64-bit pointer).
#[cfg(target_arch = "wasm32")]
pub mod abi;
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) mod sessions;
pub mod status;

//! # vitaminc-wasi-guest
//!
//! WASI guest module exposing `vitaminc` AEAD encryption of [`FfiValue`]
//! trees to non-Rust hosts — the Go bindings spike. Built for
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
//! See [`abi`] for the export surface and buffer-ownership rules, and
//! [`codec`] for the transport encoding (transport-only — the sealed leaf
//! format inside the envelope is the only frozen byte format).
//!
//! [`FfiValue`]: vitaminc_aead_value::FfiValue

pub mod abi;
pub mod codec;

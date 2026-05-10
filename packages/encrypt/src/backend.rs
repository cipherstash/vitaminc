//! Backend abstraction over AES-256-GCM implementations.
//!
//! Two implementations are selected via `cfg`:
//!
//! - **Native** (`cfg(not(target_arch = "wasm32"))`): `aws-lc-rs` —
//!   FIPS-validated, hardware-accelerated.
//! - **Wasm32** (`cfg(target_arch = "wasm32")`): `aes-gcm` from RustCrypto —
//!   pure Rust, builds without a C toolchain.
//!
//! Both implementations conform to RFC 5116 AES-256-GCM and produce
//! byte-identical ciphertext+tag output for the same inputs.
//!
//! The internal `_test-rust-crypto-backend` feature forces the RustCrypto
//! backend on native targets so CI can exercise it without wasm tooling.

#[cfg(any(target_arch = "wasm32", feature = "_test-rust-crypto-backend"))]
mod rust_crypto;
#[cfg(any(target_arch = "wasm32", feature = "_test-rust-crypto-backend"))]
pub(crate) use rust_crypto::CipherKey;

#[cfg(not(any(target_arch = "wasm32", feature = "_test-rust-crypto-backend")))]
mod aws_lc;
#[cfg(not(any(target_arch = "wasm32", feature = "_test-rust-crypto-backend")))]
pub(crate) use aws_lc::CipherKey;

/// AES-256-GCM nonce length, in bytes.
pub(crate) const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length, in bytes.
pub(crate) const TAG_LEN: usize = 16;

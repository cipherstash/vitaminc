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

#[cfg(not(target_arch = "wasm32"))]
mod aws_lc;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use aws_lc::CipherKey;

#[cfg(target_arch = "wasm32")]
mod rust_crypto;
#[cfg(target_arch = "wasm32")]
pub(crate) use rust_crypto::CipherKey;

/// AES-256-GCM nonce length, in bytes.
pub(crate) const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length, in bytes.
pub(crate) const TAG_LEN: usize = 16;

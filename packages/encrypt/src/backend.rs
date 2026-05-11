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

#[cfg(test)]
mod tests {
    use super::CipherKey;

    /// Cross-backend byte-parity check.
    ///
    /// CI runs this same test against both backends:
    /// - `cargo test -p vitaminc-encrypt` exercises `aws-lc-rs`
    /// - `cargo test -p vitaminc-encrypt --features _test-rust-crypto-backend`
    ///   exercises RustCrypto's `aes-gcm`
    ///
    /// Both must produce the byte string in `EXPECTED`. If they agree, the two
    /// backends are byte-identical for this input — which, with their
    /// RFC 5116 conformance, is what guarantees ciphertexts written under one
    /// backend decrypt cleanly under the other (the whole point of supporting
    /// wasm32 alongside native).
    #[test]
    fn cross_backend_byte_parity() {
        // Fixed inputs — chosen to exercise: non-empty plaintext, non-empty AAD,
        // a plaintext length that's not a block boundary (so we cover GCM's
        // partial-block handling).
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        ];
        let plaintext = b"vitaminc cross-backend parity vector";
        let aad = b"vitaminc-encrypt KAT v1";

        // Ciphertext (36 bytes) || GCM tag (16 bytes), computed deterministically
        // from the inputs above by an RFC 5116 AES-256-GCM implementation.
        // Verified to be produced identically by both `aws-lc-rs` and RustCrypto
        // `aes-gcm` when this test was introduced.
        const EXPECTED: [u8; 52] = [
            0x90, 0x71, 0x08, 0x4c, 0x28, 0xa2, 0x6c, 0xdc, 0x42, 0x06, 0xf5, 0xbc, 0x74, 0x09,
            0xed, 0xbc, 0x11, 0xcf, 0x32, 0x75, 0xfc, 0xd3, 0x62, 0x1c, 0xfd, 0x7c, 0x4f, 0xf2,
            0x06, 0x8b, 0x03, 0x64, 0xb1, 0x02, 0x28, 0x8d, 0xed, 0x9a, 0xa3, 0xcf, 0x46, 0x3d,
            0xa6, 0xb2, 0x0e, 0x7f, 0x86, 0x23, 0x76, 0x7a, 0xfb, 0x0a,
        ];

        let cipher = CipherKey::new(&key).expect("key construction failed");

        let mut sealed = plaintext.to_vec();
        cipher.seal(&nonce, aad, &mut sealed).expect("seal failed");
        assert_eq!(
            sealed,
            EXPECTED.as_slice(),
            "ciphertext+tag diverged from cross-backend KAT"
        );

        let mut to_open = sealed.clone();
        let pt_len = cipher
            .open(&nonce, aad, &mut to_open)
            .expect("open failed");
        assert_eq!(&to_open[..pt_len], plaintext, "round-trip plaintext mismatch");
    }
}

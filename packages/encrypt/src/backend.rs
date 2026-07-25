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
///
/// The RustCrypto backend needs it to size the plaintext buffer when opening
/// (`aws-lc-rs` manages tag layout internally). It is also used by
/// `Aes256Cipher::encrypt_bytes_array` in every configuration to reserve
/// buffer capacity for the appended tag, so the in-place seal never
/// reallocates — hence the constant is no longer gated.
pub(crate) const TAG_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use super::CipherKey;

    // wasm-pack invokes Node by default — no `wasm_bindgen_test_configure!` needed.
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    /// Cross-backend byte-parity check.
    ///
    /// CI runs this same test against all three configurations:
    /// - `cargo test -p vitaminc-encrypt` — `aws-lc-rs` on native
    /// - `cargo test -p vitaminc-encrypt --features _test-rust-crypto-backend`
    ///   — RustCrypto on native
    /// - `wasm-pack test --node packages/encrypt` — RustCrypto compiled to
    ///   wasm32-unknown-unknown and run in Node
    ///
    /// All three must produce the byte string in `EXPECTED`. The third gates
    /// the actual wasm codegen path (not just the proxied native build) — so a
    /// regression that only surfaces under wasm32 (e.g. SIMD intrinsic fallback,
    /// 32-bit pointer arithmetic) would still be caught.
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
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
        let pt_len = cipher.open(&nonce, aad, &mut to_open).expect("open failed");
        assert_eq!(
            &to_open[..pt_len],
            plaintext,
            "round-trip plaintext mismatch"
        );
    }

    // Deterministic counterparts to the quickcheck round-trip tests in
    // `cipher::test`. Those property tests can't run under wasm-bindgen-test
    // because quickcheck's runner uses `std::thread`, which isn't available on
    // wasm32-unknown-unknown — so the cases below carry the same `#[cfg_attr]`
    // attribute swap as the KAT and gate all three configurations (native
    // aws-lc-rs, native RustCrypto, wasm32 RustCrypto in Node) on the same
    // round-trip and failure-path behaviour.

    fn fixed_key() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    fn fixed_nonce() -> [u8; 12] {
        [
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
        ]
    }

    fn roundtrip(plaintext: &[u8], aad: &[u8]) {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let cipher = CipherKey::new(&key).expect("key");

        let mut buf = plaintext.to_vec();
        cipher.seal(&nonce, aad, &mut buf).expect("seal");

        let pt_len = cipher.open(&nonce, aad, &mut buf).expect("open");
        assert_eq!(&buf[..pt_len], plaintext);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn roundtrip_no_aad() {
        roundtrip(b"hello world", b"");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn roundtrip_with_aad() {
        roundtrip(b"hello world", b"associated data");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn roundtrip_empty_plaintext() {
        roundtrip(b"", b"some aad");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn roundtrip_multi_block_plaintext() {
        // 200 bytes — spans multiple AES blocks (16B each) plus a partial tail,
        // catching any block-boundary handling regression.
        let pt: Vec<u8> = (0..200u8).collect();
        roundtrip(&pt, b"multi-block aad");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn open_fails_with_wrong_aad() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let cipher = CipherKey::new(&key).expect("key");

        let mut buf = b"payload".to_vec();
        cipher.seal(&nonce, b"correct-aad", &mut buf).expect("seal");

        let mut tampered = buf.clone();
        assert!(
            cipher.open(&nonce, b"wrong-aad", &mut tampered).is_err(),
            "open must reject mismatched AAD"
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn open_fails_with_wrong_key() {
        let nonce = fixed_nonce();

        let key_a = fixed_key();
        let mut key_b = fixed_key();
        key_b[0] ^= 0xff;

        let cipher_a = CipherKey::new(&key_a).expect("key a");
        let cipher_b = CipherKey::new(&key_b).expect("key b");

        let mut buf = b"payload".to_vec();
        cipher_a.seal(&nonce, b"", &mut buf).expect("seal");

        assert!(
            cipher_b.open(&nonce, b"", &mut buf).is_err(),
            "open must reject ciphertext sealed under a different key"
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn open_fails_with_tampered_ciphertext() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let cipher = CipherKey::new(&key).expect("key");

        let mut buf = b"payload".to_vec();
        cipher.seal(&nonce, b"", &mut buf).expect("seal");

        // Flip a bit in the ciphertext (not the tag) — GCM authentication
        // must catch this.
        buf[0] ^= 0x01;

        assert!(
            cipher.open(&nonce, b"", &mut buf).is_err(),
            "open must reject ciphertext whose bytes have been modified"
        );
    }
}

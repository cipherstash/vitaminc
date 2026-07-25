//! The wasm export surface. Conventions (following the cipherstash-suite
//! WASI bridge):
//!
//! - The host owns all buffer lifecycles. It writes inputs into guest
//!   memory obtained from [`vc_alloc`] and releases every buffer — its own
//!   inputs and the guest's outputs — with [`vc_dealloc`], which **zeroizes
//!   before freeing** (transport buffers carry plaintext on both the
//!   encrypt input and decrypt output paths).
//! - [`vc_encrypt`]/[`vc_decrypt`] return a `u64` packing the output
//!   buffer as `ptr << 32 | len`, or `0` on any failure. Like the
//!   trait-layer `Unspecified`, failures carry no detail: every input to
//!   the decrypt path is attacker-reachable.
//! - Panics are caught at the boundary and reported as `0`, never as a
//!   wasm trap.
//!
//! Wasm modules are single-threaded; the host must serialize calls into
//! one instance.

use std::panic::{catch_unwind, AssertUnwindSafe};

use vitaminc_aead::{Aad, Encrypt};
use vitaminc_aead_value::FfiValue;
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use zeroize::Zeroize;

use crate::codec;

/// Allocate `len` bytes of guest memory for the host to write into.
/// Returns a pointer valid until passed to [`vc_dealloc`], or null if the
/// allocation fails.
#[no_mangle]
pub extern "C" fn vc_alloc(len: u32) -> *mut u8 {
    let buf = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(buf) as *mut u8
}

/// Zeroize and free a buffer previously returned by [`vc_alloc`] or packed
/// into a [`vc_encrypt`]/[`vc_decrypt`] result. `len` must be the original
/// length.
///
/// # Safety
///
/// `ptr`/`len` must denote exactly one live buffer handed out by this
/// module; double-free or a wrong length is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn vc_dealloc(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    let mut buf = unsafe { Vec::from_raw_parts(ptr, len as usize, len as usize) };
    buf.zeroize();
}

fn pack(out: Vec<u8>) -> u64 {
    let boxed = out.into_boxed_slice();
    let len = boxed.len() as u64;
    let ptr = Box::into_raw(boxed) as *mut u8 as usize as u64;
    (ptr << 32) | len
}

/// # Safety
///
/// All pointer/length pairs must denote readable guest memory.
unsafe fn input<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    if ptr.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len as usize) }
    }
}

fn cipher_from(key: &[u8]) -> Option<Aes256Cipher> {
    let key: [u8; 32] = key.try_into().ok()?;
    Aes256Cipher::new(&Key::from(key)).ok()
}

/// Encrypt a transport-encoded [`FfiValue`] tree.
///
/// Inputs: 32-byte key, caller AAD (may be empty), transport value bytes.
/// Output: packed pointer to transport-encoded ciphertext tree, `0` on
/// failure.
///
/// # Safety
///
/// All pointer/length pairs must denote readable guest memory (normally
/// buffers the host wrote via [`vc_alloc`]).
#[no_mangle]
pub unsafe extern "C" fn vc_encrypt(
    key_ptr: *const u8,
    key_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
    val_ptr: *const u8,
    val_len: u32,
) -> u64 {
    let (key, aad, val) = unsafe {
        (
            input(key_ptr, key_len),
            input(aad_ptr, aad_len),
            input(val_ptr, val_len),
        )
    };
    catch_unwind(AssertUnwindSafe(|| encrypt(key, aad, val)))
        .unwrap_or(None)
        .map_or(0, pack)
}

fn encrypt(key: &[u8], aad: &[u8], val: &[u8]) -> Option<Vec<u8>> {
    let cipher = cipher_from(key)?;
    let value = codec::decode_value(&mut codec::Reader::new(val)).ok()?;
    let ct = value.encrypt_with_aad(&cipher, Aad::from_slice(aad)).ok()?;
    let mut out = Vec::new();
    codec::encode_ciphertext(&ct, &mut out).ok()?;
    Some(out)
}

/// Decrypt a transport-encoded ciphertext tree back into a
/// transport-encoded [`FfiValue`] tree. The output buffer contains
/// plaintext — the host must copy it out and immediately release it with
/// [`vc_dealloc`] (which wipes it).
///
/// # Safety
///
/// All pointer/length pairs must denote readable guest memory.
#[no_mangle]
pub unsafe extern "C" fn vc_decrypt(
    key_ptr: *const u8,
    key_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
    ct_ptr: *const u8,
    ct_len: u32,
) -> u64 {
    let (key, aad, ct) = unsafe {
        (
            input(key_ptr, key_len),
            input(aad_ptr, aad_len),
            input(ct_ptr, ct_len),
        )
    };
    catch_unwind(AssertUnwindSafe(|| decrypt(key, aad, ct)))
        .unwrap_or(None)
        .map_or(0, pack)
}

fn decrypt(key: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = cipher_from(key)?;
    let ct: AesCipherText = codec::decode_ciphertext(&mut codec::Reader::new(ct)).ok()?;
    let value: FfiValue = cipher.decrypt_with_aad(ct, Aad::from_slice(aad)).ok()?;
    let mut out = Vec::new();
    codec::encode_value(value, &mut out).ok()?;
    Some(out)
}

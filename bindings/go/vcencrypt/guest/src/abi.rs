//! The wasm export surface. Conventions (following the cipherstash-suite
//! WASI bridge):
//!
//! - The host owns all buffer lifecycles. It writes inputs into guest
//!   memory obtained from [`vc_alloc`] and releases every buffer — its own
//!   inputs and the guest's outputs — with [`vc_dealloc`], which **zeroizes
//!   before freeing** (transport buffers carry plaintext on both the
//!   encrypt input and decrypt output paths).
//! - A cipher is a **session handle**: the host calls [`vc_cipher_init`] once
//!   with the key, then passes the returned handle to [`vc_encrypt`] /
//!   [`vc_decrypt`], and [`vc_cipher_free`] when done. The guest owns the key
//!   schedule for the handle's lifetime; the key bytes the host passed in are
//!   zeroized inside the guest right after the cipher is built (the host still
//!   wipes its own input buffer on dealloc).
//!
//! # Result encoding
//!
//! [`vc_cipher_init`], [`vc_encrypt`] and [`vc_decrypt`] all return a single
//! `u64` split into a high and a low 32-bit field:
//!
//! - **success** — the high 32 bits are non-zero. For a buffer result they are
//!   the output pointer and the low 32 bits its length; for
//!   [`vc_cipher_init`] they are the handle and the low bits are unused.
//! - **error** — the high 32 bits are zero and the low 32 bits are a status
//!   code ([`STATUS_AUTH`], [`STATUS_ENCODING`], [`STATUS_BAD_HANDLE`],
//!   [`STATUS_INTERNAL`]). A valid output pointer / handle is never zero, so
//!   the two spaces never collide.
//!
//! Statuses are the only detail leaked: they distinguish an authentication
//! failure from a malformed input or an unknown handle, but reveal nothing
//! about the plaintext. Panics are caught at the boundary and reported as
//! [`STATUS_INTERNAL`], never as a wasm trap.
//!
//! Wasm modules are single-threaded; the host must serialize calls into one
//! instance.

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use vitaminc_aead::{Aad, Encrypt};
use vitaminc_aead_value::{transport as codec, FfiValue};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use zeroize::Zeroize;

/// AEAD open failure: wrong key, wrong AAD, or tampered ciphertext.
pub const STATUS_AUTH: u32 = 1;
/// Malformed transport bytes on the encrypt input or decrypt input path.
pub const STATUS_ENCODING: u32 = 2;
/// The handle is unknown (never issued, or already freed).
pub const STATUS_BAD_HANDLE: u32 = 3;
/// A caught panic, a cipher that could not be constructed, or any other
/// unexpected internal failure.
pub const STATUS_INTERNAL: u32 = 4;

thread_local! {
    // Wasm is single-threaded, so a thread-local `RefCell` is a plain owner of
    // the session table — no `Send`/`Sync` bound on `Aes256Cipher` required.
    static SESSIONS: RefCell<Sessions> = RefCell::new(Sessions {
        next: 1,
        ciphers: HashMap::new(),
    });
}

struct Sessions {
    // Handle ids start at 1 so a zero high-field can never be a valid handle
    // (see the result encoding).
    next: u32,
    ciphers: HashMap<u32, Aes256Cipher>,
}

/// Allocate `len` bytes of guest memory for the host to write into.
/// Returns a pointer valid until passed to [`vc_dealloc`], or null if the
/// allocation fails.
#[no_mangle]
pub extern "C" fn vc_alloc(len: u32) -> *mut u8 {
    let buf = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(buf) as *mut u8
}

/// Zeroize and free a buffer previously returned by [`vc_alloc`] or packed
/// into a result. `len` must be the original length.
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

/// Pack a buffer result: `ptr << 32 | len`. The pointer is never null for a
/// live allocation, so the high 32 bits are non-zero (a success marker).
fn ok_buffer(out: Vec<u8>) -> u64 {
    let boxed = out.into_boxed_slice();
    let len = boxed.len() as u64;
    let ptr = Box::into_raw(boxed) as *mut u8 as usize as u64;
    (ptr << 32) | len
}

/// Pack a handle result: `handle << 32`. Handles start at 1, so the high 32
/// bits are non-zero; the low bits are unused.
fn ok_handle(handle: u32) -> u64 {
    (handle as u64) << 32
}

/// Pack an error: the status in the low 32 bits, high bits zero.
fn err_status(status: u32) -> u64 {
    status as u64
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

/// Build a cipher from raw key bytes, zeroizing the guest-side stack copy of
/// the key material once the cipher (and its key schedule) owns it. The key
/// schedule inside `Aes256Cipher` is wiped best-effort when the cipher is
/// dropped in `vc_cipher_free`; that wipe is owned by the crypto backend.
fn build_cipher(key: &[u8]) -> Result<Aes256Cipher, u32> {
    let mut key_copy: [u8; 32] = key.try_into().map_err(|_| STATUS_INTERNAL)?;
    let cipher = Aes256Cipher::new(&Key::from(key_copy)).map_err(|_| STATUS_INTERNAL);
    key_copy.zeroize();
    cipher
}

/// Initialise a cipher session from a 32-byte key, returning a handle.
///
/// # Safety
///
/// `key_ptr`/`key_len` must denote readable guest memory.
#[no_mangle]
pub unsafe extern "C" fn vc_cipher_init(key_ptr: *const u8, key_len: u32) -> u64 {
    let key = unsafe { input(key_ptr, key_len) };
    catch_unwind(AssertUnwindSafe(|| cipher_init(key)))
        .unwrap_or(Err(STATUS_INTERNAL))
        .map_or_else(err_status, ok_handle)
}

fn cipher_init(key: &[u8]) -> Result<u32, u32> {
    let cipher = build_cipher(key)?;
    SESSIONS.with(|s| {
        let mut s = s.borrow_mut();
        let handle = s.next;
        // Saturating rather than wrapping so an id can never wrap back onto a
        // live handle in a long-lived instance; a spike never exhausts u32.
        s.next = s.next.saturating_add(1);
        s.ciphers.insert(handle, cipher);
        Ok(handle)
    })
}

/// Drop a cipher session, wiping its key schedule (best-effort, owned by the
/// backend). Freeing an unknown handle is a no-op.
#[no_mangle]
pub extern "C" fn vc_cipher_free(handle: u32) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        SESSIONS.with(|s| {
            s.borrow_mut().ciphers.remove(&handle);
        });
    }));
}

/// Run `f` with the cipher bound to `handle`, or report [`STATUS_BAD_HANDLE`].
fn with_cipher<R>(handle: u32, f: impl FnOnce(&Aes256Cipher) -> Result<R, u32>) -> Result<R, u32> {
    SESSIONS.with(|s| {
        let s = s.borrow();
        let cipher = s.ciphers.get(&handle).ok_or(STATUS_BAD_HANDLE)?;
        f(cipher)
    })
}

/// Encrypt a transport-encoded [`FfiValue`] tree under the session `handle`.
///
/// Output: packed pointer to a transport-encoded ciphertext tree, or a status.
///
/// # Safety
///
/// All pointer/length pairs must denote readable guest memory.
#[no_mangle]
pub unsafe extern "C" fn vc_encrypt(
    handle: u32,
    val_ptr: *const u8,
    val_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    let (aad, val) = unsafe { (input(aad_ptr, aad_len), input(val_ptr, val_len)) };
    catch_unwind(AssertUnwindSafe(|| encrypt(handle, aad, val)))
        .unwrap_or(Err(STATUS_INTERNAL))
        .map_or_else(err_status, ok_buffer)
}

fn encrypt(handle: u32, aad: &[u8], val: &[u8]) -> Result<Vec<u8>, u32> {
    // Decode the input value first so garbage bytes surface as an encoding
    // error even for an unknown handle.
    let value = codec::decode_value(&mut codec::Reader::new(val)).map_err(|_| STATUS_ENCODING)?;
    with_cipher(handle, |cipher| {
        let ct: AesCipherText = value
            .encrypt_with_aad(cipher, Aad::from_slice(aad))
            .map_err(|_| STATUS_INTERNAL)?;
        let mut out = Vec::new();
        // Re-home the Box<dyn Any + Send> passthrough currency to FfiValue
        // value-nodes before encoding.
        codec::encode_ciphertext_boxed(ct, &mut out).map_err(|_| STATUS_ENCODING)?;
        Ok(out)
    })
}

/// Decrypt a transport-encoded ciphertext tree back into a transport-encoded
/// [`FfiValue`] tree under the session `handle`. The output buffer contains
/// plaintext — the host must copy it out and immediately release it with
/// [`vc_dealloc`] (which wipes it).
///
/// # Safety
///
/// All pointer/length pairs must denote readable guest memory.
#[no_mangle]
pub unsafe extern "C" fn vc_decrypt(
    handle: u32,
    ct_ptr: *const u8,
    ct_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    let (aad, ct) = unsafe { (input(aad_ptr, aad_len), input(ct_ptr, ct_len)) };
    catch_unwind(AssertUnwindSafe(|| decrypt(handle, aad, ct)))
        .unwrap_or(Err(STATUS_INTERNAL))
        .map_or_else(err_status, ok_buffer)
}

fn decrypt(handle: u32, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, u32> {
    // Decode + re-home to the Box passthrough currency the decipher expects.
    let ct: AesCipherText =
        codec::decode_ciphertext_boxed(&mut codec::Reader::new(ct)).map_err(|_| STATUS_ENCODING)?;
    with_cipher(handle, |cipher| {
        let value: FfiValue = cipher
            .decrypt_with_aad(ct, Aad::from_slice(aad))
            .map_err(|_| STATUS_AUTH)?;
        let mut out = Vec::new();
        codec::encode_value(value, &mut out).map_err(|_| STATUS_ENCODING)?;
        Ok(out)
    })
}

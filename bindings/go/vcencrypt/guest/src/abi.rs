//! The wasm export surface. Conventions (following the cipherstash-suite
//! WASI bridge):
//!
//! - The host owns all buffer lifecycles. It writes inputs into guest
//!   memory obtained from [`vc_alloc`] and releases every buffer — its own
//!   inputs and the guest's outputs — with [`vc_dealloc`], which **zeroizes
//!   before freeing** (transport buffers carry plaintext on both the
//!   encrypt input and decrypt output paths). The guest keeps its own
//!   registry of every buffer it hands out, so `vc_dealloc` never trusts
//!   the host's length: an unknown pointer (including a double-free) is a
//!   no-op, a length mismatch refuses to free, and the wipe always covers
//!   the true allocation.
//! - A cipher is a **session handle**: the host calls [`vc_cipher_init`] once
//!   with the key, then passes the returned handle to [`vc_encrypt`] /
//!   [`vc_decrypt`], and [`vc_cipher_free`] when done. The guest owns the key
//!   schedule for the handle's lifetime; the key bytes the host passed in are
//!   zeroized inside the guest right after the cipher is built (the host still
//!   wipes its own input buffer on dealloc). Handle ids are never reused: at
//!   id exhaustion [`vc_cipher_init`] fails with [`STATUS_INTERNAL`] rather
//!   than aliasing a live handle.
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
//! This packing embeds 32-bit pointers, and the bounds checks below read the
//! wasm linear-memory size, so this module only exists on `wasm32` targets
//! (see `lib.rs`) — a native build exports no `vc_*` symbols at all rather
//! than a silently wrong ABI.
//!
//! # Hostile-input posture
//!
//! Every export validates its inputs before any unsafe construction: a
//! pointer/length pair must lie inside the current linear memory (and under
//! `isize::MAX`), a null pointer with a nonzero length is rejected rather
//! than read as empty — silently treating a null AAD pointer as an empty AAD
//! would drop the context binding — and the key length is checked at the
//! boundary. Invalid input yields [`STATUS_ENCODING`], never a trap, so one
//! bad call cannot poison the instance for every other open handle.
//!
//! The guest is built for `wasm32-wasip1`, whose panic strategy is fixed at
//! `abort`: a panic that does occur traps and kills the instance **without
//! running destructors**, so no drop-based wipe (key schedules, plaintext
//! buffers) runs. The `catch_unwind` at each export is belt-and-braces for a
//! hypothetical unwind build, not a load-bearing guarantee — the guarantee
//! is the validation above, which keeps reachable panic sources out of the
//! boundary code.
//!
//! Statuses are the only detail leaked: they distinguish an authentication
//! failure from a malformed input or an unknown handle, but reveal nothing
//! about the plaintext.
//!
//! Wasm modules are single-threaded; the host must serialize calls into one
//! instance.

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use vitaminc_aead::{Aad, Element, Encrypt};
use vitaminc_aead_value::{transport as codec, FfiValue};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText};
use zeroize::Zeroize;

use crate::sessions::{build_cipher, Sessions};
pub use crate::status::{STATUS_AUTH, STATUS_BAD_HANDLE, STATUS_ENCODING, STATUS_INTERNAL};

thread_local! {
    // Wasm is single-threaded, so thread-local `RefCell`s are plain owners
    // of this state — no `Send`/`Sync` bounds required.
    static SESSIONS: RefCell<Sessions> = RefCell::new(Sessions::new());

    // Every buffer the guest has handed out and not yet reclaimed — from
    // `vc_alloc` and from packed results — keyed by start address, holding
    // the true length. `vc_dealloc` consults this instead of trusting the
    // host: a wrong host length would otherwise zeroize past the allocation
    // and free with a mismatched layout (heap corruption).
    static BUFFERS: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
}

/// Allocate `len` bytes of guest memory for the host to write into.
/// Returns a pointer valid until passed to [`vc_dealloc`], or null if the
/// allocation fails. The null branch is real: allocation goes through
/// `try_reserve_exact`, not the aborting global-allocator error path, so an
/// oversized request is a recoverable host-side error instead of a trap
/// that poisons the instance.
#[no_mangle]
pub extern "C" fn vc_alloc(len: u32) -> *mut u8 {
    let len = len as usize;
    let mut buf: Vec<u8> = Vec::new();
    if buf.try_reserve_exact(len).is_err() {
        return core::ptr::null_mut();
    }
    buf.resize(len, 0);
    register(buf)
}

/// Register a buffer in [`BUFFERS`] and leak it to a raw pointer for the
/// host. The registry entry is what makes the matching [`vc_dealloc`] sound.
fn register(buf: Vec<u8>) -> *mut u8 {
    let boxed = buf.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    BUFFERS.with(|b| b.borrow_mut().insert(ptr as usize, len));
    ptr
}

/// Zeroize and free a buffer previously handed out by [`vc_alloc`] or packed
/// into a result. The guest's own registry supplies the true length; `len`
/// is cross-checked but never trusted. An unknown pointer (including a
/// double-free) is a no-op; a length mismatch means the host's bookkeeping
/// has desynced from ours, so the buffer is kept live and registered rather
/// than freed out from under a confused host.
///
/// # Safety
///
/// `ptr` should be a pointer this module handed out. The registry makes any
/// other pointer (or a stale one) a no-op rather than undefined behaviour,
/// but a pointer that happens to alias a *different* live registered buffer
/// of the same length would free that buffer.
#[no_mangle]
pub unsafe extern "C" fn vc_dealloc(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    let real_len = match BUFFERS.with(|b| b.borrow_mut().remove(&(ptr as usize))) {
        Some(real_len) => real_len,
        None => return,
    };
    if real_len != len as usize {
        BUFFERS.with(|b| b.borrow_mut().insert(ptr as usize, real_len));
        return;
    }
    // SAFETY: the registry guarantees `(ptr, real_len)` is exactly one live
    // allocation this module handed out via `register`, and the entry has
    // just been removed so it cannot be freed twice.
    let mut buf = unsafe { Vec::from_raw_parts(ptr, real_len, real_len) };
    buf.zeroize();
}

/// Pack a buffer result: `ptr << 32 | len`. The pointer is never null for a
/// live allocation, so the high 32 bits are non-zero (a success marker).
/// The buffer is registered so the host's eventual [`vc_dealloc`] wipes and
/// frees exactly what was allocated.
fn ok_buffer(out: Vec<u8>) -> u64 {
    let len = out.len() as u64;
    let ptr = register(out) as usize as u64;
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

/// Current linear-memory size in bytes. `u64` because a full 4 GiB memory
/// (65536 pages) overflows a 32-bit `usize`.
fn linear_memory_bytes() -> u64 {
    core::arch::wasm32::memory_size::<0>() as u64 * 65536
}

/// Borrow a host-supplied `(ptr, len)` pair, validating before any slice
/// exists: null-with-nonzero-length is rejected (treating it as empty would
/// silently drop an AAD context binding), the length must be under
/// `isize::MAX`, and the whole range must lie inside the current linear
/// memory. A pair that fails validation yields [`STATUS_ENCODING`]; a pair
/// that passes can still name the wrong bytes — the host owns its pointers —
/// but can never fault or over-read past linear memory.
fn input<'a>(ptr: *const u8, len: u32) -> Result<&'a [u8], u32> {
    let len = len as usize;
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() || len > isize::MAX as usize {
        return Err(STATUS_ENCODING);
    }
    let end = (ptr as usize).checked_add(len).ok_or(STATUS_ENCODING)?;
    if end as u64 > linear_memory_bytes() {
        return Err(STATUS_ENCODING);
    }
    // SAFETY: non-null, in-bounds of linear memory, and under `isize::MAX`;
    // wasm linear memory is fully initialized (fresh pages are zero), so
    // reading the range as bytes is defined.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Initialise a cipher session from a 32-byte key, returning a handle.
///
/// # Safety
///
/// `key_ptr`/`key_len` should name the buffer the host wrote the key into.
/// The guest bounds-checks the range against linear memory — a bad pair
/// returns [`STATUS_ENCODING`] instead of faulting — but cannot verify the
/// bytes are the ones the host intended.
#[no_mangle]
pub unsafe extern "C" fn vc_cipher_init(key_ptr: *const u8, key_len: u32) -> u64 {
    catch_unwind(AssertUnwindSafe(|| cipher_init(input(key_ptr, key_len)?)))
        .unwrap_or(Err(STATUS_INTERNAL))
        .map_or_else(err_status, ok_handle)
}

fn cipher_init(key: &[u8]) -> Result<u32, u32> {
    let cipher = build_cipher(key)?;
    SESSIONS.with(|s| s.borrow_mut().insert(cipher))
}

/// Drop a cipher session, wiping its key schedule (best-effort, owned by the
/// backend). Freeing an unknown handle is a no-op.
#[no_mangle]
pub extern "C" fn vc_cipher_free(handle: u32) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        SESSIONS.with(|s| {
            s.borrow_mut().remove(handle);
        });
    }));
}

/// Run `f` with the cipher bound to `handle`, or report [`STATUS_BAD_HANDLE`].
fn with_cipher<R>(handle: u32, f: impl FnOnce(&Aes256Cipher) -> Result<R, u32>) -> Result<R, u32> {
    SESSIONS.with(|s| {
        let s = s.borrow();
        let cipher = s.get(handle).ok_or(STATUS_BAD_HANDLE)?;
        f(cipher)
    })
}

/// Encrypt a transport-encoded [`FfiValue`] tree under the session `handle`.
///
/// Output: packed pointer to a transport-encoded ciphertext tree, or a status.
///
/// # Safety
///
/// Pointer/length pairs should name buffers the host wrote via [`vc_alloc`].
/// The guest bounds-checks each range against linear memory — a bad pair
/// returns [`STATUS_ENCODING`] instead of faulting — but cannot verify the
/// bytes are the ones the host intended.
#[no_mangle]
pub unsafe extern "C" fn vc_encrypt(
    handle: u32,
    val_ptr: *const u8,
    val_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        encrypt(
            handle,
            input(aad_ptr, aad_len)?,
            input(val_ptr, val_len)?,
            false,
        )
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Like [`vc_encrypt`], but seals the value as a *sequence element* — the
/// [`Element`] wrapper's derivation, byte-identical to what batch encryption
/// of a sequence binds per element. A row inserted through this export
/// interchanges with rows written by encrypting a whole sequence under the
/// same AAD.
///
/// # Safety
///
/// As for [`vc_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn vc_encrypt_element(
    handle: u32,
    val_ptr: *const u8,
    val_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        encrypt(
            handle,
            input(aad_ptr, aad_len)?,
            input(val_ptr, val_len)?,
            true,
        )
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

fn encrypt(handle: u32, aad: &[u8], val: &[u8], as_element: bool) -> Result<Vec<u8>, u32> {
    // Decode the input value first so garbage bytes surface as an encoding
    // error even for an unknown handle.
    let value = codec::decode_value(&mut codec::Reader::new(val)).map_err(|_| STATUS_ENCODING)?;
    with_cipher(handle, |cipher| {
        let aad = Aad::from_slice(aad);
        let ct: AesCipherText = if as_element {
            Element(value).encrypt_with_aad(cipher, aad)
        } else {
            value.encrypt_with_aad(cipher, aad)
        }
        .map_err(|_| STATUS_INTERNAL)?;
        let mut out = Vec::new();
        // Re-home the Box<dyn Any + Send> passthrough payload type to FfiValue
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
/// As for [`vc_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn vc_decrypt(
    handle: u32,
    ct_ptr: *const u8,
    ct_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        decrypt(
            handle,
            input(aad_ptr, aad_len)?,
            input(ct_ptr, ct_len)?,
            false,
        )
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Like [`vc_decrypt`], but opens the ciphertext as a *sequence element* —
/// the read-side counterpart of [`vc_encrypt_element`]. This is how a host
/// decrypts a single row that was batch-encrypted as part of a sequence:
/// the caller presents the same AAD it gave the batch encrypt, and the
/// [`Element`] wrapper derives the element AAD internally.
///
/// # Safety
///
/// As for [`vc_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn vc_decrypt_element(
    handle: u32,
    ct_ptr: *const u8,
    ct_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        decrypt(
            handle,
            input(aad_ptr, aad_len)?,
            input(ct_ptr, ct_len)?,
            true,
        )
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

fn decrypt(handle: u32, aad: &[u8], ct: &[u8], as_element: bool) -> Result<Vec<u8>, u32> {
    // Decode + re-home to the Box passthrough payload type the decipher expects.
    let ct: AesCipherText =
        codec::decode_ciphertext_boxed(&mut codec::Reader::new(ct)).map_err(|_| STATUS_ENCODING)?;
    with_cipher(handle, |cipher| {
        let aad = Aad::from_slice(aad);
        let value: FfiValue = if as_element {
            cipher
                .decrypt_with_aad::<Element<FfiValue>, _>(ct, aad)
                .map(Element::into_inner)
        } else {
            cipher.decrypt_with_aad(ct, aad)
        }
        .map_err(|_| STATUS_AUTH)?;
        let mut out = Vec::new();
        codec::encode_value(value, &mut out).map_err(|_| STATUS_ENCODING)?;
        Ok(out)
    })
}

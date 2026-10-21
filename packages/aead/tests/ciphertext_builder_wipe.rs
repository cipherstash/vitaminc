//! A `CipherTextBuilder` whose seal fails must not free the plaintext
//! buffer with the plaintext still in it.
//!
//! The builder hands the sealing closure the plaintext buffer, and a
//! backend that fails may leave plaintext there. This test installs a
//! global allocator that, while armed, counts how many secret words are
//! still in each block as it is freed. It lives in its own test binary so
//! the allocator sees nothing but this seal.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vitaminc_aead::{CipherTextBuilder, NonceGenerator, RandomNonceGenerator};
use vitaminc_protected::Protected;

const SECRET: u64 = 0x5EC2_E7C0_FFEE_D00D;

static ARMED: AtomicBool = AtomicBool::new(false);
static LEFT_IN_FREED_BLOCKS: AtomicUsize = AtomicUsize::new(0);

struct Inspecting;

// SAFETY: every call is forwarded to `System` unchanged. `dealloc` only
// reads the block it is about to free, which the caller still owns.
unsafe impl GlobalAlloc for Inspecting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes.
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            let found = block
                .as_chunks::<8>()
                .0
                .iter()
                .filter(|w| **w == SECRET.to_ne_bytes())
                .count();
            LEFT_IN_FREED_BLOCKS.fetch_add(found, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Inspecting = Inspecting;

/// Four secret words, as the bytes of a plaintext buffer.
fn plaintext() -> Vec<u8> {
    SECRET.to_ne_bytes().repeat(4)
}

// One test, so no other thread allocates while the allocator is armed.
#[test]
fn a_failed_seal_frees_no_plaintext() {
    // The allocator does see the words when a block that holds them is
    // freed unwiped.
    let bare = plaintext();
    LEFT_IN_FREED_BLOCKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    drop(bare);
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(LEFT_IN_FREED_BLOCKS.load(Ordering::SeqCst), 4);

    // A seal that fails without touching the buffer, as a backend that
    // refuses its input would.
    let nonce = RandomNonceGenerator::<12>::init()
        .and_then(|g| g.generate())
        .expect("nonce");
    let secret = Protected::new(plaintext());
    LEFT_IN_FREED_BLOCKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let sealed = CipherTextBuilder::new()
        .append_nonce(nonce)
        .append_target_plaintext(secret)
        .accepts_ciphertext_and_tag_ok(|_| Err("seal failed"))
        .build();
    ARMED.store(false, Ordering::SeqCst);
    assert!(sealed.is_err(), "the seal should have failed");
    assert_eq!(LEFT_IN_FREED_BLOCKS.load(Ordering::SeqCst), 0);
}

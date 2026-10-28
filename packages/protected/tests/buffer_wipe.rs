//! Dropping a `Buffer` must wipe its allocation before it is freed.
//!
//! This test installs a global allocator that watches one allocation and
//! records whether every byte of it was zero when it was freed. It lives
//! in its own test binary so that allocator sees nothing but this test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use vitaminc_protected::{Buffer, Controlled};

/// The allocation under watch, whether it was freed, and whether every
/// byte was zero when it was.
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static FREED: AtomicBool = AtomicBool::new(false);
static FREED_ZEROED: AtomicBool = AtomicBool::new(false);

struct Watching;

// SAFETY: every call is forwarded to `System` unchanged. `dealloc` only
// reads the block it is about to free, which the caller still owns.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Only the first free of the watched address is the buffer's own;
        // the address can be handed out again afterwards.
        let watched = WATCHED.compare_exchange(
            ptr,
            std::ptr::null_mut(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        if watched.is_ok() {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes.
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            FREED_ZEROED.store(block.iter().all(|&b| b == 0), Ordering::SeqCst);
            FREED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

#[test]
fn dropping_a_buffer_frees_its_allocation_wiped() {
    let mut out = Buffer::with_capacity(64);
    out.extend_from_slice(b"a secret that must not outlive its buffer");
    WATCHED.store(out.risky_ref().as_ptr().cast_mut(), Ordering::SeqCst);
    drop(out);
    assert!(
        FREED.load(Ordering::SeqCst),
        "the buffer's allocation was never freed"
    );
    assert!(
        FREED_ZEROED.load(Ordering::SeqCst),
        "the buffer's allocation was freed with its bytes still in it"
    );
}

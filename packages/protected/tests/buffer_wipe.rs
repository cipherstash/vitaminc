//! A `Buffer` must wipe an allocation before it is freed: when it is
//! dropped, and when it grows out of one into a bigger one.
//!
//! These tests install a global allocator that watches one allocation and
//! records whether every byte of it was zero when it was freed. They live
//! in their own test binary so that allocator sees nothing but them, and
//! they take turns, since there is one allocation under watch at a time.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, MutexGuard};

use vitaminc_protected::{Buffer, Controlled};

/// The allocation under watch, whether it was freed, and whether every
/// byte was zero when it was.
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static FREED: AtomicBool = AtomicBool::new(false);
static FREED_ZEROED: AtomicBool = AtomicBool::new(false);

/// Held by a test for as long as it watches an allocation.
static TURN: Mutex<()> = Mutex::new(());

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

/// Wait for this test's turn to watch an allocation. Taken before the
/// buffer is made, so the buffer is dropped before the turn passes on.
fn take_turn() -> MutexGuard<'static, ()> {
    TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Start watching the allocation `out` holds now.
fn watch(out: &Buffer) {
    FREED.store(false, Ordering::SeqCst);
    FREED_ZEROED.store(false, Ordering::SeqCst);
    WATCHED.store(out.risky_ref().as_ptr().cast_mut(), Ordering::SeqCst);
}

/// Fail unless the watched allocation was freed, and freed all zeros.
fn assert_freed_wiped(when: &str) {
    assert!(
        FREED.load(Ordering::SeqCst),
        "the buffer's allocation was never freed {when}"
    );
    assert!(
        FREED_ZEROED.load(Ordering::SeqCst),
        "the buffer's allocation was freed with its bytes still in it {when}"
    );
}

/// A buffer holding secret bytes up to its capacity, so the next byte
/// written makes it grow.
fn full_buffer() -> Buffer {
    let mut out = Buffer::with_capacity(64);
    let capacity = out.risky_ref().capacity();
    for i in 0..capacity {
        out.push(0xA5 ^ i as u8);
    }
    assert_eq!(
        out.risky_ref().capacity(),
        capacity,
        "filling the buffer to its capacity does not grow it"
    );
    out
}

#[test]
fn dropping_a_buffer_frees_its_allocation_wiped() {
    let _turn = take_turn();
    let mut out = Buffer::with_capacity(64);
    out.extend_from_slice(b"a secret that must not outlive its buffer");
    watch(&out);
    drop(out);
    assert_freed_wiped("when it was dropped");
}

#[test]
fn growing_by_push_frees_the_old_allocation_wiped() {
    let _turn = take_turn();
    let mut out = full_buffer();
    watch(&out);
    out.push(0x5A);
    assert_freed_wiped("when a push made it grow");
    assert_eq!(out.risky_ref().last(), Some(&0x5A), "the byte was written");
}

#[test]
fn growing_by_extend_from_slice_frees_the_old_allocation_wiped() {
    let _turn = take_turn();
    let mut out = full_buffer();
    watch(&out);
    out.extend_from_slice(b"more secret");
    assert_freed_wiped("when extend_from_slice made it grow");
    assert!(
        out.risky_ref().ends_with(b"more secret"),
        "the bytes were written"
    );
}

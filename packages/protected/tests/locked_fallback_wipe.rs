//! On the heap-backed fallback (non-Unix targets and Miri) an observing
//! global allocator can see the bytes of a `Locked` region at the moment it
//! is released. They must be zero on every release path, including the one
//! where `T`'s destructor panics.
#![cfg(not(all(unix, not(miri))))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use vitaminc_protected::Locked;
use zeroize::Zeroize;

/// The region under observation, set by the test before the release.
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
/// Whether the watched allocation was released with every byte zero.
static RELEASED_ZEROED: AtomicBool = AtomicBool::new(false);
const SIZE: usize = 32;

struct Observing;

// SAFETY: every call is forwarded to `System`; the inspection reads only the
// allocation being freed, which is still live at that point.
unsafe impl GlobalAlloc for Observing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr == WATCHED.load(Ordering::SeqCst) && layout.size() == SIZE {
            let bytes = std::slice::from_raw_parts(ptr, SIZE);
            RELEASED_ZEROED.store(bytes.iter().all(|&b| b == 0), Ordering::SeqCst);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOC: Observing = Observing;

struct Angry([u8; SIZE]);
impl Zeroize for Angry {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for Angry {
    fn drop(&mut self) {
        panic!("angry");
    }
}

#[test]
fn the_region_is_released_zeroed_when_the_destructor_panics() {
    let key = Locked::new(Angry([0xEE; SIZE])).unwrap();
    WATCHED.store(key.risky_ref().0.as_ptr().cast_mut(), Ordering::SeqCst);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(key)));
    assert!(r.is_err());
    assert!(
        RELEASED_ZEROED.load(Ordering::SeqCst),
        "the region reached the allocator with the secret still in it"
    );
}

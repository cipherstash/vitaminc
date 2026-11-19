//! With `WipingAllocator` installed as the global allocator, a secret in a
//! `Vec` that is dropped bare, or that grows past its capacity, is not left
//! in the block that is freed.
//!
//! The check is the one `residue_heap` makes: an allocator underneath the
//! wiping one that, while armed, scans every block it is handed back for a
//! planted marker, and counts the blocks. The wiping allocator sits above
//! it, so what the scan sees is what the wipe left.
//!
//! The allocator is process-wide, so the tests that arm it take `SCAN`.
//!
//! Not run under Miri: the scan compares every byte of a block being freed,
//! and a block's spare capacity is uninitialised memory.
#![cfg(not(miri))]

use core::hint::black_box;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use vitaminc_protected::{Controlled, Protected, WipingAllocator};

const MARKER: &[u8] = b"vitaminc wiping allocator marker: bytes that must not be freed as they are";

static ARMED: AtomicBool = AtomicBool::new(false);
static FREES: AtomicUsize = AtomicUsize::new(0);
static HITS: AtomicUsize = AtomicUsize::new(0);
static SCAN: Mutex<()> = Mutex::new(());

/// The system allocator, scanning each block it is handed back for
/// `MARKER` while armed.
struct Scanning;

unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Acquire) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes.
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(MARKER.len()).any(|w| w == MARKER) {
                HITS.fetch_add(1, Ordering::AcqRel);
            }
            FREES.fetch_add(1, Ordering::AcqRel);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: WipingAllocator<Scanning> = WipingAllocator::new(Scanning);

/// How many blocks were freed while `f` ran, and how many of them still
/// held `MARKER`.
fn freed(f: impl FnOnce()) -> (usize, usize) {
    let _guard = SCAN.lock().unwrap_or_else(|e| e.into_inner());
    FREES.store(0, Ordering::Release);
    HITS.store(0, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    ARMED.store(false, Ordering::Release);
    let seen = (FREES.load(Ordering::Acquire), HITS.load(Ordering::Acquire));
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
    seen
}

mod given_the_scan {
    use super::*;

    /// A block freed through `Scanning` itself, below the wipe, shows the
    /// marker: the scan looks at the right memory.
    #[test]
    fn sees_a_block_freed_unwiped() {
        let layout = Layout::from_size_align(MARKER.len(), 1).unwrap();
        let (frees, hits) = freed(|| unsafe {
            let ptr = Scanning.alloc(layout);
            assert!(!ptr.is_null());
            core::ptr::copy_nonoverlapping(MARKER.as_ptr(), ptr, MARKER.len());
            Scanning.dealloc(ptr, layout);
        });
        assert_eq!(frees, 1);
        assert_eq!(
            hits, 1,
            "the scan should find the marker in the freed block"
        );
    }
}

mod given_a_vec_dropped_bare {
    use super::*;

    #[test]
    fn its_block_is_wiped_before_it_is_freed() {
        let bare = black_box(MARKER.to_vec());
        let (frees, hits) = freed(|| drop(black_box(bare)));
        assert!(frees >= 1, "the block was freed");
        assert_eq!(hits, 0, "and the marker was not in it");
    }
}

mod given_a_vec_grows_past_its_capacity {
    use super::*;

    #[test]
    fn the_block_it_leaves_is_wiped_before_it_is_freed() {
        let mut v = Vec::with_capacity(MARKER.len());
        v.extend_from_slice(black_box(MARKER));
        let (frees, hits) = freed(|| {
            v.extend_from_slice(&[0u8; 4096]);
            black_box(&v);
        });
        assert!(frees >= 1, "the old block was freed");
        assert_eq!(hits, 0, "and the marker was not in it");
        drop(v);
    }

    /// The case `Protected` cannot reach on its own: a `Vec` grown inside
    /// the wrapper frees its old block, and the wrapper's wipe only reaches
    /// the new one.
    #[test]
    fn inside_a_protected_the_block_it_leaves_is_wiped_too() {
        let mut p = Protected::new(Vec::with_capacity(MARKER.len()));
        p.risky_update(|v| v.extend_from_slice(black_box(MARKER)));
        let (frees, hits) = freed(|| {
            p.risky_update(|v| v.extend_from_slice(&[0u8; 4096]));
            black_box(&p);
        });
        assert!(frees >= 1, "the old block was freed");
        assert_eq!(hits, 0, "and the marker was not in it");
        drop(p);
    }
}

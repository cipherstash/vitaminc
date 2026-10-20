//! What the `Controlled` combinators leave on the heap.
//!
//! The combinators hand the closure the inner value as an `Owned`, which
//! wipes it on drop. For a heap-backed value such as `Vec<u8>` that means the
//! buffer is zeroed before it is freed, however the closure ends: by reading
//! the value, by taking it out with `into_inner` and wrapping it again, or by
//! panicking.
//!
//! The check is an allocator that, while armed, scans every block being freed
//! for a planted marker before handing it to the system allocator. The scan
//! happens inside `dealloc`, while the block is still owned, so no freed
//! memory is ever read. `realloc` is left to the trait's default (allocate,
//! copy, free through this wrapper), so a block a growing buffer abandons is
//! scanned as well.
//!
//! The allocator is process-wide, so the tests that arm it take `SCAN`.
//!
//! Not run under Miri: the scan compares every byte of a block being freed,
//! and a block's spare capacity is uninitialised memory.
#![cfg(not(miri))]

use core::cell::UnsafeCell;
use core::hint::black_box;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use vitaminc_protected::{Controlled, Protected};

const MARKER: &[u8] = b"vitaminc residue marker: heap secret bytes that must be wiped";
const MAX_PATTERN: usize = 128;

struct Pattern(UnsafeCell<[u8; MAX_PATTERN]>);
// Written only while disarmed, under `SCAN`; read only while armed.
unsafe impl Sync for Pattern {}

static PATTERN: Pattern = Pattern(UnsafeCell::new([0; MAX_PATTERN]));
static PATTERN_LEN: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static SCAN: Mutex<()> = Mutex::new(());

struct ScanningAlloc;

unsafe fn block_holds_pattern(ptr: *const u8, size: usize) -> bool {
    let len = PATTERN_LEN.load(Ordering::Acquire);
    if len == 0 || size < len {
        return false;
    }
    let pat = core::slice::from_raw_parts(PATTERN.0.get().cast::<u8>(), len);
    let block = core::slice::from_raw_parts(ptr, size);
    block.windows(len).any(|w| w == pat)
}

unsafe impl GlobalAlloc for ScanningAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Acquire) && block_holds_pattern(ptr, layout.size()) {
            HITS.fetch_add(1, Ordering::AcqRel);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: ScanningAlloc = ScanningAlloc;

/// Freed blocks holding `MARKER` while `f` runs.
fn leaked_blocks(f: impl FnOnce()) -> usize {
    let _guard = SCAN.lock().unwrap_or_else(|e| e.into_inner());
    assert!(MARKER.len() <= MAX_PATTERN);
    // SAFETY: written while disarmed and under `SCAN`, so no `dealloc` reads
    // the pattern concurrently.
    unsafe {
        core::slice::from_raw_parts_mut(PATTERN.0.get().cast::<u8>(), MARKER.len())
            .copy_from_slice(MARKER)
    };
    PATTERN_LEN.store(MARKER.len(), Ordering::Release);
    HITS.store(0, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    ARMED.store(false, Ordering::Release);
    PATTERN_LEN.store(0, Ordering::Release);
    let hits = HITS.load(Ordering::Acquire);
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
    hits
}

fn secret() -> Protected<Vec<u8>> {
    Protected::new(black_box(MARKER.to_vec()))
}

mod given_the_scan {
    use super::*;

    #[test]
    fn sees_a_vec_freed_unwiped() {
        let n = leaked_blocks(|| {
            let bare: Vec<u8> = secret().risky_unwrap();
            drop(black_box(bare));
        });
        assert!(n >= 1, "the scan should find the marker in the freed block");
    }
}

mod given_a_heap_inner_the_closure_only_reads {
    use super::*;

    #[test]
    fn map_wipes_it_before_the_free() {
        let p = secret();
        let n = leaked_blocks(|| drop(black_box(p.map(|v| v.len()))));
        assert_eq!(n, 0, "map should wipe the Vec the closure dropped");
    }

    #[test]
    fn map_ok_wipes_it_before_the_free() {
        let p = secret();
        let n = leaked_blocks(|| {
            let out: Result<Protected<usize>, ()> = p.map_ok(|v| Ok(v.len()));
            drop(black_box(out));
        });
        assert_eq!(n, 0, "map_ok should wipe the Vec the closure dropped");
    }

    #[test]
    fn zip_wipes_both_before_the_free() {
        let (a, b) = (secret(), secret());
        let n = leaked_blocks(|| drop(black_box(a.zip(b, |a, b| a.len() + b.len()))));
        assert_eq!(n, 0, "zip should wipe both Vecs the closure dropped");
    }

    #[test]
    fn zip_ref_wipes_the_moved_one_before_the_free() {
        let (a, b) = (secret(), secret());
        let n = leaked_blocks(|| {
            drop(black_box(a.zip_ref(&b, |a, b: &Vec<u8>| a.len() + b.len())));
            drop(b);
        });
        assert_eq!(n, 0, "zip_ref should wipe the Vec the closure dropped");
    }

    #[test]
    fn update_with_wipes_the_other_before_the_free() {
        let (mut a, b) = (secret(), secret());
        let n = leaked_blocks(|| {
            a.update_with(b, |a, b| a.truncate(b.len() / 2));
            drop(a);
        });
        assert_eq!(n, 0, "update_with should wipe the Vec the closure dropped");
    }
}

mod given_a_heap_inner_the_closure_takes_out {
    use super::*;

    #[test]
    fn into_inner_moves_the_same_buffer() {
        let p = secret();
        let before = p.risky_ref().as_ptr();
        let n = leaked_blocks(|| {
            let out: Protected<String> = p
                .map_ok(|v| String::from_utf8(v.into_inner()))
                .expect("the marker is ASCII");
            assert_eq!(out.risky_ref().as_ptr(), before, "no copy should be made");
            drop(out);
        });
        assert_eq!(n, 0, "the converted String should be wiped by its wrapper");
    }
}

mod given_the_closure_panics {
    use super::*;

    #[test]
    fn the_value_is_wiped_on_unwind() {
        let p = secret();
        let n = leaked_blocks(|| {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _: Protected<usize> = p.map(|v| {
                    black_box(&*v);
                    panic!("closure failed with the secret in hand")
                });
            }));
            assert!(outcome.is_err(), "the closure should have panicked");
        });
        assert_eq!(n, 0, "an unwinding closure should still wipe the Vec");
    }
}

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use std::alloc::System;

use crate::locked::wipe_raw;

/// A global allocator that wipes every block before it is freed, so a secret
/// is not left in freed memory by a `Vec` that grew, or by a buffer freed
/// bare.
///
/// [`Protected`] and [`Buffer`] wipe what they hold when they drop. They
/// cannot reach a block that is freed from under them: a `Vec<u8>` that
/// outgrows its allocation moves to a fresh block and frees the old one with
/// the bytes still in it, and `zeroize` on the `Vec` only reaches the current
/// block. [`Buffer`] closes that gap for the bytes it writes, by growing into
/// a fresh allocation and wiping the old one itself. This allocator closes it
/// for every allocation in the process, including the ones made by code that
/// does not know it is handling a secret: a `Vec` grown by pushes, a `String`
/// that reallocates, a dependency's working buffer.
///
/// It wraps another [`GlobalAlloc`], [`System`] by default. Allocation is
/// passed through. Deallocation wipes the block, with the same volatile stores
/// and fence that [`Locked`] and [`Buffer`] use, and then frees it.
/// Reallocation takes a new block, copies the bytes over, and wipes and frees
/// the old one. It never grows a block in place: the allocator underneath
/// could move the bytes to do that, and this one would not see the block they
/// left.
///
/// # Cost
///
/// Every free in the process wipes its block, and every reallocation copies
/// rather than growing in place. That is a store over every freed byte and a
/// copy on every growth, for every allocation and not only the secret ones.
/// So it is off by default, behind the `wiping-allocator` feature, for a
/// program whose threat model includes memory it has freed: a core dump, a
/// page swapped to disk, a read by whatever shares the machine.
///
/// # What it does not cover
///
/// - Blocks freed by another allocator. Memory that a C library or a foreign
///   runtime allocates and frees never passes through this one.
/// - Memory the operating system reclaims without a free. A process that
///   aborts or is killed leaves its heap as it was, as it leaves anything
///   `Protected` holds; [`Locked`] is for a secret that must not reach a core
///   dump or swap.
/// - The stack. What the `Controlled` combinators leave there is measured by
///   this crate's residue tests, not by the allocator.
/// - A read of a block while it is live. This is about what a program leaves
///   behind, not about who can read a secret it is using.
///
/// # Examples
///
/// ```
/// use vitaminc_protected::WipingAllocator;
///
/// #[global_allocator]
/// static ALLOCATOR: WipingAllocator = WipingAllocator::new(std::alloc::System);
///
/// // Growing past its capacity moves this `Vec` to a new block. The block it
/// // leaves is wiped before it is freed.
/// let mut secret = Vec::with_capacity(1);
/// secret.extend_from_slice(b"longer than one byte");
/// ```
///
/// [`Protected`]: crate::Protected
/// [`Buffer`]: crate::Buffer
/// [`Locked`]: crate::Locked
#[cfg_attr(docsrs, doc(cfg(feature = "wiping-allocator")))]
pub struct WipingAllocator<A = System> {
    inner: A,
}

impl<A> WipingAllocator<A> {
    /// Wrap `inner`, which allocates and frees; this allocator wipes.
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

// SAFETY: every allocation and free is passed to `inner`, which upholds the
// trait's contract, with the layout the caller gave. `dealloc` writes to a
// block the caller still owns and is giving up, before `inner` frees it.
// `realloc` does what the trait's default does: a new block from `inner`, the
// shorter of the two sizes copied over, and the old block freed through
// `dealloc` only once the new one is in hand. When `inner` gives no block the
// old one is untouched and still the caller's, as the contract requires.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's obligations are this method's own.
        unsafe { self.inner.alloc(layout) }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's obligations are this method's own.
        unsafe { self.inner.alloc_zeroed(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: by this method's contract `ptr` is a block of
        // `layout.size()` bytes that `inner` gave out and the caller is
        // giving up, so it is valid for writes until `inner` frees it.
        unsafe {
            wipe_raw(ptr, layout.size());
            self.inner.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: by this method's contract `new_size` is not zero and does
        // not overflow `isize` when rounded up to `layout.align()`.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: the caller's obligations are this method's own.
        let new = unsafe { self.inner.alloc(new_layout) };
        if !new.is_null() {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes and
            // `new` a fresh one of `new_size`, so they do not overlap and
            // each holds the shorter length. `ptr` is then given up, as
            // `dealloc` requires.
            unsafe {
                ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// What the allocator underneath was handed back.
    #[derive(Default)]
    struct Seen {
        frees: AtomicUsize,
        /// Bytes that were not zero in the blocks freed.
        bytes_left: AtomicUsize,
    }

    /// The system allocator, counting each block it frees and the bytes of
    /// it that were not wiped. The tests write every byte of a block before
    /// it is freed, so the count reads nothing uninitialised.
    struct Counting(Arc<Seen>);

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes, each
            // of which the test wrote.
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            let left = block.iter().filter(|&&b| b != 0).count();
            self.0.bytes_left.fetch_add(left, Ordering::SeqCst);
            self.0.frees.fetch_add(1, Ordering::SeqCst);
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    fn wiping() -> (WipingAllocator<Counting>, Arc<Seen>) {
        let seen = Arc::new(Seen::default());
        (WipingAllocator::new(Counting(Arc::clone(&seen))), seen)
    }

    fn layout(size: usize) -> Layout {
        Layout::from_size_align(size, 1).unwrap()
    }

    /// A block of `size` bytes, every one `byte`.
    unsafe fn filled(alloc: &impl GlobalAlloc, size: usize, byte: u8) -> *mut u8 {
        let ptr = unsafe { alloc.alloc(layout(size)) };
        assert!(!ptr.is_null(), "a block of {size} bytes was given");
        unsafe { ptr::write_bytes(ptr, byte, size) };
        ptr
    }

    unsafe fn holds(ptr: *const u8, len: usize, byte: u8) -> bool {
        unsafe { core::slice::from_raw_parts(ptr, len) }
            .iter()
            .all(|&b| b == byte)
    }

    mod given_a_block_is_freed {
        use super::*;

        #[test]
        fn it_is_wiped_first() {
            let (alloc, seen) = wiping();
            unsafe {
                let ptr = filled(&alloc, 64, 0xAB);
                alloc.dealloc(ptr, layout(64));
            }
            assert_eq!(seen.frees.load(Ordering::SeqCst), 1, "the block was freed");
            assert_eq!(
                seen.bytes_left.load(Ordering::SeqCst),
                0,
                "with nothing in it"
            );
        }
    }

    mod given_a_zeroed_block {
        use super::*;

        #[test]
        fn it_is_zero_and_is_freed() {
            let (alloc, seen) = wiping();
            unsafe {
                let ptr = alloc.alloc_zeroed(layout(64));
                assert!(!ptr.is_null());
                assert!(holds(ptr, 64, 0), "every byte is zero");
                alloc.dealloc(ptr, layout(64));
            }
            assert_eq!(seen.frees.load(Ordering::SeqCst), 1);
        }
    }

    mod given_a_block_grows {
        use super::*;

        #[test]
        fn the_bytes_move_and_the_old_block_is_wiped_before_it_is_freed() {
            let (alloc, seen) = wiping();
            unsafe {
                let old = filled(&alloc, 64, 0xAB);
                let new = alloc.realloc(old, layout(64), 128);
                assert!(!new.is_null(), "a larger block was given");
                assert!(holds(new, 64, 0xAB), "the bytes were copied over");
                assert_eq!(
                    seen.frees.load(Ordering::SeqCst),
                    1,
                    "the old block was freed"
                );
                assert_eq!(seen.bytes_left.load(Ordering::SeqCst), 0, "wiped first");
                ptr::write_bytes(new.add(64), 0xCD, 64);
                alloc.dealloc(new, layout(128));
            }
            assert_eq!(seen.frees.load(Ordering::SeqCst), 2);
            assert_eq!(seen.bytes_left.load(Ordering::SeqCst), 0);
        }
    }

    mod given_a_block_shrinks {
        use super::*;

        #[test]
        fn the_leading_bytes_move_and_the_old_block_is_wiped_before_it_is_freed() {
            let (alloc, seen) = wiping();
            unsafe {
                let old = filled(&alloc, 64, 0xAB);
                let new = alloc.realloc(old, layout(64), 16);
                assert!(!new.is_null(), "a smaller block was given");
                assert!(holds(new, 16, 0xAB), "the leading bytes were copied over");
                assert_eq!(
                    seen.frees.load(Ordering::SeqCst),
                    1,
                    "the old block was freed"
                );
                assert_eq!(seen.bytes_left.load(Ordering::SeqCst), 0, "wiped first");
                alloc.dealloc(new, layout(16));
            }
            assert_eq!(seen.frees.load(Ordering::SeqCst), 2);
            assert_eq!(seen.bytes_left.load(Ordering::SeqCst), 0);
        }
    }

    mod given_a_growth_the_allocator_underneath_refuses {
        use super::*;

        /// The contract: on failure the old block is untouched and still
        /// the caller's.
        #[test]
        #[cfg_attr(
            miri,
            ignore = "Miri stops at an allocation it cannot make, rather than returning null"
        )]
        fn the_old_block_is_left_as_it_was() {
            let (alloc, seen) = wiping();
            unsafe {
                let old = filled(&alloc, 64, 0xAB);
                let new = alloc.realloc(old, layout(64), isize::MAX as usize);
                assert!(new.is_null(), "no block that large can be given");
                assert_eq!(
                    seen.frees.load(Ordering::SeqCst),
                    0,
                    "the old block was not freed"
                );
                assert!(holds(old, 64, 0xAB), "and holds what it did");
                alloc.dealloc(old, layout(64));
            }
            assert_eq!(seen.frees.load(Ordering::SeqCst), 1);
            assert_eq!(seen.bytes_left.load(Ordering::SeqCst), 0);
        }
    }
}

//! The backend for targets with no memory locking (non-Unix builds, and
//! Miri, which has no `mlock`): a plain heap allocation that is wiped on
//! release. Every region reports its lock as unavailable.
//!
//! Also compiled into Unix test builds, where it is not the backend in use,
//! so that its own tests below run (and are mutated) on the platforms CI has.

use super::LockError;
use core::ptr::NonNull;
use std::alloc::{alloc_zeroed, dealloc, Layout};

pub(super) struct Region {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl Region {
    pub(super) fn allocate(
        size: usize,
        align: usize,
    ) -> Result<(Self, Option<LockError>), LockError> {
        // `alloc_zeroed` requires a non-zero size; a zero-sized `T` gets one byte.
        let layout = Layout::from_size_align(size.max(1), align)
            .map_err(|_| LockError::Alignment { align, page: 0 })?;
        // SAFETY: the layout has non-zero size.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).ok_or_else(|| LockError::Map {
            bytes: layout.size(),
            source: std::io::Error::from(std::io::ErrorKind::OutOfMemory),
        })?;
        Ok((Self { ptr, layout }, Some(LockError::Unavailable)))
    }

    pub(super) fn ptr(&self) -> NonNull<u8> {
        self.ptr
    }

    /// The allocation is exactly the value's size, so the value is at its
    /// start; there is no guard to sit against.
    pub(super) fn value_ptr(&self, _size: usize, _align: usize) -> NonNull<u8> {
        self.ptr
    }

    pub(super) fn wipe(&mut self) {
        // SAFETY: the allocation is live, exclusively borrowed and writable
        // for `layout.size()` bytes. Written as `MaybeUninit<u8>` because a
        // `T` may have left padding in it.
        unsafe { super::wipe_raw(self.ptr.as_ptr(), self.layout.size()) };
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // The wipe is part of the release so that a panicking `T::drop`, or
        // a constructor that never wrote a `T`, still hands back zeroed bytes.
        self.wipe();
        // SAFETY: `ptr` was returned by `alloc_zeroed` with this exact layout.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, System};
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

    /// One allocation under observation: whether it was released, and
    /// whether every byte was zero when it was.
    static WATCHED: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
    static RELEASED: AtomicBool = AtomicBool::new(false);
    static RELEASED_ZEROED: AtomicBool = AtomicBool::new(false);

    struct Observing;

    // SAFETY: every call is forwarded to `System`; the inspection reads only
    // the allocation being freed, which is still live at that point.
    unsafe impl GlobalAlloc for Observing {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            System.alloc(layout)
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            System.alloc_zeroed(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // Only the first release of the watched address is the region's
            // own; the address is free to be reused afterwards, and a later
            // occupant's bytes are neither ours nor necessarily initialised.
            let watched = WATCHED.compare_exchange(
                ptr,
                std::ptr::null_mut(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            if watched.is_ok() {
                let bytes = core::slice::from_raw_parts(ptr, layout.size());
                RELEASED_ZEROED.store(bytes.iter().all(|&b| b == 0), Ordering::SeqCst);
                RELEASED.store(true, Ordering::SeqCst);
            }
            System.dealloc(ptr, layout)
        }
    }

    #[global_allocator]
    static ALLOC: Observing = Observing;

    fn fill(region: &Region, len: usize, byte: u8) -> &[u8] {
        // SAFETY: the allocation is live and at least `len` bytes.
        unsafe {
            let bytes = core::slice::from_raw_parts_mut(region.ptr().as_ptr(), len);
            bytes.fill(byte);
            bytes
        }
    }

    #[test]
    fn a_region_is_a_zeroed_heap_allocation_that_reports_no_lock() {
        let (region, lock) = Region::allocate(32, 8).unwrap();
        assert!(matches!(lock, Some(LockError::Unavailable)), "{lock:?}");
        assert_eq!(region.ptr().as_ptr() as usize % 8, 0);
        assert_eq!(region.layout.size(), 32);
        // SAFETY: 32 live, zero-initialised bytes.
        let bytes = unsafe { core::slice::from_raw_parts(region.ptr().as_ptr(), 32) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn the_value_is_at_the_start_of_the_allocation() {
        let (region, _) = Region::allocate(24, 8).unwrap();
        assert_eq!(region.value_ptr(24, 8), region.ptr());
    }

    #[test]
    fn a_zero_sized_request_still_gets_a_byte() {
        let (region, _) = Region::allocate(0, 1).unwrap();
        assert_eq!(region.layout.size(), 1);
    }

    #[test]
    fn a_wipe_zeroes_the_whole_allocation() {
        let (mut region, _) = Region::allocate(48, 1).unwrap();
        assert!(fill(&region, 48, 0xAB).iter().all(|&b| b == 0xAB));
        region.wipe();
        // SAFETY: 48 live bytes.
        let bytes = unsafe { core::slice::from_raw_parts(region.ptr().as_ptr(), 48) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn dropping_a_region_releases_it_zeroed() {
        let (region, _) = Region::allocate(64, 1).unwrap();
        fill(&region, 64, 0xCD);
        WATCHED.store(region.ptr().as_ptr(), Ordering::SeqCst);
        drop(region);
        assert!(
            RELEASED.load(Ordering::SeqCst),
            "the allocation was never freed"
        );
        assert!(
            RELEASED_ZEROED.load(Ordering::SeqCst),
            "the allocation reached the allocator with its contents intact"
        );
    }
}

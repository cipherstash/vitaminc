//! The backend for targets with no memory locking (non-Unix builds, and
//! Miri, which has no `mlock`): a plain heap allocation that is wiped on
//! release. Every region reports its lock as unavailable.

use super::LockError;
use core::ptr::NonNull;
use std::alloc::{alloc_zeroed, dealloc, Layout};
use zeroize::Zeroize;

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

    pub(super) fn wipe(&mut self) {
        // SAFETY: the allocation is live, exclusively borrowed, and was
        // zero-initialised, so every byte is initialised.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) };
        bytes.zeroize();
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

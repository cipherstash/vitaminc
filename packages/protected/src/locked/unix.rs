//! The Unix backend: an anonymous `mmap` region with guard pages, locked with
//! `mlock` and, on Linux, excluded from core dumps with `MADV_DONTDUMP`.

use super::LockError;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::io;
use zeroize::Zeroize;

/// One mapping: a guard page, the interior, a guard page. Two words: the
/// page size is a process constant, so the interior and the total length
/// are derived rather than stored.
pub(super) struct Region {
    base: NonNull<u8>,
    interior_len: usize,
}

fn page_size() -> usize {
    static PAGE: AtomicUsize = AtomicUsize::new(0);
    match PAGE.load(Ordering::Relaxed) {
        0 => {
            // SAFETY: sysconf has no preconditions.
            let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let page = usize::try_from(raw)
                .ok()
                .filter(|p| p.is_power_of_two())
                .unwrap_or(4096);
            PAGE.store(page, Ordering::Relaxed);
            page
        }
        page => page,
    }
}

/// The soft `RLIMIT_MEMLOCK`, for the error message when a lock is refused.
/// `None` when the limit is unlimited or could not be read.
fn memlock_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit for the duration of the call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
    if rc != 0 || lim.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    // `rlim_t` is `u64` on Linux and macOS but not on every Unix.
    #[allow(clippy::useless_conversion)]
    u64::try_from(lim.rlim_cur).ok()
}

impl Region {
    /// Map a guarded region whose interior can hold `size` bytes at `align`,
    /// and try to lock it. The lock outcome is returned separately from the
    /// region: a refused lock is a degraded region, not a failed one, and the
    /// caller's policy decides which it is.
    pub(super) fn allocate(
        size: usize,
        align: usize,
    ) -> Result<(Self, Option<LockError>), LockError> {
        let page = page_size();
        if align > page {
            return Err(LockError::Alignment { align, page });
        }
        // At least one page, so a zero-sized `T` still has a real interior
        // to point into and guards on both sides of it.
        let interior_len = size.max(1).div_ceil(page) * page;
        let total = interior_len + 2 * page;

        // SAFETY: an anonymous private mapping with no address hint has no
        // preconditions; the result is checked against MAP_FAILED below.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(LockError::Map {
                bytes: total,
                source: io::Error::last_os_error(),
            });
        }
        let base = NonNull::new(base.cast::<u8>()).ok_or_else(|| LockError::Map {
            bytes: total,
            source: io::Error::other("mmap returned a null mapping"),
        })?;
        // From here on `region` owns the mapping; an early return unmaps it.
        let region = Self { base, interior_len };

        let guard = |ptr: *mut u8| -> Result<(), LockError> {
            // SAFETY: both guard pages are page-aligned ranges inside the mapping.
            let rc = unsafe { libc::mprotect(ptr.cast(), page, libc::PROT_NONE) };
            if rc == 0 {
                Ok(())
            } else {
                Err(LockError::Guard {
                    source: io::Error::last_os_error(),
                })
            }
        };
        guard(base.as_ptr())?;
        // SAFETY: the trailing guard starts at base + page + interior_len, inside the mapping.
        guard(unsafe { base.as_ptr().add(page + interior_len) })?;

        let interior = region.interior();
        // SAFETY: the interior is a page-aligned, mapped, writable range.
        let rc = unsafe { libc::mlock(interior.as_ptr().cast(), interior_len) };
        let lock = (rc != 0).then(|| LockError::Refused {
            bytes: interior_len,
            limit: memlock_limit(),
            source: io::Error::last_os_error(),
        });

        #[cfg(target_os = "linux")]
        {
            // Exclusion from core dumps. This cannot fail for a private
            // anonymous mapping we own, and there is nothing to do if it did:
            // the mapping is still usable and still locked.
            // SAFETY: same range as the mlock above.
            let _ = unsafe {
                libc::madvise(interior.as_ptr().cast(), interior_len, libc::MADV_DONTDUMP)
            };
        }

        Ok((region, lock))
    }

    fn interior(&self) -> NonNull<u8> {
        // SAFETY: base + page is inside a mapping of interior_len + 2 * page bytes.
        unsafe { NonNull::new_unchecked(self.base.as_ptr().add(page_size())) }
    }

    fn total(&self) -> usize {
        self.interior_len + 2 * page_size()
    }

    /// The interior: `interior_len` bytes, page-aligned, readable and writable.
    pub(super) fn ptr(&self) -> NonNull<u8> {
        self.interior()
    }

    /// Overwrite the whole interior with zeros using volatile writes and a
    /// compiler fence (`zeroize`'s own primitive), so the wipe cannot be
    /// elided as a dead store.
    pub(super) fn wipe(&mut self) {
        // SAFETY: the interior is a live, exclusively borrowed, writable range
        // of `interior_len` initialised bytes (mmap zero-fills).
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(self.interior().as_ptr(), self.interior_len) };
        bytes.zeroize();
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: the interior was locked (or the lock was refused, in which
        // case munlock is a no-op) and `base..base+total` is our mapping.
        // Neither call can meaningfully fail on a mapping we own, and there is
        // no caller to report to from a destructor.
        unsafe {
            let _ = libc::munlock(self.interior().as_ptr().cast(), self.interior_len);
            let _ = libc::munmap(self.base.as_ptr().cast(), self.total());
        }
    }
}

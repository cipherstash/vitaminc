//! The Unix backend: an anonymous `mmap` region with guard pages, locked with
//! `mlock` and, on Linux, excluded from core dumps with `MADV_DONTDUMP`.
//! Releasing the region wipes it first, whatever path led to the release.
//!
//! Under Miri the same code maps, uses and releases the region: Miri models
//! `mmap` and `munmap`, so the pointer arithmetic is checked for real, and
//! only the calls it has no model for (`mprotect`, `mlock`, `madvise`) are
//! skipped.

use super::layout;
use super::LockError;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::io;

/// One mapping: a guard page, the interior, a guard page. Two words: the
/// page size is a process constant, so the interior and the total length
/// are derived rather than stored.
pub(super) struct Region {
    base: NonNull<u8>,
    interior_len: usize,
    /// The process that holds the lock. A forked child inherits the
    /// mapping, the guards and the dump exclusion, but not the lock.
    pid: libc::pid_t,
}

fn process_id() -> libc::pid_t {
    // SAFETY: getpid has no preconditions and cannot fail.
    unsafe { libc::getpid() }
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

/// The `mmap` arguments that are data rather than logic.
///
/// The flag bits are disjoint, so `|`, `^` and `+` all produce the same
/// value: every operator mutation in here is equivalent, hence the skip
/// (cargo-mutants honours it on a module, not on a `const`).
#[mutants::skip]
mod flags {
    /// The interior is readable and writable; the guard pages are
    /// re-protected to `PROT_NONE` after the map.
    pub(super) const INTERIOR_PROT: libc::c_int = libc::PROT_READ | libc::PROT_WRITE;
    pub(super) const MAP_FLAGS: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    /// No file backs an anonymous mapping; portable code passes `-1`.
    pub(super) const NO_FILE: libc::c_int = -1;
}
use flags::{INTERIOR_PROT, MAP_FLAGS, NO_FILE};

/// The soft `RLIMIT_MEMLOCK`, for the error message when a lock is refused.
/// `None` when the limit is unlimited, could not be read, or does not exist:
/// `mlock` exists everywhere this backend builds, but the limit that governs
/// it does not (illumos and Solaris, for instance, have no `RLIMIT_MEMLOCK`;
/// see `build.rs`), and a refusal there simply goes unexplained.
pub(super) fn memlock_limit() -> Option<u64> {
    #[cfg(not(memlock_limit))]
    {
        None
    }
    #[cfg(memlock_limit)]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `lim` is a valid, writable rlimit for the duration of the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
        if rc != 0 {
            return None;
        }
        if lim.rlim_cur == libc::RLIM_INFINITY {
            return None;
        }
        // `rlim_t` is `u64` on Linux and macOS but not on every Unix.
        #[allow(clippy::useless_conversion)]
        u64::try_from(lim.rlim_cur).ok()
    }
}

impl Region {
    /// Map a guarded region whose interior can hold `size` bytes at `align`,
    /// try to lock it and, on Linux, exclude it from core dumps. Those two
    /// outcomes are returned separately from the region: a protection that
    /// was refused is a degraded region, not a failed one, and the caller's
    /// policy decides which it is. When both are refused the lock refusal is
    /// the one reported.
    pub(super) fn allocate(
        size: usize,
        align: usize,
    ) -> Result<(Self, Option<LockError>), LockError> {
        let page = page_size();
        if align > page {
            return Err(LockError::Alignment { align, page });
        }
        let interior_len = layout::interior_len(size, page);
        let total = layout::total_len(interior_len, page);

        // SAFETY: an anonymous private mapping with no address hint has no
        // preconditions; the result is checked against MAP_FAILED below.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                INTERIOR_PROT,
                MAP_FLAGS,
                NO_FILE,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(LockError::Map {
                bytes: total,
                source: io::Error::last_os_error(),
            });
        }
        let Some(base) = NonNull::new(base.cast::<u8>()) else {
            // A mapping at address zero is a success the kernel may hand
            // out where low mappings are permitted, but not one a
            // `NonNull` region can own. Give it back rather than leak it.
            // SAFETY: `base..base+total` is the mapping just returned.
            unsafe {
                let _ = libc::munmap(base, total);
            }
            return Err(LockError::Map {
                bytes: total,
                source: io::Error::other("mmap returned a mapping at address zero"),
            });
        };
        // From here on `region` owns the mapping; an early return unmaps it.
        let region = Self {
            base,
            interior_len,
            pid: process_id(),
        };

        // Miri has no model for guard pages, the lock or the dump exclusion;
        // the region is still mapped, used and released for real, and its
        // lock is reported as unavailable.
        #[cfg(miri)]
        let lock = Some(LockError::Unavailable);
        #[cfg(not(miri))]
        let lock = region.protect(page)?;

        Ok((region, lock))
    }

    /// The guard pages, the lock and, on Linux, the dump exclusion. A guard
    /// that cannot be protected is an error; the other two are reported.
    #[cfg(not(miri))]
    fn protect(&self, page: usize) -> Result<Option<LockError>, LockError> {
        let interior_len = self.interior_len;
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
        guard(self.base.as_ptr())?;
        // SAFETY: the trailing guard starts at base + page + interior_len, inside the mapping.
        guard(unsafe { self.base.as_ptr().add(page + interior_len) })?;

        let lock = self.lock();

        // Exclusion from core dumps, applied whether or not the lock was
        // refused: the two protections are independent, and a value that
        // could not be locked is exactly the one a dump would otherwise
        // carry. A private anonymous mapping we own cannot be refused on its
        // own account, but a seccomp filter can refuse the call itself, and
        // `mlock` does not imply this protection.
        #[cfg(target_os = "linux")]
        let dump = {
            let interior = self.interior();
            // SAFETY: same range as the mlock above.
            let rc = unsafe {
                libc::madvise(interior.as_ptr().cast(), interior_len, libc::MADV_DONTDUMP)
            };
            (rc != 0).then(|| LockError::Dump {
                source: io::Error::last_os_error(),
            })
        };
        #[cfg(not(target_os = "linux"))]
        let dump: Option<LockError> = None;

        Ok(lock.or(dump))
    }

    /// Lock the interior against swapping; the refusal, if any.
    #[cfg(not(miri))]
    fn lock(&self) -> Option<LockError> {
        let interior_len = self.interior_len;
        // SAFETY: the interior is a page-aligned, mapped, writable range.
        let rc = unsafe { libc::mlock(self.interior().as_ptr().cast(), interior_len) };
        (rc != 0).then(|| {
            // errno first: reading the limit is another system call.
            let source = io::Error::last_os_error();
            LockError::Refused {
                bytes: interior_len,
                limit: memlock_limit(),
                source,
            }
        })
    }

    /// Whether this is the process the lock was taken in.
    pub(super) fn same_process(&self) -> bool {
        self.pid == process_id()
    }

    /// Take the lock again in the current process, and own it here from now
    /// on; the refusal, if any.
    pub(super) fn relock(&mut self) -> Option<LockError> {
        self.pid = process_id();
        #[cfg(miri)]
        {
            Some(LockError::Unavailable)
        }
        #[cfg(not(miri))]
        {
            self.lock()
        }
    }

    fn interior(&self) -> NonNull<u8> {
        // SAFETY: base + page is inside a mapping of interior_len + 2 * page bytes.
        unsafe { NonNull::new_unchecked(self.base.as_ptr().add(page_size())) }
    }

    fn total(&self) -> usize {
        layout::total_len(self.interior_len, page_size())
    }

    /// The interior: `interior_len` bytes, page-aligned, readable and
    /// writable. The value itself is at [`value_ptr`](Self::value_ptr);
    /// tests use this to look at the whole interior.
    #[cfg(test)]
    pub(super) fn ptr(&self) -> NonNull<u8> {
        self.interior()
    }

    /// Where a value of `size` bytes at `align` lives: as close to the
    /// trailing guard page as its alignment allows, so a write past its end
    /// reaches the guard within `align` bytes instead of wandering through
    /// the rest of the page. `size` never exceeds `interior_len`, which was
    /// rounded up from it.
    pub(super) fn value_ptr(&self, size: usize, align: usize) -> NonNull<u8> {
        let offset = layout::value_offset(self.interior_len, size, align);
        // SAFETY: `offset + size <= interior_len`, so the result is inside
        // the interior.
        unsafe { NonNull::new_unchecked(self.interior().as_ptr().add(offset)) }
    }

    /// Overwrite the whole interior with zeros using volatile writes and a
    /// compiler fence, so the wipe cannot be elided as a dead store.
    pub(super) fn wipe(&mut self) {
        // SAFETY: the interior is a live, exclusively borrowed, writable
        // range of `interior_len` bytes. It is written byte by byte as
        // `MaybeUninit<u8>` because a `T` may have left padding in it.
        unsafe { super::wipe_raw(self.interior().as_ptr(), self.interior_len) };
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // The wipe lives here, not in `Locked::drop`, so that it runs on
        // every path that releases the region: a `T` whose destructor
        // panics, a constructor that never got as far as writing a `T`.
        self.wipe();
        // SAFETY: the interior was locked (or the lock was refused, in which
        // case munlock is a no-op) and `base..base+total` is our mapping.
        // Neither call can meaningfully fail on a mapping we own, and there is
        // no caller to report to from a destructor.
        unsafe {
            #[cfg(not(miri))]
            let _ = libc::munlock(self.interior().as_ptr().cast(), self.interior_len);
            let _ = libc::munmap(self.base.as_ptr().cast(), self.total());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_total_is_the_interior_plus_a_guard_page_each_side() {
        let page = page_size();
        let (region, _) = Region::allocate(1, 1).unwrap();
        assert_eq!(region.total(), 3 * page);
        let (region, _) = Region::allocate(page + 1, 1).unwrap();
        assert_eq!(region.total(), 4 * page);
    }

    #[test]
    fn an_alignment_of_one_page_is_the_most_the_region_offers() {
        let page = page_size();
        assert!(Region::allocate(1, page).is_ok());
        assert!(matches!(
            Region::allocate(1, page * 2),
            Err(LockError::Alignment { align, page: p }) if align == page * 2 && p == page
        ));
    }

    #[test]
    fn the_value_sits_against_the_trailing_guard() {
        let page = page_size();
        let (region, _) = Region::allocate(32, 1).unwrap();
        let end = region.ptr().as_ptr() as usize + page;
        assert_eq!(region.value_ptr(32, 1).as_ptr() as usize + 32, end);
        // Alignment can hold it back, but by less than one alignment unit.
        let (region, _) = Region::allocate(24, 16).unwrap();
        let end = region.ptr().as_ptr() as usize + page;
        let value = region.value_ptr(24, 16).as_ptr() as usize;
        assert_eq!(value % 16, 0);
        assert!(
            end - (value + 24) < 16,
            "{} bytes of slack",
            end - (value + 24)
        );
        // A value that fills the interior exactly starts at its start.
        let (region, _) = Region::allocate(page, 1).unwrap();
        assert_eq!(region.value_ptr(page, 1), region.ptr());
    }

    #[test]
    fn a_wipe_zeroes_the_whole_interior() {
        let page = page_size();
        let (mut region, _) = Region::allocate(1, 1).unwrap();
        // SAFETY: the interior is `page` live, writable bytes.
        unsafe { core::slice::from_raw_parts_mut(region.ptr().as_ptr(), page).fill(0xEE) };
        region.wipe();
        // SAFETY: `page` initialised bytes; the wipe writes every one.
        let bytes = unsafe { core::slice::from_raw_parts(region.ptr().as_ptr(), page) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[cfg(all(memlock_limit, not(miri)))]
    #[test]
    fn the_memlock_limit_is_the_soft_limit_when_finite() {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `lim` is a valid, writable rlimit for the duration of the call.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
        assert_eq!(rc, 0);
        let expected = if lim.rlim_cur == libc::RLIM_INFINITY {
            None
        } else {
            #[allow(clippy::useless_conversion)]
            u64::try_from(lim.rlim_cur).ok()
        };
        assert_eq!(memlock_limit(), expected);
    }
}

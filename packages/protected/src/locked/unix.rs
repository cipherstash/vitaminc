//! The Unix backend: an anonymous `mmap` region with guard pages, locked with
//! `mlock` and, on Linux, excluded from core dumps with `MADV_DONTDUMP`.
//! Releasing the region wipes it first, whatever path led to the release.
//!
//! Under Miri the same code maps, uses and releases the region: Miri models
//! `mmap` and `munmap`, so the pointer arithmetic is checked for real. The
//! calls it has no model for (`mprotect`, `mlock`, `madvise`) are each
//! wrapped once, in `guard`, `lock` and `exclude_from_dumps`, and the Miri
//! branch lives inside each wrapper rather than as a separate function, so
//! that every function here is one the native test suite compiles and the
//! mutation gate can judge.

use super::layout;
use super::LockError;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::io;
use std::sync::Once;

/// One mapping: a guard page, the interior, a guard page. Three words: the
/// page size is a process constant, so the interior and the total length
/// are derived rather than stored, and the third is the owning process.
pub(super) struct Region {
    base: NonNull<u8>,
    interior_len: usize,
    /// The fork generation the lock was taken in. A forked child inherits
    /// the mapping, the guards and the dump exclusion, but not the lock, so
    /// a value must know it has crossed a fork: the generation is bumped in
    /// every child the C library's `fork` creates. A pid would not do, since
    /// pids are recycled; a child made behind the atfork handlers' back (a
    /// raw `clone`) is not detected.
    generation: u32,
}

/// Bumped in every child that `fork` creates, by an atfork handler
/// registered on first use. An atomic increment is async-signal-safe,
/// which is all a child handler may do.
static FORK_GENERATION: AtomicU32 = AtomicU32::new(0);

extern "C" fn note_fork_in_child() {
    let _ = FORK_GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// How registering the handler went: 0 once it is in place, otherwise the
/// errno `pthread_atfork` returned. A process that cannot track forks must
/// say so on every value, since a child would otherwise inherit a lock it
/// does not have without the value knowing.
static ATFORK_RC: AtomicI32 = AtomicI32::new(0);

fn fork_generation() -> u32 {
    static REGISTERED: Once = Once::new();
    REGISTERED.call_once(|| {
        // Miri has neither fork nor atfork. Registration fails only for
        // want of memory, and the outcome is kept for `fork_tracking`.
        #[cfg(not(miri))]
        // SAFETY: the handler touches one atomic and nothing else.
        unsafe {
            let rc = libc::pthread_atfork(None, None, Some(note_fork_in_child));
            ATFORK_RC.store(rc, Ordering::Release);
        }
    });
    FORK_GENERATION.load(Ordering::Acquire)
}

/// Why forks cannot be tracked in this process, if they cannot: the
/// handler was never registered. Registration is attempted first, so the
/// answer is never "not yet". The failure cannot be provoked in a test (it
/// takes an allocation failure inside libc), hence the mutation skip; the
/// error it would produce is tested through [`untracked`].
#[cfg_attr(test, mutants::skip)]
fn fork_tracking() -> Option<LockError> {
    let _ = fork_generation();
    untracked(ATFORK_RC.load(Ordering::Acquire))
}

/// The degradation for a registration that returned `rc`.
fn untracked(rc: i32) -> Option<LockError> {
    (rc != 0).then(|| LockError::Untracked {
        source: io::Error::from_raw_os_error(rc),
    })
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
/// (cargo-mutants honours it on a module, not on a `const`; under
/// `cfg_attr(test, ..)` the `mutants` crate stays a dev-dependency).
#[cfg_attr(test, mutants::skip)]
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
    /// Map a guarded region whose interior can hold a value of `layout`,
    /// try to lock it and, on Linux, exclude it from core dumps. Those two
    /// outcomes are returned separately from the region: a protection that
    /// was refused is a degraded region, not a failed one, and the caller's
    /// policy decides which it is. When both are refused the lock refusal is
    /// the one reported.
    pub(super) fn allocate(layout: Layout) -> Result<(Self, Option<LockError>), LockError> {
        let page = page_size();
        let align = layout.align();
        if align > page {
            return Err(LockError::Alignment { align, page });
        }
        let interior_len = layout::interior_len(layout.size(), page);
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
            generation: fork_generation(),
        };
        let lock = region.protect(page)?;
        Ok((region, lock))
    }

    /// The guard pages, the lock and, on Linux, the dump exclusion. A guard
    /// that cannot be protected is an error; the other two are reported.
    fn protect(&self, page: usize) -> Result<Option<LockError>, LockError> {
        self.guard(self.base.as_ptr(), page)?;
        // SAFETY: the trailing guard starts at base + page + interior_len, inside the mapping.
        self.guard(
            unsafe { self.base.as_ptr().add(page + self.interior_len) },
            page,
        )?;
        Ok(self.lock_and_exclude())
    }

    /// The two protections that do not depend on each other, both attempted
    /// whatever the other's outcome: a value that could not be locked is
    /// exactly the one a dump would otherwise carry. When both are refused
    /// the lock refusal is reported. Construction and [`relock`](Self::relock)
    /// both come through here, so a relock cannot forget a refused dump
    /// exclusion.
    fn lock_and_exclude(&self) -> Option<LockError> {
        let lock = self.lock();
        let tracking = fork_tracking();
        let dump = self.exclude_from_dumps();
        lock.or(tracking).or(dump)
    }

    /// Make the page at `ptr` inaccessible. Miri has no `mprotect`; the
    /// region has no guards under it.
    fn guard(&self, ptr: *mut u8, page: usize) -> Result<(), LockError> {
        #[cfg(miri)]
        {
            let _ = (ptr, page);
            Ok(())
        }
        #[cfg(not(miri))]
        {
            // SAFETY: both guard pages are page-aligned ranges inside the mapping.
            let rc = unsafe { libc::mprotect(ptr.cast(), page, libc::PROT_NONE) };
            if rc == 0 {
                Ok(())
            } else {
                Err(LockError::Guard {
                    source: io::Error::last_os_error(),
                })
            }
        }
    }

    /// Lock the interior against swapping; the refusal, if any. Miri has
    /// no `mlock`; the lock is reported as unavailable under it.
    fn lock(&self) -> Option<LockError> {
        #[cfg(miri)]
        {
            Some(LockError::Unavailable)
        }
        #[cfg(not(miri))]
        {
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
    }

    /// Exclusion from core dumps. A private anonymous mapping we own cannot
    /// be refused on its own account, but a seccomp filter can refuse the
    /// call itself, and `mlock` does not imply this protection. Only Linux
    /// and Android have it, and Miri has no `madvise`; elsewhere there is
    /// nothing to refuse.
    fn exclude_from_dumps(&self) -> Option<LockError> {
        #[cfg(not(all(any(target_os = "linux", target_os = "android"), not(miri))))]
        {
            None
        }
        #[cfg(all(any(target_os = "linux", target_os = "android"), not(miri)))]
        {
            let interior = self.interior();
            // SAFETY: the interior is a page-aligned, mapped range we own.
            let rc = unsafe {
                libc::madvise(
                    interior.as_ptr().cast(),
                    self.interior_len,
                    libc::MADV_DONTDUMP,
                )
            };
            (rc != 0).then(|| LockError::Dump {
                source: io::Error::last_os_error(),
            })
        }
    }

    /// Whether this is the process the lock was taken in: no `fork` since.
    pub(super) fn same_process(&self) -> bool {
        self.generation == fork_generation()
    }

    /// Take the lock again in the current process, and own it here from now
    /// on, re-applying the dump exclusion with it; the refusal, if any.
    pub(super) fn relock(&mut self) -> Option<LockError> {
        self.generation = fork_generation();
        self.lock_and_exclude()
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

    /// Where a value of `layout` lives: as close to the trailing guard page
    /// as its alignment allows, so a write past its end reaches the guard
    /// within `align` bytes instead of wandering through the rest of the
    /// page. The size never exceeds `interior_len`, which was rounded up
    /// from it.
    pub(super) fn value_ptr(&self, layout: Layout) -> NonNull<u8> {
        let offset = layout::value_offset(self.interior_len, layout.size(), layout.align());
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
        // SAFETY: `base..base+total` is our mapping. Unmapping releases the
        // lock with it, so there is no `munlock`; munmap cannot meaningfully
        // fail on a mapping we own, and there is no caller to report to
        // from a destructor.
        unsafe {
            let _ = libc::munmap(self.base.as_ptr().cast(), self.total());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    #[test]
    fn the_total_is_the_interior_plus_a_guard_page_each_side() {
        let page = page_size();
        let (region, _) = Region::allocate(layout(1, 1)).unwrap();
        assert_eq!(region.total(), 3 * page);
        let (region, _) = Region::allocate(layout(page + 1, 1)).unwrap();
        assert_eq!(region.total(), 4 * page);
    }

    #[test]
    fn a_failed_atfork_registration_is_a_degradation_naming_its_errno() {
        assert!(untracked(0).is_none());
        match untracked(libc::ENOMEM) {
            Some(LockError::Untracked { source }) => {
                assert_eq!(source.raw_os_error(), Some(libc::ENOMEM));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_region_belongs_to_the_fork_generation_it_was_locked_in() {
        let (mut region, _) = Region::allocate(layout(1, 1)).unwrap();
        assert!(region.same_process());
        // As if a fork had happened since: the region's generation is behind.
        region.generation = region.generation.wrapping_sub(1);
        assert!(!region.same_process());
        let _ = region.relock();
        assert!(region.same_process(), "relock takes ownership here");
    }

    #[test]
    fn an_alignment_of_one_page_is_the_most_the_region_offers() {
        let page = page_size();
        assert!(Region::allocate(layout(1, page)).is_ok());
        assert!(matches!(
            Region::allocate(layout(1, page * 2)),
            Err(LockError::Alignment { align, page: p }) if align == page * 2 && p == page
        ));
    }

    #[test]
    fn the_value_sits_against_the_trailing_guard() {
        let page = page_size();
        let (region, _) = Region::allocate(layout(32, 1)).unwrap();
        let end = region.ptr().as_ptr() as usize + page;
        assert_eq!(region.value_ptr(layout(32, 1)).as_ptr() as usize + 32, end);
        // Alignment can hold it back, but by less than one alignment unit.
        let (region, _) = Region::allocate(layout(24, 16)).unwrap();
        let end = region.ptr().as_ptr() as usize + page;
        let value = region.value_ptr(layout(24, 16)).as_ptr() as usize;
        assert_eq!(value % 16, 0);
        assert!(
            end - (value + 24) < 16,
            "{} bytes of slack",
            end - (value + 24)
        );
        // A value that fills the interior exactly starts at its start.
        let (region, _) = Region::allocate(layout(page, 1)).unwrap();
        assert_eq!(region.value_ptr(layout(page, 1)), region.ptr());
    }

    #[test]
    fn a_wipe_zeroes_the_whole_interior() {
        let page = page_size();
        let (mut region, _) = Region::allocate(layout(1, 1)).unwrap();
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

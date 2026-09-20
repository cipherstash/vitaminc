//! Helpers shared by the `Locked` integration tests: reading the kernel's
//! view of a mapping from `/proc/self/smaps`, and telling whether `mlock`
//! in this process is real.
#![allow(dead_code)]

/// Set by the CI job whose host is known to lock memory for real: there,
/// a case that would otherwise skip (a small limit, a privileged user, a
/// sanitizer's `mlock` interceptor) must fail instead, so that a
/// regression that never took a lock cannot pass every job.
pub fn lock_required() -> bool {
    std::env::var_os("LOCKED_TESTS_REQUIRE_LOCK").is_some()
}

/// The line with `prefix` in the `/proc/self/smaps` entry containing
/// `addr`, trimmed, with the prefix removed.
#[cfg(target_os = "linux")]
pub fn smaps_line(addr: usize, prefix: &str) -> String {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut in_region = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ') {
            if let Some((lo, hi)) = range.split_once('-') {
                if let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                {
                    in_region = lo <= addr && addr < hi;
                    continue;
                }
            }
        }
        if in_region {
            if let Some(v) = line.strip_prefix(prefix) {
                return v.trim().to_string();
            }
        }
    }
    panic!("no smaps entry contains {addr:#x} with a {prefix} line");
}

/// The `VmFlags:` of the smaps entry containing `addr`.
#[cfg(target_os = "linux")]
pub fn vm_flags(addr: usize) -> String {
    smaps_line(addr, "VmFlags:")
}

/// A numeric smaps field (KiB) of the entry containing `addr`.
#[cfg(target_os = "linux")]
pub fn smaps_field(addr: usize, prefix: &str) -> Option<u64> {
    smaps_line(addr, prefix).split(' ').next()?.parse().ok()
}

/// Whether `mlock` reports success without locking (the sanitizer
/// runtimes make it do so), judged from a page of our own.
#[cfg(target_os = "linux")]
pub fn mlock_is_a_no_op() -> bool {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    // SAFETY: an anonymous private mapping of one page; checked below.
    let probe = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(probe, libc::MAP_FAILED);
    // SAFETY: `probe` is a page we own.
    let locked = unsafe { libc::mlock(probe, page) } == 0;
    let counted = smaps_field(probe as usize, "Locked:").unwrap_or(0) > 0;
    // SAFETY: still our page, released exactly once.
    unsafe {
        let _ = libc::munlock(probe, page);
        let _ = libc::munmap(probe, page);
    }
    locked && !counted
}

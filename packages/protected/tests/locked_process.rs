//! `Locked<T>` cases that need a process of their own: a lowered
//! `RLIMIT_MEMLOCK`, a write into a guard page, and the once-only policy.
//! Each case re-executes this test binary with `LOCKED_CHILD_CASE` set and
//! inspects the exit status. None of this can run under Miri, which has no
//! `mlock`, `mprotect`, or subprocesses. The `RLIMIT_MEMLOCK` cases build
//! only where the limit exists (`cfg(memlock_limit)`, from `build.rs`).
//! The `fork` case is not here: a libtest process is never single-threaded,
//! so it lives in `locked_fork.rs`, which has no harness.
#![cfg(all(unix, not(miri)))]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};
#[cfg(memlock_limit)]
use vitaminc_protected::LockError;
use vitaminc_protected::{LockPolicy, Locked};

mod common;
#[cfg(target_os = "linux")]
use common::vm_flags;

const CASE: &str = "LOCKED_CHILD_CASE";

fn child(case: &str) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .env(CASE, case)
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .output()
        .unwrap()
}

#[cfg(memlock_limit)]
fn lower_memlock_to_zero() {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid rlimit. Lowering a soft limit needs no privilege.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
    assert_eq!(rc, 0, "setrlimit: {}", std::io::Error::last_os_error());
}

/// Lower the limit to zero and confirm the process now cannot lock a page.
/// Root and `CAP_IPC_LOCK` are exempt from `RLIMIT_MEMLOCK`, and the
/// sanitizer runtimes intercept `mlock` to return success without locking
/// (their shadow memory must never be pinned), so in those processes a
/// refusal cannot be provoked and the case is skipped, loudly.
#[cfg(memlock_limit)]
fn refusal_can_be_provoked() -> bool {
    lower_memlock_to_zero();
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
    unsafe {
        let _ = libc::munmap(probe, page);
    }
    if locked {
        eprintln!(
            "skipped: this process can lock memory with RLIMIT_MEMLOCK at zero \
             (root, CAP_IPC_LOCK, or a sanitizer's mlock interceptor)"
        );
    }
    !locked
}

/// The child half of every case. With the variable unset this is a no-op
/// test in the parent's own run.
#[test]
fn child_entry() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    match case.as_str() {
        #[cfg(memlock_limit)]
        "refused_best_effort" => {
            if !refusal_can_be_provoked() {
                return;
            }
            let key = Locked::new([1u8; 32]).unwrap();
            assert!(!key.locked());
            // The dump exclusion does not depend on the lock: a value that
            // could not be locked is still kept out of core dumps.
            #[cfg(target_os = "linux")]
            {
                let flags = vm_flags(key.risky_ref().as_ptr() as usize);
                assert!(flags.split(' ').any(|f| f == "dd"), "VmFlags: {flags}");
            }
            assert!(
                matches!(key.lock_error(), Some(LockError::Refused { .. })),
                "{:?}",
                key.lock_error()
            );
            // The refusal names the limit, which is now zero.
            let msg = key.lock_error().unwrap().to_string();
            assert!(
                msg.contains("RLIMIT_MEMLOCK soft limit is 0 bytes"),
                "{msg}"
            );
            assert!(matches!(
                key.require_locked(),
                Err(LockError::Refused { .. })
            ));
        }
        #[cfg(memlock_limit)]
        "refused_strict" => {
            if !refusal_can_be_provoked() {
                return;
            }
            LockPolicy::Strict.set().unwrap();
            assert_eq!(LockPolicy::current(), LockPolicy::Strict);
            let r: Result<Locked<[u8; 32]>, _> = Locked::new([1u8; 32]);
            assert!(matches!(r, Err(LockError::Refused { .. })), "{r:?}");
        }
        "policy_is_set_once" => {
            assert_eq!(LockPolicy::current(), LockPolicy::BestEffort);
            LockPolicy::Strict.set().unwrap();
            LockPolicy::Strict.set().unwrap(); // same value again is fine
            let err = LockPolicy::BestEffort.set().unwrap_err();
            assert_eq!(err.current, LockPolicy::Strict);
        }
        "drop_unmaps" => {
            // `msync` answers ENOMEM for a range with no mapping. Single-
            // threaded here, so nothing can reuse the address between the
            // drop and the probe.
            let probe = |addr: *mut u8, len: usize| -> Option<i32> {
                // SAFETY: msync on an arbitrary page-aligned range has no
                // preconditions; an unmapped range is an error, not UB.
                let rc = unsafe { libc::msync(addr.cast(), len, libc::MS_ASYNC) };
                (rc != 0).then(|| std::io::Error::last_os_error().raw_os_error().unwrap())
            };
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
            let key = Locked::new([1u8; 32]).unwrap();
            // The value sits at the end of its page; the interior is that
            // page, and `msync` wants the page-aligned start.
            let interior = (key.risky_ref().as_ptr() as usize & !(page - 1)) as *mut u8;
            assert_eq!(
                probe(interior, page),
                None,
                "the interior is mapped while live"
            );
            drop(key);
            // The interior and both guards: a partial unmap leaves one of them.
            for addr in [unsafe { interior.sub(page) }, interior, unsafe {
                interior.add(page)
            }] {
                assert_eq!(
                    probe(addr, page),
                    Some(libc::ENOMEM),
                    "{addr:?} still mapped"
                );
            }
        }
        "overrun_faults" => {
            let key = Locked::new([1u8; 32]).unwrap();
            let start = key.risky_ref().as_ptr();
            // A byte-aligned value sits flush against the trailing guard:
            // the very next byte after it must fault.
            let past = unsafe { start.add(32) } as *mut u8;
            unsafe { std::ptr::write_volatile(past, 1) };
            unreachable!("the write into the guard page must fault");
        }
        other => panic!("unknown case {other}"),
    }
}

fn assert_passed(out: &Output) {
    assert!(
        out.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(memlock_limit)]
#[test]
fn a_refused_lock_is_reported_under_best_effort() {
    assert_passed(&child("refused_best_effort"));
}

#[cfg(memlock_limit)]
#[test]
fn a_refused_lock_fails_the_constructor_under_strict() {
    assert_passed(&child("refused_strict"));
}

#[test]
fn the_policy_is_set_once_per_process() {
    assert_passed(&child("policy_is_set_once"));
}

#[test]
fn dropping_the_value_unmaps_the_interior_and_both_guards() {
    assert_passed(&child("drop_unmaps"));
}

#[test]
fn a_write_past_the_value_faults_on_the_guard_page() {
    let out = child("overrun_faults");
    let signal = out.status.signal();
    assert!(
        matches!(signal, Some(libc::SIGSEGV) | Some(libc::SIGBUS)),
        "expected a fault, got {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

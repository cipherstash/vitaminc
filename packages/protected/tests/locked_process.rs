//! `Locked<T>` cases that need a process of their own: a lowered
//! `RLIMIT_MEMLOCK`, a write into a guard page, and the once-only policy.
//! Each case re-executes this test binary with `LOCKED_CHILD_CASE` set and
//! inspects the exit status. None of this can run under Miri, which has no
//! `mlock`, `mprotect`, or subprocesses.
#![cfg(all(unix, not(miri)))]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};
use vitaminc_protected::{LockError, LockPolicy, Locked};

const CASE: &str = "LOCKED_CHILD_CASE";

fn child(case: &str) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .env(CASE, case)
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .output()
        .unwrap()
}

fn lower_memlock_to_zero() {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid rlimit. Lowering a soft limit needs no privilege.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
    assert_eq!(rc, 0, "setrlimit: {}", std::io::Error::last_os_error());
}

/// Root (or CAP_IPC_LOCK) is exempt from RLIMIT_MEMLOCK, so a refusal cannot
/// be provoked.
fn privileged() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// The child half of every case. With the variable unset this is a no-op
/// test in the parent's own run.
#[test]
fn child_entry() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    match case.as_str() {
        "refused_best_effort" => {
            lower_memlock_to_zero();
            let key = Locked::new([1u8; 32]).unwrap();
            assert!(!key.locked());
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
        "refused_strict" => {
            lower_memlock_to_zero();
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
        "overrun_faults" => {
            let key = Locked::new([1u8; 32]).unwrap();
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
            let start = key.risky_ref().as_ptr();
            // The interior is exactly one page for a 32-byte value; the byte
            // after it is the trailing guard.
            let past = unsafe { start.add(page) } as *mut u8;
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

#[test]
fn a_refused_lock_is_reported_under_best_effort() {
    if privileged() {
        return;
    }
    assert_passed(&child("refused_best_effort"));
}

#[test]
fn a_refused_lock_fails_the_constructor_under_strict() {
    if privileged() {
        return;
    }
    assert_passed(&child("refused_strict"));
}

#[test]
fn the_policy_is_set_once_per_process() {
    assert_passed(&child("policy_is_set_once"));
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

//! A forked child inherits a `Locked` value's memory but not its lock, and
//! the value must say so until `relock`. This test has no harness
//! (`harness = false` in Cargo.toml) because `fork` from a multithreaded
//! process, which every libtest process is, leaves the child with only
//! async-signal-safe calls, and the child here allocates and reads
//! `/proc`. With a plain `main` the process is genuinely single-threaded.
//! Miri has no `fork`, and nothing here runs off Unix.

mod common;

fn main() {
    #[cfg(all(unix, not(miri)))]
    run();
    #[cfg(not(all(unix, not(miri))))]
    println!("skipped: needs Unix and no Miri");
}

#[cfg(all(unix, not(miri)))]
fn run() {
    #[cfg(target_os = "linux")]
    use common::{mlock_is_a_no_op, smaps_field};
    use vitaminc_protected::{LockError, Locked};

    let mut key = Locked::new([1u8; 32]).unwrap();
    if !key.locked() {
        assert!(
            !common::lock_required(),
            "not locked in the parent ({:?}), and this job requires it",
            key.lock_error()
        );
        println!("skipped: not locked in the parent, so there is nothing to lose");
        return;
    }
    #[cfg(target_os = "linux")]
    let mlock_no_op = mlock_is_a_no_op();
    // SAFETY: this process has no test harness and spawns no threads, so
    // fork has no other thread to leave half-way through anything.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        // The child. The memory came along; the lock did not, and
        // the value must say so before and after `relock`.
        let mut ok = !key.locked() && matches!(key.lock_error(), Some(LockError::Forked));
        #[cfg(target_os = "linux")]
        {
            ok &= smaps_field(key.risky_ref().as_ptr() as usize, "Locked:") == Some(0);
        }
        ok &= key.relock().is_ok() && key.locked();
        #[cfg(target_os = "linux")]
        if !mlock_no_op {
            ok &= smaps_field(key.risky_ref().as_ptr() as usize, "Locked:") > Some(0);
        }
        ok &= key.require_locked().is_ok();
        // SAFETY: _exit ends the child without running the
        // parent's destructors or the harness's exit handlers.
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0;
    // SAFETY: `status` is a valid, writable int for the call.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the child's checks failed (status {status})"
    );
    // The parent is untouched.
    assert!(key.locked());
    println!("ok: the child saw the lock gone, took it back, and the parent kept its own");
}

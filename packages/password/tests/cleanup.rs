//! Observe the string allocation while it is still live, just before freeing
//! it. Safe Rust cannot inspect freed memory; this allocator observes only the
//! initialized bytes of a specifically registered allocation before deallocation.
#![deny(unsafe_op_in_unsafe_fn)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

static WATCHED: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static LENGTH: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicBool = AtomicBool::new(false);
static WIPED: AtomicBool = AtomicBool::new(false);

struct Watching;

// SAFETY: requests are forwarded to System with the original pointer/layout.
// The watched allocation belongs to the sole test below. Its original string
// length identifies initialized bytes; dealloc observes them before freeing,
// when there can be no live references or concurrent mutation of the allocation.
// These hooks do not allocate or panic, including during thread-local teardown.
unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        // SAFETY: forwarded allocator request with unchanged layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = REALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        // SAFETY: forwarded allocator request with unchanged arguments.
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHED
            .compare_exchange(
                ptr,
                std::ptr::null_mut(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            let len = LENGTH.load(Ordering::SeqCst);
            // SAFETY: registration records the string's initialized length,
            // never its spare capacity. The same allocation is still live and
            // exclusively owned by this deallocation call. Clearing WATCHED
            // ensures a later reuse of its address cannot be observed as it.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
            WIPED.store(bytes.iter().all(|&byte| byte == 0), Ordering::SeqCst);
            FREED.store(true, Ordering::SeqCst);
        }
        // SAFETY: forwarded allocator request with unchanged pointer/layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

fn check_conversion(convert: impl FnOnce() -> Protected<String>, unwind: bool) {
    ALLOCATIONS.set(0);
    REALLOCATIONS.set(0);
    COUNTING.set(true);
    let output = convert();
    COUNTING.set(false);
    assert_eq!(ALLOCATIONS.get(), 1, "conversion must allocate once");
    assert_eq!(
        REALLOCATIONS.get(),
        0,
        "conversion must not grow secret storage"
    );

    let contents = output.risky_ref();
    assert!(!contents.is_empty());
    assert!(contents.bytes().all(|byte| byte != 0));
    FREED.store(false, Ordering::SeqCst);
    WIPED.store(false, Ordering::SeqCst);
    LENGTH.store(contents.len(), Ordering::SeqCst);
    WATCHED.store(contents.as_ptr().cast_mut(), Ordering::SeqCst);

    if unwind {
        let result = std::panic::catch_unwind(move || {
            let _owned = output;
            panic!("exercise secret cleanup during unwinding");
        });
        assert!(result.is_err());
    } else {
        drop(output);
    }
    assert!(FREED.load(Ordering::SeqCst), "allocation was not freed");
    assert!(
        WIPED.load(Ordering::SeqCst),
        "secret bytes survived until deallocation"
    );
}

// One test owns the observation state, so tests never race for WATCHED. The
// count is thread-local so allocations by the test harness do not affect it.
#[test]
fn conversions_allocate_once_and_wipe_on_drop_and_unwind() {
    let mut rng = SafeRand::from_seed([7; 32]);
    for unwind in [false, true] {
        let password = Password::<20>::random(&mut rng).unwrap();
        check_conversion(|| password.into_protected_string(), unwind);
        let password = AlphaNumericPassword::<22>::random(&mut rng).unwrap();
        check_conversion(|| password.into_protected_string(), unwind);
        let password = AlphaPassword::<23>::random(&mut rng).unwrap();
        check_conversion(|| password.into_protected_string(), unwind);
        let password = Password::<128>::random(&mut rng).unwrap();
        check_conversion(|| password.into_protected_string(), unwind);
        let password = AlphaNumericPassword::<128>::random(&mut rng).unwrap();
        check_conversion(|| password.into_protected_string(), unwind);
        let password = AlphaPassword::<128>::random(&mut rng).unwrap();
        check_conversion(|| password.into_protected_string(), unwind);
    }
}

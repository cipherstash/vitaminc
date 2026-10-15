//! What collecting terms beside encryption allocates, counted by a global
//! allocator. In its own test binary, so no other test allocates while one
//! is counting.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use vitaminc_aead::plan;
use vitaminc_normalize::plan_with_terms;

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to `System` unchanged; the counter is the
// only addition.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the caller's contract is `System`'s.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is `System`'s.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the caller's contract is `System`'s.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Ordering::SeqCst);
    f();
    ALLOCATIONS.load(Ordering::SeqCst) - before
}

/// Beside encryption, a walk that pushes no term allocates one buffer for
/// the keys on its path and nothing for any container or entry, however
/// many there are.
#[test]
fn a_walk_with_no_terms_allocates_only_the_key_buffer() {
    let mut inner = BTreeMap::new();
    for key in ["a", "b", "c", "d"] {
        inner.insert(key, vec![None::<u32>, None]);
    }
    let mut doc = BTreeMap::new();
    for key in ["p", "q", "r"] {
        doc.insert(key, vec![inner.clone(), inner.clone()]);
    }
    let encrypting = allocations(|| {
        plan::<_, (), _>(doc.clone(), "ctx").expect("plans");
    });
    let with_terms = allocations(|| {
        let (_, terms) = plan_with_terms::<_, (), _>(doc.clone(), "ctx").expect("plans");
        assert!(terms.is_empty());
    });
    assert_eq!(with_terms, encrypting + 1);
}

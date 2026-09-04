//! Test-only observers shared by the wrapper-type unit tests. Each one makes
//! a `Zeroize` call visible from outside the value so a test can prove that a
//! wrapper's `Drop` ran (or deliberately did not run) the payload's wipe.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A payload whose `zeroize` sets a flag. It has no `Drop` of its own, so the
/// flag can only be raised by a wrapper's drop glue (or an explicit call).
///
/// `Copy` is deliberate (#263): `Protected<T>` used to be `Copy` whenever `T`
/// was, which made a zeroizing `Drop` structurally impossible for exactly the
/// payloads that carry key material. Every test that observes a wipe through
/// `Tracked` therefore does so with a `Copy` payload.
#[derive(Clone, Copy)]
pub(crate) struct Tracked<'a>(pub(crate) &'a AtomicBool);

impl Tracked<'_> {
    pub(crate) fn was_zeroized(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Zeroize for Tracked<'_> {
    fn zeroize(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A `Clone` payload whose `zeroize` bumps a counter, so a test can prove each
/// duplicate is wiped exactly once.
#[derive(Clone)]
pub(crate) struct Counted<'a>(pub(crate) &'a AtomicUsize);

impl Counted<'_> {
    pub(crate) fn wipes(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Zeroize for Counted<'_> {
    fn zeroize(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Compile-time check that `T` claims `ZeroizeOnDrop`. Pair it with a
/// runtime `Tracked` observation: the marker alone says nothing about whether
/// a wipe actually runs.
pub(crate) fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

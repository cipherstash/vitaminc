use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use zeroize::Zeroize;

/// The inner value a [`Controlled`](crate::Controlled) combinator hands to its
/// closure.
///
/// The value stays where it is, inside the wrapper the combinator was called
/// on, and `Owned` points at it. Handing an `Owned` to the closure therefore
/// moves a pointer, not the value, so an inline value such as `[u8; 32]` is
/// not copied on the way in. The closure owns it from there: it is wiped when
/// the `Owned` drops, including when the closure panics, so a closure that
/// only reads the value (through `Deref`) leaves nothing behind.
///
/// A closure that needs the bare value, to convert it or move it on, takes
/// it with [`into_inner`](Self::into_inner), which moves it out and wipes the
/// slot it came from. From then on the closure owns the wipe, until the value
/// goes back into a controlled wrapper. For a heap value that move is a
/// pointer copy and the buffer is reused; for an inline value it is a copy of
/// the bytes, and every later move of the bare value makes another, so read
/// inline values through the `Owned` where possible.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Controlled, Protected};
/// // Read only: the Vec is wiped when `v` drops.
/// let len = Protected::new(vec![1u8, 2, 3]).map(|v| v.len());
/// assert_eq!(len.risky_unwrap(), 3);
///
/// // Convert: the same buffer becomes the String, nothing is copied.
/// let text = Protected::new(vec![104u8, 105])
///     .map_ok(|v| String::from_utf8(v.into_inner()))
///     .expect("valid UTF-8");
/// assert_eq!(text.risky_unwrap(), "hi");
/// ```
///
/// `Owned` is `Send` or `Sync` exactly when `T` is, as a `&mut T` would be,
/// so a closure can move it into a scoped thread.
pub struct Owned<'a, T: Zeroize> {
    /// The live value, inside the wrapper `with_owned` holds.
    slot: NonNull<T>,
    /// Set once the slot no longer holds a live `T`: taken out, or dropped
    /// here. `with_owned` reads it to know whether the value still needs
    /// dropping.
    dead: NonNull<bool>,
    _borrow: PhantomData<&'a mut T>,
}

impl<'a, T: Zeroize> Owned<'a, T> {
    /// Point at `slot`, which must hold a live `T` for as long as this value
    /// or `dead` is used. `dead` must be `false`.
    fn new(slot: &'a mut T, dead: &'a mut bool) -> Self {
        debug_assert!(!*dead);
        Self {
            slot: NonNull::from(slot),
            dead: NonNull::from(dead),
            _borrow: PhantomData,
        }
    }

    /// Move the bare value out, wiping the slot it leaves behind.
    ///
    /// After this the value is no longer wiped on drop: the caller owns that,
    /// until the value is wrapped again. A result that is not used is
    /// dropped on the spot, unwiped, so the compiler warns when that happens.
    #[must_use = "the bare value is dropped unwiped if it is not used"]
    pub fn into_inner(self) -> T {
        let this = ManuallyDrop::new(self);
        // SAFETY: `dead` is false (it is only set here and in `drop`, and
        // both consume `self`), so the slot holds a live `T`. It is read
        // once, then overwritten bitwise and marked dead, and `with_owned`
        // neither reads nor drops a dead slot, so the returned value is the
        // sole owner.
        unsafe {
            let inner = ptr::read(this.slot.as_ptr());
            crate::locked::wipe_bytes(this.slot.as_ptr());
            *this.dead.as_ptr() = true;
            inner
        }
    }
}

// SAFETY: `Owned` is an exclusive borrow of a `T` and of a `bool`, so it
// can cross threads under the same conditions as a `&mut T`. Dropping it
// elsewhere wipes and drops the `T` on that thread, which `T: Send` allows.
unsafe impl<T: Zeroize + Send> Send for Owned<'_, T> {}
// SAFETY: a shared `&Owned` only reaches `&T`, through `Deref`.
unsafe impl<T: Zeroize + Sync> Sync for Owned<'_, T> {}

impl<T: Zeroize> Deref for Owned<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the slot holds a live `T` until `into_inner` or `drop`,
        // both of which consume `self`, and `_borrow` keeps it exclusively
        // borrowed for `'a`.
        unsafe { self.slot.as_ref() }
    }
}

impl<T: Zeroize> DerefMut for Owned<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as for `deref`, and `&mut self` makes the access exclusive.
        unsafe { self.slot.as_mut() }
    }
}

impl<T: Zeroize> Zeroize for Owned<'_, T> {
    fn zeroize(&mut self) {
        (**self).zeroize();
    }
}

impl<T: Zeroize> Drop for Owned<'_, T> {
    fn drop(&mut self) {
        // SAFETY: the slot holds a live `T` (see `deref`). It is marked dead
        // first, so that `with_owned` never touches it again even if the
        // wipe or the destructor below panics. It is then wiped and dropped
        // exactly once: `wipe_then_drop` runs the destructor even when the
        // wipe panics. The bytes left by the destructor are wiped by
        // `with_owned` afterwards.
        unsafe {
            *self.dead.as_ptr() = true;
            wipe_then_drop(self.slot.as_ptr());
        }
    }
}

/// Zeroize the `T` at `value`, then run its destructor, which runs even if
/// `zeroize` panics. This is the same order and guarantee as `Locked`'s
/// `Drop`.
///
/// # Safety
///
/// `value` must point to a live `T` that nothing else will drop or use.
unsafe fn wipe_then_drop<T: Zeroize>(value: *mut T) {
    /// Runs `T`'s destructor when it goes out of scope, so that a panic in
    /// `T::zeroize` still drops the value.
    struct DropValue<T>(*mut T);
    impl<T> Drop for DropValue<T> {
        fn drop(&mut self) {
            // SAFETY: the pointee is a live `T`; this is its only drop.
            unsafe { ptr::drop_in_place(self.0) };
        }
    }
    let value = DropValue(value);
    // SAFETY: the caller guarantees the pointee is live and unaliased.
    unsafe { (*value.0).zeroize() };
    drop(value);
}

/// Run `f` on the value inside `wrapper`, in place, then wipe the wrapper.
///
/// The value is dropped when `f`'s `Owned` drops, or moved out by
/// `into_inner`, or, if `f` forgets the `Owned`, dropped here. In every case
/// the wrapper's bytes are overwritten before this returns, including when
/// `f` panics.
pub(crate) fn with_owned<W, R>(wrapper: W, f: impl FnOnce(Owned<'_, W::Inner>) -> R) -> R
where
    W: crate::Controlled + Sized,
{
    /// Finishes the slot on every exit path: drops the value if it is still
    /// live, then wipes the wrapper's bytes.
    ///
    /// The wrapper is held as a `MaybeUninit`, not a `ManuallyDrop`: once the
    /// value is taken or dropped its bytes may not be a valid `W` (a taken
    /// `Vec` leaves a null pointer behind), and a `MaybeUninit` field puts no
    /// validity requirement on them when `drop` borrows `self`.
    struct Finish<W: crate::Controlled> {
        wrapper: MaybeUninit<W>,
        dead: bool,
    }

    impl<W: crate::Controlled> Drop for Finish<W> {
        fn drop(&mut self) {
            /// Wipes the wrapper's bytes when it goes out of scope, so that a
            /// panic while dropping the value still wipes them.
            struct Wipe<W>(*mut W);
            impl<W> Drop for Wipe<W> {
                fn drop(&mut self) {
                    // SAFETY: the pointee is the wrapper in `Finish`, which
                    // is never read as a `W` again after this, which is
                    // `wipe_bytes`'s contract.
                    unsafe { crate::locked::wipe_bytes(self.0) };
                }
            }
            let wipe = Wipe(self.wrapper.as_mut_ptr());
            if !self.dead {
                // SAFETY: while `dead` is false the wrapper is a valid `W`
                // and its value is live, with nothing else left to drop it:
                // `Owned` sets `dead` whenever it drops or takes the value.
                // The reference is derived from `wipe`'s pointer, so the
                // wipe's later use of that pointer stays valid. The
                // wrapper's own `Drop` is skipped on purpose: the
                // `ControlledPrivate` contract makes it a zeroize and
                // nothing more, which `wipe_then_drop` already does.
                unsafe {
                    let inner: *mut W::Inner = (*wipe.0).inner_mut();
                    wipe_then_drop(inner);
                }
            }
            drop(wipe);
        }
    }

    let mut finish = Finish {
        wrapper: MaybeUninit::new(wrapper),
        dead: false,
    };
    let Finish { wrapper, dead } = &mut finish;
    // SAFETY: `wrapper` was initialised just above and nothing has taken or
    // dropped its value yet.
    let wrapper = unsafe { wrapper.assume_init_mut() };
    f(Owned::new(wrapper.inner_mut(), dead))
}

#[cfg(test)]
mod tests {
    use crate::{with_owned, Protected};
    use core::cell::Cell;
    use zeroize::Zeroize;

    /// Records when it is wiped and when it is dropped, so a test can tell
    /// which of the two drops (`Owned`'s or `with_owned`'s backstop) did the
    /// work, and when.
    struct Spy<'a> {
        wiped: &'a Cell<u32>,
        dropped: &'a Cell<u32>,
    }

    impl Zeroize for Spy<'_> {
        fn zeroize(&mut self) {
            self.wiped.set(self.wiped.get() + 1);
        }
    }

    impl Drop for Spy<'_> {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
        }
    }

    fn spy<'a>(wiped: &'a Cell<u32>, dropped: &'a Cell<u32>) -> Protected<Spy<'a>> {
        Protected::new(Spy { wiped, dropped })
    }

    mod given_the_closure_drops_the_owned {
        use super::*;

        #[test]
        fn the_value_is_wiped_and_dropped_right_then() {
            let (wiped, dropped) = (Cell::new(0), Cell::new(0));
            with_owned(spy(&wiped, &dropped), |o| {
                drop(o);
                assert_eq!(wiped.get(), 1, "dropping the Owned should wipe the value");
                assert_eq!(dropped.get(), 1, "dropping the Owned should drop the value");
            });
            assert_eq!(wiped.get(), 1, "the backstop should not wipe it again");
            assert_eq!(dropped.get(), 1, "the backstop should not drop it again");
        }
    }

    mod given_the_closure_forgets_the_owned {
        use super::*;

        #[test]
        fn the_value_is_wiped_and_dropped_when_with_owned_returns() {
            let (wiped, dropped) = (Cell::new(0), Cell::new(0));
            with_owned(spy(&wiped, &dropped), |o| {
                core::mem::forget(o);
                assert_eq!(wiped.get(), 0, "nothing should have run yet");
            });
            assert_eq!(wiped.get(), 1, "the backstop should wipe the value");
            assert_eq!(dropped.get(), 1, "the backstop should drop the value");
        }
    }

    mod given_the_closure_takes_the_value_out {
        use super::*;

        #[test]
        fn returns_the_same_buffer() {
            let v = vec![1u8, 2, 3];
            let ptr = v.as_ptr();
            let out = with_owned(Protected::new(v), |o| o.into_inner());
            assert_eq!(out, [1, 2, 3], "the value should come back unchanged");
            assert_eq!(out.as_ptr(), ptr, "the buffer should be moved, not copied");
        }

        #[test]
        fn nothing_wipes_or_drops_it_until_the_caller_does() {
            let (wiped, dropped) = (Cell::new(0), Cell::new(0));
            let bare = with_owned(spy(&wiped, &dropped), |o| o.into_inner());
            assert_eq!(wiped.get(), 0, "a taken value is the caller's to wipe");
            assert_eq!(dropped.get(), 0, "a taken value is the caller's to drop");
            drop(bare);
            assert_eq!(dropped.get(), 1, "the caller's drop should be the only one");
        }
    }

    mod given_the_closure_panics {
        use super::*;

        #[test]
        fn the_value_is_wiped_and_dropped_once() {
            let (wiped, dropped) = (Cell::new(0), Cell::new(0));
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_owned(spy(&wiped, &dropped), |o| {
                    let _hold = o;
                    panic!("closure failed with the value in hand")
                })
            }));
            assert!(outcome.is_err(), "the closure should have panicked");
            assert_eq!(wiped.get(), 1, "unwinding should wipe the value once");
            assert_eq!(dropped.get(), 1, "unwinding should drop the value once");
        }
    }

    mod given_a_heap_value {
        use super::*;

        #[test]
        fn zeroize_clears_it_in_place() {
            with_owned(Protected::new(vec![7u8; 4]), |mut o| {
                o.zeroize();
                assert!(o.is_empty(), "zeroize on a Vec clears it");
            });
        }
    }

    /// Panics the first time it is wiped or dropped, as chosen, and counts
    /// its drops. It owns a `Box` so that a second drop is a double free,
    /// which Miri reports and the allocator usually aborts on.
    struct PanicsOnce<'a> {
        in_zeroize: bool,
        panicked: &'a Cell<bool>,
        dropped: &'a Cell<u32>,
        _heap: Box<u64>,
    }

    impl PanicsOnce<'_> {
        fn panic_once(&self, here: bool) {
            if here && !self.panicked.replace(true) {
                panic!("first call panics");
            }
        }
    }

    impl Zeroize for PanicsOnce<'_> {
        fn zeroize(&mut self) {
            self.panic_once(self.in_zeroize);
        }
    }

    impl Drop for PanicsOnce<'_> {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
            self.panic_once(!self.in_zeroize);
        }
    }

    /// How the closure lets go of the `Owned`.
    enum Release {
        /// Drop it, so `Owned`'s own `Drop` does the work.
        Drop,
        /// Forget it, so `with_owned`'s backstop does the work.
        Forget,
    }

    /// Runs a closure that releases a `PanicsOnce` as `release` says, and
    /// returns how many times it was dropped, after checking that the panic
    /// reached the caller.
    fn drops_after_panic(in_zeroize: bool, release: Release) -> u32 {
        let (panicked, dropped) = (Cell::new(false), Cell::new(0));
        let value = Protected::new(PanicsOnce {
            in_zeroize,
            panicked: &panicked,
            dropped: &dropped,
            _heap: Box::new(7),
        });
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_owned(value, |o| match release {
                Release::Drop => drop(o),
                Release::Forget => core::mem::forget(o),
            })
        }));
        assert!(outcome.is_err(), "the panic should reach the caller");
        assert!(panicked.get(), "the value should have panicked");
        dropped.get()
    }

    mod given_the_values_destructor_panics {
        use super::*;

        #[test]
        fn dropping_the_owned_drops_it_once() {
            assert_eq!(drops_after_panic(false, Release::Drop), 1);
        }

        #[test]
        fn the_backstop_drops_it_once() {
            assert_eq!(drops_after_panic(false, Release::Forget), 1);
        }
    }

    mod given_the_values_zeroize_panics {
        use super::*;

        #[test]
        fn dropping_the_owned_still_drops_it_once() {
            assert_eq!(drops_after_panic(true, Release::Drop), 1);
        }

        #[test]
        fn the_backstop_still_drops_it_once() {
            assert_eq!(drops_after_panic(true, Release::Forget), 1);
        }
    }

    mod given_a_send_value {
        use super::*;

        #[test]
        fn the_owned_can_move_to_a_scoped_thread() {
            let len = with_owned(Protected::new(vec![1u8, 2, 3]), |o| {
                std::thread::scope(|s| s.spawn(move || o.len()).join().expect("thread"))
            });
            assert_eq!(len, 3);
        }
    }
}

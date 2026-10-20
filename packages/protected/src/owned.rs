use core::marker::PhantomData;
use core::mem::ManuallyDrop;
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
    /// until the value is wrapped again.
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
        // SAFETY: the slot holds a live `T` (see `deref`). It is wiped, then
        // dropped exactly once here, and marked dead so `with_owned` does
        // not drop it again. The bytes left by the destructor are wiped by
        // `with_owned` afterwards.
        unsafe {
            let slot = self.slot.as_ptr();
            (*slot).zeroize();
            ptr::drop_in_place(slot);
            *self.dead.as_ptr() = true;
        }
    }
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
    struct Finish<W: crate::Controlled> {
        wrapper: ManuallyDrop<W>,
        dead: bool,
    }

    impl<W: crate::Controlled> Drop for Finish<W> {
        fn drop(&mut self) {
            let inner: *mut W::Inner = self.wrapper.inner_mut();
            // SAFETY: while `dead` is false the slot holds a live value that
            // nothing else will drop: `Owned` sets `dead` whenever it drops
            // or takes the value. The wrapper is in a `ManuallyDrop` and is
            // never read again after the wipe, which is `wipe_bytes`'s
            // contract. Its `Drop` is skipped on purpose: it would zeroize a
            // value that is gone.
            unsafe {
                if !self.dead {
                    (*inner).zeroize();
                    ptr::drop_in_place(inner);
                }
                crate::locked::wipe_bytes(&mut self.wrapper as *mut ManuallyDrop<W>);
            }
        }
    }

    let mut finish = Finish {
        wrapper: ManuallyDrop::new(wrapper),
        dead: false,
    };
    let Finish { wrapper, dead } = &mut finish;
    f(Owned::new(wrapper.inner_mut(), dead))
}

#[cfg(test)]
mod tests {
    use crate::{with_owned, Protected};
    use zeroize::Zeroize;

    #[test]
    fn into_inner_hands_back_the_same_buffer() {
        let v = vec![1u8, 2, 3];
        let ptr = v.as_ptr();
        let out = with_owned(Protected::new(v), |o| o.into_inner());
        assert_eq!(out, [1, 2, 3], "the value should come back unchanged");
        assert_eq!(out.as_ptr(), ptr, "the buffer should be moved, not copied");
    }

    #[test]
    fn zeroize_wipes_in_place() {
        with_owned(Protected::new(vec![7u8; 4]), |mut o| {
            o.zeroize();
            assert!(o.is_empty(), "zeroize on a Vec clears it");
        });
    }

    #[test]
    fn a_forgotten_owned_is_still_dropped() {
        // Nothing observable without an allocator scan; this checks the
        // path runs without a double free or a leak check failure.
        with_owned(Protected::new(vec![7u8; 4]), |o| core::mem::forget(o));
    }
}

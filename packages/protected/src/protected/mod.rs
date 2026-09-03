use super::Controlled;
use crate::private::ControlledPrivate;
use crate::OpaqueDebug;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The most basic controlled type.
/// It ensures inner types are `Zeroize` and implements `Debug` and `Display` safely (i.e. inner sensitive values are redacted).
///
/// The inner value is wiped when the `Protected` is dropped (`ZeroizeOnDrop`),
/// so the `T: Zeroize` bound is required on the type itself.
#[derive(Zeroize, ZeroizeOnDrop, OpaqueDebug)]
pub struct Protected<T: Zeroize>(pub(crate) T);

impl<T: Zeroize> Protected<T> {
    /// Create a new [Protected] from an inner value.
    pub const fn new(x: T) -> Self {
        Self(x)
    }

    /// Move the inner value out without running the zeroizing `Drop`.
    ///
    /// Ownership of the (still sensitive) value transfers to the caller, which
    /// becomes responsible for its lifecycle. See [`crate::move_inner_out`] for
    /// the shared primitive and the rationale (including why the source slot is
    /// not scrubbed).
    fn into_inner_unchecked(self) -> T {
        crate::move_inner_out(self)
    }
}

// SAFETY: `inner_ptr` returns a pointer to `self`'s live, owned inner field, and
// `Protected`'s derived `Drop` only zeroizes — satisfying `MoveInner`'s contract.
unsafe impl<T: Zeroize> crate::MoveInner for Protected<T> {
    type Inner = T;
    fn inner_ptr(&self) -> *const T {
        &self.0
    }
}

impl<T: Zeroize> Protected<Protected<T>> {
    #[inline]
    /// Flatten a [Protected] of [Protected] into a single [Protected].
    /// Similar to `Option::flatten`.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
    /// let x = Protected::new(Protected::new([0u8; 32]));
    /// let y = x.flatten();
    /// assert_eq!(y.risky_unwrap(), [0u8; 32]);
    /// ```
    ///
    /// Like [Option], flattening only removes one level of nesting at a time.
    ///
    pub fn flatten(self) -> Protected<T> {
        self.into_inner_unchecked()
    }
}

impl<T: Zeroize> Protected<Option<T>> {
    #[inline]
    /// Transpose a [Protected] of `Option` into an `Option` of [Protected].
    /// Similar to `Option::transpose`.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::Protected;
    /// let x = Protected::new(Some([0u8; 32]));
    /// let y = x.transpose();
    /// assert!(y.is_some())
    /// ```
    pub fn transpose(self) -> Option<Protected<T>> {
        self.into_inner_unchecked().map(Protected::new)
    }
}

impl<T: Zeroize> ControlledPrivate for Protected<T> {}

impl<T> Controlled for Protected<T>
where
    T: Zeroize,
{
    fn risky_unwrap(self) -> Self::Inner {
        self.into_inner_unchecked()
    }

    type Inner = T;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(x)
    }

    fn risky_ref(&self) -> &T {
        &self.0
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        &mut self.0
    }
}

// NOTE: `Protected<T>` deliberately does NOT implement `Copy`. `Copy` and
// `Drop` are mutually exclusive in Rust, and the zeroizing `Drop` is the whole
// point — a bitwise copy would leave un-zeroized duplicates of the secret.
// Use `Clone` (explicit) where a duplicate is genuinely needed.

impl<T> Clone for Protected<T>
where
    T: Clone + Zeroize,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, A> Extend<A> for Protected<T>
where
    T: Extend<A> + Zeroize,
{
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = A>,
    {
        self.0.extend(iter);
    }
}

#[cfg(feature = "arbitrary")]
impl<T> quickcheck::Arbitrary for Protected<T>
where
    T: quickcheck::Arbitrary + Zeroize,
{
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let inner = T::arbitrary(g);
        Self::new(inner)
    }
}

/// Convenience function to flatten an array of [Protected] into a [Protected] array.
///
/// # Example
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{flatten_array, Controlled, Protected};
/// let x = Protected::new(1);
/// let y = Protected::new(2);
/// let z = Protected::new(3);
/// let array: [Protected<u8>; 3] = [x, y, z];
/// let flattened: Protected<[u8; 3]> = flatten_array(array);
/// assert_eq!(flattened.risky_unwrap(), [1, 2, 3]);
/// ```
pub fn flatten_array<const N: usize, T>(array: [Protected<T>; N]) -> Protected<[T; N]>
where
    T: Zeroize,
{
    // `[_; N]::map` moves each `Protected<T>` into the closure; `risky_unwrap`
    // moves the inner secret straight through — no copy, and no `T: Copy` /
    // `Default` bound (the secret is never duplicated).
    Protected::new(array.map(|p| p.risky_unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_new_array() {
        let x = Protected::new([0u8; 32]);
        assert_eq!(x.0, [0u8; 32]);
    }

    /// Regression test for #181: dropping a `Protected<T>` must zeroize its
    /// inner value. Uses an inner type whose `Zeroize` sets a flag, so we can
    /// observe that `Drop` ran the wipe (the bytes themselves are freed and
    /// can't be inspected after drop).
    #[test]
    fn drop_zeroizes_inner() {
        struct Tracked<'a>(&'a AtomicBool);
        impl Zeroize for Tracked<'_> {
            fn zeroize(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let zeroized = AtomicBool::new(false);
        {
            let _p = Protected::new(Tracked(&zeroized));
            assert!(!zeroized.load(Ordering::SeqCst));
        }
        assert!(
            zeroized.load(Ordering::SeqCst),
            "Protected::drop should zeroize the inner value"
        );
    }

    /// Regression test for #263: a `Copy` payload must still be wiped when
    /// the wrapper drops. `Protected<T>` used to be `Copy` whenever `T` was,
    /// which made a zeroizing `Drop` structurally impossible for exactly the
    /// payloads that carry key material (`[u8; 32]` and friends). The payload
    /// here is `Copy`, and the wipe must run anyway.
    #[test]
    fn drop_zeroizes_copy_payload() {
        #[derive(Clone, Copy)]
        struct CopyTracked<'a>(&'a AtomicBool);
        impl Zeroize for CopyTracked<'_> {
            fn zeroize(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let zeroized = AtomicBool::new(false);
        {
            let _p = Protected::new(CopyTracked(&zeroized));
            assert!(!zeroized.load(Ordering::SeqCst));
        }
        assert!(
            zeroized.load(Ordering::SeqCst),
            "Protected::drop must zeroize a Copy payload"
        );
    }

    /// Regression test for #263: `ZeroizeOnDrop` on `Protected<T>` must be
    /// backed by real drop glue, not a bare marker impl. Byte arrays and byte
    /// vectors are the payloads downstream key material actually uses.
    #[test]
    fn zeroize_on_drop_is_backed_by_drop_glue() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Protected<[u8; 32]>>();
        assert_zeroize_on_drop::<Protected<Vec<u8>>>();

        // A marker-only `ZeroizeOnDrop` leaves `[u8; 32]` with no destructor
        // at all; `needs_drop` is the compiler's word on whether one exists.
        // Each pair shows the payload alone contributes no glue, so the
        // wrapper's `true` can only come from `Protected`'s zeroizing `Drop`.
        // (`Protected<Vec<u8>>` proves nothing here: `Vec` brings its own
        // destructor, so `needs_drop` stays true even with no wipe at all.)
        assert!(!std::mem::needs_drop::<[u8; 32]>());
        assert!(std::mem::needs_drop::<Protected<[u8; 32]>>());
        assert!(!std::mem::needs_drop::<u64>());
        assert!(std::mem::needs_drop::<Protected<u64>>());
    }

    /// The canonical downstream nesting from the `Exportable` docs: the drop
    /// glue must propagate through all three wrapper layers, and the payload
    /// alone contributes none of it.
    #[test]
    fn nested_wrappers_keep_zeroizing_drop_glue() {
        use crate::{Equatable, Exportable};
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Exportable<Equatable<Protected<[u8; 32]>>>>();
        assert_zeroize_on_drop::<Equatable<Exportable<Protected<[u8; 32]>>>>();
        assert!(!std::mem::needs_drop::<[u8; 32]>());
        assert!(std::mem::needs_drop::<
            Exportable<Equatable<Protected<[u8; 32]>>>,
        >());
        assert!(std::mem::needs_drop::<
            Equatable<Exportable<Protected<[u8; 32]>>>,
        >());
    }

    /// The README's clone contract: a clone is a distinct value with its own
    /// zeroizing `Drop`, so each duplicate is wiped exactly once, when it
    /// itself drops. Fails if `Clone` ever starts aliasing the payload or the
    /// clone loses its drop glue.
    #[test]
    fn each_clone_is_wiped_independently() {
        use std::sync::atomic::AtomicUsize;

        #[derive(Clone)]
        struct Counted<'a>(&'a AtomicUsize);
        impl Zeroize for Counted<'_> {
            fn zeroize(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let wipes = AtomicUsize::new(0);
        let original = Protected::new(Counted(&wipes));
        let dup = original.clone();
        drop(original);
        assert_eq!(
            wipes.load(Ordering::SeqCst),
            1,
            "original wiped on its own drop"
        );
        drop(dup);
        assert_eq!(wipes.load(Ordering::SeqCst), 2, "clone wiped independently");
    }

    /// Regression test for #263: `Protected`'s drop glue runs the payload's
    /// `Zeroize` to completion — the payload observes its own wiped bytes
    /// from inside `zeroize`, while the value is still live, so the
    /// observation never touches a dropped value. (That the array wipe
    /// itself writes zeros is the `zeroize` crate's property; what this
    /// pins for `Protected` is that the wipe runs and finishes.)
    #[test]
    fn drop_runs_payload_zeroize_to_completion() {
        struct Recorded<'a> {
            bytes: [u8; 32],
            wiped: &'a Cell<Option<[u8; 32]>>,
        }
        impl Zeroize for Recorded<'_> {
            fn zeroize(&mut self) {
                self.bytes.zeroize();
                self.wiped.set(Some(self.bytes));
            }
        }

        let wiped = Cell::new(None);
        {
            let _p = Protected::new(Recorded {
                bytes: [0xAB_u8; 32],
                wiped: &wiped,
            });
            assert!(wiped.get().is_none());
        }
        assert_eq!(
            wiped.get(),
            Some([0_u8; 32]),
            "Protected::drop must wipe the array bytes"
        );
    }

    /// `risky_unwrap` must move the secret out *without* the wrapper's `Drop`
    /// zeroizing it on the way (the caller now owns the live value).
    #[test]
    fn risky_unwrap_does_not_zeroize() {
        struct Tracked<'a>(&'a AtomicBool);
        impl Zeroize for Tracked<'_> {
            fn zeroize(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let zeroized = AtomicBool::new(false);
        // The recovered value is live and owned here; `Tracked` has no `Drop`,
        // so letting it fall out of scope is a no-op and the flag stays false.
        let _recovered = Protected::new(Tracked(&zeroized)).risky_unwrap();
        assert!(
            !zeroized.load(Ordering::SeqCst),
            "risky_unwrap must not zeroize the value it hands back"
        );
    }

    /// `flatten` and `transpose` route through `into_inner_unchecked`, so the
    /// consumed outer wrapper must NOT wipe the value it hands on — the
    /// result still owns the live secret. The wipe belongs to whoever drops
    /// the result, and it must still happen there.
    #[test]
    fn flatten_and_transpose_move_without_zeroizing() {
        struct Tracked<'a>(&'a AtomicBool);
        impl Zeroize for Tracked<'_> {
            fn zeroize(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let zeroized = AtomicBool::new(false);
        let flattened = Protected::new(Protected::new(Tracked(&zeroized))).flatten();
        assert!(
            !zeroized.load(Ordering::SeqCst),
            "flatten must not zeroize the value it hands on"
        );
        drop(flattened);
        assert!(
            zeroized.load(Ordering::SeqCst),
            "the flattened wrapper still wipes on drop"
        );

        let zeroized = AtomicBool::new(false);
        let transposed = Protected::new(Some(Tracked(&zeroized))).transpose();
        assert!(
            !zeroized.load(Ordering::SeqCst),
            "transpose must not zeroize the value it hands on"
        );
        drop(transposed);
        assert!(
            zeroized.load(Ordering::SeqCst),
            "the transposed wrapper still wipes on drop"
        );
    }

    #[test]
    fn test_opaque_debug() {
        let x = Protected::new([0u8; 32]);
        assert_eq!(
            format!("{x:?}"),
            "vitaminc_protected::protected::Protected<[u8; 32]>(\"***\")"
        );
    }

    #[test]
    fn test_flatten() {
        let x = Protected::new(Protected::new([0u8; 32]));
        let y = x.flatten();
        assert_eq!(y.risky_unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_flatten_array() {
        let x = Protected::new(1);
        let y = Protected::new(2);
        let z = Protected::new(3);
        let array: [Protected<u8>; 3] = [x, y, z];
        let flattened = flatten_array(array);
        assert!(matches!(flattened, Protected(_)));
        assert_eq!(flattened.risky_unwrap(), [1, 2, 3]);
    }
}

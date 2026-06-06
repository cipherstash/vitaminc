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
        let field: *const T = &self.0;
        // SAFETY: `field` points to `self`'s live owned inner; `Protected`'s
        // `Drop` only zeroizes.
        unsafe { crate::move_inner_out(self, field) }
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

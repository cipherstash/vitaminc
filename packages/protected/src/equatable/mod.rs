use crate::{exportable::SafeSerialize, private::ControlledPrivate, Controlled, Protected};
use core::num::NonZeroU16;
use serde::{Serialize, Serializer};
use subtle::ConstantTimeEq as SubtleCtEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A _controlled_ wrapper type that allows for constant time equality checks of a [Controlled] type.
/// The immediate inner type must also be [Controlled] (typically [Protected]).
///
/// # Examples
///
/// Initializing an [Equatable]:
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Equatable, Controlled, Protected};
/// let x: Equatable<Protected<u8>> = 42.into();
/// let y: Equatable<Protected<u8>> = Equatable::<Protected<u8>>::new(42);
/// ```
///
/// # Constant time comparisons
///
/// [Equatable] requires that types are equatable in constant time.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Equatable, Protected};
/// let x: Equatable<Protected<u8>> = 112.into();
/// let y: Equatable<Protected<u8>> = 112.into();
///
/// assert!(x.constant_time_eq(&y));
/// ```
///
/// The [Equatable] type also implements `PartialEq` and `Eq` for easy comparison using the constant time implementation.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Equatable, Protected};
/// let x: Equatable<Protected<u8>> = 112.into();
/// let y: Equatable<Protected<u8>> = 112.into();
/// assert_eq!(x, y);
/// ```
///
/// # Nesting [Equatable] types
///
/// Constant time comparison also works for nested `Equatable` types.
/// This way, the ordering or depth of the nesting doesn't matter, the comparison will always be constant time.
///
/// See also [crate::Exportable].
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Exportable, Equatable, Protected};
/// let x: Equatable<Protected<[u8; 16]>> = [0u8; 16].into();
/// let y: Exportable<Equatable<Protected<[u8; 16]>>> = Exportable::new([0u8; 16]);
///
/// assert_eq!(x, y);
/// ```
///
/// # Opaque Debug
///
/// Because [Equatable] wraps [Controlled], inner types will never be printed.
/// It's therefore safe to use it in debug output and in custom types.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Equatable, Controlled, Protected};
///
/// type Inner = Equatable<Protected<u8>>;
///
/// #[derive(Debug, PartialEq)]
/// struct SafeType(Inner);
/// let x = SafeType(Inner::new(100));
/// assert!(format!("{:?}", x).contains("Protected<u8>"));
/// ```
///
/// # Usage in a struct
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Equatable, Protected};
///
/// #[derive(Debug, PartialEq)]
/// struct AuthenticatedString {
///   tag: Equatable<Protected<[u8; 32]>>,
///   value: String
/// }
///
/// impl AuthenticatedString {
///     fn new(tag: [u8; 32], value: String) -> Self {
///         Self { tag: tag.into(), value }
///     }
/// }
///
/// let a = AuthenticatedString::new([0u8; 32], "Hello, world!".to_string());
/// let b = AuthenticatedString::new([0u8; 32], "Hello, world!".to_string());
/// assert_eq!(a, b);
/// ```
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Equatable<T: Zeroize>(pub(crate) T);

impl<T: Zeroize> Equatable<T> {
    /// Create a new `Equatable` from an inner value.
    pub fn new(x: <Equatable<T> as Controlled>::Inner) -> Self
    where
        Self: Controlled,
    {
        Self::init_from_inner(x)
    }

    /// Move the inner value out without running the zeroizing `Drop`.
    /// See [`crate::move_inner_out`] for the shared primitive and rationale.
    fn into_inner_unchecked(self) -> T {
        crate::move_inner_out(self)
    }
}

// SAFETY: `inner_ptr` returns a pointer to `self`'s live, owned inner field, and
// `Equatable`'s derived `Drop` only zeroizes — satisfying `MoveInner`'s contract.
unsafe impl<T: Zeroize> crate::MoveInner for Equatable<T> {
    type Inner = T;
    fn inner_ptr(&self) -> *const T {
        &self.0
    }
}

impl<T> From<T> for Equatable<T>
where
    T: ControlledPrivate + Zeroize,
{
    fn from(x: T) -> Self {
        Self(x)
    }
}

impl<T: Controlled> Equatable<T>
where
    T::Inner: ConstantTimeEq,
{
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.risky_ref().constant_time_eq(other.risky_ref())
    }
}

// TODO: Canwe make a blanket impl for all Paranoid types?
impl<T: ControlledPrivate + Zeroize> ControlledPrivate for Equatable<T> {}

impl<T> Controlled for Equatable<T>
where
    T: Controlled,
{
    type Inner = T::Inner;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(T::init_from_inner(x))
    }

    fn risky_ref(&self) -> &Self::Inner {
        self.0.risky_ref()
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        self.0.inner_mut()
    }

    fn risky_unwrap(self) -> Self::Inner {
        self.into_inner_unchecked().risky_unwrap()
    }
}

impl<T, A> Extend<A> for Equatable<T>
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

// TODO: Further constrain this
impl<T> From<T> for Equatable<Protected<T>>
where
    T: Into<Protected<T>> + Zeroize,
{
    fn from(x: T) -> Self {
        Self(Protected::init_from_inner(x))
    }
}

/// PartialEq is implemented in constant time for any `Equatable` to any (nested) `Equatable`.
impl<T, O> PartialEq<O> for Equatable<T>
where
    T: Controlled,
    O: Controlled,
    <T as Controlled>::Inner: ConstantTimeEq<O::Inner>,
{
    fn eq(&self, other: &O) -> bool {
        self.risky_ref().constant_time_eq(other.risky_ref())
    }
}

impl<T, O> ConstantTimeEq<O> for Equatable<T>
where
    T: Controlled,
    O: Controlled,
    <T as Controlled>::Inner: ConstantTimeEq<O::Inner>,
{
    fn constant_time_eq(&self, other: &O) -> bool {
        self.risky_ref().constant_time_eq(other.risky_ref())
    }
}

pub trait ConstantTimeEq<Rhs: ?Sized = Self>: private::SupportsConstantTimeEq {
    /// This method tests for `self` and `other` values to be equal, using constant time operations.
    /// Implementations will mostly use `ConstantTimeEq::ct_eq` to achieve this but because
    /// not everything is implemented in `subtle-ng`, we create our own "wrapping" trait.
    fn constant_time_eq(&self, other: &Rhs) -> bool; // TODO: Use a Choice type like subtle

    // TODO: Do we also need a constant_time_neq ?
}

impl<const N: usize, T> ConstantTimeEq<Self> for [T; N]
where
    T: ConstantTimeEq,
{
    fn constant_time_eq(&self, other: &Self) -> bool {
        let mut x = true;
        for (ai, bi) in self.iter().zip(other.iter()) {
            // FIXME: This may get shortcircuited (should use the same idea as subtle)
            x &= ai.constant_time_eq(bi);
        }

        x
    }
}

macro_rules! impl_constany_time_eq {
    ($($type:ty),+) => {
        $(
            impl ConstantTimeEq for $type {
                fn constant_time_eq(&self, other: &Self) -> bool {
                    self.ct_eq(other).into()
                }
            }
        )+
    };
}

impl_constany_time_eq!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128);

impl ConstantTimeEq for NonZeroU16 {
    #[inline]
    fn constant_time_eq(&self, other: &Self) -> bool {
        // The NonZeroX types don't implement Xor so we need to get the inner value.
        // Because the inner value is Copy, we must make sure to Zeroize the copied value
        // when we're done with our check.
        let mut a_inner = self.get();
        let mut b_inner = other.get();
        let result = a_inner.constant_time_eq(&b_inner);
        a_inner.zeroize();
        b_inner.zeroize();
        result
    }
}

impl ConstantTimeEq for [u8] {
    fn constant_time_eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        let mut x = true;
        for (ai, bi) in self.iter().zip(other.iter()) {
            x &= ai.constant_time_eq(bi);
        }

        x
    }
}

impl ConstantTimeEq for str {
    /// Check whether two strings are equal.
    ///
    /// This function short-circuits if the lengths of the input strings
    /// are different.
    #[inline]
    fn constant_time_eq(&self, other: &Self) -> bool {
        self.as_bytes().constant_time_eq(other.as_bytes())
    }
}

impl ConstantTimeEq for String {
    /// Check whether two strings are equal.
    ///
    /// This function short-circuits if the lengths of the input strings
    /// are different.
    fn constant_time_eq(&self, other: &Self) -> bool {
        self.as_bytes().constant_time_eq(other.as_bytes())
    }
}

/// Serialize is implemented for any `Equatable` type that has a `SafeSerialize` inner type.
impl<T> Serialize for Equatable<T>
where
    T: Controlled,
    T::Inner: SafeSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.risky_ref().safe_serialize(serializer)
    }
}

mod private {
    use std::num::NonZeroU16;

    use super::Equatable;

    /// Private marker trait.
    pub trait SupportsConstantTimeEq {}

    impl<T: zeroize::Zeroize> SupportsConstantTimeEq for Equatable<T> {}
    impl<const N: usize, T> SupportsConstantTimeEq for [T; N] {}
    impl SupportsConstantTimeEq for u8 {}
    impl SupportsConstantTimeEq for u16 {}
    impl SupportsConstantTimeEq for u32 {}
    impl SupportsConstantTimeEq for u64 {}
    impl SupportsConstantTimeEq for u128 {}
    impl SupportsConstantTimeEq for usize {}
    impl SupportsConstantTimeEq for i8 {}
    impl SupportsConstantTimeEq for i16 {}
    impl SupportsConstantTimeEq for i32 {}
    impl SupportsConstantTimeEq for i64 {}
    impl SupportsConstantTimeEq for i128 {}
    impl SupportsConstantTimeEq for isize {}
    impl SupportsConstantTimeEq for NonZeroU16 {}
    impl SupportsConstantTimeEq for [u8] {}
    impl SupportsConstantTimeEq for String {}
    impl SupportsConstantTimeEq for str {}
}

#[cfg(test)]
mod tests {
    use super::ConstantTimeEq;
    use crate::test_util::Tracked;
    use crate::{Controlled, Equatable, Protected};
    use core::num::NonZeroU16;
    use std::sync::atomic::AtomicBool;

    /// `Equatable`'s `ZeroizeOnDrop` comes from the derive; this pins the
    /// generated drop glue so removing the derive fails a test, not just a
    /// promise. The `!Copy` half lives in `tests/ui/negative_space`.
    #[test]
    fn drop_zeroizes_inner() {
        let zeroized = AtomicBool::new(false);
        let tracked = Tracked(&zeroized);
        {
            let _e = Equatable(tracked);
            assert!(!tracked.was_zeroized());
        }
        assert!(
            tracked.was_zeroized(),
            "Equatable::drop must zeroize the inner value"
        );
    }

    /// `risky_unwrap` routes through `into_inner_unchecked` and then the inner
    /// wrapper's `risky_unwrap`: neither layer may wipe the value it hands on,
    /// since the caller now owns the live secret.
    #[test]
    fn risky_unwrap_does_not_zeroize() {
        let zeroized = AtomicBool::new(false);
        let tracked = Tracked(&zeroized);
        // `Tracked` has no `Drop`, so the recovered value falling out of
        // scope is a no-op and the flag can only be raised by a wrapper.
        let _recovered = Equatable(Protected::new(tracked)).risky_unwrap();
        assert!(
            !tracked.was_zeroized(),
            "Equatable::risky_unwrap must not zeroize the value it hands back"
        );
    }

    #[test]
    fn test_opaque_debug() {
        let x: Equatable<Protected<[u8; 32]>> = Equatable::new([0u8; 32]);
        assert_eq!(
            format!("{x:?}"),
            "Equatable(vitaminc_protected::protected::Protected<[u8; 32]>(\"***\"))"
        );
    }

    #[test]
    fn test_safe_eq_arr() {
        // Using 2 ways to get an equatable value
        let x: Equatable<Protected<[u8; 16]>> = Equatable::from([0u8; 16]);
        let y: Equatable<Protected<[u8; 16]>> = Equatable::new([0u8; 16]);

        assert_eq!(x, y);
        assert!(x.constant_time_eq(&y));
    }

    #[test]
    fn test_equality_u8() {
        let x: Equatable<Protected<u8>> = Equatable::new(27);
        let y: Equatable<Protected<u8>> = Equatable::new(27);

        assert_eq!(x, y);
        assert!(x.constant_time_eq(&y));
    }

    #[test]
    fn test_inequality_u8() {
        let x: Equatable<Protected<u8>> = Equatable::new(27);
        let y: Equatable<Protected<u8>> = Equatable::new(0);

        assert_ne!(x, y);
        assert!(!x.constant_time_eq(&y));
    }

    // The tests below exercise the `ConstantTimeEq` impls directly (the tests
    // above only reach the `Protected<u8>`/`[u8; N]` inner types via `Equatable`).
    // Each asserts equal -> true (kills a `-> false` mutant), unequal -> false
    // (kills a `-> true` mutant), a partial difference (kills `&=` -> `|=` in the
    // accumulator), and a length mismatch where applicable. See issue #206.
    #[test]
    fn ct_eq_u8_slice() {
        let a: &[u8] = &[1, 2, 3, 4];
        let equal: &[u8] = &[1, 2, 3, 4];
        let last_differs: &[u8] = &[1, 2, 3, 5];
        let first_differs: &[u8] = &[9, 2, 3, 4];
        let shorter: &[u8] = &[1, 2, 3];

        assert!(a.constant_time_eq(equal));
        assert!(!a.constant_time_eq(last_differs));
        assert!(!a.constant_time_eq(first_differs));
        assert!(!a.constant_time_eq(shorter));
    }

    #[test]
    fn ct_eq_str() {
        assert!("hunter2".constant_time_eq("hunter2"));
        assert!(!"hunter2".constant_time_eq("hunter3"));
        assert!(!"hunter2".constant_time_eq("hunter")); // length mismatch
    }

    #[test]
    fn ct_eq_string() {
        let a = String::from("hunter2");
        assert!(a.constant_time_eq(&String::from("hunter2")));
        assert!(!a.constant_time_eq(&String::from("hunter3")));
        assert!(!a.constant_time_eq(&String::from("hunter"))); // length mismatch
    }

    #[test]
    fn ct_eq_nonzero_u16() {
        let a = NonZeroU16::new(42).unwrap();
        assert!(a.constant_time_eq(&NonZeroU16::new(42).unwrap()));
        assert!(!a.constant_time_eq(&NonZeroU16::new(43).unwrap()));
    }

    #[test]
    fn ct_eq_array() {
        let a: [u8; 4] = [1, 2, 3, 4];

        assert!(a.constant_time_eq(&[1, 2, 3, 4]));
        assert!(!a.constant_time_eq(&[1, 2, 3, 5]));
        assert!(!a.constant_time_eq(&[9, 2, 3, 4])); // partial difference
    }

    #[test]
    fn ct_eq_equatable_trait_impl() {
        // UFCS selects the `ConstantTimeEq for Equatable` trait impl rather than
        // the inherent `Equatable::constant_time_eq` method exercised above.
        let x: Equatable<Protected<u8>> = Equatable::new(5);
        let y: Equatable<Protected<u8>> = Equatable::new(5);
        let z: Equatable<Protected<u8>> = Equatable::new(6);

        assert!(ConstantTimeEq::constant_time_eq(&x, &y));
        assert!(!ConstantTimeEq::constant_time_eq(&x, &z));
    }
}

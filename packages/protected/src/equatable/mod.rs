use crate::{exportable::SafeSerialize, private::ControlledPrivate, Controlled, Protected};
use core::num::NonZeroU16;
use serde::{Serialize, Serializer};
use subtle::ConstantTimeEq as SubtleCtEq;
use zeroize::Zeroize;

/// A _controlled_ wrapper type that allows for constant time equality checks of a [Controlled] type.
/// The immediate inner type must also be [Controlled] (typically [Protected]).
///
/// # Examples
///
/// Initializing an [Equatable]:
///
/// ```
/// use vitaminc_protected::{Equatable, Controlled, Protected};
/// let x: Equatable<Protected<u8>> = 42.into();
/// let y: Equatable<Protected<u8>> = Equatable::<Protected<u8>>::new(42);
/// ```
///
/// # Constant time comparisons
///
/// [Equatable] requires that types are equatable in constant time.
///
/// ```
/// use vitaminc_protected::{Equatable, Protected};
/// let x: Equatable<Protected<u8>> = 112.into();
/// let y: Equatable<Protected<u8>> = 112.into();
///
/// assert!(x.constant_time_eq(&y));
/// ```
///
/// The [Equatable] type also implements `PartialEq` and `Eq` for easy comparison using the constant time implementation.
///
/// ```
/// use vitaminc_protected::{Equatable, Protected};
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
/// use vitaminc_protected::{Exportable, Equatable, Protected};
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
/// use vitaminc_protected::{Equatable, Controlled, Protected};
///
/// type Inner = Equatable<Protected<u8>>;
///
/// #[derive(Debug, PartialEq)]
/// struct SafeType(Inner);
/// let x = SafeType(Inner::new(100));
/// assert_eq!(format!("{:?}", x), "SafeType(Equatable(Protected<u8> { ... }))");
/// ```
///
/// # Usage in a struct
///
/// ```
/// use vitaminc_protected::{Equatable, Protected};
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
#[derive(Debug, Zeroize)]
pub struct Equatable<T>(pub(crate) T);

impl<T> Equatable<T> {
    /// Create a new `Equatable` from an inner value.
    pub fn new(x: <Equatable<T> as ControlledPrivate>::Inner) -> Self
    where
        Self: ControlledPrivate,
    {
        Self::init_from_inner(x)
    }
}

impl<T> From<T> for Equatable<T>
where
    T: ControlledPrivate,
{
    fn from(x: T) -> Self {
        Self(x)
    }
}

impl<T: ControlledPrivate> Equatable<T>
where
    T::Inner: ConstantTimeEq,
{
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

// TODO: Canwe make a blanket impl for all Paranoid types?
impl<T: ControlledPrivate> ControlledPrivate for Equatable<T> {
    type Inner = T::Inner;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(T::init_from_inner(x))
    }

    fn inner(&self) -> &Self::Inner {
        self.0.inner()
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        self.0.inner_mut()
    }
}

impl<T> Controlled for Equatable<T>
where
    T: Controlled,
{
    fn risky_unwrap(self) -> Self::Inner {
        self.0.risky_unwrap()
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
    T: ControlledPrivate,
    O: ControlledPrivate,
    <T as ControlledPrivate>::Inner: ConstantTimeEq<O::Inner>,
{
    fn eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

impl<T, O> ConstantTimeEq<O> for Equatable<T>
where
    T: ControlledPrivate,
    O: ControlledPrivate,
    <T as ControlledPrivate>::Inner: ConstantTimeEq<O::Inner>,
{
    fn constant_time_eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
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
    T: ControlledPrivate,
    T::Inner: SafeSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner().safe_serialize(serializer)
    }
}

mod private {
    use std::num::NonZeroU16;

    use super::Equatable;

    /// Private marker trait.
    pub trait SupportsConstantTimeEq {}

    impl<T> SupportsConstantTimeEq for Equatable<T> {}
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
    use crate::{Equatable, Protected};

    #[test]
    fn test_opaque_debug() {
        let x: Equatable<Protected<[u8; 32]>> = Equatable::new([0u8; 32]);
        assert_eq!(format!("{:?}", x), "Equatable(Protected<[u8; 32]> { ... })");
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
}

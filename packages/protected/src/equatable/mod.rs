use crate::{private::ProtectSealed, Controlled, ControlledMethods, ControlledNew, Protected};
use core::num::NonZeroU16;
use subtle::ConstantTimeEq as SubtleCtEq;
use zeroize::Zeroize;

/// A wrapper type that allows for constant time equality checks of a `Paranoid` type.
///
/// # Examples
///
/// Initializing an [Equatable] from a [Protected] type:
///
/// ```
/// use vitaminc_protected::{Equatable, Protected, ProtectNew};
/// // Initialize from a "raw"
/// let x: Equatable<Protected<u8>> = Equatable::new(42);
/// // Or initialize from another adapter
/// let y: Equatable<Protected<u8>> = Equatable::init(Protected::new(42));
/// ```
///
/// # Constant time comparisons
///
/// [Equatable] ensures that inner values are equatable in constant time.
///
/// ```
/// use vitaminc_protected::{Equatable, Protected, ProtectNew};
/// let x: Equatable<Protected<u8>> = Equatable::new(112);
/// let y: Equatable<Protected<u8>> = Equatable::new(112);
///
/// assert!(x.constant_time_eq(&y));
/// ```
///
/// For convenience, [Equatable] implements `PartialEq` and `Eq` using the constant time implementation.
///
/// ```
/// use vitaminc_protected::{Equatable, Protected, ProtectNew};
/// let x: Equatable<Protected<u8>> = Equatable::new(112);
/// let y: Equatable<Protected<u8>> = Equatable::new(112);
/// assert_eq!(x, y);
/// ```
///
/// # Nesting `Equatable` types
///
/// Constant time comparison also works for heterogenous [Equatable] types
/// so long as the inner types implement `ConstantTimeEq`.
///
/// See also [Exportable].
///
/// TODO: Reinstate this once exportable is back
/// ```
/// /*use vitaminc_protected::{Exportable, Equatable, Protected, ProtectNew};
/// let x: Equatable<Protected<[u8; 16]>> = Equatable::new([0u8; 16]);
/// let y: Exportable<Equatable<Protected<[u8; 16]>>> = Exportable::new([0u8; 16]);
///
/// assert_eq!(x, y);*/
/// ```
///
/// # Opaque Debug
///
/// Because [Equatable] wraps [Protected], inner types will never be printed.
/// It's therefore safe to use [Equatable] in debug output and in custom types.
///
/// ```
/// use vitaminc_protected::{Equatable, Protected, ProtectNew};
///
/// #[derive(Debug, PartialEq)]
/// struct SafeType(Equatable<Protected<u8>>);
/// let x = SafeType(Equatable::new(100));
/// assert_eq!(format!("{:?}", x), "SafeType(Equatable(Protected<u8> { ... }))");
/// ```
///
/// # Usage in a struct
///
/// ```
/// use vitaminc_protected::{Equatable, Protected, ProtectNew};
///
/// #[derive(Debug, PartialEq)]
/// struct AuthenticatedString {
///   tag: Equatable<Protected<[u8; 32]>>,
///   value: String
/// }
///
/// impl AuthenticatedString {
///     fn new(tag: [u8; 32], value: String) -> Self {
///         Self { tag: Equatable::new(tag), value }
///     }
/// }
///
/// let a = AuthenticatedString::new([0u8; 32], "Hello, world!".to_string());
/// let b = AuthenticatedString::new([0u8; 32], "Hello, world!".to_string());
/// assert_eq!(a, b);
/// ```
#[derive(Debug, Zeroize)]
pub struct Equatable<T>(pub(crate) T);

impl<T> Equatable<T>
where
    T: Controlled,
{
    /// Initialize an `Equatable` from an inner value.
    /// Note that this is different to [ProtectNew::new] as it takes the immediate child of the `Equatable`
    /// rather than the innermost "raw" value.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Equatable, Protected, ProtectNew};
    /// let x: Equatable<Protected<u8>> = Equatable::init(Protected::new(42));
    /// ```
    ///
    /// Trying to call `init` with a type that is not `Protect` will result in a compile error.
    ///
    /// ```compile_fail
    /// use vitaminc_protected::Equatable;
    /// let x: Equatable<u8> = Equatable::init(42);
    /// ```
    ///
    pub const fn init(x: T) -> Self {
        Self(x)
    }
}

impl<T> Controlled for Equatable<T>
where
    T: Controlled,
{
    type RawType = T::RawType;

    fn risky_unwrap(self) -> T::RawType {
        self.0.risky_unwrap()
    }
}

impl<T, I> ControlledNew<I> for Equatable<T>
where
    T: ControlledNew<I>,
    Self: Controlled<RawType = I>,
{
    fn new(raw: Self::RawType) -> Self {
        Self(T::new(raw))
    }
}

impl<T> From<T> for Equatable<T>
where
    T: ProtectSealed,
{
    fn from(x: T) -> Self {
        Self(x)
    }
}

impl<T> Equatable<T>
where
    Self: ControlledMethods,
    <Equatable<T> as Controlled>::RawType: ConstantTimeEq,
{
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

// FIXME: This is super clunky
// We should have a separate trait for getting the inner value of a `Protected`
impl<T> ControlledMethods for Equatable<T>
where
    T: Controlled + ControlledMethods,
{
    // TODO: Consider removing this or making it a separate trait usable only within the crate
    // Or could it return a ProtectedRef?
    fn inner(&self) -> &Self::RawType {
        self.0.inner()
    }

    fn inner_mut(&mut self) -> &mut Self::RawType {
        self.0.inner_mut()
    }
}

// TODO: Consider removing this
impl<T> From<T> for Equatable<Protected<T>>
where
    T: Into<Protected<T>> + Zeroize,
{
    fn from(x: T) -> Self {
        Self(Protected::new(x))
    }
}

// Clone and Copy are implemented for `Equatable` if the inner type is Clone and Copy
impl<T> Copy for Equatable<T> where T: Copy {}

impl<T> Clone for Equatable<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// PartialEq is implemented in constant time for any `Equatable` to any (nested) `Equatable`.
impl<T, O> PartialEq<O> for Equatable<T>
where
    Self: ControlledMethods,
    <Equatable<T> as Controlled>::RawType: ConstantTimeEq<O::RawType>,
    O: ControlledMethods,
{
    fn eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

impl<T, O> ConstantTimeEq<O> for Equatable<T>
where
    Self: ControlledMethods<RawType = T>,
    O: ControlledMethods,
    T: ConstantTimeEq<O::RawType>,
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

impl ConstantTimeEq for u8 {
    fn constant_time_eq(&self, other: &Self) -> bool {
        // TODO: It would be nice to not have to rely on the subtle crate
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for u16 {
    fn constant_time_eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for u32 {
    fn constant_time_eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for u64 {
    fn constant_time_eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for u128 {
    fn constant_time_eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for usize {
    fn constant_time_eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

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
    impl SupportsConstantTimeEq for NonZeroU16 {}
    impl SupportsConstantTimeEq for [u8] {}
    impl SupportsConstantTimeEq for String {}
    impl SupportsConstantTimeEq for str {}
}

#[cfg(test)]
mod tests {
    use crate::{Equatable, ControlledNew, Protected};

    #[test]
    fn test_opaque_debug() {
        let x: Equatable<Protected<[u8; 32]>> = Equatable::new([0u8; 32]);
        assert_eq!(format!("{:?}", x), "Equatable(Protected<[u8; 32]> { ... })");
    }

    #[test]
    fn test_safe_eq_arr() {
        // Using 2 ways to get an equatable value
        let x: Equatable<Protected<[u8; 16]>> = Equatable::new([0u8; 16]);
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

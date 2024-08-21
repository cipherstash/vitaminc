use crate::{private::ParanoidPrivate, Exportable, Paranoid, Protected};
use core::num::NonZeroU16;
use subtle::ConstantTimeEq as SubtleCtEq;
use zeroize::Zeroize;

/// A wrapper type that allows for constant time equality checks of a `Paranoid` type.
///
/// # Examples
///
/// Initializing an `Equatable` from a `Protected` type:
///
/// ```
/// use vitaminc_protected::{Equatable, Paranoid, Protected};
/// let x: Equatable<Protected<u8>> = 42.into();
/// let y: Equatable<Protected<u8>> = Protected::new(42).into();
/// let z: Equatable<Protected<u8>> = Protected::new(42).equatable();
/// ```
///
/// # Constant time comparisons
///
/// `Equatable` requires that types are equatable in constant time.
///
/// ```
/// use vitaminc_protected::{Equatable, Protected};
/// let x: Equatable<Protected<u8>> = 112.into();
/// let y: Equatable<Protected<u8>> = 112.into();
///
/// assert!(x.constant_time_eq(&y));
/// ```
///
/// The `Equatable` type also implements `PartialEq` and `Eq` for easy comparison using the constant time implementation.
///
/// ```
/// use vitaminc_protected::{Equatable, Protected};
/// let x: Equatable<Protected<u8>> = 112.into();
/// let y: Equatable<Protected<u8>> = 112.into();
/// assert_eq!(x, y);
/// ```
///
/// # Nesting `Equatable` types
///
/// Constant time comparison also works for nested `Equatable` types.
/// This way, the ordering or depth of the nesting doesn't matter, the comparison will always be constant time.
///
/// See also `Exportable`.
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
/// Because `Equatable` wraps `Paranoid`, inner types will never be printed.
/// It's therefore safe to use `Equatable` in debug output and in custom types.
///
/// ```
/// use vitaminc_protected::{Equatable, Paranoid, Protected};
///
/// #[derive(Debug, PartialEq)]
/// struct SafeType(Equatable<Protected<u8>>);
/// let x = SafeType(Protected::new(100).equatable());
/// dbg!(x);
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
#[derive(Debug)]
pub struct Equatable<T>(pub(crate) T);

impl<T> Equatable<T> {
    /// Create a new `Equatable` from an inner value.
    pub fn new(x: <Equatable<T> as ParanoidPrivate>::Inner) -> Self
    where
        Self: ParanoidPrivate,
    {
        Self::init_from_inner(x)
    }

    pub fn exportable(self) -> Exportable<Self> {
        Exportable(self)
    }
}

impl<T> From<T> for Equatable<T>
where
    T: ParanoidPrivate,
{
    fn from(x: T) -> Self {
        Self(x)
    }
}

impl<T: ParanoidPrivate> Equatable<T>
where
    T::Inner: ConstantTimeEq,
{
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

// TODO: Canwe make a blanket impl for all Paranoid types?
impl<T: ParanoidPrivate> ParanoidPrivate for Equatable<T> {
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

impl<T> Paranoid for Equatable<T>
where
    T: Paranoid,
{
    fn unwrap(self) -> Self::Inner {
        self.0.unwrap()
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
    T: ParanoidPrivate,
    O: ParanoidPrivate,
    <T as ParanoidPrivate>::Inner: ConstantTimeEq<O::Inner>,
{
    fn eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

impl<T, O> ConstantTimeEq<O> for Equatable<T>
where
    T: ParanoidPrivate,
    O: ParanoidPrivate,
    <T as ParanoidPrivate>::Inner: ConstantTimeEq<O::Inner>,
{
    fn constant_time_eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

pub trait ConstantTimeEq<Rhs: ?Sized = Self> {
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

#[cfg(test)]
mod tests {
    use crate::{Equatable, Exportable, Paranoid, Protected};

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
    fn test_conversion() {
        let x: Equatable<Protected<u8>> = 0.into();
        let a: Equatable<Protected<u8>> = Protected::new(0).into();
        let b = Protected::<u8>::new(0).equatable();

        assert_eq!(x, a);
        assert_eq!(x, b);
    }

    #[test]
    fn test_conversion_2() {
        // TODO: Create a macro to test lots of these
        let x: Protected<[u8; 16]> = [0u8; 16].into();
        let y: Equatable<Protected<[u8; 16]>> = [0u8; 16].into();
        assert_eq!(y, x.equatable());
    }

    #[test]
    fn test_conversion_string() {
        // TODO: Create a macro to test lots of these
        let x: Protected<String> = Protected::new("hello".to_string());
        let y: Equatable<Protected<String>> = Equatable::new("hello".to_string());
        assert_eq!(y, x.equatable());
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

    #[test]
    fn test_serialize_deserialize_exportable_inner() {
        let x: Equatable<Protected<u8>> = Equatable::new(42);
        let y = bincode::serialize(&x.exportable()).unwrap();

        let z: Exportable<Equatable<Protected<u8>>> = bincode::deserialize(&y).unwrap();
        assert_eq!(z, Protected::new(42).equatable());
    }
}

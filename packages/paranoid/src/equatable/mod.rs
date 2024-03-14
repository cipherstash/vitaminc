use crate::{Paranoid, Protected};
use core::num::NonZeroU16;
use subtle::ConstantTimeEq as SubtleCtEq;
use zeroize::Zeroize;

pub struct Equatable<T>(pub(crate) T);

impl<T: Zeroize> From<Protected<T>> for Equatable<Protected<T>> {
    fn from(x: Protected<T>) -> Self {
        Self(x)
    }
}

impl<T: Paranoid> Equatable<T>
where
    T::Inner: ConstantTimeEq,
{
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

impl<T: Paranoid> Paranoid for Equatable<T> {
    type Inner = T::Inner;

    fn new(x: Self::Inner) -> Self {
        Self(T::new(x))
    }

    fn inner(&self) -> &Self::Inner {
        self.0.inner()
    }
}

// Further constrain this
impl<T> From<T> for Equatable<Protected<T>> where T: Into<Protected<T>> + Zeroize {
    fn from(x: T) -> Self {
        Self(Protected::new(x))
    }
}

/// PartialEq is implemented in constant time.
/*impl<T: Paranoid> PartialEq for Equatable<T>
where
    T::Inner: ConstantTimeEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}*/

// FIXME: If this works we should do it for ConstantTimeEq not PartialEq (just do PartialEq on Paranoid)
impl<T, O> PartialEq<O> for Equatable<T>
where
    T: Paranoid,
    O: Paranoid,
    <T as Paranoid>::Inner: PartialEq<O::Inner>,
{
    fn eq(&self, other: &O) -> bool {
        self.inner() == other.inner()
    }
}

pub trait ConstantTimeEq<Rhs: ?Sized = Self> {
    /// This method tests for `self` and `other` values to be equal, using constant time operations.
    /// Implementations will mostly use `ConstantTimeEq::ct_eq` to achieve this but because
    /// not everything is implemented in `subtle-ng`, we create our own "wrapping" trait.
    fn constant_time_eq(&self, other: &Rhs) -> bool; // TODO: Use a Choice type like subtle
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

#[cfg(test)]
mod tests {
    use crate::{Equatable, Exportable, Paranoid, Protected};

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
        let y: Equatable::<Protected<[u8; 16]>> = [0u8; 16].into();
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
    fn test_serialize_deserialize() {
        let x: Equatable<Protected<u8>> = Equatable::new(42);
        let y = bincode::serialize(&x.exportable()).unwrap();

        let z: Exportable<Equatable<Protected<u8>>> = bincode::deserialize(&y).unwrap();
        assert_eq!(z.inner(), &42);
    }
}

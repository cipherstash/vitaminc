use crate::Paranoid;
use core::num::NonZeroU16;
use subtle::ConstantTimeEq as SubtleCtEq;
use zeroize::Zeroize;

pub struct Equatable<T>(T);

impl<T: Paranoid> Equatable<T>
where
    T::Inner: ConstantTimeEq,
{
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        self.inner().constant_time_eq(&other.inner())
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

impl<T: Paranoid> From<T> for Equatable<T> {
    fn from(x: T) -> Self {
        Self(x)
    }
}

/// PartialEq is implemented in constant time.
impl<T: Paranoid> PartialEq for Equatable<T>
where
    T::Inner: ConstantTimeEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner().constant_time_eq(&other.inner())
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
    use crate::{Equatable, Paranoid, Protected};

    #[test]
    fn test_safe_eq_arr() {
        let x: Equatable<Protected<[u8; 16]>> = Equatable::new([0u8; 16]);
        let y: Equatable<Protected<[u8; 16]>> = Equatable::new([0u8; 16]);

        assert_eq!(x, y);
        assert!(x.constant_time_eq(&y));
    }

    #[test]
    fn test_conversion() {
        let x: Protected<[u8; 16]> = [0u8; 16].into();
        let y: Equatable<Protected<[u8; 16]>> = x.into();
        assert_eq!(y, Equatable::new([0u8; 16]));
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

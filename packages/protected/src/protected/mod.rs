use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::{Protect, ProtectMethods, ProtectNew};

/// Basic building block for Paranoid.
/// It uses a similar design "adapter" pattern to `std::slide::Iter`.
/// `Protected` adds Zeroize and OpaqueDebug.
#[derive(Zeroize)]
pub struct Protected<T>(pub(super) T);

opaque_debug::implement!(Protected<T>);

impl<T> Protect for Protected<T> where T: Zeroize {
    type RawType = T;

    fn risky_unwrap(self) -> T {
        self.0
    }
}

impl<T> ProtectNew<T> for Protected<T> where Self: Protect {
    fn new(raw: T) -> Self {
        Protected(raw)
    }
}

impl<T> Protected<Protected<T>> {
    #[inline]
    /// Flatten a `Protected` of `Protected` into a single `Protected`.
    /// Similar to `Option::flatten`.
    ///
    /// ```
    /// use vitaminc_protected::{Protect, Protected, ProtectNew};
    /// let x = Protected::new(Protected::new([0u8; 32]));
    /// let y = x.flatten();
    /// assert_eq!(y.risky_unwrap(), [0u8; 32]);
    /// ```
    ///
    /// Like [Option], flattening only removes one level of nesting at a time.
    ///
    pub fn flatten(self) -> Protected<T> {
        self.0
    }
}

impl<T> Protected<Option<T>> {
    #[inline]
    /// Transpose a `Protected` of `Option` into an `Option` of `Protected`.
    /// Similar to `Option::transpose`.
    ///
    /// ```
    /// use vitaminc_protected::{Protected, ProtectNew};
    /// let x = Protected::new(Some([0u8; 32]));
    /// let y = x.transpose();
    /// assert!(y.is_some())
    /// ```
    pub fn transpose(self) -> Option<Protected<T>> {
        self.0.map(Protected)
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Protected<T> {}

/// Implement `ProtectMethods` for `Protected`.
/// Note that not all `Protected<T>` are `Protect` because the inner type may not be `Zeroize`.
impl<T> ProtectMethods for Protected<T> where Protected<T>: Protect<RawType = T> {
    // TODO: Consider removing this or making it a separate trait usable only within the crate
    fn inner(&self) -> &T {
        &self.0
    }

    fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Copy for Protected<T> where T: Copy {}

impl<T> Clone for Protected<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Convenience function to flatten an array of `Protected` into a `Protected` array.
///
/// # Example
///
/// ```
/// use vitaminc_protected::{flatten_array, Protect, Protected, ProtectNew};
/// let x = Protected::new(1);
/// let y = Protected::new(2);
/// let z = Protected::new(3);
/// let array: [Protected<u8>; 3] = [x, y, z];
/// let flattened = flatten_array(array);
/// assert!(matches!(flattened, Protected));
/// assert_eq!(flattened.risky_unwrap(), [1, 2, 3]);
/// ```
pub fn flatten_array<const N: usize, T>(array: [Protected<T>; N]) -> Protected<[T; N]>
where
    T: Zeroize + Default + Copy, // TODO: Default won't be needed if we use MaybeUninit
{
    let mut out: [T; N] = [Default::default(); N];
    array.iter().enumerate().for_each(|(i, x)| {
        out[i] = x.risky_unwrap();
    });
    Protected::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_array() {
        let x = Protected::new([0u8; 32]);
        assert_eq!(x.0, [0u8; 32]);
    }

    #[test]
    fn test_opaque_debug() {
        let x = Protected::new([0u8; 32]);
        assert_eq!(format!("{:?}", x), "Protected<[u8; 32]> { ... }");
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

    #[test]
    fn test_zip() {
        let x = Protected::new(1);
        let y = Protected::new(2);
        let z: Protected<u32> = x.zip(y, |a, b| {
            a + b
        });
        assert_eq!(z.risky_unwrap(), 3);
    }
}
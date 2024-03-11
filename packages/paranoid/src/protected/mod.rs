use crate::Paranoid;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod conversions;

/// Basic building block for Paranoid.
/// Conceptually similar to `std::slide::Iter`.
/// `Protected` adds Zeroize and OpaqueDebug.
#[derive(Zeroize)]
pub struct Protected<T>(T);

impl<T: Zeroize> ZeroizeOnDrop for Protected<T> {}

impl<T> Paranoid for Protected<T>
where
    T: Zeroize,
{
    type Inner = T;

    fn new(x: Self::Inner) -> Self {
        Self(x)
    }

    fn inner(&self) -> &T {
        &self.0
    }
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
}

use crate::{private::ParanoidPrivate, Equatable, Exportable, Paranoid};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod conversions;

/// Basic building block for Paranoid.
/// It uses a similar design "adapter" pattern to `std::slide::Iter`.
/// `Protected` adds Zeroize and OpaqueDebug.
#[derive(Zeroize)]
pub struct Protected<T>(T);

impl<T> Protected<T> {
    /// Create a new `Protected` from an inner value.
    pub fn new(x: T) -> Self where T: Zeroize {
        Self(x)
    }

    pub fn equatable(self) -> Equatable<Self> {
        Equatable(self)
    }

    pub fn exportable(self) -> Exportable<Self> {
        Exportable(self)
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Protected<T> {}

impl<T> ParanoidPrivate for Protected<T>
where
    T: Zeroize,
{
    type Inner = T;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(x)
    }

    fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> Paranoid for Protected<T> where T: Zeroize {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_array() {
        let x = Protected::init_from_inner([0u8; 32]);
        assert_eq!(x.0, [0u8; 32]);
    }

    #[test]
    fn test_opaque_debug() {
        let x = Protected::init_from_inner([0u8; 32]);
        assert_eq!(format!("{:?}", x), "Protected<[u8; 32]> { ... }");
    }
}

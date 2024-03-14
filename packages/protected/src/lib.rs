mod conversions;
mod equatable;
mod exportable;
use private::ParanoidPrivate;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod private;
pub trait Paranoid: private::ParanoidPrivate {}

pub use equatable::Equatable;
pub use exportable::Exportable;

// TODO: Add compile tests


/// Basic building block for Paranoid.
/// It uses a similar design "adapter" pattern to `std::slide::Iter`.
/// `Protected` adds Zeroize and OpaqueDebug.
#[derive(Zeroize)]
pub struct Protected<T>(T);

opaque_debug::implement!(Protected<T>);

// TODO: Docs
impl<T> Protected<T> {
    /// Create a new `Protected` from an inner value.
    pub fn new(x: T) -> Self
    where
        T: Zeroize,
    {
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
        let x = Protected::new([0u8; 32]);
        assert_eq!(x.0, [0u8; 32]);
    }

    #[test]
    fn test_opaque_debug() {
        let x = Protected::new([0u8; 32]);
        assert_eq!(format!("{:?}", x), "Protected<[u8; 32]> { ... }");
    }
}


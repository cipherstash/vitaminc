mod conversions;
mod digest;
mod equatable;
mod exportable;
mod indexable;
mod usage;

use std::marker::PhantomData;
use equatable::ConstantTimeEq;
use private::ParanoidPrivate;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod private;

// Exports
pub use digest::ProtectedDigest;
pub use equatable::Equatable;
pub use exportable::Exportable;
pub use indexable::Indexable;
pub use usage::{Acceptable, DefaultScope, Scope, Usage};

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

    /// Create a `Protected` from an inner value which may also be adapted.
    /// Return values must be given a type hint which means this is mostly useful to handle creation
    /// of adapted types. If you want to create a non-adapted `Protected` from an inner value, use `new`.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use protected::{Protected, Equatable, Usage};
    /// let x: Protected<[u8; 32]> = Protected::from_inner([0u8; 32]);
    /// let y: Equatable<Protected<String>> = Protected::from_inner(String::from("hello"));
    /// let z: Usage<Equatable<Protected<u32>>> = Protected::from_inner(500);
    /// ```
    pub fn from_inner<O>(x: T) -> O
    where
        O: ParanoidPrivate<Inner = T>,
    {
        O::init_from_inner(x)
    }

    /// Convert this `Protected` into one that is equatable in constant time.
    /// Returns a new `Equatable` adapter.
    ///
    /// # Example
    ///
    /// ```
    /// use protected::{Equatable, Protected};
    ///
    /// let x = Protected::new([0u8; 32]);
    /// let y: Equatable<Protected<[u8; 32]>> = x.equatable();
    /// ```
    pub fn equatable(self) -> Equatable<Self> {
        Equatable(self)
    }

    /// Convert this `Protected` into one that is exportable in constant time using Serde.
    /// Returns a new `Exportable` adapter.
    ///
    /// # Example
    ///
    /// ```
    /// use protected::{Exportable, Protected};
    ///
    /// let x = Protected::new([0u8; 32]);
    /// let y: Exportable<Protected<[u8; 32]>> = x.exportable();
    /// ```
    pub fn exportable(self) -> Exportable<Self> {
        Exportable(self)
    }

    // TODO: This needs to be implemented for all types (put on the Paranoid trait)
    pub fn for_scope<S: Scope>(self) -> Usage<Self, S> {
        Usage(self, PhantomData)
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

    fn inner_mut(&mut self) -> &mut Self::Inner {
        &mut self.0
    }
}

pub trait Paranoid: private::ParanoidPrivate {
    fn equatable(self) -> Equatable<Self>
    where
        Self: Sized,
        Self::Inner: ConstantTimeEq {
            Equatable(self)
        }

    fn exportable(self) -> Exportable<Self>
    where
        Self: Sized,
        Self::Inner: Serialize {
            Exportable(self)
        }

    fn for_scope<S: Scope>(self) -> Usage<Self, S>
    {
        Usage(self, PhantomData)
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

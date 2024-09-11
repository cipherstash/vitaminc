use crate::{equatable::ConstantTimeEq, private::ControlledPrivate, Controlled, Equatable};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use zeroize::Zeroize;

// TODO: Docs
#[derive(Debug, Zeroize)]
pub struct Exportable<T>(pub(crate) T);

// TODO: Can we implement Hex and Base64 for inner types that implement them?
impl<T> Exportable<T> {
    /// Create a new `Exportable` from an inner value.
    pub fn new(x: <Exportable<T> as ControlledPrivate>::Inner) -> Self
    where
        Self: Controlled,
    {
        Self::init_from_inner(x)
    }

    pub fn equatable(self) -> Equatable<Self> {
        Equatable(self)
    }
}

impl<T> Copy for Exportable<T> where T: Copy {}

impl<T> Clone for Exportable<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// PartialEq is implemented in constant time for any `Equatable` to any (nested) `Equatable`.
impl<T, O> PartialEq<O> for Exportable<T>
where
    T: ControlledPrivate,
    O: ControlledPrivate,
    <T as ControlledPrivate>::Inner: ConstantTimeEq<O::Inner>,
{
    fn eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

impl<T: ControlledPrivate> ControlledPrivate for Exportable<T> {
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

impl<T> Controlled for Exportable<T>
where
    T: Controlled,
{
    fn risky_unwrap(self) -> Self::Inner {
        self.0.risky_unwrap()
    }
}

impl<T> Serialize for Exportable<T>
where
    T: ControlledPrivate,
    T::Inner: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner().serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Exportable<T>
where
    T: ControlledPrivate,
    T::Inner: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::Inner::deserialize(deserializer).map(Exportable::init_from_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Equatable, Protected};

    #[test]
    fn test_opaque_debug() {
        let x: Exportable<Protected<[u8; 32]>> = Exportable::new([0u8; 32]);
        assert_eq!(
            format!("{:?}", x),
            "Exportable(Protected<[u8; 32]> { ... })"
        );
    }

    #[test]
    fn test_serialize_deserialize() {
        let x: Exportable<Protected<u8>> = Exportable::init_from_inner(42);
        let y = bincode::serialize(&x).unwrap();

        let z: Exportable<Protected<u8>> = bincode::deserialize(&y).unwrap();
        assert_eq!(z.inner(), &42);
    }

    #[test]
    fn test_serialize_deserialize_nested() {
        let x: Exportable<Equatable<Protected<u8>>> = Exportable::init_from_inner(42);
        let y = bincode::serialize(&x).unwrap();

        let z: Exportable<Equatable<Protected<u8>>> = bincode::deserialize(&y).unwrap();
        assert_eq!(z, x);
    }

    #[test]
    fn test_equatable_inner() {
        let x: Exportable<Protected<u8>> = Exportable::init_from_inner(42);
        let y: Exportable<Equatable<Protected<u8>>> = Exportable::init_from_inner(42);

        assert_eq!(x.equatable(), y);
    }
}

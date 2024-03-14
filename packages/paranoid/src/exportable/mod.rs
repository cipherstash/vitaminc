use crate::{equatable::ConstantTimeEq, private::ParanoidPrivate, Equatable, Paranoid};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

// TODO: Docs
#[derive(Debug)]
pub struct Exportable<T>(pub(crate) T);

impl<T> Exportable<T> {
    /// Create a new `Exportable` from an inner value.
    pub fn new(x: <Exportable<T> as ParanoidPrivate>::Inner) -> Self
    where
        Self: Paranoid,
    {
        Self::init_from_inner(x)
    }

    pub fn equatable(self) -> Equatable<Self> {
        Equatable(self)
    }
}

/// PartialEq is implemented in constant time for any `Equatable` to any (nested) `Equatable`.
impl<T, O> PartialEq<O> for Exportable<T>
where
    T: ParanoidPrivate,
    O: ParanoidPrivate,
    <T as ParanoidPrivate>::Inner: ConstantTimeEq<O::Inner>,
{
    fn eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}

impl<T: ParanoidPrivate> ParanoidPrivate for Exportable<T> {
    type Inner = T::Inner;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(T::init_from_inner(x))
    }

    fn inner(&self) -> &Self::Inner {
        self.0.inner()
    }
}

impl<T> Paranoid for Exportable<T> where T: ParanoidPrivate {}

impl<T> Serialize for Exportable<T>
where
    T: ParanoidPrivate,
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
    T: ParanoidPrivate,
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

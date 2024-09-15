mod safe_deserialize;
mod safe_serialize;
use crate::{equatable::ConstantTimeEq, private::ControlledPrivate, Controlled};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use zeroize::Zeroize;

pub use safe_deserialize::SafeDeserialize;
pub use safe_serialize::SafeSerialize;

// TODO: Docs
#[derive(Debug, Zeroize)]
pub struct Exportable<T>(pub(crate) T);

// TODO: Can we implement Hex and Base64 for inner types that implement them?
// But using safe versions
impl<T> Exportable<T> {
    /// Create a new `Exportable` from an inner value.
    pub fn new(x: <Exportable<T> as ControlledPrivate>::Inner) -> Self
    where
        Self: Controlled,
    {
        Self::init_from_inner(x)
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
    T::Inner: SafeSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner().safe_serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Exportable<T>
where
    T: ControlledPrivate,
    T::Inner: SafeDeserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::safe_deserialize(deserializer)
    }
}

/// Blanket implementation for all controlled types who's inner type implements `SafeSerialize`.
impl<T> SafeSerialize for T
where
    T::Inner: SafeSerialize,
    T: ControlledPrivate,
{
    fn safe_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner().safe_serialize(serializer)
    }
}

/// Blanket implementation for all controlled types who's inner type implements `SafeSerialize`.
impl<'de, T> SafeDeserialize<'de> for T
where
    T::Inner: SafeDeserialize<'de>,
    T: ControlledPrivate,
{
    fn safe_deserialize<S>(deserializer: S) -> Result<Self, S::Error>
    where
        S: Deserializer<'de>,
    {
        T::Inner::safe_deserialize(deserializer).map(T::init_from_inner)
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
    fn test_serialize_bytes() {
        // TODO: Test for other types
        let x: Exportable<Protected<[u8; 64]>> = Exportable::new([0; 64]);
        let y = serde_json::to_string(&x).unwrap();
        dbg!(&y);
    }

    // TODO: Controlled types should only implement Serialize/Deserialize
    // if their inner types implement `SafeSerialize`/`SafeDeserialize`.
    #[test]
    fn test_serialize_deserialize_inner() {
        let x: Equatable<Exportable<Protected<u8>>> = Equatable::new(42);
        let y = bincode::serialize(&x).unwrap();

        let z: Exportable<Equatable<Protected<u8>>> = bincode::deserialize(&y).unwrap();
        assert_eq!(z, x);
    }

    #[test]
    fn test_equatable_inner() {
        let x: Equatable<Protected<u8>> = Equatable::new(42);
        let y: Exportable<Equatable<Protected<u8>>> = Exportable::new(42);

        assert_eq!(x, y);
    }
}

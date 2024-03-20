mod safe_serialize;

use self::safe_serialize::SafeType;
pub use self::safe_serialize::{SafeDeserialize, SafeSerialize};
use crate::{
    equatable::ConstantTimeEq,
    private::{self, ParanoidPrivate},
    Equatable, IsEquatable, Paranoid,
};
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

/// Equatable types implement equatable directly.
impl<T> private::Equatable for Exportable<T> where T: Paranoid + private::Equatable {}
impl<T> IsEquatable for Exportable<T> where T: Paranoid + IsEquatable {}

/// PartialEq is implemented in constant time for any `Equatable` to any (nested) `Equatable`.
impl<T, O> PartialEq<O> for Exportable<T>
where
    T: ParanoidPrivate + IsEquatable,
    O: ParanoidPrivate + IsEquatable,
    //<T as ParanoidPrivate>::Inner: ConstantTimeEq<O::Inner>,
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

    fn inner_mut(&mut self) -> &mut Self::Inner {
        self.0.inner_mut()
    }
}

impl<T> Serialize for Exportable<T>
where
    T: ParanoidPrivate,
    T::Inner: SafeSerialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner()
            .safe_serialize(serializer)
            .map(|x| x.into_inner())
    }
}

impl<'de, T> Deserialize<'de> for Exportable<T>
where
    T: ParanoidPrivate,
    T::Inner: SafeDeserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let i: T::Inner = T::Inner::safe_deserialize(deserializer).map(|x| x.into_inner())?;
        Ok(Exportable::init_from_inner(i))
    }
}

impl<T> SafeSerialize for Exportable<T>
where
    T: ParanoidPrivate,
    T::Inner: SafeSerialize,
{
    fn safe_serialize<S: Serializer>(&self, serializer: S) -> Result<SafeType<S::Ok>, S::Error> {
        self.inner().safe_serialize(serializer)
    }
}

impl<T> Paranoid for Exportable<T> where T: Paranoid {}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use zeroize::Zeroize;

    use super::*;
    use crate::{Equatable, Protected};

    #[derive(Serialize, Deserialize, Zeroize)]
    struct Foo {
        key: Exportable<Protected<[u8; 32]>>,
        version: u8,
    }

    #[derive(Serialize, Deserialize, Zeroize, Debug)]
    struct ProtectedFoo {
        key: Exportable<Equatable<Protected<[u8; 32]>>>,
        version: u8,
    }
    impl SafeSerialize for ProtectedFoo {}
    impl<'de> SafeDeserialize<'de> for ProtectedFoo {}
    impl ConstantTimeEq for ProtectedFoo {
        fn constant_time_eq(&self, other: &Self) -> bool {
            self.key == other.key && self.version == other.version
        }
    }

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

    #[test]
    fn test_serialize_struct() {
        let x = Foo {
            key: Exportable::new([0u8; 32]),
            version: 1,
        };
        let y = bincode::serialize(&x).unwrap();

        let z: Foo = bincode::deserialize(&y).unwrap();
        assert_eq!(z.key.inner(), &[0u8; 32]);
        assert_eq!(z.version, 1);
    }

    #[test]
    fn test_serialize_exportable_protected_struct() {
        let x: Exportable<Protected<ProtectedFoo>> = Protected::new(ProtectedFoo {
            key: Exportable::new([0u8; 32]),
            version: 1,
        })
        .exportable();
        let y = bincode::serialize(&x).unwrap();

        let z: Foo = bincode::deserialize(&y).unwrap();
        assert_eq!(z.key.inner(), &[0u8; 32]);
        assert_eq!(z.version, 1);
    }

    #[test]
    fn test_roundtrip_exportable_protected_struct() {
        let x: Exportable<Protected<ProtectedFoo>> = Protected::new(ProtectedFoo {
            key: Exportable::new([0u8; 32]),
            version: 1,
        })
        .exportable();
        let y = bincode::serialize(&x).unwrap();

        let z: Exportable<Protected<ProtectedFoo>> = bincode::deserialize(&y).unwrap();
        // TODO: would be nice to do assert_eq!(z.equatable(), x.equatable()); but we need a derive macro for ConstantTimeEq
        assert_eq!(z.equatable(), x.equatable());
    }
}

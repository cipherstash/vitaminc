use crate::{equatable::ConstantTimeEq, Protect, ProtectMethods, ProtectNew};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

// TODO: Docs
#[derive(Debug)]
pub struct Exportable<T>(pub(crate) T);

impl<T> Exportable<T> where T: Protect {
    pub fn init(x: T) -> Self {
        Self(x)
    }
}

/// PartialEq is implemented in constant time for any `Equatable` to any (nested) `Equatable`.
impl<T, O> PartialEq<O> for Exportable<T> where Self: ProtectMethods, <Exportable<T> as Protect>::RawType: ConstantTimeEq<<O as Protect>::RawType>, O: ProtectMethods {
    fn eq(&self, other: &O) -> bool {
        self.inner().constant_time_eq(other.inner())
    }
}


impl<T> Protect for Exportable<T> where T: Protect {
    type RawType = T::RawType;

    fn risky_unwrap(self) -> T::RawType {
        self.0.risky_unwrap()
    }
}

impl<T, I> ProtectNew<I> for Exportable<T> where T: ProtectNew<I>, Self: Protect<RawType = I> {
    fn new(raw: Self::RawType) -> Self {
        Self(T::new(raw))
    }
}

// FIXME: This is super clunky
// We should have a separate trait for getting the inner value of a `Protected`
impl<T> ProtectMethods for Exportable<T> where T: Protect + ProtectMethods {
    // TODO: Consider removing this or making it a separate trait usable only within the crate
    // Or could it return a ProtectedRef?
    fn inner(&self) -> &Self::RawType {
        self.0.inner()
    }

    fn inner_mut(&mut self) -> &mut Self::RawType {
        self.0.inner_mut()
    }
}

impl<T> Serialize for Exportable<T>
where
    Self: ProtectMethods,
    <Exportable<T> as Protect>::RawType: Serialize,
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
    Self: ProtectMethods + ProtectNew<<Exportable<T> as Protect>::RawType>,
    <Exportable<T> as Protect>::RawType: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        <Exportable<T> as Protect>::RawType::deserialize(deserializer).map(Self::new)
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
        let x: Exportable<Protected<u8>> = Exportable::new(42);
        let y = bincode::serialize(&x).unwrap();

        let z: Exportable<Protected<u8>> = bincode::deserialize(&y).unwrap();
        assert_eq!(z.inner(), &42);
    }

    #[test]
    fn test_serialize_deserialize_nested() {
        let x: Exportable<Equatable<Protected<u8>>> = Exportable::new(42);
        let y = bincode::serialize(&x).unwrap();

        let z: Exportable<Equatable<Protected<u8>>> = bincode::deserialize(&y).unwrap();
        assert_eq!(z, x);
    }

    #[test]
    fn test_equatable_inner() {
        let x: Equatable<Exportable<Protected<u8>>> = Equatable::new(42);
        let y: Exportable<Equatable<Protected<u8>>> = Exportable::new(42);

        assert_eq!(x, y);
    }
}

use crate::{Equatable, Paranoid};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

// TODO: Docs
pub struct Exportable<T>(T);

impl<T> PartialEq for Exportable<Equatable<T>>
where
    T: Paranoid,
    <T as Paranoid>::Inner: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner() == other.inner()
    }
}

impl<T: Paranoid> Paranoid for Exportable<T> {
    type Inner = T::Inner;

    fn new(x: Self::Inner) -> Self {
        Self(T::new(x))
    }

    fn inner(&self) -> &Self::Inner {
        self.0.inner()
    }
}

impl<T> Serialize for Exportable<T>
where
    T: Paranoid,
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
    T: Paranoid,
    T::Inner: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::Inner::deserialize(deserializer).map(Exportable::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Equatable, Protected};

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
}

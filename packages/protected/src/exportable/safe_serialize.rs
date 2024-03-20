use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub struct SafeType<T>(T);
impl<T> SafeType<T> {
    pub(super) fn into_inner(self) -> T {
        self.0
    }
}

pub trait SafeSerialize: Serialize {
    fn safe_serialize<S: Serializer>(&self, serializer: S) -> Result<SafeType<S::Ok>, S::Error> {
        // TODO: Here is why we probably *do* want to implement Serialize for SafeSerializer
        self.serialize(serializer).map(SafeType)
    }
}

pub trait SafeDeserialize<'de>: Deserialize<'de> {
    fn safe_deserialize<D>(deserializer: D) -> Result<SafeType<Self>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize(deserializer).map(SafeType)
    }
}

impl<const N: usize> SafeSerialize for [u8; N]
where
    [u8; N]: Serialize,
{
    fn safe_serialize<S: Serializer>(&self, serializer: S) -> Result<SafeType<S::Ok>, S::Error> {
        // TODO: Make this a method on SafeType (but call it SafeSerializer or something)
        serdect::array::serialize_hex_lower_or_bin(&self, serializer).map(SafeType)
    }
}

impl<'de, const N: usize> SafeDeserialize<'de> for [u8; N]
where
    [u8; N]: Deserialize<'de> + Default,
{
    fn safe_deserialize<D>(deserializer: D) -> Result<SafeType<Self>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut buf: Self = Default::default();
        serdect::array::deserialize_hex_or_bin(&mut buf, deserializer)?;
        Ok(SafeType(buf))
    }
}

impl SafeSerialize for u8 {}
impl<'de> SafeDeserialize<'de> for u8 {}

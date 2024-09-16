use serde::{Deserialize, Deserializer};

use crate::private::ControlledPrivate;

pub trait SafeDeserialize<'de>: Sized {
    fn safe_deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
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

impl<'de, const N: usize> SafeDeserialize<'de> for [u8; N] {
    fn safe_deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_bytes::ByteArray::deserialize(deserializer).map(|bytes| bytes.into_array())
    }
}

macro_rules! impl_safe_deserialize {
    ($($type:ty),+) => {
        $(
            impl<'de> SafeDeserialize<'de> for $type {
                #[inline]
                fn safe_deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    serde::Deserialize::deserialize(deserializer)
                }
            }
        )+
    };
}

impl_safe_deserialize!(
    i8, i16, i32, i64, i128, u8, u16, u32, u64, u128, f32, f64, bool, char, String
);

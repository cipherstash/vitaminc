use std::num::{
    NonZeroI128, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI8, NonZeroIsize, NonZeroU128,
    NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8, NonZeroUsize,
};

use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};

use crate::private::ControlledPrivate;

// TODO: Create a serialize method on exportable which maps into the serialized form
// Exportable should also implement a "safe" version of Hex (serdect)
// And a reader?

pub trait SafeSerialize {
    fn safe_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
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

// This code is adapted from the serde source code
macro_rules! impl_safe_serialize {
    ($type:ty, $serialize_fn:ident $($cast:tt)*) => {
        impl SafeSerialize for $type {
            #[inline]
            fn safe_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.$serialize_fn(*self $($cast)*)
            }
        }
    };
}

impl_safe_serialize!(u8, serialize_u8);
impl_safe_serialize!(u16, serialize_u16);
impl_safe_serialize!(u32, serialize_u32);
impl_safe_serialize!(u64, serialize_u64);
impl_safe_serialize!(u128, serialize_u128);
impl_safe_serialize!(usize, serialize_u64 as u64);
impl_safe_serialize!(i8, serialize_i8);
impl_safe_serialize!(i16, serialize_i16);
impl_safe_serialize!(i32, serialize_i32);
impl_safe_serialize!(i64, serialize_i64);
impl_safe_serialize!(i128, serialize_i128);
impl_safe_serialize!(isize, serialize_i64 as i64);
impl_safe_serialize!(f32, serialize_f32);
impl_safe_serialize!(f64, serialize_f64);
impl_safe_serialize!(char, serialize_char);
impl_safe_serialize!(bool, serialize_bool);

impl SafeSerialize for String {
    #[inline]
    fn safe_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self)
    }
}

impl<const N: usize> SafeSerialize for [u8; N] {
    fn safe_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self)
    }
}

macro_rules! impl_safe_serialize_nonzero {
    ($type:ty, $serialize_fn:ident $($cast:tt)*) => {
        impl SafeSerialize for $type {
            #[inline]
            fn safe_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.$serialize_fn(self.get() $($cast)*)
            }
        }
    };
}

impl_safe_serialize_nonzero!(NonZeroU8, serialize_u8);
impl_safe_serialize_nonzero!(NonZeroU16, serialize_u16);
impl_safe_serialize_nonzero!(NonZeroU32, serialize_u32);
impl_safe_serialize_nonzero!(NonZeroU64, serialize_u64);
impl_safe_serialize_nonzero!(NonZeroU128, serialize_u128);
impl_safe_serialize_nonzero!(NonZeroUsize, serialize_u64 as u64);
impl_safe_serialize_nonzero!(NonZeroI8, serialize_i8);
impl_safe_serialize_nonzero!(NonZeroI16, serialize_i16);
impl_safe_serialize_nonzero!(NonZeroI32, serialize_i32);
impl_safe_serialize_nonzero!(NonZeroI64, serialize_i64);
impl_safe_serialize_nonzero!(NonZeroI128, serialize_i128);
impl_safe_serialize_nonzero!(NonZeroIsize, serialize_i64 as i64);

macro_rules! tuple_impls {
    ($($len:expr => ($($n:tt $name:ident)+))+) => {
        $(
            #[cfg_attr(docsrs, doc(hidden))]
            impl<$($name),+> SafeSerialize for ($($name,)+)
            where
                $($name: SafeSerialize + Serialize,)+
            {
                tuple_impl_body!($len => ($($n)+));
            }
        )+
    };
}

macro_rules! tuple_impl_body {
    ($len:expr => ($($n:tt)+)) => {
        #[inline]
        fn safe_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut tuple = serializer.serialize_tuple($len)?;
            $(
                tuple.serialize_element(&self.$n)?;
            )+
            tuple.end()
        }
    };
}
/// This trait is implemented for tuples up to 10 items long (the same as Zeroize).
impl<T> SafeSerialize for (T,)
where
    T: Serialize + SafeSerialize,
{
    tuple_impl_body!(1 => (0));
}

tuple_impls! {
    2 => (0 T0 1 T1)
    3 => (0 T0 1 T1 2 T2)
    4 => (0 T0 1 T1 2 T2 3 T3)
    5 => (0 T0 1 T1 2 T2 3 T3 4 T4)
    6 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5)
    7 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6)
    8 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7)
    9 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8)
    10 => (0 T0 1 T1 2 T2 3 T3 4 T4 5 T5 6 T6 7 T7 8 T8 9 T9)
}

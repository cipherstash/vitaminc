use bitvec::{array::BitArray, order::Msb0};
use protected::{Paranoid, Protected};
use std::num::{NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8};

use crate::PermutationKey;

pub struct BitwisePermutation<'k, K>(&'k K);

impl<'k, K> BitwisePermutation<'k, K> {
    pub fn new(k: &'k K) -> Self {
        Self(k)
    }

    pub fn permute<T>(&self, input: T) -> T
    where
        T: BitwisePermutableBy<K>,
    {
        input.permute(self.0)
    }
}

// TODO: Convert this to BitwisePermute (like Permute)
// TODO: Make this a private trait
pub trait BitwisePermutableBy<K> {
    fn permute(self, key: &K) -> Self;
}

macro_rules! impl_bitwise_permutable {
    ($N:literal, $int_type:ty, $nonzero_type:ty, $array_size:expr) => {
        impl BitwisePermutableBy<PermutationKey<$N>> for Protected<$nonzero_type> {
            fn permute(self, key: &PermutationKey<$N>) -> Self {
                self.map(|x| {
                    let bytes = x.get().to_be_bytes();
                    let arr: BitArray<[u8; $array_size], Msb0> = BitArray::new(bytes);
                    let out: BitArray<[u8; $array_size], Msb0> = key.iter().enumerate().fold(
                        BitArray::new([0; $array_size]),
                        |mut out, (i, k)| {
                            out.set(i, *unsafe { arr.get_unchecked(k) });
                            out
                        },
                    );

                    let mapped = <$int_type>::from_be_bytes(out.into_inner());
                    Protected::new(unsafe { <$nonzero_type>::new_unchecked(mapped) })
                })
            }
        }
    };
}

impl_bitwise_permutable!(8, u8, NonZeroU8, 1);
impl_bitwise_permutable!(16, u16, NonZeroU16, 2);
impl_bitwise_permutable!(32, u32, NonZeroU32, 4);
impl_bitwise_permutable!(64, u64, NonZeroU64, 8);
impl_bitwise_permutable!(128, u128, NonZeroU128, 16);

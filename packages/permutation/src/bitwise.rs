use bitvec::{array::BitArray, order::Msb0};
use std::num::{NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8};
use vitaminc_protected::{Paranoid, Protected};

use crate::{IsPermutable, PermutationKey};

// TODO: Make this a private trait
pub trait BitwisePermute<T>
where
    T: IsPermutable,
{
    fn bitwise_permute(&self, input: Protected<T>) -> Protected<T>;
}

/*macro_rules! impl_bitwise_permutable {
    ($N:literal, $int_type:ty, $nonzero_type:ty, $array_size:expr) => {
        impl BitwisePermutableBy<PermutationKey<$N>> for Protected<$nonzero_type>
        where
            $nonzero_type: ValidPermutationSize,
        {
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
*/

// TODO: Use a macro for these
impl BitwisePermute<u8> for PermutationKey<8>
where
    u8: IsPermutable,
{
    fn bitwise_permute(&self, input: Protected<u8>) -> Protected<u8> {
        input.map(|x| {
            let bytes = x.to_be_bytes();
            let arr: BitArray<[u8; 1], Msb0> = BitArray::new(bytes);
            let out: BitArray<[u8; 1], Msb0> =
                self.iter()
                    .enumerate()
                    .fold(BitArray::new([0; 1]), |mut out, (i, k)| {
                        out.set(i, *unsafe { arr.get_unchecked(k) });
                        out
                    });

            let mapped = u8::from_be_bytes(out.into_inner());
            Protected::new(mapped)
        })
    }
}

impl BitwisePermute<u16> for PermutationKey<16> {
    fn bitwise_permute(&self, input: Protected<u16>) -> Protected<u16> {
        input.map(|x| {
            let bytes = x.to_be_bytes();
            let arr: BitArray<[u8; 2], Msb0> = BitArray::new(bytes);
            let out: BitArray<[u8; 2], Msb0> =
                self.iter()
                    .enumerate()
                    .fold(BitArray::new([0; 2]), |mut out, (i, k)| {
                        out.set(i, *unsafe { arr.get_unchecked(k) });
                        out
                    });

            let mapped = u16::from_be_bytes(out.into_inner());
            Protected::new(mapped)
        })
    }
}

impl BitwisePermute<u32> for PermutationKey<32> {
    fn bitwise_permute(&self, input: Protected<u32>) -> Protected<u32> {
        input.map(|x| {
            let bytes = x.to_be_bytes();
            let arr: BitArray<[u8; 4], Msb0> = BitArray::new(bytes);
            let out: BitArray<[u8; 4], Msb0> =
                self.iter()
                    .enumerate()
                    .fold(BitArray::new([0; 4]), |mut out, (i, k)| {
                        out.set(i, *unsafe { arr.get_unchecked(k) });
                        out
                    });

            let mapped = u32::from_be_bytes(out.into_inner());
            Protected::new(mapped)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use crate::tests;
    use crate::{BitwisePermute, PermutationKey};
    use vitaminc_protected::{Paranoid, Protected};
    use zeroize::Zeroize;

    use super::IsPermutable;

    fn test_permute<const N: usize, T>(input: Protected<T>)
    where
        // FIXME: These trait bounds are pretty clunky
        T: IsPermutable + Zeroize + Debug + PartialEq + Copy,
        [u8; N]: IsPermutable,
        PermutationKey<N>: BitwisePermute<T>,
    {
        let key = tests::gen_key([0; 32]);
        let output = key.bitwise_permute(input);
        assert_ne!(output.unwrap(), input.unwrap());
    }

    #[test]
    fn bitwise_permute_case() {
        test_permute::<8, u8>(Protected::new(117));
        test_permute::<16, u16>(Protected::new(46321));
    }
}

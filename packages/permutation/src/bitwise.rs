use crate::{private::IsPermutable, PermutationKey};
use bitvec::{array::BitArray, order::Msb0};
use std::num::{NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8};
use vitaminc_protected::{Controlled, Protected};

// TODO: Make this a private trait
pub trait BitwisePermute<T>
where
    T: IsPermutable,
{
    fn bitwise_permute(&self, input: Protected<T>) -> Protected<T>;
}

macro_rules! impl_bitwise_permutable {
    ($N:literal, $int_type:ty, $array_size:expr) => {
        impl BitwisePermute<$int_type> for PermutationKey<$N>
        where
            $int_type: IsPermutable,
        {
            fn bitwise_permute(&self, input: Protected<$int_type>) -> Protected<$int_type> {
                input.map(|x| {
                    let bytes = x.to_be_bytes();
                    let arr: BitArray<[u8; $array_size], Msb0> = BitArray::new(bytes);
                    let out: BitArray<[u8; $array_size], Msb0> = self.iter().enumerate().fold(
                        BitArray::new([0; $array_size]),
                        |mut out, (i, k)| {
                            out.set(i, *unsafe { arr.get_unchecked(k) });
                            out
                        },
                    );

                    <$int_type>::from_be_bytes(out.into_inner())
                })
            }
        }
    };
}

impl_bitwise_permutable!(8, u8, 1);
impl_bitwise_permutable!(16, u16, 2);
impl_bitwise_permutable!(32, u32, 4);
impl_bitwise_permutable!(64, u64, 8);
impl_bitwise_permutable!(128, u128, 16);

macro_rules! impl_nonzeroint_bitwise_permutable {
    ($N:literal, $nonzero_type:ty) => {
        impl BitwisePermute<$nonzero_type> for PermutationKey<$N> {
            fn bitwise_permute(&self, input: Protected<$nonzero_type>) -> Protected<$nonzero_type> {
                // If the input is NonZero, the output will be NonZero
                self.bitwise_permute(input.map(|x| x.get()))
                    .map(|x| unsafe { <$nonzero_type>::new_unchecked(x) })
            }
        }
    };
}

impl_nonzeroint_bitwise_permutable!(8, NonZeroU8);
impl_nonzeroint_bitwise_permutable!(16, NonZeroU16);
impl_nonzeroint_bitwise_permutable!(32, NonZeroU32);
impl_nonzeroint_bitwise_permutable!(64, NonZeroU64);
impl_nonzeroint_bitwise_permutable!(128, NonZeroU128);

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::num::{NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8};

    use crate::tests;
    use crate::{BitwisePermute, PermutationKey};
    use vitaminc_protected::{Controlled, Protected};
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
        assert_ne!(output.risky_unwrap(), input.risky_unwrap());
    }

    #[test]
    fn bitwise_permute_case() {
        test_permute::<8, u8>(Protected::new(117));
        test_permute::<16, u16>(Protected::new(46321));
        test_permute::<32, u32>(Protected::new(87483343));
        test_permute::<64, u64>(Protected::new(2813387843809117391));
        test_permute::<128, u128>(Protected::new(28133878438091173912256));

        test_permute::<8, _>(Protected::new(NonZeroU8::new(77).unwrap()));
        test_permute::<16, _>(Protected::new(NonZeroU16::new(13267).unwrap()));
        test_permute::<32, _>(Protected::new(NonZeroU32::new(12345678).unwrap()));
        test_permute::<64, _>(Protected::new(NonZeroU64::new(7178231783183).unwrap()));
        test_permute::<128, _>(Protected::new(NonZeroU128::new(29472929298731313).unwrap()));
    }
}

use crate::{elementwise::permute_array, PermutationKey};
use std::num::{NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8};
use zeroize::{Zeroize, Zeroizing};

// TODO: Make this a private trait
// FIXME: This trait is backwards - self should be T and the argument should be a key
pub trait BitwisePermute<const N: usize, T> {
    fn bitwise_permute(&self, input: T) -> T;
}

macro_rules! impl_bitwise_permutable {
    ($N:literal, $int_type:ty, $array_size:expr) => {
        impl BitwisePermute<$N, $int_type> for PermutationKey<$N> {
            fn bitwise_permute(&self, mut input: $int_type) -> $int_type {
                // Unpack the input into one byte per bit (MSB-first), permute
                // the bit-vector through the constant-time `permute_array`
                // primitive, then re-pack. The previous implementation used
                // `bitvec::get_unchecked(secret_index)` which performs a
                // secret-dependent bit load; even though the bit array fits in
                // a single cache line, this defends against intra-cache-line
                // microarchitectural leaks (port pressure, etc.).
                let bytes = Zeroizing::new(input.to_be_bytes());
                let mut bits: Zeroizing<[u8; $N]> = Zeroizing::new([0u8; $N]);
                for j in 0..$N {
                    bits[j] = (bytes[j / 8] >> (7 - (j % 8))) & 1;
                }
                let permuted = Zeroizing::new(permute_array(self, *bits));
                let mut out = [0u8; $array_size];
                for j in 0..$N {
                    out[j / 8] |= (permuted[j] & 1) << (7 - (j % 8));
                }
                input.zeroize();
                <$int_type>::from_be_bytes(out)
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
        impl BitwisePermute<$N, $nonzero_type> for PermutationKey<$N> {
            fn bitwise_permute(&self, mut input: $nonzero_type) -> $nonzero_type {
                let out = self.bitwise_permute(input.get());
                input.zeroize();
                // If the input is NonZero, the output will be NonZero
                unsafe { <$nonzero_type>::new_unchecked(out) }
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

    use crate::private::IsPermutable;
    use crate::tests;
    use crate::{BitwisePermute, PermutationKey};
    use zeroize::Zeroize;

    fn test_permute<const N: usize, T>(input: T)
    where
        // FIXME: These trait bounds are pretty clunky
        T: Zeroize + Debug + PartialEq + Copy,
        PermutationKey<N>: BitwisePermute<N, T>,
        [u8; N]: IsPermutable,
    {
        let key = tests::gen_key([0; 32]);
        let output = key.bitwise_permute(input);
        assert_ne!(output, input);
    }

    #[test]
    fn bitwise_permute_case() {
        test_permute::<8, u8>(117);
        test_permute::<16, u16>(46321);
        test_permute::<32, u32>(87483343);
        test_permute::<64, u64>(2813387843809117391);
        test_permute::<128, u128>(28133878438091173912256);

        test_permute::<8, _>(NonZeroU8::new(77).unwrap());
        test_permute::<16, _>(NonZeroU16::new(13267).unwrap());
        test_permute::<32, _>(NonZeroU32::new(12345678).unwrap());
        test_permute::<64, _>(NonZeroU64::new(7178231783183).unwrap());
        test_permute::<128, _>(NonZeroU128::new(29472929298731313).unwrap());
    }
}

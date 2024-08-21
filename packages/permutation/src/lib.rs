mod bitwise;
mod elementwise;
mod key;

pub use bitwise::BitwisePermute;
pub use elementwise::{Depermute, Permute};
pub use key::PermutationKey;
use vitaminc_protected::Protected;

const fn identity<const N: usize, T>() -> Protected<[u8; N]>
where
    [T; N]: private::IsPermutable,
{
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = i as u8;
        i += 1;
    }
    Protected::new(out)
}

mod private {
    use std::num::{NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8};
    pub trait IsPermutable {}

    impl IsPermutable for [u8; 8] {}
    impl IsPermutable for [u8; 16] {}
    impl IsPermutable for [u8; 32] {}
    impl IsPermutable for [u8; 64] {}
    impl IsPermutable for [u8; 128] {}
    impl IsPermutable for [u16; 8] {}
    impl IsPermutable for [u16; 16] {}
    impl IsPermutable for [u16; 32] {}
    impl IsPermutable for [u16; 64] {}
    impl IsPermutable for [u16; 128] {}
    impl IsPermutable for NonZeroU8 {}
    impl IsPermutable for NonZeroU16 {}
    impl IsPermutable for NonZeroU32 {}
    impl IsPermutable for NonZeroU64 {}
    impl IsPermutable for NonZeroU128 {}
    impl IsPermutable for u8 {}
    impl IsPermutable for u16 {}
    impl IsPermutable for u32 {}
    impl IsPermutable for u64 {}
    impl IsPermutable for u128 {}
}

#[cfg(test)]
mod tests {
    use super::private::IsPermutable;
    use crate::PermutationKey;
    use rand::SeedableRng;
    use vitaminc_random::{Generatable, SafeRand};

    pub fn gen_rand_key<const N: usize>() -> PermutationKey<N>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy();
        PermutationKey::random(&mut rng).expect("Failed to generate key")
    }

    pub fn gen_key<const N: usize>(seed: [u8; 32]) -> PermutationKey<N>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_seed(seed);
        PermutationKey::random(&mut rng).expect("Failed to generate key")
    }
}

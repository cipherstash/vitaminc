#![doc = include_str!("../README.md")]
mod bitwise;
mod elementwise;
mod key;

// TODO: Add tests and docs for use with Controlled types

pub use bitwise::BitwisePermute;
pub use elementwise::{Depermute, Permute};
pub use key::PermutationKey;

mod private {
    use vitaminc_protected::Zeroed;

    pub trait IsPermutable: Zeroed {}
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
    impl IsPermutable for [u32; 8] {}
    impl IsPermutable for [u32; 16] {}
    impl IsPermutable for [u32; 32] {}
    impl IsPermutable for [u32; 64] {}
    impl IsPermutable for [u32; 128] {}

    pub(crate) const fn identity<const N: usize>() -> [u8; N]
    where
        [u8; N]: IsPermutable,
    {
        let mut out = [0; N];
        let mut i = 0;
        while i < N {
            out[i] = i as u8;
            i += 1;
        }
        out
    }
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

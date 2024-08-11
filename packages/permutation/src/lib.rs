mod bitwise;
mod elementwise;
mod key;

pub use bitwise::BitwisePermute;
pub use elementwise::{Depermute, Permute};
pub use key::PermutationKey;
use vitaminc_protected::{Paranoid, Protected};

pub fn identity<const N: usize>() -> Protected<[u8; N]> {
    Protected::generate(|| {
        // TODO: Use MaybeUninit
        let mut key = [0; N];
        for (i, elem) in key.iter_mut().enumerate() {
            *elem = i as u8;
        }
        key
    })
}

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

#[cfg(test)]
mod tests {
    use crate::PermutationKey;
    use rand::SeedableRng;
    use vitaminc_random::{Generatable, SafeRand};

    pub fn gen_rand_key<const N: usize>() -> PermutationKey<N> {
        let mut rng = SafeRand::from_entropy();
        PermutationKey::random(&mut rng).expect("Failed to generate key")
    }

    pub fn gen_key<const N: usize>(seed: [u8; 32]) -> PermutationKey<N> {
        let mut rng = SafeRand::from_seed(seed);
        PermutationKey::random(&mut rng).expect("Failed to generate key")
    }

    // TODO: Make this a function inside protected (maybe there are others we can do too) - a util module
    pub fn array_gen<const N: usize>() -> [u8; N] {
        let mut input: [u8; N] = [0; N];
        input.iter_mut().enumerate().for_each(|(i, x)| {
            *x = (i + 1) as u8;
        });
        input
    }
}

mod bitwise;
mod elementwise;
mod key;

pub use bitwise::{BitwisePermutableBy, BitwisePermutation};
pub use elementwise::{Depermute, Permute};
pub use key::PermutationKey;
use protected::{Paranoid, Protected};

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

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use random::Generatable;
    use crate::PermutationKey;

    pub fn gen_rand_key<const N: usize>() -> PermutationKey<N> {
        let mut rng = random::SafeRand::from_entropy();
        PermutationKey::generate(&mut rng).expect("Failed to generate key")
    }

    pub fn gen_key<const N: usize>(seed: [u8; 32]) -> PermutationKey<N> {
        let mut rng = random::SafeRand::from_seed(seed);
        PermutationKey::generate(&mut rng).expect("Failed to generate key")
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

#![doc = include_str!("../README.md")]
mod bitwise;
mod elementwise;
mod key;
mod shuffle;

// TODO: Add tests and docs for use with Controlled types

pub use bitwise::BitwisePermute;
pub use elementwise::{Depermute, Permute};
pub use key::PermutationKey;

mod private {
    use crate::shuffle::{batcher_gate_count, batcher_schedule};
    use vitaminc_protected::Zeroed;

    pub trait IsPermutable: Zeroed {
        /// The Batcher odd-even mergesort network for arrays of this length,
        /// used for oblivious key generation. Depends only on the length, so
        /// all element types of a given length share one schedule.
        const SCHEDULE: &'static [(u8, u8)];
    }

    macro_rules! impl_permutable {
        ($($n:literal),* $(,)?) => {
            paste::paste! {
                $(
                    const [<SCHEDULE_ $n>]: [(u8, u8); batcher_gate_count($n)] =
                        batcher_schedule($n);
                    impl IsPermutable for [u8; $n] {
                        const SCHEDULE: &'static [(u8, u8)] = &[<SCHEDULE_ $n>];
                    }
                    impl IsPermutable for [u16; $n] {
                        const SCHEDULE: &'static [(u8, u8)] = &[<SCHEDULE_ $n>];
                    }
                    impl IsPermutable for [u32; $n] {
                        const SCHEDULE: &'static [(u8, u8)] = &[<SCHEDULE_ $n>];
                    }
                )*
            }
        };
    }

    impl_permutable!(8, 16, 32, 64, 128);

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
    use vitaminc_random::{Generatable, SafeRand, SeedableRng};

    pub fn gen_rand_key<const N: usize>() -> Result<PermutationKey<N>, Box<dyn std::error::Error>>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy()?;
        Ok(PermutationKey::random(&mut rng)?)
    }

    pub fn gen_key<const N: usize>(seed: [u8; 32]) -> PermutationKey<N>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_seed(seed);
        PermutationKey::random(&mut rng).expect("Failed to generate key")
    }
}

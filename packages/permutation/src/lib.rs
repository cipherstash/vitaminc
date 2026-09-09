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

    /// The array shapes a `PermutationKey<N>` can act on. Each impl carries
    /// the compare-exchange schedule of the sorting network for its length,
    /// so the set of supported lengths lives in exactly one place: adding a
    /// length without a network is a missing associated const, caught when
    /// this crate compiles, never a downstream const-eval failure.
    pub trait IsPermutable: Zeroed {
        /// The Batcher network for this length, as `(a, b)` gate pairs with
        /// `a < b`. Only the `[u8; N]` impl builds one; the wider element
        /// types alias it, since the network depends on the length alone.
        const SCHEDULE: &'static [(u8, u8)];
    }

    macro_rules! permutable {
        ($($n:literal),* $(,)?) => {$(
            impl IsPermutable for [u8; $n] {
                const SCHEDULE: &'static [(u8, u8)] =
                    &batcher_schedule::<{ batcher_gate_count($n) }>($n);
            }
            impl IsPermutable for [u16; $n] {
                const SCHEDULE: &'static [(u8, u8)] = <[u8; $n] as IsPermutable>::SCHEDULE;
            }
            impl IsPermutable for [u32; $n] {
                const SCHEDULE: &'static [(u8, u8)] = <[u8; $n] as IsPermutable>::SCHEDULE;
            }
        )*};
    }

    permutable!(8, 16, 32, 64, 128);

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

use serde::{Deserialize, Serialize};
use vitaminc_protected::{Controlled, Exportable, Protected, Zeroed};
use vitaminc_random::{Generatable, RandomError, SafeRand, SeedableRng};
use zeroize::Zeroize;

use super::private::IsPermutable;
use crate::{
    elementwise::{depermute_array, permute_array, Permute},
    private::identity,
};

pub(crate) type KeyInner<const N: usize> = Exportable<Protected<[u8; N]>>;

// NOTE: no `Copy` — `KeyInner` is a `Protected` secret, and the reasons it can
// never be `Copy` (see the `vitaminc_protected::Protected` docs) apply to any
// wrapper around it. Use `Clone` where a copy is needed.
//
// The key IS wiped on drop: `KeyInner` is `Exportable<Protected<[u8; N]>>`, both
// of which are `ZeroizeOnDrop`, so the field's drop glue zeroizes the bytes. We
// deliberately do NOT derive `ZeroizeOnDrop` on `PermutationKey` itself: a `Drop`
// impl would forbid the `.0` field moves in `complement` / `Permute::permute`
// (E0509), and recovering them would mean duplicating `protected`'s
// `ptr::read`+`forget` move-out primitive into this crate. The drop-glue
// guarantee holds as long as `KeyInner` stays `ZeroizeOnDrop`.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
pub struct PermutationKey<const N: usize>(KeyInner<N>);

impl<const N: usize> PermutationKey<N> {
    /// # Safety
    ///
    /// This function is unsafe because it does not check that the key is a valid permutation.
    ///
    pub unsafe fn new_unchecked(key: [u8; N]) -> Self {
        Self(KeyInner::<N>::new(key))
    }

    /// Creates a new permutation key from a seed.
    /// TODO: Perhaps seed should be protected?
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, RandomError>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_seed(seed);
        Generatable::random(&mut rng)
    }

    /// Returns the inverse of this key.
    ///
    /// Borrows `self` — inversion builds a fresh key from the borrowed
    /// permutation, so there is no need to consume (or clone) the original.
    pub fn invert(&self) -> Self
    where
        [u8; N]: IsPermutable,
    {
        Self(KeyInner::new(depermute_array(self, identity())))
    }

    /// Returns the complement of the key with respect to the target key.
    /// That is: `C(T) = Self`
    ///
    /// # Example
    ///
    /// ```
    /// # mod vitaminc { pub mod permutation { pub use vitaminc_permutation::*; } pub mod random { pub use vitaminc_random::*; } }
    /// use vitaminc::permutation::{Permute, PermutationKey};
    /// use vitaminc::random::{Generatable, SafeRand, SeedableRng};
    /// let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
    /// let key = PermutationKey::random(&mut rng).expect("Random error");
    /// let target = PermutationKey::random(&mut rng).expect("Random error");
    /// let complement = key.complement(&target);
    /// let input: [u8; 16] = Generatable::random(&mut rng).expect("Random error");
    /// assert_eq!(
    ///     complement.permute(target).permute(input),
    ///     key.permute(input)
    /// );
    /// ```
    pub fn complement(&self, target: &Self) -> Self
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        // `invert` borrows, so we map the inverse of the borrowed `target`
        // through `permute_array` without ever copying the key.
        Self(target.invert().0.map(|arr| permute_array(self, arr)))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Protected<u8>> + '_ {
        self.0.iter()
    }
}

impl<const N: usize> Generatable for PermutationKey<N>
where
    [u8; N]: IsPermutable,
{
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let key = KeyInner::<N>::generate(identity).map(|key| {
            // Fisher-Yates: for i from N-1 down to 0, swap i with a uniform
            // j in 0..=i. `i + 1` candidates, so the bound is `next_below(i + 1)`.
            // j == i (no swap) must be as likely as any other choice or the
            // permutation is not uniform.
            (0..N).rev().fold(key, |mut key, i| {
                let mut j = rng.next_below(i as u32 + 1) as usize;
                key.swap(i, j);
                j.zeroize();
                key
            })
        });

        Ok(Self(key))
    }
}

impl<const N: usize> Permute<PermutationKey<N>> for PermutationKey<N>
where
    [u8; N]: IsPermutable + Zeroed,
{
    fn permute(&self, Self(inner): Self) -> Self {
        Self(inner.map(|arr| permute_array(self, arr)))
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    /// The generator is Fisher-Yates over the identity, drawing
    /// `next_below(i + 1)` for `i` from `N - 1` down to `0`. Replaying that
    /// with a second generator on the same seed must reproduce the key
    /// exactly, which pins both the draw order and the bound.
    #[test]
    fn key_is_fisher_yates_over_next_below() {
        let key = PermutationKey::<16>::from_seed(SEED).expect("random");
        let mut rng = SafeRand::from_seed(SEED);
        let mut expected: [u8; 16] = core::array::from_fn(|i| i as u8);
        for i in (0..16).rev() {
            let j = rng.next_below(i as u32 + 1) as usize;
            expected.swap(i, j);
        }
        let got: Vec<u8> = key.iter().map(|b| b.risky_unwrap()).collect();
        assert_eq!(got, expected);
    }

    /// Every element lands in every position about equally often. The old
    /// bound was exclusive at powers of two, so at `i = 1` the swap was
    /// forced and at `i = 2, 4` element `i` could never stay put; that
    /// skews these counts far outside the tolerance below (7σ at this
    /// sample size), while a uniform generator sits well inside it.
    #[test]
    fn keys_are_uniform_over_positions() {
        const N: usize = 8;
        const SAMPLES: usize = 40_000;
        let expected = (SAMPLES / N) as f64;
        let tolerance = expected * 0.10;

        let mut rng = SafeRand::from_seed(SEED);
        let mut counts = [[0usize; N]; N];
        for _ in 0..SAMPLES {
            let key = PermutationKey::<N>::random(&mut rng).expect("random");
            for (position, value) in key.iter().enumerate() {
                counts[position][value.risky_unwrap() as usize] += 1;
            }
        }
        for (position, row) in counts.iter().enumerate() {
            for (value, &count) in row.iter().enumerate() {
                assert!(
                    (count as f64 - expected).abs() <= tolerance,
                    "value {value} at position {position}: {count} (expected ~{expected})"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        elementwise::Permute,
        key::KeyInner,
        private::{identity, IsPermutable},
        PermutationKey,
    };
    use vitaminc_protected::{Controlled, Zeroed};
    use vitaminc_random::{Generatable, SafeRand};

    use crate::tests;

    fn test_key_invert<const N: usize>() -> Result<(), Box<dyn std::error::Error>>
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let key: PermutationKey<N> = tests::gen_rand_key()?;
        let inverted = key.invert();

        // p(p^-1(x)) = x
        assert_eq!(
            key.permute(inverted).0.risky_unwrap(),
            KeyInner::<N>::generate(identity).risky_unwrap(),
            "Failed to invert key of size {N}"
        );
        Ok(())
    }

    fn test_key_complement<const N: usize>() -> Result<(), Box<dyn std::error::Error>>
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let key: PermutationKey<N> = tests::gen_rand_key()?;
        let target: PermutationKey<N> = tests::gen_rand_key()?;
        let complement = key.complement(&target);

        let mut rng = SafeRand::from_entropy()?;
        let input: [u8; N] = Generatable::random(&mut rng)?;

        // c(t)(x) = p(x)
        assert_eq!(
            complement.permute(target).permute(input),
            key.permute(input),
            "Failed to complement key of size {N}"
        );
        Ok(())
    }

    #[test]
    fn key_inversion_case() -> Result<(), Box<dyn std::error::Error>> {
        test_key_invert::<8>()?;
        test_key_invert::<16>()?;
        test_key_invert::<32>()?;
        test_key_invert::<64>()?;
        Ok(())
    }

    #[test]
    fn key_complement_case() -> Result<(), Box<dyn std::error::Error>> {
        test_key_complement::<8>()?;
        test_key_complement::<16>()?;
        test_key_complement::<32>()?;
        test_key_complement::<64>()?;
        Ok(())
    }
}

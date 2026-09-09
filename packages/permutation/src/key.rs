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
    ///
    /// Derivation is deterministic: a given seed always yields the same key.
    /// If it returns [`RandomError::SeedRejected`] (probability ≈ N²/2⁵⁷,
    /// at most ≈ 2⁻⁴³ for N = 128), the seed can *never* derive a key —
    /// discard it and provision a fresh seed. Only retain seeds whose first
    /// derivation succeeds.
    ///
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
        // Oblivious sort-by-random-key shuffle: unlike Fisher–Yates, whose
        // `swap(i, j)` addresses memory with the secret draw `j`, timing and
        // access patterns here are functions of `N` only. See `crate::shuffle`.
        //
        // Exactly one batch is attempted: `Err(SeedRejected)` means the seed
        // behind `rng` is unusable and must be replaced, not retried.
        //
        // The permutation is written straight into the key's own wiped-on-
        // drop slot, so no plain `[u8; N]` copy of it exists at any point;
        // on failure the zeroed slot is dropped and wiped like any key.
        let mut key = KeyInner::<N>::generate(|| [0; N]);
        crate::shuffle::random_permutation(rng, key.inner_mut())?;
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
mod tests {
    use crate::{
        elementwise::Permute,
        key::KeyInner,
        private::{identity, IsPermutable},
        PermutationKey,
    };
    use vitaminc_protected::{Controlled, Zeroed};
    use vitaminc_random::{Generatable, SafeRand, SeedableRng};

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
        test_key_invert::<128>()?;
        Ok(())
    }

    /// A generated key is a valid permutation: every value in `0..N` present
    /// exactly once. The invert / complement round-trips imply this only
    /// transitively; checking it directly at the `PermutationKey` level fails
    /// loudly if the generator regresses, whichever shuffle it uses.
    fn test_key_is_a_permutation<const N: usize>() -> Result<(), Box<dyn std::error::Error>>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_seed([7u8; 32]);
        for _ in 0..64 {
            let key: PermutationKey<N> = Generatable::random(&mut rng)?;
            let mut seen = [false; N];
            for v in key.iter() {
                let v = v.risky_unwrap() as usize;
                assert!(v < N, "value {v} out of range for N = {N}");
                assert!(!seen[v], "value {v} appears twice for N = {N}");
                seen[v] = true;
            }
            assert!(seen.iter().all(|&s| s), "missing value for N = {N}");
        }
        Ok(())
    }

    #[test]
    fn key_is_a_permutation_case() -> Result<(), Box<dyn std::error::Error>> {
        test_key_is_a_permutation::<8>()?;
        test_key_is_a_permutation::<16>()?;
        test_key_is_a_permutation::<32>()?;
        test_key_is_a_permutation::<64>()?;
        test_key_is_a_permutation::<128>()?;
        Ok(())
    }

    #[test]
    fn key_position_uniformity() -> Result<(), Box<dyn std::error::Error>> {
        // Chi-squared test over the position matrix: counts[v][i] tallies how
        // often value `v` ends up at position `i`. Under a uniform permutation
        // every cell has the same expectation. This catches the power-of-two
        // bias in the old inclusive bounded draw (issue #198), where the swap
        // target at power-of-two Fisher–Yates steps could never equal the step
        // index itself.
        const N: usize = 8;
        const SAMPLES: usize = 20_000;
        let mut rng = SafeRand::from_seed([7u8; 32]);
        let mut counts = [[0u32; N]; N];
        for _ in 0..SAMPLES {
            let key: PermutationKey<N> = Generatable::random(&mut rng)?;
            for (i, v) in key.iter().enumerate() {
                counts[v.risky_unwrap() as usize][i] += 1;
            }
        }
        let expected = (SAMPLES / N) as f64;
        let chi2: f64 = counts
            .iter()
            .flatten()
            .map(|&c| {
                let d = f64::from(c) - expected;
                d * d / expected
            })
            .sum();
        // The position matrix is doubly stochastic, so (N - 1)² = 49 degrees
        // of freedom; p = 0.001 critical value is 85.35. The seed is fixed, so
        // this is deterministic — no flakiness.
        assert!(chi2 < 85.35, "chi-squared too high: {chi2}");
        Ok(())
    }

    #[test]
    fn key_complement_case() -> Result<(), Box<dyn std::error::Error>> {
        test_key_complement::<8>()?;
        test_key_complement::<16>()?;
        test_key_complement::<32>()?;
        test_key_complement::<64>()?;
        test_key_complement::<128>()?;
        Ok(())
    }
}

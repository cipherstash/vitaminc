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

/// One seed in a [`PermutationKey::from_seeds`] batch could not derive a key.
///
/// `index` is the seed's position in the iterator passed to `from_seeds`.
/// For [`RandomError::SeedRejected`] that seed can never derive a key.
/// `from_seeds` consumed and wiped the batch, so recovery starts from the
/// caller's own retained seeds: replace the one at `index` with a fresh
/// seed and derive the whole batch again.
#[derive(Debug, thiserror::Error)]
#[error("seed at index {index} could not derive a key: {source}")]
pub struct BatchSeedError {
    /// Position of the failing seed in the batch.
    pub index: usize,
    /// Why derivation failed for that seed.
    #[source]
    pub source: RandomError,
}

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

    /// Derives one key per seed, in order, wiping each seed once its
    /// generator is built.
    ///
    /// Each seed is derived exactly as [`PermutationKey::from_seed`] would:
    /// independently and deterministically, so the batch is bit-identical to
    /// calling `from_seed` per seed. Seeds arrive as [`Controlled`] values
    /// (for instance `Protected<[u8; 32]>`) rather than bare bytes, so a
    /// batch of retained secrets is never copied around unwiped.
    ///
    /// A rejected seed fails the whole call and [`BatchSeedError`] names its
    /// lane. No keys are delivered for the lanes before it, so a caller can
    /// never end up holding a key vector that is out of step with its seeds.
    ///
    /// The call consumes the seeds, and every one that was unwrapped is
    /// wiped whether or not the batch succeeds; the error carries only the
    /// index. Recovery is therefore the caller's, from its own copy of the
    /// batch: keep the seeds in their [`Controlled`] containers (a
    /// `Vec<Protected<[u8; 32]>>`, say) and pass `from_seeds` a view of them
    /// (clones, or a mapping iterator) rather than the originals; on
    /// [`RandomError::SeedRejected`] replace the seed at the reported index
    /// with a fresh one and derive the whole batch again. A caller that
    /// cannot retain or regenerate its seeds has nothing to retry with.
    ///
    /// The batch entry point exists for bulk workloads (e.g. deriving the
    /// per-block permutations for a batch of ORE encryptions): it fixes the
    /// API shape so a future vectorized backend can derive lanes in parallel
    /// while remaining bit-identical to per-seed scalar derivation.
    pub fn from_seeds<C>(seeds: impl IntoIterator<Item = C>) -> Result<Vec<Self>, BatchSeedError>
    where
        [u8; N]: IsPermutable,
        C: Controlled<Inner = [u8; 32]>,
    {
        Self::derive_batch(seeds, Generatable::random)
    }

    /// The batch loop behind [`from_seeds`](Self::from_seeds), with the
    /// per-lane derivation injected. Exists so tests can drive a rejected
    /// lane: the natural rate is ≈ 2⁻⁴³ per seed, unreachable by search.
    fn derive_batch<C>(
        seeds: impl IntoIterator<Item = C>,
        mut derive: impl FnMut(&mut SafeRand) -> Result<Self, RandomError>,
    ) -> Result<Vec<Self>, BatchSeedError>
    where
        C: Controlled<Inner = [u8; 32]>,
    {
        seeds
            .into_iter()
            .enumerate()
            .map(|(index, seed)| {
                let mut rng = SafeRand::from_controlled_seed(seed);
                derive(&mut rng).map_err(|source| BatchSeedError { index, source })
            })
            .collect()
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
        BatchSeedError, PermutationKey,
    };
    use vitaminc_protected::{Controlled, Protected, Zeroed};
    use vitaminc_random::{Generatable, RandomError, SafeRand, SeedableRng};

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
        let raw: f64 = counts
            .iter()
            .flatten()
            .map(|&c| {
                let d = f64::from(c) - expected;
                d * d / expected
            })
            .sum();
        // Each sample is a permutation matrix, not N independent draws, so
        // the raw Pearson sum over the N² cells is not χ² on (N − 1)² = 49
        // degrees of freedom: its mean is N/(N − 1) times that. Scaling by
        // (N − 1)/N recovers a χ²(49) statistic (verified by simulation:
        // mean 49.0, 0.1% above the threshold). p = 0.001 critical value for
        // χ²(49) is 85.35. The seed is fixed, so the value is reproducible;
        // an honest generator would exceed the threshold for about one seed
        // in a thousand.
        let chi2 = raw * (N - 1) as f64 / N as f64;
        assert!(chi2 < 85.35, "chi-squared too high: {chi2}");
        Ok(())
    }

    #[test]
    fn batch_matches_single_seed_derivation() -> Result<(), Box<dyn std::error::Error>> {
        // The batch path must be indistinguishable from calling `from_seed`
        // per seed: same keys, same order. Distinct seeds pin the ordering —
        // a reordered or repeated lane would produce a mismatched key.
        let seeds: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let batch = PermutationKey::<64>::from_seeds(seeds.iter().copied().map(Protected::new))?;
        assert_eq!(batch.len(), seeds.len());
        for (seed, key) in seeds.into_iter().zip(batch) {
            let expected = PermutationKey::<64>::from_seed(seed)?;
            assert_eq!(
                key.0.risky_unwrap(),
                expected.0.risky_unwrap(),
                "batch lane diverged from from_seed for seed {:?}",
                seed[0]
            );
        }
        Ok(())
    }

    #[test]
    fn batch_of_nothing_is_empty() -> Result<(), Box<dyn std::error::Error>> {
        let none = std::iter::empty::<Protected<[u8; 32]>>();
        assert!(PermutationKey::<8>::from_seeds(none)?.is_empty());
        Ok(())
    }

    /// A rejected seed fails the batch with its own lane index, and no lane
    /// after it is derived. Natural rejection is ≈ 2⁻⁴³ per seed, so it is
    /// injected through the private seam rather than found by search.
    #[test]
    fn rejected_lane_is_reported_by_index_and_stops_the_batch() {
        let seeds = (0u8..5).map(|i| Protected::new([i; 32]));
        let mut calls = 0;
        let err = PermutationKey::<16>::derive_batch(seeds, |rng| {
            calls += 1;
            if calls == 3 {
                Err(RandomError::SeedRejected)
            } else {
                Generatable::random(rng)
            }
        })
        .expect_err("lane 2 was rejected");
        assert_eq!(err.index, 2);
        assert!(matches!(err.source, RandomError::SeedRejected));
        assert_eq!(calls, 3, "lanes after the rejected one must not be derived");
    }

    /// Fixed-seed golden vectors for every supported `N`, captured on the
    /// commit before batch derivation landed. `from_seed` is a durable
    /// contract: a key derived from a retained seed must never change, or
    /// data permuted under it becomes unrecoverable. The README doctest pins
    /// only `N = 8`, and the relative tests here (batch vs single,
    /// determinism, validity) cannot see a change that alters every
    /// derivation the same way. Each value is the key applied to the
    /// identity array.
    #[test]
    fn from_seed_golden_vectors() -> Result<(), Box<dyn std::error::Error>> {
        fn check<const N: usize>(expected: [u8; N]) -> Result<(), Box<dyn std::error::Error>>
        where
            [u8; N]: IsPermutable + Zeroed,
        {
            let key = PermutationKey::<N>::from_seed([0u8; 32])?;
            let identity: [u8; N] = core::array::from_fn(|i| i as u8);
            assert_eq!(key.permute(identity), expected, "N = {N}");
            Ok(())
        }
        check::<8>([3, 0, 4, 5, 7, 6, 1, 2])?;
        check::<16>([9, 3, 8, 13, 0, 4, 5, 15, 12, 10, 7, 11, 6, 1, 2, 14])?;
        check::<32>([
            9, 3, 28, 31, 30, 26, 8, 13, 0, 4, 23, 5, 15, 12, 24, 20, 18, 10, 7, 16, 11, 27, 22,
            17, 6, 29, 19, 21, 1, 25, 2, 14,
        ])?;
        check::<64>([
            58, 9, 47, 3, 28, 56, 36, 31, 43, 30, 33, 57, 26, 41, 53, 8, 13, 0, 60, 40, 4, 23, 5,
            15, 12, 24, 20, 52, 18, 10, 7, 16, 55, 11, 63, 49, 46, 39, 27, 35, 22, 59, 38, 17, 6,
            44, 48, 29, 45, 19, 42, 21, 54, 1, 25, 32, 50, 37, 51, 2, 62, 34, 14, 61,
        ])?;
        check::<128>([
            58, 76, 72, 87, 9, 119, 47, 3, 28, 56, 36, 31, 43, 110, 30, 89, 33, 112, 57, 26, 41,
            73, 117, 68, 53, 8, 13, 0, 97, 60, 115, 40, 4, 23, 5, 15, 12, 123, 69, 24, 103, 111,
            91, 126, 20, 118, 52, 127, 124, 18, 94, 105, 10, 7, 88, 16, 109, 55, 74, 11, 80, 106,
            63, 77, 83, 49, 113, 82, 46, 39, 114, 98, 27, 116, 104, 35, 90, 22, 59, 38, 17, 6, 75,
            81, 44, 92, 48, 93, 29, 45, 120, 100, 19, 78, 42, 21, 54, 1, 95, 84, 25, 125, 107, 71,
            32, 50, 79, 96, 101, 85, 37, 51, 122, 102, 67, 2, 99, 64, 62, 86, 70, 66, 65, 34, 14,
            61, 108, 121,
        ])?;
        Ok(())
    }

    /// The error names the lane so a caller can discard exactly that seed.
    #[test]
    fn batch_error_reports_the_lane() {
        let err = BatchSeedError {
            index: 3,
            source: RandomError::SeedRejected,
        };
        assert_eq!(
            err.to_string(),
            "seed at index 3 could not derive a key: The seed produced an unusable batch; discard it and generate a fresh seed"
        );
        assert!(std::error::Error::source(&err).is_some());
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

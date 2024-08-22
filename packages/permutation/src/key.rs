use vitaminc_protected::{Paranoid, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};
use zeroize::Zeroize;

use super::private::IsPermutable;
use crate::{
    elementwise::{Depermute, Permute},
    identity,
};

#[derive(Copy, Clone, Debug)]
pub struct PermutationKey<const N: usize>(Protected<[u8; N]>);
// TODO: Derive macro
// TODO: It would be really handy to be able to mark named types as Paranoid, too
// but this currently doesn't work.
// We could move the Associated type to the Paranoid trait, and give it a bound of ParanoidPrivate
// This is basically providing a way to make custom adapters
/*impl Paranoid for PermutationKey<1> {
    fn unwrap(self) -> Protected<[u8; 1]> {
        self.0.unwrap()
    }
}*/

impl<const N: usize> PermutationKey<N> {
    /// # Safety
    ///
    /// This function is unsafe because it does not check that the key is a valid permutation.
    ///
    pub unsafe fn new_unchecked(key: [u8; N]) -> Self {
        Self(Protected::new(key))
    }

    /// Consumes the key and returns its inverse.
    pub fn invert(self) -> Self
    where
        [u8; N]: IsPermutable,
    {
        Self(self.depermute(identity::<N, u8>()))
    }

    /// Returns the complement of the key with respect to the target key.
    /// That is: `C(T) = Self`
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_permutation::{Permute, PermutationKey};
    /// use vitaminc_random::{Generatable, SafeRand, SeedableRng};
    /// use vitaminc_protected::{Paranoid, Protected};
    /// let mut rng = SafeRand::from_entropy();
    /// let key = PermutationKey::random(&mut rng).unwrap();
    /// let target = PermutationKey::random(&mut rng).unwrap();
    /// let complement = key.complement(&target);
    /// let input: Protected<[u8; 16]> = Protected::random(&mut rng).unwrap();
    /// assert_eq!(
    ///     complement.permute(target).permute(input).unwrap(),
    ///     key.permute(input).unwrap()
    /// );
    /// ```
    pub fn complement(&self, target: &Self) -> Self
    where
        [u8; N]: IsPermutable,
    {
        self.permute(target.invert())
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
        let key = identity::<N, u8>().map(|key| {
            (0..N).rev().fold(key, |mut key, i| {
                // TODO: Use Protected
                let mut j = rng.next_bounded_u32(i as u32) as usize;
                key.swap(i, j);
                j.zeroize();
                key
            })
        });

        Ok(Self(key))
    }
}

/// A permutation key can be permuted by another permutation key.
impl<const N: usize> Permute<PermutationKey<N>> for PermutationKey<N>
where
    [u8; N]: IsPermutable,
{
    fn permute(&self, input: PermutationKey<N>) -> PermutationKey<N> {
        Self(self.permute(input.0))
    }
}

#[cfg(test)]
mod tests {
    use crate::{elementwise::Permute, identity, private::IsPermutable, PermutationKey};
    use vitaminc_protected::{Paranoid, Protected};
    use vitaminc_random::{Generatable, SafeRand, SeedableRng};

    use crate::tests;

    fn test_key_invert<const N: usize>()
    where
        [u8; N]: IsPermutable,
    {
        let key: PermutationKey<N> = tests::gen_rand_key();
        let inverted = key.invert();

        // p(p^-1(x)) = x
        assert_eq!(
            key.permute(inverted).0.unwrap(),
            identity::<N, u8>().unwrap(),
            "Failed to invert key of size {N}"
        );
    }

    fn test_key_complement<const N: usize>()
    where
        [u8; N]: IsPermutable,
    {
        let key: PermutationKey<N> = tests::gen_rand_key();
        let target: PermutationKey<N> = tests::gen_rand_key();
        let complement = key.complement(&target);

        let mut rng = SafeRand::from_entropy();
        let input: Protected<[u8; N]> = Protected::random(&mut rng).unwrap();

        // c(t)(x) = p(x)
        assert_eq!(
            complement.permute(target).permute(input).unwrap(),
            key.permute(input).unwrap(),
            "Failed to complement key of size {N}"
        );
    }

    #[test]
    fn key_inversion_case() {
        test_key_invert::<8>();
        test_key_invert::<16>();
        test_key_invert::<32>();
        test_key_invert::<64>();
    }

    #[test]
    fn key_complement_case() {
        test_key_complement::<8>();
        test_key_complement::<16>();
        test_key_complement::<32>();
        test_key_complement::<64>();
    }
}

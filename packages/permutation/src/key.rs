use vitaminc_protected::{ControlledInit, ControlledNew, ControlledMethods, Exportable, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};
use zeroize::Zeroize;

use super::private::IsPermutable;
use crate::{
    elementwise::{Depermute, Permute},
    identity,
};

// Controls for the key: Protected and Exportable
pub(crate) type KeyInner<const N: usize> = Exportable<Protected<[u8; N]>>;

#[derive(Copy, Clone, Debug, Zeroize)]
pub struct PermutationKey<const N: usize>(KeyInner<N>);

impl<const N: usize> ControlledInit for PermutationKey<N> {
    type Inner = KeyInner<N>;

    fn init(value: Exportable<Protected<[u8; N]>>) -> Self {
        Self(value)
    }

    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

impl<const N: usize> PermutationKey<N> {
    /// # Safety
    ///
    /// This function is unsafe because it does not check that the key is a valid permutation.
    ///
    pub unsafe fn new_unchecked(key: [u8; N]) -> Self {
        Self::new(key)
    }

    /// Consumes the key and returns its inverse.
    pub fn invert(self) -> Self
    where
        [u8; N]: IsPermutable,
    {
        Self(self.depermute(Exportable::init(identity::<N, u8>())))
    }

    /// Returns the complement of the key with respect to the target key.
    /// That is: `C(T) = Self`
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_permutation::{Permute, PermutationKey};
    /// use vitaminc_random::{Generatable, SafeRand, SeedableRng};
    /// use vitaminc_protected::{Protect, Protected};
    /// let mut rng = SafeRand::from_entropy();
    /// let key = PermutationKey::random(&mut rng).unwrap();
    /// let target = PermutationKey::random(&mut rng).unwrap();
    /// let complement = key.complement(&target);
    /// let input: Protected<[u8; 16]> = Protected::random(&mut rng).unwrap();
    /// assert_eq!(
    ///     complement.permute(target).permute(input).risky_unwrap(),
    ///     key.permute(input).risky_unwrap()
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
    use vitaminc_protected::{Controlled, Protected};
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
            key.permute(inverted).0.risky_unwrap(),
            identity::<N, u8>().risky_unwrap(),
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
            complement.permute(target).permute(input).risky_unwrap(),
            key.permute(input).risky_unwrap(),
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

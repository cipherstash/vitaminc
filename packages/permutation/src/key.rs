use vitaminc_protected::{Controlled, Exportable, Protected, Zeroed};
use vitaminc_random::{Generatable, RandomError, SafeRand};
use zeroize::Zeroize;

use super::private::IsPermutable;
use crate::{
    elementwise::{depermute_array, permute_array, Permute},
    private::identity,
};

pub(crate) type KeyInner<const N: usize> = Exportable<Protected<[u8; N]>>;

#[derive(Copy, Clone, Debug)]
pub struct PermutationKey<const N: usize>(KeyInner<N>);

impl<const N: usize> PermutationKey<N> {
    /// # Safety
    ///
    /// This function is unsafe because it does not check that the key is a valid permutation.
    ///
    pub unsafe fn new_unchecked(key: [u8; N]) -> Self {
        Self(KeyInner::<N>::new(key))
    }

    /// Consumes the key and returns its inverse.
    pub fn invert(self) -> Self
    where
        [u8; N]: IsPermutable,
    {
        Self(KeyInner::new(depermute_array(&self, identity())))
    }

    /// Returns the complement of the key with respect to the target key.
    /// That is: `C(T) = Self`
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_permutation::{Permute, PermutationKey};
    /// use vitaminc_random::{Generatable, SafeRand, SeedableRng};
    /// let mut rng = SafeRand::from_entropy();
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
            (0..N).rev().fold(key, |mut key, i| {
                let mut j = rng.next_bounded_u32(i as u32) as usize;
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

    fn test_key_invert<const N: usize>()
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let key: PermutationKey<N> = tests::gen_rand_key();
        let inverted = key.invert();

        // p(p^-1(x)) = x
        assert_eq!(
            key.permute(inverted).0.risky_unwrap(),
            KeyInner::<N>::generate(identity).risky_unwrap(),
            "Failed to invert key of size {N}"
        );
    }

    fn test_key_complement<const N: usize>()
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let key: PermutationKey<N> = tests::gen_rand_key();
        let target: PermutationKey<N> = tests::gen_rand_key();
        let complement = key.complement(&target);

        let mut rng = SafeRand::from_entropy();
        let input: [u8; N] = Generatable::random(&mut rng).unwrap();

        // c(t)(x) = p(x)
        assert_eq!(
            complement.permute(target).permute(input),
            key.permute(input),
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

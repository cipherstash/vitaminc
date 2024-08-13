use rand::Rng;
use vitaminc_protected::{Paranoid, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};
use zeroize::Zeroize;

use crate::{
    elementwise::{Depermute, Permute},
    identity, IsPermutable,
};

#[derive(Copy, Clone, Debug)]
pub struct PermutationKey<const N: usize>(Protected<[u8; N]>);
// TODO: Derive macro
// TODO: It would be really handy to be able to mark named types as Paranoid, too
// but this currently doesn't work.
// We could move the Associated type to the Paranoid trait, and give it a bound of ParanoidPrivate
/*impl Paranoid for PermutationKey<1> {
    fn unwrap(self) -> Protected<[u8; 1]> {
        self.0.unwrap()
    }
}*/

impl<const N: usize> PermutationKey<N>
//where
//    [u8; N]: ValidPermutationSize,
{
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

    pub(crate) fn iter(&self) -> impl Iterator<Item = Protected<u8>> + '_ {
        self.0.iter()
    }
}

impl<const N: usize> Generatable for PermutationKey<N> where [u8; N]: IsPermutable {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let key = identity::<N, u8>().map(|mut key| {
            for i in (0..N).rev() {
                // TODO: Confirm that this uses rejection sampling to avoid modulo bias
                let mut j = rng.gen_range(0..=i);
                key.swap(i, j);
                j.zeroize();
            }
            Protected::new(key)
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
        let x = input.0.map(|source| {
            // TODO: Use MaybeUninit
            let out = self
                .iter()
                .enumerate()
                .fold([Default::default(); N], |mut out, (i, k)| {
                    out[i] = source[k.map(|x| Protected::from(x as usize))];
                    out
                });

            Protected::new(out)
        });
        Self(x)
    }
}

#[cfg(test)]
mod tests {
    use super::PermutationKey;
    use crate::{elementwise::Permute, identity, IsPermutable};
    use vitaminc_protected::Paranoid;

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

    #[test]
    fn key_inversion_case() {
        test_key_invert::<8>();
        test_key_invert::<16>();
        test_key_invert::<32>();
        test_key_invert::<64>();
    }
}

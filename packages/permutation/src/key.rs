use protected::{Paranoid, Protected};
use rand::Rng;
use random::Generatable;
use zeroize::Zeroize;

use crate::{elementwise::Permute};

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

impl<const N: usize> PermutationKey<N> {
    // TODO: Don't allow this - we should use generate, load_checked etc
    /// # Safety
    /// 
    /// This function is unsafe because it does not check that the key is a valid permutation.
    /// 
    pub unsafe fn new_unchecked(key: [u8; N]) -> Self {
        Self(Protected::new(key))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Protected<u8>> + '_ {
        self.0.iter()
    }
}

impl<const N: usize> Generatable for PermutationKey<N> {
    fn generate(rng: &mut random::SafeRand) -> Result<Self, random::RandomError> {
        // TODO: Consider using MaybeUninit
        let mut key: [u8; N] = [0; N];
        for (i, elem) in key.iter_mut().enumerate() {
            *elem = i as u8;
        }
        for i in (0..N).rev() {
            // TODO: Confirm that this uses rejection sampling to avoid modulo bias
            let mut j = rng.gen_range(0..=i);
            key.swap(i, j);
            j.zeroize();
        }

        Ok(Self(Protected::new(key)))
    }
}

/// A permutation key can be permuted by another permutation key.
impl<const N: usize> Permute<PermutationKey<N>> for PermutationKey<N>
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
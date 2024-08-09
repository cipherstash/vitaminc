use protected::{Paranoid, Protected};
use zeroize::Zeroize;

use crate::PermutationKey;

pub struct Permutation<'k, K>(&'k K);

impl<'k, K> Permutation<'k, K> {
    pub fn new(k: &'k K) -> Self {
        Self(k)
    }

    pub fn permute<T>(&self, input: T) -> T
    where
        T: PermutableBy<K>,
    {
        input.permute(&self.0)
    }
}

// TODO: Make this a private trait
pub trait PermutableBy<K> {
    fn permute(self, key: &K) -> Self;
}

impl<const N: usize, T> PermutableBy<PermutationKey<N>> for Protected<[T; N]>
where
    T: Zeroize + Default + Copy,
{
    fn permute(self, key: &PermutationKey<N>) -> Self {
        self.map(|source| {
            // TODO: Use MaybeUninit
            let out = key
                .iter()
                .enumerate()
                .fold([Default::default(); N], |mut out, (i, k)| {
                    let k2 = k.map(|x| Protected::from(x as usize));
                    out[i] = source[k2];
                    out
                });

            Protected::new(out)
        })
    }
}

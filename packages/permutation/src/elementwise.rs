use crate::{key::KeyInner, private::IsPermutable, PermutationKey};
use vitaminc_protected::{ControlledMethods, Protected};
use zeroize::Zeroize;

// TODO: Make this a private trait
// TODO: Docs
pub trait Permute<T> {
    fn permute(&self, input: T) -> T;
}

impl<const N: usize, T> Permute<Protected<[T; N]>> for PermutationKey<N>
where
    T: Zeroize + Default + Copy,
    [u8; N]: IsPermutable,
{
    fn permute(&self, input: Protected<[T; N]>) -> Protected<[T; N]> {
        input.map(|source| {
            // TODO: Use MaybeUninit or array::from_fn
            self.iter()
                .enumerate()
                .fold([Default::default(); N], |mut out, (i, k)| {
                    out[i] = source[k.map(|x| x as usize)];
                    out
                })
        })
    }
}

pub trait Depermute<T> {
    fn depermute(&self, input: T) -> T;
}

impl<const N: usize> Depermute<KeyInner<N>> for PermutationKey<N>
where
    [u8; N]: IsPermutable,
{
    fn depermute(&self, input: KeyInner<N>) -> KeyInner<N> {
        let _out = input.map(|source| {
            // TODO: Use MaybeUninit
            self.iter()
                .enumerate()
                .fold([Default::default(); N], |mut out, (i, k)| {
                    out[k.map(|x| x as usize)] = source[i];
                    out
                })
        });

        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::IsPermutable;
    use crate::tests;
    use crate::{Depermute, PermutationKey, Permute};
    use rand::SeedableRng;
    use vitaminc_protected::{Controlled, ControlledMethods, Protected};
    use vitaminc_random::{Generatable, SafeRand};

    fn test_permute<const N: usize>()
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy();
        let input: Protected<[u8; N]> = Protected::random(&mut rng).unwrap();
        let key: PermutationKey<N> = tests::gen_rand_key();
        let output = key.permute(input);
        // Note that this may fail for some inputs
        assert_ne!(output.risky_unwrap(), input.risky_unwrap());
    }

    fn test_depermute<const N: usize>()
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy();
        let input: Protected<[u8; N]> =
            Protected::generate(|| Generatable::random(&mut rng).unwrap());
        let key: PermutationKey<N> = tests::gen_rand_key();
        let output = key.permute(input);
        let depermuted = key.depermute(output);
        assert_eq!(depermuted.risky_unwrap(), input.risky_unwrap());
    }

    fn test_associativity<const N: usize>()
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy();
        let key_1 = tests::gen_key([0; 32]);
        let key_2 = tests::gen_key([1; 32]);
        let input: Protected<[u8; N]> = Protected::random(&mut rng).unwrap();

        // p_2(p_1(input))
        let output_1 = key_2.permute(key_1.permute(input));

        // p_2(p_1)(input)
        let output_2 = key_2.permute(key_1).permute(input);

        assert_eq!(output_1.risky_unwrap(), output_2.risky_unwrap());
    }

    #[test]
    fn permute_case() {
        test_permute::<8>();
        test_permute::<16>();
        test_permute::<32>();
        test_permute::<64>();
    }

    #[test]
    fn depermutation_case() {
        test_depermute::<8>();
        test_depermute::<16>();
        test_depermute::<32>();
        test_depermute::<64>();
    }

    #[test]
    fn associativity_case() {
        test_associativity::<8>();
        test_associativity::<16>();
        test_associativity::<32>();
        test_associativity::<64>();
    }
}

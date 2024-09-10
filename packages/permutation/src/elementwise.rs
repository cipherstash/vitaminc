use crate::{private::IsPermutable, PermutationKey};
use vitaminc_protected::{Controlled, Zeroed};
use zeroize::Zeroize;

// TODO: Make this a private trait
// FIXME: This trait is backwards - self should be T and the argument should be a key
pub trait Permute<T> {
    fn permute(&self, input: T) -> T;
}

pub trait Depermute<T> {
    fn depermute(&self, input: T) -> T;
}

/// Implement permutation for Protected type containing a permutable array.
impl<const N: usize, T> Permute<[T; N]> for PermutationKey<N>
where
    T: Zeroize + Default + Copy,
    [T; N]: IsPermutable + Zeroed,
{
    fn permute(&self, input: [T; N]) -> [T; N] {
        permute_array(self, input)
    }
}

impl<const N: usize, T> Depermute<[T; N]> for PermutationKey<N>
where
    T: Zeroize + Default + Copy,
    [T; N]: IsPermutable + Zeroed,
{
    fn depermute(&self, input: [T; N]) -> [T; N] {
        depermute_array(self, input)
    }
}

#[inline]
pub fn permute_array<const N: usize, T>(key: &PermutationKey<N>, mut input: [T; N]) -> [T; N]
where
    [T; N]: IsPermutable + Zeroed,
    T: Zeroize + Copy,
{
    let out: [T; N] = key
        .iter()
        .enumerate()
        // TODO: Use MaybeUninit or array::from_fn
        .fold(Zeroed::zeroed(), |mut out, (i, k)| {
            out[i] = input[k.map(|x| x as usize)];
            out
        });

    // We copied all elements to the output so we should zeroize the input
    input.zeroize();
    out
}

#[inline]
pub fn depermute_array<const N: usize, T>(key: &PermutationKey<N>, mut input: [T; N]) -> [T; N]
where
    [T; N]: IsPermutable + Zeroed,
    T: Zeroize + Copy,
{
    // TODO: Use MaybeUninit
    let out: [T; N] = key
        .iter()
        .enumerate()
        .fold(Zeroed::zeroed(), |mut out, (i, k)| {
            out[k.map(|x| x as usize)] = input[i];
            out
        });

    // We copied all elements to the output so we should zeroize the input
    input.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests;
    use crate::{Depermute, PermutationKey, Permute};
    use rand::SeedableRng;
    use vitaminc_random::{Generatable, SafeRand};

    fn test_permute<const N: usize>()
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let mut rng = SafeRand::from_entropy();
        let input: [u8; N] = Generatable::random(&mut rng).unwrap();
        let key: PermutationKey<N> = tests::gen_rand_key();
        let output = key.permute(input);
        // Note that this may fail for some inputs
        assert_ne!(output, input);
    }

    fn test_depermute<const N: usize>()
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let mut rng = SafeRand::from_entropy();
        let input: [u8; N] = Generatable::random(&mut rng).unwrap();
        let key: PermutationKey<N> = tests::gen_rand_key();
        let output = key.permute(input);
        let depermuted = key.depermute(output);
        assert_eq!(depermuted, input);
    }

    fn test_associativity<const N: usize>()
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy();
        let key_1 = tests::gen_key([0; 32]);
        let key_2 = tests::gen_key([1; 32]);
        let input: [u8; N] = Generatable::random(&mut rng).unwrap();

        // p_2(p_1(input))
        let output_1 = key_2.permute(key_1.permute(input));

        // p_2(p_1)(input)
        let output_2 = key_2.permute(key_1).permute(input);

        assert_eq!(output_1, output_2);
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

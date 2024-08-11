use crate::{IsPermutable, PermutationKey};
use vitaminc_protected::{Paranoid, Protected};
use zeroize::Zeroize;

// TODO: Make this a private trait
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
            // TODO: Use MaybeUninit
            let out = self
                .iter()
                .enumerate()
                .fold([Default::default(); N], |mut out, (i, k)| {
                    out[i] = source[k.map(|x| Protected::from(x as usize))];
                    out
                });

            Protected::new(out)
        })
    }
}

pub trait Depermute<T> {
    fn depermute(&self, input: T) -> T;
}

impl<const N: usize, T> Depermute<Protected<[T; N]>> for PermutationKey<N>
where
    T: Zeroize + Default + Copy,
    [T; N]: IsPermutable,
{
    fn depermute(&self, input: Protected<[T; N]>) -> Protected<[T; N]> {
        input.map(|source| {
            // TODO: Use MaybeUninit
            let out = self
                .iter()
                .enumerate()
                .fold([Default::default(); N], |mut out, (i, k)| {
                    out[k.map(|x| Protected::from(x as usize))] = source[i];
                    out
                });

            Protected::new(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::tests;
    use crate::{Depermute, PermutationKey, Permute};
    use rand::SeedableRng;
    use vitaminc_protected::{Paranoid, Protected};
    use vitaminc_random::{Generatable, SafeRand};

    use super::IsPermutable;

    macro_rules! permutation_test {
        ($N:expr, $expected:expr) => {
            paste::item! {
                #[test]
                fn [< test_permutation_ $N >]() {
                    let input: Protected<[u8; $N]> = Protected::generate(tests::array_gen);
                    let key = tests::gen_key([0; 32]);
                    let output = key.permute(input);
                    assert_eq!(output.unwrap(), $expected);
                }

                #[test]
                fn [< test_associativity_ $N >]() {
                    let key_1 = tests::gen_key([0; 32]);
                    let key_2 = tests::gen_key([1; 32]);

                    // p_2(p_1(input))
                    let input: Protected<[u8; 8]> = Protected::generate(tests::array_gen);
                    let output_1 = key_2.permute(key_1.permute(input));

                    // p_2(p_1)(input)
                    // TODO: This extra input isn't needed (because COPY)
                    let input: Protected<[u8; 8]> = Protected::generate(tests::array_gen);
                    let output_2 = key_2.permute(key_1).permute(input);

                    assert_eq!(output_1.unwrap(), output_2.unwrap());
                }
            }
        };
    }

    // TODO: Change these to use functions instead
    permutation_test!(8, [3, 4, 6, 7, 8, 5, 1, 2]);
    permutation_test!(16, [13, 8, 4, 6, 9, 16, 12, 1, 5, 14, 15, 7, 11, 2, 3, 10]);
    permutation_test!(
        32,
        [
            13, 9, 28, 12, 22, 24, 1, 15, 26, 11, 27, 31, 30, 20, 21, 8, 17, 3, 25, 18, 10, 32, 7,
            29, 2, 14, 6, 16, 23, 4, 5, 19
        ]
    );

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
        assert_eq!(depermuted.unwrap(), input.unwrap());
    }

    #[test]
    fn depermutation_case() {
        test_depermute::<8>();
        test_depermute::<16>();
        test_depermute::<32>();
        test_depermute::<64>();
    }
}

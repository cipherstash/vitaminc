use protected::{Paranoid, Protected};
use crate::PermutationKey;

// TODO: Make this a private trait
pub trait Permute<T> {
    fn permute(&self, input: T) -> T;
}

impl<const N: usize> Permute<Protected<[u8; N]>> for PermutationKey<N>
where
Protected<[u8; N]>: ValidPermutationSize
{
    fn permute(&self, input: Protected<[u8; N]>) -> Protected<[u8; N]>
 {
        input.map(|source| {
            // TODO: Use MaybeUninit
            let out = self
                .iter()
                .enumerate()
                .fold([0; N], |mut out, (i, k)| {
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

impl<const N: usize> Depermute<Protected<[u8; N]>> for PermutationKey<N>
where
    Protected<[u8; N]>: ValidPermutationSize,
{
    fn depermute(&self, input: Protected<[u8; N]>) -> Protected<[u8; N]> {
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

trait ValidPermutationSize {}

impl ValidPermutationSize for Protected<[u8; 4]> {}
impl ValidPermutationSize for Protected<[u8; 8]> {}
impl ValidPermutationSize for Protected<[u8; 16]> {}
impl ValidPermutationSize for Protected<[u8; 32]> {}
impl ValidPermutationSize for Protected<[u8; 64]> {}

#[cfg(test)]
mod tests {
    use protected::{Paranoid, Protected};
    use rand::SeedableRng;
    use random::Generatable;
    use crate::{PermutationKey, Depermute, Permute};
    use crate::tests;

    use super::ValidPermutationSize;

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
    permutation_test!(4, [2, 4, 1, 3]);
    permutation_test!(8, [3, 4, 6, 7, 8, 5, 1, 2]);
    permutation_test!(16, [13, 8, 4, 6, 9, 16, 12, 1, 5, 14, 15, 7, 11, 2, 3, 10]);
    permutation_test!(32,
        [13, 9, 28, 12, 22, 24, 1, 15, 26, 11, 27, 31, 30, 20, 21, 8, 17, 3, 25, 18, 10, 32, 7, 29, 2, 14, 6, 16, 23, 4, 5, 19]
    );

    fn test_depermute<const N: usize>() where Protected<[u8; N]>: ValidPermutationSize {
        let mut rng = random::SafeRand::from_entropy();
        let input: Protected<[u8; N]> = Protected::generate(|| {
            Generatable::generate(&mut rng).unwrap()
        });
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

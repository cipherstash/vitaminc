use protected::{Paranoid, Protected};
use zeroize::Zeroize;
use crate::PermutationKey;

// TODO: Make this a private trait
pub trait Permute<T> {
    fn permute(&self, input: T) -> T;
}

impl<const N: usize, T> Permute<Protected<[T; N]>> for PermutationKey<N>
where
    T: Zeroize + Default + Copy,
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

#[cfg(test)]
mod tests {
    use protected::{Paranoid, Protected};
    use rand::SeedableRng;
    use random::Generatable;
    use crate::{PermutationKey, Permute};

    fn gen_key<const N: usize>(seed: [u8; 32]) -> PermutationKey<N> {
        let mut rng = random::SafeRand::from_seed(seed);
        PermutationKey::generate(&mut rng).expect("Failed to generate key")
    }

    fn array_gen<const N: usize>() -> [u8; N] {
        let mut input: [u8; N] = [0; N];
        input.iter_mut().enumerate().for_each(|(i, x)| {
            *x = (i + 1) as u8;
        });
        input
    }

    macro_rules! permutation_test {
        ($N:expr, $expected:expr) => {
            paste::item! {
                #[test]
                fn [< test_permutation_ $N >]() {
                    let input: Protected<[u8; $N]> = Protected::generate(array_gen);
                    let key = gen_key([0; 32]);
                    let output = key.permute(input);
                    assert_eq!(output.unwrap(), $expected);
                }

                #[test]
                fn [< test_associativity_ $N >]() {
                    let key_1 = gen_key([0; 32]);
                    let key_2 = gen_key([1; 32]);
            
                    // p_2(p_1(input))
                    let input: Protected<[u8; 8]> = Protected::generate(array_gen);
                    let output_1 = key_2.permute(key_1.permute(input));
            
                    // p_2(p_1)(input)
                    let input: Protected<[u8; 8]> = Protected::generate(array_gen);
                    let output_2 = key_2.permute(key_1).permute(input);
            
                    assert_eq!(output_1.unwrap(), output_2.unwrap());
                }
            }
        };
    }

    permutation_test!(4, [2, 4, 1, 3]);
    permutation_test!(8, [3, 4, 6, 7, 8, 5, 1, 2]);
    permutation_test!(16, [13, 8, 4, 6, 9, 16, 12, 1, 5, 14, 15, 7, 11, 2, 3, 10]);
    permutation_test!(32,
        [13, 9, 28, 12, 22, 24, 1, 15, 26, 11, 27, 31, 30, 20, 21, 8, 17, 3, 25, 18, 10, 32, 7, 29, 2, 14, 6, 16, 23, 4, 5, 19]
    );
}

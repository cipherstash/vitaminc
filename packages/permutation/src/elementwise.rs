use crate::{private::IsPermutable, PermutationKey};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use vitaminc_protected::{Controlled, Zeroed};
use zeroize::{Zeroize, Zeroizing};

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
    T: Zeroize + Default + Copy + ConditionallySelectable,
    [T; N]: IsPermutable + Zeroed,
{
    fn permute(&self, input: [T; N]) -> [T; N] {
        permute_array(self, input)
    }
}

impl<const N: usize, T> Depermute<[T; N]> for PermutationKey<N>
where
    T: Zeroize + Default + Copy + ConditionallySelectable,
    [T; N]: IsPermutable + Zeroed,
{
    fn depermute(&self, input: [T; N]) -> [T; N] {
        depermute_array(self, input)
    }
}

#[inline]
pub fn permute_array<const N: usize, T>(key: &PermutationKey<N>, input: [T; N]) -> [T; N]
where
    [T; N]: IsPermutable + Zeroed,
    T: Zeroize + Copy + ConditionallySelectable,
{
    // Key bytes are u8, so an `N > 256` permutation could never be expressed by
    // the key — and `(j as u8)` below would silently wrap, breaking the
    // ct_eq comparison. Surface the limit at compile time.
    const { assert!(N <= 256, "permutation length must fit in u8") };

    // Constant-time scan: for each output position `i`, the key byte `kv`
    // selects which input element to copy. We scan all `j` in 0..N and use
    // `ConditionallySelectable` so the access pattern is independent of `kv`,
    // preventing cache-line timing leaks of the secret key bytes. Secret
    // locals — including the partially-populated `out` — are wrapped in
    // `Zeroizing` so they are wiped on any unwind path.
    let input = Zeroizing::new(input);
    let mut out: Zeroizing<[T; N]> = Zeroizing::new(Zeroed::zeroed());
    for (i, k) in key.iter().enumerate() {
        let kv = Zeroizing::new(k.risky_unwrap());
        let mut selected = Zeroizing::new(input[0]);
        for (j, src) in input.iter().enumerate().skip(1) {
            let mask = (j as u8).ct_eq(&*kv);
            selected.conditional_assign(src, mask);
        }
        out[i] = *selected;
    }
    // Move the populated array out, leaving a fresh zeroed array for the
    // `Zeroizing` Drop to clean (a no-op wipe in the success path).
    core::mem::replace(&mut *out, Zeroed::zeroed())
}

#[inline]
pub fn depermute_array<const N: usize, T>(key: &PermutationKey<N>, input: [T; N]) -> [T; N]
where
    [T; N]: IsPermutable + Zeroed,
    T: Zeroize + Copy + ConditionallySelectable,
{
    // See `permute_array` — same u8-fit constraint applies here.
    const { assert!(N <= 256, "permutation length must fit in u8") };

    // Constant-time scatter: for each (i, kv), write `input[i]` to `out[kv]`
    // by scanning every output slot and conditionally assigning when `j == kv`.
    // Secret locals — including the partially-populated `out` — are wrapped
    // in `Zeroizing` for unwind safety.
    let input = Zeroizing::new(input);
    let mut out: Zeroizing<[T; N]> = Zeroizing::new(Zeroed::zeroed());
    for (i, k) in key.iter().enumerate() {
        let kv = Zeroizing::new(k.risky_unwrap());
        let src = Zeroizing::new(input[i]);
        for (j, dst) in out.iter_mut().enumerate() {
            let mask = (j as u8).ct_eq(&*kv);
            dst.conditional_assign(&*src, mask);
        }
    }
    core::mem::replace(&mut *out, Zeroed::zeroed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests;
    use crate::{Depermute, PermutationKey, Permute};
    use vitaminc_random::{Generatable, SafeRand};

    fn test_permute<const N: usize>() -> Result<(), Box<dyn std::error::Error>>
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let mut rng = SafeRand::from_entropy()?;
        let input: [u8; N] = Generatable::random(&mut rng)?;
        let key: PermutationKey<N> = tests::gen_rand_key()?;
        let output = key.permute(input);
        // Note that this may fail for some inputs
        assert_ne!(output, input);
        Ok(())
    }

    fn test_depermute<const N: usize>() -> Result<(), Box<dyn std::error::Error>>
    where
        [u8; N]: IsPermutable + Zeroed,
    {
        let mut rng = SafeRand::from_entropy()?;
        let input: [u8; N] = Generatable::random(&mut rng)?;
        let key: PermutationKey<N> = tests::gen_rand_key()?;
        let output = key.permute(input);
        let depermuted = key.depermute(output);
        assert_eq!(depermuted, input);
        Ok(())
    }

    fn test_associativity<const N: usize>() -> Result<(), Box<dyn std::error::Error>>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy()?;
        let key_1 = tests::gen_key([0; 32]);
        let key_2 = tests::gen_key([1; 32]);
        let input: [u8; N] = Generatable::random(&mut rng)?;

        // p_2(p_1(input))
        let output_1 = key_2.permute(key_1.permute(input));

        // p_2(p_1)(input)
        let output_2 = key_2.permute(key_1).permute(input);

        assert_eq!(output_1, output_2);
        Ok(())
    }

    #[test]
    fn permute_case() -> Result<(), Box<dyn std::error::Error>> {
        test_permute::<8>()?;
        test_permute::<16>()?;
        test_permute::<32>()?;
        test_permute::<64>()?;
        Ok(())
    }

    #[test]
    fn depermutation_case() -> Result<(), Box<dyn std::error::Error>> {
        test_depermute::<8>()?;
        test_depermute::<16>()?;
        test_depermute::<32>()?;
        test_depermute::<64>()?;
        Ok(())
    }

    #[test]
    fn associativity_case() -> Result<(), Box<dyn std::error::Error>> {
        test_associativity::<8>()?;
        test_associativity::<16>()?;
        test_associativity::<32>()?;
        test_associativity::<64>()?;
        Ok(())
    }
}

//! A library for permuting data in a secure and efficient manner.
//!
//! ## Warning
//!
//! This library is a low-level primitive designed to be used in cryptographic applications.
//! It is not recommended to use this library directly unless you are familiar with the underlying
//! cryptographic principles.
//!
//! ## Relationship to `vitaminc-protected`
//!
//! This library is designed to work with the `vitaminc-protected` library.
//! All inputs and outputs are wrapped in a `Protected` type which ensures that the data is correctly zeroized when it goes out of scope.
//!
//! ## Example: Permuting an array
//!
//! ```rust
//! use vitaminc_permutation::{Permute, PermutationKey};
//! use vitaminc_random::{Generatable, SafeRand, SeedableRng};
//! use vitaminc_protected::{Paranoid, Protected};
//! let mut rng = SafeRand::from_seed([0; 32]);
//! let key = PermutationKey::random(&mut rng).unwrap();
//! let input = Protected::new([1, 2, 3, 4, 5, 6, 7, 8]);
//! assert_eq!(key.permute(input).unwrap(), [5, 3, 6, 2, 4, 8, 1, 7]);
//! ```
//!
//! ## Bitwise Permutations
//!
//! The `BitwisePermute` trait is a low-level trait that allows for bitwise permutations.
//! This is useful for when you need to permute a single byte or a small number of bytes.
//!
//! ```rust
//! use vitaminc_permutation::{BitwisePermute, PermutationKey};
//! use vitaminc_protected::{Paranoid, Protected};
//! use vitaminc_random::{Generatable, SafeRand, SeedableRng};
//! let mut rng = SafeRand::from_seed([0; 32]);
//! let key = PermutationKey::random(&mut rng).unwrap();
//! let input: Protected<u32> = Protected::new(1000);
//! assert_eq!(key.bitwise_permute(input).unwrap(), 1082155265);
//! ```
//!
//! ## Permutations and Security
//!
//! As a quick primer (or refresher), a permutation is an array of numbers which “shuffles” an input.
//! Each element of the permutation says which element of the input should be output in that position.
//!
//! For example:
//!
//! ```plaintext
//! // Input array
//! X = [6, 7, 8, 9]
//! // Permutation
//! P = [2, 0, 3, 1]
//! // Permuted output
//! Y = [8, 6, 9, 7]
//! ```
//!
//! Because the first element of P is 2, we take the 2nd element (counting from 0) from X and place it in the output.
//! The next element, 6, comes from the 0th position and so on.
//!
//! This operation is often written as Y=P(X).
//!
//! Permutations like this are useful because there is a _super-exponential_ relationship between the size of the
//! permutation and the number of possible inputs that could have been processed by a given key.
//!
//! For example, a 3-element input X was permuted by a permutation P.
//! We don’t know X or P but we do know the output.
//!
//! Let’s say `Y=[2, 1, 0]`, the input could have been:
//!
//! ```plaintext
//! [0, 1, 2]
//! [0, 2, 1]
//! [1, 0, 2]
//! [1, 2, 0]
//! [2, 0, 1]
//! [2, 1, 0] // A permutation that does nothing
//! ```
//!
//! A permutation of N elements will have `N!` (factorial) possible values.
//! For N=16, the number of permutations is ~20 trillion.
//! For N=32, about 2x10^35. This number can be represented by about 117 bits (compare that to AES-128 which is 128-bits).
//!
//! A permutation is loosely analogous to an XOR operation.
//! In fact, XOR can be thought of a 1-bit (2-element) permutation operating on a 1-bit (2-element) input.
//! If the key is 1, the input bit is flipped, otherwise it isn’t.
//!
//! ```plaintext
//! Input | Key | Out
//! 0     |  0  | 0
//! 0     |  1  | 1
//! 1     |  0  | 1
//! 1     |  1  | 0
//! ```
//!
//! The XOR of a key with a plaintext has perfect security but if an attacker knows both the input and the output,
//! the key is trivial to recover (k=input^output).
//!
//! Despite this, XOR features heavily in modern cryptography and forms the basis of virtually all block-cipher modes.
//! These modes are designed to take advantage of the secret properties of XOR without creating a situation where
//! an input and output to an XOR is accessible to an attacker without a key.
//!
//! In a sense, permutations are the generalised version of XOR.
//! They too have perfect secrecy but, like XOR, if an attacker knows the input and output to a permutation,
//! the permutation itself is trivially recoverable.
//!
mod bitwise;
mod elementwise;
mod key;

pub use bitwise::BitwisePermute;
pub use elementwise::{Depermute, Permute};
pub use key::PermutationKey;
use vitaminc_protected::Protected;

/// Defines the identity permutation for a given type and length.
const fn identity<const N: usize, T>() -> Protected<[u8; N]>
where
    [T; N]: private::IsPermutable,
{
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = i as u8;
        i += 1;
    }
    Protected::new(out)
}

mod private {
    use std::num::{NonZeroU128, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8};
    pub trait IsPermutable {}

    impl IsPermutable for [u8; 8] {}
    impl IsPermutable for [u8; 16] {}
    impl IsPermutable for [u8; 32] {}
    impl IsPermutable for [u8; 64] {}
    impl IsPermutable for [u8; 128] {}
    impl IsPermutable for [u16; 8] {}
    impl IsPermutable for [u16; 16] {}
    impl IsPermutable for [u16; 32] {}
    impl IsPermutable for [u16; 64] {}
    impl IsPermutable for [u16; 128] {}
    impl IsPermutable for NonZeroU8 {}
    impl IsPermutable for NonZeroU16 {}
    impl IsPermutable for NonZeroU32 {}
    impl IsPermutable for NonZeroU64 {}
    impl IsPermutable for NonZeroU128 {}
    impl IsPermutable for u8 {}
    impl IsPermutable for u16 {}
    impl IsPermutable for u32 {}
    impl IsPermutable for u64 {}
    impl IsPermutable for u128 {}
}

#[cfg(test)]
mod tests {
    use super::private::IsPermutable;
    use crate::PermutationKey;
    use rand::SeedableRng;
    use vitaminc_random::{Generatable, SafeRand};

    pub fn gen_rand_key<const N: usize>() -> PermutationKey<N>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_entropy();
        PermutationKey::random(&mut rng).expect("Failed to generate key")
    }

    pub fn gen_key<const N: usize>(seed: [u8; 32]) -> PermutationKey<N>
    where
        [u8; N]: IsPermutable,
    {
        let mut rng = SafeRand::from_seed(seed);
        PermutationKey::random(&mut rng).expect("Failed to generate key")
    }
}

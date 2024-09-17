# Vitamin C Permutation

[![Crates.io](https://img.shields.io/crates/v/vitaminc-permutation.svg)](https://crates.io/crates/vitaminc-permutation)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A library for permuting data in a secure and efficient manner.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Warning

This library is a low-level primitive designed to be used in cryptographic applications.
It is not recommended to use this library directly unless you are familiar with the underlying
cryptographic principles.

### Relationship to `vitaminc-protected`

This library is designed to work with the `vitaminc-protected` library.

## Example: Permuting an array

```rust
use vitaminc_permutation::{Permute, PermutationKey};
use vitaminc_random::{Generatable, SafeRand, SeedableRng};
use vitaminc_protected::{Controlled, Protected};
let mut rng = SafeRand::from_seed([0; 32]);
let key = PermutationKey::random(&mut rng).expect("Random error");
let input: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
assert_eq!(key.permute(input), [5, 3, 6, 2, 4, 8, 1, 7]);
```

## Bitwise Permutations

The `BitwisePermute` trait is a low-level trait that allows for bitwise permutations.
This is useful for when you need to permute a single byte or a small number of bytes.

```rust
use vitaminc_permutation::{BitwisePermute, PermutationKey};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, SafeRand, SeedableRng};
let mut rng = SafeRand::from_seed([0; 32]);
let key = PermutationKey::random(&mut rng).expect("Random error");
let input: u32 = 1000;
assert_eq!(key.bitwise_permute(input), 1082155265);
```

## Permutations and Security

As a quick primer (or refresher), a permutation is an array of numbers which “shuffles” an input.
Each element of the permutation says which element of the input should be output in that position.

For example:

```plaintext
// Input array
X = [6, 7, 8, 9]
// Permutation
P = [2, 0, 3, 1]
// Permuted output
Y = [8, 6, 9, 7]
```

Because the first element of P is 2, we take the 2nd element (counting from 0) from X and place it in the output.
The next element, 6, comes from the 0th position and so on.

This operation is often written as Y=P(X).

Permutations like this are useful because there is a _super-exponential_ relationship between the size of the
permutation and the number of possible inputs that could have been processed by a given key.

For example, a 3-element input X was permuted by a permutation P.
We don’t know X or P but we do know the output.

Let’s say `Y=[2, 1, 0]`, the input could have been:

```plaintext
[0, 1, 2]
[0, 2, 1]
[1, 0, 2]
[1, 2, 0]
[2, 0, 1]
[2, 1, 0] // A permutation that does nothing
```

A permutation of N elements will have `N!` (factorial) possible values.
For N=16, the number of permutations is ~20 trillion.
For N=32, about 2x10^35. This number can be represented by about 117 bits (compare that to AES-128 which is 128-bits).

A permutation is loosely analogous to an XOR operation.
In fact, XOR can be thought of a 1-bit (2-element) permutation operating on a 1-bit (2-element) input.
If the key is 1, the input bit is flipped, otherwise it isn’t.

```plaintext
Input | Key | Out
0     |  0  | 0
0     |  1  | 1
1     |  0  | 1
1     |  1  | 0
```

The XOR of a key with a plaintext has perfect security but if an attacker knows both the input and the output,
the key is trivial to recover (k=input^output).

Despite this, XOR features heavily in modern cryptography and forms the basis of virtually all block-cipher modes.
These modes are designed to take advantage of the secret properties of XOR without creating a situation where
an input and output to an XOR is accessible to an attacker without a key.

In a sense, permutations are the generalised version of XOR.
They too have perfect secrecy but, like XOR, if an attacker knows the input and output to a permutation,
the permutation itself is trivially recoverable.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

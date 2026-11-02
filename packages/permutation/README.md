# Vitamin C Permutation

[![Crates.io](https://img.shields.io/crates/v/vitaminc-permutation.svg)](https://crates.io/crates/vitaminc-permutation)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A library for permuting data in a secure and efficient manner.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Installation

```sh
cargo add vitaminc-permutation
```

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
assert_eq!(key.permute(input), [4, 1, 5, 6, 8, 7, 2, 3]);
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
assert_eq!(key.bitwise_permute(input), 606208516);
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

There are `N!` possible permutations of `N` positions. A **uniformly random
permutation** selects each with probability `1 / N!`. This describes the
distribution of the shuffle, not the secrecy of the shuffled data.

This crate generates permutations by assigning random sort keys to positions and
sorting them through a fixed sorting network. If any sort keys collide, generation
fails with `RandomError::SeedRejected`; see [`PermutationKey::from_seed`] for
recovery. With independent, uniformly random sort keys, every position ordering is
equally likely conditional on no collision. In practice the randomness comes from
`SafeRand`, a seeded cryptographic pseudorandom generator, so its security also
depends on the seed and generator.

A position permutation preserves every element's value and the number of times it
appears. A bitwise permutation preserves the number of set bits (Hamming weight).
For example, every permutation of `[0, 0, 0, 0]` is unchanged, whereas every
permutation of `[0, 0, 0, 1]` still contains one `1`. An observer can distinguish
these inputs without knowing the permutation. Even a uniformly random shuffle
therefore does not provide perfect secrecy for arbitrary data.

If all inputs are rearrangements of one fixed, known collection, a fresh,
independent, uniformly random permutation can hide their original ordering. That
restricted guarantee does not extend to arbitrary inputs or reuse of a secret
permutation. When all input elements are distinct, a known input and its output
reveal the permutation; repeated elements leave ambiguity.

XOR changes bit values rather than moving bit positions. XOR encryption provides
perfect secrecy under the one-time-pad assumptions: a uniformly random,
independent secret pad as long as the message, used only once. Merely using a
secret XOR key or a secret position permutation does not provide that guarantee.

Use these permutations as building blocks in a cryptographic construction whose
security analysis accounts for the input domain, the information preserved by
permutation, and key reuse. They are not a standalone cipher for arbitrary values.

## Cargo features

This crate defines no Cargo feature flags.

## Compatibility

Requires Rust <!-- msrv:vitaminc-permutation -->**1.88.0**<!-- /msrv --> and the Rust standard library (`std`).
MSRV increases require a minor release; patch releases retain the existing
floor. See the [workspace compatibility policy](https://github.com/cipherstash/vitaminc#compatibility).

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

<!-- GitHub API links target the latest release; src/lib.rs resolves these for rustdoc. -->
[`PermutationKey::from_seed`]: https://docs.rs/vitaminc-permutation/latest/vitaminc_permutation/struct.PermutationKey.html#method.from_seed

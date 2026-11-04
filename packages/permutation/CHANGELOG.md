
## [0.9.0] - 2026-11-04

### Breaking

- **Breaking:** `PermutationKey::new_unchecked` is removed. Use `PermutationKey::new(Protected::new(bytes))` instead. It returns a `Result`, refuses bytes that are not a permutation with `NotAPermutation`, and wipes the container it is given.
- **Breaking:** `PermutationKey<N>` no longer implements `Zeroize`. Zeroizing a key left a live key of all zeros, which is not a permutation. Dropping a key wipes it. As a result, a key cannot be held in `Protected`, in `Zeroizing`, or in a struct that derives `Zeroize`.
- **Breaking:** `PermutationKey<N>` implements `Deserialize` only for supported key sizes. Deserializing an unsupported size is now a compile error.
- **Breaking:** the minimum supported Rust version is now 1.89. 0.8.1 declared 1.88.

### Fixes

- Deserializing a key now checks, in constant time, that it holds each of `0..N` exactly once. A key that fails the check is refused, and the error does not include its bytes.
  Before, a key with a repeated or out-of-range index was accepted. A `NonZero` permutation through such a key could produce zero, which is undefined behavior from safe code.
  The serialized format is unchanged, and every valid key still deserializes. The crate no longer contains `unsafe` code.

## [0.8.1] - 2026-10-26

## [0.8.0] - 2026-10-21

## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** replace rejection sampling with fixed-count Lemire draw ([#281](https://github.com/cipherstash/vitaminc/pull/281))
- **Breaking:** oblivious key generation via sort-by-random-key ([#282](https://github.com/cipherstash/vitaminc/pull/282))

### Features

- batch key derivation API (plan step 1) ([#283](https://github.com/cipherstash/vitaminc/pull/283))

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** `PermutationKey` is no longer `Copy` — it wraps a secret that now zeroizes on drop, and a bitwise copy would leave un-wiped duplicates. Use `Clone` where a copy is needed.



### Fixes

- close cache-timing side-channel in permute_array
- wrap secret locals in Zeroizing for unwind safety
- assert N <= 256 and zeroize partially-populated output
- make bitwise_permute constant-time

### Testing

- strengthen bitwise_permute coverage


### Documentation

- update doctests to show vitaminc::* import paths


### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- update codebase for rand 0.9 breaking changes

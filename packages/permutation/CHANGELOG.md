
## [0.9.1] - 2026-11-06

## [0.9.0] - 2026-11-04

### Breaking

- **Breaking:** `PermutationKey::new_unchecked` is removed.
  Use `PermutationKey::new(Protected::new(bytes))` instead.
  The new function returns a `Result`, and refuses bytes that are not a permutation with `NotAPermutation`.
  The function also wipes the container you pass to it.
- **Breaking:** `PermutationKey<N>` no longer implements `Zeroize`.
  Zeroizing a key left a usable key of all zeros.
  A key of all zeros is not a permutation.
  Dropping a key still wipes it.
  As a result, you cannot put a key in `Protected`, in `Zeroizing`, or in a struct that derives `Zeroize`.
- **Breaking:** `PermutationKey<N>` implements `Deserialize` only for the key sizes that this crate supports.
  Deserializing a key of another size is now a compile error.
- **Breaking:** the crate now needs Rust 1.89 or later.
  Version 0.8.1 needed Rust 1.88.

### Fixes

- Deserialization now checks, in constant time, that a key contains each index below `N` exactly once.
  The error for a key that fails the check does not include the key's bytes.
  In 0.8.1, deserializing accepted a key with a repeated or out-of-range index.
  With such a key, permuting a `NonZero` value could produce zero.
  A `NonZero` value of zero is undefined behavior, reached from safe code.
  The serialized format is unchanged, and every valid key still deserializes.
  The crate no longer contains `unsafe` code.

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


## [0.9.0] - 2026-11-04

### Breaking

- **Breaking:** `Password::new` is removed.
  To keep an existing secret, wrap the secret in `Protected::new` instead.
- **Breaking:** each password type now has a minimum length, and the compiler checks it.
  `Password<N>` needs at least 20 characters.
  `AlphaNumericPassword<N>` needs at least 22 characters.
  `AlphaPassword<N>` needs at least 23 characters.
  Each minimum gives more than 128 bits of entropy.
  The minimums also apply when you generate a password with your own random number generator.
  If your code uses a shorter length, increase the length, because a shorter length no longer compiles.
- **Breaking:** the crate now needs Rust 1.89 or later.
  Version 0.8.1 needed Rust 1.88.

### Features

- The new `generate()` function on each password type makes a password of the minimum length.
  The function uses randomness from the operating system, and returns `Result<_, RandomError>`.
- The new `len()` and `is_empty()` methods report the length of a password without reading its characters.
- This crate now re-exports `Protected` and `RandomError`, so you need only this crate to generate a password.
- The `vitaminc` crate now exposes this crate as `vitaminc::password`, behind its `password` feature.

### Fixes

- `into_protected_string()` now works.
  In 0.8.1, the method panicked with `unimplemented!`.
  The conversion wipes the original characters.
  The returned string is wiped when it is dropped.

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

### Documentation

- qualify "uniform" with the reduction's bias bound
- state the bounded draw's bias bound in the README

### Fixes

- correct the bias ceiling and the claims around it

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

### Documentation

- README and rustdoc corrected; SECURITY.md added.





### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- update codebase for rand 0.9 breaking changes


## [0.9.0] - 2026-11-04

### Breaking

- **Breaking:** `Password::new` is removed. To keep an existing secret, wrap it in `Protected::new`.
- **Breaking:** each password type now has a minimum length, checked at compile time. `Password<N>` needs at least 20 characters, `AlphaNumericPassword<N>` at least 22, and `AlphaPassword<N>` at least 23. Each minimum gives more than 128 bits of entropy. The minimums also apply to generation with an RNG you supply. A shorter `N` fails to compile, so use a longer length.
- **Breaking:** the minimum supported Rust version is now 1.89. 0.8.1 declared 1.88.

### Features

- `generate()` on `Password`, `AlphaNumericPassword` and `AlphaPassword` makes a password of the minimum length from operating system entropy, and returns `Result<_, RandomError>`.
- `len()` and `is_empty()` report a password's length without reading its characters.
- The crate re-exports `Protected` and `RandomError`, so generating a password needs only this crate.
- The `vitaminc` facade exposes the crate as `vitaminc::password`.

### Fixes

- `into_protected_string()` works. In 0.8.1 it panicked with `unimplemented!`. The conversion wipes the original characters, and the returned string is wiped on drop.

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

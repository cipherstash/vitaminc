# Changelog

All notable changes to the `vitaminc-random` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** replace rejection sampling with fixed-count Lemire draw ([#281](https://github.com/cipherstash/vitaminc/pull/281))
- **Breaking:** oblivious key generation via sort-by-random-key ([#282](https://github.com/cipherstash/vitaminc/pull/282))
- **Breaking:** make a secret bound total with `Protected<NonZeroU32>`
- **Breaking:** draw `NonZeroU16` with one bounded call, not an in-stream retry

### Documentation

- qualify "uniform" with the reduction's bias bound

### Features

- batch key derivation API (plan step 1) ([#283](https://github.com/cipherstash/vitaminc/pull/283))

### Fixes

- correct the bias ceiling and the claims around it
- the NonZeroU16 draw's distance is just under 2⁻⁶⁴, not exactly

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** `Generatable` impls for `Protected`/`Equatable`/`Exportable` now require `T: Zeroize`, matching the wrappers' zeroize-on-drop guarantee; generic callers may need the added bound.



### Features

- add wasm32 support via RustCrypto backend


### Documentation

- update doctests to show vitaminc::* import paths


### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- update codebase for rand 0.9 breaking changes

### Changed

- Upgraded `rand` from 0.8 to 0.9 and `rand_chacha` from 0.3 to 0.9.
- `RngCore` impl for `SafeRand` no longer includes `try_fill_bytes` (removed from trait in rand 0.9).
- `Generatable` impls now use infallible `fill` instead of `try_fill`.
- `Generatable` impls for integer primitives use `Rng::random()` instead of deprecated `Rng::gen()`.

### Added

- `SafeRand::from_entropy()` convenience method (wraps `SeedableRng::from_os_rng()` which replaced `from_entropy` in rand 0.9). Callers no longer need to import `SeedableRng` to use this method.

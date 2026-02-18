# Changelog

All notable changes to the `vitaminc-random` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]


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

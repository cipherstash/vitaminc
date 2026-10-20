
## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.
- **Breaking:** `Context::for_none` is removed. `vitaminc-aead` 0.6 encrypts `None` as a null leaf, so there is no absence marker left to derive. Every other derivation produces the same bytes as in 0.5.1.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

### Fixes

- an encoded context proves nothing about emptiness

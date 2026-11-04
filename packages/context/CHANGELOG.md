
## [0.9.0] - 2026-11-04

### Breaking

- **Breaking:** the minimum supported Rust version is now 1.89. 0.8.1 declared 1.88.

### Not guaranteed

- The docs now say what a context does not bind. A map's context binds each entry's key, but not which entries the map holds. A sequence's context binds neither an element's index nor the sequence's length. Rows come back from a database in any order, and some columns may be missing. See ADR 0002.

## [0.8.1] - 2026-10-26

## [0.8.0] - 2026-10-21

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

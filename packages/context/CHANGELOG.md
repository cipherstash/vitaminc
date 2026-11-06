
## [0.9.1] - 2026-11-06

## [0.9.0] - 2026-11-04

### Breaking

- **Breaking:** the crate now needs Rust 1.89 or later.
  Version 0.8.1 needed Rust 1.88.

### What is not authenticated

- The documentation now says what a context does not bind.
  For a map, the context binds each entry's key, but not which entries the map contains.
  For a sequence, the context binds neither the index of an element nor the length of the sequence.
  A database returns rows in any order, and a query can read some columns and not others.
  Architecture decision record (ADR) 0002 explains this design.

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

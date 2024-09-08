# Vitamin C Random

[![Crates.io](https://img.shields.io/crates/v/vitaminc-random.svg)](https://crates.io/crates/vitaminc-random)
[![Workflow Status](https://github.com/cipherstash/vitaminc/workflows/main/badge.svg)](https://github.com/cipherstash/vitaminc/actions?query=workflow%3A%22main%22)

A carefully designed random number generator that is safe to use for cryptographic purposes.

## Bounded Random Numbers

The `BoundedRng` trait provides a way to generate random numbers within a specific range.

```rust
use vitaminc_random::{BoundedRng, SafeRand, SeedableRng};

let mut rng = SafeRand::from_entropy();
let value: u32 = rng.next_bounded(10);
assert!(value <= 10);
```

Or using a `Protected` value:

```rust
use vitaminc_protected::{Protect, Protected, ProtectNew};
use vitaminc_random::{BoundedRng, SafeRand, SeedableRng};

let mut rng = SafeRand::from_entropy();
let value: Protected<u32> = rng.next_bounded(Protected::new(10));
assert!(value.risky_unwrap() <= 10);
```

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

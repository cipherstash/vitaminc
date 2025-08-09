# Vitamin C Random

[![Crates.io](https://img.shields.io/crates/v/vitaminc-random.svg)](https://crates.io/crates/vitaminc-random)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A carefully designed random number generator that is safe to use for cryptographic purposes.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Generatable

Types implementing the [`Generatable`] trait can be generated randomly using [`SafeRand`].

```rust
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

let mut rng = SafeRand::from_entropy();
let x: [u8; 32] = Generatable::random(&mut rng).unwrap();
```

You can implement `Generatable` for your own types using the derive macro:

```rust
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

#[derive(Generatable)]
struct MyStruct {
    id: u32,
    key: [u8; 16],
}

// Create a random number generator and generate an instance of MyStruct.
let mut rng = vitaminc_random::SafeRand::from_entropy();
let instance: MyStruct = Generatable::random(&mut rng).unwrap();
println!("Generated id: {}", instance.id);
```

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
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{BoundedRng, SafeRand, SeedableRng};

let mut rng = SafeRand::from_entropy();
let value: Protected<u32> = rng.next_bounded(Protected::new(10));
assert!(value.risky_unwrap() <= 10);
```

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

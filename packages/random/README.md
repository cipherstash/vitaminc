# Vitamin C Random

[![Crates.io](https://img.shields.io/crates/v/vitaminc-random.svg)](https://crates.io/crates/vitaminc-random)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A carefully designed random number generator that is safe to use for cryptographic purposes.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Generatable

Types implementing the [`Generatable`] trait can be generated randomly using [`SafeRand`].

```rust
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
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
let mut rng = vitaminc_random::SafeRand::from_entropy().expect("Failed to seed RNG");
let instance: MyStruct = Generatable::random(&mut rng).unwrap();
println!("Generated id: {}", instance.id);
```

## Bounded Random Numbers

`SafeRand::next_below(n)` returns a value in `0..n`, the bound every index-shaped use
wants. It makes exactly one 64-bit draw per call, reduced with Lemire's multiply-high
method, so the number of draws does not depend on the values drawn. The reduction's
statistical distance from uniform is at most `n / 2⁶⁴`; a protocol that needs exact
uniformity must account for that term.

```rust
use vitaminc_random::{SafeRand, SeedableRng};

let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
let index = rng.next_below(10);
assert!(index < 10);
```

The bound may also be a `Protected<u32>`, in which case the result is `Protected` too:

```rust
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{SafeRand, SeedableRng};

let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
let index: Protected<u32> = rng.next_below(Protected::new(10));
assert!(index.risky_unwrap() < 10);
```

Both are the `BoundedRng::next_below` trait method. The older **inclusive** form,
`next_bounded(max)` for `0..=max`, lives on the separate, deprecated `BoundedRngInclusive`
trait and on `SafeRand::next_bounded_u32`; both are deprecated in favour of
`next_below(max + 1)`.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

# Vitamin C Random

[![Crates.io](https://img.shields.io/crates/v/vitaminc-random.svg)](https://crates.io/crates/vitaminc-random)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A carefully designed random number generator that is safe to use for cryptographic purposes.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Installation

<!-- workspace-deps:start -->
```toml
[dependencies]
vitaminc-random = "0.8.1"
```

The examples using `Protected` also require `vitaminc-protected = "0.8.1"`
under `[dependencies]`.
<!-- workspace-deps:end -->

## WebAssembly

For a JavaScript host, use the `wasm32-unknown-unknown` target:

```sh
rustup target add wasm32-unknown-unknown
cargo check --target wasm32-unknown-unknown
```

This crate enables `getrandom` 0.4's `wasm_js` feature on wasm32. That feature
selects the JavaScript entropy backend automatically on `wasm32-unknown-unknown`;
consumers need no extra feature, direct `getrandom` dependency, or
`getrandom_backend="wasm_js"` rustflag. The explicit flag was required by
`getrandom` 0.3.0–0.3.3; dependencies still using those older versions may have
their own configuration requirements.

At runtime, the backend calls `crypto.getRandomValues` through `wasm-bindgen`.
Package the application with `wasm-bindgen` or `wasm-pack` and load its generated
JavaScript glue in a browser, worker, or Node.js 19 or later. A compilation check
does not generate the glue or verify the host's entropy source. See
[getrandom's WebAssembly support](https://docs.rs/getrandom/0.4.3/getrandom/#webassembly-support).

For WASI hosts, use a WASI target such as `wasm32-wasip1`. On that target,
`getrandom` uses the host's WASI randomness interface rather than JavaScript,
even though the `wasm_js` feature is enabled. No JavaScript glue is needed.

## Generatable

Types implementing the [`Generatable`] trait can be generated randomly using [`SafeRand`].

```rust
use vitaminc_random::{Generatable, SafeRand};

let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
let x: [u8; 32] = Generatable::random(&mut rng).unwrap();
```

You can implement `Generatable` for your own types using the derive macro:

```rust
use vitaminc_random::{Generatable, SafeRand};

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
use vitaminc_random::SafeRand;

let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
let index = rng.next_below(10);
assert!(index < 10);
```

The bound may also be a `Protected<u32>`, in which case the result is `Protected` too:

```rust
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::SafeRand;

let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
let index: Protected<u32> = rng.next_below(Protected::new(10));
assert!(index.risky_unwrap() < 10);
```

A `Protected<u32>` bound of zero panics, and that panic is observable on the secret. When
a secret bound might be zero, check it once at construction and pass a
`Protected<NonZeroU32>`; that form never panics:

```rust
use std::num::NonZeroU32;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::SafeRand;

let mut rng = SafeRand::from_entropy().expect("Failed to seed RNG");
let bound = Protected::new(NonZeroU32::new(10).expect("non-zero"));
let index: Protected<u32> = rng.next_below(bound);
assert!(index.risky_unwrap() < 10);
```

All three are the `BoundedRng::next_below` trait method. The older **inclusive** form,
`next_bounded(max)` for `0..=max`, lives on the separate, deprecated `BoundedRngInclusive`
trait and on `SafeRand::next_bounded_u32`; both are deprecated in favour of
`next_below(max + 1)`.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

# Vitamin C Traits

[![Crates.io](https://img.shields.io/crates/v/vitaminc-traits.svg)](https://crates.io/crates/vitaminc-traits)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

This crate provides traits for hashing and encryption algorithms.
These are very similar to the traits provided by the `digest` and other crates in the RustCrypto project
with some key differences:

* The `Update` trait takes a specific input type. This allows us to reason about the input type and its sensitivity.
* The `Output` traits are generic over the output type. This allows us to reason about the output type and its sensitivity.
* Protected output types can implement `OutputSize` through the [Controlled] bound.
* `const` generics are used to specify the output size of the hash instead of GenericArray.

Async versions of some of these traits are provided in the `async-traits` crate.

## Installation

```sh
cargo add vitaminc-traits vitaminc-protected
```

## Adapting a digest

This example adapts SHA-256 to `Update` and `FixedOutput`. Inputs and outputs
use `Protected`, and `ProtectedDigest` holds the digest state. In addition to
`vitaminc-traits` and `vitaminc-protected`, add `sha2` with its `zeroize` feature
(`cargo add sha2 --features zeroize`).

```rust
use vitaminc_protected::{Controlled, Protected, ProtectedDigest};
use vitaminc_traits::{FixedOutput, Update};

struct Sha256(ProtectedDigest<sha2::Sha256>);

impl Update<&Protected<Vec<u8>>> for Sha256 {
    fn update(&mut self, input: &Protected<Vec<u8>>) {
        self.0.update(input);
    }
}

impl FixedOutput<32, Protected<[u8; 32]>> for Sha256 {
    fn finalize_into(self, output: &mut Protected<[u8; 32]>) {
        self.0.finalize_into(output);
    }
}

let input = Protected::new(b"abc".to_vec());
let digest = Sha256(ProtectedDigest::new()).chain(&input).finalize_fixed();

// SHA-256 of the public test input "abc".
assert_eq!(digest.risky_ref(), &[
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
]);
```

## Cargo features

This crate defines no Cargo feature flags.

## Compatibility

Requires Rust **1.88.0** and the Rust standard library (`std`).
MSRV increases require a minor release; patch releases retain the existing
floor. See the [workspace compatibility policy](https://github.com/cipherstash/vitaminc#compatibility).

## Acknowledgements

Shoutout to Tony Arcieri, Artyom Pavlov and all the contributors to the Rust Crypto project which was the inspiration for this crate.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

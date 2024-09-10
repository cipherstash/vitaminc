# Vitamin C Traits

[![Crates.io](https://img.shields.io/crates/v/vitaminc-traits.svg)](https://crates.io/crates/vitaminc-traits)
[![Workflow Status](https://github.com/cipherstash/vitaminc/workflows/main/badge.svg)](https://github.com/cipherstash/vitaminc/actions?query=workflow%3A%22main%22)

This crate provides traits for hashing and encryption algorithms.
These are very similar to the traits provided by the `digest` and other crates in the RustCrypto project
with some key differences:

* The `Update` trait takes a specific input type. This allows us to reason about the input type and its sensitivity.
* The `Output` traits are generic over the output type. This allows us to reason about the output type and its sensitivity.
* All types have a trait bound of [Controlled]
* `const` generics are used to specify the output size of the hash instead of GenericArray.

Async versions of some of these traits are provided in the `async-traits` crate.

## Acknowledgements

Shoutout to Tony Arcieri, Artyom Pavlov and all the contributors to the Rust Crypto project which was the inspiration for this crate.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT
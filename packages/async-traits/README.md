# Vitamin C Async Traits

[![Crates.io](https://img.shields.io/crates/v/vitaminc-async-traits.svg)](https://crates.io/crates/vitaminc-async-traits)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

Async versions of the Vitamin C cryptographic traits — e.g. fixed-output hashing and MAC finalisation for backends that are inherently asynchronous (such as AWS KMS).

This is the companion crate to [`vitaminc-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/traits) and offers
`async` versions of some of the traits defined there.

For example, [AsyncFixedOutputReset], the async version of `FixedOutputReset`, is used to implement HMAC using Amazon's KMS.
See [`vitaminc-kms`](https://github.com/cipherstash/vitaminc/tree/main/packages/kms).

For a runnable example without a network service or async runtime, see
[`AsyncFixedOutput`](https://docs.rs/vitaminc-async-traits/latest/vitaminc_async_traits/trait.AsyncFixedOutput.html).
It adapts a prepared protected result to the trait, polls the future, and
checks the returned bytes. For an AWS-backed example, see the
[KMS setup guide](https://docs.rs/vitaminc-kms).

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Installation

```sh
cargo add vitaminc-async-traits
```

## Cargo features

This crate defines no Cargo feature flags.

## Compatibility

Requires Rust <!-- msrv:vitaminc-async-traits -->**1.88.0**<!-- /msrv --> and the Rust standard library (`std`).
MSRV increases require a minor release; patch releases retain the existing
floor. See the [workspace compatibility policy](https://github.com/cipherstash/vitaminc#compatibility).

## Acknowledgements

Shoutout to [Tony Arcieri](https://github.com/tarcieri), [Artyom Pavlov](https://github.com/newpavlov) and all the contributors to the [Rust Crypto](https://github.com/RustCrypto) project which was the inspiration for this crate.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

# Vitamin C Async Traits

[![Crates.io](https://img.shields.io/crates/v/vitaminc-async-traits.svg)](https://crates.io/crates/vitaminc-async-traits)
[![Workflow Status](https://github.com/cipherstash/vitaminc/workflows/main/badge.svg)](https://github.com/cipherstash/vitaminc/actions?query=workflow%3A%22main%22)

This is the companion crate to [`vitaminc-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/traits) and offers
`async` versions of some of the traits defined there.

For example, [AsyncFixedOutputReset], the async version of `FixedOutputReset`, is used to implement HMAC using Amazon's KMS.
See [`vitaminc-kms`](https://github.com/cipherstash/vitaminc/tree/main/packages/kms).

## Acknowledgements

Shoutout to Tony Arcieri, Artyom Pavlov and all the contributors to the Rust Crypto project which was the inspiration for this crate.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT
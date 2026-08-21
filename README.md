<!-- TODO: Logo -->
# Vitamin C

Vitamin C is like vitamins for your Rust code, especially code dealing with cryptography and managing sensitive data.
It is actually a suite of crates that you can use individually or via this top-level crate via features.

Vitamin C is in active development and aims to address the following:

* **Misuse Resistance:** it aims to make it difficult to write code that is insecure.

* **Verified**: be verified using formal methods and testing and selects dependencies that are verified.

* **Vetted**: be vetted by security experts and selects dependencies that are vetted.

* **Minimal**: be minimal and only include what is necessary.

* **Consistent**: have a consistent interface with everything in one place.

* **Compatible**: support embedded (`no_std`) and WASM targets.

* **Fast**: speed and security _can_ be friends!

## Usage

You can install the top-level `vitaminc` crate and enable specific features:

```plaintext
cargo add vitaminc --features protected,random
```

Or, if you only need a specific capability, you can install a crate directly:

```plaintext
cargo add vitaminc-protected
```

## Testing

Prerequisites:

* [localstack](https://github.com/localstack/localstack) is installed

To run the tests:

* Start localstack (typically done by running `localstack start` from the shell)
* `cargo test`


# Features and sub-crates

| Feature      | Source            | Crates.io                                                                                              | Documentation |
|--------------|------------------|--------------------------------------------------------------------------------------------------------|---------------|
| `aead`  | [`vitaminc-aead`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead) | [![crates.io](https://img.shields.io/crates/v/vitaminc-aead.svg)](https://crates.io/crates/vitaminc-aead) | [![docs.rs](https://docs.rs/vitaminc-aead/badge.svg)](https://docs.rs/vitaminc-aead) |
| `async-traits`  | [`vitaminc-async-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/async-traits) | [![crates.io](https://img.shields.io/crates/v/vitaminc-async-traits.svg)](https://crates.io/crates/vitaminc-async-traits) | [![docs.rs](https://docs.rs/vitaminc-async-traits/badge.svg)](https://docs.rs/vitaminc-async-traits) |
| `encrypt`  | [`vitaminc-encrypt`](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt) | [![crates.io](https://img.shields.io/crates/v/vitaminc-encrypt.svg)](https://crates.io/crates/vitaminc-encrypt) | [![docs.rs](https://docs.rs/vitaminc-encrypt/badge.svg)](https://docs.rs/vitaminc-encrypt) |
| `hmac`  | [`vitaminc-hmac`](https://github.com/cipherstash/vitaminc/tree/main/packages/hmac) | [![crates.io](https://img.shields.io/crates/v/vitaminc-hmac.svg)](https://crates.io/crates/vitaminc-hmac) | [![docs.rs](https://docs.rs/vitaminc-hmac/badge.svg)](https://docs.rs/vitaminc-hmac) |
| `aws-kms`  | [`vitaminc-kms`](https://github.com/cipherstash/vitaminc/tree/main/packages/kms) | [![crates.io](https://img.shields.io/crates/v/vitaminc-kms.svg)](https://crates.io/crates/vitaminc-kms) | [![docs.rs](https://docs.rs/vitaminc-kms/badge.svg)](https://docs.rs/vitaminc-kms) |
| —¹  | [`vitaminc-password`](https://github.com/cipherstash/vitaminc/tree/main/packages/password) | [![crates.io](https://img.shields.io/crates/v/vitaminc-password.svg)](https://crates.io/crates/vitaminc-password) | [![docs.rs](https://docs.rs/vitaminc-password/badge.svg)](https://docs.rs/vitaminc-password) |
| `permutation`  | [`vitaminc-permutation`](https://github.com/cipherstash/vitaminc/tree/main/packages/permutation) | [![crates.io](https://img.shields.io/crates/v/vitaminc-permutation.svg)](https://crates.io/crates/vitaminc-permutation) | [![docs.rs](https://docs.rs/vitaminc-permutation/badge.svg)](https://docs.rs/vitaminc-permutation) |
| `prf`  | [`vitaminc-prf`](https://github.com/cipherstash/vitaminc/tree/main/packages/prf) | [![crates.io](https://img.shields.io/crates/v/vitaminc-prf.svg)](https://crates.io/crates/vitaminc-prf) | [![docs.rs](https://docs.rs/vitaminc-prf/badge.svg)](https://docs.rs/vitaminc-prf) |
| `protected`  | [`vitaminc-protected`](https://github.com/cipherstash/vitaminc/tree/main/packages/protected) | [![crates.io](https://img.shields.io/crates/v/vitaminc-protected.svg)](https://crates.io/crates/vitaminc-protected) | [![docs.rs](https://docs.rs/vitaminc-protected/badge.svg)](https://docs.rs/vitaminc-protected) |
| `random`  | [`vitaminc-random`](https://github.com/cipherstash/vitaminc/tree/main/packages/random) | [![crates.io](https://img.shields.io/crates/v/vitaminc-random.svg)](https://crates.io/crates/vitaminc-random) | [![docs.rs](https://docs.rs/vitaminc-random/badge.svg)](https://docs.rs/vitaminc-random) |
| `traits`  | [`vitaminc-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/traits) | [![crates.io](https://img.shields.io/crates/v/vitaminc-traits.svg)](https://crates.io/crates/vitaminc-traits) | [![docs.rs](https://docs.rs/vitaminc-traits/badge.svg)](https://docs.rs/vitaminc-traits) |

¹ `vitaminc-password` is not currently exposed as a `vitaminc` facade feature — depend on the crate directly.

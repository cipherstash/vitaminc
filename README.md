TODO: Logo

# VitaminC

VitaminC is like vitamins for your Rust code, especially code dealing with cryptography and managing sensitive data.
It is actually a suite of crates that you can use individually or via this top-level crate via features.

VitaminC is in active development and aims to address the following:

* **Misuse Resistance:** VitaminC aims to make it difficult to write code that is insecure.
* **Verified**: VitaminC will be verified using formal methods and testing and selects dependencies that are verified.
* **Vetted**: VitaminC will be vetted by security experts and selects dependencies that are vetted.
* **Minimal**: VitaminC will be minimal and only include what is necessary.
* **Consistent**: VitaminC should have a consistent interface with everything in one place.
* **Compatible**: VitaminC will support embedded (`no_std`) and WASM targets.
* **Fast**: Speed and security _can_ be friends!

## Usage

You can install the top-level `vitaminc` crate and enable specific features:

```plaintext
cargo add vitaminc --features protected,random
```

Or, if you only need a specific capability, you can install a crate directly:

```plaintext
cargo add vitaminc-protected
```

# Features and sub-crates

| Feature      | Crate            | Crates.io                                                                                              | Documentation |
|--------------|------------------|--------------------------------------------------------------------------------------------------------|---------------|
| `protected`  | [`vitaminc-protected`] | [![crates.io](https://img.shields.io/crates/v/vitaminc-protected.svg)](https://crates.io/crates/vitaminc-protected) | [![docs.rs](https://docs.rs/vitaminc-protected/badge.svg)](https://docs.rs/vitaminc-protected) |
| `permutation`  | [`vitaminc-permutation`] | [![crates.io](https://img.shields.io/crates/v/vitaminc-permutation.svg)](https://crates.io/crates/vitaminc-permutation) | [![docs.rs](https://docs.rs/vitaminc-permutation/badge.svg)](https://docs.rs/vitaminc-permutation) |
| `random`  | [`vitaminc-random`] | [![crates.io](https://img.shields.io/crates/v/vitaminc-random.svg)](https://crates.io/crates/vitaminc-random) | [![docs.rs](https://docs.rs/vitaminc-random/badge.svg)](https://docs.rs/vitaminc-random) |


[//]: # (crates)

[vitaminc-permutation]: ./packages/permutation/
[vitaminc-protected]: ./packages/protected/
[vitaminc-random]: ./packages/random/
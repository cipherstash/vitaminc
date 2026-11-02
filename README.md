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

* **Compatible**: support native and WebAssembly applications, with embedded
  (`no_std`) support as a future goal. All crates currently require `std`.

* **Fast**: speed and security _can_ be friends!

## Which crate should I use?

| I want to… | Start with |
| --- | --- |
| Encrypt and decrypt Rust values with AES-256-GCM | [`vitaminc-encrypt`](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt) |
| Keep sensitive values out of debug output and wipe them on drop | [`vitaminc-protected`](https://github.com/cipherstash/vitaminc/tree/main/packages/protected) |
| Generate cryptographic randomness | [`vitaminc-random`](https://github.com/cipherstash/vitaminc/tree/main/packages/random) |
| Describe structured values or implement an encryption backend | [`vitaminc-aead`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead), with [`vitaminc-context`](https://github.com/cipherstash/vitaminc/tree/main/packages/context) for associated data |
| Derive pseudorandom values or equality-index terms | [`vitaminc-prf`](https://github.com/cipherstash/vitaminc/tree/main/packages/prf) for the interfaces, [`vitaminc-hmac`](https://github.com/cipherstash/vitaminc/tree/main/packages/hmac) for HMAC-SHA256, and [`vitaminc-normalize`](https://github.com/cipherstash/vitaminc/tree/main/packages/normalize) for equality encodings |
| Integrate an order-revealing encryption scheme | [`vitaminc-ore`](https://github.com/cipherstash/vitaminc/tree/main/packages/ore) for terms and scheme interfaces; supply an ORE backend |
| Implement a hash/MAC adapter, including a remote provider | [`vitaminc-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/traits) and [`vitaminc-async-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/async-traits); [`vitaminc-kms`](https://github.com/cipherstash/vitaminc/tree/main/packages/kms) supplies AWS KMS HMAC |
| Exchange encoded values across a language boundary, or store versioned blobs | [`vitaminc-aead-frame`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-frame); read its [storage contract](https://github.com/cipherstash/vitaminc/blob/main/packages/aead-frame/STORAGE.md) before persisting data |
| Build a native Node.js addon | [`vitaminc-aead-napi`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-napi); this is a Rust library for addons, not an npm package |

The facade's features expose most of these crates. `vitaminc-aead-frame` and
`vitaminc-aead-napi` are direct dependencies. Indexes reveal information about
values; read the normalization and ORE guides before choosing an index.

## Usage

You can install the top-level `vitaminc` crate and enable specific features:

```plaintext
cargo add vitaminc --features protected,random
```

Or, if you only need a specific capability, you can install a crate directly:

```plaintext
cargo add vitaminc-protected
```

With the `protected` feature enabled, keep a value in a `Protected` wrapper
to redact its debug output and wipe its contents when it is dropped:

```rust
use vitaminc::protected::{Controlled, Protected};

let mut token = Protected::new(String::from("example-token"));
token.update(|value| value.push_str("-updated"));

let debug = format!("{token:?}");
assert!(debug.contains("***"));
assert!(!debug.contains("example-token"));
```

## Compatibility

The minimum supported Rust version (MSRV) is <!-- msrv:workspace -->**1.88.0**<!-- /msrv -->, except for
`vitaminc-kms`, which requires <!-- msrv:vitaminc-kms -->**1.94.1**<!-- /msrv -->. Enabling the facade's `aws-kms`
feature raises its requirement to <!-- msrv:vitaminc/aws-kms -->**1.94.1**<!-- /msrv --> too.

MSRV increases require a minor release (for example, 0.8 to 0.9) and must be
called out in release notes. Patch releases retain the existing floor.

All crates require `std`; there is no `no_std` configuration yet. Supported
targets include native builds, `vitaminc-encrypt` on `wasm32-unknown-unknown`,
and the separate encryption guest on `wasm32-wasip1`. JavaScript WASM hosts need Web
Crypto and the generated bindings described in the
[encryption setup guide](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt#webassembly-setup).
The KMS adapter and Node addon bindings target native applications.

License: MIT. `vitaminc-ore` also includes Unicode-licensed data and declares
`MIT AND Unicode-3.0`; see its license files.

# Features and sub-crates

The facade enables no features by default. Each feature exposes the named
crate. Some also enable supporting facade features:

| Feature | Also enables |
| --- | --- |
| `context`, `permutation` | `protected` |
| `prf` | `context` |
| `hmac` | `prf` |
| `async-traits`, `aws-kms` | `traits` |
| `aead` | `context` |
| `encrypt` | `traits`, `aead` |
| `normalize` | `aead`; also PRF normalization if `prf` is enabled |
| `ore` | `normalize` |

These dependencies apply transitively. `normalize` alone does not enable
`prf`. For options such as `hlist`, `chrono`, or `bitvec`, add the relevant
crate directly and enable its feature; the facade does not forward them.

| Feature      | Source            | Crates.io                                                                                              | Documentation |
|--------------|------------------|--------------------------------------------------------------------------------------------------------|---------------|
| `aead`  | [`vitaminc-aead`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead) | [![crates.io](https://img.shields.io/crates/v/vitaminc-aead.svg)](https://crates.io/crates/vitaminc-aead) | [![docs.rs](https://docs.rs/vitaminc-aead/badge.svg)](https://docs.rs/vitaminc-aead) |
| Direct dependency | [`vitaminc-aead-frame`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-frame) | [![crates.io](https://img.shields.io/crates/v/vitaminc-aead-frame.svg)](https://crates.io/crates/vitaminc-aead-frame) | [![docs.rs](https://docs.rs/vitaminc-aead-frame/badge.svg)](https://docs.rs/vitaminc-aead-frame) |
| Direct dependency | [`vitaminc-aead-napi`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-napi) | [![crates.io](https://img.shields.io/crates/v/vitaminc-aead-napi.svg)](https://crates.io/crates/vitaminc-aead-napi) | [![docs.rs](https://docs.rs/vitaminc-aead-napi/badge.svg)](https://docs.rs/vitaminc-aead-napi) |
| `async-traits`  | [`vitaminc-async-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/async-traits) | [![crates.io](https://img.shields.io/crates/v/vitaminc-async-traits.svg)](https://crates.io/crates/vitaminc-async-traits) | [![docs.rs](https://docs.rs/vitaminc-async-traits/badge.svg)](https://docs.rs/vitaminc-async-traits) |
| `context`  | [`vitaminc-context`](https://github.com/cipherstash/vitaminc/tree/main/packages/context) | [![crates.io](https://img.shields.io/crates/v/vitaminc-context.svg)](https://crates.io/crates/vitaminc-context) | [![docs.rs](https://docs.rs/vitaminc-context/badge.svg)](https://docs.rs/vitaminc-context) |
| `encrypt`  | [`vitaminc-encrypt`](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt) | [![crates.io](https://img.shields.io/crates/v/vitaminc-encrypt.svg)](https://crates.io/crates/vitaminc-encrypt) | [![docs.rs](https://docs.rs/vitaminc-encrypt/badge.svg)](https://docs.rs/vitaminc-encrypt) |
| `hmac`  | [`vitaminc-hmac`](https://github.com/cipherstash/vitaminc/tree/main/packages/hmac) | [![crates.io](https://img.shields.io/crates/v/vitaminc-hmac.svg)](https://crates.io/crates/vitaminc-hmac) | [![docs.rs](https://docs.rs/vitaminc-hmac/badge.svg)](https://docs.rs/vitaminc-hmac) |
| `normalize`  | [`vitaminc-normalize`](https://github.com/cipherstash/vitaminc/tree/main/packages/normalize) | [![crates.io](https://img.shields.io/crates/v/vitaminc-normalize.svg)](https://crates.io/crates/vitaminc-normalize) | [![docs.rs](https://docs.rs/vitaminc-normalize/badge.svg)](https://docs.rs/vitaminc-normalize) |
| `ore`  | [`vitaminc-ore`](https://github.com/cipherstash/vitaminc/tree/main/packages/ore) | [![crates.io](https://img.shields.io/crates/v/vitaminc-ore.svg)](https://crates.io/crates/vitaminc-ore) | [![docs.rs](https://docs.rs/vitaminc-ore/badge.svg)](https://docs.rs/vitaminc-ore) |
| `aws-kms`  | [`vitaminc-kms`](https://github.com/cipherstash/vitaminc/tree/main/packages/kms) | [![crates.io](https://img.shields.io/crates/v/vitaminc-kms.svg)](https://crates.io/crates/vitaminc-kms) | [![docs.rs](https://docs.rs/vitaminc-kms/badge.svg)](https://docs.rs/vitaminc-kms) |
| —¹  | [`vitaminc-password`](https://github.com/cipherstash/vitaminc/tree/main/packages/password) | [![crates.io](https://img.shields.io/crates/v/vitaminc-password.svg)](https://crates.io/crates/vitaminc-password) | [![docs.rs](https://docs.rs/vitaminc-password/badge.svg)](https://docs.rs/vitaminc-password) |
| `permutation`  | [`vitaminc-permutation`](https://github.com/cipherstash/vitaminc/tree/main/packages/permutation) | [![crates.io](https://img.shields.io/crates/v/vitaminc-permutation.svg)](https://crates.io/crates/vitaminc-permutation) | [![docs.rs](https://docs.rs/vitaminc-permutation/badge.svg)](https://docs.rs/vitaminc-permutation) |
| `prf`  | [`vitaminc-prf`](https://github.com/cipherstash/vitaminc/tree/main/packages/prf) | [![crates.io](https://img.shields.io/crates/v/vitaminc-prf.svg)](https://crates.io/crates/vitaminc-prf) | [![docs.rs](https://docs.rs/vitaminc-prf/badge.svg)](https://docs.rs/vitaminc-prf) |
| `protected`  | [`vitaminc-protected`](https://github.com/cipherstash/vitaminc/tree/main/packages/protected) | [![crates.io](https://img.shields.io/crates/v/vitaminc-protected.svg)](https://crates.io/crates/vitaminc-protected) | [![docs.rs](https://docs.rs/vitaminc-protected/badge.svg)](https://docs.rs/vitaminc-protected) |
| `random`  | [`vitaminc-random`](https://github.com/cipherstash/vitaminc/tree/main/packages/random) | [![crates.io](https://img.shields.io/crates/v/vitaminc-random.svg)](https://crates.io/crates/vitaminc-random) | [![docs.rs](https://docs.rs/vitaminc-random/badge.svg)](https://docs.rs/vitaminc-random) |
| `traits`  | [`vitaminc-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/traits) | [![crates.io](https://img.shields.io/crates/v/vitaminc-traits.svg)](https://crates.io/crates/vitaminc-traits) | [![docs.rs](https://docs.rs/vitaminc-traits/badge.svg)](https://docs.rs/vitaminc-traits) |

¹ `vitaminc-password` is not currently exposed as a `vitaminc` facade feature — depend on the crate directly.

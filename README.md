# Vitamin C

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/cipherstash/vitaminc/main/docs/assets/readme-header-dark.png">
  <img src="https://raw.githubusercontent.com/cipherstash/vitaminc/main/docs/assets/readme-header-light.png" alt="Vitamin C — Misuse resistant vitamins for your cryptography. Open source, by CipherStash." width="1024">
</picture>


Vitamin C is a set of Rust crates that help you use cryptography safely and
handle secret values. The crates' types and APIs make the secure way to write
code the easy way. Invalid states and configurations fail to compile wherever
the crates can make them fail.
Compile-time checks matter even more when AI writes the code.

A secure algorithm alone does not make cryptography secure. Keys need enough
randomness. Secrets need careful handling. Encrypted data must only decrypt in
the context it was encrypted for. A mistake in any of these details can break
the security that the algorithm provides.

Vitamin C has crates to:

- protect secret values in memory;
- generate cryptographically secure random values;
- handle keys and passwords;
- encrypt structured values;
- encode cryptographic context in a form that cannot be read two ways.

The crates use libraries such as Subtle, Zeroize, and RustCrypto.

You can add each crate you need as its own dependency. You can also add the
`vitaminc` facade crate. The facade re-exports each crate when you enable the
feature for it.

[CipherStash](https://cipherstash.com) develops Vitamin C. Vitamin C is open
source. The project is in active development toward version 1.0. CipherStash
welcomes feedback and
[contributions](https://github.com/cipherstash/vitaminc/blob/main/CONTRIBUTING.md).

## Contents

- [Design goals](#design-goals)
- [Choose a crate](#choose-a-crate)
- [Installation and usage](#installation-and-usage)
  - [Use the facade crate](#use-the-facade-crate)
  - [Use individual crates](#use-individual-crates)
  - [Crates and features that need a direct dependency](#crates-and-features-that-need-a-direct-dependency)
- [Examples](#examples)
  - [Protect your own secret types](#protect-your-own-secret-types)
  - [Protect existing values with wrappers](#protect-existing-values-with-wrappers)
  - [Generate a password and keep it protected](#generate-a-password-and-keep-it-protected)
  - [Derive `Generatable` for your own types](#derive-generatable-for-your-own-types)
  - [Encrypt a secret in its application context](#encrypt-a-secret-in-its-application-context)
  - [Encrypt your own Rust structs](#encrypt-your-own-rust-structs)
  - [Keep long-lived keys in locked memory](#keep-long-lived-keys-in-locked-memory)
- [Supporting crates](#supporting-crates)
- [Compatibility](#compatibility)
- [Facade features](#facade-features)
- [Access the plain value of a secret](#access-the-plain-value-of-a-secret)

## Design goals

* **Misuse resistant**: make the secure way the easy way. Make types and APIs
  reject invalid use at compile time wherever they can.
* **Verified**: test with property tests, mutation tests, and fuzzing. Use
  formal methods where practical. Prefer dependencies that are verified.
* **Vetted**: write code that security experts can review. Prefer dependencies
  that experts have reviewed.
* **Minimal**: include only what is necessary. Put optional parts behind
  features.
* **Consistent**: give the crates interfaces that work together.
* **Compatible**: support native and WebAssembly applications. Embedded
  (`no_std`) support is a future goal. Every crate requires `std` today.
* **Fast**: keep the code fast, without making it less secure.

## Choose a crate

### Main crates

Most applications need only these crates. The "Facade feature" column names
the `vitaminc` feature that enables each crate. You can also add each crate as
its own dependency. The [supporting crates](#supporting-crates) are listed
after the examples.

| Crate&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Purpose | Facade feature | Links |
| --- | --- | --- | --- |
| [`vitaminc`](https://github.com/cipherstash/vitaminc/tree/main/packages/vitaminc) | Use the other crates through one dependency, with a feature for each crate. The facade enables no features by default. | Not applicable | [crates.io](https://crates.io/crates/vitaminc) · [docs.rs](https://docs.rs/vitaminc) |
| [`vitaminc-protected`](https://github.com/cipherstash/vitaminc/tree/main/packages/protected) | Wrap secret values. Debug output hides them, code must call a named method to read them, and they are wiped (overwritten with zeros) when dropped. | `protected` | [crates.io](https://crates.io/crates/vitaminc-protected) · [docs.rs](https://docs.rs/vitaminc-protected) |
| [`vitaminc-password`](https://github.com/cipherstash/vitaminc/tree/main/packages/password) | Generate passwords with safe default lengths, and keep them protected. | `password` | [crates.io](https://crates.io/crates/vitaminc-password) · [docs.rs](https://docs.rs/vitaminc-password) |
| [`vitaminc-random`](https://github.com/cipherstash/vitaminc/tree/main/packages/random) | Generate cryptographically secure random values, including random values of your own types. | `random` | [crates.io](https://crates.io/crates/vitaminc-random) · [docs.rs](https://docs.rs/vitaminc-random) |
| [`vitaminc-encrypt`](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt) | Encrypt and decrypt Rust values with AES-256-GCM. Keys stay protected, and the crate generates each nonce for you. | `encrypt` | [crates.io](https://crates.io/crates/vitaminc-encrypt) · [docs.rs](https://docs.rs/vitaminc-encrypt) |

## Installation and usage

You can add Vitamin C in two ways:

- Add the `vitaminc` facade, and enable a feature for each crate you need.
- Add each crate you need as its own dependency.

Both ways give you the same types and APIs. Only the dependency declarations
and the import paths differ. You can use both ways in one project.

### Use the facade crate

The facade enables no features by default. Enable a feature for each crate you
need:

```sh
cargo add vitaminc --features protected
```

Each feature adds a module to the facade, such as `vitaminc::protected` for the
`protected` feature. Import from that module:

```rust
use vitaminc::protected::{Controlled, Protected};

let mut token = Protected::new(String::from("example-token"));
token.update(|value| value.push_str("-updated"));

let debug = format!("{token:?}");
assert!(debug.contains("***"));
assert!(!debug.contains("example-token"));
```

`Protected` hides its contents in debug output. `Protected` also wipes its
contents when it is dropped.

To enable more than one crate, separate the features with commas:

```sh
cargo add vitaminc --features protected,random,encrypt
```

These features add the modules `vitaminc::protected`, `vitaminc::random`, and
`vitaminc::encrypt`.

### Use individual crates

Add each crate you need:

```sh
cargo add vitaminc-protected
```

In Rust imports, write the crate name with underscores in place of hyphens. The
same example becomes:

```rust
use vitaminc_protected::{Controlled, Protected};

let mut token = Protected::new(String::from("example-token"));
token.update(|value| value.push_str("-updated"));

let debug = format!("{token:?}");
assert!(debug.contains("***"));
assert!(!debug.contains("example-token"));
```

Add other crates the same way. For example, add `vitaminc-random` and
`vitaminc-encrypt`, and import them as `vitaminc_random` and
`vitaminc_encrypt`.

### Crates and features that need a direct dependency

Even when you use the facade, you need a direct dependency for these:

- The `vitaminc-aead-frame` and `vitaminc-aead-napi` crates. The facade does
  not currently include them.
- Crate features such as `hlist`, `chrono`, and `bitvec`. Enable them on the
  crate that defines them, because the facade does not pass them on.
- Some derive macros. A derive macro can need a direct dependency on the crate
  that re-exports it. Each crate's setup guide says whether its macros need one.

## Examples

Each example starts with the `cargo add` commands it needs, and runs on its
own. Most examples import the crates directly. The password example also shows
the facade.

### Protect your own secret types

To protect a secret type that you define, derive these traits:

- `OpaqueDebug`, from `vitaminc-protected`, hides the contents in debug output.
- `TimingSafeEq`, from `vitaminc-protected`, compares contents of equal length
  without stopping at the first byte that differs.
- `Zeroize` and `ZeroizeOnDrop`, from the Zeroize crate, wipe the contents.

```sh
cargo add vitaminc-protected
cargo add zeroize --features derive
```

```rust
use vitaminc_protected::{OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(OpaqueDebug, TimingSafeEq, Zeroize, ZeroizeOnDrop)]
struct ApiToken(String);

// These values are fixed for this example. Generate real tokens with SafeRand, as shown below.
let token = ApiToken("sk-ant-api03-M_qo...".to_string());
let same = ApiToken("sk-ant-api03-M_qo...".to_string());
let different = ApiToken("sk-ant-api04-M_an...".to_string());

println!("{token:?}"); // Prints the type name, with "***" in place of the contents.
assert_eq!(token, same);
assert_ne!(token, different);
assert!(bool::from(token.ts_eq(&same)));
```

The `Zeroize` derive adds a `.zeroize()` method. Call `.zeroize()` to wipe the
fields. The `ZeroizeOnDrop` derive adds a destructor that wipes the fields when
the value is dropped.

The timing protection depends on the field types. Two strings of equal length
are compared in constant time, so the time taken does not depend on their
contents. A string's length and an enum's variant are not treated as secrets.

### Protect existing values with wrappers

To protect a value of a type from another crate, such as `String`, wrap it in
`Protected`. To compare protected values, use `Equatable`. Both wrappers hide
their contents in debug output, and wipe them when dropped.

```sh
cargo add vitaminc-protected
```

Comparing two `Protected` values with `==` **does not compile**. The compile
error stops you from comparing secrets with the inner type's ordinary
comparison by mistake:

```rust,compile_fail,E0369
use vitaminc_protected::Protected;

let expected = Protected::new(*b"demo");
let supplied = Protected::new(*b"demo");

let matches = expected == supplied; // Error: Protected does not implement PartialEq.
```

To compare protected values, wrap them in `Equatable`. `Equatable` uses the
constant-time comparison of the inner type. This version compiles:

```rust
use vitaminc_protected::{Controlled, Equatable, Protected};

let mut secret = Protected::new(String::from("example-token"));
secret.update(|text| text.make_ascii_uppercase());
println!("{secret:?}"); // Debug output hides the contents.

let expected: Equatable<Protected<[u8; 4]>> = Equatable::new(*b"demo");
let supplied: Equatable<Protected<[u8; 4]>> = Equatable::new(*b"demo");
assert_eq!(expected, supplied);
```

The wrappers do not implement `Deref`. To change a value inside its wrapper,
call `update`.

### Generate a password and keep it protected

This example generates a password with a safe default length, from a generator
seeded by the operating system. The example then converts the password to a
protected string for your application to use:

```sh
cargo add vitaminc-password
```

```rust
use vitaminc_password::{AlphaNumericPassword, Protected};

let password = AlphaNumericPassword::generate().expect("password generation failed");
assert_eq!(password.len(), 22); // The length is not secret. The characters stay protected.
let text: Protected<String> = password.into_protected_string();
println!("{text:?}"); // Debug output does not show the password.
```

Each password type has a default length that gives more than 128 bits of
entropy, when the generator is securely seeded:

| Password type | Characters | Default length |
| --- | --- | ---: |
| `Password` | Printable ASCII | 20 |
| `AlphaNumericPassword` | Letters and digits | 22 |
| `AlphaPassword` | Letters | 23 |

Each default length is also the minimum length. If you set a shorter length,
the build fails. To generate longer passwords, or many passwords at once, use
`Generatable::random`. The password guide explains how, in
[Longer passwords and batches](https://github.com/cipherstash/vitaminc/tree/main/packages/password#longer-passwords-and-batches).

Converting a password to a protected string wipes the original characters. The
protected string is wiped when it is dropped.

To use the facade instead, enable its `password` feature. The `password`
feature also enables `protected` and `random`:

```sh
cargo add vitaminc --features password
```

```rust
use vitaminc::password::AlphaNumericPassword;

let password = AlphaNumericPassword::generate().expect("password generation failed");
let text = password.into_protected_string();
println!("{text:?}");
```

### Derive `Generatable` for your own types

To generate random values of your own structs, derive `Generatable`. Every
field must implement `Generatable`. `Protected<[u8; 32]>` implements
`Generatable`, so protected fields work too. You get the derive macro from
`vitaminc-random`:

```sh
cargo add vitaminc-random vitaminc-protected
```

```rust
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, SafeRand};

#[derive(Generatable)]
struct ApiToken {
    bytes: Protected<[u8; 32]>,
}

let mut rng = SafeRand::from_entropy().expect("system entropy unavailable");
let secret: Protected<[u8; 32]> = Generatable::random(&mut rng).expect("generation failed");
// The derived implementation generates each field with the RNG you pass in.
let token = ApiToken::random(&mut rng).expect("generation failed");

println!("{secret:?}");
println!("{:?}", token.bytes); // Debug output hides the contents of protected fields.
```

For real secrets, seed the generator from the operating system, as
`SafeRand::from_entropy` does. A fixed seed is useful in tests, because a test
then generates the same values each time. Anyone who knows the seed can
generate those values too.

### Encrypt a secret in its application context

This example generates a protected 256-bit key, and encrypts a value with
AES-256-GCM. `vitaminc-encrypt` generates the nonce for each encryption. You
also supply a context, such as a tenant and a field name. Decryption fails
unless you supply the same context:

```sh
cargo add vitaminc-encrypt vitaminc-random vitaminc-protected
```

```rust
use vitaminc_encrypt::{decrypt, encrypt, Aes256Cipher, Key};
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, SafeRand};

let mut rng = SafeRand::from_entropy().expect("system entropy unavailable");
let key = Key::random(&mut rng).expect("key generation failed");
let cipher = Aes256Cipher::new(&key).expect("cipher creation failed");
let context = "tenant:42/api-token";
let secret = Protected::new(String::from("example-token"));
let ciphertext = encrypt(&secret, &cipher, context).expect("encryption failed");

let recovered: Protected<String> =
    decrypt(&cipher, ciphertext, context).expect("decryption failed");
println!("{recovered:?}"); // The decrypted value is also protected.

let ciphertext = encrypt(&secret, &cipher, context).expect("encryption failed");
let wrong_context: Result<Protected<String>, _> =
    decrypt(&cipher, ciphertext, "tenant:99/api-token");
assert!(wrong_context.is_err());
```

The context is used as associated data. Encryption authenticates the context,
but does not encrypt it. Use a context that does not change, and that cannot be
confused with another context. Supply the same context when you decrypt.

### Encrypt your own Rust structs

To encrypt a struct, derive `Encrypt` and `Decrypt`. You do not need to
serialize the struct first, or take its protected fields out of their
wrappers:

```sh
cargo add vitaminc-aead vitaminc-encrypt vitaminc-random vitaminc-protected
```

```rust
use vitaminc_aead::{Decrypt, Encrypt};
use vitaminc_encrypt::{decrypt, encrypt, Aes256Cipher, Key};
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, SafeRand};

#[derive(Encrypt, Decrypt)]
struct Credential {
    label: String,
    token: Protected<String>,
}

let mut rng = SafeRand::from_entropy().expect("system entropy unavailable");
let key = Key::random(&mut rng).expect("key generation failed");
let cipher = Aes256Cipher::new(&key).expect("cipher creation failed");
let credential = Credential {
    label: String::from("deployment"),
    token: Protected::new(String::from("example-token")),
};

let ciphertext = encrypt(&credential, &cipher, "tenant:42/credential")
    .expect("encryption failed");
let recovered: Credential = decrypt(&cipher, ciphertext, "tenant:42/credential")
    .expect("decryption failed");
assert_eq!(recovered.label, credential.label);
println!("{:?}", recovered.token); // The decrypted token is also protected.
```

Each field is encrypted separately. A field's ciphertext only decrypts under
that field's name. When you decrypt into `Credential`, the decryption also
checks that the value has the fields `Credential` expects.

Encryption does not authenticate a container as a whole. That is, it does not
authenticate which entries a map has, or the order and length of a sequence.
The
[encryption guide](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt#how-it-fits-together)
explains what the data model guarantees.

### Keep long-lived keys in locked memory

For a secret that lives longer than one call, use `Locked`. `Locked` asks the
operating system to protect the memory where the secret is stored. This example
generates the key's bytes directly in that memory. The example then refuses to
use the key unless the memory is locked:

```sh
cargo add vitaminc-protected vitaminc-random
```

```rust
use vitaminc_protected::Locked;
use vitaminc_random::{Rng, SafeRand};

let mut rng = SafeRand::from_entropy().expect("system entropy unavailable");
let key = Locked::<[u8; 32]>::generate(|bytes| rng.fill_bytes(bytes))
    .expect("key allocation failed");

match key.require_locked() {
    Ok(key) => {
        // Borrow the bytes only for the operation that needs them.
        key.with(|bytes| assert_eq!(bytes.len(), 32));
    }
    Err(error) => {
        // The key has been dropped and wiped. Do not continue with this key.
        eprintln!("locked key storage unavailable: {error}");
    }
}
```

On Unix, `Locked` uses `mlock`. `mlock` stops the operating system writing the
memory to swap. `Locked` also puts guard pages on each side of the memory. On
Linux, the memory is also left out of core dumps.

The operating system can refuse to lock memory. Some platforms cannot lock
memory at all. By default, the constructors try to lock the memory. If they
cannot, they still return a value. Call `require_locked()` when your code
must have locked memory.

Store inline data such as `[u8; 32]` in `Locked`. A `Vec` or `String` keeps its
contents in a separate buffer, so `Locked` would only lock the `Vec` or
`String` header. The
[locked storage guide](https://github.com/cipherstash/vitaminc/tree/main/packages/protected#locked-storage-for-long-lived-secrets)
gives the details for each platform.

## Supporting crates

These crates contain lower-level components, traits for backends, derive
macros, and bindings for other languages. Most applications use them only
through the main crates. When you extend Vitamin C, or connect it to another
language or service, add them as direct dependencies.

| Crate | Purpose | Facade feature | Links |
| --- | --- | --- | --- |
| [`vitaminc-aead`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead) | The data model for encrypting structured values, and the traits that an authenticated encryption backend implements. | `aead` | [crates.io](https://crates.io/crates/vitaminc-aead) · [docs.rs](https://docs.rs/vitaminc-aead) |
| [`vitaminc-aead-derive`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-derive) | The `Encrypt` and `Decrypt` derive macros. `vitaminc-aead` re-exports them. | Through `vitaminc-aead` | [crates.io](https://crates.io/crates/vitaminc-aead-derive) · [docs.rs](https://docs.rs/vitaminc-aead-derive) |
| [`vitaminc-aead-frame`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-frame) | Encodings for sending values and ciphertexts between programs, and a versioned format for storing them. | Direct dependency | [crates.io](https://crates.io/crates/vitaminc-aead-frame) · [docs.rs](https://docs.rs/vitaminc-aead-frame) |
| [`vitaminc-aead-napi`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-napi) | Converts values between Rust and JavaScript in native Node.js addons, through Node-API. This crate is a Rust library, not an npm package. | Direct dependency | [crates.io](https://crates.io/crates/vitaminc-aead-napi) · [docs.rs](https://docs.rs/vitaminc-aead-napi) |
| [`vitaminc-async-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/async-traits) | Async traits for hash and message authentication code (MAC) providers that run remotely. | `async-traits` | [crates.io](https://crates.io/crates/vitaminc-async-traits) · [docs.rs](https://docs.rs/vitaminc-async-traits) |
| [`vitaminc-context`](https://github.com/cipherstash/vitaminc/tree/main/packages/context) | Encodes context in one fixed form that cannot be read two ways, for authenticated encryption and pseudorandom functions (PRFs). | `context` | [crates.io](https://crates.io/crates/vitaminc-context) · [docs.rs](https://docs.rs/vitaminc-context) |
| [`vitaminc-hmac`](https://github.com/cipherstash/vitaminc/tree/main/packages/hmac) | An HMAC-SHA256 backend that runs in your process, for pseudorandom functions over structured values. | `hmac` | [crates.io](https://crates.io/crates/vitaminc-hmac) · [docs.rs](https://docs.rs/vitaminc-hmac) |
| [`vitaminc-kms`](https://github.com/cipherstash/vitaminc/tree/main/packages/kms) | An HMAC backend that uses AWS Key Management Service (KMS). | `aws-kms` | [crates.io](https://crates.io/crates/vitaminc-kms) · [docs.rs](https://docs.rs/vitaminc-kms) |
| [`vitaminc-normalize`](https://github.com/cipherstash/vitaminc/tree/main/packages/normalize) | Encodes structured values in one fixed form, for equality indexes. | `normalize` | [crates.io](https://crates.io/crates/vitaminc-normalize) · [docs.rs](https://docs.rs/vitaminc-normalize) |
| [`vitaminc-ore`](https://github.com/cipherstash/vitaminc/tree/main/packages/ore) | Order terms and scheme traits for order-revealing encryption (ORE). You need to supply an ORE backend. | `ore` | [crates.io](https://crates.io/crates/vitaminc-ore) · [docs.rs](https://docs.rs/vitaminc-ore) |
| [`vitaminc-permutation`](https://github.com/cipherstash/vitaminc/tree/main/packages/permutation) | Keyed permutations of arrays and bits. | `permutation` | [crates.io](https://crates.io/crates/vitaminc-permutation) · [docs.rs](https://docs.rs/vitaminc-permutation) |
| [`vitaminc-prf`](https://github.com/cipherstash/vitaminc/tree/main/packages/prf) | Traits for deriving pseudorandom values, and terms for equality indexes, from structured data. | `prf` | [crates.io](https://crates.io/crates/vitaminc-prf) · [docs.rs](https://docs.rs/vitaminc-prf) |
| [`vitaminc-protected-derive`](https://github.com/cipherstash/vitaminc/tree/main/packages/protected-derive) | The `OpaqueDebug` and `TimingSafeEq` derive macros. `vitaminc-protected` re-exports them. | Through `vitaminc-protected` | [crates.io](https://crates.io/crates/vitaminc-protected-derive) · [docs.rs](https://docs.rs/vitaminc-protected-derive) |
| [`vitaminc-random-derives`](https://github.com/cipherstash/vitaminc/tree/main/packages/random-derives) | The `Generatable` derive macro. `vitaminc-random` re-exports it. | Through `vitaminc-random` | [crates.io](https://crates.io/crates/vitaminc-random-derives) · [docs.rs](https://docs.rs/vitaminc-random-derives) |
| [`vitaminc-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/traits) | Hash and MAC traits that backends implement. | `traits` | [crates.io](https://crates.io/crates/vitaminc-traits) · [docs.rs](https://docs.rs/vitaminc-traits) |

Before you use these crates, read these notes:

- Use each derive macro through the crate that re-exports it. Follow that
  crate's setup guide.
- Before you store encoded values, read the
  [storage contract](https://github.com/cipherstash/vitaminc/blob/main/packages/aead-frame/STORAGE.md)
  for `vitaminc-aead-frame`.
- An index reveals information about the values in it. For example, an
  equality index shows which values are equal, and an ORE index shows their
  order. Before you choose an index, read the
  [`vitaminc-normalize` guide](https://github.com/cipherstash/vitaminc/tree/main/packages/normalize)
  and the [`vitaminc-ore` guide](https://github.com/cipherstash/vitaminc/tree/main/packages/ore).

## Compatibility

The minimum supported Rust version (MSRV) is <!-- msrv:workspace -->**1.89.0**<!-- /msrv -->, except for
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

## Facade features

The facade enables no features by default. Each feature exposes the named
crate. Some also enable supporting facade features:

| Feature | Also enables |
| --- | --- |
| `context`, `permutation` | `protected` |
| `password` | `protected`, `random` |
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

## Access the plain value of a secret

Some APIs need the plain value of a secret, outside its wrapper. For those
APIs, the `Controlled` trait has methods that give you the plain value. Each
method makes you responsible for keeping the value safe:

| Method | What it gives you | What you must do |
| --- | --- | --- |
| `risky_ref()` | A shared borrow of the plain value. | Stop the code that receives the value from logging, serializing, or copying it by mistake. |
| `risky_inner_mut()` | A mutable borrow of the plain value. | The same as for `risky_ref()`. Also, replacing the value can discard the old contents without wiping them. |
| `risky_unwrap()` | The plain value, which you now own. The wrapper is consumed. | Wipe the value yourself, and make sure it is not disclosed. |

For example, borrow the plain value only in the block of code that needs it:

```sh
cargo add vitaminc-protected
```

```rust
use vitaminc_protected::{Controlled, Protected};

let token = Protected::new(String::from("example-token"));
{
    let plaintext: &str = token.risky_ref();
    // Pass plaintext only to the API that needs it. Do not log it.
    assert!(!plaintext.is_empty());
}
// token is still protected, and is wiped when it is dropped.
```

The wrapper cannot protect a copy that the receiving code makes.

A password's `into_unprotected_string()` method returns an ordinary `String`.
You must wipe that `String` yourself.

The closures you pass to `update`, `map`, and `Locked::with` also receive the
plain value. A closure makes clear which code can use the plain value. The
closure does not stop that code from copying or revealing the value. Where you
can, use APIs that take the protected value directly, as the encryption
examples above do.

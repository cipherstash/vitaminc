# Vitamin C

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/cipherstash/vitaminc/main/docs/assets/readme-header-dark.png">
  <img src="https://raw.githubusercontent.com/cipherstash/vitaminc/main/docs/assets/readme-header-light.png" alt="Vitamin C — Misuse resistant vitamins for your cryptography. Open source, by CipherStash." width="1024">
</picture>


Strong cryptography depends on more than choosing a secure algorithm. Keys need
sufficient randomness, secrets need careful handling, and encrypted data needs
to be bound to the context in which it is used. Getting these details wrong can
undermine the guarantees of the underlying primitives.

Vitamin C is a suite of Rust crates that makes these details easier to get
right. It provides components for protecting secret values, generating
cryptographic randomness, handling keys and passwords, encrypting structured
values, and encoding cryptographic context unambiguously. It builds on libraries
such as Subtle, Zeroize, and RustCrypto, with types and APIs designed to prevent
misuse. The goal is to make invalid states and configurations fail to compile
wherever possible. This matters even more when code is written by AI.

Developed at [CipherStash](https://cipherstash.com), Vitamin C is open source
and in active development toward 1.0. Use individual crates for the capabilities
you need, or enable them through the top-level `vitaminc` crate. Feedback and
[contributions](https://github.com/cipherstash/vitaminc/blob/main/CONTRIBUTING.md)
are welcome.

## Which crate should I use?

### Main crates

Start here for application development. The facade feature column shows how to
access each component through `vitaminc`; you can also depend on it directly.

| Crate&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Purpose | Facade feature | Links |
| --- | --- | --- | --- |
| [`vitaminc`](https://github.com/cipherstash/vitaminc/tree/main/packages/vitaminc) | Access the suite through one crate with opt-in features. | — | [crates.io](https://crates.io/crates/vitaminc) · [docs.rs](https://docs.rs/vitaminc) |
| [`vitaminc-protected`](https://github.com/cipherstash/vitaminc/tree/main/packages/protected) | Protect secret values with redacted debug output, controlled access, and zeroization on drop. | `protected` | [crates.io](https://crates.io/crates/vitaminc-protected) · [docs.rs](https://docs.rs/vitaminc-protected) |
| [`vitaminc-password`](https://github.com/cipherstash/vitaminc/tree/main/packages/password) | Generate protected passwords with safe default lengths. | `password` | [crates.io](https://crates.io/crates/vitaminc-password) · [docs.rs](https://docs.rs/vitaminc-password) |
| [`vitaminc-random`](https://github.com/cipherstash/vitaminc/tree/main/packages/random) | Generate cryptographic randomness and random instances of your types. | `random` | [crates.io](https://crates.io/crates/vitaminc-random) · [docs.rs](https://docs.rs/vitaminc-random) |
| [`vitaminc-encrypt`](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt) | Encrypt and decrypt Rust values with AES-256-GCM, protected keys, and automatic nonce generation. | `encrypt` | [crates.io](https://crates.io/crates/vitaminc-encrypt) · [docs.rs](https://docs.rs/vitaminc-encrypt) |

## Installation and usage

Choose either the top-level `vitaminc` facade or individual crates. Both paths
provide the same underlying types and APIs; the dependency declarations and
import paths differ. You can also combine them when a component or feature
requires a direct dependency.

### Option 1: Use the facade crate

The facade gives you one entry point to the suite. It enables no features by
default, so select the components you need:

```sh
cargo add vitaminc --features protected
```

Import through the corresponding module, such as `vitaminc::protected`:

```rust
use vitaminc::protected::{Controlled, Protected};

let mut token = Protected::new(String::from("example-token"));
token.update(|value| value.push_str("-updated"));

let debug = format!("{token:?}");
assert!(debug.contains("***"));
assert!(!debug.contains("example-token"));
```

The wrapper redacts debug output and wipes its contents when dropped. Enable
additional components with comma-separated features, for example
`cargo add vitaminc --features protected,random,encrypt`. Those components are
available as `vitaminc::protected`, `vitaminc::random`, and `vitaminc::encrypt`.

### Option 2: Use individual crates directly

Add the crates for the capabilities you need:

```sh
cargo add vitaminc-protected
```

Use the crate name with underscores in Rust imports. The same example becomes:

```rust
use vitaminc_protected::{Controlled, Protected};

let mut token = Protected::new(String::from("example-token"));
token.update(|value| value.push_str("-updated"));

let debug = format!("{token:?}");
assert!(debug.contains("***"));
assert!(!debug.contains("example-token"));
```

For more capabilities, add the corresponding crates, such as
`vitaminc-random` and `vitaminc-encrypt`, and import them as `vitaminc_random`
and `vitaminc_encrypt`.

`vitaminc-aead-frame` and `vitaminc-aead-napi` currently require direct
dependencies. Crate-specific options such as `hlist`, `chrono`,
and `bitvec` also require enabling features on the relevant crate directly.
Follow each crate's setup guide for derive macros: some require a direct
parent-crate dependency even when you use the facade.

## Examples

Each snippet is self-contained and shows its dependencies. Most use direct
crate imports; the password example also demonstrates the facade API.

### Make your own secret types safer

Combine `OpaqueDebug` and `TimingSafeEq` with Zeroize's derives to redact debug
output, compare fixed-size secrets without short-circuiting, and wipe them on
drop:

```sh
cargo add vitaminc-protected
cargo add zeroize --features derive
```

```rust
use vitaminc_protected::{OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(OpaqueDebug, TimingSafeEq, Zeroize, ZeroizeOnDrop)]
struct ApiToken(String);

// Fixed values for this demonstration; generate real tokens with SafeRand below.
let token = ApiToken(String);
let same = ApiToken("sk-ant-api03-M_qo...".to_string());
let different = ApiToken("sk-ant-api04-M_an...".to_string());

println!("{token:?}"); // The type name is visible; its contents appear as "***".
assert_eq!(token, same);
assert_ne!(token, different);
assert!(bool::from(token.ts_eq(&same)));
```

`Zeroize` provides an explicit `.zeroize()` method; the `ZeroizeOnDrop` derive
also generates the destructor that wipes the fields. Timing guarantees depend
on the field types: this example uses fixed-size bytes, while string lengths
and enum variants are not treated as secrets.

### Protect existing values with wrappers

Use `Protected` for existing types such as `String`, and `Equatable` when you
need comparisons. Both retain redacted debug output and zeroization on drop.

```sh
cargo add vitaminc-protected
```

Ordinary equality on `Protected` values **does not compile**. This prevents
accidentally using the underlying type's ordinary comparison for a secret:

```rust,compile_fail,E0369
use vitaminc_protected::Protected;

let expected = Protected::new(*b"demo");
let supplied = Protected::new(*b"demo");

let matches = expected == supplied; // Error: Protected does not implement PartialEq.
```

Opt in to comparisons with `Equatable`, which uses the inner type's
constant-time comparison implementation. This version compiles:

```rust
use vitaminc_protected::{Controlled, Equatable, Protected};

let mut secret = Protected::new(String::from("example-token"));
secret.update(|text| text.make_ascii_uppercase());
println!("{secret:?}"); // Contents are redacted.

let expected: Equatable<Protected<[u8; 4]>> = Equatable::new(*b"demo");
let supplied: Equatable<Protected<[u8; 4]>> = Equatable::new(*b"demo");
assert_eq!(expected, supplied);
```

The wrappers do not implement `Deref`. Use `update` to modify a value within
its wrapper and `Equatable` to compare protected values.

### Generate a password and keep it protected

Generate a password with a safe default length and system entropy, then convert
it to a protected string for use by your application:

```sh
cargo add vitaminc-password
```

```rust
use vitaminc_password::{AlphaNumericPassword, Protected};

let password = AlphaNumericPassword::generate().expect("password generation failed");
assert_eq!(password.len(), 22); // Public metadata; the contents stay protected.
let text: Protected<String> = password.into_protected_string();
println!("{text:?}"); // The password stays out of debug output.
```

The default lengths are 20 printable ASCII characters for `Password`, 22 letters
and digits for `AlphaNumericPassword`, and 23 letters for `AlphaPassword`. Each
exceeds the 128-bit entropy target with a securely seeded generator. Explicit
lengths below these minimums fail when built; use `Generatable::random` for
[longer passwords or batches](https://github.com/cipherstash/vitaminc/tree/main/packages/password#longer-passwords-and-batches).
Conversion wipes the original characters, and the protected string is wiped
on drop.

The same API is available through the facade's `password` feature, which also
enables `protected` and `random`:

```sh
cargo add vitaminc --features password
```

```rust
use vitaminc::password::AlphaNumericPassword;

let password = AlphaNumericPassword::generate().expect("password generation failed");
let text = password.into_protected_string();
println!("{text:?}");
```

### Generate cryptographic randomness for your types

Seed `SafeRand` from system entropy and use `Generatable` for random values.
The derive can fill your own structs, including protected fields:

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
let token = ApiToken::random(&mut rng).expect("generation failed");

println!("{secret:?}");
println!("{:?}", token.bytes); // Protected fields redact their contents.
```

Use system entropy for real secrets. Fixed seeds are useful for reproducible
tests, but make their generated values reproducible too.

### Encrypt a secret in its application context

Generate a protected 256-bit key and encrypt a value with AES-256-GCM. Vitamin C
generates the nonce. Associated data binds the ciphertext to the application
context you supply, such as a tenant and field:

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
println!("{recovered:?}"); // The decrypted value remains protected.

let ciphertext = encrypt(&secret, &cipher, context).expect("encryption failed");
let wrong_context: Result<Protected<String>, _> =
    decrypt(&cipher, ciphertext, "tenant:99/api-token");
assert!(wrong_context.is_err());
```

Associated data is authenticated, not encrypted. Use a stable, unambiguous
identifier and supply the same context when decrypting.

### Encrypt your own Rust structs

Derive `Encrypt` and `Decrypt` to encrypt structured values without manually
serializing them or unwrapping protected fields:

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
println!("{:?}", recovered.token); // The decrypted token remains protected.
```

Each field's value is encrypted and bound to its name. Reading into this struct
also checks its expected fields. Container membership and sequence order are
not authenticated as a whole; see the
[encryption guide](https://github.com/cipherstash/vitaminc/tree/main/packages/encrypt#how-it-fits-together)
for the data model's guarantees.

### Keep long-lived keys in locked memory

`Locked` adds operating-system memory protections for secrets that live beyond
a single call. Generate the bytes directly into its storage and require a
successful lock before using the key:

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
        // Borrow the bytes for the operation that needs them.
        key.with(|bytes| assert_eq!(bytes.len(), 32));
    }
    Err(error) => {
        // The value has been dropped and wiped. Do not proceed with this key.
        eprintln!("locked key storage unavailable: {error}");
    }
}
```

On Unix, locked storage uses `mlock` and guard pages; Linux also excludes it
from core dumps. Locking can be refused or unavailable, so constructors are
best-effort by default and `require_locked()` makes that requirement explicit.
Use inline data such as `[u8; 32]`: locking a `Vec` or `String` would lock its
header, not its separate buffer. See the
[locked storage guide](https://github.com/cipherstash/vitaminc/tree/main/packages/protected#locked-storage-for-long-lived-secrets)
for platform details.

## Supporting and specialized crates

These provide lower-level building blocks, backend interfaces, derive macros,
and language integration. Most application developers will use them indirectly
through the main crates; depend on them directly when you need to extend or
integrate the suite.

| Crate | Purpose | Facade feature | Links |
| --- | --- | --- | --- |
| [`vitaminc-aead`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead) | Structured value model and traits for authenticated encryption backends. | `aead` | [crates.io](https://crates.io/crates/vitaminc-aead) · [docs.rs](https://docs.rs/vitaminc-aead) |
| [`vitaminc-aead-derive`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-derive) | `Encrypt` and `Decrypt` derive macros, re-exported by `vitaminc-aead`. | Via parent crate | [crates.io](https://crates.io/crates/vitaminc-aead-derive) · [docs.rs](https://docs.rs/vitaminc-aead-derive) |
| [`vitaminc-aead-frame`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-frame) | Transport codecs and a versioned storage format for values and ciphertexts. | Direct dependency | [crates.io](https://crates.io/crates/vitaminc-aead-frame) · [docs.rs](https://docs.rs/vitaminc-aead-frame) |
| [`vitaminc-aead-napi`](https://github.com/cipherstash/vitaminc/tree/main/packages/aead-napi) | Node-API value bridge for native Node.js addons; a Rust library, not an npm package. | Direct dependency | [crates.io](https://crates.io/crates/vitaminc-aead-napi) · [docs.rs](https://docs.rs/vitaminc-aead-napi) |
| [`vitaminc-async-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/async-traits) | Async hash and MAC interfaces for remote providers. | `async-traits` | [crates.io](https://crates.io/crates/vitaminc-async-traits) · [docs.rs](https://docs.rs/vitaminc-async-traits) |
| [`vitaminc-context`](https://github.com/cipherstash/vitaminc/tree/main/packages/context) | Canonical context encoding for authenticated encryption and pseudorandom functions. | `context` | [crates.io](https://crates.io/crates/vitaminc-context) · [docs.rs](https://docs.rs/vitaminc-context) |
| [`vitaminc-hmac`](https://github.com/cipherstash/vitaminc/tree/main/packages/hmac) | Local HMAC-SHA256 backend for structured pseudorandom functions. | `hmac` | [crates.io](https://crates.io/crates/vitaminc-hmac) · [docs.rs](https://docs.rs/vitaminc-hmac) |
| [`vitaminc-kms`](https://github.com/cipherstash/vitaminc/tree/main/packages/kms) | AWS KMS HMAC backend. | `aws-kms` | [crates.io](https://crates.io/crates/vitaminc-kms) · [docs.rs](https://docs.rs/vitaminc-kms) |
| [`vitaminc-normalize`](https://github.com/cipherstash/vitaminc/tree/main/packages/normalize) | Canonical equality encodings for structured values. | `normalize` | [crates.io](https://crates.io/crates/vitaminc-normalize) · [docs.rs](https://docs.rs/vitaminc-normalize) |
| [`vitaminc-ore`](https://github.com/cipherstash/vitaminc/tree/main/packages/ore) | Order terms and scheme interfaces for order-revealing encryption; requires an ORE backend. | `ore` | [crates.io](https://crates.io/crates/vitaminc-ore) · [docs.rs](https://docs.rs/vitaminc-ore) |
| [`vitaminc-permutation`](https://github.com/cipherstash/vitaminc/tree/main/packages/permutation) | Keyed permutations of arrays and bits. | `permutation` | [crates.io](https://crates.io/crates/vitaminc-permutation) · [docs.rs](https://docs.rs/vitaminc-permutation) |
| [`vitaminc-prf`](https://github.com/cipherstash/vitaminc/tree/main/packages/prf) | Interfaces for deriving pseudorandom values and equality-index terms from structured data. | `prf` | [crates.io](https://crates.io/crates/vitaminc-prf) · [docs.rs](https://docs.rs/vitaminc-prf) |
| [`vitaminc-protected-derive`](https://github.com/cipherstash/vitaminc/tree/main/packages/protected-derive) | `OpaqueDebug` and `TimingSafeEq` derive macros, re-exported by `vitaminc-protected`. | Via parent crate | [crates.io](https://crates.io/crates/vitaminc-protected-derive) · [docs.rs](https://docs.rs/vitaminc-protected-derive) |
| [`vitaminc-random-derives`](https://github.com/cipherstash/vitaminc/tree/main/packages/random-derives) | `Generatable` derive macro, re-exported by `vitaminc-random`. | Via parent crate | [crates.io](https://crates.io/crates/vitaminc-random-derives) · [docs.rs](https://docs.rs/vitaminc-random-derives) |
| [`vitaminc-traits`](https://github.com/cipherstash/vitaminc/tree/main/packages/traits) | Shared hash and MAC interfaces for backend implementations. | `traits` | [crates.io](https://crates.io/crates/vitaminc-traits) · [docs.rs](https://docs.rs/vitaminc-traits) |

Use derive macros through their parent crates and follow those crates' setup
guides. Before persisting encoded values, read the frame crate's
[storage contract](https://github.com/cipherstash/vitaminc/blob/main/packages/aead-frame/STORAGE.md).
Indexes reveal information about values; read the
[normalization](https://github.com/cipherstash/vitaminc/tree/main/packages/normalize)
and [ORE](https://github.com/cipherstash/vitaminc/tree/main/packages/ore) guides
before choosing an index.

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

## Features and sub-crates

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

## Design goals

* **Misuse resistant**: make the secure path easy, with types and APIs that
  reject invalid usage at compile time where possible.
* **Verified**: combine property and mutation testing, fuzzing, and formal
  methods where practical, and prefer verified dependencies.
* **Vetted**: design for expert review and prefer reviewed dependencies.
* **Minimal**: include only what is necessary and keep optional capabilities
  behind features.
* **Consistent**: provide interfaces that work together across the suite.
* **Compatible**: support native and WebAssembly applications, with embedded
  (`no_std`) support as a future goal. All crates currently require `std`.
* **Fast**: pursue performance without compromising security.

## Escape hatches - use with care!

Some integrations require access to the underlying secret. The `Controlled`
trait provides explicit escape hatches for those boundaries:

| Method | Responsibility you take on |
| --- | --- |
| `risky_ref()` | Borrow the plain value. Prevent the receiving code from logging, serializing, or copying it unintentionally. |
| `risky_inner_mut()` | Mutably borrow the plain value. Replacing it can also discard the old contents without wiping them. |
| `risky_unwrap()` | Consume the wrapper and take ownership of the plain value. You must arrange its zeroization and prevent disclosure. |

For example, borrow a secret only for the scope in which a plain reference is
required:

```sh
cargo add vitaminc-protected
```

```rust
use vitaminc_protected::{Controlled, Protected};

let token = Protected::new(String::from("example-token"));
{
    let plaintext: &str = token.risky_ref();
    // Pass plaintext only to the API that requires it; do not log it.
    assert!(!plaintext.is_empty());
}
// The original token remains protected and is wiped when it is dropped.
```

The wrapper cannot protect copies made by the receiving code. Likewise,
passwords' `into_unprotected_string()` returns an ordinary `String` whose
zeroization becomes your responsibility.

Closures passed to `update`, `map`, or `Locked::with` also access plain values.
They make the scope explicit, but do not prevent your code from copying or
revealing a secret. Prefer APIs that accept the protected value directly, as
the encryption examples above do.

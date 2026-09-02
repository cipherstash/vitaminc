# Vitamin C Protected

[![Crates.io](https://img.shields.io/crates/v/vitaminc-protected.svg)](https://crates.io/crates/vitaminc-protected)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Safe wrappers for sensitive data

`Protected` is a set of types that remove some of the sharp edges of working with sensitive data in Rust.
Its interface is conceptually similar to `Option` or `Result`.

### Sensitive data footguns

Rust is a safe language, but it's still possible to make mistakes when working with sensitive data.
These can include (but are not limited to):

* Not zeroizing sensitive data when it's no longer needed
* Accidentally leaking sensitive data in logs or error messages
* Performing comparison operations on sensitive data in a way that leaks timing information
* Serializing sensitive data in a way that leaks information

`Protected` and the other types in this crate aim to make it easier to avoid these mistakes.

## Usage

The `Protected` type is the most basic building block in this crate.
You can use it to wrap any type that you want to protect so long as it implements the `Zeroize` trait.

```rust
use vitaminc_protected::Protected;

let x = Protected::new([0u8; 32]);
```

`Protected` will call `zeroize` on the inner value when it goes out of scope.
It also provides an "opaque" implementation of the `Debug` trait so you can debug protected values
without accidentally leaking their innards.

```rust
use vitaminc_protected::{Controlled, Protected};
let x = Protected::new([0u8; 32]);
assert!(format!("{x:?}").contains("Protected<[u8; 32]>"));
```

The inner value is not accessible directly, but you can use the `risky_unwrap` method as an escape hatch to get it back.
`risky_unwrap` is defined in the [Controlled] trait so you'll need to bring that in scope.

```rust
use vitaminc_protected::{Controlled, Protected};

let x = Protected::new([0u8; 32]);
assert_eq!(x.risky_unwrap(), [0; 32]);
```

`Protected` does not implement `Deref` so you cannot access the data directly.
This is to prevent accidental leakage of the inner value.
It also means comparisons (like `PartialEq`) are not implemented for `Protected`.

If you want to safely compare values, you can use [Equatable].

### Equatable

The `Equatable` type is a wrapper around `Protected` that implements constant-time comparison.
It implements `PartialEq` for any inner type that implements [ConstantTimeEq].

```rust
use vitaminc_protected::{Equatable, Protected};

let x: Equatable<Protected<u32>> = Equatable::new(100);
let y: Equatable<Protected<u32>> = Equatable::new(100);
assert_eq!(x, y);
```

### Exportable

The `Exportable` type is a wrapper around `Protected` that supports safe serialization via the `SafeSerialize` and `SafeDeserialize` traits.

### Usage

The `Usage` type is a wrapper around `Protected` that allows you to specify a scope for the data.

This adapter is WIP.

### Working with wrapped values

None of the adapters implement `Deref` so you can't access the inner value directly.
This is to prevent accidental leakage of the inner value by being explicit about when and how you want to work with the inner value.

You can `map` over the inner value to transform it, so long as the adapter is the same type.
For example, you can map a `Protected<T>` to a `Protected<U>`.

```rust
use vitaminc_protected::{Controlled, Protected};

// Calculate the sum of values in the array with the result as a `Protected`
let x: Protected<[u8; 4]> = Protected::new([1, 2, 3, 4]);
let result: Protected<u8> = x.map(|arr| arr.as_slice().iter().sum());
assert_eq!(result.risky_unwrap(), 10);
```

If you have a pair of `Protected` values, you can `zip` them together with a function that combines them.

```rust
use vitaminc_protected::{Controlled, Protected};

let x: Protected<u8> = Protected::new(1);
let y: Protected<u8> = Protected::new(2);
let z: Protected<u8> = x.zip(y, |a, b| a + b);
```

If the inner type is an `Option` you can call `transpose` to swap the `Protected` and the `Option`.

```rust
use vitaminc_protected::{Controlled, Protected};

let x = Protected::new(Some([0u8; 32]));
let y = x.transpose();
assert!(y.is_some());
```

A `Protected` of `Protected` can be "flattened" into a single `Protected`.

```rust
# use vitaminc_protected::{Controlled, Protected};

let x = Protected::new(Protected::new([0u8; 32]));
let y = x.flatten();
assert_eq!(y.risky_unwrap(), [0u8; 32]);
```

Use [flatten_array] to convert a `[Protected<T>; N]` into a `Protected<[T; N]>`.

### Protected digests

`ProtectedDigest` requires a fixed-output implementation that zeroizes its
internal state on drop. Enable the digest crate's zeroization feature, such as
`sha2 = { version = "0.11", features = ["zeroize"] }`.

Unkeyed digests use `new`; keyed fixed-output functions implementing `KeyInit`
use `new_with_key` so the key remains in a `Controlled` container at the API
boundary.

Secret inputs use `update` and protected outputs use `finalize_into`. Public
protocol framing and intentionally exposed outputs cross separate, explicitly
named channels:

```rust
use sha2::Sha256;
use vitaminc_protected::{Controlled, Protected, ProtectedDigest};

let secret = Protected::new(*b"secret");
let mut digest = ProtectedDigest::<Sha256>::new();
digest.update_public(b"example/domain/v1");
digest.update(&secret);

let mut output = Protected::new([0u8; 32]);
digest.finalize_into(&mut output);
assert_ne!(output.risky_ref(), &[0u8; 32]);
```

### Also in this crate

Beyond the adapters above, the crate exports `TimingSafeEq` and `Choice` (timing-safe comparison), `OpaqueDebug` and `Redacted` (leak-resistant `Debug`), `ProtectedDigest`, `Zeroed`, and `AsProtectedRef` — see the [docs.rs API reference](https://docs.rs/vitaminc-protected) for details.

### Non-empty contexts

An AEAD associated-data value or PRF context can legitimately be empty, but a caller that uses one value to domain-separate fields needs it *not* to be. `NonEmpty<T>` carries that invariant in the type, checked once at construction: `nonempty!("users/email")` is checked at compile time (an empty literal does not compile), and `NonEmpty::new(value)` checks a dynamic value structurally — `""`, `None`, `Some("")` and `("", "")` are all rejected, without parsing any encoding. An API that requires the invariant takes `NonEmpty<T>` directly; a bare `&str` argument cannot be value-checked at compile time, so there is deliberately no implicit conversion from one.

```rust
use vitaminc_protected::{nonempty, EmptyError, NonEmpty};

// Compile-time checked: nonempty!("") does not compile.
assert_eq!(nonempty!("users/email").get(), &"users/email");

// Runtime checked, once, for dynamic values.
assert!(NonEmpty::new(String::from("users/email")).is_ok());
assert_eq!(NonEmpty::new(("", None::<&str>)).unwrap_err(), EmptyError);
```

### Generators

`Protected` supports generating new values from functions that return the inner value.

```rust
# use vitaminc_protected::{Controlled, Protected};
fn array_gen<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| (i + 1) as u8)
}

let input: Protected<[u8; 8]> = Protected::generate(array_gen);
```

You can also generate values from functions that return a `Result` with the inner value.

```rust
# use vitaminc_protected::{Controlled, Protected};
use std::string::FromUtf8Error;

let input: Result<Protected<String>, FromUtf8Error> = Protected::generate_ok(|| {
  String::from_utf8(vec![1, 2, 3, 4, 5, 6, 7, 8])
});
```

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

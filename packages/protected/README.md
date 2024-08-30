# Vitamin C Protected

[![Crates.io](https://img.shields.io/crates/v/vitaminc-protected.svg)](https://crates.io/crates/vitaminc-protected)
[![Workflow Status](https://github.com/cipherstash/vitaminc/workflows/main/badge.svg)](https://github.com/cipherstash/vitaminc/actions?query=workflow%3A%22main%22)

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
use vitaminc_protected::{Paranoid, Protected};
let x = Protected::new([0u8; 32]);
assert_eq!(format!("{x:?}"), "Protected<[u8; 32]> { ... }");
```

The inner value is not accessible directly, but you can use the `unwrap` method as an escape hatch to get it back.
`unwrap` is defined in the `Paranoid` trait so you'll need to bring that in scope.

```rust
use vitaminc_protected::{Paranoid, Protected};

let x = Protected::new([0u8; 32]);
assert_eq!(x.unwrap(), [0; 32]);
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

The `Exportable` type is a wrapper around `Protected` that implements constant-time serialization.

This adapter is WIP.

### Usage

The `Usage` type is a wrapper around `Protected` that allows you to specify a scope for the data.

This adapter is WIP.

### Working with wrapped values

None of the adapters implement `Deref` so you can't access the inner value directly.
This is to prevent accidental leakage of the inner value by being explicit about when and how you want to work with the inner value.

You can `map` over the inner value to transform it, so long as the adapter is the same type.
For example, you can map a `Protected<T>` to a `Protected<U>`.

```rust
use vitaminc_protected::{Paranoid, Protected};

// Calculate the sum of values in the array with the result as a `Protected`
let x: Protected<[u8; 4]> = Protected::new([1, 2, 3, 4]);
let result: Protected<u8> = x.map(|arr| arr.as_slice().iter().sum());
assert_eq!(result.unwrap(), 10);
```

If you have a pair of `Protected` values, you can `zip` them together with a function that combines them.

```rust
use vitaminc_protected::{Paranoid, Protected};

let x: Protected<u8> = Protected::new(1);
let y: Protected<u8> = Protected::new(2);
let z: Protected<u8> = x.zip(y, |a, b| a + b);
```

If the inner type is an `Option` you can call `transpose` to swap the `Protected` and the `Option`.

```rust
use vitaminc_protected::{Paranoid, Protected};

let x = Protected::new(Some([0u8; 32]));
let y = x.transpose();
assert!(matches!(y, Some(Protected)));
```

A `Protected` of `Protected` can be "flattened" into a single `Protected`.

```rust
# use vitaminc_protected::{Paranoid, Protected};

let x = Protected::new(Protected::new([0u8; 32]));
let y = x.flatten();
assert_eq!(y.unwrap(), [0u8; 32]);
```

Use [flatten_array] to convert a `[Protected<T>; N]` into a `Protected<[T; N]>`.

### Generators

`Protected` supports generating new values from functions that return the inner value.

```rust
# use vitaminc_protected::{Paranoid, Protected};
fn array_gen<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| (i + 1) as u8)
}

let input: Protected<[u8; 8]> = Protected::generate(array_gen);
```

You can also generate values from functions that return a `Result` with the inner value.

```rust
# use vitaminc_protected::{Paranoid, Protected};
use std::string::FromUtf8Error;

let input: Result<Protected<String>, FromUtf8Error> = Protected::generate_ok(|| {
  String::from_utf8(vec![1, 2, 3, 4, 5, 6, 7, 8])
});
```

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

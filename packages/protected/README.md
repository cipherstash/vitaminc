[![Crates.io](https://img.shields.io/crates/v/vitaminc-protected.svg)](https://crates.io/crates/vitaminc-protected)
[![Workflow Status](https://github.com/cipherstash/vitaminc/workflows/main/badge.svg)](https://github.com/cipherstash/vitaminc/actions?query=workflow%3A%22main%22)

# vitaminc-protected

## VitaminC Protected

### Safe wrappers for sensitive data

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

### Usage

The `Protected` type is the most basic building block in this crate.
You can use it to wrap any type that you want to protect so long as it implements the `Zeroize` trait.

```rust
use vitaminc_protected::Protected;

let x = Protected::new([0u8; 32]);
```

`Protected` will call `zeroize` on the inner value when it goes out of scope.
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



Current version: 0.1.0-pre

## CipherStash

VitaminC is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

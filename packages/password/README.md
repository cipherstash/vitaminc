# Vitamin C Password

Generate passwords with at least 128 bits of entropy from a securely seeded
random generator, and keep their contents protected until use. This crate
provides generation and secret handling, not password hashing, storage or login
verification.

## Installation

<!-- workspace-deps:start -->
```toml
[dependencies]
vitaminc-password = "0.8.1"
vitaminc-protected = "0.8.1"
vitaminc-random = "0.8.1"
```
<!-- workspace-deps:end -->

## Quick Start

[`Password`] chooses a 20-character password and seeds its generator from the
operating system. Propagate entropy failures; there is no predictable fallback.
Convert to a protected string to keep automatic wiping and redacted debug output:

```rust
use vitaminc_password::Password;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::RandomError;

fn new_password() -> Result<Protected<String>, RandomError> {
    Ok(Password::generate()?.into_protected_string())
}

fn example() -> Result<(), RandomError> {
    let secret = new_password()?;
    assert_eq!(secret.risky_ref().len(), 20);
    // Borrow through `risky_ref()` only at the external interface that needs it.
    // Dropping `secret` wipes its string allocation.
    Ok(())
}

if let Err(error) = example() {
    eprintln!("Password generation failed: {error}");
    std::process::exit(1);
}
```

The `password` feature of the `vitaminc` facade also exposes this crate as
`vitaminc::password` and enables `vitaminc::protected` and `vitaminc::random`.

## Alphabets and defaults

Each type offers `generate()` with no arguments. Its default is the shortest
length exceeding the 128-bit target for that alphabet:

| Type | Alphabet | Default and minimum length | Approximate entropy |
| --- | --- | ---: | ---: |
| [`Password`] | 94 non-space printable ASCII characters | 20 | 131 bits |
| [`AlphaNumericPassword`] | `A-Z`, `a-z`, `0-9` | 22 | 131 bits |
| [`AlphaPassword`] | `A-Z`, `a-z` | 23 | 131 bits |

```rust
use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};

let standard: Password<20> = Password::generate()?;
let alphanumeric: AlphaNumericPassword<22> = AlphaNumericPassword::generate()?;
let alphabetic: AlphaPassword<23> = AlphaPassword::generate()?;
# Ok::<(), vitaminc_random::RandomError>(())
```

An alphabet specifies the allowed characters, not required character classes:
a password need not contain a digit, punctuation, or both letter cases. The
standard alphabet includes quotes, slashes and other punctuation. Pass passwords
as data through the destination's API; do not interpolate them into commands,
SQL or markup.

## Longer passwords and batches

Use `Generatable::random` for an explicit compile-time length or to reuse a
securely seeded generator across a batch. Building a generation call below the
type's minimum length fails compilation; `cargo check` alone may not evaluate
that const-generic assertion. There is no public raw-value constructor. Use
`Protected<String>` for an existing password received from elsewhere.

```rust
use vitaminc_password::AlphaNumericPassword;
use vitaminc_random::{Generatable, SafeRand};

let mut rng = SafeRand::from_entropy()?;
for _ in 0..10 {
    let password = AlphaNumericPassword::<32>::random(&mut rng)?;
    let secret = password.into_protected_string();
    // Pass each protected value to its destination.
}
# Ok::<(), vitaminc_random::RandomError>(())
```

The supplied RNG must have an unpredictable seed. Fixed seeds are for tests:
reusing a seed repeats the stream and therefore the passwords. Length checks do
not make a predictable seed secure. There is no guaranteed seeded-output
compatibility across library versions.

## Secret handling

Passwords own a `Protected<[char; N]>`. Generation writes into the protected
array; converting to a protected string borrows that array while it remains
wrapped, then drops and wipes it. The destination string is protected before
writing, and reserves all `N` ASCII bytes up front to avoid reallocating secret
contents. Both owners retain their cleanup behavior during unwinding.

The password types have opaque `Debug`, no `Copy`, `Clone`, `Default`, `Display`,
`Deref`, serialization, or ordinary equality. Conversion consumes the password.
Protection ends where the contents are explicitly exposed: borrowing or exporting
can let other code copy or log them. Zeroization does not wipe compiler-created
copies or protect against process termination, swap, or memory dumps; memory is
not locked.

Use `into_unprotected_string()` only when an external interface requires an
owned plain `String`. The source array is still wiped, but the returned string
is not automatically wiped:

```rust
use vitaminc_password::Password;

let exported: String = Password::generate()?.into_unprotected_string();
assert_eq!(exported.len(), 20);
// The receiver of `exported` is responsible for its lifecycle and cleanup.
# Ok::<(), vitaminc_random::RandomError>(())
```

## Randomness and entropy

Generation uses `SafeRand` (ChaCha20), with one fixed-count bounded draw per
character in `0..alphabet_size`. All characters are reachable. The draw is
near-uniform, not exactly uniform: its exact statistical distance from uniform
is at most 2⁻⁵⁹ per character for these alphabets. The displayed entropy uses the
idealized `N * log2(alphabet_size)` estimate; the bias is too small to change
which minimum length exceeds 128 bits. The target assumes an unpredictable RNG
seed. Fixed draw count is not a guarantee of constant-time execution of the
whole generator or conversion.

## Compatibility

Requires Rust <!-- msrv:vitaminc-password -->**1.89.0**<!-- /msrv --> and `std`.
There are no optional crate features. Native and JavaScript WebAssembly builds
use the entropy backend supplied by `vitaminc-random`; JavaScript hosts need Web
Crypto and the corresponding WASM bindings. Length is a const generic; extremely
large values consume correspondingly large stack space. String conversion
allocates memory.

Compared with the unfinished API, the public `Password::new` constructor is
removed and lengths below 20/22/23 are rejected when generation is built. Replace
raw wrapping with `Protected::new`, and increase generated lengths to the minimum
for the selected alphabet.

License: MIT. Part of [Vitamin C](https://github.com/cipherstash/vitaminc),
from [CipherStash](https://cipherstash.com).

[`Password`]: https://docs.rs/vitaminc-password/latest/vitaminc_password/struct.Password.html
[`AlphaNumericPassword`]: https://docs.rs/vitaminc-password/latest/vitaminc_password/struct.AlphaNumericPassword.html
[`AlphaPassword`]: https://docs.rs/vitaminc-password/latest/vitaminc_password/struct.AlphaPassword.html

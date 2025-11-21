# Vitamin C Password

[![Crates.io](https://img.shields.io/crates/v/vitaminc-password.svg)](https://crates.io/crates/vitaminc-password)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

Secure password generator with protected memory handling.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Features

- **Cryptographically secure**: Uses `vitaminc-random` for secure random generation
- **Protected memory**: Passwords are stored in `Protected` types that zeroize on drop
- **Multiple character sets**: Choose from standard (all printable), alphanumeric, or alphabetic passwords
- **Compile-time length**: Password length is specified at compile time for type safety
- **No heap allocations** (until conversion to String): Passwords stored as fixed-size arrays

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
vitaminc-password = "0.1.0-pre4"
vitaminc-random = "0.1.0-pre4"
```

## Quick Start

```rust
use vitaminc_password::Password;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

// Generate a 16-character password with all printable characters
let mut rng = SafeRand::from_entropy();
let password: Password<16> = Generatable::random(&mut rng)?;
```

## Usage

### Password Types

Vitamin C Password provides three types of passwords with different character sets:

1. **`Password<N>`** - Uses all 94 printable ASCII characters
2. **`AlphaNumericPassword<N>`** - Uses only letters (A-Z, a-z) and numbers (0-9) - 62 characters
3. **`AlphaPassword<N>`** - Uses only letters (A-Z, a-z) - 52 characters

The `N` parameter specifies the password length at compile time.

### Generating Passwords

#### Standard Password (All Printable Characters)

Includes uppercase, lowercase, numbers, and special characters:

```rust
use vitaminc_password::Password;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

let mut rng = SafeRand::from_entropy();

// Generate a 20-character password
let password: Password<20> = Generatable::random(&mut rng)?;
```

**Character set**: `A-Z`, `a-z`, `0-9`, and special characters:
```
~ ` ! @ # $ % ^ & * ( ) _ - + = { [ } ] | \ : ; " ' < , > . ? /
```

#### Alphanumeric Password

For systems that don't accept special characters:

```rust
use vitaminc_password::AlphaNumericPassword;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

let mut rng = SafeRand::from_entropy();

// Generate a 16-character alphanumeric password
let password: AlphaNumericPassword<16> = Generatable::random(&mut rng)?;
```

**Character set**: `A-Z`, `a-z`, `0-9` (62 characters)

#### Alphabetic Password

For maximum compatibility or readability:

```rust
use vitaminc_password::AlphaPassword;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

let mut rng = SafeRand::from_entropy();

// Generate a 24-character alphabetic password
let password: AlphaPassword<24> = Generatable::random(&mut rng)?;
```

**Character set**: `A-Z`, `a-z` (52 characters)

### Password Length

The password length is specified as a const generic parameter. You can generate passwords of any length:

```rust
let short: Password<8> = Generatable::random(&mut rng)?;
let medium: Password<16> = Generatable::random(&mut rng)?;
let long: Password<32> = Generatable::random(&mut rng)?;
let very_long: Password<128> = Generatable::random(&mut rng)?;
```

### Converting to String

Passwords are stored securely in `Protected` types. When you need to use them (e.g., to send to an API or display to the user), you can convert them to strings:

#### Protected String (Recommended)

Maintains protection with automatic zeroization:

```rust
use vitaminc_protected::Protected;

let password: Password<16> = Generatable::random(&mut rng)?;
let protected_string: Protected<String> = password.into_protected_string();
// Use the protected string...
// It will be zeroized when dropped
```

**Note**: This functionality is currently under development (see WIP markers in code).

#### Unprotected String

For final use where the password needs to leave protected memory:

```rust
let password: Password<16> = Generatable::random(&mut rng)?;
let string: String = password.into_unprotected_string();
// Use the string immediately
// No automatic zeroization after this point
```

**Important**: Once converted to an unprotected `String`, the password is no longer automatically zeroized. Only use this as a final step right before the password is needed.

## Password Strength

The entropy (randomness) of a password depends on both its length and the character set size:

**Entropy formula**: `log2(charset_size^length)` bits

### Standard Password
- Character set: 94 characters
- 16 characters: ~105 bits of entropy
- 20 characters: ~131 bits of entropy
- 32 characters: ~210 bits of entropy

### Alphanumeric Password
- Character set: 62 characters
- 16 characters: ~95 bits of entropy
- 20 characters: ~119 bits of entropy
- 32 characters: ~190 bits of entropy

### Alphabetic Password
- Character set: 52 characters
- 16 characters: ~91 bits of entropy
- 20 characters: ~113 bits of entropy
- 32 characters: ~181 bits of entropy

**Recommendation**: For most use cases, 16-20 characters provides excellent security (>100 bits of entropy).

## Security Features

### Cryptographically Secure Random Generation

All passwords are generated using `vitaminc-random`'s `SafeRand`, which uses ChaCha20, a cryptographically secure pseudo-random number generator (CSPRNG).

### Protected Memory

Passwords are stored in `Protected<[char; N]>`, which ensures:

- **Automatic zeroization**: Memory is cleared when the password is dropped
- **No accidental leakage**: Debug output shows `Protected { ... }` instead of the actual password
- **Constant-time operations**: Where applicable, to prevent timing side-channels

### Unbiased Character Selection

The crate uses bounded random number generation to ensure each character in the character set has an equal probability of being selected, preventing bias that could reduce password entropy.

## Use Cases

### Password Manager

Generate secure passwords for user accounts:

```rust
use vitaminc_password::Password;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

fn generate_user_password(length: usize) -> Result<String, RandomError> {
    let mut rng = SafeRand::from_entropy();
    match length {
        16 => {
            let password: Password<16> = Generatable::random(&mut rng)?;
            Ok(password.into_unprotected_string())
        },
        20 => {
            let password: Password<20> = Generatable::random(&mut rng)?;
            Ok(password.into_unprotected_string())
        },
        32 => {
            let password: Password<32> = Generatable::random(&mut rng)?;
            Ok(password.into_unprotected_string())
        },
        _ => panic!("Unsupported length"),
    }
}
```

### API Key Generation

Generate alphanumeric API keys:

```rust
use vitaminc_password::AlphaNumericPassword;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

fn generate_api_key() -> Result<String, RandomError> {
    let mut rng = SafeRand::from_entropy();
    let key: AlphaNumericPassword<32> = Generatable::random(&mut rng)?;
    Ok(key.into_unprotected_string())
}
```

### Temporary Passwords

Generate pronounceable temporary passwords:

```rust
use vitaminc_password::AlphaPassword;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

fn generate_temp_password() -> Result<String, RandomError> {
    let mut rng = SafeRand::from_entropy();
    let password: AlphaPassword<12> = Generatable::random(&mut rng)?;
    Ok(password.into_unprotected_string())
}
```

## Best Practices

1. **Use appropriate length**: Aim for at least 16 characters for user passwords
2. **Choose the right character set**: Use `Password` for maximum security, `AlphaNumericPassword` for compatibility
3. **Minimize lifetime**: Convert to String only when needed and use immediately
4. **Don't log passwords**: The `Protected` wrapper prevents accidental logging, but be careful after conversion
5. **Consider the context**: API keys and machine passwords can be longer (32+ characters) since users don't type them

## Current Limitations

This crate is currently in early development (pre-release). Some functionality is not yet complete:

- `into_protected_string()` is not yet implemented
- `into_unprotected_string()` is not yet implemented
- Tests are marked as `#[ignore]` pending full implementation

Check the [GitHub repository](https://github.com/cipherstash/vitaminc) for the latest development status.

## Roadmap

Future enhancements under consideration:

- Custom character sets
- Pattern-based password generation (e.g., word-based passwords)
- Password strength estimation
- HKDF-based generation with user-provided context
- Full `into_protected_string()` implementation

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

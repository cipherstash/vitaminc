# Vitamin C: Encrypt

Secure, flexible and fast encryption for Rust types.

## Installation



## Usage

```rust
use vitaminc_encrypt::Key;
use vitaminc_random::{SafeRand, SeedableRng, Generatable};

// Generate a key
let mut rng = SafeRand::from_entropy();
let key = Key::random(&mut rng).expect("Failed to generate key");

// Use it to encrypt a message
let ciphertext = vitaminc_encrypt::encrypt(&key, "message".to_string()).expect("Failed to encrypt");
```
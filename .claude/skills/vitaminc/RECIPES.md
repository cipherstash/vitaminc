# vitaminc recipes

One recipe per task. Each is complete, compiles, and is the production path: copy it as written. Imports use the individual crates; with the facade crate, `vitaminc_protected::X` is `vitaminc::protected::X`, and so on.

## Hold a secret

Wrap the secret the moment it exists, and keep it wrapped until the last call that needs it.

```rust
use vitaminc_protected::{Controlled, Protected};

/// Read a token from the environment straight into a `Protected`.
fn api_token() -> Result<Protected<String>, std::env::VarError> {
    Protected::generate_ok(|| std::env::var("API_TOKEN"))
}

/// Transform without unwrapping: the closure sees the value, the result stays protected.
fn token_len(token: Protected<String>) -> Protected<usize> {
    token.map(|t| t.len())
}

/// At the boundary to an API that takes a plain `&str`, borrow with `risky_ref`.
/// Keep the borrow inside one call, never store it.
fn send(token: &Protected<String>, client: impl Fn(&str)) {
    client(token.risky_ref());
}
```

## Compare secrets

`Protected` has no `PartialEq`. Compare through `Equatable`, which is constant-time.

```rust
use vitaminc_protected::{Equatable, Protected};

fn tag_matches(
    presented: &Equatable<Protected<[u8; 32]>>,
    expected: &Equatable<Protected<[u8; 32]>>,
) -> bool {
    presented == expected
}

let a: Equatable<Protected<[u8; 32]>> = Equatable::new([7; 32]);
let b: Equatable<Protected<[u8; 32]>> = Equatable::new([7; 32]);
assert!(tag_matches(&a, &b));
```

## Generate random values

```rust
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, RandomError, SafeRand, SeedableRng};

fn random_secret() -> Result<Protected<[u8; 32]>, RandomError> {
    let mut rng = SafeRand::from_entropy()?;
    Protected::random(&mut rng)
}

/// A uniform index in `0..len`, for choosing from a list.
fn random_index(rng: &mut SafeRand, len: u32) -> u32 {
    rng.next_below(len)
}
```

Derive `Generatable` to generate a whole struct of random fields:

```rust
use vitaminc_random::{Generatable, RandomError, SafeRand, SeedableRng};

#[derive(Generatable)]
struct SessionSecrets {
    signing: [u8; 32],
    encryption: [u8; 32],
}

fn new_session() -> Result<SessionSecrets, RandomError> {
    SessionSecrets::random(&mut SafeRand::from_entropy()?)
}
```

## Generate a password

```rust
use vitaminc_password::{AlphaNumericPassword, Password};
use vitaminc_random::{Generatable, RandomError, SafeRand, SeedableRng};

fn new_passwords() -> Result<(Password<20>, AlphaNumericPassword<16>), RandomError> {
    let mut rng = SafeRand::from_entropy()?;
    Ok((Generatable::random(&mut rng)?, Generatable::random(&mut rng)?))
}
```

## Encrypt a value or a struct

Generate the key, build a cipher, and encrypt under associated data (AAD) naming the record the ciphertext belongs to. Decryption must present the same AAD, so a ciphertext copied onto another record fails to open. Nonces are generated for you.

```rust
use vitaminc_encrypt::{decrypt, encrypt, Aes256Cipher, Decrypt, Encrypt, Key};
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

#[derive(Debug, PartialEq, Encrypt, Decrypt)]
struct User {
    #[aead(passthrough)] // stored in the clear: only for non-sensitive fields
    id: u64,
    email: String,
    date_of_birth: String,
}

fn round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::random(&mut SafeRand::from_entropy()?)?;
    let cipher = Aes256Cipher::new(&key)?;

    let user = User { id: 42, email: "ada@example.com".into(), date_of_birth: "1815-12-10".into() };
    let aad = format!("users/{}", user.id);

    let ciphertext = encrypt(&user, &cipher, aad.as_str())?;
    let back: User = decrypt(&cipher, ciphertext, aad.as_str())?;
    assert_eq!(back, user);

    // The same ciphertext under another record's AAD does not open.
    let ciphertext = encrypt(&user, &cipher, aad.as_str())?;
    assert!(decrypt::<User, _, _>(&cipher, ciphertext, "users/43").is_err());
    Ok(())
}
round_trip().unwrap();
```

To encrypt a single secret, pass the `Protected` itself. It is walked inside the wrapper and decrypts back into one:

```rust
use vitaminc_encrypt::{decrypt, encrypt, Aes256Cipher, Key};
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

fn store_token(token: Protected<String>) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = Aes256Cipher::new(&Key::random(&mut SafeRand::from_entropy()?)?)?;
    let ciphertext = encrypt(token, &cipher, "integrations/github/token")?;
    let _back: Protected<String> = decrypt(&cipher, ciphertext, "integrations/github/token")?;
    Ok(())
}
```

## Wrap a data key under a key-encryption key

```rust
use vitaminc_encrypt::{Aes256Cipher, Key};
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

fn rotate_data_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = SafeRand::from_entropy()?;
    let kek = Aes256Cipher::new(&Key::random(&mut rng)?)?;

    let dek = Key::random(&mut rng)?;
    let wrapped = dek.wrap(&kek, "tenants/acme/dek/1")?; // store this

    let dek = Key::from_wrapped(&kek, wrapped, "tenants/acme/dek/1")?;
    let _data_cipher = Aes256Cipher::new(&dek)?;
    Ok(())
}
```

## Keyed hash, blind index, or equality term

An unkeyed hash of a low-entropy value (an email, a phone number) is reversible by guessing. Derive a keyed term instead, under a context naming the index and its version. Writes and queries must use the same input type and context.

```rust
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{PrfKeyInit, PrfValue};
use vitaminc_protected::Protected;

async fn email_term(prf: &HmacSha256Prf, email: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(email.prf_with_context(prf, "users/email/exact/v1").await?)
}

fn index_key_from_secret_store(bytes: Vec<u8>) -> Result<HmacSha256Prf, Box<dyn std::error::Error>> {
    // Rejects keys shorter than the minimum length instead of deriving weak terms.
    Ok(HmacSha256Prf::try_from_bytes(Protected::new(bytes))?)
}

let prf = index_key_from_secret_store(vec![7; 32]).unwrap();
let a = futures::executor::block_on(email_term(&prf, "ada@example.com")).unwrap();
let b = futures::executor::block_on(email_term(&prf, "ada@example.com")).unwrap();
assert_eq!(a, b);
```

`vec![7; 32]` stands in for bytes fetched from your secret store; generate the real key with `Protected::<[u8; 32]>::random` and pass it to `HmacSha256Prf::new`.

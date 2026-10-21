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
use vitaminc_random::{Generatable, RandomError, SafeRand};

fn random_secret() -> Result<Protected<[u8; 32]>, RandomError> {
    let mut rng = SafeRand::from_entropy()?;
    Protected::random(&mut rng)
}

/// A uniform index in `0..len`, for choosing from a list. `next_below` panics on a
/// zero bound, since `0..0` has nothing to draw, so an empty list is refused here.
fn random_index(rng: &mut SafeRand, len: u32) -> Option<u32> {
    (len > 0).then(|| rng.next_below(len))
}
```

Derive `Generatable` to generate a whole struct of random fields:

```rust
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, RandomError, SafeRand};

#[derive(Generatable)]
struct SessionSecrets {
    signing: Protected<[u8; 32]>,
    encryption: Protected<[u8; 32]>,
}

fn new_session() -> Result<SessionSecrets, RandomError> {
    SessionSecrets::random(&mut SafeRand::from_entropy()?)
}
```

## Generate a password

Draw each character uniformly with `next_below`, and build the string inside `Protected::generate` so it is wrapped from the start. Reserve the full capacity first, so the string never reallocates and leaves an unwiped copy behind. With this 62-character set, 16 characters give about 95 bits; refuse a shorter `len` rather than issue a guessable password.

```rust
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::SafeRand;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn new_password(rng: &mut SafeRand, len: usize) -> Option<Protected<String>> {
    if len < 16 {
        return None;
    }
    Some(Protected::generate(|| {
        let mut password = String::with_capacity(len);
        for _ in 0..len {
            password.push(CHARSET[rng.next_below(CHARSET.len() as u32) as usize] as char);
        }
        password
    }))
}
```

## Encrypt a value or a struct

Build the cipher at startup from a key that outlives the process (see "Wrap a data key" below), and pass it to every call. `Aes256Cipher` is not `Sync`, so build one per thread or task from the same key rather than sharing one across threads. A key generated inside the function that encrypts is lost when it returns, and so is everything sealed under it. Encrypt under associated data (AAD) naming the record the ciphertext belongs to. Decryption must present the same AAD, so a ciphertext copied onto another record fails to open. Nonces are generated for you.

```rust
use vitaminc_encrypt::{
    decrypt, encrypt, Aes256Cipher, AesCipherText, DecodeError, Decrypt, DecryptError, Encrypt,
    EncryptError, Unspecified,
};

#[derive(Encrypt, Decrypt)]
struct User {
    #[aead(passthrough)] // stored in the clear: only for non-sensitive fields
    id: u64,
    email: String,
    date_of_birth: String,
}

/// Seal a user for storage. `cipher` is built at startup, one per thread or task.
fn seal_user(cipher: &Aes256Cipher, user: &User) -> Result<AesCipherText, EncryptError<Unspecified>> {
    encrypt(user, cipher, format!("users/{}", user.id).as_str())
}

/// Open the record stored under `id`. Take `id` from the lookup, not from the stored
/// value: the passthrough copy is unauthenticated. Under another record's id this fails.
fn open_user(
    cipher: &Aes256Cipher,
    id: u64,
    stored: AesCipherText,
) -> Result<User, DecryptError<DecodeError, Unspecified>> {
    decrypt(cipher, stored, format!("users/{id}").as_str())
}
```

To encrypt a single secret, pass the `Protected` itself. It is walked inside the wrapper and decrypts back into one:

```rust
use vitaminc_encrypt::{
    decrypt, encrypt, Aes256Cipher, AesCipherText, DecodeError, DecryptError, EncryptError,
    Unspecified,
};
use vitaminc_protected::Protected;

fn seal_token(cipher: &Aes256Cipher, token: Protected<String>) -> Result<AesCipherText, EncryptError<Unspecified>> {
    encrypt(token, cipher, "integrations/github/token")
}

fn open_token(
    cipher: &Aes256Cipher,
    stored: AesCipherText,
) -> Result<Protected<String>, DecryptError<DecodeError, Unspecified>> {
    decrypt(cipher, stored, "integrations/github/token")
}
```

## Wrap a data key under a key-encryption key

Generate the data key once, when its owner (a tenant, a table) is created, and store only the wrapped form. At every startup, unwrap it and build the cipher the encrypt recipes take. `kek` is the key-encryption key the service holds for its whole lifetime; it is never generated per call. It is built from 32 bytes held in the secret store, passed straight to `Key::from`.

Wrap each data key under AAD naming its owner. Under one KEK, a wrapped key copied onto another tenant's record then fails to unwrap rather than opening as that tenant's key.

```rust
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use vitaminc_random::{Generatable, SafeRand};

/// Run at startup, on the root key's bytes fetched from the secret store. `Key` takes a
/// plain array (it has no constructor from `Protected` yet) and wraps it at once: fetch
/// straight into this call, and keep no other copy of the bytes.
fn key_encryption_cipher(root_key: [u8; 32]) -> Result<Aes256Cipher, Box<dyn std::error::Error>> {
    Ok(Aes256Cipher::new(&Key::from(root_key))?)
}

/// Run once, when the tenant is created. Store the result with the tenant.
fn new_data_key(
    kek: &Aes256Cipher,
    rng: &mut SafeRand,
    tenant_id: &str,
) -> Result<AesCipherText, Box<dyn std::error::Error>> {
    let dek = Key::random(rng)?;
    Ok(dek.wrap(kek, format!("tenants/{tenant_id}/dek/1").as_str())?)
}

/// Run at every startup, on the stored result of `new_data_key` for the same tenant.
fn data_cipher(
    kek: &Aes256Cipher,
    tenant_id: &str,
    wrapped: AesCipherText,
) -> Result<Aes256Cipher, Box<dyn std::error::Error>> {
    let dek = Key::from_wrapped(kek, wrapped, format!("tenants/{tenant_id}/dek/1").as_str())?;
    Ok(Aes256Cipher::new(&dek)?)
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

/// Take the key bytes already wrapped, straight from the secret store's read.
fn index_key_from_secret_store(
    bytes: Protected<Vec<u8>>,
) -> Result<HmacSha256Prf, Box<dyn std::error::Error>> {
    // Rejects keys shorter than the minimum length instead of deriving weak terms.
    Ok(HmacSha256Prf::try_from_bytes(bytes)?)
}

let prf = index_key_from_secret_store(Protected::new(vec![7; 32])).unwrap();
let a = futures::executor::block_on(email_term(&prf, "ada@example.com")).unwrap();
let b = futures::executor::block_on(email_term(&prf, "ada@example.com")).unwrap();
assert_eq!(a, b);
```

`vec![7; 32]` stands in for bytes fetched from your secret store; generate the real key with `Protected::<[u8; 32]>::random` and pass it to `HmacSha256Prf::new`.

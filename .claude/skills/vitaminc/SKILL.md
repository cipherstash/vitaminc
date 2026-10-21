---
name: vitaminc
description: Using the vitaminc Rust crates for secrets and cryptography. Use when Rust code holds keys, passwords, tokens or other secrets; generates random values or passwords; encrypts or decrypts values or structs; wraps keys; derives keyed hashes or searchable index terms; or compares secrets.
---

# vitaminc

vitaminc is a suite of Rust crates that replace common cryptography footguns with types. When Rust code touches a secret, use the vitaminc type for the job instead of a raw value or a hand-rolled routine. Code written this way is checked by the compiler rather than by the reviewer.

For the reasoning behind these types, and for designing APIs of your own, see the `misuse-resistance` skill.

## Install

Use the facade crate with a feature per capability, and import through it (`vitaminc::protected::Protected`):

```sh
cargo add vitaminc --features protected,random,encrypt
```

Or add individual crates (`cargo add vitaminc-protected`). All crates release together under one version. Deriving `Encrypt`/`Decrypt` also needs a direct `vitaminc-aead` dependency, because the generated code names that crate.

## Task map

| Task | Use | In place of |
|---|---|---|
| Hold a key, token, password or other secret | `Protected<T>` (`protected`) | `String`, `Vec<u8>`, `[u8; N]`, `Zeroizing<T>` |
| Hold a key for the whole process | `Locked<T>` (`protected`) | a `static` or lazily initialised byte array |
| Compare secrets or tags | `Equatable<Protected<T>>`, `TimingSafeEq` (`protected`) | `==` |
| Hash secret input | `ProtectedDigest` (`protected`) | a digest fed raw secret bytes |
| Require a non-empty label or context | `NonEmpty<T>`, `nonempty!` (`protected`) | `&str` |
| Generate random bytes, keys or structs | `SafeRand` + `Generatable` (`random`) | `rand::thread_rng`, `rand::random` |
| Pick a random index | `SafeRand::next_below` (`random`) | `rng.gen::<u32>() % n` |
| Generate a password | `SafeRand::next_below` per character, built inside `Protected::generate` (`random`, `protected`) | `rand`'s `Alphanumeric` sampler, or `vitaminc-password`, whose value cannot be read yet |
| Encrypt a value or struct | `encrypt` / `decrypt`, `Aes256Cipher`, `#[derive(Encrypt, Decrypt)]` (`encrypt`) | an AEAD crate with nonces managed by hand |
| Wrap a data key under a key-encryption key | `Key::wrap` / `Key::from_wrapped` (`encrypt`) | encrypting key bytes as ordinary data |
| Keyed hash, blind index, equality term | `HmacSha256Prf` + `PrfValue::prf_with_context` (`hmac`, `prf`) | an unkeyed hash, or HMAC with no context |
| HMAC with the key held in AWS KMS | `AwsKmsHmac` (`aws-kms`) | fetching the key into process memory |
| Order-revealing or normalised index terms | `vitaminc-ore`, `vitaminc-normalize` (`ore`, `normalize`) | encoding values for comparison by hand |

Working code for each common task is in [RECIPES.md](RECIPES.md). Read the recipe before writing the code, and copy it as written. For rows without a recipe, read the crate's docs on docs.rs.

## Rules

- **Wrap at the source.** A secret becomes `Protected` the moment it is read or generated (`Protected::generate_ok`, `Protected::random`) and stays wrapped until the last call that needs it. Transform it with `map`, `zip` and `flatten`, which keep the result wrapped.
- **Unwrap only at a boundary.** `risky_unwrap` and `risky_ref` hand the plain value to code outside vitaminc, along with the duty to wipe it and keep it out of logs. Use them only at the call into an external API, inside that one call.
- **Bind every ciphertext to its place.** Pass associated data naming what the ciphertext belongs to, such as `"users/42/email"`, as the third argument to `encrypt` and `decrypt`. A ciphertext moved to another record then fails to open. `()` is for values that truly belong nowhere.
- **Name every derivation.** Give `prf_with_context` a context naming the index and its version, such as `"users/email/exact/v1"`, and use the same input type and context for writes and for queries.
- **Keys come from a generator, an unwrap or the secret store**: generate a data key once with `Key::random(&mut SafeRand)`, store it wrapped, and load it with `Key::from_wrapped`. The root key-encryption key is the one key built from bytes: fetch its 32 bytes from the secret store at startup and pass them straight to `Key::from`, keeping no other copy. No vitaminc API fetches an AES key from a KMS (`AwsKmsHmac` computes HMACs only), so the secret store is the caller's code. A key written into the source, such as `Key::from([0u8; 32])`, is a test fixture.
- **Log the error kind, never the value.** Cipher failures are deliberately the opaque `Unspecified`: a wrong key, a wrong AAD and a tampered ciphertext look the same.

## Behaviour to know

- `#[aead(passthrough)]` stores a field in the clear by design: it is neither encrypted nor authenticated, so it can be read, edited or removed in storage while every encrypted field beside it still decrypts. Use it only for non-sensitive fields, treat what it returns as untrusted input, and never let it decide authorization, tenancy or which record to trust. A value that must be readable but tamper-evident belongs in the associated data.
- In an encrypted sequence, each element is bound to the sequence but not to its index, and the element count is not authenticated. If order or completeness matters, put it in the value or the associated data.
- `Aes256Cipher` is not `Sync` (its nonce generator is a `RefCell`). Build one per thread or per task rather than sharing one.
- `Protected` is never `Copy`. Duplicate it with an explicit `clone()`; each clone is wiped when dropped.
- `Locked` is best-effort by default: when the OS refuses to lock memory, the value still exists and `lock_error()` says why. Call `require_locked()`, or set `LockPolicy::Strict` at startup, when locking is mandatory.
- `vitaminc-password` is not usable yet. `Password<N>`, `AlphaNumericPassword<N>` and `AlphaPassword<N>` generate a value but give no way to read it: their string conversions (`into_protected_string`, `into_unprotected_string`) are unimplemented and panic. Use the password recipe in RECIPES.md instead.

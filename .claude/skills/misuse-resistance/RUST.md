# Misuse resistance in Rust

Techniques for reaching each rung of the ladder in [SKILL.md](SKILL.md). The snippets use only `std` so they show the pattern; in production, reach for a vetted crate for the secret type itself (`vitaminc-protected`, or `zeroize` plus `subtle`). Cryptographic internals are `todo!()`, so a copied snippet fails loudly instead of shipping a placeholder: do the same in your own examples.

## Rung 1: impossible to get wrong

Remove the parameter. If the library generates the nonce, no caller can reuse one.

```rust
pub struct Ciphertext { nonce: [u8; 12], sealed: Vec<u8> }

pub struct Cipher { /* key, rng */ }

impl Cipher {
    // No `nonce` argument: the cipher draws a fresh one per call.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Ciphertext {
        let nonce = self.fresh_nonce();
        let sealed = self.seal(&nonce, plaintext, aad);
        Ciphertext { nonce, sealed }
    }

    fn fresh_nonce(&self) -> [u8; 12] { todo!("draw from the CSPRNG") }
    fn seal(&self, _nonce: &[u8; 12], _plaintext: &[u8], _aad: &[u8]) -> Vec<u8> { todo!("AEAD seal") }
}
```

Make the valid value the only value. Private fields plus one constructor mean every instance passed the check. A blanket implementation over a sealed trait means no downstream type can supply its own, divergent, implementation.

```rust
mod sealed { pub trait Sealed {} }

/// Implemented only inside this crate.
pub trait Algorithm: sealed::Sealed { const NAME: &'static str; }

pub struct Aes256Gcm;
impl sealed::Sealed for Aes256Gcm {}
impl Algorithm for Aes256Gcm { const NAME: &'static str = "AES-256-GCM"; }
```

## Rung 2: won't compile

Put the invariant in the type.

- **Newtypes over raw bytes.** `Key([u8; 32])`, never `&[u8]`. A key, a nonce and a ciphertext should not be interchangeable.
- **Const generics for lengths.** A `[u8; 32]` argument makes the length check infallible and removes the error path. Take runtime-length material through a separate, fallible `try_from_bytes` that rejects weak inputs.
- **Typestate.** Encode protocol steps as types, so the unsafe order does not type-check:

```rust
pub struct VerifyingKey { /* public key */ }

pub struct Unverified { message: Vec<u8>, signature: [u8; 64] }
pub struct Verified(Vec<u8>);

pub struct BadSignature;

impl Unverified {
    // The caller supplies a key, never the check: the library owns the
    // verification, so there is no predicate to stub out with `|_| true`.
    pub fn verify(self, key: &VerifyingKey) -> Result<Verified, BadSignature> {
        key.check(&self.message, &self.signature)?;
        Ok(Verified(self.message))
    }
}

impl VerifyingKey {
    fn check(&self, _message: &[u8], _signature: &[u8; 64]) -> Result<(), BadSignature> {
        todo!("signature verification")
    }
}

/// Only verified messages can be processed. `Verified` has a private field, so
/// the only way to obtain one is a signature check the library performs.
pub fn process(message: Verified) -> usize { message.0.len() }
```

- **Consume one-shot values.** Take `self` by value for anything that must be used once (a nonce, a one-time key, a request token), so a second use is a move error.
- **Withhold dangerous traits.** A secret type implements no `Copy` (a copy has no owner to wipe it on drop), no `Default` (a default key is an all-zero key), no `Deref`, no derived `PartialEq` (it is not constant-time), no `Display`, and no `Serialize` unless through an explicitly named export type.
- **Post-monomorphisation checks.** A `const` assertion can reject a generic parameter at compile time. Use a named associated `const` item, not an inline `const { }` block: trybuild does not report inline-const failures.
- **Test the guarantee.** Every rung-2 claim gets a compile-fail test (trybuild) showing the misuse does not compile. Without one, a refactor can silently drop it to rung 6 or 7.

## Rung 3: compiles with a warning

- `#[must_use]` on results, tags, and anything whose silent drop is a bug.
- `#[deprecated(note = "use X instead: <reason>")]` names the replacement.
- Ship a `clippy.toml` snippet with `disallowed-methods` / `disallowed-types` for downstream users (for example, banning a non-cryptographic RNG in key-handling code).

## Rung 4: the simplest use is correct

- The shortest constructor yields the secure configuration. Options exist only to make it stricter, or sit behind an explicitly named alternative.
- Prefer one function with no choices over a builder with secure defaults: a builder invites changing them.

## Rung 5: the name says how to use it

Name escape hatches so they are obvious and greppable: `risky_unwrap`, `risky_ref`, a `hazmat` module, an `insecure-*` feature, `*_unchecked`. Obvious, not easy: a caller who needs a legacy algorithm should find the door, and a reviewer should find every use with one search.

## Rung 6: fails loudly at runtime

- Return `Result` with an error that reveals nothing about the secret. Cipher failures are one opaque error: a wrong key, a wrong AAD and a tampered ciphertext are indistinguishable.
- Refuse weak input (short keys, empty contexts) at construction, once, then carry the proof in the type.
- Return errors rather than panicking on conditions that depend on a secret: a panic is an observable side channel.

## Secret types: the full checklist

A type holding a secret:

- wipes on drop (`Zeroize` + `ZeroizeOnDrop`, or a wrapper that does it);
- prints an opaque `Debug`, no `Display`;
- exposes its contents only through named, greppable methods, and offers `map`-style combinators so most code never unwraps;
- compares in constant time, if at all;
- serialises only through an explicit export type;
- for process-lifetime secrets, lives in memory locked against swap and core dumps, since nothing drops a static or a killed process.

## Errors

- `Display` and `Debug` on error types never include plaintext, keys, or values derived from them. Report the path or position (`field "email"`), not the value. Redact messages that come from user-supplied types.
- Mark error enums `#[non_exhaustive]` so variants can be added without a breaking change.

## Features

Optional functionality goes behind cargo features. Dangerous functionality goes behind a feature whose name says so, off by default.

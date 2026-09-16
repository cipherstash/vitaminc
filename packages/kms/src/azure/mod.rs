//! Azure Key Vault (and Managed HSM) adapters.
//!
//! One adapter type per key purpose (see `CONTEXT.md`):
//!
//! - [`AzureDataKeySource`]: data keys via local generation plus
//!   `wrapKey`/`unwrapKey`, and direct `encrypt`/`decrypt`, over an RSA
//!   or oct-HSM key ([`AzureKeyKind`]).
//! - [`AzureMacKey`]: HMAC via `sign`/`verify` with `HS*` on an oct-HSM key.
//! - [`AzureSigningKey`]: `sign`/`verify`/`getKey` over an RSA or EC key.
//!
//! Every adapter takes a ready [`azure_security_keyvault_keys::KeyClient`];
//! credentials and endpoint are the caller's concern.
//!
//! Each adapter binds to one key *name*. New work goes to whichever version
//! the vault currently considers current, and anything that has to be
//! reversed later — a [`KeyId`](crate::KeyId), a ciphertext — records the
//! exact version that produced it, so rotating a key never strands data.
//! `with_key_version` pins a version where a caller needs one.

mod data_key;
mod envelope;
mod mac;
mod sign;
#[cfg(test)]
mod testing;

pub use data_key::{AzureDataKeySource, AzureKeyKind, Error as AzureDataKeySourceError};
pub use mac::{AzureMacKey, Error as AzureMacKeyError};
pub use sign::{AzureSigningKey, Error as AzureSigningKeyError};

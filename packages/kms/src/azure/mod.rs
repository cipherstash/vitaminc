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


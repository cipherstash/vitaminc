//! HashiCorp Vault Transit adapters.
//!
//! One adapter type per key purpose (see `CONTEXT.md`):
//!
//! - [`VaultDataKeySource`]: data keys via `datakey`/`datakeys` (native
//!   batch) and `decrypt` with `batch_input`, plus direct `encrypt`/`decrypt`.
//! - [`VaultMacKey`]: HMAC via `hmac` and `verify`.
//! - [`VaultSigningKey`]: signatures via `sign` and `verify`, public key via
//!   `export/public-key`.
//!
//! Every adapter takes a ready [`vaultrs::client::VaultClient`]; address,
//! token, namespace and TLS are the caller's concern. Keys must not be
//! `derived` (the traits carry no context). One Transit key may back both
//! a MAC key and a signing key.


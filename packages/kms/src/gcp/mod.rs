//! Google Cloud KMS adapters.
//!
//! One adapter type per key purpose (see `CONTEXT.md`):
//!
//! - [`GcpDataKeySource`]: bound to a `CryptoKey`; data keys via local
//!   generation plus `encrypt`/`decrypt`, and direct `encrypt`/`decrypt`.
//! - [`GcpMacKey`]: bound to a `CryptoKeyVersion`; `macSign`/`macVerify`.
//! - [`GcpSigningKey`]: bound to a `CryptoKeyVersion`; `asymmetricSign`,
//!   local verification against `getPublicKey`.
//!
//! Every adapter takes a ready [`google_cloud_kms_v1::client::KeyManagementService`];
//! credentials and endpoint are the caller's concern. Every call computes
//! CRC32C checksums on the request and verifies them on the response, as
//! Google's data-integrity guidelines require.
//!
//! Two consequences of Google Cloud KMS's shape are worth stating here,
//! because they are what make these adapters differ from the other
//! backends':
//!
//! - **Which key a call targets.** `encrypt` accepts a `CryptoKey` and
//!   uses its primary version, and `decrypt` accepts nothing else — the
//!   ciphertext itself names the version that made it. Every other crypto
//!   operation is defined only on a `CryptoKeyVersion`. So
//!   [`GcpDataKeySource`] binds to a `CryptoKey` while [`GcpMacKey`] and
//!   [`GcpSigningKey`] bind to a `CryptoKeyVersion`.
//! - **Verification.** [`GcpMacKey`] verifies server-side with
//!   `macVerify`, whose verdict arrives as data and whose second-order
//!   `verifiedSuccessIntegrity` flag is resolved inside the adapter, by
//!   discarding the response and retrying once. [`GcpSigningKey`] has no server-side counterpart to
//!   call — Google Cloud KMS has no asymmetric verify — so it fetches the
//!   public key once at construction and verifies **locally**, consuming
//!   the caller's digest as-is. That is also why its constructor is
//!   `async` and fallible: it is the moment the bound key version's
//!   algorithm is checked against the requested [`crate::SignatureAlgorithm`].

mod data_key;
mod integrity;
mod mac;
mod sign;

#[cfg(test)]
mod test_support;

pub use data_key::{Error as GcpDataKeySourceError, GcpDataKeySource};

/// [`GcpDataKeySource`] with pooled key isolation: one key shared across a
/// batch, one `encrypt` per batch. Build it as
/// `PooledDataKeySource::new(GcpDataKeySource::new(...))`. See
/// [`PooledDataKeySource`](crate::PooledDataKeySource) for the trade-off.
pub type GcpPooledDataKeySource<const N: usize> = crate::PooledDataKeySource<GcpDataKeySource<N>>;
pub use mac::{Error as GcpMacKeyError, GcpMacKey};
pub use sign::{Error as GcpSigningKeyError, GcpSigningKey};

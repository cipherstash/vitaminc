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


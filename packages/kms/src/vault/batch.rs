//! The two Transit batch endpoints `vaultrs` does not define.
//!
//! `vaultrs` covers every single-item Transit call, but neither
//! `POST {mount}/datakeys/:type/:name` nor `batch_input` on
//! `POST {mount}/decrypt/:name`. Those two are the only native batch
//! primitives any of the four backends offer, so ADR 0002 commits to
//! defining them here with `rustify`'s endpoint macro — the same macro
//! `vaultrs` uses — and executing them through the caller's
//! [`vaultrs::client::VaultClient`] via [`vaultrs::api::exec_with_result`].
//!
//! Both request structs mirror `vaultrs`'s own shape: `mount` and `name`
//! build the path and are `#[endpoint(skip)]`ped out of the body, and
//! every remaining field is serialised into the JSON body.

use rustify_derive::Endpoint;
use serde::{Deserialize, Serialize};

/// `POST {mount}/datakeys/plaintext/{name}` — mint `count` distinct data
/// keys of `bits` bits in one round trip.
///
/// The plural `datakeys` path is a different endpoint from the singular
/// `datakey` one `vaultrs` wraps, not a parameterisation of it: it takes a
/// `count` and answers with a `key_pairs` array.
///
/// It is **Vault Enterprise only**, which HashiCorp's API reference does
/// not say. Community Vault registers only `datakey/:type/:name` (see
/// `builtin/logical/transit/path_datakey.go`) and answers this path with
/// `404 unsupported path`; `derivedkeys` is absent for the same reason.
/// Verified against `hashicorp/vault:2.1.0`.
#[derive(Debug, Endpoint)]
#[endpoint(
    path = "{self.mount}/datakeys/plaintext/{self.name}",
    method = "POST",
    response = "GenerateDataKeysResponse"
)]
pub(super) struct GenerateDataKeysRequest {
    #[endpoint(skip)]
    pub mount: String,
    #[endpoint(skip)]
    pub name: String,
    /// How many keys to mint. Every key in the batch is distinct, which is
    /// what makes `KeyIsolation::PerValue` affordable here.
    pub count: u64,
    /// Key size in bits. Vault accepts only 128, 256 or 512.
    pub bits: u16,
}

#[derive(Debug, Deserialize)]
pub(super) struct GenerateDataKeysResponse {
    pub key_pairs: Vec<DataKeyPair>,
}

#[derive(Debug, Deserialize)]
pub(super) struct DataKeyPair {
    /// Base64 key material.
    pub plaintext: String,
    /// The `vault:v<N>:...` handle that decrypts it again.
    pub ciphertext: String,
}

/// `POST {mount}/decrypt/{name}` with `batch_input` — unwrap many data
/// keys in one round trip.
///
/// Vault documents that `batch_results` keeps the input order, so the
/// adapter maps results back positionally rather than by `reference`.
///
/// `partial_failure_response_code` is set to 200 deliberately. Vault's
/// default is 400, which makes a partly-failed batch arrive as an HTTP
/// error with the per-item detail thrown away; at 200 the adapter reads
/// `batch_results` itself and can say which index failed. A batch in which
/// *every* item fails still comes back as an HTTP error whatever this is
/// set to, so a failure is an error either way — only the message differs.
#[derive(Debug, Endpoint)]
#[endpoint(
    path = "{self.mount}/decrypt/{self.name}",
    method = "POST",
    response = "BatchDecryptResponse"
)]
pub(super) struct BatchDecryptRequest {
    #[endpoint(skip)]
    pub mount: String,
    #[endpoint(skip)]
    pub name: String,
    pub batch_input: Vec<BatchDecryptItem>,
    pub partial_failure_response_code: u16,
}

#[derive(Debug, Serialize)]
pub(super) struct BatchDecryptItem {
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct BatchDecryptResponse {
    pub batch_results: Vec<BatchDecryptResult>,
}

/// One slot of `batch_results`. Vault fills in exactly one of the two:
/// `plaintext` on success, `error` on a per-item failure.
#[derive(Debug, Deserialize)]
pub(super) struct BatchDecryptResult {
    pub plaintext: Option<String>,
    pub error: Option<String>,
}

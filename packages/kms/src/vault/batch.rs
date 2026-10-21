//! The Transit endpoints `vaultrs` does not define, or defines without a
//! field the adapter needs.
//!
//! `vaultrs` covers every single-item Transit call, but neither
//! `POST {mount}/datakeys/:type/:name` nor `batch_input` on
//! `POST {mount}/decrypt/:name`. Those two are the only native batch
//! primitives any of the four backends offer, so ADR 0003 commits to
//! defining them here with `rustify`'s endpoint macro — the same macro
//! `vaultrs` uses — and executing them through the caller's
//! [`vaultrs::client::VaultClient`] via [`vaultrs::api::exec_with_result`].
//!
//! `sign` and `verify` are here too, because the `vaultrs` 0.8 requests
//! have no `salt_length` field, and RSA-PSS needs it (see [`SignRequest`]).
//! Their `ed25519` forms are here for the same reason of shape: they send
//! a message, and no hash fields (see [`SignMessageRequest`]).
//!
//! Every request struct mirrors `vaultrs`'s own shape: `mount` and `name`
//! build the path and are `#[endpoint(skip)]`ped out of the body, and
//! every remaining field is serialised into the JSON body.

use rustify_derive::Endpoint;
use serde::{Deserialize, Serialize};
use vaultrs::api::transit::responses::{SignDataResponse, VerifySignedDataResponse};
use vaultrs::api::transit::{HashAlgorithm, MarshalingAlgorithm, SignatureAlgorithm};

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

/// `POST {mount}/sign/{name}` — the single-item sign call, with the
/// `salt_length` field that `vaultrs` 0.8's `SignDataRequest` does not
/// have.
///
/// For RSA-PSS, Vault's `salt_length` default is `auto`. On `sign`, `auto`
/// gives the largest salt the key allows (222 bytes for `rsa-2048` with
/// SHA-256), not the digest-length salt that
/// [`RsaPssSha256`](crate::algorithm::SignatureAlgorithm::RsaPssSha256)
/// and its siblings promise. The adapter sends `"hash"`, which is the
/// digest length. Verified against `hashicorp/vault:2.1.0`.
#[derive(Debug, Endpoint)]
#[endpoint(
    path = "{self.mount}/sign/{self.name}",
    method = "POST",
    response = "SignDataResponse"
)]
pub(super) struct SignRequest {
    #[endpoint(skip)]
    pub mount: String,
    #[endpoint(skip)]
    pub name: String,
    pub input: String,
    pub key_version: u64,
    pub hash_algorithm: HashAlgorithm,
    pub prehashed: bool,
    pub marshaling_algorithm: MarshalingAlgorithm,
    /// RSA only. Vault documents it as unused for ECDSA.
    pub signature_algorithm: Option<SignatureAlgorithm>,
    /// RSA-PSS only. See the struct docs.
    pub salt_length: Option<&'static str>,
}

/// `POST {mount}/verify/{name}` — the single-item verify call, with the
/// `salt_length` field that `vaultrs` 0.8's `VerifySignedDataRequest` does
/// not have.
///
/// With `"hash"`, Vault accepts only a digest-length PSS salt, which is the
/// salt [`SignRequest`] asks for. With the `auto` default, Vault would
/// accept any salt length.
#[derive(Debug, Endpoint)]
#[endpoint(
    path = "{self.mount}/verify/{self.name}",
    method = "POST",
    response = "VerifySignedDataResponse"
)]
pub(super) struct VerifyRequest {
    #[endpoint(skip)]
    pub mount: String,
    #[endpoint(skip)]
    pub name: String,
    pub input: String,
    /// `vault:v<N>:<base64>`.
    pub signature: String,
    pub hash_algorithm: HashAlgorithm,
    pub prehashed: bool,
    pub marshaling_algorithm: MarshalingAlgorithm,
    pub signature_algorithm: Option<SignatureAlgorithm>,
    pub salt_length: Option<&'static str>,
}

/// `POST {mount}/sign/{name}` for an `ed25519` key, which signs the whole
/// message. Vault ignores `hash_algorithm`, `marshaling_algorithm`,
/// `signature_algorithm` and `salt_length` for this key type, so the
/// request does not send them, and a reader of a request log does not see
/// a hash that is not used.
///
/// `prehashed` must be `false`: Vault answers `true` with `400 only Pure
/// Ed25519 signatures supported, prehashed must be false`. The adapter
/// sends it explicitly, so a change of Vault's default cannot change what
/// is signed. Verified against `hashicorp/vault:2.1.0`.
#[derive(Debug, Endpoint)]
#[endpoint(
    path = "{self.mount}/sign/{self.name}",
    method = "POST",
    response = "SignDataResponse"
)]
pub(super) struct SignMessageRequest {
    #[endpoint(skip)]
    pub mount: String,
    #[endpoint(skip)]
    pub name: String,
    /// The base64 message.
    pub input: String,
    pub key_version: u64,
    pub prehashed: bool,
}

/// `POST {mount}/verify/{name}` for an `ed25519` key. See
/// [`SignMessageRequest`].
#[derive(Debug, Endpoint)]
#[endpoint(
    path = "{self.mount}/verify/{self.name}",
    method = "POST",
    response = "VerifySignedDataResponse"
)]
pub(super) struct VerifyMessageRequest {
    #[endpoint(skip)]
    pub mount: String,
    #[endpoint(skip)]
    pub name: String,
    /// The base64 message.
    pub input: String,
    /// `vault:v<N>:<base64>`.
    pub signature: String,
    pub prehashed: bool,
}

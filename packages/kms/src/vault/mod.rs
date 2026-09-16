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
//!
//! One edition caveat: batch *generation* (`datakeys`) is Vault
//! Enterprise-only, which HashiCorp's API reference does not say. Batch
//! retrieval (`decrypt` with `batch_input`) is in both editions. See
//! [`VaultDataKeySource`].
//!
//! # Key-version binding
//!
//! Vault's `hmac` and `sign` answer with `vault:v<N>:<base64>`, where `N`
//! is the key version that produced the tag. The trait boundary carries
//! raw canonical bytes (ADR 0001), so the adapter strips that prefix on
//! the way out — and `verify` has to put it back on the way in, because
//! Vault's `verify` will not accept a bare tag.
//!
//! [`VaultMacKey`] and [`VaultSigningKey`] therefore bind to one explicit
//! key version at construction, the same shape Google Cloud KMS forces by
//! binding to a `CryptoKeyVersion`. They pass that version on generation
//! and rebuild `vault:v<version>:` on verification. **Rotating the backend
//! key does not move an existing adapter onto the new version**: build a
//! second adapter for it, and keep the old one for as long as tags made
//! under the old version must still verify.
//!
//! [`VaultDataKeySource`] needs no such binding — its `KeyId` is the whole
//! `vault:v<N>:...` string, so the version travels with the data key.

mod batch;
mod data_key;
mod mac;
mod sign;

pub use data_key::{Error as VaultDataKeySourceError, VaultDataKeySource};
pub use mac::{Error as VaultMacKeyError, VaultMacKey};
pub use sign::{Error as VaultSigningKeyError, VaultSigningKey};

use base64::prelude::{Engine as _, BASE64_STANDARD};

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_STANDARD.decode(value)
}

/// Build the `vault:v<key_version>:<payload>` form Vault's `verify` wants,
/// from a tag the trait boundary carries as raw bytes.
pub(crate) fn with_key_version(key_version: u32, payload: &[u8]) -> String {
    format!("vault:v{}:{}", key_version, b64_encode(payload))
}

/// The inverse: take the base64 payload out of `vault:v<key_version>:...`,
/// rejecting any other key version so a silent version mismatch cannot
/// turn into a tag that never verifies again.
pub(crate) fn strip_key_version(value: &str, key_version: u32) -> Option<&str> {
    value.strip_prefix(&format!("vault:v{key_version}:"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;
    use vaultrs::client::VaultClientSettingsBuilder;

    /// The Transit key name the zero-network unit tests pretend to use.
    pub(crate) const KEY_NAME: &str = "unit-test-key";

    /// The path a Transit engine takes when it is enabled without one.
    pub(crate) const DEFAULT_MOUNT: &str = "transit";

    /// A `VaultClient` pointed at a local mock server. `vaultrs` offers no
    /// mock seam of its own, so the seam is the HTTP address.
    pub(crate) fn test_client(server: &MockServer) -> vaultrs::client::VaultClient {
        vaultrs::client::VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(server.base_url())
                .token("unit-test-token")
                .build()
                .unwrap(),
        )
        .unwrap()
    }

    /// Wrap a payload in the envelope every Vault API response carries;
    /// `vaultrs` strips it and rejects a response without it.
    pub(crate) fn data(body: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "request_id": "00000000-0000-0000-0000-000000000000",
            "lease_id": "",
            "renewable": false,
            "lease_duration": 0,
            "data": body,
            "warnings": null,
            "wrap_info": null,
            "auth": null,
        })
    }

    /// The dev-mode Vault of `packages/kms/docker-compose.yml`. The
    /// integration tests below talk to it rather than skipping themselves
    /// when it is absent (CIP-4029): a silently skipped test proves
    /// nothing.
    const INTEGRATION_ADDRESS: &str = "http://localhost:8200";
    const INTEGRATION_TOKEN: &str = "root";

    /// Build a Transit key of `key_type` under a name no other test uses,
    /// enabling the Transit engine first if it is not already mounted.
    ///
    /// Every test makes its own key, so tests never contend over key
    /// versions and the dev server needs no cleaning up between runs.
    pub(crate) async fn transit_key(
        key_type: vaultrs::api::transit::KeyType,
    ) -> (vaultrs::client::VaultClient, String) {
        use vaultrs::api::transit::requests::CreateKeyRequest;
        use vaultrs::error::ClientError;

        let client = vaultrs::client::VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(INTEGRATION_ADDRESS)
                .token(INTEGRATION_TOKEN)
                .build()
                .unwrap(),
        )
        .unwrap();

        // Idempotent: concurrent tests race to enable the same mount and
        // all but one of them lose.
        match vaultrs::sys::mount::enable(&client, DEFAULT_MOUNT, "transit", None).await {
            Ok(()) => {}
            Err(ClientError::APIError { errors, .. })
                if errors.iter().any(|e| e.contains("path is already in use")) => {}
            Err(e) => panic!("could not enable the transit engine at {INTEGRATION_ADDRESS}: {e}"),
        }

        let name = unique_key_name();
        let mut opts = CreateKeyRequest::builder();
        opts.key_type(key_type);
        vaultrs::transit::key::create(&client, DEFAULT_MOUNT, &name, Some(&mut opts))
            .await
            .unwrap();

        (client, name)
    }

    fn unique_key_name() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("vitaminc-test-{nanos}-{n}")
    }

    #[test]
    fn a_tag_round_trips_through_the_versioned_form() {
        let tag = [0xABu8, 0xCD, 0xEF];

        let versioned = with_key_version(7, &tag);

        assert_eq!(versioned, "vault:v7:q83v");
        assert_eq!(
            b64_decode(strip_key_version(&versioned, 7).unwrap()).unwrap(),
            tag
        );
    }

    #[test]
    fn stripping_rejects_another_version_or_no_prefix() {
        assert!(strip_key_version("vault:v2:q83v", 1).is_none());
        assert!(strip_key_version("q83v", 1).is_none());
        // `v1` must not match a `v12` prefix.
        assert!(strip_key_version("vault:v12:q83v", 1).is_none());
    }
}

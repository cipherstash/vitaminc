# Vitamin C KMS

[![Crates.io](https://img.shields.io/crates/v/vitaminc-kms.svg)](https://crates.io/crates/vitaminc-kms)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

A `MAC` implementation using [vitaminc](https://github.com/cipherstash/vitaminc) that uses AWS KMS to generate HMACs.
This implementation is asynchronous and uses the [aws_sdk_kms] crate to interact with AWS KMS.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Key-provider capability traits

Alongside [`AwsKmsHmac`], this crate defines a family of small, capability-based
traits for using a KMS backend as a key provider: minting and retrieving data
keys ([`GenerateDataKey`]/[`RetrieveDataKey`], with batch variants
[`BatchGenerateDataKey`]/[`BatchRetrieveDataKey`] and the
[`fan_out_generate`]/[`pooled_key_generate`]/[`dedup_retrieve`] shims for
backends without native batch support), deriving a deterministic per-keyset
index key ([`load_index_key`]), encrypting/decrypting directly under a
KMS-held key ([`EncryptWithKey`]/[`DecryptWithKey`]), and MAC/signing
operations ([`GenerateMac`]/[`VerifyMac`], [`Sign`]/[`Verify`],
[`GetPublicKey`]).

These traits deliberately cover more than any single consumer (e.g.
`stack-encrypt`) calls today. `vitaminc-kms` is a general-purpose,
open-source cryptography crate, not a private integration layer for one
downstream project — limiting its trait surface to exactly what one consumer
currently calls would fit an internal abstraction, but not the philosophy of
a general-purpose crate meant for other users and use cases. The traits
reflect the real capabilities KMS vendors offer, not just the narrow slice
one caller happens to exercise today.

[`AwsKmsHmac`] is deliberately unrelated to these traits: it's built on AWS
KMS's `GenerateMac` operation as a streaming `Update`/`AsyncFixedOutput`
construction, a different capability shape entirely, and shares no code with
them.

# Example

```no_run
use aws_sdk_kms::Client;
use vitaminc_protected::Protected;
use vitaminc_traits::Update;
use vitaminc_async_traits::AsyncFixedOutput;
use vitaminc_kms::{AwsKmsHmac, Info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    # use aws_sdk_kms::types::{KeySpec, KeyUsageType};
    # let endpoint_url = "http://localhost:4566";
    # let creds = aws_sdk_kms::config::Credentials::new("fake", "fake", None, None, "test");
    use aws_config::{BehaviorVersion, Region};

    let config = aws_sdk_kms::config::Builder::default()
        .behavior_version(BehaviorVersion::v2026_01_12())
        .region(Region::new("us-east-1"))
    #   .credentials_provider(creds)
        .endpoint_url(endpoint_url)
        .build();

    # let key = Client::from_conf(config.clone())
    #   .create_key()
    #   .key_usage(KeyUsageType::GenerateVerifyMac)
    #   .key_spec(KeySpec::Hmac512)
    #   .send()
    #   .await?;
    # let key_id = key.key_metadata().unwrap().key_id().to_owned();
    // `key_id` is the ID or ARN of the KMS key to use
    let tag = AwsKmsHmac::<64>::new(config, key_id)
        .chain(&Protected::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
        .chain(Info("account_id"))
        .try_finalize_fixed()
        .await?;

    Ok(())
}
```

## Running the tests

Most tests use `aws-smithy-mocks` and need no external service. A few
(`AwsKmsHmac`'s `test_finalize`) exercise a real `aws-sdk-kms` client against
[LocalStack](https://www.localstack.cloud/) on `localhost:4566` — bring it up
with the bundled `docker-compose.yml`:

```sh
docker compose -f packages/kms/docker-compose.yml up -d
cargo test -p vitaminc-kms
docker compose -f packages/kms/docker-compose.yml down
```

LocalStack Community's `kms` service covers the operations this crate needs
(`CreateKey`/`GenerateDataKey`/`Decrypt`/`GenerateMac`) — no Pro tier required.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

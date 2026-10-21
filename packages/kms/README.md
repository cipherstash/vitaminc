# Vitamin C KMS

[![Crates.io](https://img.shields.io/crates/v/vitaminc-kms.svg)](https://crates.io/crates/vitaminc-kms)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

Capability traits for using a key management service as a key provider,
with adapters for AWS KMS, Azure Key Vault, Google Cloud KMS and HashiCorp
Vault Transit. Everything is asynchronous.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## Key-provider capability traits

The crate defines a family of small, capability-based traits: minting and
retrieving data keys ([`GenerateDataKey`]/[`RetrieveDataKey`], with batch
variants [`BatchGenerateDataKey`]/[`BatchRetrieveDataKey`] and the
[`fan_out_generate`]/[`dedup_retrieve`] shims for
backends without native batch support), deriving a deterministic per-keyset
index key ([`load_index_key`]), encrypting/decrypting directly under a
KMS-held key ([`EncryptWithKey`]/[`DecryptWithKey`]), and MAC/signing
operations ([`GenerateMac`]/[`VerifyMac`], [`Sign`]/[`Verify`] over a
digest, [`SignMessage`]/[`VerifyMessage`] over a whole message, and
[`GetPublicKey`]).

These traits deliberately cover more than any single consumer (e.g.
`stack-encrypt`) calls today. `vitaminc-kms` is a general-purpose,
open-source cryptography crate, not a private integration layer for one
downstream project. The traits reflect the real capabilities KMS vendors
offer, not just the narrow slice one caller happens to exercise today.

## Key providers

The capability traits describe what one backend key can do. A *key
provider* is the shape a client library is generic over:
[`KeyProvider`] mints and retrieves batches of data keys against one
backend key or keyset bound at construction, and [`IndexKeyProvider`]
loads the one fixed index key for that keyset. They are separate traits
because a vendor source supplies the first natively and the second only
through a persisted identifier, while a service such as ZeroKMS supplies
both.

Every key in a batch carries a [`Binding`]: bytes the caller attaches when
the key is minted and must present again to retrieve it. A backend either
binds those bytes into the key server-side or ignores them, and says which
through [`BindingSupport`], so a caller that needs binding can check
before it depends on it. The AWS KMS and Google Cloud KMS sources are
`Bound`. The Azure Key Vault and Vault Transit sources are `Unbound`.

Every vendor data key source in this crate implements [`KeyProvider`], so
the same consumer runs on any of them. The pieces built on top:

- [`FixedIndexKeySource<T>`](provider::FixedIndexKeySource) pairs any
  provider with the one `KeyId` a deployment provisioned for index-key
  derivation, giving it an [`IndexKeyProvider`] as well.
- [`CachingKeyProvider<T>`](provider::CachingKeyProvider) (feature
  `caching`, on by default) memoizes retrieved keys, keyed on the key id
  *and* the binding, so a hit is never a key the backend would have answered
  differently for. Minting is never cached: a cached mint would share one
  key across values, and one shared key cannot carry the binding of each
  value. Opt in deliberately: against a backend that audits each
  retrieval, a hit skips that audit entry and policy check.
- `FakeKeyProvider`, behind the `test-support` feature, is an in-memory
  provider whose generate/retrieve round-trips and whose bindings are
  enforced, for consumers' own tests.

## Adapters

Each vendor lives behind a Cargo feature that pulls in only that vendor's
SDK. `aws` is on by default.

| Feature | Backend | Data keys | Direct encrypt | MAC | Signing | Local tests |
|---|---|---|---|---|---|---|
| `aws` | AWS KMS | `AwsDataKeySource` | same type | `AwsMacKey` | `AwsSigningKey` | LocalStack |
| `azure` | Azure Key Vault / Managed HSM | `AzureDataKeySource` (Managed HSM `oct-HSM` only) | same type | `AzureMacKey` | `AzureSigningKey` | Lowkey Vault (MAC and signing only) |
| `gcp` | Google Cloud KMS | `GcpDataKeySource` | same type | `GcpMacKey` | `GcpSigningKey`, `GcpEd25519Key` | SDK stub only |
| `vault` | HashiCorp Vault Transit | `VaultDataKeySource` (`derived=true` keys only) | same type | `VaultMacKey` | `VaultSigningKey`, `VaultEd25519Key` | Vault dev server |

There is one adapter type per key purpose, because a backend key is created
for one purpose. A data key source also implements direct encryption under
the same symmetric key. MAC keys and signing keys are separate types, so a
symmetric adapter never exposes `GetPublicKey`.

Every adapter takes a ready vendor client. Credentials, endpoints and TLS
are the caller's concern; the adapter holds a client and one bound key.
Adapters live in their vendor module (`vitaminc_kms::azure::AzureMacKey`,
`vitaminc_kms::vault::VaultSigningKey`, ...); only the AWS data key source
and [`AwsKmsHmac`], which predate the modules, are also at the crate root.

Design notes that apply across vendors:

- **Batches.** AWS, Azure and Google have no batch primitive, so their
  batch traits fan out one call per key. There is no pooled source that
  mints one key per batch: one shared key cannot carry the bindings of
  several values (`docs/adr/0007`). Vault batches retrieval natively on
  every edition and generation natively on Vault Enterprise (on Community
  the adapter falls back to one call per key, see `docs/adr/0003`), always
  at per-value isolation. The token needs `read` on `<mount>/keys/<name>`
  and `update` on `<mount>/datakey/plaintext/<name>` and
  `<mount>/decrypt/<name>`; `update` on `<mount>/datakeys/plaintext/<name>`
  is optional. If Vault answers that path with `403`, the source uses the
  fan-out until it is rebuilt.
- **Signature algorithms** are named once, by [`SignatureAlgorithm`], and
  mapped by each adapter. ECDSA signatures are DER, Ed25519 signatures are
  the raw 64 bytes, and public keys are DER `SubjectPublicKeyInfo`, whatever
  the vendor returns natively (`docs/adr/0002`).
- **Ed25519** signs the whole message, so it is not a [`SignatureAlgorithm`]
  (those sign a digest). Google and Vault offer it with no pre-hashed mode,
  and AWS and Azure do not offer it. `GcpEd25519Key` and `VaultEd25519Key`
  implement [`SignMessage`]/[`VerifyMessage`] and not [`Sign`]/[`Verify`],
  and the digest signing keys do the opposite. Thus a digest cannot go to an
  Ed25519 key, and a message cannot go to a digest key: the call does not
  compile.
- **Key versions.** Azure `KeyId`s and ciphertexts carry the key version
  the vault used, so retrieval survives rotation. MAC and signing keys from
  Azure, Google and Vault bind to an explicit key version at construction,
  so a rotation does not make old tags or signatures fail to verify.
- **Google Cloud integrity.** Every GCP call sets CRC32C request checksums
  and verifies the response checksums, retrying once on a mismatch.

[`AwsKmsHmac`] predates the traits: a streaming `Update`/`AsyncFixedOutput`
MAC construction over AWS KMS `GenerateMac`. It is unrelated to the adapter
types and shares no code with them.

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

Unit tests mock each vendor's transport and need no network. The
integration tests talk to local emulators on fixed ports, and fail rather
than skip when one is absent:

| Backend | Emulator | Port |
|---|---|---|
| AWS KMS | [LocalStack](https://www.localstack.cloud/) Community | 4566 |
| HashiCorp Vault | `hashicorp/vault` in dev mode (or [OpenBao](https://openbao.org/) as a drop-in) | 8200 |
| Azure Key Vault | [Lowkey Vault](https://github.com/nagyesta/lowkey-vault) | 8443 |
| Google Cloud KMS | none viable; unit tests only | — |

Bring them up with the bundled compose file:

```sh
docker compose -f packages/kms/docker-compose.yml up -d --wait
cargo test -p vitaminc-kms --all-features
docker compose -f packages/kms/docker-compose.yml down
```

`cargo test -p vitaminc-kms` with default features runs only the AWS
adapter's tests and needs only LocalStack.

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT

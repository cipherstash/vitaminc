# CIP-3965/CIP-3985 AWS KMS API reference

This is a comprehensive reference for AWS KMS's API surface, covering every
operation listed in scope for the Rust capability-trait design effort. Unlike
[`cip-3965-backend-api-survey.md`](./cip-3965-backend-api-survey.md), which
maps a narrow, ZeroKMS-shaped subset of four vendors onto three operations,
this doc is single-vendor and exhaustive: one section per operation, with
full request parameters, response fields, error variants, and key-material
semantics, so the trait design can be checked against AWS's actual surface
rather than a use-case-shaped slice of it.

All facts below were fetched from the live pages at
`docs.aws.amazon.com/kms/latest/APIReference/` (and two developer-guide pages
for key-state and multi-Region-key semantics) in September 2026 — not from
memory. Exact field names, types, and enum values are transcribed verbatim
from those pages. See [Sources](#sources) for the full URL list.

**Shared conventions across nearly all operations**, stated once here rather
than repeated in every section:

- **`KeyId`** (String, length 1–2048) is the near-universal way to identify a
  KMS key. For cryptographic operations (`Encrypt`, `Decrypt`,
  `GenerateDataKey*`, `Sign`, `Verify`, `GenerateMac`, `VerifyMac`,
  `GetPublicKey`, `DescribeKey`, `CreateGrant`, `ListGrants`, `RevokeGrant`,
  `EnableKey`/`DisableKey`, rotation, deletion) it accepts key ID, key ARN,
  alias name (`alias/...`), or alias ARN, with cross-account calls requiring
  the ARN form. For key-policy and alias-management operations
  (`PutKeyPolicy`, `GetKeyPolicy`, `ListKeyPolicies`, `CreateAlias.TargetKeyId`,
  `UpdateAlias.TargetKeyId`) it accepts **only** key ID or key ARN — never an
  alias — a narrower contract worth modeling as a distinct type from the
  general-purpose key identifier.
- **`GrantTokens`** (Array of strings, 0–10 items, each 1–8192 chars) appears
  on essentially every cryptographic and grant-related call. It lets a caller
  present proof of a just-created grant before that grant has propagated
  fleet-wide (AWS KMS's permission model is eventually consistent, typically
  within 5 minutes).
- **`DryRun`** (Boolean) appears on many, but not all, mutating operations; on
  success it throws `DryRunOperationException` rather than performing the
  operation. Its presence is inconsistent — noted per-operation below.
- **Error taxonomy**: `DependencyTimeoutException` and `KMSInternalException`
  (both 500, retryable) and `KMSInvalidStateException`/`NotFoundException`
  (400) recur across nearly all operations. Operation-specific exceptions are
  called out per section. AWS overloads `KMSInvalidStateException` and
  `UnsupportedOperationException` heavily — many distinct causes share one
  exception type, distinguished only by the message text.
- **Cross-account support** varies per operation and is called out
  explicitly in each section — it is not a blanket property of the API.

---

## Key lifecycle

### CreateKey

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
(response type: [`KeyMetadata`](https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html))

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `BypassPolicyLockoutSafetyCheck` | Boolean | No | Default `false`. Skips the check that the calling principal can make a subsequent `PutKeyPolicy` call. |
| `CustomerMasterKeySpec` | String | No | **Deprecated** — use `KeySpec`. Same enum as `KeySpec` minus the newest additions. |
| `CustomKeyStoreId` | String | No | Length 1–64. Store's `ConnectionState` must be `CONNECTED`. Only for symmetric encryption keys (single Region). |
| `Description` | String | No | Length 0–8192. |
| `KeySpec` | String | No | Default `SYMMETRIC_DEFAULT`. Valid values: `RSA_2048 \| RSA_3072 \| RSA_4096 \| ECC_NIST_P256 \| ECC_NIST_P384 \| ECC_NIST_P521 \| ECC_SECG_P256K1 \| SYMMETRIC_DEFAULT \| HMAC_224 \| HMAC_256 \| HMAC_384 \| HMAC_512 \| SM2 \| ML_DSA_44 \| ML_DSA_65 \| ML_DSA_87 \| ECC_NIST_EDWARDS25519`. Immutable after creation. |
| `KeyUsage` | String | No for symmetric (default `ENCRYPT_DECRYPT`); **required** otherwise | Valid values: `SIGN_VERIFY \| ENCRYPT_DECRYPT \| GENERATE_VERIFY_MAC \| KEY_AGREEMENT`. Immutable; exactly one usage per key. |
| `MultiRegion` | Boolean | No | Default `false`. Creates a multi-Region **primary** key. Immutable. Not allowed with custom key stores. |
| `Origin` | String | No | Default `AWS_KMS`. Valid values: `AWS_KMS \| EXTERNAL \| AWS_CLOUDHSM \| EXTERNAL_KEY_STORE`. Immutable. `EXTERNAL` valid only for symmetric keys; `AWS_CLOUDHSM`/`EXTERNAL_KEY_STORE` require `KeySpec=SYMMETRIC_DEFAULT` + `CustomKeyStoreId`. |
| `Policy` | String | No | Length 1–32768. Pattern `[\t\n\r\x20-\xFF]+` (tab/LF/CR plus printable ASCII and Latin-1 Supplement). Defaults to the AWS default key policy if omitted. |
| `Tags` | Array of `Tag` | No | `{TagKey, TagValue}`, both required; at most one tag per `TagKey`. |
| `XksKeyId` | String | Required iff `Origin=EXTERNAL_KEY_STORE` | Length 1–128, pattern `^[a-zA-Z0-9-_.]+$`. Must be an existing external AES-256 symmetric key. |

**Response fields**: `KeyMetadata` object (full shape in the [Shared type: `KeyMetadata`](#shared-type-keymetadata) box below).

**Errors**: `CloudHsmClusterInvalidConfigurationException`, `CustomKeyStoreInvalidStateException`, `CustomKeyStoreNotFoundException`, `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `LimitExceededException`, `MalformedPolicyDocumentException`, `TagException`, `UnsupportedOperationException`, `XksKeyAlreadyInUseException`, `XksKeyInvalidConfigurationException`, `XksKeyNotFoundException`.

**Key-material notes**

- **Default** (no params): symmetric, `SYMMETRIC_DEFAULT` (256-bit AES-GCM, or 128-bit SM4 in China Regions), `ENCRYPT_DECRYPT`, `Origin=AWS_KMS`.
- **Asymmetric**: RSA (`RSA_2048/3072/4096`) → `ENCRYPT_DECRYPT` or `SIGN_VERIFY`. NIST ECC (`ECC_NIST_P256/P384/P521`) → `SIGN_VERIFY` or `KEY_AGREEMENT`. `ECC_NIST_EDWARDS25519` (Ed25519) → `SIGN_VERIFY` only. `ECC_SECG_P256K1` (secp256k1) → `SIGN_VERIFY` only. `ML_DSA_44/65/87` (post-quantum) → `SIGN_VERIFY` only. `SM2` (China Regions only) → `ENCRYPT_DECRYPT`, `SIGN_VERIFY`, or `KEY_AGREEMENT`.
- **HMAC**: `KeySpec=HMAC_224/256/384/512`, `KeyUsage` must be explicitly set to `GENERATE_VERIFY_MAC` even though it's the only legal value.
- **Multi-Region primary keys**: `MultiRegion=true` creates a primary; replicas come from `ReplicateKey` (not in scope here); `UpdatePrimaryRegion` swaps roles. Not usable with custom key stores.
- **Imported material**: `Origin=EXTERNAL` creates a key with **no material** (symmetric only) — see [ImportKeyMaterial](#importkeymaterial).
- **Custom key stores**: `Origin=AWS_CLOUDHSM` generates a non-exportable 256-bit key inside a CloudHSM cluster; `Origin=EXTERNAL_KEY_STORE` associates an existing external key (double-encryption). Only `SYMMETRIC_DEFAULT`/`ENCRYPT_DECRYPT` keys allowed in custom key stores.

#### Shared type: `KeyMetadata`

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html — returned by `CreateKey`, `DescribeKey`, and `ReplicateKey`.

| Field | Type | Notes |
|---|---|---|
| `KeyId` | String (required) | Length 1–2048. |
| `Arn` | String | Length 20–2048. |
| `AWSAccountId` | String | 12-digit account ID. |
| `CloudHsmClusterId` | String | Pattern `cluster-[2-7a-zA-Z]{11,16}`. Only for CloudHSM key store keys. |
| `CreationDate` | Timestamp | |
| `CurrentKeyMaterialId` | String | Fixed length 64, `^[a-f0-9]+$`. Only for symmetric keys with `AWS_KMS`/`EXTERNAL` origin. |
| `CustomerMasterKeySpec` | String | **Deprecated**, mirrors `KeySpec` minus newest values. |
| `CustomKeyStoreId` | String | Length 1–64. Only for custom key store keys. |
| `DeletionDate` | Timestamp | Only when `KeyState=PendingDeletion`. |
| `Description` | String | Length 0–8192. |
| `Enabled` | Boolean | `true` iff `KeyState=Enabled`. |
| `EncryptionAlgorithms` | Array&lt;String&gt; | `SYMMETRIC_DEFAULT \| RSAES_OAEP_SHA_1 \| RSAES_OAEP_SHA_256 \| SM2PKE`. Present only if `KeyUsage=ENCRYPT_DECRYPT`. |
| `ExpirationModel` | String | `KEY_MATERIAL_EXPIRES \| KEY_MATERIAL_DOES_NOT_EXPIRE`. Only if `Origin=EXTERNAL`. |
| `KeyAgreementAlgorithms` | Array&lt;String&gt; | `ECDH`. |
| `KeyManager` | String | `AWS \| CUSTOMER`. |
| `KeySpec` | String | Full enum (see `CreateKey` above). |
| `KeyState` | String | `Creating \| Enabled \| Disabled \| PendingDeletion \| PendingImport \| PendingReplicaDeletion \| Unavailable \| Updating`. |
| `KeyUsage` | String | `SIGN_VERIFY \| ENCRYPT_DECRYPT \| GENERATE_VERIFY_MAC \| KEY_AGREEMENT`. |
| `MacAlgorithms` | Array&lt;String&gt; | `HMAC_SHA_224 \| HMAC_SHA_256 \| HMAC_SHA_384 \| HMAC_SHA_512`. Only if `KeyUsage=GENERATE_VERIFY_MAC`. |
| `MultiRegion` | Boolean | `true` for multi-Region primary/replica keys. |
| `MultiRegionConfiguration` | object | Only if `MultiRegion=true`: `MultiRegionKeyType` (`PRIMARY \| REPLICA`), `PrimaryKey {Arn, Region}`, `ReplicaKeys [{Arn, Region}]`. |
| `Origin` | String | `AWS_KMS \| EXTERNAL \| AWS_CLOUDHSM \| EXTERNAL_KEY_STORE`. |
| `PendingDeletionWindowInDays` | Integer | Range 1–365. Only when `KeyState=PendingReplicaDeletion`. |
| `SigningAlgorithms` | Array&lt;String&gt; | `RSASSA_PSS_SHA_256/384/512 \| RSASSA_PKCS1_V1_5_SHA_256/384/512 \| ECDSA_SHA_256/384/512 \| SM2DSA \| ML_DSA_SHAKE_256 \| ED25519_SHA_512 \| ED25519_PH_SHA_512`. Only if `KeyUsage=SIGN_VERIFY`. |
| `ValidTo` | Timestamp | Only if `Origin=EXTERNAL` and `ExpirationModel=KEY_MATERIAL_EXPIRES`. |
| `XksKeyConfiguration` | `{Id: string}` | Only for external key store keys. |

**Key state transitions**: `Creating → Enabled ⇄ Disabled → PendingDeletion/PendingReplicaDeletion`, plus `PendingImport` and `Unavailable`/`Updating` as transient/special states. Full compatibility matrix (which operations succeed in which state) is at https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html and is referenced by nearly every state-sensitive operation's error docs — see the [rotation/deletion](#key-state-compatibility-matrix) section for the concrete matrix as fetched.

---

### DescribeKey

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html

**Request**: `KeyId` (String, required, 1–2048, accepts ID/ARN/alias/alias-ARN); `GrantTokens` (optional, 0–10 items, 1–8192 chars each).

**Response**: `KeyMetadata` (same shape as `CreateKey`'s response). For multi-Region keys, shows the primary and all replicas via `MultiRegionConfiguration`. For custom-key-store keys, shows `CloudHsmClusterId` or `XksKeyConfiguration` as applicable.

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `NotFoundException`.

**Key-material notes**: Does **not** return aliases, rotation status, tags, key policy, or grants — those require `ListAliases`, `GetKeyRotationStatus`, `ListResourceTags`, `GetKeyPolicy`, `ListGrants` respectively. This makes `DescribeKey` a partial view; a trait's "get everything about a key" convenience method would need to fan out to five calls.

---

### EnableKey

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKey.html

**Request**: `KeyId` (String, required, 1–2048, **key ID or ARN only — no alias**).

**Response**: none (HTTP 200, empty body).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `LimitExceededException`, `NotFoundException`.

**Key-material notes**: Cross-account not supported. Sets `KeyState=Enabled`; key must already be in a compatible state or `KMSInvalidStateException` fires.

---

### DisableKey

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html

**Request**: `KeyId` (String, required, 1–2048, key ID/ARN only).

**Response**: none.

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes**: Cross-account not supported. Sets `KeyState=Disabled`. **Notably lacks `LimitExceededException`**, unlike `EnableKey` — a subtle asymmetry worth preserving exactly rather than assuming the two operations share an identical error set.

---

### ListKeys

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html
(entry type: [`KeyListEntry`](https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyListEntry.html) = `{KeyArn, KeyId}`)

**Request**: `Limit` (Integer, optional, range 1–1000, default 100); `Marker` (String, optional, length 1–1024, pattern `[ -ÿ]*`, from prior `NextMarker`).

**Response**: `Keys` (array of `{KeyArn, KeyId}`), `NextMarker` (present iff `Truncated=true`), `Truncated` (Boolean).

**Errors**: `DependencyTimeoutException`, `InvalidMarkerException`, `KMSInternalException`.

**Key-material notes**: Cross-account not supported (account+Region scoped only). Returns bare ID/ARN pairs — no type, state, or origin info; callers must follow up with `DescribeKey` per key.

---

## Data key generation

All four operations below share a common request skeleton: `KeyId` (required, symmetric encryption key only — no asymmetric key, no custom key store as the wrapping key), `EncryptionContext` (optional map, AAD-style, symmetric-only, exact case-sensitive match required on decrypt, **explicitly documented as non-confidential** — visible in CloudTrail), `GrantTokens` (optional, 0–10 items), `DryRun` (optional).

### GenerateDataKey

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. Symmetric encryption key only. |
| `KeySpec` | String | Exactly one of `KeySpec`/`NumberOfBytes` | Valid values: `AES_256 \| AES_128`. `AES_128`/16 bytes generates an SM4 key in China Regions. |
| `NumberOfBytes` | Integer | Exactly one of `KeySpec`/`NumberOfBytes` | Range 1–1024. |
| `EncryptionContext` | Map&lt;String,String&gt; | No | See shared conventions above. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items, 1–8192 chars each. |
| `DryRun` | Boolean | No | |
| `Recipient` | `RecipientInfo {AttestationDocument: blob, KeyEncryptionAlgorithm: string}` | No | For AWS Nitro Enclaves/NitroTPM. Only valid `KeyEncryptionAlgorithm` is `RSAES_OAEP_SHA_256`. When set, `Plaintext` in the response is null/empty and `CiphertextForRecipient` is populated instead. |

**Response fields**: `CiphertextBlob` (base64, 1–6144 bytes — the wrapped DEK), `Plaintext` (base64, 1–4096 bytes — the raw DEK; null/empty if `Recipient` used), `CiphertextForRecipient` (base64, 1–6144, only with `Recipient`), `KeyId` (String, the wrapping key's ARN), `KeyMaterialId` (fixed 64-char lowercase hex, `^[a-f0-9]+$`; omitted when `Recipient` is used).

**Errors**: `DependencyTimeoutException`, `DisabledException`, `DryRunOperationException`, `InvalidGrantTokenException`, `InvalidKeyUsageException`, `KeyUnavailableException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes**: One call returns **both** plaintext and ciphertext forms of the same key — one round trip produces both. Nitro Enclaves/NitroTPM supported via `Recipient`. Cross-account via key/alias ARN. Required permission: `kms:GenerateDataKey`.

---

### GenerateDataKeyWithoutPlaintext

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html

**Request**: identical to `GenerateDataKey` **minus `Recipient`** — `KeyId`, `KeySpec`/`NumberOfBytes` (exactly one), `EncryptionContext`, `GrantTokens`, `DryRun`.

**Response fields**: `CiphertextBlob` (base64, 1–6144 — **no plaintext ever returned**), `KeyId`, `KeyMaterialId` (fixed 64-char hex).

**Errors**: same set as `GenerateDataKey`.

**Key-material notes**: For components that should never see plaintext key material — the encrypted key must later be unwrapped via a separate `Decrypt` call. No `Recipient` support (nothing plaintext to protect for an enclave). Required permission: `kms:GenerateDataKeyWithoutPlaintext`.

---

### GenerateDataKeyPair

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. Symmetric encryption key (wraps the private key); no asymmetric key, no custom key store. |
| `KeyPairSpec` | String | Yes | Valid values: `RSA_2048 \| RSA_3072 \| RSA_4096 \| ECC_NIST_P256 \| ECC_NIST_P384 \| ECC_NIST_P521 \| ECC_SECG_P256K1 \| SM2 \| ECC_NIST_EDWARDS25519`. `SM2` China-Regions-only. |
| `EncryptionContext` | Map&lt;String,String&gt; | No | Applies to encryption of the **private key**. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |
| `DryRun` | Boolean | No | |
| `Recipient` | `RecipientInfo` | No | Nitro Enclaves/NitroTPM; only `RSAES_OAEP_SHA_256`. When used, `PrivateKeyPlaintext` is null/empty and `CiphertextForRecipient` carries the private key encrypted for the enclave. |

**Response fields**: `PublicKey` (base64, 1–8192, DER X.509 SubjectPublicKeyInfo per RFC 5280 — always plaintext), `PrivateKeyPlaintext` (base64, 1–4096, DER PKCS8 PrivateKeyInfo per RFC 5958; null/empty if `CiphertextForRecipient` present), `PrivateKeyCiphertextBlob` (base64, 1–6144, private key wrapped under `KeyId`), `CiphertextForRecipient` (base64, 1–6144, only with `Recipient`), `KeyId` (ARN of wrapping key), `KeyMaterialId` (fixed 64-char hex), `KeyPairSpec` (echoes request).

**Errors**: same base set as `GenerateDataKey` **plus `UnsupportedOperationException`** (a specified parameter/resource isn't valid for this operation — not present on the symmetric-only operations).

**Key-material notes**: AWS recommends ECC pairs for signing-only and RSA/SM2 pairs for either encrypt-or-sign (not both) — a **recommendation**, not enforced the way native asymmetric KMS keys enforce `KeyUsage` separation; a caller can misuse a data-key-pair for both purposes with no server-side guard. Required permission: `kms:GenerateDataKeyPair`.

---

### GenerateDataKeyPairWithoutPlaintext

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPairWithoutPlaintext.html

**Request**: identical to `GenerateDataKeyPair` **minus `Recipient`** — `KeyId`, `KeyPairSpec` (same 9-value enum), `EncryptionContext`, `GrantTokens`, `DryRun`.

**Response fields**: `PublicKey` (base64, 1–8192, plaintext DER X.509 SPKI), `PrivateKeyCiphertextBlob` (base64, 1–6144 — **no plaintext private key ever returned**), `KeyId`, `KeyMaterialId`, `KeyPairSpec`.

**Errors**: same set as `GenerateDataKeyPair` (including `UnsupportedOperationException`).

**Key-material notes**: Use when the plaintext private key isn't needed immediately — obtain the public key now, `Decrypt` the private key later only when actually signing/decrypting. Required permission: `kms:GenerateDataKeyPairWithoutPlaintext`.

**Cross-cutting note on the four generation operations**: the `Plaintext`-returning and `WithoutPlaintext` variants differ only in (a) whether plaintext key material appears in the response and (b) whether `Recipient`/`CiphertextForRecipient` is supported (only on the plaintext-returning variants, since it's a substitute delivery channel for plaintext that otherwise wouldn't exist). A trait design could treat "WithoutPlaintext" as a response projection over one request shape, except that `Recipient` becomes meaningless on that path — parallel-but-overlapping request types may be cleaner than a shared one. Blob ceilings recur throughout: ciphertext/wrapped forms max 6144 bytes, plaintext forms max 4096 bytes, `PublicKey` max 8192 bytes, `KeyMaterialId` always a fixed 64-char lowercase-hex string.

---

## Encrypt, Decrypt, ReEncrypt

### Encrypt

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html

Encrypts up to 4096 bytes of plaintext with a KMS key (symmetric or asymmetric, `KeyUsage=ENCRYPT_DECRYPT`). Not intended for wrapping data keys (use `GenerateDataKey`/`GenerateDataKeyPair` for that shape instead).

**Max plaintext size by key/algorithm**: `SYMMETRIC_DEFAULT` → 4096 bytes; `RSA_2048`+`RSAES_OAEP_SHA_1` → 214, +`RSAES_OAEP_SHA_256` → 190; `RSA_3072` → 342 / 318; `RSA_4096` → 470 / 446; `SM2`+`SM2PKE` (China only) → 1024.

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. |
| `Plaintext` | Base64 blob | Yes | Length 1–4096 bytes. |
| `DryRun` | Boolean | No | |
| `EncryptionAlgorithm` | String | Required only for asymmetric keys | Default `SYMMETRIC_DEFAULT`. Valid values: `SYMMETRIC_DEFAULT \| RSAES_OAEP_SHA_1 \| RSAES_OAEP_SHA_256 \| SM2PKE` (China only). |
| `EncryptionContext` | Map&lt;String,String&gt; | No | Symmetric keys only. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |

**Response fields**: `CiphertextBlob` (base64, 1–6144), `EncryptionAlgorithm` (algorithm actually used), `KeyId` (always the full ARN, regardless of what identifier form the request used).

**Errors**: `DependencyTimeoutException`, `DisabledException`, `DryRunOperationException`, `InvalidGrantTokenException`, `InvalidKeyUsageException`, `KeyUnavailableException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes**: Cross-account via key/alias ARN. Required permission: `kms:Encrypt`. Asymmetric ciphertext carries no embedded metadata — the same `KeyId` + algorithm must be supplied on decrypt; symmetric ciphertext embeds key metadata so `KeyId` is not strictly required on `Decrypt` (but is best practice).

---

### Decrypt

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html

Decrypts ciphertext from `Encrypt`, `GenerateDataKey`, `GenerateDataKeyPair`, `GenerateDataKeyWithoutPlaintext`, or `GenerateDataKeyPairWithoutPlaintext`, or externally-produced ciphertext encrypted under an asymmetric KMS key's downloaded public key. **Cannot** decrypt ciphertext from other formats (AWS Encryption SDK, S3 client-side encryption). Supports Nitro Enclaves/NitroTPM attestation via `Recipient`.

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `CiphertextBlob` | Base64 blob | Required except when `DryRun=true` + `DryRunModifiers=IGNORE_CIPHERTEXT` | Length 1–6144. |
| `DryRun` | Boolean | No | |
| `DryRunModifiers` | Array&lt;String&gt; | No, only meaningful with `DryRun=true` | Valid value: `IGNORE_CIPHERTEXT` (skip ciphertext validation; test authorization only). |
| `EncryptionAlgorithm` | String | Required only if ciphertext was produced under an asymmetric key | Same 4-value enum as `Encrypt`. Must match the encrypting algorithm exactly. |
| `EncryptionContext` | Map&lt;String,String&gt; | No | Symmetric keys only; must exactly (case-sensitive) match what was used to encrypt. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |
| `KeyId` | String | **Conditionally required** — required if ciphertext was encrypted under an asymmetric key, or if `DryRun=true` + `DryRunModifiers=IGNORE_CIPHERTEXT`; otherwise optional (KMS derives it from symmetric-ciphertext metadata, but specifying it pins the expectation — a mismatch throws `IncorrectKeyException`) | Length 1–2048. |
| `Recipient` | `RecipientInfo` | No | Only `RSAES_OAEP_SHA_256`. Response then carries `CiphertextForRecipient` instead of `Plaintext`. |

**Response fields**: `CiphertextForRecipient` (base64, 1–6144, only with `Recipient`), `EncryptionAlgorithm`, `KeyId` (ARN), `KeyMaterialId` (fixed 64-char hex, symmetric keys only, omitted with `Recipient`), `Plaintext` (base64, 1–4096; null/empty if `CiphertextForRecipient` present).

**Errors**: `DependencyTimeoutException`, `DisabledException`, `DryRunOperationException`, `IncorrectKeyException`, `InvalidCiphertextException`, `InvalidGrantTokenException`, `InvalidKeyUsageException`, `KeyUnavailableException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes**: Cross-account supported. Required permission: `kms:Decrypt` — AWS recommends granting this via key policy rather than IAM policy to avoid over-broad cross-account decrypt access. `EncryptionContext` mismatch → `InvalidCiphertextException`.

---

### ReEncrypt

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html

Decrypts then re-encrypts entirely **inside KMS** — plaintext never crosses the service boundary to the caller. Used to rotate the protecting key, move data to a different KMS key, or change the encryption context under the same key.

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `DestinationKeyId` | String | **Always required** — no default/implied destination | Length 1–2048. Symmetric or asymmetric, `KeyUsage=ENCRYPT_DECRYPT`. |
| `CiphertextBlob` | Base64 blob | Required except with `DryRun=true` + `IGNORE_CIPHERTEXT` | Length 1–6144. |
| `DestinationEncryptionAlgorithm` | String | Required only if destination key is asymmetric | Default `SYMMETRIC_DEFAULT`; same 4-value enum. |
| `DestinationEncryptionContext` | Map&lt;String,String&gt; | No | Valid only if destination key is symmetric. Independent of `SourceEncryptionContext` — ReEncrypt can legitimately change the context as part of the operation. |
| `DryRun` | Boolean | No | |
| `DryRunModifiers` | Array&lt;String&gt; | No | `IGNORE_CIPHERTEXT`, only with `DryRun=true`. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. Grants using `SourceArn` constraints must use the *same* `SourceArn` on both the source key's `ReEncryptFrom` grant and the destination key's `ReEncryptTo` grant. |
| `SourceEncryptionAlgorithm` | String | Required only if source ciphertext was encrypted under an asymmetric key | Default `SYMMETRIC_DEFAULT`. Must match the original encryption algorithm. |
| `SourceEncryptionContext` | Map&lt;String,String&gt; | No | Must equal what was used at original encryption. |
| `SourceKeyId` | String | Required only if source ciphertext was encrypted under an asymmetric key, or with `DryRun=true` + `IGNORE_CIPHERTEXT`; otherwise optional (derived from symmetric blob metadata; mismatch → `IncorrectKeyException`) | Length 1–2048. |

**Response fields**: `CiphertextBlob` (re-encrypted, base64 1–6144), `DestinationEncryptionAlgorithm`, `DestinationKeyMaterialId` (only if destination key symmetric), `KeyId` (the destination key's ARN — the key that performed the re-encrypt), `SourceEncryptionAlgorithm`, `SourceKeyId`, `SourceKeyMaterialId` (only if the original encryption used a symmetric key).

**Errors**: same 10-exception set as `Decrypt` (`DependencyTimeoutException`, `DisabledException`, `DryRunOperationException`, `IncorrectKeyException`, `InvalidCiphertextException`, `InvalidGrantTokenException`, `InvalidKeyUsageException`, `KeyUnavailableException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`) — applicable to either the source or destination key.

**Key-material notes**: Source and destination keys can be in different accounts (cross-account supported both directions). **Requires two separate permissions**: `kms:ReEncryptFrom` on the source key's policy **and** `kms:ReEncryptTo` on the destination key's policy — console-created keys get both automatically, but programmatically-created keys or manually-managed policies must add both explicitly.

---

## Sign, Verify, MAC, public key export

### Sign

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. `KeyUsage` must be `SIGN_VERIFY`. |
| `Message` | Base64 blob | Yes | Length 1–4096 bytes. Larger messages must be hashed by the caller and passed as a digest with `MessageType=DIGEST`. |
| `SigningAlgorithm` | String | Yes | Valid values: `RSASSA_PSS_SHA_256 \| RSASSA_PSS_SHA_384 \| RSASSA_PSS_SHA_512 \| RSASSA_PKCS1_V1_5_SHA_256 \| RSASSA_PKCS1_V1_5_SHA_384 \| RSASSA_PKCS1_V1_5_SHA_512 \| ECDSA_SHA_256 \| ECDSA_SHA_384 \| ECDSA_SHA_512 \| SM2DSA \| ML_DSA_SHAKE_256 \| ED25519_SHA_512 \| ED25519_PH_SHA_512`. |
| `MessageType` | String | No | Valid values: `RAW \| DIGEST \| EXTERNAL_MU`. `RAW` = unhashed (KMS hashes it); `DIGEST` = pre-hashed (length must match algorithm's hash output); `EXTERNAL_MU` = 64-byte ML-DSA "μ" representative per NIST FIPS 204 §6.2, length must be exactly 64. `ED25519_SHA_512` requires `RAW`; `ED25519_PH_SHA_512` requires `DIGEST` (KMS still internally SHA-512-prehashes per FIPS 186-5 §7.8.1 step 1 — the input is effectively hashed twice for `ED25519_PH_SHA_512`). Using `RAW` on an already-hashed digest double-hashes and breaks verification. `SM2DSA` hashes internally with SM3. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |
| `DryRun` | Boolean | No | |

**Response fields**: `KeyId` (ARN), `Signature` (base64, 1–6144; RSA → PKCS#1/RFC 8017; ECDSA → DER per ANSI X9.62-2005/RFC 3279 §2.2.3), `SigningAlgorithm`.

**Errors**: `DependencyTimeoutException`, `DisabledException`, `DryRunOperationException`, `InvalidGrantTokenException`, `InvalidKeyUsageException`, `KeyUnavailableException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes**: Requires `kms:Sign`. Signatures carry no timestamp — embed one in the signed message if freshness matters. Verify via `Verify`, or download the public key via `GetPublicKey` and verify offline (outside the audit/FIPS boundary — see `Verify` below).

---

### Verify

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. Must be the exact key used to sign. |
| `Message` | Base64 blob | Yes | Length 1–4096 bytes. |
| `Signature` | Base64 blob | Yes | Length 1–6144 bytes. |
| `SigningAlgorithm` | String | Yes | Same 13-value enum as `Sign`; must match what was used to sign. |
| `MessageType` | String | No | Same 3-value enum as `Sign`; need not literally match the `MessageType` used at signing time, but must correctly describe whether `Message` here is raw or already hashed, or verification silently fails. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |
| `DryRun` | Boolean | No | |

**Response fields**: `KeyId` (ARN), `SignatureValid` (Boolean — **only ever `true`**; a failed verification throws `KMSInvalidSignatureException` instead of returning `false`), `SigningAlgorithm`.

**Errors**: same set as `Sign`, **plus `KMSInvalidSignatureException`** (signature does not verify against the given message/key/algorithm — this is the "expected failure" path, not an infrastructure error).

**Key-material notes**: Requires `kms:Verify`. Verification happens inside the FIPS boundary and is logged to CloudTrail — the documented advantage over offline verification with a downloaded public key. SM2 offline verification (China Regions) needs a distinguishing ID; KMS defaults to `1234567812345678` if unspecified.

---

### GenerateMac

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. Must identify an HMAC key. |
| `MacAlgorithm` | String | Yes | Valid values: `HMAC_SHA_224 \| HMAC_SHA_256 \| HMAC_SHA_384 \| HMAC_SHA_512`. Must be one the key's `MacAlgorithms` (from `DescribeKey`) supports. |
| `Message` | Base64 blob | Yes | Length 1–4096 bytes. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |
| `DryRun` | Boolean | No | |

**Response fields**: `KeyId`, `Mac` (base64, 1–6144, standard RFC 2104 HMAC), `MacAlgorithm`.

**Errors**: `DisabledException`, `DryRunOperationException`, `InvalidGrantTokenException`, `InvalidKeyUsageException` (key must have `KeyUsage=GENERATE_VERIFY_MAC`), `KeyUnavailableException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`. **Notably lacks `DependencyTimeoutException`**, unlike `Sign`/`Verify`/`GetPublicKey`.

**Key-material notes**: Requires `kms:GenerateMac`. No timestamp embedded — same freshness caveat as `Sign`.

---

### VerifyMac

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_VerifyMac.html

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. Must be the same HMAC key used to generate the MAC. |
| `Mac` | Base64 blob | Yes | Length 1–6144 bytes — the value from `GenerateMac`. |
| `MacAlgorithm` | String | Yes | Same 4-value enum; must match generation. |
| `Message` | Base64 blob | Yes | Length 1–4096 bytes; same message used to generate. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |
| `DryRun` | Boolean | No | |

**Response fields**: `KeyId`, `MacAlgorithm`, `MacValid` (Boolean — **only ever `true`**; failure throws `KMSInvalidMacException`).

**Errors**: same as `GenerateMac`, **plus `KMSInvalidMacException`**. Also lacks `DependencyTimeoutException`.

**Key-material notes**: Requires `kms:VerifyMac`.

---

### GetPublicKey

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html

**Request parameters**: `KeyId` (String, required, 1–2048), `GrantTokens` (optional, 0–10 items). **No `DryRun`** — read-only, so dry-run is meaningless.

**Response fields**

| Name | Type | Notes |
|---|---|---|
| `CustomerMasterKeySpec` | String | **Deprecated.** Enum does **not** include the newer ML-DSA/Edwards25519 values — a good reason to exclude this field from a Rust model entirely and use `KeySpec` only. |
| `EncryptionAlgorithms` | Array&lt;String&gt; | Only if `KeyUsage=ENCRYPT_DECRYPT`. |
| `KeyAgreementAlgorithms` | Array&lt;String&gt; | Only if `KeyUsage=KEY_AGREEMENT`. `ECDH` is the sole value. |
| `KeyId` | String | ARN. |
| `KeySpec` | String | Current field — full 16-value enum including `ML_DSA_44/65/87` and `ECC_NIST_EDWARDS25519`. |
| `KeyUsage` | String | `SIGN_VERIFY \| ENCRYPT_DECRYPT \| GENERATE_VERIFY_MAC \| KEY_AGREEMENT`. |
| `PublicKey` | Base64 blob (1–8192) | DER X.509 SubjectPublicKeyInfo, RFC 5280. |
| `SigningAlgorithms` | Array&lt;String&gt; | Only if `KeyUsage=SIGN_VERIFY`. |

**Errors**: `DependencyTimeoutException`, `DisabledException`, `InvalidArnException`, `InvalidGrantTokenException`, `InvalidKeyUsageException`, `KeyUnavailableException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, `UnsupportedOperationException` — the latter two (`InvalidArnException`, `UnsupportedOperationException`) are unique to this operation among the five in this section.

**Key-material notes**: Requires `kms:GetPublicKey`. The private key never leaves KMS unencrypted; this lets external code encrypt/verify without a KMS round trip per operation, at the cost of KMS's own algorithm/usage enforcement (external code must self-police correct algorithm use — AWS explicitly recommends preferring in-KMS `Encrypt`/`ReEncrypt`/`Verify` where the round trip is affordable). Same SM2 distinguishing-ID default as `Verify`.

---

## Key import (BYOK)

### GetParametersForImport

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html

Step 1 of the BYOK flow: returns the RSA public wrapping key and an import token. Target key must already exist with `Origin=EXTERNAL` and no material (state `PendingImport`), created via `CreateKey`. Not usable on custom-key-store keys. Cross-account: no.

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. `Origin` must be `EXTERNAL`. |
| `WrappingAlgorithm` | String | Yes | Valid values: `RSAES_PKCS1_V1_5` (**deprecated**, unsupported since 2023-10-10), `RSAES_OAEP_SHA_1`, `RSAES_OAEP_SHA_256`, `RSA_AES_KEY_WRAP_SHA_1`, `RSA_AES_KEY_WRAP_SHA_256`, `SM2PKE`. `RSA_AES_*` variants wrap material with a local AES key, then wrap that AES key with the RSA public key — required for importing RSA private key material. `RSAES_*` variants wrap material directly with the RSA public key and cannot be used for RSA private key material. `RSAES_OAEP_SHA_256`/`SHA_1` cannot be combined with `RSA_2048` wrapping key spec to wrap `ECC_NIST_P521` key material. |
| `WrappingKeySpec` | String | Yes | Valid values: `RSA_2048 \| RSA_3072 \| RSA_4096 \| SM2`. |

**Response fields**: `ImportToken` (base64, 1–6144), `KeyId` (ARN), `ParametersValidTo` (Timestamp), `PublicKey` (base64, 1–4096, RSA public wrapping key).

The public key and import token are a matched pair, both valid for **24 hours**; an expired pair cannot be used and requires a fresh call.

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, `UnsupportedOperationException`.

**Key-material notes**: Required permission `kms:GetParametersForImport`. Different wrapping key spec/algorithm combos may be chosen on each reimport.

---

### ImportKeyMaterial

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html

Step 2 of BYOK: imports (or reimports) key material, and sets/updates the material's expiration model/date. Cross-account: no.

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `EncryptedKeyMaterial` | Base64 blob | Yes | Length 1–6144. Must be encrypted under the public key from `GetParametersForImport`, using the algorithm specified in that same call. |
| `ImportToken` | Base64 blob | Yes | Length 1–6144. Must be from the same `GetParametersForImport` response as the public key used. |
| `KeyId` | String | Yes | Length 1–2048. Must match the `KeyId` from the corresponding `GetParametersForImport` call. `Origin=EXTERNAL`; `KeyState` should be `PendingImport` (reimport/rotation scenarios can also target `Enabled`). |
| `ExpirationModel` | String | No | Valid values: `KEY_MATERIAL_EXPIRES` (default), `KEY_MATERIAL_DOES_NOT_EXPIRE`. Cannot be changed for the current material without a reimport. |
| `ImportType` | String | No | Valid values: `NEW_KEY_MATERIAL`, `EXISTING_KEY_MATERIAL`. Symmetric keys only. Defaults to `NEW_KEY_MATERIAL` before any import has occurred, `EXISTING_KEY_MATERIAL` after. For multi-Region keys: import `NEW_KEY_MATERIAL` into the primary first, then `EXISTING_KEY_MATERIAL` (identical bytes) into each replica, before `RotateKeyOnDemand` can run on the primary. |
| `KeyMaterialDescription` | String | No | Length 0–256, pattern `^[a-zA-Z0-9:/_\s.-]+$`. Symmetric keys only. If omitted, the prior description is retained. |
| `KeyMaterialId` | String | No | Fixed length 64, pattern `^[a-f0-9]+$`. Symmetric keys only. Cannot be set with `ImportType=NEW_KEY_MATERIAL`. Targets a specific already-associated material blob on reimport (valid IDs from `ListKeyRotations`). |
| `ValidTo` | Timestamp | Required iff `ExpirationModel=KEY_MATERIAL_EXPIRES`; forbidden otherwise | Must be in the future, **max 365 days out**. On reaching this time, AWS KMS deletes the key material and the key becomes unusable until reimported. |

**Response fields**: `KeyId` (ARN), `KeyMaterialId` (fixed 64-char hex).

**Errors**: `DependencyTimeoutException`, `ExpiredImportTokenException`, `IncorrectKeyMaterialException`, `InvalidArnException`, `InvalidCiphertextException`, `InvalidImportTokenException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, `UnsupportedOperationException`.

**Key-material notes — full BYOK workflow**:

1. `CreateKey` with `Origin=EXTERNAL` → key with **no material**, state `PendingImport`.
2. `GetParametersForImport` → `PublicKey` + `ImportToken` (paired, 24h validity).
3. Wrap raw key material locally with `PublicKey` per the chosen `WrappingAlgorithm`.
4. `ImportKeyMaterial` → on success, state becomes `Enabled`. For symmetric keys requiring multiple key materials, **all** must be imported before the key is usable.
5. **Reimport/rotation**: for asymmetric and HMAC keys, material cannot be changed after initial import — reimport only re-establishes the *same* material (e.g. after expiry/deletion). For **symmetric** keys, multiple materials can be imported and rotated on demand via `RotateKeyOnDemand`.
6. **Multi-Region**: import `NEW_KEY_MATERIAL` into the primary, `EXISTING_KEY_MATERIAL` into each replica.
7. `ExpirationModel`/`ValidTo` is a linked, mutually-required pair; on expiry, material is auto-deleted and the key becomes unusable until reimported.
8. Required permission: `kms:ImportKeyMaterial`.

---

### DeleteImportedKeyMaterial

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html *(natural counterpart to `ImportKeyMaterial`, not itemized in the original scope list but essential to the BYOK lifecycle)*

**Request**: `KeyId` (String, required, 1–2048, `Origin=EXTERNAL`); `KeyMaterialId` (String, optional, fixed 64-char hex — if omitted, deletes the *current* material).

**Response**: `KeyId` (ARN), `KeyMaterialId` (length 0–64 in the response — looser than the fixed-64 request constraint).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, `UnsupportedOperationException`.

**Key-material notes**: If the key is `PendingDeletion`, state is unchanged; otherwise the key reverts to **`PendingImport`** — the same "no usable material" state as a freshly created `EXTERNAL`-origin key. For multi-Region symmetric keys, deleting the primary's material while it is in a pending-rotation state also deletes all replicas' material; deleting a replica's material alone leaves the primary and other replicas untouched. Required permission: `kms:DeleteImportedKeyMaterial`.

---

## Rotation and deletion

### RotateKeyOnDemand

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_RotateKeyOnDemand.html

**Request**: `KeyId` (String, required, 1–2048).

**Response**: `KeyId` (String, 1–2048).

**Errors**: `ConflictException` (an automatic rotation is in progress or scheduled within the next 20 minutes), `DependencyTimeoutException`, `DisabledException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `LimitExceededException` (on-demand rotation cap reached), `NotFoundException`, `UnsupportedOperationException` (e.g. custom key store, or `Origin=EXTERNAL` with no rotation-eligible material state).

**Key-material notes**: **Symmetric encryption keys only** — no asymmetric, HMAC, custom-key-store keys, and (for imported material) rotation requires new material already imported and in state `PENDING_ROTATION` (via `ListKeyRotations`). **On-demand rotation cap: 25 rotations per key** (per the live doc page). Does not change the existing automatic-rotation schedule. Cannot be used on AWS managed keys (always auto-rotate yearly) or AWS owned keys (rotation controlled by the owning service). For multi-Region keys: import identical new material into the primary and every replica, then call this only on the **primary**. Cross-account: no. Required permission: `kms:RotateKeyOnDemand`.

---

### EnableKeyRotation

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html

**Request**: `KeyId` (String, required, 1–2048); `RotationPeriodInDays` (Integer, optional, **valid range 90–2560**, default 365 — also usable to change the period on a key that already has rotation enabled; constrainable via the `kms:RotationPeriodInDays` condition key).

**Response**: none (HTTP 200, empty body).

**Errors**: `DependencyTimeoutException`, `DisabledException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, `UnsupportedOperationException`.

**Key-material notes**: Symmetric encryption keys only (`AWS_KMS` origin) — not for asymmetric, HMAC, imported-material, or custom-key-store keys. For multi-Region keys, set on the **primary** only; applies to the whole set. AWS managed keys always rotate yearly (not configurable); AWS owned keys are rotated by the owning service. On-demand rotation can be used regardless of whether automatic rotation is enabled. Cross-account: no. Required permission: `kms:EnableKeyRotation`.

---

### DisableKeyRotation

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKeyRotation.html

**Request**: `KeyId` (String, required, 1–2048).

**Response**: none.

**Errors**: identical set to `EnableKeyRotation`.

**Key-material notes**: Same key-type restriction as `EnableKeyRotation`. For multi-Region keys, disable on the primary to affect the whole set. Customer managed keys only. Cross-account: no. Required permission: `kms:DisableKeyRotation`.

---

### GetKeyRotationStatus *(natural counterpart, not in the original scope list but load-bearing for rotation semantics)*

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html

**Request**: `KeyId` (String, required, 1–2048 — **cross-account requires the ARN form**, unlike the enable/disable/rotate operations).

**Response**: `KeyId`, `KeyRotationEnabled` (Boolean), `NextRotationDate` (Timestamp), `OnDemandRotationStartDate` (Timestamp, **present only while an on-demand rotation is in progress** — removed once it completes; query `ListKeyRotations` for history), `RotationPeriodInDays` (Integer, 90–2560, default 365).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, `UnsupportedOperationException`. No `DisabledException` — this is a pure read.

**Key-material notes**: For AWS managed keys, `KeyRotationEnabled` is always `true`. If the key is disabled, rotation is paused (not cancelled) — re-enabling triggers an immediate rotation if ≥1 year has passed since the last one, otherwise the prior schedule resumes. If `PendingDeletion`, reports `KeyRotationEnabled=false` and no rotation occurs; cancelling deletion restores the original status. This is the **only** one of the rotation operations that supports cross-account access.

---

### ScheduleKeyDeletion

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html

**Request**: `KeyId` (String, required, 1–2048); `PendingWindowInDays` (Integer, optional, **valid range 7–30**, default 30; constrainable via `kms:ScheduleKeyDeletionPendingWindowInDays`. If the key is a multi-Region **primary** with live replicas, the waiting period doesn't start until the last replica is deleted; otherwise it starts immediately. Actual deletion may occur up to 24h after the scheduled date).

**Response fields**: `DeletionDate` (Timestamp — **absent** if the key is a multi-Region primary with existing replicas, since the date is unknown until the last replica is gone), `KeyId` (ARN), `KeyState` (`Creating \| Enabled \| Disabled \| PendingDeletion \| PendingImport \| PendingReplicaDeletion \| Unavailable \| Updating`), `PendingWindowInDays` (7–30).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`. **No `UnsupportedOperationException`** — this operation works across key types/origins/custom key stores.

**Key-material notes**: On success, state becomes `PendingDeletion` (or `PendingReplicaDeletion` for a multi-Region primary with live replicas) and the key becomes unusable for cryptographic operations during the window. When the key is finally deleted, AWS KMS deletes the key, its material, **and all aliases referring to it**. Per the key-state matrix (below), `ListGrants`/`RetireGrant`/`RevokeGrant` continue to succeed on a `PendingDeletion`/`PendingReplicaDeletion` key — existing grants remain manageable — but `CreateGrant` fails. For multi-Region keys, a primary awaiting replica deletion can sit in `PendingReplicaDeletion` indefinitely; deleted replicas can be recreated from the primary via `ReplicateKey`. For custom key stores, deleting a CloudHSM key store key makes a best-effort attempt to remove the backing HSM material (may need manual cluster-backup cleanup); deleting an external-key-store key has **no effect** on the external material. Only customer managed keys can be scheduled for deletion. Cross-account: no. Required permission: `kms:ScheduleKeyDeletion`.

---

### CancelKeyDeletion

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html

**Request**: `KeyId` (String, required, 1–2048).

**Response**: `KeyId` (ARN).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException` (fires specifically when the key is **not** currently `PendingDeletion`), `NotFoundException`.

**Key-material notes**: On success, state becomes **`Disabled`** — not automatically re-enabled; a follow-up `EnableKey` is required to use the key again. The key must currently be `PendingDeletion`, or the call fails. For custom-key-store keys, `PendingDeletion` is preserved even if the store is disconnected, so cancellation remains possible throughout the window. Cancelling restores the key's prior rotation status. Cross-account: no. Required permission: `kms:CancelKeyDeletion`.

#### Key state compatibility matrix

Source: https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html. Columns are key states; ✓ = succeeds, X = fails (exception noted), ? = succeeds unless the key is in a custom key store (then `UnsupportedOperationException`).

| Operation | Enabled | Disabled | PendingDeletion/ReplicaDeletion | PendingImport | Unavailable | Creating | Updating |
|---|---|---|---|---|---|---|---|
| `RotateKeyOnDemand` | ? | X (disabled) | X (pending deletion) | X (pending import) | X | X (creating) | ? |
| `EnableKeyRotation` | ? | X (disabled) | X (pending deletion) | X (`EXTERNAL` origin unsupported) | X | X | ? |
| `DisableKeyRotation` | ? | X (disabled) | X (pending deletion) | X | X | X | ? |
| `GetKeyRotationStatus` | ? | ? | ? | X | X | ? | ? |
| `ScheduleKeyDeletion` | ✓ | ✓ | X (already pending deletion) | ✓ | ✓ | ✓ | X (updating) |
| `CancelKeyDeletion` | X (not pending deletion) | X | ✓ | X | X | X | X |
| `CreateGrant` | ✓ | X (disabled) | X (pending deletion) | X (pending import) | ✓ | X (creating) | ✓ |
| `ListGrants` / `RetireGrant` / `RevokeGrant` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

The exceptions above carry specific message text per cause (e.g. `KMSInvalidStateException: {{key ARN}} is pending deletion`) — AWS overloads a small set of exception *types* across many distinct causes distinguished only by message. Notable takeaway: existing grants remain fully manageable (list/retire/revoke) throughout a key's entire lifecycle including while pending deletion, but no *new* grant can be created once deletion is scheduled.

---

## Tags and grants

### TagResource

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_TagResource.html
(tag shape: [`Tag`](https://docs.aws.amazon.com/kms/latest/APIReference/API_Tag.html) = `{TagKey (1–128 chars, required), TagValue (0–256 chars, required, may be empty)}`)

**Request**: `KeyId` (String, required, 1–2048 — **customer managed keys only**, not AWS managed/owned keys, custom key stores, or aliases); `Tags` (array of `Tag`, required).

**Response**: none.

**Errors**: `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `LimitExceededException` (the 50-tags-per-key quota), `NotFoundException`, `TagException`.

**Key-material notes**: Tagging/untagging can grant or deny access via ABAC (attribute-based access control) — key/IAM policies can condition on tag values, so these calls are not purely cosmetic. At most one tag per `TagKey`; re-tagging an existing key with the same key replaces its value. Max 50 user-created tags per key. Required permission: `kms:TagResource`.

---

### UntagResource

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_UntagResource.html

**Request**: `KeyId` (String, required, 1–2048); `TagKeys` (array of strings, required, each 1–128 chars — values only, no `TagValue`).

**Response**: none.

**Errors**: `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`, `TagException`. **No `LimitExceededException`** (removal can't exceed a quota).

**Key-material notes**: Succeeds silently even if a named tag key isn't present — no error, no distinguishing response field; use `ListResourceTags` to confirm effect. Same ABAC caution as `TagResource`. Required permission: `kms:UntagResource`.

---

### ListResourceTags

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ListResourceTags.html

**Request**: `KeyId` (String, required, 1–2048); `Limit` (Integer, optional — the doc's prose says "must be between 1 and 50 inclusive" while the field metadata states a max of 1000; treat 50 as the practical default and 1000 as the documented outer ceiling — a genuine inconsistency in AWS's own docs, not a transcription error here); `Marker` (String, optional, length 1–1024, opaque, from prior `NextMarker`).

**Response**: `Tags` (array of `Tag`), `NextMarker` (present iff `Truncated=true`), `Truncated` (Boolean).

**Errors**: `InvalidArnException`, `InvalidMarkerException`, `KMSInternalException`, `NotFoundException`. **No `KMSInvalidStateException`** — unlike `TagResource`/`UntagResource`, this read-only call isn't state-gated. Cross-account: no.

---

### CreateGrant

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html

**Request parameters**

| Name | Type | Required | Constraints |
|---|---|---|---|
| `KeyId` | String | Yes | Length 1–2048. ARN form required for cross-account grants. |
| `Operations` | Array&lt;String&gt; | Yes | Exact valid values: `Decrypt \| Encrypt \| GenerateDataKey \| GenerateDataKeyWithoutPlaintext \| ReEncryptFrom \| ReEncryptTo \| Sign \| Verify \| GetPublicKey \| CreateGrant \| RetireGrant \| DescribeKey \| GenerateDataKeyPair \| GenerateDataKeyPairWithoutPlaintext \| GenerateMac \| VerifyMac \| DeriveSharedSecret`. Each must be valid for the key's type/usage (e.g. `Sign` on a symmetric key is rejected). |
| `Constraints` | `GrantConstraints` | No | See below. |
| `DryRun` | Boolean | No | |
| `GranteePrincipal` | String | Exactly one of this or `GranteeServicePrincipal` | Length 1–256, pattern `^[\w+=,.@:/-]+$`. AWS principal ARN. |
| `GranteeServicePrincipal` | String | Exactly one of this or `GranteePrincipal` | Length 1–128, pattern `^([A-Za-z0-9\-]+)\.([A-Za-z0-9\-]+)(\.[A-Za-z0-9\-]+)+$` (dotted service-principal form, e.g. `acm.amazonaws.com`). Requires a `SourceArn` constraint and one of `RetiringPrincipal`/`RetiringServicePrincipal`. |
| `GrantTokens` | Array&lt;String&gt; | No | 0–10 items. |
| `Name` | String | No | Length 1–256, pattern `^[a-zA-Z0-9:/_-]+$`. Enables idempotent retry: an identical `Name`+params returns the existing `GrantId` rather than duplicating — but a **new** `GrantToken` is minted each call regardless (all tokens for one `GrantId` are interchangeable). Without `Name`, every retry creates a distinct grant. |
| `RetiringPrincipal` | String | No, mutually exclusive with `RetiringServicePrincipal` | Length 1–256, same pattern as `GranteePrincipal`. Principal permitted to call `RetireGrant`. |
| `RetiringServicePrincipal` | String | No, mutually exclusive with `RetiringPrincipal` | Length 1–128, dotted service pattern. |

**`GrantConstraints` shape**: `EncryptionContextEquals` (Map&lt;String,String&gt; — grant applies only if the request's context exactly matches), `EncryptionContextSubset` (Map&lt;String,String&gt; — grant applies only if the request's context is a superset of this). Up to 8 context pairs, each value ≤384 chars. Only meaningful for operations that take `EncryptionContext` (symmetric crypto ops) — not applicable to asymmetric/HMAC operations. `DescribeKey`/`RetireGrant` may appear in a grant carrying such a constraint, but the constraint doesn't apply to them. `SourceArn` (String — restricts use to requests made on behalf of a given resource ARN, equivalent to the `aws:SourceArn` condition key; applies to `DescribeKey` but not `RetireGrant`).

**Response fields**: `GrantId` (String, 1–128 — durable identifier for `ListGrants`/`RetireGrant`/`RevokeGrant`), `GrantToken` (String, 1–8192 — opaque immediate-use proof, bypassing the eventual-consistency window).

**Errors**: `DependencyTimeoutException`, `DisabledException`, `DryRunOperationException`, `InvalidArnException`, `InvalidGrantTokenException`, `KMSInternalException`, `KMSInvalidStateException`, `LimitExceededException` (the 50,000-grants-per-key quota).

**Key-material notes — why grant tokens exist**: grant creation/retirement/revocation has a short (typically &lt;5 minute) propagation delay across AWS KMS's fleet ("eventual consistency"). A `GrantId` alone can't prove authorization immediately after creation, since other parts of the fleet may not see the new grant yet. `GrantToken` is a self-contained, immediately-usable proof — pass it via `GrantTokens` on subsequent calls (including nested `CreateGrant` calls) to bypass the window. Once consistency is reached, the grantee needs no token — the grant is simply visible to policy evaluation. Cross-account: yes, via key ARN. Required permission: `kms:CreateGrant`.

---

### RetireGrant

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_RetireGrant.html

**Request**: `GrantId` (String, optional — length 1–128), `GrantToken` (String, optional — length 1–8192), `KeyId` (String, optional — length 1–2048), `DryRun` (Boolean, optional). All four are individually documented as "Required: No", but functionally the caller must supply **either** `GrantToken` alone, **or** both `GrantId` and `KeyId`, to identify the target grant.

**Response**: none.

**Errors**: `DependencyTimeoutException`, `DryRunOperationException`, `InvalidArnException`, `InvalidGrantIdException`, `InvalidGrantTokenException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes — who may call `RetireGrant`**: the grant's designated retiring principal (`RetiringPrincipal`/`RetiringServicePrincipal`); the grantee principal, if the grant's own `Operations` includes `RetireGrant`; the AWS account that owns the key; or any principal delegated retirement permission. This is **not** a simple key-policy `kms:RetireGrant` check — authorization is determined by the grant itself. This is the mechanism for a **grantee (or delegate) voluntarily relinquishing** a grant. Cross-account: yes.

---

### RevokeGrant

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_RevokeGrant.html

**Request**: `GrantId` (String, required, 1–128), `KeyId` (String, required, 1–2048 — ARN required for cross-account), `DryRun` (Boolean, optional). **No `GrantToken` parameter** — unlike `RetireGrant`, this operation only accepts the ID form.

**Response**: none.

**Errors**: `DependencyTimeoutException`, `DryRunOperationException`, `InvalidArnException`, `InvalidGrantIdException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`. **No `InvalidGrantTokenException`**, consistent with lacking a `GrantToken` param.

**Key-material notes**: This is how the **key owner/administrator unilaterally terminates** a grant, regardless of the grantee's or retiring principal's wishes — a straightforward key-policy-gated action (`kms:RevokeGrant`), contrasting with `RetireGrant`'s grant-determined authorization model. Both operations are subject to the same eventual-consistency delay before deletion is visible fleet-wide. Cross-account: yes.

---

### ListGrants

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ListGrants.html
(entry type: `GrantListEntry`)

**Request**: `KeyId` (String, **required**, 1–2048 — ARN for cross-account), `GranteePrincipal` (String, optional, mutually exclusive with `GranteeServicePrincipal`), `GranteeServicePrincipal` (String, optional, usable only by service-principal callers), `GrantId` (String, optional — filters to one grant), `Limit` (Integer, optional, range 1–100, default 50), `Marker` (String, optional, length 1–1024).

**Response**: `Grants` (array of `GrantListEntry`), `NextMarker`, `Truncated`.

**`GrantListEntry` fields**: `Constraints` (`GrantConstraints`), `CreationDate` (epoch number), `GranteePrincipal`, `GranteeServicePrincipal`, `GrantId`, `IssuingAccount` (ARN-form account root), `KeyId`, `Name` (empty string if unset), `Operations` (array), `RetiringPrincipal`, `RetiringServicePrincipal`.

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `InvalidGrantIdException`, `InvalidMarkerException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`. Cross-account: yes, via key ARN. Required permission: `kms:ListGrants`.

---

### ListRetirableGrants *(natural counterpart, essential to the "what can I retire" workflow)*

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ListRetirableGrants.html

**Request**: `Limit` (Integer, optional, range 1–100, default 50), `Marker` (String, optional, length 1–1024), `RetiringPrincipal` (String, exactly one of this or `RetiringServicePrincipal` — must be a principal **in the caller's own account**), `RetiringServicePrincipal` (String, usable only by service-principal callers).

**Response**: same shape as `ListGrants` (`Grants` array of `GrantListEntry`, `NextMarker`, `Truncated`).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `InvalidMarkerException`, `KMSInternalException`, `NotFoundException`. **No `KMSInvalidStateException`/`InvalidGrantIdException`** — this operation doesn't target one key/grant.

**Key-material notes — how this differs from `ListGrants`**: `ListGrants` requires a `KeyId` and lists grants **on that one key**. `ListRetirableGrants` takes **no `KeyId`** and instead lists grants **across the entire account/Region** — potentially spanning keys owned by *other* AWS accounts — that name the given principal as retiring principal. Required permission is `kms:ListRetirableGrants`, evaluated against the caller's **own** account; no permission is needed in the accounts that own the underlying keys, since authorization is based on the right to act as the named retiring principal, not on key access.

---

## Key policy and aliases

### PutKeyPolicy

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html

**Request**: `KeyId` (String, required, 1–2048, **key ID or ARN only — no alias**); `Policy` (String, required, length 1–32768, pattern `[\t\n\r\x20-\xFF]+` — must allow the calling principal to make a subsequent `PutKeyPolicy` call unless the lockout check is bypassed; a statement missing `Resource`/`Action` is silently ineffective rather than rejected); `BypassPolicyLockoutSafetyCheck` (Boolean, optional, default `false`); `PolicyName` (String, optional, default and **only valid value** `default`, length 1–128, pattern `[\w]+`).

**Response**: none.

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `LimitExceededException`, `MalformedPolicyDocumentException`, `NotFoundException`, `UnsupportedOperationException`.

**Key-material notes**: Cross-account: no. Requires `kms:PutKeyPolicy` in the key's own policy.

---

### GetKeyPolicy

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyPolicy.html

**Request**: `KeyId` (String, required, 1–2048); `PolicyName` (String, optional, default/only value `default`).

**Response**: `Policy` (String, length **1–131072** — note this is 4x `PutKeyPolicy`'s 32768-char write limit, an asymmetric ceiling), `PolicyName` (always `default`).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes**: Cross-account: no. The default key policy grants `kms:*` on `Resource: "*"` to the account root (`Principal: {"AWS": "arn:aws:iam::<account>:root"}`) under Sid `"Enable IAM User Permissions"` — the canonical mechanism by which IAM policies (not just key policies) can subsequently govern access.

---

### ListKeyPolicies *(bonus — vestigial but load-bearing for API completeness)*

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeyPolicies.html

**Request**: `KeyId` (String, required, 1–2048); `Limit` (Integer, optional, range 1–1000, default 100 — doc notes "only one policy can be attached to a key," making pagination essentially moot); `Marker` (String, optional).

**Response**: `PolicyNames` (array — **always `["default"]`**), `Truncated`, `NextMarker`.

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`. Cross-account: no.

**Key-material notes**: Currently vestigial/forward-compatible — AWS KMS supports exactly one policy per key today.

---

### CreateAlias

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html

**Request**: `AliasName` (String, required, length 1–256, pattern `^alias/[a-zA-Z0-9/_-]+$` — must start with `alias/`, **cannot start with `alias/aws/`**, which is reserved for AWS managed keys; may appear in plaintext in CloudTrail — don't put sensitive info in the name); `TargetKeyId` (String, required, length 1–2048, key ID or ARN — no alias-as-target — must be a **customer managed key in the same Region**; empty/null rejected).

**Response**: none — the doc explicitly states this operation returns no data; use `ListAliases` to retrieve the alias afterward.

**Errors**: `AlreadyExistsException` (alias name already exists — unique per account+Region), `DependencyTimeoutException`, `InvalidAliasNameException`, `KMSInternalException`, `KMSInvalidStateException`, `LimitExceededException`, `NotFoundException`.

**Key-material notes**: Cross-account: no. Requires **both** `kms:CreateAlias` on the alias (IAM policy) *and* `kms:CreateAlias` on the target key (key policy) — a dual permission check. Cannot alias an AWS managed key via this call. Aliases are **unique per account+Region**, but the same alias name can exist in different Regions pointing at different keys — confirming aliases are per-Region constructs, with no automatic propagation to a multi-Region key's replicas (each replica needs its own `CreateAlias`). A key can have multiple aliases; each alias points to exactly one key at a time. You cannot create a dangling alias yourself (a valid target is mandatory).

---

### ListAliases

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_ListAliases.html
(entry type: `AliasListEntry`)

**Request**: `KeyId` (String, optional, 1–2048 — omit for all aliases in the account+Region, or filter to one key); `Limit` (Integer, optional, range **1–100**, default 50); `Marker` (String, optional).

**Response**: `Aliases` (array of `AliasListEntry`), `Truncated`, `NextMarker`.

**`AliasListEntry` fields** (all individually optional per-entry): `AliasArn` (String, 20–2048), `AliasName` (String, 1–256, pattern `^[a-zA-Z0-9:/_-]+$` — a **looser** pattern than `CreateAlias`'s write-path pattern, including `:` and not anchoring the `alias/` prefix in the regex itself), `TargetKeyId` (String, 1–2048 — **can be absent**), `CreationDate` (Timestamp), `LastUpdatedDate` (Timestamp — can be missing).

**Errors**: `DependencyTimeoutException`, `InvalidArnException`, `InvalidMarkerException`, `KMSInternalException`, `NotFoundException`. Cross-account: no.

**Key-material notes**: Aliases **can point to nothing** — the response can include predefined AWS-created aliases with no `TargetKeyId`, not yet associated with a key; these don't count against the per-key alias quota (contrast with `CreateAlias`, which cannot itself create such a dangling alias). Response mixes user-created aliases with AWS-created ones for AWS managed keys (recognizable by `alias/aws/<service>` naming). No multi-Region-specific flagging — a replica key's aliases list exactly like any other key's.

---

### UpdateAlias

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_UpdateAlias.html

**Request**: `AliasName` (String, required, 1–256, pattern `^alias/[a-zA-Z0-9/_-]+$` — identifies the existing alias only, **cannot rename**); `TargetKeyId` (String, required, 1–2048 — new key must be in the same account+Region; **cannot target an AWS managed key**).

**Response**: none.

**Errors**: `DependencyTimeoutException`, `KMSInternalException`, `KMSInvalidStateException`, `LimitExceededException`, `NotFoundException`. **No `InvalidArnException`/`InvalidAliasNameException`** — unlike `PutKeyPolicy`/`CreateAlias`, since the alias name isn't being freshly format-validated, only looked up.

**Key-material notes**: **Critical type-compatibility rule**: the current and new key must be the same type (both symmetric, both asymmetric, or both HMAC) and have the same `KeyUsage` — repointing across incompatible types/usages is rejected; the documented workaround is `DeleteAlias` + `CreateAlias`. Same workaround applies for renaming (not supported directly). Requires **three** separate `kms:UpdateAlias` checks: on the alias (IAM), on the current target key (key policy), and on the new target key (key policy). Aliases are explicitly not a property of the key itself — they don't appear in `DescribeKey` output and creating/updating/deleting one never affects the underlying key. Cross-account: no.

---

### DeleteAlias

**Doc:** https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html

**Request**: `AliasName` (String, required, 1–256, pattern `^[a-zA-Z0-9:/_-]+$` — the **looser** read-path pattern, matching `AliasListEntry.AliasName` rather than `CreateAlias`/`UpdateAlias`'s stricter write-path pattern; a documented inconsistency in AWS's own schema, worth flagging for a Rust validator that needs to pick one).

**Response**: none.

**Errors**: `DependencyTimeoutException`, `KMSInternalException`, `KMSInvalidStateException`, `NotFoundException`.

**Key-material notes**: Requires `kms:DeleteAlias` on both the alias (IAM) and the target key (key policy). Never affects the underlying key — only the friendly name is removed. Cross-account: no.

---

## Cross-cutting observations for Rust capability-trait design

1. **`KeyId` is not one type.** Cryptographic operations accept key ID, key ARN, alias name, or alias ARN; key-policy and alias-management operations accept **only** key ID or key ARN. A single `KeyIdentifier` enum spanning all four forms would silently over-permit inputs to the narrower operations — worth two distinct types (or a marker/phantom-typed identifier) rather than one.

2. **Conditional-required fields are common, not rare.** `Decrypt.KeyId`, `ReEncrypt.SourceKeyId`, `ImportKeyMaterial.ValidTo`, `CreateGrant`'s `GranteePrincipal`/`GranteeServicePrincipal` XOR, and `RetireGrant`'s `(GrantId, KeyId)` XOR `GrantToken` are all "required depending on another field's value," not plain `Option<T>`. A naive `Option`-per-field struct loses these invariants; builder-pattern or enum-of-variants validation at construction time would catch misuse before a network round trip that AWS will otherwise reject.

3. **Response `KeyId` is always normalized to a full ARN**, regardless of what identifier form the request used — a useful guarantee for a trait's return types, and worth preserving (don't re-derive or truncate it).

4. **The `Plaintext`/`WithoutPlaintext` and `Recipient`-bearing pairs are not simply "same request, different response projection."** `Recipient` (Nitro Enclave/NitroTPM support) exists only on the plaintext-returning variants of `GenerateDataKey*`/`GenerateDataKeyPair*` and on `Decrypt` — it has no meaning on a `WithoutPlaintext` call, since there's no plaintext to redirect to an enclave. Modeling these as fully independent request/response types (rather than one generic request with an optional output mode) avoids exposing a field that's always meaningless in one branch.

5. **"Verify"-shaped operations never return `false`.** `Verify`, `VerifyMac` — a failed check throws `KMSInvalidSignatureException`/`KMSInvalidMacException` rather than returning `SignatureValid: false`/`MacValid: false`. A Rust trait should treat "verification failed" as a distinct, expected, non-retryable error variant, not fold it into a boolean return — matching AWS's own modeling rather than smoothing it into an `Ok(bool)`.

6. **Error-set asymmetries are real, not incidental**, and several are easy to miss without reading each page individually: `EnableKey` has `LimitExceededException`, `DisableKey` doesn't. `GenerateMac`/`VerifyMac` lack `DependencyTimeoutException` where `Sign`/`Verify`/`GetPublicKey` have it. `GetPublicKey` uniquely carries `InvalidArnException` and `UnsupportedOperationException` among the sign/verify/mac family. `ScheduleKeyDeletion` is the one deletion/rotation op with **no** `UnsupportedOperationException` (it works uniformly across key types). `RevokeGrant` has no `GrantToken` param and thus no `InvalidGrantTokenException`, while `RetireGrant` has both. A shared `KmsError` enum is still appropriate, but per-operation trait method signatures should not assume a uniform error surface — several "this can't happen for this call" assumptions are wrong.

7. **Grant tokens are a first-class eventual-consistency workaround, not an auth artifact.** `CreateGrant` returns a `GrantId` (durable) and a `GrantToken` (ephemeral proof, usable immediately, before the grant is visible fleet-wide — typically <5 min). Any trait operation that accepts `GrantTokens` needs to model "I just created a grant and want to use it right away" as a real, expected pattern, not an edge case — this recurs on essentially every cryptographic operation.

8. **`RetireGrant` vs `RevokeGrant` encode two different security models in one API surface.** `RetireGrant`'s authorization is *determined by the grant itself* (retiring principal, or grantee if `RetireGrant` is in its own `Operations` list, or the key-owning account) — not a simple key-policy check. `RevokeGrant` is a plain key-policy-gated unilateral action by the key owner. A trait exposing both should not collapse them into "delete a grant" with a boolean flag; they have genuinely different callers and different failure semantics.

9. **AWS's own docs contain internal inconsistencies** worth not silently "fixing" away in a trait's validation layer without a decision: `ListResourceTags.Limit`'s prose (max 50) contradicts its field metadata (max 1000); `CreateAlias`/`UpdateAlias`'s alias-name pattern is stricter than `DeleteAlias`'s and `AliasListEntry.AliasName`'s. A defensive client-side validator should enforce the stricter write-path pattern and treat the looser read-path pattern as "trust what the server already accepted."

10. **Aliases are not key properties** — `DescribeKey` never returns them, `CreateAlias`/`UpdateAlias`/`DeleteAlias` never affect the underlying key, and they are strictly per-Region even for multi-Region key sets (no propagation to replicas). A trait design treating "get everything about a key" as a single call is wrong for aliases (and equally for tags, rotation status, policy, and grants — five separate calls are required, per point 2 in the DescribeKey section above).

11. **Batch-like behavior is essentially absent.** Every operation surveyed operates on one key/ciphertext/grant/alias/tag-set per call; there is no AWS KMS analog to Vault's `batch_input` or plural `datakeys` endpoint (per the existing four-vendor survey). The one arguable exception is `TagResource`, which accepts an array of tags in one call (not a batch of *operations*, just a batch of key-value pairs within one resource's tag set) — not a precedent for genuine multi-key/multi-ciphertext batching.

12. **Multi-Region keys are a cross-cutting concern touching nearly every operation category**, not a self-contained feature: `CreateKey` (immutable `MultiRegion` flag), rotation (must target the primary; replicas follow), deletion (`PendingReplicaDeletion` state, deletion clock gated on replica count), import (material must be imported into primary then each replica identically), and aliases (explicitly *not* propagated). A trait design that treats "multi-Region" as an opt-in wrapper around a single-Region trait will likely need hooks in at least four of these areas rather than one isolated extension point.

---

## Sources

- `CreateKey` — https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
- `KeyMetadata` (shared response type) — https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyMetadata.html
- `DescribeKey` — https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html
- `EnableKey` — https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKey.html
- `DisableKey` — https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html
- `ListKeys` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html
- `KeyListEntry` — https://docs.aws.amazon.com/kms/latest/APIReference/API_KeyListEntry.html
- `GenerateDataKey` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
- `GenerateDataKeyWithoutPlaintext` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html
- `GenerateDataKeyPair` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html
- `GenerateDataKeyPairWithoutPlaintext` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPairWithoutPlaintext.html
- `Encrypt` — https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
- `Decrypt` — https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
- `ReEncrypt` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html
- `Sign` — https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- `Verify` — https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html
- `GenerateMac` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html
- `VerifyMac` — https://docs.aws.amazon.com/kms/latest/APIReference/API_VerifyMac.html
- `GetPublicKey` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html
- `GetParametersForImport` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html
- `ImportKeyMaterial` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html
- `DeleteImportedKeyMaterial` — https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html
- `RotateKeyOnDemand` — https://docs.aws.amazon.com/kms/latest/APIReference/API_RotateKeyOnDemand.html
- `EnableKeyRotation` — https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html
- `DisableKeyRotation` — https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKeyRotation.html
- `GetKeyRotationStatus` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html
- `ScheduleKeyDeletion` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html
- `CancelKeyDeletion` — https://docs.aws.amazon.com/kms/latest/APIReference/API_CancelKeyDeletion.html
- Key states developer guide — https://docs.aws.amazon.com/kms/latest/developerguide/key-state.html
- `TagResource` — https://docs.aws.amazon.com/kms/latest/APIReference/API_TagResource.html
- `Tag` (shared type) — https://docs.aws.amazon.com/kms/latest/APIReference/API_Tag.html
- `UntagResource` — https://docs.aws.amazon.com/kms/latest/APIReference/API_UntagResource.html
- `ListResourceTags` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ListResourceTags.html
- `CreateGrant` — https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateGrant.html
- `RetireGrant` — https://docs.aws.amazon.com/kms/latest/APIReference/API_RetireGrant.html
- `RevokeGrant` — https://docs.aws.amazon.com/kms/latest/APIReference/API_RevokeGrant.html
- `ListGrants` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ListGrants.html
- `ListRetirableGrants` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ListRetirableGrants.html
- `PutKeyPolicy` — https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
- `GetKeyPolicy` — https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyPolicy.html
- `ListKeyPolicies` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeyPolicies.html
- `CreateAlias` — https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateAlias.html
- `ListAliases` — https://docs.aws.amazon.com/kms/latest/APIReference/API_ListAliases.html
- `UpdateAlias` — https://docs.aws.amazon.com/kms/latest/APIReference/API_UpdateAlias.html
- `DeleteAlias` — https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteAlias.html

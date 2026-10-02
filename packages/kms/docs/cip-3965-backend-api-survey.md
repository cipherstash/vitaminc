# CIP-3965 backend API survey: mapping AWS KMS, Azure Key Vault, HashiCorp Vault, and Google Cloud KMS onto ZeroKMS's operations

[`cipherstash-suite/packages/stack-kms/docs/cip-3965-stack-encrypt-call-surface.md`](../../../../cipherstash-suite/packages/stack-kms/docs/cip-3965-stack-encrypt-call-surface.md)
established that `stack-encrypt`'s entire production call surface reduces to
three operations:

1. **`generate_keys`** — batch-generate N fresh data keys for a keyset; get
   back `(key material, iv, tag)` per key, in order. ZeroKMS derives the key
   locally from partial "reencrypted" material the service returns, combined
   with the client's own keyset via `recipher::ProxyCipher` — the full key
   never exists server-side.
2. **`retrieve_keys`** — batch re-derive N previously-generated keys given
   each one's `(iv, tag)`. Same reencryption-based derivation, replaying the
   stored IV instead of minting a fresh one.
3. **`load_index_key`** — given a keyset id/name (or none, for "default"),
   deterministically derive a per-keyset index key, used **locally** (no
   further KMS calls) to drive the HMAC-SHA256 PRF behind searchable-encryption
   index terms. Same keyset always yields the same index key.

This doc surveys the four CIP-3965 target vendors' real APIs and maps each
onto these three operations.

---

## AWS KMS

**Generate + wrap.** [`GenerateDataKey`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html):
request takes `KeyId`, `KeySpec` (`AES_256`/`AES_128`) or `NumberOfBytes`, and
an optional `EncryptionContext` (string-to-string map, AAD-style — must be
supplied identically on decrypt or the call fails with
`InvalidCiphertextException`). Response returns `Plaintext` (the raw DEK,
≤4096 bytes) and `CiphertextBlob` (the DEK wrapped under the specified KMS
key, ≤6144 bytes) in the *same* call — one round trip produces both forms.
One key per call; no batch parameter.

**Retrieve/unwrap.** [`Decrypt`](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html):
takes `CiphertextBlob` + the same `EncryptionContext` used at generation time,
returns `Plaintext` + `KeyId`. One ciphertext per call.

**Deterministic derivation.** None. Every `GenerateDataKey` call mints fresh
random bytes; there is no "give me the same key twice" primitive.

**Caching.** The [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html)
ships a `CachingCryptoMaterialsManager` that caches already-generated data
keys keyed by encryption context, with TTL / max-bytes / max-messages
thresholds — an opt-in, application-level cache in front of ordinary
`GenerateDataKey`/`Decrypt` calls. Separately, the
[**AWS KMS Hierarchical Keyring**](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html)
is structurally the closest AWS analog to ZeroKMS's model: a KMS-protected
*branch key* is persisted in a DynamoDB-backed key store, cached locally, and
used to derive a unique per-message wrapping key **without a KMS call per
operation** — the branch key itself is what gets reused/rotated, not the
per-message key. It requires provisioning and operating a DynamoDB table as
an extra piece of infrastructure, which is a real operational cost, not just
an API detail.

**Auth.** IAM (SigV4-signed requests; typically an IAM role via the SDK's
default credential chain).

### Maps to ZeroKMS ops

- `generate_keys` → `GenerateDataKey` per key (no native batch — N calls, or N
  keys wrapped under the *same* KMS key requested serially/concurrently).
  `EncryptionContext` is a natural home for ZeroKMS's currently-unused
  `descriptor`/`context` fields if AWS ever needs them.
- `retrieve_keys` → `Decrypt` per ciphertext blob (no native batch either).
- `load_index_key` → **gap**. No deterministic derivation. AWS's own
  Hierarchical Keyring — the pattern AWS itself uses to solve "cheap,
  repeated, locally-derivable keys" — is the template: derive the index key
  from a *fixed* wrapped blob (a `CiphertextBlob` created once per keyset,
  stored, and `Decrypt`ed once at cipher construction, exactly as
  `load_index_key` already does today for ZeroKMS) rather than expecting AWS
  KMS to derive it. This keeps `load_index_key`'s contract (`Decrypt` a
  stored root blob) but drops the "the *service* derives it" assumption
  baked into ZeroKMS's design — the determinism instead has to come entirely
  from the trait implementation storing and reusing one fixed ciphertext.

**Subtle incompatibility — the security model, not just the shape.**
ZeroKMS's `(iv, tag)` reconstruction requires *both* the client's local
keyset (via `recipher`) and the server's reencrypted material — a
server-only compromise plus stored `(iv, tag)` is not sufficient to recover a
key. AWS KMS's `CiphertextBlob` is the opposite: it is a complete,
self-contained wrapped key that `Decrypt` unwraps entirely server-side. A
compromised AWS account (or a leaked `CiphertextBlob` combined with
compromised IAM credentials) is sufficient to recover the plaintext DEK.
Papering over this difference at the trait level — treating `CiphertextBlob`
as "just a different shape of `(iv, tag)`" — would silently drop a security
property `stack-encrypt`'s current design provides. This needs to be an
explicit, documented trait-level distinction (or an explicit non-goal), not
an implementation detail.

**No native batching anywhere in the KMS API itself** means the trait's
"batch N keys in one call" contract (the whole reason `stack-encrypt`
`dispatch()`es once per request kind) cannot be satisfied by AWS KMS as a
single network round trip — an AWS backend has to fan out N
`GenerateDataKey`/`Decrypt` calls (concurrently) behind one trait call, or
lean on caching to avoid needing N calls in the first place. Concurrency
against per-second request limits (and the `EncryptionContext` correctness
of concurrent context values) becomes an implementation concern for the AWS
backend specifically.

---

## Azure Key Vault

**Generate + wrap.** No native "generate data key" call. The standard
pattern: the client generates the DEK locally (a CSPRNG), then calls
[`wrapKey`](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key)
(`POST {vaultBaseUrl}/keys/{key-name}/{key-version}/wrapkey`) with `alg`
(e.g. `RSA-OAEP-256`, `A256KW`, or an AEAD alg like `A256GCM`) and `value`
(the DEK, base64url). AEAD algorithms accept `aad`/`iv`/`tag` fields on
both request and response — an AAD-binding mechanism, same shape as AWS's
`EncryptionContext` but per-call rather than a persistent map. Response is
`{ kid, value }` (or `+ iv/tag` for AEAD algs) — one key per call, no batch
parameter.

**Retrieve/unwrap.** `unwrapKey` (same URL shape, `.../unwrapkey`), mirror of
`wrapKey`: takes the wrapped `value` (+ `iv`/`tag` for AEAD algs), returns the
plaintext `value`. One key per call.

**Deterministic derivation.** None documented — Key Vault's operations are
plain wrap/unwrap and encrypt/decrypt on caller-supplied or vault-generated
asymmetric/symmetric keys; there is no context-derived-key primitive.

**Caching.** No first-party caching mechanism (no Hierarchical-Keyring
equivalent). The application-level pattern is the same DIY approach as plain
AWS `GenerateDataKey`/`Decrypt` without the Encryption SDK: cache the
unwrapped DEK client-side for a bounded time, on the caller's own terms.

**Auth.** Microsoft Entra ID (Azure AD) OAuth2 token, scope
`https://vault.azure.net/.default`.

### Maps to ZeroKMS ops

- `generate_keys` → generate the DEK locally, then `wrapKey` per key (no
  native batch; N calls). Unlike AWS, Azure has no single call that returns
  *both* plaintext and wrapped forms together — generation and wrapping are
  two separate client-side/server-side steps by construction, which is a
  closer shape match to ZeroKMS's split (client contributes the plaintext
  side, server contributes the wrap) than AWS's one-call `GenerateDataKey`.
- `retrieve_keys` → `unwrapKey` per `(kid, value[, iv, tag])` (no native
  batch).
- `load_index_key` → **gap**, same as AWS: no deterministic derivation.
  Same workaround applies — `unwrapKey` a fixed stored blob once per keyset
  at construction time.

**Subtle incompatibility.** Azure's `wrapKey`/`unwrapKey` is *also* a
complete server-side operation (the vault holds the full KEK and performs the
wrap/unwrap entirely itself) — the same "server-only compromise is
sufficient" security-model gap as AWS KMS, for the same reason. Azure adds
one more wrinkle worth flagging: `aad`/`iv`/`tag` are only meaningful for AEAD
wrap algorithms (`A*GCM`); the RSA-OAEP and AES-KW algorithms shown in the
default examples carry no AAD field at all, so an AWS-style "always bind a
context" default is algorithm-dependent here in a way it isn't for AWS or
ZeroKMS.

---

## HashiCorp Vault (Transit secrets engine)

**Generate + wrap.** [`POST /transit/datakey/:type/:name`](https://developer.hashicorp.com/vault/api-docs/secret/transit),
`:type` is `plaintext` (returns both `plaintext` and `ciphertext`) or
`wrapped` (`ciphertext` only) — the one vendor here with an AWS-`GenerateDataKey`-shaped
single call. Takes `context` (base64, only meaningful for a `derived` key —
see below), `nonce`, `bits`. One key per call to this singular endpoint; a
**separate, plural** endpoint, `/transit/datakeys/:type/:name`, accepts a
`count` parameter and returns a `key_pairs` array — genuine batch generation
in one round trip, unlike AWS or Azure. *(Later finding: this plural endpoint
is Vault Enterprise only; Community Vault has just the singular path.)*

**Retrieve/unwrap.** `POST /transit/decrypt/:name` with `ciphertext` (+
`context`/`nonce` for a derived key). Critically, `encrypt`/`decrypt` **do**
support `batch_input`: an array of `{ plaintext | ciphertext, context, nonce,
reference }` objects processed in one call, order-preserving in the
response — real batch retrieve, matching the shape `stack-encrypt`'s
`dispatch()` wants.

**Deterministic derivation — the one vendor with a real answer.** A Transit
key created with `"derived": true` requires a `context` on every operation
against it, and (per Vault's docs) enabling **convergent encryption** on such
a key means "the same context and nonce" (or, in newer convergent-version
modes, context alone) "generates the same ciphertext" — i.e. deterministic
output for the same input. This is the one vendor of the four with a
first-class, documented deterministic-derivation feature, and it is the
closest conceptual match to ZeroKMS's `load_index_key`. It comes with an
explicit operational warning in Vault's own docs: convergent encryption
requires careful nonce handling and weakens semantic security for the data
it's applied to (patterns become derivable when the same context repeats) —
it is not simply "free determinism," and Vault documents it as a
special-purpose mode rather than the default.

**Caching.** No documented first-party caching layer (no Hierarchical-Keyring
analog); same DIY story as Azure/GCP.

**Auth.** Vault token (via AppRole, Kubernetes auth, cloud IAM auth methods,
etc. — pluggable per Vault's auth-method framework).

### Maps to ZeroKMS ops

- `generate_keys` → `/transit/datakey/plaintext/:name`, batched via
  `/transit/datakeys/plaintext/:name?count=N` — the closest native batch
  match of the four vendors.
- `retrieve_keys` → `/transit/decrypt/:name` with `batch_input` — also a
  native batch match, and the *only* vendor surveyed where "retrieve N keys
  in one call" is a first-party operation rather than a workaround.
- `load_index_key` → **partial match, not a gap** — a `derived` +
  convergent-mode Transit key can plausibly return the same key material for
  the same `context` deterministically, which is structurally what
  `load_index_key` needs. This should be evaluated carefully rather than
  assumed safe: convergent encryption's security caveats are about the
  *data* encrypted under it, and `load_index_key`'s output here is key
  material, not application data — that changes which caveats apply and
  needs its own analysis before relying on it, not a blanket "Vault solves
  this."

**Subtle incompatibility.** Vault Transit's plaintext DEK model is the same
"server holds/derives the complete key" shape as AWS and Azure — no
client-side keyset contribution like ZeroKMS's `recipher`-based scheme, so
the same server-compromise caveat applies. Also: Vault's `context` parameter
is *only* meaningful when the key was created with `derived: true` at
key-creation time — it's a per-key mode switch, not a per-request option, so
a generalized trait can't treat "pass a context" as always available the way
AWS's `EncryptionContext` or Azure's `aad` are (both work on any key,
per-request).

---

## Google Cloud KMS

**Generate + wrap.** No native "generate data key" call, and no
`GenerateDataKey`/`datakey`-shaped endpoint at all. The
[documented envelope-encryption pattern](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt)
is: generate the DEK locally, then call
`POST {name=.../cryptoKeys/*}:encrypt` with `plaintext` and optional
`additionalAuthenticatedData` (AAD, same size-budget class as the plaintext)
to wrap it. Response is `ciphertext` (+ CRC32C integrity fields) — one item
per call, no batch parameter. Google's Tink library builds a
higher-level "envelope AEAD" abstraction on top of this exact
generate-locally-then-`Encrypt` pattern; it is a client-library convenience,
not a different server API.

**Retrieve/unwrap.** `:decrypt` on the same crypto key resource, mirrored
request/response (`ciphertext`[`+aad`] → `plaintext`). One item per call.

**Deterministic derivation.** None documented for symmetric `ENCRYPT_DECRYPT`
keys — every `Encrypt` call on a random plaintext DEK produces fresh
ciphertext by construction (GCM, so it's also nonce-randomized under the
hood), and there is no context-derived-key mode analogous to Vault's.

**Caching.** No first-party caching mechanism; same DIY story as Azure and
Vault.

**Auth.** Google Cloud IAM (OAuth2 / service-account credentials via the
standard GCP credential chain).

### Maps to ZeroKMS ops

- `generate_keys` → generate the DEK locally, then `:encrypt` per key (no
  native batch; N calls). Same two-step shape as Azure.
- `retrieve_keys` → `:decrypt` per ciphertext (no native batch).
- `load_index_key` → **gap**, same as AWS and Azure, same workaround (a
  fixed, stored ciphertext `Decrypt`ed once at construction).

**Subtle incompatibility.** Same server-side-complete-unwrap security-model
gap as AWS/Azure/Vault relative to ZeroKMS's client-contributes-material
scheme. One GCP-specific wrinkle: the payload size budget for HSM-protected
keys is *combined* across `plaintext` + `additionalAuthenticatedData`
(8 KiB total), tighter than AWS's independent limits (4096-byte plaintext DEK,
separately-capped `EncryptionContext`) — worth knowing if a `descriptor` /
context payload and the wrapped-key bytes both need to fit through GCP's
`encrypt` call in one shot for an HSM-backed key.

---

## Cross-vendor comparison

| | AWS KMS | Azure Key Vault | HashiCorp Vault (Transit) | Google Cloud KMS |
|---|---|---|---|---|
| Generate+wrap in one call | Yes (`GenerateDataKey`) | No (generate locally + `wrapKey`) | Yes (`datakey/plaintext`) | No (generate locally + `encrypt`) |
| Native batch (generate) | No | No | **Enterprise only** (`datakeys/…?count=N`; Community answers `404 unsupported path` — found during implementation, see ADR 0002) | No |
| Native batch (retrieve) | No | No | **Yes** (`batch_input`) | No |
| Deterministic derivation | No (Hierarchical Keyring caches a branch key instead) | No | **Partial** (`derived` + convergent mode — needs its own security review before use as a KDF) | No |
| First-party caching primitive | Yes (Encryption SDK CMM; Hierarchical Keyring for the no-per-op-call case) | No | No | No |
| Per-call AAD/context binding | Yes (`EncryptionContext`, any key) | Algorithm-dependent (`aad`, AEAD algs only) | Key-creation-time-gated (`context`, only if `derived: true`) | Yes (`additionalAuthenticatedData`, any key) |
| Security model for retrieval | Server-side-complete unwrap | Server-side-complete unwrap | Server-side-complete unwrap | Server-side-complete unwrap |

*(ZeroKMS, for reference: generate+wrap in one call, native batch on both
generate and retrieve, deterministic index-key derivation via
`load_index_key`, no first-party "caching" concept because it's designed to
be called per value already, and reconstruction requires both client and
server material — none of the four vendors match that last property.)*

## Implications for trait design

1. None of the four vendors natively batches `generate_keys` the way ZeroKMS
   does, except Vault's plural `datakeys` endpoint (generate) and Vault's
   `batch_input` (retrieve). A generalized trait whose contract promises
   "one batched call" either has to let vendor implementations fan out
   concurrent single-item calls under the hood (breaking the "one round
   trip" property `dispatch()`'s docs currently rely on, for three of four
   vendors), or the trait's batching guarantee needs to be reframed as "one
   logical operation, vendor-dependent round-trip count" rather than "one
   network call."
2. `load_index_key` — deterministic per-keyset key derivation with no
   further KMS calls — has no clean equivalent in AWS, Azure, or GCP's
   native APIs. The workaround available to all three (store one fixed
   wrapped blob per keyset, unwrap it once at construction, exactly as
   `load_index_key` already does today) preserves the *contract*
   (`load_index_key` still returns a deterministic `(keyset_id, key)`) at
   the cost of pushing the "make it deterministic" property entirely onto
   the trait implementation rather than the vendor — the vendor is reduced
   to a plain unwrap of client-controlled ciphertext. Vault's convergent
   mode is the one vendor-native alternative, but it needs its own security
   review (it was designed for deterministic *data* encryption, not
   explicitly as a KDF) before being treated as equivalent.
3. Every vendor surveyed reconstructs a key from server-side material alone
   (a complete wrap/unwrap or `Encrypt`/`Decrypt`), unlike ZeroKMS, which
   requires both the client's local keyset and the server's reencrypted
   material to reconstruct a key. This is a real security-model difference,
   not an API-shape difference, and needs to be an explicit, named property
   of the trait (e.g., documented per-backend, not silently assumed
   equivalent) rather than something a uniform trait interface quietly
   papers over.
4. Only AWS ships a first-party answer to "avoid a round trip per
   operation" (the Encryption SDK's caching CMM, and especially the
   Hierarchical Keyring's cached-branch-key model, which is structurally the
   closest vendor-native analog to ZeroKMS's own design). Azure, Vault, and
   GCP have no such primitive, so caching for those three — and for AWS if
   the Hierarchical Keyring's DynamoDB dependency is unwanted — has to be a
   capability the trait implementation (or a shared wrapper around any
   `DataKeySource` impl) provides itself, not something delegated to the
   vendor API.
5. AAD-style context binding exists in some form for three of four vendors
   (AWS `EncryptionContext`, Azure `aad` on AEAD algs only, GCP
   `additionalAuthenticatedData`) but is absent or key-mode-gated for the
   fourth (Vault, only under `derived: true`). If the generalized trait ever
   wants to forward `stack-encrypt`'s currently-unused `descriptor`/`context`
   fields to a backend, it can't assume every backend supports it
   uniformly or unconditionally.

## Sources

- AWS KMS: [`GenerateDataKey`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html), [Data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html), [Hierarchical Keyring](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-hierarchical-keyring.html)
- Azure Key Vault: [`wrapKey`](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key)
- HashiCorp Vault: [Transit secrets engine API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- Google Cloud KMS: [`cryptoKeys.encrypt`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt)

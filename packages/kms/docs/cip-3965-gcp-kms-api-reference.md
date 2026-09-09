# CIP-3965/3985 Google Cloud KMS API reference

This doc is a full reference for Google Cloud KMS's `v1` REST API surface, scoped
to the resources and methods relevant to CIP-3965/3985's Rust capability-trait
design. It supersedes the narrow GCP section of
[`cip-3965-backend-api-survey.md`](./cip-3965-backend-api-survey.md), which
covered only the `encrypt`/`decrypt` pair needed for one use case
(`stack-encrypt`'s envelope-encryption mapping). That doc's GCP section and its
cross-vendor comparison table still stand for the narrower question they
answer; this doc exists to answer a different question — how much of GCP's
*actual* surface should the generalized traits cover.

All facts below come from the GCP KMS `v1` [Discovery
Document](https://cloudkms.googleapis.com/$discovery/rest?version=v1) — the
machine-readable service description Google generates from the same
protobuf source as the REST reference pages at
`cloud.google.com/kms/docs/reference/rest` — cross-checked against the
individual REST reference pages, the [quotas
page](https://docs.cloud.google.com/kms/quotas), and the [digital-signature
docs](https://docs.cloud.google.com/kms/docs/create-validate-signatures)
where the discovery doc doesn't carry a detail (e.g. RSA signing's exact
byte-length formula). Where a field description is quoted, it's copied
verbatim from the discovery document's `description` string, not paraphrased.

**Method count:** 30 methods across 5 resource types (KeyRing, CryptoKey,
CryptoKeyVersion, ImportJob, Location), covering every method the task named
plus the handful (`patch` on CryptoKeyVersion, `testIamPermissions`) that sit
next to them in the same resource groups.

---

## 1. Resource model

```
projects/{project}/locations/{location}/
  keyRings/{keyRing}                          — logical grouping, immutable, no delete
    cryptoKeys/{cryptoKey}                    — logical key, purpose is immutable
      cryptoKeyVersions/{cryptoKeyVersion}    — actual key material + state
    importJobs/{importJob}                    — wrapping-key handshake for BYOK
```

- A **KeyRing** is a pure container: `name` + `createTime`, nothing else. It
  cannot be deleted via the API at all (no `keyRings.delete` — the discovery
  doc lists `delete` in the resource's Python-binding surface but the actual
  REST method does not exist for KeyRing the way it does for CryptoKey/EKM
  resources; keyrings are permanent for the life of the project location).
- A **CryptoKey** is a logical key: it has a `purpose` (immutable — set once
  at creation, never changed) and zero or more **CryptoKeyVersions**, each of
  which holds actual key material and can be independently enabled, disabled,
  or destroyed. Exactly one version can be the `primary` version, and only
  for `purpose = ENCRYPT_DECRYPT` keys — `primary` is the version an `Encrypt`
  call uses when you address the CryptoKey by name rather than a specific
  version.
- An **ImportJob** is a short-lived (3-day) wrapping-key handshake: create
  one, fetch its generated public key, wrap your own key material with it
  offline, then call `cryptoKeyVersions.import` referencing the job. It is
  not a place key material passes through Google's control plane — Google
  never sees the plaintext key.

### CryptoKeyPurpose → allowed operations

| Purpose | Allowed operations |
|---|---|
| `ENCRYPT_DECRYPT` | `Encrypt`, `Decrypt`. Only purpose that supports a `primary` version and automatic rotation (`rotationPeriod`/`nextRotationTime`). |
| `ASYMMETRIC_SIGN` | `AsymmetricSign`, `GetPublicKey`. |
| `ASYMMETRIC_DECRYPT` | `AsymmetricDecrypt`, `GetPublicKey`. |
| `RAW_ENCRYPT_DECRYPT` | `RawEncrypt`, `RawDecrypt`. "Meant to be used for interoperable symmetric encryption and does not support automatic CryptoKey rotation." |
| `MAC` | `MacSign`, `MacVerify`. |
| `KEY_ENCAPSULATION` | `GetPublicKey`, `Decapsulate` (post-quantum KEM; out of this doc's requested scope but exists — see §8). |
| `AES_WRAPPING` | AES key wrap (`AES_256_KWP`, RFC 5649) — newest purpose in the enum, for wrapping/unwrapping other keys rather than data. |

`versionTemplate.algorithm` is required at `CryptoKey` creation and is
immutable per-version thereafter (it's a read-only field on
`CryptoKeyVersion` itself — you set it via the *template*, not per-version).

### Protection levels

Five values, not four — `HSM_SINGLE_TENANT` is a newer addition beyond the
`SOFTWARE`/`HSM`/`EXTERNAL`/`EXTERNAL_VPC` set the task and the earlier
survey named:

| Value | Meaning |
|---|---|
| `SOFTWARE` | "Crypto operations are performed in software." |
| `HSM` | "Crypto operations are performed in a Hardware Security Module." (Google-managed, multi-tenant.) |
| `EXTERNAL` | "Crypto operations are performed by an external key manager." (Cloud EKM, direct.) |
| `EXTERNAL_VPC` | "Crypto operations are performed in an EKM-over-VPC backend." (Cloud EKM via VPC, needs an `EkmConnection`.) |
| `HSM_SINGLE_TENANT` | "Crypto operations are performed in a single-tenant HSM." Dedicated (not shared-tenant) HSM instance; pairs with `trustedWrappingEnabled`/`hsmTrusted` fields and a `cryptoKeyBackend` pointing at a `projects/*/locations/*/singleTenantHsmInstances/*` resource. |

`protectionLevel` is set once via `CryptoKeyVersionTemplate.protectionLevel`
(default `SOFTWARE`) and is **output-only, immutable** on every individual
`CryptoKeyVersion` — there is no way to change a version's protection level
after creation; a rotation to a different protection level requires a new
`CryptoKey`/version with a different template.

---

## 2. Conventions that apply across (almost) every method

### 2.1 CRC32C integrity checksums — every crypto-operation request/response

Every payload-carrying field on `Encrypt`, `Decrypt`, `RawEncrypt`,
`RawDecrypt`, `AsymmetricSign`, `AsymmetricDecrypt`, `MacSign`, `MacVerify`,
and `GenerateRandomBytes` has a matching optional `*Crc32c` **request**
field (an `int64`-typed CRC32C of that field, client-computed) and, on the
corresponding response, both an echoed `*Crc32c` field for the response
payload and a `verified*Crc32c` boolean confirming the *request's* checksum
was received and checked server-side. This is Google's documented
[data-integrity
guarantee](https://cloud.google.com/kms/docs/data-integrity-guidelines) for
protecting against corruption in transit that TLS alone wouldn't catch
(bit flips from a compromised proxy, a buggy intermediate). The documented
client protocol on every one of these fields, verbatim: "Discard the
response in case of non-matching checksum values, and perform a limited
number of retries. A persistent mismatch may indicate an issue in your
computation of the CRC32C checksum." This is optional plumbing (all `*Crc32c`
fields are `Optional.`), but it's a *repeated, uniform* per-call verification
handshake unique to GCP among the surveyed vendors — a trait that wants to
expose it has to decide whether it's a first-class part of the request/
response shape or an implementation-only concern.

### 2.2 Resource-name-as-target, not a separate `keyId` parameter

Every crypto operation (`encrypt`, `decrypt`, `rawEncrypt`, `rawDecrypt`,
`asymmetricSign`, `asymmetricDecrypt`, `macSign`, `macVerify`,
`getPublicKey`) takes the full resource `name` as a **path** parameter
(`{+name}:encrypt`, etc.), not a body field — the key/version is baked into
the URL, and the request body carries only the payload. This means "which
key" is inseparable from "which endpoint" at the HTTP layer; a trait
abstraction needs a resource-name builder as a first-class concern, not an
optional extra.

### 2.3 Two different "which version gets used" models

- **`cryptoKeys.encrypt`**'s `name` path parameter pattern is
  `^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/.*$` — the
  trailing `.*` deliberately allows *either* a bare CryptoKey resource name
  (server picks the current `primary` version) *or* a full
  `.../cryptoKeys/{k}/cryptoKeyVersions/{v}` name (pins a specific version).
  Documented explicitly: "If a CryptoKey is specified, the server will use
  its primary version."
- **`cryptoKeys.decrypt`**'s `name` pattern is the *strict* form —
  `^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$` — a
  CryptoKey only, **never** a specific version. Decrypt cannot be pointed at
  a version at all; "the server will choose the appropriate version"
  (GCP's ciphertext blobs self-identify which of the CryptoKey's enabled
  versions produced them). `DecryptResponse.usedPrimary` (a `bool`) tells
  you after the fact whether the primary version happened to be the one
  used.

  This is a real asymmetry worth naming explicitly for trait design:
  `Encrypt` supports "pin an exact version," `Decrypt` never does — decrypt
  is *ciphertext-directed*, not *caller-directed*, for `ENCRYPT_DECRYPT`
  purpose keys.

- Every **other** crypto operation (`rawEncrypt`/`rawDecrypt`,
  `asymmetricSign`/`asymmetricDecrypt`, `macSign`/`macVerify`,
  `getPublicKey`) is defined only on `cryptoKeyVersions`, never on
  `cryptoKeys` — the caller *must* name an exact version; there is no
  "use the primary" shortcut for any of them. (This also means the task's
  framing of `cryptoKeys.rawEncrypt`/`cryptoKeys.rawDecrypt` doesn't match
  the actual API shape — the real methods are
  `cryptoKeyVersions.rawEncrypt`/`rawDecrypt`. See §9.)

### 2.4 Error model

Every method returns a standard `google.rpc.Status` on failure: `code`
(`int32`, a `google.rpc.Code` enum value), `message` (developer-facing
string), `details` (array of typed error-detail messages). GCP KMS does not
define KMS-specific error codes beyond this — it reuses the platform-wide
[`google.rpc.Code`](https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto)
enum and [AIP-193](https://google.aip.dev/193) HTTP mapping used by every
Google Cloud API:

| Code | HTTP | Typical KMS trigger |
|---|---|---|
| `INVALID_ARGUMENT` | 400 | Malformed resource name; missing required field (`purpose`, `version_template.algorithm`, `wrappedKey`+`importJob`); plaintext/AAD over the size budget (§3); both `data` and `digest` supplied to `AsymmetricSign`; digest algorithm mismatched to the key's algorithm; a `*Crc32c` mismatch reported as an error rather than silently accepted. |
| `FAILED_PRECONDITION` | 400 | CryptoKeyVersion not in `ENABLED` state for a crypto op; `updatePrimaryVersion` called on a non-`ENCRYPT_DECRYPT`-purpose key; `restore` called on a version not in `DESTROY_SCHEDULED`; Cloud KMS API not yet enabled/propagated in the project. |
| `NOT_FOUND` | 404 | KeyRing/CryptoKey/CryptoKeyVersion/ImportJob resource name doesn't exist or caller lacks even `get`-level visibility. |
| `ALREADY_EXISTS` | 409 | `keyRingId`/`cryptoKeyId`/`importJobId` already taken within the parent scope (all three `Id` values are caller-chosen, not server-generated, so collisions are a normal outcome to handle). |
| `PERMISSION_DENIED` | 403 | Caller's principal lacks the specific `cloudkms.*` IAM permission for that method (see per-method tables below) on that resource. |
| `RESOURCE_EXHAUSTED` | 429 | A quota (§7) is exceeded — cryptographic-request, read-request, write-request, or (post Feb-2026) token-bucket quota. |
| `UNAUTHENTICATED` | 401 | Missing/invalid/expired credentials. |
| `ABORTED` | 409 | Concurrent modification conflict (e.g. IAM policy `etag` mismatch on `setIamPolicy`). |
| `DEADLINE_EXCEEDED` / `UNAVAILABLE` / `INTERNAL` | 504 / 503 / 500 | Transient service-side failures — the documented advice for all of these, and for CRC32C mismatches, is "perform a limited number of retries," i.e. these are meant to be retried, not surfaced raw. |

Because this error model is uniform across every method (nothing here is
KMS-specific beyond *which* IAM permission or *which* precondition), it
isn't repeated per-method below except where a method has a genuinely
distinctive failure mode.

### 2.5 Auth & OAuth scopes

Every single method in this doc accepts the same two OAuth scopes
(interchangeably — either satisfies the API):
`https://www.googleapis.com/auth/cloud-platform` and
`https://www.googleapis.com/auth/cloudkms`. IAM permissions are always
`cloudkms.<resourceType>.<verb>` (e.g. `cloudkms.cryptoKeys.encrypt`,
`cloudkms.cryptoKeyVersions.destroy`) checked against the specific resource
addressed by the call's path parameter.

---

## 3. The HSM combined-size budget — confirmed precisely

Directly from the discovery document's `EncryptRequest.plaintext` field
description (verbatim):

> "Required. The data to encrypt. Must be no larger than 64KiB. The maximum
> size depends on the key version's protection_level. For SOFTWARE,
> EXTERNAL, and EXTERNAL_VPC keys, the plaintext must be no larger than
> 64KiB. For HSM keys, the combined length of the plaintext and
> additional_authenticated_data fields must be no larger than 8KiB."

And `EncryptRequest.additionalAuthenticatedData` (verbatim): "The maximum
size depends on the key version's protection_level. For SOFTWARE, EXTERNAL,
and EXTERNAL_VPC keys the AAD must be no larger than 64KiB. For HSM keys, the
combined length of the plaintext and additional_authenticated_data fields
must be no larger than 8KiB."

This confirms the earlier survey's finding exactly: **for `HSM` (and, by the
same 8 KiB combined language, `HSM_SINGLE_TENANT`) protection level, it is
one shared 8 KiB budget for `plaintext + additionalAuthenticatedData`
together**, not 8 KiB each. `SOFTWARE`, `EXTERNAL`, and `EXTERNAL_VPC` each
get an independent 64 KiB ceiling per field (128 KiB combined, in effect).
This is tighter than AWS KMS's model, where `Plaintext` (≤4096 bytes) and the
`EncryptionContext` map are capped independently of each other with no
combined ceiling.

`RawEncryptRequest` carries the **identical wording**, but only names
`SOFTWARE` and `HSM` explicitly (the raw-encrypt doc text doesn't mention
`EXTERNAL`/`EXTERNAL_VPC` at all) — worth treating as "undocumented for
those protection levels" rather than assuming the 64 KiB SOFTWARE figure
silently extends to them for raw operations, since `RAW_ENCRYPT_DECRYPT` is
a separate CryptoKey purpose from `ENCRYPT_DECRYPT` and the two are not
guaranteed to share every constraint just because the request-shape
descriptions overlap.

There is no documented combined-size caveat for `MacSignRequest.data`,
`AsymmetricDecryptRequest.ciphertext`, or `AsymmetricSignRequest.data`/
`.digest` — those have their own independent constraints (below), not a
shared plaintext+AAD-style budget, because none of those operations take an
AAD parameter at all.

---

## 4. KeyRing methods

### 4.1 `keyRings.create`

`POST /v1/{parent=projects/*/locations/*}/keyRings`

| Param | In | Type | Required | Constraint |
|---|---|---|---|---|
| `parent` | path | string | Yes | `^projects/[^/]+/locations/[^/]+$` |
| `keyRingId` | query | string | Yes | `[a-zA-Z0-9_-]{1,63}`, unique within the location |

Request/response body: `KeyRing` — only two fields exist on the whole
resource: `name` (output-only) and `createTime` (output-only). There is
nothing else to configure on a KeyRing; all configuration lives on the
CryptoKeys inside it. IAM: `cloudkms.keyRings.create`. Errors:
`ALREADY_EXISTS` (id taken), `INVALID_ARGUMENT` (bad `keyRingId` pattern),
`PERMISSION_DENIED`.

### 4.2 `keyRings.get`

`GET /v1/{name=projects/*/locations/*/keyRings/*}` → `KeyRing`. IAM:
`cloudkms.keyRings.get`.

### 4.3 `keyRings.list`

`GET /v1/{parent=projects/*/locations/*}/keyRings` →
`ListKeyRingsResponse { keyRings[], totalSize, nextPageToken }`. Query
params: `pageSize` (int32), `pageToken`, `filter`, `orderBy` (all optional;
`totalSize` is "not populated if... filter is applied"). IAM:
`cloudkms.keyRings.list`.

### 4.4 `keyRings.getIamPolicy` / `setIamPolicy` / `testIamPermissions`

Standard [IAM v1 mixin](https://cloud.google.com/iam/docs/reference/rest)
methods, identical shape on every resource type in this API that supports
IAM (KeyRing, CryptoKey, ImportJob — **not** CryptoKeyVersion, which inherits
its parent CryptoKey's IAM policy and has no policy of its own):

- `getIamPolicy`: `GET {resource}:getIamPolicy`, optional query param
  `options.requestedPolicyVersion` (int32: 0, 1, or 3 — "3" required if the
  policy has any conditional bindings). Returns `Policy`.
- `setIamPolicy`: `POST {resource}:setIamPolicy`, body
  `SetIamPolicyRequest { policy: Policy, updateMask?: FieldMask }`. Returns
  the resulting `Policy`. Docs explicitly warn: if you use IAM Conditions you
  **must** set `Policy.etag` on every `setIamPolicy` call, or IAM will
  silently downgrade a v3 (conditional) policy to v1 and drop every
  condition.
- `testIamPermissions`: `POST {resource}:testIamPermissions`, body
  `{ permissions: string[] }` → `{ permissions: string[] }` (the subset the
  caller actually holds). No wildcard permissions allowed in the request.

`Policy` itself: `version` (int32: 0/1/3), `bindings[]` (`{role, members[],
condition?}`), `auditConfigs[]`, `etag` (bytes, for optimistic concurrency —
`ABORTED`/409 on a stale etag).

---

## 5. CryptoKey methods

### 5.1 `cryptoKeys.create`

`POST /v1/{parent=projects/*/locations/*/keyRings/*}/cryptoKeys`

| Param | In | Type | Required | Notes |
|---|---|---|---|---|
| `parent` | path | string | Yes | `.../keyRings/[^/]+$` |
| `cryptoKeyId` | query | string | Yes | `[a-zA-Z0-9_-]{1,63}`, unique within the KeyRing |
| `skipInitialVersionCreation` | query | bool | No | "creates CryptoKey without any CryptoKeyVersions. You must manually call CreateCryptoKeyVersion or ImportCryptoKeyVersion before you can use this CryptoKey." |
| `trustedWrappingEnabled` | query | bool | No | Applies to the *first* auto-created version; `HSM_SINGLE_TENANT` only; not valid for `ENCRYPT_DECRYPT` purpose. |

Request body — `CryptoKey`:

| Field | Type | Required/mutability | Notes |
|---|---|---|---|
| `purpose` | enum `CryptoKeyPurpose` | **Required**, immutable | See §1 table. |
| `versionTemplate.algorithm` | enum `CryptoKeyVersionAlgorithm` | **Required** | "For backwards compatibility, GOOGLE_SYMMETRIC_ENCRYPTION is implied if both this field is omitted and CryptoKey.purpose is ENCRYPT_DECRYPT." |
| `versionTemplate.protectionLevel` | enum `ProtectionLevel` | Optional, immutable | Defaults to `SOFTWARE`. |
| `labels` | map<string,string> | Optional | User metadata. |
| `rotationPeriod` | google-duration | Optional | "at least 24 hours and at most 876,000 hours"; requires `nextRotationTime` also set; `ENCRYPT_DECRYPT`-purpose only — "For other keys, this field must be omitted." |
| `nextRotationTime` | google-datetime | Optional | Same `ENCRYPT_DECRYPT`-only restriction. |
| `importOnly` | bool | Optional, immutable | "Whether this key may contain imported versions only." |
| `destroyScheduledDuration` | google-duration | Optional, immutable | Default 30 days if unset — the delay every `destroy` (§6.5) schedules before permanent deletion. |
| `cryptoKeyBackend` | string | Optional, immutable | Only meaningful for `EXTERNAL_VPC` (`.../ekmConnections/*`) or `HSM_SINGLE_TENANT` (`.../singleTenantHsmInstances/*`) protection levels. |
| `keyAccessJustificationsPolicy` | object | Optional | Assured Workloads justification-code allowlist; out of scope here but notable: "If... empty (zero allowed justification code), all encrypt, decrypt, and sign operations will fail" — a policy object that can brick every crypto op on the key if misconfigured. |
| `name`, `createTime`, `primary` | — | Output-only | `primary` is a full embedded `CryptoKeyVersion` copy, present only for `ENCRYPT_DECRYPT` keys. |

Response: the created `CryptoKey`. IAM: `cloudkms.cryptoKeys.create`.

### 5.2 `cryptoKeys.get`

`GET /v1/{name=.../cryptoKeys/*}` → `CryptoKey`. IAM: `cloudkms.cryptoKeys.get`.

### 5.3 `cryptoKeys.list`

`GET /v1/{parent=.../keyRings/*}/cryptoKeys` →
`ListCryptoKeysResponse { cryptoKeys[], totalSize, nextPageToken }`. Query:
`pageSize`, `pageToken`, `filter`, `orderBy`, plus a CryptoKey-specific
`versionView` enum (`CRYPTO_KEY_VERSION_VIEW_UNSPECIFIED` | `FULL`) — controls
whether the embedded `primary` CryptoKeyVersion in each listed CryptoKey
includes its `attestation` field (`FULL`) or omits it (default). IAM:
`cloudkms.cryptoKeys.list`.

### 5.4 `cryptoKeys.patch`

`PATCH /v1/{cryptoKey.name=.../cryptoKeys/*}` — body: partial `CryptoKey`,
**required** query param `updateMask` (google-fieldmask, comma-separated
field paths). Response: the updated `CryptoKey`. Since `purpose` and
`versionTemplate.*` and most identity fields are immutable, in practice this
is mainly for `labels`, `rotationPeriod`/`nextRotationTime`, and
`keyAccessJustificationsPolicy`. IAM: `cloudkms.cryptoKeys.update`.

### 5.5 `cryptoKeys.updatePrimaryVersion`

`POST /v1/{name=.../cryptoKeys/*}:updatePrimaryVersion` — body:
`UpdateCryptoKeyPrimaryVersionRequest { cryptoKeyVersionId: string }`
(required — just the version's short ID, not a full resource name).
Response: the updated `CryptoKey`. **"Returns an error if called on a key
whose purpose is not ENCRYPT_DECRYPT"** — `FAILED_PRECONDITION`/400 for any
other purpose. IAM: `cloudkms.cryptoKeys.update`.

### 5.6 `cryptoKeys.encrypt` / `cryptoKeys.decrypt`

See §2.3 for the name-targeting asymmetry between the two. Full field
tables:

**`EncryptRequest`**

| Field | Type | Required | Constraint |
|---|---|---|---|
| `plaintext` | bytes | **Yes** | ≤64 KiB (SOFTWARE/EXTERNAL/EXTERNAL_VPC) or combined ≤8 KiB with AAD (HSM) — §3 |
| `additionalAuthenticatedData` | bytes | No | Same size rules as above; must match exactly on decrypt |
| `plaintextCrc32c` | int64 | No | §2.1 |
| `additionalAuthenticatedDataCrc32c` | int64 | No | §2.1 |

**`EncryptResponse`**: `name` (resource name of the version actually used —
"Check this field to verify that the intended resource was used for
encryption"), `ciphertext` (bytes), `ciphertextCrc32c`, `protectionLevel`,
`verifiedPlaintextCrc32c` (bool), `verifiedAdditionalAuthenticatedDataCrc32c`
(bool).

**`DecryptRequest`**: `ciphertext` (bytes, **required**),
`additionalAuthenticatedData` (bytes, optional — "must match the data
originally supplied"), `ciphertextCrc32c`, `additionalAuthenticatedDataCrc32c`.

**`DecryptResponse`**: `plaintext` (bytes), `plaintextCrc32c`,
`usedPrimary` (bool — see §2.3), `protectionLevel`.

IAM: `cloudkms.cryptoKeys.encrypt` / `cloudkms.cryptoKeys.decrypt` — note
these are IAM permissions distinct from the generic `get`/`update`, so a
principal can be scoped to crypto-use-only without any read/write access to
key metadata.

### 5.7 `cryptoKeys.getIamPolicy` / `setIamPolicy` / `testIamPermissions`

Identical shape to §4.4, resource pattern `.../cryptoKeys/[^/]+$`. IAM
permission to call `getIamPolicy` itself is `cloudkms.cryptoKeys.getIamPolicy`
(and `...setIamPolicy` / `...testIamPermissions` respectively — these are
themselves permissions, checked before the call is allowed to inspect or
change other permissions).

---

## 6. CryptoKeyVersion methods

### 6.1 `cryptoKeyVersions.create`

`POST /v1/{parent=.../cryptoKeys/*}/cryptoKeyVersions` — body: partial
`CryptoKeyVersion`. Almost every field on `CryptoKeyVersion` is
output-only (§1's protection level, the algorithm, all the timestamps), so
in practice the only field worth setting on create is **`state`** — which is
*not* marked output-only in the schema, and "If unset, state will be set to
ENABLED." This means you can create a version directly into `DISABLED`
state without an extra follow-up call, which is a small but real deviation
from "create always returns something you then have to separately act on."
Response: the created `CryptoKeyVersion`, initially `PENDING_GENERATION`
until key material generation finishes (server auto-transitions it to
`ENABLED`, or to `GENERATION_FAILED` with `generationFailureReason` set).
IAM: `cloudkms.cryptoKeyVersions.create`.

### 6.2 `cryptoKeyVersions.get` / `.list`

`GET /v1/{name=.../cryptoKeyVersions/*}` → `CryptoKeyVersion`.
`GET /v1/{parent=.../cryptoKeys/*}/cryptoKeyVersions` →
`ListCryptoKeyVersionsResponse { cryptoKeyVersions[], totalSize,
nextPageToken }`, with the same `pageSize`/`pageToken`/`filter`/`orderBy` +
`view` (`CRYPTO_KEY_VERSION_VIEW_UNSPECIFIED` | `FULL`, controlling
`attestation` inclusion) parameters as §5.3. IAM: `cloudkms.cryptoKeyVersions.get` / `.list`.

Full `CryptoKeyVersion` resource:

| Field | Type | Output-only | Notes |
|---|---|---|---|
| `name` | string | Yes | |
| `state` | enum `CryptoKeyVersionState` | **No** | See below — writable via `create`/`patch`. |
| `protectionLevel` | enum `ProtectionLevel` | Yes | |
| `algorithm` | enum `CryptoKeyVersionAlgorithm` | Yes | 48-value enum, §9. |
| `attestation` | `KeyOperationAttestation` | Yes | HSM-only (`protectionLevel = HSM`); absent otherwise. |
| `createTime`, `generateTime`, `destroyTime`, `destroyEventTime`, `importTime` | timestamp | Yes | Present/absent per state. |
| `importJob` | string | Yes | Set only if this version's material was imported. |
| `importFailureReason`, `generationFailureReason`, `externalDestructionFailureReason` | string | Yes | Set only in the matching failure state. |
| `externalProtectionLevelOptions` | object | **No** | `externalKeyUri`, `ekmConnectionKeyPath`, `ekmConnectionBackendOverride` — configuration, not just reporting, for `EXTERNAL`/`EXTERNAL_VPC`. |
| `reimportEligible` | bool | Yes | Whether a `DESTROYED` version can be brought back by reimporting the same key material. |
| `trustedWrappingEnabled` | bool | **No**, immutable | `HSM_SINGLE_TENANT` only; every purpose except `ENCRYPT_DECRYPT`; settable only at creation/import time. |
| `hsmTrusted` | bool | Yes | `AES_256_WRAPPING` purpose + `HSM_SINGLE_TENANT` only. |

`CryptoKeyVersionState` (11 values): `CRYPTO_KEY_VERSION_STATE_UNSPECIFIED`,
`PENDING_GENERATION`, `ENABLED`, `DISABLED`, `DESTROYED`,
`DESTROY_SCHEDULED`, `PENDING_IMPORT`, `IMPORT_FAILED`, `GENERATION_FAILED`,
`PENDING_EXTERNAL_DESTRUCTION`, `EXTERNAL_DESTRUCTION_FAILED`. Only
`ENABLED` versions can be used for crypto operations; every other state
either can't be acted on yet (`PENDING_*`) or is terminal/needs a lifecycle
call (`disable`/`enable` via `patch`, `destroy`, `restore`).

### 6.3 `cryptoKeyVersions.patch`

`PATCH /v1/{name=.../cryptoKeyVersions/*}` + required `updateMask` — the
mechanism for `ENABLED ⇄ DISABLED` toggling (there is no dedicated
`enable`/`disable` RPC; it's a `patch` on `state`). IAM:
`cloudkms.cryptoKeyVersions.update`.

### 6.4 `cryptoKeyVersions.updatePrimaryVersion`

Does **not exist on CryptoKeyVersion** — the task's method list groups it
there, but it's a `CryptoKey`-level method (§5.5): you tell the *CryptoKey*
which of its child versions to promote, you don't call anything on the
version itself.

### 6.5 `cryptoKeyVersions.destroy`

`POST /v1/{name}:destroy`, empty request body
(`DestroyCryptoKeyVersionRequest {}`). Effect: `state` → `DESTROY_SCHEDULED`,
`destroyTime` = now + `CryptoKey.destroyScheduledDuration` (default 30
days). At `destroyTime`, GCP automatically flips it to `DESTROYED` and the
key material is irrecoverably deleted server-side — "no longer stored."
Reversible up until that point via `restore`. Response: the updated
`CryptoKeyVersion`. IAM: `cloudkms.cryptoKeyVersions.destroy`.

### 6.6 `cryptoKeyVersions.restore`

`POST /v1/{name}:restore`, empty body (`RestoreCryptoKeyVersionRequest {}`).
Only succeeds while `state = DESTROY_SCHEDULED`; on success, `state` →
`DISABLED` (not back to `ENABLED` — you still need a `patch` to re-enable
it) and `destroyTime` is cleared. `FAILED_PRECONDITION` if called outside
that window (key material is already gone once `DESTROYED`, and `restore`
cannot bring back destroyed material — only re-`import`ing the same key
bytes into a `reimportEligible` version can, which is a materially different
recovery path). IAM: `cloudkms.cryptoKeyVersions.restore`.

### 6.7 `cryptoKeyVersions.rawEncrypt` / `rawDecrypt`

The portable/interoperable-crypto counterpart to §5.6, for
`RAW_ENCRYPT_DECRYPT`-purpose keys — designed so the raw AES-GCM/CBC/CTR
ciphertext produced can be decrypted by a non-GCP AES implementation (unlike
`Encrypt`'s opaque, GCP-internal ciphertext envelope format).

**`RawEncryptRequest`**

| Field | Type | Required | Notes |
|---|---|---|---|
| `plaintext` | bytes | **Yes** | Size budget same wording as §3 (SOFTWARE ≤64 KiB / HSM combined ≤8 KiB with AAD; EXTERNAL/EXTERNAL_VPC not mentioned in this method's docs) |
| `additionalAuthenticatedData` | bytes | No | "may only be used in conjunction with an algorithm that accepts additional authenticated data (for example, AES-GCM)" — i.e. meaningless/rejected for AES-CBC/CTR keys |
| `initializationVector` | bytes | No | "If it is not provided for AES-CBC and AES-CTR, one will be generated." Implies AES-GCM's IV is *always* server-generated, never caller-suppliable — asymmetric from CBC/CTR. |
| `plaintextCrc32c`, `additionalAuthenticatedDataCrc32c`, `initializationVectorCrc32c` | int64 | No | §2.1 pattern, now three checksummed fields instead of two. |

**`RawEncryptResponse`**: `ciphertext` (bytes — "In the case of AES-GCM, the
authentication tag is the tag_length bytes at the end of this field," i.e.
tag is concatenated onto ciphertext, not returned separately), `name`,
`initializationVector` (bytes — server-generated IV, must be stored by the
caller for decryption), `tagLength` (int32), `protectionLevel`, plus the
full checksum/verified-checksum set for all three fields.

**`RawDecryptRequest`**: `ciphertext` (**required**), `initializationVector`
(**required** — "must match the data originally provided in
RawEncryptResponse.initialization_vector"), `additionalAuthenticatedData`
(optional, must match), `tagLength` (int32, optional — "If unspecified (0),
the default value for the key's algorithm will be used (for AES-GCM, the
default value is 16)"), plus three `*Crc32c` fields.

**`RawDecryptResponse`**: `plaintext`, `plaintextCrc32c`, `protectionLevel`,
plus `verified*Crc32c` booleans for ciphertext/IV/AAD.

IAM: `cloudkms.cryptoKeyVersions.rawEncrypt` / `.rawDecrypt` — **distinct
permissions** from `cloudkms.cryptoKeys.encrypt`/`.decrypt`, so raw and
regular crypto access can be granted independently even where both purposes
theoretically coexist in the same project.

### 6.8 `cryptoKeyVersions.asymmetricSign` / `asymmetricDecrypt`

**`AsymmetricSignRequest`**: exactly one of `data` (bytes) or `digest`
(`Digest` message — one of `sha256`/`sha384`/`sha512`/`externalMu`, all
bytes) is supplied, never both — "It can't be supplied if
AsymmetricSignRequest.digest is supplied." The digest "must be produced with
the same digest algorithm as specified by the key version's algorithm."
`data` is required instead of `digest` for the `RSA_SIGN_RAW_PKCS1_*`
algorithms and for signing with a Cloud EKM key — GCP hashes `data`
internally when a digest-based algorithm is used, but raw/EKM algorithms
need the unhashed bytes. Per the create-validate-signatures doc: for
`RSA_SIGN_RAW_PKCS1_*`, "the data has a length limit of 11 bytes fewer than
the RSA key size" (e.g. 2048-bit RSA → max 245 bytes of `data`). Plus
`dataCrc32c`/`digestCrc32c`.

**`AsymmetricSignResponse`**: `signature` (bytes), `name`,
`protectionLevel`, `signatureCrc32c`, `verifiedDataCrc32c`,
`verifiedDigestCrc32c`.

**`AsymmetricDecryptRequest`**: `ciphertext` (**required** — "The data
encrypted with the named CryptoKeyVersion's public key using OAEP"),
`ciphertextCrc32c`.

**`AsymmetricDecryptResponse`**: `plaintext`, `plaintextCrc32c`,
`protectionLevel`, `verifiedCiphertextCrc32c`.

IAM: `cloudkms.cryptoKeyVersions.useToSign` /
`cloudkms.cryptoKeyVersions.useToDecrypt` — yet another distinct permission
naming pattern (`useTo*` rather than the operation-named
`encrypt`/`rawEncrypt` style), worth flagging since a trait that maps
"operation → permission string 1:1 by pattern" breaks here.

### 6.9 `cryptoKeyVersions.macSign` / `macVerify`

**`MacSignRequest`**: `data` (bytes, **required**) + `dataCrc32c`. No
documented size ceiling distinct from the general per-request payload limit
— no combined-budget language like §3 applies here (MAC has no AAD
concept).

**`MacSignResponse`**: `mac` (bytes), `name`, `protectionLevel`,
`macCrc32c`, `verifiedDataCrc32c`.

**`MacVerifyRequest`**: `data` (**required**), `mac` (**required** — "The
signature to verify"), `dataCrc32c`, `macCrc32c`.

**`MacVerifyResponse`**: **`success`** (bool) — this is the interesting
shape deviation: verification failure is a normal `200 OK` response with
`success: false`, not an error. There's also
**`verifiedSuccessIntegrity`** (bool) — a second-order integrity check *on
the success flag itself*: "If the value of this field contradicts the value
of [MacVerifyResponse.success], discard the response and perform a limited
number of retries," i.e. even the boolean verdict has its own
tamper-detection field layered on top, guarding against a
corrupted-in-transit `true` masquerading as a verified failure or vice
versa.

IAM: `cloudkms.cryptoKeyVersions.useToSign` /
`cloudkms.cryptoKeyVersions.useToVerify`.

### 6.10 `cryptoKeyVersions.getPublicKey`

`GET /v1/{name=.../cryptoKeyVersions/*}/publicKey` — the one crypto
operation shaped like a plain resource `get`, not a `:verb` RPC. Query
param `publicKeyFormat` (enum `PUBLIC_KEY_FORMAT_UNSPECIFIED` | `PEM` | `DER`
| `NIST_PQC` | `XWING_RAW_BYTES`) — "required for PQC algorithms"; for
non-PQC algorithms, omitting it defaults to PEM, but "an error will be
returned" for PQC algorithms if omitted.

`PublicKey` response: `pem` (string), `publicKey` (`ChecksummedData { data:
bytes, crc32cChecksum: int64 }` — the format-appropriate encoding),
`pemCrc32c` (int64, "NOTE: This field is in Beta"), `name`,
`publicKeyFormat`, `algorithm`, `protectionLevel`. Note `pem` and
`publicKey.data` are two separate fields carrying overlapping information in
different encodings/checksums — another place a trait mapping "one response,
one payload field" doesn't quite fit.

Only valid for `ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`, and
`KEY_ENCAPSULATION` purpose keys (the ones with a public half at all). IAM:
`cloudkms.cryptoKeyVersions.viewPublicKey`.

### 6.11 `cryptoKeyVersions.import` (ImportCryptoKeyVersion)

`POST /v1/{parent=.../cryptoKeys/*}/cryptoKeyVersions:import` — this is the
method the task calls "`cryptoKeys.import`," but it lives on
`cryptoKeyVersions`, not `cryptoKeys`, and there is no `cryptoKeys.import`
method at all.

**`ImportCryptoKeyVersionRequest`**:

| Field | Type | Required | Notes |
|---|---|---|---|
| `importJob` | string | **Yes** | Name of a previously-created, still-`ACTIVE` ImportJob whose wrapping key was used. |
| `wrappedKey` | bytes | One-of with `rsaAesWrappedKey` | The actual wrapped key material; format depends on the ImportJob's `importMethod` (§6.12). |
| `rsaAesWrappedKey` | bytes | (deprecated alias) | "This field has the same meaning as wrapped_key. Prefer to use that field in new work." |
| `algorithm` | enum | **Yes** | "does not need to match the version_template of the CryptoKey this version imports into" — the imported version's algorithm is declared per-import, independent of the parent CryptoKey's template default. |
| `cryptoKeyVersion` | string | Optional | Name of an *existing* version to re-import into, rather than creating a new one — but only legal if that version is currently `DESTROYED` or `IMPORT_FAILED` **and** was itself created via a prior `ImportCryptoKeyVersion` call, and "the key material and algorithm must match the previous CryptoKeyVersion exactly if the CryptoKeyVersion has ever contained key material." |
| `trustedWrappingEnabled` | bool | Optional | `HSM_SINGLE_TENANT` + non-`ENCRYPT_DECRYPT` only. |

This is a genuinely dual-purpose method — it's simultaneously "create a new
CryptoKeyVersion" (the common case) *and* "overwrite/reactivate a specific
existing destroyed version" (the `cryptoKeyVersion` field case), selected by
whether that one optional field is set. It doesn't decompose cleanly into
separate create/update trait methods without either duplicating this
either/or logic or picking one behavior and dropping the other.

Response: the created/updated `CryptoKeyVersion` (state `PENDING_IMPORT` →
`ENABLED`, or `IMPORT_FAILED` with `importFailureReason` set). IAM:
`cloudkms.cryptoKeyVersions.create` (per the `parent` field's doc note:
"The create permission is only required on this key when creating a new
CryptoKeyVersion" — i.e. re-importing into an existing destroyed version
needs a *different*, unspecified-in-the-discovery-doc permission set, not
`create`).

### 6.12 ImportJob (create/get/list) — the wrapping-key handshake `import` depends on

`POST /v1/{parent=.../keyRings/*}/importJobs?importJobId=...` — same
`[a-zA-Z0-9_-]{1,63}` id pattern as KeyRing/CryptoKey. Request body sets two
required, immutable fields: `importMethod` (enum, 9 values — `RSA_OAEP_*`
variants at 3072/4096-bit with SHA-1 or SHA-256, three variants, plus
`HPKE_KEM_ML_KEM_768`/`_1024`/`XWING`-based post-quantum-safe wrapping added
more recently) and `protectionLevel` ("must match the protection_level of
the version_template on the CryptoKey you attempt to import into").

Lifecycle: `state` starts `PENDING_GENERATION` while GCP generates the
wrapping keypair server-side, auto-transitions to `ACTIVE` (`publicKey`
becomes available — a `WrappingPublicKey { pem, data: bytes }`), and expires
to `EXPIRED` **3 days after creation**, non-reversibly — "Once expired,
Cloud KMS will no longer be able to import or unwrap any key material that
was wrapped with the ImportJob's public key." Any `import` call referencing
an expired job fails.

`importJobs.get` supports the same `publicKeyFormat` query override as
`getPublicKey`. `importJobs.list` is the standard
paginated-list-with-filter/orderBy shape.
`importJobs.{get,set}IamPolicy`/`testIamPermissions` exist too, same shape
as §4.4, since ImportJob is IAM-securable like KeyRing/CryptoKey.

IAM: `cloudkms.importJobs.create` / `.get` / `.list`.

---

## 7. `generateRandomBytes`

`POST /v1/{location=projects/*/locations/*}:generateRandomBytes` — note this
hangs off **Location**, not KeyRing or CryptoKey; it's not scoped to any
particular key at all, just a project+region.

`GenerateRandomBytesRequest`: `lengthBytes` (int32, **"Minimum 8 bytes,
maximum 1024 bytes"**), `protectionLevel` (enum — **"Currently, only HSM
protection level is supported"**; `SOFTWARE`/`EXTERNAL`/etc. all
presumably reject with an error, though the discovery doc doesn't name the
specific code).

`GenerateRandomBytesResponse`: `data` (bytes), `dataCrc32c` (§2.1 pattern —
request-side has no matching field to verify since there's no input payload
to checksum, only the output).

IAM: needs the location-level `cloudkms.cryptoKeyVersions.viewCryptoKeyVersion`-adjacent... actually the discovery document does not list a distinct IAM permission constant for this method beyond the two universal OAuth scopes; Cloud KMS's IAM reference documents it under
`cloudkms.locations.generateRandomBytes` (mentioned in the [permissions
reference](https://cloud.google.com/kms/docs/reference/permissions-and-roles),
not in the discovery doc itself — flagged here as coming from a different
source than the rest of this table).

Notable for trait design: this is the **only** method in the entire surface
that isn't scoped to a specific key or key ring at all, and its
protection-level parameter isn't "which of my keys' protection levels" but
"which HSM boundary should generate this randomness" — a capability trait
modeling "operations on a key" won't have a natural home for it without a
separate "backend-level" or "location-level" capability.

---

## 8. Out of scope, but real — the rest of GCP KMS's `v1` surface

The discovery document's full schema/resource list is far larger than the
task's requested method set. Whether the generalized traits should reach
further than the requested list is exactly the open question this doc was
commissioned to inform, so it's worth naming what else exists rather than
silently dropping it:

- **`cryptoKeyVersions.encapsulate` / `.decapsulate`** — post-quantum key
  encapsulation (`KEY_ENCAPSULATION` purpose, `ML_KEM_768`/`1024`,
  `KEM_XWING`, `KEM_ECDH_P256`/`P384` algorithms). Structurally adjacent to
  `asymmetricSign`/`asymmetricDecrypt` (same per-version addressing, same
  CRC32C pattern) but a distinct operation family entirely absent from the
  task's list.
- **`cryptoKeyVersions.exportTrustedKeyWrappedCryptoKeyVersion` /
  `.importTrustedKeyWrappedCryptoKeyVersion`** — a second, distinct
  import/export path specific to `HSM_SINGLE_TENANT`'s "trusted wrapping"
  feature, separate from the ImportJob-based flow in §6.11-6.12.
- **Autokey** (`folders.locations.autokeyConfig`,
  `projects.locations.keyHandles`) — a higher-level provisioning layer
  where GCP auto-creates KeyRings/CryptoKeys on demand per-resource rather
  than the caller managing them explicitly.
- **EkmConnection / EkmConfig** (`projects.locations.ekmConnections`,
  `.ekmConfig`) — the actual configuration resources behind
  `EXTERNAL`/`EXTERNAL_VPC` protection levels; this doc's CryptoKey/Version
  sections reference `cryptoKeyBackend` and `externalProtectionLevelOptions`
  as fields but never document how an EkmConnection itself gets set up.
- **SingleTenantHsmInstance + quorum-approval workflow**
  (`singleTenantHsmInstances`, `singleTenantHsmInstanceProposals`,
  `ExecuteSingleTenantHsmInstanceProposal`,
  `ApproveSingleTenantHsmInstanceProposal`) — dedicated-HSM lifecycle
  management gated behind a multi-party quorum-approval protocol
  (`QuorumAuth`, `RequiredActionQuorumParameters`, `Challenge`/
  `ChallengeReply`) with no analog anywhere else in this doc or in any of
  the other three vendors surveyed in the original CIP-3965 doc.
- **KeyAccessJustificationsPolicy / `KeyAccessJustificationsEnrollmentConfig`**
  — Assured Workloads-specific access-justification enforcement, touched on
  in §5.1 only as a `CryptoKey` field, not explored as its own capability
  surface here.
- **`RetiredResources`** — a listing of CryptoKeys that have been fully
  deleted (all versions destroyed) but whose metadata GCP retains for
  audit/billing history.

None of these were in the task's requested method list, and none are
covered above beyond this paragraph — flagged here purely so the "should
the trait cover more of GCP's surface" question in the CIP has an honest
inventory of what "more" could mean.

---

## 9. `CryptoKeyVersionAlgorithm` — full enum (48 values)

Shared verbatim across `CryptoKeyVersion.algorithm`,
`CryptoKeyVersionTemplate.algorithm`, `PublicKey.algorithm`, and
`ImportCryptoKeyVersionRequest.algorithm` — one enum, reused everywhere an
algorithm choice appears:

**Symmetric (7):** `GOOGLE_SYMMETRIC_ENCRYPTION`, `AES_128_GCM`,
`AES_256_GCM`, `AES_128_CBC`, `AES_256_CBC`, `AES_128_CTR`, `AES_256_CTR`.

**RSA signing (11):** `RSA_SIGN_PSS_2048_SHA256`, `RSA_SIGN_PSS_3072_SHA256`,
`RSA_SIGN_PSS_4096_SHA256`, `RSA_SIGN_PSS_4096_SHA512`,
`RSA_SIGN_PKCS1_2048_SHA256`, `RSA_SIGN_PKCS1_3072_SHA256`,
`RSA_SIGN_PKCS1_4096_SHA256`, `RSA_SIGN_PKCS1_4096_SHA512`,
`RSA_SIGN_RAW_PKCS1_2048`, `RSA_SIGN_RAW_PKCS1_3072`,
`RSA_SIGN_RAW_PKCS1_4096`.

**RSA decryption/OAEP (7):** `RSA_DECRYPT_OAEP_2048_SHA256`,
`RSA_DECRYPT_OAEP_3072_SHA256`, `RSA_DECRYPT_OAEP_4096_SHA256`,
`RSA_DECRYPT_OAEP_4096_SHA512`, `RSA_DECRYPT_OAEP_2048_SHA1`,
`RSA_DECRYPT_OAEP_3072_SHA1`, `RSA_DECRYPT_OAEP_4096_SHA1`.

**EC signing (4):** `EC_SIGN_P256_SHA256`, `EC_SIGN_P384_SHA384`,
`EC_SIGN_SECP256K1_SHA256` ("only supported for HSM protection level"),
`EC_SIGN_ED25519`.

**HMAC/MAC (5):** `HMAC_SHA256`, `HMAC_SHA1`, `HMAC_SHA384`, `HMAC_SHA512`,
`HMAC_SHA224`.

**External:** `EXTERNAL_SYMMETRIC_ENCRYPTION`.

**Post-quantum KEM (3):** `ML_KEM_768`, `ML_KEM_1024`, `KEM_XWING`.

**Post-quantum signatures (8):** `PQ_SIGN_ML_DSA_44`, `PQ_SIGN_ML_DSA_65`,
`PQ_SIGN_ML_DSA_87`, `PQ_SIGN_SLH_DSA_SHA2_128S`,
`PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256`, `PQ_SIGN_ML_DSA_44_EXTERNAL_MU`,
`PQ_SIGN_ML_DSA_65_EXTERNAL_MU`, `PQ_SIGN_ML_DSA_87_EXTERNAL_MU`.

**Classical ECDH KEM (2):** `KEM_ECDH_P256`, `KEM_ECDH_P384`.

**AES wrapping (1):** `AES_256_KWP` — "Can only be used by keys with
purpose AES_WRAPPING."

Plus `CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED`. GCP's algorithm list is
substantially larger and more actively growing (three separate NIST PQC
families already shipped) than any of AWS/Azure/Vault's equivalents covered
in the original survey — a trait-level `Algorithm` enum modeled after GCP's
would need real headroom for vendor-specific growth, not a fixed closed set.

---

## 10. Notes for Rust capability-trait design

1. **Two-tier "which version" model (§2.3)** is the single most
   trait-shape-relevant finding: `Encrypt` accepts either a key or a
   specific version as the target and `Decrypt` never accepts a version at
   all, while every non-`ENCRYPT_DECRYPT` operation *requires* an exact
   version. A trait that models "an encrypt/decrypt capability" uniformly
   across purposes will paper over a real difference in whether the caller
   or the ciphertext determines which key material gets used.
2. **CRC32C end-to-end integrity checking (§2.1)** is optional but pervasive
   and uniform — present on literally every payload field of every crypto
   RPC. If the traits want to expose it, it's naturally a cross-cutting
   concern (a wrapper/middleware over any GCP call), not a per-method
   parameter, since the pattern and its retry semantics are identical
   everywhere it appears.
3. **`MacVerify`'s success-as-data, not success-as-error (§6.9)** is a shape
   a generic `verify() -> Result<(), Error>` trait method would flatten
   incorrectly unless deliberately designed around — GCP treats "verified
   and it failed" as a normal response, with its own nested integrity flag
   on the verdict itself.
4. **IAM permission naming isn't a uniform function of the operation name
   (§6.8's `useToSign`/`useToDecrypt` vs. the `encrypt`/`rawEncrypt`
   pattern elsewhere)** — anything that tries to derive "what to check
   before calling X" from the method name mechanically will need a lookup
   table, not a naming convention.
5. **`ImportCryptoKeyVersion`'s dual create-or-reimport behavior (§6.11)**
   doesn't decompose into separate `create`/`update` trait calls without
   either duplicating GCP's conditional logic client-side or picking one
   path and dropping the other.
6. **The 8 KiB combined HSM budget (§3) is a hard, silent trap for anyone
   porting AWS-shaped code**, where plaintext and context/AAD are
   independently capped — a generalized "encrypt with AAD" trait method
   needs its size-validation logic to know which vendor it's talking to,
   or it needs to expose the budget as vendor-queryable metadata rather
   than a trait-wide constant.
7. **`generateRandomBytes` (§7) doesn't belong to any key-scoped capability**
   at all — it's the only method addressed at the location level, which
   argues for a distinct, key-independent trait rather than trying to
   attach it to whatever trait owns per-key crypto operations.
8. GCP's real `v1` surface (§8) is roughly 4-5x larger than the method list
   this doc was asked to cover, almost entirely in directions (Autokey,
   EKM connection management, single-tenant HSM quorum approval, KEM
   encapsulate/decapsulate) that have no equivalent in any of AWS/Azure/
   Vault as surveyed in the original CIP-3965 doc — none of it is a compatibility
   target for a cross-vendor trait, but the KEM operations in particular
   sit close enough to the requested `asymmetricSign`/`asymmetricDecrypt`
   shape that a trait boundary drawn too tightly around today's requested
   method list may need revisiting once post-quantum KEM support becomes a
   real requirement.

---

## Sources

- [Cloud KMS `v1` Discovery Document](https://cloudkms.googleapis.com/$discovery/rest?version=v1) — primary source for every field, enum, parameter, and IAM-scope table in this doc.
- [`projects.locations.keyRings.create`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings/create)
- [`projects.locations.keyRings.cryptoKeys.create`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/create)
- [`projects.locations.keyRings.cryptoKeys.patch`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/patch)
- [`projects.locations.keyRings.cryptoKeys.updatePrimaryVersion`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/updatePrimaryVersion)
- [`projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.create`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/create)
- [`projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.destroy`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/destroy)
- [`projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.restore`](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/restore)
- [`projects.locations.keyRings.cryptoKeys.cryptoKeyVersions` (resource reference)](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions)
- [`projects.locations.keyRings.cryptoKeys.encrypt`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/encrypt) (referenced in the earlier CIP-3965 survey)
- [`projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.asymmetricSign`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
- [Creating and validating digital signatures](https://docs.cloud.google.com/kms/docs/create-validate-signatures) — RSA raw-signing byte-length formula, EC hash-algorithm flexibility.
- [Verifying attestations](https://docs.cloud.google.com/kms/docs/attest-key) — `KeyOperationAttestation`/`CertificateChains` semantics.
- [Cloud KMS quotas](https://docs.cloud.google.com/kms/quotas) — current and post-Feb-2026 quota structure (§7 IAM-permission caveat aside, quota figures directly from this page).
- [Cloud KMS data integrity guidelines](https://cloud.google.com/kms/docs/data-integrity-guidelines) — CRC32C checksum protocol (§2.1), corroborating the discovery doc's per-field descriptions.
- [Google API error model / AIP-193](https://google.aip.dev/193) — `google.rpc.Status`/`Code` → HTTP mapping (§2.4).
- [`cip-3965-backend-api-survey.md`](./cip-3965-backend-api-survey.md) — prior, narrower cross-vendor survey this doc supersedes for GCP specifically.

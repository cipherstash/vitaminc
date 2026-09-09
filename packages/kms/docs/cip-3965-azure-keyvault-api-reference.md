# CIP-3965 Azure Key Vault Keys API reference

This is a comprehensive reference for Azure Key Vault's (and, where it differs,
Managed HSM's) **Keys** data-plane REST API, produced to inform whether the
Rust capability traits under design for `vitaminc-kms` (CIP-3965/CIP-3985)
should cover more of Azure's surface than the narrow `wrapKey`/`unwrapKey`
subset captured in
[`cip-3965-backend-api-survey.md`](./cip-3965-backend-api-survey.md). That
earlier doc covers 4 operations across all four target vendors combined; this
one covers 22 Azure Key Vault Keys operations in full, one section each.

All operations share:

- **Base URL / auth.** `{vaultBaseUrl}/keys/...` (a plain multi-tenant vault)
  or `{hsmBaseUrl}/keys/...` (Managed HSM — same paths, same request/response
  shapes, different host). Every call requires a Microsoft Entra ID (Azure
  AD) OAuth2 bearer token, scope `https://vault.azure.net/.default`, sent as
  `Authorization: Bearer <token>`. There is no key-based or SAS auth for the
  data plane.
- **API versioning.** The classic version scheme was `7.x` (this org's
  earlier survey cited `7.4`); Microsoft has since moved to date-based
  versions (current: `2025-07-01`). Both schemes are live and the request/
  response shapes referenced below are stable across the two for the Keys
  operations — differences noted inline where they exist (e.g. `hsmPlatform`,
  `KeyAttestation` are newer additions).
- **Generic error envelope.** Every operation's non-2xx response is a
  `KeyVaultError` — `{ "error": { "code": string, "message": string,
  "innererror"?: Error } }`, where `Error` recurses (`code`, `message`,
  `innererror`). **There is no officially published closed enum of `code`
  string values** in the per-operation REST references — unlike AWS KMS's
  named exception types (e.g. `InvalidCiphertextException`), Azure's `code`
  is effectively free-form/implementation-defined. What *is* documented,
  separately from the operation references, is the HTTP-status-level
  contract (see "Cross-cutting error behaviour" below).
- **Permissions.** Each operation requires a specific RBAC data action or
  legacy access-policy permission (e.g. `keys/create`, `keys/wrapKey`,
  `keys/release`), enumerated per operation below.

## Key type / algorithm support matrix

| Key type | Encrypt/Decrypt, Wrap/Unwrap | Sign/Verify | Where supported |
|---|---|---|---|
| RSA, RSA-HSM (2048/3072/4096-bit) | `RSA-OAEP-256`, `RSA-OAEP`\*, `RSA1_5`\* | `PS256/384/512`, `RS256/384/512`, `RSNULL` | Standard Key Vault, Premium, Managed HSM |
| EC, EC-HSM (P-256, P-256K, P-384, P-521) | **Not supported at all** (`NA`) | `ES256`, `ES256K`, `ES384`, `ES512` (curve-locked: P-256→ES256, P-256K→ES256K, P-384→ES384, P-521→ES512) | Standard Key Vault, Premium, Managed HSM |
| oct-HSM (symmetric, 128/192/256-bit) | `AES-KW`, `AES-GCM`, `AES-CBC` | `HS256/384/512` (HMAC) | **Managed HSM** (production); **Key Vault Premium only, and there only in public preview** — "not recommended for production workloads," no SLA. Not available in Standard Key Vault at all. |

\* Not recommended by Microsoft; retained for backward compatibility only.

This is a significant finding relative to the earlier narrow survey: **EC
keys cannot be used for `encrypt`/`decrypt`/`wrapKey`/`unwrapKey` at all** —
Key Vault has no ECIES equivalent — so a generalized trait that assumes any
key can be handed to an "encrypt" capability will fail for EC keys
specifically, not just behave differently. Symmetric (`oct`/`oct-HSM`)
support is HSM-and-tier-gated in a way that has no analog in the other three
vendors surveyed: it's simply absent from Standard Key Vault, preview-only in
Premium, and only production-ready on Managed HSM.

The full `JsonWebKeyType` enum (`kty`): `EC`, `EC-HSM`, `RSA`, `RSA-HSM`,
`oct`, `oct-HSM`. `JsonWebKeyCurveName` (`crv`): `P-256`, `P-384`, `P-521`,
`P-256K`.

`JsonWebKeyOperation` (the `key_ops` values a key can be restricted to):
`encrypt`, `decrypt`, `sign`, `verify`, `wrapKey`, `unwrapKey`, `import`,
`export`.

**There is no `export` operation.** Despite `export` appearing as a
`JsonWebKeyOperation` enum value, the service "doesn't support EXPORT
operations. Once a key is provisioned, you can't extract it or modify its key
material." The only way to move key material out of the service is
`backup`/`restore` (still opaque/service-protected, see below) or, for
attested confidential-compute scenarios, `release` (also below, and gated by
the `exportable` attribute + a `release_policy`, not the `export` key_ops
flag).

## Common types referenced throughout

**`JsonWebKey`** (the public/private key material container, used in
`create`/`import`/`get`/etc. responses): `kid`, `kty`, `key_ops[]`, and
type-specific fields — RSA: `n`, `e`, and (only ever present on *input* to
`importKey`, never returned) `d`, `dp`, `dq`, `p`, `q`, `qi`; EC: `crv`, `x`,
`y`, (`d` on import only); symmetric: `k` (on import only); plus `key_hsm`
(base64url, "Protected Key, used with 'Bring Your Own Key'"). All byte
fields are base64url. **`getKey` never returns private/symmetric material**
— `d`/`p`/`q`/etc./`k` are write-only on import and are not echoed back, nor
returned by `get`, ever.

**`KeyAttributes`**: `enabled` (bool), `nbf`/`exp` (unix time, optional),
`created`/`updated` (unix time, read-only), `recoveryLevel`
(`DeletionRecoveryLevel`, read-only), `recoverableDays` (int, 7–90 when
soft-delete enabled else 0), `exportable` (bool — gates `release`),
`hsmPlatform` (string; `"2"` = FIPS 140-3 L3 latest HSM, `"1"` = FIPS 140-2
L2 previous HSM, `"0"` = FIPS 140-2 L1 software), `attestation`
(`KeyAttestation`: `certificatePemFile`, `privateKeyAttestation`,
`publicKeyAttestation`, `version` — all base64url, HSM-key-generation
attestation evidence).

**`DeletionRecoveryLevel`** (soft-delete/purge-protection state, read-only,
returned on every key): `Purgeable`, `Recoverable+Purgeable`, `Recoverable`,
`Recoverable+ProtectedSubscription`, `CustomizedRecoverable+Purgeable`,
`CustomizedRecoverable`, `CustomizedRecoverable+ProtectedSubscription`.

**`KeyReleasePolicy`**: `contentType` (string, defaults to `application/json;
charset=utf-8`), `data` (base64url blob encoding the actual policy rules —
opaque to the REST schema itself), `immutable` (bool — one-way flag; once
set, the policy can never be changed again "under any circumstances").
"Release policy must be provided when creating the first version of an
exportable key."

**Not-yet-valid / expired key behaviour.** A key outside its `nbf`/`exp`
window is blocked from *most* operations (403), but **`decrypt`, `release`,
`unwrap`, and `verify` remain permitted regardless of `nbf`/`exp`** — the
documented rationale is recovering old data / testing new keys before
production cut-over. This is a real asymmetry a Rust trait's operation set
needs to be aware of: "is this key usable right now" is not one boolean, it
depends on which of the ~8 crypto/management operations you're asking about.

---

## `createKey`

`POST {vaultBaseUrl}/keys/{key-name}/create?api-version=...` — permission
`keys/create`.

**Path params:** `key-name` (string, pattern `^[0-9a-zA-Z-]+$`, required),
`vaultBaseUrl` (required). **Query:** `api-version` (required).

**Request body (`KeyCreateParameters`):**

| Field | Required | Type | Notes |
|---|---|---|---|
| `kty` | **Yes** | `JsonWebKeyType` | |
| `crv` | No | `JsonWebKeyCurveName` | EC only |
| `key_ops` | No | `JsonWebKeyOperation[]` | restricts what the key may later be used for |
| `key_size` | No | int32 | RSA: 2048/3072/4096 |
| `public_exponent` | No | int32 | RSA only |
| `attributes` | No | `KeyAttributes` | must still send `"attributes": {}` even if empty — the field itself isn't optional to omit in practice per the docs' example |
| `release_policy` | No | `KeyReleasePolicy` | required on first version if the key is `exportable` |
| `tags` | No | object (string→string) | up to 15 tags, 256 chars each (name and value) |

**Response `200 OK` → `KeyBundle`:** `key` (`JsonWebKey`, public parts only),
`attributes`, `managed` (bool — true if lifecycle-owned by another service,
e.g. backing a certificate), `release_policy`, `tags`.

**Errors:** generic `KeyVaultError` on any non-200 (see cross-cutting
section). If the named key already exists, `createKey` **creates a new
version** rather than erroring — this is an upsert-into-new-version
semantic, not a create-or-fail one.

---

## `importKey`

`PUT {vaultBaseUrl}/keys/{key-name}?api-version=...` — permission
`keys/import`.

**Request body (`KeyImportParameters`):**

| Field | Required | Type | Notes |
|---|---|---|---|
| `key` | **Yes** | `JsonWebKey` | full material, including private components (`d`, `p`, `q`, `dp`, `dq`, `qi` for RSA; `d` for EC; `k` for symmetric) |
| `Hsm` | No | bool | import as HSM-protected vs software key |
| `attributes` | No | `KeyAttributes` | |
| `release_policy` | No | `KeyReleasePolicy` | |
| `tags` | No | object | |

**Response / errors:** identical shape to `createKey` (`KeyBundle` /
`KeyVaultError`). Same upsert-new-version-if-exists semantics as `createKey`.

Note the field-name inconsistency baked into the wire schema: `Hsm` is
capitalized while every other top-level field (`attributes`, `key`,
`release_policy`, `tags`) is lowercase — worth knowing if hand-rolling
(de)serialization rather than trusting a generated client.

---

## `getKey`

`GET {vaultBaseUrl}/keys/{key-name}/{key-version}?api-version=...` —
permission `keys/get`.

`key-version` is a **required path segment**, but "This URI fragment is
optional. If not specified, the latest version of the key is returned" — in
practice this means callers hit `.../keys/{key-name}/` (trailing empty
segment) to mean "latest," not that the parameter is truly absent from the
URL. Returns `KeyBundle`. "If the requested key is symmetric, no key material
is released in the response" — `getKey` **never** returns private/symmetric
bytes for any key type, only public parts (RSA `n`/`e`, EC `x`/`y`/`crv`) or,
for symmetric keys, no key-bearing fields at all beyond `kid`/`kty`/`key_ops`.

---

## `getKeyVersions`

`GET {vaultBaseUrl}/keys/{key-name}/versions?api-version=...&maxresults=...`
— permission `keys/list`.

**Query:** `maxresults` (optional, int32, min 1 / max 25, default page size
25 if omitted).

**Response `KeyListResult`:** `value: KeyItem[]`, `nextLink` (string —
cursor-style pagination; absent when there are no further pages). `KeyItem`
is a **stripped-down** projection: `kid`, `attributes`, `managed`, `tags` —
**no `key` field at all**, i.e. listing versions never returns any key
material, public or private, only metadata + the `kid` (which embeds the
version in its path and can be `getKey`-ed individually).

---

## `getKeys` (list keys in vault)

`GET {vaultBaseUrl}/keys?api-version=...&maxresults=...` — permission
`keys/list`. Same `KeyListResult`/`KeyItem` shape and pagination as
`getKeyVersions`, but listing only the latest version's metadata per
key-name (not every version of every key).

---

## `updateKey`

`PATCH {vaultBaseUrl}/keys/{key-name}/{key-version}?api-version=...` —
permission `keys/update`. **Both `key-name` and `key-version` are required
path segments here (unlike `getKey`, no "latest" shorthand is documented) —
you must target a specific existing version.**

**Request body (`KeyUpdateParameters`)**, all optional: `attributes`,
`key_ops`, `release_policy`, `tags`. **"The cryptographic material of a key
itself cannot be changed"** — this is a metadata-only PATCH; there is no
field in the schema through which key bytes could even be sent.

**Response:** `KeyBundle`. Errors: generic. Key must already exist — this is
the one create/import/update trio operation that does *not* silently create
something new if the target is missing.

---

## `deleteKey`

`DELETE {vaultBaseUrl}/keys/{key-name}?api-version=...` — permission
`keys/delete`. Deletes **the whole key (all versions)** — "cannot be used to
remove individual versions." Immediately makes the key unusable for
sign/verify/wrap/unwrap/encrypt/decrypt (cryptographic material is removed
from active use right away, independent of the soft-delete retention
window).

**Response `200 OK` → `DeletedKeyBundle`:** everything in `KeyBundle` plus
`recoveryId` (URL identifying the deleted-key recovery object),
`deletedDate` (unixtime), `scheduledPurgeDate` (unixtime — retention-window
end). This is the operation that hands back the two extra fields
(`recoveryId`, `scheduledPurgeDate`) needed to drive the soft-delete
lifecycle (`getDeletedKey` / `recoverDeletedKey` / `purgeDeletedKey` below).

---

## `getDeletedKey`

`GET {vaultBaseUrl}/deletedkeys/{key-name}?api-version=...` — permission
`keys/get`. Returns the same `DeletedKeyBundle` as `deleteKey`'s response.
"Applicable for soft-delete enabled vaults... will return an error if
invoked on a non soft-delete enabled vault" — since **soft-delete has been
mandatory for all vaults since 2020**, this error path is now largely
historical, but it's still a documented failure mode of the operation
against very old/legacy vault configurations.

There is also a plural `GET {vaultBaseUrl}/deletedkeys?api-version=...`
(list all deleted keys, same `KeyListResult` pagination shape) — not in this
doc's required-coverage list but worth knowing it exists as the deleted-key
analog of `getKeys`.

---

## `purgeDeletedKey`

`DELETE {vaultBaseUrl}/deletedkeys/{key-name}?api-version=...` — permission
`keys/purge`. **The one operation in the entire Keys API with an empty
success response**: `204 No Content`, no body at all (every other operation
returns a JSON bundle/result object on success). Permanently, irreversibly
destroys the key — no further recovery possible. Same soft-delete-vault
applicability caveat as `getDeletedKey`.

---

## `recoverDeletedKey`

`POST {vaultBaseUrl}/deletedkeys/{key-name}/recover?api-version=...` —
permission `keys/recover`. No request body. "Recovers the deleted key back
to its latest version under `/keys`... consider this the inverse of the
delete operation." Returns `KeyBundle` (not `DeletedKeyBundle` — the
recovery/purge-date fields are gone once recovered, as expected).
"An attempt to recover a non-deleted key will return an error."

---

## `backupKey`

`POST {vaultBaseUrl}/keys/{key-name}/backup?api-version=...` — permission
(despite the URL segment matching `keys/...`) **`key/backup`** — note the
singular `key` in the permission string as documented, inconsistent with
every other permission string in this API which uses plural `keys/...`.

No request body. **Response `BackupKeyResult`:** `{ "value":
"<base64url blob>" }` — a single opaque string, no structure exposed to the
caller at all.

Critical semantic details, quoted directly because they matter for trait
design:

- "This operation does **NOT** return key material in a form that can be
  used outside the Azure Key Vault system" — the blob is meaningless outside
  Key Vault/Managed HSM, encrypted to a vault/HSM-internal protection key,
  not to anything the caller controls.
- "**BACKUP/RESTORE can be performed within geographical boundaries only**;
  a BACKUP from one geographical area cannot be restored to another
  geographical area" (their example: US ↔ EU).
- "**Individual versions of a key cannot be backed up**" — it's always the
  whole key (all versions) or nothing, same granularity restriction as
  `deleteKey`.
- For Managed HSM specifically, a *full-HSM* backup/restore also exists as a
  **separate, distinct API surface** (`PUT
  {hsmBaseUrl}/restore?api-version=...` for a whole-HSM restore, plus
  `securitydomain/download`/`upload` operations) — not the per-key
  `backupKey`/`restoreKey` covered here. That surface backs up/restores an
  entire Managed HSM instance's contents (all keys, versions, attributes,
  tags, role assignments) at once, requires the source and destination HSM
  to share the same **security domain**, is a **long-running operation**
  (returns a job ID immediately, polled separately), and — while in
  progress — puts the whole HSM into a restore mode where "all data plane
  commands except check-restore-status are disabled." This is a materially
  different operation shape (async job + full-instance scope) from anything
  else in the per-key Keys API and would need its own trait-level modelling
  if Managed HSM's full-backup story is ever in scope.

---

## `restoreKey`

`POST {vaultBaseUrl}/keys/restore?api-version=...` — permission
`keys/restore`. **Not scoped to a `key-name` path segment at all** — the
target key name is embedded inside the opaque backup blob itself, not
supplied by the caller.

**Request body (`KeyRestoreParameters`):** `{ "value": "<base64url blob
from backupKey>" }` — the only field, required.

Constraints, quoted: "If the key name is not available in the target Key
Vault, the RESTORE operation will be rejected" (i.e. restoring to a vault
that already has a same-named, still-live key fails — the target namespace
must be clear); "the final key identifier will change if the key is
restored to a different vault" (the `kid` host changes, obviously, but the
key *name* is preserved); "Restore will restore all versions and preserve
version identifiers"; and two explicit security constraints — **the target
vault must be owned by the same Azure subscription as the source vault**,
and the caller needs `restore` permission on the *target*. Response:
`KeyBundle`.

---

## `encrypt`

`POST {vaultBaseUrl}/keys/{key-name}/{key-version}/encrypt?api-version=...`
— permission `keys/encrypt`. Both `key-name` and `key-version` required
(no "latest" shorthand — same as `updateKey`, unlike `getKey`).

"Only supports a single block of data" — no chunking/streaming primitive;
size is bounded by key type + algorithm. "Only strictly necessary for
symmetric keys... supported for asymmetric keys as a convenience for callers
that have a key-reference but no access to the public key material" — i.e.
for RSA keys, `encrypt` is a network round trip doing what the caller could
do locally with the public key; Microsoft's own guidance elsewhere in the
docs is "encrypt operations should be performed locally" for best
performance.

**Request body (`KeyOperationsParameters`) — this is the schema-level fact
that most needs stating precisely for trait design:**

| Field | Required | Type | Notes |
|---|---|---|---|
| `alg` | **Yes** | `JsonWebKeyEncryptionAlgorithm` | |
| `value` | **Yes** | base64url | plaintext to encrypt |
| `aad` | No | base64url | "Additional data to authenticate but not encrypt/decrypt when using authenticated crypto algorithms" |
| `iv` | No | base64url | "Cryptographically random, non-repeating initialization vector for symmetric algorithms" |
| `tag` | No | base64url | "The tag to authenticate when performing decryption with an authenticated algorithm" |

**The wire schema is one flat object with all four optional fields present
regardless of `alg`** — it is *not* a tagged union/discriminated schema per
algorithm. The REST API definition does not itself reject `aad`/`iv`/`tag`
when sent alongside a non-AEAD algorithm like `RSA-OAEP`; the constraint that
these fields are "only meaningful… when using authenticated crypto
algorithms" is stated in prose, not enforced by the schema shape. This
confirms and sharpens the earlier survey's finding: it's algorithm-dependent
*semantically*, but the wire contract gives a Rust client no static
guarantee — a hand-rolled `KeyOperationsParameters` struct with all-optional
fields is actually a faithful transcription of the API, whereas a
per-algorithm enum with only-the-relevant-fields-present (which is the more
natural Rust shape) is imposing structure the API itself doesn't have.

The full `JsonWebKeyEncryptionAlgorithm` enum, applicable across
`encrypt`/`decrypt`/`wrapKey`/`unwrapKey` uniformly (same enum, same
request/response shape, for all four operations):

| Value | AEAD? (accepts/needs `aad`/`iv`/`tag`) | Key type | Note |
|---|---|---|---|
| `RSA-OAEP` | No | RSA/RSA-HSM | Not recommended (SHA-1) |
| `RSA-OAEP-256` | No | RSA/RSA-HSM | Recommended RSA default |
| `RSA1_5` | No | RSA/RSA-HSM | Not recommended (PKCS#1 v1.5) |
| `A128GCM`/`A192GCM`/`A256GCM` | **Yes** | oct/oct-HSM | AES-GCM; `iv` required in practice (server can't invent a "cryptographically random, non-repeating" IV that survives round-tripping to the caller for `decrypt` unless the caller supplies/receives it — see `KeyOperationResult` below), `tag` returned on encrypt, required on decrypt |
| `A128KW`/`A192KW`/`A256KW` | No | oct/oct-HSM | AES key wrap (RFC 3394) — no IV/tag, deterministic |
| `A128CBC`/`A192CBC`/`A256CBC` | No | oct/oct-HSM | needs `iv`, no authentication tag (Microsoft's own docs warn against decrypting CBC ciphertext without a separate integrity check, e.g. HMAC) |
| `A128CBCPAD`/`A192CBCPAD`/`A256CBCPAD` | No | oct/oct-HSM | CBC + PKCS padding, same no-tag caveat |
| `CKM_AES_KEY_WRAP` / `CKM_AES_KEY_WRAP_PAD` | No | oct/oct-HSM | PKCS#11-style AES key wrap variants |

**Response `KeyOperationResult`:** `kid`, `value` (result bytes), plus the
**same optional `aad`/`iv`/`tag` fields mirrored back** — for GCM, the
service returns the `iv` it used (if the caller didn't supply one — the
schema doesn't document whether the server will generate an IV if omitted;
the `A128GCM` example implies IVs are typically caller-supplied for
Key-Vault-side crypto, unlike `stack-encrypt`'s ZeroKMS integration where the
service always mints the IV) and the `tag` needed later for `decrypt`.

**Decrypt-specific note:** the docs explicitly warn "Microsoft recommends
not to use CBC algorithms for decryption without first ensuring the
integrity of the ciphertext using an HMAC" — i.e. the API will *happily*
decrypt CBC ciphertext with no tag and no integrity check at all; there is
no server-side protection against a padding-oracle-style attack on
`A*CBC`/`A*CBCPAD` decrypt calls. Any capability trait that exposes raw
`decrypt` needs to either forbid non-AEAD algorithms for a "safe decrypt"
capability or push this warning onto the caller explicitly.

---

## `decrypt`

Mirror of `encrypt`: same URL shape (`.../decrypt`), same
`KeyOperationsParameters` request / `KeyOperationResult` response, same
`JsonWebKeyEncryptionAlgorithm` enum, permission `keys/decrypt`. "Applies to
asymmetric and symmetric keys... since it uses the private portion of the
key" (unlike `encrypt`, which for RSA is a convenience wrapper over public-key
math). For GCM algorithms, `tag` is required to authenticate the ciphertext
on the way in — omitting it doesn't get you a signature-less "just decrypt"
mode.

---

## `wrapKey`

`POST {vaultBaseUrl}/keys/{key-name}/{key-version}/wrapkey?api-version=...`
— permission `keys/wrapKey`. Identical request/response shape and algorithm
enum to `encrypt` (same `KeyOperationsParameters`/`KeyOperationResult`/
`JsonWebKeyEncryptionAlgorithm`) — **`wrapKey` and `encrypt` are, at the
schema level, the same operation under a different URL and different
permission**; the docs' own framing is that `wrapKey`/`unwrapKey` exist
"to provide semantic and authorization separation, and consistency across
key types" versus `encrypt`/`decrypt`, not because the underlying mechanics
differ. For a Rust trait, this means `wrap`/`encrypt` could plausibly share
one underlying HTTP-call implementation gated only by which permission/URL
segment and semantic intent applies — there's no structural reason they need
distinct request/response types.

---

## `unwrapKey`

Mirror of `wrapKey`; `.../unwrapkey`, permission `keys/unwrapKey`. Same
relationship to `decrypt` as `wrapKey` has to `encrypt`.

---

## `sign`

`POST {vaultBaseUrl}/keys/{key-name}/{key-version}/sign?api-version=...` —
permission `keys/sign`. "Strictly, this operation is 'sign hash' — the
service doesn't hash content as part of signature creation. Applications
should hash the data to be signed locally, then request the service sign the
hash."

**Request body (`KeySignParameters`) — notably narrower than the
encrypt/wrap family, no `aad`/`iv`/`tag` fields at all:**

| Field | Required | Type |
|---|---|---|
| `alg` | **Yes** | `JsonWebKeySignatureAlgorithm` |
| `value` | **Yes** | base64url — the **pre-computed digest**, not the original message |

**Response `KeyOperationResult`:** `kid`, `value` (the signature). The
response type is the *same* `KeyOperationResult` shape used by
encrypt/decrypt/wrap/unwrap, so it carries unused `aad`/`iv`/`tag` optional
fields that are simply never populated for sign — another instance of one
shared response schema being reused across semantically distinct operation
families.

**Full `JsonWebKeySignatureAlgorithm` enum**, with exact digest-length
constraints where documented:

| Value | Key type / curve | Digest requirement |
|---|---|---|
| `PS256`/`PS384`/`PS512` | RSA/RSA-HSM | RSASSA-PSS, SHA-256/384/512 + matching MGF1 |
| `RS256`/`RS384`/`RS512` | RSA/RSA-HSM | RSASSA-PKCS1-v1_5; digest must be **exactly** 32/48/64 bytes respectively — "the application supplied digest value must be computed using SHA-256 [etc.] and must be 32 bytes in length" |
| `ES256` | EC/EC-HSM, **P-256 only** | SHA-256 digest; curve/algorithm are locked together — the docs describe this as a hard requirement, and mismatches ("sign and verify algorithm must match the key type and size") return a documented **key-size-incorrect error** |
| `ES384` | EC/EC-HSM, **P-384 only** | SHA-384 |
| `ES512` | EC/EC-HSM, **P-521 only** | SHA-512 (note: P-521, not P-512 — a common naming trap) |
| `ES256K` | EC/EC-HSM, **P-256K only** | SHA-256; "pending standardization" per Microsoft's own wording |
| `HS256`/`HS384`/`HS512` | oct/oct-HSM (symmetric) | HMAC-SHA-256/384/512 |
| `RSNULL` | RSA | "Reserved" / RFC 2437, "a specialized use-case to enable certain TLS scenarios" — not a general-purpose signing algorithm |

The curve↔algorithm binding above is a hard constraint worth flagging for
trait design: a Rust `SignatureAlgorithm` enum that's independent of the
key's curve would let a caller construct an invalid combination the API
will reject with a (documented but not enum-typed) "key-size-incorrect"
error rather than at compile time.

---

## `verify`

`POST {vaultBaseUrl}/keys/{key-name}/{key-version}/verify?api-version=...`
— permission `keys/verify`.

**Request body (`KeyVerifyParameters`):** `alg` (**required**,
`JsonWebKeySignatureAlgorithm`), `digest` (**required**, base64url — same
pre-hashed digest semantics as `sign`'s `value`), `value` (**required**,
base64url — the signature to check). Three required fields, no optional
ones at all — the only operation in this whole API surface with zero
optional request fields.

**Response `KeyVerifyResult`:** `{ "value": boolean }` — the only operation
in the API whose success response is a bare boolean rather than a bundle/
result object carrying `kid`/metadata.

Documentation text inconsistency worth flagging verbatim, since it's from
the official per-operation reference and could mislead a spec-reading
implementer: `sign`'s description says it "is applicable to asymmetric and
symmetric keys," while `verify`'s description says it "is applicable to
**symmetric** keys stored in Azure Key Vault" and separately notes verify is
offered for asymmetric keys "as a convenience for callers that only have a
key-reference and not the public portion of the key" — i.e. `verify` works
for both key families in practice (RSA/EC public-key verification and HMAC
symmetric verification), but the two operations' prose descriptions are
worded inconsistently about which key types they name first.

---

## `rotateKey`

`POST {vaultBaseUrl}/keys/{key-name}/rotate?api-version=...` — permission
`keys/rotate`. No request body. "Creates a new key version... based on the
key [rotation] policy" — this is a manual/on-demand trigger of the *same*
rotation logic the automatic policy (below) would otherwise apply on a
schedule; it does not accept parameters to override the policy for this one
invocation. Response: `KeyBundle` (the newly-created version).

**Managed HSM difference:** rotation (`rotateKey` and both rotation-policy
operations below) is **"available only on Key Vault resources (not on
Managed HSM)"** per Microsoft's own key-operations reference. This is a
genuine capability gap between the two backends sharing the same nominal
API surface — a Rust trait that treats "Key Vault" and "Managed HSM" as
interchangeable implementations of one `KeysApi` trait needs `rotate*` to be
either a separately-gated capability or an operation that's allowed to
return "unsupported" for one of its two concrete backends.

---

## `getKeyRotationPolicy`

`GET {vaultBaseUrl}/keys/{key-name}/rotationpolicy?api-version=...` —
permission `keys/get`.

**Response `KeyRotationPolicy`:** `id` (string), `lifetimeActions`
(`LifetimeActions[]`), `attributes` (`KeyRotationPolicyAttributes`:
`created`, `updated` — unixtime, read-only — and `expiryTime`, an ISO 8601
duration string, e.g. `P2Y`, applied to the *next* rotated version).

`LifetimeActions` = `{ trigger: LifetimeActionsTrigger, action:
LifetimeActionsType }`. `LifetimeActionsTrigger`: `timeAfterCreate`
(ISO 8601 duration, e.g. `P90D` — "only applies to rotate") **or**
`timeBeforeExpiry` (ISO 8601 duration — applies to rotate *or* notify).
`LifetimeActionsType.type` is the `KeyRotationPolicyAction` enum: `Rotate`
("rotate the key based on the key policy") or `Notify` ("trigger Event Grid
events... Key Vault only").

**Explicitly documented cardinality constraint** on the schema itself (not
just prose elsewhere): *"For preview, `lifetimeActions` can only have two
items at maximum: one for rotate, one for notify. Notification time [is]
default[ed] to 30 days before expiry and it is not configurable."* — i.e.
even though `lifetimeActions` is typed as an unbounded array, the service
enforces (as of this writing) a hard cap of exactly one `Rotate` action and
one `Notify` action, with the `Notify` trigger's timing not actually
settable via the documented `timeBeforeExpiry` field for that action in
practice (the docs say it defaults and "is not configurable" despite the
schema exposing a field that looks like it should configure it).

---

## `updateKeyRotationPolicy`

`PUT {vaultBaseUrl}/keys/{key-name}/rotationpolicy?api-version=...` —
permission `keys/update`. "Set specified members in the key policy. Leave
others as undefined" (PUT-with-partial-update semantics, not strict REST PUT
replace-the-whole-resource semantics). Request body: `attributes`
(optional), `lifetimeActions` (optional) — both top-level fields optional,
same shapes as the `get` response. Response: `KeyRotationPolicy` (the
resulting merged policy).

`expiryTime` constraint, quoted: **"It should be at least 28 days."** ISO
8601 duration format, with Microsoft's own examples: `P90D` (90 days),
`P3M` (3 months), `PT48H` (48 hours — note this example is *below* the
28-day minimum, so it's illustrating the *format*, not a valid value for
this particular field), `P1Y10D` (1 year 10 days).

---

## `release` (secure key release)

`POST {vaultBaseUrl}/keys/{key-name}/{key-version}/release?api-version=...`
— permission `keys/release`.

Purpose: securely hand an exportable key's material to code running inside
an attested confidential-compute environment (e.g. an SGX enclave, per the
worked example's `sgx-mrenclave`/`sgx-mrsigner` claims) — the "release
policy" is a set of attestation claims the calling environment must satisfy
(TEE identity, debuggability flag, issuer, etc.) before the service will
hand over key bytes. **The target key must have `attributes.exportable ==
true`** and a `release_policy` set (per `KeyAttributes`/`KeyReleasePolicy`
above); this is the *only* operation gated by the `exportable` attribute.
"Applicable to all key types."

**Request body (`KeyReleaseParameters`):**

| Field | Required | Type | Notes |
|---|---|---|---|
| `target` | **Yes** | string, `minLength: 1` | the attestation assertion (a JWT in the worked example) proving the calling environment meets the key's release policy |
| `enc` | No | `KeyEncryptionAlgorithm` | how the exported key material itself gets wrapped for transit — `CKM_RSA_AES_KEY_WRAP`, `RSA_AES_KEY_WRAP_256`, or `RSA_AES_KEY_WRAP_384` |
| `nonce` | No | string | caller-supplied freshness value |

**Response `KeyReleaseResult`:** `{ "value": string }` — "a signed object
containing the released key" (in the worked example, this is itself a
base64-encoded JSON document embedding the key's `attributes`, `key`
(including `key_hsm`), and `release_policy` — i.e. the release result is a
**nested, self-describing bundle**, not a flat key-material blob like
`backupKey`'s output, and its exact schema is not itself part of the typed
REST reference — it's opaquely typed as `string`).

This is the operation in the whole Keys API with the least request/response
regularity relative to everything else: unlike every other crypto operation,
its inputs are attestation/freshness data rather than key material or
ciphertext, and its output is an opaquely-typed signed envelope rather than
a `KeyBundle`/`KeyOperationResult`. A capability trait modelling `release`
as "just another crypto operation" alongside encrypt/sign/wrap would be
misrepresenting how different its actual contract is.

---

## Cross-cutting error behaviour

Beyond the per-operation `KeyVaultError` envelope (`code`/`message`/
`innererror`, no published closed vocabulary of `code` values in the
operation-level REST reference), Microsoft's separate [REST API error
codes](https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes)
guide documents the HTTP-status-level contract that applies uniformly
across all 22 operations above:

- **401 Unauthenticated** — missing/expired/malformed bearer token, or a
  token issued for the wrong `aud` (must be exactly `https://vault.azure.net`
  with no trailing slash — a token scoped to, e.g., Microsoft Graph will not
  work even if otherwise valid).
- **403 Insufficient permission** — two indistinguishable-without-vault-logs
  causes: (a) no RBAC role/access-policy grant for the calling identity, or
  (b) the caller's IP/network isn't allow-listed in the vault's firewall
  rules. Enabling vault diagnostic logging is Microsoft's documented way to
  tell which one applies.
- **429 Too Many Requests** — throttling, with concrete example limits
  quoted directly: **HSM 2048-bit key creation: 10 requests/10s**; **all
  other HSM transactions: 2,000 requests/10s**; **general vault request
  cap: 4,000 requests/10s** (Key Operations specifically have their own,
  separately documented limits). Recommended mitigation is exponential
  backoff, client-side caching, or splitting keys across multiple vaults
  (subscription-level cap is 5× a single vault's limit).
- Implicit but not separately elaborated in that guide: **404** for a
  missing key/version/vault, and **400**-class responses for malformed
  request bodies (bad base64url, invalid enum value, etc.) — both fall under
  the same generic `KeyVaultError` "Other Status Codes" catch-all in every
  per-operation reference rather than getting their own documented page.

For trait design, the practical implication is that Azure gives you a
strong, closed contract at the **HTTP status** layer (401/403/404/429/2xx)
but an open, undocumented one at the **`code` string** layer — a Rust error
type should probably discriminate primarily on status code (+ retry
guidance for 429) rather than attempting to model `code` as a closed enum,
since Microsoft hasn't committed to one.

---

## Summary: what this means for capability-trait design

1. **`encrypt`/`decrypt`/`wrapKey`/`unwrapKey` are four URLs over one wire
   schema.** `KeyOperationsParameters`/`KeyOperationResult` are identical
   across all four, and `wrapKey`≈`encrypt`/`unwrapKey`≈`decrypt`
   structurally (same enum, same fields) — the vendor's own reason for the
   split is semantic/authorization separation, not a functional one. A
   trait could reasonably implement all four against one internal HTTP
   helper.
2. **`aad`/`iv`/`tag` optionality is enforced by convention, not by the
   schema.** All three fields are always-optional on the wire regardless of
   `alg`; whether they're meaningful is entirely a function of which of the
   16 `JsonWebKeyEncryptionAlgorithm` values you picked (AEAD: `A*GCM` only;
   non-AEAD: RSA family, `A*KW`, `A*CBC[PAD]`, `CKM_AES_KEY_WRAP[_PAD]`).
   Modelling this as a Rust enum-per-algorithm with algorithm-appropriate
   fields is *more* type-safe than the API itself, which is a legitimate
   design choice to make deliberately rather than by accident.
3. **`sign`/`verify` use a structurally different, narrower schema** (no
   `aad`/`iv`/`tag` at all) and carry a hard curve↔algorithm binding
   (`ES256`↔P-256 etc.) that the service enforces at call time with a
   documented but not type-level "key-size-incorrect" error.
4. **EC keys support signing only** — `encrypt`/`decrypt`/`wrap`/`unwrap`
   are simply inapplicable (`NA` in Microsoft's own matrix), not merely
   discouraged. **Symmetric (`oct`/`oct-HSM`) keys are the inverse and then
   some**: HMAC sign/verify plus AES encrypt/wrap, but the entire key type
   is unavailable on Standard Key Vault, preview-only on Premium, and only
   production-grade on Managed HSM — a three-way tier/backend gate with no
   analog among RSA/EC.
5. **Not every operation returns a bundle.** `purgeDeletedKey` returns
   `204 No Content` (no body at all); `verify` returns a bare
   `{value: bool}`; `release`'s `value` is an opaquely-typed nested signed
   envelope, not a typed bundle. A trait's response modelling can't assume
   one uniform "operation result" shape.
6. **Whole-key-only granularity recurs across three unrelated operations**:
   `deleteKey`, `backupKey`, and (implicitly) `restoreKey` all operate on
   "the key" (all versions) and explicitly disclaim per-version scoping —
   this is a consistent vendor-wide constraint, not an accident of one
   operation.
7. **`rotateKey` and both rotation-policy operations are Key-Vault-only**,
   absent on Managed HSM, despite the two backends otherwise sharing the
   same URL shapes and schemas for every other operation in this document —
   the one clean backend-capability split in the whole surface.
8. **`release` doesn't fit the request/response pattern of anything else**
   in the API — attestation-shaped input, opaque signed-envelope output,
   gated by a distinct `exportable` attribute + `release_policy` rather than
   by `key_ops`. It is the operation most likely to need its own capability
   trait rather than folding into a generic crypto-operation trait.
9. **Error modelling should discriminate on HTTP status, not `code` string**
   — Microsoft documents 401/403/429 behaviour precisely but leaves the
   `KeyVaultError.error.code` string vocabulary unenumerated in the
   operation-level reference, unlike AWS KMS's named exception types.

## Sources

All operation-level references below are the `2025-07-01` API-version
rendering of `learn.microsoft.com/en-us/rest/api/keyvault/keys/...`
(equivalently reachable via the classic `?view=rest-keyvault-keys-7.4`
query used in the earlier survey doc — both resolve to the same canonical
pages):

- [Create Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/create-key/create-key)
- [Import Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/import-key/import-key)
- [Get Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key)
- [Get Key Versions](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key-versions/get-key-versions)
- [Get Keys](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys)
- [Update Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/update-key/update-key)
- [Delete Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/delete-key/delete-key)
- [Get Deleted Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-deleted-key/get-deleted-key)
- [Purge Deleted Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/purge-deleted-key/purge-deleted-key)
- [Recover Deleted Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/recover-deleted-key/recover-deleted-key)
- [Backup Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/backup-key/backup-key)
- [Restore Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/restore-key/restore-key)
- [encrypt](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/encrypt/encrypt)
- [decrypt](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/decrypt/decrypt)
- [wrap Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key)
- [unwrap Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/unwrap-key/unwrap-key)
- [sign](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign)
- [verify](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/verify/verify)
- [Rotate Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/rotate-key/rotate-key)
- [Get Key Rotation Policy](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key-rotation-policy/get-key-rotation-policy)
- [Update Key Rotation Policy](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/update-key-rotation-policy/update-key-rotation-policy)
- [release](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/release/release)

Conceptual/cross-cutting references:

- [Key types, algorithms, and operations (Key Vault)](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details) — key-type/algorithm matrix, `oct-HSM` preview status, `nbf`/`exp` date-controlled-operations behaviour, RBAC permission list, "no EXPORT operation" statement
- [REST API error codes](https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes) — 401/403/429 semantics and throttling limits
- [Azure Key Vault Managed HSM overview](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview) — Managed HSM's single-tenant/local-RBAC model, security-domain isolation
- [Full backup/restore and selective restore for Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/backup-restore) — whole-instance backup/restore, distinct from per-key `backupKey`/`restoreKey`

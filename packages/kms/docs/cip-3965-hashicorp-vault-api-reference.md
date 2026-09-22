# CIP-3965: HashiCorp Vault Transit secrets engine — full API reference

[`cip-3965-backend-api-survey.md`](./cip-3965-backend-api-survey.md) mapped all
four CIP-3965 vendors onto ZeroKMS's three-operation surface
(`generate_keys`/`retrieve_keys`/`load_index_key`) and, for Vault, covered only
`datakey`/`datakeys`, `encrypt`/`decrypt`, and a first pass at `derived`/
convergent-mode semantics. This document is the full reference for Vault
Transit's actual API surface — every endpoint under `/transit`, as documented
at
[developer.hashicorp.com/vault/api-docs/secret/transit](https://developer.hashicorp.com/vault/api-docs/secret/transit)
— so the Rust capability traits being designed for CIP-3965/CIP-3985 can be
checked against the vendor's real surface rather than the narrow slice one
use case needed. All paths below assume Transit is mounted at the default
`/transit` path (mount path is caller-configurable in Vault; adjust
accordingly). All request/response bodies are JSON; all `data`-typed request
fields (`plaintext`, `context`, `nonce`, `ciphertext` where wrapped, `input`,
`iv`, `associated_data`) are base64-encoded strings unless noted otherwise.
Enterprise-only endpoints/parameters are marked **(Enterprise)**.

## Key types and capabilities

| Type | Class | Encrypt/Decrypt | Sign/Verify | Derivation | Convergent encryption |
|---|---|---|---|---|---|
| `aes128-gcm96` | symmetric AEAD, 96-bit nonce | Yes | No | Yes | Yes |
| `aes256-gcm96` (default) | symmetric AEAD, 96-bit nonce | Yes | No | Yes | Yes |
| `chacha20-poly1305` | symmetric AEAD | Yes | No | Yes | Yes |
| `aes128-cbc` **(Enterprise)** | symmetric, CBC | Yes | No | Yes | Yes |
| `aes256-cbc` **(Enterprise)** | symmetric, CBC | Yes | No | Yes | Yes |
| `ed25519` | asymmetric | No | Yes | Yes (same context ⇒ same derived key *and* same signature — the signing analogue of convergent encryption) | N/A |
| `ecdsa-p256`/`p384`/`p521` | asymmetric | No | Yes | No | N/A |
| `rsa-2048`/`3072`/`4096` | asymmetric | Yes (OAEP/PKCS1v15) | Yes (PSS/PKCS1v15) | No | N/A |
| `hmac` | MAC-only, variable 32–512-byte key | No | HMAC gen/verify only | No | N/A |
| `aes128-cmac`/`192-cmac`/`256-cmac` **(Enterprise)** | MAC-only | No | CMAC gen/verify only | No | N/A |
| `ml-dsa` **(Enterprise, experimental)** | asymmetric, post-quantum, needs `parameter_set` (`44`/`65`/`87`) | No | Yes | No | N/A |
| `slh-dsa` **(Enterprise, experimental)** | asymmetric, post-quantum, needs `parameter_set` | No | Yes | No | N/A |
| `hybrid` **(Enterprise, experimental)** | PQC + EC hybrid signature, needs `parameter_set`, `hybrid_key_type_pqc`, `hybrid_key_type_ec` | No | Yes | No | N/A |
| `managed_key` **(Enterprise)** | external KMS/HSM-backed | Sign/verify well-supported; encrypt/decrypt only for PKCS#11-backed managed keys | Yes | No | No |

Every key type also generates a second, independent, random 256-bit HMAC key
at creation/rotation time, so **any** key (not just `hmac`-typed ones)
supports `hmac`/`verify` operations. FIPS 140-3 mode excludes
`chacha20-poly1305` and `ed25519` as uncertified. RSA uses OAEP+SHA-256/MGF
for encrypt/decrypt, PSS for sign/verify (configurable hash, used for MGF
too), and PKCS#1v1.5 for sign/verify.

Source: [Key types](https://developer.hashicorp.com/vault/docs/secrets/transit#key-types), [Create key](https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key).

## Derivation and convergent encryption — precise semantics

**`derived`** (bool, set at key creation, immutable) is a *per-key* mode
switch, not a per-request option: once a key is created with
`derived: true`, every `encrypt`/`decrypt`/`rewrap`/`datakey`/`datakeys`/
`sign`/`verify` call against it **must** supply `context` (base64), which
Vault uses to derive a per-context key from the underlying key via a KDF.
`ed25519` is the only asymmetric type that supports `derived` — a `sign` call
with the same `context` derives the same signing key and therefore the same
signature, described in Vault's own docs as "a signing analogue to
`convergent_encryption`."

**`convergent_encryption`** (bool, set at key creation, immutable) requires
`derived: true` and means: for a fixed `context`, the *nonce* Vault uses for
the AEAD/CBC operation is itself deterministically derived rather than
randomly generated, so the same `plaintext` + `context` always produces the
same `ciphertext`. This is what makes convergent-mode keys usable for
equality-queryable encrypted storage (e.g. "find all rows with this
encrypted value").

### Convergent-encryption version history (exact, per Vault's docs)

Vault has shipped three distinct convergent-encryption algorithms, tracked
per-key as an internal `convergent_version`:

- **Version 1** — the client supplies its own `nonce` on every operation.
  "Highly flexible but if done incorrectly can be dangerous." This mode only
  ever existed in **Vault 0.6.1**, and keys created under it **cannot be
  upgraded** to a later version.
- **Version 2** — Vault derives the nonce algorithmically from the context
  (client no longer supplies one). However, "the algorithm used was
  susceptible to offline plaintext-confirmation attacks, which could allow
  attackers to brute force decryption if the plaintext size was small."
  Version-2 keys **can** be upgraded: performing a `rotate` on the key
  creates a new key version that uses the version-3 algorithm; existing
  ciphertext must then be `rewrap`ped against the new version to actually
  move it onto version 3 (rotate alone does not touch already-stored
  ciphertext).
  Version 2 covers keys created from Vault 0.6.2 through some later release
  (Vault does not use this "version 2/3" label as a doc-visible key-creation
  parameter — it is an internal migration state you can only see indirectly,
  via `rotate` + `rewrap` being the documented upgrade path).
- **Version 3** (current default for new convergent keys) — "a different
  algorithm designed to be resistant to offline plaintext-confirmation
  attacks. It is similar to AES-SIV in that it uses a PRF to generate the
  nonce from the plaintext" (not just the context — the plaintext itself
  feeds the nonce derivation, which is what closes the version-2 weakness).

### Nonce parameter, by era

The API-level `nonce` request parameter on `encrypt`/`decrypt`/`rewrap`/
`datakey`/`datakeys` reflects this history directly:

- **Vault 0.6.1 keys (convergent version 1):** `nonce` (base64, exactly 96
  bits / 12 bytes) is **required** on every operation, and "the user must
  ensure that for any given context (and thus, any given encryption key)
  this nonce value is never reused." Reuse under the same context breaks
  semantic security outright.
- **Vault 0.6.2+ keys (convergent version 2 or 3):** `nonce` is **not
  required** — Vault derives it internally from context (v2) or from
  context+plaintext (v3) — and, per **CVE-2023-4680 / HCSEC-2023-28**
  (fixed in Vault 1.14.3 / 1.13.7 / 1.12.11), supplying a nonce explicitly
  when convergent encryption is *not* enabled used to be silently accepted,
  letting a caller with encrypt permission choose nonces on a supposedly
  non-convergent key. That let an attacker, with known plaintext/nonce
  pairs, mount offline decryption of arbitrary ciphertext under the same
  key and, for AES-GCM, derive the GCM authentication subkey. Patched Vault
  versions reject a caller-supplied `nonce` unless convergent encryption is
  actually enabled on the key.

Net effect for anyone designing a KDF-shaped abstraction on top of this: a
"give me the same derived key/ciphertext for the same input" contract is
**not** uniform across Vault versions or convergent-version states — it
depends on which convergent version the specific key/version was created
under, and the only forward-compatible way to reach version 3 for an
existing key is `rotate` (mints a new key version on v3) followed by
`rewrap` of every stored ciphertext (moves it onto that version). There is
no request-level "opt into v3" flag; it's a key-lifecycle operation.

**Security caveat, verbatim intent from Vault's docs:** convergent
encryption trades semantic security for queryability — "it is very
important when using this mode that you ensure that all nonces are unique
for a given context" (true even in v2/v3 designs; the *value* of a
deterministic ciphertext is that identical plaintext+context repeats
identically, which is the whole point, but also means pattern/frequency
analysis is possible across ciphertexts sharing a context). Vault documents
this as a special-purpose mode for things like queryable-encrypted-database
columns, not a general "give me a stable derived secret" primitive — and
per the narrower CIP-3965 survey's flag, using it as a KMS-side analogue of
`load_index_key` (deriving *key material*, not encrypting *application
data*) is a different threat model than the one Vault's caveats are written
for, and needs its own review rather than inheriting Vault's data-encryption
sign-off.

Sources: [Convergent encryption](https://developer.hashicorp.com/vault/docs/secrets/transit#convergent-encryption), [Create key](https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key), [Encrypt data](https://developer.hashicorp.com/vault/api-docs/secret/transit#encrypt-data), [HCSEC-2023-28 / CVE-2023-4680](https://discuss.hashicorp.com/t/hcsec-2023-28-vault-s-transit-secrets-engine-allowed-nonce-specified-without-convergent-encryption/58249).

---

## Key management endpoints

### Create key — `POST /transit/keys/:name`

Creates a new named key. Values set here are immutable after creation.

**Parameters:**
- `name` (string, required, in URL path)
- `type` (string, default `"aes256-gcm96"`) — one of the key types in the
  table above.
- `derived` (bool, default `false`)
- `convergent_encryption` (bool, default `false`) — requires `derived: true`.
- `exportable` (bool, default `false`) — one-way; cannot be unset once true.
- `allow_plaintext_backup` (bool, default `false`) — one-way; cannot be
  unset once true.
- `auto_rotate_period` (duration string, default `"0"` = disabled) — minimum
  1 hour if non-zero.
- `key_size` (int, optional) — variable key size in bytes; currently only
  applicable to `hmac` type, must be 32–512.
- `managed_key_name` / `managed_key_id` (string) — required (one of) when
  `type: managed_key`.
- `parameter_set` (string) — required for `ml-dsa` (`44`/`65`/`87`) and
  `slh-dsa` (e.g. `slh-dsa-sha2-128s`, `slh-dsa-shake-256f`, etc. — 12
  named parameter sets) and `hybrid`.
- `hybrid_key_type_pqc` (string) — required for `hybrid`; currently only
  `ML-DSA`.
- `hybrid_key_type_ec` (string) — required for `hybrid`; one of
  `ecdsa-p256`/`p384`/`p521`/`ed25519`.

No response body of note beyond standard success (echoes nothing back —
`Read key` is the way to see the resulting config).

### Read key — `GET /transit/keys/:name`

**Response fields:** `type`, `name`, `keys` (object: version number →
Unix-epoch creation timestamp — *not* the key material), `derived`,
`exportable`, `allow_plaintext_backup`, `deletion_allowed`,
`min_decryption_version`, `min_encryption_version`, `supports_encryption`,
`supports_decryption`, `supports_derivation`, `supports_signing` (all four
derived purely from key type), `imported` (bool). Asymmetric keys also
return public-key material in a type-appropriate format inline.

### List keys — `LIST /transit/keys`

**Response:** `{ "keys": [<name>, ...] }` — names only, no metadata.

### Delete key — `DELETE /transit/keys/:name`

Irreversible; permanently prevents decrypting anything under this key.
**Requires `deletion_allowed: true`** to have been set via `.../config`
first — otherwise Vault refuses the delete. No request body.

### Update key configuration — `POST /transit/keys/:name/config`

**Parameters:**
- `min_decryption_version` (int, default `0`) — floor on which key versions
  may still decrypt/verify.
- `min_encryption_version` (int, default `0`) — floor on which key versions
  may encrypt/sign/HMAC; must be `0` (⇒ use latest) or ≥
  `min_decryption_version`.
- `deletion_allowed` (bool, default `false`)
- `exportable` (bool, default `false`) — one-way.
- `allow_plaintext_backup` (bool, default `false`) — one-way.
- `auto_rotate_period` (duration, optional) — `"0"` disables; omitting the
  field leaves the existing period unchanged (this endpoint's fields are
  independently settable, unlike creation where everything is supplied at
  once).

### Rotate key — `POST /transit/keys/:name/rotate`

Creates a new key version; subsequent plaintext encrypt/sign/HMAC calls use
the new version by default. Does **not** touch already-stored ciphertext —
that needs an explicit `rewrap`. The reference doc frames this as
supported "for keys that support encryption and decryption operations,"
but rotation also applies to signing-only key types (it mints a new
signing key version) — Transit's `rotate` is a general per-key-type
operation, not encrypt/decrypt-specific. For a variable key-size
algorithm, the new version reuses the previous version's key size.

**Parameters:**
- `managed_key_name` / `managed_key_id` (string) — required (one of) if the
  key type is `managed_key`.

**Constraint:** imported keys can only be rotated in-Vault if
`allow_rotation: true` was set at import time, and once such a key is
rotated inside Vault, it permanently loses the ability to accept further
`import_version` calls.

### Trim key — `POST /transit/keys/:name/trim`

Permanently deletes archived key versions older than a floor, to bound the
keyring's storage size (relevant because the whole version archive lives in
a single storage entry — a real operational concern on Raft-backed storage
under frequent rotation).

**Parameters:**
- `min_available_version` (int, required) — all versions strictly older than
  this are permanently deleted. Constraint: must be ≤ the lesser of the
  key's current `min_decryption_version` and `min_encryption_version`, and
  **the call is rejected outright if either of those is currently `0`**
  (i.e. you must have already raised both floors above zero via
  `.../config` before you're allowed to trim anything).

No response body beyond success/failure.

### Import key — `POST /transit/keys/:name/import`

Creates a new key from externally-generated key material (the BYOK
mechanism), as opposed to Vault generating material itself. Two mutually
exclusive request shapes:

1. **Private/symmetric import** — set `ciphertext` (+`hash_function`);
   Vault derives the public key automatically for asymmetric types.
2. **Public-key-only import** — set only `public_key`; this permanently
   restricts the key to verify/encrypt-only operations (no private
   material exists).

**Parameters (shared across both shapes unless noted):**
- `name` (string, required, URL)
- `ciphertext` (string, required unless `public_key` set) — base64 blob:
  first 512 bytes are an ephemeral 256-bit AES key RSA-wrapped under
  Vault's `wrapping_key`, remainder is the import key material AES-wrapped
  under that ephemeral key.
- `hash_function` (string, default `"SHA256"`) — RSA-OAEP hash for
  unwrapping; one of `SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`.
- `type` (string, required) — same type enum as Create key, minus
  `managed_key`, `ml-dsa`, `hybrid`, `slh-dsa` (not listed as importable in
  the docs' import-endpoint type enum).
- `public_key` (string, optional) — plaintext PEM; mutually distinct path
  from `ciphertext`.
- `allow_rotation` (bool, default `false`) — must be set to permit later
  in-Vault `rotate` calls on this key at all.
- `derived` (bool, default `false`), `context` (string, required if
  `derived: true`), `exportable` (bool, default `false`, one-way),
  `allow_plaintext_backup` (bool, default `false`, one-way),
  `auto_rotate_period` (duration, default `"0"`).

**Constraint:** once an imported key is rotated in-Vault, `import_version`
against it is permanently disabled (Vault-generated versions can't accept
externally-supplied material after that point).

### Import key version — `POST /transit/keys/:name/import_version`

Imports additional external key material into an **existing, previously
imported** key (never into a Vault-generated key). Notably lets you attach
a private key to a previously public-key-only import at a later date.

**Parameters:** `name` (URL), `ciphertext` (required, same wrapped-blob
format as Import key), `hash_function` (default `"SHA256"`), `public_key`
(optional), `version` (int, optional — which version to update; if omitted,
a new version is created unless a private key is supplied for the
"latest" version and that version is currently missing private material).

### Get wrapping key — `GET /transit/wrapping_key`

Returns the current 4096-bit RSA public key callers must use to wrap
material for `import`/`import_version`/`byok-export`. **Response:**
`{ "public_key": "<PEM>" }`. No parameters.

### Securely export key (BYOK, cross-cluster) — `GET /transit/byok-export/:destination/:source(/:version)`

Wraps `source`'s key material under a **destination** RSA key (typically
another Vault/mount's `wrapping_key`) so it can be fed straight into that
target's `import` endpoint — cluster-to-cluster BYOK without ever exposing
plaintext key material or needing the CLI helper.

**Parameters (all in URL path):**
- `destination` (string, required) — the RSA key to encrypt to; **must be
  an RSA key type**.
- `source` (string, required) — the key being exported.
- `version` (string, optional) — a specific version, `latest`, or omitted
  entirely to return **all** versions.

**Response:** `{ "name": "<source>", "keys": { "<version>": "<wrapped-b64>", ... } }`.

### Export key — `GET /transit/export/:key_type/:name(/:version)`

Returns raw key material — **requires the key to have `exportable: true`.**

**Parameters (URL):**
- `key_type` (string, required) — one of `encryption-key`, `signing-key`,
  `hmac-key`, `public-key` (works even on non-exportable keys' public
  halves — NIST-curve EC, Ed25519, RSA), `certificate-chain` (whatever was
  set via `set-certificate`), `cmac-key` **(Enterprise)**.
- `name` (string, required)
- `version` (string, optional) — a version number, `latest`, or omitted for
  all versions.

**Response:** `{ "name": ..., "keys": { "<version>": "<material>", ... } }`.

### Sign CSR — `POST /transit/keys/:name/csr`

Lets a CSR be signed by an asymmetric key's private material **without the
key ever leaving Transit**.

**Parameters:** `name` (URL, required), `version` (string, default current;
`latest` or unset both mean current), `csr` (string, PEM, optional — a
template to copy and re-key; if omitted, an empty CSR is signed).

**Response:** `{ "name", "version", "csr": "<PEM>" }`.

### Set certificate chain — `POST /transit/keys/:name/set-certificate`

Associates (and **overwrites** any prior) certificate chain with a key
version, so certs can be tracked alongside the key material in one mount.

**Parameters:** `name` (URL, required), `version` (string, default
current), `certificate_chain` (string, required) — one or more concatenated
PEM blocks, end-entity certificate first.

### Write / read global keys configuration — `POST` / `GET /transit/config/keys`

Mount-wide (not per-key) setting.

**Parameters (write):** `disable_upsert` (bool, default `false`) — when
`true`, `encrypt` can no longer auto-create a nonexistent key even for
callers with `create` capability (falls back to `update` semantics, i.e.
error if key absent).

**Response (read):** `{ "disable_upsert": <bool> }`.

---

## Cryptographic operation endpoints

### Encrypt data — `POST /transit/encrypt/:name`

**Upsert behavior:** if the key doesn't exist and the caller has `create`
ACL capability on this path, Vault auto-creates it with defaults (derived
on/off inferred from whether `context` is non-empty); with only `update`
capability and a missing key, the call errors. Global `disable_upsert`
forces `create`-capability callers through `update` semantics too.

**Parameters:**
- `name` (URL, required)
- `plaintext` (string, required unless `batch_input` used) — base64.
- `associated_data` (string, optional) — base64 AAD, AEAD types only
  (`aes128-gcm96`, `aes256-gcm96`, `chacha20-poly1305`).
- `context` (string, optional/required-if-`derived`) — base64.
- `nonce` (string, optional) — base64, exactly 96 bits; **required only**
  for convergent keys generated under Vault 0.6.1 (convergent version 1);
  not required (and, per CVE-2023-4680's fix, not accepted at all unless
  convergent encryption is enabled) on 0.6.2+ keys. Caller must guarantee
  uniqueness per context when supplied.
- `key_version` (int, default `0` = latest) — must be `0` or ≥
  `min_encryption_version`.
- `padding_scheme` (string, default `"oaep"`) — RSA only; `oaep` or
  `pkcs1v15` (docs flag `pkcs1v15` as legacy/weak).
- `iv` (string, optional) — base64, exactly 128 bits, AES-CBC only; if
  omitted Vault generates and prepends a random IV. Caller must never reuse
  per context/key.
- `type` (string, default `"aes256-gcm96"`) — only consulted on upsert.
- `convergent_encryption` (bool) — only consulted on upsert.
- `reference` (string, optional) — echoed back per-item in `batch_results`
  to correlate inputs to outputs; batch-only.
- `batch_input` (array of `{plaintext, context, nonce, ...}`, optional) —
  when set, top-level `plaintext`/`context`/`nonce` are ignored; response
  order matches input order.
- `partial_failure_response_code` (int, default `400`) — HTTP status to
  return when some but not all batch items fail (all-fail still returns an
  error status regardless of this setting). Docs explicitly warn: "some
  failures (such as failure to decrypt) could be indicative of a security
  breach and should not be ignored."

**Response:** `{ "ciphertext": "vault:v<N>:<b64>" }` (single) or
`{ "batch_results": [ { "ciphertext": ... } | { "error": "..." }, ... ] }`
(batch).

Max request size: 32MB (tunable per Vault listener config).

### Decrypt data — `POST /transit/decrypt/:name`

**Parameters:** `name` (URL), `ciphertext` (required unless `batch_input`),
`associated_data` (optional, AEAD only), `padding_scheme` (default
`"oaep"`), `context` (required if `derived`), `nonce` (same
version-gated-requirement as encrypt), `reference`, `batch_input` (array of
`{ciphertext, context, nonce}`), `partial_failure_response_code` (default
`400`).

**Response:** `{ "plaintext": "<b64>" }` or batched
`{ "batch_results": [ { "plaintext": ... } | { "error": ... }, ... ] }`.

### Rewrap data — `POST /transit/rewrap/:name`

Re-encrypts existing ciphertext under the **latest** key version without
ever exposing plaintext to the caller — safe to delegate to less-trusted
callers/automation, and the mandatory step to actually migrate stored
ciphertext onto a new convergent-encryption algorithm version after
`rotate`.

**Parameters:** `name` (URL), `ciphertext` (required unless `batch_input`),
`decrypt_padding_scheme` (default `"oaep"`), `encrypt_padding_scheme`
(default `"oaep"`, `pkcs1v15` flagged legacy), `context` (required if
`derived`), `key_version` (default `0` = latest, else ≥
`min_encryption_version`), `nonce`, `reference`, `batch_input` (array of
`{ciphertext, context, nonce}`).

**Response:** `{ "ciphertext": "vault:v<N>:..." }` or batched equivalent.
Note: no `partial_failure_response_code` documented for this endpoint
(present on encrypt/decrypt, absent here in the reference doc).

### Generate data key (single) — `POST /transit/datakey/:type/:name`

Generates one new random high-entropy key, wrapped under the named Transit
key, with the plaintext optionally also returned — the split lets an ACL
policy allow an untrusted caller to mint keys for a trusted caller to
consume without the minter ever seeing plaintext.

**Parameters (URL):** `type` (required) — `plaintext` (returns plaintext +
ciphertext) or `wrapped` (ciphertext only); `name` (required).

**Body parameters:** `context` (required if `derived`), `nonce`
(version-gated as above), `bits` (default `256`; one of `128`/`256`/`512`),
`padding_scheme` (default `"oaep"`, RSA-wrapping only), `key_version`
(default `0`).

**Response:** `{ "plaintext": "<b64>", "ciphertext": "vault:v<N>:..." }`
(`plaintext` field omitted for `type=wrapped`).

### Generate multiple data keys — `POST /transit/datakeys/:type/:name` **(Enterprise)**

The genuine batch-generation endpoint (plural path) — distinct from the
singular `datakey` endpoint above, and the only native "N keys, one round
trip" primitive across all four CIP-3965 vendors surveyed for *generation*.

> **Enterprise only, although the API reference does not say so.**
> Verified against `hashicorp/vault:2.1.0` (Community): the path answers
> `404 unsupported path`, the server's OpenAPI listing has no `datakeys`
> or `derivedkeys`, and the open-source Transit backend registers only the
> singular path. Batch `decrypt` via `batch_input` is in every edition.

**Path parameters:** `type` (`plaintext`|`wrapped`, required), `name`
(required).

**Body parameters:** `count` (int, required — how many keys), `bits`
(default `256`), `key_version` (default `0`), `context` (required if
`derived` — note this applies the **same** context to every key in the
batch; there is no per-item context list for this endpoint, unlike
`encrypt`/`decrypt`/`rewrap`'s `batch_input`).

**Response:** `{ "key_pairs": [ { "ciphertext": ..., "plaintext": ... }, ... ], "key_version": <N> }`.

### Generate derived keys — `POST /transit/derivedkeys/:type/:name`

A distinct, third key-generation endpoint: derives a **sequence** of keys
from the Transit key's associated HMAC key (not the primary encryption
key), indexed by an integer range, using `salt`/`info`/`key_index` inputs
to a KDF. The doc is explicit that "derivation from the base key is
unrelated to the key derivation applied to generate the data keys" — i.e.
this is a second, independent derivation concept layered on top of (and
orthogonal to) `derived`/`context` on the underlying key.

**Path parameters:** `type` (`plaintext`|`wrapped`, required), `name`
(required).

**Body parameters:** `salt` (string, required), `key_index_from` (int,
required, inclusive), `key_index_to` (int, required, **exclusive**), `bits`
(default `256`), `key_version` (default `0`), `info` (string, optional,
additional KDF input), `context` (required if the underlying key has
`derived: true`).

**Response:** an object keyed by string index (`"0"`, `"1"`, ...) → `{
plaintext, ciphertext }`, plus `key_version`. Note this response shape is
**not** wrapped in a `data.key_pairs` array like `datakeys` — it's a flat
map keyed by index, a genuinely different response shape from every other
batch-ish endpoint in Transit.

### Generate random bytes — `POST /transit/random(/:source)(/:bytes)`

**Parameters:** `bytes` (int, default `32`, settable via URL segment or
body), `format` (`"base64"` default or `"hex"`), `source` (default
`"platform"`; `"seal"` **(Enterprise)** for entropy augmentation, `"all"` to
mix all sources), `drbg` not part of this endpoint's public parameter list
in the current reference (earlier summarization conflated this with an
unrelated field — treat with caution, verify against the live docs page if
depended on).

**Response:** `{ "random_bytes": "<encoded>" }`.

### Hash data — `POST /transit/hash(/:algorithm)`

Stateless — not tied to any named key.

**Parameters:** `algorithm` (default `"sha2-256"`, URL or body — one of
`sha2-224/256/384/512`, `sha3-224/256/384/512`), `input` (required, base64),
`format` (`"hex"` default or `"base64"`).

**Response:** `{ "sum": "<encoded>" }`.

### Generate HMAC — `POST /transit/hmac/:name(/:algorithm)`

Works against **any** key type (every key type carries its own independent
256-bit HMAC secret regardless of its primary algorithm), using the
key's current version unless overridden.

**Parameters:** `name` (URL, required), `key_version` (default `0` =
latest, else ≥ `min_encryption_version`), `algorithm` (default
`"sha2-256"`, same 8-algorithm set as Hash), `input` (base64; required
unless `batch_input` given), `reference` (batch correlation), `batch_input`
(array of `{input}`; empty/missing `input` in a batch item yields
`{"error": "missing input for HMAC"}` for that item, not a whole-request
failure).

**Response:** `{ "hmac": "vault:v<N>:<encoded>" }` or `batch_results`.

### Sign data — `POST /transit/sign/:name(/:hash_algorithm)`

**Parameters:** `name` (URL), `key_version` (default `0`), `hash_algorithm`
(default `"sha2-256"`; `sha1` — flagged compromised, blockable via policy
deny on the `.../sign/:name/sha1` path — `sha2-*`, `sha3-*`, or `none`),
`input` (base64; required unless `batch_input`), `context` (base64,
required if `derived`; **currently only meaningful for `ed25519` keys**),
`signature_context` (base64) **(Enterprise)** — for Ed25519ctx/Ed25519ph,
`prehashed` (bool, default `false`; combined with `hash_algorithm=sha2-512`
on Ed25519 activates Ed25519ph **(Enterprise)**; combined with
`hash_algorithm=none` + `signature_algorithm=pkcs1v15` produces an RFC
3447 §9.2 `PKCSv1_5_NoOID` signature instead of the usual
`PKCSv1_5_DERnull`), `signature_algorithm` (RSA only, default `"pss"`, or
`pkcs1v15`), `marshaling_algorithm` (ECDSA only, default `"asn1"`, or `"jws"`
— also switches output to URL-safe base64), `salt_length` (RSA-PSS only,
default `"auto"`, or `"hash"`, or an explicit integer), `reference`,
`batch_input` (array of `{input, context}` — a derived-`ed25519` batch
response additionally includes a `publickey` field per item, the derived
public key for that item's context).

**Response:** `{ "signature": "vault:v<N>:<b64>" }` (+ `publickey` for
derived-ed25519) or `batch_results`.

### Verify signed data — `POST /transit/verify/:name(/:hash_algorithm)`

Accepts output from **sign**, **HMAC**, or **CMAC (Enterprise)** — exactly
one of `signature`/`hmac`/`cmac` must be supplied (and for batches, all
items must consistently use the same one of the three; mixing is an
error).

**Parameters:** `name`, `hash_algorithm` (same set as sign, same SHA-1
policy-deny mechanism at `.../verify/:name/sha1`), `input` (required unless
`batch_input`), `signature` / `hmac` / `cmac` **(Enterprise)** (exactly one),
`mac_length` (int, default `0`, CMAC only), `context`, `signature_context`
**(Enterprise)**, `prehashed`, `signature_algorithm`, `marshaling_algorithm`,
`salt_length`, `reference`, `batch_input`.

**Response:** `{ "valid": <bool> }` or `batch_results` of `{ "valid": bool }`
per item (note: an unparseable/malformed input yields `{"valid": false}`,
not necessarily an `error` item — verify is designed to always answer
true/false where structurally possible rather than throw).

### Generate CMAC **(Enterprise)** — `POST /transit/cmac/:name(/:url_mac_length)`

**Parameters:** `name`, `key_version` (default `0`), `input` (required
unless `batch_input`), `mac_length` (int, default `0`, body — "cannot be
larger than the cipher's block size"), `url_mac_length` (int, default `0`,
URL segment — overrides `mac_length` if given), `batch_input` (array of
`{input, mac_length}`).

**Response:** `{ "cmac": "vault:v<N>:<b64>" }` or `batch_results` (each
item also echoes `reference`).

---

## Backup, restore, and cache endpoints

### Backup key — `GET /transit/backup/:name`

Returns a **plaintext** backup blob (base64-encoded JSON containing the
full key policy: every version's key material, HMAC key, timestamps,
convergent/derivation config, archive metadata). **Requires
`allow_plaintext_backup: true`** to have been set on the key (per the
general "immutable, plaintext-exposing capabilities are one-way opt-ins"
pattern used throughout Transit config).

**Parameters:** `name` (URL, required).

**Response:** `{ "backup": "<base64-JSON>" }`.

### Restore key — `POST /transit/restore(/:name)`

**Parameters:** `backup` (string, required) — the exact blob from
`/backup`; `name` (string, optional URL segment) — restore under a
different name than the original; `force` (bool, default `false`) — by
default Vault **refuses to restore over an existing key name**; `force`
overrides that. Docs explicitly recommend restoring to a scratch name
first to validate before trusting a real restore.

### Trim key

Covered above under Key management (`POST /transit/keys/:name/trim`) —
included here for cross-reference since it's part of the same
backup/version-lifecycle story (trim permanently prunes what backup/restore
would otherwise carry forward).

### Configure cache — `POST /transit/cache-config`

Mount-wide LRU cache size for the Transit engine's internal key-material
cache. **Note the operational trap:** "configuration changes will not be
applied until the transit plugin is reloaded," which requires a separate
call to `/sys/plugins/reload/backend` — writing this config alone does not
take effect.

**Parameters:** `size` (int, default `0` = unlimited/disabled-limit) — must
be `0` or ≥ `10` (documented minimum non-zero cache size).

### Read transit cache configuration — `GET /transit/cache-config`

**Response:** `{ "size": <int> }`.

---

## Managed keys **(Enterprise)**

Not a distinct endpoint but a `type: managed_key` mode across the existing
endpoints: Transit looks up (and, best-effort, can generate) the key by
name/ID against an external KMS/HSM registered via
`/sys/managed-keys`. **Sign/verify** are well-supported across all managed
key backends; **encrypt/decrypt** are currently only supported for
PKCS#11-backed managed keys (AWS/GCP/Azure managed-key encrypt/decrypt are
noted as planned, not implemented, as of this documentation snapshot). Where
a mechanism needs an IV, it's supplied via the ordinary `nonce` parameter on
`encrypt`/`decrypt`. Signing/verifying may require pre-hashing, signaled via
the ordinary `prehashed` parameter.

---

## Batch input — cross-endpoint semantics

`batch_input` is supported on: `encrypt`, `decrypt`, `rewrap`, `hmac`,
`sign`, `verify`, `cmac` **(Enterprise)**, and (in its own single-context
form) `datakeys`/`derivedkeys`. General rules, consistent across all of
them:

- Setting `batch_input` causes Vault to **ignore** any single-item
  equivalent parameters in the same request (e.g. top-level `plaintext` is
  ignored if `batch_input` is present on `encrypt`).
- Response order **always** matches input order (explicitly documented,
  not just implied).
- Per-item failures land as `{"error": "<message>"}` in that item's
  `batch_results` slot rather than failing the whole request — but the
  **overall HTTP status code** for a partially-failed batch is controlled
  by `partial_failure_response_code` (default `400`) on the endpoints that
  support it (`encrypt`, `decrypt`; not documented on `rewrap`/`hmac`/
  `sign`/`verify`/`cmac` in the reference, though the same
  batch_results/error shape applies there). An **all-failed** batch always
  returns an error status regardless of this setting.
- `reference` is a pure passthrough echo per item, for correlating
  unordered-looking results back to request intent — safe to rely on even
  though order is also preserved.

This is the one place where "one logical trait call ⇒ one Vault round trip"
genuinely holds across a wide swath of operations (not just
generate/retrieve as the narrower survey found) — `sign`, `verify`, and
`hmac` all get real batch support too, which the earlier survey didn't need
to characterize.

---

## Error conditions and structural constraints (cross-cutting)

- `key_version` (wherever accepted) must be `0` (⇒ latest) or ≥ the key's
  current `min_encryption_version`; otherwise the call errors.
- `min_encryption_version` itself must be `0` or ≥ `min_decryption_version`
  — Vault enforces the ordering at config-write time, not at use time.
- `deletion_allowed`, `exportable`, and `allow_plaintext_backup` are each
  independent boolean gates that must be explicitly opened via
  `.../config` (or at creation) before the corresponding destructive/
  exposing operation (`DELETE`, `export`/`byok-export`, `backup`) is
  permitted; `exportable` and `allow_plaintext_backup` are **one-way** —
  Vault will not let you flip either back to `false` once set.
  `deletion_allowed`, by contrast, is not documented as one-way (can be
  toggled back off).
- `trim` additionally requires both `min_decryption_version` and
  `min_encryption_version` to already be non-zero, and its
  `min_available_version` cannot exceed the lesser of the two.
- `auto_rotate_period`, wherever accepted, cannot be shorter than 1 hour
  (except `"0"`, which disables it).
- Convergent-mode `nonce`/`iv` values must never repeat for a given
  context/key — this is a caller obligation Vault cannot itself enforce,
  and reuse is a silent security failure, not a rejected request.
- Import/import_version/byok-export/wrapping_key form one closed
  subsystem: `import` creates a new key; `import_version` only works on a
  key that was itself created via `import` (never on Vault-generated
  material) and stops working forever once that key is rotated in-Vault;
  `byok-export` requires the *destination* to be an RSA key type
  specifically.
- Request bodies are capped at 32MB by Vault's HTTP listener by default
  (tunable) — relevant for large `plaintext`/`batch_input` payloads.

---

## Notes relevant to Rust capability-trait design

- **Shape diversity is real, not incidental.** `datakey` (single, returns
  plaintext+ciphertext), `datakeys` (batch, single shared context, array
  response), and `derivedkeys` (batch, per-index range, *flat map* response
  keyed by string index rather than an array) are three structurally
  different generation endpoints, not three parameterizations of one shape
  — a trait abstraction that tries to unify them into one method risks
  losing the "one context for the whole batch" vs. "index-ranged
  derivation" distinction, which matters for correctness, not just
  ergonomics.
- **`derived` is a key-creation-time mode, not a call-time option**,
  confirming the narrower survey's flag — any trait method that wants to
  pass a context/AAD-like value has to know up front whether the target
  key supports it at all, unlike AWS/GCP where context/AAD is always legal.
- **Convergent-mode correctness depends on Vault-side key history that the
  caller cannot see or control directly** — whether a given key is on
  convergent version 1 (permanently stuck, 0.6.1 only), 2 (upgradable via
  rotate+rewrap), or 3 isn't exposed as a queryable field on `Read key`'s
  documented response; a trait that wants to assert "this key is safe to
  treat as a stable KDF" has no first-class way to check that assumption
  via the API itself.
- **Batch endpoints don't uniformly support partial-failure status-code
  control** (`encrypt`/`decrypt` document
  `partial_failure_response_code`; `rewrap`/`hmac`/`sign`/`verify`/`cmac`
  do not) even though all of them share the same `batch_results`/`error`
  item shape — a generalized batch-result type in the trait can be uniform,
  but per-endpoint HTTP-status-mapping behavior cannot be assumed uniform
  underneath it.
- **`rotate` and `rewrap` are two separate, both-required steps** for
  migrating ciphertext onto a new key version (or a new convergent
  algorithm version) — there's no single "re-key everything" endpoint;
  `rotate` only affects what *new* encryptions use.

---

## Sources

- [Transit secrets engine — HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/transit) (all per-endpoint parameter/response detail; raw source: [`transit.mdx`, v1.21.x](https://raw.githubusercontent.com/hashicorp/web-unified-docs/main/content/vault/v1.21.x/content/api-docs/secret/transit.mdx))
- [Transit secrets engine — conceptual docs](https://developer.hashicorp.com/vault/docs/secrets/transit) (key types table, convergent-encryption version history, NIST rotation guidance, working-set/archive storage notes; raw source: [`index.mdx`, v1.21.x](https://raw.githubusercontent.com/hashicorp/web-unified-docs/main/content/vault/v1.21.x/content/docs/secrets/transit/index.mdx))
- [HCSEC-2023-28 / CVE-2023-4680 — nonce specified without convergent encryption](https://discuss.hashicorp.com/t/hcsec-2023-28-vault-s-transit-secrets-engine-allowed-nonce-specified-without-convergent-encryption/58249)
- [`cip-3965-backend-api-survey.md`](./cip-3965-backend-api-survey.md) — the narrower, four-vendor comparative survey this document supersedes for Vault-specific depth.

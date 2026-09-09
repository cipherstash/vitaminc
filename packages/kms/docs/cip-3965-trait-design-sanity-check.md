# CIP-3965/CIP-3985 trait design: sanity check against Azure Key Vault, HashiCorp Vault, and Google Cloud KMS

This is the design-notes-only sanity check CIP-3965 calls for ("design notes
are sufficient; implementations are out of scope") — for each of the three
non-ZeroKMS, non-AWS target vendors, how would its real API (per
[`cip-3965-azure-keyvault-api-reference.md`](./cip-3965-azure-keyvault-api-reference.md),
[`cip-3965-hashicorp-vault-api-reference.md`](./cip-3965-hashicorp-vault-api-reference.md),
[`cip-3965-gcp-kms-api-reference.md`](./cip-3965-gcp-kms-api-reference.md))
satisfy each Group 2 trait defined in this crate's `src/`. No code, no new
facts — this only recombines what the four reference docs and the design
tickets (CIP-3986 through CIP-4005, all on Linear map CIP-3985) already
established.

---

## Azure Key Vault

**`GenerateDataKey`/`RetrieveDataKey`.** No native "generate data key" call
(per the original 4-vendor survey). An adapter generates the plaintext
locally (CSPRNG), calls `wrapKey` to produce the `KeyId` (the wrapped
`value`, `+iv+tag` for AEAD algs), and reverses via `unwrapKey`. Confirmed by
the Azure reference: `wrapKey`/`unwrapKey` request bodies are the same flat
`KeyOperationsParameters` shape whether or not the key is asymmetric —
`EC` keys, however, **cannot wrap/unwrap at all** ("NA" in Microsoft's own
support matrix), so an Azure adapter is only constructible over an
RSA or oct(-HSM) key, never an EC one. `KeyReconstruction::ServerOnly` — the
vault holds the full KEK and performs the wrap/unwrap entirely itself.

**`BatchGenerateDataKey`/`BatchRetrieveDataKey`.** No native batch endpoint
for `wrapKey`/`unwrapKey`. `fan_out_generate`/`dedup_retrieve` are the only
option — `KeyIsolation::PerValue` is achievable (N `wrapKey` calls), but
`pooled_key_generate` is the only way to get to O(1) calls, since Azure has
no batch primitive at all here.

**`load_index_key`.** No deterministic-derivation primitive exists (per the
original survey). The universal workaround applies unmodified: provision one
fixed plaintext key once (locally generate + `wrapKey`), persist the
resulting `KeyId`, `unwrapKey` it on every `load_index_key` call.

**`EncryptWithKey`/`DecryptWithKey`.** Maps onto `encrypt`/`decrypt`
directly. Two real frictions: (1) the EC gap above applies here too — no EC
key can implement this trait at all; (2) Microsoft's own guidance is that
RSA `encrypt` calls are "a network round trip doing what the caller could do
locally with the public key" and recommends doing it locally instead — an
Azure `EncryptWithKey` adapter is a legitimate but not best-practice choice
for RSA specifically. The CBC algorithms (`A*CBC`/`A*CBCPAD`) carry no
authentication tag at all and Microsoft's docs explicitly warn against
decrypting them without a separate integrity check — an Azure `DecryptWithKey`
adapter should refuse to offer these algorithms, or push the warning
directly onto its caller in its own docs, not silently allow a
padding-oracle-shaped footgun.

**`GenerateMac`/`VerifyMac`, `Sign`/`Verify`.** Azure unifies both into one
`sign`/`verify` operation family — the algorithm enum spans HMAC
(`HS256`/`384`/`512`) and asymmetric (`PS*`/`RS*`/`ES*`) uniformly. An Azure
adapter's `GenerateMac`/`Sign` impls both call the same underlying `sign`
endpoint internally with a different `alg`; ditto `VerifyMac`/`Verify` and
`verify`. The curve↔algorithm binding is a hard runtime constraint (`ES256`
requires P-256 etc.) that the trait's construction-time key binding (CIP-3986)
already protects against at the *instance* level — an adapter is constructed
against one specific key, so it can validate the pairing once at construction
rather than per call. `Verify`/`VerifyMac` map cleanly onto Azure's bare
`{value: bool}` response — no exception translation needed, unlike AWS.

**`GetPublicKey`.** `getKey` already returns public-key material for
asymmetric keys (`n`/`e` for RSA, `x`/`y`/`crv` for EC) and "no key material
is released" for symmetric keys — an Azure `GetPublicKey` adapter is
`getKey` with the caller extracting the public fields, and should be
statically unavailable (not just runtime-erroring) for a symmetric-only
adapter if the type system can express that; this trait design's Q6
(CIP-4005) didn't require that distinction, so an Azure adapter over an
`oct` key should return a clear `Self::Error` rather than accidentally
implementing the trait at all.

---

## HashiCorp Vault (Transit)

**`GenerateDataKey`/`RetrieveDataKey`.** Vault's `datakey/plaintext/:name`
is the one vendor with an AWS-`GenerateDataKey`-shaped single call
(plaintext + ciphertext together) — the cleanest `GenerateDataKey` mapping
of the four vendors. `decrypt/:name` reverses it. `KeyReconstruction::ServerOnly`
— same reasoning as every non-ZeroKMS vendor.

**`BatchGenerateDataKey`/`BatchRetrieveDataKey`.** Vault is the *only*
vendor with genuine native batch support on both sides:
`datakeys/plaintext/:name?count=N` and `decrypt/:name` with `batch_input`
are real one-round-trip batch primitives. A Vault adapter should implement
`BatchGenerateDataKey`/`BatchRetrieveDataKey` natively rather than falling
back to `fan_out_generate`/`dedup_retrieve` — `KeyIsolation::PerValue` at
native-batch cost, the best outcome any vendor offers here.

**`load_index_key`.** The one vendor with a partial *native* answer —
`derived: true` + convergent encryption gives deterministic output for the
same context. CIP-3988 explicitly deferred relying on this pending its own
security review, and the follow-up Vault API research sharpened why: three
convergent-encryption algorithm versions exist (v1 dead-end legacy, v2
vulnerable to offline plaintext-confirmation on small plaintexts, v3 current
default), with no API field to query which version a key is on, and
CVE-2023-4680 shows a real historical nonce-reuse vulnerability in this
exact mechanism. **This sanity check does not reverse that deferral** — a
Vault adapter should use the same universal fixed-blob-retrieve pattern
(`datakey` once, persist the `KeyId`, `decrypt` it every time) as every
other vendor, not convergent mode, until that review happens.

**`EncryptWithKey`/`DecryptWithKey`.** Maps onto `encrypt/:name`/`decrypt/:name`
directly — the most generous size budget of the four vendors (32MB vs. AWS's
4096 bytes or GCP's 64 KiB), so a Vault `EncryptWithKey` adapter is the one
implementation of this trait that could plausibly be used for more than a
small payload in practice, even though the trait itself makes no such
promise (CIP-4004).

**`GenerateMac`/`VerifyMac`, `Sign`/`Verify`.** Vault splits generation
(`hmac/:name` vs `sign/:name`, separate endpoints) but unifies verification
(`verify/:name` accepts exactly one of `signature`/`hmac`/`cmac`) — the
inverse of Azure's unification shape. A Vault adapter's `VerifyMac`/`Verify`
both call `verify/:name`, supplying `hmac` or `signature` respectively.
Vault's `verify` is designed to always answer `true`/`false` — even
malformed input yields `{valid: false}` rather than an error — which maps
onto this design's `Result<bool, Error>` shape with no translation needed,
same as Azure and unlike AWS.

**`GetPublicKey`.** `export/public-key/:name` works "even on non-exportable
keys' public halves" — i.e. it's ungated by the `exportable: true` flag that
controls private-material export, so a Vault `GetPublicKey` adapter doesn't
need any special key configuration beyond having an asymmetric key at all.

---

## Google Cloud KMS

**`GenerateDataKey`/`RetrieveDataKey`.** No native "generate data key" call
(same two-step shape as Azure): generate the plaintext locally, `:encrypt`
to wrap it into the `KeyId`, `:decrypt` to reverse. One GCP-specific
friction the reference doc surfaces: `Encrypt` can target either a
`CryptoKey` (uses its primary version) or a specific `CryptoKeyVersion`,
but `Decrypt`'s path pattern **forbids** naming a version at all — the
ciphertext itself determines which version decrypts it. This is actually a
clean fit for `GenerateDataKey`/`RetrieveDataKey`'s shape (construction-time
binds the adapter to one `CryptoKey`, and GCP's own versioning is invisible
to the trait either way), but it means a GCP adapter cannot offer
"encrypt under a pinned version" as part of this trait — only "encrypt under
whatever the CryptoKey's current primary is," which is `GenerateDataKey`'s
implicit assumption already. `KeyReconstruction::ServerOnly`.

**`BatchGenerateDataKey`/`BatchRetrieveDataKey`.** No native batch endpoint.
Same as Azure and AWS: `fan_out_generate`/`pooled_key_generate` and
`dedup_retrieve` are the only options.

**`load_index_key`.** No deterministic-derivation primitive (confirmed by
the GCP reference — every `Encrypt` call on a random plaintext DEK produces
fresh ciphertext by construction). Universal workaround applies unmodified.

**`EncryptWithKey`/`DecryptWithKey`.** Maps onto `cryptoKeys.encrypt`/`decrypt`
directly, with the tightest size interaction of the four vendors: HSM keys
share one 8 KiB budget across `plaintext` *and* `additionalAuthenticatedData`
combined (SOFTWARE/EXTERNAL keys get 64 KiB independently per field) — this
design's Q4 (CIP-4004, no AAD in the base trait) sidesteps the
budget-sharing question entirely for now, since there's no AAD parameter to
share the budget with. The same `Encrypt`-can/`Decrypt`-cannot-target-a-version
asymmetry from `GenerateDataKey` applies here too.

**`GenerateMac`/`VerifyMac`, `Sign`/`Verify`.** GCP splits cleanly along the
same lines as AWS — `macSign`/`macVerify` (MAC purpose keys) vs.
`asymmetricSign` (SIGN purpose keys) are separate operation families on
different key types, matching this design's decision to keep MAC and Sign
as separate traits. The one real translation a GCP adapter's `VerifyMac`
must do: `MacVerify` returns `success: false` as normal 200-response data
(matching this design's `Result<bool, Error>` shape directly, same as
Azure/Vault), **but** it also carries a second `verifiedSuccessIntegrity`
flag guarding the verdict's own transit integrity — per Google's own
guidance, a GCP adapter must retry internally when that flag contradicts
`success` before ever returning to the caller, rather than exposing a third
state through this trait's two-state `Result<bool, Error>` contract
(exactly the resolution CIP-4005 already settled on).

**`GetPublicKey`.** `cryptoKeyVersions.getPublicKey` is the one GCP crypto
operation shaped like a plain resource `get` rather than a `:verb` RPC —
maps directly, valid only for `ASYMMETRIC_SIGN`/`ASYMMETRIC_DECRYPT`/
`KEY_ENCAPSULATION` purpose keys, matching this trait's implicit "only
meaningful for asymmetric keys" assumption.

---

## Cross-vendor pattern check

Every friction point found above was already anticipated by a design
decision made without vendor-specific knowledge at the time:

- The **construction-time key binding** (CIP-3986) absorbs GCP's
  Encrypt/Decrypt version-targeting asymmetry and Azure's curve↔algorithm
  binding for free — neither needed a new mechanism once vendor research
  landed.
- The **`Result<bool, Error>` shape for verification** (CIP-4005) correctly
  anticipated that 3 of 4 vendors return a plain boolean and designed the
  one exception (GCP's integrity flag) to be resolved inside the adapter,
  not leaked into the trait.
- The **explicit, never-defaulted batch strategy split** (CIP-3987) is
  necessary precisely because only Vault has a native batch primitive —
  Azure and GCP both fall through to the same shim helpers AWS does.
- No vendor forced a change to any already-closed ticket's trait shape.
  The one real per-vendor *constraint* surfaced here — Azure's EC keys
  being unable to implement `GenerateDataKey`/`RetrieveDataKey`/
  `EncryptWithKey`/`DecryptWithKey` at all — is a fact about which keys a
  future Azure adapter can be constructed over, not a gap in the trait
  design itself.

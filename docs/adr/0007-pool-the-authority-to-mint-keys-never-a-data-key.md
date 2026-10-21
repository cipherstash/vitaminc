# Pool the authority to mint keys, never a data key

`vitaminc-kms` had two ways to fill a batch of data keys. `fan_out_generate`
makes one backend call per value: full per-value isolation, N round trips.
`pooled_key_generate` made one call, minted one key and cloned it N times: one
round trip, and every value in the batch shared a key.

Pooling in that second form could not bind. One key cannot carry a batch's
several bindings, and binding it to the first would make every other item
unretrievable. So `PooledDataKeySource` and the three vendor pooled sources
ignored the binding. Binding is now mandatory (CIP-4981, ADR 0006), so that
form was removed, and the round-trip saving went with it.

The saving is worth keeping. This ADR is how to keep it.

## Decision

**A pooled source shares the authority to mint keys, never a key.** One backend
call fetches an *authority key*, which the adapter caches in memory. Each value
then gets its own data key, derived locally from the cached authority key and a
fresh per-value salt. Nothing is shared between values except the authority.

Concretely, per value:

```
data key = KDF(authority key, salt, binding)
KeyId    = (authority key version, salt)
```

The caller still gets one distinct key per value, still under its own binding,
and the backend is called once per cache refresh rather than once per value.

This follows AWS's Hierarchical keyring, which is the same idea: it "derives a
unique wrapping key from the plaintext branch key and a 16-byte random salt",
and separately "generates a plaintext data key" for every request. Its branch
keys live in a key store and are cached locally under a TTL and an entry
capacity.

### One derivation, not two

AWS derives a *wrapping key* from the branch key and uses it to encrypt a
separately generated data key. We derive the data key itself.

AWS needs the extra tier because the ESDK's data key must exist independently
of any one keyring — several keyrings each wrap the same data key. We have no
such requirement: a data key source returns key material to one caller. Adding
a wrapping key would buy an indirection nothing here uses, and would put a
second piece of key material in memory.

### The binding goes into the derivation

Binding is an input to the KDF, not metadata beside it. A `KeyId` presented
under a different binding derives a different key, so the binding is enforced
by arithmetic rather than by a backend check. That is strictly stronger than
what the vendor-bound sources do, where the backend refuses a mismatch — here
there is nothing to refuse, because the wrong binding simply cannot produce the
key.

It also means a pooled source needs no special pleading about binding. It
binds, like everything else.

## Isolation is the wrong axis for this

`KeyIsolation` says whether a batch holds one key per value or one key shared
across it. A source built this way reports `PerValue`, because that is what it
delivers. What differs from `fan_out_generate` is not isolation but how many
round trips it makes and what it keeps in memory.

The constant bundles three properties that only move together because
clone-one-key makes them:

| | clone-one-key | authority key |
| --- | --- | --- |
| keys per batch | one, shared | one per value |
| backend round trips | one | one per cache refresh |
| binding possible | no | yes |

So the capability belongs on its own trait, not as a third `KeyIsolation`
variant. A source that can mint locally from cached authority material says so
by implementing that trait, and cache policy — TTL, entry capacity, refresh
behaviour under load — is configuration on it. Hanging strategies off
`KeyIsolation` would re-bundle exactly what this design separates.

Nothing implements `Pooled` now, so the variant should go (CIP-5062). A
two-valued enum with one unreachable value is worse than no enum.

## The authority key is a new kind of key

`CONTEXT.md` knows two tiers: a **backend key**, held by the vendor and bound
at construction, and a **data key**, minted or retrieved for the caller. An
authority key is a third, and it is unlike both: the backend wraps it, the
client holds it in plaintext while it is cached, and it mints many data keys.

That raises questions this ADR does not answer, because they need the
implementation to answer honestly:

* where the store lives, and whether it is ours or the deployment's;
* how versioning and rotation work, and what a `KeyId` naming a retired
  version does;
* whether an authority key is per backend key, per tenant, or per keyset.

The glossary term lands with the implementation rather than here, so
`CONTEXT.md` keeps describing what the crate actually does.

## This is the first source whose KeyId is a descriptor

`KeyCustody` (CIP-4980) says whether a `KeyId` is wrapped key material or a
reference the backend resolves. Every source in the
crate today is `ClientHeld`: the bytes are the data key under encryption.

An authority-key source is the first `BackendHeld` one. Its `KeyId` is
`(version, salt)` — a descriptor that carries no key material and is useless
without the authority key, which the backend still holds wrapped. Losing the
`KeyId` loses the value; losing the cache costs a round trip and nothing more.

## Auditing and material in memory

`CachingKeyProvider` takes a position we are now inverting, and it should be
restated rather than quietly dropped. Its documentation says that against a
bound backend every retrieval is an authorization decision the backend logs, so
a cache hit skips the round trip *and* the audit entry, and therefore to "opt in
deliberately; never a default — a deployment that relies on per-retrieval
auditing must not wrap its provider in this."

An authority-key source has the same property one tier up, and makes it the
normal path. Two consequences follow, and both are deliberate:

* **Per-value retrieval is no longer per-value authorization.** The backend
  authorizes the authority key once per refresh. A deployment that needs an
  audit record per value must use a fan-out source, and the type should say so
  where a reader will find it.
* **Plaintext key material lives longer.** Today an adapter fetches, uses and
  drops. A cached authority key sits in memory for its TTL and can mint any
  data key in its scope while it does. It must be `Protected`, it must zeroize
  on eviction and expiry, and the TTL is a security control rather than a
  memory one — which is the opposite of how `CachingKeyProvider` documents its
  own bounds.

## Consequences

* `pooled_key_generate`, `PooledDataKeySource`, `AwsPooledDataKeySource`,
  `AzurePooledDataKeySource` and `GcpPooledDataKeySource` are gone (CIP-4981).
  Nothing replaces them one-for-one: callers that wanted fewer round trips get an authority-key
  source, and callers that wanted per-value isolation already had
  `fan_out_generate`.
* `KeyIsolation` loses `Pooled`, and probably loses its reason to exist.
* A backend can support this only if it can wrap and unwrap a key we hold in
  plaintext. All four vendors can.
* The KDF, the salt width and the `KeyId` encoding become a wire format, and
  need the same canonical treatment as ADR 0002 gave signatures.

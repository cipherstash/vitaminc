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
`AuthorityKeySource` (feature `authority-keys`) implements this. ADR 0008
records the KDF, the salt and the `KeyId` bytes.

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

The cost is that retrieval cannot detect a wrong binding. It returns a key,
and that key opens nothing. The consumer's AEAD reports the failure, as it
does for any wrong key. This is the one source where a wrong binding is not
an error from the provider, and its documentation says so.

## Isolation is the wrong axis for this

`KeyIsolation` said whether a batch holds one key per value or one key shared
across it. A source built this way delivers one key per value. What differs
from `fan_out_generate` is not isolation but how many round trips it makes and
what it keeps in memory.

The constant bundles three properties that only move together because
clone-one-key makes them:

| | clone-one-key | authority key |
| --- | --- | --- |
| keys per batch | one, shared | one per value |
| backend round trips | one | one per cache refresh |
| binding possible | no | yes |

So the capability belongs on its own trait, not as a third `KeyIsolation`
variant. A source that can mint locally from cached authority material says so
by implementing `DerivesFromAuthorityKey`, and cache policy is configuration
on it: `AuthorityKeyCachePolicy` holds the TTL and the entry capacity, and the
refresh behaviour under load is fixed (concurrent misses share one fetch).
Hanging strategies off `KeyIsolation` would re-bundle exactly what this design
separates.

Nothing implemented `Pooled`, so the variant went (CIP-5062). That left an
enum with one value, which tells a reader nothing, so `KeyIsolation` and every
`ISOLATION` constant went too. No consumer read them.

## The authority key is a new kind of key

`CONTEXT.md` knew two tiers: a **backend key**, held by the vendor and bound
at construction, and a **data key**, minted or retrieved for the caller. An
authority key is a third, between them, and it is unlike both: the backend
wraps it, the client holds it in plaintext while it is cached, and it mints
many data keys.

**What it is.** An authority key is a 32-byte data key of an ordinary inner
`KeyProvider` (any vendor source, or ZeroKMS), minted under a fixed binding
that names its version (ADR 0008). So no backend needs a new primitive, and
the backend binds and authorizes the authority key as it does any data key.

**Where the store lives.** In the deployment's configuration, not in this
crate and not in a service. `AuthorityKeySource::provision` mints a version
once and returns its wrapped id. The deployment persists that id, exactly as
it persists the index key id of a `FixedIndexKeySource`, and builds an
`AuthorityKeys` from its configuration: one wrapped id per version, and the
version that is current. We do not build a key store like AWS's DynamoDB
branch-key store. A map that the deployment already knows how to keep is
enough, and a service would be one more thing to secure.

**Versioning and rotation.** New data keys use the current version, and each
`KeyId` names the version it was derived under. To rotate, the deployment
provisions a new version, adds it, and makes it current. Earlier versions
stay for retrieval. A `KeyId` that names a version the deployment does not
hold is a typed error, `UnknownVersion`. A version can go only when no
stored `KeyId` names it. Rotation of the backend key under an authority key
is the backend's business, as for any wrapped data key.

**Scope.** One `AuthorityKeySource` holds the authority keys of one inner
provider, which is bound to one backend key. Per tenant or per keyset is a
deployment choice: build one source per tenant, each with its own
`AuthorityKeys`. The crate does not decide it.

## This is the first source whose KeyId is a descriptor

`KeyCustody` (CIP-4980) says whether a `KeyId` is wrapped key material or a
reference the backend resolves. Every vendor source in the
crate is `ClientHeld`: the bytes are the data key under encryption.

An authority-key source is the first `BackendHeld` one. Its `KeyId` is
`(version, salt)` — a descriptor that carries no key material and is useless
without the authority key, which only the backend can unwrap. Losing the
`KeyId` loses the value; losing the cache costs a round trip and nothing more.
The storage obligation moves to the authority key: losing the wrapped id of a
version loses every value derived under it.

Its `KeyReconstruction` is the inner provider's. A data key is recoverable
exactly when its authority key is, and the inner provider decides that.

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

Both are now stated where a reader finds them: on `AuthorityKeySource`, on
`DerivesFromAuthorityKey`, on `AuthorityKeyCachePolicy`, and on
`CachingKeyProvider`, which points to the authority-key source as the same
trade one tier up. The cached authority key is `Protected` and zeroizes when
it leaves the cache. The cache has no background task, so an expired key
leaves memory at the next maintenance, or when the deployment calls
`purge_expired`, as for `CachingKeyProvider`.

## Consequences

* `pooled_key_generate`, `PooledDataKeySource`, `AwsPooledDataKeySource`,
  `AzurePooledDataKeySource` and `GcpPooledDataKeySource` are gone (CIP-4981).
  Nothing replaces them one-for-one: callers that wanted fewer round trips get an authority-key
  source, and callers that wanted per-value isolation already had
  `fan_out_generate`.
* `KeyIsolation` and its `ISOLATION` constants are removed (CIP-5062).
* A backend can support this only if it can wrap and unwrap a key we hold in
  plaintext. All four vendors can, because the authority key is one of their
  own data keys.
* The KDF, the salt width and the `KeyId` encoding are a wire format. ADR 0008
  records them, with known-answer vectors.
* An empty batch makes no backend call, and does not fetch or refresh an
  authority key.

# Two of the four vendor sources bind their bytes, and two cannot

ADR 0003 gave every key provider a `Binding` and a `BindingSupport` constant,
left all four vendor data key sources `Unbound`, and said the work of binding
them needed its own migration answer. This is that work, and the answer is not
the one ADR 0003 assumed: it said AWS KMS, Google Cloud KMS and Azure Key
Vault "each have a mechanism that could carry the same bytes". Two do. Azure's
does not reach the path a data key actually takes.

## Decision

**AWS KMS and Google Cloud KMS bind; Azure Key Vault and Vault Transit do
not.** `BINDING` is now declared on `RetrieveDataKey` — beside
`RECONSTRUCTION`, and forwarded to `KeyProvider` the way `RECONSTRUCTION` and
`ISOLATION` already were, rather than hardcoded in the adapter macro. Whether
a source binds is the source's own property, not the adapter's.

Every capability trait now carries the binding: `generate_data_key`,
`retrieve_data_key` and both batch forms. A source that cannot bind names the
parameter `_binding` and says why on its `BINDING` constant.

**AWS** sends the binding as an `EncryptionContext` entry under one fixed key,
base64-encoded because AWS requires printable strings and a binding is
arbitrary bytes. **Google** sends it as additional authenticated data,
checksummed like the plaintext.

**Azure cannot.** A data key here is *wrapped*, not AEAD-encrypted:
`wrapKey`/`unwrapKey` take `RSA-OAEP-256` or `A256KW`, and neither algorithm
has a place to put additional authenticated data — Key Vault accepts `aad`
only on the AES-GCM `encrypt`/`decrypt` operations. Binding would mean moving
the data-key path onto those, which changes the `KeyId` envelope (it would
gain an IV and tag) and works only for an `oct-HSM` key. Support would then
depend on a *runtime* key kind, and an associated constant cannot; an RSA
vault could never bind at all.

**Vault cannot**, for the same shape of reason. Transit's only
binding-shaped input is the derivation `context`, which exists only on a key
created with `derived=true`. Honouring the binding would mean requiring a
derived key — rejecting deployments whose Transit key is not one — and
derivation is again a property of the backend key, discovered at runtime.

We rejected "support both, and let `BINDING` follow the key" for both
backends: it would make binding support a runtime value, which defeats the
compile-time assertion that is the constant's whole purpose.

## An empty binding sends nothing

`Binding::EMPTY` means "nothing to bind", and the faithful encoding of that is
an *absent* encryption context or *absent* AAD, not an empty one. This also
means a caller that never passes a binding sends exactly what it always sent,
so only callers who actually bind see any change on the wire.

## Pooling gives up binding

`PooledDataKeySource` is always `Unbound`, whatever it wraps. One key shared
across a batch cannot carry the batch's several bindings, and binding it to
the first would make every other item in the batch unretrievable. The wrapper
therefore drops the binding on *both* sides — it mints under `Binding::EMPTY`
and retrieves under `Binding::EMPTY`, so the two halves agree — and declares
`Unbound` so a caller cannot trust a binding that was never sent.

Wrapping a `Bound` source does not produce a bound pool. Pooling is a choice
against binding as well as against per-value key isolation.

## Migration: none, and the break is deliberate

A key minted by a released version of one of these sources was never bound to
anything, so it cannot be retrieved once the source binds — AWS refuses a
`Decrypt` whose `EncryptionContext` differs, and Google refuses a `decrypt`
whose AAD differs.

We chose to flip outright and call it breaking, rather than fall back to an
unbound retrieval or hide the flip behind a builder. A retrieval that silently
retries without the binding would weaken the guarantee exactly when it
matters and would have to be removed later anyway; an opt-in builder would
make `BINDING` a runtime value, which is the thing this design exists to
avoid.

Concretely: **data keys minted by `AwsDataKeySource` or `GcpDataKeySource`
before this change are unretrievable after it, unless they were minted under
`Binding::EMPTY`** — which is the case for every caller that never passed a
binding, since an empty binding sends no context either way. A deployment that
did pass bindings must re-mint.

## Consequences

- `dedup_retrieve` keys on the whole `(KeyId, Binding)` pair. A `Bound`
  backend answers the same id differently under different bindings — one of
  them by refusing — so deduping on the id alone would hand one item a key it
  never asked for. This is the caching consequence ADR 0003 predicted,
  arriving in the batch helper rather than in a cache.
- `Binding` and `BindingSupport` moved from `provider` to `data_key`, beside
  the traits that now take and declare them, and are re-exported from
  `provider` so its public surface is unchanged.
- `load_index_key` retrieves under `Binding::EMPTY`. An index key is one per
  backend key rather than one per value, so it has no context to bind, and the
  provisioning call whose result it loads has none either.
- The direct `EncryptWithKey`/`DecryptWithKey` paths bind nothing. They are
  not the data-key path and carry no caller context.

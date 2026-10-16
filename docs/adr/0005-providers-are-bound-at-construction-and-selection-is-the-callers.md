# Key providers are bound to one backend key at construction, and selecting between them is the caller's business

Vitamin C is a general-purpose cryptography suite. Its first consumer,
CipherStash's Stack Encrypt, groups keys into keysets and picks one per
operation: a client holds many, and a stored value names the keyset it was
sealed under. It was proposed that `vitaminc-kms` gain a factory that turns a
keyset identifier into a key provider, so that the consumer could ask this
crate for the right provider on each call.

We decided that it does not. A key provider is bound to one backend key at
construction and has no per-call selector. A consumer that holds more than one
keeps its own registry, and hands each provider whatever identity it needs. A
keyset is a CipherStash concept, so "keyset" may appear in this crate's prose
only as an example of a backend key — beside an AWS key ARN or a Vault transit
key name — and never in a definition or a signature.

This costs the consumer nothing, which is why the boundary is worth holding.
ZeroKMS's own protocol carries the keyset id **once per request**, not per
payload, and the server resolves it to a single authority key for the whole
batch. A client that holds many keysets therefore already issues one request
per keyset. A provider bound at construction is a faithful model of that wire
protocol rather than a restriction laid on top of it.

The alternative was a generic factory trait parameterised over an opaque
handle, so that this crate could support selection without ever saying
"keyset". We rejected it. It would have exactly one implementor; it would drag
resolution caching, name lookup and provider lifetimes into a crate that has
no use for any of them; and it would re-admit the per-call selector that the
data-key traits promise does not exist, keeping the boundary only by avoiding
a word.

## Consequences

- Nothing in this crate's API names a keyset, a tenant or a workspace.
- A consumer that needs many owns the registry, its cache and its eviction
  policy — and gets one implementation of them that every backend inherits,
  rather than one per backend.
- A deployment's keyset on a vendor backend is already expressible here:
  `FixedIndexKeySource<T>` pairs a provider with the one persisted index-key
  `KeyId`, which is what such a keyset is.
- If a backend ever appears whose keys genuinely cannot be selected at
  construction, this is the decision to revisit.

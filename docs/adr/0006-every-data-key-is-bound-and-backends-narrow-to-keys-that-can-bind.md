# Every data key is bound, and backends narrow to the keys that can bind

ADR 0004 gives every key provider a `Binding` per key. This ADR records that
binding is mandatory for every data key source, and what each backend gives
up so that it can bind.

A key that is not bound to its context is not committed to it. A caller that
passes a binding and gets a key back believes the key is tied to that
binding. If the source ignored the binding, the caller has no server-side
check, and nothing in the code tells it so. That violates misuse resistance
in nearly every case. So a configuration that cannot bind loses the
data-key capability, rather than accepting a binding and dropping it.

## Decision

**Every data key source binds.** Every capability trait carries the binding:
`generate_data_key`, `retrieve_data_key` and both batch forms. Every source
sends it to its backend on both sides, and the backend refuses a retrieval
under a different binding. No source declares whether it binds, because all
of them do.

**AWS KMS** sends the binding as an `EncryptionContext` entry under one fixed
key. The value is base64, because AWS requires printable strings and a
binding is arbitrary bytes.

**Google Cloud KMS** sends the binding as additional authenticated data, with
a checksum like the plaintext.

**Azure narrows to `oct-HSM` keys, which means Managed HSM.** Key Vault takes
additional authenticated data only on `A256GCM` `encrypt` and `decrypt`.
`wrapKey` and `unwrapKey` take none, with either `RSA-OAEP-256` or `A256KW`.
So the data-key path moves from `wrapKey` to `A256GCM` `encrypt`, and the
binding is its `aad`. The `KeyId` envelope carries the IV and the tag beside
the key id and the ciphertext. Only an `oct-HSM` key does `A256GCM`, so:

- RSA keys can no longer back a data key source, and the RSA path goes.
- `oct-HSM` keys are production-ready on Managed HSM only. They are in
  preview on Key Vault Premium, and Standard Key Vault has none.
- Lowkey Vault, the emulator the other Azure adapters test against, rejects
  `A256GCM`. The only Azure data-key path is therefore covered by
  stub-transport unit tests only, and no emulator covers it. CIP-4072 tracks
  that gap.

**Vault narrows to `derived=true` Transit keys.** Transit's only input that
can carry a binding is the derivation `context`. A derived key derives a key
from the Transit key and the context, so a retrieval under another context
derives another key and fails. A key that is not derived accepts a context
and silently ignores it. So:

- The source's constructor reads the key's metadata (`GET
  <mount>/keys/<name>`) and refuses a key that is not derived. That costs one
  round trip per source, and the token needs `read` on that path. We chose
  the check over a documented requirement, because a key that is not derived
  fails silently, not loudly.
- A derived key refuses an empty context. So the context is one tag byte
  and then the binding bytes. `Binding::EMPTY` still gives a non-empty
  context, and the encoding stays one-to-one. Direct encryption, which has
  no binding, sends a fixed context with a different tag byte, so a direct
  ciphertext never opens as a data key.
- The Enterprise `datakeys` endpoint takes one context for the batch. The
  source uses it only when every key in the batch has the same binding, and
  fans out otherwise.
- A MAC key needs a Transit key that is *not* derived, because its trait
  carries no context. One Transit key can no longer back both a data key
  source and a MAC key.

We rejected "support both, and let the key decide" for Azure and Vault. A
source that binds on some keys and not on others gives the caller no way to
know which one it has, and that is the misuse this decision removes.

## An empty binding sends nothing

For AWS, Google and Azure, `Binding::EMPTY` is sent as an *absent*
encryption context, AAD or `aad`, not an empty one. The backends authenticate
the two the same way, and a caller with nothing to bind sends exactly what
the backend sends by default. Vault cannot send nothing, so it sends the tag
byte alone, as above. `Binding::EMPTY` is still a binding everywhere: a key
minted under it comes back only under it.

## Pooling goes

A pooled source cloned one key across a batch. One key cannot carry a batch's
several bindings, so every pooled source ignored the binding.
`pooled_key_generate`, `PooledDataKeySource` and the three vendor pooled
sources are removed. ADR 0007 records how to keep the round-trip saving
without sharing a data key.

## Migration: none

No data key source in this crate has shipped. Nothing was minted under the
behaviour this replaces, so nothing needs a migration.

## Consequences

- `dedup_retrieve` keys on the whole `(KeyId, Binding)` pair. A backend
  answers the same id differently under different bindings — one of them by
  refusing — so deduping on the id alone would hand one item a key it never
  asked for. This is the caching consequence ADR 0004 predicts, arriving in
  the batch helper rather than in a cache.
- `load_index_key` retrieves under `Binding::EMPTY`. An index key is one per
  backend key rather than one per value, so it has no context to bind, and
  the provisioning call whose result it loads has none either.
- The direct `EncryptWithKey`/`DecryptWithKey` paths bind nothing. They are
  not the data-key path and carry no caller context. On Vault they send one
  fixed derivation context, because a derived key refuses a call with none.

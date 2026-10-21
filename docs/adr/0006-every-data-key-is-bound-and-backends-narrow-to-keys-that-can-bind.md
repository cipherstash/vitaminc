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
binding is arbitrary bytes. A second entry names the use (see "Data keys and
direct ciphertexts are domain-separated").

**Google Cloud KMS** sends the binding, after one tag byte, as additional
authenticated data, with a checksum like the plaintext.

**Azure narrows to `oct-HSM` keys, which means Managed HSM.** Key Vault takes
additional authenticated data only on `A256GCM` `encrypt` and `decrypt`.
`wrapKey` and `unwrapKey` take none, with either `RSA-OAEP-256` or `A256KW`.
So the data-key path moves from `wrapKey` to `A256GCM` `encrypt`, and the
binding, after one tag byte, is its `aad`. The `KeyId` envelope carries the IV and the tag beside
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
  ciphertext never opens as a data key. Google and Azure now use the same
  encoding (see below).
- The Enterprise `datakeys` endpoint takes one context for the batch. The
  source uses it only when every key in the batch has the same binding, and
  fans out otherwise.
- A MAC key needs a Transit key that is *not* derived, because its trait
  carries no context. One Transit key can no longer back both a data key
  source and a MAC key.

We rejected "support both, and let the key decide" for Azure and Vault. A
source that binds on some keys and not on others gives the caller no way to
know which one it has, and that is the misuse this decision removes.

## Data keys and direct ciphertexts are domain-separated

Every vendor data key source also implements `EncryptWithKey` and
`DecryptWithKey` under the same backend key. The two uses must not open each
other's ciphertexts. A direct ciphertext must not open as a data key under
any binding, and a data key's `KeyId` must not open through `decrypt`.

The attack this stops (CIP-5094) is against the index key. The index key is
a data key under `Binding::EMPTY` (`FixedIndexKeySource`, `load_index_key`).
An earlier version of this ADR sent `Binding::EMPTY` to AWS, Google and Azure
as an *absent* encryption context, AAD or `aad`, and direct encryption sent
none either. So the two uses sent the same request, and:

- A caller that may use `decrypt` and can read the index `KeyId` got the
  index key in plaintext.
- A caller that can write a stored `KeyId` could put a direct ciphertext of
  `N` bytes there, and so choose a data key.

So each source now marks the use in what it binds, and no binding can give
the bytes of the other use. Vault already did this, because a derived key
refuses an empty context.

| Backend | Use | What the backend binds |
|---|---|---|
| AWS KMS | data key, `Binding::EMPTY` | `EncryptionContext` `{"vitaminc:use": "data-key"}` |
| AWS KMS | data key, other binding | `EncryptionContext` `{"vitaminc:use": "data-key", "vitaminc:binding": base64(binding)}` |
| AWS KMS | direct `Encrypt`/`Decrypt` | `EncryptionContext` `{"vitaminc:use": "encrypt-with-key"}` |
| Google Cloud KMS | data key | AAD `0x01 ‖ binding` (`0x01` alone for `Binding::EMPTY`) |
| Google Cloud KMS | direct `encrypt`/`decrypt` | AAD `0x00 ‖ "vitaminc-kms/gcp/encrypt-with-key"` |
| Azure Managed HSM | data key | `A256GCM` `aad` `0x01 ‖ binding` (`0x01` alone for `Binding::EMPTY`) |
| Azure Managed HSM | direct `encrypt`/`decrypt` | `A256GCM` `aad` `0x00 ‖ "vitaminc-kms/azure/encrypt-with-key"` |
| Vault Transit | data key | derivation `context` base64(`0x01 ‖ binding`) |
| Vault Transit | direct `encrypt`/`decrypt` | derivation `context` base64(`0x00 ‖ "vitaminc-kms/vault/encrypt-with-key"`) |

`‖` is concatenation. The base64 is standard and padded.

For Google, Azure and Vault, the first byte is the use. A data key's bytes
start with `0x01` and a direct ciphertext's start with `0x00`, so the two
sets of bytes never meet. Within data keys the encoding is one-to-one: two
bindings give the same bytes only if they are the same binding. The bytes
are never empty, so an empty `aad` or context is never sent. Vault needs
that, because a derived key refuses an empty context.

AWS matches the `EncryptionContext` as a whole map, and a `Decrypt` must
send the same map as the `GenerateDataKey` or `Encrypt` did. The
`"vitaminc:use"` entry differs between the two uses, so AWS refuses a
swapped blob with `InvalidCiphertextException`. An empty binding adds no
`"vitaminc:binding"` entry, but the use entry is always there, so no call
sends an empty context.

An `EncryptionContext` is not secret: AWS writes it to CloudTrail in
plaintext. The `"vitaminc:use"` entry tells a reader only which of the two
uses a call was. The binding entry was already there.

`Binding::EMPTY` is a binding like any other on every backend: a key minted
under it comes back only under it.

## Pooling goes

A pooled source cloned one key across a batch. One key cannot carry a batch's
several bindings, so every pooled source ignored the binding.
`pooled_key_generate`, `PooledDataKeySource` and the three vendor pooled
sources are removed. ADR 0007 records how to keep the round-trip saving
without sharing a data key.

## Migration: none

No data key source in this crate has shipped. Nothing was minted under the
behaviour this replaces, so nothing needs a migration. That includes the
domain separation above: it changes the wire format of the AWS, Google and
Azure data key sources, and none of them has shipped. `AwsKmsHmac`, which has
shipped, is a MAC and does not change.

## Consequences

- `dedup_retrieve` keys on the whole `(KeyId, Binding)` pair. A backend
  answers the same id differently under different bindings — one of them by
  refusing — so deduping on the id alone would hand one item a key it never
  asked for. This is the caching consequence ADR 0004 predicts, arriving in
  the batch helper rather than in a cache.
- `load_index_key` retrieves under `Binding::EMPTY`. An index key is one per
  backend key rather than one per value, so it has no context to bind, and
  the provisioning call whose result it loads has none either.
- The direct `EncryptWithKey`/`DecryptWithKey` paths carry no caller
  context. Each sends one fixed value that names the use, as in the table
  above, so a direct ciphertext never opens as a data key. A new source that
  implements both traits must do the same.

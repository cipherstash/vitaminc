# A key provider takes a binding per key

A data key is minted for one value in one place, and a caller wants that
context tied to the key, so that a key cannot open a different value. ZeroKMS
does this already. It binds the caller's descriptor into the key server-side
and logs it on every retrieval, so a retrieval under a different descriptor
fails at the service. Each vendor backend has a mechanism that can carry the
same bytes: an AWS KMS `EncryptionContext`, Google Cloud KMS additional
authenticated data, the `aad` of an Azure `A256GCM` operation, and the
derivation `context` of a derived Vault Transit key.

We decided that `generate_keys` and `retrieve_keys` take a `Binding` per key,
and that every provider binds those bytes into the key. A retrieval under a
binding other than the one the key was minted with fails. There is no
provider that accepts a binding and ignores it. ADR 0006 records why, and what
two of the backends give up so that they can bind.

The alternative was to leave binding out of the trait, and let each caller's
own authenticated data be the only tie between a key and its context. That
would have put ZeroKMS's server-side enforcement and its per-retrieval audit
entry out of reach of the trait, and made ZeroKMS a special case rather than
one backend among several.

## Consequences

- `Binding` is a newtype rather than a bare `&[u8]`, so a plaintext or a key
  id cannot be passed where a binding belongs.
- A provider does not declare whether it binds, because every provider does.
  An earlier draft of this ADR gave each provider a `BindingSupport` constant,
  `Bound` or `Unbound`. An `Unbound` provider silently ignored a non-empty
  binding. That is a misuse the type system let a caller write without
  knowing it, so the constant was removed before it shipped (CIP-4981).
- `Binding::EMPTY` is still a binding. A key minted under it comes back only
  under it.
- A binding is not secret. Each backend receives it in the request, and some
  record it (AWS writes the `EncryptionContext` to CloudTrail, and ZeroKMS
  logs the descriptor). Callers must not put secret data in a binding.
- A cache in front of a provider must key on the binding as well as the key
  id. An id alone is not the question the caller asked, and a hit on it could
  hand back a key the backend would have refused.

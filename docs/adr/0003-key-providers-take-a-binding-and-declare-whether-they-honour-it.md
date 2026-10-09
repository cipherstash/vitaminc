# A key provider takes a binding per key, and declares whether it honours it

A data key is minted for one value in one place, and a caller wants that
context tied to the key, so that a key cannot open a different value. The
backends disagree about whether they can do this. ZeroKMS binds the caller's
descriptor into the key server-side and logs it on every retrieval, so a
retrieval under a different descriptor fails at the service. AWS KMS, Google
Cloud KMS and Azure Key Vault each have a mechanism that could carry the same
bytes — `EncryptionContext`, additional authenticated data, and the AEAD `aad`
parameter — but the adapters do not use them yet, and a non-derived Vault
Transit key has nothing to bind with at all. A trait that hid this difference
would let a caller believe it had server-side enforcement when it had none.

We decided that `generate_keys` and `retrieve_keys` take a `Binding` per key,
and that every provider declares a `BindingSupport` constant saying whether it
binds those bytes (`Bound`) or ignores them (`Unbound`). ZeroKMS is `Bound`.
The four vendor data key sources are `Unbound` today. An `Unbound` provider
never errors on a non-empty binding; it simply does not enforce it, and says
so. The alternative was to leave binding out of the trait and let each
caller's own authenticated data be the only tie between a key and its context.
That would have put ZeroKMS's server-side enforcement and its per-retrieval
audit entry out of reach of the trait, and made ZeroKMS a special case rather
than one backend among several.

## Consequences

- `Binding` is a newtype rather than a bare `&[u8]`, so a plaintext or a key
  id cannot be passed where a binding belongs.
- `BINDING` is an associated constant, fixed per provider type, so a
  deployment that requires server-side binding can assert on it at compile
  time. Consumers do not gate on it; the policy belongs to the deployment.
- Because callers may assert on it, moving a vendor source from `Unbound` to
  `Bound` is an observable change, and keys minted while it was `Unbound`
  cannot later be retrieved under a binding the backend now enforces. That
  work needs its own migration answer.
- A cache in front of a provider must key on the binding as well as the key
  id. An id alone is not the question the caller asked, and a hit on it could
  hand back a key the backend would have refused.

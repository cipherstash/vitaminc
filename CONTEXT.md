# Vitamin C

A Rust framework of small, misuse-resistant cryptography crates. The KMS
terms below describe how `vitaminc-kms` uses a vendor key service as a key
provider.

## Language

### KMS

**Backend**:
A vendor key service that holds keys and performs cryptographic operations
on them (AWS KMS, Azure Key Vault or Managed HSM, HashiCorp Vault Transit,
Google Cloud KMS).
_Avoid_: Vendor, provider, KMS (as a noun for one service)

**Backend key**:
The one key, or the one set of keys a backend manages as a unit, that an
adapter is bound to at construction (a key ARN, a Key Vault key name, a
Transit key name, a `CryptoKey`, a ZeroKMS keyset). Whether the backend
implements it as a single key or as a set is the backend's business, and
not something an adapter or a caller can see.
_Avoid_: Master key, KEK, root key

**Adapter**:
A Rust type that implements one or more capability traits against one
backend key. There is one adapter type per key purpose per backend.
_Avoid_: Client, backend (for the Rust type), implementation, Group 2
(design-ticket jargon for the capability traits)

**Key purpose**:
The class of operations a backend key can perform, fixed when the key is
created: data-key (which includes direct encrypt and decrypt), MAC, or
signing. On Vault Transit, one key can serve both MAC and signing. A
data-key purpose needs a `derived=true` Transit key, and MAC needs a key
that is not derived, so no Transit key serves data keys and another purpose.
_Avoid_: Key usage, key type (which names the algorithm, not the purpose)

**Signing key**:
An adapter over a backend key whose purpose is signing. It signs, verifies
a signature, and returns the public key. A signing key takes a digest
(`Sign`) or the whole message (`SignMessage`, for Ed25519), never both:
the scheme sets which. The digest schemes share one adapter type per
backend, and Ed25519 has its own.

**MAC key**:
An adapter over a backend key whose purpose is MAC. It generates and
verifies HMAC tags.

**Data key source**:
An adapter that implements the data-key capability traits (generate and
retrieve).

**Key provider**:
The consumer-facing shape built on top of a data key source or a service
like ZeroKMS: batches of data keys, each under a binding, plus the index
key, against one backend key bound at construction. It is what Stack
Encrypt is generic over.
_Avoid_: Group 1 (design-ticket jargon), backend

**Binding**:
Bytes a caller attaches to a data key when it is minted and must present
again to retrieve it. Every data key source binds it into the key
server-side, so a retrieval under a different binding fails. A backend key
that cannot bind cannot back a data key source. Stack Encrypt's descriptor
is a binding.
_Avoid_: context (overloaded), AAD (one vendor's mechanism)

**Data key**:
Key material that a data key source mints or retrieves for a caller to use
locally.
_Avoid_: DEK, plaintext key, wrapped key (for the material itself)

**KeyId**:
The opaque, backend-encoded handle that retrieves one data key. Each
backend chooses its own encoding. What the handle *is* — wrapped key
material, or a reference the backend resolves — is its key custody.
_Avoid_: Ciphertext blob, token. Also "wrapped key" for the handle itself:
that names what a client-held handle contains, not the handle.

**Key custody**:
Whether a KeyId is the data key in wrapped form, which the caller holds and
the backend keeps no copy of, or a reference the backend resolves from
material it holds. Every vendor backend is the first, ZeroKMS the second. A
client-held handle is the only copy of its key, so losing it loses the data
the key sealed.
_Avoid_: Key ownership, key location

**Key isolation**:
Whether a batch of data keys holds one distinct key per value or one key
shared across the batch.

**Key reconstruction**:
Whether a backend can rebuild a data key from server-side material alone,
or needs material the client holds as well.

**Index key**:
A fixed, deterministic key, one per backend key, that a caller uses
locally to derive search-index terms. Never used as a data key.

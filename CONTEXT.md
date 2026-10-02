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
The single key a backend holds and that an adapter is bound to at
construction (a key ARN, a Key Vault key name, a Transit key name, a
`CryptoKey`).
_Avoid_: Master key, KEK, root key, keyset

**Adapter**:
A Rust type that implements one or more capability traits against one
backend key. There is one adapter type per key purpose per backend.
_Avoid_: Client, backend (for the Rust type), implementation

**Key purpose**:
The class of operations a backend key can perform, fixed when the key is
created: data-key (which includes direct encrypt and decrypt), MAC, or
signing. Vault Transit is the one backend where a key can serve more than
one purpose.
_Avoid_: Key usage, key type (which names the algorithm, not the purpose)

**Signing key**:
An adapter over a backend key whose purpose is signing. It signs a digest,
verifies a signature, and returns the public key.

**MAC key**:
An adapter over a backend key whose purpose is MAC. It generates and
verifies HMAC tags.

**Data key source**:
An adapter that implements the data-key capability traits (generate and
retrieve).

**Data key**:
Key material that a data key source mints or retrieves for a caller to use
locally.
_Avoid_: DEK, plaintext key, wrapped key (for the material itself)

**KeyId**:
The opaque, backend-encoded handle that retrieves one data key. Each
backend chooses its own encoding.
_Avoid_: Ciphertext blob, wrapped key, token

**Key isolation**:
Whether a batch of data keys holds one distinct key per value or one key
shared across the batch.

**Key reconstruction**:
Whether a backend can rebuild a data key from server-side material alone,
or needs material the client holds as well.

**Index key**:
A fixed, deterministic per-keyset key that a caller uses locally to derive
search-index terms. Never used as a data key.

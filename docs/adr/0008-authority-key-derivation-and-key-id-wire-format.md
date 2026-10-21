# Authority-key derivation and KeyId wire format

ADR 0007 makes `AuthorityKeySource` derive each data key from a cached
authority key. A caller stores the `KeyId` that it hands back, and a later
process derives the same key from it. So the derivation and the `KeyId`
bytes are a wire format, like the signature encodings of ADR 0002. This ADR
records that format. A change to any of it is a new format byte (for the
`KeyId`) or a new label (for the derivation), never an edit in place.

All integers are unsigned and big-endian. `||` is concatenation.

## The authority key

An authority key is 32 bytes. The inner `KeyProvider<32>` mints it once per
version, and unwraps it on each cache refresh, under this binding:

```
authority binding = "vitaminc-kms/authority-key/v1" || u32(version)
```

The label is 29 ASCII bytes with no terminator, so the binding is always
33 bytes. The binding is not `Binding::EMPTY` and is not a caller's binding.
So a value's data key, or the index key, cannot be an authority key, and
the wrapped id of one version does not unwrap as another version on a
backend that binds (all of them, ADR 0006).

The deployment stores one wrapped id per version, which is the inner
provider's own `KeyId` and has that provider's format.

## The data key

For each value, the source takes 16 bytes from `vitaminc-random`'s
`SafeRand` as the salt, and derives an `N`-byte data key with HKDF-SHA256
(RFC 5869):

```
PRK  = HKDF-Extract(salt = salt, IKM = authority key)
info = "vitaminc-kms/authority-key/v1/data-key"   (38 ASCII bytes)
       || u32(version)
       || u16(N)
       || u64(len(binding))
       || binding
OKM  = HKDF-Expand(PRK, info, N)
```

* Every field of `info` except the binding has a fixed width, and the
  binding carries its length, so two different inputs never give the same
  `info`.
* The version is in `info`, so two versions that hold the same authority
  key still derive different data keys from the same salt.
* `N` is in `info`, so a 16-byte key is not the prefix of the 32-byte key
  for the same salt and binding. `N` is 1 to 8160 (255 blocks of 32 bytes),
  which a compile-time check enforces.
* The binding is an input, not a check. A different binding derives a
  different key. The source cannot detect a wrong binding, and does not try
  to: the key opens nothing, and the consumer's AEAD reports that.
* Every value that HKDF derives on the way to a data key is wiped when it
  is dropped. The PRK and each HKDF-Expand block are written straight into
  `Protected` memory. The HMAC states that take in the authority key and
  the PRK wipe on drop (`hmac` and `sha2` with `zeroize`). Only the hash
  function's own working memory is out of reach, the same as for every
  other HMAC in this workspace.

## The KeyId

```
KeyId = 0x01 || u32(version) || salt      (1 + 4 + 16 = 21 bytes)
```

`0x01` is the format byte. A `KeyId` carries no key material, so key
custody is `BackendHeld`: it is useless without the authority key of its
version.

Retrieval decodes and resolves the whole batch before it makes a backend
call:

* a `KeyId` that is not exactly 21 bytes, or whose first byte is not
  `0x01`, is `AuthorityKeyError::MalformedKeyId { position }`;
* a version that the deployment's `AuthorityKeys` does not hold is
  `AuthorityKeyError::UnknownVersion { position, version }`.

Neither one panics, and neither one costs a backend call.

## Known-answer vectors

The unit tests in `packages/kms/src/provider/authority_key.rs` pin these.
An independent HKDF-SHA256 (Python's `hmac` and `hashlib`) computed them.

Authority key `00 01 02 … 1f`, salt `a0 a1 a2 … af`:

| version | N | binding | data key |
|---|---|---|---|
| 1 | 32 | `users/email` | `07d8cd3caa4ae196ec3a44c83071db7a8ad46f8d291fa2cce78caa5060c8b248` |
| 1 | 32 | empty | `53b1023e582deafa9c737e82cabb35a8d3e300dc0f6ac74f1a1144b818877c05` |
| 2 | 32 | `users/email` | `3ed427e20193b3c58a1c28608d4dd61281c733be531775e06a23b24a74027542` |
| 1 | 16 | `users/email` | `081d4dac89ad5d0bb587f5b9ad5a75fd` |
| 1 | 64 | `users/email` | `17b1325a45d3e012f50fe0a1b34350dcde2d9cd3b573d797e6e9c415f46225d5d975e716e6b19eae4fbdb22998c06d01c3e50c8eddf5b4446afc58047d07d61d` |

Version `0x01020304`, salt `a0 … af`:

* `KeyId` = `01 01020304 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf`
* authority binding = `"vitaminc-kms/authority-key/v1" || 01020304`

## Why HKDF-SHA256

No crate in this workspace exposes a KDF. `vitaminc-hmac` is a structured
PRF with its own encoding and a fixed 32-byte output. HKDF is the standard
KDF for a uniformly random key and a random salt.

The source builds HKDF itself on `hmac` 0.13, not on RustCrypto's `hkdf`
crate. RFC 5869 is two HMAC steps, so the code is short. The `hkdf` crate
keeps the PRK and each expand block in plain arrays and drops them without
wiping them. For a 32-byte data key, the one expand block *is* the data
key. Our version writes each of these values into `Protected` memory, which
zeroizes on drop. The RFC 5869 SHA-256 test vectors (appendix A, cases 1 to
3) check it, together with the known answers above. It also adds no crate
to the tree. AWS's Hierarchical keyring uses a KDF in counter mode
with HMAC-SHA256 as the PRF (NIST SP 800-108) for the same job, as its
specification says (`aws-kms-hierarchical-keyring.md` in
`awslabs/aws-encryption-sdk-specification`). Its key store and
wrapping-key tier are not used here (ADR 0007), so there is no reason to match its primitive.

## Consequences

* A stored `KeyId` stays readable while the deployment keeps the wrapped
  authority key of its version, and the inner backend key can unwrap it.
* A new derivation or `KeyId` layout needs a new format byte and a new
  label, and retrieval must keep the old ones.

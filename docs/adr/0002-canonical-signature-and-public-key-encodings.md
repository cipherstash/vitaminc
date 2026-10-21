# Canonical encodings for signatures and public keys across KMS backends

The `Sign`, `Verify`, `SignMessage`, `VerifyMessage`, and `GetPublicKey` traits
in `vitaminc-kms` return bytes that callers persist and verify outside the
backend that produced them. The four backends disagree on encoding: AWS KMS and
Google Cloud KMS return ECDSA signatures as DER, Azure Key Vault returns raw
`r || s`, and Vault Transit prefixes its output with `vault:v1:` and offers DER
or JWS. Public keys come back as DER from AWS, PEM from Google and Vault, and as
JWK fields from Azure. Vault returns an Ed25519 public key as the raw 32 bytes
in base64, not as PEM.

We decided that the traits promise one canonical form, and each adapter
converts to and from it: ECDSA signatures in DER (ASN.1 `SEQUENCE` of `r` and
`s`), RSA signatures as the raw signature bytes, Ed25519 signatures as the raw
64 bytes of RFC 8032, and public keys as DER `SubjectPublicKeyInfo` (for
Ed25519, the RFC 8410 form: `id-Ed25519` with no parameters). The alternative,
passing each vendor's native form through and documenting it, would make a
stored signature or public key unreadable after a change of backend, which
defeats the purpose of a portable key-provider crate. The cost is a JWK-to-SPKI
encoder for Azure, a raw-to-SPKI encoder for Vault's Ed25519 keys, and prefix
handling for Vault, all inside the adapters.

## Ed25519 has its own traits

`Sign` and `Verify` take a digest that the caller computed. Pure Ed25519 signs
the message itself: the hash is part of the signature scheme. Google Cloud KMS
and Vault Transit, the two backends that offer Ed25519, have no pre-hashed mode
for it (Vault refuses `prehashed: true` on an `ed25519` key), and AWS KMS and
Azure Key Vault do not offer Ed25519. So Ed25519 cannot be a member of
`SignatureAlgorithm`, and it gets the `SignMessage` and `VerifyMessage` traits,
which take the whole message.

Ed25519 keys are their own adapter types (`GcpEd25519Key`, `VaultEd25519Key`),
not a second algorithm enum on the digest adapters. Each adapter type
implements one trait pair and not the other. So a digest cannot go to an
Ed25519 key, and a message cannot go to a digest key: the call does not
compile. An enum value would move that check to run time.

## Consequences

- A consumer can verify a signature produced under one backend with a public
  key fetched from another backend that holds the same key material.
- Adapters must reject, at construction, any algorithm whose vendor encoding
  they cannot convert.
- A scheme that signs a message, and not a digest, goes behind `SignMessage`
  with its own adapter type. It does not go into `SignatureAlgorithm`.

# Canonical encodings for signatures and public keys across KMS backends

The `Sign`, `Verify`, and `GetPublicKey` traits in `vitaminc-kms` return bytes
that callers persist and verify outside the backend that produced them. The
four backends disagree on encoding: AWS KMS and Google Cloud KMS return ECDSA
signatures as DER, Azure Key Vault returns raw `r || s`, and Vault Transit
prefixes its output with `vault:v1:` and offers DER or JWS. Public keys come
back as DER from AWS, PEM from Google and Vault, and as JWK fields from Azure.

We decided that the traits promise one canonical form, and each adapter
converts to and from it: ECDSA signatures in DER (ASN.1 `SEQUENCE` of `r` and
`s`), RSA signatures as the raw signature bytes, and public keys as DER
`SubjectPublicKeyInfo`. The alternative, passing each vendor's native form
through and documenting it, would make a stored signature or public key
unreadable after a change of backend, which defeats the purpose of a portable
key-provider crate. The cost is a JWK-to-SPKI encoder for Azure and prefix
handling for Vault, both inside the adapters.

## Consequences

- A consumer can verify a signature produced under one backend with a public
  key fetched from another backend that holds the same key material.
- Adapters must reject, at construction, any algorithm whose vendor encoding
  they cannot convert.

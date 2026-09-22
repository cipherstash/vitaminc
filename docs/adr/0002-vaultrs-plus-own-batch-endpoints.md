# Use `vaultrs` for Vault Transit, with our own definitions of the two batch endpoints it lacks

HashiCorp publishes no Rust client for Vault. The dominant community crate,
`vaultrs`, covers every single-item Transit operation the Vault adapter needs
but supports neither `POST /transit/datakeys/:type/:name` nor `batch_input`
on `decrypt`. Those two calls are the only native batch primitives any of the
four backends offer, and the adapter design commits to using them
(`KeyIsolation::PerValue` at one round trip).

We decided to depend on `vaultrs` for client configuration, authentication,
and single-item calls, and to define the two batch endpoints ourselves with
the same `rustify` endpoint macro `vaultrs` uses, executed through the
caller's `VaultClient`. The alternatives were a hand-written `reqwest` client
for the whole Transit surface, which would make us own auth and token
handling, or giving up native batch and falling back to fan-out, which would
make Vault no better than the vendors that have no batch call at all.

## Correction found during implementation

The plural `datakeys` endpoint is Vault Enterprise only. HashiCorp's API
reference does not mark it so, but Community Vault 2.1.0 answers it with
`404 unsupported path`, and the open-source Transit backend registers only
the singular `datakey` path. Batch `decrypt` with `batch_input` is in every
edition.

So batch retrieval is one round trip everywhere, and batch generation is one
round trip only on Enterprise. On Community the adapter pays one failed
probe, remembers the answer, and fans out one `datakey` call per key. The
security property is unchanged: per-value isolation either way. Only the
round-trip count depends on the edition. We kept the native endpoint rather
than dropping it because Enterprise users get the benefit for free and the
fallback costs Community users one extra request per adapter instance.

## Consequences

- The adapter honours the rule that the caller builds and authenticates the
  vendor client.
- `vaultrs` has effectively one maintainer. If it stalls, the two endpoint
  definitions show how to replace the rest with `rustify` or `reqwest`
  calls without changing the adapter's public surface.
- A consumer that needs one-round-trip batch generation on Vault needs
  Enterprise. The adapter does not expose which path it took.

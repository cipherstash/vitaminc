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

## Consequences

- The adapter honours the rule that the caller builds and authenticates the
  vendor client.
- `vaultrs` has effectively one maintainer. If it stalls, the two endpoint
  definitions show how to replace the rest with `rustify` or `reqwest`
  calls without changing the adapter's public surface.

# Dependency audits

This directory is [cargo-vet](https://mozilla.github.io/cargo-vet/)'s store.
`cargo vet` fails when a third-party crate version in `Cargo.lock` has
neither an audit nor an exemption, and CI runs it on every PR (`vet.yml`).
Nothing here is edited by hand except `audits.toml`'s criteria and the
`dependency-criteria` tables in `config.toml`; the tool rewrites the rest.

- `audits.toml`: audits we have recorded, and the `crypto-reviewed` criterion.
- `config.toml`: which registries we import, what each first-party crate
  requires of its dependencies, and the exemptions still outstanding.
- `imports.lock`: the imported audits as of the last `cargo vet` without
  `--locked`. Committed, so CI depends only on the tree.

## When a dependency PR fails `🔏 cargo vet`

The failure means a version moved and nobody has read the delta. Run, on the
PR's branch:

```sh
cargo vet                      # says which crate and versions need an audit
cargo vet diff <crate> <old> <new>   # the published tarballs, not git
```

Read the diff, then record it:

```sh
cargo vet certify <crate> <old> <new>
```

`certify` asks which criteria you are vouching for and opens an editor for
notes. Commit `supply-chain/` to the PR. The `who` field is you: an agent may
do the reading and draft the notes, but the entry is a person's word.

What to look for is the same list as the `crypto-reviewed` description in
`audits.toml`, plus for every crate: a new or changed `build.rs`, new
dependencies or features, anything that reads the environment, files, the
network or process arguments and is not explained by the changelog, and hunks
that do not map to an upstream PR.

## Criteria

- `safe-to-deploy` (built in): default for every normal dependency.
- `safe-to-run` (built in): default for dev-dependencies.
- `crypto-reviewed` (ours): required in addition for the crates the
  primitives are built on, as `dependency-criteria` on the first-party crate
  that depends on them. These are the same crates `dependabot.yml` keeps out
  of the grouped patch PR. Zcash's registry defines a criterion of the same
  name; it is deliberately not mapped to ours, since ours means a read by
  this team.
- `does-not-implement-crypto` (ours, same as Google's): implies
  `crypto-reviewed`. Criteria are transitive, so requiring `crypto-reviewed`
  of `aws-lc-rs` requires it of `cc` and `cmake` too; this is how a build
  script or proc macro answers that without a cryptographer. Google's audits
  under this name are imported as-is.

## Exemptions

`cargo vet init` exempted everything in the tree at the time; the imported
registries (Google, Mozilla, Bytecode Alliance, ISRG, Zcash) then covered a
third of it. The rest is debt, not approval. Burn it down from the top:

```sh
cargo vet suggest             # smallest set of audits that would clear exemptions
cargo vet certify <crate> <version>   # a full audit of one version
cargo vet prune               # drop exemptions the imports now cover
```

Start with the `crypto-reviewed` exemptions. Never add an exemption to make a
PR pass; that is what `certify` is for.

## Refreshing imports

```sh
cargo vet regenerate imports  # fetch the registries, update imports.lock
cargo vet prune
```

Do this in its own PR so the diff to `imports.lock` is reviewable on its own.
Adding a registry is a trust decision: their `safe-to-deploy` becomes ours.

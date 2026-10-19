# Claude Code Guidelines for vitaminc

## Principles

Vitamin C is a suite of crates for cryptography and handling sensitive data. These goals (from `README.md`) guide every design and code change. They describe where the project is heading, not what every crate does today: make each change move toward them, and check the code for the current state. When two goals conflict, call out the trade-off rather than silently picking one.

- **Misuse resistant**: make the secure path the easy path. Prefer types and APIs that make insecure code hard to write or fail to compile.
- **Verified**: back changes with tests, and with formal methods where practical. Prefer dependencies that are themselves verified.
- **Vetted**: prefer dependencies that security experts have reviewed. Write code so it is easy for an expert to review.
- **Minimal**: include only what is necessary, in both code and dependencies. Put optional functionality behind features.
- **Consistent**: keep interfaces consistent across crates, so everything feels like one library reachable from the `vitaminc` facade.
- **Compatible**: work toward support for embedded (`no_std`) and WASM targets. Keep the WASM builds that CI checks today passing, and keep core crates and traits-only feature sets free of threads, timers and native-only dependencies. No crate is `no_std` yet, and vendor adapters (AWS, Azure, GCP, Vault) and `aead-napi` are native-only by design. Discuss before removing `std` support to reach `no_std`.
- **Fast**: speed and security can be friends. Keep performance in mind without trading away security.

## Commits

- Use conventional commit messages: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`, `perf:`, `ci:`
- Write commit subjects that describe the *why*, not just the *what*
- Scope commits to the affected crate when possible (e.g. `feat(aead): add streaming encryption support`)
- Commit messages are for contributors; the changelog comes from changesets, not commits

## Changesets

A PR that changes what a published crate ships adds a changeset in `.sampo/changesets/`: the changelog entry, written in the PR that makes the change. `.sampo/README.md` has the format; the `📝 Changesets` check enforces it.

- Bump `patch`, or `minor` for a breaking change. Never `major`: the crates are 0.x, and sampo would release 1.0.0
- Tag every entry: `Breaking`, `Features`, `Fixes`, `Performance`, `Documentation` or `Dependencies`
- Name only the crates the entry is about; every crate gets the new version regardless
- Write from the user's perspective: what changed and why it matters, not implementation details
- Lead a breaking change with **Breaking:** and say what the caller has to do; state a wire-format change's compatibility consequence
- One changeset per change. When review changes the change, update its changeset in the same PR
- A PR that ships nothing (CI, tests, internal refactoring) gets the `no-changeset` label instead

## Releases

sampo versions the crates and writes the changelogs; release-plz publishes. See `RELEASING.md` for the full process.

- Do NOT manually edit `CHANGELOG.md` files on feature branches — write a changeset
- Do NOT manually bump versions in `Cargo.toml` — sampo does it from the changesets
- Do NOT edit the release PR (`release/main`): it is rebuilt on every push to `main`. Fix an entry by editing its changeset on `main`
- All 20 published crates release together as one `fixed` group in `.sampo/config.toml`

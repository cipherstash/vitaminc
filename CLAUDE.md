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
- These messages feed into automated changelog generation via git-cliff, so clarity matters

## Documentation

Use the repository-local [rust-documentation skill](.agents/skills/rust-documentation/SKILL.md)
for Rust documentation work. Follow [the documentation conventions](docs/documentation.md)
for this repository's checks, README links, and separation of user-facing docs
from contributor workflows. Repository requirements take precedence over the
skill's general guidance.

## Releases

Releases are automated with release-plz. See `RELEASING.md` for the full process.

- Do NOT manually edit `CHANGELOG.md` files on feature branches — release-plz manages them
- Do NOT manually bump versions in `Cargo.toml` — release-plz handles this
- All 19 crates release together as a single version group

## Changelogs on release PRs

When working on a release PR (created by release-plz), you may be asked to rewrite the auto-generated changelog entries. Follow these guidelines:

- Write entries from the user's perspective, not the developer's
- Focus on what changed and why it matters, not implementation details
- Group related commits into a single entry where it makes sense
- Call out breaking changes prominently with a **Breaking:** prefix
- Keep entries concise — one line per change is ideal

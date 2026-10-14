# Claude Code Guidelines for vitaminc

## Principles

Vitamin C is a suite of crates for cryptography and handling sensitive data. These goals (from `README.md`) guide every design and code change. When two goals conflict, call out the trade-off rather than silently picking one.

- **Misuse resistant**: make the secure path the easy path. Prefer types and APIs that make insecure code hard to write or fail to compile.
- **Verified**: back changes with tests, and with formal methods where practical. Prefer dependencies that are themselves verified.
- **Vetted**: prefer dependencies that security experts have reviewed. Write code so it is easy for an expert to review.
- **Minimal**: include only what is necessary, in both code and dependencies. Put optional functionality behind features.
- **Consistent**: keep interfaces consistent across crates, so everything feels like one library reachable from the `vitaminc` facade.
- **Compatible**: keep crates working on embedded (`no_std`) and WASM targets.
- **Fast**: speed and security can be friends. Keep performance in mind without trading away security.

## Commits

- Use conventional commit messages: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`, `perf:`, `ci:`
- Write commit subjects that describe the *why*, not just the *what*
- Scope commits to the affected crate when possible (e.g. `feat(aead): add streaming encryption support`)
- These messages feed into automated changelog generation via git-cliff, so clarity matters

## Releases

Releases are automated with release-plz. See `RELEASING.md` for the full process.

- Do NOT manually edit `CHANGELOG.md` files on feature branches — release-plz manages them
- Do NOT manually bump versions in `Cargo.toml` — release-plz handles this
- All 18 crates release together as a single version group

## Changelogs on release PRs

When working on a release PR (created by release-plz), you may be asked to rewrite the auto-generated changelog entries. Follow these guidelines:

- Write entries from the user's perspective, not the developer's
- Focus on what changed and why it matters, not implementation details
- Group related commits into a single entry where it makes sense
- Call out breaking changes prominently with a **Breaking:** prefix
- Keep entries concise — one line per change is ideal

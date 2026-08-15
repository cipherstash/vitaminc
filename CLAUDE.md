# Claude Code Guidelines for vitaminc

## Commits

- Use conventional commit messages: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`, `perf:`, `ci:`
- Write commit subjects that describe the *why*, not just the *what*
- Scope commits to the affected crate when possible (e.g. `feat(aead): add streaming encryption support`)
- These messages feed into automated changelog generation via git-cliff, so clarity matters

## Releases

Releases are automated with release-plz. See `RELEASING.md` for the full process.

- Do NOT manually edit `CHANGELOG.md` files on feature branches — release-plz manages them
- Do NOT manually bump versions in `Cargo.toml` — release-plz handles this
- All 14 crates release together as a single version group

## Changelogs on release PRs

When working on a release PR (created by release-plz), you may be asked to rewrite the auto-generated changelog entries. Follow these guidelines:

- Write entries from the user's perspective, not the developer's
- Focus on what changed and why it matters, not implementation details
- Group related commits into a single entry where it makes sense
- Call out breaking changes prominently with a **Breaking:** prefix
- Keep entries concise — one line per change is ideal

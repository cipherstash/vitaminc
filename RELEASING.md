# Releasing vitaminc

Each change carries its own changelog entry, as a changeset written in the pull request that makes it. [sampo](https://github.com/bruits/sampo) turns the pending changesets into the next version and each crate's `CHANGELOG.md`, and [release-plz](https://release-plz.dev/) publishes to crates.io.

## How it works

### 1. Each pull request carries a changeset

A pull request that changes what a crate ships adds a changeset: a Markdown file in `.sampo/changesets/` holding the changelog entry, the crates it is about, the bump, and the heading it goes under. `sampo add` writes one, or write it by hand:

```markdown
---
cargo/vitaminc-aead-frame: minor (Breaking)
---

**Breaking:** the value frame's container tags move to `0xF0`–`0xF2`. A frame holding an array, an object or a passthrough is not read correctly across versions, so hosts and guests must upgrade together.
```

`.sampo/README.md` says how to write one. In short:

- **The bump** is `patch`, or `minor` for a breaking change: the crates are 0.x, and sampo takes `major` literally and would release 1.0.0.
- **The tag** is the heading: `Breaking`, `Features`, `Fixes`, `Performance`, `Documentation` or `Dependencies`.
- **The entry** is written for someone upgrading. It leads with `**Breaking:**` for a breaking change and says what the caller has to do. A wire-format change says whether data written by the previous version still reads. Say what is deliberately not guaranteed. Write what changed and why it matters, not how it was implemented.
- **One change, one changeset**, updated in the same PR when review changes the change. The entry is reviewed with the code, while its context is fresh.

The `📝 Changesets` check (`.github/workflows/changesets.yml`) fails a PR that changes a published crate's shipped files without adding a changeset, and a changeset that names an unknown crate, uses `major` in 0.x, has no tag, or puts a Breaking entry in a patch. A PR that needs no entry (CI, tests, internal refactoring) carries the `no-changeset` label instead.

Commit messages are for contributors now: no changelog is generated from them. Keep using [conventional commits](https://www.conventionalcommits.org/) all the same.

### 2. The workflow keeps a release PR up to date

On every push to `main`, the `Release PR` job in `.github/workflows/release-plz.yml` runs on main's checkout:

- `sampo release` takes every pending changeset, bumps all 20 crates to one new version (the highest bump any changeset asks for), writes each entry into the changelogs of the crates it names, and deletes the changesets. Every crate's changelog gets the new version heading, with or without entries.
- `.github/scripts/tidy_changelogs.py` drops the lines sampo adds to explain the lockstep ("Bumped due to fixed dependency group policy", "Updated dependencies: ..."), which sampo has no setting for, and puts each release's headings in the configured order, so Breaking leads.
- `.github/scripts/sync_nested_lockfiles.py` re-syncs the lockfiles of the two test workspaces, `packages/aead-napi/tests/addon` and `bindings/go/vcencrypt/guest`, which pin the workspace crates by version and which sampo does not update.
- `cargo semver-checks` compares each crate's API with its last release on crates.io. Its result goes in the PR body; see [Semver checking](#semver-checking).
- The job commits all of that to the `release/main` branch and opens the release PR, or updates it. It makes the commit through GitHub's API (`.github/scripts/commit_on_branch.py`), so GitHub signs it as the release app; `main` requires signed commits, and a commit pushed with git from the workflow would be unsigned.

With no pending changesets the job does nothing.

The release branch is rebuilt from `main` on every push, so **don't edit the release PR**: the next push to `main` throws the edit away. To change an entry, edit its changeset on `main` in a follow-up PR; to change the version, change a changeset's bump. Both last, unlike an edit to the release branch.

### 3. You review the release PR

The PR body lists every entry by crate, as readers will see it. Check:

- **The version.** It is the highest bump among the changesets. The check on each PR refuses a Breaking entry with a `patch` bump, but a breaking change nobody wrote a Breaking changeset for is only caught by semver-checks.
- **The entries read as one changelog.** They were written PR by PR; two that describe one feature can be merged by editing the changesets on `main`.
- **Compatibility claims are true.** They are the part people act on, so check them against the code.

### 4. Merge the release PR

Merging the release PR triggers the `Release` job, which runs `release-plz release`:

- Publishes every crate not yet on crates.io at its version, in dependency order
- Creates a git tag for each crate (`<crate>-v<version>`)
- Creates a GitHub release for each, from the newest section of its `CHANGELOG.md`

The job runs on every push to `main`, but publishes only when the commit is a merged release PR (`release_always = false`), which release-plz recognises by the PR's branch, `release/main` (`pr_branch_prefix`). Nothing is published from ordinary merges.

### Prereleases

`sampo pre enter <label>` puts crates in prerelease mode: releases are then `0.7.0-alpha`, `0.7.0-alpha.1`, and so on, and the consumed changesets are kept in `.sampo/prerelease/` so the stable release still lists them. `sampo pre exit` graduates. Either is a change to `.sampo/` made in a PR, so leaving the train is an explicit, reviewed step. (Not yet tried with the lockstep group.)

### A crate's first release

The `Release` job publishes through crates.io trusted publishing, and crates.io lets a crate be set up for that only once it exists, so the job cannot publish a crate that has never been released. A personal token cannot finish the release either: every crate already on trusted publishing accepts new versions only from it, and refuses a token with `403 Forbidden`. So a release that includes a new crate takes these steps:

1. Merge the release PR as usual. The job publishes crates in dependency order and fails at the first new one (`Trusted Publishing tokens do not support creating new crates`); the crates before it are released.
2. From the merge commit, publish **only the new crates** with a crates.io token of your own, in dependency order. Every dependency a new crate has must already be on crates.io at the release version; `cargo publish --dry-run --locked -p <crate>`, which needs no token, says whether it is. If a new crate depends on an existing crate the job has not reached yet, re-run the job after step 3 for the crates it can now publish, then come back for the rest. Make the token narrow: the `publish-new` scope, the crate pattern `vitaminc*`, and an expiry of the next day. Hand it over through the environment rather than `cargo login`, which would keep it in `~/.cargo/credentials.toml`:

   ```bash
   git switch --detach <merge-commit>
   read -rs CARGO_REGISTRY_TOKEN && export CARGO_REGISTRY_TOKEN
   cargo publish --locked -p <new-crate>   # once per new crate, dependencies first
   unset CARGO_REGISTRY_TOKEN
   ```

   Do not run `release-plz release` with it: release-plz goes on to the existing crates, and crates.io refuses them.
3. On crates.io, set up trusted publishing for each new crate (repository `cipherstash/vitaminc`, workflow `release-plz.yml`). Then re-run the failed `Release` job (`gh run rerun <run-id> --failed`). It skips what is already published, publishes the rest through trusted publishing, and creates their tags and GitHub releases.
4. Tag and release each crate published in step 2. The job skips a crate that is already published and creates no tag for it, so those crates have neither. Tag the commit the other `-v<version>` tags name (`git rev-list -n1 <another crate's tag>`), and use the crate's changelog section as the notes:

   ```bash
   git tag -a <crate>-v<version> <commit> -m "chore: Release package <crate> version <version>"
   git push origin refs/tags/<crate>-v<version>
   gh release create <crate>-v<version> --verify-tag --title <crate>-v<version> --notes-file <notes.md> --latest=false
   ```

A new crate also has to join the `fixed` group in `.sampo/config.toml`; `test_release_plz_config.py` fails until it does.

## Configuration

| File | Purpose |
|---|---|
| `.sampo/config.toml` | sampo config: the lockstep group, the changelog headings |
| `.sampo/README.md` | How to write a changeset |
| `release-plz.toml` | release-plz config: publishing, tags, GitHub releases, the release PR's branch |
| `.github/workflows/release-plz.yml` | The `Release PR` and `Release` jobs |
| `.github/workflows/changesets.yml` | The `📝 Changesets` check on pull requests |

## All crates release together

The 20 published crates are one `fixed` group in `.sampo/config.toml`: every release bumps all of them to the same version, whichever crates changed. A changeset's entry goes only into the changelogs of the crates it names. `test_release_plz_config.py` checks the group is exactly the published workspace members.

## Secrets

Publishing uses crates.io trusted publishing (the workflow's `id-token: write` permission), so the repository holds no crates.io token. The workflow authenticates to GitHub as an app, through the `RELEASE_PLZ_APP_ID` variable and the `RELEASE_PLZ_APP_PRIVATE_KEY` secret, so its pushes trigger CI.

## Semver checking

The `Release PR` job runs `cargo semver-checks --workspace` against the release it is about to propose, and puts the result in the PR body. A changeset's bump is its author's judgement; this checks it. A crate whose API changed more than the new version allows (a removed item in a patch release, say) fails the check.

It does not block the PR: a failure is a question for the person merging, not proof of a regression. It also fails when it cannot run, for a crate never published, for one. It baselines against the last version *published to crates.io*, prereleases included, and applies 0.x rules, where a breaking change needs a minor bump.

## FAQ

**Does a release PR get created on every merge to main?**

No: the same release PR is updated on every push to `main` while changesets are pending. They accumulate in it until you merge it.

**Do we have to merge the release PR every time?**

No. Let changes pile up and merge it when you're ready to cut a release.

**Can I edit the release PR by hand?**

You can, but the next push to `main` rebuilds it and the edit is lost. Edit the changesets on `main` instead.

**I forgot a changeset.**

Add one in a follow-up PR. It goes into the open release PR, or the next one if that has merged.

**Why not git-cliff, as before?**

It made the changelog from commit messages, which are written for reviewers: a feature with seven review fix-ups became eight entries, filed in whichever crates the commits touched, and every release PR needed its changelog rewritten by hand. A changeset is written once, for readers, and reviewed with the code.

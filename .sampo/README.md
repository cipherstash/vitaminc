# Changesets

A changeset is the changelog entry for a change, written in the pull request
that makes it. Each one is a Markdown file in `changesets/`. The release PR
turns the pending changesets into the next version and each crate's
`CHANGELOG.md`, and deletes them.

## Writing one

Run `sampo add`, or write the file by hand under any name ending in `.md`:

```markdown
---
cargo/vitaminc-aead-frame: patch (Features)
---

A serde data format over the frame, behind the new `serde` feature. ...
```

- **Name each crate the entry is about**, as `cargo/<crate>`. The entry goes
  into those crates' changelogs only. Every crate still gets the new version.
- **Bump:** `patch` for fixes and additions, `minor` for a breaking change.
  The crates are 0.x, where a breaking change is a minor bump; `major` would
  release 1.0.0, and CI refuses it. The release takes the highest bump among
  its changesets.
- **Tag** in parentheses: `Breaking`, `Features`, `Fixes`, `Performance`,
  `Documentation` or `Dependencies`. It is the heading the entry goes under.
  A Breaking entry needs a `minor` bump.
- **Body:** write it for someone upgrading the crate, not for the reviewer.
  What changed and why it matters to them, not how it was implemented.
  - A breaking change starts `**Breaking:**`, says what breaks for the
    caller and what they have to do.
  - A wire-format change says whether data written by the previous version
    still reads.
  - Say what is deliberately not guaranteed, if a property looks
    authenticated but isn't.

One change, one changeset. When review changes the change, update its
changeset in the same PR, so the entry still describes what merges.

A PR that changes nothing a crate ships (CI, tests, internal refactoring)
needs no changeset; label it `no-changeset`.

See `RELEASING.md` for the release itself.

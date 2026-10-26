# Maintaining documentation

## Audience

Crate READMEs are included in rustdoc. Keep them and API comments focused
on installation, usage, behavior, security limits, and compatibility.
Explain current behavior directly instead of referring readers to an ADR.
Test inventories, CI gates, contributor rules, and design history belong in
[CONTRIBUTING.md](../CONTRIBUTING.md) or other repository-only documents.
Ordinary source comments can explain implementation and testing decisions.

The storage specification is also included in rustdoc. Keep its format and
compatibility contract there; put corpus maintenance and CI instructions in
the contributor guide.

## Shared README links

Most crate landing pages include their README with `include_str!`. Keep one
copy of the prose and examples, while giving each renderer useful links.

## API references

In a README, use reference links for API items and define their destinations
at the bottom of the file:

```markdown
Inputs implement [`PrfValue`].

[`PrfValue`]: https://docs.rs/vitaminc-prf/latest/vitaminc_prf/trait.PrfValue.html
```

These URLs are for readers browsing GitHub or crates.io and follow the latest
published API. A Git tag's README also follows these URLs; use that release's
docs.rs pages for its versioned API reference.

Before including the README in `src/lib.rs`, define the same reference labels
with intra-doc paths:

```text
//! [`PrfValue`]: crate::PrfValue
//!
#![doc = include_str!("../README.md")]
```

Markdown uses the first definition of a reference label. Rustdoc therefore
uses the local definition, resolves the item against the crate being built,
and checks the link. GitHub sees the HTTP definition in the README. Keep the
label spelling, including backticks, identical in both files. Use paths
already in scope where possible; disambiguate traits and derives with
`trait@` or `macro@` when needed.

When adding a reference, add both definitions and inspect the resulting
`href`. A successful rustdoc build alone is not enough: some invalid paths
containing `::` can be interpreted as URL schemes and escape link linting.
Do not put direct `/latest/` item links in the shared prose, since rustdoc
cannot replace them with links to the current version.

Cross-crate references within the workspace use versioned URLs built with
`concat!` and `env!("CARGO_PKG_VERSION")`. The workspace crates release together,
so this follows the documented release without a manually maintained version.
This also works for the AEAD derive crate, which cannot depend normally on its
parent, and avoids cross-crate paths becoming literal URLs in some workspace
documentation builds. Links to external project landing pages are discovery
links and may follow their latest release.

## Repository guides

Use absolute GitHub URLs for repository files linked from shared READMEs.
Relative paths such as `STORAGE.md` point into generated API directories when
rendered by rustdoc, where those files do not exist. Links to `main` deliberately
open the current repository guide. For historical behavior, consult the
matching Git tag and its versioned API documentation.

Link to user-facing specifications such as `packages/aead-frame/STORAGE.md`
where they help readers use an API. Keep ADR links in contributor documents.

## Checks

Build both default and relevant optional-feature documentation with warnings
denied, and inspect the generated links:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

Also render the README as ordinary Markdown, which has no Rust name resolver.
Check reference definitions, repository paths and anchors, and API destination
paths. Preserve the existing doctests when changing shared examples.

Installation versions and MSRV numbers have their own synchronizers; see
[RELEASING.md](../RELEASING.md) for their markers and commands.

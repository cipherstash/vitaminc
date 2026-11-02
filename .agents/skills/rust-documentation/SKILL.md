---
name: rust-documentation
license: Apache-2.0
description: Design, write, build, test, and publish Rust documentation with rustdoc, cargo doc, doctests, intra-doc links, crate-level guides, examples, README synchronization, mdBook, docs.rs metadata, link checking, documentation CI, and the Rust API Guidelines Documentation chapter (C-DOC, C-LINK, C-META, C-EXAMPLE). Use when users ask for Rust API docs, a project book, runnable examples, docs.rs readiness, missing-doc policy, API guideline compliance, documentation architecture, or stale documentation repair.
---

# Rust Documentation

Treat documentation as an executable interface. Keep API reference close to code, conceptual and operational guides in an appropriate book or repository document, and examples compiled against the supported API.

## Scope and Routing

Use this skill for rustdoc comments, crate and module documentation, doctests, intra-doc links, README generation, mdBook, docs.rs configuration, link checking, spelling, and documentation release gates.

Route general test architecture to `rust-testing`, public API compatibility to `rust-code-review`, Cargo metadata and publishing to `rust-cargo-build`, API shape and trait design decisions to `rust-api-design`, and non-Rust office document formats to their dedicated document skills. This skill documents what already exists; `rust-api-design` decides what the API should be.

## Workflow

### 1. Identify readers and documentation surfaces

Inventory public crates, binaries, features, targets, examples, READMEs, books, generated references, and hosted output. Define the audience and owner for each surface:

| Surface | Primary purpose |
|---|---|
| Crate and module docs | Entry path, architecture, feature and platform overview |
| Item docs | Contract, errors, panics, safety, examples, complexity |
| Doctests and examples | Executable usage and compatibility proof |
| README | Discovery, installation, minimal quick start, support policy |
| mdBook | Tutorials, concepts, operations, migration, long-form guides |
| docs.rs | Versioned public API publication |

Avoid duplicating the same prose across surfaces without a declared source of truth.

### 2. Document the contract

For each public API, document only applicable sections:

- what the item does and important semantics;
- `# Examples` with assertions and realistic imports;
- `# Errors` for each meaningful failure category;
- `# Panics` for reachable panic conditions;
- `# Safety` for caller obligations on unsafe APIs;
- cancellation, blocking, allocation, complexity, platform, feature, and MSRV constraints.

Prefer intra-doc links such as ``[`Client::send`]`` over brittle hand-written URLs. Enable broken-link checking at the crate boundary:

```rust
#![deny(rustdoc::broken_intra_doc_links)]
```

Adopt `missing_docs` deliberately; do not enable it globally before deciding which public compatibility surface requires documentation.

## Rust API Guidelines — Documentation Rules

The [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/documentation.html) define five documentation rules (C-DOC, C-DOC-COMMENT, C-META, C-EXAMPLE, C-LINK) that high-quality crates are expected to satisfy. Treat them as the acceptance bar for documentation of any public crate. Full rationale, anti-patterns, and worked examples live in [API Guidelines — Documentation](references/api-guidelines-documentation.md); this section is the routing summary.

### C-DOC — Document all items

Every public item (function, struct, enum, trait, module, etc.) carries a doc comment. Enforce mechanically with the `missing_docs` lint:

```rust
// src/lib.rs
#![deny(missing_docs)]
```

Decide the scope deliberately. `#![deny(missing_docs)]` at the crate root is the strongest policy; if some surfaces (sealed modules, generated code, deliberately unstable APIs) need exemptions, scope the lint with `#[allow(missing_docs)]` on the smallest possible item and record why.

### C-DOC-COMMENT — `///` versus `//!`

- `///` documents the **next item** (function, struct, field, module declared by name below it).
- `//!` documents the **current module or crate** (placed at the top of a file, or inside a module body).
- Both render Markdown and support intra-doc links `[`Foo`]`.

Use `//!` at the top of `src/lib.rs` and any module root that needs an overview; use `///` for every documented item.

### C-META — Crate-level docs must cover essentials

`src/lib.rs` must open with `//!` documentation covering:

- what the crate does and a link to usage examples;
- how to get started (link to setup/integration docs or a quick start);
- feature flags and what each enables;
- Minimum Supported Rust Version (MSRV);
- license, conventionally dual `MIT OR Apache-2.0`.

Run `cargo doc --no-deps -p <crate>` and check that the crate landing page reads as a self-contained overview, not just a module list.

### C-EXAMPLE — Runnable examples with `# Examples`

Every public item should have a `# Examples` section. Examples should compile and run as doctests. Pick fence attributes precisely:

- no attribute — compile and run;
- ```` ```no_run ```` — compile but skip execution (network, files, hardware);
- ```` ```ignore ```` — skip entirely, with a documented reason;
- ```` ```compile_fail ```` — only in proc-macro crates to demonstrate rejected input.

Avoid `no_run` as a disguise for broken examples; if a workflow needs files or credentials, move it into `examples/` and test it as a real target.

### C-LINK — Intra-doc links

Use `[`ItemType`]` and `[`ItemType::method`]` syntax so rustdoc resolves targets and tracks renames. Never hand-write paths to types in the same crate. Enable broken-link enforcement at the crate boundary:

```rust
#![deny(rustdoc::broken_intra_doc_links)]
```

For full examples, anti-patterns, the lint matrix, and the verification commands per rule, read [API Guidelines — Documentation](references/api-guidelines-documentation.md).

### 3. Make examples executable

Use doctests for small public API contracts and `examples/` crates for complete workflows. Mark fences precisely:

- ordinary Rust fences compile and run;
- `no_run` compiles code that requires unavailable external effects;
- `compile_fail` proves rejected usage without locking full diagnostics;
- `ignore` is a last resort with a documented reason.

Run:

```bash
cargo test --workspace --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

Read [rustdoc and Doctests](references/rustdoc-and-doctests.md) when authoring API documentation.

### 4. Build long-form guides with mdBook

Use mdBook for tutorials, architecture, operations, and migration material that would overload API docs. Keep `SUMMARY.md` as the explicit navigation contract. Test Rust code samples with `mdbook test`, build in CI, and check internal plus external links. Read [mdBook and Project Guides](references/mdbook-and-guides.md).

### 5. Prepare versioned publication

Inspect package metadata, docs.rs target and feature configuration, README links, repository URLs, licenses, examples, and hidden/private APIs. Verify docs using the locked dependency graph and supported MSRV/current stable rather than only the author's machine.

Do not publish, change hosted documentation, or enable external analytics without authorization. Read [Documentation Release Quality](references/documentation-release-quality.md).

## Quality Gates

```bash
cargo fmt --all --check
cargo test --workspace --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
mdbook test path/to/book
mdbook build path/to/book
lychee README.md docs book/src
typos README.md docs book/src src
```

Run only tools present in the project or approved for installation. Pin non-Rust documentation tools in CI and do not silently rewrite prose during a check-only job.

## Completion Criteria

- Give each audience a clear entry point and avoid conflicting sources of truth.
- Document public errors, panics, safety, features, targets, and compatibility where applicable.
- Compile and run representative documentation examples.
- Reject broken intra-doc and repository links.
- Build the same feature and target documentation intended for publication.
- Record skipped external, platform, or hosted verification explicitly.

## Resources

- [rustdoc and Doctests](references/rustdoc-and-doctests.md)
- [mdBook and Project Guides](references/mdbook-and-guides.md)
- [Documentation Release Quality](references/documentation-release-quality.md)
- [API Guidelines — Documentation](references/api-guidelines-documentation.md)
- [Execution Scenarios](examples/examples.md)
- `examples/golden-docs/`: a compilable crate with enforced intra-doc links and doctests.

## Upstream Sources

- [The rustdoc Book](https://doc.rust-lang.org/rustdoc/)
- [Rustdoc documentation tests](https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html)
- [Cargo doc](https://doc.rust-lang.org/cargo/commands/cargo-doc.html)
- [mdBook](https://rust-lang.github.io/mdBook/)
- [docs.rs metadata](https://docs.rs/about/metadata)
- [Rust API Guidelines — Documentation](https://rust-lang.github.io/api-guidelines/documentation.html)

## Data Privacy

This skill does not collect, store, or transmit user data. Review examples, generated source links, build logs, and hosted analytics for secrets or proprietary paths before publication.

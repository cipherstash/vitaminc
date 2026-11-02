# API Guidelines — Documentation

Authoritative reference for the five documentation rules in the Rust API Guidelines: **C-DOC**, **C-DOC-COMMENT**, **C-META**, **C-EXAMPLE**, and **C-LINK**. Apply them as the acceptance bar for any crate that will be published or consumed by third parties.

Source: <https://rust-lang.github.io/api-guidelines/documentation.html>

## Quick reference

| Rule | Intent | Mechanical check |
|---|---|---|
| C-DOC | Every public item is documented | `#![deny(missing_docs)]` |
| C-DOC-COMMENT | `///` for items, `//!` for modules/crates | `cargo doc` renders correctly |
| C-META | Crate-level docs cover what, how, features, MSRV, license | Manual review of `src/lib.rs` landing page |
| C-EXAMPLE | Public items have `# Examples` that run | `cargo test --doc` |
| C-LINK | Use `[`Foo`]` intra-doc links | `#![deny(rustdoc::broken_intra_doc_links)]` |

---

## C-DOC — Document all items

> "All items exported from a crate are documented."

Every public item — functions, structs, enums, variants, fields, traits, trait methods, type aliases, modules, constants, statics, macros — must carry a doc comment.

### Enforcement

Put the lint at the crate root in `src/lib.rs`:

```rust
// src/lib.rs
#![deny(missing_docs)]

//! Crate-level docs go here (see C-META).
```

If `missing_docs` is added late, expect a large diff. Decide deliberately whether to:

- Deny globally (`#![deny(missing_docs)]`) — strongest policy, recommended for libraries.
- Warn globally (`#![warn(missing_docs)]`) — gradual adoption.
- Allow with scoped denies on stable modules — for crates with mixed-stability surfaces.

### Scoping exemptions

Sealed modules, generated code, and deliberately unstable APIs may need targeted `#[allow(missing_docs)]` on the smallest item that warrants it. Always pair an `#[allow]` with a comment explaining why:

```rust
/// Public but intentionally undocumented until API stabilizes.
#[allow(missing_docs)]
#[doc(hidden)]
pub mod unstable {
    // ...
}
```

### Gotchas

- `missing_docs` fires on the visibility that rustdoc sees. A `pub` item inside a non-`pub` module is not part of the public surface, so the lint will not fire on it. Re-exporting it publicly triggers the lint.
- Trait methods inherit the trait's documentation policy: if the trait is `pub`, every method must be documented (unless it has a default and the trait is sealed).
- Re-exports (`pub use foo::Bar;`) themselves do not require docs if the underlying item has them; rustdoc displays the original.

---

## C-DOC-COMMENT — `///` versus `//!`

> "Use `///` for item docs, `//!` for module/crate docs."

| Syntax | Documents | Placement |
|---|---|---|
| `///` | The **next item** | Immediately above the item, no blank line |
| `//!` | The **enclosing module or crate** | At the top of the file, or anywhere inside a module body |

Both support full Markdown and intra-doc links.

### Correct usage

```rust
// src/lib.rs
//! # mycrate
//!
//! A short description that appears on the crate landing page.
//! See C-META for the required sections.

/// A widget that frobnicates.
///
/// Use [`Widget::new`] to construct one.
pub struct Widget { /* ... */ }

/// Methods on [`Widget`].
impl Widget {
    /// Create a new widget with default configuration.
    pub fn new() -> Self { /* ... */ }
}

/// Operations on widgets.
pub mod ops {
    //! Module-level docs explaining what "operations" means here.

    /// Rotate the widget by `degrees`.
    pub fn rotate(_w: &mut super::Widget, _degrees: f32) { /* ... */ }
}
```

### Common mistakes

```rust
// Wrong: `///` above a module declaration documents the module
//        from the parent's perspective, not the contents.
/// This looks like module docs but is an item doc on the `foo` mod item.
mod foo {}

// Wrong: `//!` directly above an item is a syntax error or attaches
//        to the wrong scope.
pub fn bar() {
    //! This documents bar's enclosing module, NOT bar itself.
}
```

Rule of thumb: `//!` always describes *where you are*; `///` always describes *what comes next*.

---

## C-META — Crate-level docs must include essentials

> "Crate-level docs include a summary of what the crate does, how to use it, links to examples, feature flags, MSRV, and license."

Place this content as `//!` documentation at the top of `src/lib.rs`. It becomes the landing page on docs.rs.

### Required checklist

A reader landing on the crate's docs page should learn:

1. **What the crate does** — one or two paragraphs, with a link to examples or a quick start.
2. **How to get started** — installation command, minimal usage, link to setup or integration docs.
3. **Feature flags** — every `#[cfg(feature = ...)]` surface mentioned, with what each flag enables or disables.
4. **MSRV** — the minimum supported Rust version, with policy (e.g., "supports last 3 stable minors").
5. **License** — typically `MIT OR Apache-2.0`, with a link to the files.

### Template

```rust
// src/lib.rs
//! # mycrate
//!
//! `mycrate` provides [ concise purpose ].
//!
//! ## Quick start
//!
//! ```toml
//! [dependencies]
//! mycrate = "0.1"
//! ```
//!
//! ```rust
//! use mycrate::Widget;
//! let w = Widget::new();
//! ```
//!
//! ## Features
//!
//! - `std` (default): enables I/O and error integration with `std`.
//! - `serde`: enables serialization via [`serde`].
//! - `tokio`: async runtime support.
//!
//! ## Minimum Supported Rust Version
//!
//! This crate requires Rust **1.75**. MSRV bumps are a minor breaking change
//! and will be noted in the changelog.
//!
//! ## License
//!
//! Dual-licensed under either of
//! - Apache License, Version 2.0 (<http://www.apache.org/licenses/LICENSE-2.0>)
//! - MIT License (<http://opensource.org/licenses/MIT>)
//! at your option.
//!
//! [`serde`]: https://docs.rs/serde
```

### Verification

```bash
cargo doc --no-deps --open
```

Pretend you have never seen the crate. Does the landing page answer "what is this, how do I install it, what features exist, what Rust version do I need, what license?" If not, C-META is not satisfied.

### Gotchas

- Feature flags introduced in `Cargo.toml` but missing from the crate docs are a C-META violation even when they are obvious. Enumerate every non-trivial feature.
- MSRV in README and `Cargo.toml`'s `rust-version` field and crate-level docs must agree. Drift here is a documentation bug.
- License SPDX expression in `Cargo.toml` (e.g., `license = "MIT OR Apache-2.0"`) must match the prose in the crate docs.

---

## C-EXAMPLE — Runnable examples with `# Examples`

> "Every public item has a `# Examples` section, examples are valid runnable Rust, and the fence attributes are chosen precisely."

### Structure

```rust
/// Add two numbers.
///
/// # Examples
///
/// ```
/// use mycrate::add;
/// assert_eq!(add(2, 3), 5);
/// ```
///
/// # Panics
///
/// Panics on integer overflow in debug mode.
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}
```

The `# Examples` heading is recognized by rustdoc and surfaced in the rendered docs; keep the spelling exact.

### Fence attribute matrix

| Attribute | Compiles? | Runs? | Use when |
|---|---|---|---|
| none (```` ``` ````) | Yes | Yes | Default. Small, deterministic, no external state. |
| `no_run` | Yes | No | Real code that needs files, network, hardware, or credentials. |
| `ignore` | No | No | Demonstrates setup that cannot be expressed in a doctest. Add a reason comment. |
| `compile_fail` | Yes (must fail) | No | Proc-macro crates only, to demonstrate rejected input. |
| `should_panic` | Yes | Yes (must panic) | Testing documented panic behavior. |
| `ignore` + `edition2018` etc. | No | No | Edition-specific examples; rare. |

### Hidden setup lines

Prefix a line with `#` to include it in compilation but hide it from rendered output:

```rust
/// # Examples
///
/// ```
/// # use mycrate::Client;
/// # let client = Client::connect("127.0.0.1:0").unwrap();
/// client.ping();
/// ```
pub fn ping(&self) { /* ... */ }
```

This keeps the visible example focused on the call site while still compiling.

### Choosing between `no_run`, `ignore`, and `examples/`

- `no_run` — the example is realistic and would compile and run, but the runtime side effects (network, files, GPU) are unavailable in CI. **Prefer this over `ignore`.**
- `ignore` — last resort. Add a comment: ```` ```ignore // requires GPU hardware ````.
- `examples/` directory — for multi-file workflows that exceed a doc comment. Move the workflow into a real binary target and test it with `cargo test --example`.

### Anti-patterns

- Using `no_run` to disguise an example that no longer compiles. CI will still compile `no_run` fences; if the example is broken, CI fails.
- Using `compile_fail` outside macro crates. It is a contract that the code *must* fail to compile; using it for "this API is hard to use" misleads readers.
- Examples without assertions. `assert_eq!` or `assert!` turns the example into a regression test for free.
- Examples that use `unwrap()` on user input. Doctests run as external consumers; show realistic error handling when the API returns `Result`.

### Verification

```bash
cargo test --workspace --doc --all-features
```

Every fenced example without `ignore` or `compile_fail` runs as a doctest. Treat doctest failures with the same severity as unit test failures.

---

## C-LINK — Intra-doc links

> "Docs use intra-doc links `[`Foo`]` for items; rustdoc resolves them and the `broken_intra_doc_links` lint rejects broken references."

### Syntax

| Form | Resolves to |
|---|---|
| ``[`Foo`]`` | Item `Foo` in scope |
| ``[`Foo::bar`]`` | Associated function or method |
| ``[`Foo<T>`]`` | Generic type (angle brackets inside backticks) |
| ``[`module::Foo`]`` | Fully-qualified path |
| ``[`Item`]`` (in prose) | Auto-linked, rendered without backticks |

```rust
/// Returns a [`Vec`] of [`Item`]s, sorted by [`Item::priority`].
///
/// See also [`crate::engine::Engine`] for the caller-side context.
pub fn collect(items: &[Item]) -> Vec<Item> { /* ... */ }
```

### Enforcement

Enable broken-link checking at the crate root:

```rust
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::private_intra_doc_links)]
```

- `broken_intra_doc_links` — fails the build when an intra-doc link target cannot be resolved.
- `private_intra_doc_links` — warns when a public doc links to a private item (which will not resolve in the published docs).

### Why not hand-written URLs?

- Renaming a type silently breaks hand-written `crate::foo::struct.Foo.html` style URLs.
- Intra-doc links are validated at doc-build time; URLs are not.
- Intra-doc links render correctly across rustdoc versions and renderers (docs.rs, local, mdbook preprocessor).

### Disambiguation

When a name resolves ambiguously (e.g., a module and a type share a name), use the prefix form:

```rust
/// See the [`mod@engine`] module or the [`engine()`] function.
```

Prefixes: `mod@`, `struct@`, `enum@`, `trait@`, `fn@`, `type@`, `const@`, `static@`, `macro@`, `value@`.

### Verification

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

Any unresolved intra-doc link fails the build. Run this in CI; it is the cheapest and most effective documentation quality gate.

---

## Verification matrix (all five rules)

Run this block before tagging a release. Each command maps to one or more C-* rules.

```bash
# C-DOC: missing_docs enforced via #![deny(missing_docs)] in lib.rs
cargo build --all-features

# C-EXAMPLE: every fenced example compiles and runs
cargo test --workspace --doc --all-features

# C-LINK: intra-doc links resolve
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# C-META, C-DOC-COMMENT: visual review of the landing page
cargo doc --no-deps --open
```

C-META is the only rule without a mechanical check; it requires a human reading the rendered landing page against the checklist in the C-META section.

## Sources

- [Rust API Guidelines — Documentation](https://rust-lang.github.io/api-guidelines/documentation.html)
- [The rustdoc Book — Write documentation](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html)
- [The rustdoc Book — Documentation tests](https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html)
- [The rustdoc Book — Lints](https://doc.rust-lang.org/rustdoc/lints.html)
- [Rust Reference — The `missing_docs` lint](https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html#missing-docs)
- [docs.rs metadata](https://docs.rs/about/metadata)

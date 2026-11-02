# rustdoc and Doctests

## Documentation structure

- Put `//!` documentation at crate and module roots to explain purpose, boundaries, feature flags, platform support, and the recommended entry path.
- Put `///` documentation on public items to define behavior and contracts.
- Link types and methods with intra-doc links so rustdoc can validate targets and track renamed items.
- Re-export intentionally; rustdoc follows the public module graph, so internal layout should not become the only discoverable navigation path.

## Executable examples

Doctests compile as external users of a library and therefore exercise public visibility. Use hidden lines beginning with `#` for setup that should compile but need not distract readers. Include assertions so the example verifies behavior.

Choose fence attributes deliberately:

| Attribute | Meaning |
|---|---|
| none | Compile and run |
| `no_run` | Compile but do not execute |
| `should_panic` | Run and require a panic |
| `compile_fail` | Require compilation failure |
| `ignore` | Skip; include a reason and issue when temporary |

Do not use `no_run` merely to hide an example that no longer works. Move workflows needing files, sockets, credentials, or several modules into `examples/` and test them as real targets.

## Lints and CI

Useful crate attributes include:

```rust
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::private_intra_doc_links)]
```

Evaluate `missing_docs` against the intended public surface. Generated code, sealed modules, and deliberately unstable APIs may need scoped policy rather than blanket allowances.

Run docs under meaningful features and targets. `--all-features` can reveal conflicts but may not represent a supported combination, so also test the project's declared feature matrix.

## Contract sections

Document `Errors`, `Panics`, and `Safety` only when relevant. Also state blocking, cancellation, allocation, complexity, ordering, thread-safety, platform, and persistence semantics when callers must design around them.

## Sources

- [rustdoc: How to write documentation](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html)
- [rustdoc: Documentation tests](https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html)
- [rustdoc lints](https://doc.rust-lang.org/rustdoc/lints.html)


## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** the derives now find the protected crate from your `Cargo.toml`: a dependency on `vitaminc-protected` under any name, or on `vitaminc` (as `vitaminc::protected`). A crate that reached `OpaqueDebug` only through another crate's re-export, with no dependency of its own on `vitaminc-protected` or `vitaminc`, used to compile and now fails with an error naming the fixes. Add one of those dependencies, or point the derive at the re-export with `#[opaque_debug(crate = "path::to::protected")]` (or `#[timing_safe(crate = "...")]` for `TimingSafeEq`).
- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.

### Features

- Both derives now name their traits by full path, so `#[derive(vitaminc_protected::OpaqueDebug)]` and `#[derive(vitaminc_protected::TimingSafeEq)]` work without a `use` of the trait. `TimingSafeEq` also works for crates that depend only on the `vitaminc` umbrella crate, or that rename the dependency; in 0.5.1 it required a dependency named `vitaminc_protected`.
- New `#[opaque_debug(crate = "...")]` and `#[timing_safe(crate = "...")]` attributes set the path to the protected crate. The value is used as written. A value that is not a path is rejected.

### Fixes

- The derives no longer fail to compile on valid input. In 0.5.1 these broke: `OpaqueDebug` on any generic enum (lifetimes, type or const parameters); an enum variant field named `f`; a `#[non_sensitive]` field of a generic type (it now gets a `Debug` bound; masked fields get none); an empty enum; a const parameter or an in-scope item (unit struct, tuple struct, constant) named like a generated local, such as `f`, `tn`, `ds`, `dt`, `acc` or `other`; and a `write!` or `concat!` macro defined in the caller's module. Generated names no longer trigger `non_snake_case` for uppercase field names.
- `OpaqueDebug` output fixes: a `#[non_sensitive]` enum field named `tn` printed the type name instead of its value, and raw identifier fields printed as `r#type:` instead of `type:`. An `#[opaque_debug(...)]` attribute with an unknown key is now a compile error; in 0.5.1 it was ignored and the mask fell back to `***`.
- `OpaqueDebug` enum output now matches struct output and `#[derive(Debug)]`: `path::E::V { a: "***", b: 2 }` instead of `path::E::V {a: "***", b: 2}`, and `{:#?}` now prints the multi-line layout instead of being ignored. Code that matched the exact 0.5.1 enum text will see different output.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

### Dependencies

- syn 3.




### Fixes

- remove circular dev-dependency between vitaminc-protected and vitaminc


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

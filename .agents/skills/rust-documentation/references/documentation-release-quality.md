# Documentation Release Quality

## Source-of-truth policy

Assign one owner for installation commands, feature names, compatibility, and examples. Generate or include shared text only when the resulting links work in every renderer. README generators such as `cargo-rdme` can help, but a check mode in CI is required to detect drift.

## docs.rs readiness

Inspect `[package.metadata.docs.rs]` for:

- supported targets;
- selected features or `all-features`;
- rustdoc arguments needed for conditional APIs;
- platform dependencies available in the docs.rs build environment.

Build locally with equivalent flags when possible. A successful default `cargo doc` does not prove all hosted feature combinations work.

## Release checklist

- Package metadata links to the correct repository, documentation, homepage, license, and README.
- Quick-start commands use the released package name and supported feature flags.
- Doctests and examples compile on the declared MSRV and current stable.
- Public links resolve and do not depend on private files or local paths.
- Generated source, logs, screenshots, and examples contain no credentials or private endpoints.
- Deprecations link to replacements and migration guidance.
- Published API docs correspond to the package contents from `cargo package --list`.

## Useful tools

- rustdoc and `cargo doc` for API reference;
- `mdbook` for long-form guides;
- `lychee` for link checking;
- `typos` or a project-approved spelling tool;
- `cargo-rdme` when crate docs are the README source of truth.

Tool installation and version pinning belong in repository policy; do not install or auto-fix without authorization.

## Sources

- [Cargo package metadata](https://doc.rust-lang.org/cargo/reference/manifest.html#the-package-section)
- [docs.rs metadata](https://docs.rs/about/metadata)
- [cargo package](https://doc.rust-lang.org/cargo/commands/cargo-package.html)

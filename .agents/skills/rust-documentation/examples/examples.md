# Rust Documentation Execution Scenarios

## Build public API documentation

User request:

> Document this library's client API, including errors, panics, examples, and feature-dependent methods.

Inspect the public surface and feature matrix, add contract-focused rustdoc with intra-doc links, make examples executable, and run doctests plus `cargo doc` with warnings denied. Do not invent behavior from implementation details.

## Create a project guide

User request:

> Turn these scattered architecture and operations notes into a maintainable Rust project manual.

Keep API details in rustdoc, create an audience-oriented mdBook navigation path, test Rust snippets, check links, and define which source owns installation and compatibility information.

## Prepare docs.rs publication

User request:

> Verify that all public features and supported targets will render correctly on docs.rs.

Inspect package metadata and the supported feature matrix, reproduce docs.rs flags locally when practical, run doctests on MSRV and current stable, and report target-specific builds that cannot be verified locally.

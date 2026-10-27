# mdBook and Project Guides

Use mdBook for reader journeys that span several concepts or operational steps. API reference remains in rustdoc.

## Information architecture

Define the reader's first successful path before adding chapters. A useful book commonly separates:

1. installation and compatibility;
2. a minimal verified walkthrough;
3. concepts and architecture;
4. task-oriented recipes;
5. operations and troubleshooting;
6. migration and compatibility notes;
7. links to versioned API reference.

Keep `SUMMARY.md` intentional and shallow. Avoid a chapter per source module or a dump of internal types.

## Reproducible builds

Pin mdBook and preprocessors in CI. Keep generated output outside version control unless hosting requires it. Run:

```bash
mdbook test book
mdbook build book
```

Preprocessors and alternative renderers execute during builds; treat them as supply-chain dependencies and restrict them to necessary capabilities.

## Code samples and links

- Prefer samples that compile with the same dependency versions as the project.
- Test snippets or source them from compiled example files when practical.
- Use a link checker for internal anchors and external URLs.
- Avoid linking only to `latest` API docs when a versioned manual describes a released product.
- Record redirects and renamed pages during migrations.

## Sources

- [mdBook guide](https://rust-lang.github.io/mdBook/)
- [mdBook command line](https://rust-lang.github.io/mdBook/cli/index.html)
- [mdBook preprocessors](https://rust-lang.github.io/mdBook/for_developers/preprocessors.html)

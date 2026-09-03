
## [0.2.0-pre.2] - 2026-09-03

### Breaking

- **Breaking:** make the PRF own its key and derive by reference ([#307](https://github.com/cipherstash/vitaminc/pull/307))

### Features

- add structured PRF foundation
- reject duplicate map keys at build time
- add NonEmpty context wrapper checked once at construction

### Fixes

- prevent ambiguous value encodings
- preserve protected secret lifecycles
- tag Option contexts with the option-some domain
- derive HashMap terms in a deterministic order
- wipe HMAC key-normalization temporaries
- give refine its own domain tag
- judge context emptiness before encoding, and align conversion coverage

### Performance

- stream fixed-size leaves without heap copies

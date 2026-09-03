
## [0.2.0-pre.2] - 2026-09-03

### Breaking

- **Breaking:** make the PRF own its key and derive by reference ([#307](https://github.com/cipherstash/vitaminc/pull/307))
- **Breaking:** construct only through PrfKeyInit; pin non-Clone with a compile-fail case

### Features

- add the vitaminc-hmac PRF backend crate

### Fixes

- require a full-strength PRF key

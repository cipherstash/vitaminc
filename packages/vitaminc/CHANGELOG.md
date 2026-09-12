
## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

## [0.2.0] - 2026-09-03

### Features

- Structured PRF support: the `prf` feature exposes `vitaminc-prf` and the `vitaminc-hmac` HMAC-SHA256 backend, and works standalone without other features.

### Fixes

- PRF keys must be full strength — keys shorter than 32 bytes are rejected.

### Documentation

- READMEs and rustdoc corrected (fabricated APIs, stale claims); SECURITY.md added.




### Refactoring

- normalize vitaminc re-exports to module aliases


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

## [0.2.0] - 2026-09-02

### Features

- The structured PRF foundation and its HMAC backend are reachable from the facade crate.

### Fixes

- The `prf` feature builds on its own, without pulling in unrelated features.
- Weak PRF keys are rejected.





### Refactoring

- normalize vitaminc re-exports to module aliases


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- suppress unused_results lint in OpaqueDebug generated code

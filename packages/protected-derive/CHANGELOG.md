
## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** raise the MSRV to 1.88 and pin kms to the AWS SDK floor
- **Breaking:** resolve the protected crate path so derives work without a use

### Fixes

- keep generics on the Debug impl OpaqueDebug emits for enums
- do not let a field named f shadow the Debug formatter
- keep generated locals clear of the input's generics
- finish OpaqueDebug hygiene and bound shown generic fields
- keep TimingSafeEq locals clear of const parameters and qualify its paths
- stop in-scope items and const parameters capturing OpaqueDebug locals
- share derive hygiene so items and consts named like generated locals can't capture them in bounds or TimingSafeEq
- let the derives build under a caller's forbid(dead_code) and with uppercase field names

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

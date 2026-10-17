
## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** raise the MSRV to 1.88 and pin kms to the AWS SDK floor
- **Breaking:** remove Encrypt, Decipher, DecipherVisitor, SeqAccess and MapAccess

### Fixes

- give ContextTag its async methods and say what the walk authenticates

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Breaking

- **Breaking:** one canonical context encoding shared by AAD and PRF derivations

### Fixes

- an encoded context proves nothing about emptiness

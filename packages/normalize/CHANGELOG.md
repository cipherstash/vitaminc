
## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** rename aead-value to aead-frame and reduce it to the transport
- **Breaking:** name the source trait Encrypt so it pairs with Decrypt
- **Breaking:** require Copy of every normalizer, and name a value that does not fit an index's type

### Documentation

- publish the frozen decimal layout on the public decimal function

### Features

- add vitaminc-normalize with the Terms sink
- say which field Terms refused
- collect equality terms without encrypting
- compare paths and steps by value
- let Terms collect terms under a normalizer of the caller's own

### Fixes

- redact Normalized and Term through OpaqueDebug
- put the NormalizeError on TermError's source chain
- refuse in terms what encryption refuses
- let the decimal encoder refuse a mantissa or scale out of range itself
- name the index a refused term was for, not always equality

### Performance

- build a term's path only when it is pushed

# vitaminc-kms

## 0.6.1 — 2026-10-18

## 0.6.0 — 2026-10-17

### Breaking

- **Breaking:** the crate now declares a minimum supported Rust version of 1.94.1, above the 1.88 the other vitaminc crates declare. 0.5.1 declared none. The AWS SDK releases this crate resolves to (`aws-config` 1.9 and `aws-sdk-kms` 1.112 and later) need Rust 1.94.1, and the crate now declares that floor so the MSRV-aware resolver and crates.io report it. The AWS SDK version requirements themselves are unchanged (`aws-sdk-kms` 1.109.0, `aws-config` 1.8.18), so nothing changes in your own AWS dependencies; you need Rust 1.94.1 or later to build this crate. The same floor applies to the `aws-kms` feature of the `vitaminc` crate.

## 0.5.1 — 2026-10-05

## 0.5.0 — 2026-09-20

## 0.4.0 — 2026-09-12

## 0.3.0 — 2026-09-07

## 0.2.0 — 2026-09-03

### Dependencies

- aws-sdk-kms 1.109.0, aws-config 1.8.18.

### Documentation

- README and rustdoc corrected; SECURITY.md added.


### Miscellaneous

- bump aws-sdk-kms from 1.106.0 to 1.107.0
- bump aws-config from 1.8.16 to 1.8.17


### Miscellaneous

- bump aws-config from 1.8.14 to 1.8.15
- bump tokio from 1.50.0 to 1.52.2
- bump aws-sdk-kms from 1.102.0 to 1.106.0
- bump tokio from 1.52.2 to 1.52.3


### Fixes

- update deprecated BehaviorVersion to v2026_01_12


### Miscellaneous

- bump aws-config from 1.8.6 to 1.8.7
- bump tokio from 1.48.0 to 1.49.0
- release v0.1.0-pre4.1


### Miscellaneous

- bump aws-config from 1.8.6 to 1.8.7
- bump tokio from 1.48.0 to 1.49.0

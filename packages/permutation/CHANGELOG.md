


### Fixes

- close cache-timing side-channel in permute_array
- wrap secret locals in Zeroizing for unwind safety
- assert N <= 256 and zeroize partially-populated output
- make bitwise_permute constant-time

### Testing

- strengthen bitwise_permute coverage


### Documentation

- update doctests to show vitaminc::* import paths


### Fixes

- update codebase for rand 0.9 breaking changes

### Miscellaneous

- release v0.1.0-pre4.1


### Fixes

- update codebase for rand 0.9 breaking changes

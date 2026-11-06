
## [0.9.1] - 2026-11-06

### Documentation

- state the ProtectedRef wipe contract, not the open hole

### Features

- Buffer, byte slices and Vec<u8> lend a ProtectedRef<[u8]>
- a Buffer moves into a Protected<Vec<u8>>
- ProtectedRef::as_deref narrows a protected borrow, and Cow<[u8]> lends its bytes
- ProtectedRef::as_ref_of narrows an array borrow to its bytes

### Fixes

- a plain Vec<u8> or [u8] does not lend a ProtectedRef

## [0.9.0] - 2026-11-04

### Breaking

- **Breaking:** `Usage<T, S>` no longer implements `AsProtectedRef`.
  A scoped value can no longer reach code that ignores its scope by mistake.
  Code that ignores scope includes `zip_ref`, `update_with_ref`, and encryption.
  To reach the value on purpose, call `Controlled::risky_ref`.
  `Protected` still lends a `ProtectedRef`.
  `Equatable` and `Exportable` also lend a `ProtectedRef` when the type they wrap lends one.
- **Breaking:** `str` and `Cow<str>` now lend both `ProtectedRef<'_, str>` and `ProtectedRef<'_, [u8]>`.
  If nothing else in your code fixes the type, `s.as_protected_ref()` needs a type annotation.
  Choose `str` to seal the string as text.
  Text decrypts as a `String`.
  Choose `[u8]` to seal the string as bytes.
- **Breaking:** the crate now needs Rust 1.89 or later.
  Version 0.8.1 needed Rust 1.88.

### Features

- The new `Buffer` type contains secret output bytes.
  A `Buffer` wipes each allocation that it outgrows.
  A `Buffer` also wipes its bytes when it is dropped.
  `Buffer` is a `Controlled` type, so you use it like this:

  - To read the bytes, call `risky_ref`.
  - To take the `Vec<u8>` out of the `Buffer`, call `risky_unwrap`.
  - To change bytes in place, call `overwrite`.

  `Buffer` does not implement `Clone`, `PartialEq`, or `Deref`.
  The `Debug` output of a `Buffer` is redacted.
  The frame and blob writers in `vitaminc-aead` and `vitaminc-aead-frame` return a `Buffer`.
- The new `ProtectedRef::risky_ref` method reads a value through a protected borrow, on purpose.
  The method gives the same access as `Controlled::risky_ref` gives on the owner of the value.

### Performance

- `Locked` regions and `Buffer` are now wiped 16 bytes per volatile store, not 1 byte.
  The wiping guarantee is unchanged.

### What is not guaranteed

- A `ProtectedRef` does not guarantee that its value is wiped.
  A `str`, `[u8; N]`, or `Cow<str>` can lend a `ProtectedRef`.
  Those types do not wipe their values.
  The documentation in 0.8.1 said otherwise.
- If you pass a borrow of a `Locked` value to a function, the function can read the value outside locked memory.

## [0.8.1] - 2026-10-26

## [0.8.0] - 2026-10-21

## [0.7.0] - 2026-10-20

## [0.6.1] - 2026-10-18

## [0.6.0] - 2026-10-17

### Breaking

- **Breaking:** `TimingSafeEq` now has a blanket `impl<T: TimingSafeEq + ?Sized> TimingSafeEq for &T`, which replaces the old `&str` impl. If your crate has its own `impl TimingSafeEq for &YourType` where `YourType: TimingSafeEq`, it now conflicts with the blanket impl and fails to compile. Delete it; the blanket impl provides the same comparison. There is no `&mut T` impl.
- **Breaking:** the crate now declares a minimum supported Rust version of 1.88. 0.5.1 declared none.

### Features

- `TimingSafeEq` is implemented for `bool`, `f32`, `f64` and `str`, and for any `&T` where `T: TimingSafeEq` (so `&[u8]`, `&str` and `&[T; N]` work). `#[derive(TimingSafeEq)]` now accepts borrowed fields such as `&'a [u8]` and fields of these types. Floats compare by bit pattern, not IEEE `==`: a `NaN` equals a `NaN` with the same bits, and `-0.0` does not equal `0.0`. Do not derive std's `PartialOrd` or `Ord` beside `TimingSafeEq` on a type with float fields, since the two disagree on `NaN` and signed zero; nothing warns about this.
- The re-exported `OpaqueDebug` and `TimingSafeEq` derives no longer need a `use` of the trait, work through the `vitaminc` umbrella crate or a renamed dependency, and accept a `crate = "..."` attribute. They also fix several inputs that failed to compile in 0.5.1. See the `vitaminc-protected-derive` 0.6.0 changelog, including one case that now fails to compile.

## [0.5.1] - 2026-10-05

## [0.5.0] - 2026-09-20

### Documentation

- `Locked` says what each backend gives, and `new` what a move can leave behind

### Features

- `Locked<T>`, mlock-backed storage for secrets that outlive a call

### Fixes

- a `Locked` region is wiped on every release and holds a `T` before it is one
- `Locked` applies each protection independently and wipes storage as bytes
- a `Locked` value knows which process holds its lock
- `Locked` relocks every protection, zeroizes `T` before dropping it, and survives a local review
- a process that cannot track forks says so on every `Locked` value

## [0.4.0] - 2026-09-12

## [0.3.0] - 2026-09-07

### Breaking

- **Breaking:** rename `IsEmpty` to `MaybeEmpty`

### Documentation

- scope the Usage wipe claim to fields that carry drop glue
- stop describing map as an escape hatch
- spell out what `NonEmpty::with` does not do for the tail

### Features

- `NonEmpty::with` and `From<integer>` for `NonEmpty`
- keep `IsEmpty` as a deprecated alias for `MaybeEmpty`

### Fixes

- bound `NonEmpty::with` on `MaybeEmpty` and document its shape
- lift the `MaybeEmpty` bound from `with`'s tail; mark constructors `#[must_use]`

## [0.2.0] - 2026-09-03

### Breaking

- **Breaking:** Controlled types (`Protected`, `Equatable`, `Exportable`) now zeroize their contents on drop, and `Controlled` requires `Zeroize` ([#181](https://github.com/cipherstash/vitaminc/pull/181)). Payload types and custom `Controlled` impls must implement `Zeroize`.

### Features

- `NonEmpty` wrapper proves a context non-empty once, at construction; the `nonempty!` macro accepts byte strings and wider inputs, and `Cow` emptiness is judged generically.

### Fixes

- `ProtectedDigest` secret lifecycle hardened: digest state must implement `ZeroizeOnDrop`, and outputs write directly into protected or explicitly public destinations.

### Documentation

- READMEs and rustdoc corrected (fabricated APIs, stale claims); SECURITY.md added.

### Security

- require `ProtectedDigest` state to implement `ZeroizeOnDrop`
- write digest outputs directly into protected or explicitly public destinations

### Breaking changes

- remove return-by-value `ProtectedDigest` finalization helpers
- add explicit public input and output methods to `ProtectedDigest`



### Miscellaneous

- bump digest to 0.11 and sha2 to 0.11

### Style

- apply rustfmt to long array literal in conversions test


### Documentation

- update doctests to show vitaminc::* import paths


### Fixes

- replace bincode with rmp-serde in tests

### Miscellaneous

- bump serde_json from 1.0.145 to 1.0.149
- bump bincode from 1.3.3 to 3.0.0
- bump quickcheck from 1.0.3 to 1.1.0
- bump opaque-debug from 0.3.1 to 0.4.0
- release v0.1.0-pre4.1


### Fixes

- replace bincode with rmp-serde in tests

### Miscellaneous

- bump serde_json from 1.0.145 to 1.0.149
- bump bincode from 1.3.3 to 3.0.0
- bump quickcheck from 1.0.3 to 1.1.0
- bump opaque-debug from 0.3.1 to 0.4.0

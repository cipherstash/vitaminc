# vitaminc-aead-napi

NAPI (Node-API) bindings layer for the Vitamin-C AEAD encryption traits —
the JS-specific piece of exposing `vitaminc` encryption to Node.js.

The value tree itself lives in the language-neutral `vitaminc-aead-value`
crate ([`Value`]): an owned, `Send`, self-describing representation of a
dynamically typed value, with `Encrypt`/`Decrypt` impls and a frozen,
cross-language leaf wire format. This crate adds only what is JS-specific:

- **`NapiValue`** — a newtype over [`Value`] carrying the
  `FromNapiValue`/`ToNapiValue` conversions (the orphan rule prevents
  implementing napi's traits on the foreign type directly). Conversions run
  on the JS thread; everything past the `#[napi]` boundary works with the
  bare `Value`, on any thread.
  - JS `number` ↔ `Value::Float64`. `BigInt` selects the smallest fitting
    integer width through 128 bits, preferring signed at each width. Every
    integer kind decodes as `BigInt`; `Float32` widens exactly to `number`.
    Equality terms share one domain across integer widths, so a `BigInt`
    written as `int8` matches the same number written as `int64` from Go;
    both float widths likewise share one domain. Integers and floats stay
    distinct, so a JS `number` 5 (`Float64`) does not match an `int64` 5:
    use `BigInt` for integer data.
  - JS `Date` ↔ `Timestamp` at millisecond precision. Sub-millisecond
    timestamps and leap seconds decode as
    `{ timestamp: "RFC3339-with-nanoseconds" }`, also accepted on input, so no
    precision is discarded. Years outside 0000–9999 use an ISO 8601 expanded
    year (`+12000-01-01T00:00:00.000000001Z`), accepted on input as well.
  - Calendar dates use `{ date: "YYYY-MM-DD" }` (including ISO extended years);
    finite decimals use `{ decimal: "1.50" }`, retaining scale and signed zero.
    These wrappers reserve exactly one own enumerable property; an object with
    additional properties remains an ordinary object. Decimal input is exact
    fixed-point text, not a JS number or an arbitrary decimal-library instance.
    NaN and infinities throw `TypeError` with code `ERR_NON_FINITE_DECIMAL`.
    Other scalar failures, including a wrapper whose payload is not a string,
    have stable `ERR_INTEGER_RANGE`, `ERR_INVALID_DATE`,
    `ERR_INVALID_TIMESTAMP` and `ERR_INVALID_DECIMAL` codes.
  - **The wrapper keys are reserved.** An object with exactly one own
    enumerable property named `date`, `timestamp` or `decimal` is always read
    as a wrapper. Other languages can store such an object as ordinary data,
    so decrypting it in JS and encrypting it again is lossy: Go's
    `{"date": "2024-01-01"}` comes back as a `date` scalar, and
    `{"date": "tomorrow"}` throws `ERR_INVALID_DATE`. Avoid these one-key
    shapes in data that crosses languages.
- **`JsCipherText<Leaf, P>`** — projects the generic `CipherText` container
  onto plain JS values (`{ t, v }` nodes with `Buffer` leaves) and back, as
  an in-memory/application-side representation. Durable cross-language
  database storage is the EQL layer's job, not this projection's. The
  passthrough payload `P` converts through `NapiPassthrough`, implemented
  for `NapiValue` and `()`, which applies the tree's nesting limit to the
  payload too.

This crate is a library consumed by the Node addon (cdylib/npm package);
it is not itself loadable from Node.

## Testing the conversion layer

`cargo test -p vitaminc-aead-napi` runs pure Rust boundary tests and builds a
small standalone addon to run two suites inside Node:
`tests/value-conformance.cjs` for scalar conversions, and
`tests/object-safety.cjs` for which object keys are read, how output
properties are written, and the ciphertext node projection.
Node.js must be available on PATH. The addon is a separate Cargo workspace so
the library's `napi/noop` dev feature cannot stub the real Node symbols.

Rust, Node, Go's codec, and the embedded WASM guest consume the same
`testdata/value-conformance.json` vectors. They pin all scalar tags, numeric
boundaries, calendar/decimal payloads and hostile-input refusals. JS integer
host values round-trip as BigInt; Float32 becomes a JS number and re-encodes
as Float64. Go retains its established undefined-to-nil projection. These two
host projections are explicit fields in the corpus; Rust codec vectors always
round-trip byte-for-byte.

A second live Node test converts a sample for every `ValueKind::ALL` entry
through `NapiValue::to_napi_value` and checks its JavaScript value, so adding
a kind without a sample or a working output conversion fails CI. It also
covers `Null`, `Undefined`, and `Passthrough`, which have no kind. Run it
locally (use `.dylib` instead of `.so` on macOS):

```sh
cargo build --locked -p vitaminc-aead-napi --example kind_inventory
node packages/aead-napi/tests/kind_inventory.cjs target/debug/examples/libkind_inventory.so
```

The JS-boundary conversion functions — `js_to_value`, `value_to_js`,
`node_to_js`, `node_from_js` — and their helpers — `own_enumerable_keys`,
`get_property_unknown`, `ensure_plain_object`, `wrapper_text`,
`wrapper_to_js` — take a live
`napi_env`, `Unknown`, or `Object`, which only exists inside a running V8
isolate, so Rust unit tests cannot reach them. The Node suites do:
`tests/node.rs` rebuilds the test addon from the crate's source, so the
mutation gate tests these functions like any other code. Only the CRAP gate
still exempts them, by name in `.cargo-crap.toml`, because they run inside
the separately built addon, where `cargo llvm-cov` cannot measure their
coverage. The smaller helpers in the same position (`define_own_properties`,
`own_property`, `new_array`, `get_own`, `lossless_string`, `node_object`)
are simple enough to stay under the CRAP threshold even at 0% coverage, so
they are not exempted.

## Safety notes

- Unsafe code is limited to the conversion trait methods napi-rs requires
  (`FromNapiValue`/`ToNapiValue` for `NapiValue` and `JsCipherText`).
  Everything else uses napi-rs's safe API. The crate denies
  `unsafe_op_in_unsafe_fn` and `clippy::undocumented_unsafe_blocks`, so each
  unsafe block states why it is sound.
- The original copies of encrypted values in the V8 heap are owned by the
  JS engine and cannot be wiped from Rust.
- Property names that would touch the prototype chain (`__proto__`,
  `constructor`, `prototype`) are rejected in both directions. Nesting is
  limited to 128 levels in both directions too, counted as the transport
  decoder counts it, including inside a ciphertext's passthrough payload. A
  tree built in Rust is measured before it is converted, and one that is too
  deep is dropped without recursing, so even a tree far too deep for the
  stack fails cleanly instead of aborting Node.
- Only **plain objects** (prototype `Object.prototype` or `null`) are
  accepted for encryption. `Map`, `Set`, `RegExp`, `DataView`, class
  instances and other exotic objects keep their state in internal slots and
  would silently encrypt as `{}` — they are rejected with an error instead.
- Object enumeration reads **own, enumerable, string-keyed** properties
  only, so a polluted `Object.prototype` (or inherited enumerable getters)
  can never leak keys into — or run code during — encryption. An own
  property explicitly set to `undefined` round-trips.
- Sparse arrays (`[, , "x"]`, `new Array(n)`) are rejected; `[undefined]`
  is not sparse and round-trips. A hole is detected per index via
  `Object.hasOwn` semantics, so a polluted `Array.prototype` cannot fill
  holes with inherited elements.
- JS-reported array lengths are never trusted for up-front allocation
  (a `new Array(2**32 - 1)` costs the attacker one line and materialises
  nothing), in both the value converter and the ciphertext rebuilder.
- Strings and object keys containing unpaired UTF-16 surrogates are
  **rejected** rather than silently normalized: the UTF-8 fetch would
  replace a lone surrogate with U+FFFD, sealing a plaintext that no longer
  equals what the caller passed, or a key that no longer names its
  property. Each property is read back through its original JS key.
- Everything this crate builds in JS is written with **own-property
  defines** (`napi_define_properties`, one call per object), not `[[Set]]`
  assignment: decrypted object properties and array elements, and every
  ciphertext node's `t`, `v`, sequence elements and map entries. A polluted
  setter on `Object.prototype` or `Array.prototype` can never observe
  decrypted plaintext or ciphertext, or swallow a property.
- A ciphertext node handed back for decryption must be an object. N-API
  reads properties of a primitive through its wrapper, so a bare string
  would otherwise take `t` and `v` from `String.prototype`.
- Errors carry no cryptographic detail (`Unspecified` at the trait layer).

[`Value`]: vitaminc_aead_value::Value

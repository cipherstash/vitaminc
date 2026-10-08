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
  - JS `Date` ↔ `Timestamp` at millisecond precision within chrono's range.
    Sub-millisecond timestamps, leap seconds and timestamps beyond JS Date's
    range decode as `{ timestamp: "RFC3339-with-nanoseconds" }`, also accepted
    on input, so no precision is discarded.
  - Calendar dates use `{ date: "YYYY-MM-DD" }` (including ISO extended years);
    finite decimals use `{ decimal: "1.50" }`, retaining scale and signed zero.
    These wrappers reserve exactly one own enumerable property; an object with
    additional properties remains an ordinary object. Decimal input is exact
    fixed-point text, not a JS number or an arbitrary decimal-library instance.
    NaN and infinities throw `TypeError` with code `ERR_NON_FINITE_DECIMAL`.
    Other scalar failures have stable `ERR_INTEGER_RANGE`, `ERR_INVALID_DATE`,
    `ERR_INVALID_TIMESTAMP` and `ERR_INVALID_DECIMAL` codes.
- **`JsCipherText<Leaf, P>`** — projects the generic `CipherText` container
  onto plain JS values (`{ t, v }` nodes with `Buffer` leaves) and back, as
  an in-memory/application-side representation. Durable cross-language
  database storage is the EQL layer's job, not this projection's.

This crate is a library consumed by the Node addon (cdylib/npm package);
it is not itself loadable from Node.

## Testing the conversion layer

`cargo test -p vitaminc-aead-napi` runs pure Rust boundary tests and builds a
small standalone addon to run `tests/value-conformance.cjs` inside Node.
Node.js must be available on PATH. The addon is a separate Cargo workspace so
the library's `napi/noop` dev feature cannot stub the real Node symbols.

Rust, Node, Go's codec, and the embedded WASM guest consume the same
`testdata/value-conformance.json` vectors. They pin all scalar tags, numeric
boundaries, calendar/decimal payloads and hostile-input refusals. JS integer
host values round-trip as BigInt; Float32 becomes a JS number and re-encodes
as Float64. Go retains its established undefined-to-nil projection. These two
host projections are explicit fields in the corpus; Rust codec vectors always
round-trip byte-for-byte.

The existing named metric exemptions for live N-API entry points remain;
new pure scalar conversion helpers participate in coverage and mutation gates.
The Node test runs in package-scoped mutation tests as well as CI.

## Safety notes

- The original copies of encrypted values in the V8 heap are owned by the
  JS engine and cannot be wiped from Rust.
- Property names that would touch the prototype chain (`__proto__`,
  `constructor`, `prototype`) are rejected in both directions, and
  recursion depth is bounded.
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
- Strings containing unpaired UTF-16 surrogates are **rejected** rather
  than silently normalized: the UTF-8 fetch would replace a lone surrogate
  with U+FFFD, sealing a plaintext that no longer equals what the caller
  passed.
- Decrypted objects (and rebuilt ciphertext maps) are written with
  **own-property defines** (`napi_define_properties`), not `[[Set]]`
  assignment, so a polluted `Object.prototype` setter can never observe
  decrypted plaintext or swallow a property.
- Errors carry no cryptographic detail (`Unspecified` at the trait layer).

[`Value`]: vitaminc_aead_value::Value

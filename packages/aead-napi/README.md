# vitaminc-aead-napi

NAPI (Node-API) bindings layer for the Vitamin-C AEAD encryption — the
JS-specific piece of exposing `vitaminc` encryption to Node.js.

The data model is the FFI boundary (ADR 0001): a value coming in is a
[`Plaintext`] source and a value going out is built by a [`Sink`], and
nothing sits in between. This crate supplies the JavaScript side of both:

- **`JsRef<'e>`** — a live JavaScript value as a `Plaintext`. The walk runs
  on the JavaScript thread, reading each value as it goes, so no value tree
  is built and a scalar leaves the engine only to go straight to the sink.
  `encrypt(JsRef::new(value), &cipher, aad)` seals a value in place. To
  encrypt off the JavaScript thread, `JsRef::to_frame` snapshots the value
  as a frame there, and a worker seals the frame with no JavaScript access.
- **`JsBuilder<'e>`** — a `Sink` that builds JavaScript values, for
  `decrypt_into(&cipher, ct, aad, JsBuilder::new(&env))`, or
  `JsBuilder::build(&env, frame)` for a frame.
- **`JsCipherText<Leaf, P>`** — projects the generic `CipherText` container
  onto plain JS values (`{ t, v }` nodes with `Buffer` leaves) and back, as
  an in-memory/application-side representation. Durable cross-language
  database storage is the EQL layer's job, not this projection's. The
  passthrough payload `P` converts through `NapiPassthrough`, implemented
  for `PassthroughFrame` (the sink-based tree's payload) and `()`, which
  applies the tree's nesting limit to the payload too.
- **`Wrappers`** — the wrapper classes `VcDate`, `VcTimestamp`,
  `VcDecimal` and `VcUuid`, defined once per environment and exported by an
  addon with `Wrappers::exports`.

## The mapping

| JavaScript                          | Scalar                                   |
| ----------------------------------- | ---------------------------------------- |
| `null`                              | null                                     |
| `undefined`                         | null, logical type `Undefined`           |
| `boolean`                           | bool                                     |
| `number`                            | float (`F64`)                            |
| `bigint`                            | int, at the narrowest fitting width      |
| `string`                            | text                                     |
| `Buffer`, `Uint8Array`              | bytes                                    |
| `Date`                              | `Timestamp(Millis)` over the `i64` count |
| `VcDate("YYYY-MM-DD")`              | `Date` over the day count                |
| `VcTimestamp("RFC 3339, ns")`       | `Timestamp(Nanos)` over the count        |
| `VcDecimal("1.50")`                 | `Decimal { scale }` over the mantissa    |
| `VcUuid("hyphenated hex")`          | `Uuid` over sixteen bytes                |
| `Array`                             | sequence                                 |
| plain object                        | map, over own enumerable string keys     |

And back: every int width is a `BigInt`; both float widths are a `number`
(`f32` widens exactly); a timestamp in any unit is a `Date` when it is
whole milliseconds and a `VcTimestamp` otherwise, so no precision is
discarded; a calendar date, a decimal and a UUID are their wrapper. A
`Date` is stored as its millisecond count and read back as the same
count, never converted through seconds and nanoseconds. A logical type
this build does not know has no JavaScript value and is refused rather
than shown with its type dropped.

Equality terms share one domain across integer widths, so a `BigInt`
written as `int8` matches the same number written as `int64` from Go;
both float widths likewise share one domain. Integers and floats stay
distinct, so a JS `number` 5 does not match an `int64` 5: use `BigInt` for
integer data.

### The wrapper classes

JavaScript has no type of its own for a calendar date, a timestamp finer
than a millisecond, a decimal or a UUID, so each is an instance of a small
class holding its text: `new VcDecimal("1.50")`. The constructor takes a
string and nothing else; the text is checked, and the scalar built from
it, when the value is encrypted, so one rule applies however the instance
was made. `value` is an own, read-only, enumerable property, so
`JSON.stringify` (which gives the bare text through `toJSON`),
`structuredClone` and a deep equality all see it.

An instance is not a plain object, so it is never confused with data
another language wrote as an ordinary one-key object: Go's
`{"date": "2024-01-01"}` decrypts in JS as that object and encrypts again
unchanged (#382). Decimal text is exact fixed-point, not a JS number or an
arbitrary decimal-library instance; a negative zero reads back as zero
with its scale kept (ADR 0001). A leap second has no count since the epoch
and is refused. Timestamps outside years 0000–9999 use an ISO 8601
expanded year (`+12000-01-01T00:00:00.000000001Z`), on both sides.

Scalar failures throw a `TypeError` with a stable code: `ERR_INTEGER_RANGE`,
`ERR_INVALID_DATE`, `ERR_INVALID_TIMESTAMP`, `ERR_INVALID_DECIMAL`,
`ERR_NON_FINITE_DECIMAL` and `ERR_INVALID_UUID`.

The classes live in the environment's instance data
(`napi_set_instance_data`), which an addon that uses this crate must leave
to it.

## Errors

A getter that throws, a string with an unpaired surrogate, a `BigInt` out
of range or a `Date` outside chrono's range stops the walk through the
sink's `Error::source`, as a [`JsFault`] carrying the napi status and
reason. At the boundary, `JsFault::from_source` turns it back into the
napi error, and a pending JavaScript exception surfaces unchanged: the
application sees the error its getter threw.

This crate is a library consumed by the Node addon (cdylib/npm package);
it is not itself loadable from Node.

## Testing the conversion layer

`cargo test -p vitaminc-aead-napi` runs pure Rust boundary tests and builds a
small standalone addon to run four suites inside Node:
`tests/value-conformance.cjs` for scalar conversions against the shared
corpus, `tests/object-safety.cjs` for which object keys are read, how
output properties are written, and the ciphertext node projection,
`tests/kind_inventory.cjs` for every scalar kind the build can produce,
and `tests/encrypt.cjs` for every row of the mapping encrypted and
decrypted through real AES-256-GCM, with the error, depth and async
guarantees above. Node.js must be available on PATH. The addon is a
separate Cargo workspace so the library's `napi/noop` dev feature cannot
stub the real Node symbols.

Rust, Node, Go's codec, and the embedded WASM guest consume the same
`testdata/value-conformance.json` vectors. They pin all scalar tags, numeric
boundaries, calendar/decimal payloads and hostile-input refusals. JS integer
host values round-trip as BigInt; Float32 becomes a JS number and re-encodes
as Float64; a whole-millisecond timestamp becomes a `Date` and re-encodes as
`Timestamp(Millis)` in the `0xF3` envelope. Go retains its established
undefined-to-nil projection. These host projections are explicit fields in
the corpus; Rust codec vectors always round-trip byte-for-byte.

The functions that walk and build live JavaScript values take a
`napi_env`, `Unknown` or `Object`, which only exists inside a running V8
isolate, so Rust unit tests cannot reach them. The Node suites do:
`tests/node.rs` rebuilds the test addon from the crate's source, so the
mutation gate tests these functions like any other code. Only the CRAP gate
still exempts them, by file and by name in `.cargo-crap.toml`, because they
run inside the separately built addon, where `cargo llvm-cov` cannot
measure their coverage.

## Safety notes

- Unsafe code is limited to the conversion trait methods napi-rs requires
  (`FromNapiValue`/`ToNapiValue` for `JsCipherText`). Everything else uses
  napi-rs's safe API. The crate denies `unsafe_op_in_unsafe_fn` and
  `clippy::undocumented_unsafe_blocks`, so each unsafe block states why it
  is sound.
- The original copies of encrypted values in the V8 heap are owned by the
  JS engine and cannot be wiped from Rust. A frame snapshot is `Protected`
  and wiped on drop.
- Property names that would touch the prototype chain (`__proto__`,
  `constructor`, `prototype`) are rejected in both directions. Nesting is
  limited to 128 levels in both directions too, counted as the frame counts
  it, including inside a ciphertext's passthrough payload. The walk and the
  build each check the depth before recursing, so a tree far too deep for
  the stack fails cleanly instead of aborting Node, and a document at the
  limit walks in a debug build.
- Only **plain objects** (prototype `Object.prototype` or `null`) and the
  wrapper classes are accepted for encryption. `Map`, `Set`, `RegExp`,
  `DataView`, class instances and other exotic objects keep their state in
  internal slots and would silently encrypt as `{}` — they are rejected with
  an error instead.
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
  nothing), in the walk, the build and the ciphertext rebuilder.
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

[`Plaintext`]: vitaminc_aead::Plaintext
[`Sink`]: vitaminc_aead::Sink
[`JsFault`]: crate::JsFault
